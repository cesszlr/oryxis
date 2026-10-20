//! Leaving the vault, by hand or by idle timer.
//!
//! The two paths differ on purpose and are worth reading side by
//! side: `LockVault` is a full teardown (sessions, tabs, secrets),
//! `SoftLockVault` is soft (zeroize the key, show the lock screen,
//! keep the live SSH sessions, since an established channel never
//! needs the key again).

use super::*;

impl Oryxis {
    pub(super) fn handle_vault_lock(
        &mut self,
        message: VaultMessage,
    ) -> Task<Message> {
        match message {

            // ── Manual lock confirmation ──
            VaultMessage::LockVaultConfirm => {
                // Lock Vault tears every live session and tab down, so the
                // button asks first (an accidental click would sever all
                // open connections). Close the surface that fired it (the
                // burger menu; the palette already closes on activate) so
                // the confirm layers over a plain view, mirroring
                // RequestClearHistory's overlay close.
                self.vaults.cur_mut().panels.burger_menu = false;
                if self.vaults.cur().vault_ui.has_user_password {
                    // A standing choice saved from the dialog's "always
                    // use the selected option" opt-in commits directly;
                    // Settings > Security exposes the same value so the
                    // dialog can be brought back ("ask", the default).
                    match self.vaults.cur().prefs.manual_lock_action.as_str() {
                        "sleep" => {
                            return Task::done(Message::Vault(VaultMessage::SoftLockVault));
                        }
                        "lock" => {
                            return Task::done(Message::Vault(VaultMessage::LockVault));
                        }
                        _ => {
                            // The opt-in never carries over from an
                            // earlier arming: a stale check would turn a
                            // one-off choice into a standing one.
                            self.vaults.cur_mut().vault_ui.lock_confirm_remember = false;
                            self.vaults.cur_mut().vault_ui.lock_confirm = true;
                        }
                    }
                }
            }
            VaultMessage::CancelLockVaultConfirm => {
                self.vaults.cur_mut().vault_ui.lock_confirm = false;
            }
            VaultMessage::LockVaultConfirmRememberToggled => {
                self.vaults.cur_mut().vault_ui.lock_confirm_remember = !self.vaults.cur_mut().vault_ui.lock_confirm_remember;
            }
            VaultMessage::LockVaultConfirmProceed { sleep } => {
                // Persist the standing choice BEFORE committing: both lock
                // paths sweep dialog state, and the soft lock zeroizes the
                // key (settings survive; the vault stays readable for
                // settings without the master key).
                if self.vaults.cur().vault_ui.lock_confirm_remember {
                    let value = if sleep { "sleep" } else { "lock" };
                    self.vaults.cur_mut().prefs.manual_lock_action = value.into();
                    self.persist_setting("manual_lock_action", value);
                }
                return Task::done(Message::Vault(if sleep {
                    VaultMessage::SoftLockVault
                } else {
                    VaultMessage::LockVault
                }));
            }

            // ── Vault lock (manual + idle auto-lock) ──
            VaultMessage::SoftLockVault => {
                // Soft lock: the user walked away, not "I'm done". Zeroize
                // the master key and drop to the lock screen, but keep
                // live SSH sessions and tabs so long-running remote work
                // survives the idle period (established channels never
                // need the key again; credentials are only read at
                // connect time). The manual LockVault stays a full
                // teardown. While locked, the session-log flush and
                // auto-reconnect tickers unmount (subscription.rs), so
                // nothing hits the sealed vault; what the recordings
                // produce meanwhile is spooled to disk under a key of
                // this process (`session_spool`) and drained after
                // unlock.
                // A debouncing host-editor auto-save needs the key;
                // persist it before the vault seals. Interrupted: an
                // idle lock concluded nothing, so a half-typed Parent
                // Group name must not become a vault group.
                self.editor_flush_interrupted();
                // What the recordings hold now reaches the vault while
                // the key is still there; only what arrives after the
                // lock goes to the spool.
                if self.vaults.cur().store.is_some() && self.vaults.cur().vault_ui.has_user_password {
                    self.flush_session_logs();
                }
                let ov = self.vaults.cur_mut();
                if let Some(vault) = &mut ov.store
                    && ov.vault_ui.has_user_password
                {
                    vault.lock();
                    self.vaults.cur_mut().vault_ui.state = VaultState::Locked;
                    self.vaults.cur_mut().master_password = None;
                    // What of the app's own (one-per-app) state this lock
                    // may sweep: only what belongs to this vault. The idle
                    // lock of a vault in the background runs with another
                    // vault's window in the fields, whose surface stays.
                    let scope = self.lock_sweep_scope();
                    // The lock screen leads with biometrics when enrolled;
                    // a fallback choice from a previous lock must not stick.
                    self.vaults.cur_mut().vault_ui.password_fallback = false;
                    // The confirm dialog cannot survive either lock path: it
                    // is moot once the lock screen is up, and a stale latch
                    // would re-open over the unlocked app.
                    self.vaults.cur_mut().vault_ui.lock_confirm = false;
                    // Sweep UI that may hold typed or revealed secrets;
                    // everything else (tabs, terminals) stays.
                    self.vaults.cur_mut().revealed_secrets.clear();
                    // A confirm dialog from the unlocked app must not
                    // outlive the lock: the lock screen now renders a
                    // dialog that exists (so the close-window guard can
                    // ask there), and a "Delete?" from before the lock
                    // would be one click from acting on a vault whose
                    // owner walked away. Only a dialog raised over this
                    // vault: an idle lock of a vault in the background
                    // leaves another vault's dialog alone.
                    if scope.floats_mine {
                        self.error_dialog = None;
                    }
                    self.vaults.cur_mut().panels.host_panel = false;
                    self.vaults.cur_mut().host_panel_error = None;
                    self.vaults.cur_mut().editor_form = crate::state::ConnectionForm::default();
                    // The highlight-rule editor edits a copy of a row in
                    // one of those lists; with its list gone, close it so
                    // nothing reopens over the unlocked screen.
                    self.close_highlight_rule_editor();
                    // The key-generation panel carries export
                    // passphrases and a public-key view; sweep it (a
                    // still-running generation task is dropped on
                    // completion by the locked-vault check).
                    self.vaults.cur_mut().panels.key_generate_panel = false;
                    self.vaults.cur_mut().keys_ui.generate_form = crate::state::KeyGenerateForm::default();
                    // The key import panel (holds a pasted cert / PEM) and
                    // the cert viewer are vault-area surfaces; drop them.
                    // The live PEM editor buffer is private material, so it
                    // is reset too, matching the generate-panel sweep.
                    self.vaults.cur_mut().panels.key_panel = false;
                    self.vaults.cur_mut().keys_ui.import_form = crate::state::KeyImportForm::default();
                    self.vaults.cur_mut().keys_ui.import_content = iced::widget::text_editor::Content::new();
                    self.vaults.cur_mut().keys_ui.import_public_content = iced::widget::text_editor::Content::new();
                    self.vaults.cur_mut().keys_ui.import_cert_content = iced::widget::text_editor::Content::new();
                    self.vaults.cur_mut().cert_viewer = None;
                    // The History content-search results hold decrypted
                    // command lines / output excerpts; same rule.
                    self.history_content_reset();
                    // The ssh-agent goes dark (keys ungated) while locked;
                    // the listener stays up so a `git` sees an empty agent.
                    self.agent_on_lock();
                    // Floats, pickers, the SFTP buffer's dialogs, the
                    // monitor and the pending dial prompts are the app's
                    // (one each), swept only when this vault's; see
                    // `lock_sweep_scope` for what the lock screen still
                    // needs of them (issue #169, the careful paste).
                    self.sweep_app_surface_for_lock(scope);
                    // A master-password candidate typed into the change /
                    // set-password form must not survive the soft lock.
                    self.vaults.cur_mut().vault_ui.new_password.clear();
                    self.vaults.cur_mut().vault_ui.confirm_password.clear();
                    // Abort an in-flight KDF calibration too: its snapshot is
                    // secret material and the apply must not land post-lock.
                    self.vaults.cur_mut().vault_ui.pending_kdf_pw = None;
                    // Same for the MCP panel's master-password confirm.
                    self.vaults.cur_mut().mcp.vault_pw_prompt = None;
                    self.vaults.cur_mut().mcp.vault_pw_error = false;
                    // The one Show on the MCP panel governs the master
                    // password too (when the snippet embeds it); a reveal
                    // left on would spell it out the moment the vault opens.
                    self.vaults.cur_mut().mcp.token_visible = false;
                    // Quick-connect entries hold typed plaintext credentials;
                    // sweep the secrets but keep the connections themselves,
                    // matching the soft-lock promise that live tabs survive.
                    // A post-unlock reconnect of a password-based quick host
                    // falls back to the interactive prompt.
                    for entry in self.vaults.cur_mut().quick_connects.values_mut() {
                        entry.password = None;
                        entry.totp_secret = None;
                        entry.proxy_password = None;
                    }
                    self.sweep_sync_passphrase();
                    // Land the keyboard in the unlock field so the user
                    // returning to the machine just types the password:
                    // in the window that shows this vault's lock screen.
                    if scope.in_view {
                        return crate::widgets::focus_input(iced::widget::Id::new(
                            "vault-unlock-password",
                        ));
                    }
                }
            }
            VaultMessage::LockVault => {
                // Same as the soft lock: flush a debouncing host-editor
                // auto-save while the key still exists, and on the same
                // interrupted terms.
                self.editor_flush_interrupted();
                if let Some(vault) = self.vaults.cur_mut().store.as_mut() {
                    vault.lock();
                    // The dialog that armed this is committed; clear the
                    // latch so it cannot re-open over the unlocked app.
                    self.vaults.cur_mut().vault_ui.lock_confirm = false;
                    if self.vaults.cur().vault_ui.has_user_password {
                        self.vaults.cur_mut().vault_ui.state = VaultState::Locked;
                        // The in-memory master password dies with the
                        // lock, like the soft lock already does (it
                        // feeds biometric enroll and the MCP config
                        // embed; neither may outlive the vault key).
                        self.vaults.cur_mut().master_password = None;
                        // ssh-agent goes dark on lock (listener stays up).
                        self.agent_on_lock();
                        // And the MCP panel's typed confirm buffer.
                        self.vaults.cur_mut().mcp.vault_pw_prompt = None;
                        self.vaults.cur_mut().mcp.vault_pw_error = false;
                        // The one Show on the MCP panel governs the master
                        // password too (when the snippet embeds it); a reveal
                        // left on would spell it out the moment the vault opens.
                        self.vaults.cur_mut().mcp.token_visible = false;
                        // Same reset as the soft lock: lead with biometrics.
                        self.vaults.cur_mut().vault_ui.password_fallback = false;
                        self.vaults.cur_mut().connections.clear();
                        self.vaults.cur_mut().quick_connects.clear();
                        self.vaults.cur_mut().keys.clear();
                        self.vaults.cur_mut().snippets.clear();
                        self.vaults.cur_mut().groups.clear();
                        // The relay deploy's parked SSH session and its
                        // rendered plan (the plan carries the token):
                        // the lock severs every live connection, this
                        // one included, and a plan for a host that is
                        // no longer loaded has nothing to run against.
                        // `reset_probe` also ABORTS a probe or run in
                        // flight, so "severs" is true of a deploy too.
                        self.vaults.cur_mut().sync.relay_deploy.reset_probe();
                        // The same sweep the soft lock runs: the sync
                        // passphrase edit (including the decrypted
                        // stored value an open edit caches) must not
                        // outlive the key behind the lock screen.
                        self.sweep_sync_passphrase();
                        // What this lock severs is THIS vault's: its tabs,
                        // its SFTP tabs. Another open vault's sessions go on
                        // (each vault locks on its own).
                        let in_view = self.sever_vault_sessions();
                        let scope = self.lock_sweep_scope();
                        // Its port forwards too: they are live sessions,
                        // and the auto-start ones come back with the
                        // unlock (the soft lock keeps them).
                        let forwards = self.stop_vault_forwards();
                        // The reopen stack goes with them (issue #186).
                        // A manual lock is an explicit "I'm done" that
                        // severs every session; leaving a chord that
                        // dials one of them back afterwards would be the
                        // same stale state this sweep exists to clear.
                        // The SOFT lock deliberately keeps it, along with
                        // the tabs and sessions it also keeps.
                        self.vaults.cur_mut().closed_tabs.clear();
                        // And so does the restore-on-launch snapshot,
                        // for the same reason and by the same rule
                        // (issue #206): the strip it names is the one
                        // this lock just severed, and it is a row a
                        // LOCKED vault can still be read for. The gate
                        // below would write the emptied strip out on
                        // the next message anyway; saying it here is
                        // what makes it a decision rather than a
                        // side effect.
                        if self.vaults.cur().prefs.restore_tabs_on_launch {
                            self.persist_setting("open_tabs", "[]");
                            self.persist_setting("open_tabs_active", "");
                            self.open_tabs_signature = 0;
                        }
                        // And what the launch still owed that strip
                        // (issue #229): dials queued for chips this
                        // lock is about to tear down, and a landing
                        // nobody took.
                        self.vaults.cur_mut().launch_dials.clear();
                        self.vaults.cur_mut().launch_landing = None;
                        self.vaults.cur_mut().launch_landing_deferred = None;
                        // A batch connect still in progress goes the same
                        // way: the next unlock must not resume dialling a
                        // list the user picked before locking.
                        self.vaults.cur_mut().batch_dials.clear();
                        self.clear_terminal_tab_memory();
                        if in_view {
                            self.active_view = View::Dashboard;
                        }
                        // Mirror the soft-lock UI sweep: the manual lock
                        // used to leave overlays, side panels, revealed
                        // secrets and pending auth prompts armed behind
                        // the lock screen (stale state a stray key or a
                        // late async completion could act on, and typed
                        // or revealed secrets have no business surviving
                        // an explicit "I'm done").
                        self.vaults.cur_mut().revealed_secrets.clear();
                        // History content-search results hold decrypted
                        // command lines / output excerpts; sweep like the
                        // soft lock does.
                        self.history_content_reset();
                        // The app's own floats, pickers, SFTP dialogs,
                        // monitor and dial prompts: only this vault's
                        // ("Lock all" runs this once per vault from one
                        // window).
                        self.sweep_app_surface_for_lock(scope);
                        self.vaults.cur_mut().panels.host_panel = false;
                        self.vaults.cur_mut().host_panel_error = None;
                        self.vaults.cur_mut().editor_form = crate::state::ConnectionForm::default();
                        self.vaults.cur_mut().panels.key_generate_panel = false;
                        self.vaults.cur_mut().keys_ui.generate_form = crate::state::KeyGenerateForm::default();
                        self.vaults.cur_mut().panels.key_panel = false;
                        self.vaults.cur_mut().keys_ui.import_form = crate::state::KeyImportForm::default();
                        self.vaults.cur_mut().keys_ui.import_content = iced::widget::text_editor::Content::new();
                        self.vaults.cur_mut().keys_ui.import_public_content = iced::widget::text_editor::Content::new();
                        self.vaults.cur_mut().keys_ui.import_cert_content = iced::widget::text_editor::Content::new();
                        self.vaults.cur_mut().cert_viewer = None;
                        self.vaults.cur_mut().vault_ui.new_password.clear();
                        self.vaults.cur_mut().vault_ui.confirm_password.clear();
                        // Abort an in-flight KDF calibration (snapshot is
                        // secret material; the apply must not land post-lock).
                        self.vaults.cur_mut().vault_ui.pending_kdf_pw = None;
                        // Same auto-focus as the soft lock: the unlock
                        // field is the only thing to interact with.
                        if in_view {
                            return Task::batch([
                                forwards,
                                crate::widgets::focus_input(iced::widget::Id::new(
                                    "vault-unlock-password",
                                )),
                            ]);
                        }
                        return forwards;
                    } else {
                        // No user password: re-open immediately
                        if let Some(vault) = self.vaults.cur_mut().store.as_mut() {
                            let _ = vault.open_without_password();
                        }
                    }
                }
            }
            // The parent routed us here, so anything else is a
            // grouping mistake, not a runtime case.
            m => return crate::dispatch::unrouted(m),
        }
        Task::none()
    }

    /// Drop every trace of the sync group passphrase this session holds:
    /// the edit buffer, the decrypted stored value an open edit caches
    /// for its match hint, the edit mode itself, and a round's armed
    /// key. Shared by BOTH locks, because each is a door behind which a
    /// secret must not sit in RAM. The armed key goes too: a locked
    /// vault cannot store it anyway (`set_sync_sftp_passphrase` needs
    /// the master key), so the round that comes back finds nothing to
    /// commit. The stored value itself rides the encrypted setting.
    fn sweep_sync_passphrase(&mut self) {
        self.vaults.cur_mut().sync.passphrase_input.clear();
        self.vaults.cur_mut().sync.passphrase_matches = None;
        self.vaults.cur_mut().sync.passphrase_stored = None;
        self.vaults.cur_mut().sync.passphrase_editing = false;
        self.vaults.cur_mut().sync.passphrase_field_id = None;
        self.vaults.cur_mut().sync.passphrase_sealed = None;
    }

    /// End every session of the vault the code acts on: its terminal tabs
    /// and their remote sessions, its SFTP tabs, its desktop tunnels, the
    /// callback tunnels and prompts of its panes. Every other vault's go
    /// on. The window in the fields loses its own surface (SFTP buffer,
    /// tab in front) only when it shows this vault; another window keeps
    /// its tab in front at the index it has after the removal. Answers
    /// whether the window in the fields shows the vault. Shared by the
    /// manual lock and the deletion of a vault.
    pub(crate) fn sever_vault_sessions(&mut self) -> bool {
        let vault = self.vaults.current_id();
        let mine = |owner: Option<uuid::Uuid>| owner.is_none_or(|v| v == vault);
        // The window in the fields shows this vault (the
        // lock button), or another one ("Lock all", one
        // `ForVault` per vault): only the first has its own
        // surface reset here.
        let in_view = self.vaults.window_id() == vault;
        // Close live remote sessions, not just the panes
        // referencing them, so locking the vault really
        // severs the remote connections.
        for tab in self.tabs.iter().filter(|t| mine(t.vault)) {
            Self::close_tab_sessions(tab);
        }
        // Drop RDP/VNC tunnels too (each Arc drop cancels
        // the -L forward); locking severs everything. The
        // terminal's callback tunnels go the same way, and
        // a link waiting on an answer stops waiting.
        self.vaults.cur_mut().remote_desktop_forwards.clear();
        // And the login staged for mstsc: a client still
        // up holds it in memory, the store need not.
        crate::remote_desktop::sweep_stale_credentials();
        // The panes that stay are the other vaults'.
        let staying_panes: std::collections::HashSet<uuid::Uuid> = self
            .tabs
            .iter()
            .filter(|t| !mine(t.vault))
            .flat_map(|t| t.pane_grid.panes.values().map(|p| p.id))
            .collect();
        self.link_forwards.retain(|(pane, _), _| staying_panes.contains(pane));
        if self
            .link_confirm
            .as_ref()
            .is_some_and(|c| !c.pane_id.is_some_and(|p| staying_panes.contains(&p)))
        {
            self.link_confirm = None;
        }
        // A buffer parked for Save Output is the terminal's
        // text, gone with the terminal.
        self.save_output = None;
        // Standalone SFTP tabs ride their own SSH channels:
        // close every mounted session and drop the tabs (plus
        // their tab-order entries and the hoisted buffer), mirroring
        // the terminal teardown above. Without this an SFTP tab's
        // session Arc would outlive the lock screen and reappear
        // mounted after unlock.
        for tab in self.sftp_tabs.iter().filter(|t| mine(t.vault)) {
            if let Some(session) = &tab.state.left.session {
                session.close();
            }
            if let Some(session) = &tab.state.right.session {
                session.close();
            }
        }
        // The ACTIVE standalone tab's live state rides the
        // swap-on-focus buffer (`self.sftp`), not its parked
        // `state` slot (a taken default), so its sessions must
        // be closed here too: replacing the buffer below only
        // drops the Arc, and a clone held by an in-flight
        // transfer would keep the connection alive behind the
        // lock screen. A hybrid owner's mounts sit on pane
        // sessions already closed above; close() is idempotent.
        // Only when the buffer is this vault's: a window on another
        // vault holds that vault's.
        if in_view {
            if let Some(session) = &self.cur_sftp().left.session {
                session.close();
            }
            if let Some(session) = &self.cur_sftp().right.session {
                session.close();
            }
        }
        let gone_sftp: std::collections::HashSet<uuid::Uuid> = self
            .sftp_tabs
            .iter()
            .filter(|t| mine(t.vault))
            .map(|t| t.id)
            .collect();
        self.sftp_tabs.retain(|t| !mine(t.vault));
        self.tab_order.retain(|r| {
            !matches!(r, crate::state::TabRef::Sftp(id) if gone_sftp.contains(id))
        });
        if in_view {
            self.sftp = crate::state::SftpState::default();
            self.active_sftp = None;
        }
        // The progress card of a dial on one of these tabs
        // ends with it; one on a staying tab follows its
        // tab to the new index.
        let dialing = self
            .connecting
            .as_ref()
            .and_then(|c| self.tabs.get(c.tab_idx))
            .map(|t| (t._id, mine(t.vault)));
        if dialing.is_some_and(|(_, gone)| gone) {
            self.abort_progress_dial();
            self.connecting = None;
        }
        let active_id = self.active_tab.and_then(|i| self.tabs.get(i)).map(|t| t._id);
        self.tabs.retain(|t| !mine(t.vault));
        if let Some((id, false)) = dialing
            && let Some(c) = self.connecting.as_mut()
            && let Some(idx) = self.tabs.iter().position(|t| t._id == id)
        {
            c.tab_idx = idx;
        }
        // Another vault's window keeps its tab in front, at
        // the index it has now.
        self.active_tab = if in_view {
            None
        } else {
            active_id.and_then(|id| self.tabs.iter().position(|t| t._id == id))
        };
        in_view
    }
}

/// Which of the app's one-per-app surfaces a lock of the acting vault
/// may sweep ([`Oryxis::lock_sweep_scope`]): the idle lock of a vault in
/// the background, and "Lock all", run with another vault's window in
/// the fields, whose menus, dialogs, buffer and dials are not this
/// vault's to close.
#[derive(Clone, Copy)]
pub(crate) struct LockSweepScope {
    /// The window in the fields shows the locking vault.
    pub(crate) in_view: bool,
    /// The floating layer (menus, modals) was raised over a window on
    /// the locking vault.
    pub(crate) floats_mine: bool,
    /// The dial in progress (its prompts: host key, 2FA, auth switch)
    /// is a tab of the locking vault's.
    pub(crate) dial_mine: bool,
}

impl Oryxis {
    pub(crate) fn lock_sweep_scope(&self) -> LockSweepScope {
        let vault = self.vaults.current_id();
        let window = self.vaults.window_id();
        let in_view = window == vault;
        let floats_mine = self.vault_of_window(self.float_window) == vault;
        // A dial with a progress card is its tab's vault's; a prompt a
        // pane's reconnect raised belongs to whatever this window shows.
        let dial_mine = self
            .connecting
            .as_ref()
            .and_then(|c| self.tabs.get(c.tab_idx))
            .map(|t| t.vault_or(window) == vault)
            .unwrap_or(in_view);
        LockSweepScope { in_view, floats_mine, dial_mine }
    }

    /// The app-level half of a lock's sweep, soft or hard, each piece
    /// only when `scope` says it is the locking vault's.
    pub(crate) fn sweep_app_surface_for_lock(&mut self, scope: LockSweepScope) {
        let vault = self.vaults.current_id();
        let window = self.vaults.window_id();
        // The session player / log viewer hold DECRYPTED recording bytes
        // (a session that ran `cat /etc/shadow` keeps that output in the
        // emulator grid / rendered spans). Secret-bearing UI like a
        // revealed secret, with no vault written on it: swept whichever
        // vault locks; it can only be rebuilt from its vault anyway.
        self.session_player = None;
        self.viewing_session_log = None;
        // The burger menu is the vault's own (drawn by its windows).
        self.vaults.cur_mut().panels.burger_menu = false;
        if scope.floats_mine {
            self.overlay = None;
            self.card_context_menu = None;
            // Top-strip pickers (command palette, tab-jump, new-tab
            // picker) are NOT rendered over the lock screen, but their
            // `show_*` flags still make `any_modal_blocks_input()` true,
            // so the modal key router would keep processing arrows /
            // Enter for the hidden surface behind the lock screen (the
            // command palette could even dispatch an action while
            // locked). A careful-paste / snippet-variables confirm
            // parked over a live session is ARMED state: its keynav
            // default is the Confirm row, the lock screen never
            // re-records the modal ring, and a stray Enter on the lock
            // screen would inject the staged text into the still-live
            // session, the exact auto-run the careful paste exists to
            // stop. Close them and drop the stale modal recording.
            self.close_modal(crate::state::Modal::CommandPalette);
            self.close_modal(crate::state::Modal::TabJump);
            self.close_modal(crate::state::Modal::NewTabPicker);
            self.close_modal(crate::state::Modal::CarefulPaste);
            self.close_modal(crate::state::Modal::SnippetVars);
            self.pending_paste_install = None;
            self.pending_paste_snippet = None;
            self.modal_nav_reset();
        }
        if scope.in_view {
            // The SFTP buffer in the fields is this window's: its row
            // menu (a dropdown, not a Modal, so the modal sweep never
            // reaches it; left armed, the Enter that submits the unlock
            // password activated its stale default row, issue #169) and
            // its dialogs, which carry remote paths and live action
            // buttons; a watch holding a pending save goes with them.
            self.sftp.row_menu = None;
            self.sftp.picker_open = false;
            self.sftp.new_entry = None;
            self.sftp.delete_confirm.clear();
            self.sftp.overwrite_prompt = None;
            self.sftp.properties = None;
            self.sftp.edit_watches.clear();
            self.sftp_edit_reopen = None;
            // Monitor samples are host telemetry gathered while unlocked;
            // a locked screen shows nothing about the fleet. The stamp
            // bump inside makes a probe still in flight land dead.
            self.monitor_reset_all();
        }
        // Watches parked in this vault's standalone / hybrid tab states
        // feed the same 2 s tick; left alive they would keep uploading
        // local saves (under an autosave grant) behind the lock screen,
        // and dirty ones would re-prompt after unlock. Another vault's
        // tabs keep theirs.
        for tab in self.sftp_tabs.iter_mut().filter(|t| t.vault.unwrap_or(window) == vault) {
            tab.state.edit_watches.clear();
        }
        let mut panes: Vec<uuid::Uuid> = Vec::new();
        for tab in self.tabs.iter_mut().filter(|t| t.vault_or(window) == vault) {
            tab.files_state.edit_watches.clear();
            panes.extend(tab.pane_grid.panes.values().map(|p| p.id));
        }
        // The tmux listings of this vault's panes: what runs on a host
        // is telemetry too, and a locked screen owes the fleet nothing.
        for pane in panes {
            self.tmux_reset_pane(&pane);
        }
        if scope.dial_mine {
            // A pending keyboard-interactive prompt belongs to an
            // in-flight connect; cancel it cleanly (the engine treats
            // `None` as auth abort). A pending host-key prompt is a
            // security dialog for an in-flight backgrounded connect;
            // reject it (safe default) rather than leaving it rendered
            // over the lock screen. Mirrors SshHostKeyReject.
            if self.pending_kbi_prompt.take().is_some() {
                self.kbi_inputs.clear();
                if let Some(ref tx) = self.kbi_response_tx {
                    let _ = tx.try_send(None);
                }
            }
            if self.pending_host_key.take().is_some()
                && let Some(tx) = self.active_host_key_tx.take()
            {
                let _ = tx.try_send(false);
            }
            self.pending_kbi_quick = None;
            // A parked identity/key switch must not fire a reconnect
            // behind the lock screen.
            self.pending_auth_switch = None;
        }
    }
}

