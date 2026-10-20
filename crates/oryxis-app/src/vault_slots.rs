//! The vaults this process has open, and which one a piece of code is
//! working on.
//!
//! Several vaults may be open at once, and every window works on one of
//! them (`MULTI_VAULT_SPEC.md`): the window carries the vault's id
//! (`ExtraWindow::vault`, and for the window whose values are in the
//! fields, [`VaultSlots::current_id`]), and reads and writes that vault
//! here. Vault data never moves: a view is built with `&self`, so it
//! could not be swapped into the fields for the window being drawn the
//! way `enter_window` swaps a window's own values in `update`.
//!
//! [`VaultSlots::cur`] is the one way to read a vault and resolves "the
//! vault of the window acting now": during a view pass, the window being
//! drawn (`window_ctx::viewed_vault`); otherwise the window whose values
//! are in the fields (the resident one, or the window `update_in_window`
//! entered). [`VaultSlots::cur_mut`] is the `update`-only way to change
//! it. The fields are private, so no code can reach a vault around the
//! resolution and read another window's.

use std::collections::HashMap;

use uuid::Uuid;

use oryxis_core::models::{Connection, Group, Identity, SshKey};
use oryxis_vault::VaultStore;

/// One open vault: its store and what the app loaded from it.
pub(crate) struct OpenVault {
    /// The registry id (`oryxis_vault::device::VaultEntry::id`).
    pub(crate) id: Uuid,
    /// `None` when the file did not open (the open-failed screen).
    pub(crate) store: Option<VaultStore>,
    /// The file (`None` only when no home directory resolves): what the
    /// open-failed screen names and the rebuild works on.
    pub(crate) path: Option<std::path::PathBuf>,
    /// Made with "New vault" in this session, from a window on the vault
    /// named here: its setup screen is the master-password step alone,
    /// not the first-run carousel, and cancelling that step goes back
    /// there (the empty new vault goes away).
    pub(crate) created_from: Option<Uuid>,
    /// A `.oryxis` export to bring in once this vault, made for it
    /// ("Import as a new vault"), is set up: the import needs the vault's
    /// key, which its setup step makes.
    pub(crate) pending_import: Option<crate::state::PendingImport>,
    /// `load_data_from_vault` ran for it in this process (a vault opened
    /// unlocked by a window switching to it loads on the switch).
    pub(crate) loaded: bool,
    /// Instant of the last user input (keyboard / mouse / IME) in a
    /// window on this vault: the idle anchor of its own
    /// `auto_lock_minutes`. A vault no window shows idles. Not persisted.
    pub(crate) last_user_activity: std::time::Instant,
    /// Instant of the last free-space / size-cap check on this vault's
    /// recordings. The flush runs every 2 s (and on a 64 KiB burst),
    /// while a `statvfs` plus a `SUM(LENGTH(data))` are far too costly
    /// at that cadence, so the check is throttled to
    /// `SESSION_LOG_CAPACITY_INTERVAL`. Not persisted.
    pub(crate) last_session_log_capacity_check: std::time::Instant,
    /// Where this vault's recordings go while it is soft-locked
    /// (`session_spool`).
    pub(crate) spool: crate::session_spool::VaultSpool,
    // Data
    pub(crate) connections: Vec<Connection>,
    pub(crate) groups: Vec<Group>,
    /// Saved split-panel arrangements. Each references hosts by id and/or
    /// local shells; opening one rebuilds a single splitted tab.
    pub(crate) session_groups: Vec<oryxis_core::models::SessionGroup>,
    /// Loaded command history for `command_history_host`, most recent
    /// first (the History tab derives its "frequent" shortlist from this).
    pub(crate) command_history: Vec<oryxis_vault::CommandHistoryEntry>,
    /// Which saved host `command_history` was loaded for (`None` when the
    /// focused pane isn't a saved host).
    pub(crate) command_history_host: Option<Uuid>,
    // Keys
    pub(crate) keys: Vec<SshKey>,
    // Identities
    pub(crate) identities: Vec<Identity>,
    // Cached set of identity ids whose `password` column is non-NULL.
    // Hydrated by `load_data_from_vault`. The keychain view reads this
    // per card to decide whether to render the masked-bullets badge,
    // a per-frame `get_identity_password` decrypt would otherwise run
    // for every identity on every view() rebuild and slow the main
    // loop enough to fill iced's 100-slot subscription channel.
    pub(crate) identities_with_password: std::collections::HashSet<Uuid>,
    /// Cached set of connection ids whose `password` column holds a
    /// value, hydrated by `load_data_from_vault` like the identity set
    /// above. It answers `host_answers_credentials` for the listing's
    /// effective login (a group's identity default is gated on it), so
    /// the card can say per frame what the dial will do without a
    /// query per host. Every `save_connection` site that does not
    /// reload passes `None` for the password, which is what keeps the
    /// set true between loads.
    pub(crate) connections_with_password: std::collections::HashSet<Uuid>,
    // Proxy Identities, reusable proxy configs edited inline inside
    // the Settings → Proxies section. The saved list lives here; the
    // inline editor's transient state is grouped in `proxy_identity_form`
    // (in-memory only until SaveProxyIdentity flushes to the vault).
    pub(crate) proxy_identities: Vec<oryxis_core::models::proxy_identity::ProxyIdentity>,
    // Login scripts: reusable expect/send automations for hosts behind
    // an interactive bastion, referenced by `Connection.login_script_id`.
    // Created from the host editor (where the user is already looking at
    // the host that needs one) and managed in Settings → Connection.
    pub(crate) login_scripts: Vec<oryxis_core::models::LoginScript>,
    // Cloud Accounts, CloudProfile rows + the wizard form. Wizard is
    // intentionally minimal in v0.6 PR 3: provider + AWS profile auth
    // only. Access key + SSO + the discover-and-pick step land in
    // follow-up PRs once the foundation is exercised.
    pub(crate) cloud_profiles: Vec<oryxis_core::models::cloud_profile::CloudProfile>,
    // Snippets
    pub(crate) snippets: Vec<oryxis_core::models::snippet::Snippet>,
    /// User-defined terminal color schemes, shown in the theme pickers
    /// alongside the built-in presets and resolved by name.
    pub(crate) custom_terminal_themes:
        Vec<oryxis_core::models::custom_terminal_theme::CustomTerminalTheme>,
    /// User-defined chrome (UI) themes, shown in Interface alongside the
    /// built-in app themes and resolved by name.
    pub(crate) custom_ui_themes:
        Vec<oryxis_core::models::custom_ui_theme::CustomUiTheme>,
    // Port forwards (standalone entity, independent of any terminal)
    pub(crate) port_forward_rules:
        Vec<oryxis_core::models::port_forward_rule::PortForwardRule>,
    // Known hosts & logs
    pub(crate) known_hosts: Vec<oryxis_core::models::known_host::KnownHost>,
    pub(crate) logs: Vec<oryxis_core::models::log_entry::LogEntry>,
    pub(crate) logs_page: usize,
    pub(crate) logs_total: usize,
    // Session logs (terminal recording)
    pub(crate) session_logs: Vec<oryxis_vault::SessionLogEntry>,
    pub(crate) session_logs_page: usize,
    pub(crate) session_logs_total: usize,
    /// Recently visited Files-sidebar folders, keyed by saved-host id.
    ///
    /// The per-pane list is deliberately wiped on disconnect, because a
    /// reconnect can land on a different tree; keeping the history HERE,
    /// scoped to the host it belongs to, is what makes that wipe harmless
    /// and lets the list survive closing the tab (issue #114 / #85).
    /// Only `PaneOrigin::Host` panes qualify: a quick-connect id is
    /// in-memory and a local shell has no host to key on.
    pub(crate) files_recent_folders: std::collections::HashMap<uuid::Uuid, Vec<String>>,
    /// What the user configured in this vault (every preference that is
    /// not the device's, see `state::DevicePrefs`).
    pub(crate) prefs: crate::state::AppPrefs,
    /// Ad-hoc quick-connect hosts, keyed by connection id. Never touches
    /// the vault or `connections` (so no grid / sync / export leakage).
    /// Entries carry the credentials typed in the editor flow so a
    /// reconnect can reuse them; swept on vault lock, pruned when the
    /// last pane referencing an entry closes.
    pub(crate) quick_connects: std::collections::HashMap<Uuid, crate::state::QuickConnectEntry>,
    /// Tabs the user closed, newest last, capped: the stack
    /// `ReopenClosedTab` pops (issue #186). Terminal and SFTP tabs share
    /// it, so the chord always brings back the last chip that left the
    /// strip whichever kind it was. See [`crate::state::ClosedTab`] for
    /// why it holds a pin spec and why it is not persisted.
    pub(crate) closed_tabs: Vec<crate::state::ClosedTab>,
    /// Restored tabs still owed a dial under "connect at launch" (issue
    /// #229), in strip order. Drained ONE AT A TIME by
    /// `advance_launch_dials` from the update funnel, the next only once
    /// no dial is in flight anywhere, because the host-key, 2FA and
    /// command-proxy answers ride single staging slots that several
    /// first-time dials at once would overwrite. Seeded once per process
    /// next to the restore; a manual lock drops it with the strip.
    pub(crate) launch_dials: std::collections::VecDeque<uuid::Uuid>,
    /// Saved hosts still owed a dial by a batch connect from the host
    /// list (issue #230), in the order the dashboard showed them. Same
    /// shape and same reason as `launch_dials`: drained ONE AT A TIME by
    /// `advance_batch_dials` from the update funnel, because the
    /// host-key, 2FA and command-proxy answers ride single staging slots,
    /// and a batch of freshly imported hosts is exactly the batch of
    /// first-time dials that would mis-route them. Host ids, never list
    /// indices: every dial flushes the editor, which re-sorts the list.
    pub(crate) batch_dials: std::collections::VecDeque<uuid::Uuid>,
    /// The chip to land on after the restore, when the user asked to
    /// open on the tab that was active (issue #229). Resolved to a live
    /// strip entry at restore time and TAKEN by the boot / unlock site
    /// that lands, so a later unlock (a soft lock) finds nothing.
    pub(crate) launch_landing: Option<crate::state::TabRef>,
    /// The landing tab when its dial had to wait for the local terminal
    /// scan: the launch queue selects it once it dials it, because
    /// selecting a dormant tab earlier runs the foreground reopen, which
    /// would resolve the terminal against a list that does not exist yet.
    pub(crate) launch_landing_deferred: Option<uuid::Uuid>,
    /// History view: also search inside recorded session content
    /// (typed commands + output), the toggle chip inside the search
    /// field. Session-scoped UI state, not persisted.
    pub(crate) history_search_content: bool,
    /// Async results + scan progress for the content search above.
    pub(crate) history_content: crate::state::HistoryContentSearch,
    /// Live RDP/VNC-over-SSH tunnels, keyed by the host's connection id.
    /// A managed `-L` forward paired with its launch generation. The tunnel
    /// self-closes once the desktop client disconnects and it goes idle (see
    /// `spawn_autoclose_local_forward_task`); relaunching a host replaces its
    /// entry (dropping the old `ForwardSession` cancels it), and vault
    /// lock / app close clears the map. The generation lets a stale
    /// self-close from a superseded tunnel skip the current entry.
    pub(crate) remote_desktop_forwards: std::collections::HashMap<
        Uuid,
        (u64, std::sync::Arc<oryxis_ssh::ForwardSession>),
    >,
    /// Whether this vault's restore-on-launch pass has already run in
    /// this process (each vault restores its own strip the first time it
    /// is loaded). `load_data_from_vault` re-runs on connection save, sync
    /// and vault reload; pins survive that because they dedupe by pin
    /// identity, and ordinary tabs cannot (two tabs on one host are
    /// legitimate), so this is what stops a re-run from recreating tabs
    /// the user has closed since boot.
    pub(crate) open_tabs_restored: bool,
    /// Its chrome theme. Mirrors the process-wide theme while a window
    /// on this vault is the one `update` works on (`VaultSlots::switch_to`
    /// applies it, the update funnel reads it back); a window on it
    /// draws in it (`theme::with_selection`, `view_for_window`).
    pub(crate) ui_theme: crate::theme::ThemeSelection,
    /// Icon + color picker state (target routing, current selection,
    /// search). The open flag (`show_icon_picker`) and the HSV popover
    /// anchor (`icon_color_popover`) stay alongside it on `Oryxis`.
    pub(crate) icon_picker: crate::state::IconPickerState,
    pub(crate) chain_editor_adding: bool,
    pub(crate) chain_editor_search: String,
    // Armed when "Edit host" tears down a still-live connect (prompt
    // cancelled / dial abandoned): the provoked error arrives after the
    // progress card is gone and would otherwise land inside the editor
    // as `host_panel_error`. Consumed by the next `SshError` that finds
    // no progress card; a fresh connect clears the ambiguity because it
    // sets `connecting` again.
    pub(crate) pending_edit_cancel: bool,
    pub(crate) editor_form: crate::state::ConnectionForm,
    /// Multi-line buffer for the host's initial command. Kept out of the
    /// form struct because `text_editor::Content` isn't Clone.
    pub(crate) editor_initial_command: iced::widget::text_editor::Content,
    pub(crate) host_panel_error: Option<String>,
    pub(crate) editor_session_group: crate::state::SessionGroupForm,
    /// Multi-line buffer for the currently-shown pane's startup script. Kept
    /// out of the form struct because `text_editor::Content` isn't Clone.
    pub(crate) session_group_script_editor: iced::widget::text_editor::Content,
    pub(crate) session_group_panel_error: Option<String>,
    /// The hosts the open "Move to group" picker will move.
    pub(crate) move_hosts_pending: Vec<uuid::Uuid>,
    /// Folder rename inline editor, `Some((group_id, current_input))`
    /// while the modal is open.
    pub(crate) folder_rename: Option<(Uuid, String)>,
    /// Manual host-group editor side panel (label + icon + color). Open
    /// when `group_edit_visible`; `group_edit_id` is the group being
    /// edited. `group_edit_icon` / `group_edit_color` are empty strings
    /// when unset (no override → folder default glyph / accent).
    pub(crate) group_edit: crate::state::GroupEditForm,
    /// Folder delete confirmation, group ID waiting for the user to
    /// pick "move hosts to root" / "delete with hosts" / cancel.
    pub(crate) folder_delete: Option<Uuid>,
    /// SFTP browser state of the **active** SFTP tab. A working buffer:
    /// the focused SFTP tab's live state lives here, the others park their
    /// state in `SftpTab::state` (swap-on-focus). With no SFTP tab focused
    /// this still holds the last-focused tab's state until it is parked.
    /// Which card / row / chip the cursor is over, for the floating
    /// hover-revealed actions every list uses. Twenty fields until
    /// they moved here; see `state::hover`.
    /// See [`crate::state::ThemeEditorUi`].
    pub(crate) theme_ui: crate::state::ThemeEditorUi,
    /// See [`crate::state::VaultImportState`].
    pub(crate) vault_import: crate::state::VaultImportState,
    /// Everything the user can change and the vault persists in its
    /// `settings` table, in one place instead of 112 fields.
    ///
    /// Named `prefs`, not `settings`, because the `settings_*`
    /// fields that stay behind are the Settings SCREEN's own state
    /// (open section, scroll offset, search) and belong to the view,
    /// not to the user's configuration.
    /// See [`crate::state::PanelsOpen`].
    pub(crate) panels: crate::state::PanelsOpen,
    /// See [`crate::state::CloudDiscoverUi`].
    pub(crate) cloud_discover: crate::state::CloudDiscoverUi,
    /// See [`crate::state::SnippetForm`].
    pub(crate) snippet_form: crate::state::SnippetForm,
    /// See [`crate::state::KeysUi`].
    pub(crate) keys_ui: crate::state::KeysUi,
    /// Parsed certificate on display in the read-only cert viewer modal
    /// (B2). `Some` = modal open; keyed to `Modal::CertificateViewer`.
    pub(crate) cert_viewer: Option<crate::state::CertViewerData>,
    pub(crate) identity_form: crate::state::IdentityForm,
    pub(crate) identity_context_menu: Option<usize>,
    pub(crate) proxy_identity_form: crate::state::ProxyIdentityForm,
    pub(crate) login_script_form: crate::state::LoginScriptForm,
    /// Settings > Terminal: the inline editor for one highlight rule.
    /// The list itself is a preference (`prefs.highlight_rules`).
    pub(crate) highlight_rule_form: crate::state::HighlightRuleForm,
    /// Transient state for the add/edit cloud-account wizard (covers all
    /// provider + auth combinations).
    pub(crate) cloud_form: crate::state::CloudForm,
    /// Native combo_box state for the host editor's Initial Command /
    /// Snippet field. A forced-selection searchable combo: options are
    /// the None / Custom sentinels plus the snippet labels; the picked
    /// label commits through `EditorStartupChoiceChanged` (no free-text
    /// path). Rebuilt on editor-open via `rebuild_editor_combos`.
    pub(crate) editor_startup_combo: iced::widget::combo_box::State<String>,
    /// Login-automation picker: off / every saved script / new.
    pub(crate) editor_login_script_combo: iced::widget::combo_box::State<String>,
    /// Template picker inside the inline "new script" sub-form.
    pub(crate) editor_script_template_combo: iced::widget::combo_box::State<String>,
    /// Native combo_box state for the host editor's SSH Key field. Same
    /// forced-selection searchable pattern as the startup combo: options
    /// are the `(none)` sentinel plus the key labels; picking commits
    /// through `EditorKeyChanged`. Rebuilt on editor-open and cleared on
    /// focus (`EditorKeyComboOpened`) so search starts fresh.
    pub(crate) editor_key_combo: iced::widget::combo_box::State<String>,
    /// Shared search input for the group picker (used by both side
    /// panels' Parent Group fields). Reset on every open.
    pub(crate) group_picker_search: String,
    /// Host editor's startup-command source (None / a snippet / custom).
    pub(crate) editor_startup_choice: crate::state::StartupChoice,
    /// Modal that asks the user to pick the transport for the EC2
    /// hosts about to be imported. Only opened when there's at
    /// least one EC2 selected, pure-ECS imports skip straight to
    /// the import logic since dynamic groups always use ECS Exec.
    pub(crate) cloud_import_confirm_visible: bool,
    /// Edit-dynamic-group form. Opened from the ⋮ menu on a dynamic
    /// group card (root or nested). Edits the `cloud_query.template`
    /// fields: username, initial_command, transport, key, identity.
    pub(crate) cloud_dynamic_form: crate::state::CloudDynamicForm,
    pub(crate) ui_theme_import_content: iced::widget::text_editor::Content,
    pub(crate) ui_theme_import_name: String,
    pub(crate) ui_theme_import_error: Option<String>,
    /// Custom UI (chrome) theme editor modal + its color-picker popover and
    /// the hovered card (mirrors the terminal-theme editor).
    pub(crate) ui_theme_editor: Option<crate::state::UiThemeEditorForm>,
    pub(crate) port_forward_form: crate::state::PortForwardRuleForm,
    /// Index of the port-forward card whose kebab menu is open. Keeps the
    /// kebab mounted while the pointer travels to the menu.
    pub(crate) port_forward_context_menu: Option<usize>,
    /// Signature of the editor form as of the last persist (or the
    /// baseline recorded when the editor opened): what
    /// `editor_autosave_dirty` compares against. `None` = no baseline
    /// yet; the first post-open editor message records it.
    pub(crate) editor_saved_snapshot: Option<String>,
    /// Secret fields currently revealed via their eye toggle. Render
    /// state only, never persisted; cleared per-field on toggle.
    pub(crate) revealed_secrets: std::collections::HashSet<crate::state::SecretField>,
    pub(crate) export_password: String,
    pub(crate) export_include_keys: bool,
    /// Which entity families to write into the export, one checkbox per
    /// category in the dialog. Reset to `all()` each time the dialog opens.
    pub(crate) export_selection: oryxis_vault::ExportSelection,
    pub(crate) export_status: Option<Result<String, String>>,
    /// SFTP backup target picker. Shown when the user routes an
    /// export/import through a remote host instead of a local file.
    /// `is_import` flips the same picker between writing the encrypted
    /// blob (export) and reading it back (import); the export/import
    /// password + selection state above is reused as-is.
    pub(crate) sftp_backup: crate::state::SftpBackupForm,
    /// Latest result of an `~/.ssh/config` import, `Ok(message)` is
    /// rendered as a green banner, `Err` as red, in the Security
    /// section's import card.
    pub(crate) ssh_config_import_status: Option<Result<String, String>>,
    pub(crate) share: crate::state::ShareForm,
    /// Hosts parsed from a picked `~/.ssh/config`, awaiting the user's
    /// pick of which to import. Non-empty drives the preview modal.
    pub(crate) ssh_import_hosts: Vec<crate::ssh_config::SshConfigHost>,
    /// A third-party import (PuTTY, ...) waiting in the same preview
    /// dialog. Mutually exclusive with `ssh_import_hosts`; the shared
    /// `ssh_import_selected` / `ssh_import_existing` vecs serve both.
    pub(crate) ssh_import_direct: Option<crate::importers::DirectImport>,
    /// Inline error of the Import hub modal ("couldn't recognize this
    /// file"); cleared on open and on a successful detection.
    pub(crate) import_hub_error: Option<String>,
    /// The folder the dashboard had open when the Import hub was opened
    /// from it (issue #230): every host the hub's flows end up saving
    /// lands there, the way "Export hosts" from the same menu is
    /// pre-scoped to it. A SNAPSHOT rather than a live read of
    /// `active_group`, because the confirm can be several messages
    /// away (the mRemoteNG password round trip, the `.oryxis` redirect
    /// into Settings > Security) and `active_group` survives a trip
    /// into Settings, where an import started from the Security cards
    /// must never inherit it. `None` = the root. Cleared by every
    /// dismiss and every confirm, and by the Settings-originated import
    /// entries.
    pub(crate) import_target_group: Option<Uuid>,
    /// A protected mRemoteNG file held while the hub asks for its
    /// password. Swept with the hub (dismiss / open / success).
    pub(crate) import_hub_pending: Option<Vec<u8>>,
    /// The file password typed in the hub for `import_hub_pending`.
    pub(crate) import_hub_password: String,
    /// Per-host tick state, parallel to `ssh_import_hosts`.
    pub(crate) ssh_import_selected: Vec<bool>,
    /// Per-host "label already exists" flag, parallel to
    /// `ssh_import_hosts`; these are surfaced and default to unticked.
    pub(crate) ssh_import_existing: Vec<bool>,
    // MCP Server
    pub(crate) mcp: crate::state::McpState,
    // Sync (settings + runtime engine handles + pairing/SFTP forms)
    pub(crate) sync: crate::state::SyncState,
    /// Its lock state and the screens around opening it.
    pub(crate) vault_ui: crate::state::VaultUi,
    /// Master password retained in memory for the in-place relaunch
    /// (`relaunch_self`), which hands it to the replacement process.
    /// Populated after a successful unlock / setup, cleared if the user
    /// explicitly re-locks.
    pub(crate) master_password: Option<String>,
    /// See [`crate::state::ChatUi`].
    pub(crate) chat_ui: crate::state::ChatUi,
    // Per-list sort modes for the Hosts / Keychain / Snippets grids.
    // Persisted via the `hosts_sort` / `keys_sort` / `snippets_sort`
    // settings keys; loaded on boot and rewritten on each pick. The
    // active value drives both the trigger button's glyph and the
    // check mark in the dropdown.
    pub(crate) hosts_sort: crate::state::ListSort,
    pub(crate) keys_sort: crate::state::ListSort,
    pub(crate) snippets_sort: crate::state::ListSort,
    /// Resolved + compiled highlight rules per host, keyed by connection
    /// id and validated by a signature of its inputs (see
    /// `highlight_rules_for`), so the entry can never go stale.
    /// A `RefCell` because BOTH consumers need it and one of them is
    /// `view()`: the widget paints from the same resolved set the
    /// backend watches with, and a rule that coloured one pattern while
    /// firing on another would be the worst kind of bug here. Same
    /// pattern as the keynav recording.
    pub(crate) highlight_rules_cache: std::cell::RefCell<
        std::collections::HashMap<uuid::Uuid, (u64, std::sync::Arc<oryxis_terminal::CompiledRules>)>,
    >,
    /// Which install script (issue #147) already ran on which host,
    /// keyed (host id, snippet id) with the last run time. Mirror of
    /// the vault's `install_runs` table; drives the "installed here"
    /// hint on the snippet surfaces. Local bookkeeping, never synced.
    pub(crate) install_runs:
        std::collections::HashMap<(Uuid, Uuid), chrono::DateTime<chrono::Utc>>,
    /// Name of the active app theme (built-in or custom UI theme). The
    /// `AppTheme` enum can't name a custom theme, so this tracks the
    /// selection for highlighting + delete/rename bookkeeping.
    pub(crate) active_app_theme_name: String,
    /// Opt-in toggle (`remote_desktop_enabled` setting, off by default):
    /// when off, all remote-desktop UI (the "Add remote desktop" entry,
    /// the settings row) is hidden so it doesn't clutter the light-user
    /// interface. Existing RemoteDesktop hosts stay visible and usable.
    pub(crate) remote_desktop_enabled: bool,
    /// Theme derived from the active app theme, used as the global
    /// fallback when neither `terminal_theme_override` nor a per-host
    /// override is set.
    /// Cached resolved global terminal palette (built-in or custom).
    /// Applied to new tabs / local shells / cloud sessions; recomputed when
    /// the global theme or a custom theme changes.
    pub(crate) terminal_palette: oryxis_terminal::TerminalPalette,
    /// User pick that overrides the app-theme-derived terminal palette.
    /// `None` means "follow the app theme" (default). Stored as the
    /// theme's display name (e.g. "Dracula") so the value survives new
    /// theme additions without a migration.
    pub(crate) terminal_theme_override: Option<String>,
    pub(crate) terminal_font_size: f32,
    pub(crate) terminal_font_name: String,
    /// Weight every terminal cell is drawn at (issue #155). Global,
    /// like the family and the size next to it: a per-host weight
    /// over a global family would let a host ask for a weight the
    /// family it can't choose has no face for.
    pub(crate) terminal_font_weight: crate::fonts::TerminalFontWeight,
    /// Stroke widening applied to every terminal glyph. Global for the
    /// same reason the weight is: it compensates for the rasterizer,
    /// not for a host.
    pub(crate) terminal_text_thickness: crate::fonts::TextThickness,
    /// The shell-integration key this vault mints once and every pane then
    /// demands from `OSC 633 ; E` (see `shell_integration.rs`). Held in
    /// state only so Settings can show and copy the snippet; the value the
    /// capture actually compares against lives in the terminal crate,
    /// installed at boot.
    pub(crate) shell_integration_nonce: String,
    /// Privacy Mode (issue #78): global toggle, session override, hint
    /// flag, always/never mask lists, per-class gates and the Logs
    /// reveal toggle. See [`crate::state::PrivacyState`].
    pub(crate) privacy: crate::state::PrivacyState,
    /// Live width of the right-side editor drawer (host / key / identity /
    /// snippet / port-forward / cloud forms, all of them: they share one
    /// width, like they shared one constant). Defaults to `PANEL_WIDTH`,
    /// dragged via the drawer's edge handle, persisted as the
    /// `side_panel_width` setting on release.
    pub(crate) panel_width: f32,
    /// Toggles the SFTP feature entirely. Off hides the SFTP sidebar
    /// entry (both expanded and collapsed) so users who never transfer
    /// files don't have it taking up nav space. The SFTP settings panel
    /// still renders so the user can re-enable + tweak in one place,
    /// mirroring how `ai_enabled` works.
    pub(crate) sftp_enabled: bool,
    // AI Chat settings
    pub(crate) ai: crate::state::AiState,
    /// When on, the dashboard root shows two sections, Groups (manual
    /// folder cards) and Hosts (a flat list of every connection,
    /// including those that live inside a group). When off, root
    /// matches the legacy behaviour: groups at top, only ungrouped
    /// hosts beneath. Default: on. (Dashboard layout, not a sync field.)
    pub(crate) flatten_hosts: bool,
}

impl OpenVault {
    /// Its `auto_lock_minutes`, `None` while off (`"0"` or unparseable).
    pub(crate) fn auto_lock_after(&self) -> Option<std::time::Duration> {
        self.prefs
            .auto_lock_minutes
            .parse::<u64>()
            .ok()
            .filter(|m| *m > 0)
            .map(|m| std::time::Duration::from_secs(m * 60))
    }

    /// Whether the idle auto-lock could ever fire for it: unlocked, with a
    /// threshold, and a master password (without one, locking reopens at
    /// once; auto-locking would just churn).
    pub(crate) fn auto_lock_armed(&self) -> bool {
        self.vault_ui.state == crate::state::VaultState::Unlocked
            && self.vault_ui.has_user_password
            && self.auto_lock_after().is_some()
    }

    /// Armed, and idle past its threshold.
    pub(crate) fn auto_lock_due(&self) -> bool {
        self.auto_lock_due_at(std::time::Instant::now())
    }

    /// [`Self::auto_lock_due`] at `now`.
    pub(crate) fn auto_lock_due_at(&self, now: std::time::Instant) -> bool {
        self.auto_lock_armed()
            && self
                .auto_lock_after()
                .is_some_and(|after| now.saturating_duration_since(self.last_user_activity) >= after)
    }

    /// A vault just opened, nothing loaded from it yet (`load_data_from_vault`
    /// fills it after the unlock).
    pub(crate) fn new(id: Uuid, store: Option<VaultStore>) -> Self {
        Self {
            id,
            store,
            path: None,
            created_from: None,
            pending_import: None,
            loaded: false,
            last_user_activity: std::time::Instant::now(),
            last_session_log_capacity_check: std::time::Instant::now(),
            spool: crate::session_spool::VaultSpool::default(),
            connections: Vec::new(),
            connections_with_password: std::collections::HashSet::new(),
            groups: Vec::new(),
            session_groups: Vec::new(),
            keys: Vec::new(),
            identities: Vec::new(),
            identities_with_password: std::collections::HashSet::new(),
            proxy_identities: Vec::new(),
            login_scripts: Vec::new(),
            snippets: Vec::new(),
            cloud_profiles: Vec::new(),
            port_forward_rules: Vec::new(),
            known_hosts: Vec::new(),
            logs: Vec::new(),
            logs_page: 0,
            logs_total: 0,
            session_logs: Vec::new(),
            session_logs_page: 0,
            session_logs_total: 0,
            command_history: Vec::new(),
            command_history_host: None,
            custom_terminal_themes: Vec::new(),
            custom_ui_themes: Vec::new(),
            files_recent_folders: std::collections::HashMap::new(),
            prefs: crate::state::AppPrefs::default(),
            quick_connects: std::collections::HashMap::new(),
            closed_tabs: Vec::new(),
            launch_dials: std::collections::VecDeque::new(),
            launch_landing: None,
            launch_landing_deferred: None,
            batch_dials: std::collections::VecDeque::new(),
            remote_desktop_forwards: std::collections::HashMap::new(),
            history_content: crate::state::HistoryContentSearch::default(),
            history_search_content: false,
            open_tabs_restored: false,
            ui_theme: crate::theme::ThemeSelection::current(),
            editor_form: crate::state::ConnectionForm::default(),
            editor_initial_command: iced::widget::text_editor::Content::new(),
            host_panel_error: None,
            editor_session_group: crate::state::SessionGroupForm::default(),
            session_group_script_editor: iced::widget::text_editor::Content::new(),
            session_group_panel_error: None,
            group_edit: crate::state::GroupEditForm::default(),
            folder_delete: None,
            folder_rename: None,
            identity_form: crate::state::IdentityForm::default(),
            identity_context_menu: None,
            proxy_identity_form: crate::state::ProxyIdentityForm::default(),
            login_script_form: crate::state::LoginScriptForm::default(),
            highlight_rule_form: crate::state::HighlightRuleForm::default(),
            cloud_form: crate::state::CloudForm::default(),
            cloud_dynamic_form: crate::state::CloudDynamicForm::default(),
            cloud_import_confirm_visible: false,
            cloud_discover: crate::state::CloudDiscoverUi::default(),
            port_forward_form: crate::state::PortForwardRuleForm::default(),
            port_forward_context_menu: None,
            snippet_form: crate::state::SnippetForm::default(),
            keys_ui: crate::state::KeysUi::default(),
            theme_ui: crate::state::ThemeEditorUi::default(),
            ui_theme_editor: None,
            ui_theme_import_content: iced::widget::text_editor::Content::new(),
            ui_theme_import_name: String::new(),
            ui_theme_import_error: None,
            editor_startup_choice: crate::state::StartupChoice::None,
            editor_saved_snapshot: None,
            revealed_secrets: std::collections::HashSet::new(),
            move_hosts_pending: Vec::new(),
            cert_viewer: None,
            panels: crate::state::PanelsOpen::default(),
            editor_startup_combo: iced::widget::combo_box::State::new(Vec::new()),
            editor_login_script_combo: iced::widget::combo_box::State::new(Vec::new()),
            editor_script_template_combo: iced::widget::combo_box::State::new(Vec::new()),
            editor_key_combo: iced::widget::combo_box::State::new(Vec::new()),
            group_picker_search: String::new(),
            pending_edit_cancel: false,
            export_password: String::new(),
            export_include_keys: true,
            export_selection: oryxis_vault::ExportSelection::all(),
            export_status: None,
            share: crate::state::ShareForm::default(),
            sftp_backup: crate::state::SftpBackupForm::default(),
            ssh_config_import_status: None,
            ssh_import_hosts: Vec::new(),
            ssh_import_direct: None,
            import_hub_error: None,
            import_target_group: None,
            import_hub_pending: None,
            import_hub_password: String::new(),
            ssh_import_selected: Vec::new(),
            ssh_import_existing: Vec::new(),
            vault_import: crate::state::VaultImportState::default(),
            chain_editor_adding: false,
            chain_editor_search: String::new(),
            icon_picker: crate::state::IconPickerState::default(),
            sync: crate::state::SyncState::default(),
            mcp: crate::state::McpState::default(),
            vault_ui: crate::state::VaultUi::default(),
            master_password: None,
            privacy: crate::state::PrivacyState::default(),
            ai: crate::state::AiState::default(),
            chat_ui: crate::state::ChatUi::default(),
            terminal_theme_override: None,
            terminal_palette: oryxis_terminal::TerminalPalette::default(),
            terminal_font_size: 14.0,
            terminal_font_name: "SauceCodePro Nerd Font".to_string(),
            terminal_font_weight: crate::fonts::TerminalFontWeight::default(),
            terminal_text_thickness: crate::fonts::TextThickness::default(),
            hosts_sort: crate::state::ListSort::default(),
            keys_sort: crate::state::ListSort::default(),
            snippets_sort: crate::state::ListSort::default(),
            flatten_hosts: true,
            shell_integration_nonce: String::new(),
            sftp_enabled: true,
            remote_desktop_enabled: false,
            install_runs: std::collections::HashMap::new(),
            active_app_theme_name: "Oryxis Dark".to_string(),
            highlight_rules_cache: std::cell::RefCell::new(std::collections::HashMap::new()),
            panel_width: crate::app::PANEL_WIDTH,
        }
    }
}

/// Where a vault just opened stands: brand new (`NeedSetup`), locked
/// behind its master password (`Locked`), or open (`Unlocked`: no
/// password, or `inherited` was the right one), and whether it has a
/// master password at all.
///
/// The plaintext `has_user_password` flag is read before
/// `open_without_password`, which runs a full Argon2id KDF against the
/// empty password just to learn that the vault is locked (~17 ms on every
/// open of a password vault). Legacy vaults that predate the flag get it
/// backfilled here.
pub(crate) fn initial_lock_state(
    store: &mut VaultStore,
    inherited: Option<&str>,
) -> (crate::state::VaultState, bool) {
    use crate::state::VaultState;
    if !store.is_initialized() {
        // Stamp the Ctrl+digit slot migration as already done, so the
        // boot migration in `load_data_from_vault` leaves this vault on
        // the new mapping (slot N = tab N). Only vaults that predate the
        // change reach that migration unstamped and keep Home in the first
        // slot. This is the one place that can tell a fresh vault from an
        // existing one.
        let _ = store.set_setting("tab_slots_home_migrated", "true");
        return (VaultState::NeedSetup, false);
    }
    let unlock_inherited = |store: &mut VaultStore| {
        let unlocked = inherited.is_some_and(|pw| store.unlock(pw).is_ok());
        if unlocked { VaultState::Unlocked } else { VaultState::Locked }
    };
    let flag = store.get_setting("has_user_password").ok().flatten();
    if matches!(flag.as_deref(), Some("1")) {
        // Skip the empty-password KDF entirely; try the inherited password
        // (`--inherit-vault` stdin) before the lock screen.
        return (unlock_inherited(store), true);
    }
    // The flag says "0" or is missing (legacy vault): try the empty
    // unlock, and backfill the flag when it was missing.
    match store.open_without_password() {
        Ok(()) => {
            if flag.is_none() {
                let _ = store.set_setting("has_user_password", "0");
            }
            (VaultState::Unlocked, false)
        }
        Err(_) => {
            if flag.is_none() {
                let _ = store.set_setting("has_user_password", "1");
            }
            (unlock_inherited(store), true)
        }
    }
}

/// Every open vault, and the one the window acting now works on.
pub(crate) struct VaultSlots {
    open: HashMap<Uuid, OpenVault>,
    /// The vault the window whose values are in the fields works on:
    /// what its strip shows (`reconcile_tab_order`).
    window: Uuid,
    /// The vault the running code acts on: the window's, or another one
    /// for the length of a `ForVault` message or a pass over every vault
    /// (`act_on`).
    current: Uuid,
}

/// Where `VaultSlots` stood before a window's values came into the fields,
/// put back when they leave (`enter_window` / `exit_window`).
#[derive(Debug, Clone, Copy)]
pub(crate) struct SlotMark {
    window: Uuid,
    current: Uuid,
}

impl SlotMark {
    /// The vault of the window whose values were in the fields.
    pub(crate) fn window(self) -> Uuid {
        self.window
    }
}

impl VaultSlots {
    /// A process with one vault open (or the one it failed to open).
    pub(crate) fn single(vault: OpenVault) -> Self {
        let current = vault.id;
        Self { open: HashMap::from([(current, vault)]), window: current, current }
    }

    /// Every open vault, for the app-wide passes that visit each (the
    /// persisted strips, the agent's key list). Code about the acting
    /// window reads [`Self::cur`].
    pub(crate) fn all(&self) -> impl Iterator<Item = &OpenVault> {
        self.open.values()
    }

    /// The ids of every open vault.
    pub(crate) fn ids(&self) -> impl Iterator<Item = Uuid> + '_ {
        self.open.keys().copied()
    }

    /// Add a vault just opened beside the others (`open_vault`).
    pub(crate) fn insert(&mut self, vault: OpenVault) {
        self.open.insert(vault.id, vault);
    }

    /// Take vault `id` out of this process (its store closes with it).
    /// Never the vault the window in the fields or the running code is
    /// on: the caller moves away first.
    pub(crate) fn remove(&mut self, id: Uuid) -> Option<OpenVault> {
        if id == self.window || id == self.current {
            return None;
        }
        self.open.remove(&id)
    }

    /// Whether vault `id` is open in this process.
    pub(crate) fn is_open(&self, id: Uuid) -> bool {
        self.open.contains_key(&id)
    }

    /// The id of the vault the window in the fields works on: what a
    /// new window opened from it starts on.
    pub(crate) fn current_id(&self) -> Uuid {
        self.current
    }

    /// The id of the vault the window in the fields works on.
    pub(crate) fn window_id(&self) -> Uuid {
        self.window
    }

    /// Act on vault `id`: the outgoing vault keeps the process-wide theme
    /// it had, the incoming one's becomes it. Returns the outgoing one.
    fn set_acting(&mut self, id: Uuid) -> Uuid {
        self.cur_mut().ui_theme = crate::theme::ThemeSelection::current();
        let previous = std::mem::replace(&mut self.current, id);
        self.cur().ui_theme.apply();
        previous
    }

    /// Act on vault `id` for a while (a `ForVault` message, a pass over
    /// every vault), the window in the fields unchanged. Undo with
    /// [`Self::act_back`] and the returned id.
    pub(crate) fn act_on(&mut self, id: Uuid) -> Uuid {
        self.set_acting(id)
    }

    /// The end of [`Self::act_on`].
    pub(crate) fn act_back(&mut self, previous: Uuid) {
        self.set_acting(previous);
    }

    /// A window on vault `id` takes the fields (`enter_window`): it is
    /// what the strip shows and what the code acts on. Undo with
    /// [`Self::leave_window`] and the returned mark.
    pub(crate) fn enter_window(&mut self, id: Uuid) -> SlotMark {
        let mark = SlotMark { window: self.window, current: self.current };
        self.window = id;
        self.set_acting(id);
        mark
    }

    /// The end of [`Self::enter_window`]: answers the vault the leaving
    /// window works on (it may have switched meanwhile).
    pub(crate) fn leave_window(&mut self, mark: SlotMark) -> Uuid {
        let leaving = self.window;
        self.window = mark.window;
        self.set_acting(mark.current);
        leaving
    }

    /// The window in the fields now works on vault `id` (the switcher).
    pub(crate) fn switch_window_to(&mut self, id: Uuid) {
        self.window = id;
        self.set_acting(id);
    }

    /// The vault the acting window works on.
    pub(crate) fn cur(&self) -> &OpenVault {
        let id = crate::window_ctx::viewed_vault().unwrap_or(self.current);
        self.open
            .get(&id)
            .or_else(|| self.open.get(&self.current))
            .expect("the current vault is always open")
    }

    /// The vault the running `update` works on, to change it. Never
    /// called while a view is built (views get `&self`).
    pub(crate) fn cur_mut(&mut self) -> &mut OpenVault {
        self.open.get_mut(&self.current).expect("the current vault is always open")
    }

    /// The vault of the window in the fields, to change it, even while a
    /// `ForVault` message acts on another: what the user does in a
    /// window is that window's vault's (its auto-lock idle anchor).
    pub(crate) fn window_vault_mut(&mut self) -> &mut OpenVault {
        self.open.get_mut(&self.window).expect("the window's vault is always open")
    }
}

#[cfg(test)]
impl VaultSlots {
    pub(crate) fn insert_for_test(&mut self, vault: OpenVault) {
        self.insert(vault);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bare(id: Uuid) -> OpenVault {
        OpenVault::new(id, None)
    }

    #[test]
    fn the_window_in_the_fields_decides_the_vault() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let mut slots = VaultSlots::single(bare(a));
        slots.insert_for_test(bare(b));
        assert_eq!(slots.cur().id, a);
        // `enter_window` of a window on vault `b`.
        let mark = slots.enter_window(b);
        assert_eq!(mark.window(), a);
        assert_eq!(slots.cur().id, b);
        assert_eq!(slots.cur_mut().id, b);
        assert_eq!(slots.window_id(), b);
        // `exit_window`.
        assert_eq!(slots.leave_window(mark), b);
        assert_eq!(slots.cur().id, a);
        assert_eq!(slots.window_id(), a);
    }

    #[test]
    fn acting_on_another_vault_keeps_the_window_where_it_is() {
        let (a, b, c) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let mut slots = VaultSlots::single(bare(a));
        slots.insert_for_test(bare(b));
        slots.insert_for_test(bare(c));
        let previous = slots.act_on(b);
        assert_eq!((slots.current_id(), slots.window_id()), (b, a));
        // A window on `c` entered while acting on `b` gives both back.
        let mark = slots.enter_window(c);
        assert_eq!((slots.current_id(), slots.window_id()), (c, c));
        slots.leave_window(mark);
        assert_eq!((slots.current_id(), slots.window_id()), (b, a));
        slots.act_back(previous);
        assert_eq!((slots.current_id(), slots.window_id()), (a, a));
    }

    #[test]
    fn a_view_pass_reads_the_vault_of_the_window_it_draws() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let mut slots = VaultSlots::single(bare(a));
        slots.insert_for_test(bare(b));
        crate::window_ctx::with_viewed_vault_for_test(Some(b), || {
            assert_eq!(slots.cur().id, b, "an extra window on vault b draws vault b");
        });
        assert_eq!(slots.cur().id, a, "the pass ends, the fields' vault again");
    }

    #[test]
    fn a_window_naming_a_vault_that_is_not_open_falls_back_to_the_current() {
        let a = Uuid::new_v4();
        let slots = VaultSlots::single(bare(a));
        crate::window_ctx::with_viewed_vault_for_test(Some(Uuid::new_v4()), || {
            assert_eq!(slots.cur().id, a);
        });
    }

    /// An unlocked vault with a master password and a threshold, its
    /// last input now; `later(idle)` is the instant `idle` after it (a
    /// sum: an instant BEFORE now may not exist on a machine just booted).
    fn armed(minutes: &str) -> OpenVault {
        let mut v = bare(Uuid::new_v4());
        v.vault_ui.state = crate::state::VaultState::Unlocked;
        v.vault_ui.has_user_password = true;
        v.prefs.auto_lock_minutes = minutes.into();
        v
    }

    fn later(v: &OpenVault, idle: std::time::Duration) -> std::time::Instant {
        v.last_user_activity + idle
    }

    #[test]
    fn each_vault_locks_by_its_own_threshold_and_its_own_input() {
        let min = std::time::Duration::from_secs(60);
        // Idle past its own five minutes: due, whatever the others do.
        let quick = armed("5");
        assert!(quick.auto_lock_due_at(later(&quick, 6 * min)));
        // The same idle under a longer threshold of its own: not yet.
        let patient = armed("10");
        assert!(patient.auto_lock_armed());
        assert!(!patient.auto_lock_due_at(later(&patient, 6 * min)));
        // Fresh input in its windows: not due.
        assert!(!quick.auto_lock_due_at(later(&quick, std::time::Duration::ZERO)));
    }

    #[test]
    fn the_auto_lock_never_arms_where_a_lock_could_not_hold() {
        let long = std::time::Duration::from_secs(3600);
        // Off ("0") or a row that does not parse.
        assert!(!armed("0").auto_lock_armed());
        assert!(!armed("soon").auto_lock_armed());
        // No master password: locking would reopen at once.
        let mut open = armed("1");
        open.vault_ui.has_user_password = false;
        assert!(!open.auto_lock_due_at(later(&open, long)));
        // Already locked: nothing to do.
        let mut locked = armed("1");
        locked.vault_ui.state = crate::state::VaultState::Locked;
        assert!(!locked.auto_lock_due_at(later(&locked, long)));
    }

    #[test]
    fn input_counts_for_the_windows_vault_while_another_acts() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let mut slots = VaultSlots::single(bare(a));
        slots.insert_for_test(bare(b));
        let previous = slots.act_on(b);
        assert_eq!(slots.window_vault_mut().id, a);
        slots.act_back(previous);
    }

}
