//! The vault doors (`MultiVaultMessage`): the switcher chip and its menu,
//! a new vault, a window moving to another vault, locking every vault.
//!
//! A vault is opened in this process the first time a window asks for
//! it (`open_vault`), from the registry in `device.json`; from then on it
//! stays open (locked or not) beside the others in `VaultSlots`. Moving a
//! window to it parks what the window showed of the vault it leaves
//! (`switch_window_vault`).

use iced::Task;
use uuid::Uuid;

use crate::app::{Message, MultiVaultMessage, Oryxis, VaultMessage};
use crate::state::{OverlayContent, OverlayState, VaultDialog, VaultDialogMode, VaultState};
use crate::vault_slots::OpenVault;
use oryxis_vault::device::VaultEntry;
use oryxis_vault::VaultStore;

/// Where the switcher chip that was pressed sits: under the toolbar's
/// leading edge, or at the top of the nav rail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VaultChipPlace {
    Toolbar,
    Rail,
    /// The chevron of the tab bar's Home tab.
    Tabs,
}

/// Whether a settings row of one vault is copied into a vault being
/// created from it. What is copied is the user's PREFERENCES; never what
/// names an entity of the source vault (a default key, identity, folder
/// or proxy: the ids mean nothing in the new file), what one vault keeps
/// about its own state (its tabs, its sync, its bookkeeping), a secret
/// (sealed with the source's key, unreadable by the new one) or a
/// device key (shared already).
pub(crate) fn copies_to_new_vault(key: &str) -> bool {
    const VAULT_STATE: &[&str] = &[
        "has_user_password",
        "biometric_unlock_enabled",
        "open_tabs",
        "open_tabs_active",
        "pinned_tabs",
        "mcp_server_token",
        "mcp_config_vault_pw",
        // Exposing a vault to AI clients is that vault's own choice.
        "mcp_server_enabled",
        "mcp_server_allow_writes",
        "shell_integration_nonce",
        "default_key_id",
        "default_identity_id",
        "default_group_id",
        "default_proxy_identity_id",
        "files_recent_folders",
    ];
    !(oryxis_vault::device::is_device_key(key)
        || oryxis_vault::store::ENCRYPTED_SETTING_KEYS.contains(&key)
        || VAULT_STATE.contains(&key)
        || key.starts_with("sync_")
        || key.starts_with("hint_")
        || key.ends_with("_migrated")
        || key.ends_with("_applied")
        || key.ends_with("_seeded"))
}

impl Oryxis {
    pub(crate) fn handle_multi_vault(&mut self, message: MultiVaultMessage) -> Task<Message> {
        let task = self.handle_multi_vault_inner(message);
        // Every door here may change the list or what is on disk.
        self.refresh_vault_presence();
        task
    }

    fn handle_multi_vault_inner(&mut self, message: MultiVaultMessage) -> Task<Message> {
        match message {
            MultiVaultMessage::ShowVaultSwitcher(place) => {
                // Under the chip's real rectangle (last drawn), never a
                // constant: the chip moves with the rail and the toolbar.
                let b = match place {
                    VaultChipPlace::Toolbar => self.vault_chip_bounds.get(),
                    VaultChipPlace::Rail => self.vault_badge_bounds.get(),
                    VaultChipPlace::Tabs => self.vault_tab_bounds.get(),
                };
                // Under the control, flush with its leading edge (the
                // whole Home pill in the strip, not its chevron); a strip
                // docked at the bottom is kept inside the window by the
                // overlay's own clamp. A door never drawn (the keyboard
                // opening a hidden switcher) hangs it under the tab bar's
                // leading edge.
                let (x, y) = if b.width > 0.0 {
                    (crate::widgets::leading_edge_x(b), b.y + b.height + 4.0)
                } else if crate::i18n::is_rtl_layout() {
                    (self.cur_window_size().width - 8.0, 44.0)
                } else {
                    (8.0, 44.0)
                };
                self.overlay = Some(OverlayState {
                    content: OverlayContent::VaultSwitcher,
                    x,
                    y,
                });
            }
            MultiVaultMessage::SwitchToVault(id) => {
                self.overlay = None;
                return self.switch_this_window_to_vault(id);
            }
            MultiVaultMessage::OpenVaultInNewWindow(id) => {
                self.overlay = None;
                if !self.ensure_vault_open(id) {
                    return self.show_toast(crate::i18n::t("vault_status_missing").to_string());
                }
                return self.open_window_on_vault(id);
            }
            MultiVaultMessage::ShowNewVault => {
                self.overlay = None;
                self.vault_dialog = Some(VaultDialog::create());
                return crate::widgets::focus_input(iced::widget::Id::new(VAULT_DIALOG_NAME_INPUT));
            }
            MultiVaultMessage::ShowVaultSettings => {
                self.overlay = None;
                return self.update(Message::Tabs(crate::app::TabsMessage::OpenSettingsSection(
                    crate::state::SettingsSection::Vaults,
                )));
            }
            MultiVaultMessage::ShowRenameVault(id) => {
                self.vault_dialog = Some(VaultDialog::rename(id, self.vault_name(id)));
                return crate::widgets::focus_input(iced::widget::Id::new(VAULT_DIALOG_NAME_INPUT));
            }
            MultiVaultMessage::ShowDeleteVault(id) => {
                // The last vault cannot go (a device always has one), and
                // only an unlocked vault can: its unlock is the proof.
                if self.vault_count() <= 1 || !self.vault_deletable(id) {
                    return Task::none();
                }
                self.vault_dialog = Some(VaultDialog::delete(id));
                return crate::widgets::focus_input(iced::widget::Id::new(VAULT_DIALOG_NAME_INPUT));
            }
            MultiVaultMessage::VaultDialogNameChanged(name) => {
                if let Some(form) = self.vault_dialog.as_mut() {
                    form.name = name;
                    form.error = None;
                }
            }
            MultiVaultMessage::NewVaultCopyFromChanged(source) => {
                if let Some(form) = self.vault_dialog.as_mut() {
                    form.copy_from = source;
                }
            }
            MultiVaultMessage::VaultDialogSubmit => {
                let Some(mode) = self.vault_dialog.as_ref().map(|d| d.mode) else {
                    return Task::none();
                };
                return match mode {
                    VaultDialogMode::Create => self.create_vault(),
                    VaultDialogMode::Rename(id) => self.rename_vault(id),
                    VaultDialogMode::Delete(id) => self.delete_vault(id),
                };
            }
            MultiVaultMessage::CancelVaultSetup => return self.cancel_vault_setup(),
            MultiVaultMessage::CancelVaultDialog => self.vault_dialog = None,
            MultiVaultMessage::RemoveVaultFromList(id) => {
                self.error_dialog = Some(crate::state::ErrorDialog {
                    title: crate::i18n::t("vault_remove_title").replacen("{name}", &self.vault_name(id), 1),
                    body: crate::i18n::t("vault_remove_body").to_string(),
                    link: None,
                    action: Some(crate::state::ErrorDialogAction {
                        label: crate::i18n::t("vault_remove_from_list").to_string(),
                        message: Box::new(Message::MultiVault(MultiVaultMessage::RemoveVaultFromListConfirmed(id))),
                        danger: true,
                    }),
                });
            }
            MultiVaultMessage::RemoveVaultFromListConfirmed(id) => {
                return self.forget_vault(id, false).unwrap_or_else(|e| self.show_toast(e));
            }
            MultiVaultMessage::OpenExistingVault => {
                return Task::perform(
                    async {
                        rfd::AsyncFileDialog::new()
                            .add_filter(crate::i18n::t("vault_file_filter"), &["db"])
                            .pick_file()
                            .await
                            .map(|h| h.path().to_path_buf())
                    },
                    |picked| Message::MultiVault(MultiVaultMessage::ExistingVaultPicked(picked)),
                );
            }
            // A cancelled dialog is silent.
            MultiVaultMessage::ExistingVaultPicked(None) => {}
            MultiVaultMessage::ExistingVaultPicked(Some(path)) => return self.open_existing_vault(path),
            MultiVaultMessage::LockVaultById(id) => {
                if self.vaults.is_open(id) {
                    return Task::done(Message::ForVault(id, Box::new(Message::Vault(VaultMessage::LockVault))));
                }
            }
            MultiVaultMessage::VaultHotkeyCaptureStart(id) => self.editing_vault_hotkey = Some(id),
            MultiVaultMessage::VaultHotkeyClear(id) => {
                self.editing_vault_hotkey = None;
                return self.set_vault_hotkey(id, None);
            }
            MultiVaultMessage::VaultStartPickerToggled(on) => {
                self.device_prefs.vault_start_picker = on;
                self.persist_setting("vault_start_picker", if on { "true" } else { "false" });
            }
            MultiVaultMessage::PickStartVault(id) => return self.pick_start_vault(id),
            MultiVaultMessage::VaultSwitcherPlaceChanged(place) => {
                self.device_prefs.vault_switcher_place = place;
                self.persist_setting("vault_switcher_place", place.code());
            }
            MultiVaultMessage::VaultSwitcherHideSingleToggled(hide) => {
                self.device_prefs.vault_switcher_hide_single = hide;
                self.persist_setting("vault_switcher_hide_single", if hide { "true" } else { "false" });
            }
            MultiVaultMessage::LockAllVaults => {
                self.overlay = None;
                // Locking ends every session of every vault it locks:
                // asked first, like the single lock.
                self.error_dialog = Some(crate::state::ErrorDialog {
                    title: crate::i18n::t("vault_lock_all_title").to_string(),
                    body: crate::i18n::t("vault_lock_all_body").to_string(),
                    link: None,
                    action: Some(crate::state::ErrorDialogAction {
                        label: crate::i18n::t("vault_lock_all").to_string(),
                        message: Box::new(Message::MultiVault(MultiVaultMessage::LockAllVaultsConfirmed)),
                        danger: true,
                    }),
                });
            }
            MultiVaultMessage::LockAllVaultsConfirmed => {
                let lockable: Vec<Uuid> = self
                    .vaults
                    .all()
                    .filter(|v| v.vault_ui.has_user_password && v.vault_ui.state == VaultState::Unlocked)
                    .map(|v| v.id)
                    .collect();
                return Task::batch(lockable.into_iter().map(|id| {
                    Task::done(Message::ForVault(id, Box::new(Message::Vault(VaultMessage::LockVault))))
                }));
            }
        }
        Task::none()
    }

    /// The vaults this device knows, in registry order (`device.json`).
    pub(crate) fn registered_vaults(&self) -> Vec<VaultEntry> {
        oryxis_vault::device::installed()
            .map(|d| d.vaults())
            .unwrap_or_else(|| vec![VaultEntry::first()])
    }

    /// What a vault is called on screen: its label, else the default
    /// name of an install's first vault.
    pub(crate) fn vault_display_name(entry: &VaultEntry) -> String {
        entry
            .label
            .clone()
            .unwrap_or_else(|| crate::i18n::t("vault_default_name").to_string())
    }

    /// The name of vault `id` as the registry has it.
    pub(crate) fn vault_name(&self, id: Uuid) -> String {
        self.registered_vaults()
            .iter()
            .find(|v| v.id == id)
            .map(Self::vault_display_name)
            .unwrap_or_else(|| crate::i18n::t("vault_default_name").to_string())
    }

    /// Make sure vault `id` is open in this process, opening its file
    /// from the registry when it is not. `false` when the registry does
    /// not know it.
    ///
    /// A vault whose file is gone (a USB key pulled) is UNAVAILABLE and
    /// is not opened: the open would make an empty vault in its place.
    /// It comes back by itself once the file is there again.
    pub(crate) fn ensure_vault_open(&mut self, id: Uuid) -> bool {
        if self.vaults.is_open(id) {
            return true;
        }
        let Some(entry) = self.registered_vaults().into_iter().find(|v| v.id == id) else {
            return false;
        };
        if self.vault_file(id).is_none() {
            return false;
        }
        self.open_vault(&entry);
        true
    }

    /// Whether vault `id` can be shown: open in this process, or its file
    /// was there when last checked (`refresh_vault_presence`).
    pub(crate) fn vault_available(&self, id: Uuid) -> bool {
        self.vaults.is_open(id) || self.vault_presence.get(&id).copied().unwrap_or(false)
    }

    /// Check which registered vault files are there, for the views (see
    /// `vault_presence`), and take each vault's chord from the registry
    /// (`vault_chords`).
    pub(crate) fn refresh_vault_presence(&mut self) {
        let entries = self.registered_vaults();
        self.vault_presence = entries.iter().map(|entry| (entry.id, self.vault_file(entry.id).is_some())).collect();
        self.vault_chords = entries
            .iter()
            .filter_map(|entry| {
                let chord = entry.hotkey.as_deref().and_then(crate::hotkeys::HotkeyBinding::parse)?;
                Some((entry.id, chord))
            })
            .collect();
    }

    /// Whether a start shows the vault picker: asked for in Settings >
    /// Vaults, several vaults registered, and nothing on the command line
    /// or in a deep link already saying where to go. Read before any
    /// vault's data loads, straight from the device store.
    pub(crate) fn start_picker_wanted(&self) -> bool {
        let asked = oryxis_vault::device::installed()
            .and_then(|d| d.get("vault_start_picker"))
            .is_some_and(|v| v == "true");
        asked
            && self.vault_count() > 1
            && self.pending_auto_connect.is_none()
            && self.pending_deep_link.is_none()
            && self.pending_connect_target.is_none()
    }

    /// Whether the window being handled shows the start picker: the
    /// resident one, while no vault was picked yet (it is the only window
    /// a start opens).
    pub(crate) fn start_picker_here(&self) -> bool {
        self.start_picker && self.cur_window().is_none()
    }

    /// The start picker's answer. The vault the start opened in the
    /// background (unloaded: its data, sync and forwards waited for this
    /// pick) is that vault's first showing; any other vault takes the
    /// window, and the unused one closes.
    fn pick_start_vault(&mut self, id: Uuid) -> Task<Message> {
        if !self.start_picker {
            return Task::none();
        }
        let boot = self.vaults.window_id();
        if id == boot {
            self.start_picker = false;
            if let Some(device) = oryxis_vault::device::installed()
                && let Err(e) = device.set_last_vault(id)
            {
                tracing::warn!("could not remember the last vault: {e}");
            }
            return self.vault_shown();
        }
        if !self.ensure_vault_open(id) {
            return self.show_toast(crate::i18n::t("vault_status_missing").to_string());
        }
        self.start_picker = false;
        let task = self.switch_this_window_to_vault(id);
        // Never shown, nothing of it loaded: closing it drops its key
        // (a vault without a password was unlocked to read its theme).
        if !self.vaults.all().any(|v| v.id == boot && v.loaded) {
            self.drop_parked_views_of(boot);
            drop(self.vaults.remove(boot));
        }
        task
    }

    /// The window taking the focus is the one in use: its vault is the
    /// one the next start opens (`set_last_vault` writes only a change).
    pub(crate) fn remember_window_vault(&self) {
        if let Some(device) = oryxis_vault::device::installed()
            && let Err(e) = device.set_last_vault(self.vaults.window_id())
        {
            tracing::warn!("could not remember the last vault: {e}");
        }
    }

    /// The vault whose chord this keypress is, if any.
    pub(crate) fn vault_chord_hit(
        &self,
        key: &iced::keyboard::Key,
        modifiers: &iced::keyboard::Modifiers,
    ) -> Option<Uuid> {
        self.vault_chords
            .iter()
            .find(|(_, chord)| chord.match_event(key, modifiers).is_some())
            .map(|(id, _)| *id)
    }

    /// The vault holding `chord` (by keypress), other than `except`.
    pub(crate) fn vault_holding_chord(
        &self,
        chord: &crate::hotkeys::HotkeyBinding,
        except: Option<Uuid>,
    ) -> Option<Uuid> {
        self.vault_chords
            .iter()
            .find(|(id, held)| Some(*id) != except && held.shares_keypress(chord))
            .map(|(id, _)| *id)
    }

    /// Write vault `id`'s chord to the registry (the cache follows on the
    /// way out of `handle_multi_vault`, or here for the key path).
    pub(crate) fn set_vault_hotkey(
        &mut self,
        id: Uuid,
        chord: Option<crate::hotkeys::HotkeyBinding>,
    ) -> Task<Message> {
        let text = chord.map(|c| c.serialize());
        if let Some(device) = oryxis_vault::device::installed()
            && let Err(e) = device.set_hotkey(id, text.as_deref())
        {
            return self.show_toast(e.to_string());
        }
        self.refresh_vault_presence();
        Task::none()
    }

    /// The keyboard's way to the switcher (the "Open vault switcher"
    /// action): the menu opens under whichever door this window draws,
    /// and under the tab bar's leading edge when none is drawn (the
    /// switcher hidden with a single vault).
    pub(crate) fn open_vault_switcher_from_keyboard(&mut self) -> Task<Message> {
        let drawn = |cell: &crate::widgets::BoundsCell| cell.get().width > 0.0;
        let place = if self.vault_switcher_in_tabs() {
            VaultChipPlace::Tabs
        } else if drawn(&self.vault_badge_bounds) && !drawn(&self.vault_chip_bounds) {
            VaultChipPlace::Rail
        } else {
            VaultChipPlace::Toolbar
        };
        self.handle_multi_vault(MultiVaultMessage::ShowVaultSwitcher(place))
    }

    /// "Next vault" / "Previous vault": the window moves `step` places
    /// along the registry's order, wrapping, over the vaults that can be
    /// shown (an unavailable one is passed over).
    pub(crate) fn switch_to_adjacent_vault(&mut self, step: isize) -> Task<Message> {
        self.refresh_vault_presence();
        let here = self.vaults.window_id();
        let ring: Vec<Uuid> = self
            .registered_vaults()
            .into_iter()
            .map(|e| e.id)
            .filter(|id| *id == here || self.vault_available(*id))
            .collect();
        let Some(at) = ring.iter().position(|id| *id == here) else {
            return Task::none();
        };
        let next = ring[(at as isize + step).rem_euclid(ring.len() as isize) as usize];
        if next == here {
            return Task::none();
        }
        self.switch_this_window_to_vault(next)
    }

    /// Open `entry`'s file beside the vaults already open: where it
    /// stands (new, locked, open) decided the way the start decides it
    /// for the first one. A file that does not open is still added, on
    /// its open-failed screen (the reason, and the rebuild when it is
    /// damaged), like a start whose vault does not open.
    fn open_vault(&mut self, entry: &VaultEntry) {
        let path = oryxis_vault::device::installed().map(|d| d.resolve(entry));
        // Only the app's own folder is made; a vault registered elsewhere
        // (a USB key) is opened where it is, never a folder made for it.
        if entry.path.is_relative()
            && let Some(parent) = path.as_ref().and_then(|p| p.parent())
        {
            let _ = std::fs::create_dir_all(parent);
        }
        let opened = match path.as_ref() {
            Some(p) => VaultStore::open(p),
            None => Err(oryxis_vault::VaultError::Io(std::io::Error::other("No home directory"))),
        };
        let mut vault = match opened {
            Ok(store) => OpenVault::new(entry.id, Some(store)),
            Err(e) => {
                tracing::error!(vault = %entry.id, "vault open failed: {e}");
                let source = match &e {
                    oryxis_vault::VaultError::Open { source, .. } => Some(&**source),
                    _ => None,
                };
                let mut vault = OpenVault::new(entry.id, None);
                vault.vault_ui.open_error = Some(e.to_string());
                vault.vault_ui.open_read_only =
                    matches!(source, Some(oryxis_vault::VaultError::ReadOnly));
                vault.vault_ui.open_corrupt =
                    matches!(source, Some(oryxis_vault::VaultError::Corrupt(_)));
                vault
            }
        };
        vault.path = path;
        vault.vault_ui.setup_enable_biometric = self.biometric_available;
        if let Some(store) = vault.store.as_mut() {
            let (state, has_password) = crate::vault_slots::initial_lock_state(store, None);
            vault.vault_ui.state = state;
            vault.vault_ui.has_user_password = has_password;
            // Read before the unlock, like the first vault's at start:
            // the lock screen offers biometrics and wears the vault's
            // theme (a custom one resolves once its themes are loaded).
            vault.prefs.biometric_unlock_enabled = matches!(
                store.get_setting("biometric_unlock_enabled").ok().flatten().as_deref(),
                Some("true")
            );
            vault.ui_theme = crate::theme::ThemeSelection::named(
                store.get_setting("app_theme").ok().flatten().as_deref(),
            );
        }
        self.vaults.insert(vault);
    }

    /// The window in the fields works on vault `id` from now on, and the
    /// next start opens it.
    pub(crate) fn switch_this_window_to_vault(&mut self, id: Uuid) -> Task<Message> {
        if !self.ensure_vault_open(id) {
            return self.show_toast(crate::i18n::t("vault_status_missing").to_string());
        }
        self.switch_window_vault(id);
        if let Some(device) = oryxis_vault::device::installed()
            && let Err(e) = device.set_last_vault(id)
        {
            tracing::warn!("could not remember the last vault: {e}");
        }
        self.vault_shown()
    }

    /// A vault a window just started showing: one already open whose data
    /// this process never loaded loads now; a locked one's unlock field
    /// takes the focus.
    fn vault_shown(&mut self) -> Task<Message> {
        match self.vaults.cur().vault_ui.state {
            // Opened without a password and never shown: everything an
            // unlock gives (data, sync, auto-start forwards, plugins).
            VaultState::Unlocked if !self.vaults.cur().loaded => self.finish_vault_open(),
            VaultState::Locked => crate::widgets::focus_input(iced::widget::Id::new(
                "vault-unlock-password",
            )),
            _ => Task::none(),
        }
    }

    /// Open saved host `id` from a door that belongs to the app, not to
    /// a window (the tray's recent hosts): on the open vault that holds
    /// it, in a window on that vault (the one the user works in first),
    /// or a new window on it when none shows it. A vault that is locked
    /// keeps the dial for its unlock, behind its lock screen.
    pub(crate) fn open_host_anywhere(&mut self, id: Uuid) -> Task<Message> {
        let Some(owner) = self
            .vaults
            .all()
            .find(|v| v.connections.iter().any(|c| c.id == id))
            .map(|v| v.id)
        else {
            return Task::none();
        };
        let (window, open) = if self.vault_of_window(self.input_window()) == owner {
            (self.input_window(), Task::none())
        } else if let Some(window) = self.window_on_vault(owner) {
            (window, Task::none())
        } else {
            let (window, open) = self.open_window_for_vault(owner);
            let shown = self.run_in_window(Some(window), Self::vault_shown);
            (Some(window), Task::batch([open, shown]))
        };
        let dial = self.run_in_window(window, move |app| {
            if app.vaults.cur().vault_ui.state == VaultState::Unlocked {
                app.update(Message::Ssh(crate::app::SshMessage::ConnectSavedHost(id)))
            } else {
                app.pending_auto_connect = Some(id);
                Task::none()
            }
        });
        Task::batch([open, dial])
    }

    /// A new window working on vault `id`, on its hosts screen (or its
    /// lock screen).
    fn open_window_on_vault(&mut self, id: Uuid) -> Task<Message> {
        let (window, open) = self.open_window_for_vault(id);
        let shown = self.run_in_window(Some(window), Self::vault_shown);
        Task::batch([open, shown])
    }

    /// Create the vault the dialog describes: registered, its file made
    /// (with the chosen vault's preferences copied in, once), and this
    /// window moved to it, where its setup screen asks for the master
    /// password (or none).
    fn create_vault(&mut self) -> Task<Message> {
        let Some(form) = self.vault_dialog.as_ref() else {
            return Task::none();
        };
        let name = form.name.trim().to_string();
        let copy_from = form.copy_from;
        if name.is_empty() {
            if let Some(form) = self.vault_dialog.as_mut() {
                form.error = Some(crate::i18n::t("vault_name_required").to_string());
            }
            return Task::none();
        }
        match self.make_vault(&name, copy_from) {
            Ok(id) => {
                self.vault_dialog = None;
                self.enter_new_vault(id)
            }
            Err(e) => {
                if let Some(form) = self.vault_dialog.as_mut() {
                    form.error = Some(e);
                }
                Task::none()
            }
        }
    }

    /// Make a vault called `name`: registered, its file made, and
    /// `copy_from`'s preferences copied in once. Answers its id, or the
    /// text of what failed (a vault whose file could not be made leaves
    /// the registry again).
    pub(crate) fn make_vault(&self, name: &str, copy_from: Option<Uuid>) -> Result<Uuid, String> {
        let failed = |e: String| crate::i18n::t("vault_create_failed").replacen("{error}", &e, 1);
        let device = oryxis_vault::device::installed().ok_or_else(|| failed("no device store".into()))?;
        let entry = device.create_entry(name).map_err(|e| failed(e.to_string()))?;
        let path = device.resolve(&entry);
        let created = path
            .parent()
            .map_or(Ok(()), std::fs::create_dir_all)
            .map_err(oryxis_vault::VaultError::Io)
            .and_then(|()| VaultStore::open(&path));
        let store = match created {
            Ok(store) => store,
            Err(e) => {
                // Nothing usable was made: the registry forgets it.
                let _ = device.unregister(entry.id);
                return Err(failed(e.to_string()));
            }
        };
        if let Some(source) = copy_from {
            self.copy_settings_into(source, &store);
        }
        Ok(entry.id)
    }

    /// Move this window to vault `id` just made, on its setup step alone
    /// (Cancel there goes back and removes the empty vault).
    pub(crate) fn enter_new_vault(&mut self, id: Uuid) -> Task<Message> {
        let from = self.vaults.window_id();
        let task = self.switch_this_window_to_vault(id);
        self.vaults.cur_mut().created_from = Some(from);
        task
    }

    /// Rename vault `id` to the dialog's name (blank goes back to the
    /// default name of an install's first vault).
    fn rename_vault(&mut self, id: Uuid) -> Task<Message> {
        let Some(name) = self.vault_dialog.as_ref().map(|d| d.name.trim().to_string()) else {
            return Task::none();
        };
        if name.is_empty() && id != oryxis_vault::device::FIRST_VAULT_ID {
            if let Some(form) = self.vault_dialog.as_mut() {
                form.error = Some(crate::i18n::t("vault_name_required").to_string());
            }
            return Task::none();
        }
        if let Some(device) = oryxis_vault::device::installed()
            && let Err(e) = device.rename(id, &name)
        {
            if let Some(form) = self.vault_dialog.as_mut() {
                form.error = Some(e.to_string());
            }
            return Task::none();
        }
        // The agent names a key's vault when several serve.
        if let Some(runtime) = &self.agent.runtime {
            runtime.relabel(id, self.vault_name(id));
        }
        self.vault_dialog = None;
        Task::none()
    }

    /// Delete vault `id` for good, once the dialog proved it: the name
    /// typed back exactly, the vault open and unlocked. Never the last
    /// vault.
    fn delete_vault(&mut self, id: Uuid) -> Task<Message> {
        let Some(typed) = self.vault_dialog.as_ref().map(|d| d.name.trim().to_string()) else {
            return Task::none();
        };
        let refuse = |s: &mut Self, error: String| {
            if let Some(form) = s.vault_dialog.as_mut() {
                form.error = Some(error);
            }
            Task::none()
        };
        if typed != self.vault_name(id) {
            return refuse(self, crate::i18n::t("vault_delete_name_mismatch").to_string());
        }
        if !self.vault_deletable(id) {
            return refuse(self, crate::i18n::t("vault_delete_unlock_first").to_string());
        }
        match self.forget_vault(id, true) {
            Ok(task) => {
                self.vault_dialog = None;
                task
            }
            Err(e) => refuse(self, e),
        }
    }

    /// Whether vault `id` may be deleted from here: another vault is
    /// there to take its windows, and it is open and unlocked (a vault
    /// without a master password counts as unlocked once open). Its
    /// unlock is the proof of ownership: the dialog asks only for the
    /// name.
    pub(crate) fn vault_deletable(&self, id: Uuid) -> bool {
        self.registered_vaults().iter().any(|v| v.id != id && self.vault_available(v.id))
            && self.vault_available(id)
            && self.vaults.all().any(|v| v.id == id && v.vault_ui.state == VaultState::Unlocked)
    }

    /// The file of registered vault `id`, when it is there (opening a
    /// missing one would create an empty vault in its place).
    pub(crate) fn vault_file(&self, id: Uuid) -> Option<std::path::PathBuf> {
        let entry = self.registered_vaults().into_iter().find(|v| v.id == id)?;
        oryxis_vault::device::installed().map(|d| d.resolve(&entry)).filter(|p| p.is_file())
    }

    /// The vault that takes over the windows of vault `id` while it goes:
    /// the one this code is on, else another open one, else the first in
    /// the list that opens.
    fn heir_of(&mut self, id: Uuid) -> Option<Uuid> {
        let current = self.vaults.current_id();
        if current != id {
            return Some(current);
        }
        if let Some(open) = self.vaults.ids().find(|v| *v != id) {
            return Some(open);
        }
        let candidates: Vec<Uuid> = self.registered_vaults().into_iter().map(|v| v.id).filter(|v| *v != id).collect();
        candidates.into_iter().find(|v| self.ensure_vault_open(*v))
    }

    /// Take vault `id` off this device: every window on it moves to
    /// another vault, its sessions end, it closes, and the registry
    /// forgets it. With `delete`, its file and everything beside it go
    /// too (the WAL and shared-memory files, the rebuild lock, damaged
    /// copies, the biometric entry); without, the file stays where it is
    /// ("Remove from list": a vault on a USB key, or one that is gone).
    ///
    /// Nothing is touched on disk unless the vault really closed: a
    /// window still on it (its heir would not open) refuses the whole
    /// operation, with the reason as the error.
    fn forget_vault(&mut self, id: Uuid, delete: bool) -> Result<Task<Message>, String> {
        if self.vault_count() <= 1 {
            return Err(crate::i18n::t("vault_last_stays").to_string());
        }
        let Some(heir) = self.heir_of(id) else {
            return Err(crate::i18n::t("vault_no_heir").to_string());
        };
        let mut tasks = Vec::new();
        // Every window on it moves to the heir first (the vault in the
        // fields cannot close under its own window).
        for window in self.windows_on_vault(id) {
            tasks.push(self.run_in_window(window, |s| s.switch_this_window_to_vault(heir)));
        }
        if !self.windows_on_vault(id).is_empty() {
            return Err(crate::i18n::t("vault_no_heir").to_string());
        }
        let path = self.vault_file(id);
        if self.vaults.is_open(id) {
            // The agent's own handle on the file goes first: its keys
            // leave the roster, and the file is no longer held open
            // (Windows refuses to delete an open file).
            if let Some(runtime) = &self.agent.runtime {
                runtime.detach(id);
            }
            let previous = self.vaults.act_on(id);
            self.sever_vault_sessions();
            tasks.push(self.stop_vault_forwards());
            self.vaults.act_back(previous);
            // Whatever parked view still names it holds tabs that just
            // ended.
            self.drop_parked_views_of(id);
            // Closing the store closes the file before it is removed
            // (Windows refuses to delete an open file).
            if self.vaults.remove(id).is_none() {
                return Err(crate::i18n::t("vault_no_heir").to_string());
            }
        }
        let device = oryxis_vault::device::installed();
        // The variables its MCP secrets ride in every client config go
        // with it: the password still opens a file that is only left
        // (or gone), and the slug is free for a later vault, which
        // would inherit them. Read before the registry forgets the slug.
        let names = device.as_ref().and_then(|d| d.entry(id)).map(|e| oryxis_vault::device::mcp_env_names(&e));
        if let Some(device) = &device
            && let Err(e) = device.unregister(id)
        {
            tracing::warn!("could not unregister vault {id}: {e}");
            return Err(e.to_string());
        }
        if let Some(names) = names {
            let secrets = crate::mcp::McpSecrets { names, token: String::new(), vault_pw: None };
            tasks.push(Task::perform(
                async move { crate::mcp::strip_vault_password_everywhere(&secrets) },
                |result| match result {
                    Ok(()) => Message::NoOp,
                    Err(e) => Message::ToastShow(crate::i18n::t("vault_mcp_config_not_cleaned").replacen("{error}", &e, 1)),
                },
            ));
        }
        // Its spool was sealed under a key that went with it.
        crate::session_spool::SessionSpool::remove_for(id);
        if delete && let Some(path) = path {
            if self.biometric_available {
                crate::biometric::forget_account_of(&path);
            }
            // The user was told the vault is deleted: a file that stays
            // (held open by another process) is said, not logged.
            if !remove_vault_files(&path) {
                tasks.push(self.show_toast(
                    crate::i18n::t("vault_delete_file_left").replacen("{path}", &path.display().to_string(), 1),
                ));
            }
        }
        Ok(Task::batch(tasks))
    }

    /// Register the vault file the user picked and move this window to it
    /// (its lock screen asks for its master password). A file that is not
    /// a set-up Oryxis vault is refused untouched; one already in the list
    /// is simply shown.
    fn open_existing_vault(&mut self, path: std::path::PathBuf) -> Task<Message> {
        if !oryxis_vault::device::is_vault_file(&path) {
            return self.show_toast(crate::i18n::t("vault_open_not_a_vault").to_string());
        }
        let Some(device) = oryxis_vault::device::installed() else {
            return Task::none();
        };
        let label = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        match device.register_existing(&path, &label) {
            Ok((entry, _)) => self.switch_this_window_to_vault(entry.id),
            Err(e) => self.show_toast(format!("{}: {e}", crate::i18n::t("vault_open_failed"))),
        }
    }

    /// The setup step of a vault made with "New vault" was abandoned: the
    /// window goes back to the vault it was made from, and the new one,
    /// which holds nothing yet, is unregistered and its file removed.
    fn cancel_vault_setup(&mut self) -> Task<Message> {
        let abandoned = self.vaults.cur().id;
        let Some(back) = self.vaults.cur().created_from else {
            return Task::none();
        };
        if self.vaults.cur().vault_ui.state != VaultState::NeedSetup {
            return Task::none();
        }
        let task = self.switch_this_window_to_vault(back);
        // Still shown by another window: it stays until that one moves on.
        if self.window_on_vault(abandoned).is_some() {
            return task;
        }
        self.drop_parked_views_of(abandoned);
        let path = self.vaults.remove(abandoned).and_then(|v| v.path);
        if let Some(device) = oryxis_vault::device::installed()
            && let Err(e) = device.unregister(abandoned)
        {
            tracing::warn!("could not unregister the abandoned vault: {e}");
        }
        if let Some(path) = path {
            for suffix in ["", "-wal", "-shm"] {
                let file = std::path::PathBuf::from(format!("{}{suffix}", path.display()));
                if let Err(e) = std::fs::remove_file(&file)
                    && e.kind() != std::io::ErrorKind::NotFound
                {
                    tracing::warn!(path = %file.display(), "could not remove the abandoned vault: {e}");
                }
            }
        }
        task
    }

    /// Copy vault `source`'s preferences into `target` (a vault being
    /// created), the rows `copies_to_new_vault` lets through. Read from
    /// the open store when the source is open, from its file otherwise
    /// (settings are plaintext: no unlock needed).
    fn copy_settings_into(&self, source: Uuid, target: &VaultStore) {
        let rows = match self.vaults.all().find(|v| v.id == source).and_then(|v| v.store.as_ref()) {
            Some(store) => store.list_settings(),
            None => {
                let path = self
                    .registered_vaults()
                    .into_iter()
                    .find(|v| v.id == source)
                    .and_then(|e| oryxis_vault::device::installed().map(|d| d.resolve(&e)));
                match path.map(VaultStore::open) {
                    Some(Ok(store)) => store.list_settings(),
                    Some(Err(e)) => Err(e),
                    None => Ok(Vec::new()),
                }
            }
        };
        match rows {
            Ok(rows) => {
                for (key, value) in rows.into_iter().filter(|(k, _)| copies_to_new_vault(k)) {
                    if let Err(e) = target.set_setting(&key, &value) {
                        tracing::warn!("copying setting {key} into the new vault: {e}");
                    }
                }
            }
            Err(e) => tracing::warn!("reading the settings to copy: {e}"),
        }
    }
}

/// Remove a vault's file and everything that lives beside it under its
/// name: `-wal`, `-shm`, `.rebuild-lock`, and every `.damaged-<stamp>`
/// copy (with their own `-wal` / `-shm`). A file already gone is fine;
/// one that will not go is logged.
/// Answers whether every file went.
fn remove_vault_files(path: &std::path::Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let Some(dir) = path.parent() else {
        return false;
    };
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    let mut all = true;
    for entry in entries.flatten() {
        let file = entry.file_name();
        let Some(file) = file.to_str() else {
            continue;
        };
        let companion = file == name
            || file.strip_prefix(name).is_some_and(|rest| {
                matches!(rest, "-wal" | "-shm" | ".rebuild-lock") || rest.starts_with(".damaged-")
            });
        if companion
            && let Err(e) = std::fs::remove_file(entry.path())
            && e.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(path = %entry.path().display(), "could not remove a deleted vault's file: {e}");
            all = false;
        }
    }
    all
}

/// The id of the "New vault" dialog's name field.
pub(crate) const VAULT_DIALOG_NAME_INPUT: &str = "new-vault-name";

#[cfg(test)]
mod tests {
    use super::copies_to_new_vault;

    #[test]
    fn a_new_vault_takes_preferences_and_nothing_that_names_the_old_one() {
        for key in ["app_theme", "terminal_font_size", "auto_lock_minutes", "terminal_highlight_rules"] {
            assert!(copies_to_new_vault(key), "{key} is a preference");
        }
        for key in [
            "has_user_password",
            "open_tabs",
            "pinned_tabs",
            "sync_enabled",
            "sync_device_identity",
            "ai_api_key",
            "mcp_server_token",
            "mcp_server_enabled",
            "mcp_server_allow_writes",
            "default_key_id",
            "hint_privacy_mask",
            "port_forwards_migrated",
            "keepalive_default_v2_applied",
            "install_presets_seeded",
            "language",
            "hotkey_new_tab",
        ] {
            assert!(!copies_to_new_vault(key), "{key} stays with its vault (or the device)");
        }
    }
}
