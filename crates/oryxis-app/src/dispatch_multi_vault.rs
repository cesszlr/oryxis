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
use crate::state::{NewVaultForm, OverlayContent, OverlayState, VaultState};
use crate::vault_slots::OpenVault;
use oryxis_vault::device::VaultEntry;
use oryxis_vault::VaultStore;

/// Where the switcher chip that was pressed sits: under the toolbar's
/// leading edge, or at the top of the nav rail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VaultChipPlace {
    Toolbar,
    Rail,
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
        match message {
            MultiVaultMessage::ShowVaultSwitcher(place) => {
                // Under the chip's real rectangle (last drawn), never a
                // constant: the chip moves with the rail and the toolbar.
                let b = match place {
                    VaultChipPlace::Toolbar => self.vault_chip_bounds.get(),
                    VaultChipPlace::Rail => self.vault_badge_bounds.get(),
                };
                let (x, y) = match place {
                    VaultChipPlace::Toolbar => (b.x, b.y + b.height + 4.0),
                    VaultChipPlace::Rail => (b.x, b.y + b.height + 4.0),
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
                    return Task::none();
                }
                return self.open_window_on_vault(id);
            }
            MultiVaultMessage::ShowNewVault => {
                self.overlay = None;
                self.new_vault = Some(NewVaultForm::default());
                return crate::widgets::focus_input(iced::widget::Id::new(NEW_VAULT_NAME_INPUT));
            }
            MultiVaultMessage::NewVaultNameChanged(name) => {
                if let Some(form) = self.new_vault.as_mut() {
                    form.name = name;
                    form.error = None;
                }
            }
            MultiVaultMessage::NewVaultCopyFromChanged(source) => {
                if let Some(form) = self.new_vault.as_mut() {
                    form.copy_from = source;
                }
            }
            MultiVaultMessage::CreateVault => return self.create_vault(),
            MultiVaultMessage::CancelVaultSetup => return self.cancel_vault_setup(),
            MultiVaultMessage::CancelNewVault => self.new_vault = None,
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
    pub(crate) fn ensure_vault_open(&mut self, id: Uuid) -> bool {
        if self.vaults.is_open(id) {
            return true;
        }
        let Some(entry) = self.registered_vaults().into_iter().find(|v| v.id == id) else {
            return false;
        };
        self.open_vault(&entry);
        true
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
            return Task::none();
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
            VaultState::Unlocked if !self.vaults.cur().loaded => {
                self.load_data_from_vault();
                Task::none()
            }
            VaultState::Locked => crate::widgets::focus_input(iced::widget::Id::new(
                "vault-unlock-password",
            )),
            _ => Task::none(),
        }
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
        let Some(form) = self.new_vault.as_ref() else {
            return Task::none();
        };
        let name = form.name.trim().to_string();
        let copy_from = form.copy_from;
        if name.is_empty() {
            if let Some(form) = self.new_vault.as_mut() {
                form.error = Some(crate::i18n::t("vault_name_required").to_string());
            }
            return Task::none();
        }
        let Some(device) = oryxis_vault::device::installed() else {
            return Task::none();
        };
        let entry = match device.create_entry(&name) {
            Ok(entry) => entry,
            Err(e) => {
                if let Some(form) = self.new_vault.as_mut() {
                    form.error = Some(crate::i18n::t("vault_create_failed").replacen("{error}", &e.to_string(), 1));
                }
                return Task::none();
            }
        };
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
                if let Some(form) = self.new_vault.as_mut() {
                    form.error = Some(crate::i18n::t("vault_create_failed").replacen("{error}", &e.to_string(), 1));
                }
                return Task::none();
            }
        };
        if let Some(source) = copy_from {
            self.copy_settings_into(source, &store);
        }
        drop(store);
        self.new_vault = None;
        let from = self.vaults.window_id();
        let task = self.switch_this_window_to_vault(entry.id);
        self.vaults.cur_mut().created_from = Some(from);
        task
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

/// The id of the "New vault" dialog's name field.
pub(crate) const NEW_VAULT_NAME_INPUT: &str = "new-vault-name";

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
