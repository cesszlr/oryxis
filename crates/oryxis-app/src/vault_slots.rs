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
    /// See [`crate::state::ChatUi`].
    pub(crate) chat_ui: crate::state::ChatUi,
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
    pub(crate) ai: crate::state::AiState,
    /// When on, the dashboard root shows two sections, Groups (manual
    /// folder cards) and Hosts (a flat list of every connection,
    /// including those that live inside a group). When off, root
    /// matches the legacy behaviour: groups at top, only ungrouped
    /// hosts beneath. Default: on. (Dashboard layout, not a sync field.)
    pub(crate) flatten_hosts: bool,
}

impl OpenVault {
    /// A vault just opened, nothing loaded from it yet (`load_data_from_vault`
    /// fills it after the unlock).
    pub(crate) fn new(id: Uuid, store: Option<VaultStore>) -> Self {
        Self {
            id,
            store,
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

/// Every open vault, and the one the window acting now works on.
pub(crate) struct VaultSlots {
    open: HashMap<Uuid, OpenVault>,
    /// The vault of the window whose values are in the fields.
    current: Uuid,
}

impl VaultSlots {
    /// A process with one vault open (or the one it failed to open).
    pub(crate) fn single(vault: OpenVault) -> Self {
        let current = vault.id;
        Self { open: HashMap::from([(current, vault)]), current }
    }

    /// The id of the vault the window in the fields works on: what a
    /// new window opened from it starts on.
    pub(crate) fn current_id(&self) -> Uuid {
        self.current
    }

    /// Make `id` the vault of the window in the fields (the window swap
    /// of `enter_window` / `exit_window`), handing back the one it
    /// replaces.
    pub(crate) fn set_current(&mut self, id: Uuid) -> Uuid {
        std::mem::replace(&mut self.current, id)
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
}

#[cfg(test)]
impl VaultSlots {
    /// Open a second vault beside the first (the multi-vault doors that
    /// open one in the app arrive with the switcher).
    pub(crate) fn insert_for_test(&mut self, vault: OpenVault) {
        self.open.insert(vault.id, vault);
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
        let resident = slots.set_current(b);
        assert_eq!(resident, a);
        assert_eq!(slots.cur().id, b);
        assert_eq!(slots.cur_mut().id, b);
        // `exit_window`.
        slots.set_current(resident);
        assert_eq!(slots.cur().id, a);
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
}
