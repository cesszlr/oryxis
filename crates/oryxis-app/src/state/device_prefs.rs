//! The preferences of this DEVICE rather than of a vault: the keys
//! `oryxis_vault::device` routes to `device.json` (UI language, window
//! and tray behaviour, the renderer, offline mode and updates, the
//! programs and folders on this disk). One per process, whichever vault
//! a window works on; every other preference is a vault's
//! (`AppPrefs`, held by each `vault_slots::OpenVault`).

#[derive(Debug, Clone)]
pub(crate) struct DevicePrefs {
    pub(crate) sftp_default_editor: String,
    /// Renderer backend selection: "auto" (default), "opengl" (force
    /// wgpu's GL backend, still GPU), or "software" (tiny-skia / CPU).
    /// `main` translates this into `WGPU_BACKEND` / `ICED_BACKEND` at
    /// startup, an escape hatch for GPU/driver stacks that corrupt the
    /// wgpu surface. Read at boot only (the env vars are resolved before
    /// the runtime starts), so changing it asks the user to restart.
    pub(crate) renderer_backend: String,
    /// Folder for the per-host command logs. `None` = the default
    /// `~/.oryxis/command-history/`. Persisted as
    /// `command_history_file_dir` (empty string = default).
    pub(crate) command_history_file_dir: Option<String>,
    /// Destination folder for ZMODEM downloads. Empty = the OS Downloads
    /// dir (or `~/.oryxis/downloads`). Persisted as `zmodem_download_dir`.
    pub(crate) zmodem_download_dir: String,
    /// Renders the terminal perf HUD (per-phase frame timing + fps) in
    /// the top-right of every pane. Off by default; the `ORYXIS_TERM_PERF`
    /// env var forces it on too. `"perf_overlay"` setting.
    pub(crate) perf_overlay: bool,
    /// Offline mode: the app makes no request of its own (update checks,
    /// font and plugin downloads). Mirror of the process-wide gate in
    /// `crate::offline`, which is what the fetch functions read; this
    /// field is what the toggles render. Hydrated pre-unlock like the
    /// update settings. `"offline_mode"` setting.
    pub(crate) offline_mode: bool,
    /// Settings > Advanced debug logging: mirror of the `debug_logging`
    /// setting, true while tracing events are also written to the
    /// exportable `~/.oryxis/oryxis-debug.log` file (see `logging.rs`).
    pub(crate) debug_logging: bool,
    /// When on, clicking the window's close button hides to the
    /// system tray instead of quitting. Only honoured on Windows
    /// (the tray module is a no-op everywhere else). Default off
    /// so we don't surprise users who never knew there was a tray.
    pub(crate) close_to_tray: bool,
    /// When on, minimizing the window hides it from the taskbar and
    /// leaves only the tray icon visible. Windows-only. Default off.
    pub(crate) minimize_to_tray: bool,
    /// Language picker choice as persisted in the `language` setting:
    /// `"auto"` (default, follow the OS locale) or a concrete language
    /// code ("en", "pt-BR", ...). The *resolved* language always lives
    /// in `i18n::Language::active()`; this field only drives the
    /// Settings picker selection so "Auto (OS)" survives restarts as a
    /// choice instead of collapsing into the detected language.
    pub(crate) language_choice: String,
    /// Folder those files live in; `None` = `~/.oryxis/session-logs/`.
    /// Persisted as `session_log_file_dir` (a set value only).
    pub(crate) session_log_file_dir: Option<String>,
    /// Folder a snippet's save steps write into; `None` =
    /// `<Documents>/Oryxis` (`<home>/Oryxis` without one). Persisted as
    /// `snippet_output_dir` (a set value only). Device-local: a snippet
    /// names a file, never where it goes.
    pub(crate) snippet_output_dir: Option<String>,
    pub(crate) auto_check_updates: bool,
    /// Release stream the updater follows (`stable` / `nightly`).
    pub(crate) update_channel: crate::update::UpdateChannel,
    /// The vault switcher stays hidden while this device has a single
    /// vault (`vault_switcher_hide_single`).
    pub(crate) vault_switcher_hide_single: bool,
    /// Where the vault switcher lives (`vault_switcher_place`).
    pub(crate) vault_switcher_place: VaultSwitcherPlace,
    /// This device's display name in the sync peer lists (`sync_device_name`).
    pub(crate) sync_device_name: String,
    /// The sync listener's port as typed (`sync_listen_port`, `"0"` ==
    /// ephemeral): one listener per device, whichever vault syncs.
    pub(crate) sync_listen_port: String,
}

impl Default for DevicePrefs {
    fn default() -> Self {
        Self {
            sftp_default_editor: String::new(),
            renderer_backend: "auto".to_string(),
            command_history_file_dir: None,
            zmodem_download_dir: String::new(),
            perf_overlay: false,
            offline_mode: false,
            debug_logging: false,
            close_to_tray: false,
            minimize_to_tray: false,
            language_choice: "auto".into(),
            snippet_output_dir: None,
            session_log_file_dir: None,
            auto_check_updates: true,
            update_channel: crate::update::UpdateChannel::default(),
            vault_switcher_hide_single: false,
            vault_switcher_place: VaultSwitcherPlace::default(),
            sync_device_name: String::new(),
            sync_listen_port: "0".into(),
        }
    }
}

/// Where the vault switcher lives. Device-level: it is how this person
/// works the app, whatever vault a window is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum VaultSwitcherPlace {
    /// The tab bar's Home tab carries the vault (its name, and a chevron
    /// that opens the switcher), Termius's shape.
    #[default]
    Tabs,
    /// A chip at the head of the vault toolbar (the badge at the top of
    /// the nav rail).
    Toolbar,
}

impl VaultSwitcherPlace {
    pub(crate) const ALL: [Self; 2] = [Self::Tabs, Self::Toolbar];

    /// The value persisted as `vault_switcher_place`.
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::Tabs => "tabs",
            Self::Toolbar => "toolbar",
        }
    }

    /// The persisted value back; anything else is `None` (the default
    /// stays).
    pub(crate) fn from_code(code: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.code() == code)
    }

    pub(crate) fn label_key(self) -> &'static str {
        match self {
            Self::Tabs => "vault_switcher_place_tabs",
            Self::Toolbar => "vault_switcher_place_toolbar",
        }
    }
}

#[cfg(test)]
mod vault_switcher_place_tests {
    use super::VaultSwitcherPlace;

    #[test]
    fn the_place_code_round_trips_and_defaults_to_the_tab_bar() {
        for place in VaultSwitcherPlace::ALL {
            assert_eq!(VaultSwitcherPlace::from_code(place.code()), Some(place));
        }
        assert_eq!(VaultSwitcherPlace::from_code(""), None);
        assert_eq!(VaultSwitcherPlace::default(), VaultSwitcherPlace::Tabs);
    }
}

