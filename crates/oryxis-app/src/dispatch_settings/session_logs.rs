//! Session recording and connection history: what is captured, how long
//! it is kept, and whether the host is probed for its OS.
//!
//! Handled here rather than in `dispatch_ssh` because they are settings
//! rows; the capture itself lives with the session (CLAUDE.md's
//! name-family rule).

use super::*;

impl Oryxis {
    pub(super) fn handle_settings_session_logs(
        &mut self,
        message: SettingsMessage,
    ) -> Result<Task<Message>, SettingsMessage> {
        match message {
            SettingsMessage::SettingToggleSessionLogging => {
                self.vaults.cur_mut().prefs.session_logging = !self.vaults.cur_mut().prefs.session_logging;
                self.persist_setting(
                    "session_logging",
                    if self.vaults.cur().prefs.session_logging { "true" } else { "false" },
                );
            }
            SettingsMessage::SettingToggleSessionLogFull => {
                self.vaults.cur_mut().prefs.session_log_full = !self.vaults.cur_mut().prefs.session_log_full;
                self.persist_setting(
                    "session_log_full",
                    if self.vaults.cur().prefs.session_log_full { "true" } else { "false" },
                );
            }
            SettingsMessage::SettingToggleSessionLogCompress => {
                self.vaults.cur_mut().prefs.session_log_compress = !self.vaults.cur_mut().prefs.session_log_compress;
                self.persist_setting(
                    "session_log_compress",
                    if self.vaults.cur().prefs.session_log_compress { "true" } else { "false" },
                );
            }
            SettingsMessage::SettingToggleSessionLogFile => {
                self.vaults.cur_mut().prefs.session_log_file = !self.vaults.cur_mut().prefs.session_log_file;
                self.persist_setting(
                    "session_log_file",
                    if self.vaults.cur().prefs.session_log_file { "true" } else { "false" },
                );
                // Switching it off mid-session forgets the file every
                // live recording had picked, so switching it back on
                // starts a new one rather than resuming a file whose
                // middle is missing.
                if !self.vaults.cur().prefs.session_log_file {
                    for tab in &mut self.tabs {
                        for pane in tab.pane_grid.panes.values_mut() {
                            pane.session_log_file = None;
                        }
                    }
                }
            }
            SettingsMessage::PickSessionLogFileDir => {
                return Ok(Task::perform(
                    tokio::task::spawn_blocking(|| {
                        rfd::FileDialog::new()
                            .set_title(crate::i18n::t("session_log_folder_title"))
                            .pick_folder()
                            .map(|p| p.display().to_string())
                    }),
                    |res| {
                        Message::Settings(SettingsMessage::SessionLogFileDirPicked(
                            res.ok().flatten(),
                        ))
                    },
                ));
            }
            SettingsMessage::SessionLogFileDirPicked(dir) => {
                if let Some(dir) = dir {
                    self.persist_setting("session_log_file_dir", &dir);
                    self.device_prefs.session_log_file_dir = Some(dir);
                    // The live recordings keep writing where they
                    // already are: a file cut in half at a folder change
                    // is worse than one that finishes where it started.
                }
            }
            SettingsMessage::ClearSessionLogFileDir => {
                // An empty value is what boot reads as "default", so the
                // reset persists the same shape it will be read back as.
                // Live recordings keep their folder, as above.
                self.persist_setting("session_log_file_dir", "");
                self.device_prefs.session_log_file_dir = None;
            }
            SettingsMessage::PickSnippetOutputDir => {
                return Ok(Task::perform(
                    tokio::task::spawn_blocking(|| {
                        rfd::FileDialog::new()
                            .set_title(crate::i18n::t("snippet_output_dir"))
                            .pick_folder()
                            .map(|p| p.display().to_string())
                    }),
                    |res| Message::Settings(SettingsMessage::SnippetOutputDirPicked(res.ok().flatten())),
                ));
            }
            SettingsMessage::SnippetOutputDirPicked(dir) => {
                if let Some(dir) = dir {
                    self.persist_setting("snippet_output_dir", &dir);
                    self.device_prefs.snippet_output_dir = Some(dir);
                }
            }
            SettingsMessage::ClearSnippetOutputDir => {
                // Empty is what boot reads as "default".
                self.persist_setting("snippet_output_dir", "");
                self.device_prefs.snippet_output_dir = None;
            }
            SettingsMessage::SettingToggleConnectionHistory => {
                self.vaults.cur_mut().prefs.connection_history = !self.vaults.cur_mut().prefs.connection_history;
                self.persist_setting(
                    "connection_history",
                    if self.vaults.cur().prefs.connection_history { "true" } else { "false" },
                );
            }
            SettingsMessage::LogsSizeCapChanged(code) => {
                let cap = code.parse::<u64>().ok().filter(|n| *n > 0);
                self.vaults.cur_mut().prefs.session_log_max_bytes = cap;
                self.persist_setting("session_log_max_bytes", code);
                // Apply right away, same reason the retention picker
                // does: picking a smaller cap must have a visible
                // effect, not wait for the next flush tick.
                let ov = self.vaults.cur_mut();
                if let (Some(cap), Some(vault)) = (cap, &ov.store) {
                    match vault.prune_session_logs_to_fit(cap) {
                        Ok(0) => {}
                        Ok(n) => tracing::info!("session log size cap pruned {n} recordings"),
                        Err(e) => tracing::warn!("session log size-cap prune failed: {e}"),
                    }
                    ov.session_logs_page = 0;
                    ov.session_logs_total = vault.count_session_logs().unwrap_or(0);
                    ov.session_logs = vault
                        .list_session_logs_page(0, 50)
                        .unwrap_or_default();
                }
            }
            SettingsMessage::LogsRetentionChanged(code) => {
                self.vaults.cur_mut().prefs.logs_retention = code.to_string();
                self.persist_setting("logs_retention", code);
                // Apply right away so picking a shorter window has a
                // visible effect, then refresh the cached Logs state.
                let ov = self.vaults.cur_mut();
                if let Some(days) = Self::retention_days(code)
                    && let Some(vault) = &ov.store
                {
                    let cutoff = chrono::Utc::now() - chrono::Duration::days(days);
                    match vault.prune_logs_older_than(cutoff) {
                        Ok(0) => {}
                        Ok(n) => tracing::info!("logs retention pruned {n} rows"),
                        Err(e) => tracing::warn!("logs retention prune failed: {e}"),
                    }
                    ov.logs_page = 0;
                    ov.session_logs_page = 0;
                    ov.logs_total = vault.count_logs().unwrap_or(0);
                    ov.logs = vault.list_logs_page(0, 50).unwrap_or_default();
                    ov.session_logs_total = vault.count_session_logs().unwrap_or(0);
                    ov.session_logs =
                        vault.list_session_logs_page(0, 50).unwrap_or_default();
                }
            }
            SettingsMessage::SettingToggleOsDetection => {
                self.vaults.cur_mut().prefs.os_detection = !self.vaults.cur_mut().prefs.os_detection;
                self.persist_setting(
                    "os_detection",
                    if self.vaults.cur().prefs.os_detection { "true" } else { "false" },
                );
            }
            m => return Err(m),
        }
        Ok(Task::none())
    }
}
