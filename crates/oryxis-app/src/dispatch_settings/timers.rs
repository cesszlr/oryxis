//! The settings that own a clock: auto-reconnect, the vault's idle
//! auto-lock, and the connect animation.
//!
//! Their ticks live with them. `AutoReconnectTick` is the largest thing
//! here because a reconnect has to decide, per dormant tab, whether it
//! is due, allowed and not already in flight.

use super::*;

impl Oryxis {
    pub(super) fn handle_settings_timers(
        &mut self,
        message: SettingsMessage,
    ) -> Result<Task<Message>, SettingsMessage> {
        match message {
            SettingsMessage::SettingToggleAutoReconnect => {
                self.vaults.cur_mut().prefs.auto_reconnect = !self.vaults.cur_mut().prefs.auto_reconnect;
                self.persist_setting(
                    "auto_reconnect",
                    if self.vaults.cur().prefs.auto_reconnect { "true" } else { "false" },
                );
            }
            SettingsMessage::SettingMaxReconnectChanged(val) => {
                self.vaults.cur_mut().prefs.max_reconnect_attempts = sanitize_uint(&val, 100);
                self.persist_setting(
                    "max_reconnect_attempts",
                    &self.vaults.cur().prefs.max_reconnect_attempts,
                );
            }
            SettingsMessage::SettingAutoLockChanged(val) => {
                self.vaults.cur_mut().prefs.auto_lock_minutes = sanitize_uint(&val, 1440);
                self.persist_setting("auto_lock_minutes", &self.vaults.cur().prefs.auto_lock_minutes);
            }
            SettingsMessage::SettingManualLockActionChanged(val) => {
                // Sibling of the lock family above: what the Lock Vault
                // button does. The pick_list only offers the three known
                // tokens, but the guard keeps a corrupted row from
                // sticking as a phantom fourth state.
                let normalized = match val.as_str() {
                    "sleep" | "lock" => val.as_str(),
                    _ => "ask",
                };
                self.vaults.cur_mut().prefs.manual_lock_action = normalized.into();
                self.persist_setting("manual_lock_action", normalized);
            }
            SettingsMessage::AutoLockTick => {
                // Idle check, per open vault: each against its own
                // threshold and the input in ITS windows, so a vault
                // nobody is looking at locks on time while the user
                // works in another. Guarded on Unlocked so a tick racing
                // the lock is a no-op, and on a parseable non-zero
                // threshold (the subscription only mounts then, but the
                // setting can change between mount and fire).
                let idle: Vec<uuid::Uuid> = self
                    .vaults
                    .all()
                    .filter(|v| v.auto_lock_due())
                    .map(|v| v.id)
                    .collect();
                return Ok(Task::batch(idle.into_iter().map(|vault| {
                    tracing::info!(%vault, "vault auto-lock after its idle threshold");
                    Task::done(Message::ForVault(
                        vault,
                        Box::new(Message::Vault(VaultMessage::SoftLockVault)),
                    ))
                })));
            }
            SettingsMessage::ConnectAnimTick => {
                self.connect_anim_tick = self.connect_anim_tick.wrapping_add(1);
            }
            SettingsMessage::AutoReconnectTick => {
                // Liveness sweep, independent of the auto-reconnect setting.
                // A pane whose SSH writer task has died reports
                // `is_alive() == false` while its reader may still be
                // draining output: the tab looks "connected" but silently
                // swallows every keystroke (the writer's `send` errors and
                // the input sites discard it). Nothing else checks
                // `is_alive`, so without this such a pane stays a dead
                // input sink forever. Surface it as a real disconnect so the
                // UI updates and, when enabled, reconnect kicks in. Panes
                // already torn down have `session == None` and are
                // skipped, so this can't loop.
                let dead: Vec<_> = self
                    .tabs
                    .iter()
                    .flat_map(|t| t.pane_grid.panes.values())
                    .filter(|p| p.session.as_ref().is_some_and(|s| !s.is_alive()))
                    .map(|p| p.id)
                    .collect();
                if !dead.is_empty() {
                    // As the pane's own stream would say it: on the
                    // vault of its tab, in the window holding it.
                    return Ok(Task::batch(dead.into_iter().map(|id| {
                        Task::done(Message::ForPane(
                            id,
                            Box::new(Message::Ssh(SshMessage::SshDisconnected(id))),
                        ))
                    })));
                }
                // Each open vault by its own setting, over its own tabs
                // and hosts: a tab of another vault does not resolve
                // against this one's connections. ONE dial per tick for
                // the whole app, never one per vault: the host-key / 2FA
                // / command-proxy answers ride single staging slots, so
                // the first vault with a candidate takes the tick and the
                // next tick picks up the next.
                let mut picked = false;
                let reconnect = self.on_each_open_vault(|app| {
                    if picked {
                        return None;
                    }
                    let candidate = app.auto_reconnect_candidate();
                    picked = candidate.is_some();
                    candidate
                });
                return Ok(Task::batch(reconnect.into_iter().map(Task::done)));
            }
            m => return Err(m),
        }
        Ok(Task::none())
    }

    /// The acting vault's next auto-reconnect, as the message to send:
    /// the first of its disconnected SSH tabs whose host is under the
    /// attempt limit, one per tick to avoid thrashing (the next tick
    /// picks up the next candidate). `None` with the setting off or the
    /// vault locked (a reconnect needs its credentials).
    fn auto_reconnect_candidate(&mut self) -> Option<Message> {
        let ov = self.vaults.cur();
        if !ov.prefs.auto_reconnect || ov.vault_ui.state != crate::state::VaultState::Unlocked {
            return None;
        }
        let max_attempts: u32 = ov.prefs.max_reconnect_attempts.parse().unwrap_or(5);
        let (here, window) = (self.vaults.current_id(), self.vaults.window_id());
        let tab_idx = (0..self.tabs.len()).find(|&i| {
            let tab = &self.tabs[i];
            if tab.vault_or(window) != here || !tab.label.ends_with(" (disconnected)") {
                return false;
            }
            // Never auto-reconnect a split tab: `ReconnectTab` removes +
            // rebuilds the whole tab, which would kill the live sibling
            // panes. (Belt + suspenders: a multi-pane tab isn't relabeled
            // "(disconnected)" in the first place, see `SshDisconnected`.)
            if tab.pane_grid.panes.len() > 1 {
                return false;
            }
            let base = tab.label.trim_end_matches(" (disconnected)");
            // Quick-connect hosts resolve via the same label lookup; their
            // counters key on the ephemeral id, which is stable for the
            // life of the entry.
            let Some(conn) = self.any_connection_by_label(base) else {
                return false;
            };
            // Nobody started this dial, so it may not ask for a touch: a
            // security-key host waits for a click.
            if self.host_signs_with_token(conn) {
                return false;
            }
            let attempts = self.reconnect_counters.get(&conn.id).copied().unwrap_or(0);
            attempts < max_attempts
        })?;
        let base = self.tabs[tab_idx].label.trim_end_matches(" (disconnected)").to_string();
        if let Some(cid) = self.any_connection_by_label(&base).map(|c| c.id) {
            *self.reconnect_counters.entry(cid).or_insert(0) += 1;
        }
        // On the tab's vault, in the window holding it, so a prompt the
        // dial raises floats where the tab is.
        let pane = self.tabs[tab_idx].active().id;
        Some(Message::ForPane(pane, Box::new(Message::Tabs(TabsMessage::ReconnectTab(tab_idx)))))
    }
}
