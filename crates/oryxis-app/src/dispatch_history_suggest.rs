//! History-suggest popup: offer commands from the host's command history
//! that complete the line being typed (issue #266, asked for as "suggest
//! commands typed before, pick one to enter it"; WindTerm and Termius
//! ship the same).
//!
//! The password popup's contract (`dispatch_password_suggest.rs`), over
//! text instead of a credential:
//!
//! - **Nothing is ever typed without a pick.** Enter with nothing selected
//!   belongs to the shell; a pick puts the command on the line and only
//!   Shift+Enter submits it, because a command the user did not finish
//!   reading should not run.
//! - **Judged on the echo, never on the keystroke.** What the user typed
//!   is a command line only when its echo stands at a prompt on the grid,
//!   which is exactly the evidence the history CAPTURE demands before it
//!   records anything (`command_capture.rs`). So a user write marks the
//!   pane pending, and the probe runs in the output funnel, after
//!   `process`, with the same prompt-state gates: `AtPrompt` reads the
//!   line from the prompt's own coordinates, `NoIntegration` reads the
//!   cursor line past a classic prompt marker, `Busy` and the alternate
//!   screen offer nothing (a program's stdin, a password prompt, vim).
//! - **The mirror is the source of the prefix.** `InputTracker::composing_line`
//!   answers only while it can vouch for the line (caret at the end, no
//!   history recall, no tab completion, no paste in flight); a tainted
//!   line gets no popup, since nothing says what the remote editor holds.
//!   A pick reads it AGAIN at pick time: the popup's rows were matched
//!   against the line as it was at the last echo, and a keystroke can
//!   land between that echo and the pick (a Down + Enter burst, a click
//!   inside one round trip), so the bytes typed are computed against the
//!   line the mirror holds now, and a line it cannot vouch for types
//!   nothing.
//!
//! Inside tmux the popup does not open: the outer grid is the alternate
//! screen for the whole session, and the shell's own report (`OSC 633 ;
//! E`) arrives only at submit. A measured limitation, not a gate to
//! loosen.

use iced::Task;

use crate::app::{Message, Oryxis, TerminalMessage};
use crate::state::{HistorySuggestion, OverlayContent, OverlayState, Pane, PromptState};

/// Rows the popup offers at most. Eight is what a glance takes in; the
/// sidebar History tab is where the whole list lives.
pub(crate) const MAX_ROWS: usize = 8;

/// What the probe found on the grid for a pane with a pending write.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum HistoryProbe {
    /// The typed line stands echoed at a prompt: `typed` is the mirror's
    /// text, `anchor` the grid cell (column, viewport row) the line
    /// starts at, where the popup hangs.
    Match { typed: String, anchor: (u16, u16) },
    /// The mirror holds a line the grid does not show yet (the echo is
    /// still in flight): nothing to offer on this batch, ask again on
    /// the next one.
    NotYet,
    /// Nothing to complete here, for good until the user types again:
    /// an empty or tainted line, a running program, the alternate
    /// screen, a line the user asked history to ignore.
    Off,
}

/// Read the pane's grid for the line the user is composing. Runs INSIDE
/// the terminal lock of the output funnel, after the batch was processed
/// and the OSC 133 marks applied, so `pane.prompt` and the rows it points
/// at describe this very batch.
pub(crate) fn probe_history_suggest(pane: &Pane, term: &oryxis_terminal::TerminalState) -> HistoryProbe {
    if term.is_alt_screen() {
        return HistoryProbe::Off;
    }
    let Some(typed) = pane.input_tracker.composing_line() else {
        return HistoryProbe::Off;
    };
    // The `HISTCONTROL=ignorespace` convention the capture honours: a
    // line the user keeps out of history is not completed from it either.
    if typed.trim().is_empty() || typed.starts_with(' ') {
        return HistoryProbe::Off;
    }
    let echoed = match pane.prompt {
        // A program is reading stdin: whatever is typed is not a command.
        PromptState::Busy => return HistoryProbe::Off,
        // The shell said where the command line starts.
        PromptState::AtPrompt { abs_line, col } => term.logical_line_from_abs(abs_line, col),
        // No integration: the cursor line has to carry a classic prompt,
        // and the text after it has to be what was typed (the echo check
        // that keeps an unechoed password out of the capture keeps it out
        // of here too).
        PromptState::NoIntegration => term
            .cursor_logical_line()
            .as_deref()
            .and_then(crate::command_capture::strip_prompt)
            .map(str::to_string),
    };
    match echoed {
        // The grid read ends at the last non-blank cell, so a typed
        // trailing space is compared without it.
        Some(line) if line.trim_end() == typed.trim_end() => {
            let (col, row) = term.cursor_cell();
            let width = typed.chars().count().min(u16::MAX as usize) as u16;
            HistoryProbe::Match {
                typed,
                anchor: (col.saturating_sub(width), row),
            }
        }
        _ => HistoryProbe::NotYet,
    }
}

/// The commands worth offering for `typed`, in the order the popup shows
/// them: commands that EXTEND the typed line first, then commands that
/// merely contain it (case-insensitively), most recently used first
/// within each group (the pool's own order), capped at [`MAX_ROWS`]. A
/// command equal to the line offers nothing and is left out. Pure.
pub(crate) fn rank_history(pool: &[String], typed: &str) -> Vec<HistorySuggestion> {
    if typed.trim().is_empty() {
        return Vec::new();
    }
    let needle = typed.to_lowercase();
    let mut out: Vec<HistorySuggestion> = pool
        .iter()
        .filter(|c| c.as_str() != typed && c.starts_with(typed))
        .take(MAX_ROWS)
        .map(|c| HistorySuggestion {
            command: c.clone(),
            extends_typed: true,
        })
        .collect();
    if out.len() < MAX_ROWS {
        let room = MAX_ROWS - out.len();
        out.extend(
            pool.iter()
                .filter(|c| {
                    c.as_str() != typed
                        && !c.starts_with(typed)
                        && c.to_lowercase().contains(&needle)
                })
                .take(room)
                .map(|c| HistorySuggestion {
                    command: c.clone(),
                    extends_typed: false,
                }),
        );
    }
    out
}

/// The bytes a pick types into the pane to turn `typed`, the line the
/// mirror holds NOW, into `command`: the rest of the command when it
/// extends the line, else one erase per typed character (the pane's own
/// Backspace byte, so an appliance on Ctrl+H reads it too) followed by
/// the whole command; a Carriage Return when the pick runs it. Whether
/// the command extends the line is decided here, on the live line, not
/// on the row's flag: the row was classified against the line as it was
/// at the last echo. The text rides a bracketed paste when the terminal
/// asked for one, so a command with a tab or a newline in it lands
/// literally.
pub(crate) fn completion_bytes(
    typed: &str,
    command: &str,
    backspace: u8,
    bracketed: bool,
    run: bool,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    let text: &str = match command.strip_prefix(typed) {
        Some(rest) => rest,
        None => {
            bytes.extend(std::iter::repeat_n(backspace, typed.chars().count()));
            command
        }
    };
    bytes.extend(oryxis_terminal::wrap_paste(text, bracketed));
    if run {
        bytes.push(b'\r');
    }
    bytes
}

impl Oryxis {
    /// Whether suggestions are on for the acting vault. Nested under the
    /// capture toggle in Settings, and effective only with it: a hidden
    /// row means off, and without the capture there is no history to
    /// offer and no mirror being fed (`feed_input_capture` runs the
    /// tracker under the capture's own gate).
    pub(crate) fn history_suggest_enabled(&self) -> bool {
        let prefs = &self.vaults.cur().prefs;
        prefs.command_history && prefs.terminal_history_suggest
    }

    /// The pane whose typed line may raise or refresh the popup right
    /// now, or `None` when none should. Every test is "the user is
    /// looking at this pane and nothing else holds the screen", the
    /// password popup's list, plus the pane having a history to draw
    /// from (a saved host, not an SFTP console) and no runner on it.
    pub(crate) fn history_suggest_target(&self) -> Option<uuid::Uuid> {
        if !self.history_suggest_enabled() {
            return None;
        }
        // Another overlay owns the slot; our own popup refreshes in place.
        if self
            .overlay
            .as_ref()
            .is_some_and(|o| !matches!(o.content, OverlayContent::HistorySuggest { .. }))
        {
            return None;
        }
        if self.any_modal_blocks_input() {
            return None;
        }
        if self.vaults.cur().vault_ui.state != crate::state::VaultState::Unlocked {
            return None;
        }
        if !self.terminal_surface_visible() {
            return None;
        }
        let tab = self.tabs.get(self.cur_active_tab()?)?;
        if tab.files_mode {
            return None;
        }
        let pane = tab.active();
        // Only a saved host has a history (the capture keys on it), and
        // an SFTP console's vocabulary is `sftp(1)`'s, kept out of the
        // history for the same reason it is not offered back here.
        if !matches!(pane.origin, crate::state::PaneOrigin::Host(_))
            || pane.purpose == crate::state::PanePurpose::SftpConsole
        {
            return None;
        }
        // A login script or a ZMODEM transfer owns the pane's bytes.
        if pane.login_script.is_some() || pane.zmodem.is_some() {
            return None;
        }
        Some(pane.id)
    }

    /// The open popup's pane, when one is up.
    pub(crate) fn history_suggest_pane(&self) -> Option<uuid::Uuid> {
        match self.overlay.as_ref().map(|o| &o.content) {
            Some(OverlayContent::HistorySuggest { pane_id, .. }) => Some(*pane_id),
            _ => None,
        }
    }

    /// Close the popup if it is open, leaving any other overlay alone.
    /// Context switches that make the suggestion stale (a click on a
    /// pane, a tab switch, the setting turned off) call this.
    pub(crate) fn dismiss_history_suggest(&mut self) {
        if self.history_suggest_pane().is_some() {
            self.overlay = None;
        }
    }

    /// Same, only when the popup belongs to `pane_id` (a disconnect on a
    /// split tab whose other panes are live).
    pub(crate) fn dismiss_history_suggest_for(&mut self, pane_id: uuid::Uuid) {
        if self.history_suggest_pane() == Some(pane_id) {
            self.overlay = None;
        }
    }

    /// After every user write to the active pane of `tab_idx` (the end of
    /// `feed_input_capture`, once the mirror has seen the bytes): a line
    /// that emptied (submit, Ctrl+C, Ctrl+U) ends this line's popup
    /// state and closes the popup at once, so a prompt that follows the
    /// command (`sudo`) finds the overlay slot free; a line that goes on
    /// marks the pane for the next probe and drops the keyboard
    /// selection, since the rows are about to be refiltered and Enter
    /// must not accept one the user has not seen.
    pub(crate) fn history_suggest_after_input(&mut self, tab_idx: usize) {
        let Some(pane) = self.tabs.get_mut(tab_idx).map(|t| t.active_mut()) else {
            return;
        };
        let pane_id = pane.id;
        if pane.input_tracker.line_is_empty() {
            pane.history_suggest = Default::default();
            self.dismiss_history_suggest_for(pane_id);
            return;
        }
        pane.history_suggest.pending = true;
        if let Some(OverlayContent::HistorySuggest {
            pane_id: open_on,
            selected,
            ..
        }) = self.overlay.as_mut().map(|o| &mut o.content)
            && *open_on == pane_id
        {
            *selected = None;
        }
    }

    /// Act on a probe taken for `pane_id` in this output batch, with the
    /// pane borrow gone: open, refresh or close the popup. `NotYet` keeps
    /// the pane pending and closes a popup the grid no longer backs.
    pub(crate) fn refresh_history_suggest(&mut self, pane_id: uuid::Uuid, probe: HistoryProbe) {
        let HistoryProbe::Match { typed, anchor } = probe else {
            if let Some(pane) = self.pane_by_id_mut(pane_id) {
                // `Off` is settled; `NotYet` asks the next batch again.
                pane.history_suggest.pending = probe == HistoryProbe::NotYet;
            }
            self.dismiss_history_suggest_for(pane_id);
            return;
        };
        let Some(pane) = self.pane_by_id_mut(pane_id) else {
            return;
        };
        // The echo was found: this write is answered.
        pane.history_suggest.pending = false;
        if pane.history_suggest.muted {
            self.dismiss_history_suggest_for(pane_id);
            return;
        }
        let crate::state::PaneOrigin::Host(host) = pane.origin else {
            return;
        };
        // The pool is decrypted once per composed line: the first probe
        // that finds an echo loads it, the submit drops it
        // (`history_suggest_after_input`). A locked vault opens no row,
        // and an empty pool simply offers nothing.
        if pane.history_suggest.pool.is_none() {
            let pool: Vec<String> = self
                .vaults
                .cur()
                .store
                .as_ref()
                .and_then(|v| v.list_command_history(&host).ok())
                .unwrap_or_default()
                .into_iter()
                .map(|e| e.command)
                .collect();
            if let Some(pane) = self.pane_by_id_mut(pane_id) {
                pane.history_suggest.pool = Some(pool);
            }
        }
        let Some(pane) = self.pane_by_id(pane_id) else {
            return;
        };
        let entries = rank_history(pane.history_suggest.pool.as_deref().unwrap_or(&[]), &typed);
        if entries.is_empty() {
            self.dismiss_history_suggest_for(pane_id);
            return;
        }
        let Some((x, y, caret_top)) = self.history_suggest_anchor(pane_id, anchor) else {
            // Not drawn yet: the next batch tries again.
            if let Some(pane) = self.pane_by_id_mut(pane_id) {
                pane.history_suggest.pending = true;
            }
            return;
        };
        match self.overlay.as_mut() {
            Some(OverlayState {
                content:
                    OverlayContent::HistorySuggest {
                        pane_id: open_on,
                        entries: rows,
                        typed: shown,
                        selected,
                        caret_top: pivot,
                        ..
                    },
                x: ox,
                y: oy,
            }) if *open_on == pane_id => {
                // A pure output refresh keeps a selection that still
                // names a row; a write already dropped it.
                if selected.is_some_and(|i| i >= entries.len()) {
                    *selected = None;
                }
                *rows = entries;
                *shown = typed;
                *pivot = caret_top;
                *ox = x;
                *oy = y;
            }
            Some(_) => {}
            None => {
                self.overlay = Some(OverlayState {
                    content: OverlayContent::HistorySuggest {
                        pane_id,
                        entries,
                        typed,
                        selected: None,
                        caret_top,
                        scroll: 0.0,
                    },
                    x,
                    y,
                });
            }
        }
    }

    /// Window coordinates under the cell the typed line starts at, plus
    /// that cell's top edge (the flip pivot). `None` before the pane has
    /// reported a drawn rect.
    fn history_suggest_anchor(&self, pane_id: uuid::Uuid, cell: (u16, u16)) -> Option<(f32, f32, f32)> {
        let pane = self.pane_by_id(pane_id)?;
        let bounds = pane.bounds.get();
        if bounds.width <= 0.0 || bounds.height <= 0.0 {
            return None;
        }
        let caret = oryxis_terminal::ime_caret_rect(
            bounds,
            self.terminal_font_px(),
            Some(self.vaults.cur().terminal_font_name.as_str()),
            self.vaults.cur().terminal_font_weight.font_weight(),
            cell,
        );
        Some((
            caret.x,
            caret.y + caret.height + crate::dispatch_password_suggest::CARET_GAP,
            caret.y,
        ))
    }

    /// The open popup's pane + entries + typed line + selection.
    fn history_suggest_state(&self) -> Option<(uuid::Uuid, &[HistorySuggestion], &str, Option<usize>)> {
        match self.overlay.as_ref().map(|o| &o.content) {
            Some(OverlayContent::HistorySuggest {
                pane_id,
                entries,
                typed,
                selected,
                ..
            }) => Some((*pane_id, entries.as_slice(), typed.as_str(), *selected)),
            _ => None,
        }
    }

    /// Keep the keyboard selection inside the popup's viewport, scrolling
    /// only when it would leave it (the password popup's contract, with
    /// uniform rows).
    fn history_suggest_scroll_into_view(&mut self, idx: usize) -> Task<Message> {
        use crate::views::layout::{
            history_suggest_layout, HISTORY_SUGGEST_ROW_GAP, HISTORY_SUGGEST_ROW_H,
            HISTORY_SUGGEST_SCROLL_ID,
        };
        let window_h = self.cur_window_size().height;
        let Some(OverlayContent::HistorySuggest {
            entries, scroll, ..
        }) = self.overlay.as_mut().map(|o| &mut o.content)
        else {
            return Task::none();
        };
        let Some(viewport) = history_suggest_layout(entries.len(), window_h).rows_viewport else {
            return Task::none();
        };
        let pitch = HISTORY_SUGGEST_ROW_H + HISTORY_SUGGEST_ROW_GAP;
        let content = entries.len() as f32 * HISTORY_SUGGEST_ROW_H
            + entries.len().saturating_sub(1) as f32 * HISTORY_SUGGEST_ROW_GAP;
        let max_scroll = (content - viewport).max(0.0);
        let row_top = idx as f32 * pitch;
        let at = scroll.clamp(0.0, max_scroll);
        let next = if row_top < at {
            row_top
        } else if row_top + HISTORY_SUGGEST_ROW_H > at + viewport {
            row_top + HISTORY_SUGGEST_ROW_H - viewport
        } else {
            return Task::none();
        };
        let next = next.clamp(0.0, max_scroll);
        *scroll = next;
        iced::widget::operation::scrollable::scroll_to(
            iced::widget::Id::new(HISTORY_SUGGEST_SCROLL_ID),
            iced::widget::scrollable::AbsoluteOffset { x: 0.0, y: next },
            iced::widget::operation::Animation::Instant,
        )
    }

    pub(crate) fn handle_history_suggest(&mut self, message: TerminalMessage) -> Task<Message> {
        match message {
            TerminalMessage::HistorySuggestNavigate(delta) => {
                let Some((_, entries, _, selected)) = self.history_suggest_state() else {
                    return Task::none();
                };
                let len = entries.len();
                if len == 0 {
                    return Task::none();
                }
                // The first move engages the popup on its first row
                // whatever the direction (Up as an opener reaches the
                // list, not its end).
                let next = match selected {
                    None => 0,
                    Some(cur) => (cur as i64 + delta as i64).rem_euclid(len as i64) as usize,
                };
                if let Some(OverlayContent::HistorySuggest { selected, .. }) =
                    self.overlay.as_mut().map(|o| &mut o.content)
                {
                    *selected = Some(next);
                }
                return self.history_suggest_scroll_into_view(next);
            }
            TerminalMessage::HistorySuggestScrolled(offset) => {
                if let Some(OverlayContent::HistorySuggest { scroll, .. }) =
                    self.overlay.as_mut().map(|o| &mut o.content)
                {
                    *scroll = offset;
                }
            }
            TerminalMessage::HistorySuggestDismiss => {
                // Esc means "not for this line": the popup stays down
                // until the line is submitted or emptied, which
                // `history_suggest_after_input` resets.
                if let Some(pane_id) = self.history_suggest_pane()
                    && let Some(pane) = self.pane_by_id_mut(pane_id)
                {
                    pane.history_suggest.muted = true;
                }
                self.dismiss_history_suggest();
            }
            TerminalMessage::HistorySuggestPick(idx, run) => {
                let Some((pane_id, entries, _, _)) = self.history_suggest_state() else {
                    return Task::none();
                };
                let Some(entry) = entries.get(idx).cloned() else {
                    return Task::none();
                };
                self.overlay = None;
                let Some(tab_idx) = self.pane_tab_index(pane_id) else {
                    return Task::none();
                };
                let Some(pane) = self.pane_by_id_mut(pane_id) else {
                    return Task::none();
                };
                // The line as the mirror holds it NOW, not as the popup
                // matched it: a keystroke between the last echo and the
                // pick (a Down + Enter burst, a click inside one round
                // trip) would otherwise be typed over, or erased one
                // short. A line the mirror cannot vouch for any more
                // (tainted, caret moved) gets nothing typed into it.
                let Some(typed) = pane.input_tracker.composing_line() else {
                    return Task::none();
                };
                // The completed line is not offered against again: a
                // longer command that happens to extend it would reopen
                // the popup over text the user just chose. The submit
                // (or the next emptied line) lifts the mute.
                pane.history_suggest.muted = true;
                let bracketed = pane
                    .terminal
                    .lock()
                    .map(|s| s.bracketed_paste_enabled())
                    .unwrap_or(false);
                let backspace = pane.quirks.backspace.byte(false);
                let bytes = completion_bytes(&typed, &entry.command, backspace, bracketed, run);
                // Through the capture funnel: the mirror ends up holding
                // the whole line, and a run records the command's use
                // like a typed one. Ring-preserving, like the History
                // tab's own injection.
                self.write_ring_injection_to_tab(tab_idx, &bytes);
            }
            m => return crate::dispatch::unrouted(m),
        }
        Task::none()
    }

    /// Keyboard contract of the popup, run before the modal router (the
    /// password popup's slot, right after it).
    ///
    /// Non-modal, and more hands-off than the password popup: typing is
    /// not an answer here but more of the prefix, so printable keys pass
    /// through UNTOUCHED and the next echo refilters the rows. Unengaged,
    /// only Esc and Down address it (Up stays readline's history, Tab the
    /// shell's completion, Enter the shell's submit). Engaged, Up / Down
    /// move, Enter completes the line, Shift+Enter completes and runs.
    pub(crate) fn handle_history_suggest_key(
        &mut self,
        event: &iced::keyboard::Event,
    ) -> Option<Task<Message>> {
        use iced::keyboard::{key::Named, Event, Key};
        let (_, _, _, selected) = self.history_suggest_state()?;
        // A modal opened over it (a reconnect's host-key prompt): the
        // suggestion is stale, the modal's router gets the key.
        if self.any_modal_blocks_input() {
            self.dismiss_history_suggest();
            return None;
        }
        let Event::KeyPressed { key, modifiers, .. } = event else {
            return None;
        };
        if modifiers.control() || modifiers.alt() || modifiers.logo() {
            return None;
        }
        let msg = |m: TerminalMessage| Some(Task::done(Message::Terminal(m)));
        match key {
            Key::Named(Named::Escape) => msg(TerminalMessage::HistorySuggestDismiss),
            Key::Named(Named::ArrowDown) => msg(TerminalMessage::HistorySuggestNavigate(1)),
            Key::Named(Named::ArrowUp) if selected.is_some() => {
                msg(TerminalMessage::HistorySuggestNavigate(-1))
            }
            Key::Named(Named::Enter) if let Some(i) = selected => {
                msg(TerminalMessage::HistorySuggestPick(i, modifiers.shift()))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{InbandCapture, PendingCapture};

    fn pool(cmds: &[&str]) -> Vec<String> {
        cmds.iter().map(|c| c.to_string()).collect()
    }

    fn commands(rows: &[HistorySuggestion]) -> Vec<(&str, bool)> {
        rows.iter().map(|r| (r.command.as_str(), r.extends_typed)).collect()
    }

    #[test]
    fn extending_commands_lead_and_containing_ones_follow_in_recency_order() {
        let p = pool(&[
            "git status",
            "docker ps",
            "git stash pop",
            "sudo git stash",
            "git stash",
            "ls",
        ]);
        assert_eq!(
            commands(&rank_history(&p, "git sta")),
            [("git status", true), ("git stash pop", true), ("git stash", true), ("sudo git stash", false)]
        );
        // Containment is case-insensitive; an extension is exact, since
        // a pick types only the rest and the typed part stays as typed.
        assert_eq!(
            commands(&rank_history(&p, "GIT STA")),
            [("git status", false), ("git stash pop", false), ("sudo git stash", false), ("git stash", false)]
        );
    }

    #[test]
    fn a_line_already_in_history_offers_nothing_for_itself() {
        let p = pool(&["ls", "ls -la"]);
        assert_eq!(commands(&rank_history(&p, "ls")), [("ls -la", true)]);
        assert!(rank_history(&p, "ls -la").is_empty());
        assert!(rank_history(&p, "").is_empty());
        assert!(rank_history(&p, "   ").is_empty());
    }

    #[test]
    fn the_list_is_capped_at_the_popup_rows() {
        let many: Vec<String> = (0..20).map(|i| format!("echo {i}")).collect();
        let rows = rank_history(&many, "echo");
        assert_eq!(rows.len(), MAX_ROWS);
        // Most recent first: the pool's own order, untouched.
        assert_eq!(rows[0].command, "echo 0");
        assert_eq!(rows[MAX_ROWS - 1].command, format!("echo {}", MAX_ROWS - 1));
    }

    #[test]
    fn a_pick_types_the_rest_or_erases_and_retypes() {
        let extends = "git status --short";
        assert_eq!(completion_bytes("git sta", extends, 0x7f, false, false), b"tus --short");
        assert_eq!(completion_bytes("git sta", extends, 0x7f, false, true), b"tus --short\r");
        // Bracketed paste wraps the text, the Enter stays outside it.
        let wrapped = completion_bytes("git sta", extends, 0x7f, true, true);
        assert!(wrapped.starts_with(b"\x1b[200~tus --short\x1b[201~"));
        assert_eq!(wrapped.last(), Some(&b'\r'));
        // A containing match erases what was typed, one Backspace per
        // CHARACTER (not per byte: `ça` is two chars), with the pane's
        // own Backspace byte, then types the whole command.
        let contains = "sudo git stash";
        assert_eq!(
            completion_bytes("git sta", contains, 0x08, false, false),
            b"\x08\x08\x08\x08\x08\x08\x08sudo git stash"
        );
        assert_eq!(
            completion_bytes("ça", contains, 0x7f, false, false),
            b"\x7f\x7fsudo git stash"
        );
    }

    /// The row was matched against `echo HI`; by the time of the pick
    /// the mirror holds `echo HIS` (a keystroke inside one round trip).
    /// The bytes are computed against the LIVE line: the rest after
    /// `echo HIS`, never the rest after the stale prefix, which would
    /// have typed `echo HISST_ONE`. And a line the keystroke took past
    /// the command (`echo HIX`) is erased whole, one Backspace per
    /// character of the LIVE line.
    #[test]
    fn a_pick_completes_the_line_the_mirror_holds_now_not_the_one_the_row_saw() {
        assert_eq!(completion_bytes("echo HIS", "echo HIST_ONE", 0x7f, false, false), b"T_ONE");
        assert_eq!(
            completion_bytes("echo HIX", "echo HIST_ONE", 0x7f, false, false),
            b"\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7fecho HIST_ONE"
        );
    }

    /// Drive a real terminal with `output`, feed the pane's mirror with
    /// `typed`, and probe: what the output funnel does.
    fn probe(output: &[u8], typed: &[u8], prompt: PromptState) -> HistoryProbe {
        let term = std::sync::Arc::new(std::sync::Mutex::new(
            oryxis_terminal::TerminalState::new_no_pty(80, 24).unwrap(),
        ));
        let mut pane = Pane::new("t".into(), term.clone());
        pane.prompt = prompt;
        pane.input_tracker.feed(typed);
        let mut state = term.lock().unwrap();
        state.process(output);
        // The OSC 133 marks of `output`, applied as the funnel applies
        // them, so `AtPrompt` carries the prompt's real coordinates.
        let marks = state.take_shell_marks();
        if !marks.is_empty() {
            let mut pending: Option<PendingCapture> = None;
            let mut inband = InbandCapture::default();
            crate::command_capture::observe_output_marks(
                &mut pane.prompt,
                &mut pending,
                &mut inband,
                &state,
                &marks,
                &[],
            );
        }
        probe_history_suggest(&pane, &state)
    }

    #[test]
    fn an_echoed_line_at_a_classic_prompt_is_a_match_anchored_at_its_start() {
        let p = probe(b"wilson@web:~$ git sta", b"git sta", PromptState::NoIntegration);
        assert_eq!(
            p,
            HistoryProbe::Match {
                typed: "git sta".into(),
                // The prompt is 14 cells, the typed text 7: the cursor sits
                // at 21 and the line starts at 14.
                anchor: (14, 0),
            }
        );
    }

    #[test]
    fn the_echo_still_in_flight_asks_the_next_batch() {
        // The grid shows one keystroke less than the mirror: the last
        // echo has not arrived.
        let p = probe(b"wilson@web:~$ git st", b"git sta", PromptState::NoIntegration);
        assert_eq!(p, HistoryProbe::NotYet);
    }

    #[test]
    fn an_unechoed_line_is_never_completed() {
        // `read -s` / a password prompt: the typed text is nowhere on the
        // grid, and the cursor line carries no prompt marker either.
        let p = probe(b"Password: ", b"hunter2", PromptState::NoIntegration);
        assert_eq!(p, HistoryProbe::NotYet);
    }

    #[test]
    fn the_shells_own_prompt_mark_places_the_line() {
        let p = probe(
            b"\x1b]133;A\x07\x1b]133;B\x07git sta",
            b"git sta",
            PromptState::NoIntegration,
        );
        assert_eq!(
            p,
            HistoryProbe::Match {
                typed: "git sta".into(),
                anchor: (0, 0),
            }
        );
    }

    #[test]
    fn a_running_program_an_alternate_screen_or_a_tainted_line_offer_nothing() {
        assert_eq!(
            probe(b"wilson@web:~$ git sta", b"git sta", PromptState::Busy),
            HistoryProbe::Off
        );
        assert_eq!(
            probe(b"\x1b[?1049hgit sta", b"git sta", PromptState::NoIntegration),
            HistoryProbe::Off
        );
        // Tab completion: the mirror no longer knows the line.
        assert_eq!(
            probe(b"wilson@web:~$ git status", b"git sta\t", PromptState::NoIntegration),
            HistoryProbe::Off
        );
        // ignorespace: a line kept out of history is not completed from it.
        assert_eq!(
            probe(b"wilson@web:~$  git sta", b" git sta", PromptState::NoIntegration),
            HistoryProbe::Off
        );
        // Nothing typed yet.
        assert_eq!(
            probe(b"wilson@web:~$ ", b"", PromptState::NoIntegration),
            HistoryProbe::Off
        );
    }
}
