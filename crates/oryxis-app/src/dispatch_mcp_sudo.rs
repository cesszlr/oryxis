//! The app's side of `oryxis_vault::mcp_consent`: `oryxis-mcp` asks to
//! hand a host's stored password to `sudo`, and the person answers here.
//!
//! The folder is polled by the deep-link subscription. A request is
//! CLAIMED only when its vault is open and unlocked in this instance:
//! the answer is signed with that vault's key, and a question nobody can
//! answer is better left unclaimed, so the server tells its agent to
//! have the vault unlocked instead of waiting a full minute. Every way a
//! dialog ends writes an answer (the person, its deadline, the vault
//! locking, the app quitting), except a request the server withdrew,
//! which only goes away.

use iced::Task;
use oryxis_vault::mcp_consent::{self, Answer, Decision, DenyReason, SudoRequest};

use crate::app::{Message, Oryxis};
use crate::messages::McpMessage;
use crate::state::McpSudoCard;

impl Oryxis {
    pub(crate) fn handle_mcp_sudo(&mut self, message: McpMessage) -> Result<Task<Message>, McpMessage> {
        match message {
            McpMessage::McpSudoScanned(scan) => Ok(self.mcp_sudo_scanned(scan)),
            McpMessage::McpSudoClaimed(request) => {
                let id = request.id.clone();
                if !self.mcp_sudo.push(McpSudoCard { request: *request }) {
                    return Ok(Task::none());
                }
                Ok(Task::perform(
                    async { tokio::time::sleep(mcp_consent::DECISION_WINDOW).await },
                    move |()| Message::Mcp(McpMessage::McpSudoExpired(id.clone())),
                ))
            }
            McpMessage::McpSudoAnswered(decision) => {
                if let Some(card) = self.mcp_sudo.take_pending() {
                    let reason = (!decision.allows()).then_some(DenyReason::Person);
                    self.mcp_sudo_answer(&card.request, decision, reason);
                }
                Ok(Task::none())
            }
            McpMessage::McpSudoExpired(id) => {
                for card in self.mcp_sudo.remove_where(|r| r.id == id) {
                    self.mcp_sudo_answer(&card.request, Decision::Deny, Some(DenyReason::TimedOut));
                }
                Ok(Task::none())
            }
            other => Err(other),
        }
    }

    /// The folder changed: drop the dialogs whose request the server
    /// withdrew, then claim what this instance can ask.
    fn mcp_sudo_scanned(&mut self, scan: mcp_consent::Scan) -> Task<Message> {
        let Some(dir) = mcp_consent::consent_dir() else {
            return Task::none();
        };
        // A dialog whose claim is gone stands for a call that ended
        // (cancelled, or timed out on the server's side): nothing to
        // answer any more. Read off the folder now, not off the scan:
        // a claim made after the scan would read as withdrawn.
        let withdrawn: Vec<String> = self
            .mcp_sudo
            .ids()
            .into_iter()
            .filter(|id| mcp_consent::status(&dir, id) != mcp_consent::Status::Claimed)
            .collect();
        if !withdrawn.is_empty() {
            self.mcp_sudo.remove_where(|r| withdrawn.contains(&r.id));
        }
        let mut tasks = Vec::new();
        for request in scan.posted {
            let Some(window) = self.mcp_sudo_window(&request) else {
                continue;
            };
            let Some(request) = mcp_consent::claim(&dir, &request.id) else {
                continue;
            };
            tracing::info!(
                target = "oryxis::mcp",
                request = %request.id,
                host = %request.host_label,
                vault = %request.vault_label,
                "sudo approval asked"
            );
            // Raised in that window, so the floating layer is its own
            // (`claim_floats`).
            let vault = request.vault_id;
            let msg = Message::ForVault(vault, Box::new(Message::Mcp(McpMessage::McpSudoClaimed(Box::new(request)))));
            let msg = match window.or_else(crate::app::resident_window_id) {
                Some(w) => Message::InWindow(w, Box::new(msg)),
                None => msg,
            };
            tasks.push(Task::done(msg));
        }
        Task::batch(tasks)
    }

    /// The window to ask `request` in (`None` inside = the resident
    /// one), or `None` when this instance cannot ask it: no window is up
    /// (hidden to the tray), or the request's vault is not open and
    /// unlocked here, so the answer could not be signed. The window the
    /// user works in when it is on that vault; else that window anyway
    /// when ITS vault is unlocked (a locked one draws its lock screen and
    /// no dialog); else a window on the request's vault.
    fn mcp_sudo_window(&self, request: &SudoRequest) -> Option<Option<iced::window::Id>> {
        if self.is_window_hidden || !self.mcp_sudo_vault_unlocked(request.vault_id) {
            return None;
        }
        let input = self.input_window();
        let input_vault = self.vault_of_window(input);
        if input_vault == request.vault_id || self.mcp_sudo_vault_unlocked(input_vault) {
            return Some(input);
        }
        self.window_on_vault(request.vault_id)
    }

    fn mcp_sudo_vault_unlocked(&self, vault: uuid::Uuid) -> bool {
        self.vaults.all().any(|v| {
            v.id == vault
                && v.vault_ui.state == crate::state::VaultState::Unlocked
                && v.store.as_ref().is_some_and(|s| !s.is_locked())
        })
    }

    /// Write the answer to `request`. An allowance is signed with its
    /// vault's key; a vault that cannot sign (locked meanwhile) turns it
    /// into a refusal, never an unsigned allowance.
    pub(crate) fn mcp_sudo_answer(&self, request: &SudoRequest, decision: Decision, reason: Option<DenyReason>) {
        let Some(dir) = mcp_consent::consent_dir() else {
            return;
        };
        let signed = || {
            self.vaults
                .all()
                .find(|v| v.id == request.vault_id)
                .and_then(|v| v.store.as_ref())
                .and_then(|s| s.mcp_consent_tag(request, decision).ok())
        };
        let answer = match (decision.allows(), decision.allows().then(signed).flatten()) {
            (true, Some(tag)) => Answer { decision, reason: None, tag },
            (true, None) => Answer {
                decision: Decision::Deny,
                reason: Some(DenyReason::Locked),
                tag: String::new(),
            },
            (false, _) => Answer { decision: Decision::Deny, reason, tag: String::new() },
        };
        tracing::info!(
            target = "oryxis::mcp",
            request = %request.id,
            host = %request.host_label,
            decision = ?answer.decision,
            reason = ?answer.reason,
            "sudo approval answered"
        );
        if let Err(e) = mcp_consent::answer(&dir, &request.id, &answer) {
            tracing::warn!(target = "oryxis::mcp", request = %request.id, "sudo approval answer not written: {e}");
        }
    }

    /// The update funnel's: a card that reached the screen in this
    /// update is scrolled to its head. The dialog is one scrollable in
    /// one widget slot, and the next queued request takes it inside the
    /// update that answers the one before (an answer, Esc, its deadline,
    /// the vault locking, the server withdrawing it): no frame goes by
    /// with the slot empty, so the card would open at the offset the
    /// previous one was answered at, its buttons on screen and its
    /// host, login and warnings above the fold. In the window that
    /// draws the card (`floats_here`): the handover raises nothing, so
    /// `claim_floats` does not move it.
    pub(crate) fn mcp_sudo_housekeeping(&mut self) -> Option<Task<Message>> {
        if !self.mcp_sudo.came_up() {
            return None;
        }
        let window = self.float_window.filter(|w| {
            self.extra_windows.contains_key(w) || self.window_ctx.as_ref().is_some_and(|c| c.id == *w)
        });
        Some(self.run_in_window(window, |_| {
            iced::widget::operation::scrollable::scroll_to(
                iced::widget::Id::new(crate::views::mcp_sudo::MCP_SUDO_CARD_SCROLL_ID),
                iced::widget::scrollable::AbsoluteOffset { x: 0.0, y: 0.0 },
                iced::widget::operation::Animation::Instant,
            )
        }))
    }

    /// The acting vault is locking (soft or manual) or going away: its
    /// questions are refused, the other vaults' stay up.
    pub(crate) fn mcp_sudo_on_lock(&mut self) {
        let vault = self.vaults.current_id();
        for card in self.mcp_sudo.remove_where(|r| r.vault_id == vault) {
            self.mcp_sudo_answer(&card.request, Decision::Deny, Some(DenyReason::Locked));
        }
    }

    /// The app is quitting or hiding to the tray (`persist_before_exit`):
    /// every question still up is refused, so the server answers its
    /// agent now rather than at its deadline.
    pub(crate) fn mcp_sudo_on_exit(&mut self) {
        for card in self.mcp_sudo.remove_where(|_| true) {
            self.mcp_sudo_answer(&card.request, Decision::Deny, Some(DenyReason::AppClosed));
        }
    }
}
