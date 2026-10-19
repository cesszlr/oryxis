//! How the connection is reached: proxy, jump chain, port forwards,
//! keepalive.
//!
//! The chain editor is a modal over the form (a host can reference other
//! hosts as hops), so its open/close and hop moves live with the field
//! they edit rather than with the editor's own lifecycle.

use super::*;

impl Oryxis {
    pub(super) fn handle_editor_network(&mut self, message: EditorMessage) -> Task<Message> {
        match message {
            EditorMessage::EditorProxyKindChanged(kind) => {
                let prev = self.vaults.cur().editor_form.proxy_kind;
                self.vaults.cur_mut().editor_form.proxy_kind = kind;
                match kind {
                    ProxyKind::Identity(_) => {
                        // Switching to a saved identity, wipe inline state
                        // so a later switch back to Custom starts clean.
                        // The identity carries its own host/port/username/
                        // password, all hydrated by `resolve_proxy` at
                        // connect time.
                        self.vaults.cur_mut().editor_form.proxy_host.clear();
                        self.vaults.cur_mut().editor_form.proxy_port.clear();
                        self.vaults.cur_mut().editor_form.proxy_username.clear();
                        // SecretInput::clear also drops the touched flag,
                        // back to "preserve the stored value".
                        self.vaults.cur_mut().editor_form.proxy_password.clear();
                        self.vaults.cur_mut().editor_form.proxy_command.clear();
                    }
                    _ => {
                        // Coming back from an Identity selection: empty
                        // form, fall through to default-port pre-fill.
                        if matches!(prev, ProxyKind::Identity(_)) {
                            self.vaults.cur_mut().editor_form.proxy_host.clear();
                            self.vaults.cur_mut().editor_form.proxy_port.clear();
                            self.vaults.cur_mut().editor_form.proxy_username.clear();
                            self.vaults.cur_mut().editor_form.proxy_password.clear();
                            self.vaults.cur_mut().editor_form.proxy_command.clear();
                        }
                        // Pre-fill the canonical port for the chosen type
                        // when the field is still blank, saves the user a
                        // hop and is easy to override by typing.
                        if self.vaults.cur().editor_form.proxy_port.is_empty()
                            && let Some(default_port) = kind.default_port()
                        {
                            self.vaults.cur_mut().editor_form.proxy_port = default_port.to_string();
                        }
                    }
                }
            }
            EditorMessage::EditorProxyHostChanged(v) => { self.vaults.cur_mut().editor_form.proxy_host = v; }
            EditorMessage::EditorProxyPortChanged(v) => { self.vaults.cur_mut().editor_form.proxy_port = v; }
            EditorMessage::EditorProxyUsernameChanged(v) => { self.vaults.cur_mut().editor_form.proxy_username = v; }
            EditorMessage::EditorProxyPasswordChanged(v) => {
                self.vaults.cur_mut().editor_form.proxy_password.set(v.into_inner());
            }
            EditorMessage::EditorToggleProxyPasswordVisibility => {
                self.toggle_editor_secret(super::EditorSecret::ProxyPassword);
            }
            EditorMessage::EditorProxyCommandChanged(v) => { self.vaults.cur_mut().editor_form.proxy_command = v; }
            EditorMessage::OpenChainEditor => {
                self.vaults.cur_mut().panels.chain_editor = true;
                self.vaults.cur_mut().chain_editor_adding = false;
                self.vaults.cur_mut().chain_editor_search.clear();
            }
            EditorMessage::CloseChainEditor => {
                self.vaults.cur_mut().panels.chain_editor = false;
                self.vaults.cur_mut().chain_editor_adding = false;
                self.vaults.cur_mut().chain_editor_search.clear();
            }
            EditorMessage::ChainEditorStartAdd => {
                self.vaults.cur_mut().chain_editor_adding = true;
                self.vaults.cur_mut().chain_editor_search.clear();
            }
            EditorMessage::ChainEditorCancelAdd => {
                self.vaults.cur_mut().chain_editor_adding = false;
                self.vaults.cur_mut().chain_editor_search.clear();
            }
            EditorMessage::ChainEditorSearchChanged(v) => {
                self.vaults.cur_mut().chain_editor_search = v;
            }
            EditorMessage::ChainEditorAddHop(id) => {
                // Append the hop, ignoring duplicates so the same host
                // can't appear twice in one chain.
                if !self.vaults.cur().editor_form.jump_chain.contains(&id) {
                    self.vaults.cur_mut().editor_form.jump_chain.push(id);
                }
                self.vaults.cur_mut().chain_editor_adding = false;
                self.vaults.cur_mut().chain_editor_search.clear();
            }
            EditorMessage::ChainEditorRemoveHop(idx) => {
                if idx < self.vaults.cur().editor_form.jump_chain.len() {
                    self.vaults.cur_mut().editor_form.jump_chain.remove(idx);
                }
            }
            EditorMessage::ChainEditorMoveHopUp(idx) => {
                if idx > 0 && idx < self.vaults.cur().editor_form.jump_chain.len() {
                    self.vaults.cur_mut().editor_form.jump_chain.swap(idx, idx - 1);
                }
            }
            EditorMessage::ChainEditorMoveHopDown(idx) => {
                if idx + 1 < self.vaults.cur().editor_form.jump_chain.len() {
                    self.vaults.cur_mut().editor_form.jump_chain.swap(idx, idx + 1);
                }
            }
            EditorMessage::EditorAddPortForward => {
                self.vaults.cur_mut().editor_form.port_forwards.push(PortForwardForm::default());
            }
            EditorMessage::EditorRemovePortForward(i) => {
                if i < self.vaults.cur().editor_form.port_forwards.len() {
                    self.vaults.cur_mut().editor_form.port_forwards.remove(i);
                }
            }
            EditorMessage::EditorPortFwdLocalPortChanged(i, v) => {
                if let Some(pf) = self.vaults.cur_mut().editor_form.port_forwards.get_mut(i) {
                    pf.local_port = v;
                }
            }
            EditorMessage::EditorPortFwdRemoteHostChanged(i, v) => {
                if let Some(pf) = self.vaults.cur_mut().editor_form.port_forwards.get_mut(i) {
                    pf.remote_host = v;
                }
            }
            EditorMessage::EditorPortFwdRemotePortChanged(i, v) => {
                if let Some(pf) = self.vaults.cur_mut().editor_form.port_forwards.get_mut(i) {
                    pf.remote_port = v;
                }
            }
            EditorMessage::EditorKeepaliveChanged(v) => {
                // Digits only; preserve empty (= inherit global). Cap at
                // 86_400s (1 day) like the global setting field, so users
                // can't accidentally type a runaway value.
                let digits: String = v.chars().filter(|c| c.is_ascii_digit()).collect();
                self.vaults.cur_mut().editor_form.keepalive_interval = if digits.is_empty() {
                    String::new()
                } else {
                    let n: u64 = digits.parse().unwrap_or(86_400);
                    n.min(86_400).to_string()
                };
            }
            EditorMessage::EditorMacAddressChanged(v) => {
                // Free text while typing; parse_mac validates on save so
                // a half-typed MAC doesn't fight the user per keystroke.
                self.vaults.cur_mut().editor_form.mac_address = v;
            }
            // Routed here by the parent; anything else is a
            // grouping mistake, not a runtime case.
            m => return crate::dispatch::unrouted(m),
        }
        Task::none()
    }
}
