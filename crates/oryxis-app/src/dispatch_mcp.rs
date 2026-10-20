//! `Oryxis::handle_mcp`: settings-panel-independent dispatch arms for the
//! mcp area, split out of dispatch.rs. Returns `Err(message)` for anything
//! it doesn't claim so the try_handler! chain falls through.
#![allow(clippy::result_large_err)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::collapsible_match)]
#![allow(clippy::too_many_lines)]

use iced::Task;

use crate::app::{McpMessage, PluginMessage, Message, Oryxis};
use crate::mcp::{install_mcp_config_to_file, install_mcp_config_to_wsl, mcp_config_snippet, mcp_config_snippet_wsl};

impl Oryxis {
    pub(crate) fn handle_mcp(
        &mut self,
        message: McpMessage,
    ) -> Task<Message> {
        match message {
            // ── MCP ──
            McpMessage::ToggleMcpServer => {
                self.vaults.cur_mut().mcp.server_enabled = !self.vaults.cur_mut().mcp.server_enabled;
                if let Some(vault) = &self.vaults.cur().store {
                    let _ = vault.set_setting("mcp_server_enabled", if self.vaults.cur().mcp.server_enabled { "true" } else { "false" });
                }
                // With several vaults every vault gets a token when its
                // MCP goes on: `oryxis-mcp` serves a tokenless vault only
                // to a config from before there were several (a client
                // configured for one vault must not reach another).
                if self.vaults.cur().mcp.server_enabled {
                    self.mcp_ensure_token_with_several_vaults();
                }
                // MCP ships as a plugin (~5 MB binary external clients
                // like Claude Desktop spawn). First-time enable triggers
                // the install modal; an already-installed plugin or a
                // dev binary on the side both make this a no-op.
                if self.vaults.cur().mcp.server_enabled
                    && !crate::mcp_install::is_installed()
                    && !crate::dispatch_plugins::dev_binary_present("mcp")
                {
                    return Task::done(Message::Plugin(PluginMessage::ShowPluginInstallModal(
                        "mcp".to_string(),
                    )));
                }
            }
            McpMessage::ToggleMcpAllowWrites => {
                self.vaults.cur_mut().mcp.allow_writes = !self.vaults.cur_mut().mcp.allow_writes;
                self.persist_setting(
                    "mcp_server_allow_writes",
                    if self.vaults.cur().mcp.allow_writes { "true" } else { "false" },
                );
            }
            McpMessage::ShowMcpInfo => {
                self.vaults.cur_mut().mcp.show_info = true;
                self.vaults.cur_mut().mcp.config_copied = false;
                return self.mcp_detect_clients();
            }
            McpMessage::HideMcpInfo => {
                self.vaults.cur_mut().mcp.show_info = false;
                self.vaults.cur_mut().mcp.config_copied = false;
            }
            McpMessage::CopyMcpConfig => {
                self.mcp_ensure_token_with_several_vaults();
                self.vaults.cur_mut().mcp.config_copied = true;
                let secrets = self.mcp_secrets();
                let client = self.vaults.cur().mcp.client;
                let snippet = if self.vaults.cur().mcp.target_wsl {
                    mcp_config_snippet_wsl(client, &secrets)
                } else {
                    mcp_config_snippet(client, &secrets)
                };
                return iced::clipboard::write(snippet).discard();
            }
            McpMessage::InstallMcpConfig => {
                // The button is inert for a client not detected, but the
                // keyboard row (and anything else that sends this) is not
                // the button: Claude Code's config sits in `~`, a folder
                // that always exists, so the write's own folder test
                // cannot stand in for the detection.
                if !self.vaults.cur().mcp.detected.contains(&self.vaults.cur().mcp.client) {
                    return Task::none();
                }
                self.mcp_ensure_token_with_several_vaults();
                self.vaults.cur_mut().mcp.install_status = None;
                let secrets = self.mcp_secrets();
                let wsl = self.vaults.cur().mcp.target_wsl;
                let client = self.vaults.cur().mcp.client;
                return Task::perform(
                    async move {
                        if wsl {
                            install_mcp_config_to_wsl(client, &secrets)
                        } else {
                            install_mcp_config_to_file(client, &secrets)
                        }
                    },
                    |v| Message::Mcp(McpMessage::InstallMcpConfigResult(v)),
                );
            }
            McpMessage::SetMcpTarget(is_wsl) => {
                self.vaults.cur_mut().mcp.target_wsl = is_wsl;
                // The Copy / Install feedback from the previous target no
                // longer reflects what's on screen, and neither does the
                // detection: the distro has its own set of clients.
                self.vaults.cur_mut().mcp.config_copied = false;
                self.vaults.cur_mut().mcp.install_status = None;
                return self.mcp_detect_clients();
            }
            McpMessage::SetMcpClient(client) => {
                self.vaults.cur_mut().mcp.client = client;
                self.vaults.cur_mut().mcp.config_copied = false;
                self.vaults.cur_mut().mcp.install_status = None;
            }
            McpMessage::McpClientsDetected { wsl, found, markers } => {
                // An answer for the other target is stale: the toggle
                // moved while the distro was being asked.
                if wsl != self.vaults.cur().mcp.target_wsl {
                    return Task::none();
                }
                self.vaults.cur_mut().mcp.detecting = false;
                self.vaults.cur_mut().mcp.detected = found;
                self.vaults.cur_mut().mcp.wsl_markers = markers;
                // A client that cannot exist on this target (the desktop
                // app inside a distro) falls back to the default row.
                if self.vaults.cur().mcp.target_wsl
                    && !crate::mcp_clients::McpClient::available_in_wsl().contains(&self.vaults.cur().mcp.client)
                {
                    self.vaults.cur_mut().mcp.client = crate::mcp_clients::McpClient::default();
                }
            }
            McpMessage::InstallMcpConfigResult(result) => {
                self.vaults.cur_mut().mcp.install_status = Some(result);
            }
            McpMessage::RegenerateMcpToken => {
                let mut bytes = [0u8; 32];
                getrandom::fill(&mut bytes)
                    .expect("OS RNG unavailable");
                let mut token = String::with_capacity(64);
                for b in bytes {
                    use std::fmt::Write as _;
                    let _ = write!(token, "{b:02x}");
                }
                self.persist_setting("mcp_server_token", &token);
                self.vaults.cur_mut().mcp.server_token = token;
                // Reveal once after regenerating so the user can copy
                // it without an extra click; flip it back to masked
                // explicitly via `ToggleMcpTokenVisibility`. Not when
                // the snippet embeds the master password: the one Show
                // governs both, and the user asked for a token, not to
                // see that.
                self.vaults.cur_mut().mcp.token_visible = !self.vaults.cur_mut().mcp.include_vault_password;
                // The Claude config on disk still carries the old
                // token, prompt the user to re-install.
                self.vaults.cur_mut().mcp.install_status = None;
            }
            McpMessage::ToggleMcpTokenVisibility => {
                self.vaults.cur_mut().mcp.token_visible = !self.vaults.cur_mut().mcp.token_visible;
            }
            McpMessage::CopyMcpToken => {
                return iced::clipboard::write(self.vaults.cur().mcp.server_token.clone()).discard();
            }
            McpMessage::McpVaultPwPromptOpen => {
                self.vaults.cur_mut().mcp.vault_pw_prompt = Some(String::new());
                self.vaults.cur_mut().mcp.vault_pw_error = false;
            }
            McpMessage::McpVaultPwPromptCancel => {
                self.vaults.cur_mut().mcp.vault_pw_prompt = None;
                self.vaults.cur_mut().mcp.vault_pw_error = false;
            }
            McpMessage::McpVaultPwInput(v) => {
                if let Some(buf) = &mut self.vaults.cur_mut().mcp.vault_pw_prompt {
                    *buf = v;
                }
            }
            McpMessage::McpVaultPwConfirm => {
                let Some(typed) = self.vaults.cur().mcp.vault_pw_prompt.clone() else {
                    return Task::none();
                };
                let ok = self
                    .vaults.cur().store
                    .as_ref()
                    .map(|v| v.verify_password(&typed).unwrap_or(false))
                    .unwrap_or(false);
                if ok {
                    // Persist the CONSENT, never the password: snippets
                    // and installs read it from `master_password` at use
                    // time. Refresh that copy from the verified input so
                    // the embed can't go stale.
                    self.vaults.cur_mut().mcp.include_vault_password = true;
                    // The one Show governs the token AND the password it
                    // now embeds, and the user asked to embed it, not to
                    // see it: same rule as the regenerate arm.
                    self.vaults.cur_mut().mcp.token_visible = false;
                    self.persist_setting("mcp_config_vault_pw", "true");
                    self.vaults.cur_mut().master_password = Some(typed);
                    self.vaults.cur_mut().mcp.vault_pw_prompt = None;
                    self.vaults.cur_mut().mcp.vault_pw_error = false;
                    // The snippet content changed; stale Copy / Install
                    // feedback would claim the on-disk config already
                    // carries it.
                    self.vaults.cur_mut().mcp.config_copied = false;
                    self.vaults.cur_mut().mcp.install_status = None;
                } else {
                    self.vaults.cur_mut().mcp.vault_pw_error = true;
                    if let Some(buf) = &mut self.vaults.cur_mut().mcp.vault_pw_prompt {
                        buf.clear();
                    }
                }
            }
            McpMessage::McpVaultPwRemove => {
                self.vaults.cur_mut().mcp.include_vault_password = false;
                self.persist_setting("mcp_config_vault_pw", "false");
                self.vaults.cur_mut().mcp.config_copied = false;
                self.vaults.cur_mut().mcp.vault_pw_strip_status = None;
                // Actively scrub the plaintext password from EVERY config
                // that carries it (native + WSL), in place and off the UI
                // thread. Flipping the consent alone would leave the
                // credential in `~/.claude.json` while the UI claims it was
                // revoked; and scrubbing only the currently-selected target
                // would miss a copy installed into the other one. The strip
                // is presence-gated per target, so it never creates a
                // config nor promotes the legacy dead-letter.
                let secrets = self.mcp_secrets();
                return Task::perform(
                    async move { crate::mcp::strip_vault_password_everywhere(&secrets) },
                    |v| Message::Mcp(McpMessage::McpVaultPwStripResult(v)),
                );
            }
            McpMessage::McpVaultPwStripResult(res) => {
                self.vaults.cur_mut().mcp.vault_pw_strip_status = Some(res);
            }
        }
        Task::none()
    }
}

impl Oryxis {
    /// With several vaults registered, give the acting vault a token
    /// when it has none: a config written now names vaults by slug, and
    /// `oryxis-mcp` serves a tokenless vault to such a config only when
    /// named by `--vault`.
    fn mcp_ensure_token_with_several_vaults(&mut self) {
        if self.vault_count() > 1 && self.vaults.cur().mcp.server_token.is_empty() {
            let _ = self.handle_mcp(McpMessage::RegenerateMcpToken);
        }
    }

    /// Ask which AI clients are installed for the current target, off
    /// the UI thread: the native check is a few `stat`s, the WSL one a
    /// `wsl.exe` spawn. The answer carries the target it was asked
    /// about so a toggle flipped meanwhile drops it.
    fn mcp_detect_clients(&mut self) -> Task<Message> {
        self.vaults.cur_mut().mcp.detecting = true;
        let wsl = self.vaults.cur().mcp.target_wsl;
        Task::perform(
            async move {
                if wsl {
                    let (found, markers) = crate::mcp::detect_wsl_clients();
                    (found, markers)
                } else {
                    (crate::mcp::detect_native_clients(), Vec::new())
                }
            },
            move |(found, markers)| Message::Mcp(McpMessage::McpClientsDetected { wsl, found, markers }),
        )
    }
}
