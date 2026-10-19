//! Settings > AI: the provider, the model, the key, and the toggles.
//!
//! Everything here is one field written and persisted. The key is the
//! exception: it is encrypted per-field like a password, so it is saved
//! through its own arm rather than on every keystroke.

use iced::Task;
use crate::app::{AiMessage, Message, Oryxis};


impl Oryxis {
    pub(super) fn handle_ai_config(&mut self, message: AiMessage) -> Task<Message> {
        match message {
            AiMessage::ToggleAiEnabled => {
                self.vaults.cur_mut().ai.enabled = !self.vaults.cur_mut().ai.enabled;
                // Disabling AI ungates the Chat tab everywhere, taking the
                // Stop / Reset affordances with it; a chat task left running
                // on any tab would have no reachable stop control.
                if !self.vaults.cur().ai.enabled {
                    self.abort_all_chat_tasks();
                }
                if let Some(vault) = &self.vaults.cur().store {
                    let _ = vault.set_setting("ai_enabled", if self.vaults.cur().ai.enabled { "true" } else { "false" });
                }
            }
            AiMessage::ToggleAiSaveHistory => {
                self.vaults.cur_mut().ai.save_history = !self.vaults.cur_mut().ai.save_history;
                if let Some(vault) = &self.vaults.cur().store {
                    let _ = vault.set_setting(
                        "ai_save_history",
                        if self.vaults.cur().ai.save_history { "true" } else { "false" },
                    );
                }
                // Turning it off does NOT delete what is stored: that is a
                // separate, destructive act the user did not ask for, and
                // the History screen already has a delete for it. It does
                // detach the live tabs, so a conversation resumed after the
                // switch comes back on starts a new row instead of
                // appending to one the user thought they had stopped.
                if !self.vaults.cur().ai.save_history {
                    for idx in 0..self.tabs.len() {
                        self.detach_saved_chat(idx);
                    }
                }
            }
            AiMessage::ToggleAiReasoning => {
                self.vaults.cur_mut().ai.reasoning = !self.vaults.cur_mut().ai.reasoning;
                if let Some(vault) = &self.vaults.cur().store {
                    let _ = vault.set_setting(
                        "ai_reasoning",
                        if self.vaults.cur().ai.reasoning { "true" } else { "false" },
                    );
                }
            }
            AiMessage::AiProviderChanged(provider) => {
                // Accept either a display name (from the dropdown) or the
                // internal id. Fall back to keeping the current provider if
                // the value can't be resolved.
                let info = crate::ai::provider_from_display(&provider)
                    .unwrap_or_else(|| crate::ai::provider_info(&provider));
                self.vaults.cur_mut().ai.provider = info.id.to_string();
                if let Some(vault) = &self.vaults.cur().store {
                    let _ = vault.set_setting("ai_provider", &self.vaults.cur().ai.provider);
                }
                // Suggest the provider's default model when the user hasn't
                // picked one. For Custom we keep whatever model is set.
                if !info.default_model.is_empty() {
                    self.vaults.cur_mut().ai.model = info.default_model.into();
                    if let Some(vault) = &self.vaults.cur().store {
                        let _ = vault.set_setting("ai_model", &self.vaults.cur().ai.model);
                    }
                }
                // Presets always use their bundled URL; clear any stale
                // override so Save doesn't carry it across providers.
                if info.kind != crate::ai::ProviderKind::Custom {
                    self.vaults.cur_mut().ai.api_url.clear();
                    if let Some(vault) = &self.vaults.cur().store {
                        let _ = vault.set_setting("ai_api_url", "");
                    }
                }
            }
            AiMessage::AiModelChanged(model) => {
                self.vaults.cur_mut().ai.model = model;
                if let Some(vault) = &self.vaults.cur().store {
                    let _ = vault.set_setting("ai_model", &self.vaults.cur().ai.model);
                }
            }
            AiMessage::AiApiKeyChanged(key) => {
                self.vaults.cur_mut().ai.api_key = key.into_inner();
            }
            AiMessage::AiApiUrlChanged(url) => {
                self.vaults.cur_mut().ai.api_url = url;
                if let Some(vault) = &self.vaults.cur().store {
                    let _ = vault.set_setting("ai_api_url", &self.vaults.cur().ai.api_url);
                }
            }
            AiMessage::AiSystemPromptAction(action) => {
                let was_edit = action.is_edit();
                self.vaults.cur_mut().ai.system_prompt.perform(action);
                if was_edit
                    && let Some(vault) = &self.vaults.cur().store
                {
                    let _ = vault.set_setting("ai_system_prompt", &self.vaults.cur().ai.system_prompt.text());
                }
            }
            AiMessage::SaveAiApiKey => {
                if !self.vaults.cur().ai.api_key.is_empty()
                    && let Some(vault) = &self.vaults.cur().store
                    && vault.set_ai_api_key(&self.vaults.cur().ai.api_key).is_ok() {
                        self.vaults.cur_mut().ai.api_key.clear();
                        self.vaults.cur_mut().ai.api_key_set = true;
                }
            }
            // Routed here by `handle_ai`; anything else is a
            // grouping mistake rather than a runtime case.
            m => return crate::dispatch::unrouted(m),
        }
        Task::none()
    }
}
