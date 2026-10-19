//! `Oryxis::handle_proxy_identity`, match arms for the Proxy
//! Identity inline form lives under `Settings → Proxies`. CRUD over
//! reusable proxy configurations referenced from connections via
//! `Connection.proxy_identity_id`.

#![allow(clippy::result_large_err)]

use iced::Task;

use oryxis_core::models::connection::ProxyType;
use oryxis_core::models::proxy_identity::ProxyIdentity;

use crate::app::{ProxyIdentityMessage, Message, Oryxis};
use crate::state::ProxyKind;

impl Oryxis {
    pub(crate) fn handle_proxy_identity(
        &mut self,
        message: ProxyIdentityMessage,
    ) -> Task<Message> {
        match message {
            ProxyIdentityMessage::ShowProxyIdentityForm(maybe_id) => {
                self.overlay = None;
                let ov = self.vaults.cur_mut();
                ov.proxy_identity_form.visible = true;
                ov.proxy_identity_form.error = None;

                if let Some(id) = maybe_id
                    && let Some(pi) = ov.proxy_identities.iter().find(|p| p.id == id)
                {
                    let has_pw = ov
                        .store
                        .as_ref()
                        .and_then(|v| v.get_proxy_identity_password(&id).ok())
                        .flatten()
                        .is_some();
                    ov.proxy_identity_form.editing_id = Some(id);
                    ov.proxy_identity_form.label = pi.label.clone();
                    ov.proxy_identity_form.kind = match &pi.proxy_type {
                        ProxyType::Socks5 => ProxyKind::Socks5,
                        ProxyType::Socks4 => ProxyKind::Socks4,
                        ProxyType::Http => ProxyKind::Http,
                        ProxyType::Command(_) => ProxyKind::Command,
                    };
                    ov.proxy_identity_form.host = pi.host.clone();
                    ov.proxy_identity_form.port = if pi.port == 0 {
                        String::new()
                    } else {
                        pi.port.to_string()
                    };
                    ov.proxy_identity_form.username = pi.username.clone().unwrap_or_default();
                    // Mirror the connection-password UX, never pre-fill the
                    // encrypted password, just flag that one exists so the
                    // user can leave it untouched to preserve.
                    ov.proxy_identity_form.password.clear();
                    ov.proxy_identity_form.has_existing_password = has_pw;
                } else {
                    ov.proxy_identity_form.editing_id = None;
                    ov.proxy_identity_form.label = String::new();
                    ov.proxy_identity_form.kind = ProxyKind::Socks5;
                    ov.proxy_identity_form.host = String::new();
                    ov.proxy_identity_form.port = "1080".into();
                    ov.proxy_identity_form.username = String::new();
                    ov.proxy_identity_form.password.clear();
                    ov.proxy_identity_form.has_existing_password = false;
                }
                ov.proxy_identity_form.password_visible = false;
            }
            ProxyIdentityMessage::HideProxyIdentityForm => {
                self.vaults.cur_mut().proxy_identity_form.visible = false;
                self.vaults.cur_mut().proxy_identity_form.error = None;
            }
            ProxyIdentityMessage::ProxyIdentityFormLabelChanged(v) => {
                self.vaults.cur_mut().proxy_identity_form.label = v;
            }
            ProxyIdentityMessage::ProxyIdentityFormKindChanged(kind) => {
                // The picker only ever feeds back the four wire types
                // (SOCKS5/SOCKS4/HTTP/Command); guarding here keeps the
                // form coherent if a future caller passes None/Identity.
                if matches!(
                    kind,
                    ProxyKind::Socks5 | ProxyKind::Socks4 | ProxyKind::Http | ProxyKind::Command
                ) {
                    self.vaults.cur_mut().proxy_identity_form.kind = kind;
                    if let Some(p) = kind.default_port()
                        && self.vaults.cur().proxy_identity_form.port.is_empty()
                    {
                        self.vaults.cur_mut().proxy_identity_form.port = p.to_string();
                    }
                }
            }
            ProxyIdentityMessage::ProxyIdentityFormHostChanged(v) => {
                self.vaults.cur_mut().proxy_identity_form.host = v;
            }
            ProxyIdentityMessage::ProxyIdentityFormPortChanged(v) => {
                self.vaults.cur_mut().proxy_identity_form.port = v;
            }
            ProxyIdentityMessage::ProxyIdentityFormUsernameChanged(v) => {
                self.vaults.cur_mut().proxy_identity_form.username = v;
            }
            ProxyIdentityMessage::ProxyIdentityFormPasswordChanged(v) => {
                self.vaults.cur_mut().proxy_identity_form.password.set(v.into_inner());
            }
            ProxyIdentityMessage::ProxyIdentityFormPasswordToggleVisibility => {
                self.vaults.cur_mut().proxy_identity_form.password_visible =
                    !self.vaults.cur().proxy_identity_form.password_visible;
            }
            ProxyIdentityMessage::SaveProxyIdentity => {
                let label = self.vaults.cur().proxy_identity_form.label.trim().to_string();
                if label.is_empty() {
                    self.vaults.cur_mut().proxy_identity_form.error =
                        Some(crate::i18n::t("proxy_identity_err_label_required").into());
                    return Task::none();
                }

                // Build the ProxyType based on the chosen kind.
                let proxy_type = match self.vaults.cur().proxy_identity_form.kind {
                    ProxyKind::Socks5 => ProxyType::Socks5,
                    ProxyKind::Socks4 => ProxyType::Socks4,
                    ProxyKind::Http => ProxyType::Http,
                    ProxyKind::Command => {
                        // The Command variant in a *saved* identity needs a
                        // command string; we don't expose a separate field
                        // for it here yet, so reject early instead of
                        // silently storing an empty command.
                        self.vaults.cur_mut().proxy_identity_form.error =
                            Some(crate::i18n::t("proxy_identity_err_command_unsupported").into());
                        return Task::none();
                    }
                    ProxyKind::None | ProxyKind::Identity(_) => {
                        // These can't be the kind of a saved identity itself.
                        self.vaults.cur_mut().proxy_identity_form.error =
                            Some(crate::i18n::t("proxy_identity_err_invalid_kind").into());
                        return Task::none();
                    }
                };

                let port: u16 = match self.vaults.cur().proxy_identity_form.port.parse() {
                    Ok(p) if p > 0 => p,
                    _ => {
                        self.vaults.cur_mut().proxy_identity_form.error =
                            Some(crate::i18n::t("proxy_err_port_invalid").into());
                        return Task::none();
                    }
                };

                if self.vaults.cur().proxy_identity_form.host.trim().is_empty() {
                    self.vaults.cur_mut().proxy_identity_form.error =
                        Some(crate::i18n::t("proxy_err_host_required").into());
                    return Task::none();
                }

                let now = chrono::Utc::now();
                let mut identity = if let Some(id) = self.vaults.cur().proxy_identity_form.editing_id {
                    self.vaults.cur().proxy_identities
                        .iter()
                        .find(|p| p.id == id)
                        .cloned()
                        .unwrap_or_else(|| ProxyIdentity::new(label.clone()))
                } else {
                    ProxyIdentity::new(label.clone())
                };
                identity.label = label;
                identity.proxy_type = proxy_type;
                identity.host = self.vaults.cur().proxy_identity_form.host.clone();
                identity.port = port;
                identity.username = if self.vaults.cur().proxy_identity_form.username.is_empty() {
                    None
                } else {
                    Some(self.vaults.cur().proxy_identity_form.username.clone())
                };
                identity.updated_at = now;

                // Only forward the password to the vault when the user
                // actually edited the field, preserves the existing
                // encrypted value otherwise (mirrors `save_identity`).
                // Tri-state per SecretInput::resolve.
                let password_arg = self.vaults.cur().proxy_identity_form.password.resolve();

                if let Some(vault) = &self.vaults.cur().store {
                    match vault.save_proxy_identity(&identity, password_arg) {
                        Ok(()) => {
                            self.vaults.cur_mut().proxy_identity_form.visible = false;
                            self.vaults.cur_mut().proxy_identity_form.error = None;
                            self.load_data_from_vault();
                        }
                        Err(e) => {
                            self.vaults.cur_mut().proxy_identity_form.error = Some(e.to_string());
                        }
                    }
                }
            }
            ProxyIdentityMessage::DeleteProxyIdentity(id) => {
                if let Some(vault) = &self.vaults.cur().store {
                    let _ = vault.delete_proxy_identity(&id);
                    self.load_data_from_vault();
                }
            }
            ProxyIdentityMessage::ProxySearchChanged(v) => self.nav.proxy_search = v,
        }
        Task::none()
    }
}
