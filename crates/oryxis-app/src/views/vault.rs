//! Vault setup / unlock / error screens.

use iced::Widget as _;
use iced::border::Radius;
use iced::widget::{button, column, container, svg, text, Space};
use iced::{Background, Border, Color, Element, Length, Padding};

use crate::app::{VaultMessage, Message, Oryxis};
use crate::i18n::t;
use crate::theme::{mix, OryxisColors};
use crate::views::chrome::window_chrome_bar;
use crate::widgets::{accent_gradient, styled_button, styled_icon_button};

/// Wrap a vault screen body with the top window chrome so the user can still
/// drag / minimize / maximize / close before unlocking the vault. Also adds
/// the edge-resize border so the lock screen is as resizable as the main app.
pub(crate) fn with_chrome<'a>(body: Element<'a, Message>, maximized: bool) -> Element<'a, Message> {
    // 1 px hairline between the chrome bar and the screen body, matches the
    // separator that sits below the tab bar on the main view.
    let h_separator = iced::widget::container(iced::widget::Space::new().height(1))
        .width(Length::Fill)
        .style(|_| iced::widget::container::Style {
            background: Some(iced::Background::Color(OryxisColors::t().border)),
            ..Default::default()
        });
    let content: Element<'a, Message> =
        iced::widget::column![window_chrome_bar(), h_separator, body]
            .width(Length::Fill)
            .height(Length::Fill)
            .boxed();
    let overlay = if maximized { None } else { Some(crate::views::layout::resize_border()) };
    crate::views::layout::wrap_with_resize(content, overlay)
}

impl Oryxis {
    /// Master-password field. Wraps the shared `password_input_with_eye`
    /// helper with the vault's wider 300 px container and hero-sized
    /// inner padding.
    fn vault_master_password_field<'a>(
        &'a self,
        placeholder: &'a str,
        on_submit: Message,
    ) -> Element<'a, Message> {
        // Carries a focus id so the lock screen can auto-focus it on
        // arrival (boot, manual lock, idle auto-lock): the master
        // password should be typeable without a click.
        container(crate::widgets::password_input_with_eye_id(
            placeholder,
            &self.vault_ui.password_input,
            |v| Message::Vault(VaultMessage::VaultPasswordChanged(v.into())),
            Some(on_submit),
            self.vault_ui.password_visible,
            Message::Vault(VaultMessage::VaultTogglePasswordVisibility),
            12.0,
            Some(iced::widget::Id::new("vault-unlock-password")),
        ))
        .width(300)
        .boxed()
    }

    // The first-run setup screen used to live here as `view_vault_setup`.
    // It is now the final slide of the onboarding carousel
    // (`views/onboarding.rs`), rendered off `VaultState::NeedSetup`.

    pub(crate) fn view_vault_unlock(&self) -> Element<'_, Message> {
        // Biometric-first layout when enrolled (market convention:
        // 1Password / Bitwarden lock screens): the presence check is the
        // primary action, the typed password an explicit fallback revealed
        // by `VaultShowPasswordFallback`. A failed / cancelled OS prompt
        // flips to the fallback automatically (see `BiometricUnlockResult`)
        // so the user is never stuck without an input.
        let bio_first =
            self.biometric_unlock_offered() && !self.vault_ui.password_fallback;

        let logo = svg(self.logo_handle.clone())
            .width(64)
            .height(64);
        let title = text("Oryxis").size(28).color(OryxisColors::t().accent);
        let subtitle = text(crate::i18n::t(if bio_first {
            "biometric_unlock_subtitle"
        } else {
            "enter_password"
        }))
        .size(14)
        .color(OryxisColors::t().text_secondary);

        let unlock_area: Element<'_, Message> = if bio_first {
            let bio_btn = styled_icon_button(
                crate::biometric::bio_icon()
                    .size(14)
                    .color(OryxisColors::t().button_text)
                    .boxed(),
                crate::biometric::bio_unlock_label(),
                Message::Vault(VaultMessage::BiometricUnlockRequested),
                OryxisColors::t().accent,
            );
            // Muted text link to the typed-password form; background tint
            // on hover so it still reads as clickable.
            let fallback_link = button(
                text(crate::i18n::t("use_master_password"))
                    .size(12)
                    .color(OryxisColors::t().text_muted),
            )
            .on_press(Message::Vault(VaultMessage::VaultShowPasswordFallback))
            .padding(Padding { top: 6.0, right: 12.0, bottom: 6.0, left: 12.0 })
            .style(|_, status| {
                let bg = match status {
                    button::Status::Hovered | button::Status::Pressed => {
                        OryxisColors::t().bg_hover
                    }
                    _ => Color::TRANSPARENT,
                };
                button::Style {
                    background: Some(Background::Color(bg)),
                    border: Border { radius: Radius::from(6.0), ..Default::default() },
                    ..Default::default()
                }
            });
            column![bio_btn, Space::new().height(10), fallback_link]
                .align_x(iced::Alignment::Center)
                .boxed()
        } else {
            let input = self.vault_master_password_field(
                crate::i18n::t("master_password_placeholder"),
                Message::Vault(VaultMessage::VaultUnlock),
            );
            let btn = styled_button(
                crate::i18n::t("unlock"),
                Message::Vault(VaultMessage::VaultUnlock),
                OryxisColors::t().accent,
            );
            // On the fallback layout biometrics stay one click away as the
            // secondary affordance (it raises the OS presence prompt
            // off-thread, see `BiometricUnlockRequested`).
            let biometric_btn: Element<'_, Message> = if self.biometric_unlock_offered() {
                column![
                    Space::new().height(8),
                    styled_icon_button(
                        crate::biometric::bio_icon()
                            .size(14)
                            .color(crate::theme::contrast_text_for(OryxisColors::t().bg_hover))
                            .boxed(),
                        crate::biometric::bio_unlock_label(),
                        Message::Vault(VaultMessage::BiometricUnlockRequested),
                        OryxisColors::t().bg_hover,
                    ),
                ]
                .align_x(iced::Alignment::Center)
                .boxed()
            } else {
                Space::new().boxed()
            };
            column![input, Space::new().height(12), btn, biometric_btn]
                .align_x(iced::Alignment::Center)
                .boxed()
        };

        let error = if let Some(err) = &self.vault_ui.error {
            text(err.clone()).size(13).color(OryxisColors::t().error).boxed()
        } else {
            Space::new().boxed()
        };

        let destroy_section: Element<'_, Message> = if self.vault_ui.destroy_confirm {
            column![
                text(crate::i18n::t("vault_destroy_confirm")).size(12).color(OryxisColors::t().error),
                Space::new().height(6),
                styled_button(crate::i18n::t("destroy_vault"), Message::Vault(VaultMessage::VaultDestroy), OryxisColors::t().error),
            ].align_x(iced::Alignment::Center).boxed()
        } else {
            button(
                text(crate::i18n::t("forgot_password")).size(12).color(OryxisColors::t().text_muted),
            )
            .on_press(Message::Vault(VaultMessage::VaultDestroyConfirm))
            .padding(Padding { top: 6.0, right: 12.0, bottom: 6.0, left: 12.0 })
            .style(|_, _| button::Style::default())
            .boxed()
        };

        // The unlock form sits on a gradient card centered on an
        // accent-washed page, sharing the onboarding carousel's design
        // language (see `views/onboarding.rs`): same card chrome (radius 18,
        // 1px border, soft drop shadow) and the same two-layer diagonal
        // accent gradient (`widgets::accent_gradient`).
        let card_inner = column![logo, Space::new().height(16), title, Space::new().height(8), subtitle, Space::new().height(24), unlock_area, Space::new().height(8), error, Space::new().height(16), destroy_section]
            .width(Length::Fill)
            .align_x(iced::Alignment::Center);

        let card = container(card_inner)
            .padding(Padding { top: 48.0, right: 48.0, bottom: 40.0, left: 48.0 })
            .width(Length::Fixed(460.0))
            .style(|_| {
                let base = OryxisColors::t().bg_primary;
                let accent = OryxisColors::t().accent;
                container::Style {
                    background: Some(accent_gradient(mix(base, accent, 0.12), base)),
                    border: Border {
                        radius: Radius::from(18.0),
                        color: OryxisColors::t().border,
                        width: 1.0,
                    },
                    shadow: iced::Shadow {
                        color: Color { a: 0.32, ..Color::BLACK },
                        offset: iced::Vector::new(0.0, 12.0),
                        blur_radius: 40.0,
                    },
                    ..Default::default()
                }
            });

        let body: Element<'_, Message> = container(card)
            .center(Length::Fill)
            .style(|_| {
                let base = OryxisColors::t().bg_sidebar;
                let accent = OryxisColors::t().accent;
                container::Style {
                    background: Some(accent_gradient(mix(base, accent, 0.22), base)),
                    ..Default::default()
                }
            })
            .width(Length::Fill)
            .height(Length::Fill)
            .boxed();
        with_chrome(body, self.cur_maximized())
    }

    /// The screen a boot lands on when `VaultStore::open_default` failed
    /// (`VaultState::Loading` after boot): the reason the engine gave,
    /// the file it was opening and where the debug log goes, every line
    /// selectable so a report can carry them verbatim. No control on
    /// it: the chrome bar above is the way out.
    pub(crate) fn view_vault_open_failed(&self) -> Element<'_, Message> {
        let c = OryxisColors::t();
        let vault_path = oryxis_core::paths::oryxis_dir()
            .map(|d| d.join("vault.db").display().to_string())
            .unwrap_or_else(|| "~/.oryxis/vault.db".to_string());
        let log_path = crate::logging::log_path()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "~/.oryxis/oryxis-debug.log".to_string());
        let mut col = column![
            text(t("vault_open_failed")).size(18).color(c.error),
        ]
        .spacing(10);
        if let Some(reason) = &self.vault_ui.open_error {
            col = col.push(
                text(reason.clone()).size(13).selectable(true).color(c.text_primary).boxed(),
            );
        }
        col = col
            .push(
                text(t("vault_open_failed_file").replace("{path}", &vault_path))
                    .size(13)
                    .selectable(true)
                    .color(c.text_secondary)
                    .boxed(),
            )
            .push(
                text(t(if self.vault_ui.open_read_only {
                    // Refused on purpose, with the reason: see
                    // `VaultUi::open_read_only`.
                    "vault_open_read_only_hint"
                } else {
                    "vault_open_failed_hint"
                }))
                .size(13)
                .color(c.text_secondary)
                .boxed(),
            )
            .push(
                text(t("vault_open_failed_log").replace("{path}", &log_path))
                    .size(13)
                    .selectable(true)
                    .color(c.text_secondary)
                    .boxed(),
            );
        let body: Element<'_, Message> = container(container(col).width(Length::Fixed(640.0)).padding(24))
            .center(Length::Fill)
            .style(|_| container::Style {
                background: Some(Background::Color(OryxisColors::t().bg_primary)),
                ..Default::default()
            })
            .width(Length::Fill)
            .height(Length::Fill)
            .boxed();
        with_chrome(body, self.cur_maximized())
    }

    // -- Main layout --
}
