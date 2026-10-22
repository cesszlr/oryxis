//! "Let sudo use the password stored for this host?": the question
//! `oryxis-mcp` puts to the person before it hands a host's stored
//! password to `sudo` for an AI client (`dispatch_mcp_sudo`).
//!
//! Everything the decision rests on is spelled out: which client (in
//! its own words, which is all there is), which vault and host, the
//! route the dial takes, the login whose password goes, and the command
//! verbatim. Nothing here is redacted under Privacy Mode, like the
//! command-proxy prompt: approving what nobody can read is a click, not
//! an approval.

use iced::Widget as _;
use iced::border::Radius;
use iced::widget::{column, container, scrollable, text, Space};
use iced::{Background, Border, Element, Length};

use oryxis_vault::mcp_consent::Decision;

use crate::app::{Message, Oryxis};
use crate::i18n::t;
use crate::messages::McpMessage;
use crate::state::McpSudoCard;
use crate::theme::OryxisColors;
use crate::widgets::{dir_row, panel_field, styled_button};

impl Oryxis {
    /// The dialog for the request on screen. Deny is the default row
    /// (Enter refuses unless the ring moved), and Esc / a click outside
    /// refuse too (`Modal::McpSudoConfirm`).
    pub(crate) fn build_mcp_sudo_dialog<'a>(&'a self, card: &'a McpSudoCard) -> Element<'a, Message> {
        self.modal_nav_reset();
        let r = &card.request;
        let value = |s: String| -> Element<'a, Message> {
            text(s).size(13).color(OryxisColors::t().text_primary).boxed()
        };

        let mut info = column![
            text(t("mcp_sudo_title")).size(16).color(OryxisColors::t().warning),
            Space::new().height(6),
            text(t("mcp_sudo_body")).size(13).color(OryxisColors::t().text_secondary),
            Space::new().height(12),
        ];
        if let Some(client) = &r.client {
            info = info.push(panel_field(t("mcp_sudo_client"), value(client.clone())));
            info = info.push(Space::new().height(8).boxed());
        }
        info = info
            // The name this app shows for it: the request's label is the
            // server's, which falls back to the slug.
            .push(panel_field(t("vault"), value(self.vault_name(r.vault_id))))
            .push(Space::new().height(8).boxed())
            .push(panel_field(t("host"), value(format!("{} ({})", r.host_label, r.address))))
            .push(Space::new().height(8).boxed());
        if !r.route.is_empty() {
            info = info
                .push(panel_field(t("mcp_sudo_route"), value(r.route.join(" → "))))
                .push(Space::new().height(8).boxed());
        }
        info = info
            .push(panel_field(t("username"), value(r.login.clone())))
            .push(Space::new().height(8).boxed())
            .push(panel_field(
                t("mcp_sudo_command"),
                container(
                    // Always a scrollable (the tree keeps its shape from
                    // one request to the next); a long command scrolls
                    // inside a fixed box instead of pushing the buttons
                    // off the screen.
                    scrollable(
                        text(r.command.clone())
                            .size(12)
                            .font(iced::Font::MONOSPACE)
                            .color(OryxisColors::t().text_primary),
                    )
                    .width(Length::Fill)
                    .height(command_box_height(&r.command)),
                )
                .width(Length::Fill)
                .padding(10)
                .style(|_: &iced::Theme| container::Style {
                    background: Some(Background::Color(OryxisColors::t().bg_sidebar)),
                    border: Border {
                        radius: Radius::from(6.0),
                        color: OryxisColors::t().border,
                        width: 1.0,
                    },
                    ..Default::default()
                })
                .boxed(),
            ))
            .push(Space::new().height(10).boxed())
            .push(text(t("mcp_sudo_session_note")).size(12).color(OryxisColors::t().text_muted).boxed());

        let answer = |d: Decision| Message::Mcp(McpMessage::McpSudoAnswered(d));
        let buttons = dir_row(vec![
            self.modal_nav_slot_default(
                crate::keynav::RowAction::activate(answer(Decision::Deny)),
                6.0,
                true,
                styled_button(t("mcp_sudo_deny"), answer(Decision::Deny), OryxisColors::t().error),
            ),
            Space::new().width(Length::Fill).boxed(),
            self.modal_nav_slot(
                crate::keynav::RowAction::activate(answer(Decision::Once)),
                6.0,
                false,
                styled_button(t("mcp_sudo_once"), answer(Decision::Once), OryxisColors::t().bg_hover),
            ),
            Space::new().width(8).boxed(),
            self.modal_nav_slot(
                crate::keynav::RowAction::activate(answer(Decision::Session)),
                6.0,
                false,
                styled_button(t("mcp_sudo_session"), answer(Decision::Session), OryxisColors::t().accent),
            ),
        ]);

        container(
            column![info, Space::new().height(16), buttons]
                .padding(24)
                .width(520),
        )
        .style(|_: &iced::Theme| container::Style {
            background: Some(Background::Color(OryxisColors::t().bg_surface)),
            border: Border { radius: Radius::from(12.0), color: OryxisColors::t().border, width: 1.0 },
            ..Default::default()
        })
        .boxed()
    }
}

/// The command box's height: its own for a short command, a fixed
/// 160 px (about ten lines) past that, scrolled.
fn command_box_height(command: &str) -> Length {
    let lines: usize = command.lines().map(|l| 1 + l.chars().count() / 60).sum();
    if lines > 10 { Length::Fixed(160.0) } else { Length::Shrink }
}
