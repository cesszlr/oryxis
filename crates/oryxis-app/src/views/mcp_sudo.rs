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
//!
//! The command is the agent's text, and the agent is what the person is
//! judging, so the dialog never shows it in part: the whole command is
//! drawn (long tokens broken at the glyph), its line and character
//! count is said beside it, the paste guard's content warnings (hidden
//! or bidirectional characters, raw control sequences, a download piped
//! into a shell, a homograph) stand above it, and the buttons come AFTER
//! the last line. When the card outgrows the window the card itself
//! scrolls, so reaching Allow with the mouse means passing the tail; a
//! command box of a fixed height would let a benign first line sit over
//! forty blank ones and the payload below the fold.

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
use crate::widgets::{dir_align_x, dir_row, panel_field, styled_button};

/// The card's scrollable, for the scroll back to its head when the next
/// request takes the screen (`mcp_sudo_housekeeping`).
pub(crate) const MCP_SUDO_CARD_SCROLL_ID: &str = "mcp-sudo-card-scroll";

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
        let c = OryxisColors::t();
        let size = crate::state::command_size(&r.command);
        let command_label = crate::i18n::t_fill(
            "mcp_sudo_command_size",
            &[
                ("lines", &crate::i18n::line_count(size.lines)),
                ("chars", &crate::i18n::char_count(size.chars)),
            ],
        );
        // One row per content warning (`paste_guard`), the careful-paste
        // dialog's shape; the column is always pushed, empty when the
        // command is clean.
        let mut warnings = iced::widget::Column::<Element<'_, Message>>::new().spacing(4);
        for w in crate::paste_guard::paste_warnings(&r.command) {
            warnings = warnings.push(
                dir_row(vec![
                    iced_fonts::lucide::triangle_alert().size(13).color(c.error).boxed(),
                    Space::new().width(6).boxed(),
                    container(text(t(w.label_key())).size(12).color(c.error))
                        .width(Length::Fill)
                        .boxed(),
                ])
                .align_y(iced::Alignment::Center)
                .boxed(),
            );
        }
        let command_block = column![
            text(command_label).size(12).color(c.text_muted),
            Space::new().height(4),
            warnings,
            Space::new().height(4),
            container(
                // The whole command, a long token broken at the glyph
                // so nothing hides past the right edge either.
                text(r.command.clone())
                    .size(12)
                    .font(iced::Font::MONOSPACE)
                    .wrapping(iced::widget::text::Wrapping::WordOrGlyph)
                    .color(c.text_primary),
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
            }),
        ]
        .width(Length::Fill)
        .align_x(dir_align_x());
        info = info
            .push(panel_field(t("username"), value(r.login.clone())))
            .push(Space::new().height(8).boxed())
            .push(command_block.boxed())
            .push(Space::new().height(10).boxed())
            .push(text(t("mcp_sudo_session_note")).size(12).color(c.text_muted).boxed());

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

        // The card is one scrollable, title to buttons: a short command
        // takes its own height, a long one makes the card as tall as the
        // window and scrolls, the buttons after the command's last line.
        // Always a scrollable, so the tree keeps its shape from one
        // request to the next; the same slot keeps the offset too, and a
        // queued request taking the screen is scrolled back to its head
        // by id (`mcp_sudo_housekeeping`), or it would open on the
        // buttons of a card whose head nobody read.
        container(
            scrollable(
                column![info, Space::new().height(16), buttons]
                    .padding(24)
                    .width(Length::Fill),
            )
            .id(iced::widget::Id::new(MCP_SUDO_CARD_SCROLL_ID))
            .width(Length::Fill)
            .height(Length::Shrink),
        )
        .width(520)
        .style(|_: &iced::Theme| container::Style {
            background: Some(Background::Color(OryxisColors::t().bg_surface)),
            border: Border { radius: Radius::from(12.0), color: OryxisColors::t().border, width: 1.0 },
            ..Default::default()
        })
        .boxed()
    }
}
