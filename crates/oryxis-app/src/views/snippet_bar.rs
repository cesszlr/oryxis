//! The snippet bar (issue #266): one button per snippet marked "show in
//! the snippet bar", under the active tab's panes. A click runs the
//! snippet on the tab in front, a right-click pastes it (no Enter), the
//! same two doors the snippet sidebar offers.
//!
//! It exists only while some snippet carries the mark: no setting turns
//! it on, and there is never an empty bar. Mouse only, like the status
//! bar under it: every snippet already has its keyboard doors (its own
//! chord, the palette, the sidebar's ring), and a ring stop here would
//! sit between the terminal and the keys it is typing.

use iced::Widget as _;
use iced::border::Radius;
use iced::widget::button::Status as BtnStatus;
use iced::widget::{button, column, container, scrollable, text, MouseArea, Space};
use iced::{Background, Border, Color, Element, Length, Padding};

use crate::app::{Message, Oryxis, SnippetMessage};
use crate::i18n::t;
use crate::theme::OryxisColors;
use crate::widgets::dir_row;

/// A button's caption, in characters: past it the label is cut and the
/// full name stays in the tooltip.
const LABEL_MAX: usize = 28;
/// Lines of the command the tooltip previews, each (and the name above
/// them) cut at `PREVIEW_COLS`, which is what bounds the tooltip's width.
const PREVIEW_LINES: usize = 3;
const PREVIEW_COLS: usize = 80;

impl Oryxis {
    /// The bar for the window being drawn, `None` while no snippet of its
    /// vault is marked, and in immersive fullscreen (the terminal alone).
    pub(crate) fn snippet_bar(&self) -> Option<Element<'_, Message>> {
        if self.cur_immersive() {
            return None;
        }
        let mut buttons: Vec<Element<'_, Message>> = Vec::new();
        for snip in self.vaults.cur().snippets.iter().filter(|s| s.show_in_bar) {
            buttons.push(snippet_bar_button(snip));
        }
        if buttons.is_empty() {
            return None;
        }
        // Under RTL the buttons start at the right edge, the tab strip's
        // recipe: `dir_row` mirrors their order, a `Fill` container aligned
        // leading places a bar that fits (inside a horizontal scrollable it
        // resolves to the wider of the viewport and the buttons), and the
        // offset counts from the right (`Anchor::End`).
        let rtl = crate::i18n::is_rtl_layout();
        let strip = scrollable(
            container(dir_row(buttons).spacing(6).align_y(iced::Alignment::Center))
                .width(Length::Fill)
                .align_x(crate::widgets::dir_align_x()),
        )
        .direction(scrollable::Direction::Horizontal(
            scrollable::Scrollbar::new()
                .width(3)
                .scroller_width(3)
                .margin(0)
                .anchor(if rtl { scrollable::Anchor::End } else { scrollable::Anchor::Start }),
        ))
        .width(Length::Fill);
        // A hairline on the top edge only, the status bar's shape: iced's
        // border has one width for all four sides.
        let hairline = container(Space::new().height(1))
            .width(Length::Fill)
            .style(|_: &iced::Theme| container::Style {
                background: Some(Background::Color(OryxisColors::t().border)),
                ..Default::default()
            });
        let body = container(strip)
            .padding(Padding { top: 4.0, right: 8.0, bottom: 4.0, left: 8.0 })
            .width(Length::Fill)
            .style(|_: &iced::Theme| container::Style {
                background: Some(Background::Color(OryxisColors::t().bg_sidebar)),
                ..Default::default()
            });
        Some(column![hairline, body].width(Length::Fill).boxed())
    }
}

/// One snippet's button: the label, hover and press feedback, the click
/// runs, the right-click pastes (a snippet with actions only runs, as in
/// the sidebar), and a tooltip previewing what it sends.
fn snippet_bar_button(snip: &oryxis_core::models::snippet::Snippet) -> Element<'_, Message> {
    let id = snip.id;
    let pastes = !snip.has_steps();
    let btn = button(
        text(crate::util::elide_chars(&snip.label, LABEL_MAX))
            .size(12)
            .color(OryxisColors::t().text_primary),
    )
    .padding(Padding { top: 3.0, right: 10.0, bottom: 3.0, left: 10.0 })
    .on_press(Message::Snippet(SnippetMessage::SnippetBarRun(id)))
    .style(|_, status| {
        let c = OryxisColors::t();
        let bg = match status {
            BtnStatus::Pressed => Color { a: 0.24, ..c.accent },
            BtnStatus::Hovered => c.bg_hover,
            _ => c.bg_surface,
        };
        button::Style {
            background: Some(Background::Color(bg)),
            text_color: c.text_primary,
            border: Border { radius: Radius::from(6.0), color: c.border, width: 1.0 },
            ..Default::default()
        }
    });
    // Always wrapped, so the tree has one shape whichever kind of snippet
    // sits in a slot (widget state is matched by index and type).
    let mut area = MouseArea::new(btn);
    if pastes {
        area = area.on_right_press(Message::Snippet(SnippetMessage::SnippetBarPaste(id)));
    }
    iced::widget::tooltip(
        area,
        snippet_bar_tip(snip, pastes),
        iced::widget::tooltip::Position::Top,
    )
    .boxed()
}

/// The tooltip: the full name, the first lines of what it sends, and
/// which click does what.
fn snippet_bar_tip(
    snip: &oryxis_core::models::snippet::Snippet,
    pastes: bool,
) -> Element<'_, Message> {
    let c = OryxisColors::t();
    let mut lines = snip.command.lines();
    let mut preview: Vec<String> = lines
        .by_ref()
        .take(PREVIEW_LINES)
        .map(|l| crate::util::elide_chars(l, PREVIEW_COLS))
        .collect();
    if lines.next().is_some() {
        preview.push("...".into());
    }
    let hint = if pastes { t("snippet_bar_hint_run_paste") } else { t("snippet_bar_hint_run") };
    container(
        column![
            text(crate::util::elide_chars(&snip.label, PREVIEW_COLS)).size(12).color(c.text_primary),
            text(preview.join("\n"))
                .size(11)
                .font(iced::Font::MONOSPACE)
                .color(c.text_secondary),
            text(hint).size(10).color(c.text_muted),
        ]
        .spacing(4),
    )
    .padding(Padding { top: 6.0, right: 10.0, bottom: 6.0, left: 10.0 })
    .style(|_| container::Style {
        background: Some(Background::Color(OryxisColors::t().bg_surface)),
        border: Border { radius: Radius::from(6.0), color: OryxisColors::t().border, width: 1.0 },
        ..Default::default()
    })
    .boxed()
}
