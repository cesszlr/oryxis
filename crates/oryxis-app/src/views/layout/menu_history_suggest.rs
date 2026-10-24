//! The history-suggest popup (issue #266): commands from the host's
//! history that complete the line being typed, anchored under the start
//! of that line.
//!
//! The password popup's shape (`menu_password_suggest.rs`): it rides the
//! overlay-menu machinery for positioning and chrome but is NOT a menu,
//! records no `RowAction` slots and is not a `modal_nav_surface`; the
//! selection is a local index driven by `handle_history_suggest_key`,
//! because the surface underneath is a live PTY. Rows are uniform here
//! (one command, one line), so the layout counts instead of measuring
//! each row.

use super::*;
use crate::state::HistorySuggestion;
use iced::widget::column;

/// Vertical metrics of the popup. The builder draws by these and
/// [`history_suggest_layout`] sums them, so the height the box is placed
/// by cannot drift from the box that gets painted.
const TITLE_SIZE: f32 = 11.0;
const ROW_SIZE: f32 = 12.0;
const HINT_SIZE: f32 = 10.0;
/// The history glyph, taller than the text beside it, sets the row's
/// height.
const ICON_SIZE: f32 = 14.0;
const TITLE_PAD: Padding = Padding {
    top: 2.0,
    right: 12.0,
    bottom: 4.0,
    left: 12.0,
};
const ROW_PAD: Padding = Padding {
    top: 6.0,
    right: 12.0,
    bottom: 6.0,
    left: 12.0,
};
const HINT_PAD: Padding = Padding {
    top: 4.0,
    right: 12.0,
    bottom: 2.0,
    left: 12.0,
};
/// Gap between rows, and between the title / list / hint.
pub(crate) const HISTORY_SUGGEST_ROW_GAP: f32 = 2.0;
/// The popup never eats more than this much of the window; past it the
/// list scrolls.
const MAX_WINDOW_FRACTION: f32 = 0.6;
/// Width of the box (`overlay_menu_width`). A command line per row, so
/// wider than the credential popup; what does not fit is elided.
pub(crate) const POPUP_WIDTH: f32 = 420.0;
/// Longest command the row prints before eliding: the box is a fixed
/// width and every row is measured as one line.
const ROW_MAX_CHARS: usize = 60;
/// Scrollable id of the row list, so keyboard navigation can drive it.
pub(crate) const SCROLL_ID: &str = "history-suggest-scroll";

/// Drawn height of one text line (iced's default line height, 1.3x,
/// pinned in `main.rs`).
fn line_height(size: f32) -> f32 {
    size * 1.3
}

/// Drawn height of one command row: one text line, never shorter than
/// the glyph beside it.
pub(crate) const HISTORY_SUGGEST_ROW_H: f32 = ROW_PAD.top + ICON_SIZE * 1.3 + ROW_PAD.bottom;

/// Everything in the box that is NOT a row.
fn chrome_height() -> f32 {
    let title = TITLE_PAD.top + line_height(TITLE_SIZE) + TITLE_PAD.bottom;
    let hint = HINT_PAD.top + line_height(HINT_SIZE) + HINT_PAD.bottom;
    2.0 * super::menus::MENU_CHROME_PAD_V + title + hint + 2.0 * HISTORY_SUGGEST_ROW_GAP
}

/// Height of the row list: `rows` rows plus the gaps between them.
fn rows_height(rows: usize) -> f32 {
    rows as f32 * HISTORY_SUGGEST_ROW_H + rows.saturating_sub(1) as f32 * HISTORY_SUGGEST_ROW_GAP
}

/// Resolved vertical layout of the popup for `rows` rows in a window
/// `window_h` tall. Same contract as the password popup's: a full row
/// always fits, however short the window gets.
pub(crate) fn history_suggest_layout(rows: usize, window_h: f32) -> super::menu_password_suggest::PopupLayout {
    use super::menu_password_suggest::PopupLayout;
    let chrome = chrome_height();
    let natural = chrome + rows_height(rows);
    let cap = (window_h * MAX_WINDOW_FRACTION).max(chrome + HISTORY_SUGGEST_ROW_H);
    if natural <= cap {
        return PopupLayout {
            total: natural,
            rows_viewport: None,
        };
    }
    let viewport = cap - chrome;
    PopupLayout {
        total: chrome + viewport,
        rows_viewport: Some(viewport),
    }
}

/// One line of the command, elided past [`ROW_MAX_CHARS`]. A newline
/// inside a multi-line command is shown as a space so the row stays one
/// line (the layout measures it as one).
fn row_text(command: &str) -> String {
    let flat: String = command
        .chars()
        .map(|c| if c == '\n' || c == '\t' { ' ' } else { c })
        .collect();
    if flat.chars().count() <= ROW_MAX_CHARS {
        return flat;
    }
    let head: String = flat.chars().take(ROW_MAX_CHARS - 1).collect();
    format!("{head}\u{2026}")
}

impl Oryxis {
    /// Borrows nothing: every label is cloned into an owned widget, like
    /// the password popup's builder.
    pub(crate) fn build_menu_history_suggest(
        &self,
        entries: &[HistorySuggestion],
        typed: &str,
        selected: Option<usize>,
    ) -> Element<'static, Message> {
        let title = container(
            text(crate::i18n::t("history_suggest_title"))
                .size(TITLE_SIZE)
                .wrapping(iced::widget::text::Wrapping::None)
                .color(OryxisColors::t().text_muted),
        )
        .padding(TITLE_PAD)
        .width(Length::Fill)
        .align_x(dir_align_x());

        let mut list = iced::widget::Column::<iced::Element<'_, _>>::new()
            .spacing(HISTORY_SUGGEST_ROW_GAP)
            .width(Length::Fill);

        for (idx, entry) in entries.iter().enumerate() {
            let is_selected = selected == Some(idx);
            // The part already typed reads muted and the rest stands
            // out, so the row says what a pick will ADD; a containing
            // match (the typed text somewhere inside) is shown whole.
            let shown = row_text(&entry.command);
            let label: Element<'static, Message> = if entry.extends_typed
                && shown.starts_with(typed)
                && shown.len() > typed.len()
            {
                let typed_span: iced::widget::text::Span<'static, ()> =
                    iced::widget::text::Span::new(typed.to_string())
                        .color(OryxisColors::t().text_muted);
                let rest_span: iced::widget::text::Span<'static, ()> =
                    iced::widget::text::Span::new(shown[typed.len()..].to_string())
                        .color(OryxisColors::t().text_primary);
                iced::widget::text::Rich::<'static, (), Message>::with_spans([typed_span, rest_span])
                    .size(ROW_SIZE)
                    .wrapping(iced::widget::text::Wrapping::None)
                    .boxed()
            } else {
                text(shown)
                    .size(ROW_SIZE)
                    .wrapping(iced::widget::text::Wrapping::None)
                    .color(OryxisColors::t().text_primary)
                    .boxed()
            };
            let row: Element<'static, Message> = button(
                container(
                    dir_row(vec![
                        iced_fonts::lucide::history()
                            .size(ICON_SIZE)
                            .color(if is_selected {
                                OryxisColors::t().accent
                            } else {
                                OryxisColors::t().text_secondary
                            })
                            .boxed(),
                        Space::new().width(8).boxed(),
                        label,
                    ])
                    .align_y(iced::Alignment::Center),
                )
                .width(Length::Fill)
                .align_x(dir_align_x()),
            )
            // A click completes the line (never runs it): the row's own
            // index rides the message, since a popup that opens under a
            // resting pointer sees no hover.
            .on_press(Message::Terminal(TerminalMessage::HistorySuggestPick(idx, false)))
            .width(Length::Fill)
            .padding(ROW_PAD)
            .style(move |_, status| {
                let bg = if is_selected
                    || matches!(
                        status,
                        iced::widget::button::Status::Hovered
                            | iced::widget::button::Status::Pressed
                    ) {
                    OryxisColors::t().bg_hover
                } else {
                    Color::TRANSPARENT
                };
                button::Style {
                    background: Some(Background::Color(bg)),
                    border: Border {
                        radius: Radius::from(4.0),
                        ..Default::default()
                    },
                    ..Default::default()
                }
            })
            .boxed();
            // No hover wiring, on purpose (see the password popup):
            // `selected` is the keyboard's alone, so Enter never
            // accepts a row the mouse merely brushed.
            list = list.push(row);
        }

        let hint = container(
            text(crate::i18n::t("history_suggest_hint"))
                .size(HINT_SIZE)
                .color(OryxisColors::t().text_muted),
        )
        .padding(HINT_PAD)
        .width(Length::Fill)
        .align_x(dir_align_x());

        let layout = history_suggest_layout(entries.len(), self.cur_window_size().height);
        let list: Element<'static, Message> = match layout.rows_viewport {
            Some(h) => iced::widget::scrollable(list)
                .id(iced::widget::Id::new(SCROLL_ID))
                .width(Length::Fill)
                .height(Length::Fixed(h))
                .on_scroll(|scroll| {
                    Message::Terminal(TerminalMessage::HistorySuggestScrolled(
                        scroll.viewport.absolute_offset().y,
                    ))
                })
                .boxed(),
            None => list.boxed(),
        };

        column![title, list, hint]
            .spacing(HISTORY_SUGGEST_ROW_GAP)
            .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A window tall enough that the cap never bites.
    const ROOMY: f32 = 750.0;

    #[test]
    fn every_row_adds_its_own_pitch() {
        let one = history_suggest_layout(1, ROOMY).total;
        let two = history_suggest_layout(2, ROOMY).total;
        assert!((two - one - (HISTORY_SUGGEST_ROW_H + HISTORY_SUGGEST_ROW_GAP)).abs() < 0.01);
        assert!(history_suggest_layout(2, ROOMY).rows_viewport.is_none());
        // The full popup (eight rows) fits a 750 px window without
        // scrolling: that is the ordinary case and it must not scroll.
        assert!(history_suggest_layout(crate::dispatch_history_suggest::MAX_ROWS, ROOMY)
            .rows_viewport
            .is_none());
    }

    #[test]
    fn a_short_window_caps_the_list_and_keeps_one_whole_row() {
        let l = history_suggest_layout(8, 200.0);
        let vp = l.rows_viewport.expect("a capped list must scroll");
        assert!(vp >= HISTORY_SUGGEST_ROW_H, "one whole row must fit, got {vp}");
        assert!((l.total - chrome_height() - vp).abs() < 0.01);
        assert!(vp < rows_height(8));
    }

    #[test]
    fn a_row_prints_one_line_and_elides_past_the_box() {
        assert_eq!(row_text("ls -la"), "ls -la");
        assert_eq!(row_text("echo a\n\tb"), "echo a  b");
        let long = "x".repeat(200);
        let shown = row_text(&long);
        assert_eq!(shown.chars().count(), ROW_MAX_CHARS);
        assert!(shown.ends_with('\u{2026}'));
    }
}
