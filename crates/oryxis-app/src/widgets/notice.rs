//! The notice banner: an operation that failed over a listing that is
//! still valid.
//!
//! A pane has two message slots, and they are not one. `error` means
//! the pane has nothing to show (the connect, the first list or a
//! navigation failed) and the view takes the pane over with the message
//! and a Retry. This banner is the other slot: a transfer, a rename, a
//! delete or a new entry failed, the rows under it are still exactly
//! what is there, and taking them away with a "Retry / Pick another
//! host" screen would tell the user the CONNECTION died. It sits above
//! the listing, stays until dismissed or a navigation elsewhere (a toast
//! would be gone before a user looking elsewhere comes back, and the
//! re-list every failed operation asks for must not take it), and its
//! text is selectable, since the message is what goes into a report.

use iced::Widget as _;
use iced::border::Radius;
use iced::widget::button::Status as BtnStatus;
use iced::widget::{button, container, text, Space};
use iced::{Background, Border, Color, Element, Length, Padding};

use crate::app::Message;
use crate::i18n::t;
use crate::theme::OryxisColors;
use crate::widgets::dir_row;

/// An error-coloured line with an alert icon, the message and a × that
/// sends `on_dismiss`. The caller decides where it goes (always in a
/// slot that is pushed whether or not there is a notice, so the widgets
/// after it keep their state when one lands: issue #241).
pub(crate) fn notice_banner<'a>(message: &str, on_dismiss: Message) -> Element<'a, Message> {
    let c = OryxisColors::t();
    let dismiss = iced::widget::tooltip(
        button(
            container(iced_fonts::lucide::x().size(13).color(c.text_muted))
                .center_x(Length::Fixed(24.0))
                .center_y(Length::Fixed(22.0)),
        )
        .padding(0)
        .on_press(on_dismiss)
        .style(|_, status| {
            let bg = match status {
                BtnStatus::Hovered | BtnStatus::Pressed => OryxisColors::t().bg_hover,
                _ => Color::TRANSPARENT,
            };
            button::Style {
                background: Some(Background::Color(bg)),
                border: Border { radius: Radius::from(4.0), ..Default::default() },
                ..Default::default()
            }
        }),
        container(text(t("close")).size(11).color(c.text_primary))
            .padding(Padding { top: 4.0, right: 8.0, bottom: 4.0, left: 8.0 })
            .style(|_| container::Style {
                background: Some(Background::Color(OryxisColors::t().bg_surface)),
                border: Border {
                    radius: Radius::from(6.0),
                    color: OryxisColors::t().border,
                    width: 1.0,
                },
                ..Default::default()
            }),
        iced::widget::tooltip::Position::Top,
    );
    container(
        dir_row(vec![
            iced_fonts::lucide::circle_alert().size(14).color(c.error).boxed(),
            Space::new().width(8).boxed(),
            text(message.to_string())
                .size(12)
                .selectable(true)
                .color(c.error)
                .width(Length::Fill)
                .boxed(),
            Space::new().width(8).boxed(),
            dismiss.boxed(),
        ])
        .align_y(iced::Alignment::Center),
    )
    .padding(Padding { top: 4.0, right: 4.0, bottom: 4.0, left: 10.0 })
    .width(Length::Fill)
    .style(|_| {
        let c = OryxisColors::t();
        container::Style {
            background: Some(Background::Color(Color { a: 0.10, ..c.error })),
            border: Border {
                radius: Radius::from(6.0),
                color: Color { a: 0.35, ..c.error },
                width: 1.0,
            },
            ..Default::default()
        }
    })
    .boxed()
}
