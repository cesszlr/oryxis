//! Cursor blink, kept by the widget itself.
//!
//! The emulator only carries the BIT (`CursorStyle::blinking`, from the
//! user's default or the program's DECSCUSR / DECSET 12); the phase is
//! the frontend's. It lives here rather than on an app ticker because a
//! ticker would run `update` and rebuild the whole view twice a second
//! for one caret: the widget asks the runtime for a redraw at the next
//! flip (`request_redraw_at`, the way iced's own `text_input` blinks its
//! caret), and only this canvas redraws.
//!
//! Only the focused pane of a focused window blinks. A key, an input
//! method event, output (the render epoch moving) and the window coming
//! back each restart the run with the caret solid, and a run with
//! nothing happening RESTS solid after [`BLINK_REST_AFTER`] and asks for
//! no more frames, as GNOME's terminals and alacritty do.

use super::*;
use std::time::{Duration, Instant};

/// Half a blink cycle: the caret is on this long, then off this long.
/// CHOSEN (GNOME's `cursor-blink-time` of 1200 ms per cycle), not read
/// from the OS.
pub(super) const BLINK_HALF: Duration = Duration::from_millis(600);

/// How long a run blinks with nothing happening before the caret rests
/// solid. CHOSEN (GNOME's `cursor-blink-timeout`, 10 s; alacritty's
/// `blink_timeout` is 5 s).
pub(super) const BLINK_REST_AFTER: Duration = Duration::from_secs(10);

/// The phase of a run that began `elapsed` ago: whether the caret is in
/// its OFF half, and how long until the next change (a flip, or the
/// rest). `None` once the run rests: no more frames are needed.
pub(super) fn blink_phase(elapsed: Duration) -> (bool, Option<Duration>) {
    if elapsed >= BLINK_REST_AFTER {
        return (false, None);
    }
    let halves = elapsed.as_nanos() / BLINK_HALF.as_nanos();
    let off = halves % 2 == 1;
    // `halves` is bounded by REST / HALF, far inside a u32.
    let next_flip = BLINK_HALF * (halves as u32 + 1) - elapsed;
    (off, Some(next_flip.min(BLINK_REST_AFTER - elapsed)))
}

/// What the caret paints as, given the shape the emulator reports and
/// the blink's phase. `Hidden` is the program's DECTCEM off (`tput
/// civis`, htop, a progress bar): nothing is drawn, never a dimmed block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CaretPaint {
    Nothing,
    Block,
    Bar,
    Underline,
    Hollow,
}

pub(super) fn caret_paint(shape: CursorShape, blink_off: bool) -> CaretPaint {
    if blink_off {
        return CaretPaint::Nothing;
    }
    match shape {
        CursorShape::Block => CaretPaint::Block,
        CursorShape::Beam => CaretPaint::Bar,
        CursorShape::Underline => CaretPaint::Underline,
        CursorShape::HollowBlock => CaretPaint::Hollow,
        CursorShape::Hidden => CaretPaint::Nothing,
    }
}

impl<Message> TerminalView<Message> {
    /// The blink's share of `on_event`. `Some(result)` ends the event
    /// there (the window events nothing else in the widget reads),
    /// `None` lets it go on to the rest of `on_event`.
    pub(super) fn on_cursor_blink(
        &self,
        widget_state: &mut TerminalWidgetState,
        event: &iced::Event,
    ) -> Option<Option<CanvasAction<Message>>> {
        use iced::window;
        match event {
            iced::Event::Window(window::Event::RedrawRequested(now)) => {
                Some(self.advance_blink(widget_state, *now))
            }
            iced::Event::Window(window::Event::Focused) => {
                widget_state.window_unfocused = false;
                widget_state.blink_anchor = None;
                Some(None)
            }
            iced::Event::Window(window::Event::Unfocused) => {
                widget_state.window_unfocused = true;
                widget_state.blink_anchor = None;
                // A caret caught in its off half would stay off for as
                // long as the window is away.
                let was_off = std::mem::take(&mut widget_state.cursor_blink_off);
                Some(was_off.then(CanvasAction::request_redraw))
            }
            iced::Event::Keyboard(keyboard::Event::KeyPressed { .. })
            | iced::Event::InputMethod(_)
                if self.focused =>
            {
                widget_state.blink_anchor = None;
                widget_state.cursor_blink_off = false;
                None
            }
            _ => None,
        }
    }

    /// One frame of the blink: hand the default style to the emulator,
    /// read whether the caret blinks now, and move the phase. Runs on the
    /// `RedrawRequested` that precedes the frame's draw, so the draw
    /// reads the phase this computed.
    fn advance_blink(
        &self,
        widget_state: &mut TerminalWidgetState,
        now: Instant,
    ) -> Option<CanvasAction<Message>> {
        // Unfocused panes take no lock: every pane sees every frame.
        let blinking = (self.focused && !widget_state.window_unfocused)
            .then(|| {
                let mut s = match self.state.lock() {
                    Ok(s) => s,
                    Err(p) => p.into_inner(),
                };
                s.backend.set_default_cursor_style(self.cursor_shape, self.cursor_blink);
                let term = &s.backend.term;
                let shown = term
                    .mode()
                    .contains(alacritty_terminal::term::TermMode::SHOW_CURSOR);
                // A caret below a viewport scrolled into the history is
                // not drawn: flipping it would rebuild the grid for nothing.
                let row = term.grid().cursor.point.line.0 + s.viewport_offset();
                let on_screen = (0..term.grid().screen_lines() as i32).contains(&row);
                let epoch = s.render_epoch();
                (s.backend.cursor_blinking() && shown && on_screen).then_some(epoch)
            })
            .flatten();
        let Some(epoch) = blinking else {
            widget_state.blink_anchor = None;
            widget_state.cursor_blink_off = false;
            return None;
        };
        if widget_state.blink_epoch != Some(epoch) {
            widget_state.blink_epoch = Some(epoch);
            widget_state.blink_anchor = None;
        }
        let anchor = *widget_state.blink_anchor.get_or_insert(now);
        let (off, next) = blink_phase(now.saturating_duration_since(anchor));
        widget_state.cursor_blink_off = off;
        next.map(|wait| CanvasAction::request_redraw_at(now + wait))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_run_starts_solid_and_flips_every_half() {
        assert_eq!(blink_phase(Duration::ZERO), (false, Some(BLINK_HALF)));
        let just_off = BLINK_HALF + Duration::from_millis(1);
        assert_eq!(blink_phase(just_off), (true, Some(BLINK_HALF - Duration::from_millis(1))));
        assert_eq!(blink_phase(BLINK_HALF * 2), (false, Some(BLINK_HALF)));
    }

    #[test]
    fn the_next_wake_lands_on_the_flip_not_a_half_later() {
        let elapsed = Duration::from_millis(250);
        let (_, next) = blink_phase(elapsed);
        assert_eq!(elapsed + next.unwrap(), BLINK_HALF);
    }

    #[test]
    fn a_quiet_run_rests_solid_and_asks_for_nothing() {
        assert_eq!(blink_phase(BLINK_REST_AFTER), (false, None));
        assert_eq!(blink_phase(BLINK_REST_AFTER * 3), (false, None));
        // The last wake before the rest is the rest itself, so a caret
        // caught off is redrawn solid.
        let before = BLINK_REST_AFTER - Duration::from_millis(100);
        let (_, next) = blink_phase(before);
        assert_eq!(before + next.unwrap(), BLINK_REST_AFTER);
    }

    #[test]
    fn a_hidden_caret_paints_nothing_whatever_its_phase() {
        assert_eq!(caret_paint(CursorShape::Hidden, false), CaretPaint::Nothing);
        assert_eq!(caret_paint(CursorShape::Hidden, true), CaretPaint::Nothing);
    }

    #[test]
    fn the_off_half_paints_nothing_and_the_on_half_the_shape() {
        assert_eq!(caret_paint(CursorShape::Block, true), CaretPaint::Nothing);
        assert_eq!(caret_paint(CursorShape::Block, false), CaretPaint::Block);
        assert_eq!(caret_paint(CursorShape::Beam, false), CaretPaint::Bar);
        assert_eq!(caret_paint(CursorShape::Underline, false), CaretPaint::Underline);
        assert_eq!(caret_paint(CursorShape::HollowBlock, false), CaretPaint::Hollow);
    }
}
