viewport: 1200x750
mode: Zen
-----
# Issue #225 follow-up: a touchpad pinch over a pane zooms the terminal
# font as the Ctrl+wheel chord it is on Windows, so the "Zoom with Ctrl
# + wheel" switch covers it. `pinch <delta>` replays one whole gesture
# (start, one move, end), and the widget fires ONE step per event that
# completes one (a real trackpad delivers a gesture as dozens of small
# moves), so three gestures of 0.12 are three steps of `PINCH_STEP`
# (0.1), each leaving a remainder the end phase discards. The zoom is a
# session delta over the preference, so the stepper still reads 14 and
# the line under it says 17.
#
# `timeout 800` once the local shell is open: the live PTY keeps the
# zen emulator from ever quiescing. The pinch lands at (600, 400), the
# middle of the lone pane; the gesture has no position of its own, the
# cursor is what "over this pane" means. (92, 20) is the strip's "+"
# with no tab open, (56, 20) its Home button, (150, 20) the shell's chip
# and (370, 20) the Settings chip once both are open (the active shell chip is the wide one).
expect "Welcome to Oryxis"
click "Skip"
click "Continue without password"
expect "Create host"
click (161, 20)
settle 300
expect "Local Shell"
timeout 800
click "Local Shell"
settle 900
pinch 0.12 (600, 400)
pinch 0.12 (600, 400)
pinch 0.12 (600, 400)
settle 400
# Settings from the strip's home tab: the pane keeps its zoom.
click (56, 20)
settle 400
click (1175, 64)
settle
click "Terminal Settings"
settle
expect "Terminal Font Size"
expect "Zoomed to 17 for this session"

# With the chord off, a pinch is nothing: back to the pane, pinch out
# once more, and the line still says 17.
click (95, 68)
type ctrl+a
type "wheel"
settle
type enter
settle 500
click (1142, 70)
settle
click (219, 20)
settle 600
pinch 0.12 (600, 400)
settle 400
click (439, 20)
settle 400
expect "Zoomed to 17 for this session"
