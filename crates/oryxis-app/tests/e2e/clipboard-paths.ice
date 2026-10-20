viewport: 1200x750
mode: Zen
-----
# Every clipboard access in the app goes through the iced runtime, which
# serves one at a time on its own thread. Two concurrent Win32 clipboard
# opens in one process are FATAL (STATUS_HEAP_CORRUPTION inside
# user32!GetClipboardData, no panic, no log): that is the 2026-07-29 field
# crash, Ctrl+V in the SFTP path bar. This test walks the three paths that
# used to bypass the runtime, so a regression to a direct `arboard` call
# shows up as a failing assert here, and the two gestures beside them on
# the same shell: Ctrl+C with nothing selected leaves the clipboard
# alone (issue #258: upstream's copy wrote "" there), and a middle click
# pastes the last selection back (PRIMARY on X11 / Wayland, the pane's
# remembered selection elsewhere). One shell and one screen fill serve
# all of them: each used to be its own file with the same 8 s of setup.
#
# The emulated clipboard is the oracle: since the app writes through the
# runtime, `clipboard is "..."` sees the app's own copies.
expect "Welcome to Oryxis"
click "Skip"
click "Continue without password"
expect "Create host"

# 1. Ctrl+C with nothing selected, on the hosts screen: the clipboard
#    keeps what it had.
clipboard "kept on the hosts screen"
type ctrl+c
settle
clipboard is "kept on the hosts screen"

# 2. Paste into the SFTP path bar (the crashing gesture). The path input
#    is a text_input, so the runtime performs the read; the value is not
#    text-selectable, hence the screenshot.
click (160, 20)
expect "SFTP"
click "SFTP"
settle
expect "Select a host"
click (785, 166)
settle
clipboard "/tmp"
click (300, 105)
settle
click (300, 108)
type ctrl+v
settle
screenshot sftp-path-paste

# 3. A local shell. The selections below are PIXEL ranges, so they only
#    copy what is actually drawn at that row. Tying one to a SINGLE
#    echoed line made it depend on where the shell's prompt ended up: a
#    CI runner's `runner@fv-az...` prompt is long enough to wrap at this
#    width and push the output down a row, and an empty selection does
#    not clear the clipboard, so the assert reported whatever was there
#    instead of saying it grabbed the wrong row. Filling the screen with
#    the SAME line removes the dependency: any row in the block yields
#    the same text. `clear` puts the block at a known top.
click (402, 20)
expect "Local Shell"
# Before the click that spawns the shell: that click already leaves the
# never-ending PTY task pending and would burn the default 20 s itself.
timeout 500
click "Local Shell"
wait 4000
type "clear; yes HELLO_CLIP | head -20"
type enter
wait 4000

# 4. Copy-on-select: the widget queues the copy and the app performs it
#    through the runtime, so it lands in the emulated clipboard (before
#    the fix it went straight to the system clipboard). Seeded first, so
#    a mis-aimed grab reports the seed rather than a value an earlier
#    step left.
clipboard "seeded"
press (8, 123)
move (60, 123)
move (95, 123)
release (95, 123)
settle
clipboard is "HELLO_CLIP"

# 5. Ctrl+Shift+C copies the live selection; the shell's Ctrl+C that
#    follows (the interrupt, not a copy) leaves it there.
clipboard "seeded"
type ctrl+shift+c
wait 500
clipboard is "HELLO_CLIP"
type ctrl+c
wait 500
clipboard is "HELLO_CLIP"

# 6. Middle-click pastes the last selection back onto the (empty)
#    prompt. The terminal is a canvas, so the pasted text is only
#    visible in the screenshot; the Ctrl+C after it clears the line
#    again for the next paste.
click middle (400, 300)
wait 1200
screenshot primary-middle-click-paste
type ctrl+c
wait 500

# 7. Ctrl+Shift+V: the paste read is a Task now, and the text comes back
#    as TerminalPasteResolved before reaching the PTY.
clipboard "echo PASTED_OK"
type ctrl+shift+v
wait 1500
screenshot terminal-paste
