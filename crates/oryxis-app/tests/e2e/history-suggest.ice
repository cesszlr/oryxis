viewport: 1200x750
mode: Zen
-----
# Issue #266: typing at a prompt offers the commands run before on that
# host, under the line. The popup is the password popup's shape over
# text: Down engages, Enter completes the line, Shift+Enter completes
# and runs, Esc hides it for the rest of the line, and nothing is ever
# typed without a pick.
#
# The history is per saved host, so the fixture is a saved host with the
# Local protocol and no terminal picked (the default shell): a
# `PaneOrigin::Host` that opens without a server. The protocol pick
# list's options are not text-selectable, so the Local row is clicked by
# coordinates (screenshot `hist-protocol-menu` is where they were read).
#
# Two sections. The first runs on the harness bash as it comes (no OSC
# 133 marks): the classic-prompt heuristic reads the echoed line. The
# second gives bash the four marks (PS1 + DEBUG trap, as
# terminal-copy-last-command.ice does) so the prompt's own B mark places
# the line, and proves the completion RAN through "Copy Last Command +
# Output", whose clipboard is the command and its output exactly.
expect "Welcome to Oryxis"
click "Skip"
click "Continue without password"
expect "Create host"
click #empty-quick-host
type "localbox.example"
settle 250
type enter
settle 400
expect "New Host"
click #editor-label
type "lab-local"
settle 250
click (875, 529)
settle 300
screenshot hist-protocol-menu
click (875, 489)
settle 300
expect "Local"
click "Save"
settle 400
expect "lab-local"
# A PTY lives from here on: cap the per-instruction wait BEFORE the
# click that spawns it.
timeout 500
click "lab-local"
settle 500
wait 2500
# The popup anchors at the typed line, which needs the pane's DRAWN rect;
# the emulator only draws on `screenshot`, so this one is load-bearing.
screenshot hist-shell

# 1. Classic prompt. One command recorded, then its prefix typed: the
#    popup opens under the line with the recorded command.
type "echo HIST_ONE"
type enter
wait 1200
type "echo HI"
wait 1500
expect "From this host's history"
expect "echo HIST_ONE"
screenshot hist-popup

# 2. Esc hides it for this line: more typing does not bring it back.
#    Ctrl+C starts a fresh line, and the same prefix offers it again.
type escape
wait 400
absent "From this host's history"
type "S"
wait 1200
absent "From this host's history"
type ctrl+c
wait 600
type "echo HI"
wait 1500
expect "From this host's history"

# 3. Down engages, Enter completes the line WITHOUT running it: the popup
#    is gone and the shell is still at the prompt with the full command
#    (canvas only, so the screenshot is the record). Enter then runs it.
type down
wait 300
type enter
wait 1200
absent "From this host's history"
screenshot hist-completed
type enter
wait 1200

# 4. The mouse path: a click on a row completes the line too. The popup
#    has no backdrop (the terminal is right under it), so the click has
#    to land on the row, not on the canvas.
type "echo HI"
wait 1500
expect "From this host's history"
click "echo HIST_ONE"
wait 1200
absent "From this host's history"
screenshot hist-clicked
type ctrl+c
wait 600

# 5. The shell's own marks. With OSC 133 the line is read from the B
#    mark's coordinates; only the command that extends the prefix is
#    offered, and Shift+Enter completes AND runs it, which "Copy Last
#    Command + Output" (unbound, so through the palette) proves exactly.
type "PS1='\\[\\e]133;D;0\\a\\e]133;A\\a\\]$ \\[\\e]133;B\\a\\]'"
type enter
wait 800
type "trap 'printf \"\\e]133;C\\a\"' DEBUG"
type enter
wait 800
type "echo HIST_TWO"
type enter
wait 1200
type "echo HIST_T"
wait 1500
expect "From this host's history"
expect "echo HIST_TWO"
absent "echo HIST_ONE"
screenshot hist-popup-marks
type down
wait 300
type shift+enter
wait 1500
absent "From this host's history"
type ctrl+shift+p
settle 400
type "last command"
settle 400
type enter
expect "Copied to clipboard"
clipboard is "echo HIST_TWO\nHIST_TWO"
