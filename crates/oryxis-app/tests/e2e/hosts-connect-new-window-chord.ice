viewport: 1200x850
mode: Zen
-----
# Ctrl+Enter connects a host in a NEW window: the card menu's "Connect
# in New Window" on a chord, the twin of the Enter that connects the
# same host here. Three things, in one vault:
#
#   * the chord is SHARED with "Move tab to new window", bound to it by
#     hand first: a vault action and a tab action never see the same
#     keypress, so the capture takes nothing away and the boot pass
#     (`reset` reopens the vault) keeps the factory chord on the card;
#   * inside the new-tab picker (Ctrl+Shift+T) the chord takes the
#     highlighted row, and the picker's plain-Enter path does NOT also
#     connect that host in a tab beside it (window 1's strip stays as
#     it was);
#   * on the hosts screen it takes the card the keyboard ring focused
#     (two Tabs from the fresh screen: sub-nav, then content).
#
# The host is a saved name with no server behind it, so the dial fails
# on its own; what this asserts is the WINDOW: the emulator adopts the
# last window opened and draws it, and `window <n>` looks at another.
# The move-tab chip is clicked by position (eleven chips share the
# "(unbound)" text): the second one with the list at the top, under the
# preset selector, which is why the viewport is taller than the default
# (`shortcuts-unbound-verbs.ice` clicks the same chip).
expect "Welcome to Oryxis"
click "Skip"
click "Continue without password"
settle 250
click "Type IP or Hostname"
type "web01"
click "Continue"
settle 250
click "My Server"
type "web01"
click "Save"
settle 250
expect "web01"
# Toolbar gear (icon only, no text selector).
click (1175, 64)
settle
click "Shortcuts"
settle
expect "Connect in New Window"
expect "Move tab to new window"
click (251, 790)
settle 250
expect "Press a key or mouse button…"
type ctrl+enter
settle 250
expect "Reset"
# A second session: the override is read back, the factory chord stays.
reset
settle
expect "web01"
expect "Search hosts or quick connect (user@host)..."
# The picker, from a shell tab: the chord opens window 2 with web01
# alone, and window 1 keeps Home plus the shell.
# A PTY lives from here on, so no instruction settles on its own:
# cap the per-instruction wait (20 s by default) like the other
# shell tests do.
timeout 800
type ctrl+shift+l
settle 900
expect "bash (default)"
type ctrl+shift+t
settle 250
expect "Local Shell"
# Filter to the host: the top row is Local Shell until the search says
# otherwise, and the chord takes the highlighted row like Enter does.
type "web"
settle 250
absent "Local Shell"
expect "web01"
type ctrl+enter
settle 900
expect "web01"
absent "bash (default)"
window 1
settle 250
expect "bash (default)"
absent "web01"
# The card, from the hosts screen: Home, ring the card, chord.
click (57, 20)
settle 250
expect "Search hosts or quick connect (user@host)..."
type tab
type tab
settle 250
type ctrl+enter
settle 900
expect "web01"
absent "Search hosts or quick connect"
absent "bash (default)"
