viewport: 1200x750
mode: Zen
-----
# Issue #232: the password popup inside tmux. The multiplexer lives on
# the alternate screen, where the prompt shares its row with the pane
# beside it and the screen may belong to an editor instead, so the
# detector cuts the row at tmux's divider and only accepts the exact
# shapes programs print. The setup is password-suggest.ice's.
#
# The tmux socket lives inside the sandbox (TMUX_TMPDIR), which the
# runner wipes per test, and `-f /dev/null` keeps a runner's own
# config out of the layout.
#
# Setup is coordinate-driven because none of it is text-selectable: a
# key must exist before the keychain toolbar (and its "+ ADD" split
# button) renders at all, and the identity form's fields are
# text_inputs, whose placeholders the text selector cannot match.
expect "Welcome to Oryxis"
click "Skip"
click "Continue without password"
expect "Create host"
click "Keychain"
expect "Add a key"
# A key first: the empty keychain shows no toolbar, so "+ ADD" has
# nowhere to be until the list is non-empty.
click "Generate key"
expect "Generate key"
click (989, 137)
type "qa-key"
click "Generate"
settle 300
click "Done"
settle 300
# The "+ ADD" chevron. The screenshot before it is not decoration: menus
# anchored on real widget bounds read the LAST DRAWN rect, and the
# emulator only draws on `screenshot`.
screenshot pwsuggest-keychain
click (1155, 120)
expect "New Identity"
click "New Identity"
expect "Save Identity"
click (989, 147)
type "ops-admin"
click (1000, 225)
type "wilson"
click (1000, 304)
type "hunter2"
click "Save Identity"
settle 300
expect "ops-admin"
screenshot pwsuggest-identity

# A local shell: the popup's identity rows are origin-independent, so
# this covers the whole path without a server.
click (161, 20)
expect "Local Shell"
click "Local Shell"
settle 500
# A live PTY never lets the emulator quiesce, so every instruction from
# here would otherwise burn the full timeout.
timeout 500
wait 1500
# The popup anchors at the caret, which needs the pane's DRAWN rect.
# The emulator only draws on `screenshot`, so this one is load-bearing:
# without it the pane has never reported its bounds and the popup has
# nowhere to open. A real window draws every frame.
screenshot pwsuggest-shell

# 1. Split tmux left / right. The left pane prints words that would
# both carry and exclude a match if the row were read from column 0.
type "export TMUX_TMPDIR=$HOME/.oryxis"
type enter
type "tmux -L e2e -f /dev/null new-session"
type enter
wait 1500
type "echo old password new; tmux split-window -h"
type enter
wait 1500
screenshot pwsuggest-tmux-split

# 2. A prompt in the right pane raises the popup at its caret.
type "read -s -p '[sudo] password for wilson: ' PW"
type enter
wait 1500
expect "Stored passwords"
expect "ops-admin"
screenshot pwsuggest-tmux-popup

# 3. Picking sends that credential into the pane that asked.
click "ops-admin"
wait 800
absent "Stored passwords"
type "echo [$PW]"
type enter
wait 800
# Must show `[hunter2]` in the RIGHT pane.
screenshot pwsuggest-tmux-sent

# 4. What only looks like a prompt stays quiet on the alternate screen:
# a lower-case key an editor could be sitting after, and a prompt that
# asks the user to CHOOSE a password.
type "read -p 'password:' X"
type enter
wait 1200
absent "Stored passwords"
type enter
wait 600
type "read -s -p 'New Password: ' X"
type enter
wait 1200
absent "Stored passwords"
type enter
wait 600

type "tmux -L e2e kill-server"
type enter
wait 800
