viewport: 1200x750
mode: Zen
-----
# A vault's own shortcut (Settings > Vaults, Record): the chord moves
# the window to that vault from anywhere, a locked vault's screen
# included. A chord the hotkey table holds is refused. The palette lists
# every vault with its chord. A chord answered by the global key
# subscription does not rebuild the emulated view, so each one is
# followed by a click on empty space before the assertion.
click "Skip"
click "Continue without password"
settle 250
click (133, 21)
settle 250
click "New vault…"
settle 250
type "Work"
click "Create"
settle 250
click "Master password (optional)..."
type "work-pass-123"
click "Create Vault"
settle 250
wait 3000
settle 250
click (19, 20)
settle
click "Settings"
settle
click "Vaults"
settle 250
# Personal's Record, then Work's.
click (368, 218)
settle
type ctrl+alt+1
settle 250
expect "Ctrl + Alt + 1"
click (368, 390)
settle
type ctrl+alt+2
settle 250
expect "Ctrl + Alt + 2"
# The command palette's chord is the table's: refused, nothing changes.
click (462, 218)
settle
type ctrl+shift+p
settle 250
type escape
settle 250
click (700, 690)
settle 250
expect "Ctrl + Alt + 1"
absent "Ctrl + Shift + P"
# Home, then to Personal and back by chord.
click (70, 20)
settle 250
type ctrl+alt+1
settle 250
click (600, 650)
settle 250
expect "Personal"
absent "Work"
type ctrl+alt+2
settle 250
click (600, 650)
settle 250
expect "Work"
# Work locked: its chord-less lock screen still answers Personal's.
click (114, 21)
settle 250
click "Lock all vaults"
settle 250
click "Lock all vaults"
settle 500
expect "Other vaults:"
type ctrl+alt+1
settle 250
click (600, 700)
settle 250
expect "Create host"
expect "Personal"
