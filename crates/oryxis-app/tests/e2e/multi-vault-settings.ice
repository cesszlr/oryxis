viewport: 1200x750
mode: Zen
-----
# Settings > Vaults (multi-vault): every vault this device knows, with
# its state and file, the window's own vault marked. Rename asks for the
# name; Delete wants the vault's name typed back (the button stays inert
# until it matches) and moves this window off the vault before its file
# goes. With a single vault left, the switcher chip may be hidden.
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
expect "Work"
click (19, 20)
settle
click "Settings"
settle
click "Vaults"
settle 250
expect "This window"
expect "Unlocked"
expect "Lock"
click "Rename"
settle 250
expect "Rename Personal"
type ctrl+a
type "Home"
type enter
settle 250
expect "Home"
absent "Personal"
# Work's Delete (the second one): nothing happens until the name matches.
click (678, 349)
settle 250
expect "Delete Work?"
type "Wor"
type enter
settle 250
expect "Delete Work?"
type "k"
type enter
settle 250
wait 500
settle 250
absent "Delete Work?"
absent "Work"
expect "This window"
expect "Home"
# One vault left: the chip may go (the row's toggle).
click (1141, 414)
settle 250
click (56, 20)
settle 250
expect "Create host"
absent "Home"
