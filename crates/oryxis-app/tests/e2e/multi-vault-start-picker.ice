viewport: 1200x750
mode: Zen
-----
# A start opens the last vault used. Settings > Vaults "Ask which vault
# to open at start" puts a list of every vault in front instead (nothing
# of a vault loads before the pick): the last one used is the default
# row, the arrows move, Enter opens. `reset` is the next start.
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
# Without the option, the next start is Work's lock screen.
reset
settle 500
expect "Enter your master password to unlock."
absent "Choose a vault"
type "work-pass-123"
type enter
settle 500
wait 2000
settle 250
click (19, 20)
settle
click "Settings"
settle
click "Vaults"
settle 250
# The option's toggle.
click (1141, 695)
settle 250
reset
settle 500
expect "Choose a vault"
expect "Last used"
expect "Personal"
# Personal is the other row: Down, Enter.
type down
type enter
settle 400
expect "Create host"
reset
settle 500
expect "Choose a vault"
type enter
settle 400
expect "Create host"
