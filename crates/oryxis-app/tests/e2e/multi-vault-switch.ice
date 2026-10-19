viewport: 1200x750
mode: Zen
-----
# Several vaults in one window (multi-vault): the chip on the vault
# toolbar names the vault the window works on, its menu makes a new one
# ("New vault…" asks for a name, then the new vault's own setup step),
# and switching moves the window between them: each keeps its hosts and
# its tabs (another vault's tabs are parked, not closed). "Lock all
# vaults" locks every vault with a master password, and the lock screen
# names the vault and offers the others.
click "Skip"
click "Continue without password"
settle 250
expect "Create host"
expect "Personal"
click "Personal"
settle 250
expect "New vault…"
click "New vault…"
settle 250
expect "New vault"
type "Work"
click "Create"
settle 250
expect "Set up Work"
click "Master password (optional)..."
type "work-pass-123"
click "Create Vault"
settle 250
wait 3000
settle 250
expect "Create host"
expect "Work"
click "Type IP or Hostname"
type "work-db"
click "Continue"
settle 250
click "My Server"
type "work-db"
click "Save"
settle 250
expect "work-db"
# A tab of Work: a local shell.
type ctrl+shift+l
settle 250
wait 1000
settle 250
expect "bash (default)"
# Back on the hosts screen, over to Personal: no Work host, no Work tab.
click (56, 20)
settle 250
click "Work"
settle 250
click "Personal"
settle 250
expect "Create host"
absent "work-db"
absent "bash (default)"
# And back: Work's host and its tab, still there.
click "Personal"
settle 250
click "Work"
settle 250
expect "work-db"
expect "bash (default)"
# Lock every vault that has a password: Work locks and says so; Personal
# (no password) is one click away from its lock screen.
click "Work"
settle 250
click "Lock all vaults"
settle 250
expect "Lock all vaults?"
click "Lock all vaults"
settle 250
wait 500
settle 250
expect "Work"
expect "Other vaults:"
click "Personal"
settle 250
expect "Create host"
