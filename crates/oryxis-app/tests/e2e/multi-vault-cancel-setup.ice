viewport: 1200x750
mode: Zen
-----
# A vault made with "New vault" opens on its setup step alone (no
# welcome carousel), and cancelling that step goes back to the vault it
# was made from: the empty new vault is gone from the switcher.
click "Skip"
click "Continue without password"
settle 250
expect "Personal"
click "Personal"
settle 250
click "New vault…"
settle 250
type "Temp"
click "Create"
settle 250
expect "Set up Temp"
absent "Next"
click "Cancel"
settle 250
expect "Create host"
expect "Personal"
click "Personal"
settle 250
expect "New vault…"
absent "Temp"
