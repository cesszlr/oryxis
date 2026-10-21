viewport: 1200x750
mode: Zen
-----
# The vault switcher's "Manage vaults…" row opens Settings on its Vaults
# section and closes the menu (`MultiVaultMessage::ShowVaultSettings`).
# (133, 21) is the Home tab's chevron.
click "Skip"
click "Continue without password"
settle 250
click (133, 21)
settle 250
expect "Manage vaults…"
click "Manage vaults…"
settle 400
absent "Manage vaults…"
expect "This list belongs to this device: it is not synced and is the same in every vault."
expect "Open existing vault…"
