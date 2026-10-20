viewport: 1400x1000
mode: Zen
-----
# Two vaults on one sync target would merge into each other: each
# round reads the other vault's records out of the shared snapshot and
# writes them into its own. Personal syncs with a folder; a second
# vault pointed at the same folder is refused at its first round, the
# refusal naming the vault that already syncs there.
expect "Welcome to Oryxis"
click "Skip"
click "Continue without password"
settle
# Personal: sync on (Features & Plugins), folder transport, first round.
click (19, 20)
settle
click "Settings"
settle
click "Features & Plugins"
settle
click (1338, 207)
# Sync on mounts an engine that keeps running: no instruction reports
# done from here, so each waits out a short timeout instead (71s -> 44s
# from 5 s to 1.5 s, two clean local passes, 2026-10-20).
timeout 1500
settle
click (60, 463)
settle
expect "Transport"
click #search-settings
settle
type tab
type right
type right
settle
click #sync-folder-path
type "~/.oryxis"
settle
click #sync-folder-pass
type "hunter2"
settle
click "Sync Now"
settle 800
expect "Synced, 0 records from the snapshot"
# A second vault, Work, made from the switcher on the Home tab.
click (133, 21)
settle 250
click "New vault…"
settle 250
type "Work"
click "Create"
settle 250
click "Continue without password"
settle 250
expect "Work"
# Work: sync on, the same folder.
click (19, 20)
settle
click "Settings"
settle
click "Features & Plugins"
settle
click (1338, 207)
settle
click (60, 463)
settle
expect "Transport"
click #search-settings
settle
type tab
type right
type right
settle
click #sync-folder-path
type "~/.oryxis"
settle
click #sync-folder-pass
type "hunter2"
settle
click "Sync Now"
settle 800
expect "The vault Personal already syncs with this target. Two vaults on one target would merge into each other: pick another one."
absent "Synced, 0 records from the snapshot"
