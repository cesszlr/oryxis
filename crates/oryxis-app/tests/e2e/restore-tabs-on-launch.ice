viewport: 1200x750
mode: Zen
-----
# Issue #206: the tabs that were merely OPEN come back after a restart.
#
# Off by default, so the test turns it on first, through the settings
# search: the row sits in Interface, out of a 750 px viewport, and the
# reveal scrolls it to a fixed place near the top. That is what pins the
# one coordinate here. Clicking the LABEL does nothing (a
# `nav_toggle_row` puts the switch on the right), so the click lands on
# the toggler. To re-measure after a layout change, take a screenshot
# right after the `type enter` below and read the switch off it.
#
# A local shell is the only session a headless run can open with no host.
#
# `reset` (not `reset wipe`) restarts the app keeping the sandbox vault,
# which is the whole point: the snapshot is written to the `open_tabs`
# setting as the strip changes, so it is already on disk when the
# emulator is dropped. What comes back is a DORMANT chip: the strip has
# it, the app still opens on Hosts, and nothing is dialled until it is
# selected. Its placeholder pane carries a hint, which no text selector
# can read (it is inside the terminal canvas), so the screenshot is what
# records it and `expect "Create host"` is what proves nothing connected.
expect "Welcome to Oryxis"
click "Skip"
click "Continue without password"
expect "Create host"
click (1168, 55)
expect "Terminal Settings"
click #search-settings
type "restore last"
settle 400
expect "Restore last session's tabs"
type enter
settle 500
click (1140, 70)
settle 400
screenshot restore-tabs-setting-on
# A local shell tab, leaving Settings open so the `+` keeps its position.
click (402, 20)
expect "Local Shell"
timeout 800
click "Local Shell"
settle 1200
expect "bash (default)"
# Restart with the vault intact. The chip is back and the app is on
# Hosts, which together are "restored, dormant".
reset
settle
expect "Create host"
expect "bash (default)"
screenshot restore-tabs-dormant
# Selecting it is what connects it, exactly as a dormant pin does.
click "bash (default)"
settle 1400
screenshot restore-tabs-connected
# Turning the preference off drops the list rather than just ignoring
# it, so the next restart brings nothing back.
click (19, 20)
settle
click "Settings"
settle
click #search-settings
type "restore last"
settle 400
expect "Restore last session's tabs"
type enter
settle 500
click (1140, 70)
settle 400
reset
settle
expect "Create host"
absent "bash (default)"
