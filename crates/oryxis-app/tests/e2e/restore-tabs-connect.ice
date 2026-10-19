viewport: 1200x750
mode: Zen
-----
# Issue #229: the two asks a restored strip can make beyond coming
# back. Both rows live under "Restore last session's tabs" and only
# exist while it is on, so the test turns it on first, the way
# restore-tabs-on-launch.ice does (same reveal, same toggler
# coordinate; re-measure both together after a layout change).
#
# First half: "Open on the tab that was active" with the default
# "connect when selected". After the restart the app is NOT on Hosts
# (that is the text-level proof), and the select the landing performed
# is what connected the shell, exactly as a click on the chip would.
#
# Second half: "connect at launch" with the landing off. The app opens
# on Hosts as it always did, and the shell was dialled IN PLACE while
# it sat there: the screenshot shows the placeholder's own hint with
# the dial marker and the prompt below it, which the foreground reopen
# (a fresh tab) never produces. Canvas only, so the picture is the
# record.
#
# A local shell is the only session a headless run can open with no
# host. `reset` keeps the sandbox vault, so the rows written as the
# strip changed are what the restart reads.
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
expect "Restored tabs connect"
expect "Open on the tab that was active"
click (1140, 187)
settle 400
screenshot restore-tabs-connect-landing-on
click (402, 20)
expect "Local Shell"
timeout 800
click "Local Shell"
settle 1200
expect "bash (default)"
reset
settle
absent "Create host"
expect "bash (default)"
screenshot restore-tabs-connect-landed
# Second half, from the tab the landing put us on.
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
# The pick opens under its own row; "At launch" is its second option.
click (1068, 129)
settle 300
click (1068, 211)
settle 300
click (1140, 187)
settle 400
screenshot restore-tabs-connect-launch-picked
reset
settle
expect "Create host"
expect "bash (default)"
settle 1500
click "bash (default)"
settle 800
screenshot restore-tabs-connect-launch-pane
