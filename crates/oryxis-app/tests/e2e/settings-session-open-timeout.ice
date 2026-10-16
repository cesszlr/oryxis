viewport: 1200x750
mode: Zen
-----
# Issue #256: how long a terminal dial may take to open its shell once
# logged in (channel open, PTY, shell request) is a setting, not the
# engine's fixed 10 s. It lives in Settings > Connection beside the
# keepalive, and the settings search finds it by what a user who hit
# the error would type ("pty", from the message that names the step).
click "Skip"
click "Continue without password"
settle 250
click (1175.00, 64.00)
settle 250
type ctrl+f
type "pty"
wait 400
settle 250
expect "Session open timeout (s)"
type enter
wait 400
settle 250
expect "Session open timeout (s)"
expect "Keepalive Interval"
