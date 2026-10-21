viewport: 1200x750
mode: Zen
-----
# The reorder drag down a side-docked strip: the rows are read top to
# bottom, the ghost is a row wide, and the gap the dragged tab leaves is
# as tall as a chip (it was the content box, 10 px short, and every row
# under it jumped up on pickup).
#
# Three local shells, then Settings > Interface > Tab bar position =
# Left. Rows (each ~37 px): alpha, beta, gamma, Settings. alpha dragged
# onto gamma's lower half lands after gamma; beta (now first) dragged
# onto alpha's lower half lands last. Each release selects the tab.
# The `find` after the promoting move rebuilds the widget tree (see
# tab-drag-slide.ice).
expect "Welcome to Oryxis"
click "Skip"
click "Continue without password"
expect "Create host"
timeout 800
type ctrl+shift+l
settle 500
click right "bash (default)"
settle 250
click "Rename Tab"
settle 250
type ctrl+a
type "alpha"
type enter
settle 300
type ctrl+shift+l
settle 500
click right "bash (default)"
settle 250
click "Rename Tab"
settle 250
type ctrl+a
type "beta"
type enter
settle 300
type ctrl+shift+l
settle 700
click right "bash (default)"
settle 250
click "Rename Tab"
settle 250
type ctrl+a
type "gamma"
type enter
settle 300
order "alpha" "beta" "gamma"
expect "● gamma"
click (19, 20)
settle 300
click "Settings"
settle 500
scroll (0, 60) (600, 400)
settle 200
scroll pixels (0, -950) (600, 400)
settle 300
click (1068, 307)
settle 300
click (1068, 429)
settle 500
click "alpha"
settle 500
order "alpha" "beta" "gamma"
press (60, 68)
move (62, 76)
find "beta"
move (60, 150)
settle 200
screenshot side-1-alpha-dragged-down
release (60, 150)
settle 400
order "beta" "gamma" "alpha"
expect "● alpha"
press (60, 68)
move (62, 76)
find "gamma"
move (60, 150)
settle 200
release (60, 150)
settle 400
order "gamma" "alpha" "beta"
expect "● beta"
screenshot side-2-beta-dragged-down
