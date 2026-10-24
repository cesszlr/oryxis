viewport: 1200x750
mode: Zen
-----
# Ctrl+Tab walks tabs in one of two orders (Settings > Interface, "Ctrl+Tab
# switches tabs by"): recent use, the default since 0.9.0, or the strip's
# own order, Windows Terminal's default. The two shells share a label, so
# the Settings panel tab between them is the marker: "Terminal Settings"
# is on screen exactly when that tab is in front.
#
# Strip: [Settings, shell A, shell C]. Recent use after opening both
# shells: [C, A, Settings], with C in front. Each `type ctrl+tab` is one
# press WITH its release (the emulator restores the modifiers after a
# chord), so in recent-use order two presses toggle A and C and a
# backward press from C reaches the least recent tab, Settings. In strip
# order from Settings, two forward presses land on C (recent use would be
# back on Settings), and the third wraps to Settings again.
#
# The Settings search reveals the row; the pick list's options are not
# text-selectable, so the menu is opened and picked by coordinates
# (screenshot `tab-switch-order-menu` is where they were read). `reset`
# keeps the vault, so the value the restart shows is the persisted row.
expect "Welcome to Oryxis"
click "Skip"
click "Continue without password"
expect "Create host"
click (1168, 55)
settle 500
expect "Terminal Settings"
# A PTY lives from here on, so no instruction settles on its own: cap the
# per-instruction wait before the chord that spawns the first shell.
timeout 800
type ctrl+shift+l
settle 1500
absent "Terminal Settings"
type ctrl+shift+l
settle 1500
absent "Terminal Settings"

# 1. Recent use (default): toggle between the two shells, then back to the
#    least recent, which is the Settings tab.
type ctrl+tab
settle 800
absent "Terminal Settings"
type ctrl+tab
settle 800
absent "Terminal Settings"
type ctrl+shift+tab
settle 800
expect "Terminal Settings"

# 2. Flip the setting to strip order from the Settings tab we landed on.
click #search-settings
type "ctrl+tab"
settle 400
expect "Ctrl+Tab switches tabs by"
type enter
settle 500
click (1059, 80)
settle 300
screenshot tab-switch-order-menu
click (1059, 161)
settle 400
expect "Strip order"

# 3. Strip order: from Settings (first chip) two forward presses reach the
#    last shell, where recent use would have come back to Settings; the
#    third wraps around. Backward walks the same ring the other way.
type ctrl+tab
settle 800
absent "Terminal Settings"
type ctrl+tab
settle 800
absent "Terminal Settings"
type ctrl+tab
settle 800
expect "Terminal Settings"
type ctrl+shift+tab
settle 800
absent "Terminal Settings"
type ctrl+shift+tab
settle 800
absent "Terminal Settings"
type ctrl+shift+tab
settle 800
expect "Terminal Settings"

# 4. The pick is a vault row: the restart reads it back.
reset
settle
expect "Create host"
click (1168, 55)
settle 500
click #search-settings
type "ctrl+tab"
settle 400
type enter
settle 500
expect "Strip order"
