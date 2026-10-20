viewport: 1200x750
mode: Zen
-----
# Issue #206, the recency half: the tab popovers offer the hosts most
# recently connected, so reaching one again is not a trip through the
# picker.
#
# The list is `Connection.last_used`, which the tray submenu and the
# Windows JumpList already read and which nothing wrote until now, so
# what this really covers is the feed: the stamp is taken at the TOP of
# the connect switch, above the protocol split, which is why a dial that
# never resolves still counts as having used the host.
#
# `db.invalid` is deliberate. The stamp does not wait for the dial, so
# the outcome is irrelevant, and an address that CANNOT resolve fails in
# milliseconds instead of parking the run on a host-key prompt from
# whatever happens to be listening on the machine running the test.
#
# The label is long on purpose: the popover cuts one at 24 characters,
# so the row reads `prod-database-primary-e…`, a string that appears
# nowhere else in the frame. The chip and the progress card both carry
# the full label, and a shorter one would make every assertion here
# match all three.
settle 250
click "Skip"
settle 250
click "Continue without password"
settle 250
expect "Create host"
# Nothing has been connected yet, so the menu has nothing recent to
# offer: a row that is always there and usually does nothing reads as
# broken the first time it is tried, the same rule the reopen follows.
click right (400.00, 18.00)
settle 250
expect "New Tab"
absent "prod-database"
type escape
settle 250
# One saved host. A bare hostname (not an IP literal) opens the editor
# rather than offering an ad-hoc dial, which is what makes this a SAVE.
click #empty-quick-host
type "db.invalid"
settle 250
type enter
settle 250
expect "New Host"
click #editor-label
type "prod-database-primary-eu-west-1"
settle 250
click "Save"
settle 400
expect "prod-database-primary-eu-west-1"
timeout 800
click "prod-database-primary-eu-west-1"
settle 1500
expect "Connection failed with connection log:"
# The strip's own menu now carries it, under the hairline.
click right (400.00, 18.00)
settle 400
expect "prod-database-primary-e…"
screenshot recent-strip-menu
type escape
settle 250
# And so does the `+` popover, which is the other half of the same
# builder. It opens on HOVER rather than a click, hence the move; the
# two menus differ only in which row helper they use, because this one
# is a hover popover the keynav layer deliberately declines.
move (402.00, 20.00)
settle 400
expect "Split side by side"
expect "prod-database-primary-e…"
screenshot recent-plus-popover
