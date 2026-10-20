viewport: 1200x750
mode: Zen
-----
# An operation that fails over a listing that is still valid shows its
# message in a banner ABOVE the rows, which stay, instead of taking the
# pane over with the connect-failure screen (issue #261's screenshot: a
# failed upload drawn as "Retry / Pick another host" over nothing).
#
# The local pane is the one surface the harness can drive without a
# server: a second "New file" with the same name collides, the message
# lands, the first file's row is still there, and the × clears it.
click "Skip"
click "Continue without password"
settle 250
# New-tab button and the host picker's close: neither carries text, so
# both are coordinates (same as sftp-delete-key.ice).
click (161.00, 20.00)
settle 250
click "SFTP"
settle 250
click (785.00, 166.00)
settle 250
# The local pane's kebab menu, then its New file entry.
click (573.00, 72.00)
settle 250
click "New file"
settle 250
# The modal's input does not take focus on open.
click (599.00, 365.00)
type "twice.txt"
click "Create"
settle 250
expect "twice.txt"
click (573.00, 72.00)
settle 250
click "New file"
settle 250
click (599.00, 365.00)
type "twice.txt"
click "Create"
settle 250
# The banner and the row, together (`expect` matches the whole text node,
# quotes included; `absent` below is the substring form).
expect "\"twice.txt\" already exists"
expect "twice.txt"
# The banner's × (icon only, so a coordinate) clears it and nothing else.
click (573.00, 172.00)
settle 250
absent "already exists"
expect "twice.txt"
