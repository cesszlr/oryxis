viewport: 1200x600
mode: Zen
-----
# The group picker opens under its field with the host drawer SCROLLED,
# and the keys go straight to its search. The anchor was read in
# content space, so with the drawer scrolled 120 px the popover hung
# 120 px below the field; it is read with the scroll applied now
# (`anchor_reporter`). The click on "Top level" by POSITION is the
# anchor's proof (a text click would find the row wherever it hung),
# the folder card's count the evidence; "zzz" typed with no click on
# the search box is the focus's.
click "Skip"
click "Continue without password"
settle 250
click "Type IP or Hostname"
type "web01"
click "Continue"
settle 250
click "My Server"
type "web01"
click "Production, Staging..."
type "Prod"
settle 250
click "Save"
settle 250
expect "1 host"
click right "web01"
settle 250
click "Edit"
settle 250
expect "Edit Host"
scroll (0.00, -1.00) (1000.00, 450.00)
settle 250
# The Parent Group row now sits at the top of the drawer; its chevron:
click (1150.00, 131.00)
settle 250
type "zzz"
settle 200
expect "No matches for that filter"
type backspace
type backspace
type backspace
settle 200
# "Top level (no group)", first row under the search box.
click (896.00, 224.00)
settle 250
click (1169.00, 72.00)
settle 400
expect "0 hosts"
