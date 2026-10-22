viewport: 1200x750
mode: Zen
-----
# The snippet bar (issue #266): a snippet marked "show in the snippet
# bar" is a button under the terminal, and the bar exists only while one
# is. The card's menu puts a snippet on the bar and takes it off, naming
# the way it goes; the editor's switch opens on what the snippet holds.
# (A click on the button runs it in the pane, which no text selector can
# see inside the canvas.)
settle 250
click "Skip"
settle 250
click "Continue without password"
settle 250
click "Snippets"
settle
click "SNIPPET"
settle
# Name and command fields by position: a text_input's value is not
# text-selectable.
click (990.00, 145.00)
type "deploy-bar"
click (990.00, 612.00)
type "echo bar-ran"
click "Save"
settle 300
# A live shell keeps tasks pending: pace by time from here on.
timeout 500
type ctrl+shift+l
settle 400
expect "bash (default)"
# No snippet is marked: no bar.
absent "deploy-bar"
click "Personal"
settle 300
click "Snippets"
settle 300
click right "deploy-bar"
settle 300
click "Add to snippet bar"
settle 300
click "bash (default)"
settle 400
expect "deploy-bar"
click "deploy-bar"
settle 400
# The menu now offers the other way.
click "Personal"
settle 300
click "Snippets"
settle 300
click right "deploy-bar"
settle 300
absent "Add to snippet bar"
click "Remove from snippet bar"
settle 300
click "bash (default)"
settle 400
absent "deploy-bar"
