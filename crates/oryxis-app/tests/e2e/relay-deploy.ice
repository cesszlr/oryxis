viewport: 1400x2400
mode: Zen
-----
# E3, the relay wizard's second level: "Install on one of your hosts"
# lives inside the wizard card in Settings > Sync, reads the wizard's
# domain / token, and refuses to probe without a host. The host picker
# is a real modal (Esc closes it, the keyboard walks it) shared with the
# SFTP snapshot transport, and a probe against a host whose key is not
# known is REFUSED with the hint that names the way out, because the
# dial is unattended (strict host key, no prompt).
#
# What this cannot cover: the consent modal and the run need a probe
# to succeed, which needs a real Linux host with systemd and a
# published `relay.json`; that is the out-of-tree integration script.
#
# Tall viewport on purpose: the wizard card sits below the fold of the
# Sync page and the emulator's wheel does not reach the settings
# scrollable.
expect "Welcome to Oryxis"
click "Skip"
click "Continue without password"
expect "Create host"
click "Continue"
expect "New Host"
click "IP or Hostname"
type "127.0.0.1"
click (1190.00, 219.00)
type "RelayHost"
click "Save"
settle 500
expect "RelayHost"
# Sync is a feature toggle: enable it on the Plugins screen before the
# Sync section exists in the sidebar (toggle column pinned right, fixed
# row height).
click (19, 20)
settle
click "Settings"
settle
click "Features & Plugins"
settle
click (1338, 207)
# The engine keeps running from here on: cap the per-instruction wait.
# 1.5 s is what the probe's refusal and the picker need between two
# instructions (82s -> 43s from 5 s, two clean local passes, 2026-10-20).
timeout 1500
settle
click (60, 463)
settle
expect "Transport"
click "Set up your own relay"
settle
expect "Install on one of your hosts"
click "Install on one of your hosts"
settle
expect "Relay port"
expect "TLS via Caddy on the host"
# Caddy is off by default, so the plain-HTTP warning is what shows.
expect "Plain HTTP: the relay itself answers on the port above and the access token crosses the network unencrypted. Put TLS in front when you can."
# No host picked: the probe refuses before connecting anywhere.
click "Check host"
settle
expect "Pick a host first"
# The picker: opens, lists the vault host, Esc closes it.
click "Select a host"
settle
expect "Search hosts..."
expect "RelayHost"
type escape
settle
absent "Search hosts..."
click "Select a host"
settle
click "RelayHost"
settle
absent "Search hosts..."
absent "Pick a host first"
# Unattended dial: a host whose key is unknown, or one that answers
# nothing at all, is refused either way, and the hint under the failure
# names the way out in words that hold for both.
click "Check host"
# The refusal lands from a streamed task, one frame after the dial
# fails; give it that frame.
wait 1500
settle
expect "An unattended connection asks nothing: the host has to be reachable and its key already known. Connect to it once from a terminal tab first."
