# AgenC Bridge — setup

## What this is

A protocol, not a public API. The operator's assistant sends signed,
encrypted JSON task envelopes into a shared directory bus; an agent node
on another machine polls that bus, runs the task through its local agent,
and writes a signed, encrypted result envelope back. Full spec:
`PROTOCOL.md`. Code: `bridge.py` (Python, Linux and Windows — stdlib
plus the `cryptography` package for envelope v3; install it with
`pip install -r requirements.txt`). In this deployment the assistant is
Muse and the agent is AgenC; the protocol itself is agent-agnostic —
any assistant and any CLI agent can fill those roles.

Tested end-to-end on this cloud PC on 2026-11-06: the assistant (Muse)
sent a task, the local AgenC (OpenRouter + Crouton Alpha) ran it, and the
signed result came back in 8.3 seconds. A tampered task was rejected and
moved to `bus/dead/` without running.

## 1. On every node: give each node its own key

Install Python 3.10+ and AgenC (https://get.agenc.ag), then copy
`bridge.py` and `PROTOCOL.md` to each machine.

Each node gets its **own Ed25519 keypair** — there is no shared
secret any more (the v1 HMAC secret and the
`setup-secret-*.sh/ps1` scripts are legacy and no longer needed).

```sh
# On each node, once — creates keys/<node>.pem.enc + keys/<node>.pub
# AND the node's X25519 encryption keypair (keys/<node>.x25519.pub,
# keys/<node>.x25519.enc, keys/<node>.x25519.attest). Envelope v3
# encrypts every payload for its recipient; a node with no
# encryption keypair cannot send or receive v3 mail.
python3 bridge.py keygen --node agenc-desktop-linux

# Trust that node on every node it will talk to (repeat per node):
# trust publishes the encryption key too (auto-picked up from the
# node's local key files, attestation verified first).
python3 bridge.py trust --node agenc-desktop-linux \
    --pubkey ~/.config/agenc-bridge/keys/agenc-desktop-linux.pub \
    --role worker

# Encryption keys rotate daily: a cron runs rotate-keys, which issues
# a fresh X25519 keypair per node (48h grace for in-flight mail) and
# distributes the updated registry itself — no hand-copy. Each node
# validates the signed registry-update envelope (root pin, cert
# chains, enc attestations, newer sequence) before adopting it, and
# applies it hands-free in its poll cycle, in the hook, or via
# `bridge.py registry-pull`. A node offline at rotation time picks
# its queued update up when it reconnects, inside the grace window.
# `bridge.py distribute-registry` re-sends on demand; `resync` is
# the manual fallback (a hand-copied registry, same validation).
# What still needs a human: a desktop rotating its OWN keys has to
# get its new public key to the master (publish-enc-key + resync) —
# no desktops exist yet to test that leg against.
python3 bridge.py rotate-keys --dry-run   # what would change
python3 bridge.py keys --node agenc-desktop-linux  # key age, attestation
python3 bridge.py status   # registry seq + pending updates
```

Roles: `master` (task + result + ask + message — full control,
e.g. `agenc-cloud`; `owner` is the same set), `worker` (task +
result + ask + message — an AgenC that runs tasks, may task other
nodes, and may ask the assistant questions; its questions are
data, never commands), `asker` (ask + message — may ask the
assistant questions, may not run tasks), `slave` (result only —
runs tasks and returns results, but cannot task, ask, or message
anyone, so it can never prompt the master into an action), `relay`
(no permissions — the relay forwards only). The registry
(`trusted-keys.json`) holds public keys only and is git-ignored; a node not in it cannot
speak at all. To remove a node: `python3 bridge.py revoke
--node <name>`. Each node also gets its **own encryption key**
for its private key at rest — `keygen` creates a fresh random
one at `~/.config/agenc-bridge/passphrases/<node>` (mode 600),
or uses `AGENC_BRIDGE_PASSPHRASE_<NODE>` if that is set. A node
created before per-node keys uses the shared bridge passphrase
until it is migrated with `python3 bridge.py rekey --node
<name>` (atomic: ciphertexts swap first, then the key file,
with `.bak` backups kept until the node is proven working);
`python3 bridge.py registry` shows per node whether
its encryption key is per-node or shared (legacy). Once every
node is per-node, retire the shared passphrase with `python3
bridge.py retire-shared-passphrase` (it refuses while any node
still needs it, and names them). Never copy a
per-node key file to another machine — each machine's node
needs its own. Pin the root of trust on the machine that holds
the master key: `python3 bridge.py pin-root` (auto-pinned when
the first master is trusted; `bridge.py registry` shows the
pinned root and each node's certificate chain). To compare a key out of band before trusting

### Caps: one provider key per node

Caps are enforced by the key and by AgenC, not by the bridge
(see PROTOCOL.md). Give each worker node its **own OpenRouter
key**, with its own credit limit set at OpenRouter when the key
is created — that limit is the node's dollar cap, and OpenRouter
enforces it.

```sh
# 1. In OpenRouter, create a key for this node and set its limit.
# 2. On the node, write the key to a file (mode 600), then store it:
printf 'sk-or-v1-...' > /tmp/node-key.txt && chmod 600 /tmp/node-key.txt
python3 bridge.py provider-key --node agenc-desktop-linux \
    --from-file /tmp/node-key.txt
# The file is deleted after it is read; the key is stored encrypted
# (the node's own encryption key) and is never printed. Check it with:
python3 bridge.py registry   # shows "provider key: set" per node
```

When that node runs a task, the worker hands its key to the
agent as `OPENROUTER_API_KEY`. A node with no stored key runs on
whatever the agent's environment already has. If a stored key
cannot be decrypted, the task is rejected and the agent never
runs — it never falls back to a shared key. To remove a node's
key: `python3 bridge.py provider-key --node <name> --remove`.

Per-run bounds go on the task itself: `bridge.py send ...
--budget eco|balanced|max --max-calls <n>`. AgenC enforces
those (token preset / call cap); it takes no dollar flag, so
the dollar cap lives in the key.

To compare a key out of band before trusting it,
`python3 bridge.py fingerprint --node <name>` prints its
60-digit fingerprint — optional, the way Signal's safety-number
check is optional.

**Role changes need a master's approval.** A role is certified
by a master key (see `PROTOCOL.md`): `trust` certifies the role
it writes; `python3 bridge.py promote --node <name> --role
<role>` changes a role (a slave becoming a master, for
example); `python3 bridge.py approve --node <name>` certifies a
role that was written uncertified. All three refuse without a
master key on the machine. Approve on the machine that holds a
master key (the cloud), then copy the certified
`trusted-keys.json` to the other machines — it holds public keys
only. A role edited in the file without a fresh master signature
is ignored: every envelope from that node is rejected.

The private key is encrypted at rest with the node's own
encryption key (AES-256-CBC, PBKDF2): the file
`~/.config/agenc-bridge/passphrases/<node>` (mode 600), the env
var `AGENC_BRIDGE_PASSPHRASE_<NODE>`, or — for nodes not
migrated yet — the shared bridge passphrase
(`AGENC_BRIDGE_PASSPHRASE`, or the mode-600 file
`~/.config/agenc-bridge/passphrase`, kept on a machine so its
worker can answer unattended). Keep the per-node keys and the
shared passphrase in your password manager; the v1
`BRIDGE-PASSPHRASE.txt` file (secret + passphrase) is legacy —
the secret inside it is no longer used, the passphrase still
unlocks unmigrated nodes' private keys.

## 2. Configure AgenC on every node

```sh
agenc config set model_provider openrouter
agenc config set model meta/muse-ember
agenc config set providers.openrouter.zero_data_retention false
```

The last line is this deployment's setting: the live install
runs with zero_data_retention off for the OpenRouter provider,
which means the provider may retain prompts. Do not send it
private data you would not send to a third party.

Set the provider key in the environment on each node:

```sh
export OPENROUTER_API_KEY="sk-or-v1-..."
```

On this cloud PC the key is held in the secure vault and a fresh
surrogate is used instead of the real key; on a desktop, the real
key in the environment is the normal way.

## 3. Sandbox

- **Linux desktop:** install bubblewrap (`sudo apt install bubblewrap`)
  and leave AgenC's sandbox on its default `workspace-write` mode.
- **Windows:** AgenC has no Linux-style sandbox; run the worker
  only in a project directory you trust, and keep the approval
  policy at `on-request`.
- **This cloud PC (limitation):** `apt-get update` hangs here, so
  bubblewrap could not be installed and the local AgenC was tested
  with `sandbox_mode` set to `danger-full-access`. That is test-only
  and is **not** recommended for a desktop. Fix it here by installing
  bubblewrap and setting the sandbox back to `workspace-write`.
- **Reverse channel, tested 2026-11-06:** an agent can prompt the
  assistant as if the assistant were an LLM — `bridge.py ask`
  writes a prompt envelope, the assistant answers with
  `bridge.py reply`, the agent reads it with
  `bridge.py fetch-answer`. The fast path is the MCP tool plus the
  event hook (see PROTOCOL.md): `ask_muse` works even in headless
  one-shot mode once the two `mcp.muse-bridge.*` permissions are
  approved — no durable run needed for that. Two gotchas found by
  testing: (1) headless one-shot mode (`agenc -p`) refuses shell
  commands ("no approver"), so AgenC can only call the bridge CLI
  from a durable run (`agenc run start --permission-mode
  bypassPermissions`), which also requires the project directory
  to be a git repo with at least one commit — use the MCP tool
  instead in `-p` mode. (2) AgenC's daemon
  does not inherit shell environment variables, so the bridge
  private key and its encryption key must live in files —
  `~/.config/agenc-bridge/keys/<node>.pem.enc` and
  `~/.config/agenc-bridge/passphrases/<node>` (or the shared
  `~/.config/agenc-bridge/passphrase` for unmigrated nodes) —
  not only in `AGENC_BRIDGE_PASSPHRASE`. An env-only setup will
  fail signature checks on envelopes AgenC writes.

### MCP routing tokens

One MCP connection can talk to many targets: the routing token
goes first in the tool arguments (`token`, then `to`). Issue it
where a master key lives (the cloud), then give it to the
calling machine — the token is printed once and never stored in
plaintext, so save it where the MCP server can read it:

```sh
python3 bridge.py mcp-token --from grokbuild-cloud --to "*" --expiry-days 30
python3 bridge.py mcp-token --verify <token>   # check what it allows
python3 bridge.py mcp-token --list             # ids only, never raw tokens
python3 bridge.py mcp-token --revoke <token-id>
```

`--to "*"` is a wildcard: that caller may talk to any target
through the one connection. A token for one target only (`--to
agenc-cloud`) refuses any other target. Register the server with
the caller node and its token, then approve the two tools:

```sh
agenc mcp add muse-bridge python3 <path-to-bridge>/bridge-mcp.py \
  --node grokbuild-cloud --token <token> -t stdio
agenc permissions approve --persist user 'mcp.muse-bridge.ask_muse'
agenc permissions approve --persist user 'mcp.muse-bridge.message_muse'
```

Prefer `AGENC_BRIDGE_NODE` / `AGENC_BRIDGE_MCP_TOKEN` in the
server's environment over the flags: `--token` works, but the
token is visible in the process list (`ps`) while the server
runs. With no token and the target left at its default
(agenc-cloud), the server still signs as agenc-cloud as before —
existing setups keep working. A token is bearer until it expires
or is revoked: keep expiries short, revoke tokens you no longer
need, and never paste a token into a prompt — it goes in the
server's env, or as the `token` tool argument.

### The launcher — the system that starts

One command issues the starting token and starts the MCP
server, with the token kept completely separate from the
encrypted envelopes (it is verified in-process before anything
is sent and never travels in an envelope):

```sh
python3 bridge.py launch --node grokbuild-cloud --to "*" --expiry-days 30
```

The token is passed to the server through its environment only
— never on a command line, never printed, never logged — and it
is revoked when the server stops (Ctrl-C), so a fresh token is
issued on the next launch. `--no-revoke` leaves the token live
after the server stops. The caller node must be certified with
its key on this machine, and the token is issued only by a
master/owner with a valid root-chained certificate.

To use the launcher with AgenC, register the launcher itself as
the MCP server command — AgenC spawns it, it issues the token
and starts the server, and JSON-RPC flows through its stdio to
the server:

```sh
agenc mcp add muse-bridge python3 <path-to-bridge>/bridge.py launch \
  --node grokbuild-cloud --to "*" -t stdio
```

Then approve the two tools as above. Every AgenC session gets
a fresh token, and stopping AgenC revokes it.

## 4. Run a worker

Each node gets a name. Use `agenc-cloud` for this PC,
`agenc-desktop-linux` and `agenc-desktop-windows` for the desktops.

```sh
python3 bridge.py serve --bus /path/to/bus --node agenc-desktop-linux --project-root /path/to/project
```

`serve` polls every 10 seconds. `poll` runs one pass and exits,
which is what the sync wrappers below use.

The worker only runs `prompt` tasks, only inside `--project-root`,
and only tasks signed by a node in the trusted-keys registry with
the `task` permission. Anything else is rejected to `bus/dead/`.

## 5. Send a task (from the assistant, or any sender)

```sh
python3 bridge.py send --bus /path/to/bus --to agenc-desktop-linux \
  --prompt "Fix the failing parser test in this repo."
python3 bridge.py wait --bus /path/to/bus --id <task-id>
```

## 6. Transport: syncing the bus

The bus is just a directory. For desktop nodes, use a **private**
GitHub repo:

```sh
# on each node, once
git clone <private-repo-url> ~/agenc-bus
```

Then loop: pull, poll once, push. Wrappers are included:

- Linux: `sync-linux.sh ~/agenc-bus agenc-desktop-linux ~/project`
- Windows: `sync-windows.bat C:\agenc-bus agenc-desktop-windows C:\project`

Run the wrapper on a schedule (systemd timer / cron on Linux,
Task Scheduler on Windows, every 1–2 minutes) or in a loop.

Do not mix transports on one bus, or two copies can claim the
same task.

## 7. Node names

| Node | Machine | Role | Model |
|---|---|---|---|
| `agenc-cloud` | this cloud PC (Linux) | owner | assistant + worker (answers prompts, runs tasks) — meta/muse-ember via OpenRouter |
| `grokbuild-cloud` | this cloud PC (Linux) | worker | Grok Build CLI (`grok`) — needs `grok login` |
| `grokcode-cloud` | this cloud PC (Linux) | worker | grok-code (`grok-code`) — needs `XAI_API_KEY`; interactive only, no poll worker |
| `grokbot-cloud` | xAI cloud | asker | Grok Bot — via MCP / local execution, not a poll worker |
| `relay` | this cloud PC (Linux) | relay | — (forwards only) |
| `agenc-desktop-linux` | Your Linux desktop | worker | meta/muse-ember via OpenRouter |
| `agenc-desktop-windows` | Your Windows desktop | worker | meta/muse-ember via OpenRouter |

The cloud PC is a single node, `agenc-cloud`: the assistant and the
worker on that machine share the node name and key. Tasks and prompts
are both addressed to it; the worker claims tasks, the assistant
answers prompts. Worker agent profiles: see `WORKERS.md`.

Address a task to one node, or to `*` for any worker to pick up.

## 8. Web relay (nodes on different machines, over the internet)

The file bus above moves envelopes by syncing a directory. The
web relay (`relay-web.py`) moves them live instead: nodes connect
over WebSocket and envelopes are pushed within 0.5s. Same
handshake and verification as the localhost relay, same bus as
the durable record — only the transport changes.

```sh
# On the machine that hosts the relay (needs a public IP or domain):
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python relay-web.py --host 0.0.0.0 --port 8766 \
    --bus ~/workspace/agenc-bridge/bus
# Put TLS in front of it: --cert/--key here for wss:// directly,
# or a reverse proxy (Caddy/nginx) terminating TLS and forwarding
# plain ws:// to this port. Never expose plain ws:// to the internet.

# On every client machine (desktops, other nodes):
export AGENC_BRIDGE_WEB_RELAY=wss://relay.example.com:8766
# bridge-mcp.py then uses the web relay first, falling back to the
# localhost TCP relay and then to bus polling. The MCP server must
# run under the venv python for the web relay: .venv/bin/python
# bridge-mcp.py
```

The relay's own key is the `relay` node in the registry (role
`relay`, no permissions — it forwards only, it can't send tasks
or ask questions). Every node needs that key in its registry to
verify the relay's pushes. Test the relay with
`tests/test_relay_web.py` before pointing real nodes at it.

### Keeping the web relay up

The web relay has its own watchdog, mirroring the localhost
relay's (`relay-watchdog.sh` + `agenc-bridge-relay-watchdog`
cron, every 5 minutes). `relay-web-watchdog.sh` checks for a
listener on 127.0.0.1:8766 (`AGENC_BRIDGE_WEB_RELAY_PORT`
overrides the port) and restarts `relay-web.py` under the venv
python if it is down, logging to `relay-web.log`; it prints
nothing when the relay is healthy. On a real Linux host, run it
from `relay-web.service` (systemd, `Restart=on-failure`) or from
a cron every 5 minutes — the `agenc-bridge-web-relay-watchdog`
cron does the latter. On this cloud PC the web relay runs
locally on 127.0.0.1:8766 (not exposed to the internet) under
the same watchdog cron, so it comes back after a VM replacement
the same way the localhost relay does.

## 9. Optional DLC: bridge-guard (file exchange between agents that do not trust each other)

> **Install prompt — answer this before you finish setup:**
> The bridge has an optional add-on, **bridge-guard**, for file
> exchange between agents that do not trust each other: a guardian
> on each side approves every file, only copies leave, and a
> receipt deletes the copy. Do you want to install it?
>
> - Yes: `git clone https://github.com/Macro-Harder/bridge-guard`
>   and follow its `SETUP.md` (one guardian per side, allowlisted
>   directories only).
> - No: skip it. The bridge works fine without it — install it
>   only if the agents on the two sides do not trust each other.

bridge-guard is a separate repo and a separate install: it never
changes bridge code, never reads bridge keys, and never writes to
the bus. It validates file-request and receipt JSON and stages
copies locally; the bridge (or any other channel) moves the bytes.
See [bridge-guard](https://github.com/Macro-Harder/bridge-guard)
and its `INTEGRATION.md` for how it latches on.

## 10. Optional DLC: bulkhead (information-flow compartments)

> **Install prompt — answer this before you finish setup:**
> The bridge has an optional add-on, **bulkhead**, for keeping
> labelled data inside its compartments: labels travel with data
> across bridge messages, tool outputs, retrieval, files and
> memory, and sends, public pushes and uploads pass a checked
> gate instead of going straight out. Do you want to install it?
>
> - Yes: `git clone https://github.com/Macro-Harder/bulkhead`
>   and follow its `SETUP.md` (one declaration per connection;
>   level 5 is the default level, and enabling a connection is
>   a local choice on each side).
> - No: skip it. The bridge works fine without it — install it
>   only if data must not cross between compartments or leave
>   the machine unchecked.

bulkhead is a separate repo and a separate install: it never
changes bridge code, never reads bridge keys, and writes nothing
to the bus except ordinary bridge messages for connections the
local operator has enabled. Enabling is per-connection and is
set locally on each side only — no remote agent can turn it on,
off, or change its level. See
[bulkhead](https://github.com/Macro-Harder/bulkhead) and its
`INTEGRATION.md` for how it latches on.
