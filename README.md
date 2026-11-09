# AgenC Bridge

Talk to AgenC — and let AgenC nodes talk to each other — with a
protocol, not a public API. One assistant (or any node) can send a
task to any AgenC, and AgenC can ask the assistant questions as if
it were an LLM, agent, or, human, over a shared folder or over a persistent
authenticated connection.

> **Related:** [brainstew-threads](https://github.com/Macro-Harder/brainstew-threads) — thread wikis for [brainstew](https://github.com/Macro-Harder/brainstew), one wiki per agent/project, with a context tool that pulls only what matters. A DLC for brainstew, built from this bridge's thread wikis and context tool.

> **Related:** [bridge-guard](https://github.com/Macro-Harder/bridge-guard) — file exchange between agents that do not trust each other: a guardian on each side approves every file, only copies leave, and a receipt deletes the copy. An optional DLC for this bridge; the bridge works fine without it.

## What it is

- **Signed, encrypted envelopes** (`bridge.py`): every task, result, prompt,
  answer, and message is a JSON envelope (v3). The signature is the
  **first part of every message** — readers check it before
  anything else, and a message without a valid leading signature
  is rejected, never run. The payload is AEAD-encrypted for its
  intended recipient only (per-node X25519 keys, daily rotation
  with a 48h grace window) — the relay and anyone reading bus
  files cannot read message content, and a message sent to the
  wrong pipe fails closed. A decryption failure is communicated
  back as a mismatch rejection (id + timestamp + key ids) with a
  re-request path (`rerequest` / `resend`), never silent.
- **Mutual verification**: both ends check the other. The receiver
  verifies the signature, that the sender is a node in the
  trusted-keys registry, that the sender's role allows that kind
  of message, and that the message id has never been seen before
  (replay guard). A forged, tampered, or replayed message goes
  to `bus/dead/`.
- **Shared folder bus**: envelopes live in `bus/` (tasks, results,
  prompts, answers, messages). Sync it between machines with a
  private GitHub repo (`sync-linux.sh`, `sync-windows.bat`) or any
  shared folder.
- **Persistent relay** (`relay.py` + `link.py`): connect once,
  authenticate with a signed hello, keep the connection open.
  Envelopes are pushed the moment they exist — no polling. Every
  line on the wire also starts with its Ed25519 signature; a line
  without a valid signature is dropped and the connection closed.
  The relay watches the bus every 0.5s and pushes to connected
  nodes; offline nodes pick envelopes up from the bus when they
  reconnect.
- **Web relay** (`relay-web.py`): the same authenticated relay
  over WebSocket, so nodes on other machines can connect over the
  internet — same signed-hello handshake, same signature-first
  wire lines, same 0.5s bus watch. Run it on a host with a public
  address and put TLS (`wss://`) in front of it. The MCP server
  uses it when `AGENC_BRIDGE_WEB_RELAY` is set.
  `relay-web-watchdog.sh` (cron every 5 minutes) and
  `relay-web.service` (systemd) keep it running, mirroring the
  localhost relay's watchdog.

connecting agents

- **Works with any agent** — another AgenC, Grok Bot, Muse, or
  another agent. Grok connects three ways: Grok Bot (hosted,
  over MCP as a coordinator), Grok Build CLI (a headless poll
  worker, after `grok login`), and grok-code (third-party CLI,
  via MCP/coordinator — it has no headless mode). See
  `WORKERS.md` for install, auth, and gotchas per agent.
- **AgenC as an internal agent** (`bridge.py poll` / `serve`): an
  AgenC node claims signed tasks from the bus and runs them inside
  a project directory, and asks the assistant as if it were an
  LLM (`bridge.py ask`, or the MCP server).
- **Grok as an internal agent**: Grok Bot, Grok Build CLI, and
  grok-code all connect as native agents on the bridge — see
  `WORKERS.md` for which way each one uses.
- **Muse as an internal agent** (`bridge-mcp.py`): an MCP server with
  `ask_muse` and `message_muse` tools, so AgenC calls the
  assistant like a native tool. Prefers the relay link, falls
  back to the bus.
- **Status with a pulse** (`bridge.py status`): proves the system
  is alive right now — each relay's heartbeat (rewritten every
  couple of seconds by its watch loop) plus a live signed hello
  answered by a welcome, with round-trip time — then bus counts,
  nodes with their certificate status, and dead letters.
  `bridge.py dead` lists dead letters with the reason each was
  rejected, so a dropped envelope explains itself.
- **Archive** (`bridge.py archive`): sweeps finished bus items
  (`done/`, `read/`, `dead/`) older than N days into a dated
  sibling dir `bus-archive-<YYYYMMDD>/`, moved not deleted, so
  the bus doesn't grow forever. Live state never moves;
  `--include-claimed` also sweeps stale claims, `--dry-run`
  lists what would move.
- **Threads**: one thread per project, each a recognisable agent
  with its own rules and history (`bridge.py ask --thread <name>
  --rules "..."`, `bridge.py thread --id <name>`), all served by
  the one assistant — and each thread has a wiki of its own
  (`bus/threads/<name>/`: rules, distilled facts, and the history
  page, which is the index). `bridge.py context --thread <name>
  --query "..."` returns only the context that matters for a
  question, so long threads stay cheap to answer in.
- **Agent nodes** (`bridge.py agent --name <name> --role <role>
  --rules "..."`): when an agent needs its own powers, not just
  its own rules — a thread plus a node, with its own keypair,
  its own role, its own thread wiki, and a place in the served
  list, so the assistant answers prompts addressed to it as that
  agent, signing with its own key.
- **Caps, through the keys and AgenC** (no spend ledger in the
  bridge): each node can have its own provider key — its own
  OpenRouter key, with its own credit limit set at OpenRouter
  (`bridge.py provider-key --node <name> --from-file <path>`,
  stored encrypted, never printed). The worker hands the node's
  key to the agent as `OPENROUTER_API_KEY`, so the provider
  enforces the dollar cap. Per-run bounds go on the task:
  `bridge.py send ... --budget eco|balanced|max --max-calls <n>`
  reaches `agenc -p` as `--budget` / `--task-max-calls`, and
  AgenC enforces them. See
  `PROTOCOL.md`.
- **Instant answers**: an event hook wakes the assistant within
  seconds of a prompt landing (see `SETUP.md`).
- **Per-node keys, encrypted at rest**: every node has its own
  Ed25519 keypair, and a `trusted-keys.json` registry with roles
  (master / owner / worker / asker / slave / relay) decides what each node may do.
  Private keys live encrypted (AES-256-CBC, PBKDF2) in
  `keys/<node>.pem.enc`, each under its own per-node encryption
  key (`passphrases/<node>`, mode 600, or
  `AGENC_BRIDGE_PASSPHRASE_<NODE>`); the shared bridge
  passphrase is only a fallback for nodes not migrated yet
  (`bridge.py rekey --node <name>` migrates one — the swap is
  atomic, with `.bak` backups kept until the node is proven
  working; once every node is per-node, `bridge.py
  retire-shared-passphrase` retires the shared file). A node's key can
  be revoked without re-keying the others.
- **Pinned root of trust, signed wikis**: role certificates must
  chain to the one pinned root master (`~/.config/agenc-bridge/
  root.json`, written by `bridge.py pin-root`, or automatically
  when the first master is trusted) — editing the registry to
  make a worker a master and self-signing its certificate no
  longer verifies. Thread wikis carry a signed manifest
  (`manifest.json` over per-file hashes, signed by the thread's
  creator); `bridge.py thread` / `context` show each file as
  verified, unverified, or TAMPERED, and history turns are
  checked against their signed envelopes (`bridge.py sign-thread`
  re-seals a wiki after the operator checks it).
- **MCP routing tokens**: one MCP connection reaches many targets —
  a token goes first in the tool arguments (`token`, then `to`) and
  proves which caller may talk to which target. A token is a hash
  of a fresh random 32-byte secret (unique per issuance, never
  derived from public info); only its SHA-256 is stored, in
  `mcp-tokens.json` (mode 600). `bridge.py mcp-token --from
  <caller> --to <target>` mints one (master only; `--to "*"` is a
  wildcard for any target). Bad, expired, revoked, or wrong-target
  tokens are refused and nothing is sent. With no token and the
  default target, the server still signs as agenc-cloud as before.
- **The launcher — the system that starts**: `bridge.py launch
  --node <caller> [--to <target>] [--expiry-days N]` issues the
  starting token and starts the MCP server in the foreground, in
  one command. The token is kept completely separate from the
  encrypted envelopes: it is verified in-process by
  `bridge-mcp.py` before anything is sent and never travels in
  an envelope, so encryption can never turn a valid token into a
  rejection, and the token gate still rejects anyone who does
  not hold it. The launcher passes the token to the server
  through its environment only — never on a command line (it
  would leak in `ps`), never printed, never logged. Ctrl-C
  stops the server and revokes its token (a fresh token is
  issued on the next launch); `--no-revoke` leaves it live.
  The caller node must be certified with its key on this
  machine, and only a master/owner with a valid root-chained
  certificate may issue the token.
- **Hands-free key rotation — registry distribution**: the
  daily `rotate-keys` (cron ~03:17 CST, 48h grace, then the old
  key is destroyed) now distributes the updated registry itself
  — no hand-copy. It sends the whole registry to every other
  node as a signed `registry-update` envelope (v3, encrypted
  per-pipe like any other envelope; public keys and attestations
  only, never private keys). Each node validates the update
  exactly like `resync` (root pin, certificate chains, enc
  attestations, and a sequence newer than the one it holds)
  before adopting it, and applies it hands-free in its poll
  cycle, in the hook, or via `bridge.py registry-pull`. An
  offline node picks its queued update up when it reconnects,
  inside the grace window; a tampered, unsigned, or
  worker-sent update is refused and filed in `dead/`. `bridge.py
  distribute-registry` does the same step on demand, and
  `bridge.py status` shows the registry sequence and any
  pending updates. What still needs a human: a desktop rotating
  its *own* keys has to get its new public key to the master
  (`publish-enc-key` + `resync`) — no desktops exist yet to
  test that leg against.
- **Rejections, not silent drops**: when a check fails after the
  sender was authenticated (wrong role for the kind, unknown
  recipient, replay), the sender gets a rejection back with the
  reason — a result with status `"rejected"` for a task, an
  answer with `rejected: true` for a prompt — so `wait()` /
  `fetch-answer()` return promptly instead of timing out. The
  relay can reject on a worker's behalf, signed with the relay
  key; a rejection from any other node must still come from the
  node the original was addressed to. If the signature itself
  failed, the claimed sender cannot be trusted, so nothing is
  sent back — dead letter and log only. Messages get dead/ +
  log only (no waiter to return to).

## Files

| File | What it does |
|---|---|
| `PROTOCOL.md` | The v2 spec: envelopes, bus layout, auth, worker rules |
| `WORKERS.md` | Worker agents: AgenC, Grok Bot, Grok Build CLI, grok-code |
| `trusted-keys.example.json` | Registry format (public keys only — the real `trusted-keys.json` is git-ignored) |
| `bridge.py` | Sender + worker CLI (stdlib Python only) |
| `bridge-mcp.py` | MCP server: `ask_muse`, `message_muse` |
| `relay.py` | Persistent authenticated relay (localhost) |
| `relay-web.py` | The same relay over WebSocket (the internet leg) |
| `relay-web-watchdog.sh` | Restarts the web relay if it stops listening (cron every 5 minutes) |
| `relay-web.service` | systemd unit for the web relay on a real host |
| `link.py` | Relay client: connect once, receive pushes (`Link` for TCP, `WebLink` for the web relay) |
| `requirements.txt` | `websockets` — only needed for the web relay |
| `tests/test_relay_web.py` | Tests for the web relay (run: `.venv/bin/python -m unittest tests.test_relay_web -v`) |
| `tests/test_status.py` | Tests for `status`/`dead` (run: `python3 -m unittest tests.test_status -v`) |
| `tests/test_read.py` | Tests for read-on-read (run: `python3 -m unittest tests.test_read -v`) |
| `tests/test_threads.py` | Tests for threads (run: `python3 -m unittest tests.test_threads -v`) |
| `tests/test_context.py` | Tests for the context tool (run: `python3 -m unittest tests.test_context -v`) |
| `tests/test_caps.py` | Tests for caps through the keys and AgenC (run: `python3 -m unittest tests.test_caps -v`) |
| `tests/test_archive.py` | Tests for the bus archive (run: `python3 -m unittest tests.test_archive -v`) |
| `tests/test_agents.py` | Tests for per-agent nodes (run: `python3 -m unittest tests.test_agents -v`) |
| `tests/test_redteam.py` | Red-team tests — attacks that must fail (run: `python3 -m unittest tests.test_redteam -v`) |
| `tests/test_redteam2.py` | Red-team tests, round 2 — regression tests for the independent review's findings (run: `python3 -m unittest tests.test_redteam2 -v`) |
| `tests/test_redteam3.py` | Red-team tests, round 3 — regression tests for the insider-access review's findings: pinned root of trust, signed wiki manifests, replay-rejection guard, per-node relay rate limiting + socket cap, atomic rekey, signature-checked relay rejections, shared-passphrase retirement, MCP relay host/port override, dead sweep, certified-only token issuance (run: `python3 -m unittest tests.test_redteam3 -v`) |
| `tests/test_rejection.py` | Tests for rejection errors on failed checks (run: `python3 -m unittest tests.test_rejection -v`) |
| `tests/test_per_node_keys.py` | Tests for per-node encryption keys and `rekey` (run: `python3 -m unittest tests.test_per_node_keys -v`) |
| `tests/test_mcp_routing.py` | Tests for MCP routing tokens: issue/verify, wildcard routing to 3 targets through one connection, expired/tampered/wrong-target/revoked refusals (run: `python3 -m unittest tests.test_mcp_routing -v`) |
| `tests/test_launcher.py` | Tests for the launcher: token issued + handed over by environment only (never in `ps` args, never printed, never on disk), token revoked when the server stops, uncertified/unknown/no-master-key refusals, token-routed ask through the encrypted path through the launched server (run: `python3 -m unittest tests.test_launcher -v`) |
| `tests/test_distribution.py` | Tests for hands-free registry distribution: rotate distributes the updated registry (v3, public keys only), `registry-pull` applies it on a stale registry, poll applies a pending update, tampered and worker-sent updates refused, `resync` refuses a rollback, offline catch-up across two sequences with an older one skipped, grace-window message still decrypts, old key destroyed after grace, relay forwards a master's update and refuses a worker's (run: `python3 -m unittest tests.test_distribution -v`) |
| `SETUP.md` | Setup: cloud node + Linux/Windows desktops |
| `setup-secret-linux.sh`, `setup-secret-windows.ps1` | v1 legacy: created `secret.enc` for the old shared secret; no longer needed in v2 |
| `sync-linux.sh`, `sync-windows.bat` | GitHub-repo bus sync loops |
| `relay.service` | systemd unit for the relay |
| `relay-watchdog.sh` | Restart the relay if it stops listening (run from a cron every few minutes) |
| `watch-inbox.sh` | Watch your inbox from a shell |

## Quickstart

```bash
# 1. Give this node its own key, and trust the nodes it will talk to:
python3 bridge.py keygen --node agenc-cloud
python3 bridge.py trust --node agenc-cloud --pubkey ~/.config/agenc-bridge/keys/agenc-cloud.pub --role owner
# Pin the root of trust (auto-pinned by trust above, but say it out loud):
python3 bridge.py pin-root
python3 bridge.py registry   # shows the pinned root and each node's cert chain
python3 bridge.py rotate-keys --dry-run   # encryption keys rotate daily; see SETUP.md

# 2. Send a task to an AgenC node:
python3 bridge.py send --bus ./bus --to agenc-cloud \
    --prompt "Reply with exactly the word OK and nothing else."

# 3. Run the worker on the AgenC machine (inside a project directory):
python3 bridge.py poll --bus ./bus --node agenc-cloud \
    --project-root ~/my-project

# 4. Ask the assistant as if it were an LLM:
python3 bridge.py ask --bus ./bus --to agenc-cloud --prompt "What is 17 multiplied by 6?"
python3 bridge.py fetch-answer --bus ./bus --id <prompt-id>

# 5. (Optional) Start the relay for push delivery, no polling:
python3 relay.py               # listens on 127.0.0.1:8765

# 6. (Optional) Start the web relay so nodes on other machines can
#    connect over the internet (same handshake, WebSocket):
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python relay-web.py --host 0.0.0.0 --port 8766   # put TLS in front (see PROTOCOL.md)
export AGENC_BRIDGE_WEB_RELAY=ws://localhost:8766         # clients use it with this env var
```

## Security model — read this before you run it

- **Each node has its own key.** Every node holds an Ed25519
  keypair; the registry (`trusted-keys.json`) says which nodes
  are trusted and what each may do. A node's key can be revoked
  (`bridge.py revoke`) without re-keying the others. Never commit
  a private key, never put one in a task file, never paste one
  in chat.
- **The signature is not the key.** Each message starts with an
  Ed25519 signature made from the sender's private key. The
  signature proves the sender holds the key without revealing
  it — that is why the raw key is never the prefix. If the raw
  key started every message, anyone who saw a single message
  would own the system.
- **Roles limit what a node can do.** A `master` has full
  control; a `worker` may run tasks and ask the assistant
  questions (its questions are data, never commands) but not
  impersonate the master; an `asker` may ask the assistant
  questions but may not run tasks; a `slave` may only return
  results — it cannot task, ask, or message anyone, so it can
  never prompt the master into an action. A node that is not in
  the registry cannot speak at all.
- **Fingerprints are an optional check.** Each public key has a
  60-digit fingerprint you can compare out of band before
  trusting it — the way Signal lets you compare safety numbers.
  Optional: keys work without the comparison.
- Envelopes are signed **and encrypted** (v3): only the intended
  recipient can read a message's content. The bus repo should
  still be **private** — the routing header (who talks to whom,
  when) and thread wikis stay readable to anyone who can read it.
- The localhost relay binds **127.0.0.1 only** and never touches
  the internet. To link machines over it, both need a private
  network path (e.g. Tailscale); for the internet leg, use the
  web relay (`relay-web.py`) with TLS (`wss://`) in front of it.
  Until either is set up, the repo bus is the transport between
  machines.
- AgenC runs tasks with `sandbox_mode = danger-full-access` on
  this test machine only. On real machines, install bubblewrap
  and keep `workspace-write` sandboxing. Only run `prompt` tasks
  inside a configured project root.

## Requirements

- Python 3.10+, OpenSSL (`openssl` on PATH), the `cryptography`
  package (`pip install cryptography`, or `pip install -r
  requirements.txt` — needed for envelope v3 encryption; the web
  relay also needs `websockets`)
- AgenC installed (`https://get.agenc.ag`) on every worker node
- A SI api key (or another AgenC provider) for the model

## Daemon watchdog (cloud PC only)

AgenC on this VM has no native secure storage (libsecret is
missing), and OpenRouter credentials resolve from the
`OPENROUTER_API_KEY` environment variable only — `config.toml`
has no key slot. The daemon autostarts, so any `agenc` call made
while it is down spawns a replacement that inherits the caller's
environment; a keyless caller spawns a keyless daemon, after which
every agent run fails with 401. The daemon only holds a key when
it was started with one in its environment, so any restart loses
it.

`agenc_daemon_watchdog.py` keeps it keyed, checked every 5
minutes by the `agenc-daemon-watchdog` cron:

- `check` reads the daemon pid and looks for the
  `OPENROUTER_API_KEY` *name* in `/proc/<pid>/environ`
  (presence only — the value is never read). No tokens spent,
  no `agenc` command invoked, so a check can never trigger a
  keyless autostart.
- `fix` restarts a down or unkeyed daemon with a fresh
  OpenRouter surrogate from the secure connector, passed only
  through the child process environment — never written to a
  file, a log, or a command line.
- Activity is logged to `~/.agenc/daemon-watchdog.log`
  (state and pids only, no key material).

Per-node provider keys are unaffected: a node with a stored
provider key stays self-sufficient, and the watchdog never
touches provider keys.

## License

Apache License 2.0. See `LICENSE`. Copyright 2026 Captain.
