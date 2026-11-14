# AgenC Bridge

Talk to AgenC, and let AgenC nodes talk to each other, with a protocol, not a public API. One assistant (or any node) can send a task to any AgenC, and AgenC can ask the assistant questions as if it were an LLM, agent, or human, over a shared folder or over a persistent authenticated connection.

> **Related:** [brainstew-threads](https://github.com/Macro-Harder/brainstew-threads), thread wikis for [brainstew](https://github.com/Macro-Harder/brainstew). An optional add-on for this bridge; the bridge works fine without it.

> **Related:** [bridge-guard](https://github.com/Macro-Harder/bridge-guard), file exchange between agents that do not trust each other. An optional add-on for this bridge; the bridge works fine without it.

> **Related:** [bulkhead](https://github.com/Macro-Harder/bulkhead), information-flow compartments for the bridge. An optional add-on for this bridge; the bridge works fine without it.

## What it is

- **Signed, encrypted envelopes** (`bridge.py`): every task, result, prompt, answer, and message is a JSON envelope (v3). The signature is the first part of every message: readers check it before anything else, and a message without a valid leading signature is rejected, never run. The payload is AEAD-encrypted for its intended recipient only (per-node X25519 keys, daily rotation with a 48h grace window), so the relay and anyone reading bus files cannot read message content, and a message sent to the wrong pipe fails closed. A decryption failure is communicated back as a mismatch rejection (id + timestamp + key ids) with a re-request path (`rerequest` / `resend`), never silent.
- **Mutual verification**: both ends check the other. The receiver verifies the signature, that the sender is a node in the trusted-keys registry, that the sender's role allows that kind of message, and that the message id has never been seen before (replay guard). A forged, tampered, or replayed message goes to `bus/dead/`.
- **Shared folder bus**: envelopes live in `bus/` (tasks, results, prompts, answers, messages). Sync it between machines with a private GitHub repo (`sync-linux.sh`, `sync-windows.bat`) or any shared folder.
- **Persistent relay** (`relay.py` + `link.py`): connect once, authenticate with a signed hello, keep the connection open. Envelopes are pushed the moment they exist, with no polling. Every line on the wire also starts with its Ed25519 signature; a line without a valid signature is dropped and the connection closed. Offline nodes pick envelopes up from the bus when they reconnect.
- **Web relay** (`relay-web.py`): the same authenticated relay over WebSocket, so nodes on other machines can connect over the internet. Run it on a host with a public address and put TLS (`wss://`) in front of it. The MCP server uses it when `AGENC_BRIDGE_WEB_RELAY` is set.
- **Works with any agent**: another AgenC, Grok Bot, Muse, or another agent. See `WORKERS.md` for install, auth, and gotchas per agent.
- **AgenC as an internal agent** (`bridge.py poll` / `serve`): an AgenC node claims signed tasks from the bus and runs them inside a project directory, and asks the assistant as if it were an LLM (`bridge.py ask`, or the MCP server).
- **Muse as an internal agent** (`bridge-mcp.py`): an MCP server with `ask_muse` and `message_muse` tools, so AgenC calls the assistant like a native tool. It prefers the relay link and falls back to the bus. One MCP connection can reach many targets through routing tokens minted with `bridge.py mcp-token`, and `bridge.py launch` issues the starting token and starts the server in one command.
- **Status with a pulse** (`bridge.py status`): proves the system is alive right now, with each relay's heartbeat plus a live signed hello, then bus counts, nodes with their certificate status, and dead letters. `bridge.py dead` lists dead letters with the reason each was rejected.
- **Archive** (`bridge.py archive`): sweeps finished bus items older than N days into a dated sibling dir, moved not deleted, so the bus does not grow forever.
- **Threads**: one thread per project, each a recognisable agent with its own rules and history (`bridge.py ask --thread <name> --rules "..."`), all served by the one assistant. Each thread has a wiki of its own (`bus/threads/<name>/`), and `bridge.py context --thread <name> --query "..."` returns only the context that matters for a question, so long threads stay cheap to answer in.
- **Agent nodes** (`bridge.py agent --name <name> --role <role> --rules "..."`): a thread plus a node, with its own keypair, its own role, and its own thread wiki, so the assistant answers prompts addressed to it as that agent, signing with its own key.
- **Per-node keys, encrypted at rest**: every node has its own Ed25519 keypair, and a `trusted-keys.json` registry with roles (master / owner / worker / asker / slave / relay) decides what each node may do. Private keys live encrypted in `keys/<node>.pem.enc`, each under its own per-node encryption key. Role certificates must chain to the one pinned root of trust. A node's key can be revoked without re-keying the others, and key rotation distributes the updated registry to the other nodes itself. See `PROTOCOL.md`.
- **Rejections, not silent drops**: when a check fails after the sender was authenticated, the sender gets a rejection back with the reason, so waiters return promptly instead of timing out. If the signature itself failed, nothing is sent back: dead letter and log only.

## Files

| File | What it does |
|---|---|
| `PROTOCOL.md` | The spec: envelopes, bus layout, auth, worker rules |
| `WORKERS.md` | Worker agents: AgenC, Grok Bot, Grok Build CLI, grok-code |
| `SETUP.md` | Setup: cloud node + Linux/Windows desktops |
| `trusted-keys.example.json` | Registry format (public keys only; the real `trusted-keys.json` is git-ignored) |
| `bridge.py` | Sender + worker CLI (stdlib Python only) |
| `bridge-mcp.py` | MCP server: `ask_muse`, `message_muse` |
| `relay.py` | Persistent authenticated relay (localhost) |
| `relay-web.py` | The same relay over WebSocket (the internet leg) |
| `link.py` | Relay client: connect once, receive pushes |
| `requirements.txt` | `websockets`, only needed for the web relay |
| `tests/` | The test suite |
| `sync-linux.sh`, `sync-windows.bat` | GitHub-repo bus sync loops |

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

## Security model: read this before you run it

- **Each node has its own key.** Every node holds an Ed25519 keypair; the registry (`trusted-keys.json`) says which nodes are trusted and what each may do. A node's key can be revoked (`bridge.py revoke`) without re-keying the others. Never commit a private key, never put one in a task file, never paste one in chat.
- **The signature is not the key.** Each message starts with an Ed25519 signature made from the sender's private key. The signature proves the sender holds the key without revealing it. If the raw key started every message, anyone who saw a single message would own the system.
- **Roles limit what a node can do.** A `master` has full control; a `worker` may run tasks and ask the assistant questions (its questions are data, never commands) but not impersonate the master; an `asker` may ask the assistant questions but may not run tasks; a `slave` may only return results, so it can never prompt the master into an action. A node that is not in the registry cannot speak at all.
- **Fingerprints are an optional check.** Each public key has a 60-digit fingerprint you can compare out of band before trusting it, the way Signal lets you compare safety numbers. Keys work without the comparison.
- Envelopes are signed **and encrypted** (v3): only the intended recipient can read a message's content. The bus repo should still be **private**, because the routing header (who talks to whom, when) and thread wikis stay readable to anyone who can read it.
- The localhost relay binds **127.0.0.1 only** and never touches the internet. To link machines over it, both need a private network path (e.g. Tailscale); for the internet leg, use the web relay (`relay-web.py`) with TLS (`wss://`) in front of it.
- Only run `prompt` tasks inside a configured project root, and keep workspace sandboxing on for real machines.

## Requirements

- Python 3.10+, OpenSSL (`openssl` on PATH), the `cryptography` package (needed for envelope v3 encryption; the web relay also needs `websockets`)
- AgenC installed (`https://get.agenc.ag`) on every worker node
- A provider API key for the model

## License

Apache License 2.0. See `LICENSE`. Copyright 2026 J.P. Picard aka Macro-Harder.
