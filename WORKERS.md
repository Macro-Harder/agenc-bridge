# AgenC Bridge — worker agents

The bridge is agent-agnostic — it works with another AgenC,
Grok Bot, Muse, or another agent. AgenC is the default and the
one tested end-to-end; Grok Bot connects over MCP as a
coordinator; Grok Build CLI is a second poll worker; grok-code
connects via MCP/coordinator (no headless mode — see its
section). The assistant side is the same for all of them —
tasks and prompts are signed envelopes on the bus, whatever runs
them.

## The worker contract

A worker needs three things:

1. **A headless one-shot command** that takes a prompt, does the
   work in a project directory, prints its result, and exits.
   `bridge.py poll --agent <profile>` runs that command per task
   (see `AGENT_PROFILES` in `bridge.py`; `--agent-cmd` overrides
   it for tests or custom agents).
2. **Auth of its own** — an API key, a subscription login, or
   whatever that agent uses. The bridge never carries the agent's
   credentials; each agent authenticates itself on its own machine.
3. **A node key** — `bridge.py keygen --node <name>` + `trust`
   with role `worker` (may run tasks, may not prompt the
   assistant). See `SETUP.md` §1.

The worker only runs `prompt` tasks, only inside `--project-root`,
and only tasks signed by a node in the trusted-keys registry.

## AgenC (default profile: `--agent agenc`)

- Install: https://get.agenc.ag
- Headless: `agenc -p --no-tui "<prompt>"`
- Auth: provider key in the environment (here: OpenRouter via
  `OPENROUTER_API_KEY`); `agenc config set model_provider
  openrouter` + `model meta/muse-ember` in this deployment.
- Gotchas, found by testing: headless `-p` refuses shell commands
  ("no approver") — AgenC can only call the bridge CLI from a
  durable run (`agenc run start --permission-mode
  bypassPermissions`, project must be a git repo with a commit).
  Use the MCP tool (`ask_muse`) instead in `-p` mode. AgenC's
  daemon does not inherit shell env vars — credentials must live
  in files, not only in env vars.
- Node names in this deployment: `agenc-cloud` (this PC),
  `agenc-desktop-linux`, `agenc-desktop-windows`.

## Grok Bot (xAI cloud agent — no `--agent` profile)

Grok Bot is not a CLI — it is xAI's hosted agent with a managed
Linux computer, a terminal, and background execution. There is no
headless command for `bridge.py poll` to run, so it is **not** a
poll worker. It connects two other ways (both reported in
third-party write-ups, not verified here):

1. **Over MCP (the clean way).** Grok Bot supports custom MCP
   connectors. Register `bridge-mcp.py` as a custom MCP server
   and Grok Bot can call `ask_muse` / `message_muse` like any
   MCP client — asking the assistant questions and sending notes
   without any shell access. Pass it a routing token for its node
   (`bridge.py mcp-token --from grokbot-cloud --to "*"`) so the
   one connection can reach any target — see PROTOCOL.md.
2. **Local PC execution.** Grok Bot can run commands on an
   authorized local computer (Execution on Local Computer). On a
   machine with the bridge installed, it can run `bridge.py`
   commands there — including `poll` with another agent's
   profile — so it acts as a coordinator that launches and
   watches worker CLIs, rather than as a worker itself.

Its strength is coordination across repos, trackers, and agents,
not raw coding — for a single repo task, running the worker CLI
directly is simpler. Two warnings from the same write-ups: all
Bots on one account share the same cloud computer, so credentials
there are not isolated between Bots; and a child CLI waiting for
an interactive approval can hang an unattended workflow, so set
permissions and sandboxing before a long job starts.
- Node name: `grokbot-cloud` (role `asker` — may ask the
  assistant and send messages, may not run tasks).

## Grok Build CLI (official xAI — profile: `--agent grok-build`)

The `grok` command: xAI's CLI coding agent, the sibling of Claude
Code / Codex. Verified installed here: **grok 1.0.77** via
`npm install -g @xai-official/grok` (Node 18+ needed).

- Install: `npm install -g @xai-official/grok` (preferred — the
  `curl https://x.ai/cli/install.sh | bash` installer is
  Cloudflare-walled in some environments).
- Auth: `grok login` once — browser OAuth, token cached in
  `~/.grok/auth.json`. Needs a **SuperGrok or X Premium+**
  subscription (no per-token billing). Fallback: `XAI_API_KEY`
  env var for pay-as-you-go via api.x.ai.
- Headless (what the bridge runs):
  `grok --no-auto-update --always-approve -p "<prompt>"`
  - `--no-auto-update` skips background update checks — always
    pass it in automation.
  - `--always-approve` auto-approves tool executions. Without
    it, headless runs may stall waiting on an approval prompt.
    Omit it deliberately for read-only audit work so Grok can't
    mutate files.
  - `--output-format json` returns one JSON object at the end
    (the bridge uses plain output).
  - `--cwd <path>` sets the working directory; `--max-turns <N>`
    caps agent turns. No git repo is required.
- MCP: Grok auto-reads `CLAUDE.md`, `.claude/` (skills, MCPs),
  and `AGENTS.md`. It can also run as an ACP agent
  (`grok agent stdio`). Register the bridge MCP server
  (`bridge-mcp.py`) the same way as for AgenC — see
  `PROTOCOL.md`.
- Smoke test (needs auth): `grok --no-auto-update -p "Say ok."`
  Verified here without auth: fails cleanly with "Not signed
  in. To authenticate without a browser, run: grok login
  --device-code" — no hang, no browser needed on the machine
  itself. The bridge profile was tested the same way: a task
  sent to `grokbuild-cloud` came back as an error result with
  that message, proving the command runs and its output is
  captured. A real run needs `grok login` (or `XAI_API_KEY`).
- Node names: `grokbuild-cloud`, `grokbuild-desktop-linux`, …
  (role `worker`).

## OpenCode (open source — profile: `--agent opencode`)

sst/opencode, MIT. Verified installed here: **opencode 1.19.5**
via `npm install -g opencode-ai` (Node 18+ needed).

- Install: `npm install -g opencode-ai` (preferred), or the
  installer at https://opencode.ai/install.
- Auth: the provider's own key in the environment. This
  deployment uses OpenRouter, so `OPENROUTER_API_KEY` — the
  node's bridge provider key reaches it automatically (see
  `bridge.py provider-key`). No subscription login needed.
- Headless (what the bridge runs):
  `opencode run --auto -m openrouter/meta/muse-ember "<prompt>"`
  - `run` is the one-shot mode; the prompt is the final argument.
  - `--auto` auto-approves permissions that are not explicitly
    denied. Without it, a run that wants a tool can stall waiting
    on an approval prompt.
  - `-m provider/model` picks the model. The profile bakes in
    this deployment's OpenRouter default, the same model cloud
    AgenC uses; override with `--agent-cmd` to change it.
  - No git repo is required in the working directory.
- Smoke test (needs a provider key):
  `opencode run -m openrouter/meta/muse-ember "What is 6 times 7? Reply with just the number."`
  (The smoke test was verified with the previous default model
  on 2026-11-08; re-run it after the model change.)
- Gotcha, found by bridge testing 2026-11-08: `opencode run`
  reads a non-TTY stdin until EOF before it starts, so a worker
  that inherits an open stdin pipe hangs until the task times
  out. `bridge.py` therefore runs every agent with stdin from
  /dev/null (`run_agent`, pinned by tests/test_run_agent.py).
  End-to-end verified the same night: a task from agenc-cloud
  was answered in ~19 s with the file written as asked, and a
  task from opencode-cloud to the AgenC worker came back `ok`.
- Node names: `opencode-cloud`, `opencode-desktop-linux`, …
  (role `worker`).

## grok-code (third-party — no poll profile)

An independent open-source Grok CLI (kevdogg102396-afk/grok-code,
Apache 2.0, built with Bun). Not xAI's product — treat it as
third-party code: its installer clones a repo and runs `bun
install` under your home directory.

- Install: `curl -fsSL
  https://raw.githubusercontent.com/kevdogg102396-afk/grok-code/master/install/install.sh
  | bash` — **read the script first**; it installs Bun if
  missing, clones the repo to `~/.grok-code/app`, and writes a
  launcher to `~/.grok-code/bin/grok`. On this repo's setup the
  launcher is renamed to **`grok-code`** (see below).
  Installed and verified here: the launcher runs and fails
  cleanly with "XAI_API_KEY not set" when no key is present.
- Auth: `XAI_API_KEY` env var (key from console.x.ai, starts
  with `xai-`). No subscription login. It can also read the key
  from `~/.grok-code/.env`.
- **No headless mode (verified).** v2.0.0 has no `-p` one-shot
  flag — `--help` lists only `--model/--yolo/--manual/--auto/
  --sandbox/--no-splash/--help`, the README shows interactive
  use only, and running it with a prompt (flag or positional)
  drops into the interactive companion chooser. So grok-code
  **cannot be a `poll` worker** and has no `--agent` profile.
  What it can do: run interactively; connect to the bridge MCP
  server (`bridge-mcp.py`) from `~/.grok-code/mcp.json` and call
  `ask_muse` / `message_muse`; and run `bridge.py` commands
  through its own bash tool, i.e. act as a coordinator like
  Grok Bot. Its node key (`grokcode-cloud`, worker role) is
  already trusted, so if a headless mode appears later, the
  identity is ready.
- Interactive modes: `grok-code` (auto — asks before big
  actions), `--yolo` (no permission prompts), `--sandbox`
  (locks it to the current folder), `--model fast|reason|
  standard|4.3` (default standard; `fast` is the cheap
  2M-context daily driver). Skills are `.md` files in
  `~/.grok-code/skills/`; project context auto-reads `GROK.md`
  or `CLAUDE.md`.
- **Binary name collision — read this:** grok-code's installer
  creates a binary called `grok`, the same name as the official
  Grok Build CLI. Installing both the normal way overwrites one
  with the other. This repo installs grok-code's launcher as
  `grok-code` instead, so `grok` stays the official CLI and
  `grok-code` is the third-party one. Do not install both as
  `grok` on the same machine.
- Node names: `grokcode-cloud`, `grokcode-desktop-linux`, …
  (role `worker`; currently usable via MCP/coordinator, not poll).

## Comparison

| Agent | Install | Auth | Headless command | Bridge role |
|---|---|---|---|---|
| AgenC | get.agenc.ag | provider key | `agenc -p --no-tui` | worker (default) |
| Grok Bot | — (hosted) | xAI account | — (MCP / local execution) | asker (coordinator) |
| Grok Build CLI | `npm i -g @xai-official/grok` | `grok login` (SuperGrok / X Premium+) or `XAI_API_KEY` | `grok --no-auto-update --always-approve -p` | worker |
| OpenCode | `npm i -g opencode-ai` | provider key (`OPENROUTER_API_KEY` here) | `opencode run --auto -m <provider/model>` | worker |
| grok-code | install script (read it first) | `XAI_API_KEY` | none — interactive only | worker key, via MCP/coordinator |

## Adding another agent

If it has a headless one-shot mode, it fits: add its command to
`AGENT_PROFILES` in `bridge.py`, write its profile here
(install, auth, headless command, gotchas), generate its node
key, trust it as `worker`, and test one task through `poll`.
