#!/usr/bin/env python3
"""AgenC Bridge — MCP server: one connection, many targets.

Exposes the assistant (Muse in this deployment) to any agent over the
Model Context Protocol (stdio), with routing tokens so ONE server
process can talk to many agent nodes:
  - ask_muse(token, to?, prompt, context?, timeout_s?, thread?, rules?)
    -> the answer text.
  - message_muse(token, to?, text, needs_reply?) -> message id.

The token is FIRST in the tool arguments — the routing proof, checked
before anything is sent. A token is a hash of a fresh random secret:
`bridge.py mcp-token --from <caller> --to <target>` mints one (a
master issues it; `--to "*"` is a wildcard — one caller may talk to
any target, so 1 agent can talk to 3, 7, whatever through this one
connection). Only the token's SHA-256 hash is stored, in
~/.config/agenc-bridge/mcp-tokens.json; the token itself is printed
once at issuance and never stored in plaintext. A plain node name is
NOT a token — anyone can type one.

How a call is routed:
  1. Resolve the token — the per-call `token` argument if given,
     else this server's own default token (AGENC_BRIDGE_MCP_TOKEN /
     --token, held by the host, not typed per call). A bad, expired,
     revoked, or wrong-target token is an MCP error and NOTHING is
     sent: no envelope, no bus write.
  2. The token's `from` must be this server's caller node (--node /
     AGENC_BRIDGE_NODE, default agenc-cloud) and its `to` must be the
     requested target or "*". The caller must also hold the role
     permission for the tool (a slave caller cannot ask).
  3. The prompt/message is then written as a signed envelope from
     the caller to the target, the relay is joined as the caller,
     and the answer is waited for — and bound to its prompt the same
     way fetch-answer does, so an answer counts only if it came from
     the node that was addressed.

Legacy behaviour, unchanged: with no token at all and `to` left at
its default (agenc-cloud), the server signs as agenc-cloud, exactly
as before. With no token and a different target, it refuses and
says to supply a token for that target.

Honest limits: a token is bearer until it expires or is revoked —
anyone holding it can use it. Keep tokens in the server's
environment (AGENC_BRIDGE_MCP_TOKEN, held by the host) — the
--token flag also works, but the token is visible in the process
list (`ps`) while the server runs, so prefer the env var on a
shared machine. Keep expiries short, and revoke tokens you no
longer need. A per-call token in the tool arguments is visible to
the calling agent and to logs; prefer the server's default token
when the caller is fixed. And underneath, this
still looks synchronous to the caller but is the signed-envelope bus
— the assistant answers in seconds via the hook, not in the same
instant as a local function. If the assistant is unreachable the call
times out instead of hanging forever.

Stdlib only. Run it and point AgenC at it:
  agenc mcp add muse-bridge python3 <path-to-bridge>/bridge-mcp.py -t stdio
  agenc mcp add muse-bridge-bob python3 <path-to-bridge>/bridge-mcp.py \
      --node bob --token <token> -t stdio

The bus, keys, and tokens come from the environment:
  AGENC_BRIDGE_BUS (default ~/workspace/agenc-bridge/bus)
  AGENC_BRIDGE_NODE (default agenc-cloud)
  AGENC_BRIDGE_MCP_TOKEN (default routing token for this server)
  AGENC_BRIDGE_MCP_TOKENS (tokens file; default
    ~/.config/agenc-bridge/mcp-tokens.json)
  AGENC_BRIDGE_WEB_RELAY (optional, e.g. wss://relay.example.com:8766
    — use the web relay instead of the localhost TCP relay; needs
    the `websockets` library, see requirements.txt, and this file
    must run under the venv python: .venv/bin/python bridge-mcp.py)
  AGENC_BRIDGE_RELAY_HOST / AGENC_BRIDGE_RELAY_PORT (optional,
    default 127.0.0.1:8765 — which TCP relay to join for pushes;
    point at a staging relay on another port with these, or with
    --relay-host / --relay-port)
  the node's private key is read by bridge.py from
  ~/.config/agenc-bridge/keys/ (its own per-node encryption key
  from AGENC_BRIDGE_PASSPHRASE_<NODE> or passphrases/<node>,
  falling back to the shared AGENC_BRIDGE_PASSPHRASE or the
  passphrase file for nodes not migrated yet)
"""
import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import bridge as _bridge

BRIDGE_PY = Path(__file__).with_name("bridge.py")
BUS = Path(os.environ.get(
    "AGENC_BRIDGE_BUS", str(Path.home() / "workspace" / "agenc-bridge" / "bus")))
BUS.mkdir(parents=True, exist_ok=True)

# The caller this server speaks as, and its default routing token.
# Set from --node/--token (or AGENC_BRIDGE_NODE/AGENC_BRIDGE_MCP_TOKEN)
# in main(); tests may set them directly.
CALLER_NODE = os.environ.get("AGENC_BRIDGE_NODE", "").strip() or "agenc-cloud"
DEFAULT_TOKEN = os.environ.get("AGENC_BRIDGE_MCP_TOKEN", "").strip() or None

# Which relay to join for pushes: the localhost TCP relay by
# default, overridable per deployment — a staging relay on another
# port, or a relay on another host. Set from --relay-host /
# --relay-port (or AGENC_BRIDGE_RELAY_HOST / AGENC_BRIDGE_RELAY_PORT)
# in main(); tests may set them directly. (The web relay, when
# AGENC_BRIDGE_WEB_RELAY is set, is addressed by its URL instead.)
RELAY_HOST = os.environ.get("AGENC_BRIDGE_RELAY_HOST", "").strip() or "127.0.0.1"
try:
    RELAY_PORT = int(os.environ.get("AGENC_BRIDGE_RELAY_PORT", "").strip() or 8765)
except ValueError:
    RELAY_PORT = 8765

DEFAULT_TARGET = "agenc-cloud"


def make_link(sender):
    """Join the relay as `sender` for pushes, on the configured
    relay host/port (AGENC_BRIDGE_RELAY_HOST/PORT, default
    127.0.0.1:8765)."""
    from link import Link
    return Link(sender, host=RELAY_HOST, port=RELAY_PORT)


def run_bridge(*args):
    out = subprocess.run([sys.executable, str(BRIDGE_PY), *args],
                         capture_output=True, text=True, timeout=30)
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip() or "bridge.py failed")
    return out.stdout.strip()


def resolve_routing_token(token, to, need):
    """Decide who sends to whom for one tool call. Returns
    (sender, target). Raises RuntimeError on any failure — and the
    caller sends NOTHING when this raises.

    Token first: the per-call token, else this server's default
    token. With no token at all, only the legacy default target
    (agenc-cloud, sent as this server's caller node) is allowed.
    With a token, it must verify (hash recorded, not revoked, not
    expired, issuer still a master), its `from` must be this
    server's caller node, its `to` must be the requested target
    or "*", and the caller must hold the role permission for the
    tool. The token is never passed on a command line — it is
    verified in-process here, and only the sender/target names
    (not secrets) travel to bridge.py."""
    target = (to or "").strip() or DEFAULT_TARGET
    if not _bridge._is_safe_name(target):
        raise RuntimeError(f"bad target node: {target!r}")
    tok = (token or "").strip() or DEFAULT_TOKEN
    if tok is None:
        if target != DEFAULT_TARGET:
            raise RuntimeError(
                f"no routing token supplied for target '{target}' — "
                "issue one with `bridge.py mcp-token --from "
                f"{CALLER_NODE} --to {target}` and pass it as token, "
                "or set AGENC_BRIDGE_MCP_TOKEN on this server")
        return CALLER_NODE, target
    registry = _bridge.load_registry()
    ok, info, reason = _bridge.verify_mcp_token(tok, registry)
    if not ok:
        raise RuntimeError(
            f"routing token rejected ({reason}) — nothing was sent")
    if info["from"] != CALLER_NODE:
        raise RuntimeError(
            f"routing token is for caller '{info['from']}', but this "
            f"server runs as '{CALLER_NODE}' — nothing was sent")
    if info["to"] != "*" and info["to"] != target:
        raise RuntimeError(
            f"routing token is for target '{info['to']}', not "
            f"'{target}' — nothing was sent")
    entry = registry.get("nodes", {}).get(CALLER_NODE, {})
    if need not in entry.get("permissions", []):
        raise RuntimeError(
            f"caller {CALLER_NODE} may not send {need} messages — "
            "nothing was sent")
    return info["from"], target


def ask_muse(prompt, context="", timeout_s=300, thread="", rules="",
             to=DEFAULT_TARGET, token=None):
    """Ask a target agent a question, as if it were an LLM you can
    prompt. `token` is the routing proof (first argument) and `to`
    is the target agent — one MCP connection reaches many targets.
    The answer is waited for over a relay link if one is up (the
    answer is pushed, no polling); fall back to the bus + polling
    if no relay is reachable.

    thread names the agent this question belongs to (one thread per
    project — three projects, three threads, three agents with their
    own rules and history, all served by the one assistant).
    rules sets that thread's rules on first use."""
    sender, target = resolve_routing_token(token, to, "ask")
    ask_args = ["ask", "--bus", str(BUS), "--sender", sender,
                "--to", target, "--prompt", prompt, "--context", context]
    if thread:
        ask_args += ["--thread", thread]
    if rules:
        ask_args += ["--rules", rules]
    pid = run_bridge(*ask_args)
    web_url = os.environ.get("AGENC_BRIDGE_WEB_RELAY", "").strip()
    link = None
    try:
        if web_url:
            from link import WebLink
            link = WebLink(sender, web_url)
        else:
            link = make_link(sender)
        try:
            env = link.wait_for(pid, timeout_s=timeout_s, kind="answer")
        finally:
            link.close()
        if env is not None:
            # The relay pushed this answer, but a push is not
            # proof it came from the node the prompt was addressed
            # to — any trusted node can fabricate an answer. The
            # push also carries the raw envelope, whose payload is
            # encrypted for this caller: decrypt it first (the
            # token was already verified in-process before anything
            # was sent, and it never travels in an envelope). Bind
            # it to its prompt the same way fetch-answer does, and
            # refuse it if it does not match. A failed binding — or
            # a decrypt failure — is not a relay outage, so it is
            # raised, not fallen back from (the fallback would find
            # the same forged or undecryptable file).
            registry = _bridge.load_registry()
            try:
                plain = _bridge.decrypt_envelope(env, sender, registry)
            except _bridge.DecryptError as e:
                raise RuntimeError(
                    f"key mismatch: {_bridge.mismatch_reason(env, e)}")
            ok, reason = _bridge.verify_answer_binding(env, registry, BUS,
                                                       plain)
            if not ok:
                raise RuntimeError(
                    f"answer failed verification ({reason}), "
                    f"refusing to show it")
            if _bridge.is_rejection(env, plain):
                raise RuntimeError(
                    f"target rejected the prompt: "
                    f"{_bridge.rejection_reason(env, plain)}")
            return plain.get("answer", {}).get("text", "")
    except RuntimeError:
        raise
    except Exception:
        pass  # no relay reachable — fall back to the bus
    out = subprocess.run(
        [sys.executable, str(BRIDGE_PY), "fetch-answer",
         "--bus", str(BUS), "--id", pid, "--timeout-s", str(timeout_s)],
        capture_output=True, text=True, timeout=timeout_s + 60)
    if out.returncode != 0:
        # A rejection is not a timeout: fetch-answer says so on
        # stderr, and the caller should hear the reason, not
        # "did not answer in time".
        if "rejected" in out.stderr:
            raise RuntimeError(out.stderr.strip())
        raise TimeoutError(f"The target did not answer prompt {pid} within {timeout_s}s")
    data = json.loads(out.stdout)
    return data.get("answer", {}).get("text", "")


def message_muse(text, needs_reply=False, to=DEFAULT_TARGET, token=None):
    """Send a target agent a one-way note (no answer waited for).
    `token` is the routing proof (first argument) and `to` is the
    target agent."""
    sender, target = resolve_routing_token(token, to, "message")
    args = ["message", "--bus", str(BUS), "--sender", sender,
            "--to", target, "--text", text]
    if needs_reply:
        args.append("--needs-reply")
    return run_bridge(*args)


TOOLS = [
    {
        "name": "ask_muse",
        "description": "Ask a target agent a question, as if it were an LLM you can prompt. One MCP connection reaches many targets: pass the routing token FIRST and the target node in `to`. Returns the answer text.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "token": {"type": "string", "description": "FIRST: the routing token proving this caller may talk to the target (from `bridge.py mcp-token`). A token for another target, an expired or revoked token, or no token for a non-default target is refused and nothing is sent. Omit only when asking the default target with this server's own default token."},
                "to": {"type": "string", "description": "The target agent node to ask (default agenc-cloud). Use '*' only via a wildcard token's target — set `to` to the actual node you want."},
                "prompt": {"type": "string", "description": "The question or task for the target agent."},
                "context": {"type": "string", "description": "Optional context that helps the target answer."},
                "timeout_s": {"type": "integer", "description": "How long to wait for the answer (default 300)."},
                "thread": {"type": "string", "description": "The agent/thread this question belongs to — one per project (e.g. 'website'). The target remembers that thread's history and follows its rules. Omit for a one-off."},
                "rules": {"type": "string", "description": "This thread's rules — its agent's instructions for its project. Set on first use; kept with the thread."},
            },
            "required": ["prompt"],
        },
    },
    {
        "name": "message_muse",
        "description": "Send a target agent a one-way note (no answer waited for). One MCP connection reaches many targets: pass the routing token FIRST and the target node in `to`. Use ask_muse when you need a reply.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "token": {"type": "string", "description": "FIRST: the routing token proving this caller may talk to the target (from `bridge.py mcp-token`). A token for another target, an expired or revoked token, or no token for a non-default target is refused and nothing is sent."},
                "to": {"type": "string", "description": "The target agent node to message (default agenc-cloud)."},
                "text": {"type": "string"},
                "needs_reply": {"type": "boolean"},
            },
            "required": ["text"],
        },
    },
]


def send(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def main():
    global BUS, CALLER_NODE, DEFAULT_TOKEN, RELAY_HOST, RELAY_PORT
    ap = argparse.ArgumentParser(description="AgenC Bridge MCP server")
    ap.add_argument("--node", default=None,
                    help="caller node this server speaks as "
                         "(default: $AGENC_BRIDGE_NODE or agenc-cloud)")
    ap.add_argument("--token", default=None,
                    help="default routing token for this server "
                         "(default: $AGENC_BRIDGE_MCP_TOKEN)")
    ap.add_argument("--bus", default=None,
                    help="bus directory (default: $AGENC_BRIDGE_BUS)")
    ap.add_argument("--relay-host", default=None,
                    help="TCP relay host for pushes "
                         "(default: $AGENC_BRIDGE_RELAY_HOST or 127.0.0.1)")
    ap.add_argument("--relay-port", type=int, default=None,
                    help="TCP relay port for pushes "
                         "(default: $AGENC_BRIDGE_RELAY_PORT or 8765)")
    args = ap.parse_args()
    if args.node:
        CALLER_NODE = args.node
    if args.token:
        DEFAULT_TOKEN = args.token
    if args.bus:
        BUS = Path(args.bus)
        BUS.mkdir(parents=True, exist_ok=True)
    if args.relay_host:
        RELAY_HOST = args.relay_host
    if args.relay_port:
        RELAY_PORT = args.relay_port
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        method = req.get("method", "")
        rid = req.get("id")
        if method == "initialize":
            send({"jsonrpc": "2.0", "id": rid, "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "agenc-bridge-muse", "version": "1.0.0"},
            }})
        elif method == "notifications/initialized":
            continue
        elif method == "tools/list":
            send({"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}})
        elif method == "tools/call":
            params = req.get("params", {})
            name = params.get("name")
            args = params.get("arguments", {})
            try:
                if name == "ask_muse":
                    text = ask_muse(args.get("prompt", ""),
                                    args.get("context", ""),
                                    int(args.get("timeout_s", 300)),
                                    args.get("thread", ""),
                                    args.get("rules", ""),
                                    args.get("to", DEFAULT_TARGET) or DEFAULT_TARGET,
                                    args.get("token"))
                elif name == "message_muse":
                    text = "message sent: " + message_muse(
                        args.get("text", ""), bool(args.get("needs_reply", False)),
                        args.get("to", DEFAULT_TARGET) or DEFAULT_TARGET,
                        args.get("token"))
                else:
                    raise ValueError(f"unknown tool: {name}")
                send({"jsonrpc": "2.0", "id": rid, "result": {
                    "content": [{"type": "text", "text": text}]}})
            except Exception as e:
                send({"jsonrpc": "2.0", "id": rid, "result": {
                    "content": [{"type": "text", "text": f"error: {e}"}],
                    "isError": True}})
        else:
            send({"jsonrpc": "2.0", "id": rid, "error": {
                "code": -32601, "message": f"method not found: {method}"}})


if __name__ == "__main__":
    main()
