#!/usr/bin/env python3
"""AgenC Bridge — persistent authenticated relay (the open connection).

One process, no polling by clients. Nodes connect once, authenticate
with their own Ed25519 key, and keep the connection open. Envelopes
are then pushed the moment they exist — no back-and-forth
request/response polling.

How it works:
- Listens on 127.0.0.1:8765 (localhost only — nothing is exposed to
  the internet). A client connects and authenticates once by sending
  a signed hello: the first part of the line is its Ed25519
  signature over the hello, and the relay verifies it against the
  node's public key in the trusted-keys registry. An unknown node,
  a bad signature, or a line without a valid signature first is
  dropped and the connection closed.
- Every line after the hello starts with its signature, too:
  `<base64-signature> <json>`. The signature proves which node
  sent it, without ever sending a secret. The relay signs its own
  pushes with the relay key, so clients can verify the relay back.
- Envelopes written to the bus (by bridge.py, the hook worker, or a
  connected client) are pushed to the addressed node within 0.5s
  by the relay's bus watcher. A connected client never polls.
- If the addressed node is offline, the envelope stays in the bus
  and is delivered from there when it reconnects — the bus is
  still the durable record; the relay is the fast path.
- Every envelope is verified on receipt (signature, known sender,
  the sender's role allows that kind, the recipient is a known
  node, and — for tasks, prompts, and messages — the id was never
  seen before; results and answers share their task/prompt id, so
  their replay protection is the reader binding them to the node
  the task/prompt was addressed to, in bridge.py wait /
  fetch-answer). Unverifiable envelopes are dropped,
  never forwarded.
- When a check fails *after* the sender was authenticated
  (permission, unknown recipient, replay), the relay sends a
  rejection back — a result with status "rejected" for a task,
  an answer with rejected=True for a prompt, both signed with
  the relay key — so the sender's wait() / fetch-answer()
  returns promptly with the reason instead of timing out. If
  the signature itself failed, the claimed sender cannot be
  trusted, so nothing is sent back: log only. Messages get
  dead/ + log only (fire-and-forget, no waiter); results and
  answers are responses, so a failed one has nobody to reject
  to. Readers accept a relay rejection only from the relay
  node — a rejection from any other node must still come from
  the node the original was addressed to.

Run: python3 relay.py [--host 127.0.0.1] [--port 8765] [--bus PATH]
Keep it running with a service (see relay.service) or with
relay-watchdog.sh from a cron. For a node on another machine to
reach a relay over the internet, use the web relay (relay-web.py,
WebSocket) instead — same handshake and verification, different
transport. The file bus (GitHub repo) remains the transport between
machines when no relay is reachable, and the relay accelerates the
local side.
"""
import argparse
import base64
import json
import os
import socket
import socketserver
import sys
import threading
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import bridge

HOST = "127.0.0.1"
PORT = 8765
# Longest wire line accepted, in bytes — the same 1MB the
# WebSocket relay gets from the websockets library's default
# max_size. A line longer than this is dropped with the
# connection, so a node cannot exhaust the relay's memory by
# sending one huge line (readline() without a limit buffers it
# all before the signature check ever runs).
MAX_LINE = 1024 * 1024
# Most live sockets the relay serves at once. The cap counts
# sockets, not node names — one node holding a hundred sockets
# must occupy a hundred slots, not one. A hundred is far above
# any real deployment, and a cap stops one client from opening
# connections until the relay runs out of threads.
MAX_CONNECTIONS = 100


class RateLimiter:
    """One per node (not per connection): at most `limit` lines
    per `window` seconds, across all of that node's connections.
    A legit client sends a few lines per task; a client flooding
    the relay (each line costs an openssl verification) gets its
    connection dropped — and reconnecting does not reset its
    budget, so a flood cannot be sustained by reconnecting.
    Shared between a node's connections, so allowance is guarded
    by a lock."""

    def __init__(self, limit=600, window=60):
        self.limit = limit
        self.window = window
        self.times = []
        self.lock = threading.Lock()

    def allow(self):
        now = time.time()
        with self.lock:
            self.times = [t for t in self.times if now - t < self.window]
            if len(self.times) >= self.limit:
                return False
            self.times.append(now)
            return True

KIND_DIRS = {
    "task": lambda env, bus: bus / "tasks",
    "result": lambda env, bus: bus / "results",
    "prompt": lambda env, bus: bus / "prompts" / env.get("to", ""),
    "answer": lambda env, bus: bus / "answers",
    "message": lambda env, bus: bus / "messages" / env.get("to", ""),
    # Registry distribution: a signed registry-update envelope
    # lands in the recipient's queue, like a message — the
    # recipient validates it (root pin, cert chains, enc
    # attestations) before adopting it.
    "registry-update": lambda env, bus: bus / "registry-updates" / env.get("to", ""),
}


class SocketConn:
    """A relay connection over a TCP socket. The relay only ever calls
    send_line — the web relay (relay-web.py) provides a connection
    object with the same method, so the routing logic is shared."""

    def __init__(self, sock):
        self.sock = sock

    def send_line(self, line):
        self.sock.sendall((line + "\n").encode())

    def close(self):
        """Close the socket. shutdown() wakes a handler blocked in
        readline() on this socket, so a superseded connection
        stops serving instead of lingering for sends."""
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


class Relay:
    def __init__(self, bus, registry, name="tcp"):
        self.bus = Path(bus)
        self.registry = registry
        self.name = name
        # The pulse: the watch loop rewrites this file every couple
        # of seconds, so `bridge.py status` can see the relay is
        # alive (and how fresh it is) without connecting. It lives
        # in the bus dir, which is git-ignored — and if the bus is
        # synced, a remote relay's pulse shows up here too.
        self.heartbeat_file = self.bus / f".heartbeat-{name}"
        self._last_heartbeat = 0.0
        self.connections = {}  # node -> connection (has send_line)
        # Rate limiters are per node, not per connection (see
        # limiter_for): a node that reconnects keeps its budget.
        self.limiters = {}  # node -> RateLimiter
        # Live sockets, counted for the connection cap: one node
        # holding many sockets occupies many slots, not one.
        self.live_sockets = set()
        self.lock = threading.Lock()
        self.pushed = set()
        self.pushed_file = self.bus / "seen" / "pushed.txt"
        self.pushed_file.parent.mkdir(parents=True, exist_ok=True)
        if self.pushed_file.exists():
            # Entries are "id:kind" — a prompt and its answer share an
            # id but are different deliveries, so the key is the pair.
            for line in self.pushed_file.read_text().split():
                if ":" in line:
                    self.pushed.add(tuple(line.split(":", 1)))
                else:
                    self.pushed.add((line, ""))
        # Hellos are single-use: every hello carries a nonce, and a
        # nonce may be used once. A recorded hello line is a bearer
        # token for "be this node" — replaying it would displace the
        # real connection and receive its pushes. The set is loaded
        # from bus/seen/nonces.txt at start (so a restart does not
        # resurrect old hellos) and appended to on every hello.
        # One line per connection, ~40 bytes — negligible growth.
        self.nonces_file = self.bus / "seen" / "nonces.txt"
        self.seen_nonces = set()
        if self.nonces_file.exists():
            self.seen_nonces = set(self.nonces_file.read_text().split())

    def limiter_for(self, node):
        """The rate limiter for one node, shared across all its
        connections: a flood that reconnects does not reset its
        budget. One limiter per node, created on first use."""
        with self.lock:
            limiter = self.limiters.get(node)
            if limiter is None:
                limiter = RateLimiter()
                self.limiters[node] = limiter
            return limiter

    def _register_locked(self, node, conn):
        """Register a connection for a node. Caller must hold the
        relay lock. Returns (ok, old_conn): ok is False when the
        socket cap is reached; old_conn is a superseded connection
        for the same node, which the caller must close — a
        displaced connection stays live for sending otherwise,
        and the node would hold two live sockets. A replacement
        for a node that already holds a connection does not count
        against the cap (net socket count unchanged), so a node
        can always reconnect and displace its old socket."""
        old = self.connections.get(node)
        if old is None and len(self.live_sockets) >= MAX_CONNECTIONS:
            return False, None
        self.connections[node] = conn
        self.live_sockets.add(conn)
        if old is not None:
            self.live_sockets.discard(old)
        return True, old

    def register_connection(self, node, conn):
        with self.lock:
            return self._register_locked(node, conn)

    def unregister_connection(self, node, conn):
        """Remove a connection, but only if it is still the node's
        current one — a superseded connection must not unregister
        its replacement."""
        with self.lock:
            self.live_sockets.discard(conn)
            if self.connections.get(node) is conn:
                del self.connections[node]

    def check_hello_nonce(self, node, nonce):
        """True if this hello nonce is fresh (and record it); False
        if it is missing or has been used before. Must be called
        under the relay lock — check and record are one step."""
        if not isinstance(nonce, str) or not nonce:
            return False
        key = f"{node}:{nonce}"
        if key in self.seen_nonces:
            return False
        self.seen_nonces.add(key)
        with open(self.nonces_file, "a") as f:
            f.write(key + "\n")
        return True

    def catch_up(self, node):
        """Push a reconnecting node's live mail — only live mail.
        Scans exactly the directories that hold undelivered
        envelopes (tasks, results, answers, prompts/<node>,
        messages/<node>), never read/, done/, or dead/, and skips
        anything already in the pushed set. A reconnect used to
        re-push the node's entire history, including mail it had
        already read."""
        for kind, sub in (("task", "tasks"), ("result", "results"),
                          ("answer", "answers")):
            d = self.bus / sub
            if not d.exists():
                continue
            for path in sorted(d.glob("*.json")):
                env_id = path.stem
                if (env_id, kind) in self.pushed:
                    continue
                try:
                    envelope = bridge.read_envelope(path)
                except Exception:
                    continue
                if envelope.get("to") == node and bridge.verify_basic(
                        envelope, self.registry)[0]:
                    self.push(envelope)
                    self.mark_pushed(env_id, kind)
        for kind, sub in (("prompt", "prompts"), ("message", "messages"),
                          ("registry-update", "registry-updates")):
            d = self.bus / sub / node
            if not d.exists():
                continue
            for path in sorted(d.glob("*.json")):
                env_id = path.stem
                if (env_id, kind) in self.pushed:
                    continue
                try:
                    envelope = bridge.read_envelope(path)
                except Exception:
                    continue
                if bridge.verify_basic(envelope, self.registry)[0]:
                    self.push(envelope)
                    self.mark_pushed(env_id, kind)

    def _beat(self):
        """Write the heartbeat file (throttled to every 2s — the
        watch loop itself runs every 0.5s)."""
        now = time.time()
        if now - self._last_heartbeat < 2:
            return
        self._last_heartbeat = now
        data = {"relay": self.name, "ts": now,
                "at": bridge.utcnow(), "pid": os.getpid(),
                "connections": sorted(self.connections)}
        tmp = self.heartbeat_file.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(data))
            os.replace(tmp, self.heartbeat_file)
        except OSError:
            pass

    def mark_pushed(self, env_id, kind=""):
        key = (env_id, kind)
        if key in self.pushed:
            return
        self.pushed.add(key)
        with open(self.pushed_file, "a") as f:
            f.write(env_id + ":" + kind + "\n")

    def _sign_line(self, line):
        sig = bridge._sign_bytes(line.encode(), "relay")
        return base64.b64encode(sig).decode() + " " + line

    def push(self, envelope):
        target = envelope.get("to")
        with self.lock:
            conn = self.connections.get(target)
        if conn is None:
            return False
        # The signature is the FIRST part of every message.
        line = json.dumps({"type": "envelope", "envelope": envelope},
                          sort_keys=True, separators=(",", ":"))
        try:
            conn.send_line(self._sign_line(line))
            return True
        except OSError:
            return False

    def _write_dead(self, envelope):
        """File a dropped envelope in bus/dead/ for audit. Only
        called when the id is a safe name — verify_basic passing
        guarantees that, so an unsafe id can never become a file
        name here."""
        if not bridge._is_safe_name(envelope.get("id", "")):
            return
        dest = self.bus / "dead" / f"{envelope['id']}.json"
        if not dest.exists():
            try:
                bridge.write_envelope_file(dest, envelope)
            except OSError:
                pass

    def _reject(self, envelope, reason):
        """Send a rejection back to an authenticated sender whose
        envelope failed a check after verification (permission,
        unknown recipient, replay). Tasks get a result with
        status "rejected", prompts get an answer with
        rejected=True, both signed with the relay key and written
        where wait() / fetch-answer() look — and pushed at once
        if the sender is connected. The original goes to dead/
        for audit. A genuine result/answer already waiting is
        never overwritten. Results, answers, and messages get
        dead/ + log only: a result or an answer is a response
        with nobody to reject to, and a message is fire-and-
        forget with no waiter. Returns True if a rejection was
        written."""
        self._write_dead(envelope)
        kind = envelope.get("kind")
        if kind not in ("task", "prompt"):
            return False
        dest_dir = self.bus / ("results" if kind == "task" else "answers")
        dest = dest_dir / f"{envelope['id']}.json"
        # A genuine response already delivered must never be
        # overwritten by a replay's rejection: the live dir alone
        # is not enough — wait() / fetch-answer() move a shown
        # response to read/<sender>/, and a completed task sits
        # in done/. A replayed id that already has a genuine
        # outcome gets dead/ + log only (see
        # bridge._response_already_delivered).
        if bridge._response_already_delivered(
                bridge.bus_dirs(self.bus), kind, envelope["id"],
                envelope.get("from", ""), envelope.get("to", "")):
            return False
        try:
            if kind == "task":
                rej = {"v": bridge.VERSION, "id": envelope["id"],
                       "from": "relay", "to": envelope.get("from", ""),
                       "kind": "result", "created_at": bridge.utcnow(),
                       "result": {"status": "rejected", "returncode": None,
                                  "stdout": "", "stderr": reason,
                                  "started_at": bridge.utcnow(),
                                  "finished_at": bridge.utcnow(),
                                  "duration_s": 0}}
            else:
                rej = {"v": bridge.VERSION, "id": envelope["id"],
                       "from": "relay", "to": envelope.get("from", ""),
                       "kind": "answer",
                       "thread": envelope.get("thread", ""),
                       "created_at": bridge.utcnow(),
                       "answer": {"text": f"rejected: {reason}",
                                  "rejected": True, "reason": reason,
                                  "in_reply_to": envelope["id"]}}
            bridge.write_envelope(dest, rej, "relay", self.registry)
        except SystemExit as e:
            print(f"relay: could not send rejection for "
                  f"{envelope.get('id')}: {e}", flush=True)
            return False
        if self.push(rej):
            self.mark_pushed(rej["id"], rej["kind"])
        return True

    def handle_envelope(self, envelope):
        ok, reason = bridge.verify_basic(envelope, self.registry)
        if not ok:
            # The signature itself failed (or the sender is
            # unknown, the id is unsafe, the version is wrong, the
            # role is unapproved): the claimed `from` cannot be
            # trusted, so no rejection is sent back — log only.
            # A forged from=victim would otherwise let an
            # attacker spam the victim with rejections.
            print(f"relay: dropping envelope ({reason})", flush=True)
            return
        need = bridge.KIND_PERMISSION.get(envelope.get("kind", ""))
        entry = self.registry.get("nodes", {}).get(envelope.get("from", ""), {})
        # A rejection the relay itself sent, forwarded back over
        # the wire: it is signed with the relay key and reports a
        # drop — it holds no result/answer permission by design,
        # so the permission check below would drop it. Its
        # binding is still checked by the reader (wait /
        # fetch-answer), so letting it through the relay does not
        # let anyone forge a result.
        relay_rejection = bridge.is_relay_rejection(envelope, self.registry)
        if not relay_rejection and need and need not in entry.get("permissions", []):
            reason = (f"sender {envelope.get('from')} may not send "
                      f"{envelope.get('kind')} messages")
            print(f"relay: dropping envelope ({reason})", flush=True)
            self._reject(envelope, reason)
            return
        # Registry updates are distributed by a master only.
        # KIND_PERMISSION has no entry for registry-update (no
        # role permission covers it — every role holds "task"),
        # so the check is by role here, and again at application
        # time, where the sender's certificate must chain to the
        # root. A worker's registry update never reaches a bus.
        if envelope.get("kind") == "registry-update" and \
                entry.get("role") not in ("owner", "master"):
            reason = (f"sender {envelope.get('from')} is not a "
                      f"master and may not distribute registry updates")
            print(f"relay: dropping envelope ({reason})", flush=True)
            self._write_dead(envelope)
            return
        # The recipient must be a node the relay knows (or "*"):
        # an envelope addressed nowhere is not delivered anywhere.
        to = envelope.get("to", "")
        if to != "*" and to not in self.registry.get("nodes", {}):
            reason = f"unknown recipient {to!r}"
            print(f"relay: dropping envelope ({reason})", flush=True)
            self._reject(envelope, reason)
            return
        # Replay guard — for kinds with fresh ids only. Results
        # and answers share their task/prompt id, which the worker
        # already marked seen when it claimed the task, so a seen
        # check would drop every genuine result. Their forgery is
        # caught by the reader instead (wait/fetch-answer bind a
        # result/answer to the node the task/prompt was addressed
        # to). Tasks, prompts, messages, and registry updates get
        # fresh ids, so a seen id here is a replay.
        if envelope.get("kind") in ("task", "prompt", "message",
                                    "registry-update"):
            seen, _ = bridge.seen_ids(self.bus)
            if envelope.get("id") in seen:
                reason = (f"replayed envelope id {envelope.get('id')}")
                print(f"relay: dropping envelope ({reason})", flush=True)
                self._reject(envelope, reason)
                return
        # A prompt and its answer share an id but are different
        # deliveries — the replay guard is keyed by (id, kind).
        key = (envelope.get("id"), envelope.get("kind", ""))
        if key in self.pushed and envelope.get("kind") != "result":
            return
        dest_dir = KIND_DIRS.get(envelope.get("kind"), lambda e, b: b)(envelope, self.bus)
        dest_dir.mkdir(parents=True, exist_ok=True)
        path = dest_dir / f"{envelope['id']}.json"
        if not path.exists():
            bridge.write_envelope_file(path, envelope)
        # Pushed means delivered: only mark it when the target was
        # actually connected and the send went through. A task sent
        # while its target is offline must NOT be marked — it still
        # needs delivering, by catch-up when the target reconnects.
        if self.push(envelope):
            self.mark_pushed(envelope["id"], envelope.get("kind", ""))

    def watch_bus(self):
        """Push new bus files to connected nodes within 0.5s."""
        while True:
            self._beat()
            try:
                for kind, sub in (("task", "tasks"), ("result", "results"),
                                  ("answer", "answers")):
                    d = self.bus / sub
                    if not d.exists():
                        continue
                    for path in sorted(d.glob("*.json")):
                        env_id = path.stem
                        if (env_id, kind) in self.pushed:
                            continue
                        try:
                            envelope = bridge.read_envelope(path)
                        except Exception:
                            continue
                        if bridge.verify_basic(envelope, self.registry)[0]:
                            if self.push(envelope):
                                self.mark_pushed(env_id, kind)
                for kind, sub in (("prompt", "prompts"), ("message", "messages"),
                                  ("registry-update", "registry-updates")):
                    d = self.bus / sub
                    if not d.exists():
                        continue
                    for node_dir in d.iterdir():
                        if not node_dir.is_dir():
                            continue
                        for path in sorted(node_dir.glob("*.json")):
                            env_id = path.stem
                            if (env_id, kind) in self.pushed:
                                continue
                            try:
                                envelope = bridge.read_envelope(path)
                            except Exception:
                                continue
                            if bridge.verify_basic(envelope, self.registry)[0]:
                                if self.push(envelope):
                                    self.mark_pushed(env_id, kind)
            except Exception as e:
                print(f"relay watch error: {e}", flush=True)
            time.sleep(0.5)


def _check_line(line, registry):
    """Split a wire line into (sender, json). The first part must be
    a valid Ed25519 signature by a node in the registry. Returns
    (sender, obj) or (None, None)."""
    sig_b64, _, rest = line.partition(" ")
    if not sig_b64 or not rest:
        return None, None
    try:
        obj = json.loads(rest)
    except Exception:
        return None, None
    if obj.get("type") == "hello":
        sender = obj.get("node", "")
    elif obj.get("type") == "envelope":
        sender = obj.get("envelope", {}).get("from", "")
    else:
        return None, None
    entry = registry.get("nodes", {}).get(sender)
    if entry is None:
        return None, None
    try:
        sig = base64.b64decode(sig_b64)
    except Exception:
        return None, None
    if not bridge._verify_bytes(rest.encode(), sig, entry["public_key"]):
        return None, None
    return sender, obj


def _read_line(rfile):
    """Read one wire line, bounded by MAX_LINE. Returns the decoded
    line, or None on EOF or on a line longer than the cap (the
    caller drops the connection — a partial over-long line is not
    a message)."""
    raw = rfile.readline(MAX_LINE + 1)
    if not raw:
        return None
    if len(raw) > MAX_LINE and not raw.endswith(b"\n"):
        return None
    return raw.decode(errors="replace").strip()


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        relay = self.server.relay
        node = None
        conn = None
        try:
            line = _read_line(self.rfile)
            if line is None:
                return  # EOF or an over-long first line
            sender, hello = _check_line(line, relay.registry)
            if hello is None or hello.get("type") != "hello":
                return  # no valid signature first — reject immediately
            node = sender
            # A hello is single-use: its nonce may authenticate one
            # connection only. A replayed hello — the same signed
            # line on a second socket — would displace the real
            # connection and receive its pushes. Check before the
            # connection is registered, under the lock, so a replay
            # can never take the slot. Registration also enforces
            # the socket cap (counted in live sockets, not node
            # names) and returns any superseded connection for
            # this node, which is closed at once — a displaced
            # connection must not stay live for sending.
            conn = SocketConn(self.request)
            with relay.lock:
                if not relay.check_hello_nonce(node, hello.get("nonce", "")):
                    print(f"relay: {node} hello nonce reused — dropping",
                          flush=True)
                    return
                ok, old = relay._register_locked(node, conn)
                if not ok:
                    print("relay: connection cap reached — dropping",
                          flush=True)
                    return
            if old is not None:
                old.close()
            welcome = {"type": "welcome", "nonce": hello.get("nonce", "")}
            welcome_line = json.dumps(welcome, sort_keys=True,
                                      separators=(",", ":"))
            try:
                self.wfile.write((relay._sign_line(welcome_line) + "\n").encode())
            except (Exception, SystemExit) as e:
                # Signing the welcome needs the relay key. If it is
                # gone (deleted while running), say so — a silent
                # drop looks like a network problem.
                print(f"relay: cannot sign welcome for {node}: {e}",
                      flush=True)
                return
            self.wfile.flush()
            print(f"relay: {node} connected", flush=True)
            # Catch-up: push live mail already waiting for this node.
            relay.catch_up(node)
            # The rate limit is per node, shared across this
            # node's connections — reconnecting does not reset it.
            limiter = relay.limiter_for(node)
            while True:
                line = _read_line(self.rfile)
                if line is None:
                    return  # EOF or an over-long line — drop it
                if not limiter.allow():
                    print(f"relay: {node} exceeded the line rate — "
                          f"dropping", flush=True)
                    return
                sender, msg = _check_line(line, relay.registry)
                if msg is None:
                    print(f"relay: {node} sent a message without a valid signature — dropping", flush=True)
                    return
                if msg.get("type") == "envelope":
                    relay.handle_envelope(msg["envelope"])
        finally:
            if node and conn is not None:
                relay.unregister_connection(node, conn)
                print(f"relay: {node} disconnected", flush=True)


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


def check_relay_key():
    """Fail fast if the relay cannot sign: without its private key
    the relay stays up and accepts connections, but every hello is
    dropped (the welcome cannot be signed) and nothing in the log
    says why. Check at startup, so a missing key is a loud error,
    not a silently useless relay."""
    try:
        bridge.load_private_key_pem("relay")
    except SystemExit as e:
        print(f"relay: cannot load the relay private key: {e}",
              file=sys.stderr)
        print("relay: generate one with `bridge.py keygen --node relay` "
              "and trust it, then start the relay", file=sys.stderr)
        sys.exit(1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=HOST)
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--bus", default=str(Path.home() / "workspace" / "agenc-bridge" / "bus"))
    ap.add_argument("--registry", default=None)
    args = ap.parse_args()
    check_relay_key()
    registry = bridge.load_registry(args)
    relay = Relay(args.bus, registry, name="tcp")
    threading.Thread(target=relay.watch_bus, daemon=True).start()
    server = Server((args.host, args.port), Handler)
    server.relay = relay
    print(f"relay listening on {args.host}:{args.port} (bus {args.bus})", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
