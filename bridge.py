#!/usr/bin/env python3
"""AgenC Bridge v3 — sender and worker over a shared directory bus.

Stdlib plus the `cryptography` package (X25519 + AES-256-GCM) and
the `openssl` CLI for Ed25519. Works on Linux and
Windows (Python 3.10+).

Identity is per node, not one shared secret. Every node has its own
Ed25519 keypair. The public keys of the nodes you trust live in
`trusted-keys.json` (the registry), each with a role that says what
that node may do:

  owner  — task, ask, message (full control; your own assistant and workers)
  worker — task, message (may run tasks, may not prompt the assistant)
  asker  — ask, message (may prompt the assistant, may not run tasks)

A message is trusted only if it is signed by a key in the registry,
the signature is the FIRST part of the message, the sender's role
allows that kind of message, and the message id was never seen
before. Anything else is rejected to bus/dead/ and never runs.

Envelopes are v3: the routing header (v, id, from, to, kind,
created_at) stays plaintext and signed so the relay can route and
verify without decrypting, and the payload is AEAD-encrypted for
the intended recipient only (X25519 ECDH per sender→recipient
pipe, AES-256-GCM). A message sent to the wrong pipe does not
come out as gibberish — decryption fails closed and nothing comes
out at all. The relay never decrypts. v2 plaintext envelopes are
rejected by default; AGENC_BRIDGE_ALLOW_V2=1 re-opens the
migration window, and a v2 envelope to a node that holds an
encryption key is refused as a downgrade even then.

A rejection is sent back when a check fails *after* the sender
was authenticated (permission, unknown recipient, replay,
decryption key mismatch): the
sender's wait() / fetch-answer() returns promptly with the reason
instead of timing out. If the signature itself failed, the claimed
sender cannot be trusted, so nothing is sent back — dead/ and the
log only. The relay may reject on a worker's behalf, signed with
the relay key; a rejection from any other node must still come
from the node the original was addressed to.

The fingerprint is the optional, Signal-style check: a 60-digit
number derived from a node's public key. Two sides compare it once,
out of band, to be sure the key belongs to who they think it does.
Nothing requires the comparison — keys work without it.

Private keys live encrypted at rest in ~/.config/agenc-bridge/keys/
(AES-256-CBC, PBKDF2), each under its own per-node encryption key
(passphrases/<node>, or AGENC_BRIDGE_PASSPHRASE_<NODE>), never in
the bus and never in git. The shared bridge passphrase remains
only as a fallback for nodes not migrated yet. Each node also
holds an X25519 encryption keypair (keys/<node>.x25519.*); its
public part is published in the registry with a self-attestation
signed by the node's Ed25519 key, so a tampered registry cannot
substitute an encryption key without the node's signing key.
Encryption keys rotate daily (`bridge.py rotate-keys`); the old
key stays usable for a 48h grace window so in-flight mail still
decrypts, then it is destroyed.

Usage:
  bridge.py keygen --node NAME
  bridge.py rekey --node NAME
  bridge.py rotate-keys [--node NAME] [--dry-run]
  bridge.py publish-enc-key --node NAME
  bridge.py keys [--node NAME]
  bridge.py resync --registry PATH
  bridge.py rerequest --bus BUS --id ID --to NODE [--sender NODE]
  bridge.py resend --bus BUS --id ID [--sender NODE]
  bridge.py retire-shared-passphrase
  bridge.py pin-root [--node NAME]
  bridge.py sign-thread --bus BUS --thread NAME [--sender NODE]
  bridge.py mcp-token --from CALLER --to TARGET [--expiry-days N]
  bridge.py fingerprint --node NAME
  bridge.py trust --node NAME --pubkey FILE [--role owner|master|worker|asker|slave|relay] [--approve-by MASTER] [--enc-pubkey FILE --enc-attest FILE]
  bridge.py promote --node NAME --role ROLE [--approve-by MASTER]
  bridge.py approve --node NAME [--approve-by MASTER]
  bridge.py revoke --node NAME
  bridge.py registry
  bridge.py send --bus BUS --to NODE --prompt "..." [--model ...] [--cwd .] [--timeout-s 600]
  bridge.py wait --bus BUS --id TASK_ID [--timeout-s 900]
  bridge.py status [--bus BUS] [--node NODE]
  bridge.py dead [--bus BUS] [--limit N]
  bridge.py poll --bus BUS --node NODE --project-root DIR [--once]
  bridge.py serve --bus BUS --node NODE --project-root DIR [--interval-s 10]
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey)
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
    _CRYPTO_AVAILABLE = True
except ImportError:  # cryptography not installed on this machine
    _CRYPTO_AVAILABLE = False

VERSION = 3
# v2 plaintext envelopes are rejected by default. Set
# AGENC_BRIDGE_ALLOW_V2=1 to re-open the migration window (a v2
# envelope to a node that holds an encryption key is still refused
# as a downgrade — the window is only for nodes without one).
ENC_GRACE_HOURS = 48  # retired encryption keys stay usable this long
DEFAULT_MODEL = "stealth/crouton-alpha"


def _require_crypto():
    if not _CRYPTO_AVAILABLE:
        raise SystemExit(
            "the `cryptography` package is required for encrypted "
            "envelopes — install it with "
            "`pip install cryptography` (see requirements.txt)")


def allow_v2():
    return os.environ.get("AGENC_BRIDGE_ALLOW_V2", "").strip() == "1"

# Roles: what a node may SEND. Receiving is not restricted — a node
# only acts on envelopes addressed to it, and only runs tasks if it
# polls. master is the controller (owner is the same set, kept for
# existing registries). worker may also ask the assistant questions
# (Captain's decision, 2026-11-07) — but a worker's prompt is
# DATA, never a command: the assistant answers the question and
# does not follow instructions embedded in it. slave is locked
# down: it may only return results. It cannot task anyone, cannot
# ask the assistant, and cannot send messages — so it can never
# prompt the master (or anyone else) into an action.
ROLES = {
    "owner": ["task", "result", "ask", "message"],
    "master": ["task", "result", "ask", "message"],
    "worker": ["task", "result", "ask", "message"],
    "asker": ["ask", "message"],
    "slave": ["result"],
    "relay": [],
}
KIND_PERMISSION = {
    "task": "task",
    "result": "result",
    "prompt": "ask",
    "answer": "ask",
    "message": "message",
}


def utcnow():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


# ---------------------------------------------------------------- keys

def config_dir():
    return Path.home() / ".config" / "agenc-bridge"


def keys_dir():
    d = Path(os.environ.get("AGENC_BRIDGE_KEYS_DIR", "") or
             config_dir() / "keys")
    d.mkdir(parents=True, exist_ok=True)
    return d


def passphrases_dir():
    """Where per-node encryption keys live: one file per node.
    Explicit override first, then beside the keys dir (so a test
    run that isolates AGENC_BRIDGE_KEYS_DIR isolates these too),
    else ~/.config/agenc-bridge/passphrases/."""
    env = os.environ.get("AGENC_BRIDGE_PASSPHRASES_DIR", "").strip()
    if env:
        d = Path(env)
    else:
        kd = os.environ.get("AGENC_BRIDGE_KEYS_DIR", "").strip()
        if kd:
            d = Path(kd).parent / "passphrases"
        else:
            d = config_dir() / "passphrases"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _per_node_env_name(node):
    """Env var holding one node's encryption key, e.g.
    AGENC_BRIDGE_PASSPHRASE_AGENC_CLOUD for agenc-cloud."""
    return "AGENC_BRIDGE_PASSPHRASE_" + re.sub(r"[^A-Z0-9]", "_",
                                               node.upper())


def per_node_passphrase_path(node):
    return passphrases_dir() / node


def served_nodes_file():
    """The nodes the assistant answers prompts for — one name per
    line. agenc-cloud is always served; agent nodes (see `agent`)
    are added here when provisioned. The hook reads this file."""
    return Path(os.environ.get("AGENC_BRIDGE_SERVED_NODES", "") or
                config_dir() / "served-nodes")


def served_nodes():
    """Nodes the assistant serves, in order. Defaults to just
    agenc-cloud when the file does not exist yet."""
    path = served_nodes_file()
    if not path.exists():
        return ["agenc-cloud"]
    return [l.strip() for l in path.read_text().splitlines()
            if l.strip() and not l.strip().startswith("#")]


def _save_served_nodes(nodes):
    path = served_nodes_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(nodes) + "\n")


def default_bus():
    """The bus directory: AGENC_BRIDGE_BUS when set (tests,
    staging), else the live bus. Commands that distribute or
    read the bus must use this — a hardcoded live path leaks
    test traffic into the live bus (rotate-keys distributes
    into args.bus, so a test rotation without --bus would write
    its envelopes live)."""
    env = os.environ.get("AGENC_BRIDGE_BUS", "").strip()
    return env or str(Path.home() / "workspace" / "agenc-bridge" / "bus")


def registry_path(args=None):
    if args is not None and getattr(args, "registry", None):
        return Path(args.registry)
    env = os.environ.get("AGENC_BRIDGE_REGISTRY", "").strip()
    if env:
        return Path(env)
    return Path(__file__).parent / "trusted-keys.json"


def shared_passphrase_path():
    """Where the shared bridge passphrase file lives (the legacy
    fallback for nodes not migrated to a per-node key yet).
    Explicit override first (tests), then beside the keys dir (so
    a test run that isolates AGENC_BRIDGE_KEYS_DIR isolates this
    too), else ~/.config/agenc-bridge/passphrase."""
    env = os.environ.get("AGENC_BRIDGE_SHARED_PASSPHRASE_FILE", "").strip()
    if env:
        return Path(env)
    kd = os.environ.get("AGENC_BRIDGE_KEYS_DIR", "").strip()
    if kd:
        return Path(kd).parent / "passphrase"
    return config_dir() / "passphrase"


def load_passphrase(node=None):
    """The encryption key for one node's private key at rest.

    Resolution, in order:
    1. The node's own key — env AGENC_BRIDGE_PASSPHRASE_<NODE>
       (node uppercased, non-alnum -> _), or the file
       passphrases/<node> (mode 600).
    2. The shared bridge passphrase — env AGENC_BRIDGE_PASSPHRASE
       or the shared passphrase file — for nodes not migrated to
       a per-node key yet.
    3. An interactive prompt, if stdin is a terminal.
    A missing key fails closed — nothing is signed, nothing is sent.
    Call with the node whenever the caller knows it; without one
    only the shared passphrase is tried."""
    import getpass
    if node:
        pw = os.environ.get(_per_node_env_name(node), "").strip()
        if pw:
            return pw
        pf = per_node_passphrase_path(node)
        if pf.exists():
            return pf.read_text().strip()
    pw = os.environ.get("AGENC_BRIDGE_PASSPHRASE", "").strip()
    if pw:
        return pw
    pf = shared_passphrase_path()
    if pf.exists():
        return pf.read_text().strip()
    if sys.stdin.isatty():
        return getpass.getpass("Bridge passphrase: ")
    raise SystemExit("no bridge passphrase available: set "
                     "AGENC_BRIDGE_PASSPHRASE or store it in "
                     "~/.config/agenc-bridge/passphrase")


def encryption_key_status(node):
    """'per-node' if this node has its own encryption key (env var
    or passphrases/<node> file), 'shared' if only the shared
    bridge passphrase is available, 'none' if neither."""
    if os.environ.get(_per_node_env_name(node), "").strip():
        return "per-node"
    if per_node_passphrase_path(node).exists():
        return "per-node"
    if os.environ.get("AGENC_BRIDGE_PASSPHRASE", "").strip():
        return "shared"
    if shared_passphrase_path().exists():
        return "shared"
    return "none"


def generate_per_node_key(node):
    """Create a fresh random per-node encryption key (32 bytes,
    base64) and save it to passphrases/<node>, mode 600. The value
    is returned so the caller can encrypt with it — it is never
    printed. Refuses if the node's key comes from the
    environment (rotate it there instead of on disk)."""
    if os.environ.get(_per_node_env_name(node), "").strip():
        raise SystemExit(
            f"cannot generate a per-node key for {node}: its key "
            f"comes from {_per_node_env_name(node)} — rotate it there")
    d = passphrases_dir()
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    key = base64.b64encode(secrets.token_bytes(32)).decode()
    path = d / node
    tmp = path.with_suffix(".tmp")
    tmp.write_text(key)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    return key


def ensure_per_node_key(node):
    """The encryption key to use for a node's keys: its per-node
    key if one already exists (env or file), else a fresh random
    one saved to passphrases/<node>. Never prints the value."""
    if encryption_key_status(node) == "per-node":
        return load_passphrase(node)
    return generate_per_node_key(node)


def _openssl_enc(data, passphrase, decrypt=False):
    """AES-256-CBC/PBKDF2 via openssl. The passphrase reaches
    openssl through a pipe (fd 3), never on the command line —
    a `pass:` argument is visible to anyone who can read the
    process list while the operation runs, and this function is
    called on every sign and decrypt."""
    cmd = ["openssl", "enc", "-aes-256-cbc", "-pbkdf2"]
    if decrypt:
        cmd.append("-d")
    else:
        cmd.append("-salt")
    r, w = os.pipe()
    try:
        # A passphrase is a short string, far under the pipe
        # buffer, so this write cannot block.
        os.write(w, passphrase.encode())
        os.close(w)
        w = None
        # The pipe's read end keeps its number in the child
        # (pass_fds), so name the real fd — it is not
        # necessarily fd 3.
        cmd += ["-pass", f"fd:{r}"]
        out = subprocess.run(cmd, input=data, capture_output=True,
                             pass_fds=(r,))
    finally:
        if w is not None:
            os.close(w)
        os.close(r)
    if out.returncode != 0:
        raise SystemExit("could not decrypt: wrong passphrase?")
    return out.stdout


def fingerprint_of_pubkey_der(der_bytes):
    """Signal-style 60-digit fingerprint from a DER public key."""
    digest = hashlib.sha256(der_bytes).digest()
    num = int.from_bytes(digest[:25], "big")
    return str(num).zfill(60)[:60]


def _run_openssl(args, input_bytes=None):
    out = subprocess.run(["openssl"] + args, input=input_bytes,
                         capture_output=True)
    if out.returncode != 0:
        raise SystemExit(f"openssl failed: {out.stderr.decode().strip()}")
    return out.stdout


def _temp_file(data, suffix=""):
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.chmod(path, 0o600)
    return path


def load_private_key_pem(node):
    """Decrypt a node's private key PEM into memory, with that
    node's own encryption key (shared bridge passphrase as a
    fallback for nodes not migrated yet)."""
    enc_path = keys_dir() / f"{node}.pem.enc"
    if not enc_path.exists():
        raise SystemExit(f"no private key for node {node}: run "
                         f"`bridge.py keygen --node {node}` first")
    return _openssl_enc(enc_path.read_bytes(), load_passphrase(node),
                        decrypt=True)


def provider_key_path(node):
    """A node's provider key, encrypted at rest with the node's
    own encryption key — the same protection as its private key.
    This is the node's own OpenRouter key, with its own credit
    limit set at OpenRouter; the provider enforces that limit,
    not the bridge."""
    return keys_dir() / f"{node}.provider.enc"


def load_provider_key(node):
    """Decrypt a node's provider key into memory, with that node's
    own encryption key. Returns None if the node has none stored.
    Raises SystemExit if one is stored but cannot be decrypted
    (wrong or missing key) — the caller must fail closed, never
    fall back to a shared key."""
    path = provider_key_path(node)
    if not path.exists():
        return None
    return _openssl_enc(path.read_bytes(), load_passphrase(node),
                        decrypt=True).decode().strip()


def cmd_provider_key(args):
    """Store or remove a node's provider key. The key is never
    printed and never stored in plaintext: it is read from a file
    (deleted afterwards) or from stdin, encrypted with the node's
    own encryption key, and kept in keys/<node>.provider.enc."""
    _check_node_name(args.node)
    if args.remove:
        path = provider_key_path(args.node)
        if path.exists():
            path.unlink()
            print(f"provider key removed for {args.node}")
        else:
            print(f"no provider key stored for {args.node}")
        return 0
    if args.from_file:
        src = Path(args.from_file)
        key = src.read_text().strip()
        src.unlink()  # never leave a plaintext key lying around
    elif args.from_stdin:
        key = sys.stdin.read().strip()
    else:
        raise SystemExit("provider-key needs --from-file, "
                         "--from-stdin, or --remove")
    if not key:
        raise SystemExit("empty provider key")
    path = provider_key_path(args.node)
    path.write_bytes(_openssl_enc(key.encode(), load_passphrase(args.node)))
    os.chmod(path, 0o600)
    print(f"provider key stored for {args.node} (encrypted)")
    return 0


# ---------------------------------------------------------------- per-pipe encryption (v3)
#
# Envelope v3: the routing header (v, id, from, to, kind,
# created_at) stays plaintext and signed, so the relay can route
# and verify without decrypting; the payload (the kind-specific
# content, plus the thread for prompts/answers) is AEAD-encrypted
# for the intended recipient only.
#
# Construction: static-static X25519 ECDH between the sender's
# encryption key and the recipient's, HKDF-SHA256 to an AES-256
# key (the HKDF info binds both node names and both key ids, so a
# key derived for one pipe cannot be reused on another), AES-256-
# GCM with a random 12-byte nonce, the canonical routing header
# as associated data (so a ciphertext cannot be cut into a
# different envelope). Encrypt-then-sign at the envelope level:
# the Ed25519 signature covers header + ciphertext, so verify()
# works unchanged and the relay never decrypts.
#
# Both key ids ride in the header (enc.to_key_id, enc.from_key_id),
# and so do both public keys (enc.to_public_key, enc.from_public_key)
# — the keys are public, and the Ed25519 signature covers the whole
# header, so a forged key cannot pass verification. Rotation touches
# both sides of a pipe: a message sent before the sender rotated is
# decrypted with the sender's RETIRED public key (kept in the
# registry's enc_prev_keys, and carried in the header itself), and
# a message sent before the recipient rotated is decrypted with
# the recipient's RETIRED private key (kept locally). Keeping only
# the recipient's key id would silently break every unread
# message the moment the sender rotated. Carrying the public keys
# in the header also makes decryption registry-independent, so a
# resend can re-derive the pipe key from the original envelope
# alone after either side rotated. Retired keys live for a 48h
# grace window, then they are destroyed.
#
# An encryption public key is only trusted with a self-attestation:
# the node signs (node, enc_key_id, enc_public_key) with its
# Ed25519 signing key, and senders verify that signature against
# the node's certified signing public key before encrypting. A
# registry edit that substitutes an encryption key cannot forge
# the attestation without the node's signing key, so the
# substitution is refused instead of silently read by an attacker.
# Retired public keys carry the attestation they had when current.

class DecryptError(Exception):
    """Decryption failed. Carries what the mismatch report needs:
    which keys the message used, which keys the recipient holds."""

    def __init__(self, reason, used_to_key_id=None, used_from_key_id=None,
                 held_key_ids=None):
        super().__init__(reason)
        self.reason = reason
        self.used_to_key_id = used_to_key_id
        self.used_from_key_id = used_from_key_id
        self.held_key_ids = held_key_ids or []


def enc_pub_path(node):
    return keys_dir() / f"{node}.x25519.pub"


def enc_priv_path(node):
    return keys_dir() / f"{node}.x25519.enc"


def enc_attest_path(node):
    return keys_dir() / f"{node}.x25519.attest"


def enc_retired_list_path(node):
    """Local record of a node's retired private encryption keys:
    [{key_id, valid_until}]. The registry holds the matching
    retired PUBLIC keys (enc_prev_keys) for other nodes to find."""
    return keys_dir() / f"{node}.x25519.retired.json"


def enc_retired_priv_path(node, key_id):
    return keys_dir() / f"{node}.x25519.{key_id}.enc"


def enc_key_id_of_pubkey(raw):
    """The key id: first 12 hex of SHA-256 of the raw public key.
    Deterministic, so a key id that does not match its public key
    is detectable."""
    return hashlib.sha256(raw).hexdigest()[:12]


def enc_attestation_payload(node, key_id, public_b64):
    return canonical({"node": node, "enc_key_id": key_id,
                      "enc_public_key": public_b64})


def sign_enc_attestation(node, key_id, public_b64):
    """Self-attest an encryption public key with the node's
    Ed25519 signing key. Returns base64."""
    sig = _sign_bytes(
        enc_attestation_payload(node, key_id, public_b64).encode(), node)
    return base64.b64encode(sig).decode()


def verify_enc_attestation(node, key_id, public_b64, attestation_b64,
                           registry):
    """True if the attestation is a valid Ed25519 signature by the
    node's certified signing key over (node, key_id, public key).
    Anything else — missing, malformed, wrong key — is False."""
    entry = registry.get("nodes", {}).get(node)
    if entry is None or not attestation_b64:
        return False
    try:
        sig = base64.b64decode(attestation_b64)
    except Exception:
        return False
    return _verify_bytes(
        enc_attestation_payload(node, key_id, public_b64).encode(), sig,
        entry.get("public_key", ""))


def generate_enc_keypair(node):
    """Generate a node's X25519 encryption keypair. The private
    key is encrypted at rest with the node's own per-node
    encryption key (same mechanism as the signing key); the public
    key and its self-attestation are written beside it. Returns
    (key_id, public_b64, attestation_b64). Never prints a key."""
    _require_crypto()
    priv = X25519PrivateKey.generate()
    raw_priv = priv.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption())
    raw_pub = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    public_b64 = base64.b64encode(raw_pub).decode()
    key_id = enc_key_id_of_pubkey(raw_pub)
    attestation = sign_enc_attestation(node, key_id, public_b64)
    enc_key = load_passphrase(node)
    for path, data in (
            (enc_priv_path(node), _openssl_enc(raw_priv, enc_key)),
            (enc_pub_path(node), public_b64.encode()),
            (enc_attest_path(node), attestation.encode())):
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(data)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    return key_id, public_b64, attestation


def load_enc_private_key(node, key_id=None):
    """Decrypt a node's X25519 private key into memory — the
    current one, or a retired one by key_id. Raises SystemExit
    when the node has no encryption keypair yet."""
    _require_crypto()
    if key_id is not None:
        current = _current_enc_key_id(node)
        if current == key_id:
            path = enc_priv_path(node)
        else:
            path = enc_retired_priv_path(node, key_id)
        if not path.exists():
            raise SystemExit(f"no encryption key {key_id} for {node}")
    else:
        path = enc_priv_path(node)
        if not path.exists():
            raise SystemExit(
                f"no encryption key for node {node}: run "
                f"`bridge.py rotate-keys --node {node}` first")
    raw = _openssl_enc(path.read_bytes(), load_passphrase(node),
                       decrypt=True)
    try:
        return X25519PrivateKey.from_private_bytes(raw)
    except Exception:
        raise SystemExit(f"encryption key for {node} is unreadable")


def _current_enc_key_id(node):
    """The key id of a node's current encryption keypair, from
    its local public key file. None if it has none."""
    path = enc_pub_path(node)
    if not path.exists():
        return None
    try:
        raw = base64.b64decode(path.read_text().strip())
    except Exception:
        return None
    return enc_key_id_of_pubkey(raw)


def enc_private_key_ids(node):
    """Key ids of the private encryption keys a node holds:
    current first, then retired. Used for the mismatch report
    (which keys the recipient holds) and for decryption attempts."""
    ids = []
    cur = _current_enc_key_id(node)
    if cur:
        ids.append(cur)
    rec = _read_enc_retired(node)
    ids.extend(r["key_id"] for r in rec if r["key_id"] not in ids)
    return ids


def _read_enc_retired(node):
    path = enc_retired_list_path(node)
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text())
    except Exception:
        return []


def _write_enc_retired(node, records):
    path = enc_retired_list_path(node)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(records, indent=2))
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def enc_entry_fields(node):
    """The registry fields for a node's CURRENT encryption key,
    from its local key files: public key, key id, rotation time,
    self-attestation. None when the node has no keypair yet."""
    pub_path = enc_pub_path(node)
    attest_path = enc_attest_path(node)
    if not pub_path.exists() or not attest_path.exists():
        return None
    public_b64 = pub_path.read_text().strip()
    try:
        raw = base64.b64decode(public_b64)
    except Exception:
        return None
    key_id = enc_key_id_of_pubkey(raw)
    return {
        "enc_public_key": public_b64,
        "enc_key_id": key_id,
        "enc_rotated_at": utcnow(),
        "enc_attestation": attest_path.read_text().strip(),
    }


def _pipe_key(my_priv, other_pub_raw, sender, recipient, from_key_id,
              to_key_id):
    """ECDH + HKDF to the AES-256 pipe key. The HKDF info binds
    both node names and both key ids, so a key derived for one
    pipe cannot be reused on another."""
    _require_crypto()
    shared = my_priv.exchange(other_pub_raw)
    info = ("agenc-bridge-v3|" + sender + "|" + recipient + "|"
            + from_key_id + "|" + to_key_id).encode()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=info).derive(shared)


def _enc_header(envelope):
    """The routing header that is both plaintext and AEAD
    associated data: the ciphertext cannot be cut into a
    different envelope."""
    return {k: envelope[k] for k in
            ("v", "id", "from", "to", "kind", "created_at")
            if k in envelope}


def payload_of(envelope):
    """The encryptable payload of a v2-shaped envelope: the
    kind-specific content, plus the thread for prompts/answers
    (the thread name is metadata worth hiding with the content),
    plus the resend markers when this envelope is a re-send of
    an earlier message."""
    payload = {}
    for field in ("task", "result", "prompt", "answer", "message",
                  "registry_update",
                  "resend_of", "resend_of_created_at"):
        if field in envelope:
            payload[field] = envelope[field]
    if envelope.get("thread") is not None:
        payload["thread"] = envelope.get("thread")
    return payload


def envelope_from_payload(header, payload):
    """Rebuild a v2-shaped envelope from a decrypted payload, so
    all existing processing code works unchanged on it. NEVER
    re-verify this dict: the signature covers the raw v3
    envelope (header + ciphertext), not this plaintext form."""
    env = dict(header)
    env.update(payload)
    return env


def _lookup_other_public(registry, node, key_id):
    """Another node's encryption public key by key id: current
    first, then retired (whose attestation is checked — a
    substituted retired key is refused, not used). Returns
    (raw_bytes, ok, reason)."""
    entry = registry.get("nodes", {}).get(node)
    if entry is None:
        return None, False, f"unknown node: {node}"
    if entry.get("enc_key_id") == key_id and entry.get("enc_public_key"):
        if not verify_enc_attestation(
                node, key_id, entry["enc_public_key"],
                entry.get("enc_attestation", ""), registry):
            return None, False, (f"encryption key {key_id} for {node} "
                                 f"has no valid attestation — refusing")
        try:
            return base64.b64decode(entry["enc_public_key"]), True, ""
        except Exception:
            return None, False, f"bad encryption key for {node}"
    for prev in entry.get("enc_prev_keys", []):
        if prev.get("key_id") == key_id and prev.get("public_key"):
            if not verify_enc_attestation(
                    node, key_id, prev["public_key"],
                    prev.get("enc_attestation", ""), registry):
                return None, False, (f"retired encryption key {key_id} "
                                     f"for {node} has no valid "
                                     f"attestation — refusing")
            try:
                return base64.b64decode(prev["public_key"]), True, ""
            except Exception:
                return None, False, f"bad retired encryption key for {node}"
    return None, False, (f"no encryption key {key_id} for {node} — "
                         f"the sender's registry is stale or the key "
                         f"was destroyed after the grace window")


def encrypt_envelope(envelope, registry):
    """Encrypt a v2-shaped envelope into its v3 form (header
    plaintext + signed, payload AEAD ciphertext). The caller
    (write_envelope) decides whether v3 applies; this only runs
    when the recipient holds an encryption key. Raises
    SystemExit — never silently downgrades — when the recipient's
    key is unattested or the sender has no encryption key."""
    _require_crypto()
    sender = envelope["from"]
    recipient = envelope["to"]
    entry = registry.get("nodes", {}).get(recipient)
    if entry is None or not entry.get("enc_public_key"):
        raise SystemExit(f"recipient {recipient} has no encryption key")
    to_key_id = entry["enc_key_id"]
    if not verify_enc_attestation(recipient, to_key_id,
                                  entry["enc_public_key"],
                                  entry.get("enc_attestation", ""),
                                  registry):
        raise SystemExit(
            f"recipient {recipient}'s encryption key {to_key_id} has "
            f"no valid attestation — refusing to encrypt to it")
    try:
        my_priv = load_enc_private_key(sender)
    except SystemExit as e:
        raise SystemExit(f"cannot encrypt: {e}")
    from_key_id = _current_enc_key_id(sender)
    if not from_key_id:
        raise SystemExit(f"cannot encrypt: no encryption key for {sender}")
    other_pub = X25519PublicKey.from_public_bytes(
        base64.b64decode(entry["enc_public_key"]))
    key = _pipe_key(my_priv, other_pub, sender, recipient,
                    from_key_id, to_key_id)
    header = dict(_enc_header(envelope))
    header["v"] = VERSION
    nonce = secrets.token_bytes(12)
    plaintext = canonical(payload_of(envelope)).encode()
    ciphertext = AESGCM(key).encrypt(nonce, plaintext,
                                     canonical(header).encode())
    # Both public keys ride in the header (they are public, and
    # the Ed25519 signature covers the whole header, so a forged
    # key cannot pass verification). Decryption is then
    # registry-independent: the recipient needs only its own
    # private key and the sender's public key from the header.
    # That matters after rotation — a message sent before either
    # side rotated stays decryptable without the old registry,
    # and a resend can re-derive the pipe key from the original
    # envelope alone.
    my_pub_raw = my_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    out = dict(header)
    out["enc"] = {"alg": "X25519+AES-256-GCM",
                  "to_key_id": to_key_id,
                  "from_key_id": from_key_id,
                  "to_public_key": entry["enc_public_key"],
                  "from_public_key": base64.b64encode(my_pub_raw).decode(),
                  "nonce": base64.b64encode(nonce).decode()}
    out["ciphertext"] = base64.b64encode(ciphertext).decode()
    return out


def decrypt_envelope(envelope, me, registry):
    """Decrypt a v3 envelope for `me` (the recipient, or the
    original sender re-reading its own mail for a resend).
    Returns the plaintext envelope in v2 shape — never re-verify
    it; the signature covers the raw v3 form. A v2 envelope is
    returned as-is. Raises DecryptError on any failure, carrying
    the key ids both sides used and the ids `me` holds, so the
    mismatch report can name them."""
    if envelope.get("v") != VERSION:
        return dict(envelope)
    _require_crypto()
    enc = envelope.get("enc") or {}
    to_key_id = enc.get("to_key_id", "")
    from_key_id = enc.get("from_key_id", "")
    held = enc_private_key_ids(me)
    if me == envelope.get("to"):
        my_key_id, other, other_key_id = to_key_id, envelope.get("from", ""), from_key_id
    elif me == envelope.get("from"):
        my_key_id, other, other_key_id = from_key_id, envelope.get("to", ""), to_key_id
    else:
        raise DecryptError(f"envelope {envelope.get('id')} is not "
                           f"addressed to {me}",
                           used_to_key_id=to_key_id,
                           used_from_key_id=from_key_id,
                           held_key_ids=held)
    try:
        my_priv = load_enc_private_key(me, my_key_id)
    except SystemExit:
        raise DecryptError(
            f"no encryption key {my_key_id} for {me} — the key was "
            f"rotated and its grace window has passed",
            used_to_key_id=to_key_id, used_from_key_id=from_key_id,
            held_key_ids=held)
    # The other party's public key comes from the envelope header
    # (signed, so it is authenticated by the sender's signature);
    # the registry is only a fallback for envelopes written
    # without it. Decryption therefore does not depend on the
    # reader's registry copy still holding a rotated key.
    other_b64 = enc.get("to_public_key" if me == envelope.get("from")
                        else "from_public_key", "")
    if other_b64:
        try:
            other_raw = base64.b64decode(other_b64)
            if len(other_raw) != 32:
                raise ValueError("bad key length")
            ok, reason = True, ""
        except Exception:
            raise DecryptError("bad public key in envelope header",
                               used_to_key_id=to_key_id,
                               used_from_key_id=from_key_id,
                               held_key_ids=held)
    else:
        other_raw, ok, reason = _lookup_other_public(registry, other,
                                                     other_key_id)
    if not ok:
        raise DecryptError(reason, used_to_key_id=to_key_id,
                           used_from_key_id=from_key_id,
                           held_key_ids=held)
    try:
        other_pub = X25519PublicKey.from_public_bytes(other_raw)
        key = _pipe_key(my_priv, other_pub, envelope["from"],
                        envelope["to"], from_key_id, to_key_id)
        nonce = base64.b64decode(enc.get("nonce", ""))
        ciphertext = base64.b64decode(envelope.get("ciphertext", ""))
        plaintext = AESGCM(key).decrypt(
            nonce, ciphertext, canonical(_enc_header(envelope)).encode())
        payload = json.loads(plaintext.decode())
    except InvalidTag:
        raise DecryptError(
            "decryption failed (tampered ciphertext or wrong key)",
            used_to_key_id=to_key_id, used_from_key_id=from_key_id,
            held_key_ids=held)
    except DecryptError:
        raise
    except Exception as e:
        raise DecryptError(f"decryption failed ({e})",
                           used_to_key_id=to_key_id,
                           used_from_key_id=from_key_id,
                           held_key_ids=held)
    return envelope_from_payload(_enc_header(envelope), payload)


def mismatch_reason(envelope, err):
    """The human-readable mismatch report. It names the message
    exactly — id, created_at timestamp, from, to, kind — which
    key the message used, which keys the recipient holds, and how
    to recover: fetch the current registry from the master, then
    ask the sender to re-send that message re-encrypted under the
    current key. Never includes a token or any key value — key
    ids only."""
    held = ", ".join(err.held_key_ids) if err.held_key_ids else "none"
    return (f"key mismatch: could not decrypt {envelope.get('kind')} "
            f"{envelope.get('id')} (created "
            f"{envelope.get('created_at')}) from "
            f"{envelope.get('from')} to {envelope.get('to')}: the "
            f"message used encryption keys "
            f"{err.used_from_key_id or '?'} (sender) / "
            f"{err.used_to_key_id or '?'} (recipient), but "
            f"{envelope.get('to')} holds {held} — {err.reason}. "
            f"Fetch the current registry from the master "
            f"(`bridge.py resync --registry <path>`), then ask the "
            f"sender to re-send it: `bridge.py rerequest --id "
            f"{envelope.get('id')} --to {envelope.get('from')}`")


def log_mismatch(bus, envelope, err):
    """Append one mismatch event to bus/mismatch.jsonl (the bus
    is shared, so the sender can see it too) and return the
    record. The log carries ids and timestamps only — never key
    values, never message content, never a token."""
    record = {
        "at": utcnow(),
        "id": envelope.get("id"),
        "created_at": envelope.get("created_at"),
        "from": envelope.get("from"),
        "to": envelope.get("to"),
        "kind": envelope.get("kind"),
        "used_from_key_id": err.used_from_key_id,
        "used_to_key_id": err.used_to_key_id,
        "held_key_ids": err.held_key_ids,
        "reason": err.reason,
    }
    bus = Path(bus)
    bus.mkdir(parents=True, exist_ok=True)
    with open(bus / "mismatch.jsonl", "a") as f:
        f.write(json.dumps(record) + "\n")
    return record


def read_mismatches(bus):
    """Mismatch records, newest first. Returns [] when none."""
    path = Path(bus) / "mismatch.jsonl"
    if not path.exists():
        return []
    out = []
    for line in path.read_text().splitlines():
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    out.reverse()
    return out


def _sign_bytes(data, node):
    """Ed25519-sign bytes with a node's private key. Returns raw sig."""
    pem = load_private_key_pem(node)
    key_path = _temp_file(pem, ".pem")
    data_path = _temp_file(data, ".bin")
    try:
        return _run_openssl(["pkeyutl", "-sign", "-inkey", key_path,
                             "-rawin", "-in", data_path])
    finally:
        os.unlink(key_path)
        os.unlink(data_path)


def _verify_bytes(data, sig_bytes, pub_pem):
    """Verify an Ed25519 signature against a PEM public key."""
    pub_path = _temp_file(pub_pem.encode(), ".pem")
    data_path = _temp_file(data, ".bin")
    sig_path = _temp_file(sig_bytes, ".sig")
    try:
        out = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin",
                              "-inkey", pub_path, "-rawin", "-in", data_path,
                              "-sigfile", sig_path],
                             capture_output=True)
        return out.returncode == 0
    finally:
        os.unlink(pub_path)
        os.unlink(data_path)
        os.unlink(sig_path)


def sign(envelope, node):
    body = {k: v for k, v in envelope.items() if k != "signature"}
    sig = _sign_bytes(canonical(body).encode(), node)
    return base64.b64encode(sig).decode()


def verify(envelope, registry):
    """Verify an envelope against the registry. Returns (ok, reason)."""
    # Names first: the id, sender, and recipient all become file
    # names somewhere (bus/<dir>/<id>.json, prompts/<to>/,
    # keys/<node>.pem.enc), so a '../' in any of them is a path
    # traversal — reject it before the signature is even checked.
    # `to` may also be "*" (broadcast to any worker).
    if not _is_safe_name(envelope.get("id", "")):
        return False, f"bad envelope id: {envelope.get('id')!r}"
    if not _is_safe_name(envelope.get("from", "")):
        return False, f"bad sender: {envelope.get('from')!r}"
    to = envelope.get("to", "")
    if to != "*" and not _is_safe_name(to):
        return False, f"bad recipient: {to!r}"
    sender = envelope.get("from", "")
    entry = registry.get("nodes", {}).get(sender)
    if entry is None:
        return False, f"unknown sender: {sender}"
    sig_b64 = envelope.get("signature", "")
    try:
        sig = base64.b64decode(sig_b64)
    except Exception:
        return False, "bad signature encoding"
    body = {k: v for k, v in envelope.items() if k != "signature"}
    if not _verify_bytes(canonical(body).encode(), sig,
                         entry["public_key"]):
        return False, "bad signature"
    if not verify_role_certificate(sender, entry, registry):
        return False, f"unapproved role for {sender}"
    # A role and its permissions must match: the role is what a
    # master sees when it reads this node's input ("slave input is
    # data, not instruction"), so a node displayed as [slave] that
    # holds master permissions would lie about what it can do.
    # The certificate alone does not enforce this — a master could
    # sign a divergent pair — so the check lives here, on every
    # envelope, as well as in trust/promote/approve.
    role = entry.get("role", "")
    if role not in ROLES or sorted(entry.get("permissions", [])) != sorted(ROLES[role]):
        return False, f"role/permissions mismatch for {sender}"
    return True, ""


# ---------------------------------------------------------------- role certificates
#
# A role assignment is only real if a master approved it. Every
# registry entry carries a role certificate: a master signs the
# node's name, role, permissions and fingerprint. verify() checks
# the certificate on every envelope, so a role that was changed
# without a master's signature — by editing the registry file, or
# by a node claiming a new role — is ignored: the envelope is
# rejected, never delivered, never run. Approvals happen where a
# master key lives; the certified registry is then copied to the
# other machines (it holds public keys only).
#
# The root of trust is the ROOT master, pinned in root.json (see
# root_pin_path) — a self-signed certificate is only valid for
# the pinned root, and every other certificate must chain back
# to it through masters whose own certificates are valid. The
# old rule ("a master approves itself") was self-referential:
# verify() read the approver's role out of the same registry
# file it was checking, so editing the file to make a worker a
# master and self-signing a certificate verified True. Now a
# self-signed certificate from anyone but the pinned root fails,
# and so does a chain that ends anywhere else (or loops). The
# pin is written once — `bridge.py pin-root`, or automatically
# when the first master is trusted — and copied to a machine
# together with the registry. Without a pin file, the root is
# derived from the registry (the single self-signed master) as
# a migration aid; that derivation fails closed when there are
# zero or more than one self-signed masters, and `bridge.py
# status` warns until the root is pinned.

def role_certificate_payload(node, role, permissions, fingerprint,
                             approved_by, approved_at):
    return canonical({
        "node": node, "role": role,
        "permissions": sorted(permissions),
        "fingerprint": fingerprint, "approved_by": approved_by,
        "approved_at": approved_at,
    })


def sign_role_certificate(node, role, permissions, fingerprint, approver):
    """Sign a role certificate with a master's private key."""
    approved_at = utcnow()
    payload = role_certificate_payload(node, role, permissions,
                                       fingerprint, approver, approved_at)
    sig = _sign_bytes(payload.encode(), approver)
    return {"approved_by": approver, "approved_at": approved_at,
            "signature": base64.b64encode(sig).decode()}


def _verify_cert_signature(node, entry, registry):
    """The signature half of a role certificate: the approver
    exists, holds a master/owner role in this registry, and
    really signed this node, role, permissions and fingerprint.
    This alone is NOT enough to trust the certificate — it says
    nothing about whether the approver was itself approved (see
    cert_chain)."""
    cert = entry.get("role_certificate")
    if not cert:
        return False
    approver = cert.get("approved_by", "")
    approver_entry = registry.get("nodes", {}).get(approver)
    if approver_entry is None:
        return False
    if approver_entry.get("role") not in ("master", "owner"):
        return False
    payload = role_certificate_payload(
        node, entry.get("role", ""), entry.get("permissions", []),
        entry.get("fingerprint", ""), approver, cert.get("approved_at", ""))
    try:
        sig = base64.b64decode(cert.get("signature", ""))
    except Exception:
        return False
    return _verify_bytes(payload.encode(), sig,
                         approver_entry["public_key"])


def load_root_pin(registry):
    """The root of trust for role certificates: {"node",
    "fingerprint"}, or None if none can be established.

    The pin file (root.json) wins when it exists and names a
    master/owner in this registry with a matching fingerprint.
    Without a pin file, the root is derived from the registry
    itself: the single node whose certificate is self-signed and
    verifies. That derivation is a migration aid for registries
    created before pinning — it fails closed (None) when there
    are zero or more than one self-signed masters. A second
    self-signed master is exactly what a self-promotion forgery
    looks like, so a tampered registry has no root at all and
    every certificate in it fails verification."""
    path = root_pin_path()
    if path.exists():
        try:
            pin = json.loads(path.read_text())
        except Exception:
            return None
        node = pin.get("node", "")
        fp = pin.get("fingerprint", "")
        if _is_safe_name(node) and re.fullmatch(r"\d{60}", fp or ""):
            entry = registry.get("nodes", {}).get(node)
            if entry and entry.get("fingerprint") == fp and \
                    entry.get("role") in ("master", "owner"):
                return {"node": node, "fingerprint": fp}
        return None
    roots = []
    for name, entry in registry.get("nodes", {}).items():
        cert = entry.get("role_certificate") or {}
        if cert.get("approved_by") == name and \
                entry.get("role") in ("master", "owner") and \
                _verify_cert_signature(name, entry, registry):
            roots.append({"node": name,
                          "fingerprint": entry.get("fingerprint", "")})
    if len(roots) == 1:
        return roots[0]
    return None


def is_root_node(registry, node):
    """True if this node is the pinned (or derived) root master:
    the only node whose certificate may be self-signed."""
    pin = load_root_pin(registry)
    if pin is None:
        return False
    entry = registry.get("nodes", {}).get(node)
    return (pin["node"] == node and entry is not None
            and entry.get("fingerprint") == pin["fingerprint"])


def cert_chain(node, entry, registry, _seen=None):
    """The approval chain for a node's certificate, from the node
    up to the root master (e.g. ["bob", "alice"]), or None if the
    chain is broken. Every link must be a master whose own
    certificate is valid — a signature that verifies but chains
    to nobody is not an approval — and the chain must end at the
    pinned (or derived) root, never at the node itself unless
    that node IS the root. A cycle (A approves B, B approves A)
    is broken, not followed forever."""
    seen = set(_seen or ())
    if node in seen:
        return None
    if not _verify_cert_signature(node, entry, registry):
        return None
    cert = entry.get("role_certificate") or {}
    approver = cert.get("approved_by", "")
    if approver == node:
        return [node] if is_root_node(registry, node) else None
    approver_entry = registry.get("nodes", {}).get(approver)
    if approver_entry is None:
        return None
    rest = cert_chain(approver, approver_entry, registry,
                      seen | {node})
    if rest is None:
        return None
    return [node] + rest


def verify_role_certificate(node, entry, registry):
    """True if the entry's role was approved by a master whose
    approval chains back to the root of trust. Any change to the
    role, permissions or fingerprint after approval breaks the
    signature, so an edited entry fails here — and a certificate
    a node signed for itself fails here too, unless that node is
    the pinned root: self-approval is the root's privilege
    alone."""
    return cert_chain(node, entry, registry) is not None


def _is_sole_master(registry, node):
    """True if this node is the only master/owner in the
    registry — the first-certification case for a legacy root
    that was trusted before certificates existed."""
    masters = [n for n, e in registry.get("nodes", {}).items()
               if e.get("role") in ("master", "owner")]
    return masters == [node]


def _maybe_pin_root(registry):
    """Persist the derived root pin (best effort, never fatal):
    the first time a registry gains a single self-signed master,
    write root.json so a later edit of the registry file cannot
    move the root. Returns the pin, or None if there is nothing
    unambiguous to pin or the write failed."""
    path = root_pin_path()
    if path.exists():
        return None
    pin = load_root_pin(registry)
    if pin is None:
        return None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(pin, indent=2))
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        return pin
    except OSError:
        return None


def role_of(node, registry):
    """A node's role from the registry ('unknown' if untrusted).
    This is what a master sees when it reads that node's input."""
    return registry.get("nodes", {}).get(node, {}).get("role", "unknown")


def _check_role_permissions(role, permissions):
    """A role's permissions are the role's definition — --permissions
    may restate them but never diverge from them. A [slave] that
    holds task permission is a lie the audit trail cannot see."""
    if role not in ROLES:
        raise SystemExit(f"unknown role: {role} "
                         f"(choose from: {', '.join(ROLES)})")
    if sorted(permissions) != sorted(ROLES[role]):
        raise SystemExit(
            f"permissions {sorted(permissions)} do not match role "
            f"{role} {sorted(ROLES[role])} — a role's permissions "
            f"are its definition, not a free choice")


def _resolve_approver(registry, role, node, explicit=None):
    """Pick the master that signs a role certificate. Returns the
    approver node name, or None if no master key is available on
    this machine (the entry is then written uncertified, or the
    promotion is refused).

    Self-approval is only for a node that is ALREADY a master
    re-approving itself, or for bootstrapping the very first
    master into an empty registry. A worker or slave can never
    self-approve a promotion to master."""
    if explicit:
        entry = registry.get("nodes", {}).get(explicit)
        if entry is None:
            raise SystemExit(f"approver {explicit} is not in the registry")
        if entry.get("role") not in ("master", "owner"):
            raise SystemExit(f"approver {explicit} is not a master/owner")
        if entry.get("role_certificate") is not None:
            # A master whose certificate is present must hold one
            # that chains to the root. A self-signed certificate
            # from anyone but the root fails here — so
            # `promote --node bob --role master --approve-by bob`
            # is refused even when bob's key is on this machine.
            if not verify_role_certificate(explicit, entry, registry):
                raise SystemExit(
                    f"approver {explicit}'s own role is not certified — "
                    f"its certificate is missing or does not match its "
                    f"current role, so it cannot approve anyone")
        elif not _is_sole_master(registry, explicit):
            # A master with no certificate yet may only approve
            # when it is the only master in the registry (first
            # certification of a legacy root). Otherwise it must
            # be certified by a master first — an uncertified
            # entry that merely claims to be a master approves
            # nothing.
            raise SystemExit(
                f"approver {explicit} has no certified role yet — "
                f"it cannot approve anyone until a master certifies it")
        if not (keys_dir() / f"{explicit}.pem.enc").exists():
            raise SystemExit(
                f"no private key for approver {explicit} here — run this "
                "where a master key lives, then copy trusted-keys.json")
        return explicit
    current = registry.get("nodes", {}).get(node, {})
    # An existing master re-approving itself — but only if its
    # current certificate chains to the root, or it has never been
    # certified and is the only master (first certification of a
    # legacy root, e.g. migrating a registry created before
    # certificates). A tampered entry that merely CLAIMS to be a
    # master — certificate present but invalid, or self-signed by
    # anyone but the root — cannot approve anything.
    if current.get("role") in ("master", "owner"):
        cert = current.get("role_certificate")
        if cert is not None and verify_role_certificate(node, current, registry):
            return node
        if cert is None and _is_sole_master(registry, node):
            return node
    for name, entry in registry.get("nodes", {}).items():
        if entry.get("role") in ("master", "owner") and \
                verify_role_certificate(name, entry, registry) and \
                (keys_dir() / f"{name}.pem.enc").exists():
            return name
    # Bootstrap: the first master, into a registry with no master
    # at all, approves itself. (A non-master being promoted never
    # reaches this — it already has an entry above.)
    if not current and role in ("master", "owner") and \
            not any(e.get("role") in ("master", "owner")
                    for e in registry.get("nodes", {}).values()):
        return node
    return None


def _certify_entry(registry, node, entry, approver):
    """Attach (or keep) a role certificate for an entry. If nothing
    about the entry changed, the old certificate is still valid
    and is kept — re-running trust is safe. Returns the certificate
    or None."""
    old = registry.get("nodes", {}).get(node, {})
    old_cert = old.get("role_certificate")
    if old_cert and old.get("role") == entry.get("role") and \
            old.get("permissions") == entry.get("permissions") and \
            old.get("fingerprint") == entry.get("fingerprint"):
        return old_cert
    if approver is None:
        return None
    return sign_role_certificate(node, entry["role"],
                                 entry["permissions"],
                                 entry["fingerprint"], approver)


# ---------------------------------------------------------------- registry

def root_pin_path():
    """The local root-of-trust pin: which node is the root master
    (and its fingerprint). Env override first (tests), then beside
    the keys dir (so a test run that isolates AGENC_BRIDGE_KEYS_DIR
    isolates this too), else ~/.config/agenc-bridge/root.json.
    The pin is the one trust anchor that does NOT live in the
    registry file itself: the registry is copied between machines,
    and anyone who can write it could otherwise move the root.
    The pin file is written once (by `bridge.py pin-root`, or
    automatically when the first master is trusted) and then
    copied with the registry to each machine that should trust
    it."""
    env = os.environ.get("AGENC_BRIDGE_ROOT_PIN", "").strip()
    if env:
        return Path(env)
    kd = os.environ.get("AGENC_BRIDGE_KEYS_DIR", "").strip()
    if kd:
        return Path(kd).parent / "root.json"
    return config_dir() / "root.json"


def load_registry(args=None):
    path = registry_path(args)
    if not path.exists():
        return {"nodes": {}}
    return json.loads(path.read_text())


def save_registry(registry, args=None):
    path = registry_path(args)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(registry, indent=2))
    os.replace(tmp, path)


def cmd_keygen(args):
    """Generate a node's Ed25519 keypair, plus its X25519
    encryption keypair. The private keys are encrypted at rest
    with the node's own encryption key — a fresh random key saved
    to passphrases/<node> (mode 600), or the per-node key already
    set for it (env var or file). The public keys are printed and
    saved beside them. The key values themselves are never
    printed. The encryption public key is self-attested with the
    signing key, so `trust` can publish it after verifying the
    attestation."""
    _check_node_name(args.node)
    kd = keys_dir()
    enc_path = kd / f"{args.node}.pem.enc"
    pub_path = kd / f"{args.node}.pub"
    if enc_path.exists():
        print(f"key already exists for {args.node} at {enc_path}", file=sys.stderr)
        return 1
    pem = _run_openssl(["genpkey", "-algorithm", "ED25519"])
    der = _run_openssl(["pkey", "-pubout", "-outform", "DER"],
                       input_bytes=pem)
    pub_pem = _run_openssl(["pkey", "-pubout"], input_bytes=pem).decode()
    fp = fingerprint_of_pubkey_der(der)
    enc_key = ensure_per_node_key(args.node)
    enc_path.write_bytes(_openssl_enc(pem, enc_key))
    os.chmod(enc_path, 0o600)
    pub_path.write_text(pub_pem)
    enc_key_id, _, _ = generate_enc_keypair(args.node)
    print(f"node: {args.node}")
    print(f"private key: {enc_path} (encrypted, mode 600)")
    if os.environ.get(_per_node_env_name(args.node), "").strip():
        print(f"encryption key: per-node, from "
              f"{_per_node_env_name(args.node)}")
    else:
        print(f"encryption key: per-node, "
              f"{per_node_passphrase_path(args.node)} (mode 600)")
    print(f"public key: {pub_path}")
    print(f"encryption keypair: {enc_pub_path(args.node)} "
          f"(public), {enc_priv_path(args.node)} (private, encrypted) "
          f"— key id {enc_key_id}")
    print(f"fingerprint: {fp[:5]} {fp[5:10]} {fp[10:15]} {fp[15:20]} "
          f"{fp[20:25]} {fp[25:30]} {fp[30:35]} {fp[35:40]} {fp[40:45]} "
          f"{fp[45:50]} {fp[50:55]} {fp[55:60]}")
    print("Share the public key with the nodes that should trust this one, "
          "then run `bridge.py trust` on each of them.")
    return 0


def _backup_key_files(paths):
    """Copy each path to <path>.bak (mode 600) before it is
    replaced. Returns [(path, bak_or_None, existed)]: the .bak
    files are the recovery path if a rekey is interrupted — a
    rekey must never leave a node that cannot decrypt its own
    key."""
    backups = []
    for path in paths:
        existed = path.exists()
        bak = None
        if existed:
            bak = path.with_suffix(".bak")
            shutil.copyfile(path, bak)
            os.chmod(bak, 0o600)
        backups.append((path, bak, existed))
    return backups


def _restore_key_files(backups):
    """Put every file back the way it was before the swap:
    restore from .bak, or delete a file the swap created."""
    for path, bak, existed in backups:
        if bak is not None and bak.exists():
            shutil.copyfile(bak, path)
            os.chmod(path, 0o600)
        elif not existed and path.exists():
            path.unlink()


def cmd_rekey(args):
    """Give a node its own per-node encryption key: decrypt its
    private key (and provider key, if one is stored) with its
    current key, generate a fresh random per-node key, and
    re-encrypt under it. The new ciphertexts are computed in
    memory before anything is written, so a failure changes
    nothing on disk; after the swap the node is decrypted once
    more to prove the new key works. Fail closed throughout: if
    the current key cannot decrypt, nothing is overwritten. The
    old shared passphrase stops working for this node afterwards.
    Refuses when the node's key comes from the environment
    (rotate it there instead)."""
    _check_node_name(args.node)
    if os.environ.get(_per_node_env_name(args.node), "").strip():
        print(f"cannot rekey {args.node}: its encryption key comes "
              f"from {_per_node_env_name(args.node)} — rotate it "
              f"there instead", file=sys.stderr)
        return 1
    enc_path = keys_dir() / f"{args.node}.pem.enc"
    if not enc_path.exists():
        print(f"no private key for node {args.node}: run keygen first",
              file=sys.stderr)
        return 1
    try:
        pem = load_private_key_pem(args.node)
    except SystemExit as e:
        print(f"cannot rekey {args.node}: current key unreadable "
              f"({e}) — refusing to overwrite it", file=sys.stderr)
        return 1
    provider_path = provider_key_path(args.node)
    provider_plain = None
    if provider_path.exists():
        try:
            provider_plain = load_provider_key(args.node)
        except SystemExit as e:
            print(f"cannot rekey {args.node}: provider key unreadable "
                  f"({e}) — refusing to overwrite it", file=sys.stderr)
            return 1
    # The X25519 encryption private keys (current + retired) are
    # re-encrypted under the new per-node key as well, in the same
    # atomic swap — a rekey must never leave a node that can sign
    # but cannot decrypt its own mail.
    enc_files = []  # (path, plaintext raw key bytes)
    for enc_file in [enc_priv_path(args.node)] + [
            enc_retired_priv_path(args.node, r["key_id"])
            for r in _read_enc_retired(args.node)]:
        if not enc_file.exists():
            continue
        try:
            raw = _openssl_enc(enc_file.read_bytes(),
                               load_passphrase(args.node), decrypt=True)
        except SystemExit as e:
            print(f"cannot rekey {args.node}: encryption key "
                  f"{enc_file.name} unreadable ({e}) — refusing to "
                  f"overwrite it", file=sys.stderr)
            return 1
        enc_files.append((enc_file, raw))
    new_key = base64.b64encode(secrets.token_bytes(32)).decode()
    try:
        new_pem_enc = _openssl_enc(pem, new_key)
        new_prov_enc = (_openssl_enc(provider_plain.encode(), new_key)
                        if provider_plain is not None else None)
        new_enc = [(path, _openssl_enc(raw, new_key))
                   for path, raw in enc_files]
    except SystemExit as e:
        print(f"cannot rekey {args.node}: re-encryption failed ({e})",
              file=sys.stderr)
        return 1
    key_path = per_node_passphrase_path(args.node)
    try:
        os.chmod(passphrases_dir(), 0o700)
    except OSError:
        pass

    backups = _backup_key_files((key_path, enc_path, provider_path) +
                                tuple(p for p, _ in enc_files))

    def _swap(path, data):
        t = path.with_suffix(".tmp")
        t.write_bytes(data)
        os.chmod(t, 0o600)
        os.replace(t, path)

    try:
        # Ciphertexts first, key file last: until the key file is
        # swapped, the old key still decrypts the old ciphertexts,
        # so a crash before the last swap leaves a working node;
        # a crash after it leaves the new key with the new
        # ciphertexts — also working. The old order (key file
        # first) left a new key with old ciphertexts on a crash
        # in between, which bricked the node.
        _swap(enc_path, new_pem_enc)
        if new_prov_enc is not None:
            _swap(provider_path, new_prov_enc)
        for path, data in new_enc:
            _swap(path, data)
        tmp = key_path.with_suffix(".tmp")
        tmp.write_text(new_key)
        os.chmod(tmp, 0o600)
        os.replace(tmp, key_path)
    except OSError as e:
        _restore_key_files(backups)
        print(f"cannot rekey {args.node}: swap failed ({e}) — "
              f"restored the previous key files from .bak",
              file=sys.stderr)
        return 1
    try:
        load_private_key_pem(args.node)
        if provider_path.exists():
            load_provider_key(args.node)
        if enc_priv_path(args.node).exists():
            load_enc_private_key(args.node)
        for path, _ in enc_files[1:]:
            load_enc_private_key(args.node, path.name.split(".")[2])
    except SystemExit as e:
        _restore_key_files(backups)
        print(f"rekeyed {args.node} but verification failed ({e}) — "
              f"restored the previous key files from .bak; the node "
              f"still works with its old key", file=sys.stderr)
        return 1
    print(f"rekeyed {args.node}: private key"
          f"{' and provider key' if provider_path.exists() else ''} "
          f"{'and encryption keys ' if enc_files else ''}"
          f"now encrypted with its own per-node key at {key_path} "
          f"(mode 600)")
    print(f"previous key files kept as .bak beside the new ones — "
          f"delete them once the node is proven working")
    return 0


def _publish_enc_fields(registry, node, fields):
    """Write a node's current encryption-key fields into its
    registry entry. If the entry already held a different current
    key, that key becomes retired (public key + attestation kept
    in enc_prev_keys for the grace window) — the old private key
    is retired by rotate-keys, which owns the private side."""
    entry = registry.get("nodes", {}).get(node)
    if entry is None:
        raise SystemExit(f"{node} is not in the registry — trust it first")
    old_key_id = entry.get("enc_key_id")
    if old_key_id and old_key_id != fields["enc_key_id"] \
            and entry.get("enc_public_key"):
        prev = {"key_id": old_key_id,
                "public_key": entry["enc_public_key"],
                "enc_attestation": entry.get("enc_attestation", ""),
                "valid_until": (datetime.now(timezone.utc) +
                                timedelta(hours=ENC_GRACE_HOURS)
                                ).strftime("%Y-%m-%dT%H:%M:%SZ")}
        entry.setdefault("enc_prev_keys", [])
        if not any(p.get("key_id") == old_key_id
                   for p in entry["enc_prev_keys"]):
            entry["enc_prev_keys"].append(prev)
    entry["enc_public_key"] = fields["enc_public_key"]
    entry["enc_key_id"] = fields["enc_key_id"]
    entry["enc_rotated_at"] = fields["enc_rotated_at"]
    entry["enc_attestation"] = fields["enc_attestation"]
    return entry


def _prune_retired_enc_keys(registry, node, now):
    """Destroy retired encryption keys past their grace window:
    the public key leaves the registry, the private key file
    leaves the disk. Returns the number pruned. After the window
    closes, mail encrypted under that key is undecryptable by
    design — that is the point of rotation."""
    entry = registry.get("nodes", {}).get(node)
    if entry is None:
        return 0
    kept, pruned = [], 0
    for prev in entry.get("enc_prev_keys", []):
        if prev.get("valid_until", "") and prev["valid_until"] <= now:
            pruned += 1
            path = enc_retired_priv_path(node, prev.get("key_id", ""))
            if path.exists():
                path.unlink()
        else:
            kept.append(prev)
    entry["enc_prev_keys"] = kept
    recs = [r for r in _read_enc_retired(node)
            if any(p.get("key_id") == r["key_id"] for p in kept)]
    _write_enc_retired(node, recs)
    for path in keys_dir().glob(f"{node}.x25519.*.enc"):
        key_id = path.name.split(".")[2]
        if not any(p.get("key_id") == key_id for p in kept):
            path.unlink()
            pruned += 1
    return pruned


def cmd_rotate_keys(args):
    """Rotate encryption keypairs (daily). For each node (or
    --node): generate a fresh X25519 keypair, publish its public
    key + attestation in the registry, and retire the current
    keypair — the old public key stays in the registry's
    enc_prev_keys and the old private key stays on disk, both for
    a 48h grace window, so in-flight mail still decrypts; then
    they are destroyed. A node with no encryption keypair yet
    simply gains one (the migration path). Rotation runs where
    the node's keys live; a node whose keys are not on this
    machine is skipped with a warning, never fatal. After
    rotating, the updated registry is distributed to the other
    nodes automatically (signed registry-update envelopes —
    see distribute_registry), so no hand-copy is needed; a
    machine with no master key cannot distribute, and says so
    instead of failing. --no-distribute keeps the old behaviour
    (rotate only — distribute later with `bridge.py
    distribute-registry`). --dry-run reports what would change
    without touching keys or the registry."""
    registry = load_registry(args)
    now = utcnow()
    if args.node:
        _check_node_name(args.node)
        nodes = [args.node]
    else:
        nodes = sorted(registry.get("nodes", {}))
    rotated, skipped, pruned_total = [], [], 0
    for node in nodes:
        entry = registry.get("nodes", {}).get(node)
        if entry is None:
            skipped.append((node, "not in the registry"))
            continue
        if args.dry_run:
            cur = entry.get("enc_key_id", "none")
            due = [p["key_id"] for p in entry.get("enc_prev_keys", [])
                   if p.get("valid_until", "") <= now]
            print(f"would rotate {node} (current {cur}, rotated "
                  f"{entry.get('enc_rotated_at', 'never')})"
                  + (f"; would prune retired: {', '.join(due)}"
                     if due else ""))
            continue
        # Read the old private key BEFORE generating the new
        # pair overwrites the current key files.
        old_key_id = _current_enc_key_id(node)
        old_priv_raw = None
        if old_key_id:
            try:
                old_priv_raw = _openssl_enc(
                    enc_priv_path(node).read_bytes(),
                    load_passphrase(node), decrypt=True)
            except SystemExit as e:
                skipped.append((node, f"current encryption key "
                                f"unreadable ({e})"))
                continue
        try:
            key_id, public_b64, attestation = generate_enc_keypair(node)
        except SystemExit as e:
            skipped.append((node, str(e)))
            continue
        if old_key_id and old_key_id != key_id and old_priv_raw is not None:
            valid_until = (datetime.now(timezone.utc) +
                           timedelta(hours=ENC_GRACE_HOURS)
                           ).strftime("%Y-%m-%dT%H:%M:%SZ")
            enc_retired_priv_path(node, old_key_id).write_bytes(
                _openssl_enc(old_priv_raw, load_passphrase(node)))
            os.chmod(enc_retired_priv_path(node, old_key_id), 0o600)
            recs = _read_enc_retired(node)
            if not any(r["key_id"] == old_key_id for r in recs):
                recs.append({"key_id": old_key_id,
                             "valid_until": valid_until})
            _write_enc_retired(node, recs)
        _publish_enc_fields(registry, node, {
            "enc_public_key": public_b64, "enc_key_id": key_id,
            "enc_rotated_at": now, "enc_attestation": attestation})
        pruned_total += _prune_retired_enc_keys(registry, node, now)
        rotated.append((node, old_key_id or "none", key_id))
    if not args.dry_run:
        save_registry(registry, args)
    for node, old, new in rotated:
        print(f"rotated {node}: {old} -> {new} "
              f"(old key usable until "
              f"{(datetime.now(timezone.utc) + timedelta(hours=ENC_GRACE_HOURS)).strftime('%Y-%m-%dT%H:%M:%SZ')})")
    if pruned_total:
        print(f"pruned {pruned_total} retired key(s) past their grace window")
    for node, why in skipped:
        print(f"WARNING: skipped {node}: {why}", file=sys.stderr)
    if not args.dry_run and (rotated or pruned_total) \
            and not args.no_distribute:
        # The registry changed: close the loop hands-free by
        # distributing it. A machine with no master key cannot
        # distribute — that is a warning, not a failure: the
        # rotation itself still happened, and the registry can
        # be distributed from where a master key lives.
        distributor = _resolve_distributor(registry)
        if distributor is None:
            print("WARNING: no master key on this machine — the "
                  "updated registry was not distributed. Run "
                  "`bridge.py distribute-registry` where a master "
                  "key lives, or copy trusted-keys.json and run "
                  "`bridge.py resync --registry <path>` there.",
                  file=sys.stderr)
        else:
            seq, sent, skipped_dist = distribute_registry(
                registry, args.bus, distributor,
                reg_path=registry_path(args))
            print(f"distributed registry seq {seq} from "
                  f"{distributor} to {len(sent)} node(s)"
                  + (f": {', '.join(sent)}" if sent else ""))
            for node, why in skipped_dist:
                print(f"WARNING: skipped {node}: {why}", file=sys.stderr)
    elif not args.dry_run and args.no_distribute:
        print("distribution skipped (--no-distribute) — run "
              "`bridge.py distribute-registry` to send the updated "
              "registry to the other nodes")
    return 0


def cmd_publish_enc_key(args):
    """Publish a node's encryption public key into the local
    registry, from its local key files, with its self-attestation
    verified first. Used after keygen on a new machine, and as
    the recovery step when a registry copy lost the enc fields.
    Refuses when the attestation does not verify against the
    node's certified signing key — a key file that does not
    belong to this node is never published."""
    _check_node_name(args.node)
    registry = load_registry(args)
    entry = registry.get("nodes", {}).get(args.node)
    if entry is None:
        print(f"{args.node} is not in the registry — trust it first",
              file=sys.stderr)
        return 1
    fields = enc_entry_fields(args.node)
    if fields is None:
        print(f"no encryption keypair for {args.node}: run "
              f"`bridge.py keygen --node {args.node}` or "
              f"`bridge.py rotate-keys --node {args.node}` first",
              file=sys.stderr)
        return 1
    if not verify_enc_attestation(args.node, fields["enc_key_id"],
                                  fields["enc_public_key"],
                                  fields["enc_attestation"], registry):
        print(f"encryption key attestation for {args.node} does not "
              f"verify against its registry signing key — refusing "
              f"to publish it", file=sys.stderr)
        return 1
    _publish_enc_fields(registry, args.node, fields)
    save_registry(registry, args)
    print(f"published encryption key {fields['enc_key_id']} for "
          f"{args.node}")
    return 0


def cmd_keys(args):
    """Show encryption-key freshness per node: current key id,
    when it was rotated, whether its attestation verifies, and
    retired keys with their expiry. A node with no encryption
    key cannot receive encrypted mail; a key older than a day is
    due its daily rotation. With --node, show one node."""
    registry = load_registry(args)
    nodes = registry.get("nodes", {})
    if args.node:
        _check_node_name(args.node)
        names = [args.node] if args.node in nodes else []
        if not names:
            print(f"{args.node} is not in the registry", file=sys.stderr)
            return 1
    else:
        names = sorted(nodes)
    now = datetime.now(timezone.utc)
    for name in names:
        entry = nodes[name]
        key_id = entry.get("enc_key_id", "")
        rotated_at = entry.get("enc_rotated_at", "")
        if not entry.get("enc_public_key"):
            print(f"{name}: NO encryption key — cannot receive "
                  f"encrypted mail (run `bridge.py rotate-keys "
                  f"--node {name}`)")
            continue
        att_ok = verify_enc_attestation(
            name, key_id, entry["enc_public_key"],
            entry.get("enc_attestation", ""), registry)
        age = ""
        if rotated_at:
            try:
                dt = datetime.strptime(rotated_at, "%Y-%m-%dT%H:%M:%SZ"
                                       ).replace(tzinfo=timezone.utc)
                hours = (now - dt).total_seconds() / 3600
                age = f", rotated {hours:.0f}h ago" + (
                    " — rotation due" if hours > 24 else "")
            except ValueError:
                pass
        print(f"{name}: enc key {key_id}{age}, attestation "
              f"{'ok' if att_ok else 'BAD — refuse to encrypt to it'}")
        for prev in entry.get("enc_prev_keys", []):
            print(f"  retired {prev.get('key_id')} until "
                  f"{prev.get('valid_until')}")
        held = enc_private_key_ids(name)
        if len(held) > 1:
            print(f"  holds {len(held)} private keys "
                  f"(current + {len(held) - 1} retired)")
    return 0


def validate_registry(incoming, local_pin=None, local_seq=0):
    """Validate a registry copy the same way verify() checks
    envelopes — returns a list of problems (empty = valid).
    Checks: the incoming registry roots at the same root of
    trust as this machine's pin (when both are known) and has a
    single self-signed master to root trust in at all; every
    role/permissions pair matches its role; every role
    certificate chains to that root; every encryption key
    (current and retired) carries a valid self-attestation; and
    the incoming registry_seq is not older than the local one —
    an older copy must never roll the registry back. A tampered
    copy fails here and is refused without touching the local
    registry. Shared by resync (hand-copy) and by registry
    updates (automatic distribution)."""
    problems = []
    if not isinstance(incoming, dict) or not isinstance(
            incoming.get("nodes", {}), dict):
        return ["not a registry (no nodes mapping)"]
    incoming_pin = load_root_pin(incoming)
    if local_pin is not None and incoming_pin is not None \
            and local_pin.get("node") != incoming_pin.get("node"):
        problems.append(
            f"incoming registry roots at {incoming_pin.get('node')}, "
            f"but this machine pins {local_pin.get('node')} as the "
            f"root of trust")
    if incoming_pin is None:
        problems.append("incoming registry has no single self-signed "
                        "master to root trust in")
    incoming_seq = incoming.get("registry_seq", 0)
    if not isinstance(incoming_seq, int):
        problems.append("registry_seq is not a number")
    elif incoming_seq < local_seq:
        problems.append(
            f"registry_seq {incoming_seq} is older than the local "
            f"registry's {local_seq} — refusing a rollback")
    for name, entry in sorted(incoming.get("nodes", {}).items()):
        if not _is_safe_name(name):
            problems.append(f"{name}: unsafe node name")
            continue
        if entry.get("role") not in ROLES or sorted(
                entry.get("permissions", [])) != sorted(
                ROLES.get(entry.get("role", ""), [])):
            problems.append(f"{name}: role/permissions mismatch")
        cert = entry.get("role_certificate")
        if not cert or not verify_role_certificate(name, entry, incoming):
            problems.append(f"{name}: role certificate does not chain "
                            f"to the root")
        if entry.get("enc_public_key"):
            if not verify_enc_attestation(
                    name, entry.get("enc_key_id", ""),
                    entry["enc_public_key"],
                    entry.get("enc_attestation", ""), incoming):
                problems.append(f"{name}: encryption key attestation "
                                f"does not verify")
        for prev in entry.get("enc_prev_keys", []):
            if not verify_enc_attestation(
                    name, prev.get("key_id", ""), prev.get("public_key", ""),
                    prev.get("enc_attestation", ""), incoming):
                problems.append(f"{name}: retired encryption key "
                                f"{prev.get('key_id')} attestation does "
                                f"not verify")
    return problems


def _adopt_registry(incoming, reg_path=None):
    """Replace the local registry with a validated copy,
    atomically, keeping the old copy as .bak. The caller must
    have run validate_registry first. reg_path is the registry
    file to write (default: the usual registry path) — a
    --registry flag must flow through here, or adoption would
    land in the default file while the caller keeps reading the
    flag's."""
    dest = Path(reg_path) if reg_path else registry_path()
    if dest.exists():
        shutil.copyfile(dest, dest.with_suffix(".bak"))
    tmp = dest.with_suffix(".tmp")
    tmp.write_text(json.dumps(incoming, indent=2))
    os.replace(tmp, dest)


def cmd_resync(args):
    """Adopt a registry copy from another machine — the hand-copy
    distribution step, validated instead of blind (see
    validate_registry). A tampered copy is refused without
    touching the local registry; a good one replaces it
    atomically, with the old copy kept as .bak."""
    src = Path(args.registry)
    if not src.exists():
        print(f"no such registry file: {args.registry}", file=sys.stderr)
        return 1
    try:
        incoming = json.loads(src.read_text())
    except Exception as e:
        print(f"registry {args.registry} unreadable ({e})",
              file=sys.stderr)
        return 1
    # NOTE: args.registry is the SOURCE here (resync's own
    # --registry flag), not the local registry — the local one is
    # the ambient registry (env AGENC_BRIDGE_REGISTRY, else the
    # default beside bridge.py). Loading it with args would load
    # the source as "local" and compare it against itself, so the
    # rollback check would never fire.
    local = load_registry()
    problems = validate_registry(incoming, load_root_pin(local),
                                 _registry_seq(local))
    if problems:
        print("refusing resync: incoming registry failed validation:",
              file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    _adopt_registry(incoming, registry_path())
    pin = load_root_pin(incoming)
    print(f"resynced registry from {args.registry} "
          f"({len(incoming.get('nodes', {}))} nodes, root "
          f"{pin.get('node') if pin else '?'})")
    return 0


# ---------------------------------------------------------------- registry distribution
#
# Rotation used to end with a human step: after rotate-keys, the
# updated registry (new encryption public keys + attestations)
# had to be hand-copied to every machine and resynced there.
# Distribution closes that loop: the distributor (a certified
# master — the machine that rotated) sends the whole registry to
# every other node as a signed registry-update envelope, and each
# node adopts it hands-free after validating it exactly the way
# resync does. The envelope rides the same transports as every
# other envelope — the bus file (synced by the git bus loop),
# pushed live by the relay, caught up on reconnect — so a node
# that is offline at rotation time picks the update up when it
# reconnects, inside the 48h grace window, and nothing is ever
# silently dropped: a pending update stays in
# bus/registry-updates/<node>/ until it is applied. Only public
# keys and attestations travel; private keys never leave their
# machine. A registry_seq in the registry orders updates and
# stops rollbacks: an update older than the last one applied is
# skipped, and an incoming registry older than the local one is
# refused.

REGISTRY_UPDATE_KIND = "registry-update"


def _registry_seq(registry):
    """The registry's monotonic distribution sequence (0 when
    absent — registries written before distribution existed)."""
    seq = registry.get("registry_seq", 0)
    return seq if isinstance(seq, int) and seq >= 0 else 0


def _applied_seq_path(bus, node):
    return Path(bus) / "registry-updates" / f".applied-{node}.json"


def _read_applied_seq(bus, node):
    """The last registry_seq this node applied (0 = none yet)."""
    try:
        data = json.loads(_applied_seq_path(bus, node).read_text())
        seq = data.get("seq", 0)
        return seq if isinstance(seq, int) and seq >= 0 else 0
    except Exception:
        return 0


def _write_applied_seq(bus, node, seq):
    path = _applied_seq_path(bus, node)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps({"seq": seq, "applied_at": utcnow()}))
    os.replace(tmp, path)


def _resolve_distributor(registry, explicit=None):
    """The node that may distribute registry updates: a
    master/owner whose role certificate chains to the root and
    whose private key is on this machine — the same bar
    _resolve_token_approver enforces for token issuance. Only a
    master distributes: a worker could otherwise push a registry
    that drops a node (validation checks signatures and
    attestations, but not completeness). Returns the distributor
    node name, or None when no master key is available here."""
    if explicit:
        entry = registry.get("nodes", {}).get(explicit)
        if entry is None:
            raise SystemExit(f"distributor {explicit} is not in the registry")
        if entry.get("role") not in ("master", "owner"):
            raise SystemExit(f"distributor {explicit} is not a master/owner")
        if not verify_role_certificate(explicit, entry, registry):
            raise SystemExit(
                f"distributor {explicit}'s role is not certified — "
                f"its certificate does not chain to the root")
        if not (keys_dir() / f"{explicit}.pem.enc").exists():
            raise SystemExit(
                f"no private key for distributor {explicit} here — run "
                "this where a master key lives")
        return explicit
    for name, entry in registry.get("nodes", {}).items():
        if entry.get("role") in ("master", "owner") and \
                verify_role_certificate(name, entry, registry) and \
                (keys_dir() / f"{name}.pem.enc").exists():
            return name
    return None


def distribute_registry(registry, bus, distributor, targets=None,
                        reg_path=None):
    """Send the registry to every other node as a signed
    registry-update envelope (v3, encrypted per-pipe like any
    other envelope). Bumps registry_seq first and saves the
    registry, so the envelopes carry the sequence they
    distribute. Targets default to every node except the
    distributor and relay-role nodes (the relay holds its
    registry in memory and never decrypts, so it has nothing to
    apply). A node with no encryption key is skipped with a
    warning — it cannot receive a v3 envelope at all. Returns
    (seq, sent, skipped): the sequence distributed, the nodes
    it was sent to, and (node, reason) pairs skipped. The
    envelopes stay in bus/registry-updates/<node>/ until the
    node applies them — that directory is the queue, and the
    relay pushes them live and catches them up on reconnect."""
    seq = _registry_seq(registry) + 1
    registry["registry_seq"] = seq
    if reg_path:
        _adopt_registry(registry, reg_path)
    else:
        save_registry(registry)
    dirs = bus_dirs(bus)
    if targets is None:
        targets = [n for n, e in sorted(registry.get("nodes", {}).items())
                   if n != distributor
                   and e.get("role") != "relay"]
    sent, skipped = [], []
    for target in sorted(targets):
        entry = registry.get("nodes", {}).get(target)
        if entry is None:
            skipped.append((target, "not in the registry"))
            continue
        if not entry.get("enc_public_key"):
            skipped.append((target, "has no encryption key"))
            continue
        env_id = (f"regupd-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
                  f"-{uuid.uuid4().hex[:6]}")
        envelope = {
            "v": VERSION, "id": env_id, "from": distributor,
            "to": target, "kind": REGISTRY_UPDATE_KIND,
            "created_at": utcnow(),
            "registry_update": {"registry": registry},
        }
        dest = dirs["registry-updates"] / target
        dest.mkdir(parents=True, exist_ok=True)
        try:
            write_envelope(dest / f"{env_id}.json", envelope,
                           distributor, registry)
        except SystemExit as e:
            skipped.append((target, str(e)))
            continue
        sent.append(target)
    return seq, sent, skipped


def cmd_distribute_registry(args):
    """Distribute the local registry to the other nodes now —
    the step rotate-keys runs automatically after rotating. The
    caller must be a certified master with its key here."""
    if args.to:
        _check_node_name(args.to)
    registry = load_registry(args)
    distributor = _resolve_distributor(registry, args.distributor)
    if distributor is None:
        raise SystemExit(
            "cannot distribute the registry: no master key on this "
            "machine — run this where a master key lives")
    targets = [args.to] if args.to else None
    seq, sent, skipped = distribute_registry(
        registry, args.bus, distributor, targets,
        reg_path=registry_path(args))
    print(f"distributed registry seq {seq} from {distributor} "
          f"to {len(sent)} node(s)"
          + (f": {', '.join(sent)}" if sent else ""))
    for node, why in skipped:
        print(f"WARNING: skipped {node}: {why}", file=sys.stderr)
    return 0


def apply_registry_update(envelope, plain, bus, registry, me,
                          reg_path=None):
    """Apply one decrypted registry-update envelope for `me`.
    Returns (ok, reason, applied): applied is True only when
    the local registry actually changed. Checks, in order:
    the sender is a certified master/owner (only a master
    distributes — a worker's update is refused even if its
    payload would validate); the sequence is newer than the
    last one applied (an older update is skipped, not an
    error); the payload registry validates exactly like resync
    (root pin, cert chains, role/permissions, enc
    attestations) and is not a rollback. A superseded update —
    its sequence no newer than the local registry's — is
    skipped, not refused: the local registry already holds this
    or a newer one (a later distribution landed first, the
    normal case when a node was offline for two rotations).
    Refusing it would file a benign envelope in dead/ and make
    registry-pull exit 1 for ordinary operation. A refused update
    is filed in dead/ with its reason; the local registry is left
    untouched. A successful application is recorded in the
    applied-seq sidecar, the envelope id is marked seen (so a
    replay is refused), and the envelope moves to read/<me>/."""
    dirs = bus_dirs(bus)
    sender = envelope.get("from", "")
    entry = registry.get("nodes", {}).get(sender, {})
    if entry.get("role") not in ("master", "owner") or \
            not verify_role_certificate(sender, entry, registry):
        return False, (f"registry update from {sender}, not a "
                       f"certified master — refusing"), False
    payload = plain.get("registry_update", {})
    incoming = payload.get("registry")
    if not isinstance(incoming, dict):
        return False, "registry update carries no registry", False
    seq = _registry_seq(incoming)
    last = _read_applied_seq(bus, me)
    if seq <= last:
        return True, (f"registry seq {seq} already applied "
                      f"(last applied {last})"), False
    # Superseded, not a rollback attempt: the local registry
    # already holds this sequence or a newer one, so there is
    # nothing to adopt and nothing to refuse — skip it (the
    # caller moves it to read/). Only a NEWER sequence reaches
    # validation below, where a tampered copy is still refused;
    # resync keeps its own rollback refusal (it has no skip
    # step — adopting an older copy there is always wrong).
    if seq <= _registry_seq(registry):
        return True, (f"skipped: registry seq {seq} is not newer "
                      f"than the local registry's "
                      f"{_registry_seq(registry)}"), False
    problems = validate_registry(incoming, load_root_pin(registry),
                                 _registry_seq(registry))
    if problems:
        return False, ("registry update failed validation: "
                       + "; ".join(problems)), False
    _adopt_registry(incoming, reg_path)
    _write_applied_seq(bus, me, seq)
    mark_seen(bus, envelope["id"])
    return True, f"applied registry seq {seq} from {sender}", True


def apply_pending_registry_updates(bus, node, registry,
                                   reg_path=None):
    """Apply every pending registry update for `node`, oldest
    first. A decryption failure leaves the envelope pending (a
    local key problem or a key mismatch is not bad data — the
    next distribution re-sends under the current keys, and the
    mismatch is already visible in status/dead/). Returns
    (registry, applied, refused): the registry re-read from
    disk when an update was adopted (the passed-in copy is
    stale then), the seqs applied, and the number refused.
    Each envelope is handled once: applied ones move to
    read/<node>/, refused ones to dead/."""
    dirs = bus_dirs(bus)
    pending_dir = dirs["registry-updates"] / node
    if not pending_dir.exists():
        return registry, [], 0
    applied, refused = [], 0
    for path in sorted(pending_dir.glob("*.json")):
        try:
            envelope = read_envelope(path)
        except Exception as e:
            print(f"unreadable registry update {path.name}: {e}",
                  file=sys.stderr)
            _move_to_dead(dirs, path)
            refused += 1
            continue
        ok, reason = check_envelope(envelope, registry, node, bus)
        if not ok:
            print(f"registry update {path.name} refused ({reason})",
                  file=sys.stderr)
            _move_to_dead(dirs, path)
            refused += 1
            continue
        try:
            plain = decrypt_envelope(envelope, node, registry)
        except DecryptError as e:
            # Not bad data: this machine cannot decrypt it yet
            # (key not loaded, or a mismatch the next
            # distribution repairs). Leave it pending and say
            # so — never silently drop it, and never file a
            # decryptable-later update in dead/.
            print(f"registry update {path.name} not decryptable yet "
                  f"({mismatch_reason(envelope, e)}) — leaving it "
                  f"pending", file=sys.stderr)
            continue
        ok, reason, changed = apply_registry_update(
            envelope, plain, bus, registry, node, reg_path)
        print(f"registry update {path.name}: {reason}", file=sys.stderr)
        if not ok:
            _move_to_dead(dirs, path)
            refused += 1
            continue
        _move_to_read(dirs, path, node)
        if changed:
            applied.append(_registry_seq(plain["registry_update"]
                                        ["registry"]))
            registry = load_registry() if reg_path is None \
                else json.loads(Path(reg_path).read_text())
    return registry, applied, refused


def cmd_registry_pull(args):
    """Apply pending registry updates for a node (the
    hands-free half of distribution). With --node, apply that
    node's updates; with no --node, apply for every node whose
    keys live here. Prints what was applied, skipped, or
    refused. Returns 1 when any update was refused (the
    refused envelopes sit in dead/ with their reasons)."""
    if args.node:
        _check_node_name(args.node)
    registry = load_registry(args)
    nodes = [args.node] if args.node else sorted(
        n for n in registry.get("nodes", {})
        if (keys_dir() / f"{n}.pem.enc").exists())
    refused_total = 0
    for node in nodes:
        _, applied, refused = apply_pending_registry_updates(
            args.bus, node, registry, registry_path(args))
        refused_total += refused
        if applied:
            print(f"{node}: applied registry seq "
                  f"{', '.join(str(s) for s in applied)}")
    if not nodes:
        print("(no nodes with keys on this machine)")
    return 1 if refused_total else 0


def _find_envelope_by_id(dirs, bus, env_id):
    """Find an envelope by id anywhere it can live: the live bus
    dirs, read/<reader>/, and bus-archive-*/. Task and prompt
    finders know their own layouts; the rest is a direct search.
    Returns the raw envelope dict, or None."""
    for finder in (_find_task_envelope, _find_prompt_envelope):
        env = finder(dirs, bus, env_id)
        if env is not None:
            return env
    for sub in ("results", "answers", "dead"):
        path = dirs[sub] / f"{env_id}.json"
        if path.exists():
            try:
                return read_envelope(path)
            except Exception:
                return None
    for sub in ("messages", "read"):
        base = dirs[sub]
        if not base.exists():
            continue
        for node_dir in base.iterdir():
            if not node_dir.is_dir():
                continue
            path = node_dir / f"{env_id}.json"
            if path.exists():
                try:
                    return read_envelope(path)
                except Exception:
                    return None
    for arch in sorted(Path(bus).parent.glob("bus-archive-*")):
        for sub in ("results", "answers", "dead"):
            path = arch / sub / f"{env_id}.json"
            if path.exists():
                try:
                    return read_envelope(path)
                except Exception:
                    return None
        for sub in ("messages", "read"):
            base = arch / sub
            if not base.exists():
                continue
            for node_dir in base.iterdir():
                if not node_dir.is_dir():
                    continue
                path = node_dir / f"{env_id}.json"
                if path.exists():
                    try:
                        return read_envelope(path)
                    except Exception:
                        return None
    return None


def cmd_rerequest(args):
    """Ask the sender of a message that could not be decrypted to
    re-send it. Looks the message up in the mismatch log (which
    carries its id and created_at timestamp), then sends a
    message envelope to the original sender asking for a resend
    of that id. The sender runs `bridge.py resend --id <id>`."""
    _check_node_name(args.sender)
    _check_to(args.to)
    if not _is_safe_name(args.id):
        print(f"bad message id: {args.id!r}", file=sys.stderr)
        return 1
    registry = load_registry(args)
    dirs = bus_dirs(args.bus)
    rec = None
    for r in read_mismatches(args.bus):
        if r.get("id") == args.id:
            rec = r
            break
    if rec is None:
        print(f"no mismatch recorded for {args.id} — nothing to "
              f"re-request (see `bridge.py status` for the mismatch "
              f"log)", file=sys.stderr)
        return 1
    if rec.get("from") != args.to:
        print(f"message {args.id} came from {rec.get('from')}, not "
              f"{args.to} — the re-request goes to the original "
              f"sender", file=sys.stderr)
        return 1
    held = ", ".join(rec.get("held_key_ids") or []) or "none"
    text = (f"resend request: please re-send {rec.get('kind')} "
            f"{rec.get('id')} (created {rec.get('created_at')}) — it "
            f"could not be decrypted (key mismatch: message used "
            f"{rec.get('used_from_key_id') or '?'} (sender) / "
            f"{rec.get('used_to_key_id') or '?'} (recipient), but "
            f"{rec.get('to')} holds {held}). Run: `bridge.py resend "
            f"--id {rec.get('id')}`")
    msg_id = f"msg-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
    envelope = {
        "v": VERSION,
        "id": msg_id,
        "from": args.sender,
        "to": args.to,
        "kind": "message",
        "created_at": utcnow(),
        "message": {"text": text, "needs_reply": True,
                    "in_reply_to": args.id},
    }
    dest = dirs["messages"] / args.to
    dest.mkdir(parents=True, exist_ok=True)
    write_envelope(dest / f"{msg_id}.json", envelope, args.sender, registry)
    print(msg_id)
    return 0


def cmd_resend(args):
    """Re-send a message a recipient could not decrypt, under the
    current keys. Finds the original envelope (by id) in done/,
    read/, tasks/, dead/, prompts/, messages/, results/, answers/
    or a bus archive, decrypts it as the original sender — the
    sender can re-derive the pipe key from its own private key
    and the recipient's key at send time, as long as both keys
    are still within their grace window — and writes a NEW
    envelope with the same kind/from/to/payload, a fresh id, and
    resend_of / resend_of_created_at naming the original. The
    recipient decrypts the new copy normally. Only the original
    sender may re-send its own mail. Fails closed when the
    original can no longer be decrypted (keys destroyed after
    the grace window) — then the message must be re-created."""
    _check_node_name(args.sender)
    if not _is_safe_name(args.id):
        print(f"bad message id: {args.id!r}", file=sys.stderr)
        return 1
    registry = load_registry(args)
    dirs = bus_dirs(args.bus)
    orig = _find_envelope_by_id(dirs, args.bus, args.id)
    if orig is None:
        print(f"no message {args.id} found in this bus (live or "
              f"archive) — nothing to re-send", file=sys.stderr)
        return 1
    if orig.get("from") != args.sender:
        print(f"message {args.id} was sent by {orig.get('from')}, not "
              f"{args.sender} — only the original sender can re-send "
              f"it", file=sys.stderr)
        return 1
    try:
        plain = decrypt_envelope(orig, args.sender, registry)
    except DecryptError as e:
        print(f"cannot resend {args.id}: the original can no longer "
              f"be decrypted ({e.reason}) — re-create the message",
              file=sys.stderr)
        return 1
    payload = payload_of(plain)
    payload["resend_of"] = args.id
    payload["resend_of_created_at"] = orig.get("created_at", "")
    new_id = (f"resend-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
              f"-{uuid.uuid4().hex[:6]}")
    new_env = {
        "v": VERSION,
        "id": new_id,
        "from": orig.get("from"),
        "to": orig.get("to"),
        "kind": orig.get("kind"),
        "created_at": utcnow(),
    }
    new_env.update(payload)
    kind = orig.get("kind")
    if kind == "task":
        dest = dirs["tasks"] / f"{new_id}.json"
    elif kind == "prompt":
        dest = dirs["prompts"] / orig.get("to", "")
        dest.mkdir(parents=True, exist_ok=True)
        dest = dest / f"{new_id}.json"
    elif kind == "message":
        dest = dirs["messages"] / orig.get("to", "")
        dest.mkdir(parents=True, exist_ok=True)
        dest = dest / f"{new_id}.json"
    elif kind == "result":
        dest = dirs["results"] / f"{new_id}.json"
    elif kind == "answer":
        dest = dirs["answers"] / f"{new_id}.json"
    else:
        print(f"cannot resend {args.id}: unknown kind {kind!r}",
              file=sys.stderr)
        return 1
    write_envelope(dest, new_env, args.sender, registry)
    print(new_id)
    return 0


def cmd_retire_shared_passphrase(args):
    """Retire the shared bridge passphrase, once every node has
    its own per-node encryption key. The shared passphrase is a
    migration fallback: anyone holding it plus a node's
    .pem.enc can read that node's key, so per-node isolation is
    only complete once the shared passphrase is gone. Refuses
    while any node in the registry still needs it (shared or no
    key at all) and names them, with the rekey command for each.
    When every node is per-node, the shared passphrase file
    (~/.config/agenc-bridge/passphrase) is renamed to
    passphrase.retired — kept as a backup, never deleted — and
    the command says so. An AGENC_BRIDGE_PASSPHRASE set in the
    environment cannot be unset from here, so it is reported
    and must be removed from the shell by hand."""
    registry = load_registry(args)
    needy = []
    for name in sorted(registry.get("nodes", {})):
        if encryption_key_status(name) != "per-node":
            needy.append(name)
    if needy:
        print("cannot retire the shared passphrase: these nodes "
              "still need it:", file=sys.stderr)
        for name in needy:
            print(f"  {name} ({encryption_key_status(name)}) — run "
                  f"`bridge.py rekey --node {name}`", file=sys.stderr)
        return 1
    shared_file = shared_passphrase_path()
    if shared_file.exists():
        # Beside the shared file itself, not config_dir(): the
        # shared file may live elsewhere (tests, or an
        # AGENC_BRIDGE_KEYS_DIR-isolated setup), and os.replace
        # cannot cross filesystems.
        retired = Path(str(shared_file) + ".retired")
        os.replace(shared_file, retired)
        print(f"shared passphrase retired: {shared_file} -> {retired} "
              f"(kept as a backup; delete it once the nodes are "
              f"proven working without it)")
    else:
        print("no shared passphrase file to retire "
              f"({shared_file} does not exist)")
    if os.environ.get("AGENC_BRIDGE_PASSPHRASE", "").strip():
        print("WARNING: AGENC_BRIDGE_PASSPHRASE is still set in this "
              "environment — unset it in the shell, or the shared "
              "passphrase stays live there", file=sys.stderr)
    print("shared passphrase retired: every node now uses its own "
          "per-node encryption key")
    return 0


def cmd_fingerprint(args):
    _check_node_name(args.node)
    pub_path = keys_dir() / f"{args.node}.pub"
    if not pub_path.exists():
        print(f"no public key for {args.node}: run keygen first", file=sys.stderr)
        return 1
    pub_pem = pub_path.read_text()
    der = _run_openssl(["pkey", "-pubin", "-outform", "DER"],
                       input_bytes=pub_pem.encode())
    fp = fingerprint_of_pubkey_der(der)
    print(f"{args.node}: {' '.join(fp[i:i + 5] for i in range(0, 60, 5))}")
    return 0


def cmd_trust(args):
    """Add a node's public key to the registry, with a role.

    The role is certified by a master (see _resolve_approver): a
    master approves itself; anyone else is approved by a master
    whose private key is on this machine. If no master key is
    here, the entry is written uncertified and a warning is
    printed — that node's input will be ignored until a master
    approves it (run `bridge.py approve` where a master key lives,
    then copy trusted-keys.json). Re-running trust for an entry
    that did not change keeps its existing certificate."""
    _check_node_name(args.node)
    registry = load_registry(args)
    pub_pem = Path(args.pubkey).read_text()
    der = _run_openssl(["pkey", "-pubin", "-outform", "DER"],
                       input_bytes=pub_pem.encode())
    fp = fingerprint_of_pubkey_der(der)
    if args.permissions:
        perms = [p.strip() for p in args.permissions.split(",") if p.strip()]
    else:
        perms = ROLES[args.role]
    _check_role_permissions(args.role, perms)
    entry = {
        "public_key": pub_pem,
        "fingerprint": fp,
        "permissions": perms,
        "role": args.role,
    }
    approver = _resolve_approver(registry, args.role, args.node,
                                 getattr(args, "approve_by", None))
    cert = _certify_entry(registry, args.node, entry, approver)
    if cert:
        entry["role_certificate"] = cert
    # Encryption key: explicit files (--enc-pubkey/--enc-attest),
    # else the node's own key files when they are on this machine
    # (keygen just wrote them, with the attestation). The
    # attestation is verified against the signing key in this
    # entry before anything is published — a key file that does
    # not belong to this node is never published. Re-trusting
    # keeps the entry's existing encryption fields (including
    # retired keys) when no new key is offered.
    old_entry = registry.get("nodes", {}).get(args.node, {})
    enc_fields = None
    if getattr(args, "enc_pubkey", None):
        try:
            public_b64 = Path(args.enc_pubkey).read_text().strip()
            raw = base64.b64decode(public_b64)
        except Exception as e:
            print(f"encryption public key {args.enc_pubkey} unreadable "
                  f"({e})", file=sys.stderr)
            return 1
        attest = ""
        if getattr(args, "enc_attest", None):
            attest = Path(args.enc_attest).read_text().strip()
        key_id = enc_key_id_of_pubkey(raw)
        if not verify_enc_attestation(
                args.node, key_id, public_b64, attest,
                {"nodes": {args.node: entry}}):
            print(f"encryption key attestation for {args.node} does "
                  f"not verify against its signing key — refusing to "
                  f"publish it", file=sys.stderr)
            return 1
        enc_fields = {"enc_public_key": public_b64, "enc_key_id": key_id,
                      "enc_rotated_at": utcnow(),
                      "enc_attestation": attest}
    else:
        enc_fields = enc_entry_fields(args.node)
        if enc_fields and not verify_enc_attestation(
                args.node, enc_fields["enc_key_id"],
                enc_fields["enc_public_key"],
                enc_fields["enc_attestation"],
                {"nodes": {args.node: entry}}):
            print(f"WARNING: encryption key attestation for "
                  f"{args.node} does not verify — encryption key "
                  f"not published", file=sys.stderr)
            enc_fields = None
    if enc_fields:
        entry.update(enc_fields)
    elif old_entry.get("enc_public_key"):
        for f in ("enc_public_key", "enc_key_id", "enc_rotated_at",
                  "enc_attestation"):
            if old_entry.get(f):
                entry[f] = old_entry[f]
    if old_entry.get("enc_prev_keys"):
        entry["enc_prev_keys"] = old_entry["enc_prev_keys"]
    registry.setdefault("nodes", {})[args.node] = entry
    save_registry(registry, args)
    # The first master trusted into a registry becomes the root of
    # trust — pin it now, so a later edit of the registry file
    # cannot move the root (see load_root_pin).
    if args.role in ("master", "owner"):
        _maybe_pin_root(registry)
    print(f"trusted {args.node} as {args.role} "
          f"(permissions: {', '.join(perms)})")
    if enc_fields:
        print(f"encryption key published: {enc_fields['enc_key_id']}")
    elif entry.get("enc_public_key"):
        print(f"encryption key kept: {entry['enc_key_id']}")
    else:
        print(f"no encryption key published for {args.node} — it can "
              f"only receive plaintext v2 mail until one is (run "
              f"`bridge.py rotate-keys --node {args.node}` where its "
              f"keys live, or `trust --enc-pubkey ... --enc-attest ...`)")
    if cert:
        print(f"role approved by {cert['approved_by']} at {cert['approved_at']}")
    else:
        print(f"WARNING: no master key here to approve this role — "
              f"{args.node} is uncertified and its input will be "
              f"ignored until a master approves it", file=sys.stderr)
    print(f"fingerprint: {' '.join(fp[i:i + 5] for i in range(0, 60, 5))}")
    print("Compare this fingerprint with the node's own `fingerprint` "
          "output before relying on it — that check is optional, but "
          "it is how you catch a key that was swapped in transit.")
    return 0


def cmd_promote(args):
    """Change a trusted node's role — a master action. The new
    role is certified by a master; without a master key on this
    machine the promotion is refused (a slave cannot promote
    itself, and neither can an edited registry file)."""
    _check_node_name(args.node)
    registry = load_registry(args)
    entry = registry.get("nodes", {}).get(args.node)
    if entry is None:
        print(f"{args.node} is not in the registry — trust it first",
              file=sys.stderr)
        return 1
    if args.permissions:
        perms = [p.strip() for p in args.permissions.split(",") if p.strip()]
    else:
        perms = ROLES[args.role]
    _check_role_permissions(args.role, perms)
    approver = _resolve_approver(registry, args.role, args.node,
                                 getattr(args, "approve_by", None))
    if approver is None:
        print(f"cannot promote {args.node}: no master key on this machine — "
              f"run this where a master key lives, then copy "
              f"trusted-keys.json", file=sys.stderr)
        return 1
    new_entry = dict(entry)
    new_entry["role"] = args.role
    new_entry["permissions"] = perms
    new_entry["role_certificate"] = sign_role_certificate(
        args.node, args.role, perms, entry["fingerprint"], approver)
    registry["nodes"][args.node] = new_entry
    save_registry(registry, args)
    print(f"promoted {args.node} to {args.role} "
          f"(permissions: {', '.join(perms)}), approved by {approver}")
    return 0


def cmd_approve(args):
    """Certify a node's current role with a master's signature.
    For entries written uncertified (no master key was on the
    machine when they were trusted). Refuses without a master key."""
    _check_node_name(args.node)
    registry = load_registry(args)
    entry = registry.get("nodes", {}).get(args.node)
    if entry is None:
        print(f"{args.node} is not in the registry — trust it first",
              file=sys.stderr)
        return 1
    approver = _resolve_approver(registry, entry.get("role", ""),
                                 args.node,
                                 getattr(args, "approve_by", None))
    if approver is None:
        print(f"cannot approve {args.node}: no master key on this machine — "
              f"run this where a master key lives, then copy "
              f"trusted-keys.json", file=sys.stderr)
        return 1
    _check_role_permissions(entry.get("role", ""),
                            entry.get("permissions", []))
    entry["role_certificate"] = sign_role_certificate(
        args.node, entry["role"], entry.get("permissions", []),
        entry["fingerprint"], approver)
    save_registry(registry, args)
    print(f"approved {args.node} as {entry['role']}, by {approver}")
    return 0


def cmd_pin_root(args):
    """Pin the root of trust: write root.json naming the root
    master and its fingerprint. With no --node, pins the derived
    root (the single self-signed master in this registry) and
    refuses if there is not exactly one — a second self-signed
    master means the registry is already tampered. With --node,
    pins that node, which must be a master/owner whose own
    certificate is self-signed and valid. Print the fingerprint
    so the operator can compare it out of band before relying
    on it; a pin for the wrong key is worse than no pin."""
    registry = load_registry(args)
    if args.node:
        _check_node_name(args.node)
        entry = registry.get("nodes", {}).get(args.node)
        if entry is None:
            print(f"{args.node} is not in the registry", file=sys.stderr)
            return 1
        if entry.get("role") not in ("master", "owner"):
            print(f"{args.node} is not a master/owner — only a master "
                  f"can be the root of trust", file=sys.stderr)
            return 1
        cert = entry.get("role_certificate") or {}
        if cert.get("approved_by") != args.node or \
                not _verify_cert_signature(args.node, entry, registry):
            print(f"{args.node}'s role is not self-approved — only a "
                  f"master whose own certificate is self-signed can "
                  f"be pinned as the root", file=sys.stderr)
            return 1
        pin = {"node": args.node,
               "fingerprint": entry.get("fingerprint", "")}
    else:
        pin = load_root_pin(registry)
        if pin is None:
            print("no root to pin: the registry has zero or more than "
                  "one self-signed master — inspect the registry "
                  "before pinning (a second self-signed master is "
                  "what a self-promotion forgery looks like)",
                  file=sys.stderr)
            return 1
    path = root_pin_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(pin, indent=2))
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    fp = pin["fingerprint"]
    print(f"root of trust pinned: {pin['node']} at {path} (mode 600)")
    print(f"fingerprint: {' '.join(fp[i:i + 5] for i in range(0, 60, 5))}")
    print("Compare this fingerprint with the root's own `fingerprint` "
          "output, and copy root.json to each machine with "
          "trusted-keys.json — a machine without the pin derives "
          "the root from the registry instead, which fails closed "
          "on a tampered file but is weaker than the pin.")
    return 0


def cmd_revoke(args):
    """Remove a node from the registry. Its messages are rejected
    from then on, even if correctly signed."""
    _check_node_name(args.node)
    registry = load_registry(args)
    if args.node not in registry.get("nodes", {}):
        print(f"{args.node} is not in the registry", file=sys.stderr)
        return 1
    del registry["nodes"][args.node]
    save_registry(registry, args)
    print(f"revoked {args.node}")
    return 0


def cmd_agent(args):
    """Provision (or remove) an agent node: one of the agent team's
    agents, with its own keys and its own powers.

    A thread gives an agent identity, rules, and history, but no
    permissions of its own — every thread is served by
    agenc-cloud. An agent node is a thread PLUS a node: its own
    Ed25519 keypair, its own role in the registry (so it can have
    different permissions from the other agents), its own thread
    wiki (named after the node), and a place in the served-nodes
    list, so the assistant's hook answers prompts addressed to
    it — as that agent, following that thread's rules, signing
    the answer with the agent's own key.

    --remove revokes the node and takes it off the served list.
    The thread wiki is kept as history."""
    from types import SimpleNamespace
    name = args.name
    _check_thread_name(name)
    if args.remove:
        registry = load_registry(args)
        if name in registry.get("nodes", {}):
            rc = cmd_revoke(SimpleNamespace(node=name,
                                            registry=args.registry))
            if rc != 0:
                return rc
        nodes = served_nodes()
        if name in nodes:
            _save_served_nodes([n for n in nodes if n != name])
        print(f"agent {name} removed (its thread wiki is kept)")
        return 0
    registry = load_registry(args)
    if name in registry.get("nodes", {}):
        print(f"{name} is already a node — use `bridge.py promote` "
              f"to change its role, or `bridge.py agent --remove` "
              f"to take it down", file=sys.stderr)
        return 1
    # 1. Its own keypair (reused if one already exists).
    kd = keys_dir()
    if not (kd / f"{name}.pem.enc").exists():
        rc = cmd_keygen(SimpleNamespace(node=name))
        if rc != 0:
            return rc
    else:
        print(f"key already exists for {name}, reusing it")
    # 2. Its own role, certified by a master.
    rc = cmd_trust(SimpleNamespace(
        node=name, pubkey=str(kd / f"{name}.pub"), role=args.role,
        permissions=None, approve_by=args.approve_by,
        registry=args.registry))
    if rc != 0:
        return rc
    # 3. Its own thread wiki, named after the node.
    dirs = bus_dirs(args.bus)
    _thread_record(dirs, name, "agenc-cloud", args.rules, registry)
    # 4. The assistant serves it.
    nodes = served_nodes()
    if name not in nodes:
        _save_served_nodes(nodes + [name])
    print(f"agent {name} ready: role {args.role}, thread {name}, "
          f"served by the assistant")
    return 0


def cmd_registry(args):
    registry = load_registry(args)
    nodes = registry.get("nodes", {})
    pin = load_root_pin(registry)
    if pin is None:
        print("WARNING: no root of trust — no certificate in this "
              "registry chains to a root (zero or more than one "
              "self-signed master). Every role is UNAPPROVED until "
              "the registry is repaired; run `bridge.py pin-root` "
              "once it names a single self-signed master.",
              file=sys.stderr)
    elif root_pin_path().exists():
        print(f"root of trust: {pin['node']} (pinned in "
              f"{root_pin_path()})")
    else:
        print(f"root of trust: {pin['node']} (derived from this "
              f"registry — run `bridge.py pin-root` to pin it)")
    if not nodes:
        print("(registry empty — no nodes trusted yet)")
        return 0
    shared = []
    for name, entry in sorted(nodes.items()):
        fp = entry.get("fingerprint", "")
        print(f"{name} [{entry.get('role', '?')}]: "
              f"{', '.join(entry.get('permissions', []))}")
        print(f"  fingerprint: {' '.join(fp[i:i + 5] for i in range(0, 60, 5))}")
        cert = entry.get("role_certificate")
        chain = cert_chain(name, entry, registry) if cert else None
        if chain:
            print(f"  role approved by {cert['approved_by']} at {cert['approved_at']} "
                  f"(chain: {' -> '.join(chain)})")
        else:
            print("  role UNAPPROVED — input from this node is ignored")
        enc = encryption_key_status(name)
        if enc == "per-node":
            print("  encryption key: per-node")
        elif enc == "shared":
            shared.append(name)
            print("  encryption key: shared (legacy — run "
                  f"`bridge.py rekey --node {name}` to give it its own)")
        else:
            print("  encryption key: none set")
        if entry.get("enc_public_key"):
            att_ok = verify_enc_attestation(
                name, entry.get("enc_key_id", ""),
                entry["enc_public_key"],
                entry.get("enc_attestation", ""), registry)
            print(f"  pipe encryption: key {entry.get('enc_key_id')} "
                  f"(rotated {entry.get('enc_rotated_at', '?')}, "
                  f"attestation {'ok' if att_ok else 'BAD'})")
            for prev in entry.get("enc_prev_keys", []):
                print(f"    retired {prev.get('key_id')} until "
                      f"{prev.get('valid_until')}")
        else:
            print("  pipe encryption: none — this node cannot receive "
                  "encrypted mail")
        print(f"  provider key: "
              f"{'set' if provider_key_path(name).exists() else 'not set'}")
    if shared:
        print(f"WARNING: {len(shared)} node(s) still use the shared "
              f"passphrase ({', '.join(shared)}) — rekey each one, "
              f"then run `bridge.py retire-shared-passphrase` to "
              f"retire it", file=sys.stderr)
    return 0


# ---------------------------------------------------------------- MCP routing tokens
#
# One MCP connection, many targets. The MCP server (bridge-mcp.py)
# speaks to many agent nodes over a single stdio connection, and
# stdio carries no per-caller identity — so the routing proof is a
# token, FIRST in the tool arguments, verified before anything is
# sent. A plain node name is NOT a token: anyone can type one.
#
# A token is a bearer credential: a fresh random 32-byte secret
# (256-bit entropy, crypto random, never derived from public info
# such as node names or timestamps alone), printed ONCE at issuance
# and never stored in plaintext anywhere — not in the tokens file,
# not in logs, not in tests or docs. What is stored, in
# ~/.config/agenc-bridge/mcp-tokens.json (mode 600, git-ignored;
# overridable with AGENC_BRIDGE_MCP_TOKENS for tests), is only the
# token's SHA-256 hash plus its metadata: a unique token_id, from,
# to ("*" is a wildcard: the caller may talk to any target), expiry,
# and who issued it. Two tokens for the same from/to still differ:
# every issuance draws fresh random bytes and a fresh token_id, so
# no two tokens are ever the same. Verification hashes the presented
# token and looks the hash up.
#
# A token is issued only by a master/owner (the approver) — a
# worker can never mint a token that lets it talk to the master,
# and issuance refuses without a master key on this machine. The
# token's from/to are still checked at use time, and the envelope
# the MCP server then writes is verified like any other (signature,
# role permission, binding), so a token is routing proof, not a
# bypass around the bridge's own checks.
#
# A token is bearer until it expires or is revoked: anyone holding
# it can use it. So keep tokens in the MCP server's environment or
# command line (held by the host, not typed into a prompt), keep
# expiries short, and revoke tokens you no longer need. A per-call
# token in the tool arguments is visible to the calling agent and
# to logs; prefer the server's own default token
# (AGENC_BRIDGE_MCP_TOKEN) when the caller is fixed.

def mcp_tokens_path():
    """Where routing-token records live: only SHA-256 hashes plus
    metadata, never a raw token. Explicit override first (tests),
    else ~/.config/agenc-bridge/mcp-tokens.json."""
    env = os.environ.get("AGENC_BRIDGE_MCP_TOKENS", "").strip()
    if env:
        return Path(env)
    return config_dir() / "mcp-tokens.json"


def _load_mcp_tokens(path=None):
    """{"tokens": [...]} from the tokens file; empty when missing
    or unreadable (a corrupt file refuses every token rather than
    crashing the caller)."""
    path = path or mcp_tokens_path()
    if not path.exists():
        return {"tokens": []}
    try:
        data = json.loads(path.read_text())
    except Exception:
        return {"tokens": []}
    if not isinstance(data, dict) or not isinstance(data.get("tokens"), list):
        return {"tokens": []}
    return data


def _save_mcp_tokens(data, path=None):
    path = path or mcp_tokens_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _parse_mcp_expiry(exp):
    """An expiry timestamp back to a datetime, or None if it does
    not parse — an unparseable expiry is treated as expired."""
    try:
        return datetime.strptime(exp, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc)
    except Exception:
        return None


def _resolve_token_approver(registry, explicit=None):
    """The master/owner that issues an MCP routing token. Only a
    master/owner whose own role certificate chains to the root —
    or, for a legacy root not yet certified, the sole master in
    the registry — and whose private key is on this machine may
    issue one. Returns the approver node name, or None if no
    master key is available here. This is the same bar
    `_resolve_approver` enforces for trust/promote/approve: a
    cert-less entry that merely claims to be a master issues
    nothing. (A token issued under the sole-master allowance
    verifies only once that master has certified itself, since
    `verify_mcp_token` requires a valid certificate for the
    issuer — issuance and verification agree everywhere else.)"""
    if explicit:
        entry = registry.get("nodes", {}).get(explicit)
        if entry is None:
            raise SystemExit(f"approver {explicit} is not in the registry")
        if entry.get("role") not in ("master", "owner"):
            raise SystemExit(f"approver {explicit} is not a master/owner")
        if entry.get("role_certificate") is not None:
            # A master whose certificate is present must hold one
            # that chains to the root. A self-signed certificate
            # from anyone but the root fails here.
            if not verify_role_certificate(explicit, entry, registry):
                raise SystemExit(
                    f"approver {explicit}'s own role is not certified — "
                    f"its certificate does not match its current role, "
                    f"so it cannot issue tokens")
        elif not _is_sole_master(registry, explicit):
            # A master with no certificate yet may only issue when
            # it is the only master in the registry (first
            # certification of a legacy root). Otherwise it must
            # be certified by a master first — an uncertified
            # entry that merely claims to be a master issues
            # nothing.
            raise SystemExit(
                f"approver {explicit} has no certified role yet — "
                f"it cannot issue tokens until a master certifies it")
        if not (keys_dir() / f"{explicit}.pem.enc").exists():
            raise SystemExit(
                f"no private key for approver {explicit} here — run this "
                "where a master key lives")
        return explicit
    for name, entry in registry.get("nodes", {}).items():
        if entry.get("role") in ("master", "owner") and \
                verify_role_certificate(name, entry, registry) and \
                (keys_dir() / f"{name}.pem.enc").exists():
            return name
    return None


def issue_mcp_token(registry, from_node, to_node, expiry_days, approver):
    """Mint a routing token: fresh random 32-byte secret + fresh
    token_id, store only the SHA-256 hash with the metadata.
    Returns (token, entry). The token is returned so the caller
    can print it once — it is never logged or stored."""
    token_id = secrets.token_hex(6)
    secret = base64.urlsafe_b64encode(
        secrets.token_bytes(32)).decode().rstrip("=")
    token = f"mcp-{token_id}-{secret}"
    now = datetime.now(timezone.utc)
    exp = now + timedelta(days=expiry_days)
    entry = {
        "token_id": token_id,
        "sha256": hashlib.sha256(token.encode()).hexdigest(),
        "from": from_node,
        "to": to_node,
        "exp": exp.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "issued_by": approver,
        "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "revoked": False,
    }
    data = _load_mcp_tokens()
    data["tokens"].append(entry)
    _save_mcp_tokens(data)
    return token, entry


def verify_mcp_token(token, registry):
    """Verify a routing token. Returns (ok, info, reason); info is
    {"token_id", "from", "to", "exp", "issued_by"} on success.
    Checks, in order: the token's hash is recorded, the token is
    not revoked, it has not expired, its from/to are safe names
    (to may be "*"), its caller is still a trusted node, and its
    issuer is still a master/owner with a valid role certificate.
    A token whose issuer lost master status dies with it."""
    if not isinstance(token, str) or not token.strip():
        return False, None, "no routing token supplied"
    digest = hashlib.sha256(token.strip().encode()).hexdigest()
    entry = None
    for candidate in _load_mcp_tokens().get("tokens", []):
        if hmac.compare_digest(candidate.get("sha256", ""), digest):
            entry = candidate
            break
    if entry is None:
        return False, None, "unknown routing token"
    if entry.get("revoked"):
        return False, None, "routing token revoked"
    exp = _parse_mcp_expiry(entry.get("exp", ""))
    if exp is None or exp <= datetime.now(timezone.utc):
        return False, None, "routing token expired"
    from_node = entry.get("from", "")
    to_node = entry.get("to", "")
    if not _is_safe_name(from_node):
        return False, None, f"bad caller in routing token: {from_node!r}"
    if to_node != "*" and not _is_safe_name(to_node):
        return False, None, f"bad target in routing token: {to_node!r}"
    if from_node not in registry.get("nodes", {}):
        return False, None, f"unknown caller in routing token: {from_node}"
    approver = entry.get("issued_by", "")
    approver_entry = registry.get("nodes", {}).get(approver)
    if approver_entry is None or \
            approver_entry.get("role") not in ("master", "owner") or \
            not verify_role_certificate(approver, approver_entry, registry):
        return False, None, ("routing token issuer is no longer a "
                             f"master: {approver}")
    return True, {
        "token_id": entry.get("token_id", ""),
        "from": from_node,
        "to": to_node,
        "exp": entry.get("exp", ""),
        "issued_by": approver,
    }, ""


def cmd_mcp_token(args):
    """Issue, verify, list, or revoke MCP routing tokens. Issuing
    prints the token itself (once) to stdout and the metadata to
    stderr — the token is never written anywhere else. Listing
    never shows a hash or a raw token, only token ids."""
    registry = load_registry(args)
    if args.list:
        entries = _load_mcp_tokens().get("tokens", [])
        if not entries:
            print("(no routing tokens issued)")
            return 0
        for e in entries:
            print(f"{e.get('token_id', '?')}: {e.get('from', '?')} -> "
                  f"{e.get('to', '?')}, expires {e.get('exp', '?')}, "
                  f"issued by {e.get('issued_by', '?')}"
                  f"{' (revoked)' if e.get('revoked') else ''}")
        return 0
    if args.verify:
        ok, info, reason = verify_mcp_token(args.verify, registry)
        if not ok:
            print(f"routing token rejected ({reason})", file=sys.stderr)
            return 1
        print(f"routing token {info['token_id']}: {info['from']} -> "
              f"{info['to']}, expires {info['exp']}, "
              f"issued by {info['issued_by']}")
        return 0
    if args.revoke:
        data = _load_mcp_tokens()
        for e in data.get("tokens", []):
            if e.get("token_id") == args.revoke:
                if e.get("revoked"):
                    print(f"routing token {args.revoke} already revoked")
                    return 0
                e["revoked"] = True
                _save_mcp_tokens(data)
                print(f"revoked routing token {args.revoke}")
                return 0
        print(f"no routing token {args.revoke!r}", file=sys.stderr)
        return 1
    # Issue.
    if not args.from_node or not args.to:
        raise SystemExit("mcp-token needs --from and --to to issue a token "
                         "(or --verify, --revoke, --list)")
    _check_node_name(args.from_node)
    _check_to(args.to)
    if args.from_node not in registry.get("nodes", {}):
        raise SystemExit(f"caller {args.from_node} is not in the registry")
    if args.to != "*" and args.to not in registry.get("nodes", {}):
        raise SystemExit(f"target {args.to} is not in the registry")
    if args.expiry_days is None or args.expiry_days <= 0:
        raise SystemExit("--expiry-days must be a positive number of days")
    approver = _resolve_token_approver(registry, args.approve_by)
    if approver is None:
        raise SystemExit(
            "cannot issue a routing token: no master key on this machine — "
            "run this where a master key lives")
    token, entry = issue_mcp_token(registry, args.from_node, args.to,
                                   args.expiry_days, approver)
    print(token)
    print(f"token {entry['token_id']}: {entry['from']} -> {entry['to']}, "
          f"expires {entry['exp']}, issued by {approver}", file=sys.stderr)
    print("This token is printed once and never stored in plaintext — "
          "save it where the MCP server can read it "
          "(AGENC_BRIDGE_MCP_TOKEN), then it cannot be shown again.",
          file=sys.stderr)
    return 0


# ---------------------------------------------------------------- launcher
#
# The launcher is the system that starts: one command that issues
# the starting (MCP) token and starts the MCP server. The token is
# kept completely separate from the encrypted envelopes — it is
# verified in-process by bridge-mcp.py before anything is sent,
# and it never travels in an envelope, so encryption can never
# turn a valid token into a rejection. The launcher hands the
# token to the server through its environment only: never on a
# command line (it would leak in `ps`), never printed, never
# logged. When the server stops, its token is revoked by default
# (a fresh token is issued on the next launch), so a token that
# outlived its server cannot be picked up and reused.

def _revoke_mcp_token_by_id(token_id):
    """Mark one routing token revoked, by token id. Returns True
    when a token with that id was found (and is now revoked)."""
    data = _load_mcp_tokens()
    for e in data.get("tokens", []):
        if e.get("token_id") == token_id:
            if not e.get("revoked"):
                e["revoked"] = True
                _save_mcp_tokens(data)
            return True
    return False


def _check_launch_node(registry, node):
    """A node the launcher may start a server as: it is in the
    registry, its role certificate chains to the root (so the
    server speaks as a certified node, not a name someone typed),
    and its private key is on this machine (the server signs
    envelopes as this node). Fails cleanly — nothing is issued
    and nothing is started when the node cannot serve."""
    entry = registry.get("nodes", {}).get(node)
    if entry is None:
        raise SystemExit(f"node {node} is not in the registry — "
                         "trust it first")
    if not verify_role_certificate(node, entry, registry):
        raise SystemExit(
            f"node {node} is not certified — its role certificate "
            f"does not chain to the root, so it cannot serve")
    if not (keys_dir() / f"{node}.pem.enc").exists():
        raise SystemExit(
            f"no private key for {node} here — run the launcher "
            "where the node's key lives")
    return entry


def issue_launch_token(registry, node, to, expiry_days, approver):
    """Pre-flight + issuance for a launch: the caller node must
    be certified with its key here, and the issuer must be a
    master/owner with a valid root-chained certificate (the same
    bar `_resolve_token_approver` enforces for `mcp-token`). The
    issued token is verified in-process once before it is handed
    out — a token that does not verify is revoked at once and
    never used. Returns (token, entry). The token itself is
    returned so the caller can pass it to the server through its
    environment; it must never be printed or logged."""
    _check_launch_node(registry, node)
    approver = _resolve_token_approver(registry, approver)
    if approver is None:
        raise SystemExit(
            "cannot issue a routing token: no master key on this "
            "machine — run this where a master key lives")
    token, entry = issue_mcp_token(registry, node, to, expiry_days,
                                   approver)
    ok, _, reason = verify_mcp_token(token, registry)
    if not ok:
        _revoke_mcp_token_by_id(entry["token_id"])
        raise SystemExit(
            f"issued token failed its own verification ({reason}) — "
            "revoked it, nothing started")
    return token, entry


def run_mcp_server(node, token, server=None, bus=None, extra_env=None):
    """Start bridge-mcp.py as a subprocess speaking as `node`,
    with the routing token in its environment only. Returns the
    Popen object; the caller owns waiting for it. The token is
    never placed on the command line (it would be visible in
    `ps` while the server runs) and never written anywhere —
    the child reads it from AGENC_BRIDGE_MCP_TOKEN. `server` is
    the MCP server script (default bridge-mcp.py beside
    bridge.py); `bus` is passed as --bus when given."""
    server = Path(server) if server else Path(__file__).with_name(
        "bridge-mcp.py")
    if not server.exists():
        raise SystemExit(f"no MCP server script at {server}")
    argv = [sys.executable, str(server), "--node", node]
    if bus:
        argv += ["--bus", str(bus)]
    env = dict(os.environ)
    if extra_env:
        env.update(extra_env)
    env["AGENC_BRIDGE_MCP_TOKEN"] = token
    env["AGENC_BRIDGE_NODE"] = node
    return subprocess.Popen(argv, env=env)


def cmd_launch(args):
    """Issue the starting token and start the MCP server, in the
    foreground: Ctrl-C stops the server and revokes its token.
    Prints only the token id, target, and expiry — never the
    token itself. --no-revoke leaves the token live after the
    server stops (hand it to another server instance yourself);
    by default a launch token dies with its server."""
    _check_node_name(args.node)
    _check_to(args.to)
    registry = load_registry(args)
    if args.to != "*" and args.to not in registry.get("nodes", {}):
        raise SystemExit(f"target {args.to} is not in the registry")
    if args.expiry_days is None or args.expiry_days <= 0:
        raise SystemExit("--expiry-days must be a positive number of days")
    token, entry = issue_launch_token(registry, args.node, args.to,
                                      args.expiry_days, args.approve_by)
    proc = run_mcp_server(args.node, token, server=args.server,
                          bus=args.bus)
    print(f"launched MCP server as {args.node} -> {args.to} "
          f"(token {entry['token_id']}, expires {entry['exp']}, "
          f"issued by {entry['issued_by']}) — the token lives only "
          f"in the server's environment, it is not printed, logged, "
          f"or passed on the command line", file=sys.stderr)
    print("Ctrl-C stops the server and revokes its token",
          file=sys.stderr)

    def _stop(signum, frame):
        # Ctrl-C / SIGTERM is a stop, not a crash: end the server
        # (wait() below then returns) and the token is revoked in
        # the finally. The handler replaces the default, so no
        # KeyboardInterrupt is raised in the parent.
        if proc.poll() is None:
            proc.terminate()

    old_int = signal.signal(signal.SIGINT, _stop)
    old_term = signal.signal(signal.SIGTERM, _stop)
    code = 0
    try:
        code = proc.wait()
    finally:
        signal.signal(signal.SIGINT, old_int)
        signal.signal(signal.SIGTERM, old_term)
        if proc.poll() is None:
            # The server outlived the wait (it survived the
            # terminate): stop it for real before revoking.
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        if not args.no_revoke:
            _revoke_mcp_token_by_id(entry["token_id"])
            print(f"stopped; routing token {entry['token_id']} revoked",
                  file=sys.stderr)
        else:
            print(f"stopped; routing token {entry['token_id']} left "
                  f"live (--no-revoke) — revoke it with `bridge.py "
                  f"mcp-token --revoke {entry['token_id']}` when done",
                  file=sys.stderr)
    return code if isinstance(code, int) and 0 <= code <= 255 else 1


# ---------------------------------------------------------------- envelopes

def seen_ids(bus):
    seen_dir = Path(bus) / "seen"
    seen_dir.mkdir(parents=True, exist_ok=True)
    seen_file = seen_dir / "seen.txt"
    if not seen_file.exists():
        return set(), seen_file
    return set(seen_file.read_text().split()), seen_file


def _check_envelope_version(envelope, registry):
    """Version gate. v3 is current. v2 plaintext is rejected by
    default; AGENC_BRIDGE_ALLOW_V2=1 re-opens the migration
    window. Inside the window, a v2 envelope is a downgrade
    exactly when BOTH sides hold an encryption key — then v3 was
    possible and plaintext is a stripping attempt, so it is
    refused. When either side holds no key, v3 was impossible
    (a legacy worker cannot encrypt its result to an encrypted
    master, and an encrypted sender cannot encrypt to a legacy
    node), so v2 is the only option and it is accepted. Outside
    the window, v2 is refused outright."""
    v = envelope.get("v")
    if v == VERSION:
        return True, ""
    if v == 2:
        if not allow_v2():
            return False, ("unsupported envelope version: 2 — v2 "
                           "plaintext envelopes are no longer accepted "
                           "(set AGENC_BRIDGE_ALLOW_V2=1 to re-open the "
                           "migration window)")
        sender_has = bool(registry.get("nodes", {}).get(
            envelope.get("from", ""), {}).get("enc_public_key"))
        to = envelope.get("to", "")
        recip_has = to != "*" and bool(registry.get("nodes", {}).get(
            to, {}).get("enc_public_key"))
        if sender_has and recip_has:
            return False, (f"downgrade refused: v2 plaintext envelope "
                           f"from {envelope.get('from')} to {to}, and "
                           f"both hold encryption keys")
        return True, ""
    return False, f"unsupported envelope version: {v}"


def _envelope_seen(bus, envelope_id):
    """True when the id is in seen.txt or carries a claim file —
    a claimed id is seen from the moment the claim lands, before
    the seen.txt append is visible to other readers."""
    seen, _ = seen_ids(bus)
    if envelope_id in seen:
        return True
    return (Path(bus) / "seen" / f"claim-{envelope_id}").exists()


def _claim_seen(bus, envelope_id):
    """Atomically claim an envelope id. Returns True when this
    caller is the first to claim it, False when it was already
    seen or claimed. The gate is an O_EXCL claim file in seen/ —
    the same idiom cmd_reply uses for its reply claim — so two
    concurrent claimers cannot both win; the winner records the
    id in seen.txt before returning."""
    if _envelope_seen(bus, envelope_id):
        return False
    claim = Path(bus) / "seen" / f"claim-{envelope_id}"
    try:
        fd = os.open(claim, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.close(fd)
    except FileExistsError:
        return False
    mark_seen(bus, envelope_id)
    return True


def check_envelope(envelope, registry, me, bus, claim=False):
    """Verify one envelope. Returns (ok, reason).

    Checks, in order: version, known sender, signature, recipient,
    the sender's role allows this kind of message, and the id was
    never seen before (replay guard).

    With claim=True the replay guard stops being check-then-mark:
    passing the check claims the id atomically (see _claim_seen),
    so exactly one of two concurrent consumers passes and the
    other is refused as a replay. Callers that consume the
    envelope (worker poll, reply, inbox) pass claim=True. The
    default stays a pure check for callers that only list
    (prompts) or must retry the same id later (registry updates
    left pending by a decryption failure) — claiming there would
    burn an id nothing consumed."""
    ok, reason = _check_envelope_version(envelope, registry)
    if not ok:
        return False, reason
    ok, reason = verify(envelope, registry)
    if not ok:
        return False, reason
    sender = envelope.get("from", "")
    if envelope.get("to") not in (me, "*"):
        return False, f"not addressed to {me}"
    need = KIND_PERMISSION.get(envelope.get("kind", ""))
    if need and need not in registry["nodes"][sender].get("permissions", []):
        return False, f"sender {sender} may not send {envelope.get('kind')} messages"
    if claim:
        if not _claim_seen(bus, envelope.get("id")):
            return False, "replayed envelope id"
    elif _envelope_seen(bus, envelope.get("id")):
        return False, "replayed envelope id"
    return True, ""


def verify_basic(envelope, registry):
    """Signature + known sender, for readers that do not know who
    'me' is (wait / fetch-answer). Returns (ok, reason)."""
    ok, reason = _check_envelope_version(envelope, registry)
    if not ok:
        return False, reason
    return verify(envelope, registry)


def _find_task_envelope(dirs, bus, task_id):
    """The original task envelope for a result id. It lives in
    done/ once the worker finished (or claimed/ in the brief
    window between writing the result and moving the task), and
    in bus-archive-*/done/ after an archive sweep. A task the
    worker rejected on verification lives in dead/ instead — the
    rejection result still has to bind to it, so dead/ (and the
    archive's dead/) is checked too."""
    for sub in ("done", "claimed", "tasks", "dead"):
        path = dirs[sub] / f"{task_id}.json"
        if path.exists():
            try:
                return read_envelope(path)
            except Exception:
                return None
    for arch in sorted(Path(bus).parent.glob("bus-archive-*")):
        for sub in ("done", "dead"):
            path = arch / sub / f"{task_id}.json"
            if path.exists():
                try:
                    return read_envelope(path)
                except Exception:
                    return None
    return None


def _find_prompt_envelope(dirs, bus, prompt_id):
    """The original prompt envelope for an answer id. It lives in
    prompts/<to>/ until answered (reply moves it to read/<to>/),
    and in bus-archive-*/read/ or prompts/ after a sweep. A prompt
    rejected on verification lives in dead/ instead — the
    rejection answer still has to bind to it, so dead/ (and the
    archive's dead/) is checked too."""
    for node_dir in dirs["prompts"].iterdir():
        path = node_dir / f"{prompt_id}.json"
        if path.exists():
            try:
                return read_envelope(path)
            except Exception:
                return None
    for node_dir in dirs["read"].iterdir():
        if not node_dir.is_dir():
            continue
        path = node_dir / f"{prompt_id}.json"
        if path.exists():
            try:
                return read_envelope(path)
            except Exception:
                return None
    dead_path = dirs["dead"] / f"{prompt_id}.json"
    if dead_path.exists():
        try:
            return read_envelope(dead_path)
        except Exception:
            return None
    for arch in sorted(Path(bus).parent.glob("bus-archive-*")):
        for sub in ("read", "prompts"):
            base = arch / sub
            if not base.exists():
                continue
            for node_dir in base.iterdir():
                if not node_dir.is_dir():
                    continue
                path = node_dir / f"{prompt_id}.json"
                if path.exists():
                    try:
                        return read_envelope(path)
                    except Exception:
                        return None
        dead_arch = arch / "dead" / f"{prompt_id}.json"
        if dead_arch.exists():
            try:
                return read_envelope(dead_arch)
            except Exception:
                return None
    return None


def is_rejection(envelope, payload=None):
    """True if this envelope is a rejection, not a real result or
    answer: a result whose status is "rejected", or an answer
    whose payload carries rejected=True. For a v3 envelope the
    flag lives in the decrypted payload, so pass it as `payload`
    (the raw envelope has only header + ciphertext); for v2 the
    envelope itself is the payload."""
    src = payload if payload is not None else envelope
    if src.get("kind") == "result":
        return (src.get("result") or {}).get("status") == "rejected"
    if src.get("kind") == "answer":
        return bool((src.get("answer") or {}).get("rejected"))
    return False


def is_relay_rejection(envelope, registry, payload=None):
    """True if this rejection was sent by the trusted relay node —
    the only node allowed to reject on behalf of a worker it is
    not. The relay holds no result/answer permission and is not
    the node the original was addressed to; that is exactly what
    makes it a rejection rather than a forgery, and only the
    relay key can sign one. A rejection from any other node must
    still pass the normal binding below. The signature is
    verified here, inside this check, on the RAW envelope — a
    caller that checked this first used to be fooled by any
    envelope claiming from=relay, whatever key signed it. The
    rejection flag itself is read from `payload` when the
    envelope is v3 (decrypted), because the raw form carries no
    payload to read. With no payload (the relay itself, which
    cannot decrypt): the relay signs nothing but rejections with
    result/answer kinds, so a relay-signed result/answer is a
    relay rejection — a forged one still fails the signature
    check above."""
    if (role_of(envelope.get("from", ""), registry) != "relay"
            or not verify_basic(envelope, registry)[0]):
        return False
    if payload is not None:
        return is_rejection(envelope, payload)
    if envelope.get("v") == VERSION:
        return envelope.get("kind") in ("result", "answer")
    return is_rejection(envelope)


def rejection_reason(envelope, payload=None):
    """The human-readable reason inside a rejection envelope.
    For v3, pass the decrypted payload — the raw envelope has
    no reason to read."""
    src = payload if payload is not None else envelope
    if src.get("kind") == "result":
        return (src.get("result") or {}).get("stderr", "")
    if src.get("kind") == "answer":
        return (src.get("answer") or {}).get("reason", "")
    return ""


def _check_response_binding(envelope, original, kind, registry,
                            payload=None):
    """A result or an answer is only believable from the node the
    original was addressed to. A signature proves the sender
    holds a trusted key — it does not prove the sender is the
    node that was asked. Without this, any trusted node could
    fabricate another node's work results or the assistant's
    answers, and the reader could not tell. Returns (ok, reason).
    A broadcast original (to == "*") has no single expected
    responder, so the sender check is skipped for it — but the
    addressee and the kind permission are still checked.
    One exception: a rejection from the trusted relay node. The
    relay reports that it dropped the original (permission,
    unknown recipient, replay); it is still addressed back to
    the original sender, and only the relay key can sign it.
    `payload` is the decrypted v3 envelope (headers are read
    from the raw envelope, the rejection flag from the payload);
    for v2 it is None and the envelope serves as both."""
    if is_relay_rejection(envelope, registry, payload):
        if envelope.get("to") != original.get("from"):
            return False, (f"{kind} addressed to {envelope.get('to')!r}, "
                           f"but the original came from "
                           f"{original.get('from')!r}")
        return True, ""
    need = KIND_PERMISSION.get(kind, "")
    sender = envelope.get("from", "")
    entry = registry.get("nodes", {}).get(sender, {})
    if need and need not in entry.get("permissions", []):
        return False, (f"sender {sender} may not send {kind} messages")
    if envelope.get("to") != original.get("from"):
        return False, (f"{kind} addressed to {envelope.get('to')!r}, "
                       f"but the original came from "
                       f"{original.get('from')!r}")
    if original.get("to") not in ("*", None) and \
            envelope.get("from") != original.get("to"):
        return False, (f"{kind} is from {envelope.get('from')!r}, but "
                       f"the original was addressed to "
                       f"{original.get('to')!r}")
    return True, ""


def verify_result_binding(envelope, registry, bus, payload=None):
    """Check a result envelope against its task. Returns
    (ok, reason). Pass the decrypted v3 payload when the
    envelope is encrypted, so a relay rejection is recognised
    (its flag lives in the payload, its signature on the raw
    envelope)."""
    dirs = bus_dirs(bus)
    task = _find_task_envelope(dirs, bus, envelope.get("id", ""))
    if task is None:
        return False, ("original task not found — cannot verify who "
                       "should have answered it")
    return _check_response_binding(envelope, task, "result", registry,
                                   payload)


def verify_answer_binding(envelope, registry, bus, payload=None):
    """Check an answer envelope against its prompt. Returns
    (ok, reason). Pass the decrypted v3 payload when the
    envelope is encrypted, so a relay rejection is recognised
    (its flag lives in the payload, its signature on the raw
    envelope)."""
    dirs = bus_dirs(bus)
    prompt = _find_prompt_envelope(dirs, bus, envelope.get("id", ""))
    if prompt is None:
        return False, ("original prompt not found — cannot verify who "
                       "should have answered it")
    return _check_response_binding(envelope, prompt, "answer", registry,
                                   payload)


def mark_seen(bus, envelope_id):
    seen, seen_file = seen_ids(bus)
    if envelope_id not in seen:
        with open(seen_file, "a") as f:
            f.write(envelope_id + "\n")


def write_envelope_file(path, envelope):
    """Write an envelope as-is, signature first, without re-signing.
    Use for forwarding an envelope that is already signed."""
    ordered = {"signature": envelope.get("signature", "")}
    ordered.update({k: v for k, v in envelope.items() if k != "signature"})
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(ordered, indent=2))
    os.replace(tmp, path)
    return ordered


def write_envelope(path, envelope, node, registry=None):
    """Write a signed envelope. The signature is the FIRST part of
    the message — readers check it before anything else, and an
    envelope without a valid leading signature is rejected.

    Encryption is decided here, from the recipient's registry
    entry and the sender's own key files — every send path goes
    through this function, so there is no way to send a plaintext
    envelope by forgetting a step:
    - recipient holds an encryption key AND the sender holds its
      own encryption private key -> v3, payload encrypted for
      that recipient (encrypt_envelope raises SystemExit instead
      of downgrading when the key is unattested or the sender's
      key cannot be read);
    - either side holds no key -> v2 plaintext, only while
      AGENC_BRIDGE_ALLOW_V2=1 (the migration window: a legacy
      worker cannot encrypt its result to an encrypted master);
      otherwise refused;
    - broadcast ("*") cannot be encrypted for one recipient ->
      v2 while the window is open, otherwise refused.
    Pass the caller's registry when one is loaded; without it
    the registry is re-read from its default location."""
    if registry is None:
        registry = load_registry()
    env = dict(envelope)
    to = env.get("to", "")
    recipient = (registry.get("nodes", {}) or {}).get(to) \
        if to != "*" else None
    sender_has_key = enc_priv_path(node).exists()
    if to == "*":
        if not allow_v2():
            raise SystemExit(
                "cannot send to '*': broadcast cannot be encrypted "
                "for one recipient, and v2 plaintext envelopes are "
                "rejected — address the task to a node")
        env["v"] = 2
    elif recipient and recipient.get("enc_public_key") and sender_has_key:
        env = encrypt_envelope(env, registry)
    else:
        if not allow_v2():
            missing = to if not (recipient and
                                 recipient.get("enc_public_key")) else node
            raise SystemExit(
                f"cannot send to {to}: {missing} has no encryption "
                f"key and v2 plaintext envelopes are rejected — run "
                f"`bridge.py rotate-keys --node {missing}` on its "
                f"machine and copy the registry")
        env["v"] = 2
    sig = sign(env, node)
    ordered = {"signature": sig}
    ordered.update({k: v for k, v in env.items() if k != "signature"})
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(ordered, indent=2))
    os.replace(tmp, path)
    return ordered


def read_envelope(path):
    return json.loads(path.read_text())


def bus_dirs(bus):
    bus = Path(bus)
    names = ["tasks", "claimed", "results", "done", "dead", "messages", "read",
             "prompts", "answers", "threads", "seen", "registry-updates"]
    for name in names:
        (bus / name).mkdir(parents=True, exist_ok=True)
    return {name: bus / name for name in names}


def _check_thread_name(name):
    """A thread is an agent's name, and it becomes a file name, so
    it may only use safe characters (no path separators)."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", name or ""):
        raise SystemExit(
            f"bad thread name {name!r}: use letters, digits, '-' or '_'")
    return name


def _is_safe_name(value):
    """A name that is safe as a file name and as a node/envelope
    field: letters, digits, '-' or '_' only, no separators, no
    '..'. Envelope ids, node names, and recipients all use this —
    they all become file names somewhere (bus/<dir>/<id>.json,
    prompts/<to>/, keys/<node>.pem.enc), so a '../' in any of them
    is a path traversal."""
    return isinstance(value, str) and bool(
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", value or ""))


def _check_node_name(name):
    """A node name becomes file names (keys/<node>.pem.enc,
    keys/<node>.pub) and registry keys, so it must be safe."""
    if not _is_safe_name(name):
        raise SystemExit(
            f"bad node name {name!r}: use letters, digits, '-' or '_'")
    return name


def _check_to(value):
    """A recipient: a safe node name, or "*" for broadcast."""
    if value != "*" and not _is_safe_name(value):
        raise SystemExit(
            f"bad recipient {value!r}: use a node name or '*'")
    return value


def _thread_dir(dirs, name):
    """A thread's wiki: one directory per thread, holding its
    record, its rules, its distilled facts, and its history.
    The history page IS the index — every turn verbatim, in
    order — so the wiki and the index are one thing, not two."""
    return dirs["threads"] / name


def _thread_history_scan(dirs, name, registry=None):
    """All prompt/answer envelopes in the bus for a thread, in
    order. Used once when migrating an old thread, and as a
    fallback when a thread has no history page yet. The archive
    is scanned too: a turn whose envelopes were swept into
    bus-archive-*/read/ is still genuine, and without the
    archive the history check would flag real turns
    UNVERIFIED — a false positive that teaches the operator to
    ignore the flag. A v3 envelope carries its thread (and
    text) only inside the ciphertext, so it is decrypted first
    — as the recipient, then as the sender, whichever local
    key this machine holds — before the thread/kind filter.
    An envelope nobody on this machine can decrypt is returned
    raw; its turn then verifies as UNVERIFIED, which is the
    safe outcome for mail the reader cannot read."""
    items = []
    seen = set()
    bases = [dirs["prompts"], dirs["answers"], dirs["read"]]
    bus = dirs["threads"].parent
    for arch in sorted(bus.parent.glob("bus-archive-*")):
        for sub in ("prompts", "answers", "read"):
            if (arch / sub).is_dir():
                bases.append(arch / sub)
    for base in bases:
        for p in base.rglob("*.json"):
            try:
                env = read_envelope(p)
            except Exception:
                continue
            if env.get("v") == VERSION:
                for me in (env.get("to", ""), env.get("from", "")):
                    if not me:
                        continue
                    try:
                        env = decrypt_envelope(env, me, registry or {})
                        break
                    except Exception:
                        continue
            if env.get("thread") != name:
                continue
            if env.get("kind") not in ("prompt", "answer"):
                continue
            key = (env.get("kind"), env.get("id"))
            if key in seen:
                continue
            seen.add(key)
            items.append(env)
    items.sort(key=lambda e: e.get("created_at", ""))
    return items


def _migrate_thread(dirs, name):
    """Old layout kept a thread as bus/threads/<name>.json. The
    new layout is a directory; move the record in, write its rules
    as a page, and rebuild its history page once from the bus."""
    old = dirs["threads"] / f"{name}.json"
    new = _thread_dir(dirs, name)
    if not old.exists() or new.exists():
        return
    record = json.loads(old.read_text())
    new.mkdir(parents=True, exist_ok=True)
    (new / "thread.json").write_text(json.dumps(record, indent=2))
    (new / "rules.md").write_text(
        f"# Rules — {name}\n\n{record.get('rules') or '(none)'}\n")
    lines = [f"# History — {name}\n"]
    for env in _thread_history_scan(dirs, name):
        if env["kind"] == "prompt":
            lines.append(f"\n## Q {env['id']} from {env.get('from')} "
                         f"at {env.get('created_at')}\n")
            lines.append(env.get("prompt", {}).get("text", "") + "\n")
        else:
            lines.append(f"\n## A {env['id']} from {env.get('from')} "
                         f"at {env.get('created_at')}\n")
            lines.append(env.get("answer", {}).get("text", "") + "\n")
    (new / "history.md").write_text("".join(lines))
    old.unlink()


def _thread_record(dirs, name, sender, rules, registry=None):
    """Load the thread's record, creating it (and its wiki) on
    first use. The record holds the agent's rules for its project.

    Rules belong to the thread's creator: only the node that
    created the thread may change them. Any other node passing
    --rules gets a warning and the old rules stand — otherwise
    any node could rewrite another agent's instructions, and the
    assistant would follow the attacker's rules on the next
    answer. (Asking in someone else's thread is still allowed;
    only the rules are owned.)"""
    _migrate_thread(dirs, name)
    tdir = _thread_dir(dirs, name)
    tdir.mkdir(parents=True, exist_ok=True)
    path = tdir / "thread.json"
    if path.exists():
        record = json.loads(path.read_text())
        if rules and rules != record.get("rules", ""):
            if record.get("created_by") != sender:
                print(f"WARNING: thread {name} belongs to "
                      f"{record.get('created_by')} — only its creator "
                      f"may change its rules; keeping the old rules",
                      file=sys.stderr)
            else:
                record["rules"] = rules
                record["updated_at"] = utcnow()
    else:
        record = {"thread": name, "created_at": utcnow(),
                  "created_by": sender, "rules": rules or "",
                  "updated_at": utcnow()}
    path.write_text(json.dumps(record, indent=2))
    (tdir / "rules.md").write_text(
        f"# Rules — {name}\n\n{record.get('rules') or '(none)'}\n")
    if registry is not None:
        _update_wiki_manifest(dirs, name, sender, registry)
    return record


def _append_history(dirs, name, kind, env_id, sender, at, text):
    """Append one turn to the thread's history page — the wiki's
    index, verbatim and in order."""
    tdir = _thread_dir(dirs, name)
    tdir.mkdir(parents=True, exist_ok=True)
    page = tdir / "history.md"
    if not page.exists():
        page.write_text(f"# History — {name}\n")
    with page.open("a") as f:
        f.write(f"\n## {'Q' if kind == 'prompt' else 'A'} {env_id} "
                f"from {sender} at {at}\n\n{text}\n")


# ---------------------------------------------------------------- thread wiki signing
#
# The wiki files live on the bus, and any node with bus write
# access could rewrite them — facts.md and history.md were plain
# files, served verbatim by `thread` / `context`, so a forged
# fact became the assistant's "memory" for that thread. Two
# checks now cover them, and both degrade to UNVERIFIED, never
# to silently trusted:
#
# - facts.md, rules.md and thread.json are covered by a signed
#   manifest (manifest.json): one entry per file with its
#   SHA-256 and a signature by the node that wrote it. Only the
#   thread's creator or an owner/master may sign — the nodes
#   that legitimately write a wiki (the asker that created the
#   thread, the assistant that answers it). A file whose hash
#   does not match its manifest entry, or whose signature does
#   not verify, is TAMPERED.
# - history.md is verified section by section against the signed
#   prompt/answer envelopes in the bus: a section counts only
#   if an envelope with that id, sender and text exists. A
#   forged turn has no such envelope and is flagged UNVERIFIED.
# `bridge.py sign-thread` (re)signs the manifest for the wiki
# as it stands now — the adoption/repair command for threads
# written before signing, or after an authorized manual edit.

_WIKI_MANIFEST_FILES = ("thread.json", "rules.md", "facts.md")


def _wiki_manifest_path(dirs, name):
    return _thread_dir(dirs, name) / "manifest.json"


def _wiki_manifest_payload(thread, file, sha256, updated_at):
    return canonical({"thread": thread, "file": file,
                      "sha256": sha256, "updated_at": updated_at})


def _wiki_signer_authorized(registry, creator, signer):
    """Who may sign a thread's manifest: the thread's creator,
    or an owner/master (the assistant). Anyone else writing the
    wiki is not a legitimate wiki writer — their entry is
    refused, and the changed file then fails verification."""
    if registry is None:
        return False
    if creator and creator == signer:
        return True
    return registry.get("nodes", {}).get(signer, {}).get("role") in (
        "owner", "master")


def _load_wiki_manifest(dirs, name):
    path = _wiki_manifest_path(dirs, name)
    if not path.exists():
        return {"thread": name, "files": {}}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {"thread": name, "files": {}}


def _update_wiki_manifest(dirs, name, signer, registry):
    """Re-sign the manifest entries for wiki files whose content
    changed, with the writing node's key. Entries whose file did
    not change are kept as-is. An unauthorized signer, or a
    signer whose key is not on this machine, signs nothing —
    the file then verifies as tampered/unverified instead of
    gaining a false signature."""
    tdir = _thread_dir(dirs, name)
    if not (tdir / "thread.json").exists():
        return
    try:
        creator = json.loads((tdir / "thread.json").read_text()).get(
            "created_by", "")
    except Exception:
        creator = ""
    manifest = _load_wiki_manifest(dirs, name)
    manifest["thread"] = name
    files = manifest.setdefault("files", {})
    changed = False
    for fname in _WIKI_MANIFEST_FILES:
        path = tdir / fname
        if not path.exists():
            if fname in files:
                del files[fname]
                changed = True
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        old = files.get(fname)
        if old and old.get("sha256") == digest:
            continue
        if not _wiki_signer_authorized(registry, creator, signer):
            print(f"WARNING: {signer} may not sign the wiki for "
                  f"thread {name} — {fname} is left unsigned and "
                  f"will show as unverified/tampered",
                  file=sys.stderr)
            continue
        updated_at = utcnow()
        payload = _wiki_manifest_payload(name, fname, digest, updated_at)
        try:
            sig = _sign_bytes(payload.encode(), signer)
        except SystemExit as e:
            print(f"WARNING: cannot sign the wiki for thread {name} "
                  f"({e}) — {fname} is left unsigned", file=sys.stderr)
            continue
        files[fname] = {"sha256": digest, "signed_by": signer,
                        "signature": base64.b64encode(sig).decode(),
                        "updated_at": updated_at}
        changed = True
    if changed:
        tmp = _wiki_manifest_path(dirs, name).with_suffix(".tmp")
        tmp.write_text(json.dumps(manifest, indent=2))
        os.replace(tmp, _wiki_manifest_path(dirs, name))


def _verify_wiki_manifest(dirs, name, registry):
    """Per-file manifest status for a thread's wiki: "verified"
    (hash matches, signature valid, signer authorized),
    "unverified" (no manifest entry — written before signing,
    or by an unsigned write), or "tampered" (hash mismatch, bad
    signature, or unauthorized signer)."""
    tdir = _thread_dir(dirs, name)
    manifest = _load_wiki_manifest(dirs, name)
    record = {}
    try:
        record = json.loads((tdir / "thread.json").read_text())
    except Exception:
        pass
    creator = record.get("created_by", "")
    out = {}
    for fname in _WIKI_MANIFEST_FILES:
        path = tdir / fname
        if not path.exists():
            continue
        entry = manifest.get("files", {}).get(fname)
        if not entry:
            out[fname] = ("unverified",
                          "no manifest entry — written before signing")
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if entry.get("sha256") != digest:
            out[fname] = ("tampered",
                          "content does not match the signed manifest")
            continue
        signer = entry.get("signed_by", "")
        signer_entry = (registry or {}).get("nodes", {}).get(signer)
        if signer_entry is None:
            out[fname] = ("tampered", f"signer {signer} is not trusted")
            continue
        if signer != creator and signer_entry.get("role") not in (
                "owner", "master"):
            out[fname] = ("tampered",
                          f"signer {signer} may not sign this wiki")
            continue
        payload = _wiki_manifest_payload(
            name, fname, entry["sha256"], entry.get("updated_at", ""))
        try:
            sig = base64.b64decode(entry.get("signature", ""))
        except Exception:
            out[fname] = ("tampered", "bad signature encoding")
            continue
        if not _verify_bytes(payload.encode(), sig,
                             signer_entry["public_key"]):
            out[fname] = ("tampered", "signature does not verify")
            continue
        out[fname] = ("verified", f"signed by {signer}")
    return out


def _verify_history_sections(dirs, name):
    """Per-section history verification: a history section counts
    only if a signed prompt/answer envelope in the bus has that
    id, sender and text. Returns {(kind, id): True/False} — keyed
    by kind as well as id, because a prompt and its answer share
    an id and must verify independently (a forged answer must
    not taint the genuine question, or vice versa)."""
    genuine = {}
    for env in _thread_history_scan(dirs, name):
        kind = "Q" if env["kind"] == "prompt" else "A"
        text = (env.get("prompt", {}).get("text", "")
                if env["kind"] == "prompt"
                else env.get("answer", {}).get("text", ""))
        genuine[(kind, env["id"])] = (env.get("from", ""), text.strip())
    history = _thread_dir(dirs, name) / "history.md"
    if not history.exists():
        return {}
    out = {}
    for section in _parse_history(history.read_text()):
        key = (section["kind"], section["id"])
        want = genuine.get(key)
        out[key] = bool(
            want and want[0] == section.get("from", "")
            and want[1] == section.get("text", "").strip())
    return out


def _print_wiki_status(wiki_status, fname):
    """One status line for a wiki file, printed with the content
    itself (stdout — the reader of `thread` / `context` must see
    it, including the hook worker that answers from context)."""
    status, detail = wiki_status.get(
        fname, ("unverified", "no manifest entry — written before signing"))
    if status == "verified":
        print(f"(wiki manifest: {fname} verified — {detail})")
    elif status == "tampered":
        print(f"WARNING: wiki manifest: {fname} TAMPERED — {detail}. "
              f"Do not trust this content as the thread's memory.")
    else:
        print(f"(wiki manifest: {fname} unverified — {detail})")


def _move_to_read(dirs, path, reader):
    """Archive a read envelope under read/<reader>/. Reading moves
    it out of the live dir, so it is shown once and then kept for
    audit instead of being re-read. A prompt and its answer share
    an id: if both land in the same reader's folder (the asker and
    the assistant are the same node), the second one is kept as
    <id>.<kind>.json instead of overwriting the first."""
    dest_dir = dirs["read"] / reader
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / path.name
    if dest.exists():
        try:
            kind = json.loads(path.read_text()).get("kind", "")
        except Exception:
            kind = ""
        if kind:
            dest = dest_dir / f"{path.stem}.{kind}.json"
    os.replace(path, dest)


def _move_to_dead(dirs, path):
    """File a refused envelope in dead/ for audit — a result or
    answer that failed verification is a forgery (or a
    misaddressed response), and it must not sit in results/ or
    answers/ forever being counted by status and re-read by the
    next wait(). A prompt and its answer share an id, so a
    collision keeps the second as <id>.<kind>.json, as
    _move_to_read does."""
    dest_dir = dirs["dead"]
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / path.name
    if dest.exists():
        try:
            kind = json.loads(path.read_text()).get("kind", "")
        except Exception:
            kind = ""
        if kind:
            dest = dest_dir / f"{path.stem}.{kind}.json"
    os.replace(path, dest)
    return dest


def cmd_send(args):
    _check_node_name(args.sender)
    _check_to(args.to)
    registry = load_registry(args)
    dirs = bus_dirs(args.bus)
    task_id = f"task-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
    envelope = {
        "v": VERSION,
        "id": task_id,
        "from": args.sender,
        "to": args.to,
        "kind": "task",
        "created_at": utcnow(),
        "task": {
            "kind": "prompt",
            "prompt": args.prompt,
            "cwd": args.cwd,
            "model": args.model,
            "timeout_s": args.timeout_s,
            "max_cost_usd": args.max_cost_usd,
            "budget": args.budget,
            "max_calls": args.max_calls,
        },
    }
    write_envelope(dirs["tasks"] / f"{task_id}.json", envelope, args.sender, registry)
    print(task_id)
    return 0


def cmd_wait(args):
    if not _is_safe_name(args.id):
        print(f"bad result id: {args.id!r}", file=sys.stderr)
        return 1
    registry = load_registry(args)
    dirs = bus_dirs(args.bus)
    deadline = time.time() + args.timeout_s
    while time.time() < deadline:
        path = dirs["results"] / f"{args.id}.json"
        if path.exists():
            envelope = read_envelope(path)
            ok, reason = verify_basic(envelope, registry)
            if not ok:
                print(f"result failed verification ({reason}), refusing to show it", file=sys.stderr)
                _move_to_dead(dirs, path)
                return 1
            # Decrypt before anything reads the payload: the
            # signature above was checked on the raw envelope
            # (header + ciphertext); the binding check below
            # needs the decrypted payload to recognise a relay
            # rejection, and the user must see plaintext, never
            # ciphertext. An undecryptable result is a mismatch:
            # report it (id + timestamp + keys) and file it in
            # dead/, instead of showing ciphertext or timing out.
            try:
                plain = decrypt_envelope(envelope,
                                         envelope.get("to", ""), registry)
            except DecryptError as e:
                reason = mismatch_reason(envelope, e)
                log_mismatch(args.bus, envelope, e)
                print(f"result {args.id} key mismatch: {reason}",
                      file=sys.stderr)
                _move_to_dead(dirs, path)
                return 1
            # A valid signature is not enough: the result must be
            # from the node the task was addressed to, addressed
            # back to the task's sender, and sent by a node whose
            # role allows results — otherwise any trusted node
            # could fabricate another node's work. The one
            # exception is a rejection from the trusted relay
            # (see _check_response_binding): the relay reports
            # that it dropped the task, and only the relay key
            # can sign that.
            ok, reason = verify_result_binding(envelope, registry, args.bus,
                                               plain)
            if not ok:
                print(f"result failed verification ({reason}), refusing to show it", file=sys.stderr)
                _move_to_dead(dirs, path)
                return 1
            # Read means read: move it to read/<reader>/ so a
            # result is shown once and then archived.
            shown = dict(plain)
            shown["from_role"] = role_of(envelope.get("from", ""), registry)
            print(json.dumps(shown, indent=2))
            _move_to_read(dirs, path, envelope.get("to", ""))
            if (plain.get("result") or {}).get("status") == "rejected":
                print(f"result rejected: "
                      f"{(plain.get('result') or {}).get('stderr', '')}",
                      file=sys.stderr)
                return 1
            return 0
        time.sleep(5)
    print(f"timed out waiting for result {args.id}", file=sys.stderr)
    return 1


def cmd_message(args):
    """Send a one-way message to another node (the reverse channel:
    worker -> assistant, or assistant -> worker, outside of a task/result pair)."""
    _check_node_name(args.sender)
    _check_to(args.to)
    registry = load_registry(args)
    dirs = bus_dirs(args.bus)
    msg_id = f"msg-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
    envelope = {
        "v": VERSION,
        "id": msg_id,
        "from": args.sender,
        "to": args.to,
        "kind": "message",
        "created_at": utcnow(),
        "message": {
            "text": args.text,
            "needs_reply": args.needs_reply,
            "in_reply_to": args.in_reply_to or "",
        },
    }
    dest = dirs["messages"] / args.to
    dest.mkdir(parents=True, exist_ok=True)
    write_envelope(dest / f"{msg_id}.json", envelope, args.sender, registry)
    print(msg_id)
    return 0


def cmd_inbox(args):
    """List unread messages for a node. Shown messages move to
    read/<node>/ unless --keep is given."""
    _check_node_name(args.node)
    registry = load_registry(args)
    dirs = bus_dirs(args.bus)
    inbox = dirs["messages"] / args.node
    inbox.mkdir(parents=True, exist_ok=True)
    found = 0
    for path in sorted(inbox.glob("*.json")):
        try:
            envelope = read_envelope(path)
        except Exception as e:
            print(f"unreadable {path.name}: {e}", file=sys.stderr)
            continue
        ok, reason = check_envelope(envelope, registry, args.node, args.bus,
                                    claim=True)
        if not ok:
            print(f"WARNING: message {path.name} failed verification ({reason}), ignored", file=sys.stderr)
            continue
        try:
            envelope = decrypt_envelope(envelope, args.node, registry)
        except DecryptError as e:
            # A message is fire-and-forget with no waiter, so
            # there is nobody to reject to: log the mismatch
            # (id + timestamp + keys, visible in status) and file
            # it in dead/, like other message failures.
            reason = mismatch_reason(envelope, e)
            log_mismatch(args.bus, envelope, e)
            print(f"WARNING: message {path.name} key mismatch ({reason}), "
                  f"filed in dead/", file=sys.stderr)
            _move_to_dead(dirs, path)
            continue
        msg = envelope.get("message", {})
        print(f"--- {envelope['id']} from {envelope.get('from')} "
              f"({role_of(envelope.get('from', ''), registry)}) at {envelope.get('created_at')} "
              f"(needs_reply={msg.get('needs_reply')}, in_reply_to={msg.get('in_reply_to') or '-'})")
        print(msg.get("text", ""))
        found += 1
        if not args.keep:
            # Read means read: shown messages move to read/<node>/.
            # (--mark-read is kept for compatibility; moving is now
            # the default. --keep leaves them in place.)
            _move_to_read(dirs, path, args.node)
    if found == 0:
        print("(inbox empty)")
    return 0


def cmd_ask(args):
    """Prompt the assistant as if it were an LLM: write a prompt envelope
    addressed to a node (normally agenc-cloud). The assistant answers it and
    writes an answer envelope back; the asker polls for it with
    fetch-answer.

    Threads: --thread names the agent this prompt belongs to (one
    thread per project — three projects, three threads, three agents
    with their own rules and history, all served by the one
    assistant). Omit it and a new thread is started. --rules sets
    that thread's rules (its agent's instructions for its project);
    they are kept with the thread and shown to the assistant with
    every answer it writes in that thread.
    """
    _check_node_name(args.sender)
    _check_to(args.to)
    registry = load_registry(args)
    dirs = bus_dirs(args.bus)
    thread = _check_thread_name(
        args.thread or f"thread-{uuid.uuid4().hex[:8]}")
    _thread_record(dirs, thread, args.sender, args.rules, registry)
    prompt_id = f"prompt-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
    envelope = {
        "v": VERSION,
        "id": prompt_id,
        "from": args.sender,
        "to": args.to,
        "kind": "prompt",
        "thread": thread,
        "created_at": utcnow(),
        "prompt": {
            "text": args.prompt,
            "context": args.context or "",
        },
    }
    dest = dirs["prompts"] / args.to
    dest.mkdir(parents=True, exist_ok=True)
    write_envelope(dest / f"{prompt_id}.json", envelope, args.sender, registry)
    _append_history(dirs, thread, "prompt", prompt_id, args.sender,
                    envelope["created_at"], args.prompt)
    print(prompt_id)
    print(f"thread {thread}", file=sys.stderr)
    return 0


_STOPWORDS = {
    "the", "a", "an", "and", "or", "but", "of", "to", "in", "on", "for",
    "with", "that", "this", "these", "those", "it", "its", "is", "are",
    "was", "were", "be", "been", "what", "which", "who", "whom", "when",
    "where", "why", "how", "do", "does", "did", "can", "could", "should",
    "would", "will", "shall", "you", "your", "yours", "my", "me", "we",
    "our", "they", "their", "them", "he", "she", "his", "her", "i", "am",
    "an", "as", "at", "by", "from", "not", "no", "yes", "if", "then",
    "than", "so", "such", "into", "about", "over", "under", "again",
    "please", "just", "also", "there", "here", "have", "has", "had",
}


def _keywords(text):
    """The meaningful words in a question: lowercased, at least 3
    letters, stopwords dropped. Used to find the older turns that
    match what is being asked now."""
    words = re.findall(r"[a-z0-9]+", (text or "").lower())
    return {w for w in words if len(w) >= 3 and w not in _STOPWORDS}


def _parse_history(text):
    """Split a thread's history page into sections, in order:
    {"kind": "Q"/"A", "id", "from", "at", "text"}."""
    sections = []
    current = None
    for line in (text or "").splitlines():
        m = re.match(r"## ([QA]) (\S+) from (\S+) at (\S+)\s*$", line)
        if m:
            current = {"kind": m.group(1), "id": m.group(2),
                       "from": m.group(3), "at": m.group(4), "text": ""}
            sections.append(current)
        elif current is not None:
            current["text"] += line + "\n"
    for s in sections:
        s["text"] = s["text"].strip()
    return sections


def _group_turns(sections):
    """Group Q/A sections into turns (a question and its answer,
    by id), in chronological order. An unanswered question is a
    turn on its own."""
    turns = []
    by_id = {}
    for s in sections:
        if s["id"] not in by_id:
            by_id[s["id"]] = {"id": s["id"], "q": None, "a": None}
            turns.append(by_id[s["id"]])
        if s["kind"] == "Q":
            by_id[s["id"]]["q"] = s
        else:
            by_id[s["id"]]["a"] = s
    return turns


def _turn_text(turn):
    parts = []
    if turn.get("q"):
        parts.append(turn["q"]["text"])
    if turn.get("a"):
        parts.append(turn["a"]["text"])
    return "\n".join(parts)


def _print_turn(turn, verified=None):
    """Print one turn. `verified` maps (kind, id) -> True/False
    (from _verify_history_sections); a False section is flagged
    inline — the text is shown (the operator needs to see what
    was forged) but marked untrusted, so it is never quoted as
    the thread's memory without the flag. verified=None means
    the sections come straight from signed envelopes, so no flag
    applies."""
    if turn.get("q"):
        q = turn["q"]
        flag = ""
        if verified is not None and not verified.get(("Q", q["id"]), False):
            flag = " [UNVERIFIED — no matching signed envelope]"
        print(f"## Q {q['id']} from {q['from']} at {q['at']}{flag}\n\n{q['text']}")
    if turn.get("a"):
        a = turn["a"]
        flag = ""
        if verified is not None and not verified.get(("A", a["id"]), False):
            flag = " [UNVERIFIED — no matching signed envelope]"
        print(f"\n## A {a['id']} from {a['from']} at {a['at']}{flag}\n\n{a['text']}")


def cmd_context(args):
    """Return only the context that matters for a question: the
    thread's rules, its distilled facts, the recent turns, and any
    older turns whose words match the question. The assistant reads
    this instead of the whole history, so a long thread stays
    cheap to answer in."""
    _check_thread_name(args.thread)
    dirs = bus_dirs(args.bus)
    _migrate_thread(dirs, args.thread)
    tdir = _thread_dir(dirs, args.thread)
    path = tdir / "thread.json"
    if not path.exists():
        print(f"no such thread: {args.thread}", file=sys.stderr)
        return 1
    record = json.loads(path.read_text())
    print(f"thread {record['thread']} — context for: "
          f"{args.query or '(no question — recent turns only)'}")
    print(f"rules: {record.get('rules') or '(none)'}")
    registry = load_registry(args)
    wiki_status = _verify_wiki_manifest(dirs, args.thread, registry)
    facts = tdir / "facts.md"
    if facts.exists() and facts.read_text().strip():
        print("--- facts")
        _print_wiki_status(wiki_status, "facts.md")
        print(facts.read_text().rstrip())
    history = tdir / "history.md"
    from_file = history.exists()
    if from_file:
        sections = _parse_history(history.read_text())
        verified = _verify_history_sections(dirs, args.thread)
    else:
        verified = None
        sections = []
        for env in _thread_history_scan(dirs, args.thread):
            if env["kind"] == "prompt":
                sections.append({"kind": "Q", "id": env["id"],
                                 "from": env.get("from", ""),
                                 "at": env.get("created_at", ""),
                                 "text": env.get("prompt", {}).get("text", "")})
            else:
                sections.append({"kind": "A", "id": env["id"],
                                 "from": env.get("from", ""),
                                 "at": env.get("created_at", ""),
                                 "text": env.get("answer", {}).get("text", "")})
    turns = _group_turns(sections)
    recent = turns[-args.recent:] if args.recent > 0 else []
    recent_ids = {t["id"] for t in recent}
    if recent:
        print(f"--- recent (last {len(recent)} turn(s))")
        for t in recent:
            _print_turn(t, verified)
    keys = _keywords(args.query)
    if keys:
        scored = []
        for t in turns:
            if t["id"] in recent_ids:
                continue
            hits = keys & _keywords(_turn_text(t))
            if hits:
                scored.append((len(hits), t))
        scored.sort(key=lambda s: (-s[0], s[1]["id"]))
        if scored:
            print(f"--- matching \"{args.query}\" "
                  f"({len(scored)} older turn(s))")
            for _, t in scored:
                _print_turn(t, verified)
    return 0


def cmd_thread(args):
    """Show a thread's wiki: the agent's rules for its project,
    its distilled facts, then its history — the index, every
    question and answer verbatim and in order. Threads never mix:
    this shows only this thread's wiki."""
    _check_thread_name(args.id)
    dirs = bus_dirs(args.bus)
    _migrate_thread(dirs, args.id)
    tdir = _thread_dir(dirs, args.id)
    path = tdir / "thread.json"
    if not path.exists():
        print(f"no such thread: {args.id}", file=sys.stderr)
        return 1
    record = json.loads(path.read_text())
    print(f"thread {record['thread']} (created by {record.get('created_by', '?')} "
          f"at {record.get('created_at', '?')})")
    print(f"rules: {record.get('rules') or '(none)'}")
    registry = load_registry(args)
    wiki_status = _verify_wiki_manifest(dirs, args.id, registry)
    _print_wiki_status(wiki_status, "rules.md")
    facts = tdir / "facts.md"
    if facts.exists() and facts.read_text().strip():
        print("--- facts")
        _print_wiki_status(wiki_status, "facts.md")
        print(facts.read_text().rstrip())
    history = tdir / "history.md"
    if history.exists() and history.read_text().strip():
        print("--- history")
        verified = _verify_history_sections(dirs, args.id)
        for section in _parse_history(history.read_text()):
            flag = ""
            if not verified.get((section["kind"], section["id"]), False):
                flag = " [UNVERIFIED — no matching signed envelope]"
            print(f"\n## {section['kind']} {section['id']} from "
                  f"{section['from']} at {section['at']}{flag}\n")
            print(section["text"])
        return 0
    # No history page yet (a thread from before the wiki): fall
    # back to the bus scan, once.
    items = _thread_history_scan(dirs, args.id)
    if not items:
        print("(no questions yet)")
        return 0
    for env in items:
        if env["kind"] == "prompt":
            print(f"--- Q {env['id']} from {env.get('from')} "
                  f"at {env.get('created_at')}")
            print(env.get("prompt", {}).get("text", ""))
        else:
            print(f"--- A {env['id']} from {env.get('from')} "
                  f"at {env.get('created_at')}")
            print(env.get("answer", {}).get("text", ""))
    return 0


def cmd_note(args):
    """Record a fact worth keeping in a thread's wiki — a decision,
    a deadline, a value a later follow-up will need. The worker
    uses this when an answer establishes one. The fact is then
    covered by the thread's signed manifest (see
    _update_wiki_manifest), so a later edit of facts.md shows up
    as tampered instead of becoming the assistant's memory."""
    _check_thread_name(args.thread)
    _check_node_name(args.sender)
    registry = load_registry(args)
    dirs = bus_dirs(args.bus)
    _migrate_thread(dirs, args.thread)
    tdir = _thread_dir(dirs, args.thread)
    if not (tdir / "thread.json").exists():
        print(f"no such thread: {args.thread}", file=sys.stderr)
        return 1
    page = tdir / "facts.md"
    if not page.exists():
        page.write_text(f"# Facts — {args.thread}\n")
    with page.open("a") as f:
        f.write(f"\n- {utcnow()}: {args.text}\n")
    _update_wiki_manifest(dirs, args.thread, args.sender, registry)
    return 0


def cmd_sign_thread(args):
    """(Re)sign a thread's wiki manifest for the files as they
    stand now — the adoption command for threads written before
    signing, and the repair command after an authorized manual
    edit. Only the thread's creator or an owner/master may sign;
    anyone else is refused, and the wiki stays unverified."""
    _check_thread_name(args.thread)
    _check_node_name(args.sender)
    registry = load_registry(args)
    dirs = bus_dirs(args.bus)
    _migrate_thread(dirs, args.thread)
    tdir = _thread_dir(dirs, args.thread)
    if not (tdir / "thread.json").exists():
        print(f"no such thread: {args.thread}", file=sys.stderr)
        return 1
    try:
        creator = json.loads((tdir / "thread.json").read_text()).get(
            "created_by", "")
    except Exception:
        creator = ""
    if not _wiki_signer_authorized(registry, creator, args.sender):
        print(f"{args.sender} may not sign the wiki for thread "
              f"{args.thread} — only its creator ({creator or '?'}) "
              f"or an owner/master may", file=sys.stderr)
        return 1
    manifest = _load_wiki_manifest(dirs, args.thread)
    manifest["thread"] = args.thread
    files = manifest.setdefault("files", {})
    signed = []
    for fname in _WIKI_MANIFEST_FILES:
        path = tdir / fname
        if not path.exists():
            files.pop(fname, None)
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        updated_at = utcnow()
        payload = _wiki_manifest_payload(args.thread, fname, digest,
                                         updated_at)
        try:
            sig = _sign_bytes(payload.encode(), args.sender)
        except SystemExit as e:
            print(f"cannot sign {fname}: {e}", file=sys.stderr)
            return 1
        files[fname] = {"sha256": digest, "signed_by": args.sender,
                        "signature": base64.b64encode(sig).decode(),
                        "updated_at": updated_at}
        signed.append(fname)
    tmp = _wiki_manifest_path(dirs, args.thread).with_suffix(".tmp")
    tmp.write_text(json.dumps(manifest, indent=2))
    os.replace(tmp, _wiki_manifest_path(dirs, args.thread))
    print(f"signed thread {args.thread}: {', '.join(signed)} "
          f"(signed by {args.sender})")
    return 0


def cmd_prompts(args):
    """List unanswered prompts for a node."""
    _check_node_name(args.node)
    registry = load_registry(args)
    dirs = bus_dirs(args.bus)
    inbox = dirs["prompts"] / args.node
    inbox.mkdir(parents=True, exist_ok=True)
    found = 0
    for path in sorted(inbox.glob("*.json")):
        try:
            envelope = read_envelope(path)
        except Exception as e:
            print(f"unreadable {path.name}: {e}", file=sys.stderr)
            continue
        ok, reason = check_envelope(envelope, registry, args.node, args.bus)
        if not ok:
            print(f"WARNING: prompt {path.name} failed verification ({reason}), ignored", file=sys.stderr)
            continue
        try:
            envelope = decrypt_envelope(envelope, args.node, registry)
        except DecryptError as e:
            # Leave it in place: `reply` is the path that rejects
            # it with the mismatch report, and reply finds the
            # prompt here. Just warn and log it.
            reason = mismatch_reason(envelope, e)
            log_mismatch(args.bus, envelope, e)
            print(f"WARNING: prompt {path.name} key mismatch ({reason}), "
                  f"not answered — reply to reject it", file=sys.stderr)
            continue
        pr = envelope.get("prompt", {})
        thread = envelope.get("thread", "")
        print(f"--- {envelope['id']} from {envelope.get('from')} "
              f"({role_of(envelope.get('from', ''), registry)})"
              f"{f' [thread {thread}]' if thread else ''} at {envelope.get('created_at')}")
        if pr.get("context"):
            print(f"Context: {pr['context']}")
        print(pr.get("text", ""))
        found += 1
    if found == 0:
        print("(no unanswered prompts)")
    return 0


def cmd_reply(args):
    """Answer a prompt: write a signed answer envelope and move the
    prompt to read/. The asker reads it with fetch-answer."""
    _check_node_name(args.from_node)
    if not _is_safe_name(args.id):
        print(f"bad prompt id: {args.id!r}", file=sys.stderr)
        return 1
    registry = load_registry(args)
    dirs = bus_dirs(args.bus)
    prompt_path = None
    for node_dir in dirs["prompts"].iterdir():
        candidate = node_dir / f"{args.id}.json"
        if candidate.exists():
            prompt_path = candidate
            break
    if prompt_path is None:
        print(f"no such prompt: {args.id}", file=sys.stderr)
        return 1
    try:
        envelope = read_envelope(prompt_path)
    except Exception as e:
        print(f"prompt {args.id} unreadable ({e}), refusing to answer", file=sys.stderr)
        return 1
    ok, reason = check_envelope(envelope, registry, args.from_node, args.bus,
                                claim=True)
    if ok:
        # Signature, role, and replay all passed — now decrypt.
        # A decryption failure is NOT silent: the sender is
        # authenticated, so it gets the mismatch report back as a
        # rejected answer — message id, timestamp, both key ids —
        # instead of a timeout. The check above claimed the id:
        # this reply path is the consumer, and a re-sent copy
        # carries a new id, so claiming here does not block it.
        try:
            envelope = decrypt_envelope(envelope, args.from_node, registry)
        except DecryptError as e:
            reason = mismatch_reason(envelope, e)
            log_mismatch(args.bus, envelope, e)
            ok = False
    if not ok:
        # An authenticated sender gets the reason back as a
        # rejected answer, so fetch-answer returns promptly
        # instead of timing out. If the signature itself failed
        # (bad signature, unknown sender, unsafe name, wrong
        # version), the claimed `from` cannot be trusted — a
        # forged from=victim would let an attacker spam the
        # victim with rejections — so nothing is sent back. A
        # prompt addressed to another node, or one already
        # answered, is not this node's to answer at all.
        basic_ok, _ = verify_basic(envelope, registry)
        seen, _ = seen_ids(args.bus)
        if (basic_ok
                and envelope.get("to") == args.from_node
                and envelope.get("id") not in seen
                and not _response_already_delivered(
                    dirs, "prompt", envelope["id"],
                    envelope.get("from", ""), envelope.get("to", ""))):
            claim = Path(args.bus) / "seen" / f"reply-{args.id}"
            try:
                fd = os.open(claim, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.close(fd)
            except FileExistsError:
                print(f"prompt {args.id} already answered", file=sys.stderr)
                return 1
            answer = {
                "v": VERSION,
                "id": envelope["id"],
                "from": args.from_node,
                "to": envelope.get("from", ""),
                "kind": "answer",
                "thread": envelope.get("thread", ""),
                "created_at": utcnow(),
                "answer": {"text": f"rejected: {reason}",
                           "rejected": True, "reason": reason,
                           "in_reply_to": envelope["id"]},
            }
            write_envelope(dirs["answers"] / f"{envelope['id']}.json",
                           answer, args.from_node, registry)
            # The prompt itself was rejected, not answered: it
            # goes to dead/, where `bridge.py dead` shows the
            # reason. (A rejected answer is not appended to the
            # thread's history — it is not an answer to the
            # question, and later context must not quote it as
            # one.)
            os.replace(prompt_path, dirs["dead"] / prompt_path.name)
            print(f"prompt {args.id} rejected: {reason}", file=sys.stderr)
            return 0
        print(f"prompt {args.id} failed verification ({reason}), refusing to answer", file=sys.stderr)
        return 1
    # Claim this reply atomically: two simultaneous replies for
    # the same prompt must not both go through. O_EXCL makes the
    # claim a single indivisible step — the loser sees the claim
    # file and is refused. (The seen guard catches the race in
    # practice, but check-then-mark is not atomic; this is.)
    claim = Path(args.bus) / "seen" / f"reply-{args.id}"
    try:
        fd = os.open(claim, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.close(fd)
    except FileExistsError:
        print(f"prompt {args.id} already answered", file=sys.stderr)
        return 1
    mark_seen(args.bus, envelope["id"])
    answer = {
        "v": VERSION,
        "id": envelope["id"],
        "from": args.from_node,
        "to": envelope.get("from", ""),
        "kind": "answer",
        # The answer carries the thread, so the asker recognises
        # which of its agents answered.
        "thread": envelope.get("thread", ""),
        "created_at": utcnow(),
        "answer": {"text": args.text, "in_reply_to": envelope["id"]},
    }
    write_envelope(dirs["answers"] / f"{envelope['id']}.json", answer, args.from_node, registry)
    if envelope.get("thread"):
        _append_history(dirs, envelope["thread"], "answer",
                        envelope["id"], args.from_node,
                        answer["created_at"], args.text)
    _move_to_read(dirs, prompt_path, envelope.get("to", ""))
    print(envelope["id"])
    return 0


def cmd_fetch_answer(args):
    """Poll for an answer to a prompt id (the asker's side)."""
    if not _is_safe_name(args.id):
        print(f"bad answer id: {args.id!r}", file=sys.stderr)
        return 1
    registry = load_registry(args)
    dirs = bus_dirs(args.bus)
    deadline = time.time() + args.timeout_s
    while time.time() < deadline:
        path = dirs["answers"] / f"{args.id}.json"
        if path.exists():
            envelope = read_envelope(path)
            ok, reason = verify_basic(envelope, registry)
            if not ok:
                print(f"answer failed verification ({reason}), refusing to show it", file=sys.stderr)
                _move_to_dead(dirs, path)
                return 1
            # Decrypt before anything reads the payload: the
            # signature above was checked on the raw envelope
            # (header + ciphertext); the binding check below
            # needs the decrypted payload to recognise a relay
            # rejection, and the user must see plaintext, never
            # ciphertext. An undecryptable answer is a mismatch:
            # report it (id + timestamp + keys) and file it in
            # dead/, instead of showing ciphertext or timing out.
            try:
                plain = decrypt_envelope(envelope,
                                         envelope.get("to", ""), registry)
            except DecryptError as e:
                reason = mismatch_reason(envelope, e)
                log_mismatch(args.bus, envelope, e)
                print(f"answer {args.id} key mismatch: {reason}",
                      file=sys.stderr)
                _move_to_dead(dirs, path)
                return 1
            # A valid signature is not enough: the answer must be
            # from the node the prompt was addressed to, addressed
            # back to the asker, and sent by a node whose role
            # allows answers — otherwise any trusted node could
            # fabricate the assistant's answers. The one
            # exception is a rejection from the trusted relay
            # (see _check_response_binding).
            ok, reason = verify_answer_binding(envelope, registry, args.bus,
                                               plain)
            if not ok:
                print(f"answer failed verification ({reason}), refusing to show it", file=sys.stderr)
                _move_to_dead(dirs, path)
                return 1
            shown = dict(plain)
            shown["from_role"] = role_of(envelope.get("from", ""), registry)
            print(json.dumps(shown, indent=2))
            _move_to_read(dirs, path, envelope.get("to", ""))
            if (plain.get("answer") or {}).get("rejected"):
                print(f"answer rejected: "
                      f"{(plain.get('answer') or {}).get('reason', '')}",
                      file=sys.stderr)
                return 1
            return 0
        time.sleep(5)
    print(f"timed out waiting for answer {args.id}", file=sys.stderr)
    return 1


def resolve_cwd(project_root, cwd):
    root = Path(project_root).resolve()
    target = (root / cwd).resolve()
    if target != root and root not in target.parents:
        raise ValueError(f"cwd escapes project root: {cwd}")
    return target


# Worker agent profiles: name -> headless command (the task prompt is
# appended as the final argument). `agenc` is the default. `grok-bot`
# has no CLI command — it is a hosted agent that connects over MCP
# instead (see WORKERS.md), so it is not a --agent choice here.
# `grok-code` is deliberately absent too: v2.0.0 has no headless
# one-shot mode (no -p flag in --help, first launch drops into an
# interactive companion chooser), so it cannot be a poll worker.
# --agent-cmd overrides any profile (tests, custom agents).
AGENT_PROFILES = {
    "agenc": None,  # [agenc, "-p", "--no-tui", prompt]
    # Grok Build CLI (official xAI): --no-auto-update skips update
    # checks in automation; --always-approve keeps headless runs from
    # stalling on tool-approval prompts. Omit it for read-only audits.
    "grok-build": ["grok", "--no-auto-update", "--always-approve", "-p"],
    # OpenCode (open source): `run` is the headless one-shot mode,
    # the prompt is its final argument; --auto auto-approves
    # permissions so unattended runs do not stall on a prompt. The
    # model is this deployment's OpenRouter default, the same one
    # cloud AgenC uses; the node's provider key reaches it as
    # OPENROUTER_API_KEY (see run_agent).
    "opencode": ["opencode", "run", "--auto", "-m",
                 "openrouter/stealth/crouton-alpha"],
}


def resolve_agent_cmd(agent, agent_cmd):
    """Turn --agent / --agent-cmd into the command list run_agent uses."""
    if agent_cmd:
        return agent_cmd.split()
    if agent not in AGENT_PROFILES:
        raise ValueError(
            f"unknown agent profile: {agent} "
            f"(choose from: {', '.join(AGENT_PROFILES)})")
    profile = AGENT_PROFILES[agent]
    if profile is None:
        return None  # default AgenC command in run_agent
    cmd = list(profile)
    # Resolve the binary: PATH first, then the installer's home dir
    # (grok-code lives in ~/.grok-code/bin, which may not be on PATH).
    resolved = shutil.which(cmd[0])
    if resolved is None and cmd[0] == "grok-code":
        home_bin = Path.home() / ".grok-code" / "bin" / "grok-code"
        resolved = str(home_bin) if home_bin.exists() else None
    cmd[0] = resolved or cmd[0]
    return cmd


def _validate_task(task):
    """Check a task envelope's fields have the types the worker
    will use, before anything runs. A signed task with a wrong-
    typed field (a list where a string belongs, a dict where a
    number belongs) used to crash the worker mid-claim and wedge
    the task in claimed/ forever. Now it is rejected like any
    other bad task: a result with status "rejected" and the task
    moved to done/. Returns an error string, or None if valid."""
    if not isinstance(task, dict):
        return "task is not an object"
    prompt = task.get("prompt")
    if not isinstance(prompt, str):
        return f"task.prompt must be a string, got {type(prompt).__name__}"
    cwd = task.get("cwd", ".")
    if not isinstance(cwd, str):
        return f"task.cwd must be a string, got {type(cwd).__name__}"
    timeout_s = task.get("timeout_s", 600)
    if isinstance(timeout_s, bool) or not isinstance(timeout_s, (int, float)):
        return f"task.timeout_s must be a number, got {type(timeout_s).__name__}"
    if timeout_s <= 0:
        return f"task.timeout_s must be positive, got {timeout_s}"
    model = task.get("model")
    if model is not None and not isinstance(model, str):
        return f"task.model must be a string, got {type(model).__name__}"
    max_cost = task.get("max_cost_usd")
    if max_cost is not None and (
            isinstance(max_cost, bool) or not isinstance(max_cost, (int, float))):
        return f"task.max_cost_usd must be a number, got {type(max_cost).__name__}"
    budget = task.get("budget")
    if budget is not None and budget not in ("eco", "balanced", "max"):
        return f"task.budget must be eco, balanced, or max, got {budget!r}"
    max_calls = task.get("max_calls")
    if max_calls is not None and (
            isinstance(max_calls, bool) or not isinstance(max_calls, int)):
        return f"task.max_calls must be an integer, got {type(max_calls).__name__}"
    if isinstance(max_calls, int) and max_calls <= 0:
        return f"task.max_calls must be positive, got {max_calls}"
    return None


def run_agent(prompt, cwd, timeout_s, agent_cmd=None, budget=None,
              max_calls=None, provider_key=None):
    """Run the configured worker agent headless on one prompt.
    agent_cmd overrides the binary for tests. budget/max_calls are
    AgenC's own per-run bounds (token preset / call cap), passed
    only to the AgenC command — other agents' CLIs don't take them.
    provider_key, when given, is the node's own provider key; it
    reaches the agent as OPENROUTER_API_KEY, so the provider (not
    the bridge) enforces that key's credit limit."""
    if agent_cmd:
        cmd = agent_cmd + [prompt]
    else:
        agenc = shutil.which("agenc") or str(Path.home() / ".local" / "bin" / "agenc")
        cmd = [agenc, "-p", "--no-tui"]
        if budget:
            cmd += ["--budget", budget]
        if max_calls:
            cmd += ["--task-max-calls", str(max_calls)]
        cmd += [prompt]
    env = dict(os.environ)
    if provider_key:
        env["OPENROUTER_API_KEY"] = provider_key
    started = time.time()
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             stdin=subprocess.DEVNULL,
                             cwd=str(cwd), timeout=timeout_s, env=env)
    except subprocess.TimeoutExpired as e:
        return {"status": "timeout", "returncode": None,
                "stdout": (e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or ""),
                "stderr": "agent run timed out",
                "started_at": datetime.fromtimestamp(started, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "finished_at": utcnow(), "duration_s": round(time.time() - started, 1)}
    except OSError as e:
        # Missing binary etc. — report it as a failed task, don't crash the worker.
        return {"status": "error", "returncode": None, "stdout": "",
                "stderr": f"agent binary not found or not runnable: {cmd[0]} ({e})",
                "started_at": datetime.fromtimestamp(started, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "finished_at": utcnow(), "duration_s": round(time.time() - started, 1)}
    return {"status": "ok" if out.returncode == 0 else "error",
            "returncode": out.returncode, "stdout": out.stdout,
            "stderr": out.stderr[-4000:],
            "started_at": datetime.fromtimestamp(started, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "finished_at": utcnow(), "duration_s": round(time.time() - started, 1)}


def _response_already_delivered(dirs, kind, env_id, sender, to=""):
    """True if a genuine response to this task/prompt already
    exists somewhere it could have been delivered from — so a
    replay must not produce a second, contradictory rejection.
    Checks the live results/ or answers/ dir, read/<sender>/
    (wait / fetch-answer move a shown response there — under
    <id>.<kind>.json when a prompt and its answer share an id
    and a reader), and, for a task, done/ (a task whose envelope
    is in done/ was processed and its result written). The old
    check looked at results/ only, so a replayed task whose
    genuine result had already been read — and moved to read/ —
    got a fresh "rejected" result, and the operator's second
    wait() showed a failure for a task that had succeeded."""
    if kind == "task":
        if (dirs["results"] / f"{env_id}.json").exists():
            return True
        read_dir = dirs["read"] / sender
        if (read_dir / f"{env_id}.json").exists():
            return True
        if (read_dir / f"{env_id}.result.json").exists():
            return True
        if (dirs["done"] / f"{env_id}.json").exists():
            return True
        return False
    if kind == "prompt":
        if (dirs["answers"] / f"{env_id}.json").exists():
            return True
        read_dir = dirs["read"] / sender
        if (read_dir / f"{env_id}.json").exists():
            return True
        if (read_dir / f"{env_id}.answer.json").exists():
            return True
        # The prompt itself was moved to read/<to>/ when it was
        # answered — an answered prompt lives in read/, not live.
        if to and (dirs["read"] / to / f"{env_id}.json").exists():
            return True
        return False
    return False


def poll_once(bus, node, project_root, registry, agent_cmd=None,
              reg_path=None):
    dirs = bus_dirs(bus)
    # Hands-free registry distribution: apply any pending
    # registry update for this node before running tasks, so a
    # node that was offline at rotation time picks the new keys
    # up the moment it polls again. With no pending updates this
    # is a no-op (the directory does not exist).
    registry, _, _ = apply_pending_registry_updates(
        bus, node, registry, reg_path)
    for path in sorted(dirs["tasks"].glob("*.json")):
        try:
            envelope = read_envelope(path)
        except Exception as e:
            print(f"unreadable {path.name}: {e}", file=sys.stderr)
            os.replace(path, dirs["dead"] / path.name)
            continue
        if envelope.get("to") not in (node, "*"):
            continue
        claimed = dirs["claimed"] / path.name
        try:
            os.replace(path, claimed)
        except FileNotFoundError:
            continue  # another worker claimed it first
        ok, reason = check_envelope(envelope, registry, node, bus,
                                    claim=True)
        if ok:
            # Signature, role, and replay all passed — now decrypt.
            # A decryption failure is NOT silent: the sender is
            # authenticated (the signature passed), so it gets the
            # mismatch report back as a rejected result — message
            # id, timestamp, both key ids — instead of a timeout.
            # The check claimed the id atomically, so no second
            # consumer can take this envelope; a re-sent copy
            # carries a new id (re-encrypted under the current
            # key), so claiming here does not block it.
            try:
                envelope = decrypt_envelope(envelope, node, registry)
            except DecryptError as e:
                reason = mismatch_reason(envelope, e)
                log_mismatch(bus, envelope, e)
                ok = False
        if not ok:
            print(f"rejected {envelope.get('id')}: failed verification ({reason})", file=sys.stderr)
            # An authenticated sender gets the reason back as a
            # rejected result, so wait() returns promptly instead
            # of timing out. If the signature itself failed (bad
            # signature, unknown sender, unsafe name, wrong
            # version, unapproved role), the claimed `from`
            # cannot be trusted — a forged from=victim would let
            # an attacker spam the victim — so nothing is sent
            # back, just dead/ + the log line above. A genuine
            # result already delivered is never overwritten: a
            # replayed task must not clobber the real result, and
            # must not invent a "rejected" one after the genuine
            # result was already read (see
            # _response_already_delivered — results/ alone is
            # not enough, the result may already be in read/).
            basic_ok, _ = verify_basic(envelope, registry)
            if basic_ok and not _response_already_delivered(
                    dirs, "task", envelope["id"],
                    envelope.get("from", "")):
                result = {"status": "rejected", "returncode": None,
                          "stdout": "", "stderr": reason,
                          "started_at": utcnow(),
                          "finished_at": utcnow(), "duration_s": 0}
                result_env = {
                    "v": VERSION, "id": envelope["id"], "from": node,
                    "to": envelope.get("from", ""), "kind": "result",
                    "created_at": utcnow(), "result": result,
                }
                try:
                    write_envelope(dirs["results"] / path.name,
                                   result_env, node, registry)
                except SystemExit as e:
                    print(f"could not send rejection for "
                          f"{envelope.get('id')}: {e}", file=sys.stderr)
                os.replace(claimed, dirs["dead"] / path.name)
                return envelope["id"]
            os.replace(claimed, dirs["dead"] / path.name)
            continue
        mark_seen(bus, envelope["id"])
        task = envelope.get("task", {})
        if task.get("kind") != "prompt":
            result = {"status": "rejected", "returncode": None, "stdout": "",
                      "stderr": f"unsupported task kind: {task.get('kind')}",
                      "started_at": utcnow(), "finished_at": utcnow(), "duration_s": 0}
        else:
            bad = _validate_task(task)
            if bad is not None:
                result = {"status": "rejected", "returncode": None,
                          "stdout": "",
                          "stderr": f"malformed task: {bad}",
                          "started_at": utcnow(),
                          "finished_at": utcnow(), "duration_s": 0}
            else:
                try:
                    cwd = resolve_cwd(project_root, task.get("cwd", "."))
                except ValueError as e:
                    result = {"status": "rejected", "returncode": None, "stdout": "",
                              "stderr": str(e), "started_at": utcnow(),
                              "finished_at": utcnow(), "duration_s": 0}
                else:
                    # Caps are enforced by the key and by AgenC, not by
                    # the bridge: the node's own provider key (if one is
                    # stored) reaches the agent as OPENROUTER_API_KEY, and
                    # the task's budget/max_calls reach AgenC as its own
                    # flags. If the node's key is stored but cannot be
                    # decrypted, fail closed — never run the task on a
                    # shared key and bypass the cap.
                    try:
                        provider_key = load_provider_key(node)
                    except SystemExit as e:
                        result = {"status": "rejected", "returncode": None,
                                  "stdout": "",
                                  "stderr": f"provider key unreadable: {e}",
                                  "started_at": utcnow(),
                                  "finished_at": utcnow(), "duration_s": 0}
                    else:
                        result = run_agent(task["prompt"], cwd,
                                           int(task.get("timeout_s", 600)),
                                           agent_cmd,
                                           budget=task.get("budget"),
                                           max_calls=task.get("max_calls"),
                                           provider_key=provider_key)
        result_env = {
            "v": VERSION, "id": envelope["id"], "from": node,
            "to": envelope.get("from", ""), "kind": "result",
            "created_at": utcnow(), "result": result,
        }
        write_envelope(dirs["results"] / path.name, result_env, node, registry)
        os.replace(claimed, dirs["done"] / path.name)
        print(f"done {envelope['id']}: {result['status']} "
              f"(task from {envelope.get('from')} "
              f"[{role_of(envelope.get('from', ''), registry)}])")
        return envelope["id"]
    return None


def cmd_poll(args):
    _check_node_name(args.node)
    agent_cmd = resolve_agent_cmd(args.agent, args.agent_cmd)
    while True:
        # Re-read the registry every cycle: a registry update
        # adopted by poll_once (or by hand, or by another
        # process) takes effect on the next poll, not after a
        # restart.
        registry = load_registry(args)
        done = poll_once(args.bus, args.node, args.project_root, registry,
                         agent_cmd=agent_cmd,
                         reg_path=registry_path(args))
        if args.once or done is None:
            return 0
        if args.interval_s:
            time.sleep(args.interval_s)


# ---------------------------------------------------------------- status / dead
#
# The pulse: status proves the system is alive right now, not just
# that files exist. Two signals per relay — the heartbeat file the
# relay's watch loop rewrites every couple of seconds, and a live
# hello (a real signed hello, answered by a welcome) with its
# round-trip time. A dead relay shows up as both a stale heartbeat
# and a failed hello.

def _age_str(ts):
    secs = max(0.0, time.time() - ts)
    if secs < 60:
        return f"{secs:.0f}s"
    if secs < 3600:
        return f"{secs / 60:.0f}m"
    if secs < 86400:
        return f"{secs / 3600:.0f}h"
    return f"{secs / 86400:.0f}d"


def _pulse_tcp(node, host, port, registry):
    """Live hello to the TCP relay. Returns (alive, ms, error)."""
    from link import Link
    start = time.time()
    try:
        link = Link(node, registry=registry, host=host, port=port)
        ms = (time.time() - start) * 1000
        link.close()
        return True, ms, ""
    except Exception as e:  # noqa: BLE001 - reported, not raised
        return False, None, str(e)


def _pulse_web(node, url, registry, timeout_s=5):
    """Live hello to the web relay, capped at timeout_s (WebLink
    alone would wait up to 15s). Returns (alive, ms, error)."""
    from link import WebLink
    result = {}

    def run():
        try:
            start = time.time()
            link = WebLink(node, url, registry=registry)
            result["ok"] = True
            result["ms"] = (time.time() - start) * 1000
            link.close()
        except Exception as e:  # noqa: BLE001 - reported, not raised
            result["ok"] = False
            result["error"] = str(e)

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout_s)
    if "ok" not in result:
        return False, None, f"no answer in {timeout_s}s"
    return result["ok"], result.get("ms"), result.get("error", "")


def _bus_counts(dirs):
    """(label, count, newest-mtime-or-None) per bus area."""
    areas = [
        ("tasks waiting", "tasks", False),
        ("claimed", "claimed", False),
        ("results", "results", False),
        ("done", "done", False),
        ("prompts unanswered", "prompts", True),
        ("answers", "answers", False),
        ("messages unread", "messages", True),
        ("read", "read", True),
        ("dead", "dead", False),
        ("registry updates pending", "registry-updates", True),
    ]
    out = []
    for label, sub, recursive in areas:
        d = dirs[sub]
        paths = list(d.rglob("*.json")) if recursive else list(d.glob("*.json"))
        newest = max((p.stat().st_mtime for p in paths), default=None)
        out.append((label, len(paths), newest))
    return out


def _dead_reason(envelope, registry, bus):
    """Why this envelope is dead: re-verify it now and report the
    failing check. Verification runs first — a tampered v3
    envelope is a bad signature, not an unreadable one. A v3
    envelope that verifies but died on decryption gets its
    reason from the mismatch log (id + timestamp + keys)."""
    ok, reason = verify_basic(envelope, registry)
    if not ok:
        return reason
    if envelope.get("v") == VERSION and envelope.get("ciphertext"):
        for rec in read_mismatches(bus):
            if rec.get("id") == envelope.get("id"):
                return (f"key mismatch at {rec.get('at')}: message used "
                        f"{rec.get('used_from_key_id') or '?'} (sender) / "
                        f"{rec.get('used_to_key_id') or '?'} (recipient), "
                        f"{rec.get('to')} holds "
                        f"{', '.join(rec.get('held_key_ids') or []) or 'none'} "
                        f"— {rec.get('reason', '')}")
    need = KIND_PERMISSION.get(envelope.get("kind", ""))
    sender = envelope.get("from", "")
    entry = registry.get("nodes", {}).get(sender, {})
    if need and need not in entry.get("permissions", []):
        return (f"sender {sender} may not send "
                f"{envelope.get('kind')} messages")
    seen, _ = seen_ids(bus)
    if (envelope.get("kind") in ("task", "prompt", "message")
            and envelope.get("id") in seen):
        return "replayed envelope id"
    return "passed verification (moved to dead/ by a reader)"


def _envelope_summary(envelope):
    kind = envelope.get("kind")
    if kind == "task":
        return envelope.get("task", {}).get("prompt", "")[:100]
    if kind == "message":
        return envelope.get("message", {}).get("text", "")[:100]
    if kind == "prompt":
        return envelope.get("prompt", {}).get("text", "")[:100]
    if kind == "answer":
        return envelope.get("answer", {}).get("text", "")[:100]
    if kind == "result":
        return f"status={envelope.get('result', {}).get('status')}"
    return ""


def cmd_status(args):
    """Live pulse + bus counts + nodes + dead-letter summary."""
    registry = load_registry(args)
    dirs = bus_dirs(args.bus)
    bus = Path(args.bus)
    print(f"Bridge status — bus {args.bus}")
    print("Pulse")
    for name, label, addr in (
            ("tcp", "tcp relay", f"{args.tcp_host}:{args.tcp_port}"),
            ("web", "web relay", "not configured")):
        hb = bus / f".heartbeat-{name}"
        if hb.exists():
            try:
                data = json.loads(hb.read_text())
                conns = len(data.get("connections", []))
                print(f"  {label} {addr}: heartbeat "
                      f"{_age_str(data.get('ts', 0))} ago "
                      f"(pid {data.get('pid', '?')}, {conns} connection(s))")
            except Exception:
                print(f"  {label} {addr}: heartbeat file unreadable")
        else:
            print(f"  {label} {addr}: no heartbeat (relay not running?)")
    alive, ms, err = _pulse_tcp(args.node, args.tcp_host, args.tcp_port,
                                registry)
    if alive:
        print(f"  tcp hello: ALIVE ({ms:.0f}ms)")
    else:
        print(f"  tcp hello: DOWN ({err})")
    url = args.web_relay or os.environ.get("AGENC_BRIDGE_WEB_RELAY")
    if url:
        alive, ms, err = _pulse_web(args.node, url, registry)
        if alive:
            print(f"  web hello ({url}): ALIVE ({ms:.0f}ms)")
        else:
            print(f"  web hello ({url}): DOWN ({err})")
    else:
        print("  web hello: not configured (set AGENC_BRIDGE_WEB_RELAY)")
    print("Bus")
    for label, count, newest in _bus_counts(dirs):
        age = f", newest {_age_str(newest)} ago" if newest else ""
        print(f"  {label}: {count}{age}")
    print("Encryption")
    mismatches = read_mismatches(args.bus)
    if mismatches:
        latest = mismatches[0]
        print(f"  key mismatches: {len(mismatches)} (most recent "
              f"{latest.get('id')} at {latest.get('at')}, created "
              f"{latest.get('created_at')} — see `bridge.py dead`)")
    else:
        print("  key mismatches: 0")
    no_enc = [n for n, e in sorted(registry.get("nodes", {}).items())
              if not e.get("enc_public_key")]
    if no_enc:
        print(f"  WARNING: {len(no_enc)} node(s) have no encryption key "
              f"({', '.join(no_enc)}) — they can only receive "
              f"plaintext v2 mail")
    stale = []
    now = datetime.now(timezone.utc)
    for n, e in sorted(registry.get("nodes", {}).items()):
        rotated_at = e.get("enc_rotated_at", "")
        if not e.get("enc_public_key") or not rotated_at:
            continue
        try:
            dt = datetime.strptime(rotated_at, "%Y-%m-%dT%H:%M:%SZ"
                                  ).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if (now - dt).total_seconds() > 24 * 3600:
            stale.append(n)
    if stale:
        print(f"  WARNING: {len(stale)} node(s) past their daily "
              f"rotation ({', '.join(stale)}) — run "
              f"`bridge.py rotate-keys`")
    print("Registry distribution")
    print(f"  registry seq: {_registry_seq(registry)}")
    pending = {}
    upd_dir = bus / "registry-updates"
    if upd_dir.exists():
        for node_dir in sorted(upd_dir.iterdir()):
            if node_dir.is_dir():
                count = len(list(node_dir.glob("*.json")))
                if count:
                    pending[node_dir.name] = count
    if pending:
        print(f"  WARNING: {sum(pending.values())} registry update(s) "
              f"pending for {', '.join(f'{n} ({c})' for n, c in sorted(pending.items()))} "
              f"— run `bridge.py registry-pull` (or wait for the next poll)")
    else:
        print("  registry updates pending: 0")
    print("Nodes")
    pin = load_root_pin(registry)
    if pin is None:
        print("  WARNING: no root of trust — run `bridge.py pin-root` "
              "once the registry names a single self-signed master")
    elif not root_pin_path().exists():
        print(f"  root of trust: {pin['node']} (derived — run "
              f"`bridge.py pin-root` to pin it)")
    shared = [n for n, e in sorted(registry.get("nodes", {}).items())
              if encryption_key_status(n) == "shared"]
    if shared:
        print(f"  WARNING: {len(shared)} node(s) still on the shared "
              f"passphrase ({', '.join(shared)}) — rekey, then "
              f"`bridge.py retire-shared-passphrase`")
    for name, entry in sorted(registry.get("nodes", {}).items()):
        cert = entry.get("role_certificate")
        if cert and verify_role_certificate(name, entry, registry):
            cert_str = f"approved by {cert['approved_by']}"
        else:
            cert_str = "UNAPPROVED"
        print(f"  {name} [{entry.get('role', '?')}]: "
              f"{', '.join(entry.get('permissions', []))} — {cert_str}")
    return 0


def cmd_dead(args):
    """List dead letters with the reason each was rejected."""
    registry = load_registry(args)
    dirs = bus_dirs(args.bus)
    files = sorted(dirs["dead"].glob("*.json"),
                   key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        print("(no dead letters)")
        return 0
    for path in files[:args.limit]:
        try:
            envelope = read_envelope(path)
        except Exception as e:
            print(f"--- {path.name}: unreadable ({e})")
            continue
        reason = _dead_reason(envelope, registry, args.bus)
        print(f"--- {envelope.get('id')} {envelope.get('kind')} "
              f"from {envelope.get('from')} "
              f"({role_of(envelope.get('from', ''), registry)}) "
              f"to {envelope.get('to')} "
              f"at {envelope.get('created_at')}: {reason}")
        summary = _envelope_summary(envelope)
        if summary:
            print(f"    {summary}")
    return 0


def cmd_archive(args):
    """Sweep finished bus items into a dated archive, so the bus
    doesn't grow forever. Only dirs whose contents are finished
    move: done/ (completed tasks), read/ (already-read mail), and
    dead/ (rejected envelopes — the audit trail is preserved, just
    moved). Live state never moves: tasks/ (waiting), claimed/
    (in flight, unless --include-claimed and older than the
    threshold — a claim that old is a dead worker), prompts/
    (unanswered), answers/, messages/ (unread). The replay guard
    (seen/) is never touched. The archive is a sibling dir,
    bus-archive-<YYYYMMDD>/, with the same subdirs."""
    from datetime import timedelta
    bus = Path(args.bus)
    dirs = bus_dirs(bus)
    cutoff = datetime.now(timezone.utc) - timedelta(days=args.older_than)
    names = ["done", "read", "dead"]
    if args.include_claimed:
        names.append("claimed")
    archive_root = bus.parent / ("bus-archive-" + datetime.now(
        timezone.utc).strftime("%Y%m%d"))
    moved = {}
    for name in names:
        # rglob: read/ holds one file per reader (read/<reader>/),
        # the other dirs are flat — recurse so both shapes move.
        for path in sorted(dirs[name].rglob("*")):
            if not path.is_file():
                continue
            age = datetime.fromtimestamp(path.stat().st_mtime,
                                         timezone.utc)
            if age >= cutoff:
                continue
            dest_dir = archive_root / name
            if args.dry_run:
                print(f"would move {name}/{path.name} "
                      f"(last modified {age.strftime('%Y-%m-%d %H:%M')} UTC)")
                moved[name] = moved.get(name, 0) + 1
                continue
            dest = dest_dir / path.relative_to(dirs[name])
            dest.parent.mkdir(parents=True, exist_ok=True)
            os.replace(path, dest)
            moved[name] = moved.get(name, 0) + 1
    total = sum(moved.values())
    if total == 0:
        print(f"(nothing older than {args.older_than} days to archive)")
        return 0
    parts = ", ".join(f"{n}: {c}" for n, c in sorted(moved.items()))
    if args.dry_run:
        print(f"would archive {total} items ({parts})")
    else:
        print(f"archived {total} items into {archive_root.name}/ ({parts})")
    return 0


def main():
    parser = argparse.ArgumentParser(description="AgenC Bridge v3")
    parser.add_argument("--registry", default=None,
                        help="trusted-keys registry (default: trusted-keys.json beside bridge.py)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("keygen", help="generate a node's Ed25519 keypair (plus its X25519 encryption keypair)")
    p.add_argument("--node", required=True)

    p = sub.add_parser("rekey", help="give a node its own per-node encryption key: re-encrypt its private key (and provider key, and encryption keys) under a fresh random key")
    p.add_argument("--node", required=True)

    p = sub.add_parser("rotate-keys", help="rotate encryption keypairs (daily): fresh X25519 key per node, old key usable for a 48h grace window, then destroyed — and distribute the updated registry to the other nodes automatically")
    p.add_argument("--node", default=None,
                   help="rotate one node (default: every node in the registry)")
    p.add_argument("--dry-run", action="store_true",
                   help="report what would change, change nothing")
    p.add_argument("--bus", default=default_bus(),
                   help="bus directory to distribute into (default: ~/workspace/agenc-bridge/bus)")
    p.add_argument("--no-distribute", action="store_true",
                   help="rotate only — do not distribute the updated registry (distribute later with distribute-registry)")

    p = sub.add_parser("publish-enc-key", help="publish a node's encryption public key into the local registry (its self-attestation is verified first)")
    p.add_argument("--node", required=True)

    p = sub.add_parser("keys", help="show encryption-key freshness per node (current key id, rotation age, attestation, retired keys)")
    p.add_argument("--node", default=None,
                   help="show one node (default: all)")

    p = sub.add_parser("resync", help="adopt a registry copy from another machine, validated against the pinned root (the hand-copy distribution step)")
    p.add_argument("--registry", required=True,
                   help="path to the registry copy to adopt")

    p = sub.add_parser("distribute-registry", help="send the local registry to the other nodes as signed registry-update envelopes (the step rotate-keys runs automatically) — a certified master distributes, each node validates before adopting")
    p.add_argument("--bus", default=default_bus(),
                   help="bus directory to write the updates into (default: ~/workspace/agenc-bridge/bus)")
    p.add_argument("--to", default=None,
                   help="distribute to one node only (default: every node except the distributor and the relay)")
    p.add_argument("--distributor", default=None,
                   help="master node distributing (default: first certified master key found locally)")

    p = sub.add_parser("registry-pull", help="apply pending registry updates for a node — the hands-free half of distribution: each update is validated exactly like resync before it is adopted")
    p.add_argument("--bus", default=default_bus(),
                   help="bus directory to read the updates from (default: ~/workspace/agenc-bridge/bus)")
    p.add_argument("--node", default=None,
                   help="apply one node's updates (default: every node whose keys live here)")

    p = sub.add_parser("rerequest", help="ask the sender of a message that could not be decrypted to re-send it (looked up in the mismatch log)")
    p.add_argument("--bus", required=True)
    p.add_argument("--id", required=True,
                   help="id of the message that did not get through")
    p.add_argument("--to", required=True,
                   help="original sender to ask")
    p.add_argument("--sender", default="agenc-cloud",
                   help="node asking for the resend")

    p = sub.add_parser("resend", help="re-send a message a recipient could not decrypt, under the current keys (fresh id, resend_of names the original)")
    p.add_argument("--bus", required=True)
    p.add_argument("--id", required=True,
                   help="id of the original message")
    p.add_argument("--sender", default="agenc-cloud",
                   help="original sender re-sending its own mail")

    sub.add_parser("retire-shared-passphrase", help="retire the shared bridge passphrase once every node has its own per-node encryption key (refuses while any node still needs it)")

    p = sub.add_parser("mcp-token", help="issue, verify, list or revoke an MCP routing token: a hash of a fresh random secret, printed once at issuance and never stored in plaintext")
    p.add_argument("--from", dest="from_node", default=None,
                   help="caller node the token is for")
    p.add_argument("--to", default=None,
                   help="target node the token may talk to, or '*' for any target")
    p.add_argument("--expiry-days", type=int, default=30,
                   help="how many days the token lasts (default 30)")
    p.add_argument("--approve-by", default=None,
                   help="master node that issues the token (default: first master key found locally)")
    p.add_argument("--verify", default=None,
                   help="check a routing token and show what it allows")
    p.add_argument("--revoke", default=None,
                   help="revoke a routing token by its token id")
    p.add_argument("--list", action="store_true",
                   help="list issued routing tokens (ids only, never hashes or raw tokens)")

    p = sub.add_parser("launch", help="the system that starts: issue the starting (MCP) token and start the MCP server in the foreground — the token is passed only through the server's environment, never printed, logged, or put on the command line, and it is revoked when the server stops")
    p.add_argument("--node", required=True,
                   help="caller node the server speaks as")
    p.add_argument("--to", default="*",
                   help="target node the token may talk to, or '*' for any target (default '*')")
    p.add_argument("--expiry-days", type=int, default=30,
                   help="how many days the token lasts (default 30)")
    p.add_argument("--approve-by", default=None,
                   help="master node that issues the token (default: first master key found locally)")
    p.add_argument("--server", default=None,
                   help="MCP server script to start (default: bridge-mcp.py beside bridge.py)")
    p.add_argument("--bus", default=None,
                   help="bus directory for the server (default: the server's own default)")
    p.add_argument("--no-revoke", action="store_true",
                   help="leave the token live after the server stops (default: revoke it)")

    p = sub.add_parser("provider-key", help="store or remove a node's own provider key (its own OpenRouter key, with its own limit set at OpenRouter)")
    p.add_argument("--node", required=True)
    p.add_argument("--from-file", default=None,
                   help="read the key from this file; the file is deleted afterwards")
    p.add_argument("--from-stdin", action="store_true",
                   help="read the key from stdin")
    p.add_argument("--remove", action="store_true",
                   help="delete the stored provider key for this node")

    p = sub.add_parser("fingerprint", help="show a node's 60-digit fingerprint")
    p.add_argument("--node", required=True)

    p = sub.add_parser("trust", help="add a node's public key to the registry")
    p.add_argument("--node", required=True)
    p.add_argument("--pubkey", required=True, help="path to the node's .pub file")
    p.add_argument("--enc-pubkey", default=None,
                   help="path to the node's .x25519.pub file (its encryption public key; its self-attestation is verified before publishing)")
    p.add_argument("--enc-attest", default=None,
                   help="path to the node's .x25519.attest file (with --enc-pubkey)")
    p.add_argument("--role", default="owner", choices=list(ROLES))
    p.add_argument("--permissions", default=None,
                   help="comma-separated list, overrides --role")
    p.add_argument("--approve-by", default=None,
                   help="master node that approves this role (default: self for master/owner, else first master key found locally)")

    p = sub.add_parser("promote", help="change a node's role (master approval required)")
    p.add_argument("--node", required=True)
    p.add_argument("--role", required=True, choices=list(ROLES))
    p.add_argument("--permissions", default=None,
                   help="comma-separated list, overrides --role")
    p.add_argument("--approve-by", default=None,
                   help="master node that approves the promotion")

    p = sub.add_parser("approve", help="certify a node's current role (master approval)")
    p.add_argument("--node", required=True)
    p.add_argument("--approve-by", default=None,
                   help="master node that approves this role")

    p = sub.add_parser("pin-root", help="pin the root of trust: write root.json naming the root master and its fingerprint (a self-signed certificate is only valid for the pinned root)")
    p.add_argument("--node", default=None,
                   help="root master to pin (default: the single self-signed master in this registry)")

    p = sub.add_parser("revoke", help="remove a node from the registry")
    p.add_argument("--node", required=True)

    p = sub.add_parser("agent", help="provision an agent node: its own keys, role, thread wiki, and a place in the served list (or remove one)")
    p.add_argument("--name", required=True,
                   help="agent name — also its node name and thread name")
    p.add_argument("--role", default="worker", choices=list(ROLES),
                   help="the agent's own role (its permissions)")
    p.add_argument("--rules", default=None,
                   help="the agent's rules for its project (its thread's rules)")
    p.add_argument("--approve-by", default=None,
                   help="master node that approves this role")
    p.add_argument("--bus", default=default_bus())
    p.add_argument("--remove", action="store_true",
                   help="revoke the agent node and take it off the served list (its thread wiki is kept)")

    sub.add_parser("registry", help="list trusted nodes")

    p = sub.add_parser("send")
    p.add_argument("--bus", required=True)
    p.add_argument("--to", required=True)
    p.add_argument("--prompt", required=True)
    p.add_argument("--sender", default="agenc-cloud")
    p.add_argument("--model", default=DEFAULT_MODEL)
    p.add_argument("--cwd", default=".")
    p.add_argument("--timeout-s", type=int, default=600)
    p.add_argument("--max-cost-usd", type=float, default=0.0)
    p.add_argument("--budget", default=None, choices=["eco", "balanced", "max"],
                   help="AgenC's own per-run token budget (eco 1M, balanced 2.4M, max unlimited)")
    p.add_argument("--max-calls", type=int, default=None,
                   help="AgenC's own per-run model call cap")

    p = sub.add_parser("wait")
    p.add_argument("--bus", required=True)
    p.add_argument("--id", required=True)
    p.add_argument("--timeout-s", type=int, default=900)

    p = sub.add_parser("message", help="send a one-way message to another node")
    p.add_argument("--bus", required=True)
    p.add_argument("--to", required=True)
    p.add_argument("--text", required=True)
    p.add_argument("--sender", default="agenc-cloud")
    p.add_argument("--needs-reply", action="store_true")
    p.add_argument("--in-reply-to", default=None)

    p = sub.add_parser("inbox", help="list unread messages for a node")
    p.add_argument("--bus", required=True)
    p.add_argument("--node", required=True)
    p.add_argument("--mark-read", action="store_true",
                   help="accepted for compatibility; messages are moved to read/ when shown unless --keep is given")
    p.add_argument("--keep", action="store_true",
                   help="leave messages in place instead of moving them to read/")

    p = sub.add_parser("ask", help="prompt another node as if it were an LLM")
    p.add_argument("--bus", required=True)
    p.add_argument("--to", default="agenc-cloud")
    p.add_argument("--prompt", required=True)
    p.add_argument("--context", default="")
    p.add_argument("--sender", default="agenc-cloud")
    p.add_argument("--thread", default=None,
                   help="the agent/thread this prompt belongs to (one per project; a new one is started if omitted)")
    p.add_argument("--rules", default=None,
                   help="this thread's rules — its agent's instructions for its project (kept with the thread)")

    p = sub.add_parser("thread", help="show a thread's wiki: rules, facts, and history")
    p.add_argument("--bus", required=True)
    p.add_argument("--id", required=True)

    p = sub.add_parser("note", help="record a fact worth keeping in a thread's wiki")
    p.add_argument("--bus", required=True)
    p.add_argument("--thread", required=True)
    p.add_argument("--text", required=True)
    p.add_argument("--sender", default="agenc-cloud",
                   help="node signing this fact into the thread's wiki manifest (default: agenc-cloud)")

    p = sub.add_parser("sign-thread", help="(re)sign a thread's wiki manifest for the files as they stand now — adoption for threads written before signing, repair after an authorized manual edit")
    p.add_argument("--bus", required=True)
    p.add_argument("--thread", required=True)
    p.add_argument("--sender", default="agenc-cloud",
                   help="node signing the manifest — the thread's creator or an owner/master (default: agenc-cloud)")

    p = sub.add_parser("context", help="return only the context that matters for a question: rules, facts, recent turns, and matching older turns")
    p.add_argument("--bus", required=True)
    p.add_argument("--thread", required=True)
    p.add_argument("--query", default="")
    p.add_argument("--recent", type=int, default=3,
                   help="how many recent turns to include (default 3)")

    p = sub.add_parser("prompts", help="list unanswered prompts for a node")
    p.add_argument("--bus", required=True)
    p.add_argument("--node", required=True)

    p = sub.add_parser("reply", help="answer a prompt by id")
    p.add_argument("--bus", required=True)
    p.add_argument("--id", required=True)
    p.add_argument("--text", required=True)
    p.add_argument("--from-node", default="agenc-cloud")

    p = sub.add_parser("fetch-answer", help="wait for an answer to a prompt id")
    p.add_argument("--bus", required=True)
    p.add_argument("--id", required=True)
    p.add_argument("--timeout-s", type=int, default=900)

    p = sub.add_parser("status", help="live pulse + bus counts + nodes + dead letters")
    p.add_argument("--bus", default=default_bus())
    p.add_argument("--node", default="agenc-cloud",
                   help="node the pulse hello signs as")
    p.add_argument("--tcp-host", default="127.0.0.1")
    p.add_argument("--tcp-port", type=int, default=8765)
    p.add_argument("--web-relay", default=None,
                   help="web relay URL to pulse (default: $AGENC_BRIDGE_WEB_RELAY)")

    p = sub.add_parser("dead", help="list dead letters with their rejection reason")
    p.add_argument("--bus", default=default_bus())
    p.add_argument("--limit", type=int, default=20)

    p = sub.add_parser("archive", help="sweep finished bus items (done/read/dead) into a dated archive")
    p.add_argument("--bus", default=default_bus())
    p.add_argument("--older-than", type=int, default=7,
                   help="archive items last modified more than this many days ago (default 7)")
    p.add_argument("--include-claimed", action="store_true",
                   help="also archive claimed items older than the threshold (a claim that old is a dead worker)")
    p.add_argument("--dry-run", action="store_true",
                   help="list what would move, move nothing")

    for name in ("poll", "serve"):
        p = sub.add_parser(name)
        p.add_argument("--bus", required=True)
        p.add_argument("--node", required=True)
        p.add_argument("--project-root", required=True)
        p.add_argument("--interval-s", type=int, default=10)
        p.add_argument("--agent", default="agenc", choices=list(AGENT_PROFILES),
                       help="worker agent profile (see WORKERS.md)")
        p.add_argument("--agent-cmd", default=None,
                       help="override the agent command for tests/custom agents, e.g. 'echo'")
        p.set_defaults(once=(name == "poll"))

    args = parser.parse_args()
    if args.cmd == "keygen":
        return cmd_keygen(args)
    if args.cmd == "rekey":
        return cmd_rekey(args)
    if args.cmd == "rotate-keys":
        return cmd_rotate_keys(args)
    if args.cmd == "publish-enc-key":
        return cmd_publish_enc_key(args)
    if args.cmd == "keys":
        return cmd_keys(args)
    if args.cmd == "resync":
        return cmd_resync(args)
    if args.cmd == "distribute-registry":
        return cmd_distribute_registry(args)
    if args.cmd == "registry-pull":
        return cmd_registry_pull(args)
    if args.cmd == "rerequest":
        return cmd_rerequest(args)
    if args.cmd == "resend":
        return cmd_resend(args)
    if args.cmd == "retire-shared-passphrase":
        return cmd_retire_shared_passphrase(args)
    if args.cmd == "mcp-token":
        return cmd_mcp_token(args)
    if args.cmd == "launch":
        return cmd_launch(args)
    if args.cmd == "provider-key":
        return cmd_provider_key(args)
    if args.cmd == "fingerprint":
        return cmd_fingerprint(args)
    if args.cmd == "trust":
        return cmd_trust(args)
    if args.cmd == "promote":
        return cmd_promote(args)
    if args.cmd == "approve":
        return cmd_approve(args)
    if args.cmd == "pin-root":
        return cmd_pin_root(args)
    if args.cmd == "revoke":
        return cmd_revoke(args)
    if args.cmd == "agent":
        return cmd_agent(args)
    if args.cmd == "registry":
        return cmd_registry(args)
    if args.cmd == "send":
        return cmd_send(args)
    if args.cmd == "wait":
        return cmd_wait(args)
    if args.cmd == "message":
        return cmd_message(args)
    if args.cmd == "inbox":
        return cmd_inbox(args)
    if args.cmd == "ask":
        return cmd_ask(args)
    if args.cmd == "thread":
        return cmd_thread(args)
    if args.cmd == "note":
        return cmd_note(args)
    if args.cmd == "sign-thread":
        return cmd_sign_thread(args)
    if args.cmd == "context":
        return cmd_context(args)
    if args.cmd == "prompts":
        return cmd_prompts(args)
    if args.cmd == "reply":
        return cmd_reply(args)
    if args.cmd == "fetch-answer":
        return cmd_fetch_answer(args)
    if args.cmd == "status":
        return cmd_status(args)
    if args.cmd == "dead":
        return cmd_dead(args)
    if args.cmd == "archive":
        return cmd_archive(args)
    return cmd_poll(args)


if __name__ == "__main__":
    sys.exit(main())
