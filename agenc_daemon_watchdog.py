#!/usr/bin/env python3
"""AgenC daemon credential watchdog — keep the daemon keyed.

Why this exists: on this VM AgenC has no native secure storage
(libsecret is missing), and OpenRouter credentials resolve from the
OPENROUTER_API_KEY environment variable only — the bundled runtime
defines them as apiKeyCredentials(["OPENROUTER_API_KEY"]), and
config.toml has no key slot. The daemon autostarts
(config daemon.autostart=true), so any `agenc` call made while the
daemon is down spawns a replacement that inherits the *caller's*
environment. A keyless caller spawns a keyless daemon, after which
every agent run fails with 401 LLMMissingCredentialsError. The
daemon itself only holds a key when it was started with one in its
environment; a restart loses it.

The VM also keeps reverting the home directory to mode 2770
(group-writable), and AgenC refuses to start in that state
("protected directory chain permits untrusted mutation"), so a
restart attempted while the mode stands fails. `fix` therefore
clears the group/world write bits from the home directory before
restarting.

This script checks, without spending any tokens, whether the running
daemon was started with a key: it looks for the OPENROUTER_API_KEY
*name* in the daemon's /proc/<pid>/environ (presence only — the
value is never read or printed). When the daemon is down or unkeyed,
`fix` restarts it with a fresh OpenRouter surrogate from the secure
connector, passed only through the child process environment — never
written to a file, a log, or a command line. The check never invokes
any `agenc` command, so it cannot trigger a keyless autostart.

Usage:
  agenc-daemon-watchdog.py check   # print daemon=keyed|unkeyed|down [pid=N]
  agenc-daemon-watchdog.py fix     # restart keyed if down/unkeyed; exit 0 when keyed

Run `fix` from a cron every 5 minutes (see agenc-daemon-watchdog cron).
Per-node provider keys are unaffected: a node with a stored provider
key stays self-sufficient, and this script never touches provider keys.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

AGENC = Path.home() / ".local/bin/agenc"
AGENC_HOME = Path.home() / ".agenc"
DAEMON_PID_FILE = AGENC_HOME / "daemon.pid"
WATCHDOG_LOG = AGENC_HOME / "daemon-watchdog.log"
DYNAMIC_CREDS_DIR = "/opt/muse/skills/custom-connector-setup/bin"

START_TIMEOUT = 60.0
STOP_TIMEOUT = 15.0
POLL_INTERVAL = 2.0


def log(msg: str) -> None:
    """One timestamped line in the watchdog log. Never call with key material."""
    line = f"{datetime.now(timezone.utc).isoformat()} {msg}\n"
    try:
        with open(WATCHDOG_LOG, "a") as f:
            f.write(line)
    except OSError:
        pass


def daemon_pid(pid_file: Path = DAEMON_PID_FILE,
               proc_root: str = "/proc") -> int | None:
    """Pid of the running daemon, or None. The pid file is authoritative;
    a stale pid (dead process, or a process that is not agenc) is None."""
    try:
        pid = int(pid_file.read_text().strip())
    except (OSError, ValueError):
        return None
    if pid <= 0:
        return None
    proc = Path(proc_root) / str(pid)
    if not proc.is_dir():
        return None
    try:
        cmdline = (proc / "cmdline").read_bytes()
    except OSError:
        return None
    # The daemon's cmdline is just "agenc" (the launcher re-execs node).
    if not cmdline.startswith(b"agenc"):
        return None
    return pid


def is_keyed(pid: int, proc_root: str = "/proc") -> bool:
    """True when the daemon process was started with OPENROUTER_API_KEY
    in its environment. Presence of the name only — the value is never
    read, decoded, or printed."""
    try:
        env = (Path(proc_root) / str(pid) / "environ").read_bytes()
    except OSError:
        return False
    return any(part.startswith(b"OPENROUTER_API_KEY=")
               for part in env.split(b"\0"))


def check(pid_file: Path = DAEMON_PID_FILE,
          proc_root: str = "/proc") -> tuple[str, int | None]:
    """Return ("keyed"|"unkeyed"|"down", pid). No tokens spent, no agenc
    command invoked, so a check can never trigger a keyless autostart."""
    pid = daemon_pid(pid_file, proc_root)
    if pid is None:
        return "down", None
    return ("keyed" if is_keyed(pid, proc_root) else "unkeyed"), pid


def fresh_surrogate() -> str:
    """One fresh OpenRouter surrogate from the secure connector. The
    surrogate is only useful to the Hatch egress proxy, which swaps it
    for the real key on approved requests to openrouter.ai. It lives in
    memory only; callers must never print, log, or store it."""
    sys.path.insert(0, DYNAMIC_CREDS_DIR)
    from dynamic_credentials import dynamic_credential_entry
    entry = dynamic_credential_entry("custom.openrouter")
    surrogate = str(entry["surrogate"]).strip()
    if not surrogate.startswith("hsurr:"):
        raise RuntimeError("secure connector returned a non-surrogate value")
    return surrogate


def _run_agenc(args: list[str], env: dict | None,
               timeout: float) -> subprocess.CompletedProcess:
    return subprocess.run([str(AGENC)] + args, env=env,
                          capture_output=True, text=True, timeout=timeout)


def stop_daemon(pid: int | None) -> None:
    """Stop the daemon; fall back to SIGTERM on the pid if the CLI cannot
    reach it. Best effort — never raises."""
    try:
        _run_agenc(["daemon", "stop"], env=None, timeout=STOP_TIMEOUT)
    except (OSError, subprocess.SubprocessError):
        pass
    deadline = time.monotonic() + STOP_TIMEOUT
    while time.monotonic() < deadline:
        if daemon_pid() is None:
            return
        time.sleep(0.5)
    if pid is not None:
        try:
            os.kill(pid, 15)
        except OSError:
            pass
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if daemon_pid() is None:
                return
            time.sleep(0.5)


def start_daemon_keyed(surrogate: str) -> None:
    """Start the daemon with the surrogate in the child environment only.
    The surrogate never appears in argv, a file, or a log."""
    env = {**os.environ, "OPENROUTER_API_KEY": surrogate}
    _run_agenc(["daemon", "start"], env=env, timeout=START_TIMEOUT)


def wait_keyed(timeout: float = START_TIMEOUT) -> tuple[str, int | None]:
    deadline = time.monotonic() + timeout
    while True:
        state, pid = check()
        if state == "keyed" or time.monotonic() >= deadline:
            return state, pid
        time.sleep(POLL_INTERVAL)


def ensure_home_not_writable(home: Path | None = None) -> bool:
    """Remove group/world write from the home directory when present.

    AgenC refuses to start while its protected directory chain permits
    group/world write, and this VM keeps reverting the home directory
    to 2770. Clear exactly those two bits, preserving everything else
    (including setgid). Returns True when a repair was applied.
    Never raises."""
    home = home or Path.home()
    try:
        perm = stat.S_IMODE(os.stat(home).st_mode)
        new = perm & ~0o022
        if new == perm:
            return False
        os.chmod(home, new)
        log(f"home {home} mode {perm:04o} -> {new:04o} "
            "(removed group/world write so the daemon can start)")
        return True
    except OSError as exc:
        log(f"home mode repair failed for {home}: {exc}")
        return False


def fix() -> int:
    """Restart the daemon keyed when it is down or unkeyed. Returns 0
    when the daemon ends up keyed, 1 otherwise."""
    state, pid = check()
    if state == "keyed":
        print(f"daemon=keyed pid={pid}")
        return 0
    ensure_home_not_writable()
    log(f"daemon {state} pid={pid}; restarting keyed")
    try:
        surrogate = fresh_surrogate()
    except Exception as exc:  # noqa: BLE001 — report, do not leak the value
        print(f"daemon={state} pid={pid} error=cannot-fetch-credential: {exc}",
              file=sys.stderr)
        log(f"daemon {state} pid={pid}; credential fetch failed")
        return 1
    try:
        if pid is not None:
            stop_daemon(pid)
        start_daemon_keyed(surrogate)
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"daemon={state} pid={pid} error=restart-failed: {exc}",
              file=sys.stderr)
        log(f"daemon {state} pid={pid}; restart failed: {exc}")
        return 1
    finally:
        # The surrogate lives only in this process's memory and the
        # daemon's environment. Drop the reference as soon as it is used.
        surrogate = ""  # noqa: F841
    state, pid = wait_keyed()
    print(f"daemon={state} pid={pid}")
    log(f"daemon {state} pid={pid} after restart")
    return 0 if state == "keyed" else 1


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in ("check", "fix"):
        print("usage: agenc-daemon-watchdog.py check|fix", file=sys.stderr)
        return 2
    if argv[1] == "check":
        state, pid = check()
        print(f"daemon={state}" + (f" pid={pid}" if pid else ""))
        return 0
    return fix()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
