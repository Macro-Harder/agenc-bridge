"""Unit tests for agenc-daemon-watchdog.py.

The check logic reads a fake /proc tree, so no real daemon is needed.
The value of the key is never asserted anywhere — only its presence.
"""
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import agenc_daemon_watchdog as w


def _make_proc(tmp, pid, *, keyed=True, cmdline=b"agenc\x00"):
    proc = Path(tmp) / "proc" / str(pid)
    proc.mkdir(parents=True)
    (proc / "cmdline").write_bytes(cmdline)
    env = b"HOME=/home/hatch\x00PATH=/usr/bin\x00"
    if keyed:
        env += b"OPENROUTER_API_KEY=hsurr:test-value-that-is-not-real\x00"
    (proc / "environ").write_bytes(env)
    return proc


class CheckTests(unittest.TestCase):
    def setUp(self):
        import shutil
        import tempfile
        self._tmpdir = tempfile.mkdtemp(prefix="daemon-watchdog-test-")
        self.tmp = Path(self._tmpdir)
        self.proc_root = str(self.tmp / "proc")
        self.pid_file = self.tmp / "daemon.pid"

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _pid_file(self, pid):
        self.pid_file.write_text(str(pid))

    def test_keyed_daemon(self):
        _make_proc(self.tmp, 1234, keyed=True)
        self._pid_file(1234)
        self.assertEqual(w.check(self.pid_file, self.proc_root),
                         ("keyed", 1234))

    def test_unkeyed_daemon(self):
        _make_proc(self.tmp, 1234, keyed=False)
        self._pid_file(1234)
        self.assertEqual(w.check(self.pid_file, self.proc_root),
                         ("unkeyed", 1234))

    def test_down_no_pid_file(self):
        self.assertEqual(w.check(self.pid_file, self.proc_root),
                         ("down", None))

    def test_down_stale_pid(self):
        self._pid_file(9999)
        self.assertEqual(w.check(self.pid_file, self.proc_root),
                         ("down", None))

    def test_down_wrong_cmdline(self):
        _make_proc(self.tmp, 1234, keyed=True, cmdline=b"python3\x00")
        self._pid_file(1234)
        self.assertEqual(w.check(self.pid_file, self.proc_root),
                         ("down", None))

    def test_is_keyed_never_reads_value(self):
        # Presence only: a keyed environ with a different value is
        # still just "keyed", and the value never leaves the bytes.
        proc = _make_proc(self.tmp, 1234, keyed=False)
        env = (proc / "environ").read_bytes()
        env += b"OPENROUTER_API_KEY=\x00"
        (proc / "environ").write_bytes(env)
        self.assertTrue(w.is_keyed(1234, self.proc_root))

    def test_fix_noop_when_keyed(self):
        import contextlib
        import io
        with mock.patch.object(w, "check", return_value=("keyed", 1234)), \
             mock.patch.object(w, "fresh_surrogate") as fresh, \
             mock.patch.object(w, "start_daemon_keyed") as start, \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(w.fix(), 0)
        fresh.assert_not_called()
        start.assert_not_called()

    def test_start_passes_key_only_via_env(self):
        seen = {}

        def fake_run(args, env=None, capture_output=None, text=None,
                     timeout=None):
            seen["args"] = args
            seen["env"] = dict(env or {})
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch.object(w.subprocess, "run", side_effect=fake_run):
            w.start_daemon_keyed("hsurr:secret-test-value")
        self.assertNotIn("hsurr:secret-test-value",
                         " ".join(seen["args"]))
        self.assertEqual(seen["env"].get("OPENROUTER_API_KEY"),
                         "hsurr:secret-test-value")


if __name__ == "__main__":
    unittest.main()
