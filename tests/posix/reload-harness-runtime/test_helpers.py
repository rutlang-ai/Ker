#!/usr/bin/env python3
"""Real-process and filesystem-boundary checks for the sandbox helpers."""

import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path("/data/workspace")
TOOLS = ROOT
KILL = TOOLS / "kill_process.sh"
TRASH = TOOLS / "rm_tmp_file.sh"
CHMOD = TOOLS / "chmod_modify.sh"
sys.path.insert(0, "/mnt/repo/tests/upstream/fstack/tests/integration/common")
import reload_checks


class HelperRuntimeTests(unittest.TestCase):
    def child(self, ignore_term=False):
        code = "import time; print('CHILD_READY', flush=True); time.sleep(60)"
        if ignore_term:
            code = ("import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                    "print('CHILD_READY', flush=True); time.sleep(60)")
        process = subprocess.Popen([sys.executable, "-B", "-c", code],
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   text=True, bufsize=1)
        identity = reload_checks.identity(process.pid)
        ready, _, _ = select.select([process.stdout], [], [], 3)
        if not ready or process.stdout.readline().strip() != "CHILD_READY":
            subprocess.run(self.command(identity, "KILL", 1), check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            process.wait(timeout=2)
            self.fail("fixture child failed to reach its ready state")
        self.addCleanup(self.stop_child, process, identity)
        return process, identity

    @staticmethod
    def stop_child(process, identity):
        if process.poll() is None:
            subprocess.run([str(KILL), "--signal", "KILL", "--pid", str(identity["pid"]),
                "--start-time", str(identity["start_time"]), "--exe", identity["exe"],
                "--device", str(identity["device"]), "--inode", str(identity["inode"]),
                "--wait", "1"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            raise AssertionError("explicit pidfd KILL did not reap fixture child")
        if process.stdout is not None:
            process.stdout.close()

    @staticmethod
    def command(identity, signal_name="TERM", wait=None):
        args = [str(KILL), "--signal", signal_name, "--pid", str(identity["pid"]),
            "--start-time", str(identity["start_time"]), "--exe", identity["exe"],
            "--device", str(identity["device"]), "--inode", str(identity["inode"])]
        if wait is not None:
            args += ["--wait", str(wait)]
        return args

    def test_capability_and_complete_identity_validation(self):
        result = subprocess.run([str(KILL), "--capabilities"], text=True, capture_output=True)
        self.assertEqual((result.returncode, result.stdout), (0, "pidfd-identity-v1\n"))
        bash_result = subprocess.run(["/bin/bash", str(KILL), "--capabilities"],
                                     text=True, capture_output=True)
        self.assertEqual((bash_result.returncode, bash_result.stdout),
                         (0, "pidfd-identity-v1\n"))
        process, identity = self.child()
        for field in ("start_time", "device", "inode"):
            wrong = dict(identity)
            wrong[field] += 1
            result = subprocess.run(self.command(wrong), capture_output=True)
            self.assertEqual(result.returncode, 4, (field, result.stderr))
            self.assertIsNone(process.poll(), field)
        for args in (("--signal", "BAD"), ("--pid", str(process.pid)),
                     (*self.command(identity), "--wait", "nan")):
            result = subprocess.run([str(KILL), *args], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIsNone(process.poll())

    def test_stop_continue_term_use_the_supplied_signal_only(self):
        process, identity = self.child()
        self.assertEqual(subprocess.run(self.command(identity, "STOP")).returncode, 0)
        self.assertIsNone(process.poll())
        self.assertEqual(subprocess.run(self.command(identity, "CONT")).returncode, 0)
        self.assertEqual(subprocess.run(self.command(identity, "TERM", 1)).returncode, 0)
        process.wait(timeout=2)

    def test_timeout_does_not_escalate_and_explicit_kill_is_separate(self):
        process, identity = self.child(ignore_term=True)
        result = subprocess.run(self.command(identity, "TERM", 0.2), capture_output=True)
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertIsNone(process.poll(), "TERM timeout unexpectedly escalated")
        self.assertEqual(subprocess.run(self.command(identity, "KILL", 1)).returncode, 0)
        process.wait(timeout=2)

    def test_trash_is_allowlisted_and_never_follows_symlinks(self):
        self.assertNotEqual(subprocess.run([str(TRASH), "/"]).returncode, 0)
        self.assertNotEqual(subprocess.run([str(TRASH), str(ROOT)]).returncode, 0)
        self.assertNotEqual(subprocess.run([str(TRASH), "/tmp"]).returncode, 0)
        self.assertNotEqual(subprocess.run([str(TRASH), "/data/workspace/../etc"]).returncode, 0)
        outsider_fd, outsider_name = tempfile.mkstemp(prefix="c10-trash-outside-")
        os.close(outsider_fd)
        outsider = Path(outsider_name)
        root = Path(tempfile.mkdtemp(prefix="reload-unit-trash-", dir=ROOT))
        link = root / "escape"
        link.symlink_to(outsider)
        try:
            self.assertEqual(subprocess.run(["/bin/bash", str(TRASH), str(link)]).returncode, 0)
            self.assertFalse(link.exists())
            self.assertTrue(outsider.exists())
            mode_file = root / "mode-fixture"
            mode_file.write_text("owned fixture")
            self.assertEqual(subprocess.run(["/bin/bash", str(CHMOD), "0600", str(mode_file)]).returncode, 0)
            self.assertEqual(mode_file.stat().st_mode & 0o777, 0o600)
            self.assertNotEqual(subprocess.run([str(CHMOD), "0777", str(outsider)]).returncode, 0)
            self.assertEqual(subprocess.run([str(TRASH), str(root)]).returncode, 0)
            self.assertFalse(root.exists())
            self.assertTrue(outsider.exists())
        finally:
            outsider.unlink(missing_ok=True)

    def test_audit_records_real_signal_and_timeout_results(self):
        process, identity = self.child(ignore_term=True)
        audit_path = ROOT / "reload-unit-audit.jsonl"
        env = dict(os.environ, KILL_IDENTITY_AUDIT=str(audit_path))
        result = subprocess.run(self.command(identity, "TERM", 0.1), env=env, capture_output=True)
        self.assertEqual(result.returncode, 3)
        self.assertIsNone(process.poll())
        records = [json.loads(line) for line in audit_path.read_text().splitlines()]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["result"], "wait_timeout")
        self.assertEqual(records[0]["signal"], "TERM")
        audit_path.unlink()


if __name__ == "__main__":
    unittest.main(verbosity=2)
