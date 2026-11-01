#!/usr/bin/env python3
"""Failure-path checks for the opt-in C10 sandbox runner."""

import importlib.util
import os
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import tempfile
import time
import unittest


REPO = Path(__file__).resolve().parents[3]
RUNNER_PATH = REPO / "tests/posix/fstack-reload-harness-runtime.py"
SPEC = importlib.util.spec_from_file_location("c10_runner", RUNNER_PATH)
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class RunnerFailureTests(unittest.TestCase):
    @staticmethod
    def process_start_time(pid):
        stat = (Path("/proc") / str(pid) / "stat").read_text()
        return stat[stat.rfind(")") + 2:].split()[19]

    def test_source_hash_mismatch_is_rejected_before_sandbox_launch(self):
        with tempfile.TemporaryDirectory(prefix="ker-c10-bad-source-") as temp:
            repo = Path(temp)
            first = next(iter(runner.PINNED))
            altered = repo / first
            altered.parent.mkdir(parents=True)
            altered.write_text("deliberately altered pinned input\n")
            result = subprocess.run(
                [sys.executable, "-B", str(RUNNER_PATH), "--repo", str(repo),
                 "--focused-only"], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("SOURCE_VERIFICATION_FAILED", result.stderr)
            self.assertIn("pinned source hash mismatch", result.stderr)

    def test_real_sandbox_child_nonzero_exit_is_preserved(self):
        if not shutil.which("bwrap"):
            self.fail("bwrap is required; runner failure propagation cannot be skipped")
        with tempfile.TemporaryDirectory(prefix="ker-c10-runner-fail-") as temp:
            command = runner.sandbox_command(REPO, Path(temp), focused=True)
            payload_at = command.index("--chdir") + 2
            command[payload_at:] = [sys.executable, "-B", "-c", "raise SystemExit(23)"]
            status, output, timed_out = runner.execute_sandbox(command, 10)
            self.assertFalse(timed_out, output)
            self.assertEqual(status, 23, output)

    def test_timeout_removes_live_processes_in_private_pid_namespace(self):
        if not shutil.which("bwrap"):
            self.fail("bwrap is required; namespace cleanup cannot be skipped")
        with tempfile.TemporaryDirectory(prefix="ker-c10-timeout-") as temp:
            marker = "ker_c10_timeout_child_" + str(os.getpid()) + "_" + str(time.time_ns())
            ready = Path(temp) / "child-ready"
            child = (
                "import pathlib,sys,time; "
                "pathlib.Path('/tmp/child-ready').write_text('ready'); "
                "time.sleep(60)"
            )
            parent = (
                "import pathlib,subprocess,sys,time; "
                "p=subprocess.Popen([sys.executable,'-B','-c',sys.argv[1],sys.argv[2]]); "
                "deadline=time.monotonic()+5; "
                "ready=pathlib.Path('/tmp/child-ready'); "
                "\nwhile not ready.exists() and time.monotonic()<deadline: time.sleep(.01)\n"
                "if not ready.exists(): raise SystemExit(91)\n"
                "time.sleep(60)"
            )
            command = [
                shutil.which("bwrap"), "--die-with-parent", "--ro-bind", "/", "/",
                "--bind", temp, "/tmp", "--proc", "/proc", "--dev", "/dev",
                "--unshare-user", "--uid", "0", "--gid", "0", "--unshare-pid",
                "--unshare-net", "--unshare-ipc", "--unshare-uts", "--clearenv",
                "--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin",
                "--chdir", "/tmp", sys.executable, "-B", "-c", parent, child, marker,
            ]
            status, output, timed_out = runner.execute_sandbox(command, 1.5)
            self.assertTrue(timed_out, output)
            self.assertEqual(status, 124, output)
            self.assertTrue(ready.exists(), "child never reached its live state")

            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                found = []
                for proc in Path("/proc").iterdir():
                    if not proc.name.isdigit():
                        continue
                    try:
                        cmdline = (proc / "cmdline").read_bytes()
                    except (FileNotFoundError, PermissionError, ProcessLookupError):
                        continue
                    if marker.encode() in cmdline:
                        found.append(proc.name)
                if not found:
                    break
                time.sleep(0.05)
            if found:
                for pid in found:
                    pid_path = Path("/proc") / pid
                    try:
                        before_start = self.process_start_time(pid)
                        if marker.encode() not in (pid_path / "cmdline").read_bytes():
                            continue
                        pidfd = os.pidfd_open(int(pid))
                        try:
                            after_start = self.process_start_time(pid)
                            after_cmdline = (pid_path / "cmdline").read_bytes()
                            if before_start == after_start and marker.encode() in after_cmdline:
                                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                        finally:
                            os.close(pidfd)
                    except (FileNotFoundError, ProcessLookupError, PermissionError):
                        pass
            self.assertFalse(found, f"sandbox timeout left marker process(es): {found}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
