"""Real-process controls for the bootstrap's pinned executable observations."""
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('source_bootstrap_under_test',
    ROOT / 'tools/nginx_source_bootstrap_supervisor.py')
boot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boot)


@unittest.skipUnless(hasattr(os, 'pidfd_open'), 'Linux pidfds required')
class ExecutableObservationTests(unittest.TestCase):
    def observer(self):
        # Exercise the same private host observation used by the full source
        # constructor. This fixture grants no source/slot/process authority.
        observer = boot.SourceBootstrapSupervisor.__new__(boot.SourceBootstrapSupervisor)
        observer._executable_files = {}
        observer.slim_pidfd = -1
        observer.workers = {}
        self.addCleanup(observer.close)
        return observer

    def actor(self, pid):
        fd = os.pidfd_open(pid)
        self.addCleanup(os.close, fd)
        return fd, boot.identity._start_ticks(pid)

    def process(self, command, **kwargs):
        child = subprocess.Popen(command, **kwargs)
        def stop():
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=3)
            for stream in (child.stdin, child.stdout, child.stderr):
                if stream is not None:
                    stream.close()
        self.addCleanup(stop)
        return child

    def test_exact_hashed_inode_is_held_and_wrong_hash_releases_fd(self):
        observer = self.observer()
        pid = os.getpid()
        pidfd, start = self.actor(pid)
        expected = hashlib.sha256(Path(f'/proc/{pid}/exe').read_bytes()).digest()
        before = set(Path('/proc/self/fd').iterdir())
        with self.assertRaises(PermissionError):
            observer._pin_executable(pid, pidfd, start, bytes(32))
        self.assertEqual(set(Path('/proc/self/fd').iterdir()), before)
        self.assertFalse(observer._executable_files)
        observer._pin_executable(pid, pidfd, start, expected)
        self.assertTrue(observer._executable_live(pid))

    def test_exec_changes_identity_even_when_pid_and_start_time_are_unchanged(self):
        sleep = shutil.which('sleep')
        if sleep is None:
            self.skipTest('sleep executable required')
        code = ('import os,sys; print("ready",flush=True); sys.stdin.buffer.read(1); '
            'os.execl(sys.argv[1],sys.argv[1],"30")')
        child = self.process([sys.executable, '-c', code, sleep],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(child.stdout.readline(), b'ready\n')
        observer = self.observer()
        pidfd, start = self.actor(child.pid)
        expected = hashlib.sha256(Path(f'/proc/{child.pid}/exe').read_bytes()).digest()
        observer._pin_executable(child.pid, pidfd, start, expected)
        child.stdin.write(b'x')
        child.stdin.flush()
        deadline = time.monotonic() + 3
        while observer._executable_live(child.pid) and time.monotonic() < deadline:
            time.sleep(.001)
        self.assertFalse(observer._executable_live(child.pid))
        self.assertEqual(boot.identity._start_ticks(child.pid), start)
        self.assertTrue(boot.identity.process_alive(pidfd))

    def test_changed_metadata_of_same_held_executable_inode_is_rejected(self):
        sleep = shutil.which('sleep')
        if sleep is None:
            self.skipTest('sleep executable required')
        with tempfile.TemporaryDirectory(prefix='ker-exe-observe-') as directory:
            executable = Path(directory) / 'sleep'
            shutil.copy2(sleep, executable)
            child = self.process([str(executable), '30'])
            observer = self.observer()
            pidfd, start = self.actor(child.pid)
            expected = hashlib.sha256(executable.read_bytes()).digest()
            observer._pin_executable(child.pid, pidfd, start, expected)
            held, original = observer._executable_files[child.pid]
            os.utime(executable, ns=(executable.stat().st_atime_ns,
                original[3] + 1000000000))
            self.assertEqual(os.fstat(held).st_ino, original[1])
            self.assertFalse(observer._executable_live(child.pid))


if __name__ == '__main__':
    unittest.main()
