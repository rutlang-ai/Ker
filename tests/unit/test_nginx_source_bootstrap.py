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
from unittest import mock
from types import SimpleNamespace
import struct

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


@unittest.skipUnless(hasattr(os, 'pidfd_open'), 'Linux pidfds required')
class AbortedRetryAuthorityTests(unittest.TestCase):
    """Reject invalid retry provenance before transferring the retry slot.

    Real pidfds/FIFOs exercise the identity guards; memory below models only
    the original source block. This is not a Nginx or native selector proof.
    """
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='ker-retry-authority-')
        self.addCleanup(self.directory.cleanup)
        self.old = subprocess.Popen(['sleep', '30'])
        self.dead = subprocess.Popen(['sleep', '30'])
        def stop(child):
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=3)
        self.addCleanup(stop, self.old)
        self.addCleanup(stop, self.dead)
        self.oldfd = os.pidfd_open(self.old.pid)
        self.deadfd = os.pidfd_open(self.dead.pid)
        self.addCleanup(os.close, self.oldfd)
        self.addCleanup(os.close, self.deadfd)
        self.oldstart = boot.identity._start_ticks(self.old.pid)
        self.dead.terminate(); self.dead.wait(timeout=3)
        def fifo(name):
            path = Path(self.directory.name) / name
            os.mkfifo(path)
            reader = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
            self.addCleanup(os.close, reader)
            return path
        self.paths = [fifo(name) for name in ('old', 'aborted', 'fresh')]
        def record(pid, start, path):
            r = [0] * 29
            r[5], r[11] = pid, start
            value = path.stat();r[24:26] = value.st_dev, value.st_ino
            return tuple(r)
        self.observer = boot.SourceBootstrapSupervisor.__new__(boot.SourceBootstrapSupervisor)
        self.observer.live = lambda: None  # Actor/executable live() has separate controls.
        self.observer.allow_abort_retry = True
        self.observer.master = SimpleNamespace(pid=os.getpid())
        self.observer.slim_reply = [0] * 29; self.observer.slim_reply[13] = 4096
        self.observer.workers = {(0, 0): (self.oldfd, record(self.old.pid,self.oldstart,self.paths[0])),
            (1, 1): (self.deadfd, record(self.dead.pid,0,self.paths[1]))}
        self.observer._completed_master_barriers = {(1, 5), (1, 9)}
        self.observer._native_retry_cookie = 7001
        self.prefix = (0x46524c4d,1,2160,1,0,1,0,0)
        self.markers = (0,0,0)
        def memory(pid,address,length):
            return struct.pack('=8I',*self.prefix) if length==32 else struct.pack('=3I',*self.markers)
        self.patch = mock.patch.object(boot,'memory',side_effect=memory)
        self.patch.start();self.addCleanup(self.patch.stop)
        self.calls = 0

    def acquire(self, index=2):
        self.calls += 1
        return os.open(self.paths[index],os.O_WRONLY|os.O_NONBLOCK)

    def test_missing_or_unknown_abort_receipt_never_issues_retry_slot(self):
        self.observer._completed_master_barriers = {(1,5)}
        with self.assertRaises(PermissionError):self.observer.prepare_aborted_retry(self.acquire)
        self.assertEqual(self.calls,0)

    def test_unknown_native_adoption_never_issues_retry_slot(self):
        self.observer._native_retry_cookie = 0
        with self.assertRaises(PermissionError):self.observer.prepare_aborted_retry(self.acquire)
        self.assertEqual(self.calls,0)

    def test_dead_old_owner_never_issues_retry_slot(self):
        self.old.terminate();self.old.wait(timeout=3)
        with self.assertRaises(PermissionError):self.observer.prepare_aborted_retry(self.acquire)
        self.assertEqual(self.calls,0)

    def test_original_epoch2_or_nonidle_block_cannot_authorize_retry(self):
        self.prefix = (0x46524c4d,1,2160,2,0,1,1,0)
        with self.assertRaises(PermissionError):self.observer.prepare_aborted_retry(self.acquire)
        self.assertEqual(self.calls,0)

    def test_reused_aborted_fifo_is_rejected_and_attempt_stays_consumed(self):
        with self.assertRaises(PermissionError):
            self.observer.prepare_aborted_retry(lambda:self.acquire(1))
        with self.assertRaises(PermissionError):self.observer.prepare_aborted_retry(self.acquire)
        self.assertEqual(self.calls,1)

    def test_failed_slot_transfer_cannot_be_replayed(self):
        def failed():
            self.calls += 1
            raise OSError('native slot transfer unconfirmed')
        with self.assertRaises(OSError):self.observer.prepare_aborted_retry(failed)
        with self.assertRaises(PermissionError):self.observer.prepare_aborted_retry(self.acquire)
        self.assertEqual(self.calls,1)

    def test_fresh_fifo_consumed_once_and_original_tombstone_retained(self):
        fd = self.observer.prepare_aborted_retry(self.acquire)
        try:
            self.assertEqual(self.observer._retry_slot,(os.fstat(fd).st_dev,os.fstat(fd).st_ino))
            self.assertEqual(self.observer.workers[(1,1)][0],self.deadfd)
            with self.assertRaises(PermissionError):self.observer.prepare_aborted_retry(self.acquire)
            self.assertEqual(self.calls,1)
        finally:os.close(fd)


if __name__ == '__main__':
    unittest.main()
