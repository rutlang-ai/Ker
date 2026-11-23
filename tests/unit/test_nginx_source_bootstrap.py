"""Real-process controls for the bootstrap's pinned executable observations."""
import hashlib
import array
import errno
import importlib.util
import os
from pathlib import Path
import shutil
import select
import subprocess
import socket
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


class ControlOnlyAuthorityTests(unittest.TestCase):
    def test_control_context_rejects_worker_master_and_full_slim_grants(self):
        observer = boot.SourceBootstrapSupervisor.__new__(boot.SourceBootstrapSupervisor)
        observer.control_only = True
        observer.shell_mode = True
        for invoke in (
                lambda: observer.reply_slim(None, b'', (), control_only=False),
                lambda: observer.reply_worker(None, b'', (), -1, None),
                lambda: observer.reply_initial_worker(None, b'', (), object(), None, 1),
                lambda: observer.master_barrier(None, b'', (), lambda: None),
                lambda: observer.activate_worker(None, {})):
            with self.subTest(call=invoke), self.assertRaises(OSError) as caught:
                invoke()
            self.assertEqual(caught.exception.errno, errno.ENOTSUP)

    def test_control_only_registered_ack_without_private_origin_cannot_activate(self):
        observer = boot.SourceBootstrapSupervisor.__new__(boot.SourceBootstrapSupervisor)
        observer.control_only = True
        observer.shell_mode = True
        observer.epoch = 77
        observer.live = lambda *_: None
        initial = boot.SourceCycleProof(1, 0, 1, 0x1000, b'i' * 32, b'n' * 32)
        candidate_proof = boot.SourceCycleProof(1, 0, 2, 0x2000, b'i' * 32, b'n' * 32)
        observer.initial_cycle_proof = initial
        observer.worker_proofs = {(0, 0): initial, (1, 1): candidate_proof}
        left, right = socket.socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        observer.workers = {(0, 0): (1, ()), (1, 1): (2, ())}
        observer.worker_channels = {(0, 0): left, (1, 1): right}
        observer._activated_workers = set()
        observer._completed_master_barriers = set()
        observer._source_shell_committed_plans = {}
        observer._source_route_park_joins = {}
        observer._source_prepared_activation_attempts = set()

        candidate = (123, 124, 1, 125, 126, 127, 128, 0, 0)
        fields = [0] * 23
        fields[2] = 5
        fields[5:8] = candidate[:3]
        fields[8:10] = (0, observer.epoch)
        fields[11:15] = candidate[3:7]
        prepared = SimpleNamespace(fields=list(fields), operation_id=31,
            source_epoch=1, command_sequence=1)
        actors = (123, os.getuid(), os.getgid())
        preparation = boot._SourceRoutePreparation(boot._SOURCE_HANDOFF_TOKEN,
            observer, None, prepared, tuple(fields), 31, 1, 1, None, (),
            (0, 0), initial, None, candidate, (1, 1), candidate_proof,
            candidate_proof, right, boot._source_socket_identity(right), actors,
            b'ack', b'ack', (123, os.getuid(), os.getgid()), left,
            boot._source_socket_identity(left)[:4])
        prepared._source_route_preparation = preparation
        observer._source_route_preparations = {id(prepared): preparation}
        watch = {'source_epoch': 1, 'generation': 1, 'role': 1,
            'pid': candidate[0], 'tid': candidate[1], 'start': candidate[3],
            'slot_device': candidate[4], 'slot_inode': candidate[5],
            'cookie': candidate[6]}
        sent = []
        observer._activate_worker_body = lambda channel, value: sent.append((channel, value))
        with self.assertRaisesRegex(PermissionError, 'NEWC34 profile and Origin'):
            boot.SourceBootstrapSupervisor.activate_prepared_first_candidate(
                observer, prepared, right, watch, SimpleNamespace(), SimpleNamespace())
        self.assertEqual(sent, [])
        self.assertTrue(observer.control_only)
        self.assertEqual(observer._source_prepared_activation_attempts, set())


class InitialWorkerGrantSendTests(unittest.TestCase):
    def test_full_seqpacket_buffer_is_one_nonblocking_attempt(self):
        sender, receiver = socket.socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
        self.addCleanup(sender.close)
        self.addCleanup(receiver.close)
        self.addCleanup(os.close, read_fd)
        self.addCleanup(os.close, write_fd)
        sent = 0
        while True:
            try:
                sender.send(b'F' * 4096)
                sent += 1
            except BlockingIOError:
                break
        self.assertGreater(sent, 0)
        # Model an accepted Origin socket left in positive-timeout mode by
        # recvmsg. The grant helper must clear Python's poll-before-send mode.
        sender.settimeout(1.0)
        deadline = time.monotonic_ns() + 1_000_000_000
        started = time.monotonic()
        with self.assertRaises(BlockingIOError):
            boot.send_initial_worker_grant(sender, b'grant', array.array('i', [read_fd]), deadline)
        self.assertLess(time.monotonic() - started, 0.2)
        self.assertEqual(sender.gettimeout(), 0.0)
        self.assertLess(time.monotonic_ns(), deadline)

    def test_real_send_after_absolute_deadline_is_unknown_and_never_success(self):
        sender, receiver = socket.socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
        fd = os.open('/dev/null', os.O_RDONLY | os.O_CLOEXEC)
        self.addCleanup(sender.close)
        self.addCleanup(receiver.close)
        self.addCleanup(os.close, fd)
        deadline = 100
        with mock.patch.object(boot.time, 'monotonic_ns', side_effect=(99, 101)):
            with self.assertRaises(TimeoutError):
                boot.send_initial_worker_grant(sender, b'grant', array.array('i', [fd]), deadline)
        packet, ancillary, flags, _ = receiver.recvmsg(16, socket.CMSG_SPACE(4))
        self.assertEqual(packet, b'grant')
        rights = []
        for level, kind, payload in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                values = array.array('i')
                values.frombytes(payload[:len(payload) - len(payload) % values.itemsize])
                rights.extend(values)
        self.assertEqual(len(rights), 1)
        self.assertTrue(flags & getattr(socket, 'MSG_CMSG_CLOEXEC', 0) or not flags)
        for received in rights:
            os.close(received)

    def test_short_send_is_failed_once(self):
        class ShortSocket:
            calls = 0
            def setblocking(self, _value):
                pass
            def sendmsg(self, *_args):
                self.calls += 1
                return 2
        channel = ShortSocket()
        deadline = time.monotonic_ns() + 1_000_000_000
        with self.assertRaises(OSError):
            boot.send_initial_worker_grant(channel, b'grant', array.array('i', [0]), deadline)
        self.assertEqual(channel.calls, 1)


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


@unittest.skipUnless(hasattr(os, 'pidfd_open'), 'Linux pidfds required')
class SuccessfulSuccessorAuthorityTests(unittest.TestCase):
    """Real pidfd/FIFO lineage controls; source memory is a model only."""
    acquire = AbortedRetryAuthorityTests.acquire

    def setUp(self):
        AbortedRetryAuthorityTests.setUp(self)
        prior = self.observer.workers
        self.observer.workers = {(0, 0): prior[(1, 1)], (1, 1): prior[(0, 0)]}
        self.observer.allow_abort_retry = False
        self.observer.allow_successor = True
        self.observer._completed_master_barriers = {(1, 5), (1, 6)}
        self.observer._native_committed_cookie = 7002
        self.prefix = (0x46524c4d, 1, 2160, 1, 1, 1, 0, 0)
        self.markers = (1, 0, 0)

    def adopt(self, index=2, cookie=7002):
        return self.acquire(index), cookie

    def test_committed_actor_and_dead_predecessor_are_retained(self):
        before = dict(self.observer.workers)
        fd = self.observer.prepare_successful_successor(self.adopt)
        try:
            self.assertEqual(self.observer.workers, before)
            self.assertEqual(self.observer._source_round(2), (1, 0))
            self.assertEqual(self.observer._successor_slot,
                (os.fstat(fd).st_dev, os.fstat(fd).st_ino))
            with self.assertRaises(PermissionError):
                self.observer.prepare_successful_successor(self.adopt)
            self.assertEqual(self.calls, 1)
        finally:
            os.close(fd)

    def test_aborted_round_is_not_a_successful_successor(self):
        self.observer._completed_master_barriers = {(1, 5), (1, 9)}
        with self.assertRaises(PermissionError):
            self.observer.prepare_successful_successor(self.adopt)
        self.assertEqual(self.calls, 0)


    def test_live_previous_peer_blocks_adoption(self):
        _, record = self.observer.workers[(0, 0)]
        self.observer.workers[(0, 0)] = (self.oldfd, record)
        with self.assertRaises(PermissionError):
            self.observer.prepare_successful_successor(self.adopt)
        self.assertEqual(self.calls, 0)

    def test_dead_current_actor_blocks_adoption(self):
        self.old.terminate(); self.old.wait(timeout=3)
        with self.assertRaises(PermissionError):
            self.observer.prepare_successful_successor(self.adopt)
        self.assertEqual(self.calls, 0)

    def test_wrong_listener_cookie_consumes_attempt_and_closes_fifo(self):
        received = []
        def wrong():
            fd, _ = self.adopt()
            received.append(fd)
            return fd, 7003
        with self.assertRaises(PermissionError):
            self.observer.prepare_successful_successor(wrong)
        with self.assertRaises(OSError):
            os.fstat(received[0])
        with self.assertRaises(PermissionError):
            self.observer.prepare_successful_successor(self.adopt)
        self.assertEqual(self.calls, 1)

    def test_reused_current_fifo_is_not_a_fresh_candidate(self):
        with self.assertRaises(PermissionError):
            self.observer.prepare_successful_successor(lambda: self.adopt(index=0))
        self.assertEqual(self.calls, 1)

    def test_changed_source_round_blocks_native_adoption(self):
        self.prefix = (0x46524c4d, 1, 2160, 2, 1, 0, 1, 1)
        with self.assertRaises(PermissionError):
            self.observer.prepare_successful_successor(self.adopt)
        self.assertEqual(self.calls, 0)

    def test_expired_authority_never_calls_native_adoption(self):
        def expired():
            raise PermissionError('finite grant expired')
        self.observer.live = expired
        with self.assertRaises(PermissionError):
            self.observer.prepare_successful_successor(self.adopt)
        self.assertEqual(self.calls, 0)

class ShellCycleEnvelopeTests(unittest.TestCase):
    CONFIG = bytes.fromhex('11' * 32)
    INI = bytes.fromhex('22' * 32)

    def setUp(self):
        self.initial = boot.SourceCycleProof(1, 0, 7, 0x100000,
            self.CONFIG, self.INI)
        self.observer = boot.SourceBootstrapSupervisor.__new__(
            boot.SourceBootstrapSupervisor)
        self.observer.shell_mode = True
        self.observer.record_struct = boot.SHELL_RECORD
        self.observer.symbols = {'ngx_cycle': 0x404000}
        self.observer.expected_config_sha256 = self.CONFIG
        self.observer.expected_ini_sha256 = self.INI
        self.observer.initial_cycle_proof = self.initial
        self.observer._used_cycle_proofs = set()
        self.observer._cycle_serial_highwater = self.initial.adapter_cycle_serial

    @staticmethod
    def fields(proof):
        return [0] * 29 + list(proof)

    def record(self, operation, flags, proof, *, actor=0, generation=1, source_epoch=1):
        record = [0] * 35
        record[:5] = [boot.MAGIC, boot.SHELL_VERSION, operation,
            boot.SHELL_RECORD.size, flags]
        record[5] = actor
        record[6] = actor
        record[7] = 1
        record[8] = generation
        record[9] = source_epoch
        record[11] = 101
        record[12] = 202
        record[13] = 0x9000
        record[14] = 3
        record[15] = 999999999999999999
        record[16] = bytes.fromhex('55' * 16)
        record[29:] = list(proof)
        return record

    def connected_child(self):
        import socket
        path = str(Path(tempfile.mkdtemp(prefix='ker-shell-cycle-')) / 'actor.sock')
        self.addCleanup(lambda: shutil.rmtree(str(Path(path).parent), ignore_errors=True))
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        listener.bind(path)
        listener.listen(1)
        pid = os.fork()
        if pid == 0:
            listener.close()
            child = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            child.connect(path)
            while True:
                time.sleep(1)
        channel, _ = listener.accept()
        listener.close()
        def reap():
            channel.close()
            try:
                os.kill(pid, 9)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
        self.addCleanup(reap)
        return pid, channel

    def observer_for_worker(self, pid):
        observer = self.observer
        observer.master = SimpleNamespace(pid=os.getpid(), start_ticks=boot.identity._start_ticks(os.getpid()))
        observer.runtime = SimpleNamespace(pid=os.getpid(), start_ticks=1,
            pidfd=os.pidfd_open(os.getpid()))
        observer.io = SimpleNamespace(pid=os.getpid(), start_ticks=1,
            pidfd=os.pidfd_open(os.getpid()))
        self.addCleanup(os.close, observer.runtime.pidfd)
        self.addCleanup(os.close, observer.io.pidfd)
        observer.binary_hash = bytes.fromhex('aa' * 32)
        observer.supervisor_start = boot.identity._start_ticks(os.getpid())
        observer.epoch = 3
        observer.deadline_ns = time.monotonic_ns() + 10_000_000_000
        observer.nonce = bytes.fromhex('55' * 16)
        observer.slim_pidfd = os.pidfd_open(os.getpid())
        self.addCleanup(os.close, observer.slim_pidfd)
        observer.slim_reply = [0] * 29
        observer.slim_reply[20] = 1
        observer.workers = {}
        observer.worker_proofs = {}
        observer._used_cycle_proofs = set()
        observer._cycle_serial_highwater = self.initial.adapter_cycle_serial
        observer.live = lambda *args, **kwargs: None
        observer._source_round = lambda epoch: (0, 1) if epoch == 1 else (_ for _ in ()).throw(PermissionError())
        self.source_prefix = (0x46524c4d, 1, 128, 1, 0, 1, 1, 0)
        def scalar(actor, name, code):
            return {'ngx_cycle': 0x200000, 'ngx_process': 3, 'ngx_worker': 0,
                'ngx_ff_process': 2, 'ngx_ff_graceful_reload': 1,
                'ngx_ff_reload_shm': 0x9000, 'ngx_process_slot': 4}[name]
        observer._scalar = scalar
        return observer

    def worker_request(self, pid, proof):
        record = self.record(1, 1, proof, actor=pid)
        record[7] = os.getpid()
        record[11] = boot.identity._start_ticks(pid)
        record[12] = boot.identity._start_ticks(os.getpid())
        record[14] = self.observer.epoch
        record[15] = self.observer.deadline_ns
        record[16] = self.observer.nonce
        return boot.SHELL_RECORD.pack(*record)

    def worker_grant_fixture(self, *, change_before_grant=False):
        import socket
        pid, channel = self.connected_child()
        observer = self.observer_for_worker(pid)
        observer.binary_hash = hashlib.sha256(Path(f'/proc/{pid}/exe').read_bytes()).digest()
        observer._executable_files = {}
        def close_worker_grant():
            # The fixture already owns cleanup of the separate slim descriptor.
            observer.slim_pidfd = -1
            observer.close()
        self.addCleanup(close_worker_grant)
        proof = boot.SourceCycleProof(1, 0, 8, 0x200000, self.CONFIG, self.INI)
        request = self.worker_request(pid, proof)
        directory = Path(tempfile.mkdtemp(prefix='ker-shell-slot-'))
        self.addCleanup(lambda: shutil.rmtree(directory, ignore_errors=True))
        fifo = directory / 'candidate.fifo'
        os.mkfifo(fifo)
        reader = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
        self.addCleanup(os.close, reader)
        slot_fd = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
        self.addCleanup(os.close, slot_fd)
        relay, relay_peer = socket.socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        self.addCleanup(relay.close)
        self.addCleanup(relay_peer.close)
        memory = mock.patch.object(boot, 'memory', side_effect=lambda p, a, n:
            struct.pack('=8I', *self.source_prefix) if n == 32 else bytes(n))
        shared = mock.patch.object(boot, 'shared_mapping', return_value=(0x9000, 0xa000, '00:00', '1'))
        memory.start(); shared.start()
        self.addCleanup(memory.stop); self.addCleanup(shared.stop)
        if change_before_grant:
            cycle_reads = {pid: 0}
            original_scalar = observer._scalar
            def scalar(actor, name, code):
                if name == 'ngx_cycle' and actor == pid:
                    cycle_reads[pid] += 1
                    if cycle_reads[pid] >= 2:
                        return 0x300000
                return original_scalar(actor, name, code)
            observer._scalar = scalar
        return observer, proof, request, pid, channel, relay, slot_fd

    def test_actual_slim_grant_rechecks_initial_cycle_pointer_before_send(self):
        observer = self.observer
        supervisor = os.getpid()
        slim_pid = supervisor + 1000
        observer.master = SimpleNamespace(pid=supervisor)
        observer.runtime = SimpleNamespace(pid=supervisor + 1, start_ticks=2,
            pidfd=os.pidfd_open(supervisor))
        observer.io = SimpleNamespace(pid=supervisor + 2, start_ticks=3,
            pidfd=os.pidfd_open(supervisor))
        self.addCleanup(os.close, observer.runtime.pidfd)
        self.addCleanup(os.close, observer.io.pidfd)
        observer.supervisor_start = boot.identity._start_ticks(supervisor)
        observer.binary_hash = bytes.fromhex('aa' * 32)
        observer.live = lambda *args, **kwargs: None
        observer._pin_executable = lambda *args, **kwargs: None
        observer.slim_proof = self.initial
        observer.shell_mode = True
        observer.record_struct = boot.SHELL_RECORD
        record = self.record(1, 0, self.initial, actor=slim_pid, generation=0,
            source_epoch=0)
        record[7] = supervisor
        record[11] = 99
        class NoSend:
            def __init__(self): self.calls = 0
            def sendmsg(self, *args, **kwargs):
                self.calls += 1
                return 0
        channel = NoSend()
        def scalar(pid, name, code):
            if name == 'ngx_cycle' and pid == slim_pid:
                return 0x300000
            return self.initial.opaque_cycle_token
        observer._scalar = scalar
        with mock.patch.object(observer, 'validate_slim', return_value=(record,
                os.pidfd_open(supervisor))) as validate:
            with self.assertRaisesRegex(PermissionError, 'ngx_cycle pointer'):
                observer.reply_slim(channel, b'wire', (slim_pid, os.getuid(), os.getgid()),
                    control_only=True)
        validate.assert_called_once()
        self.assertEqual(channel.calls, 0)
        self.assertEqual(observer.slim_pid, slim_pid)
        self.assertEqual(observer.slim_proof, self.initial)
        if observer.slim_pidfd >= 0:
            os.close(observer.slim_pidfd)
            observer.slim_pidfd = -1

    def test_v3_layout_stays_exact_and_v4_is_append_only(self):
        self.assertEqual(boot.RECORD.size, 176)
        self.assertEqual(boot.SHELL_RECORD.size, 264)
        self.assertEqual(boot.SHELL_RECORD.format,
            '=IHH8I5Q16s4I8QIIQQ32s32s')
        self.assertEqual(boot.required_source_exports(False), boot.SOURCE_EXPORT_SIZES)
        self.assertEqual(boot.required_source_exports(True),
            dict(boot.SOURCE_EXPORT_SIZES, ngx_cycle=8))
        with self.assertRaises(AttributeError):
            self.initial.opaque_cycle_token = 0x200000

    def test_shell_mode_rejects_v3_missing_and_unsupported_envelopes(self):
        shell_request = ([boot.MAGIC, boot.SHELL_VERSION, 1,
            boot.SHELL_RECORD.size, 0] + [0] * 6 + [0] * 5 + [bytes(16)]+
            [0] * 4 + [0] * 8 + [1, 0, 1, 1, bytes(32), bytes(32)])
        self.assertEqual(len(self.observer._unpack_request(
            boot.SHELL_RECORD.pack(*shell_request), 1, 0)), 35)
        legacy = ([boot.MAGIC, 3, 1, boot.RECORD.size, 0] + [0] * 6 + [0] * 5 +
            [bytes(16)] + [0] * 4 + [0] * 8)
        for packet in (boot.RECORD.pack(*legacy),
                boot.SHELL_RECORD.pack(*(shell_request[:1] + [3] + shell_request[2:])),
                boot.SHELL_RECORD.pack(*(shell_request[:3] + [boot.RECORD.size] +
                    shell_request[4:]))):
            with self.subTest(size=len(packet), version=packet[4:6]):
                with self.assertRaises(PermissionError):
                    self.observer._unpack_request(packet, 1, 0)

        legacy_observer = boot.SourceBootstrapSupervisor.__new__(
            boot.SourceBootstrapSupervisor)
        legacy_observer.shell_mode = False
        legacy_observer.record_struct = boot.RECORD
        self.assertEqual(len(legacy_observer._unpack_request(
            boot.RECORD.pack(*legacy), 1, 0)), 29)

    def test_shell_constructor_proof_is_typed_complete_and_digest_bound(self):
        self.assertIs(boot._validate_cycle_proof(self.initial, self.CONFIG, self.INI),
            self.initial)
        invalid = (
            (boot.SourceCycleProof(2, 0, 7, 0x100000, self.CONFIG, self.INI), self.CONFIG, self.INI),
            (boot.SourceCycleProof(1, 1, 7, 0x100000, self.CONFIG, self.INI), self.CONFIG, self.INI),
            (boot.SourceCycleProof(1, 0, 0, 0x100000, self.CONFIG, self.INI), self.CONFIG, self.INI),
            (boot.SourceCycleProof(1, 0, 7, 0, self.CONFIG, self.INI), self.CONFIG, self.INI),
            (boot.SourceCycleProof(1, 0, 7, 0x100000, self.CONFIG, self.INI), bytes(32), self.INI),
            (object(), self.CONFIG, self.INI),
        )
        for proof, config, ini in invalid:
            with self.subTest(proof=proof):
                with self.assertRaises(PermissionError):
                    boot._validate_cycle_proof(proof, config, ini)
        with self.assertRaises(PermissionError):
            boot._validate_cycle_proof(self.initial, self.CONFIG, b'bad')

    def test_initial_record_must_echo_origin_proof_and_candidate_must_be_fresh(self):
        initial_record = self.fields(self.initial)
        self.assertIs(self.observer._initial_cycle_proof_matches(initial_record),
            self.initial)
        wrong_initial = list(initial_record)
        wrong_initial[32] = 0x200000
        with self.assertRaises(PermissionError):
            self.observer._initial_cycle_proof_matches(wrong_initial)

        candidate = boot.SourceCycleProof(1, 0, 8, 0x200000, self.CONFIG, self.INI)
        self.assertEqual(self.observer._fresh_candidate_cycle_proof(
            self.fields(candidate)), candidate)
        self.observer._used_cycle_proofs.add((candidate.adapter_cycle_serial,
            candidate.opaque_cycle_token))
        self.observer._cycle_serial_highwater = candidate.adapter_cycle_serial
        with self.assertRaises(PermissionError):
            self.observer._fresh_candidate_cycle_proof(self.fields(candidate))
        reused_serial = candidate._replace(adapter_cycle_serial=self.initial.adapter_cycle_serial,
            opaque_cycle_token=0x300000)
        with self.assertRaises(PermissionError):
            self.observer._fresh_candidate_cycle_proof(self.fields(reused_serial))
        reused_pointer_new_cycle = candidate._replace(adapter_cycle_serial=9,
            opaque_cycle_token=self.initial.opaque_cycle_token)
        self.assertEqual(self.observer._fresh_candidate_cycle_proof(
            self.fields(reused_pointer_new_cycle)), reused_pointer_new_cycle)
        wrong_digest = candidate._replace(config_sha256=bytes.fromhex('33' * 32))
        with self.assertRaises(PermissionError):
            self.observer._fresh_candidate_cycle_proof(self.fields(wrong_digest))

    def test_exported_cycle_pointer_is_required_only_in_shell_mode(self):
        with mock.patch.object(self.observer, '_scalar', return_value=self.initial.opaque_cycle_token):
            self.observer.symbols = {'ngx_cycle': 0x404000}
            self.observer._cycle_token_live(123, self.initial.opaque_cycle_token)
        with mock.patch.object(self.observer, '_scalar', return_value=0x200000):
            with self.assertRaises(PermissionError):
                self.observer._cycle_token_live(123, self.initial.opaque_cycle_token)
        self.observer.shell_mode = False
        self.observer.symbols = {}
        self.observer._cycle_token_live(123, 0)

    def test_actual_worker_grant_rechecks_cycle_pointer_before_any_capability_send(self):
        observer, proof, request, pid, channel, relay, slot_fd = self.worker_grant_fixture(
            change_before_grant=True)
        class Spy:
            def __init__(self, wrapped):
                self.wrapped = wrapped
                self.sent = []
            def getsockopt(self, *args):
                return self.wrapped.getsockopt(*args)
            def sendmsg(self, data, *args, **kwargs):
                self.sent.append(data[0])
                return self.wrapped.sendmsg(data, *args, **kwargs)
        spy = Spy(channel)
        with self.assertRaisesRegex(PermissionError, 'ngx_cycle pointer'):
            observer.reply_worker(spy, request,
                (pid, os.getuid(), os.getgid()), slot_fd, relay)
        self.assertEqual(spy.sent, [])
        self.assertNotIn((1, 1), observer.workers)
        self.assertFalse(observer._executable_live(pid))
        self.assertNotIn((1, 1), observer.worker_proofs)
        self.assertEqual(observer._cycle_serial_highwater, self.initial.adapter_cycle_serial)

    def test_actual_failed_worker_send_consumes_proof_and_cannot_be_replayed(self):
        observer, proof, request, pid, channel, relay, slot_fd = self.worker_grant_fixture()
        class ShortSend:
            def __init__(self, wrapped):
                self.wrapped = wrapped
                self.calls = 0
            def getsockopt(self, *args):
                return self.wrapped.getsockopt(*args)
            def sendmsg(self, data, *args, **kwargs):
                self.calls += 1
                return len(data[0]) - 1
        channel = ShortSend(channel)
        with self.assertRaisesRegex(PermissionError, 'short source worker grant'):
            observer.reply_worker(channel, request,
                (pid, os.getuid(), os.getgid()), slot_fd, relay)
        self.assertTrue(observer._executable_live(pid))
        self.assertEqual(observer.worker_proofs[(1, 1)], proof)
        self.assertEqual(observer._cycle_serial_highwater, proof.adapter_cycle_serial)
        with self.assertRaisesRegex(PermissionError, 'candidate cycle serial is stale'):
            observer.reply_worker(channel, request,
                (pid, os.getuid(), os.getgid()), slot_fd, relay)
        self.assertEqual(channel.calls, 1)

    def test_actual_activation_rejects_changed_pointer_and_wrong_granted_proof(self):
        pid, channel = self.connected_child()
        observer = self.observer_for_worker(pid)
        observer.slim_pidfd = os.pidfd_open(os.getpid())
        self.addCleanup(os.close, observer.slim_pidfd)
        proof = boot.SourceCycleProof(1, 0, 8, 0x200000, self.CONFIG, self.INI)
        record = self.record(2, 1, proof, actor=pid)
        record[7] = os.getpid()
        record[11] = boot.identity._start_ticks(pid)
        record[12] = observer.master.start_ticks
        record[20] = 4
        pidfd = os.pidfd_open(pid)
        self.addCleanup(os.close, pidfd)
        observer.workers[(1, 1)] = (pidfd, tuple(record))
        observer.worker_proofs[(1, 1)] = proof
        observer._activated_workers = set()
        prefix = struct.pack('=8I', *self.source_prefix)
        with mock.patch.object(boot, 'memory', return_value=prefix):
            class Capture:
                def __init__(self, wrapped): self.wrapped, self.sent, self.short = wrapped, [], False
                def getsockopt(self, *args): return self.wrapped.getsockopt(*args)
                def setblocking(self, value): self.wrapped.setblocking(value)
                def send(self, payload, *args):
                    self.sent.append(payload)
                    return len(payload) - 1 if self.short else len(payload)
            channel = Capture(channel)
            calls = {pid: 0}
            original_scalar = observer._scalar
            def changed_pointer(actor, name, code):
                if name == 'ngx_cycle' and actor == pid:
                    calls[pid] += 1
                    if calls[pid] >= 2: return 0x300000
                return 0x200000 if name == 'ngx_cycle' else original_scalar(actor, name, code)
            observer._scalar = changed_pointer
            watch = {'source_epoch': 1, 'generation': 1, 'pid': pid}
            with self.assertRaisesRegex(PermissionError, 'ngx_cycle pointer'):
                observer.activate_worker(channel, watch)
            self.assertEqual(channel.sent, [])
            self.assertNotIn((1, 1), observer._activated_workers)
            self.assertNotIn((1, 1), getattr(observer, '_activation_attempts', set()))

            wrong = list(record)
            wrong[33] = bytes.fromhex('33' * 32)
            observer.workers[(1, 1)] = (pidfd, tuple(wrong))
            with self.assertRaisesRegex(PermissionError, 'transcript digests'):
                observer.activate_worker(channel, watch)
            self.assertEqual(channel.sent, [])

            observer.workers[(1, 1)] = (pidfd, tuple(record))
            observer._scalar = original_scalar
            channel.short = True
            with self.assertRaisesRegex(PermissionError, 'short source activation send'):
                observer.activate_worker(channel, watch)
            self.assertEqual(observer._activation_attempts, {(1, 1)})
            self.assertNotIn((1, 1), observer._activated_workers)
            with self.assertRaisesRegex(PermissionError, 'candidate/channel changed identity'):
                observer.activate_worker(channel, watch)
            self.assertEqual(len(channel.sent), 1)

    def test_source_activation_does_not_wait_for_full_unix_queue(self):
        pid, channel = self.connected_child()
        observer = self.observer_for_worker(pid)
        proof = boot.SourceCycleProof(1, 0, 8, 0x200000, self.CONFIG, self.INI)
        record = list(boot.SHELL_RECORD.unpack(self.worker_request(pid, proof)))
        record[2] = 2
        record[20] = 4
        pidfd = os.pidfd_open(pid)
        self.addCleanup(os.close, pidfd)
        observer.workers[(1, 1)] = (pidfd, tuple(record))
        observer.worker_proofs[(1, 1)] = proof
        channel.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        payload = boot.SHELL_RECORD.pack(*record)
        for _ in range(64):
            try:
                channel.send(payload, socket.MSG_DONTWAIT)
            except BlockingIOError:
                break
        else:
            self.fail('the model actor did not fill the real Unix send queue')
        channel.settimeout(0.5)
        watch = {'source_epoch': 1, 'generation': 1, 'pid': pid}
        with mock.patch.object(boot, 'memory', return_value=struct.pack('=8I', *self.source_prefix)):
            with self.assertRaises(BlockingIOError):
                observer.activate_worker(channel, watch)
            self.assertEqual(channel.gettimeout(), 0.0)
            self.assertEqual(observer._activation_attempts, {(1, 1)})
            self.assertNotIn((1, 1), getattr(observer, '_activated_workers', set()))
            with self.assertRaisesRegex(PermissionError, 'candidate/channel changed identity'):
                observer.activate_worker(channel, watch)

    @unittest.skipUnless(os.environ.get('KER_FSTACK_ACTIVATION_RECEIVER'),
        'compiled C activation fixture not supplied')
    def test_source_activation_reaches_real_c_receiver(self):
        executable = os.environ['KER_FSTACK_ACTIVATION_RECEIVER']
        for mode, status, activated in (('accept', 1, 1), ('reject', -errno.EPROTO, 0)):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix='ker-activate-') as root:
                with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as listener:
                    endpoint = str(Path(root) / 'worker.sock')
                    listener.bind(endpoint)
                    listener.listen(1)
                    listener.settimeout(2)
                    child = subprocess.Popen([executable, '--receive-activate', endpoint, mode],
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    try:
                        self.assert_activate_receiver(listener, child, status, activated)
                    finally:
                        if child.poll() is None:
                            child.kill()
                        child.communicate(timeout=2)

    def assert_activate_receiver(self, listener, child, status, activated):
        channel, _ = listener.accept()
        with channel:
            observer = self.observer_for_worker(child.pid)
            observer._activated_workers = set()
            observer._activation_attempts = set()
            proof = boot.SourceCycleProof(1, 0, 8, 0x200000, self.CONFIG, self.INI)
            record = list(boot.SHELL_RECORD.unpack(self.worker_request(child.pid, proof)))
            record[2] = 2
            record[17:20] = [os.getpid()] * 3
            record[20] = 4
            record[21:24] = [observer.supervisor_start] * 3
            pidfd = os.pidfd_open(child.pid)
            self.addCleanup(os.close, pidfd)
            observer.workers[(1, 1)] = (pidfd, tuple(record))
            observer.worker_proofs[(1, 1)] = proof
            child.stdin.write(boot.SHELL_RECORD.pack(*record))
            child.stdin.flush()
            self.assertTrue(select.select([child.stdout], [], [], 2)[0])
            self.assertEqual(child.stdout.readline(), b'RECEIVER_READY\n')
            watch = {'source_epoch': 1, 'generation': 1, 'pid': child.pid}
            with mock.patch.object(boot, 'memory',
                    return_value=struct.pack('=8I', *self.source_prefix)):
                observer.activate_worker(channel, watch)
            output, errors = child.communicate(timeout=3)
            self.assertEqual(child.returncode, 0, errors + output)
            self.assertEqual(output, f'ACTIVATE status={status} accepted={activated}\n'.encode())

    def test_actual_master_barrier_rejects_unaccepted_proof_without_apply_or_receipt(self):
        pid, connected = self.connected_child()
        observer = self.observer
        observer.shell_mode = True
        observer.record_struct = boot.SHELL_RECORD
        observer.symbols = {'ngx_cycle': 0x404000}
        observer.master = SimpleNamespace(pid=pid,
            start_ticks=boot.identity._start_ticks(pid), executable_hash=bytes.fromhex('aa' * 32))
        observer.runtime = SimpleNamespace(pid=os.getpid(), pidfd=os.pidfd_open(os.getpid()))
        observer.io = SimpleNamespace(pid=os.getpid(), pidfd=os.pidfd_open(os.getpid()))
        self.addCleanup(os.close, observer.runtime.pidfd)
        self.addCleanup(os.close, observer.io.pidfd)
        observer.supervisor_start = boot.identity._start_ticks(os.getpid())
        observer.epoch = 3
        observer.deadline_ns = time.monotonic_ns() + 5_000_000_000
        observer.nonce = bytes.fromhex('55' * 16)
        observer.live = lambda *args, **kwargs: None
        observer._source_round = lambda epoch: (0, 1)
        observer.slim_reply = [0] * 29
        observer.slim_reply[13] = 0x9000
        candidate = boot.SourceCycleProof(1, 0, 8, 0x200000, self.CONFIG, self.INI)
        observer.worker_proofs = {(1, 1): candidate}
        observer._activated_workers = {(1, 1)}
        observer._master_barriers = set()
        observer._scalar = lambda actor, name, code: (
            0x9000 if name == 'ngx_ff_reload_shm' else
            candidate.opaque_cycle_token if name == 'ngx_cycle' else 0)
        values = (0x46524c4d, 1, 128, 1, 0, 1, 1, 0)
        markers = (0, 0, 2)
        def read_memory(actor, address, length):
            return struct.pack('=8I', *values) if length == 32 else struct.pack('=3I', *markers)
        record = [0] * 35
        record[:5] = [boot.MAGIC, boot.SHELL_VERSION, 5, boot.SHELL_RECORD.size, 0]
        record[3:11] = [boot.SHELL_RECORD.size, 2, pid, pid, pid, 1, 1, 0]
        record[11:13] = [observer.master.start_ticks, observer.master.start_ticks]
        record[13:17] = [0x9000, observer.epoch, observer.deadline_ns, observer.nonce]
        record[28] = time.monotonic_ns() + 80_000_000
        wrong = candidate._replace(ini_sha256=bytes.fromhex('44' * 32))
        record[29:] = list(wrong)
        class NoReceipt:
            def __init__(self, wrapped): self.wrapped, self.sent = wrapped, []
            def getsockopt(self, *args): return self.wrapped.getsockopt(*args)
            def sendmsg(self, data, *args, **kwargs): self.sent.append(data[0]); return len(data[0])
        channel = NoReceipt(connected)
        apply = mock.Mock(return_value=None)
        with mock.patch.object(boot, 'memory', side_effect=read_memory):
            with self.assertRaisesRegex(PermissionError, 'transcript digests'):
                observer.master_barrier(channel, boot.SHELL_RECORD.pack(*record),
                    (pid, os.getuid(), os.getgid()), apply)
        apply.assert_not_called()
        self.assertEqual(channel.sent, [])
        self.assertFalse(observer._master_barriers)



class SourceCommitEvidenceProducerTests(unittest.TestCase):
    """Exercise real op6 validation/receipt/notification ordering.

    Process identities and socket credentials are real; only pinned Nginx
    memory reads are modeled. This does not claim a running-source test.
    """
    CONFIG = bytes.fromhex('11' * 32)
    INI = bytes.fromhex('22' * 32)

    def setUp(self):
        self.master_pid, self.master_channel = ShellCycleEnvelopeTests.connected_child(self)
        self.observer = boot.SourceBootstrapSupervisor.__new__(
            boot.SourceBootstrapSupervisor)
        self.master_pidfd = os.pidfd_open(self.master_pid)
        self.addCleanup(os.close, self.master_pidfd)
        self.worker = subprocess.Popen(['sleep', '30'])
        def stop_worker():
            if self.worker.poll() is None:
                self.worker.terminate()
            self.worker.wait(timeout=3)
        self.addCleanup(stop_worker)
        self.worker_pidfd = os.pidfd_open(self.worker.pid)
        self.addCleanup(os.close, self.worker_pidfd)
        self.runtime_pidfd = os.pidfd_open(os.getpid())
        self.io_pidfd = os.pidfd_open(os.getpid())
        self.addCleanup(os.close, self.runtime_pidfd)
        self.addCleanup(os.close, self.io_pidfd)
        observer = self.observer
        observer.symbols = {'ngx_cycle': 0x404000}
        observer.shell_mode = True
        observer.record_struct = boot.SHELL_RECORD
        observer.master = SimpleNamespace(pid=self.master_pid,
            start_ticks=boot.identity._start_ticks(self.master_pid),
            pidfd=self.master_pidfd)
        observer.runtime = SimpleNamespace(pid=os.getpid(), pidfd=self.runtime_pidfd,
            start_ticks=boot.identity._start_ticks(os.getpid()))
        observer.io = SimpleNamespace(pid=os.getpid(), pidfd=self.io_pidfd,
            start_ticks=boot.identity._start_ticks(os.getpid()))
        observer.supervisor_start = boot.identity._start_ticks(os.getpid())
        observer.epoch = 17
        observer.deadline_ns = time.monotonic_ns() + 5_000_000_000
        observer.slim_pid = self.master_pid
        observer.slim_start_ticks = observer.master.start_ticks
        observer.slim_pidfd = self.master_pidfd
        observer.nonce = bytes.fromhex('55' * 16)
        observer.allow_successor = False
        observer.allow_abort_retry = False
        observer.live = lambda *args, **kwargs: None
        observer.slim_reply = [0] * 35
        observer.slim_reply[13] = 0x9000
        observer.expected_config_sha256 = self.CONFIG
        observer.expected_ini_sha256 = self.INI
        proof = boot.SourceCycleProof(1, 0, 8, 0x200000,
            self.CONFIG, self.INI)
        observer.worker_proofs = {(1, 1): proof}
        observer._activated_workers = {(1, 1)}
        observer._master_barriers = {(1, 5)}
        observer._completed_master_barriers = {(1, 5)}
        observer._source_shell_committed_plans = {}
        observer._master_control_deadlines = {}
        observer.worker_process_slots = {(1, 1): 3}
        observer._scalar = lambda actor, name, code: (
            0x9000 if name == 'ngx_ff_reload_shm' else
            proof.opaque_cycle_token if name == 'ngx_cycle' else 0)
        observer._cycle_token_live = lambda *args: None
        self.proof = proof
        self.state_values = (0x46524c4d, 1, 128, 1, 0, 1, 1, 0)
        self.state_markers = (1, 0, 2)
        candidate = [0] * 35
        worker_start = boot.identity._start_ticks(self.worker.pid)
        master_start = observer.master.start_ticks
        candidate[:17] = [boot.MAGIC, boot.SHELL_VERSION, 2,
            boot.SHELL_RECORD.size, 1, self.worker.pid, self.worker.pid,
            self.master_pid, 1, 1, 0, worker_start, master_start, 0x9000,
            observer.epoch, observer.deadline_ns, observer.nonce]
        self.start = boot.identity._start_ticks(os.getpid())
        candidate[17:20] = [os.getpid(), os.getpid(), os.getpid()]
        candidate[20] = 4
        candidate[21:24] = [observer.supervisor_start, self.start, self.start]
        candidate[24:29] = [1, 2, 3, 444, 0]
        candidate[29:] = list(proof)
        self.candidate = candidate
        self.assertEqual(candidate[4], 1)  # worker role
        self.assertEqual(candidate[20], 4)  # immutable candidate flag
        self.observer.workers = {(1, 1): (self.worker_pidfd, tuple(candidate))}
        self.worker_channel, self.worker_peer = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        self.addCleanup(self.worker_channel.close)
        self.addCleanup(self.worker_peer.close)
        observer.worker_channels = {(1, 1): self.worker_channel}

    def barrier_packet(self):
        deadline = time.monotonic_ns() + 80_000_000
        self.observer._master_control_deadlines[1] = deadline
        record = [0] * 35
        record[:17] = [boot.MAGIC, boot.SHELL_VERSION, 6,
            boot.SHELL_RECORD.size, 2, self.master_pid, self.master_pid,
            self.master_pid, 1, 1, 0, self.observer.master.start_ticks,
            self.observer.master.start_ticks, 0x9000, self.observer.epoch,
            self.observer.deadline_ns, self.observer.nonce]
        record[28] = deadline
        record[29:] = list(self.proof)
        return boot.SHELL_RECORD.pack(*record)

    def invoke(self, *, outcome=None, apply_error=None, master_short=False,
            evidence_short=False):
        observer = self.observer
        state_values, state_markers = self.state_values, self.state_markers
        worker_channel = self.worker_channel
        def read_memory(actor, address, length):
            return (struct.pack('=8I', *state_values) if length == 32 else
                struct.pack('=3I', *state_markers))
        wrapped = self.master_channel
        class MasterSend:
            def getsockopt(self, *args): return wrapped.getsockopt(*args)
            def setblocking(self, value): wrapped.setblocking(value)
            def sendmsg(self, data, ancillary=(), flags=0):
                if master_short: return len(data[0]) - 1
                return wrapped.sendmsg(data, ancillary, flags)
        class EvidenceSend:
            def fileno(self): return worker_channel.fileno()
            def sendmsg(self, data, ancillary=(), flags=0):
                if evidence_short: return len(data[0]) - 1
                return worker_channel.sendmsg(data, ancillary, flags)
        observer.worker_channels[(1, 1)] = EvidenceSend()
        callback = mock.Mock(side_effect=apply_error) if apply_error else \
            mock.Mock(return_value=outcome)
        with mock.patch.object(boot, 'memory', side_effect=read_memory):
            result = observer.master_barrier(MasterSend(), self.barrier_packet(),
                (self.master_pid, os.getuid(), os.getgid()), callback)
        return callback, result

    def test_actual_op6_sends_commit_evidence_and_records_cookie_only_after_both_sends(self):
        callback, _ = self.invoke(outcome={'native_current_cookie': 7123})
        callback.assert_called_once()
        self.assertIn((1, 6), self.observer._completed_master_barriers)
        committed = self.observer._source_shell_committed_plans[(1, 1)]
        self.assertEqual(committed['native_current_cookie'], 7123)
        packet = self.worker_peer.recv(boot.COMMIT_EVIDENCE_RECORD_BYTES)
        header = boot.PREEXIT_HEADER.unpack_from(packet)
        self.assertEqual(header, (boot.PREEXIT_MAGIC, boot.PREEXIT_VERSION,
            boot.COMMIT_EVIDENCE, boot.COMMIT_EVIDENCE_RECORD_BYTES, 0))
        vector = boot.SHELL_RECORD.unpack_from(packet, boot.PREEXIT_HEADER.size)
        self.assertEqual(vector[4], 1)
        self.assertEqual(vector[20], 4)
        self.assertEqual(struct.unpack_from('=Q', packet, len(packet) - 8)[0], 7123)

    def assert_uncommitted(self):
        self.assertNotIn((1, 6), self.observer._completed_master_barriers)
        self.assertNotIn((1, 1), self.observer._source_shell_committed_plans)
        with self.assertRaises(BlockingIOError):
            self.worker_peer.recv(boot.COMMIT_EVIDENCE_RECORD_BYTES,
                socket.MSG_DONTWAIT)

    def test_failed_apply_has_no_ack_or_commit_evidence(self):
        with self.assertRaisesRegex(RuntimeError, 'native apply failed'):
            self.invoke(apply_error=RuntimeError('native apply failed'))
        self.assert_uncommitted()

    def test_short_master_ack_has_no_commit_evidence_or_committed_cookie(self):
        with self.assertRaisesRegex(PermissionError, 'short source master native barrier receipt'):
            self.invoke(outcome={'native_current_cookie': 7123}, master_short=True)
        self.assert_uncommitted()

    def test_full_real_master_queue_cannot_wait_past_native_barrier_deadline(self):
        self.master_channel.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        filler = b'x' * boot.SHELL_RECORD.size
        for _ in range(64):
            try:
                self.master_channel.send(filler, socket.MSG_DONTWAIT)
            except BlockingIOError:
                break
        else:
            self.fail('the model master did not fill the Unix send queue')
        self.master_channel.settimeout(.5)
        with self.assertRaises(BlockingIOError):
            self.invoke(outcome={'native_current_cookie': 7123})
        self.assertEqual(self.master_channel.gettimeout(), 0.0)
        self.assertIn((1, 6), self.observer._master_barriers)
        self.assert_uncommitted()

    def test_short_worker_evidence_send_has_no_committed_cookie(self):
        with self.assertRaisesRegex(PermissionError, 'COMMIT evidence send failed'):
            self.invoke(outcome={'native_current_cookie': 7123}, evidence_short=True)
        self.assert_uncommitted()

    def test_full_real_seqpacket_buffer_expires_without_commit_proof(self):
        self.worker_channel.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024)
        filler = b'x' * boot.COMMIT_EVIDENCE_RECORD_BYTES
        queued = 0
        while True:
            try:
                self.worker_channel.send(filler, socket.MSG_DONTWAIT)
                queued += 1
            except BlockingIOError:
                break
        self.assertGreater(queued, 0)
        deadline = time.monotonic_ns() + 60_000_000
        self.candidate[15] = deadline
        self.observer.workers[(1, 1)] = (self.worker_pidfd, tuple(self.candidate))
        started = time.monotonic()
        with self.assertRaisesRegex(PermissionError, 'COMMIT evidence send failed'):
            self.invoke(outcome={'native_current_cookie': 7123})
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, .5)
        self.assertGreaterEqual(elapsed, .03)
        self.assertNotIn((1, 6), self.observer._completed_master_barriers)
        self.assertNotIn((1, 1), self.observer._source_shell_committed_plans)
        for _ in range(queued):
            self.assertEqual(self.worker_peer.recv(boot.COMMIT_EVIDENCE_RECORD_BYTES), filler)


class SourcePreexitProtocolTests(unittest.TestCase):
    def setUp(self):
        self.observer = boot.SourceBootstrapSupervisor.__new__(
            boot.SourceBootstrapSupervisor)
        self.observer.shell_mode = True
        self.observer.epoch = 17
        self.observer.deadline_ns = time.monotonic_ns() + 5_000_000_000
        self.observer.nonce = bytes.fromhex('55' * 16)
        self.observer.master = SimpleNamespace(pid=os.getpid(),
            start_ticks=boot.identity._start_ticks(os.getpid()))
        self.observer.allow_successor = False
        self.observer.allow_abort_retry = False
        self.observer._completed_master_barriers = {(1, 5), (1, 6)}
        self.observer._pending_preexits = {}
        self.observer._seen_preexit_ids = set()
        self.observer.worker_process_slots = {(1, 1): 3}
        self.observer.worker_channels = {}
        self.observer.worker_proofs = {}
        self.observer._source_shell_committed_plans = {}
        self.observer.workers = {}
        self.channel, self.peer = socket.socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        self.addCleanup(self.channel.close)
        self.addCleanup(self.peer.close)
        self.channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)

        pid = os.getpid()
        start = boot.identity._start_ticks(pid)
        self.pidfd = os.pidfd_open(pid)
        self.addCleanup(os.close, self.pidfd)
        proof = boot.SourceCycleProof(1, 0, 8, 0x200000,
            bytes.fromhex('11' * 32), bytes.fromhex('22' * 32))
        record = [0] * 35
        record[:11] = [boot.MAGIC, boot.SHELL_VERSION, 2,
            boot.SHELL_RECORD.size, 1, pid, pid, pid, 1, 1, 0]
        record[11:17] = [start, start, 0x9000, 17,
            self.observer.deadline_ns, self.observer.nonce]
        record[17:29] = [pid, pid, pid, 4, start, start, start,
            1, 2, 3, 444, 0]
        record[29:] = list(proof)
        key = (1, 1)
        self.observer.workers[key] = (self.pidfd, tuple(record))
        self.observer.worker_proofs[key] = proof
        self.observer.worker_channels[key] = self.channel
        self.record = record
        self.key = key
        self.proof = proof

    def packet(self, *, operation_id=901):
        record = list(self.record)
        record[2] = boot.PREEXIT_REQUEST
        deadline = min(self.observer.deadline_ns,
            time.monotonic_ns() + boot.PREEXIT_BUDGET_NS - 1_000_000)
        return (boot.PREEXIT_HEADER.pack(boot.PREEXIT_MAGIC,
            boot.PREEXIT_VERSION, boot.PREEXIT_REQUEST,
            boot.PREEXIT_RECORD_BYTES, 0) + boot.SHELL_RECORD.pack(*record) +
            boot.PREEXIT_TAIL.pack(3, 4, operation_id, deadline, 444))

    def test_preexit_requires_real_completed_commit_and_idle_snapshot(self):
        credentials = (os.getpid(), os.getuid(), os.getgid())
        with self.assertRaisesRegex(PermissionError, 'uncommitted'):
            self.observer._accept_worker_preexit(self.key, self.channel,
                self.packet(), credentials)
        self.assertEqual(self.observer._pending_preexits, {})

    def test_bad_outer_operation_is_rejected_before_queueing(self):
        packet = bytearray(self.packet())
        packet[6:8] = struct.pack('=H', boot.PREEXIT_SETTLED)
        credentials = (os.getpid(), os.getuid(), os.getgid())
        with self.assertRaisesRegex(PermissionError, 'envelope'):
            self.observer._accept_worker_preexit(self.key, self.channel,
                bytes(packet), credentials)
        self.assertEqual(self.observer._pending_preexits, {})

    def test_private_candidate_preexit_gate_rejects_unbound_context_before_read(self):
        self.observer.control_only = True
        self.observer.worker_channels[self.key] = self.channel
        with self.assertRaisesRegex(PermissionError, 'exact private post-COMMIT authority'):
            self.observer.poll_private_candidate_preexit(SimpleNamespace())
        self.assertFalse(getattr(self.observer, '_private_candidate_preexit_consumed', False))
        self.assertEqual(self.observer._pending_preexits, {})

    def exercise_private_candidate_reader(self, retry):
        self.observer.control_only = True
        if retry:
            self.record[9] = 2
            self.observer.allow_abort_retry = True
            self.observer._completed_master_barriers = {(1, 5), (1, 9), (2, 5), (2, 6)}
            self.key = (2, 1)
            self.observer.workers[self.key] = (self.pidfd, tuple(self.record))
            self.observer.worker_proofs[self.key] = self.proof
            self.observer.worker_process_slots[self.key] = 3
        self.observer.worker_channels[self.key] = self.channel
        record = self.record
        self.observer._source_shell_committed_plans[self.key] = {
            'worker_pid': record[5], 'worker_start_ticks': record[11],
            'slot': 3, 'ready_cookie': 444, 'native_current_cookie': 444,
            'cycle_proof': self.proof,
            'idle_observation': {'source_snapshot': (self.key[0], 1, 0, 0)},
        }
        # Exercise the real credentialed seqpacket reader and _accept validator;
        # the private Origin/controller authority join is covered separately.
        self.observer._private_candidate_preexit_authority = lambda _controller: True
        self.observer.observe_committed_current_owner = lambda *_args, **_kwargs: None
        controller = SimpleNamespace(_private_candidate_preexit_pending=None,
            _private_committed_worker_key=lambda _context: self.key)
        self.peer.send(self.packet(operation_id=913))
        pending = self.observer.poll_private_candidate_preexit(controller)
        self.assertIs(type(pending), boot.PendingSourceRetirement)
        self.assertEqual(pending.key, self.key)
        self.assertIs(controller._private_candidate_preexit_pending, pending)
        self.assertIs(self.observer._pending_preexits[913][0], pending)
        self.assertTrue(self.observer._private_candidate_preexit_consumed)
        self.assertIs(self.observer.poll_private_candidate_preexit(controller), pending)
        self.assertEqual(set(self.observer._pending_preexits), {913})
        self.peer.setblocking(False)
        with self.assertRaises(BlockingIOError):
            self.peer.recv(boot.SETTLED_RECORD_BYTES)

    def test_private_candidate_reader_consumes_one_credentialed_packet_and_retains_pending(self):
        self.exercise_private_candidate_reader(retry=False)

    def test_private_retry_preexit_consumes_the_committed_second_epoch(self):
        self.exercise_private_candidate_reader(retry=True)

    def test_missing_original_supervisor_provider_cannot_authorize(self):
        pending = boot.PendingSourceRetirement(self.key, 901, os.getpid(),
            boot.identity._start_ticks(os.getpid()), 3, bytes.fromhex('33' * 32),
            time.monotonic_ns() + boot.PREEXIT_BUDGET_NS)
        self.observer._pending_preexits = {901: (pending, b'', self.channel)}
        with self.assertRaisesRegex(PermissionError, 'provider is not connected'):
            self.observer.authorize_worker_preexit(901)
        with self.assertRaises(TypeError):
            self.observer.authorize_worker_preexit(901, True)

    def test_full_real_seqpacket_buffer_expires_without_settled_proof(self):
        children = [subprocess.Popen(['sleep', '30']) for _ in range(2)]
        pidfds = [os.pidfd_open(child.pid) for child in children]
        def stop_children():
            for child in children:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=3)
            for fd in pidfds:
                os.close(fd)
        self.addCleanup(stop_children)
        for child in children:
            child.kill()
            child.wait(timeout=3)
        self.observer.runtime = SimpleNamespace(pidfd=pidfds[0])
        self.observer.io = SimpleNamespace(pidfd=pidfds[1])
        key = self.key
        deadline = time.monotonic_ns() + 60_000_000
        request = self.packet()
        request_hash = hashlib.sha256(request).digest()
        evidence_hash = bytes.fromhex('33' * 32)
        pending = boot.PendingSourceRetirement(key, 902, os.getpid(),
            boot.identity._start_ticks(os.getpid()), 3, request_hash, deadline)
        self.observer._pending_preexits = {902: (pending, request, self.channel)}
        self.observer._authorized_preexits = {902: boot.SupervisorTermEvidence(
            os.getpid(), self.observer.master.start_ticks, bytes.fromhex('44' * 32),
            'run', 'controller', 'stack', 'stopping', os.getpid(),
            pending.worker_start_ticks, 'TERM', time.monotonic_ns(), 1, 2,
            evidence_hash)}
        self.observer._completed_retirements = {}
        settlement = boot.SourceRetirementProof(902, request_hash, evidence_hash,
            bytes.fromhex('55' * 32), bytes.fromhex('66' * 32),
            bytes.fromhex('77' * 32), 0, 100, 0)
        self.channel.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024)
        filler = b'y' * boot.SETTLED_RECORD_BYTES
        queued = 0
        while True:
            try:
                self.channel.send(filler, socket.MSG_DONTWAIT)
                queued += 1
            except BlockingIOError:
                break
        self.assertGreater(queued, 0)
        started = time.monotonic()
        with self.assertRaisesRegex(PermissionError, 'SETTLED acknowledgement missed'):
            self.observer.complete_worker_preexit(902, settlement)
        elapsed = time.monotonic() - started
        self.assertGreaterEqual(elapsed, .03)
        self.assertLess(elapsed, .5)
        self.assertEqual(self.observer._completed_retirements, {})
        self.assertIn(902, self.observer._pending_preexits)
        for _ in range(queued):
            self.assertEqual(self.peer.recv(boot.SETTLED_RECORD_BYTES), filler)


if __name__ == '__main__':
    unittest.main()
