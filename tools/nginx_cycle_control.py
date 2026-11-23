"""Private authenticated KNGC transport for the serial Nginx adapter."""
import array
import hashlib
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import select
import socket
import struct
import time

_CODEC_PATH = Path(__file__).resolve().with_name('nginx_cycle_wire.py')
_CODEC_LOADER = importlib.machinery.SourceFileLoader('_ker_nginx_cycle_wire', str(_CODEC_PATH))
_CODEC_SPEC = importlib.util.spec_from_loader(_CODEC_LOADER.name, _CODEC_LOADER)
if _CODEC_SPEC is None or _CODEC_SPEC.loader is None:
    raise ImportError('cannot load KNGC codec beside serial controller')
wire = importlib.util.module_from_spec(_CODEC_SPEC)
_CODEC_LOADER.exec_module(wire)
_UCRED = struct.Struct('=3i')


class CycleControlError(RuntimeError):
    pass


def _start_ticks(pid):
    text = Path(f'/proc/{pid}/stat').read_text(encoding='ascii')
    fields = text[text.rfind(')') + 2:].split()
    if len(fields) <= 19:
        raise CycleControlError('malformed Nginx process stat')
    value = int(fields[19], 10)
    if value <= 0:
        raise CycleControlError('invalid Nginx process start time')
    return value


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb', buffering=0) as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.digest()


def _pidfd_dead(pidfd):
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL)
    events = poller.poll(0)
    return bool(events and events[0][1] & select.POLLIN)


class NginxCycleControl:
    """One master channel; records are authenticated against helper STARTED."""
    def __init__(self, runtime, *, source_socket=None):
        self.source_socket = source_socket
        self.listener = None
        self.outer = self.master = None
        if source_socket is None:
            self.outer, self.master = socket.socketpair(socket.AF_UNIX,
                socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
            self.outer.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            self.master.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            self.outer.setblocking(False)
            self.master.setblocking(False)
        else:
            source_socket = Path(source_socket)
            parent = source_socket.parent.stat()
            if (not source_socket.is_absolute() or
                    source_socket.parent.resolve(strict=True) != source_socket.parent or
                    parent.st_uid != os.getuid() or parent.st_mode & 0o077):
                raise ValueError('named KNGC endpoint requires a private canonical directory')
            self.listener = socket.socket(socket.AF_UNIX,
                socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
            # The connect-time credentials must accompany even the first queued watch.
            self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            self.listener.bind(os.fspath(source_socket))
            self.listener.listen(1)
        self.nonce = os.urandom(16)
        while not any(self.nonce):
            self.nonce = os.urandom(16)
        self.outer_pid = os.getpid()
        self.outer_start = _start_ticks(self.outer_pid)
        self.outer_exe = _sha256('/proc/self/exe')
        self.master_pidfd = -1
        self.runtime = tuple(runtime)
        self.cycle = 1
        self.receive_sequence = 1
        self.last_request = None
        self.transition_deadline = None
        self.accepted_watch_cycles = set()
        self.master_identity = None
        self.master_pidfd = -1
        self.unresolved = False
        self.closed_master = False
        if (len(self.runtime) != 3 or len(self.runtime[0]) != 16 or
                not any(self.runtime[0]) or not self.runtime[1] or
                len(self.runtime[2]) != 32 or not any(self.runtime[2])):
            self.close()
            raise ValueError('invalid initial inner runtime tuple')

    def nginx_environment(self):
        endpoint = ({'KER_NGINX_CYCLE_FD': str(self.master.fileno())}
            if self.source_socket is None else {
                'KER_NGINX_SOURCE_SERIAL_PATH': os.fspath(self.source_socket),
                'KER_NGINX_CYCLE_OUTER_PID': str(self.outer_pid),
                'KER_NGINX_CYCLE_OUTER_START': str(self.outer_start),
            })
        return {
            **endpoint,
            'KER_NGINX_CYCLE_NONCE': self.nonce.hex(),
            'KER_NGINX_CYCLE_RUNTIME_NONCE': self.runtime[0].hex(),
            'KER_NGINX_CYCLE_RUNTIME_EPOCH': str(self.runtime[1]),
            'KER_NGINX_CYCLE_WORKER_PROFILE_SHA256': self.runtime[2].hex(),
            'KER_NGINX_CYCLE_OUTER_EXE_SHA256': self.outer_exe.hex(),
        }

    def close_master_copy(self):
        if not self.closed_master and self.master is not None:
            self.master.close()
            self.closed_master = True

    def pin_master(self, companion):
        if (not companion.started or companion.master_pid <= 0 or
                companion.master_pidfd < 0 or companion.unresolved):
            raise CycleControlError('companion has no authenticated STARTED master')
        identity = (companion.master_pid, os.getuid(), os.getgid(),
            companion.master_start, bytes(companion.binary_hash))
        if (_start_ticks(companion.master_pid) != companion.master_start or
                _sha256(f'/proc/{companion.master_pid}/exe') != companion.binary_hash or
                _pidfd_dead(companion.master_pidfd)):
            raise CycleControlError('STARTED master identity is no longer live')
        if self.master_identity is not None:
            if (self.master_identity == identity and self.master_pidfd >= 0 and
                    not _pidfd_dead(self.master_pidfd)):
                return
            raise CycleControlError('KNGC master identity is already pinned')
        self.master_identity = identity
        self.master_pidfd = os.dup(companion.master_pidfd)
        os.set_inheritable(self.master_pidfd, False)

    def _check_master(self, deadline):
        identity = self.master_identity
        if identity is None or self.master_pidfd < 0 or _pidfd_dead(self.master_pidfd):
            raise CycleControlError('Nginx master pidfd is not live')
        pid, uid, gid, start, executable_hash = identity
        if (time.monotonic() >= deadline or _start_ticks(pid) != start or
                _sha256(f'/proc/{pid}/exe') != executable_hash or
                _pidfd_dead(self.master_pidfd) or time.monotonic() >= deadline):
            raise CycleControlError('Nginx master identity/deadline validation failed')
        return (pid, uid, gid)

    def receive(self, expected_type, expected_cycle, rights_count, timeout=None, deadline=None):
        if self.unresolved or self.master_identity is None:
            raise CycleControlError('cycle channel is not authenticated or is unresolved')
        if deadline is None:
            if timeout is None:
                raise ValueError('receive requires timeout or absolute deadline')
            deadline = time.monotonic() + timeout
        poller = select.poll()
        poller.register(self.outer.fileno(), select.POLLIN | select.POLLHUP |
            select.POLLERR | select.POLLNVAL)
        poller.register(self.master_pidfd, select.POLLIN | select.POLLHUP |
            select.POLLERR | select.POLLNVAL)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self.unresolved = True
                raise TimeoutError('KNGC record deadline expired')
            try:
                events = poller.poll(max(1, min(100, int(remaining * 1000))))
            except OSError:
                self.unresolved = True
                raise
            if not events:
                continue
            masks = dict(events)
            if self.master_pidfd in masks:
                self.unresolved = True
                raise CycleControlError('pinned Nginx master exited during KNGC receive')
            mask = masks.get(self.outer.fileno(), 0)
            if mask & (select.POLLERR | select.POLLNVAL) or not mask & select.POLLIN:
                self.unresolved = True
                raise CycleControlError('KNGC channel closed or failed')
            try:
                packet, ancillary, flags, _ = self.outer.recvmsg(wire.WATCH_BYTES + 1,
                    socket.CMSG_SPACE(_UCRED.size) + socket.CMSG_SPACE(16 * 4),
                    getattr(socket, 'MSG_CMSG_CLOEXEC', 0))
            except OSError:
                self.unresolved = True
                raise
            rights = []
            credentials = []
            malformed = bool(flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC))
            for level, kind, payload in ancillary:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    complete = len(payload) - len(payload) % 4
                    if complete != len(payload):
                        malformed = True
                    if complete:
                        rights.extend(array.array('i', payload[:complete]))
                elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS:
                    if len(payload) != _UCRED.size or credentials:
                        malformed = True
                    else:
                        credentials.append(_UCRED.unpack(payload))
                else:
                    malformed = True
            try:
                expected_credentials = self._check_master(deadline)
                if (malformed or len(rights) != rights_count or
                        credentials != [expected_credentials]):
                    raise CycleControlError('KNGC credentials/rights/truncation mismatch')
                kind, status, nonce, start, sequence, cycle, runtime = wire.unpack_record(packet)
                if (kind != expected_type or status or nonce != self.nonce or
                        start != self.master_identity[3] or sequence != self.receive_sequence or
                        cycle != expected_cycle):
                    raise CycleControlError('KNGC record correlation mismatch')
                self._check_master(deadline)
                if time.monotonic() >= deadline:
                    raise TimeoutError('KNGC validation exceeded its deadline')
                self.receive_sequence += 1
                if self.receive_sequence >= wire.MAX_SEQUENCE:
                    raise CycleControlError('KNGC sequence exhausted')
                return runtime, rights
            except BaseException:
                for fd in rights:
                    os.close(fd)
                self.unresolved = True
                raise

    def bind_source_master(self, launch, timeout=45):
        if (self.listener is None or self.outer is not None or self.master_identity is not None or
                launch.cycle is not self):
            raise CycleControlError('source KNGC master binding is not available')
        deadline = time.monotonic() + timeout
        self.listener.settimeout(timeout)
        channel, _ = self.listener.accept()
        try:
            credentials = channel.getsockopt(socket.SOL_SOCKET,
                socket.SO_PEERCRED, _UCRED.size)
            pid, uid, gid = _UCRED.unpack(credentials)
            if (uid, gid) != (os.getuid(), os.getgid()):
                raise CycleControlError('named KNGC endpoint peer credentials differ')
            launch.bind_master(pid, int(deadline * 1_000_000_000))
            self.pin_master(launch)
            if (pid, uid, gid) != self.master_identity[:3]:
                raise CycleControlError('named KNGC endpoint peer differs from pinned master')
            channel.setblocking(False)
            self.outer = channel
        except BaseException:
            channel.close()
            self.unresolved = True
            raise
        finally:
            self.listener.close()
            self.listener = None

    def accept_initial_watch(self, companion, timeout=10):
        if 1 in self.accepted_watch_cycles:
            raise CycleControlError('initial WATCH_BOUND was already accepted')
        if self.outer is None:
            raise CycleControlError('initial WATCH_BOUND requires a connected master')
        self.pin_master(companion)
        deadline = time.monotonic() + timeout
        runtime, fds = self.receive(wire.WATCH_BOUND, 1, 1, deadline=deadline)
        if runtime != self.runtime:
            os.close(fds[0])
            self.unresolved = True
            raise CycleControlError('WATCH_BOUND runtime differs from authenticated INNER_READY')
        self.accepted_watch_cycles.add(1)
        return fds[0]

    def accept_successor_watch(self, expected_runtime, deadline=None):
        if deadline is None:
            deadline = self.transition_deadline
        if (self.unresolved or self.cycle <= 1 or self.last_request is not None or
                deadline is None or self.cycle in self.accepted_watch_cycles or
                tuple(expected_runtime) != self.runtime):
            raise CycleControlError('successor WATCH_BOUND is not expected for this cycle')
        runtime, fds = self.receive(wire.WATCH_BOUND, self.cycle, 1, deadline=deadline)
        if runtime != self.runtime:
            os.close(fds[0])
            self.unresolved = True
            raise CycleControlError('successor WATCH_BOUND differs from authenticated INNER_READY')
        self.accepted_watch_cycles.add(self.cycle)
        self.transition_deadline = None
        return fds[0]

    def receive_drained(self, timeout=30):
        if self.last_request is not None or self.transition_deadline is not None:
            raise CycleControlError('a cycle transition is already pending')
        sequence = self.receive_sequence
        deadline = time.monotonic() + timeout
        self.receive(wire.CYCLE_DRAINED, self.cycle, 0, deadline=deadline)
        self.last_request = (sequence, self.cycle)
        self.transition_deadline = deadline
        return self.last_request

    def send_ready(self, runtime, timeout=30):
        if self.unresolved or self.last_request is None:
            raise CycleControlError('CYCLE_READY requires an authenticated DRAINED request')
        sequence, old_cycle = self.last_request
        deadline = self.transition_deadline
        if deadline is None or time.monotonic() >= deadline:
            self.unresolved = True
            raise TimeoutError('cycle transition absolute deadline expired')
        if old_cycle != self.cycle or self.cycle == wire.MAX_SEQUENCE:
            raise CycleControlError('cycle identity exhausted or changed')
        packet = wire.pack_cycle_ready(self.nonce, self.master_identity[3],
            sequence, self.cycle + 1, runtime)
        poller = select.poll()
        poller.register(self.outer.fileno(), select.POLLOUT | select.POLLHUP |
            select.POLLERR | select.POLLNVAL)
        try:
            while True:
                if time.monotonic() >= deadline:
                    raise TimeoutError('CYCLE_READY send deadline expired')
                self._check_master(deadline)
                try:
                    sent = self.outer.send(packet, getattr(socket, 'MSG_NOSIGNAL', 0))
                except BlockingIOError:
                    poller.poll(max(1, min(100, int((deadline - time.monotonic()) * 1000))))
                    continue
                if sent != len(packet):
                    raise CycleControlError('short CYCLE_READY SOCK_SEQPACKET send')
                if time.monotonic() >= deadline:
                    raise TimeoutError('CYCLE_READY completed after deadline')
                self.runtime = tuple(runtime)
                self.cycle += 1
                self.last_request = None
                return
        except BaseException:
            self.unresolved = True
            raise

    def close(self):
        for channel in (self.outer, self.master, self.listener):
            if channel is not None:
                channel.close()
        if self.master_pidfd >= 0:
            os.close(self.master_pidfd)
            self.master_pidfd = -1
