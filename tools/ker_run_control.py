"""Authenticated, one-inner ker-run relay for generation retirement watches."""
import array
import fcntl
import importlib.util
import os
from pathlib import Path
import select
import socket
import time

_WIRE_SPEC = importlib.util.spec_from_file_location(
    '_ker_run_control_wire', Path(__file__).resolve().with_name(
        'ker_run_control_wire.py'))
if _WIRE_SPEC is None or _WIRE_SPEC.loader is None:
    raise ImportError('cannot load private ker-run control codec beside module')
wire = importlib.util.module_from_spec(_WIRE_SPEC)
_WIRE_SPEC.loader.exec_module(wire)

INNER_READY = wire.INNER_READY
SETTLED_FLAGS = wire.SETTLED_FLAGS
STOP = wire.STOP
STOP_ACCEPTED = wire.STOP_ACCEPTED
VERIFY = wire.VERIFY
pack_ready = wire.pack_ready
pack_settled = wire.pack_settled
pack_stop_reply = wire.pack_stop_reply
pack_verify_result = wire.pack_verify_result
unpack_stop = wire.unpack_stop
unpack_verify = wire.unpack_verify

_UCRED = __import__('struct').Struct('=3i')
_MAX_RIGHTS = 16
_READY_TIMEOUT = 20.0
_VERIFY_TIMEOUT = 6.0
STOP_ACK_TIMEOUT = 10.0
_STOP_ACK_TIMEOUT = STOP_ACK_TIMEOUT
_SETTLE_TIMEOUT = 30.0


def _identity(pid):
    stat = Path(f'/proc/{pid}/stat').read_text(encoding='ascii')
    close = stat.rfind(')')
    fields = stat[close + 2:].split() if close >= 0 else ()
    if len(fields) <= 19:
        raise RuntimeError('malformed relay parent process identity')
    start_ticks = int(fields[19], 10)
    status = os.stat(f'/proc/{pid}')
    if pid <= 0 or start_ticks <= 0:
        raise RuntimeError('invalid relay parent identity')
    return (pid, status.st_uid, status.st_gid, start_ticks)


def _pidfd_alive(pidfd):
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR |
        select.POLLNVAL)
    return not poller.poll(0)


class KerRunControl:
    """One authenticated parent channel; ambiguity is terminal and retained.

    Relay VERIFY sequence N is deliberately mapped to C34 broker VERIFY
    sequence N. This is valid only for this reserved attachment profile:
    both counters begin at one, every pre-STOP outer operation is exactly one
    VERIFY, and STOP is terminal. Adding any other pre-STOP operation requires
    an explicit sequence mapping rather than reusing this equality.
    """

    def __init__(self, control_fd, relay_nonce, relay_epoch, broker_readiness=None,
            worker=None, worker_pidfd=-1, worker_path=None,
            app_executable_hash=None):
        # The caller transfers one host descriptor. Keep a dedicated CLOEXEC
        # copy and consume the transferred number so no later exec inherits it.
        owned_fd = -1
        channel = None
        try:
            if (control_fd < 0 or len(relay_nonce) != 16 or not any(relay_nonce) or
                    not 0 < relay_epoch < (1 << 64)):
                raise ValueError('invalid ker-run relay attachment context')
            owned_fd = fcntl.fcntl(control_fd, fcntl.F_DUPFD_CLOEXEC, 0)
            channel = socket.socket(fileno=owned_fd)
            owned_fd = -1
        finally:
            if control_fd >= 0:
                try:
                    os.close(control_fd)
                except OSError:
                    pass
            if owned_fd >= 0:
                os.close(owned_fd)
        parent_pidfd = -1
        try:
            channel.setblocking(False)
            if (channel.family != socket.AF_UNIX or
                    channel.type & 0xF != socket.SOCK_SEQPACKET):
                raise OSError(91, 'relay channel must be AF_UNIX SOCK_SEQPACKET')
            channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            peer = channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                _UCRED.size)
            peer_pid, peer_uid, peer_gid = _UCRED.unpack(peer)
            if peer_pid <= 0 or peer_pid != os.getppid():
                raise PermissionError('relay socket creator is not the direct parent')
            parent = _identity(peer_pid)
            if (peer_uid, peer_gid) != parent[1:3]:
                raise PermissionError('relay parent credentials changed during attachment')
            parent_pidfd = os.pidfd_open(peer_pid, 0)
            if _identity(peer_pid) != parent or not _pidfd_alive(parent_pidfd):
                raise ProcessLookupError('relay parent changed during attachment')
        except BaseException:
            channel.close()
            if parent_pidfd >= 0:
                os.close(parent_pidfd)
            raise
        self.channel = channel
        self.parent = parent
        self.parent_pidfd = parent_pidfd
        self.nonce = bytes(relay_nonce)
        self.epoch = relay_epoch
        self.readiness = None
        self.worker = None
        self.worker_pidfd = worker_pidfd
        self.worker_identity = None
        self.worker_path = None
        self.app_executable_hash = None
        self.worker_executable_hash = None
        self.state = 'STARTING'
        self.ready_record = None
        self.ready_deadline = time.monotonic() + _READY_TIMEOUT
        self.last_sequence = 0
        self.verify = None
        self.stop = None
        self.settle_deadline = None
        self.outbound = None
        self.outbound_action = None
        self.outbound_deadline = None
        self.unresolved = False
        self.failure = None
        if worker is not None:
            self.bind_runtime(broker_readiness, worker, worker_pidfd,
                worker_path, app_executable_hash)

    @staticmethod
    def _sha256(path):
        import hashlib
        digest = hashlib.sha256()
        with open(path, 'rb') as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(block)
        return digest.digest()

    @classmethod
    def from_environment(cls):
        keys = ('KER_RUN_CONTROL_FD', 'KER_RUN_CONTROL_NONCE',
            'KER_RUN_CONTROL_EPOCH')
        values = tuple(os.environ.get(key) for key in keys)
        if all(value is None for value in values):
            return None
        if any(value is None for value in values):
            raise ValueError('incomplete ker-run control relay environment')
        fd = -1
        try:
            fd = int(values[0], 10)
            nonce = bytes.fromhex(values[1])
            epoch = int(values[2], 10)
        except (ValueError, OverflowError) as exc:
            if fd >= 0:
                os.close(fd)
            raise ValueError('malformed ker-run control relay environment') from exc
        if (fd < 0 or len(nonce) != 16 or not any(nonce) or
                not 0 < epoch < (1 << 64)):
            if fd >= 0:
                os.close(fd)
            raise ValueError('invalid ker-run control relay environment')
        return cls(fd, nonce, epoch)

    def bind_runtime(self, broker_readiness, worker, worker_pidfd, worker_path,
            app_executable_hash):
        if (self.worker is not None or broker_readiness is None or worker is None or
                worker_pidfd < 0):
            raise RuntimeError('ker-run relay runtime bindings are one-use')
        self.readiness = broker_readiness
        self.worker = worker
        self.worker_pidfd = worker_pidfd
        self.worker_path = Path(worker_path).resolve(strict=True)
        self.app_executable_hash = bytes(app_executable_hash)
        if len(self.app_executable_hash) != 32 or not any(self.app_executable_hash):
            raise ValueError('invalid pinned broker executable hash')
        self.worker_executable_hash = self._sha256(self.worker_path)
        self.worker_identity = _identity(worker.pid)
        if not _pidfd_alive(worker_pidfd) or _identity(worker.pid) != self.worker_identity:
            raise ProcessLookupError('worker identity changed during relay binding')

    def _runtime_ready(self):
        if (self.readiness is None or self.worker is None or self.worker_pidfd < 0 or
                self.worker_path is None or self.app_executable_hash is None):
            raise RuntimeError('ker-run relay runtime has not been bound')

    def _check_parent(self):
        if not _pidfd_alive(self.parent_pidfd):
            raise ProcessLookupError('authenticated ker-run parent exited')
        if _identity(self.parent[0]) != self.parent:
            raise ProcessLookupError('authenticated ker-run parent identity changed')

    def _receive(self, rights_expected):
        packet, ancillary, flags, _ = self.channel.recvmsg(217,
            socket.CMSG_SPACE(_UCRED.size) + socket.CMSG_SPACE(_MAX_RIGHTS * 4),
            getattr(socket, 'MSG_CMSG_CLOEXEC', 0))
        credentials = None
        received_fds = []
        bad_control = False
        try:
            for level, kind, payload in ancillary:
                if level != socket.SOL_SOCKET:
                    bad_control = True
                elif kind == socket.SCM_CREDENTIALS:
                    if credentials is not None or len(payload) != _UCRED.size:
                        bad_control = True
                    else:
                        credentials = _UCRED.unpack(payload)
                elif kind == socket.SCM_RIGHTS:
                    usable = len(payload) - len(payload) % array.array('i').itemsize
                    if usable:
                        received_fds.extend(array.array('i', payload[:usable]))
                    if usable != len(payload):
                        bad_control = True
                else:
                    bad_control = True
            if (not packet or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or
                    bad_control or credentials != self.parent[:3] or
                    len(received_fds) != rights_expected or
                    _identity(self.parent[0]) != self.parent or
                    not _pidfd_alive(self.parent_pidfd)):
                raise PermissionError('invalid or unauthenticated relay request')
            owned = received_fds
            received_fds = []
            return packet, owned
        finally:
            for fd in received_fds:
                os.close(fd)

    def _send(self, record):
        if self.outbound is None:
            self.outbound = record
        elif self.outbound != record:
            raise RuntimeError('relay already has a different pending response')
        try:
            sent = self.channel.send(self.outbound,
                getattr(socket, 'MSG_NOSIGNAL', 0))
        except BlockingIOError:
            return False
        if sent != len(self.outbound):
            raise OSError(5, 'short relay SOCK_SEQPACKET send')
        self.outbound = None
        return True

    def _sent_action(self):
        action = self.outbound_action
        self.outbound_action = None
        self.outbound_deadline = None
        if action == 'ready':
            self.state = 'READY'
        elif action == 'verify':
            self.verify = None
        elif action == 'stop_accepted':
            self.state = 'STOP_ACCEPTED'
        elif action == 'settled':
            self.state = 'SETTLED'

    def _queue(self, record, action):
        if self.outbound is not None:
            raise RuntimeError('ker-run relay already has an outbound record')
        self.outbound = record
        self.outbound_action = action
        if action == 'ready':
            self.outbound_deadline = self.ready_deadline
        elif action == 'verify':
            self.outbound_deadline = self.verify['deadline']
        elif action == 'stop_accepted':
            self.outbound_deadline = self.stop['ack_deadline']
        elif action == 'settled':
            self.outbound_deadline = self.settle_deadline
        return self._flush_outbound()

    def _flush_outbound(self):
        if self.outbound is None:
            return True
        if (self.outbound_deadline is not None and
                time.monotonic() >= self.outbound_deadline):
            self._mark_unresolved('relay response send deadline expired')
            raise TimeoutError(self.failure)
        if not self._send(self.outbound):
            return False
        self._sent_action()
        return True

    def poll_inner_ready(self):
        self._runtime_ready()
        self._check_parent()
        if self.state != 'STARTING':
            return self.state != 'STARTING'
        if self.outbound is not None:
            return self._flush_outbound()
        if time.monotonic() >= self.ready_deadline:
            raise TimeoutError('inner READY absolute deadline expired')
        if not self.readiness.ready:
            return False
        app = self.readiness.app
        worker_identity = _identity(self.worker.pid)
        if (app is None or app[0] <= 0 or not _pidfd_alive(self.readiness.app_pidfd) or
                not _pidfd_alive(self.worker_pidfd) or
                _identity(self.worker.pid) != self.worker_identity):
            raise ProcessLookupError('inner broker or worker exited before relay READY')
        app_stat = Path(f'/proc/{app[0]}/stat').read_text(encoding='ascii')
        worker_stat = Path(f'/proc/{self.worker.pid}/stat').read_text(encoding='ascii')
        for stat in (app_stat, worker_stat):
            fields = stat[stat.rfind(')') + 2:].split()
            if len(fields) <= 1 or int(fields[1], 10) != os.getpid():
                raise PermissionError('READY broker/worker is not an inner child')
        worker_identity = (self.worker.pid, os.stat(f'/proc/{self.worker.pid}').st_uid,
            os.stat(f'/proc/{self.worker.pid}').st_gid, worker_identity[3])
        if self._sha256(f'/proc/{self.worker.pid}/exe') != self.worker_executable_hash:
            raise PermissionError('worker executable differs from the pinned relay profile')
        broker_nonce, broker_epoch, profile = (self.readiness.nonce,
            self.readiness.epoch, self.readiness.profile)
        self.ready_record = pack_ready(self.nonce, self.epoch, broker_nonce,
            broker_epoch, profile, self.app_executable_hash,
            self.worker_executable_hash, app, worker_identity)
        return self._queue(self.ready_record, 'ready')

    def poll(self, on_stop_request):
        self._check_parent()
        if (self.stop is not None and self.state in ('STOP_PENDING', 'STOP_ACCEPTED') and
                self.settle_deadline is not None and
                time.monotonic() >= self.settle_deadline):
            self._mark_unresolved('relay STOP/SETTLED absolute deadline expired')
            raise TimeoutError(self.failure)
        if self.state == 'STARTING':
            poller = select.poll()
            poller.register(self.channel.fileno(), select.POLLIN | select.POLLHUP |
                select.POLLERR | select.POLLNVAL)
            events = poller.poll(0)
            if events and events[0][1] & select.POLLIN:
                peek = self.channel.recv(8, socket.MSG_PEEK)
                kind = int.from_bytes(peek[6:8], 'little') if len(peek) >= 8 else 0
                packet, fds = self._receive(1 if kind == VERIFY else 0)
                for fd in fds:
                    os.close(fd)
                raise PermissionError('outer relay request arrived before INNER_READY')
            if events and events[0][1] & (select.POLLHUP | select.POLLERR | select.POLLNVAL):
                raise ConnectionError('outer relay parent channel closed before INNER_READY')
            self.poll_inner_ready()
            return
        if self.state in ('SETTLED', 'FAILED', 'UNRESOLVED'):
            return
        if self.outbound is not None:
            if not self._flush_outbound():
                return
            if self.state in ('STOP_ACCEPTED', 'SETTLED'):
                return
        if self.verify is None and self.stop is None:
            poller = select.poll()
            poller.register(self.channel.fileno(), select.POLLIN | select.POLLHUP |
                select.POLLERR | select.POLLNVAL)
            events = poller.poll(0)
            if events:
                if events[0][1] & (select.POLLHUP | select.POLLERR | select.POLLNVAL) and not events[0][1] & select.POLLIN:
                    raise ConnectionError('outer relay parent channel closed')
                peek = self.channel.recv(8, socket.MSG_PEEK)
                kind = int.from_bytes(peek[6:8], 'little') if len(peek) >= 8 else 0
                packet, fds = self._receive(1 if kind == VERIFY else 0)
                try:
                    if kind == VERIFY:
                        nonce, epoch, sequence = unpack_verify(packet)
                        if (self.state != 'READY' or nonce != self.nonce or
                                epoch != self.epoch or sequence != self.last_sequence + 1):
                            raise ValueError('out-of-order relay VERIFY')
                        self.last_sequence = sequence
                        self.readiness.begin_verify(fds[0], sequence, _VERIFY_TIMEOUT)
                        # BrokerReadiness owns this one transport reference and
                        # closes it as soon as its SCM_RIGHTS handoff succeeds.
                        fds = []
                        self.verify = {'sequence': sequence,
                            'deadline': time.monotonic() + _VERIFY_TIMEOUT}
                    elif kind == STOP:
                        nonce, epoch, sequence = unpack_stop(packet)
                        if (self.state != 'READY' or nonce != self.nonce or
                                epoch != self.epoch or sequence != self.last_sequence + 1):
                            raise ValueError('out-of-order relay STOP')
                        self.last_sequence = sequence
                        self.stop = {'sequence': sequence,
                            'ack_deadline': time.monotonic() + _STOP_ACK_TIMEOUT,
                            'deadline': time.monotonic() + _SETTLE_TIMEOUT}
                        self.settle_deadline = self.stop['deadline']
                        self.state = 'STOP_PENDING'
                        on_stop_request()
                    else:
                        raise ValueError('unknown relay request type')
                finally:
                    for fd in fds:
                        os.close(fd)
        if self.verify is not None:
            if time.monotonic() >= self.verify['deadline']:
                self._mark_unresolved('relay VERIFY deadline expired')
                raise TimeoutError(self.failure)
            result = self.readiness.poll_verify()
            if result is not None:
                self._queue(pack_verify_result(self.nonce, self.epoch,
                    self.verify['sequence'], result), 'verify')
        elif self.stop is not None and self.state == 'STOP_PENDING':
            if time.monotonic() >= self.stop['deadline']:
                self._mark_unresolved('relay STOP/SETTLED deadline expired')
                raise TimeoutError(self.failure)
            if self.readiness.poll_stop():
                accepted = pack_stop_reply(STOP_ACCEPTED, self.nonce,
                    self.epoch, self.stop['sequence'])
                self._queue(accepted, 'stop_accepted')

    def flush_settled(self):
        """Retry only a locally queued SETTLED record until its send succeeds."""
        if self.state == 'SETTLED':
            return True
        if self.state != 'STOP_ACCEPTED' or self.outbound_action != 'settled':
            raise RuntimeError('no pending SETTLED record')
        self._check_parent()
        if time.monotonic() >= self.settle_deadline:
            self._mark_unresolved('relay settlement send deadline expired')
            raise TimeoutError(self.failure)
        if self._flush_outbound():
            return self.state == 'SETTLED'
        return False

    def send_settled(self, app_status, worker_status, outstanding, flags):
        if self.state != 'STOP_ACCEPTED' or self.stop is None:
            raise RuntimeError('SETTLED requires authenticated STOP acceptance')
        if time.monotonic() >= self.settle_deadline:
            self._mark_unresolved('relay settlement deadline expired')
            raise TimeoutError(self.failure)
        app = self.readiness.app
        worker_identity = self.worker_identity
        broker_nonce, broker_epoch, profile = (self.readiness.nonce,
            self.readiness.epoch, self.readiness.profile)
        settled = pack_settled(self.nonce, self.epoch, self.stop['sequence'],
            app[0], self.worker.pid, app[3], worker_identity[3], app_status,
            worker_status, outstanding, flags, broker_nonce, broker_epoch,
            profile)
        return self._queue(settled, 'settled')

    def _mark_unresolved(self, reason):
        self.unresolved = True
        self.failure = reason
        self.state = 'UNRESOLVED'

    def close_after_settled(self):
        if self.state not in ('SETTLED', 'FAILED'):
            raise RuntimeError('relay channel cannot close before SETTLED or terminal failure')
        self.channel.close()
        os.close(self.parent_pidfd)
        self.parent_pidfd = -1
