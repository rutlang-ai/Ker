"""Private serial SDK-generation controller for the C37 integration fixture.

This module coordinates real inner ker-run processes and broker-owned Linux
sockets. It contains no TCP protocol behavior; the fixture actor owns its tiny
request/response contract.
"""
from dataclasses import dataclass
import errno
import fcntl
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import secrets
import select
import shlex
import signal
import socket
import struct
import stat
import subprocess
import sys
import time


_WIRE_PATH = Path(__file__).resolve().with_name('ker_run_control_wire.py')
_WIRE_LOADER = importlib.machinery.SourceFileLoader('_ker_serial_relay_wire', str(_WIRE_PATH))
_WIRE_SPEC = importlib.util.spec_from_loader(_WIRE_LOADER.name, _WIRE_LOADER)
if _WIRE_SPEC is None or _WIRE_SPEC.loader is None:
    raise ImportError('cannot load private ker-run relay wire codec')
wire = importlib.util.module_from_spec(_WIRE_SPEC)
_WIRE_LOADER.exec_module(wire)
_CYCLE_CONTROL_PATH = Path(__file__).resolve().with_name('nginx_cycle_control.py')
_CYCLE_CONTROL_LOADER = importlib.machinery.SourceFileLoader(
    '_ker_serial_nginx_cycle_control', str(_CYCLE_CONTROL_PATH))
_CYCLE_CONTROL_SPEC = importlib.util.spec_from_loader(
    _CYCLE_CONTROL_LOADER.name, _CYCLE_CONTROL_LOADER)
if _CYCLE_CONTROL_SPEC is None or _CYCLE_CONTROL_SPEC.loader is None:
    raise ImportError('cannot load private Nginx cycle control module')
cycle_control = importlib.util.module_from_spec(_CYCLE_CONTROL_SPEC)
_CYCLE_CONTROL_LOADER.exec_module(cycle_control)

_HANDOFF = struct.Struct('<IHHIIIIIIQHHHH16s')
_HANDOFF_MAGIC = 0x314F574B  # KWO1
_HANDOFF_VERSION = 1
_HANDOFF_OWNER_WATCH = 1
_UCRED = struct.Struct('=3i')


class ControllerError(RuntimeError):
    """Base class for a controller operation that did not prove its postcondition."""


class ProtocolError(ControllerError):
    pass


class AuthenticationError(ControllerError):
    pass


class OwnerStillLive(ControllerError):
    pass


class DeadlineExpired(ControllerError):
    pass


class RetirementMismatch(ControllerError):
    pass


class SettlementError(ControllerError):
    pass


class NewGenerationError(ControllerError):
    pass


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    uid: int
    gid: int
    start_ticks: int


@dataclass
class InnerLaunch:
    launcher: Path
    library: Path
    worker: Path
    broker: Path
    plugin_dir: Path
    root: Path
    address: str = '198.18.0.2/24'
    port_name: str = 'net_tap0'
    rpc_path: Path | None = None


@dataclass
class InnerContext:
    label: str
    process: subprocess.Popen
    pidfd: int
    relay: socket.socket
    nonce: bytes
    epoch: int
    log: object
    stats_path: Path
    rpc_path: Path
    rpc_inode: tuple | None = None
    ready_packet: bytes | None = None
    ready: tuple | None = None
    app_identity: ProcessIdentity | None = None
    worker_identity: ProcessIdentity | None = None
    app_pidfd: int = -1
    worker_pidfd: int = -1
    identity: ProcessIdentity | None = None
    executable_hash: bytes | None = None
    owner_actor: subprocess.Popen | None = None
    owner_actor_channel: socket.socket | None = None
    owner_actor_attempted: bool = False
    owner_pidfd: int = -1
    relay_sequence: int = 0
    advanced: bool = False
    settled: bool = False
    unresolved_reason: str | None = None
    failure_state: str | None = None
    events: list | None = None
    closed: bool = False


@dataclass
class OwnerWatch:
    inner: InnerContext
    actor: subprocess.Popen
    actor_identity: ProcessIdentity
    actor_pidfd: int
    channel: socket.socket
    watch_fd: int
    port: int
    address: bytes
    receipt: bytes | None = None
    last_result: bytes | None = None
    closed: bool = False


@dataclass
class ExternalOwnerWatch:
    inner: InnerContext
    actor_identity: ProcessIdentity
    actor_pidfd: int
    watch_identity: tuple
    port: int
    address: bytes
    receipt: bytes
    last_result: bytes
    closed: bool = False


@dataclass(frozen=True)
class VerifiedOwnerRetired:
    inner: InnerContext
    watch: object
    claim_receipt: bytes
    terminal_result: bytes
    _seal: object
    companion_shutdown: bool = False


@dataclass(frozen=True)
class VerifiedCompanionShutdown:
    inner: InnerContext
    watch: ExternalOwnerWatch
    companion: object
    master_identity: tuple
    settled_record: bytes
    _seal: object


@dataclass(frozen=True)
class RuntimeSettled:
    inner: InnerContext
    settled_record: bytes
    stats: dict
    _seal: object


@dataclass(frozen=True)
class NewServiceReady:
    inner: InnerContext
    address: str
    port: int
    request: bytes
    response: bytes


def _proc_identity(pid):
    stat = Path(f'/proc/{pid}/stat').read_text(encoding='ascii')
    fields = stat[stat.rfind(')') + 2:].split()
    if len(fields) <= 19:
        raise ProtocolError('malformed proc start-time record')
    start_ticks = int(fields[19], 10)
    info = os.stat(f'/proc/{pid}')
    if pid <= 0 or start_ticks <= 0:
        raise ProtocolError('invalid process identity')
    return ProcessIdentity(pid, info.st_uid, info.st_gid, start_ticks)


def _proc_parent(pid):
    stat = Path(f'/proc/{pid}/stat').read_text(encoding='ascii')
    fields = stat[stat.rfind(')') + 2:].split()
    if len(fields) <= 1:
        raise ProtocolError('malformed process parent record')
    return int(fields[1], 10)


def _sha256_proc_exe(pid):
    digest = hashlib.sha256()
    with open(f'/proc/{pid}/exe', 'rb', buffering=0) as executable:
        while True:
            block = executable.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.digest()


def _external_watch_identity(fd):
    info = os.fstat(fd)
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    if not stat.S_ISFIFO(info.st_mode) or flags & os.O_ACCMODE != os.O_WRONLY:
        raise ProtocolError('external generation watch is not a broker write-only capability pipe')
    return (info.st_dev, info.st_ino, info.st_mode, info.st_rdev, info.st_size)


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as executable:
        for block in iter(lambda: executable.read(1024 * 1024), b''):
            digest.update(block)
    return digest.digest()


def _pidfd_is_dead(pidfd):
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL)
    events = poller.poll(0)
    return bool(events and events[0][1] & select.POLLIN)


def _wait_pidfd_dead(pidfd, deadline, description):
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL)
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DeadlineExpired(f'{description} did not exit before deadline')
        events = poller.poll(max(1, min(100, int(remaining * 1000))))
        if not events:
            continue
        flags = events[0][1]
        if flags & (select.POLLERR | select.POLLNVAL) or not flags & select.POLLIN:
            raise ProtocolError(f'{description} pidfd did not report process death')
        return


def _send_packet(sock, packet, deadline):
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DeadlineExpired('relay send deadline expired')
        try:
            sent = sock.send(packet, getattr(socket, 'MSG_NOSIGNAL', 0))
        except BlockingIOError:
            poller = select.poll()
            poller.register(sock.fileno(), select.POLLOUT | select.POLLERR | select.POLLHUP)
            if not poller.poll(max(1, min(100, int(remaining * 1000)))):
                continue
            continue
        if sent != len(packet):
            raise ProtocolError('short SOCK_SEQPACKET relay send')
        return


def _receive_packet(sock, expected_size, expected_pid, deadline):
    poller = select.poll()
    poller.register(sock.fileno(), select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL)
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DeadlineExpired('relay receive deadline expired')
        events = poller.poll(max(1, min(100, int(remaining * 1000))))
        if not events:
            continue
        flags = events[0][1]
        if flags & (select.POLLERR | select.POLLNVAL):
            raise ProtocolError('relay socket poll failed')
        packet, ancillary, message_flags, _ = sock.recvmsg(4096,
            socket.CMSG_SPACE(_UCRED.size) + socket.CMSG_SPACE(16 * 4),
            getattr(socket, 'MSG_CMSG_CLOEXEC', 0))
        rights = []
        creds = []
        malformed = bool(message_flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC))
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                count = len(data) // struct.calcsize('i')
                rights.extend(struct.unpack(f'{count}i', data[:count * 4]))
            elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(data) == _UCRED.size:
                creds.append(_UCRED.unpack(data))
            else:
                malformed = True
        for fd in rights:
            os.close(fd)
        if malformed or rights or len(packet) != expected_size or len(creds) != 1:
            raise ProtocolError('malformed relay response or unexpected ancillary data')
        if creds[0] != (expected_pid, os.getuid(), os.getgid()):
            raise AuthenticationError(f'unexpected relay credentials {creds[0]!r}')
        if time.monotonic() >= deadline:
            raise DeadlineExpired('relay response arrived after its absolute deadline')
        return packet


def _recv_actor_handoff(channel, actor, expected_port, expected_address, deadline):
    channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    poller = select.poll()
    poller.register(channel.fileno(), select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL)
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DeadlineExpired('owner watch handoff timed out')
        events = poller.poll(max(1, min(100, int(remaining * 1000))))
        if not events:
            continue
        packet, ancillary, flags, _ = channel.recvmsg(1024,
            socket.CMSG_SPACE(_UCRED.size) + socket.CMSG_SPACE(8 * 4),
            getattr(socket, 'MSG_CMSG_CLOEXEC', 0))
        fds = []
        creds = []
        malformed = bool(flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC))
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                count = len(data) // 4
                fds.extend(struct.unpack(f'{count}i', data[:count * 4]))
            elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(data) == _UCRED.size:
                creds.append(_UCRED.unpack(data))
            else:
                malformed = True
        try:
            actual = _proc_identity(actor.pid)
            expected_creds = (actor.pid, actual.uid, actual.gid)
            peer = _UCRED.unpack(channel.getsockopt(socket.SOL_SOCKET,
                socket.SO_PEERCRED, _UCRED.size))
            if malformed or packet and len(packet) != _HANDOFF.size or len(fds) != 1 or len(creds) != 1:
                raise ProtocolError('malformed OWNER_WATCH handoff')
            if creds[0] != expected_creds or peer != expected_creds:
                raise AuthenticationError('OWNER_WATCH peer/record credentials mismatch')
            (magic, version, kind, size, reserved, pid, uid, gid, reserved2,
             start_ticks, family, port, address_bytes, reserved3, address) = _HANDOFF.unpack(packet)
            if (magic != _HANDOFF_MAGIC or version != _HANDOFF_VERSION or
                    kind != _HANDOFF_OWNER_WATCH or size != _HANDOFF.size or
                    reserved or reserved2 or reserved3 or pid != actor.pid or
                    (uid, gid) != (actual.uid, actual.gid) or
                    start_ticks != actual.start_ticks or family != socket.AF_INET or
                    port != expected_port or address_bytes != 4 or
                    address[:4] != expected_address or any(address[4:])):
                raise ProtocolError('OWNER_WATCH fields do not match pinned actor/launch')
            if time.monotonic() >= deadline:
                raise DeadlineExpired('OWNER_WATCH validation exceeded its absolute deadline')
            return actual, fds.pop(), port, address[:4]
        finally:
            for fd in fds:
                os.close(fd)


def _receive_actor_control(channel, actor, expected_byte, deadline):
    poller = select.poll()
    poller.register(channel.fileno(), select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL)
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DeadlineExpired('owner actor control acknowledgement timed out')
        events = poller.poll(max(1, min(100, int(remaining * 1000))))
        if not events:
            continue
        packet, ancillary, flags, _ = channel.recvmsg(32,
            socket.CMSG_SPACE(_UCRED.size) + socket.CMSG_SPACE(8 * 4),
            getattr(socket, 'MSG_CMSG_CLOEXEC', 0))
        fds = []
        creds = []
        malformed = bool(flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC))
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                count = len(data) // 4
                fds.extend(struct.unpack(f'{count}i', data[:count * 4]))
            elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(data) == _UCRED.size:
                creds.append(_UCRED.unpack(data))
            else:
                malformed = True
        for fd in fds:
            os.close(fd)
        actor_id = _proc_identity(actor.pid)
        if (malformed or fds or packet != expected_byte or len(creds) != 1 or
                creds[0] != (actor.pid, actor_id.uid, actor_id.gid)):
            raise ProtocolError('invalid owner actor control acknowledgement')
        if time.monotonic() >= deadline:
            raise DeadlineExpired('owner actor acknowledgement exceeded its absolute deadline')
        return


def _send_actor_control(channel, value, deadline):
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DeadlineExpired('owner actor control send timed out')
        try:
            sent = channel.send(value, getattr(socket, 'MSG_NOSIGNAL', 0))
        except BlockingIOError:
            poller = select.poll()
            poller.register(channel.fileno(), select.POLLOUT | select.POLLERR | select.POLLHUP)
            poller.poll(max(1, min(100, int(remaining * 1000))))
            continue
        if sent != len(value):
            raise ProtocolError('short owner actor control send')
        if time.monotonic() >= deadline:
            raise DeadlineExpired('owner actor control send completed after its deadline')
        return


class SerialGenerationController:
    """Bounded two-generation coordinator; one-use advance is internal state."""

    def __init__(self, launch: InnerLaunch, port=4127, address='198.18.0.2'):
        self.launch = launch
        self.port = port
        self.address = address
        self.address_bytes = socket.inet_aton(address)
        self._generation_counter = 0
        self._proof_seal = object()
        self._verified_proofs = {}
        self._settled_proofs = {}
        self._external_live_watches = {}
        self._companion_shutdown_proofs = {}
        self._old_context = None
        self._new_context = None
        self._advance_key = object()
        self._unresolved_context = None
        # Hash the configured executables before either generation starts.
        # INNER_READY is authenticated as a ker-run message, but its claimed
        # hashes are still checked against this controller-owned launch profile.
        self._expected_app_hash = _sha256_file(Path(launch.broker).resolve())
        self._expected_worker_hash = _sha256_file(Path(launch.worker).resolve())

    def start_inner(self, label):
        if label != 'old' or self._generation_counter != 0:
            raise ProtocolError('only the initial old generation may be started directly')
        return self._start_inner(label)

    def _start_inner(self, label, authorization=None):
        if label not in ('old', 'new'):
            raise ValueError('invalid internal generation label')
        if label == 'old' and (self._generation_counter != 0 or self._old_context is not None):
            raise ProtocolError('old generation may be started exactly once')
        if label == 'new' and (authorization is not self._advance_key or
                self._new_context is not None or self._old_context is None or
                not self._old_context.advanced):
            raise SettlementError('new generation requires the controller’s one-use advance')
        self._generation_counter += 1
        root = self.launch.root / label
        root.mkdir(parents=True, exist_ok=False)
        stats = root / 'worker-stats.json'
        rpc = (Path(self.launch.rpc_path) if self.launch.rpc_path is not None
            else root / 'rpc.sock')
        relay_parent, relay_child = socket.socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | getattr(socket, 'SOCK_CLOEXEC', 0))
        relay_parent.setblocking(False)
        relay_parent.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        nonce = secrets.token_bytes(16)
        while not any(nonce):
            nonce = secrets.token_bytes(16)
        epoch = secrets.randbits(64) or 1
        env = os.environ.copy()
        env.update(KER_RUN_CONTROL_FD=str(relay_child.fileno()),
            KER_RUN_CONTROL_NONCE=nonce.hex(), KER_RUN_CONTROL_EPOCH=str(epoch))
        cpu = min(os.sched_getaffinity(0))
        plugin = self.launch.plugin_dir / 'librte_net_tap.so'
        eal = (f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry '
            f'--iova-mode=va -m 64 -d {shlex.quote(str(plugin))} '
            '--vdev=net_tap0,iface=kerpeer,remote=kerlink')
        command = [sys.executable, str(self.launch.launcher.resolve()),
            '--library', str(self.launch.library.resolve()),
            '--io-worker', str(self.launch.worker.resolve()),
            '--address', self.launch.address, '--port', self.launch.port_name,
            '--eal', eal, '--runtime-service', '--broker-readiness',
            '--stats', str(stats), '--', str(self.launch.broker.resolve()), str(rpc)]
        log = (root / 'inner.log').open('wb')
        try:
            process = subprocess.Popen(command, env=env,
                pass_fds=(relay_child.fileno(),), stdin=subprocess.DEVNULL,
                stdout=log, stderr=subprocess.STDOUT, close_fds=True,
                start_new_session=True)
        except BaseException:
            relay_parent.close()
            relay_child.close()
            log.close()
            raise
        relay_child.close()
        context = InnerContext(label, process, -1, relay_parent, nonce, epoch,
            log, stats, rpc, events=[])
        # Retain every resource immediately after Popen succeeds. If identity
        # pinning fails, the controller stays in an unresolved state instead
        # of losing a live child or treating its failure as settlement.
        self._unresolved_context = context
        context.pidfd = os.pidfd_open(process.pid, 0)
        context.identity = _proc_identity(process.pid)
        context.executable_hash = _sha256_proc_exe(process.pid)
        self._unresolved_context = None
        if label == 'old':
            self._old_context = context
        else:
            self._new_context = context
        context.events.append({'event': label.upper() + '_INNER_SPAWN',
            'monotonic_ns': time.monotonic_ns(), 'pid': process.pid,
            'start_ticks': context.identity.start_ticks,
            'exe_sha256': context.executable_hash.hex()})
        return context

    def receive_ready(self, context, timeout=20, deadline=None):
        if context.ready is not None or context.closed or context.unresolved_reason is not None:
            raise ProtocolError('inner READY already consumed or context closed')
        deadline = time.monotonic() + timeout if deadline is None else deadline
        if time.monotonic() >= deadline:
            context.unresolved_reason = 'INNER_READY deadline expired before receive'
            if context.label == 'new':
                context.failure_state = 'NEW_FAILED'
            raise DeadlineExpired(context.unresolved_reason)
        packet = _receive_packet(context.relay, wire.READY.size,
            context.process.pid, deadline)
        app_pidfd = worker_pidfd = -1
        try:
            ready = wire.unpack_ready(packet)
            if ready[0] != context.nonce or ready[1] != context.epoch:
                raise AuthenticationError('INNER_READY relay context mismatch')
            app_tuple, worker_tuple = ready[7], ready[8]
            app_id = _proc_identity(app_tuple[0])
            worker_id = _proc_identity(worker_tuple[0])
            if ((app_id.uid, app_id.gid, app_id.start_ticks) != app_tuple[1:] or
                    (worker_id.uid, worker_id.gid, worker_id.start_ticks) != worker_tuple[1:] or
                    ready[5] != self._expected_app_hash or
                    ready[6] != self._expected_worker_hash):
                raise AuthenticationError('READY child identity/hash differs from launch profile')
            if (_proc_identity(context.process.pid) != context.identity or
                    context.executable_hash != _sha256_proc_exe(context.process.pid) or
                    _sha256_proc_exe(app_id.pid) != self._expected_app_hash or
                    _sha256_proc_exe(worker_id.pid) != self._expected_worker_hash or
                    _proc_parent(app_id.pid) != context.process.pid or
                    _proc_parent(worker_id.pid) != context.process.pid or
                    time.monotonic() >= deadline):
                raise AuthenticationError('READY child identity differs from actual process tree')
            app_pidfd = os.pidfd_open(app_id.pid, 0)
            worker_pidfd = os.pidfd_open(worker_id.pid, 0)
            if (_proc_identity(app_id.pid) != app_id or
                    _proc_identity(worker_id.pid) != worker_id or
                    _proc_parent(app_id.pid) != context.process.pid or
                    _proc_parent(worker_id.pid) != context.process.pid or
                    _sha256_proc_exe(app_id.pid) != self._expected_app_hash or
                    _sha256_proc_exe(worker_id.pid) != self._expected_worker_hash or
                    _pidfd_is_dead(app_pidfd) or _pidfd_is_dead(worker_pidfd) or
                    time.monotonic() >= deadline):
                raise AuthenticationError('READY children changed before pidfd pinning')
            st = context.rpc_path.lstat()
            context.rpc_inode = (st.st_dev, st.st_ino)
            if time.monotonic() >= deadline:
                raise DeadlineExpired('INNER_READY commit exceeded its absolute deadline')
            context.app_identity = app_id
            context.worker_identity = worker_id
            context.app_pidfd = app_pidfd
            context.worker_pidfd = worker_pidfd
            context.ready_packet = packet
            context.ready = ready
            context.events.append({'event': context.label.upper() + '_READY',
                'monotonic_ns': time.monotonic_ns(), 'pid': context.process.pid,
                'start_ticks': context.identity.start_ticks,
                'app': {'pid': app_id.pid, 'start_ticks': app_id.start_ticks,
                    'exe_sha256': self._expected_app_hash.hex()},
                'worker': {'pid': worker_id.pid, 'start_ticks': worker_id.start_ticks,
                    'exe_sha256': self._expected_worker_hash.hex()},
                'relay_nonce': context.nonce.hex(), 'relay_epoch': context.epoch,
                'broker_nonce': ready[2].hex(), 'broker_epoch': ready[3],
                'worker_profile': ready[4].hex()})
            return ready
        except BaseException as exc:
            context.unresolved_reason = f'INNER_READY validation uncertain: {exc}'
            if context.label == 'new':
                context.failure_state = 'NEW_FAILED'
            for fd in (app_pidfd, worker_pidfd):
                if fd >= 0:
                    os.close(fd)
            raise

    def launch_owner_actor(self, context, actor_path, handoff_path, generation_tag,
            timeout=10):
        if (context.ready is None or context.closed or context.owner_actor_attempted or
                context.owner_actor is not None):
            raise ProtocolError('owner actor requires a READY inner context')
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        listener.bind(str(handoff_path))
        os.chmod(handoff_path, 0o600)
        listener.listen(1)
        actor = subprocess.Popen([str(Path(actor_path).resolve()), '--serial-service',
            str(context.rpc_path), str(handoff_path), str(self.port),
            generation_tag], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, close_fds=True)
        context.owner_actor = actor
        context.owner_actor_attempted = True
        try:
            context.owner_pidfd = os.pidfd_open(actor.pid, 0)
            actor_exe = _sha256_proc_exe(actor.pid)
            expected_exe = _sha256_file(Path(actor_path).resolve())
            if actor_exe != expected_exe:
                raise AuthenticationError('owner actor executable differs from pinned test actor')
            listener.settimeout(timeout)
            channel, _ = listener.accept()
            context.owner_actor_channel = channel
            identity, watch_fd, port, address = _recv_actor_handoff(channel,
                actor, self.port, self.address_bytes, time.monotonic() + timeout)
            return OwnerWatch(context, actor, identity, context.owner_pidfd,
                channel, watch_fd, port, address)
        except BaseException:
            # Preserve exact actor/pidfd ownership; caller must mark the run
            # unresolved or use explicit test-owned cleanup.
            raise
        finally:
            listener.close()
            try:
                handoff_path.unlink()
            except FileNotFoundError:
                pass

    def prove_owner_payload(self, watch, generation_tag, nonce, timeout=8):
        if not isinstance(watch, OwnerWatch):
            raise ProtocolError('TCP payload operation requires an SDK owner actor watch')
        if generation_tag not in ('A', 'B') or not nonce:
            raise ValueError('invalid application fixture request')
        request = struct.pack('!4sIQ', b'KSG1', ord(generation_tag) - ord('A') + 1,
            nonce)
        deadline = time.monotonic() + timeout
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
        connection.settimeout(max(0.001, deadline - time.monotonic()))
        try:
            connection.connect((self.address, watch.port))
            connection.sendall(request)
            response = bytearray()
            while len(response) < 20:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise DeadlineExpired('application TCP payload response timed out')
                connection.settimeout(remaining)
                block = connection.recv(20 - len(response))
                if not block:
                    raise ProtocolError('application closed before full TCP response')
                response.extend(block)
        finally:
            connection.close()
        expected = struct.pack('!4sIQ4s', b'KSR1', ord(generation_tag) - ord('A') + 1,
            nonce, generation_tag.encode('ascii') + b'ACK')
        if bytes(response) != expected:
            raise ProtocolError(f'original-Linux TCP response mismatch: {bytes(response)!r}')
        try:
            _receive_actor_control(watch.channel, watch.actor, b'P', deadline)
        except BaseException as exc:
            watch.inner.unresolved_reason = f'actor payload acknowledgement uncertain: {exc}'
            raise
        watch.inner.events.append({'event': watch.inner.label.upper() + '_TCP_PAYLOAD',
            'monotonic_ns': time.monotonic_ns(), 'request': request.hex(),
            'response': bytes(response).hex()})
        return request, bytes(response)

    def close_owner_listener(self, watch, timeout=5):
        if not isinstance(watch, OwnerWatch):
            raise ProtocolError('listener close requires an SDK owner actor watch')
        if watch.closed or watch.actor.poll() is not None:
            raise ProtocolError('cannot close listener on an exited owner')
        deadline = time.monotonic() + timeout
        try:
            _send_actor_control(watch.channel, b'C', deadline)
            _receive_actor_control(watch.channel, watch.actor, b'C', deadline)
        except BaseException as exc:
            watch.inner.unresolved_reason = f'listener-close actor exchange uncertain: {exc}'
            raise
        # This EBUSY is required evidence: the socket/listener closed, while the
        # exact claimed owner remains alive and therefore cannot be retired.
        status, result, raw = self._verify(watch, deadline=deadline)
        if status != errno.EBUSY or result[0] != errno.EBUSY or result[-1] != 0:
            watch.inner.unresolved_reason = 'closed-listener VERIFY did not prove live-owner EBUSY'
            raise OwnerStillLive('closed-listener live owner did not remain non-retired')
        if (result[4:11] != wire._unpack_broker_result(
                watch.receipt, struct.unpack_from('<Q', watch.receipt, 40)[0])[4:11]):
            watch.inner.unresolved_reason = 'closed-listener VERIFY changed owner identity'
            raise RetirementMismatch('closed listener changed owner claim identity')
        watch.inner.events.append({'event': watch.inner.label.upper() + '_LISTENER_CLOSED_LIVE',
            'monotonic_ns': time.monotonic_ns(), 'verify_status': status,
            'owner_pid': result[4], 'owner_start': result[5], 'cookie': result[9]})
        return raw

    def exit_owner(self, watch, timeout=5):
        if not isinstance(watch, OwnerWatch):
            raise ProtocolError('owner exit requires an SDK owner actor watch')
        if watch.closed or watch.actor.poll() is not None:
            raise ProtocolError('owner actor already exited')
        deadline = time.monotonic() + timeout
        try:
            _send_actor_control(watch.channel, b'X', deadline)
            result = watch.actor.wait(timeout=max(0.001, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as exc:
            watch.inner.unresolved_reason = 'owner actor exit acknowledgement timed out'
            raise DeadlineExpired('owner did not exit on bounded control command') from exc
        if result != 0:
            watch.inner.unresolved_reason = f'owner actor exited with status {result}'
            raise ProtocolError(f'owner actor exited with status {result}')
        try:
            _wait_pidfd_dead(watch.actor_pidfd, deadline, 'owner actor')
        except BaseException as exc:
            watch.inner.unresolved_reason = f'owner actor pidfd death uncertain: {exc}'
            raise
        watch.inner.events.append({'event': watch.inner.label.upper() + '_OWNER_DEAD',
            'monotonic_ns': time.monotonic_ns(), 'pid': watch.actor.pid,
            'start_ticks': watch.actor_identity.start_ticks})

    def _verify(self, watch, timeout=8, deadline=None):
        if not isinstance(watch, OwnerWatch):
            raise ProtocolError('SDK owner VERIFY requires an actor watch')
        context = watch.inner
        if (watch.closed or context.closed or context.ready is None or
                context.unresolved_reason is not None or context.settled):
            raise ProtocolError('VERIFY on closed/unready context')
        context.relay_sequence += 1
        sequence = context.relay_sequence
        packet = wire.pack_verify(context.nonce, context.epoch, sequence)
        if deadline is None:
            deadline = time.monotonic() + timeout
        duplicate = -1
        try:
            duplicate = fcntl.fcntl(watch.watch_fd, fcntl.F_DUPFD_CLOEXEC, 0)
            while True:
                if time.monotonic() >= deadline:
                    raise DeadlineExpired('VERIFY send exceeded its absolute deadline')
                try:
                    sent = context.relay.sendmsg([packet], [(socket.SOL_SOCKET,
                        socket.SCM_RIGHTS, struct.pack('i', duplicate))],
                        getattr(socket, 'MSG_NOSIGNAL', 0))
                    if sent != wire.VERIFY_REQUEST.size:
                        raise ProtocolError('short relay VERIFY send')
                    break
                except BlockingIOError:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise DeadlineExpired('VERIFY send timed out')
                    poller = select.poll()
                    poller.register(context.relay.fileno(), select.POLLOUT | select.POLLERR)
                    poller.poll(max(1, min(100, int(remaining * 1000))))
            reply = _receive_packet(context.relay, wire.VERIFY_REPLY_PREFIX.size + 128,
                context.process.pid, deadline)
            status, broker_result = wire.unpack_verify_result(reply, context.nonce,
                context.epoch, sequence, context.ready[2], context.ready[3], context.ready[4])
            parsed = wire._unpack_broker_result(broker_result, sequence)
            watch.last_result = broker_result
            return status, parsed, broker_result
        except BaseException as exc:
            # Sequence numbers are monotonic and cannot be reused. Even if a
            # timeout occurs before send, consuming this sequence makes later
            # operations unsafe, so retain the context as unresolved.
            context.unresolved_reason = f'VERIFY sequence/response uncertain: {exc}'
            raise
        finally:
            if duplicate >= 0:
                os.close(duplicate)

    def capture_claim_receipt(self, watch):
        if not isinstance(watch, OwnerWatch):
            raise ProtocolError('claim receipt requires an SDK owner actor watch')
        if watch.receipt is not None:
            raise ProtocolError('claim receipt already captured')
        if watch.actor.poll() is not None or _pidfd_is_dead(watch.actor_pidfd):
            try:
                _, stderr = watch.actor.communicate(timeout=1)
            except subprocess.TimeoutExpired:
                stderr = b'<stderr drain timed out>'
            watch.inner.unresolved_reason = 'owner actor exited before live-owner receipt'
            raise ProtocolError(f'owner actor exited before claim receipt: {stderr!r}')
        status, result, raw = self._verify(watch)
        if status != errno.EBUSY or result[0] != errno.EBUSY or result[-1] != 0:
            watch.inner.unresolved_reason = 'initial VERIFY did not prove live-owner EBUSY'
            raise OwnerStillLive(f'expected live-owner EBUSY receipt, got {status}/{result[-1]} {result!r}')
        actor = watch.actor_identity
        if (result[4], result[5]) != (actor.pid, actor.start_ticks):
            watch.inner.unresolved_reason = 'initial VERIFY receipt names another owner'
            raise RetirementMismatch('broker live receipt is not bound to actor PID/start')
        watch.receipt = raw
        watch.inner.events.append({'event': watch.inner.label.upper() + '_OWNER_LIVE_RECEIPT',
            'monotonic_ns': time.monotonic_ns(), 'pid': actor.pid,
            'start_ticks': actor.start_ticks, 'receipt': raw.hex()})
        return raw

    def verify_owner_retired(self, watch, receipt):
        if not isinstance(watch, OwnerWatch):
            raise ProtocolError('SDK owner retirement requires an actor watch')
        if watch.receipt is None or receipt != watch.receipt:
            raise RetirementMismatch('caller receipt is not controller-captured claim receipt')
        if watch.actor.poll() is None or not _pidfd_is_dead(watch.actor_pidfd):
            raise OwnerStillLive('owner actor is not proven dead by its pidfd')
        status, result, raw = self._verify(watch)
        claim = wire._unpack_broker_result(receipt, struct.unpack_from('<Q', receipt, 40)[0])
        if status != 0 or result[0] != 0 or result[-1] != 1:
            watch.inner.unresolved_reason = 'terminal VERIFY did not prove owner retirement'
            raise RetirementMismatch('broker did not return OLD_RETIRED')
        if result[4:11] != claim[4:11]:
            watch.inner.unresolved_reason = 'terminal VERIFY changed broker-bound owner identity'
            raise RetirementMismatch('terminal result changed broker-bound owner identity')
        proof = VerifiedOwnerRetired(watch.inner, watch, receipt, raw,
            self._proof_seal)
        self._verified_proofs[id(proof)] = proof
        watch.inner.events.append({'event': watch.inner.label.upper() + '_OLD_RETIRED',
            'monotonic_ns': time.monotonic_ns(), 'receipt_sequence':
                struct.unpack_from('<Q', receipt, 40)[0], 'terminal': raw.hex()})
        return proof

    def stop_inner(self, context, retired, timeout=30, deadline=None):
        if (not isinstance(retired, VerifiedOwnerRetired) or retired.inner is not context or
                retired.watch.inner is not context or
                self._verified_proofs.get(id(retired)) is not retired or context.settled or
                context.unresolved_reason is not None):
            raise SettlementError('STOP requires this inner context’s verified retirement')
        deadline = time.monotonic() + timeout if deadline is None else deadline
        if time.monotonic() >= deadline:
            context.unresolved_reason = 'old runtime settlement deadline expired before STOP'
            raise DeadlineExpired(context.unresolved_reason)
        context.relay_sequence += 1
        sequence = context.relay_sequence
        stop_sent = False
        try:
            _send_packet(context.relay,
                wire.pack_stop(context.nonce, context.epoch, sequence), deadline)
            stop_sent = True
            context.unresolved_reason = 'STOP sent; settlement proof pending'
            accepted = _receive_packet(context.relay, wire.STOP_REPLY.size,
                context.process.pid, deadline)
            wire.unpack_stop_reply(accepted, wire.STOP_ACCEPTED, context.nonce,
                context.epoch, sequence)
            context.events.append({'event': context.label.upper() + '_STOP_ACCEPTED',
                'monotonic_ns': time.monotonic_ns(), 'sequence': sequence,
                'record': accepted.hex()})
            settled = _receive_packet(context.relay, wire.SETTLED_RECORD.size,
                context.process.pid, deadline)
            wire.unpack_settled(settled, context.ready, context.nonce, context.epoch, sequence)
            context.events.append({'event': context.label.upper() + '_SETTLED',
                'monotonic_ns': time.monotonic_ns(), 'sequence': sequence,
                'record': settled.hex()})
        except BaseException as exc:
            if stop_sent:
                context.unresolved_reason = f'STOP settlement uncertain: {exc}'
            raise
        try:
            returncode = context.process.wait(timeout=max(0.001, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as exc:
            raise SettlementError('inner process did not exit after SETTLED') from exc
        if returncode != 0:
            raise SettlementError(f'inner ker-run exited {returncode} after SETTLED')
        for pidfd, description in ((context.app_pidfd, 'broker app'),
                (context.worker_pidfd, 'IO worker'), (context.pidfd, 'inner ker-run')):
            _wait_pidfd_dead(pidfd, deadline, description)
        stats = json.loads(context.stats_path.read_text(encoding='utf-8'))
        if (stats.get('outstanding') != 0 or stats.get('run_shutdown') is not True or
                stats.get('run_shutdown_ack') is not True or
                stats.get('control_eof') is not True):
            raise SettlementError(f'inner worker stats do not prove settlement: {stats!r}')
        context.settled = True
        context.unresolved_reason = None
        context.events.append({'event': context.label.upper() + '_COMPONENTS_DEAD',
            'monotonic_ns': time.monotonic_ns(), 'inner_pid': context.process.pid,
            'app_pid': context.app_identity.pid, 'worker_pid': context.worker_identity.pid,
            'outstanding': stats['outstanding'], 'control_eof': stats['control_eof']})
        proof = RuntimeSettled(context, settled, stats, self._proof_seal)
        self._settled_proofs[id(proof)] = proof
        return proof

    def verify_external_watch(self, context, watch_fd, companion, cycle_channel,
            timeout=12, require_retired=False, live_watch=None, deadline=None):
        """Verify a C22-created watch through this inner's authenticated relay."""
        if (context is not self._old_context and context is not self._new_context) or context.ready is None:
            raise ProtocolError('external watch requires a registered ready inner')
        if context.unresolved_reason is not None or context.settled:
            raise ProtocolError('external watch VERIFY on unresolved/settled inner')
        current_watch_identity = _external_watch_identity(watch_fd)
        expected_runtime = (context.ready[2], context.ready[3], context.ready[4])
        expected_master = (companion.master_pid, os.getuid(), os.getgid(),
            companion.master_start, bytes(companion.binary_hash))
        if (tuple(cycle_channel.runtime) != expected_runtime or
                cycle_channel.master_identity != expected_master or
                cycle_channel.unresolved):
            context.unresolved_reason = 'KNGC channel does not match this ready inner and companion'
            raise AuthenticationError(context.unresolved_reason)
        registered = None
        if require_retired:
            registered = (None if live_watch is None else
                self._external_live_watches.get(id(live_watch)))
            if (live_watch is None or not isinstance(live_watch, ExternalOwnerWatch) or
                    registered is None or registered.get('watch') is not live_watch or
                    registered.get('inner') is not context or live_watch.inner is not context or
                    current_watch_identity != registered.get('watch_identity') or
                    current_watch_identity != live_watch.watch_identity or
                    registered.get('receipt') != live_watch.receipt or live_watch.closed):
                raise ProtocolError('terminal Nginx watch VERIFY requires this context’s registered authority')
        if deadline is None:
            deadline = getattr(cycle_channel, 'transition_deadline', None)
        deadline = time.monotonic() + timeout if deadline is None else deadline
        if time.monotonic() >= deadline:
            context.unresolved_reason = 'external-watch transition deadline already expired'
            raise DeadlineExpired(context.unresolved_reason)
        result = None
        raw = None
        status = None
        while time.monotonic() < deadline:
            context.relay_sequence += 1
            sequence = context.relay_sequence
            packet = wire.pack_verify(context.nonce, context.epoch, sequence)
            duplicate = -1
            try:
                duplicate = fcntl.fcntl(watch_fd, fcntl.F_DUPFD_CLOEXEC, 0)
                if time.monotonic() >= deadline:
                    raise DeadlineExpired('external-watch VERIFY expired before send')
                sent = context.relay.sendmsg([packet], [(socket.SOL_SOCKET,
                    socket.SCM_RIGHTS, struct.pack('i', duplicate))],
                    getattr(socket, 'MSG_NOSIGNAL', 0))
                if sent != wire.VERIFY_REQUEST.size:
                    raise ProtocolError('short external-watch VERIFY send')
                os.close(duplicate)
                duplicate = -1
                reply = _receive_packet(context.relay,
                    wire.VERIFY_REPLY_PREFIX.size + 128, context.process.pid, deadline)
                status, raw = wire.unpack_verify_result(reply, context.nonce,
                    context.epoch, sequence, context.ready[2], context.ready[3], context.ready[4])
                result = wire._unpack_broker_result(raw, sequence)
                if time.monotonic() >= deadline:
                    raise DeadlineExpired('external-watch VERIFY validation exceeded its deadline')
            except BaseException as exc:
                context.unresolved_reason = f'external watch VERIFY uncertain: {exc}'
                raise
            finally:
                if duplicate >= 0:
                    os.close(duplicate)
            if require_retired or status != errno.EAGAIN:
                break
            time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))
        if result is None:
            raise DeadlineExpired('external owner publication did not arrive before deadline')
        if not require_retired:
            if status != errno.EBUSY or result[0] != errno.EBUSY or result[-1] != 0:
                context.unresolved_reason = 'external watch did not prove a live published owner'
                raise OwnerStillLive(f'expected published-owner EBUSY, got {status}/{result[-1]}')
            owner_pid, owner_start = result[4], result[5]
            owner_pidfd = -1
            try:
                master_identity = _proc_identity(companion.master_pid)
                if (master_identity.start_ticks != companion.master_start or
                        _sha256_proc_exe(companion.master_pid) != companion.binary_hash or
                        _pidfd_is_dead(companion.master_pidfd)):
                    raise AuthenticationError('STARTED master identity changed during owner pinning')
                owner_identity = _proc_identity(owner_pid)
                if (_proc_parent(owner_pid) != companion.master_pid or
                        owner_identity.start_ticks != owner_start or
                        (owner_identity.uid, owner_identity.gid) !=
                            (master_identity.uid, master_identity.gid) or
                        _sha256_proc_exe(owner_pid) != companion.binary_hash):
                    raise AuthenticationError('broker owner is not a pinned Nginx worker child')
                owner_pidfd = os.pidfd_open(owner_pid, 0)
                if (_proc_identity(owner_pid) != owner_identity or
                        _proc_parent(owner_pid) != companion.master_pid or
                        _sha256_proc_exe(owner_pid) != companion.binary_hash or
                        _proc_identity(companion.master_pid) != master_identity or
                        _pidfd_is_dead(owner_pidfd) or _pidfd_is_dead(companion.master_pidfd) or
                        time.monotonic() >= deadline):
                    raise AuthenticationError('Nginx worker/master identity changed before pidfd pin')
            except BaseException as exc:
                if owner_pidfd >= 0:
                    os.close(owner_pidfd)
                context.unresolved_reason = f'Nginx owner identity pin failed: {exc}'
                raise
            master_pidfd_ref = -1
            try:
                master_pidfd_ref = os.dup(companion.master_pidfd)
                os.set_inheritable(master_pidfd_ref, False)
                if time.monotonic() >= deadline or _pidfd_is_dead(master_pidfd_ref):
                    raise DeadlineExpired('external watch registration exceeded its deadline')
                owner_watch = ExternalOwnerWatch(context, owner_identity,
                    owner_pidfd, current_watch_identity, self.port,
                    socket.inet_aton(self.address), raw, raw)
                master_identity_record = (companion.master_pid, master_identity.uid,
                    master_identity.gid, master_identity.start_ticks,
                    bytes(companion.binary_hash))
                self._external_live_watches[id(owner_watch)] = {
                    'watch': owner_watch, 'inner': context,
                    'companion': companion, 'cycle_channel': cycle_channel,
                    'watch_identity': current_watch_identity, 'receipt': raw,
                    'owner_identity': owner_identity,
                    'owner_pidfd': owner_pidfd, 'master_identity': master_identity_record,
                    'master_pidfd': master_pidfd_ref,
                    'master_executable_hash': bytes(companion.binary_hash)}
                owner_pidfd = master_pidfd_ref = -1
            except BaseException as exc:
                if owner_pidfd >= 0:
                    os.close(owner_pidfd)
                if master_pidfd_ref >= 0:
                    os.close(master_pidfd_ref)
                context.unresolved_reason = f'external watch registration failed: {exc}'
                raise
            context.events.append({'event': context.label.upper() + '_NGINX_OWNER_LIVE',
                'monotonic_ns': time.monotonic_ns(), 'pid': owner_pid,
                'start_ticks': owner_start, 'cookie': result[9], 'receipt': raw.hex()})
            return owner_watch
        if status != 0 or result[0] != 0 or result[-1] != 1:
            context.unresolved_reason = 'terminal Nginx VERIFY did not prove retirement'
            raise RetirementMismatch('broker did not return OLD_RETIRED for Nginx owner')
        claim = wire._unpack_broker_result(live_watch.receipt,
            struct.unpack_from('<Q', live_watch.receipt, 40)[0])
        if (result[4:11] != claim[4:11] or
                result[4:6] != (registered['owner_identity'].pid,
                    registered['owner_identity'].start_ticks) or
                not _pidfd_is_dead(registered['owner_pidfd']) or
                _pidfd_is_dead(registered['master_pidfd']) or
                _proc_identity(registered['master_identity'][0]).start_ticks !=
                    registered['master_identity'][3] or
                _sha256_proc_exe(registered['master_identity'][0]) !=
                    registered['master_executable_hash'] or
                time.monotonic() >= deadline):
            context.unresolved_reason = 'Nginx retirement changed owner or owner pidfd is live'
            raise RetirementMismatch('terminal receipt does not match dead Nginx owner')
        proof = VerifiedOwnerRetired(context, live_watch, live_watch.receipt,
            raw, self._proof_seal, False)
        self._verified_proofs[id(proof)] = proof
        del self._external_live_watches[id(live_watch)]
        if registered['master_pidfd'] >= 0:
            os.close(registered['master_pidfd'])
            registered['master_pidfd'] = -1
        context.events.append({'event': context.label.upper() + '_NGINX_OWNER_RETIRED',
            'monotonic_ns': time.monotonic_ns(), 'owner_pid': result[4],
            'owner_start': result[5], 'terminal': raw.hex()})
        return proof

    def record_companion_shutdown(self, context, live_watch, companion, cycle_channel):
        """Seal an authenticated final helper SETTLED plus pinned master death."""
        registered = self._external_live_watches.get(id(live_watch))
        if (context is not self._old_context and context is not self._new_context) or \
                context.ready is None or context.unresolved_reason is not None or \
                registered is None or registered.get('watch') is not live_watch or \
                registered.get('inner') is not context or live_watch.inner is not context or \
                registered.get('companion') is not companion or \
                registered.get('cycle_channel') is not cycle_channel or \
                companion.unresolved or not companion.started or not companion.stop_attempted or \
                not companion.settled or not companion.settled_record or \
                companion.helper is None or companion.helper.returncode != 0 or \
                cycle_channel.unresolved or cycle_channel.last_request is not None or \
                cycle_channel.transition_deadline is not None or \
                cycle_channel.master_identity != registered.get('master_identity') or \
                not _pidfd_is_dead(registered['master_pidfd']) or \
                cycle_channel.master_pidfd < 0 or not _pidfd_is_dead(cycle_channel.master_pidfd):
            raise SettlementError('companion shutdown is not authenticated and fully settled')
        if (companion.master_pid != registered['master_identity'][0] or
                companion.master_start != registered['master_identity'][3] or
                bytes(companion.binary_hash) != registered['master_executable_hash']):
            raise AuthenticationError('settled companion changed pinned master identity')
        proof = VerifiedCompanionShutdown(context, live_watch, companion,
            registered['master_identity'], bytes(companion.settled_record), self._proof_seal)
        self._companion_shutdown_proofs[id(proof)] = proof
        context.events.append({'event': context.label.upper() + '_NGINX_COMPANION_SETTLED',
            'monotonic_ns': time.monotonic_ns(),
            'master_pid': proof.master_identity[0],
            'master_start': proof.master_identity[3],
            'record': proof.settled_record.hex()})
        return proof

    def verify_external_shutdown_watch(self, context, watch_fd, shutdown, timeout=12):
        """Verify final owner retirement after exact companion SETTLED/master death."""
        if (not isinstance(shutdown, VerifiedCompanionShutdown) or
                shutdown._seal is not self._proof_seal or
                self._companion_shutdown_proofs.get(id(shutdown)) is not shutdown or
                shutdown.inner is not context or context.ready is None or
                context.unresolved_reason is not None or context.settled):
            raise ProtocolError("final retirement requires this controller's companion shutdown proof")
        live_watch = shutdown.watch
        registered = self._external_live_watches.get(id(live_watch))
        if (registered is None or registered.get('watch') is not live_watch or
                registered.get('inner') is not context or live_watch.inner is not context or
                registered.get('companion') is not shutdown.companion or
                registered.get('master_identity') != shutdown.master_identity or
                registered.get('cycle_channel').master_identity != shutdown.master_identity or
                not live_watch.receipt or live_watch.closed):
            raise ProtocolError('final retirement watch no longer matches settled companion proof')
        if _external_watch_identity(watch_fd) != registered.get('watch_identity'):
            raise ProtocolError('final retirement descriptor is not the registered watch capability')
        companion = shutdown.companion
        cycle_channel = registered['cycle_channel']
        if (not companion.settled or companion.unresolved or companion.helper.returncode != 0 or
                bytes(companion.settled_record) != shutdown.settled_record or
                not _pidfd_is_dead(registered['master_pidfd']) or
                cycle_channel.master_pidfd < 0 or not _pidfd_is_dead(cycle_channel.master_pidfd)):
            raise SettlementError('companion SETTLED/master-death proof changed before VERIFY')
        deadline = time.monotonic() + timeout
        context.relay_sequence += 1
        sequence = context.relay_sequence
        packet = wire.pack_verify(context.nonce, context.epoch, sequence)
        duplicate = -1
        try:
            duplicate = fcntl.fcntl(watch_fd, fcntl.F_DUPFD_CLOEXEC, 0)
            if time.monotonic() >= deadline:
                raise DeadlineExpired('final retirement VERIFY expired before send')
            sent = context.relay.sendmsg([packet], [(socket.SOL_SOCKET,
                socket.SCM_RIGHTS, struct.pack('i', duplicate))],
                getattr(socket, 'MSG_NOSIGNAL', 0))
            if sent != wire.VERIFY_REQUEST.size:
                raise ProtocolError('short final retirement VERIFY send')
            os.close(duplicate)
            duplicate = -1
            reply = _receive_packet(context.relay,
                wire.VERIFY_REPLY_PREFIX.size + 128, context.process.pid, deadline)
            status, raw = wire.unpack_verify_result(reply, context.nonce,
                context.epoch, sequence, context.ready[2], context.ready[3], context.ready[4])
            result = wire._unpack_broker_result(raw, sequence)
            claim = wire._unpack_broker_result(live_watch.receipt,
                struct.unpack_from('<Q', live_watch.receipt, 40)[0])
            if (time.monotonic() >= deadline or status != 0 or result[0] != 0 or
                    result[-1] != 1 or result[4:11] != claim[4:11] or
                    result[4:6] != (registered['owner_identity'].pid,
                        registered['owner_identity'].start_ticks) or
                    not _pidfd_is_dead(registered['owner_pidfd']) or
                    not companion.settled or companion.unresolved or
                    bytes(companion.settled_record) != shutdown.settled_record or
                    not _pidfd_is_dead(registered['master_pidfd']) or
                    not _pidfd_is_dead(cycle_channel.master_pidfd) or
                    time.monotonic() >= deadline):
                raise RetirementMismatch('terminal result does not match settled companion retirement')
        except BaseException as exc:
            context.unresolved_reason = f'final companion retirement VERIFY uncertain: {exc}'
            raise
        finally:
            if duplicate >= 0:
                os.close(duplicate)
        proof = VerifiedOwnerRetired(context, live_watch, live_watch.receipt,
            raw, self._proof_seal, True)
        self._verified_proofs[id(proof)] = proof
        del self._companion_shutdown_proofs[id(shutdown)]
        del self._external_live_watches[id(live_watch)]
        for key in ('master_pidfd',):
            fd = registered.get(key, -1)
            if fd >= 0:
                os.close(fd)
                registered[key] = -1
        context.events.append({'event': context.label.upper() + '_NGINX_OWNER_RETIRED_AFTER_SHUTDOWN',
            'monotonic_ns': time.monotonic_ns(), 'owner_pid': result[4],
            'owner_start': result[5], 'terminal': raw.hex()})
        return proof

    def record_successor_tcp_failure(self, context, error):
        if (context is not self._new_context or context.label != 'new' or
                context.closed or context.settled or context.unresolved_reason is not None or
                not isinstance(error, OSError) or error.errno != errno.ECONNREFUSED):
            raise NewGenerationError('only an observed refused successor TCP connection can fail B')
        context.failure_state = 'NEW_FAILED'
        context.unresolved_reason = 'NEW_FAILED: successor TCP listener did not accept connections'
        context.events.append({'event': 'NEW_FAILED_TCP_REFUSED',
            'monotonic_ns': time.monotonic_ns(), 'errno': error.errno,
            'pid': context.process.pid, 'rpc_path': str(context.rpc_path),
            'rpc_inode': context.rpc_inode})
        return NewGenerationError(context.unresolved_reason)

    def start_next(self, old, retired, settled, launch=None):
        if (old is not self._old_context or old.closed or old.advanced):
            raise SettlementError('advance is not available for this old context')
        if old.process.poll() is None or not _pidfd_is_dead(old.pidfd):
            raise SettlementError('old inner process is not dead')
        if not _pidfd_is_dead(old.app_pidfd) or not _pidfd_is_dead(old.worker_pidfd):
            raise SettlementError('old broker app or worker is still alive')
        if not old.settled:
            raise SettlementError('old inner runtime has no controller-recorded SETTLED proof')
        if (not isinstance(retired, VerifiedOwnerRetired) or
                not isinstance(settled, RuntimeSettled) or retired.inner is not old or
                settled.inner is not old or retired.watch.inner is not old or
                retired._seal is not self._proof_seal or
                settled._seal is not self._proof_seal or
                retired.companion_shutdown or
                self._verified_proofs.get(id(retired)) is not retired or
                self._settled_proofs.get(id(settled)) is not settled):
            raise SettlementError('advance requires retirement and settlement from the same live context')
        old.advanced = True
        del self._verified_proofs[id(retired)]
        del self._settled_proofs[id(settled)]
        self.close_watch(retired.watch)
        self.close_context(old, 'settled')
        if launch is not None:
            self.launch = launch
        return self._start_inner('new', self._advance_key)

    def close_watch(self, watch):
        if watch.closed:
            return
        if isinstance(watch, ExternalOwnerWatch):
            registered = self._external_live_watches.pop(id(watch), None)
            if registered is not None and registered.get('watch') is watch:
                master_pidfd = registered.get('master_pidfd', -1)
                if master_pidfd >= 0:
                    os.close(master_pidfd)
                    registered['master_pidfd'] = -1
            if watch.actor_pidfd >= 0:
                os.close(watch.actor_pidfd)
                watch.actor_pidfd = -1
            watch.closed = True
            return
        os.close(watch.watch_fd)
        os.close(watch.actor_pidfd)
        watch.channel.close()
        watch.inner.owner_actor_channel = None
        watch.watch_fd = watch.actor_pidfd = -1
        watch.inner.owner_pidfd = -1
        watch.closed = True

    def close_context(self, context, outcome):
        if context.closed:
            return
        if outcome != 'settled' or not context.settled:
            raise SettlementError('only a controller-settled context may be closed')
        if (context.process.poll() is None or context.app_pidfd < 0 or
                context.worker_pidfd < 0 or not _pidfd_is_dead(context.pidfd) or
                not _pidfd_is_dead(context.app_pidfd) or
                not _pidfd_is_dead(context.worker_pidfd)):
            raise SettlementError('cannot close before inner, app and worker pidfd death')
        if outcome == 'settled' and context.rpc_inode is not None:
            try:
                current = context.rpc_path.lstat()
            except FileNotFoundError:
                current = None
            if current is not None:
                if (current.st_dev, current.st_ino) != context.rpc_inode:
                    raise SettlementError('RPC pathname was replaced by an unknown inode')
                context.rpc_path.unlink()
        context.relay.close()
        for fd in (context.app_pidfd, context.worker_pidfd, context.pidfd):
            if fd >= 0:
                os.close(fd)
        context.log.close()
        context.closed = True
