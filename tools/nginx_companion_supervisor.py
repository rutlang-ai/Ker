"""Parent-side protocol client for the private Nginx containment helper."""
import array
import hashlib
import importlib.util
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import time
from types import SimpleNamespace

_WIRE_SPEC = importlib.util.spec_from_file_location(
    '_ker_nginx_companion_wire', Path(__file__).resolve().with_name(
        'nginx_companion_wire.py'))
if _WIRE_SPEC is None or _WIRE_SPEC.loader is None:
    raise ImportError('cannot load the companion wire codec beside this module')
wire = importlib.util.module_from_spec(_WIRE_SPEC)
_WIRE_SPEC.loader.exec_module(wire)

_UCRED = struct.Struct('=3i')


def _start_ticks(pid):
    text = Path(f'/proc/{pid}/stat').read_text(encoding='ascii')
    close = text.rfind(')')
    if close < 0:
        raise RuntimeError('malformed process stat')
    fields = text[close + 2:].split()
    if len(fields) <= 19:
        raise RuntimeError('incomplete process stat')
    value = int(fields[19], 10)
    if value <= 0:
        raise RuntimeError('invalid process start time')
    return value


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.digest()


def _pidfd_pid(fd):
    for line in Path(f'/proc/self/fdinfo/{fd}').read_text(encoding='ascii').splitlines():
        if line.startswith('Pid:\t'):
            pid = int(line.split('\t', 1)[1], 10)
            if pid > 0:
                return pid
    raise OSError(9, 'invalid pidfd')


def process_alive(pidfd):
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    return not poller.poll(0)


def _close_fds(fds):
    for fd in fds:
        try:
            os.close(fd)
        except OSError:
            pass


class NginxCompanion:
    """Own one helper and one exact pinned non-daemon Nginx master subtree."""
    def __init__(self, binary, config, prefix, nginx_env, cycle_control_fd=None,
                 owner_ready_required=False, rx_owner_relay_fd=None,
                 candidate_slot_transfer_fd=None, initial_slot_transfer_fd=None,
                 source_bootstrap_required=False):
        self.binary = Path(binary).resolve(strict=True)
        self.config = Path(config).resolve(strict=True)
        self.prefix = Path(prefix).resolve(strict=True)
        self.nginx_env = dict(nginx_env)
        self.cycle_control_fd = cycle_control_fd
        self.owner_ready_required = bool(owner_ready_required)
        self.source_bootstrap_required = bool(source_bootstrap_required)
        if self.source_bootstrap_required and not self.owner_ready_required:
            raise ValueError('source bootstrap requires authenticated worker READY')
        self.rx_owner_relay_fd = rx_owner_relay_fd
        if candidate_slot_transfer_fd is not None and initial_slot_transfer_fd is not None:
            raise ValueError('one delegated owner role is required')
        self.initial_slot_mode = initial_slot_transfer_fd is not None
        self.candidate_slot_transfer_fd = (initial_slot_transfer_fd if self.initial_slot_mode
            else candidate_slot_transfer_fd)
        self.candidate_slot_stat = None
        self.expected_owner_role = 1 if candidate_slot_transfer_fd is not None else 0
        if self.initial_slot_mode and (
                self.nginx_env.get('KER_NGINX_INITIAL_SLOT_FD') != str(initial_slot_transfer_fd) or
                self.nginx_env.get('KER_NGINX_SOURCE_PEER_OLD') != '1' or
                'KER_NGINX_CANDIDATE_SLOT_FD' in self.nginx_env):
            raise ValueError('initial slot requires the explicit original old-owner profile')
        if ((candidate_slot_transfer_fd is None) !=
                ('KER_NGINX_CANDIDATE_SLOT_FD' not in self.nginx_env)):
            raise ValueError('candidate slot descriptor and Nginx profile must be supplied together')
        if candidate_slot_transfer_fd is not None and int(
                self.nginx_env['KER_NGINX_CANDIDATE_SLOT_FD'], 10) != candidate_slot_transfer_fd:
            raise ValueError('candidate slot transfer descriptor differs from Nginx profile')
        self.owner_pidfd = -1
        self.owner_pid = 0
        self.owner_start = 0
        self.owner_tid = 0
        self.owner_role = 0
        self.owner_slot_device = 0
        self.owner_slot_inode = 0
        self.owner_cookie = 0
        cycle_keys = {key for key in self.nginx_env if key.startswith('KER_NGINX_CYCLE_')}
        required_cycle_keys = {'KER_NGINX_CYCLE_FD', 'KER_NGINX_CYCLE_NONCE',
            'KER_NGINX_CYCLE_RUNTIME_NONCE', 'KER_NGINX_CYCLE_RUNTIME_EPOCH',
            'KER_NGINX_CYCLE_WORKER_PROFILE_SHA256', 'KER_NGINX_CYCLE_OUTER_EXE_SHA256'}
        if ((bool(cycle_keys) != (cycle_control_fd is not None)) or
                (cycle_keys and cycle_keys != required_cycle_keys)):
            raise ValueError('cycle-control fd and complete serial Nginx profile must be supplied together')
        if cycle_control_fd is not None and int(self.nginx_env['KER_NGINX_CYCLE_FD'], 10) != cycle_control_fd:
            raise ValueError('cycle-control descriptor differs from pinned Nginx environment')
        self.binary_hash = _sha256(self.binary)
        self.config_hash = _sha256(self.config)
        self.ini_hash = _sha256(self.nginx_env['KER_FSTACK_NGINX_INI'])
        self.profile = wire.profile_hash(self.binary_hash, self.config_hash,
            self.ini_hash, str(self.prefix), self.nginx_env)
        self.helper_path = Path(__file__).resolve().with_name('ker-nginx-companion')
        if not self.helper_path.is_file():
            self.helper_path = self.helper_path.with_name('ker-nginx-companion.py')
        self.helper_path = self.helper_path.resolve(strict=True)
        self.helper_script_hash = _sha256(self.helper_path)
        self.nonce = os.urandom(16)
        while not any(self.nonce):
            self.nonce = os.urandom(16)
        self.epoch = int.from_bytes(os.urandom(8), 'little') or 1
        self.supervisor_pid = os.getpid()
        self.supervisor_uid = os.getuid()
        self.supervisor_gid = os.getgid()
        self.supervisor_start = _start_ticks(self.supervisor_pid)
        self.supervisor_pidfd = -1
        self.master_pidfd = -1
        self.master_pid = 0
        self.master_start = 0
        self.helper = None
        self.channel = None
        self.sequence = 2
        self.started = False
        self.stop_attempted = False
        self.settled = False
        self.settled_record = None
        self.unresolved = False
        self.source_watch = None
        self.source_candidate = None
        self.source_candidate_attempted = False

    def watch_source_worker(self, watch, receiver, timeout=5.0):
        if (not self.source_bootstrap_required or self.master_pidfd < 0 or
                self.started or self.unresolved or self.source_watch is not None):
            raise RuntimeError('source startup watch is not available')
        body = wire.SOURCE_WATCH_BODY.pack(watch['pid'], watch['tid'],
            watch['role'], 0, watch['start'], watch['slot_device'],
            watch['slot_inode'], watch['cookie'])
        self._send(wire.pack_record(wire.SOURCE_WATCH, body, self.nonce,
            self.epoch, 1), (receiver.fileno(), watch['pidfd']), time.monotonic() + timeout)
        self.source_watch = dict(watch)

    def _send(self, packet, rights, deadline):
        sent_rights = False
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('Nginx helper channel send deadline expired')
            try:
                if rights and not sent_rights:
                    ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                        array.array('i', rights))]
                    sent = self.channel.sendmsg([packet], ancillary,
                        getattr(socket, 'MSG_NOSIGNAL', 0))
                    if sent == len(packet):
                        sent_rights = True
                else:
                    sent = self.channel.send(packet, getattr(socket, 'MSG_NOSIGNAL', 0))
                if sent != len(packet):
                    raise OSError(5, 'short Nginx helper SOCK_SEQPACKET send')
                return
            except BlockingIOError:
                poller = select.poll()
                poller.register(self.channel.fileno(), select.POLLOUT |
                    select.POLLHUP | select.POLLERR)
                poller.poll(max(1, int(remaining * 1000)))

    def _receive(self, expected_size, deadline, rights_count):
        allowed_rights = (rights_count,) if isinstance(rights_count, int) else rights_count
        expected_sizes = ((expected_size,) if isinstance(expected_size, int)
            else tuple(expected_size))
        if not expected_sizes or any(size <= 0 for size in expected_sizes):
            raise ValueError('invalid expected helper record sizes')
        poller = select.poll()
        poller.register(self.channel.fileno(), select.POLLIN | select.POLLHUP |
            select.POLLERR | select.POLLNVAL)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('Nginx helper channel receive deadline expired')
            events = poller.poll(max(1, int(remaining * 1000)))
            if not events:
                continue
            if (events[0][1] & (select.POLLHUP | select.POLLERR | select.POLLNVAL) and
                    not events[0][1] & select.POLLIN):
                raise ConnectionError('Nginx helper control channel closed')
            packet, ancillary, flags, _ = self.channel.recvmsg(max(expected_sizes) + 1,
                socket.CMSG_SPACE(_UCRED.size) + socket.CMSG_SPACE(8 * 4),
                getattr(socket, 'MSG_CMSG_CLOEXEC', 0))
            credentials = None
            fds = []
            ancillary_error = None
            try:
                for level, kind, payload in ancillary:
                    if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS:
                        if credentials is not None or len(payload) != _UCRED.size:
                            ancillary_error = ValueError('duplicate/malformed helper credentials')
                        elif ancillary_error is None:
                            credentials = _UCRED.unpack(payload)
                    elif level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                        if allowed_rights == (0,):
                            ancillary_error = ValueError('unexpected helper descriptor ancillary data')
                        usable = len(payload) - len(payload) % 4
                        if usable:
                            fds.extend(array.array('i', payload[:usable]))
                    else:
                        ancillary_error = ValueError('unexpected helper ancillary data')
                if ancillary_error is not None:
                    raise ancillary_error
                if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
                    raise ValueError('truncated Nginx helper record')
                if credentials != (self.helper.pid, os.getuid(), os.getgid()):
                    raise PermissionError(f'helper credentials {credentials!r} did not match '
                        f'pinned Popen child {(self.helper.pid, os.getuid(), os.getgid())!r}')
                if len(packet) not in expected_sizes or len(fds) not in allowed_rights:
                    kind = wire.unpack_header(packet)[0] if len(packet) >= wire.HEADER.size else None
                    details = None
                    if kind == wire.ERROR and len(packet) == wire.ERROR_BYTES:
                        details = wire.ERROR_BODY.unpack_from(packet, wire.HEADER.size)
                    raise ValueError('helper record length or descriptor count mismatch '
                        f'kind={kind} bytes={len(packet)} expected={expected_sizes} '
                        f'fds={len(fds)} expected_fds={rights_count} error={details!r}')
                if time.monotonic() > deadline:
                    raise TimeoutError('Nginx helper record arrived after deadline')
                return packet, fds
            except BaseException:
                _close_fds(fds)
                raise

    def _receive_candidate_slot(self, timeout):
        transfer_fd = self.candidate_slot_transfer_fd
        expected_peer = os.getppid()
        transfer = socket.socket(fileno=transfer_fd)
        received_fds = []
        detached = False
        try:
            if transfer.family != socket.AF_UNIX or transfer.getsockopt(
                    socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_SEQPACKET:
                raise PermissionError('candidate-cap transfer is not a Unix seqpacket')
            transfer.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            peer = transfer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _UCRED.size)
            peer_pid, peer_uid, peer_gid = _UCRED.unpack(peer)
            if (peer_pid != expected_peer or peer_uid != os.getuid() or
                    peer_gid != os.getgid()):
                raise PermissionError('candidate-cap transfer peer is not the launching tap')
            transfer.settimeout(timeout)
            packet, ancillary, flags, _ = transfer.recvmsg(64,
                socket.CMSG_SPACE(_UCRED.size) + socket.CMSG_SPACE(4 * 4),
                getattr(socket, 'MSG_CMSG_CLOEXEC', 0))
            credentials = []
            ancillary_error = False
            for level, kind, payload in ancillary:
                if level != socket.SOL_SOCKET:
                    ancillary_error = True
                    continue
                if kind == socket.SCM_CREDENTIALS and len(payload) == _UCRED.size:
                    credentials.append(_UCRED.unpack(payload))
                elif kind == socket.SCM_RIGHTS and len(payload) % 4 == 0:
                    values = array.array('i'); values.frombytes(payload)
                    received_fds.extend(values)
                else:
                    ancillary_error = True
            truncation = flags & (getattr(socket, 'MSG_TRUNC', 0) |
                getattr(socket, 'MSG_CTRUNC', 0))
            unexpected_flags = flags & ~(getattr(socket, 'MSG_TRUNC', 0) |
                getattr(socket, 'MSG_CTRUNC', 0) |
                getattr(socket, 'MSG_CMSG_CLOEXEC', 0))
            tag = b'KER_INITIAL_SLOT_V1' if self.initial_slot_mode else b'KER_CANDIDATE_SLOT_V1'
            if (packet != tag or truncation or unexpected_flags or ancillary_error or
                    credentials != [(peer_pid, peer_uid, peer_gid)] or
                    len(received_fds) != 1):
                raise ValueError('candidate-cap transfer mismatch '
                    f'packet={packet!r} flags={flags} ancillary_error={ancillary_error} '
                    f'credentials={credentials!r} rights={len(received_fds)} '
                    f'peer={(peer_pid, peer_uid, peer_gid)!r}')
            self.candidate_slot_stat = os.fstat(received_fds[0])
            os.dup2(received_fds[0], transfer_fd, inheritable=True)
            transfer.detach()
            detached = True
            os.close(received_fds[0]); received_fds.clear()
            # The inherited transfer descriptor now carries the delegated
            # candidate capability. Keep ownership until Popen transfers it.
        except BaseException:
            for fd in received_fds:
                try: os.close(fd)
                except OSError: pass
            if detached:
                try: os.close(transfer_fd)
                except OSError: pass
            else:
                transfer.close()
            self.candidate_slot_transfer_fd = None
            raise

    def start(self, timeout=15.0, *, on_master_started=None):
        if self.helper is not None:
            raise RuntimeError('Nginx companion is one-use')
        if self.source_bootstrap_required and not callable(on_master_started):
            raise ValueError('source bootstrap requires a pinned master binding callback')
        if self.candidate_slot_transfer_fd is not None:
            self._receive_candidate_slot(timeout)
        parent, child = socket.socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        parent.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        self.channel = parent
        command = [sys.executable, str(self.helper_path),
            '--control-fd', str(child.fileno()), '--nonce', self.nonce.hex(),
            '--epoch', str(self.epoch), '--binary', str(self.binary),
            '--config', str(self.config), '--prefix', str(self.prefix),
            '--helper-sha256', self.helper_script_hash.hex()]
        helper_pass_fds = [child.fileno()]
        if self.cycle_control_fd is not None:
            command += ['--cycle-control-fd', str(self.cycle_control_fd)]
            helper_pass_fds.append(self.cycle_control_fd)
        if self.owner_ready_required:
            command.append('--owner-ready-required')
        if self.source_bootstrap_required:
            command.append('--source-bootstrap-required')
        if self.rx_owner_relay_fd is not None:
            command += ['--rx-owner-relay-fd', str(self.rx_owner_relay_fd)]
            helper_pass_fds.append(self.rx_owner_relay_fd)
        if self.candidate_slot_transfer_fd is not None:
            command += ['--initial-slot-fd' if self.initial_slot_mode else '--candidate-slot-fd',
                str(self.candidate_slot_transfer_fd)]
            helper_pass_fds.append(self.candidate_slot_transfer_fd)
        for key, value in sorted(self.nginx_env.items()):
            command += ['--nginx-env', f'{key}={value}']
        env = {'PATH': '/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE': '1'}
        try:
            self.helper = subprocess.Popen(command, env=env,
                pass_fds=tuple(helper_pass_fds), close_fds=True,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=None, start_new_session=True)
        except BaseException:
            if self.candidate_slot_transfer_fd is not None:
                try: os.close(self.candidate_slot_transfer_fd)
                except OSError: pass
                self.candidate_slot_transfer_fd = None
            raise
        finally:
            child.close()
        if self.candidate_slot_transfer_fd is not None:
            os.close(self.candidate_slot_transfer_fd)
            self.candidate_slot_transfer_fd = None
        self.channel.setblocking(False)
        self.supervisor_pidfd = os.pidfd_open(self.supervisor_pid, 0)
        deadline = time.monotonic() + timeout
        fds = []
        try:
            packet, fds = self._receive(wire.HELLO_BYTES, deadline, 0)
            record_type, nonce, epoch, sequence = wire.unpack_header(packet)
            if (record_type != wire.HELLO or nonce != self.nonce or
                    epoch != self.epoch or sequence != 0):
                raise ValueError('invalid Nginx helper HELLO')
            body = wire.START_BODY.pack(self.supervisor_pid, self.supervisor_uid,
                self.supervisor_gid, 0, self.supervisor_start,
                _sha256('/proc/self/exe'), self.binary_hash, self.config_hash)
            start_record = wire.pack_record(wire.START, body, self.nonce,
                self.epoch, 1)
            self._send(start_record, (self.supervisor_pidfd,), deadline)
            packet, fds = self._receive(wire.STARTED_BYTES, deadline, 1)
            fields = wire.unpack_record(packet, wire.STARTED, self.nonce,
                self.epoch, 1, wire.STARTED_BODY)
            (pid, uid, gid, reserved, start_ticks, binary_hash, profile) = fields
            if (reserved or pid <= 0 or uid != os.getuid() or gid != os.getgid() or
                    pid != _pidfd_pid(fds[0]) or binary_hash != self.binary_hash or
                    profile != self.profile):
                raise PermissionError('Nginx STARTED identity/profile mismatch')
            child_stat = Path(f'/proc/{pid}/stat').read_text(encoding='ascii')
            child_fields = child_stat[child_stat.rfind(')') + 2:].split()
            if (len(child_fields) <= 1 or int(child_fields[1], 10) != self.helper.pid or
                    _start_ticks(pid) != start_ticks or
                    _sha256(f'/proc/{pid}/exe') != self.binary_hash):
                raise PermissionError('Nginx master is not the exact helper-owned executable')
            self.master_pid = pid
            self.master_start = start_ticks
            self.master_pidfd = fds.pop()
            # STARTED already authenticates the exact helper-owned master.
            # Source slim startup is waiting for re-delegation at this point;
            # bind it before waiting for the first worker's independent READY.
            if on_master_started is not None:
                on_master_started(self)
            if self.owner_ready_required:
                packet, fds = self._receive((wire.OWNER_READY_BYTES,
                    wire.ERROR_BYTES), deadline, 1)
                worker_pidfd = -1
                try:
                    record_type, nonce, epoch, sequence = wire.unpack_header(packet)
                    if ((nonce, epoch, sequence) != (self.nonce, self.epoch, 1)):
                        raise ValueError('Nginx owner READY correlation mismatch')
                    if record_type == wire.ERROR:
                        fields = wire.unpack_record(packet, wire.ERROR, self.nonce,
                            self.epoch, 1, wire.ERROR_BODY)
                        wire.validate_error(fields)
                        raise RuntimeError(f'Nginx owner READY failed: {fields!r}')
                    fields = wire.unpack_record(packet, wire.OWNER_READY,
                        self.nonce, self.epoch, 1, wire.OWNER_READY_BODY)
                    wire.validate_owner_ready(fields, expected_uid=os.getuid(),
                        expected_gid=os.getgid(), expected_role=self.expected_owner_role)
                    (owner_pid, owner_uid, owner_gid, owner_role, owner_tid,
                     _reserved, owner_start, slot_device, slot_inode,
                     owner_cookie) = fields
                    if self.candidate_slot_stat is not None and (
                            slot_device != self.candidate_slot_stat.st_dev or
                            slot_inode != self.candidate_slot_stat.st_ino):
                        raise PermissionError('Nginx candidate READY does not identify the transferred slot capability')
                    if self.source_bootstrap_required:
                        if self.source_watch is None or any((
                            owner_pid != self.source_watch['pid'],
                            owner_tid != self.source_watch['tid'],
                            owner_start != self.source_watch['start'],
                            slot_device != self.source_watch['slot_device'],
                            slot_inode != self.source_watch['slot_inode'],
                            owner_cookie != self.source_watch['cookie'])):
                            raise PermissionError('source worker READY differs from exact delegated watch')
                    worker_pidfd = fds.pop()
                    if (_pidfd_pid(worker_pidfd) != owner_pid or
                            not process_alive(worker_pidfd) or
                            _start_ticks(owner_pid) != owner_start or
                            _sha256(f'/proc/{owner_pid}/exe') != self.binary_hash or
                            not Path(f'/proc/{owner_pid}/task/{owner_tid}').exists()):
                        raise PermissionError('Nginx worker READY PIDFD/process identity mismatch')
                    worker_stat = Path(f'/proc/{owner_pid}/stat').read_text(encoding='ascii')
                    worker_fields = worker_stat[worker_stat.rfind(')') + 2:].split()
                    if (owner_uid != os.getuid() or owner_gid != os.getgid() or
                            len(worker_fields) <= 1 or
                            int(worker_fields[1], 10) != self.master_pid):
                        raise PermissionError('Nginx READY worker is not a child of pinned master')
                    self.owner_pidfd = worker_pidfd
                    self.owner_pid = owner_pid
                    self.owner_start = owner_start
                    self.owner_tid = owner_tid
                    self.owner_role = owner_role
                    self.owner_slot_device = slot_device
                    self.owner_slot_inode = slot_inode
                    self.owner_cookie = owner_cookie
                    worker_pidfd = -1
                finally:
                    _close_fds(fds)
                    if worker_pidfd >= 0:
                        os.close(worker_pidfd)
            self.started = True
        except BaseException:
            self.unresolved = True
            raise
        finally:
            _close_fds(fds)

    def _request(self, record_type, response_types, response_size, timeout, validator):
        if not self.started or self.settled or self.unresolved:
            raise RuntimeError('Nginx companion is not in an active state')
        sequence = self.sequence
        packet = wire.pack_record(record_type, b'', self.nonce, self.epoch, sequence)
        deadline = time.monotonic() + timeout
        try:
            self._send(packet, (), deadline)
            response, fds = self._receive(response_size, deadline, 0)
            try:
                got_type, nonce, epoch, got_sequence = wire.unpack_header(response)
                if (nonce != self.nonce or epoch != self.epoch or
                        got_sequence != sequence or got_type not in response_types):
                    raise ValueError('Nginx helper response correlation mismatch')
                validator(response, got_type)
            finally:
                _close_fds(fds)
            self.sequence += 1
            if self.sequence > wire.MAX_SEQUENCE:
                raise OverflowError('Nginx helper request sequence exhausted')
        except BaseException:
            self.unresolved = True
            raise

    def reload(self, timeout=10.0):
        if self.owner_ready_required:
            raise NotImplementedError(
                'reload is unavailable until successor FF worker READY is authenticated')
        def validate(packet, _record_type):
            fields = wire.unpack_record(packet, wire.RELOAD_RESULT, self.nonce,
                self.epoch, self.sequence, wire.RELOAD_RESULT_BODY)
            wire.validate_reload_result(fields, self.master_start, self.profile)
            if fields[0] != 0:
                raise OSError(fields[0], 'Nginx reload failed')
        self._request(wire.RELOAD, (wire.RELOAD_RESULT,),
            (wire.RELOAD_RESULT_BYTES, wire.ERROR_BYTES), timeout, validate)

    def signal_source_hup(self, timeout=5.0):
        """Deliver HUP to the pinned source master; does not certify a reload.

        The original FSM and a separately authenticated successor determine
        the result. The current owner watch remains in force throughout.
        """
        if not self.source_bootstrap_required or not self.owner_ready_required:
            raise RuntimeError('source HUP requires the authenticated source profile')

        def validate(packet, _record_type):
            fields = wire.unpack_record(packet, wire.SOURCE_HUP_DELIVERED,
                self.nonce, self.epoch, self.sequence, wire.RELOAD_RESULT_BODY)
            wire.validate_reload_result(fields, self.master_start, self.profile)
            if fields[0] != 0:
                raise OSError(fields[0], 'source HUP delivery failed')

        self._request(wire.SOURCE_HUP, (wire.SOURCE_HUP_DELIVERED,),
            (wire.RELOAD_RESULT_BYTES, wire.ERROR_BYTES), timeout, validate)

    def watch_source_candidate(self, watch, receiver, timeout=20.0):
        """Authenticate successor READY, retaining the current owner's watch."""
        if (not self.source_bootstrap_required or not self.started or self.unresolved or
                self.settled or self.source_candidate_attempted or self.owner_role != 0 or
                watch['role'] != 1 or watch['source_epoch'] != 1 or watch['generation'] != 1):
            raise RuntimeError('source candidate watch is not available')
        self.source_candidate_attempted = True
        deadline = time.monotonic() + timeout
        body = wire.SOURCE_WATCH_BODY.pack(watch['pid'], watch['tid'], 1, 0,
            watch['start'], watch['slot_device'], watch['slot_inode'], watch['cookie'])
        fds = []
        failed = None
        try:
            self._send(wire.pack_record(wire.SOURCE_CANDIDATE_WATCH, body,
                self.nonce, self.epoch, self.sequence),
                (receiver.fileno(), watch['pidfd']), deadline)
            packet, fds = self._receive((wire.OWNER_READY_BYTES, wire.ERROR_BYTES),
                deadline, (0, 1))
            kind, nonce, epoch, sequence = wire.unpack_header(packet)
            if (nonce, epoch, sequence) != (self.nonce, self.epoch, self.sequence):
                raise ValueError('source candidate response correlation mismatch')
            if kind == wire.SOURCE_CANDIDATE_FAILED:
                fields = wire.unpack_record(packet, kind, self.nonce, self.epoch,
                    self.sequence, wire.ERROR_BODY)
                wire.validate_error(fields)
                if fds or fields[2:] != (self.master_pid, 0, self.master_start, self.profile):
                    raise PermissionError('source candidate failure changed master identity')
                failed = fields[0]
            elif kind == wire.SOURCE_CANDIDATE_READY:
                fields = wire.unpack_record(packet, kind, self.nonce, self.epoch,
                    self.sequence, wire.OWNER_READY_BODY)
                wire.validate_owner_ready(fields, expected_uid=os.getuid(),
                    expected_gid=os.getgid(), expected_role=1, expected_cookie=watch['cookie'])
                pid, _, _, role, tid, _, start, dev, inode, cookie = fields
                if (len(fds) != 1 or (pid, tid, start, dev, inode) !=
                        (watch['pid'], watch['tid'], watch['start'],
                            watch['slot_device'], watch['slot_inode']) or
                        _pidfd_pid(fds[0]) != pid or not process_alive(fds[0]) or
                        _start_ticks(pid) != start or _sha256(f'/proc/{pid}/exe') != self.binary_hash or
                        int(Path(f'/proc/{pid}/stat').read_text().rpartition(')')[2].split()[1]) != self.master_pid or
                        pid == self.owner_pid or cookie == self.owner_cookie or
                        (dev, inode) == (self.owner_slot_device, self.owner_slot_inode)):
                    raise PermissionError('source successor READY does not match delegated identity')
                self.source_candidate = SimpleNamespace(owner_pid=pid, owner_tid=tid,
                    owner_start=start, owner_role=role, owner_slot_device=dev,
                    owner_slot_inode=inode, owner_cookie=cookie, owner_pidfd=fds.pop())
            else:
                raise ValueError('unexpected source candidate response')
            self.sequence += 1
            if self.sequence > wire.MAX_SEQUENCE:
                raise OverflowError('companion request sequence exhausted')
        except BaseException:
            self.unresolved = True
            raise
        finally:
            _close_fds(fds)
        if failed is not None:
            raise ChildProcessError(failed, 'original source candidate failed before READY')
        return self.source_candidate

    def promote_source_candidate(self, timeout=5.0):
        """Replace containment watch after caller verifies native/source commit.

        This ack does not move a selector or source FSM. The caller must keep
        the original master paused at its handover hook until this returns.
        """
        candidate = self.source_candidate
        if (not self.source_bootstrap_required or candidate is None or
                not self.started or self.unresolved or self.settled):
            raise RuntimeError('source promotion is not available')
        fields = (candidate.owner_pid, os.getuid(), os.getgid(), 1,
            candidate.owner_tid, 0, candidate.owner_start, candidate.owner_slot_device,
            candidate.owner_slot_inode, candidate.owner_cookie)
        deadline = time.monotonic() + timeout
        fds = []
        try:
            self._send(wire.pack_record(wire.SOURCE_PROMOTE,
                wire.OWNER_READY_BODY.pack(*fields), self.nonce, self.epoch,
                self.sequence), (), deadline)
            packet, fds = self._receive(wire.OWNER_READY_BYTES, deadline, 0)
            got = wire.unpack_record(packet, wire.SOURCE_PROMOTED, self.nonce,
                self.epoch, self.sequence, wire.OWNER_READY_BODY)
            if got != fields or not process_alive(candidate.owner_pidfd):
                raise PermissionError('source promotion changed candidate identity')
            self.sequence += 1
            if self.sequence > wire.MAX_SEQUENCE:
                raise OverflowError('companion request sequence exhausted')
            os.close(self.owner_pidfd)
            for name, value in vars(candidate).items():
                setattr(self, name, value)
            self.source_candidate = None
        except BaseException:
            self.unresolved = True
            raise
        finally:
            _close_fds(fds)

    def check(self):
        """Raise immediately for an unsolicited pinned-master/helper failure."""
        if not self.started or self.settled or self.unresolved:
            return
        if self.helper.poll() is not None:
            self.unresolved = True
            raise RuntimeError('Nginx containment helper exited before SETTLED')
        if self.owner_ready_required and (self.owner_pidfd < 0 or
                not process_alive(self.owner_pidfd) or
                _start_ticks(self.owner_pid) != self.owner_start):
            self.unresolved = True
            raise RuntimeError('delegated Nginx FF owner exited or changed identity')
        poller = select.poll()
        poller.register(self.channel.fileno(), select.POLLIN | select.POLLHUP |
            select.POLLERR | select.POLLNVAL)
        events = poller.poll(0)
        if not events:
            return
        mask = events[0][1]
        if not mask & select.POLLIN:
            self.unresolved = True
            raise RuntimeError('Nginx containment control channel failed')
        try:
            packet, fds = self._receive(wire.ERROR_BYTES,
                time.monotonic() + 0.25, 0)
            try:
                fields = wire.unpack_record(packet, wire.ERROR, self.nonce,
                    self.epoch, self.sequence, wire.ERROR_BODY)
                wire.validate_error(fields)
                if (fields[2] != self.master_pid or
                        fields[4] != self.master_start or
                        fields[5] != self.profile):
                    raise ValueError('unsolicited error changed pinned master identity')
                raise RuntimeError(f'Nginx containment became unresolved: {fields!r}')
            finally:
                _close_fds(fds)
        except BaseException:
            self.unresolved = True
            raise

    def stop(self, timeout=15.0):
        if self.stop_attempted:
            raise RuntimeError('Nginx STOP is one-use')
        self.stop_attempted = True

        def validate(packet, record_type):
            if record_type == wire.ERROR:
                fields = wire.unpack_record(packet, wire.ERROR, self.nonce,
                    self.epoch, self.sequence, wire.ERROR_BODY)
                wire.validate_error(fields)
                raise RuntimeError(f'Nginx containment unresolved: {fields!r}')
            fields = wire.unpack_record(packet, wire.SETTLED, self.nonce,
                self.epoch, self.sequence, wire.SETTLED_BODY)
            wire.validate_settled(fields, self.master_pid, self.master_start,
                self.profile)
            if fields[0] != 0:
                raise RuntimeError(f'Nginx settlement failed: {fields!r}')
            if self.owner_ready_required and process_alive(self.owner_pidfd):
                raise RuntimeError('Nginx companion settled while delegated FF owner remains alive')
            self.settled_record = bytes(packet)
        self._request(wire.STOP, (wire.SETTLED, wire.ERROR),
            wire.SETTLED_BYTES, timeout, validate)
        try:
            self.helper.wait(timeout=2)
        except subprocess.TimeoutExpired as error:
            self.unresolved = True
            raise RuntimeError('helper did not exit after SETTLED') from error
        if self.helper.returncode != 0:
            self.unresolved = True
            raise RuntimeError(f'helper exited {self.helper.returncode} after SETTLED')
        self.settled = True

    def close(self):
        if not self.settled:
            if self.helper is None:
                if self.channel is not None:
                    self.channel.close()
                    self.channel = None
                return
            self.unresolved = True
            # Keep the supervisor channel and both PIDFDs as evidence/handles
            # while ker-run retains the worker and native broker resources.
            return
        if self.master_pidfd >= 0:
            os.close(self.master_pidfd)
            self.master_pidfd = -1
        if self.owner_pidfd >= 0:
            os.close(self.owner_pidfd)
            self.owner_pidfd = -1
        if self.source_candidate is not None:
            os.close(self.source_candidate.owner_pidfd)
            self.source_candidate = None
        if self.supervisor_pidfd >= 0:
            os.close(self.supervisor_pidfd)
            self.supervisor_pidfd = -1
        if self.channel is not None:
            self.channel.close()
            self.channel = None
