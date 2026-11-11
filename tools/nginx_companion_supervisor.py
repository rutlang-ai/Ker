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
                 owner_ready_required=False):
        self.binary = Path(binary).resolve(strict=True)
        self.config = Path(config).resolve(strict=True)
        self.prefix = Path(prefix).resolve(strict=True)
        self.nginx_env = dict(nginx_env)
        self.cycle_control_fd = cycle_control_fd
        self.owner_ready_required = bool(owner_ready_required)
        self.owner_pidfd = -1
        self.owner_pid = 0
        self.owner_start = 0
        self.owner_tid = 0
        self.owner_role = 0
        self.owner_slot_device = 0
        self.owner_slot_inode = 0
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
                        if rights_count == 0:
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
                if len(packet) not in expected_sizes or len(fds) != rights_count:
                    raise ValueError('helper record length or descriptor count mismatch')
                if time.monotonic() > deadline:
                    raise TimeoutError('Nginx helper record arrived after deadline')
                return packet, fds
            except BaseException:
                _close_fds(fds)
                raise

    def start(self, timeout=15.0):
        if self.helper is not None:
            raise RuntimeError('Nginx companion is one-use')
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
        for key, value in sorted(self.nginx_env.items()):
            command += ['--nginx-env', f'{key}={value}']
        env = {'PATH': '/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE': '1'}
        try:
            self.helper = subprocess.Popen(command, env=env,
                pass_fds=tuple(helper_pass_fds), close_fds=True,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=None, start_new_session=True)
        finally:
            child.close()
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
                        expected_gid=os.getgid(), expected_role=0)
                    (owner_pid, owner_uid, owner_gid, owner_role, owner_tid,
                     _reserved, owner_start, slot_device, slot_inode,
                     _cookie) = fields
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
        if self.supervisor_pidfd >= 0:
            os.close(self.supervisor_pidfd)
            self.supervisor_pidfd = -1
        if self.channel is not None:
            self.channel.close()
            self.channel = None
