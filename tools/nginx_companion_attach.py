"""Attach-only observer binding to an accepted original Nginx source origin.

This module may launch and reap its pinned observer helper. It never launches,
signals, waits for, or settles the original Nginx master subtree.
"""
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
import threading
import time

_WIRE_SPEC = importlib.util.spec_from_file_location(
    '_ker_nginx_companion_attach_wire', Path(__file__).resolve().with_name(
        'nginx_companion_wire.py'))
if _WIRE_SPEC is None or _WIRE_SPEC.loader is None:
    raise ImportError('cannot load the companion wire codec beside this module')
wire = importlib.util.module_from_spec(_WIRE_SPEC)
_WIRE_SPEC.loader.exec_module(wire)

_UCRED = struct.Struct('=3i')


def _is_original_shell_launch(value):
    cls = type(value)
    expected = Path(__file__).resolve().with_name('nginx_source_origin.py')
    for module in tuple(sys.modules.values()):
        if module is None:
            continue
        try:
            if Path(module.__file__).resolve(strict=True) != expected:
                continue
        except (AttributeError, OSError, TypeError):
            continue
        if cls is getattr(module, 'OriginalShellLaunch', None):
            return True
        private_type = getattr(module, 'PrivateC34OriginalShellLaunch', None)
        if cls is private_type:
            artifacts = sys.modules.get('_ker_nginx_source_c34_artifacts')
            capture = getattr(value, 'c34_artifact_capture', None)
            if (artifacts is not None and type(capture) is
                    getattr(artifacts, 'PrivateC34ArtifactCapture', None) and
                    capture.profile_id == 'NEWC34_INTEROP'):
                return True
    return False


def _pidfd_pid(fd):
    for line in Path(f'/proc/self/fdinfo/{fd}').read_text(encoding='ascii').splitlines():
        if line.startswith('Pid:\t'):
            pid = int(line.split('\t', 1)[1], 10)
            if pid > 0:
                return pid
    raise OSError(9, 'invalid pidfd')


def _start_ticks(pid):
    text = Path(f'/proc/{pid}/stat').read_text(encoding='ascii')
    fields = text[text.rfind(')') + 2:].split()
    if len(fields) <= 19:
        raise RuntimeError('malformed process stat')
    ticks = int(fields[19], 10)
    if ticks <= 0:
        raise RuntimeError('invalid process start time')
    return ticks


def _parent_pid(pid):
    text = Path(f'/proc/{pid}/stat').read_text(encoding='ascii')
    fields = text[text.rfind(')') + 2:].split()
    if len(fields) <= 1:
        raise RuntimeError('malformed process stat')
    return int(fields[1], 10)


def _sha256(path, *, deadline_ns, maximum=256 * 1024 * 1024):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if before.st_size < 0 or before.st_size > maximum:
            raise ValueError('pinned source executable exceeds the hash bound')
        total = 0
        while True:
            if time.monotonic_ns() >= deadline_ns:
                raise TimeoutError('pinned source hash deadline expired')
            try:
                block = stream.read(min(1024 * 1024, maximum - total + 1))
            except InterruptedError:
                continue
            if not block:
                break
            total += len(block)
            if total > maximum or time.monotonic_ns() >= deadline_ns:
                raise TimeoutError('pinned source hash exceeded its bound')
            digest.update(block)
        after = os.fstat(stream.fileno())
        if time.monotonic_ns() >= deadline_ns:
            raise TimeoutError('pinned source hash deadline expired')
        metadata = lambda value: (value.st_dev, value.st_ino, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)
        if metadata(before) != metadata(after) or total != after.st_size:
            raise RuntimeError('pinned source file changed during bounded hash')
    return digest.digest()


def _alive(pidfd):
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    return not poller.poll(0)


def _close_fds(fds):
    for fd in fds:
        try:
            os.close(fd)
        except OSError:
            pass


class AttachObserverUnsettled(RuntimeError):
    """Retain the exact observer helper handle after bounded cleanup timed out."""
    def __init__(self, attachment, cause):
        self.attachment = attachment
        super().__init__('attach observer helper is still exiting after setup failure')
        self.__cause__ = cause


class SourceAttachment:
    """Bind only a live ``OriginalShellLaunch`` that accepted ORIGIN_ACK.

    An exact pinned observer helper is launched for the private seqpacket
    channel. The helper receives the accepted owner/master PIDFDs; it never
    launches or owns the original Nginx master.
    """
    def __init__(self, accepted_origin, *, revoke_native_auth, helper_path=None):
        if not callable(revoke_native_auth):
            raise TypeError('attach requires the caller native-auth revocation callback')
        if not _is_original_shell_launch(accepted_origin):
            raise TypeError('attach requires the accepted OriginalShellLaunch object')
        launch = accepted_origin
        if (not getattr(launch, 'consumed', False) or launch.context is None or
                launch.master_pidfd < 0 or launch.origin_pidfd < 0 or
                launch.pidfd < 0 or launch.process is None or
                launch.process.poll() is not None or
                launch.artifact_binding is None or launch.origin_proof is None):
            raise PermissionError('attach requires a live accepted source origin')
        context = launch.context
        master = context.master
        owner_pid = launch.creator_pid
        if owner_pid != os.getpid() or _start_ticks(owner_pid) != launch.creator_start:
            raise PermissionError('accepted source owner is not the live SDK creator')
        if (_pidfd_pid(launch.master_pidfd) != master.pid or
                master.pid <= 0 or master.pidfd != launch.master_pidfd or
                not _alive(launch.master_pidfd) or
                _start_ticks(master.pid) != master.start_ticks or
                master.executable_hash != context.binary_hash or
                context.nonce != launch.nonce or context.epoch != launch.epoch or
                context.deadline_ns != launch.deadline_ns or
                _sha256(f'/proc/{master.pid}/exe',
                    deadline_ns=launch.deadline_ns) != context.binary_hash):
            raise PermissionError('accepted source master identity/profile changed')
        if time.monotonic_ns() >= launch.deadline_ns:
            raise TimeoutError('accepted source origin expired before attach')
        if launch.deadline_ns > time.monotonic_ns() + 300_000_000_000:
            raise PermissionError('accepted source origin exceeds the bounded lifetime')

        self.launch = launch
        self.context = context
        self.revoke_native_auth = revoke_native_auth
        self.owner_pid = owner_pid
        self.owner_start = launch.creator_start
        self.master_pid = master.pid
        self.master_start = master.start_ticks
        self.master_pidfd = launch.master_pidfd
        self.binary_hash = bytes(context.binary_hash)
        self.nonce = bytes(launch.nonce)
        self.epoch = launch.epoch
        self.sequence = 1
        self.attached = False
        self.ready = None
        self.candidate_ready = None
        self._candidate_watch_attempted = False
        self._revoked = False
        self.owner_pidfd = -1
        self.helper_pidfd = -1
        self.helper = None
        self.channel = None
        self.child_channel = None
        try:
            self._initialize_resources(launch, helper_path)
        except BaseException as error:
            try:
                self.close()
            except BaseException:
                pass
            if self.helper is not None and self.helper.poll() is None:
                raise AttachObserverUnsettled(self, error) from error
            raise

    def _initialize_resources(self, launch, helper_path):
        # Bind the profile to the exact accepted original artifacts, without
        # inventing a Ker helper launch profile.
        binding = launch.artifact_binding
        try:
            config_hash = bytes.fromhex(binding.config_sha256)
            ini_hash = bytes.fromhex(binding.ini_sha256)
        except (AttributeError, ValueError) as error:
            raise PermissionError('accepted source artifact digests are malformed') from error
        if len(config_hash) != 32 or len(ini_hash) != 32:
            raise PermissionError('accepted source artifact digests are malformed')
        self.owner_pidfd = os.pidfd_open(self.owner_pid, 0)
        if (_pidfd_pid(self.owner_pidfd) != self.owner_pid or
                not _alive(self.owner_pidfd) or _start_ticks(self.owner_pid) != self.owner_start):
            raise PermissionError('accepted source owner pidfd changed identity')
        profile_material = (b'ker.nginx.source-attach/v1\0' + self.nonce +
            struct.pack('<QQ', self.epoch, launch.deadline_ns) + self.binary_hash + config_hash +
            ini_hash + os.fsencode(launch.output))
        self.profile = hashlib.sha256(profile_material).digest()

        self.helper_path = Path(helper_path) if helper_path is not None else \
            Path(__file__).resolve().with_name('ker-nginx-companion.py')
        self.helper_path = self.helper_path.resolve(strict=True)
        self.helper_hash = _sha256(self.helper_path,
            deadline_ns=launch.deadline_ns, maximum=4 * 1024 * 1024)
        parent, child = socket.socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        self.channel = parent
        self.child_channel = child
        parent.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        child.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        python_path = Path(launch.python.path).resolve(strict=True)
        command = [str(python_path), str(self.helper_path), '--source-attach-only',
            '--control-fd', str(child.fileno()), '--helper-sha256',
            self.helper_hash.hex()]
        try:
            self.helper = subprocess.Popen(command,
                env={'PATH': '/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE': '1'},
                pass_fds=(child.fileno(),), close_fds=True,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=None)
        finally:
            child.close()
            self.child_channel = None
        self.helper_pid = self.helper.pid
        self.helper_start = _start_ticks(self.helper_pid)
        self.helper_pidfd = os.pidfd_open(self.helper_pid, 0)
        self.helper_exe_hash = _sha256(f'/proc/{self.helper_pid}/exe',
            deadline_ns=launch.deadline_ns)

    def _identity_body(self):
        return wire.ATTACH_BODY.pack(self.owner_pid, os.getuid(), os.getgid(), 0,
            self.owner_start, self.launch.deadline_ns, self.master_pid,
            os.getuid(), os.getgid(), 0,
            self.master_start, self.binary_hash, self.profile)

    def attach(self, timeout=5.0):
        if self.attached:
            raise RuntimeError('source attachment is one-use')
        if type(timeout) not in (int, float) or timeout <= 0:
            raise ValueError('attach timeout must be positive')
        absolute_deadline = min(self.launch.deadline_ns / 1_000_000_000,
            time.monotonic() + timeout)
        try:
            self.launch.live_supervisor(self.launch.deadline_ns)
            remaining = absolute_deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('accepted source origin expired before attach')
            if (self.helper.poll() is not None or not _alive(self.helper_pidfd) or
                    _parent_pid(self.helper_pid) != os.getpid() or
                    _start_ticks(self.helper_pid) != self.helper_start or
                    _sha256(f'/proc/{self.helper_pid}/exe',
                        deadline_ns=self.launch.deadline_ns) != self.helper_exe_hash):
                raise ProcessLookupError('pinned observer helper identity changed before attach')
            if not _alive(self.master_pidfd):
                raise ProcessLookupError('accepted original Nginx master exited before attach')
        except BaseException:
            self._fail_observation()
            raise
        packet = wire.pack_record(wire.ATTACH, self._identity_body(), self.nonce,
            self.epoch, self.sequence)
        rights = array.array('i', (self.owner_pidfd, self.master_pidfd))
        try:
            self.channel.settimeout(max(0.001, absolute_deadline - time.monotonic()))
            sent = self.channel.sendmsg([packet], [(socket.SOL_SOCKET,
                socket.SCM_RIGHTS, rights)], getattr(socket, 'MSG_NOSIGNAL', 0))
            if sent != len(packet):
                raise OSError(5, 'short source ATTACH seqpacket send')
        except BaseException:
            self._fail_observation()
            raise
        try:
            remaining = absolute_deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('ATTACHED exceeded its absolute request deadline')
            self.channel.settimeout(remaining)
            data, ancillary, flags, _ = self.channel.recvmsg(wire.ATTACHED_BYTES + 1,
                socket.CMSG_SPACE(_UCRED.size) + socket.CMSG_SPACE(4 * 4),
                getattr(socket, 'MSG_CMSG_CLOEXEC', 0))
        except BaseException:
            self._fail_observation()
            raise
        fds = []
        credentials = []
        try:
            invalid = bool(flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC))
            for level, kind, payload in ancillary:
                if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(payload) == _UCRED.size:
                    credentials.append(_UCRED.unpack(payload))
                elif level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    usable = len(payload) - len(payload) % 4
                    if usable:
                        fds.extend(array.array('i', payload[:usable]))
                    invalid = True
                else:
                    invalid = True
            expected_cred = (self.helper_pid, os.getuid(), os.getgid())
            if (invalid or fds or len(data) != wire.ATTACHED_BYTES or
                    credentials != [expected_cred]):
                kind = wire.unpack_header(data)[0] if len(data) >= wire.HEADER.size else None
                raise PermissionError('ATTACHED credentials, size, or ancillary data mismatch '
                    f'(type={kind!r}, bytes={len(data)}, credentials={credentials!r}, '
                    f'expected={expected_cred!r}, fds={len(fds)}, invalid={invalid})')
            fields = wire.unpack_record(data, wire.ATTACHED, self.nonce,
                self.epoch, self.sequence, wire.ATTACHED_BODY)
            if fields != wire.ATTACH_BODY.unpack(self._identity_body()):
                raise PermissionError('ATTACHED original identity/profile mismatch')
            self.launch.live_supervisor(self.launch.deadline_ns)
            if time.monotonic() >= absolute_deadline:
                raise TimeoutError('ATTACHED exceeded its absolute request deadline')
            if (not _alive(self.master_pidfd) or
                    _start_ticks(self.master_pid) != self.master_start):
                raise ProcessLookupError('accepted original Nginx master changed during attach')
            self.attached = True
            self.sequence += 1
            self.channel.settimeout(None)
            return fields
        except BaseException:
            _close_fds(fds)
            self.attached = False
            self._fail_observation()
            raise

    def _fail_observation(self):
        self.close()

    def receive_owner_ready(self, watch, receiver, timeout=15.0):
        try:
            return self._receive_owner_ready(watch, receiver, timeout,
                expected_role=0)
        except BaseException:
            self._fail_observation()
            raise

    def receive_first_candidate_ready(self, watch, receiver, timeout=15.0):
        """Observe one first-HUP role-1 READY on the already attached session."""
        try:
            return self._receive_owner_ready(watch, receiver, timeout,
                expected_role=1)
        except BaseException:
            self._fail_observation()
            raise

    def _receive_owner_ready(self, watch, receiver, timeout, *, expected_role=0):
        """Require one credentialed READY for the fixed initial/candidate role."""
        if (not self.attached or threading.current_thread() is not threading.main_thread() or
                os.getpid() != self.owner_pid or self.launch.context is not self.context or
                not _alive(self.owner_pidfd) or _pidfd_pid(self.owner_pidfd) != self.owner_pid or
                _start_ticks(self.owner_pid) != self.owner_start):
            raise PermissionError('source READY observation lost its main-thread Origin owner')
        if (expected_role == 0 and self.ready is not None) or (
                expected_role == 1 and (self.ready is None or
                    self.candidate_ready is not None or self._candidate_watch_attempted)):
            raise RuntimeError('source READY role is unavailable or its watch was already attempted')
        required = {'pid', 'tid', 'role', 'start', 'slot_device', 'slot_inode', 'cookie', 'pidfd'}
        if not isinstance(watch, dict) or not required <= set(watch):
            raise ValueError('source worker watch is incomplete')
        if (watch['tid'] != watch['pid'] or watch['role'] != expected_role or
                min(watch['pid'], watch['start'], watch['slot_device'],
                    watch['slot_inode'], watch['cookie']) <= 0):
            raise ValueError('attach accepts only the fixed original/candidate worker role')
        if (_pidfd_pid(watch['pidfd']) != watch['pid'] or
                not _alive(watch['pidfd']) or _start_ticks(watch['pid']) != watch['start']):
            raise PermissionError('source worker watch is stale')
        if (receiver.family != socket.AF_UNIX or
                receiver.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_SEQPACKET or
                receiver.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) != 1):
            raise PermissionError('source READY receiver lacks credentialed seqpacket transport')
        watch_body = wire.SOURCE_WATCH_BODY.pack(watch['pid'], watch['tid'],
            watch['role'], 0, watch['start'], watch['slot_device'],
            watch['slot_inode'], watch['cookie'])
        watch_record = wire.pack_record(wire.SOURCE_WATCH, watch_body,
            self.nonce, self.epoch, self.sequence)
        ready_sequence = self.sequence
        now_ns = time.monotonic_ns()
        request_deadline_ns = min(self.launch.deadline_ns,
            now_ns + int(timeout * 1_000_000_000))
        if now_ns >= request_deadline_ns:
            raise TimeoutError('accepted source origin expired before SOURCE_WATCH')
        watch_fds = array.array('i', (receiver.fileno(), watch['pidfd']))
        send_remaining = (request_deadline_ns - time.monotonic_ns()) / 1_000_000_000
        if send_remaining <= 0:
            raise TimeoutError('source watch send exceeded its absolute request deadline')
        if expected_role == 1:
            # Burn before send: a short result or lost reply leaves an unknown
            # watch outcome and this observer session cannot retry it safely.
            self._candidate_watch_attempted = True
        self.channel.settimeout(send_remaining)
        if self.channel.sendmsg([watch_record], [(socket.SOL_SOCKET,
                socket.SCM_RIGHTS, watch_fds)], getattr(socket, 'MSG_NOSIGNAL', 0)) != len(watch_record):
            raise OSError(5, 'short source SOURCE_WATCH seqpacket send')
        self.channel.settimeout(None)
        spec = importlib.util.spec_from_file_location(
            '_ker_nginx_companion_attach_helper', Path(__file__).resolve().with_name(
                'ker-nginx-companion.py'))
        if spec is None or spec.loader is None:
            raise ImportError('cannot load owner READY verifier beside attach adapter')
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        expected = (watch['pid'], os.getuid(), os.getgid(), watch['role'],
            watch['tid'], 0, watch['start'], watch['slot_device'],
            watch['slot_inode'], watch['cookie'])
        identity, ready_pidfd = helper.receive_attached_owner_ready(
            self.channel, nonce=self.nonce, epoch=self.epoch,
            sequence=ready_sequence,
            deadline_ns=request_deadline_ns,
            expected_credential=(self.helper_pid, os.getuid(), os.getgid()),
            expected_identity=expected, expected_worker_pidfd=watch['pidfd'],
            worker_binary_hash=self.binary_hash, master_pidfd=self.master_pidfd,
            master_pid=self.master_pid, master_start=self.master_start,
            owner_pidfd=self.owner_pidfd, owner_pid=self.owner_pid,
            owner_start=self.owner_start, expected_role=expected_role)
        try:
            self.launch.live_supervisor(request_deadline_ns)
            if (time.monotonic_ns() >= request_deadline_ns or
                    not _alive(self.master_pidfd) or
                    _start_ticks(self.master_pid) != self.master_start or
                    not _alive(ready_pidfd) or
                    _pidfd_pid(ready_pidfd) != identity[0] or
                    _start_ticks(identity[0]) != identity[6] or
                    _parent_pid(identity[0]) != self.master_pid):
                raise PermissionError('source READY expired or changed before attachment binding')
            master_hash = _sha256(f'/proc/{self.master_pid}/exe',
                deadline_ns=request_deadline_ns)
            worker_hash = _sha256(f'/proc/{identity[0]}/exe',
                deadline_ns=request_deadline_ns)
            if master_hash != self.binary_hash or worker_hash != self.binary_hash:
                raise PermissionError('source READY executable changed before attachment binding')
            self.launch.live_supervisor(request_deadline_ns)
            if (time.monotonic_ns() >= request_deadline_ns or
                    not _alive(self.master_pidfd) or
                    _start_ticks(self.master_pid) != self.master_start or
                    not _alive(ready_pidfd) or
                    _pidfd_pid(ready_pidfd) != identity[0] or
                    _start_ticks(identity[0]) != identity[6] or
                    _parent_pid(identity[0]) != self.master_pid or
                    time.monotonic_ns() >= request_deadline_ns):
                raise PermissionError('source READY expired or changed before attachment binding')
            self.sequence += 1
            if expected_role == 0:
                self.ready = (identity, ready_pidfd)
            else:
                self.candidate_ready = (identity, ready_pidfd)
        except BaseException:
            os.close(ready_pidfd)
            raise
        return identity, ready_pidfd

    def close(self):
        """Revoke first, then drop only observer-owned handles and reap helper."""
        revoke_error = None
        if not self._revoked:
            self._revoked = True
            try:
                self.revoke_native_auth()
            except BaseException as error:
                revoke_error = error
        try:
            self._cleanup_owned_resources()
        finally:
            self.attached = False
        if revoke_error is not None:
            raise revoke_error

    def _cleanup_owned_resources(self):
        ready = getattr(self, 'ready', None)
        for name in ('ready', 'candidate_ready'):
            ready = getattr(self, name, None)
            if ready is not None:
                try:
                    os.close(ready[1])
                except OSError:
                    pass
                setattr(self, name, None)
        for name in ('owner_pidfd',):
            fd = getattr(self, name, -1)
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
                setattr(self, name, -1)
        for name in ('child_channel', 'channel'):
            channel = getattr(self, name, None)
            if channel is not None:
                try:
                    channel.close()
                except OSError:
                    pass
                setattr(self, name, None)
        helper = getattr(self, 'helper', None)
        if helper is not None:
            try:
                helper.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                return
        helper_pidfd = getattr(self, 'helper_pidfd', -1)
        if helper_pidfd >= 0:
            try:
                os.close(helper_pidfd)
            except OSError:
                pass
            self.helper_pidfd = -1

    def check(self):
        """Revalidate the bound source actors without acquiring lifecycle authority."""
        if not self.attached or self.ready is None:
            raise RuntimeError('source attachment is not ready for observation')
        try:
            self.launch.live_supervisor(self.launch.deadline_ns)
            ready_workers = [self.ready]
            if self.candidate_ready is not None:
                ready_workers.append(self.candidate_ready)
            if (not _alive(self.master_pidfd) or
                    self.helper.poll() is not None or not _alive(self.helper_pidfd) or
                    _start_ticks(self.master_pid) != self.master_start or
                    _sha256(f'/proc/{self.master_pid}/exe',
                        deadline_ns=self.launch.deadline_ns) != self.binary_hash):
                raise ProcessLookupError('attached original master or observer helper exited')
            for identity, worker_pidfd in ready_workers:
                if (not _alive(worker_pidfd) or
                        _pidfd_pid(worker_pidfd) != identity[0] or
                        _start_ticks(identity[0]) != identity[6] or
                        _parent_pid(identity[0]) != self.master_pid or
                        _sha256(f'/proc/{identity[0]}/exe',
                            deadline_ns=self.launch.deadline_ns) != self.binary_hash or
                        not Path(f'/proc/{identity[0]}/task/{identity[4]}').exists() or
                        identity[0] <= 0):
                    raise ProcessLookupError('attached READY worker exited or changed identity '
                        f'(pid={identity[0]}, alive={_alive(worker_pidfd)}, '
                        f'start={_start_ticks(identity[0])!r}, '
                        f'parent={_parent_pid(identity[0])!r})')
            poller = select.poll()
            poller.register(self.channel.fileno(), select.POLLIN | select.POLLHUP |
                select.POLLERR | select.POLLNVAL)
            events = poller.poll(0)
            if events:
                raise ConnectionError('attached source control channel closed or sent an unexpected record')
            return True
        except BaseException:
            self._fail_observation()
            raise
