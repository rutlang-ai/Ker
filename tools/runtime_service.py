"""Private, per-run lease for the resident native IO worker.

This is deliberately separate from the socket capability broker. The ker-run
supervisor owns the worker process and its shutdown channel, so it is the
authority that can pin that real resource lifetime.
"""
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import secrets
import select
import socket
import struct
import threading
import time

_WIRE_PATH = Path(__file__).resolve().with_name('runtime_service_wire.py')
_WIRE_SPEC = importlib.util.spec_from_file_location('_ker_runtime_service_wire', _WIRE_PATH)
if _WIRE_SPEC is None or _WIRE_SPEC.loader is None:
    raise ImportError(f'cannot load runtime-service codec beside {__file__}')
wire = importlib.util.module_from_spec(_WIRE_SPEC)
_WIRE_SPEC.loader.exec_module(wire)

SO_PEERPIDFD = getattr(socket, 'SO_PEERPIDFD', 77)
_UCRED = struct.Struct('=3i')
_CREDENTIAL = struct.Struct('=3i')


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.digest()


def process_start_ticks(pid):
    text = Path(f'/proc/{pid}/stat').read_text(encoding='ascii')
    close = text.rfind(')')
    if close < 0:
        raise RuntimeError('malformed process stat')
    fields = text[close + 2:].split()
    if len(fields) <= 19:
        raise RuntimeError('short process stat')
    value = int(fields[19], 10)
    if value <= 0:
        raise RuntimeError('invalid process start time')
    return value


def process_executable_hash(pid):
    digest = hashlib.sha256()
    with open(f'/proc/{pid}/exe', 'rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.digest()


def process_comm(pid):
    return Path(f'/proc/{pid}/comm').read_text(encoding='ascii').rstrip('\n')


def _pidfd_dead(pidfd):
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLERR | select.POLLHUP | select.POLLNVAL)
    events = poller.poll(0)
    if not events:
        return False
    flags = events[0][1]
    if flags & select.POLLNVAL:
        raise OSError(9, 'pidfd became invalid')
    if flags & select.POLLERR:
        raise OSError(5, 'pidfd poll failed')
    return bool(flags & (select.POLLIN | select.POLLHUP))


class RuntimeServiceSupervisor:
    """Own one authenticated lease over a ker-run-launched child and worker."""
    def __init__(self, path, worker, worker_pidfd, worker_start_ticks,
                 worker_executable_hash, ready_record, app_executable_hash,
                 app_profile_hash, control_fd, ttl_seconds=30.0,
                 clock=time.monotonic):
        if len(worker_executable_hash) != 32 or len(app_executable_hash) != 32:
            raise ValueError('runtime-service executable hashes must be SHA256')
        if len(app_profile_hash) != 32:
            raise ValueError('runtime-service app profile must be SHA256')
        if not isinstance(ready_record, dict) or ready_record.get('process_type') != 'primary':
            raise ValueError('runtime service requires a validated primary KER_IO_READY record')
        if not isinstance(ready_record.get('mbuf_pool_count'), int) or ready_record['mbuf_pool_count'] <= 0:
            raise ValueError('runtime service requires a live worker mbuf pool')
        if not isinstance(ready_record.get('queues'), int) or ready_record['queues'] <= 0:
            raise ValueError('runtime service requires configured worker queues')
        if control_fd < 0:
            raise ValueError('runtime service requires the worker shutdown channel')
        self.path = os.path.abspath(os.fspath(path))
        if len(os.fsencode(self.path)) >= 108:
            raise ValueError('runtime-service socket path exceeds sun_path')
        self.worker = worker
        self.worker_pidfd = os.dup(worker_pidfd)
        self.worker_pid = worker.pid
        self.worker_start_ticks = worker_start_ticks
        self.worker_executable_hash = worker_executable_hash
        self.app_executable_hash = app_executable_hash
        self.supervisor_pid = os.getpid()
        self.supervisor_start_ticks = process_start_ticks(self.supervisor_pid)
        self.supervisor_executable_hash = process_executable_hash(self.supervisor_pid)
        self.control_fd = os.dup(control_fd)
        self.ready_record = dict(ready_record)
        profile = json.dumps(self.ready_record, sort_keys=True, separators=(',', ':')).encode()
        self.worker_profile_hash = hashlib.sha256(
            worker_executable_hash + profile).digest()
        self.role_profile_hash = hashlib.sha256(
            self.worker_profile_hash + app_profile_hash).digest()
        self.run_nonce = secrets.token_bytes(wire.NONCE_BYTES)
        self.ticket = secrets.token_bytes(wire.TICKET_BYTES)
        self.epoch = secrets.randbits(64) or 1
        self.ttl_seconds = ttl_seconds
        self.clock = clock
        self._lock = threading.RLock()
        self._condition = threading.Condition(self._lock)
        self._listener = None
        self._thread = None
        self._clients = set()
        self._connection_threads = set()
        self._actor = None
        self._actor_target = None
        self._claim_consumed = False
        self._revoked = False
        self._closed = False
        self._release_reason = None

    @property
    def env(self):
        return {
            'KER_RUNTIME_SERVICE_PATH': self.path,
            'KER_RUNTIME_SERVICE_NONCE': self.run_nonce.hex(),
            'KER_RUNTIME_SERVICE_EPOCH': str(self.epoch),
            'KER_RUNTIME_SERVICE_TICKET': self.ticket.hex(),
            'KER_RUNTIME_SERVICE_PROFILE': self.role_profile_hash.hex(),
            'KER_RUNTIME_SERVICE_WORKER_PROFILE': self.worker_profile_hash.hex(),
            'KER_RUNTIME_SERVICE_SUPERVISOR_PID': str(self.supervisor_pid),
            'KER_RUNTIME_SERVICE_SUPERVISOR_START_TICKS': str(self.supervisor_start_ticks),
            'KER_RUNTIME_SERVICE_SUPERVISOR_EXE_SHA256': self.supervisor_executable_hash.hex(),
            'KER_RUNTIME_SERVICE_APP_SHA256': self.app_executable_hash.hex(),
        }

    @property
    def active_count(self):
        with self._lock:
            return int(self._actor is not None and not self._revoked)

    @property
    def revoked(self):
        with self._lock:
            return self._revoked

    def start(self):
        with self._lock:
            if self._thread is not None:
                raise RuntimeError('runtime service already started')
            if os.path.lexists(self.path):
                raise FileExistsError(self.path)
            listener = socket.socket(socket.AF_UNIX,
                socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            listener.bind(self.path)
            os.chmod(self.path, 0o600)
            listener.listen(4)
            listener.settimeout(0.1)
            self._listener = listener
            self._thread = threading.Thread(target=self._serve,
                name='ker-runtime-service', daemon=True)
            self._thread.start()

    def bind_actor(self, process, pidfd, timeout=5.0):
        """Bind CLAIM to the exact direct child created by ker-run.

        The caller supplies no PID in the protocol. ker-run derives this
        identity from its Popen child and pins a duplicate pidfd here.
        """
        if process is None or process.pid <= 0 or pidfd < 0:
            raise ValueError('runtime-service actor must be a live ker-run child')
        deadline = self.clock() + timeout
        pinned_pidfd = os.dup(pidfd)
        try:
            start = process_start_ticks(process.pid)
            while True:
                if process.poll() is not None or _pidfd_dead(pinned_pidfd):
                    raise OSError(3, 'runtime-service actor exited before binding')
                exe_hash = process_executable_hash(process.pid)
                if hmac.compare_digest(exe_hash, self.app_executable_hash):
                    break
                remaining = deadline - self.clock()
                if remaining <= 0:
                    raise OSError(8, 'ker-run child did not exec the expected application')
                time.sleep(min(0.01, remaining))
            with self._condition:
                if self._actor_target is not None or self._closed or self._revoked:
                    raise RuntimeError('runtime-service actor binding is not available')
                self._actor_target = {'pid': process.pid, 'uid': os.geteuid(),
                    'start': start, 'pidfd': pinned_pidfd,
                    'exe_hash': exe_hash}
                pinned_pidfd = -1
                self._condition.notify_all()
        finally:
            if pinned_pidfd >= 0:
                os.close(pinned_pidfd)

    def _wait_actor_binding_locked(self):
        # The application can run its constructor before Popen returns to
        # ker-run. Keep its first CLAIM queued until that exact child identity
        # is bound, with a fixed short deadline and no alternate claimant.
        deadline = self.clock() + 5.0
        while self._actor_target is None and not self._closed and not self._revoked:
            remaining = deadline - self.clock()
            if remaining <= 0:
                return False
            self._condition.wait(min(remaining, 0.05))
        return self._actor_target is not None and not self._closed and not self._revoked

    def _worker_alive_locked(self):
        if self.worker.poll() is not None:
            return False
        if _pidfd_dead(self.worker_pidfd):
            return False
        if process_start_ticks(self.worker_pid) != self.worker_start_ticks:
            return False
        if not hmac.compare_digest(process_executable_hash(self.worker_pid),
                self.worker_executable_hash):
            return False
        return True

    def _revoke_locked(self, reason):
        if self._revoked:
            return
        self._revoked = True
        self._release_reason = reason
        actor = self._actor
        self._actor = None
        if actor and actor['pidfd'] >= 0:
            os.close(actor['pidfd'])
        target = self._actor_target
        self._actor_target = None
        if target and target['pidfd'] >= 0:
            os.close(target['pidfd'])
        self._condition.notify_all()

    def _reap_locked(self):
        if self._revoked:
            return
        try:
            if not self._worker_alive_locked():
                self._revoke_locked('worker-dead')
                return
        except (OSError, RuntimeError, ValueError):
            self._revoke_locked('worker-identity-error')
            return
        target = self._actor_target
        if target is not None:
            try:
                if _pidfd_dead(target['pidfd']):
                    self._revoke_locked('actor-dead')
                    return
            except OSError:
                self._revoke_locked('actor-identity-error')
                return
        actor = self._actor
        if actor is None:
            return
        try:
            if _pidfd_dead(actor['pidfd']):
                self._revoke_locked('actor-dead')
            elif self.clock() - actor['last_seen'] > self.ttl_seconds:
                self._revoke_locked('lease-expired')
        except OSError:
            self._revoke_locked('actor-identity-error')

    def _peer_identity(self, connection):
        raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _UCRED.size)
        if len(raw) != _UCRED.size:
            raise OSError(71, 'invalid peer credentials')
        pid, uid, gid = _UCRED.unpack(raw)
        if pid <= 0 or uid != os.geteuid():
            raise OSError(13, 'runtime-service peer is not authorized')
        try:
            pidfd_raw = connection.getsockopt(socket.SOL_SOCKET, SO_PEERPIDFD, 4)
            if len(pidfd_raw) != 4:
                raise OSError(71, 'invalid peer pidfd')
            pidfd = struct.unpack('=i', pidfd_raw)[0]
        except OSError:
            pidfd = os.pidfd_open(pid, 0)
        try:
            start = process_start_ticks(pid)
            exe_hash = process_executable_hash(pid)
            comm = process_comm(pid)
            if _pidfd_dead(pidfd):
                raise OSError(3, 'runtime-service peer exited during authentication')
        except BaseException:
            os.close(pidfd)
            raise
        return {'pid': pid, 'uid': uid, 'gid': gid, 'start': start,
            'pidfd': pidfd, 'exe_hash': exe_hash, 'comm': comm}

    def _response(self, operation, sequence, lease_id, status, body=b''):
        header = wire.pack_header(operation, sequence, self.epoch,
            self.run_nonce, lease_id, status=status,
            packet_length=wire.HEADER.size + len(body))
        return header + body

    def _handle(self, connection, peer, packet, last_sequence):
        try:
            operation, status, sequence, epoch, nonce, lease_id = wire.unpack_header(packet)
        except ValueError:
            return None, last_sequence
        if sequence != last_sequence + 1 or status != 0:
            return None, last_sequence
        if epoch != self.epoch or not hmac.compare_digest(nonce, self.run_nonce):
            return self._response(operation, sequence, lease_id, 116), sequence
        body = packet[wire.HEADER.size:]
        with self._condition:
            self._reap_locked()
            if self._revoked:
                return self._response(operation, sequence, lease_id, 108), sequence
            if operation == wire.CLAIM:
                if len(body) != wire.CLAIM_BODY.size or any(lease_id):
                    return None, last_sequence
                ticket, profile_hash = wire.CLAIM_BODY.unpack(body)
                if not self._wait_actor_binding_locked():
                    return self._response(operation, sequence,
                        bytes(wire.LEASE_BYTES), 11), sequence
                target = self._actor_target
                if (not hmac.compare_digest(ticket, self.ticket) or
                        not hmac.compare_digest(profile_hash, self.role_profile_hash) or
                        peer['pid'] != target['pid'] or peer['uid'] != target['uid'] or
                        peer['start'] != target['start'] or
                        not hmac.compare_digest(peer['exe_hash'], target['exe_hash']) or
                        _pidfd_dead(target['pidfd'])):
                    return self._response(operation, sequence, bytes(wire.LEASE_BYTES), 13), sequence
                if self._claim_consumed and self._actor is None:
                    return self._response(operation, sequence, bytes(wire.LEASE_BYTES), 116), sequence
                if self._actor is not None:
                    actor = self._actor
                    if (actor['pid'] != peer['pid'] or actor['start'] != peer['start'] or
                            not hmac.compare_digest(actor['exe_hash'], peer['exe_hash'])):
                        return self._response(operation, sequence, bytes(wire.LEASE_BYTES), 16), sequence
                    actor['last_seen'] = self.clock()
                    return self._response(operation, sequence, actor['lease_id'], 0,
                        wire.CLAIM_RESULT.pack(self.worker_profile_hash)), sequence
                actor_pidfd = os.dup(peer['pidfd'])
                self._actor = {**peer, 'pidfd': actor_pidfd,
                    'lease_id': secrets.token_bytes(wire.LEASE_BYTES),
                    'last_seen': self.clock(), 'released': False}
                self._claim_consumed = True
                self._condition.notify_all()
                return self._response(operation, sequence, self._actor['lease_id'], 0,
                    wire.CLAIM_RESULT.pack(self.worker_profile_hash)), sequence
            if operation not in (wire.CHECK, wire.RELEASE) or body or not any(lease_id):
                return None, last_sequence
            actor = self._actor
            if (actor is None or actor['pid'] != peer['pid'] or
                    actor['start'] != peer['start'] or
                    not hmac.compare_digest(actor['exe_hash'], peer['exe_hash']) or
                    not hmac.compare_digest(actor['lease_id'], lease_id)):
                return self._response(operation, sequence, lease_id, 116), sequence
            actor['last_seen'] = self.clock()
            if operation == wire.CHECK:
                return self._response(operation, sequence, lease_id, 0), sequence
            self._actor = None
            self._claim_consumed = True
            actor['released'] = True
            os.close(actor['pidfd'])
            self._condition.notify_all()
            return self._response(operation, sequence, lease_id, 0), sequence

    def _serve_connection(self, connection):
        try:
            peer = self._peer_identity(connection)
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        except (OSError, RuntimeError, ValueError):
            connection.close()
            return
        with self._lock:
            if self._closed:
                os.close(peer['pidfd'])
                connection.close()
                return
            self._clients.add(connection)
            self._connection_threads.add(threading.current_thread())
        last_sequence = 0
        try:
            while True:
                packet, ancillary, message_flags, _ = connection.recvmsg(
                    wire.HEADER.size + wire.CLAIM_BODY.size + 1,
                    socket.CMSG_SPACE(_CREDENTIAL.size) + socket.CMSG_SPACE(16 * 4))
                if not packet:
                    return
                if message_flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
                    return
                credentials = []
                unexpected = False
                for level, kind, data in ancillary:
                    if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS:
                        if len(data) != _CREDENTIAL.size:
                            unexpected = True
                        else:
                            credentials.append(_CREDENTIAL.unpack(data))
                    elif level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                        usable = len(data) // 4 * 4
                        for descriptor in struct.unpack('=' + 'i' * (usable // 4), data[:usable]):
                            os.close(descriptor)
                        unexpected = True
                    else:
                        unexpected = True
                if (unexpected or len(credentials) != 1 or
                        credentials[0] != (peer['pid'], peer['uid'], peer['gid'])):
                    # SO_PEERCRED is fixed at connect time. Per-message
                    # credentials reject a forked sibling using an inherited
                    # connected descriptor as the bound actor.
                    return
                try:
                    current = {'pid': peer['pid'], 'uid': peer['uid'],
                        'gid': peer['gid'], 'start': process_start_ticks(peer['pid']),
                        'pidfd': peer['pidfd'],
                        'exe_hash': process_executable_hash(peer['pid']),
                        'comm': process_comm(peer['pid'])}
                except (OSError, RuntimeError, ValueError):
                    return
                if (current['start'] != peer['start'] or
                        not hmac.compare_digest(current['exe_hash'], peer['exe_hash'])):
                    return
                response, last_sequence = self._handle(connection, current, packet,
                    last_sequence)
                if response is None:
                    return
                connection.sendall(response)
        except (OSError, RuntimeError):
            return
        finally:
            with self._lock:
                self._clients.discard(connection)
                self._connection_threads.discard(threading.current_thread())
                # Keep the lease pinned over a lost socket; the same process
                # can reconnect with its opaque lease ID until TTL expiry.
            connection.close()
            os.close(peer['pidfd'])

    def _serve(self):
        while True:
            with self._lock:
                if self._closed:
                    return
                self._reap_locked()
                listener = self._listener
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                with self._lock:
                    if self._closed:
                        return
                continue
            thread = threading.Thread(target=self._serve_connection,
                args=(connection,), name='ker-runtime-service-client', daemon=True)
            thread.start()

    def wait_for_release(self, timeout):
        deadline = self.clock() + timeout
        with self._condition:
            while self._actor is not None and not self._revoked:
                remaining = deadline - self.clock()
                if remaining <= 0:
                    self._revoke_locked('supervisor-shutdown-timeout')
                    return False
                self._condition.wait(min(remaining, 0.1))
                self._reap_locked()
            return self._actor is None and not self._revoked

    def revoke(self, reason='explicit-supervisor-shutdown'):
        with self._condition:
            self._revoke_locked(reason)

    def close(self):
        with self._condition:
            if self._closed:
                return
            self._revoke_locked('supervisor-close')
            self._closed = True
            listener = self._listener
            self._listener = None
            thread = self._thread
            clients = list(self._clients)
            connection_threads = list(self._connection_threads)
            self._condition.notify_all()
        if listener is not None:
            listener.close()
        for connection in clients:
            try:
                connection.shutdown(socket.SHUT_RDWR)
                connection.close()
            except OSError:
                pass
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2)
        for client_thread in connection_threads:
            if client_thread is not threading.current_thread():
                client_thread.join(timeout=2)
        for descriptor in (self.worker_pidfd, self.control_fd):
            if descriptor >= 0:
                os.close(descriptor)
        self.worker_pidfd = self.control_fd = -1
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass

