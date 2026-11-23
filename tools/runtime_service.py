"""Private, per-run lease for the resident native IO worker.

This is deliberately separate from the socket capability broker. The ker-run
supervisor owns the worker process and its shutdown channel, so it is the
authority that can pin that real resource lifetime.
"""
import hashlib
import hmac
import importlib.util
import json
import math
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


def _pidfd_pid(pidfd):
    """Return the PID pinned by a Linux pidfd, without trusting caller input."""
    text = Path(f'/proc/self/fdinfo/{pidfd}').read_text(encoding='ascii')
    for line in text.splitlines():
        if line.startswith('Pid:\t'):
            pid = int(line.split('\t', 1)[1], 10)
            if pid > 0:
                return pid
            break
    raise OSError(9, 'descriptor is not a live pidfd')


class RuntimeServiceSupervisor:
    """Own one authenticated lease over a ker-run-launched child and worker."""
    def __init__(self, path, worker, worker_pidfd, worker_start_ticks,
                 worker_executable_hash, ready_record, app_executable_hash,
                 app_profile_hash, control_fd, ttl_seconds=30.0,
                 clock=time.monotonic, max_clients=4, io_timeout=5.0,
                 delegation_enabled=False):
        if (not isinstance(worker_executable_hash, bytes) or
                not isinstance(app_executable_hash, bytes) or
                len(worker_executable_hash) != 32 or len(app_executable_hash) != 32):
            raise ValueError('runtime-service executable hashes must be SHA256')
        if not isinstance(app_profile_hash, bytes) or len(app_profile_hash) != 32:
            raise ValueError('runtime-service app profile must be SHA256')
        if not isinstance(ready_record, dict) or ready_record.get('process_type') != 'primary':
            raise ValueError('runtime service requires a validated primary KER_IO_READY record')
        if type(ready_record.get('mbuf_pool_count')) is not int or ready_record['mbuf_pool_count'] <= 0:
            raise ValueError('runtime service requires a live worker mbuf pool')
        if type(ready_record.get('queues')) is not int or ready_record['queues'] <= 0:
            raise ValueError('runtime service requires configured worker queues')
        if control_fd < 0:
            raise ValueError('runtime service requires the worker shutdown channel')
        if worker_pidfd < 0 or worker is None or worker.pid <= 0:
            raise ValueError('runtime service requires a live worker process and pidfd')
        if (not isinstance(ttl_seconds, (int, float)) or
                not math.isfinite(ttl_seconds) or ttl_seconds <= 0 or ttl_seconds > 300):
            raise ValueError('runtime-service lease TTL must be in (0, 300] seconds')
        if not isinstance(max_clients, int) or max_clients < 1 or max_clients > 16:
            raise ValueError('runtime-service max_clients must be in 1..16')
        if not isinstance(io_timeout, (int, float)) or not math.isfinite(io_timeout) or io_timeout <= 0 or io_timeout > 30:
            raise ValueError('runtime-service I/O timeout must be in (0, 30] seconds')
        path = os.fspath(path)
        if not isinstance(path, str):
            raise ValueError('runtime-service path must be text')
        self.path = os.path.abspath(path)
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
        self.max_clients = max_clients
        self.io_timeout = float(io_timeout)
        self.delegation_enabled = bool(delegation_enabled)
        self._lock = threading.RLock()
        self._condition = threading.Condition(self._lock)
        self._listener = None
        self._thread = None
        self._clients = set()
        self._accepted_connections = set()
        self._connection_threads = set()
        self._actor = None
        # One run has one consumed role grant. Retain only the released
        # identity/lease tuple so the same actor can settle a lost RELEASE
        # reply; this is never authority for CHECK or a new claim.
        self._released_actor = None
        self._released_actors = {}
        self._actor_target = None
        self._claim_consumed = False
        self._delegated_actors = {}
        self._delegated_grants = {}
        self._delegation_intent = None
        self._delegation_roles_intended = set()
        self._delegation_roles_issued = set()
        self._delegation_request_nonces = set()
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
            if self._revoked:
                return 0
            return (int(self._actor is not None) + len(self._delegated_actors) +
                len(self._delegated_grants))

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
            try:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                listener.bind(self.path)
                os.chmod(self.path, 0o600)
                listener.listen(4)
                listener.settimeout(0.1)
                self._listener = listener
                thread = threading.Thread(target=self._serve,
                    name='ker-runtime-service', daemon=True)
                thread.start()
                self._thread = thread
            except BaseException:
                listener.close()
                self._listener = None
                try:
                    os.unlink(self.path)
                except FileNotFoundError:
                    pass
                raise

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
                    'gid': os.getegid(),
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
        for actor in self._delegated_actors.values():
            if actor['pidfd'] >= 0:
                os.close(actor['pidfd'])
        self._delegated_actors.clear()
        for grant in self._delegated_grants.values():
            if grant['pidfd'] >= 0:
                os.close(grant['pidfd'])
        self._delegated_grants.clear()
        self._delegation_intent = None
        self._delegation_roles_intended.clear()
        self._delegation_roles_issued.clear()
        self._delegation_request_nonces.clear()
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
        now = self.clock()
        intent = self._delegation_intent
        if intent is not None and now >= intent['deadline']:
            self._delegation_intent = None
        for ticket, grant in list(self._delegated_grants.items()):
            try:
                if now >= grant['deadline'] or _pidfd_dead(grant['pidfd']):
                    os.close(grant['pidfd'])
                    del self._delegated_grants[ticket]
            except OSError:
                self._revoke_locked('delegated-grant-identity-error')
                return
        for role, actor in list(self._delegated_actors.items()):
            try:
                if (_pidfd_dead(actor['pidfd']) or
                        now - actor['last_seen'] > self.ttl_seconds):
                    os.close(actor['pidfd'])
                    del self._delegated_actors[role]
            except OSError:
                self._revoke_locked('delegated-actor-identity-error')
                return
        target = self._actor_target
        if target is not None:
            try:
                if _pidfd_dead(target['pidfd']) and self._actor is not None:
                    if not self.delegation_enabled:
                        self._revoke_locked('actor-dead')
                        return
                    os.close(self._actor['pidfd'])
                    self._actor = None
                    os.close(target['pidfd'])
                    self._actor_target = None
                    self._delegation_intent = None
            except OSError:
                self._revoke_locked('actor-identity-error')
                return
        actor = self._actor
        if actor is None:
            return
        try:
            if _pidfd_dead(actor['pidfd']):
                if self.delegation_enabled:
                    os.close(actor['pidfd'])
                    self._actor = None
                else:
                    self._revoke_locked('actor-dead')
            elif self.clock() - actor['last_seen'] > self.ttl_seconds:
                if self.delegation_enabled:
                    os.close(actor['pidfd'])
                    self._actor = None
                else:
                    self._revoke_locked('lease-expired')
        except OSError:
            self._revoke_locked('actor-identity-error')
        if self.delegation_enabled and self._actor is None:
            if self._actor_target is not None:
                os.close(self._actor_target['pidfd'])
                self._actor_target = None
            if self._delegation_intent is not None and self._delegation_intent['role'] == wire.ROLE_SLIM_STAGE1:
                self._delegation_intent = None

    def _peer_identity(self, connection):
        raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _UCRED.size)
        if len(raw) != _UCRED.size:
            raise OSError(71, 'invalid peer credentials')
        pid, uid, gid = _UCRED.unpack(raw)
        if pid <= 0 or uid != os.geteuid() or gid != os.getegid():
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

    def _handle(self, connection, peer, packet, last_sequence, rights=()):
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
                if rights or len(body) != wire.CLAIM_BODY.size or any(lease_id):
                    return None, last_sequence
                ticket, profile_hash = wire.CLAIM_BODY.unpack(body)
                if self.delegation_enabled:
                    grant = self._delegated_grants.get(ticket)
                    if grant is not None:
                        if (not hmac.compare_digest(profile_hash, self.role_profile_hash) or
                                grant['pid'] != peer['pid'] or grant['uid'] != peer['uid'] or
                                grant['gid'] != peer['gid'] or grant['start'] != peer['start'] or
                                not hmac.compare_digest(grant['exe_hash'], peer['exe_hash']) or
                                _pidfd_dead(grant['pidfd'])):
                            return self._response(operation, sequence,
                                bytes(wire.LEASE_BYTES), 13), sequence
                        if grant['role'] in self._delegated_actors:
                            return self._response(operation, sequence,
                                bytes(wire.LEASE_BYTES), 16), sequence
                        actor_pidfd = os.dup(grant['pidfd'])
                        role = grant['role']
                        actor = {**grant, 'pidfd': actor_pidfd,
                            'lease_id': secrets.token_bytes(wire.LEASE_BYTES),
                            'last_seen': self.clock(), 'released': False}
                        del self._delegated_grants[ticket]
                        os.close(grant['pidfd'])
                        self._delegated_actors[role] = actor
                        self._condition.notify_all()
                        return self._response(operation, sequence, actor['lease_id'], 0,
                            wire.CLAIM_RESULT.pack(self.worker_profile_hash)), sequence
                    if not hmac.compare_digest(ticket, self.ticket):
                        return self._response(operation, sequence,
                            bytes(wire.LEASE_BYTES), 116), sequence
                if not self._wait_actor_binding_locked():
                    return self._response(operation, sequence,
                        bytes(wire.LEASE_BYTES), 11), sequence
                target = self._actor_target
                if (not hmac.compare_digest(ticket, self.ticket) or
                        not hmac.compare_digest(profile_hash, self.role_profile_hash) or
                        peer['pid'] != target['pid'] or peer['uid'] != target['uid'] or
                        peer['gid'] != target['gid'] or
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
                    'last_seen': self.clock(), 'released': False,
                    'role': 0}
                self._claim_consumed = True
                self._condition.notify_all()
                return self._response(operation, sequence, self._actor['lease_id'], 0,
                    wire.CLAIM_RESULT.pack(self.worker_profile_hash)), sequence
            if operation == wire.DELEGATE_INTENT:
                if (not self.delegation_enabled or rights or
                        len(body) != wire.DELEGATE_INTENT_BODY.size or not any(lease_id)):
                    return None, last_sequence
                try:
                    request_nonce, child_role = wire.unpack_delegate_intent(body)
                except ValueError:
                    return None, last_sequence
                if (not any(request_nonce) or request_nonce in self._delegation_request_nonces or
                        self._delegation_intent is not None):
                    return self._response(operation, sequence, lease_id, 16), sequence
                parent = self._delegation_parent_locked(peer, lease_id)
                expected_role = (wire.ROLE_SLIM_STAGE1 if parent and parent['role'] == 0
                    else wire.ROLE_SLIM_PRIMARY if parent and
                    parent['role'] == wire.ROLE_SLIM_STAGE1 else 0)
                if (parent is None or child_role != expected_role or
                        child_role in self._delegation_roles_intended):
                    return self._response(operation, sequence, lease_id, 13), sequence
                intent_id = secrets.token_bytes(wire.INTENT_BYTES)
                self._delegation_intent = {'id': intent_id, 'nonce': request_nonce,
                    'role': child_role, 'parent': self._identity_key(parent),
                    'parent_lease': lease_id,
                    'deadline': self.clock() + 5.0}
                self._delegation_roles_intended.add(child_role)
                self._delegation_request_nonces.add(request_nonce)
                return self._response(operation, sequence, lease_id, 0,
                    wire.pack_intent_result(intent_id)), sequence
            if operation == wire.DELEGATE_BIND:
                if (not self.delegation_enabled or len(rights) != 1 or
                        len(body) != wire.DELEGATE_BIND_BODY.size or not any(lease_id)):
                    return None, last_sequence
                try:
                    intent_id = wire.unpack_delegate_bind(body)
                    intent = self._delegation_intent
                    if intent is None or self.clock() >= intent['deadline'] or not hmac.compare_digest(
                            intent['id'], intent_id):
                        return self._response(operation, sequence, lease_id, 116), sequence
                    if not hmac.compare_digest(intent['parent_lease'], lease_id):
                        return self._response(operation, sequence, lease_id, 116), sequence
                    parent = self._find_delegation_parent_locked(intent['parent'],
                        intent['parent_lease'])
                    if parent is None or not self._same_identity(parent, peer):
                        return self._response(operation, sequence, lease_id, 13), sequence
                    child_pid = _pidfd_pid(rights[0])
                    child = {'pid': child_pid, 'uid': os.stat(f'/proc/{child_pid}').st_uid,
                        'gid': os.stat(f'/proc/{child_pid}').st_gid,
                        'start': process_start_ticks(child_pid),
                        'exe_hash': process_executable_hash(child_pid),
                        'comm': process_comm(child_pid)}
                    child_stat = Path(f'/proc/{child_pid}/stat').read_text(encoding='ascii')
                    child_fields = child_stat[child_stat.rfind(')') + 2:].split()
                    if (len(child_fields) <= 1 or _pidfd_dead(rights[0]) or
                            int(child_fields[1], 10) != peer['pid'] or
                            child['uid'] != peer['uid'] or child['gid'] != peer['gid'] or
                            not hmac.compare_digest(child['exe_hash'], self.app_executable_hash)):
                        return self._response(operation, sequence, lease_id, 13), sequence
                    if len(self._delegated_grants) + len(self._delegated_actors) >= 2:
                        return self._response(operation, sequence, lease_id, 16), sequence
                    pinned = os.dup(rights[0])
                    ticket = secrets.token_bytes(wire.TICKET_BYTES)
                    self._delegated_grants[ticket] = {**child, 'pidfd': pinned,
                        'ticket': ticket, 'role': intent['role'],
                        'parent': intent['parent'], 'deadline': self.clock() + 5.0}
                    self._delegation_intent = None
                    self._delegation_roles_issued.add(intent['role'])
                    self._condition.notify_all()
                    return self._response(operation, sequence, lease_id, 0,
                        wire.pack_bind_result(ticket, intent['role'])), sequence
                except (OSError, RuntimeError, ValueError, IndexError):
                    return self._response(operation, sequence, lease_id, 13), sequence
            if rights or operation not in (wire.CHECK, wire.RELEASE) or body or not any(lease_id):
                return None, last_sequence
            actor = self._actor
            if actor is None or not self._same_identity(actor, peer) or not hmac.compare_digest(
                    actor['lease_id'], lease_id):
                actor = next((candidate for candidate in self._delegated_actors.values()
                    if self._same_identity(candidate, peer) and
                    hmac.compare_digest(candidate['lease_id'], lease_id)), None)
            if actor is None:
                released = (self._released_actors.get(
                    (peer['pid'], peer['uid'], peer['gid'], peer['start'],
                     peer['exe_hash'], lease_id)) if self.delegation_enabled else
                    self._released_actor)
                if (operation == wire.RELEASE and released is not None and
                        released['pid'] == peer['pid'] and
                        released['uid'] == peer['uid'] and
                        released['gid'] == peer['gid'] and
                        released['start'] == peer['start'] and
                        hmac.compare_digest(released['exe_hash'], peer['exe_hash']) and
                        hmac.compare_digest(released['lease_id'], lease_id)):
                    return self._response(operation, sequence, lease_id, 0), sequence
                return self._response(operation, sequence, lease_id, 116), sequence
            if (actor['pid'] != peer['pid'] or actor['uid'] != peer['uid'] or
                    actor['gid'] != peer['gid'] or actor['start'] != peer['start'] or
                    not hmac.compare_digest(actor['exe_hash'], peer['exe_hash']) or
                    not hmac.compare_digest(actor['lease_id'], lease_id)):
                return self._response(operation, sequence, lease_id, 116), sequence
            actor['last_seen'] = self.clock()
            if operation == wire.CHECK:
                return self._response(operation, sequence, lease_id, 0), sequence
            released = {key: actor[key] for key in
                ('pid', 'uid', 'gid', 'start', 'exe_hash', 'lease_id')}
            if self.delegation_enabled:
                tombstone_key = (released['pid'], released['uid'], released['gid'],
                    released['start'], released['exe_hash'], released['lease_id'])
                self._released_actors[tombstone_key] = released
            else:
                self._released_actor = released
            if actor is self._actor:
                self._actor = None
                if self._actor_target is not None:
                    os.close(self._actor_target['pidfd'])
                    self._actor_target = None
                if self._delegation_intent is not None and self._delegation_intent['parent'] == self._identity_key(actor):
                    self._delegation_intent = None
            else:
                self._delegated_actors.pop(actor['role'], None)
            self._claim_consumed = True
            actor['released'] = True
            os.close(actor['pidfd'])
            self._condition.notify_all()
            return self._response(operation, sequence, lease_id, 0), sequence

    @staticmethod
    def _identity_key(actor):
        return actor['pid'], actor['uid'], actor['gid'], actor['start'], actor['exe_hash']

    @classmethod
    def _same_identity(cls, left, right):
        return cls._identity_key(left) == cls._identity_key(right)

    def _find_delegation_parent_locked(self, identity, lease_id):
        candidates = ([self._actor] if self._actor is not None else []) + list(
            self._delegated_actors.values())
        return next((actor for actor in candidates
            if self._identity_key(actor) == identity and
            hmac.compare_digest(actor['lease_id'], lease_id)), None)

    def _delegation_parent_locked(self, peer, lease_id):
        parent = self._find_delegation_parent_locked(self._identity_key(peer), lease_id)
        if parent is None or _pidfd_dead(parent['pidfd']):
            return None
        return parent

    def _revoke_bound_actor(self, peer, reason):
        with self._condition:
            target = self._actor_target
            bound = target is not None and self._same_identity(target, peer)
            bound = bound or any(self._same_identity(actor, peer)
                for actor in self._delegated_actors.values())
            if bound:
                self._revoke_locked(reason)

    def _serve_connection(self, connection):
        peer = None
        try:
            peer = self._peer_identity(connection)
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            connection.settimeout(self.io_timeout)
        except (OSError, RuntimeError, ValueError):
            if peer is not None:
                os.close(peer['pidfd'])
            connection.close()
            with self._lock:
                self._accepted_connections.discard(connection)
                self._connection_threads.discard(threading.current_thread())
            return
        with self._lock:
            if self._closed or connection not in self._accepted_connections:
                os.close(peer['pidfd'])
                connection.close()
                self._accepted_connections.discard(connection)
                self._connection_threads.discard(threading.current_thread())
                return
            self._accepted_connections.discard(connection)
            self._clients.add(connection)
        last_sequence = 0
        try:
            while True:
                packet, ancillary, message_flags, _ = connection.recvmsg(
                    wire.HEADER.size + wire.CLAIM_BODY.size + 1,
                    socket.CMSG_SPACE(_CREDENTIAL.size) + socket.CMSG_SPACE(16 * 4),
                    getattr(socket, 'MSG_CMSG_CLOEXEC', 0))
                if not packet and not ancillary and not message_flags:
                    return
                credentials = []
                rights = []
                unexpected = False
                for level, kind, data in ancillary:
                    if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS:
                        if len(data) != _CREDENTIAL.size:
                            unexpected = True
                        else:
                            credentials.append(_CREDENTIAL.unpack(data))
                    elif level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                        usable = len(data) // 4 * 4
                        if usable != len(data):
                            unexpected = True
                        rights.extend(struct.unpack('=' + 'i' * (usable // 4), data[:usable]))
                    else:
                        unexpected = True
                try:
                    if (len(credentials) != 1 or
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
                    if message_flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
                        self._revoke_bound_actor(current, 'actor-malformed-message')
                        return
                    if unexpected:
                        self._revoke_bound_actor(current, 'actor-unexpected-ancillary')
                        return
                    if not packet:
                        self._revoke_bound_actor(current, 'actor-empty-message')
                        return
                    response, last_sequence = self._handle(connection, current, packet,
                        last_sequence, rights)
                finally:
                    for descriptor in rights:
                        os.close(descriptor)
                if response is None:
                    self._revoke_bound_actor(current, 'actor-protocol-violation')
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
            with self._lock:
                if self._closed or len(self._connection_threads) >= self.max_clients:
                    connection.close()
                    continue
                thread = threading.Thread(target=self._serve_connection,
                    args=(connection,), name='ker-runtime-service-client', daemon=True)
                self._accepted_connections.add(connection)
                self._connection_threads.add(thread)
                try:
                    thread.start()
                except BaseException:
                    self._accepted_connections.discard(connection)
                    self._connection_threads.discard(thread)
                    connection.close()
                    raise

    def wait_for_release(self, timeout):
        deadline = self.clock() + timeout
        with self._condition:
            def pinned():
                if not self.delegation_enabled:
                    return self._actor is not None
                return (self._actor is not None or bool(self._delegated_actors) or
                    bool(self._delegated_grants) or self._delegation_intent is not None)
            while pinned() and not self._revoked:
                remaining = deadline - self.clock()
                if remaining <= 0:
                    self._revoke_locked('supervisor-shutdown-timeout')
                    return False
                self._condition.wait(min(remaining, 0.1))
                self._reap_locked()
            return not pinned() and not self._revoked

    def revoke(self, reason='explicit-supervisor-shutdown'):
        with self._condition:
            self._revoke_locked(reason)

    def prepare_worker_shutdown(self, timeout):
        """Revoke the role and drop the held control writer before worker stop."""
        released = self.wait_for_release(timeout)
        with self._condition:
            self._revoke_locked('explicit-worker-shutdown')
            control_fd = self.control_fd
            self.control_fd = -1
        if control_fd >= 0:
            os.close(control_fd)
        return released

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
            clients.extend(self._accepted_connections)
            self._accepted_connections.clear()
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
