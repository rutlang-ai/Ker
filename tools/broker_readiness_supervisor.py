"""Private ker-run endpoint for the typed native socket-broker lifecycle."""
import array
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import secrets
import socket
import sys
import time

_WIRE_SPEC = importlib.util.spec_from_file_location(
    '_ker_broker_readiness_wire', Path(__file__).resolve().with_name(
        'broker_readiness_wire.py'))
if _WIRE_SPEC is None or _WIRE_SPEC.loader is None:
    raise ImportError('cannot load the broker readiness wire codec beside this module')
wire = importlib.util.module_from_spec(_WIRE_SPEC)
_WIRE_SPEC.loader.exec_module(wire)

_UCRED = __import__('struct').Struct('=3i')
_PROFILE_DOMAIN = b'ker.socket-broker.worker-profile/v1\0'
_PRIVATE_STOP_TOKEN = object()


class _PrivateStopAuthorization:
    __slots__ = ('token', 'broker', 'provider', 'context', 'pending', 'term_evidence',
        'retirement_proof', 'controller', 'deadline_ns')

    def __init__(self, token, broker, provider, context, pending, term_evidence,
            retirement_proof, controller, deadline_ns):
        if token is not _PRIVATE_STOP_TOKEN:
            raise TypeError('private STOP authorization is broker-owned')
        values = (token, broker, provider, context, pending, term_evidence,
            retirement_proof, controller, deadline_ns)
        for name, value in zip(self.__slots__, values):
            object.__setattr__(self, name, value)

    def __setattr__(self, _name, _value):
        raise AttributeError('private STOP authorization is immutable')


class PrivateStopAckReceipt:
    __slots__ = ('token', 'broker', 'authorization', 'raw_ack', 'decoded',
        'actor_identity', 'nonce', 'epoch', 'request', 'received_ns')

    def __init__(self, token, broker, authorization, raw_ack, decoded,
            actor_identity, nonce, epoch, request, received_ns):
        if token is not _PRIVATE_STOP_TOKEN:
            raise TypeError('private STOP ACK receipt is broker-owned')
        values = (token, broker, authorization, bytes(raw_ack), tuple(decoded),
            tuple(actor_identity), bytes(nonce), epoch, bytes(request), received_ns)
        for name, value in zip(self.__slots__, values):
            object.__setattr__(self, name, value)

    def __setattr__(self, _name, _value):
        raise AttributeError('private STOP ACK receipt is immutable')


class _PollSliceElapsed(TimeoutError):
    """A reactor poll interval ended; the operation deadline may still be live."""


def _identity(pid):
    stat = open(f'/proc/{pid}/stat', encoding='ascii').read()
    close = stat.rfind(')')
    if close < 0:
        raise RuntimeError('malformed process identity')
    fields = stat[close + 2:].split()
    if len(fields) <= 19:
        raise RuntimeError('malformed process identity')
    start_ticks = int(fields[19], 10)
    if start_ticks <= 0:
        raise RuntimeError('invalid process start time')
    status = os.stat(f'/proc/{pid}')
    return (pid, status.st_uid, status.st_gid, start_ticks)


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.digest()


def worker_profile_digest(worker_path, ready):
    payload = json.dumps(ready, sort_keys=True, separators=(',', ':')).encode('ascii')
    return hashlib.sha256(_PROFILE_DOMAIN + _sha256(worker_path) + payload).digest()


class BrokerReadiness:
    """One broker process, one authenticated READY and one bounded STOP/ACK."""
    def __init__(self, worker_path, worker_ready, worker_profile=None):
        self.parent, self.child = socket.socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK)
        self.parent.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        self.supervisor = _identity(os.getpid())
        self.nonce = secrets.token_bytes(16)
        while not any(self.nonce):
            self.nonce = secrets.token_bytes(16)
        self.epoch = secrets.randbits(64) or 1
        self.profile = (worker_profile_digest(worker_path, worker_ready)
            if worker_profile is None else bytes(worker_profile))
        if len(self.profile) != 32 or not any(self.profile):
            raise ValueError('worker profile digest must be a nonzero SHA-256 value')
        self.app = None
        self.app_pidfd = -1
        self.ready = False
        self.stopped = False
        self.stop_attempted = False
        self._verify = None
        self._stop = None
        self._verify_sequence = 0
        self.last_verify_packet = None
        self.last_verify_result = None
        self._private_stop_authorization = None
        self._private_stop_authorization_consumed = False
        self._private_stop_ack_receipt = None
        self._private_stop_ack_registry = {}

    def environment(self):
        return {
            'KER_BROKER_READINESS_FD': str(self.child.fileno()),
            'KER_BROKER_RUN_NONCE': self.nonce.hex(),
            'KER_BROKER_WORKER_EPOCH': str(self.epoch),
            'KER_BROKER_WORKER_PROFILE_SHA256': self.profile.hex(),
            'KER_BROKER_SUPERVISOR_START_TICKS': str(self.supervisor[3]),
        }

    def child_fd(self):
        return self.child.fileno()

    def child_started(self, process, expected_executable_hash):
        self.child.close()
        self.child = None
        self.app = _identity(process.pid)
        self.app_pidfd = os.pidfd_open(process.pid, 0)
        self.expected_executable_hash = bytes(expected_executable_hash)
        self.ready_deadline = time.monotonic() + 20.0
        if len(self.expected_executable_hash) != 32:
            raise ValueError('expected broker executable digest must be SHA-256')
        return self.app_pidfd

    def _receive(self, expected_size, deadline, allow_exited_app=False,
                 poll_slice=None):
        poller = select.poll()
        poller.register(self.parent.fileno(), select.POLLIN | select.POLLHUP |
            select.POLLERR)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('broker readiness control deadline expired')
            wait = remaining if poll_slice is None else min(remaining, poll_slice)
            events = poller.poll(max(1, int(wait * 1000)))
            if not events:
                if poll_slice is not None and time.monotonic() < deadline:
                    raise _PollSliceElapsed('broker readiness poll slice expired')
                continue
            if (events[0][1] & (select.POLLHUP | select.POLLERR | select.POLLNVAL) and
                    not events[0][1] & select.POLLIN):
                raise ConnectionError('broker readiness endpoint closed')
            packet, ancillary, flags, _ = self.parent.recvmsg(expected_size + 1,
                socket.CMSG_SPACE(_UCRED.size) + socket.CMSG_SPACE(16 * 4),
                getattr(socket, 'MSG_CMSG_CLOEXEC', 0))
            credentials = None
            received_fds = []
            ancillary_error = None
            try:
                for level, kind, payload in ancillary:
                    if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS:
                        if credentials is not None or len(payload) != _UCRED.size:
                            ancillary_error = ValueError('duplicate or malformed broker credentials')
                        elif ancillary_error is None:
                            credentials = _UCRED.unpack(payload)
                    elif level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                        usable = len(payload) - len(payload) % array.array('i').itemsize
                        if usable:
                            received_fds.extend(array.array('i', payload[:usable]))
                        ancillary_error = ValueError('unexpected broker descriptor ancillary data')
                    else:
                        ancillary_error = ValueError('unexpected broker ancillary data')
                if ancillary_error is not None:
                    raise ancillary_error
                if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
                    raise ValueError('truncated broker control record')
                if received_fds:
                    raise ValueError('broker sent unexpected descriptors')
                if credentials != self.app[:3]:
                    raise PermissionError('broker control sender is not pinned application')
                if allow_exited_app:
                    if self.app_pidfd < 0:
                        raise ProcessLookupError('invalid broker pidfd')
                else:
                    self._check_app_identity()
                if len(packet) != expected_size:
                    raise ValueError('invalid broker control record length')
                if time.monotonic() > deadline:
                    raise TimeoutError('broker control record arrived after deadline')
                return packet
            except BaseException:
                for fd in received_fds:
                    os.close(fd)
                raise

    def _check_app_identity(self):
        if self.app is None or self.app_pidfd < 0:
            raise ProcessLookupError('invalid broker process identity')
        poller = select.poll()
        poller.register(self.app_pidfd,
            select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL)
        if poller.poll(0) or _identity(self.app[0]) != self.app:
            raise ProcessLookupError('broker process identity is no longer live')
        expected = getattr(self, 'expected_executable_hash', None)
        if expected is None or _sha256(f'/proc/{self.app[0]}/exe') != expected:
            raise PermissionError('broker executable differs from the pinned app')

    def _validate_ready(self, packet):
        if self.app is None or self.ready:
            raise RuntimeError('broker readiness has invalid lifecycle state')
        nonce, epoch, profile, broker_start, count, manifest = wire.unpack_ready(packet)
        if (nonce != self.nonce or epoch != self.epoch or profile != self.profile or
                broker_start != self.app[3] or count != 0 or
                manifest != wire.EMPTY_MANIFEST_SHA256):
            raise PermissionError('broker READY did not match pinned empty runtime profile')
        self._check_app_identity()
        if time.monotonic() >= self.ready_deadline:
            raise TimeoutError('broker READY validation exceeded its absolute deadline')
        self.ready = True
        return True

    def poll_ready(self):
        if self.app is None or self.ready:
            return self.ready
        remaining = self.ready_deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('broker READY deadline expired')
        poller = select.poll()
        poller.register(self.parent.fileno(), select.POLLIN | select.POLLHUP |
            select.POLLERR | select.POLLNVAL)
        events = poller.poll(0)
        if not events:
            return False
        if (events[0][1] & (select.POLLHUP | select.POLLERR | select.POLLNVAL) and
                not events[0][1] & select.POLLIN):
            raise ConnectionError('broker readiness endpoint closed before READY')
        try:
            packet = self._receive(wire.READY_RECORD.size,
                self.ready_deadline, poll_slice=0.1)
        except _PollSliceElapsed:
            return False
        return self._validate_ready(packet)

    def stop(self, timeout=10.0):
        self.begin_stop(timeout)
        while not self.poll_stop():
            time.sleep(0.001)

    def begin_verify(self, watch_fd, sequence, timeout=6.0):
        if (not self.ready or self.stopped or self.stop_attempted or
                self._verify is not None or watch_fd < 0 or
                sequence != self._verify_sequence + 1):
            raise RuntimeError('broker VERIFY is unavailable or out of sequence')
        self._verify_sequence = sequence
        self.last_verify_packet = None
        self.last_verify_result = None
        self._verify = {'fd': watch_fd, 'sequence': sequence,
            'deadline': time.monotonic() + timeout, 'sent': False}

    def poll_verify(self):
        request = self._verify
        if request is None:
            return None
        if time.monotonic() >= request['deadline']:
            self._verify = {'fd': request['fd'], 'sequence': request['sequence'],
                'deadline': request['deadline'], 'sent': request['sent'],
                'unresolved': True}
            raise TimeoutError('broker VERIFY absolute deadline expired')
        if not request['sent']:
            try:
                rights = array.array('i', (request['fd'],))
                record = wire.pack_verify(self.nonce, self.epoch, request['sequence'])
                sent = self.parent.sendmsg([record],
                    [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)],
                    getattr(socket, 'MSG_NOSIGNAL', 0))
                if sent != len(record):
                    raise OSError(5, 'short broker VERIFY send')
                request['sent'] = True
                os.close(request['fd'])
                request['fd'] = -1
            except BlockingIOError:
                return None
            except BaseException:
                request['unresolved'] = True
                raise
        poller = select.poll()
        poller.register(self.parent.fileno(), select.POLLIN | select.POLLHUP |
            select.POLLERR | select.POLLNVAL)
        events = poller.poll(0)
        if not events:
            return None
        if (events[0][1] & (select.POLLHUP | select.POLLERR | select.POLLNVAL) and
                not events[0][1] & select.POLLIN):
            request['unresolved'] = True
            raise ConnectionError('broker VERIFY response channel closed')
        try:
            packet = self._receive(wire.VERIFY_RESULT.size,
                request['deadline'], poll_slice=0.01)
            # Keep only this one fixed-size record so a caller can retain exact
            # bounded diagnostics if strict decoding rejects the response.
            self.last_verify_packet = bytes(packet)
            self.last_verify_result = wire.unpack_verify_result(packet, self.nonce,
                self.epoch, request['sequence'])
        except _PollSliceElapsed:
            return None
        except BaseException:
            request['unresolved'] = True
            raise
        self._verify = None
        return packet

    def authorize_private_stop(self, provider, pending, term_evidence,
            retirement_proof, *, initial_controller=None):
        """Mint the sole bounded STOP admission for the exact candidate PREEXIT."""
        retirement_provider = getattr(self,
            '_private_initial_retirement_provider', None)
        provider_module = sys.modules.get(type(provider).__module__)
        provider_type = getattr(provider_module, 'SourceShellC34InteropProvider', None)
        proof_type = getattr(provider_module, 'SourceInitialListenerRetirementProof', None)
        context = getattr(provider, 'context', None)
        origin = getattr(getattr(context, 'owner_live', None), '__self__', None)
        origin_module = sys.modules.get(type(origin).__module__) if origin is not None else None
        initial = getattr(pending, 'key', None) == (0, 0)
        controller = (initial_controller if initial else
            getattr(getattr(retirement_proof, 'old_exit', None), 'controller', None))
        controller_module = sys.modules.get('_ker_nginx_source_shell_controller')
        profile_module = sys.modules.get('_ker_nginx_source_c34_profile')
        bootstrap_module = getattr(origin_module, 'bootstrap', None)
        evidence_type = getattr(bootstrap_module, 'SupervisorTermEvidence', None)
        pending_type = getattr(bootstrap_module, 'PendingSourceRetirement', None)
        pending_entry = (getattr(context, '_pending_preexits', {}).get(
            getattr(pending, 'operation_id', None), (None, None, None)))
        evidence = getattr(context, '_authorized_preexits', {}).get(
            getattr(pending, 'operation_id', None))
        if (retirement_provider is not provider or provider_module is None or
                type(provider) is not provider_type or
                (not initial and (proof_type is None or type(retirement_proof) is not proof_type or
                    retirement_proof.provider is not provider or retirement_proof.context is not context)) or
                evidence_type is None or
                type(term_evidence) is not evidence_type or evidence is not term_evidence or
                pending_type is None or type(pending) is not pending_type or
                pending_entry[0] is not pending or pending_entry[2] is not
                    getattr(context, 'worker_channels', {}).get(pending.key) or
                pending.worker_pid <= 0 or
                term_evidence.worker_pid != pending.worker_pid or
                term_evidence.worker_start_ticks != pending.worker_start_ticks or
                term_evidence.phase != 'stopping' or term_evidence.signal != 'TERM' or
                origin_module is None or
                Path(getattr(origin_module, '__file__', '')).resolve(strict=True) !=
                    Path(__file__).with_name('nginx_source_origin.py').resolve(strict=True) or
                type(origin) is not getattr(origin_module, 'PrivateC34OriginalShellLaunch', None) or
                controller_module is None or
                type(controller) is not getattr(controller_module, 'SourceShellController', None) or
                type(controller.profile) is not getattr(profile_module,
                    'PrivateNewC34InteropProfile', None) or
                controller.bootstrap_context is not context or controller.launch is not origin or
                controller.c22_provider is not provider or
                controller.profile.artifact_capture is not
                    getattr(origin, 'c34_artifact_capture', None) or
                controller.profile.helper_capture is not
                    getattr(provider, '_private_c34_helper_capture', None) or
                getattr(provider, 'broker_readiness', None) is not self or
                getattr(controller, '_private_candidate_preexit_pending', None) is not pending or
                getattr(controller, '_private_candidate_preexit_evidence', None) is not term_evidence or
                not controller._private_shutdown_binding_matches(context,
                    pending.key, retirement_proof) or
                getattr(context, 'control_only', False) is not True or
                getattr(self, 'ready', False) is not True or getattr(self, 'stopped', True) or
                self.stop_attempted or self._stop is not None or
                type(pending.deadline_ns) is not int or
                time.monotonic_ns() >= pending.deadline_ns or
                pending.deadline_ns > context.deadline_ns or
                pending.deadline_ns - time.monotonic_ns() >
                    bootstrap_module.PREEXIT_BUDGET_NS):
            raise PermissionError('private broker STOP lacks the exact live PREEXIT/TERM/C34 proof join')
        if self._private_stop_authorization is not None:
            raise PermissionError('private broker STOP authorization is one-use')
        authorization = _PrivateStopAuthorization(_PRIVATE_STOP_TOKEN, self,
            provider, context, pending, term_evidence, retirement_proof, controller,
            pending.deadline_ns)
        self._private_stop_authorization = authorization
        return authorization

    def _private_stop_authorization_live(self, authorization, *, consumed=True):
        context = getattr(authorization, 'context', None)
        pending = getattr(authorization, 'pending', None)
        provider = getattr(authorization, 'provider', None)
        evidence = getattr(authorization, 'term_evidence', None)
        proof = getattr(authorization, 'retirement_proof', None)
        controller = getattr(authorization, 'controller', None)
        if (type(authorization) is not _PrivateStopAuthorization or
                authorization.token is not _PRIVATE_STOP_TOKEN or
                authorization.broker is not self or
                self._private_stop_authorization is not authorization or
                self._private_stop_authorization_consumed is not consumed or
                authorization.deadline_ns != getattr(pending, 'deadline_ns', None) or
                time.monotonic_ns() >= authorization.deadline_ns or
                getattr(context, '_pending_preexits', {}).get(
                    getattr(pending, 'operation_id', None), (None,))[0] is not pending or
                getattr(context, '_authorized_preexits', {}).get(
                    getattr(pending, 'operation_id', None)) is not evidence or
                getattr(controller, '_private_candidate_preexit_pending', None) is not pending or
                getattr(controller, '_private_candidate_preexit_evidence', None) is not evidence or
                not controller._private_shutdown_binding_matches(context, pending.key, proof) or
                getattr(provider, 'broker_readiness', None) is not self or
                getattr(context, 'control_only', False) is not True):
            return False
        return True

    def begin_stop(self, timeout=10.0, *, private_authorization=None):
        retirement_provider = getattr(self,
            '_private_initial_retirement_provider', None)
        if retirement_provider is not None:
            authorization = private_authorization
            if (type(authorization) is not _PrivateStopAuthorization or
                    authorization.token is not _PRIVATE_STOP_TOKEN or
                    authorization.broker is not self or
                    authorization.provider is not retirement_provider or
                    authorization.context is not getattr(retirement_provider, 'context', None) or
                    authorization.pending is not getattr(authorization.controller,
                        '_private_candidate_preexit_pending', None) or
                    authorization.term_evidence is not getattr(authorization.controller,
                        '_private_candidate_preexit_evidence', None) or
                    not self._private_stop_authorization_live(authorization,
                        consumed=False) or
                    authorization.deadline_ns != authorization.pending.deadline_ns or
                    self._private_stop_authorization is not authorization or
                    self._private_stop_authorization_consumed or
                    time.monotonic_ns() >= authorization.deadline_ns):
                raise RuntimeError('private broker STOP is held without its exact one-use PREEXIT authorization')
            deadline = authorization.deadline_ns / 1_000_000_000
        else:
            deadline = time.monotonic() + timeout
        if (not self.ready or self.stopped or self.stop_attempted or
                self._verify is not None):
            raise RuntimeError('broker STOP requires READY with no VERIFY and is one-use')
        if retirement_provider is not None:
            self._private_stop_authorization_consumed = True
        self.stop_attempted = True
        self._stop = {'record': wire.pack_stop(wire.STOP, self.nonce, self.epoch,
            *self.supervisor[:3], self.supervisor[3]),
            'deadline': deadline, 'sent': False,
            'private': retirement_provider is not None,
            'authorization': private_authorization}

    def poll_stop(self):
        request = self._stop
        if request is None:
            return self.stopped
        if request.get('unresolved'):
            raise ConnectionError('broker STOP outcome is unresolved; replay is forbidden')
        authorization = request.get('authorization')
        if request.get('private'):
            if (not self._private_stop_authorization_live(authorization) or
                    authorization.deadline_ns != authorization.pending.deadline_ns or
                    time.monotonic_ns() >= authorization.deadline_ns):
                request['unresolved'] = True
                raise TimeoutError('private broker STOP exceeded its PREEXIT deadline or authorization')
        if time.monotonic() >= request['deadline']:
            request['unresolved'] = True
            raise TimeoutError('broker STOP absolute deadline expired')
        if not request['sent']:
            if request.get('private'):
                request['send_attempted'] = True
            try:
                sent = self.parent.send(request['record'],
                    getattr(socket, 'MSG_NOSIGNAL', 0))
                if sent != len(request['record']):
                    raise OSError(5, 'short broker STOP record')
                request['sent'] = True
            except BlockingIOError:
                if request.get('private'):
                    request['unresolved'] = True
                    raise
                return False
            except BaseException:
                request['unresolved'] = True
                raise
        poller = select.poll()
        poller.register(self.parent.fileno(), select.POLLIN | select.POLLHUP |
            select.POLLERR | select.POLLNVAL)
        events = poller.poll(0)
        if not events:
            return False
        if (events[0][1] & (select.POLLHUP | select.POLLERR | select.POLLNVAL) and
                not events[0][1] & select.POLLIN):
            request['unresolved'] = True
            raise ConnectionError('broker STOP response channel closed')
        try:
            # STOP_ACK may be queued by the pinned app immediately before it
            # exits as ker_posix_run unwinds. SCM credentials still bind the
            # sender; do not reject a valid queued ACK solely because pidfd is
            # readable by the time the reactor consumes it.
            packet = self._receive(wire.STOP_RECORD.size, request['deadline'],
                allow_exited_app=True)
            fields = wire.unpack_stop(packet, wire.STOP_ACK)
            expected = (self.nonce, self.epoch, wire.EMPTY_MANIFEST_SHA256,
                *self.supervisor[:3], self.supervisor[3], wire.STOP_ID)
            if fields != expected:
                raise PermissionError('broker STOP acknowledgement identity mismatch')
            if request.get('private'):
                raw_ack = bytes(packet)
                decoded = tuple(wire.unpack_stop(raw_ack, wire.STOP_ACK))
                received_ns = time.monotonic_ns()
                authorization = request.get('authorization')
                if (decoded != tuple(fields) or received_ns >= authorization.deadline_ns or
                        self._private_stop_ack_receipt is not None):
                    raise PermissionError('private STOP ACK failed its immutable receipt binding')
                receipt = PrivateStopAckReceipt(_PRIVATE_STOP_TOKEN, self,
                    authorization, raw_ack, decoded, self.app, self.nonce,
                    self.epoch, request['record'], received_ns)
                self._private_stop_ack_receipt = receipt
                self._private_stop_ack_registry[id(receipt)] = receipt
        except BaseException:
            request['unresolved'] = True
            raise
        self.stopped = True
        self._stop = None
        return True

    def private_stop_ack_receipt(self, authorization):
        """Return only the retained immutable ACK bound to this authorization."""
        receipt = self._private_stop_ack_receipt
        if (type(authorization) is not _PrivateStopAuthorization or
                authorization.token is not _PRIVATE_STOP_TOKEN or
                authorization.broker is not self or
                self._private_stop_authorization is not authorization or
                not self._private_stop_authorization_consumed or
                type(receipt) is not PrivateStopAckReceipt or
                receipt.token is not _PRIVATE_STOP_TOKEN or receipt.broker is not self or
                receipt.authorization is not authorization or
                self._private_stop_ack_registry.get(id(receipt)) is not receipt or
                receipt.raw_ack != bytes(receipt.raw_ack) or
                receipt.actor_identity != self.app or receipt.nonce != self.nonce or
                receipt.epoch != self.epoch or receipt.received_ns >= authorization.deadline_ns or
                tuple(wire.unpack_stop(receipt.raw_ack, wire.STOP_ACK)) != receipt.decoded):
            raise PermissionError('private STOP ACK receipt is missing or changed')
        expected = (self.nonce, self.epoch, wire.EMPTY_MANIFEST_SHA256,
            *self.supervisor[:3], self.supervisor[3], wire.STOP_ID)
        if (receipt.decoded != expected or
                tuple(wire.unpack_stop(receipt.request, wire.STOP)) != expected):
            raise PermissionError('private STOP ACK receipt actor binding changed')
        return receipt

    def close(self):
        if self.app_pidfd >= 0:
            os.close(self.app_pidfd)
            self.app_pidfd = -1
        if self.parent is not None:
            self.parent.close()
            self.parent = None
        if self.child is not None:
            self.child.close()
            self.child = None
