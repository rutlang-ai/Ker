#!/usr/bin/env python3
"""Run a POSIX application against imported Linux, with DPDK Ethernet I/O."""
import argparse
import array
import concurrent.futures
import contextlib
import configparser
import errno
import fcntl
import hashlib
import importlib.util
import ipaddress
import json
import os
import re
import select
from pathlib import Path
import selectors
import shlex
import signal
import shutil
import struct
import socket
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
from types import MappingProxyType
import secrets

# This launcher is also loaded by path (for example from CTest's generated
# selector tests). Load its private codec by sibling path so neither the
# caller's sys.path nor a cached module with the same public name can override it.
_RX_DECISION_WIRE_PATH = Path(__file__).resolve().with_name('rx_decision_wire.py')
_RX_OWNER_RELAY_HEADER = struct.Struct('=IHHQQ16sQQQQIIIIIHHHHIiHBB')
_RX_OWNER_RELAY_MAGIC = 0x4b525852
_RX_OWNER_RELAY_VERSION = 1
_RX_OWNER_RELAY_APP_AUTH = 3
_RX_OWNER_AUTH_RECORD = struct.Struct('=IHHIIIIIIQQQQQQ16s')
_RX_OWNER_AUTH_MAGIC = 0x4b524f41
_RX_OWNER_AUTH_VERSION = 1
_RX_OWNER_AUTH_OWNER = 1
_RX_OWNER_AUTH_ACK = 2
_RX_OWNER_AUTH_PEER = 3
_RX_OWNER_AUTH_PEER_ACK = 4
_RX_OWNER_PEER_AUTH_RECORD = struct.Struct('=IHHIIIIIIQQQQQQ16sIIQQQQQ')
_RX_OWNER_SOURCE_ROUTE_RECORD = struct.Struct('=IHHIIIIIIQQQQQQ16sIIQQQQQQQQIIiIQ')
_RX_OWNER_SOURCE_ROUTE_PREPARE = 5
_RX_OWNER_SOURCE_ROUTE_PREPARED = 6
_RX_OWNER_SOURCE_ROUTE_COMMIT = 7
_RX_OWNER_SOURCE_ROUTE_COMMITTED = 8
_RX_OWNER_SOURCE_ROUTE_ABORT = 9
_RX_OWNER_SOURCE_ROUTE_ABORTED = 10
_RX_OWNER_SOURCE_ROUTE_COMMIT_AFTER_FRAME = 11
_RX_OWNER_SOURCE_ROUTE_COMMITTED_AFTER_FRAME = 12
_RX_OWNER_SOURCE_ROUTE_SUCCESSOR_PREPARE = 13
_RX_OWNER_SOURCE_ROUTE_SUCCESSOR_PREPARED = 14
_SOURCE_ROUTE_PREPARATIONS = {}
_RX_DECISION_WIRE_SPEC = importlib.util.spec_from_file_location(
    '_ker_run_rx_decision_wire', _RX_DECISION_WIRE_PATH)
if _RX_DECISION_WIRE_SPEC is None or _RX_DECISION_WIRE_SPEC.loader is None:
    raise ImportError(f'cannot load private RX decision codec: {_RX_DECISION_WIRE_PATH}')
rx_decision_wire = importlib.util.module_from_spec(_RX_DECISION_WIRE_SPEC)
_RX_DECISION_WIRE_SPEC.loader.exec_module(rx_decision_wire)

_RUNTIME_SERVICE_SPEC = importlib.util.spec_from_file_location(
    '_ker_runtime_service', Path(__file__).resolve().with_name('runtime_service.py'))
if _RUNTIME_SERVICE_SPEC is None or _RUNTIME_SERVICE_SPEC.loader is None:
    raise ImportError(f'cannot load runtime service beside {__file__}')
runtime_service = importlib.util.module_from_spec(_RUNTIME_SERVICE_SPEC)
_RUNTIME_SERVICE_SPEC.loader.exec_module(runtime_service)

_BROKER_READINESS_SPEC = importlib.util.spec_from_file_location(
    '_ker_broker_readiness_supervisor',
    Path(__file__).resolve().with_name('broker_readiness_supervisor.py'))
if _BROKER_READINESS_SPEC is None or _BROKER_READINESS_SPEC.loader is None:
    raise ImportError('cannot load private socket-broker readiness supervisor')
broker_readiness = importlib.util.module_from_spec(_BROKER_READINESS_SPEC)
_BROKER_READINESS_SPEC.loader.exec_module(broker_readiness)

_KER_RUN_CONTROL_SPEC = importlib.util.spec_from_file_location(
    '_ker_run_control_relay', Path(__file__).resolve().with_name('ker_run_control.py'))
if _KER_RUN_CONTROL_SPEC is None or _KER_RUN_CONTROL_SPEC.loader is None:
    raise ImportError('cannot load private ker-run control relay')
ker_run_control = importlib.util.module_from_spec(_KER_RUN_CONTROL_SPEC)
_KER_RUN_CONTROL_SPEC.loader.exec_module(ker_run_control)

_NGINX_COMPANION_SPEC = importlib.util.spec_from_file_location(
    '_ker_nginx_companion_supervisor',
    Path(__file__).resolve().with_name('nginx_companion_supervisor.py'))
if _NGINX_COMPANION_SPEC is None or _NGINX_COMPANION_SPEC.loader is None:
    raise ImportError('cannot load private Nginx companion supervisor')
nginx_companion = importlib.util.module_from_spec(_NGINX_COMPANION_SPEC)
_NGINX_COMPANION_SPEC.loader.exec_module(nginx_companion)

_SOURCE_SHELL_CONTROLLER_NAME = '_ker_nginx_source_shell_controller'
source_shell_controller_module = None
_SOURCE_ORIGIN_NAME = '_ker_nginx_source_origin'


def _load_source_shell_controller():
    global source_shell_controller_module
    canonical = Path(__file__).resolve().with_name(
        'nginx_source_shell_controller.py').resolve(strict=True)
    cached = sys.modules.get(_SOURCE_SHELL_CONTROLLER_NAME)
    if cached is not None:
        if Path(cached.__file__).resolve(strict=True) != canonical:
            raise ImportError('cached source-shell controller belongs to another path')
        source_shell_controller_module = cached
        return cached
    spec = importlib.util.spec_from_file_location(_SOURCE_SHELL_CONTROLLER_NAME, canonical)
    if spec is None or spec.loader is None:
        raise ImportError('cannot load private source-shell controller')
    module = importlib.util.module_from_spec(spec)
    sys.modules[_SOURCE_SHELL_CONTROLLER_NAME] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        if sys.modules.get(_SOURCE_SHELL_CONTROLLER_NAME) is module:
            del sys.modules[_SOURCE_SHELL_CONTROLLER_NAME]
        raise
    source_shell_controller_module = module
    return module


def _load_source_origin_module():
    canonical = Path(__file__).resolve().with_name('nginx_source_origin.py').resolve(strict=True)
    cached = sys.modules.get(_SOURCE_ORIGIN_NAME)
    if cached is not None:
        if Path(cached.__file__).resolve(strict=True) != canonical:
            raise ImportError('cached source Origin belongs to another path')
        return cached
    spec = importlib.util.spec_from_file_location(_SOURCE_ORIGIN_NAME, canonical)
    if spec is None or spec.loader is None:
        raise ImportError('cannot load canonical source Origin')
    module = importlib.util.module_from_spec(spec)
    sys.modules[_SOURCE_ORIGIN_NAME] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        if sys.modules.get(_SOURCE_ORIGIN_NAME) is module:
            del sys.modules[_SOURCE_ORIGIN_NAME]
        raise
    return module

_SOURCE_NETWORK_STARTUP_NAME = '_ker_source_network_startup'


def _load_source_network_startup(path):
    """Reuse one path-checked Python module instance across embedded imports."""
    canonical = Path(path).resolve(strict=True)
    cached = sys.modules.get(_SOURCE_NETWORK_STARTUP_NAME)
    if cached is not None:
        cached_path = getattr(cached, '__file__', None)
        if (not isinstance(cached_path, str) or
                Path(cached_path).resolve(strict=False) != canonical):
            raise ImportError('cached source-network module belongs to another path')
        return cached
    spec = importlib.util.spec_from_file_location(_SOURCE_NETWORK_STARTUP_NAME, canonical)
    if spec is None or spec.loader is None:
        raise ImportError(f'cannot load private source-network startup parser: {canonical}')
    module = importlib.util.module_from_spec(spec)
    sys.modules[_SOURCE_NETWORK_STARTUP_NAME] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        if sys.modules.get(_SOURCE_NETWORK_STARTUP_NAME) is module:
            del sys.modules[_SOURCE_NETWORK_STARTUP_NAME]
        raise
    return module


source_network_startup = _load_source_network_startup(
    Path(__file__).resolve().with_name('source_network_startup.py'))


class Interrupted(Exception):
    def __init__(self, signum):
        self.signum = signum


def interrupted(signum, _frame):
    raise Interrupted(signum)


_COMPANION_RELOAD_REQUESTED = False


def companion_reload_requested(_signum, _frame):
    global _COMPANION_RELOAD_REQUESTED
    _COMPANION_RELOAD_REQUESTED = True


def process_start_ticks(pid):
    """Return Linux /proc starttime (field 22), parsing comm with spaces safely."""
    text = Path(f'/proc/{pid}/stat').read_text(encoding='ascii')
    close = text.rfind(')')
    if close < 0 or close + 2 >= len(text):
        raise RuntimeError(f'cannot parse /proc/{pid}/stat')
    fields = text[close + 2:].split()  # field 3 (state) is fields[0]
    if len(fields) <= 19:
        raise RuntimeError(f'incomplete /proc/{pid}/stat')
    start = int(fields[19], 10)
    if start <= 0:
        raise RuntimeError(f'invalid /proc/{pid}/stat starttime for pid {pid}')
    return start


def _retain_worker_pidfd(worker, retained):
    """Reuse the SDK's worker pidfd when source READY already pinned it."""
    if type(retained) is not int:
        raise TypeError('worker pidfd must be an integer descriptor')
    return retained if retained >= 0 else os.pidfd_open(worker.pid, 0)


def rx_decision_bootstrap(endpoint, target_role, target, supervisor,
                          supervisor_pidfd, nonce, worker_epoch):
    """Send a supervisor-authenticated bootstrap and duplicate both pidfds."""
    body = rx_decision_wire.BOOTSTRAP_BODY.pack(
        target_role, target.pid, target.uid, target.gid, target.start_ticks,
        supervisor.pid, supervisor.uid, supervisor.gid, 0, supervisor.start_ticks)
    header = rx_decision_wire.pack_header(rx_decision_wire.BOOTSTRAP, nonce,
        worker_epoch, control_id=1, body_bytes=len(body))
    rights = array.array('i', (target.pidfd, supervisor_pidfd))
    sent = endpoint.sendmsg([header, body], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)],
                            getattr(socket, 'MSG_NOSIGNAL', 0))
    if sent != len(header) + len(body):
        raise RuntimeError('short RX decision bootstrap send')


def rx_decision_identity(pid, pidfd):
    return SimpleNamespace(pid=pid, uid=os.stat(f'/proc/{pid}').st_uid,
        gid=os.stat(f'/proc/{pid}').st_gid, start_ticks=process_start_ticks(pid),
        pidfd=pidfd)


def rx_owner_relay_auth(endpoint, app, app_pidfd, supervisor_pidfd,
                        companion, nonce, epoch, authority_deadline_ns=None):
    owner_pid = companion.owner_pid
    owner_tid = companion.owner_tid
    owner_start = companion.owner_start
    if (endpoint is None or app is None or app_pidfd < 0 or owner_pid <= 0 or
            owner_tid <= 0 or owner_start <= 0 or not nonce or not epoch):
        raise RuntimeError('incomplete authenticated RX owner relay identity')
    now_ns = time.monotonic_ns()
    deadline_ns = now_ns + 5_000_000_000
    if authority_deadline_ns is not None:
        if type(authority_deadline_ns) is not int:
            raise TypeError('source APP_AUTH deadline must be an absolute monotonic integer')
        deadline_ns = min(deadline_ns, authority_deadline_ns)
    if now_ns >= deadline_ns:
        raise TimeoutError('source APP_AUTH grant deadline expired before send')
    app_start = process_start_ticks(app.pid)
    supervisor_start = process_start_ticks(os.getpid())
    payload = _RX_OWNER_RELAY_HEADER.pack(_RX_OWNER_RELAY_MAGIC,
        _RX_OWNER_RELAY_VERSION, _RX_OWNER_RELAY_APP_AUTH, 0, 0, nonce, epoch,
        app_start, owner_start, supervisor_start,
        app.pid, owner_pid, owner_tid, os.getpid(), 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0)
    rights = array.array('i', (app_pidfd, supervisor_pidfd))
    sent = endpoint.sendmsg([payload], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)],
        getattr(socket, 'MSG_NOSIGNAL', 0) |
        (getattr(socket, 'MSG_DONTWAIT', 0) if authority_deadline_ns is not None else 0))
    if sent != len(payload):
        raise RuntimeError('short authenticated RX owner relay bootstrap send')
    if time.monotonic_ns() >= deadline_ns:
        raise TimeoutError('source APP_AUTH send completed after its immutable deadline')


def rx_owner_expected_auth(endpoint, app, app_pidfd, supervisor_pidfd,
                           companion, nonce, epoch, supervisor_start,
                           authority_deadline_ns=None):
    if (endpoint is None or app is None or app_pidfd < 0 or supervisor_pidfd < 0 or
            companion.owner_pidfd < 0 or companion.owner_pid <= 0 or
            companion.owner_tid <= 0 or companion.owner_start <= 0 or
            companion.owner_slot_device <= 0 or companion.owner_slot_inode <= 0 or
            companion.owner_cookie <= 0):
        raise RuntimeError('incomplete supervisor-authenticated Nginx owner READY')
    app_start = process_start_ticks(app.pid)
    now_ns = time.monotonic_ns()
    deadline_ns = now_ns + 5_000_000_000
    if authority_deadline_ns is not None:
        if type(authority_deadline_ns) is not int:
            raise TypeError('source OWNER_AUTH deadline must be an absolute monotonic integer')
        deadline_ns = min(deadline_ns, authority_deadline_ns)
    if now_ns >= deadline_ns:
        raise TimeoutError('source OWNER_AUTH grant deadline expired before send')
    if (nginx_companion._pidfd_pid(app_pidfd) != app.pid or
            process_start_ticks(os.getpid()) != supervisor_start or
            not nginx_companion.process_alive(app_pidfd) or
            not nginx_companion.process_alive(supervisor_pidfd) or
            not nginx_companion.process_alive(companion.owner_pidfd)):
        raise ProcessLookupError('owner AUTH process identity is stale before send')
    payload = _RX_OWNER_AUTH_RECORD.pack(_RX_OWNER_AUTH_MAGIC,
        _RX_OWNER_AUTH_VERSION, _RX_OWNER_AUTH_OWNER,
        _RX_OWNER_AUTH_RECORD.size, os.getpid(), companion.owner_pid,
        companion.owner_tid, companion.owner_role, 0, epoch, supervisor_start,
        companion.owner_start, companion.owner_slot_device,
        companion.owner_slot_inode, companion.owner_cookie, nonce)
    rights = array.array('i', (companion.owner_pidfd, supervisor_pidfd))
    sent = endpoint.sendmsg([payload], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)],
        getattr(socket, 'MSG_NOSIGNAL', 0) |
        (getattr(socket, 'MSG_DONTWAIT', 0) if authority_deadline_ns is not None else 0))
    if sent != len(payload):
        raise RuntimeError('short supervisor-to-app owner AUTH send')
    if time.monotonic_ns() >= deadline_ns:
        raise TimeoutError('source OWNER_AUTH send completed after its immutable deadline')
    selector = selectors.DefaultSelector()
    try:
        selector.register(endpoint, selectors.EVENT_READ)
        if not selector.select(max(0, (deadline_ns - time.monotonic_ns()) / 1_000_000_000)):
            raise TimeoutError('C31 app did not acknowledge authenticated owner READY')
        packet, ancillary, flags, _address = endpoint.recvmsg(_RX_OWNER_AUTH_RECORD.size + 1,
            socket.CMSG_SPACE(struct.calcsize('=3i')) + socket.CMSG_SPACE(4 * 4),
            getattr(socket, 'MSG_CMSG_CLOEXEC', 0))
    finally:
        selector.close()
    credentials = None
    unexpected_fds = []
    ancillary_error = None
    for level, kind, value in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS:
            if credentials is not None or len(value) != struct.calcsize('=3i'):
                ancillary_error = ValueError('duplicate or malformed OWNER_AUTH ACK credentials')
            else:
                credentials = struct.unpack('=3i', value)
        elif level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            received = array.array('i')
            if len(value) % received.itemsize:
                ancillary_error = ValueError('malformed OWNER_AUTH ACK descriptor ancillary')
            received.frombytes(value[:len(value) - len(value) % received.itemsize])
            unexpected_fds.extend(received)
            ancillary_error = ValueError('unexpected descriptors in OWNER_AUTH ACK')
        else:
            ancillary_error = ValueError('unexpected OWNER_AUTH ACK ancillary data')
    try:
        if ancillary_error is not None:
            raise ancillary_error
        allowed_flags = getattr(socket, 'MSG_CMSG_CLOEXEC', 0)
        invalid_flags = (flags & ~allowed_flags if authority_deadline_ns is not None else
            flags & (getattr(socket, 'MSG_TRUNC', 0) | getattr(socket, 'MSG_CTRUNC', 0)))
        if (len(packet) != _RX_OWNER_AUTH_RECORD.size or invalid_flags or
                unexpected_fds or credentials != (app.pid, os.stat(f'/proc/{app.pid}').st_uid,
                    os.stat(f'/proc/{app.pid}').st_gid)):
            raise PermissionError('invalid C31 app owner AUTH acknowledgement credentials/shape')
        ack = _RX_OWNER_AUTH_RECORD.unpack(packet)
        expected = list(_RX_OWNER_AUTH_RECORD.unpack(payload))
        expected[2] = _RX_OWNER_AUTH_ACK
        if (tuple(expected) != ack or time.monotonic_ns() >= deadline_ns or
                process_start_ticks(app.pid) != app_start or
                nginx_companion._pidfd_pid(app_pidfd) != app.pid or
                not nginx_companion.process_alive(app_pidfd) or
                not nginx_companion.process_alive(supervisor_pidfd)):
            raise PermissionError('C31 app owner AUTH acknowledgement identity mismatch')
        if time.monotonic_ns() >= deadline_ns or not nginx_companion.process_alive(companion.owner_pidfd):
            raise ProcessLookupError('authenticated Nginx owner died before C31 app acknowledgement')
        print('KER_RX_OWNER_EXPECTED_AUTH ' + json.dumps({
            'pid': companion.owner_pid, 'start_ticks': companion.owner_start,
            'tid': companion.owner_tid, 'role': companion.owner_role,
            'slot_device': companion.owner_slot_device,
            'slot_inode': companion.owner_slot_inode, 'cookie': companion.owner_cookie,
        }, sort_keys=True, separators=(',', ':')), flush=True)
    finally:
        for fd in unexpected_fds:
            os.close(fd)


def rx_owner_peer_auth(endpoint, peer_channel, app, app_pidfd, supervisor_pidfd,
                       primary, old, nonce, epoch, authority_deadline_ns):
    """Delegate one finite old-owner binding after both real READY proofs.

    The caller retains reload-window control and must not begin traffic
    handoff before this ACK. It must keep the window authorized through the
    supplied deadline. Successful delegation consumes peer_channel; a failed
    call never permits forwarding or promises rollback to healthy service.
    The legacy single-owner launch path does not enable this opt-in protocol.
    """
    now = time.monotonic_ns()
    if (not nonce or len(nonce) != 16 or not epoch or
            authority_deadline_ns <= now or authority_deadline_ns - now > 300_000_000_000 or
            primary.owner_role != 1 or old.owner_role != 0 or
            primary.owner_pid == old.owner_pid or primary.owner_cookie == old.owner_cookie or
            (primary.owner_slot_device, primary.owner_slot_inode) ==
                (old.owner_slot_device, old.owner_slot_inode)):
        raise ValueError('invalid finite current/old owner authority')
    supervisor = os.getpid()
    supervisor_start = process_start_ticks(supervisor)
    app_start = process_start_ticks(app.pid)
    if (nginx_companion._pidfd_pid(app_pidfd) != app.pid or
            nginx_companion._pidfd_pid(supervisor_pidfd) != supervisor):
        raise PermissionError('peer authorization app/supervisor pidfd mismatch')
    for owner in (primary, old):
        if (not all(value > 0 for value in (owner.owner_pid, owner.owner_tid,
                owner.owner_start, owner.owner_slot_device, owner.owner_slot_inode, owner.owner_cookie)) or
                nginx_companion._pidfd_pid(owner.owner_pidfd) != owner.owner_pid or
                process_start_ticks(owner.owner_pid) != owner.owner_start or
                not Path(f'/proc/{owner.owner_pid}/task/{owner.owner_tid}').is_dir() or
                not nginx_companion.process_alive(owner.owner_pidfd)):
            raise ProcessLookupError('peer authorization owner READY is stale')
    fields = [
        _RX_OWNER_AUTH_MAGIC, _RX_OWNER_AUTH_VERSION, _RX_OWNER_AUTH_PEER,
        _RX_OWNER_PEER_AUTH_RECORD.size, supervisor, old.owner_pid, old.owner_tid,
        old.owner_role, 0, epoch, supervisor_start, old.owner_start,
        old.owner_slot_device, old.owner_slot_inode, old.owner_cookie, nonce,
        primary.owner_pid, primary.owner_tid, primary.owner_start,
        primary.owner_slot_device, primary.owner_slot_inode, primary.owner_cookie,
        authority_deadline_ns]
    payload = _RX_OWNER_PEER_AUTH_RECORD.pack(*fields)
    if (peer_channel.family != socket.AF_UNIX or
            peer_channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_SEQPACKET):
        raise ValueError('old-owner relay requires a Unix packet channel')
    # Enable credentials before the old worker can enqueue its AUTH_ACK.
    # Setting this only after SCM_RIGHTS reception races an already queued ACK.
    peer_channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    peer_channel.setblocking(False)
    if not (nginx_companion.process_alive(app_pidfd) and
            nginx_companion.process_alive(supervisor_pidfd)):
        raise ProcessLookupError('peer authorization actor died before send')
    rights = array.array('i', (old.owner_pidfd, peer_channel.fileno()))
    sent = endpoint.sendmsg([payload], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)],
        getattr(socket, 'MSG_NOSIGNAL', 0) | getattr(socket, 'MSG_DONTWAIT', 0))
    if sent != len(payload):
        raise RuntimeError('short supervisor-to-app peer AUTH send')
    # The old module only accepts this bootstrap from the pinned supervisor.
    # The C31 app receives the ACK on its newly delegated duplicate channel.
    rx_owner_relay_auth(peer_channel, app, app_pidfd, supervisor_pidfd, old, nonce, epoch)
    deadline = min(time.monotonic() + 5, authority_deadline_ns / 1e9)
    with selectors.DefaultSelector() as selector:
        selector.register(endpoint, selectors.EVENT_READ)
        if not selector.select(max(0, deadline - time.monotonic())):
            raise TimeoutError('old-owner peer AUTH did not complete')
    packet, ancillary, flags, _ = endpoint.recvmsg(_RX_OWNER_PEER_AUTH_RECORD.size + 1,
        socket.CMSG_SPACE(struct.calcsize('=3i')) + socket.CMSG_SPACE(4 * 4),
        getattr(socket, 'MSG_CMSG_CLOEXEC', 0))
    credentials = []
    extra_fds = []
    invalid = False
    try:
        for level, kind, value in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(value) == 12:
                credentials.append(struct.unpack('=3i', value))
            elif level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                values = array.array('i')
                values.frombytes(value[:len(value) - len(value) % values.itemsize])
                extra_fds.extend(values)
                invalid = True
            else:
                invalid = True
        expected = fields.copy()
        expected[2] = _RX_OWNER_AUTH_PEER_ACK
        if (invalid or len(packet) != _RX_OWNER_PEER_AUTH_RECORD.size or
                flags & (getattr(socket, 'MSG_TRUNC', 0) | getattr(socket, 'MSG_CTRUNC', 0)) or
                credentials != [(app.pid, os.stat(f'/proc/{app.pid}').st_uid,
                    os.stat(f'/proc/{app.pid}').st_gid)] or
                _RX_OWNER_PEER_AUTH_RECORD.unpack(packet) != tuple(expected)):
            raise PermissionError('peer AUTH ACK credentials/context mismatch')
        if (time.monotonic() >= deadline or process_start_ticks(app.pid) != app_start or
                process_start_ticks(supervisor) != supervisor_start or
                not all(nginx_companion.process_alive(fd) for fd in
                    (app_pidfd, supervisor_pidfd, primary.owner_pidfd, old.owner_pidfd))):
            raise ProcessLookupError('peer authority expired or actor died before ACK')
        peer_channel.close()
        print('KER_RX_OWNER_PEER_AUTHORIZED ' + json.dumps({
            'old_pid': old.owner_pid, 'old_cookie': old.owner_cookie,
            'primary_pid': primary.owner_pid, 'primary_cookie': primary.owner_cookie,
            'authority_deadline_ns': authority_deadline_ns}, sort_keys=True), flush=True)
    finally:
        for fd in extra_fds:
            os.close(fd)


def rx_owner_source_route_prepare(endpoint, candidate_channel, app, app_pidfd,
                                  supervisor_pidfd, current, candidate,
                                  source_master, nonce, epoch,
                                  authority_deadline_ns, operation_id,
                                  command_sequence=None, source_epoch=1,
                                  previous_aborted=None, previous_committed=None,
                                  source_context=None, source_park_evidence=None,
                                  source_cycle_proof=None, prepare_deadline_ns=None):
    """Stage a fresh same-master source candidate while retaining current route.

    The candidate ACK is consumed by C31 after this function sends supervisor
    APP_AUTH; this function waits only for C31's independently validated
    PREPARED response. The caller must send source-worker ACTIVATE afterward.
    A later epoch requires the preceding COMMIT or the explicit epoch-1 ABORT.
    `prepared.candidate_pidfd` is borrowed from the caller's READY proof; the
    caller keeps it open through any retry decision and closes it in its normal
    proof cleanup, including when PREPARE or COMMIT fails.
    """
    successor = previous_committed is not None
    upgrade = successor and source_epoch == 2 and getattr(source_context, 'upgrade_scope', False)
    if type(source_epoch) is not int or not 1 <= source_epoch <= 100 or (
            not successor and source_epoch > 2):
        raise ValueError('unsupported source-route epoch')
    now = time.monotonic_ns()
    if successor:
        previous_fields = getattr(previous_committed, 'fields', ())
        previous_sequence = getattr(previous_committed, 'command_sequence', 0)
        if command_sequence is None:
            command_sequence = previous_sequence + 1
        if (previous_aborted is not None or
                not getattr(previous_committed, 'committed', False) or
                getattr(previous_committed, 'source_epoch', 0) != source_epoch - 1 or
                previous_committed.last_command_type not in
                    (_RX_OWNER_SOURCE_ROUTE_COMMIT, _RX_OWNER_SOURCE_ROUTE_COMMIT_AFTER_FRAME) or
                previous_committed.last_status != 0 or len(previous_fields) != 23 or
                source_master.pid != previous_committed.master_pid or
                getattr(source_master, 'start_ticks', 0) != previous_committed.master_start or
                authority_deadline_ns > previous_fields[22] or
                operation_id <= previous_committed.operation_id or
                command_sequence <= previous_sequence or epoch != previous_fields[9] or
                nonce != previous_fields[15] or current.owner_role != 1 or
                (current.owner_pid, current.owner_tid, current.owner_start,
                    current.owner_slot_device, current.owner_slot_inode, current.owner_cookie) !=
                    (previous_fields[5], previous_fields[6], previous_fields[11],
                     previous_fields[12], previous_fields[13], previous_fields[14]) or
                candidate.owner_pid in (current.owner_pid, previous_fields[16],
                    previous_fields[5]) or
                candidate.owner_start in (previous_fields[11], previous_fields[18]) or
                candidate.owner_cookie in (current.owner_cookie, previous_fields[14],
                    previous_fields[21]) or
                (candidate.owner_slot_device, candidate.owner_slot_inode) in
                    ((current.owner_slot_device, current.owner_slot_inode),
                     (previous_fields[12], previous_fields[13]),
                     (previous_fields[19], previous_fields[20]))):
            raise ValueError('successor requires committed lineage and a fresh same-master candidate')
    if source_epoch == 1:
        if previous_aborted is not None or successor:
            raise ValueError('epoch 1 cannot use retry lineage')
        if command_sequence is None:
            command_sequence = 1
    elif not successor:
        previous_fields = getattr(previous_aborted, 'fields', ())
        previous_sequence = getattr(previous_aborted, 'command_sequence', 0)
        if command_sequence is None:
            command_sequence = previous_sequence + 1
        if (previous_aborted is None or not getattr(previous_aborted, 'aborted', False) or
                getattr(previous_aborted, 'source_epoch', 0) != 1 or
                len(previous_fields) != 23 or
                nginx_companion.process_alive(previous_aborted.candidate_pidfd) or
                source_master.pid != previous_aborted.master_pid or
                getattr(source_master, 'start_ticks', 0) != previous_aborted.master_start or
                authority_deadline_ns > previous_fields[22] or
                operation_id <= previous_aborted.operation_id or
                command_sequence <= previous_sequence or epoch != previous_fields[9] or
                nonce != previous_fields[15] or
                (current.owner_pid, current.owner_tid, current.owner_start,
                    current.owner_slot_device, current.owner_slot_inode, current.owner_cookie) !=
                    tuple(previous_fields[16:22]) or
                candidate.owner_pid == previous_fields[5] or
                candidate.owner_pid == previous_fields[16] or
                candidate.owner_start == previous_fields[11] or
                candidate.owner_start == previous_fields[18] or
                candidate.owner_cookie == previous_fields[14] or
                candidate.owner_cookie == previous_fields[21] or
                (candidate.owner_slot_device, candidate.owner_slot_inode) ==
                    (previous_fields[12], previous_fields[13]) or
                (candidate.owner_slot_device, candidate.owner_slot_inode) ==
                    (previous_fields[19], previous_fields[20])):
            raise ValueError('epoch 2 requires one fresh candidate after acknowledged abort')
    if (not nonce or len(nonce) != 16 or not epoch or
            authority_deadline_ns <= now or
            authority_deadline_ns - now > (1_800_000_000_000 if
                getattr(source_context, 'allow_successor', False) else 300_000_000_000) or
            current.owner_role != (1 if successor else 0) or candidate.owner_role != 1 or
            current.owner_pid == candidate.owner_pid or
            current.owner_cookie == candidate.owner_cookie or
            (current.owner_slot_device, current.owner_slot_inode) ==
                (candidate.owner_slot_device, candidate.owner_slot_inode) or
            operation_id <= 0 or command_sequence <= 0):
        raise ValueError('invalid finite source-route candidate authority')
    supervisor = os.getpid()
    supervisor_start = process_start_ticks(supervisor)
    app_start = process_start_ticks(app.pid)
    master_start = process_start_ticks(source_master.pid)
    expected_master_start = getattr(source_master, 'start_ticks', master_start)
    if master_start != expected_master_start:
        raise ProcessLookupError('source master start time changed before PREPARE')
    for owner in (current, candidate):
        if (not all(value > 0 for value in (owner.owner_pid, owner.owner_tid,
                owner.owner_start, owner.owner_slot_device, owner.owner_slot_inode,
                owner.owner_cookie)) or
                nginx_companion._pidfd_pid(owner.owner_pidfd) != owner.owner_pid or
                process_start_ticks(owner.owner_pid) != owner.owner_start or
                not Path(f'/proc/{owner.owner_pid}/task/{owner.owner_tid}').is_dir() or
                not nginx_companion.process_alive(owner.owner_pidfd)):
            raise ProcessLookupError('source-route READY identity is stale')
    if (nginx_companion._pidfd_pid(app_pidfd) != app.pid or
            nginx_companion._pidfd_pid(supervisor_pidfd) != supervisor or
            nginx_companion._pidfd_pid(source_master.pidfd) != source_master.pid or
            not nginx_companion.process_alive(source_master.pidfd)):
        raise ProcessLookupError('source-route app, supervisor, or master is stale')
    fields = [
        _RX_OWNER_AUTH_MAGIC, _RX_OWNER_AUTH_VERSION,
        _RX_OWNER_SOURCE_ROUTE_SUCCESSOR_PREPARE if successor else _RX_OWNER_SOURCE_ROUTE_PREPARE,
        _RX_OWNER_SOURCE_ROUTE_RECORD.size, supervisor, candidate.owner_pid,
        candidate.owner_tid, candidate.owner_role, int(upgrade), epoch, supervisor_start,
        candidate.owner_start, candidate.owner_slot_device,
        candidate.owner_slot_inode, candidate.owner_cookie, nonce,
        current.owner_pid, current.owner_tid, current.owner_start,
        current.owner_slot_device, current.owner_slot_inode, current.owner_cookie,
        authority_deadline_ns,
    ]
    source_bound = any(value is not None for
        value in (source_context, source_park_evidence, source_cycle_proof))
    source_bootstrap = None
    actors = (app.pid, app_start, app_pidfd, supervisor,
        supervisor_start, supervisor_pidfd, source_master.pid,
        master_start, source_master.pidfd)
    def route_actor(owner):
        return (owner, owner.owner_pid, owner.owner_tid, owner.owner_role,
            owner.owner_start, owner.owner_slot_device, owner.owner_slot_inode,
            owner.owner_cookie, owner.owner_pidfd)
    current_actor = route_actor(current)
    candidate_actor = route_actor(candidate)
    if source_bound and source_epoch > 1:
        if (type(prepare_deadline_ns) is not int or
                not time.monotonic_ns() < prepare_deadline_ns <= authority_deadline_ns):
            raise PermissionError('typed C31 successor requires a live setup deadline within its grant')
    elif prepare_deadline_ns is not None:
        raise PermissionError('C31 successor setup deadline requires typed later-round authority')
    if source_bound:
        if (source_context is None or source_cycle_proof is None or
                source_park_evidence is not None):
            raise PermissionError('typed C31 PREPARE requires the exact source context before PARK')
        source_bootstrap = sys.modules.get(type(source_context).__module__)
        expected_path = Path(__file__).resolve().with_name(
            'nginx_source_bootstrap_supervisor.py')
        preflight = getattr(source_bootstrap,
            '_validate_source_route_prepare_inputs', None)
        if (source_bootstrap is None or
                Path(getattr(source_bootstrap, '__file__', '')).resolve() != expected_path or
                not callable(preflight)):
            raise PermissionError('source handoff did not resolve the canonical bootstrap module')
        preflight(source_context, tuple(fields), source_epoch, current_actor,
            candidate_actor, source_cycle_proof, endpoint, candidate_channel, actors,
            previous_aborted=previous_aborted, previous_committed=previous_committed,
            prepare_deadline_ns=prepare_deadline_ns)
    if source_bound:
        if (type(endpoint) is not socket.socket or
                endpoint.family != socket.AF_UNIX or
                endpoint.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) !=
                    socket.SOCK_SEQPACKET or
                endpoint.gettimeout() != 0.0 or
                not fcntl.fcntl(endpoint.fileno(), fcntl.F_GETFL) & os.O_NONBLOCK or
                not fcntl.fcntl(endpoint.fileno(), fcntl.F_GETFD) & fcntl.FD_CLOEXEC):
            raise PermissionError('source C31 PREPARED requires the exact seqpacket endpoint')
    payload = _RX_OWNER_SOURCE_ROUTE_RECORD.pack(*fields, operation_id,
        command_sequence, master_start, source_master.pid, source_epoch, 0, 0, 0)
    if (type(candidate_channel) is not socket.socket or
            candidate_channel.family != socket.AF_UNIX or
            candidate_channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) !=
                socket.SOCK_SEQPACKET):
        raise ValueError('candidate route requires a Unix packet channel')
    if source_bound and (candidate_channel is endpoint or
            not fcntl.fcntl(candidate_channel.fileno(), fcntl.F_GETFL) & os.O_NONBLOCK or
            not fcntl.fcntl(candidate_channel.fileno(), fcntl.F_GETFD) & fcntl.FD_CLOEXEC):
        raise PermissionError('typed C31 PREPARE requires a distinct nonblocking CLOEXEC candidate relay')
    # The receiving app must enable credentials before APP_AUTH can queue ACK.
    if source_bound and source_epoch == 2 and not successor:
        begin = getattr(source_bootstrap, '_begin_source_route_retry_prepare', None)
        if not callable(begin):
            raise PermissionError('canonical C31 retry attempt tracker is unavailable')
        begin(source_context, previous_aborted, operation_id, command_sequence, prepare_deadline_ns)
    candidate_channel.setblocking(False)
    candidate_channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    rights = array.array('i', (candidate.owner_pidfd, candidate_channel.fileno(),
        source_master.pidfd))
    if upgrade:
        rights.append(source_context._worker_master((2, 0)).pidfd)
    sent = endpoint.sendmsg([payload], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)],
        getattr(socket, 'MSG_NOSIGNAL', 0) | getattr(socket, 'MSG_DONTWAIT', 0))
    if sent != len(payload):
        raise RuntimeError('short supervisor-to-C31 source-route PREPARE send')
    rx_owner_relay_auth(candidate_channel, app, app_pidfd, supervisor_pidfd,
        candidate, nonce, epoch, authority_deadline_ns=prepare_deadline_ns)
    deadline = min(time.monotonic() + 5, authority_deadline_ns / 1e9,
        (prepare_deadline_ns or authority_deadline_ns) / 1e9)
    with selectors.DefaultSelector() as selector:
        selector.register(endpoint, selectors.EVENT_READ)
        if not selector.select(max(0, deadline - time.monotonic())):
            raise TimeoutError('C31 did not validate candidate APP_AUTH_ACK')
    packet, ancillary, flags, _ = endpoint.recvmsg(_RX_OWNER_SOURCE_ROUTE_RECORD.size + 1,
        socket.CMSG_SPACE(struct.calcsize('=3i')) + socket.CMSG_SPACE(4 * 4),
        getattr(socket, 'MSG_CMSG_CLOEXEC', 0))
    extra_fds = []
    credentials = []
    invalid = False
    try:
        for level, kind, value in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(value) == 12:
                credentials.append(struct.unpack('=3i', value))
            elif level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                values = array.array('i')
                values.frombytes(value[:len(value) - len(value) % values.itemsize])
                extra_fds.extend(values)
                invalid = True
            else:
                invalid = True
        expected = fields.copy()
        expected[2] = (_RX_OWNER_SOURCE_ROUTE_SUCCESSOR_PREPARED if successor else
            _RX_OWNER_SOURCE_ROUTE_PREPARED)
        expected_wire = _RX_OWNER_SOURCE_ROUTE_RECORD.pack(*expected, operation_id,
            command_sequence, master_start, source_master.pid, source_epoch, 0, 0, 0)
        allowed_receive_flags = getattr(socket, 'MSG_CMSG_CLOEXEC', 0)
        if (invalid or extra_fds or flags & (getattr(socket, 'MSG_TRUNC', 0) |
                getattr(socket, 'MSG_CTRUNC', 0)) or
                (source_context is not None and flags & ~allowed_receive_flags) or
                credentials != [(app.pid, os.stat(f'/proc/{app.pid}').st_uid,
                    os.stat(f'/proc/{app.pid}').st_gid)] or
                len(packet) != _RX_OWNER_SOURCE_ROUTE_RECORD.size):
            raise PermissionError(f'source-route PREPARED credentials, size, or receive flags mismatch: '
                f'flags={flags} allowed={allowed_receive_flags} invalid={invalid} '
                f'extra_fds={len(extra_fds)} bytes={len(packet)} expected={_RX_OWNER_SOURCE_ROUTE_RECORD.size} '
                f'credentials={credentials} expected_credentials={app.pid, os.stat(f"/proc/{app.pid}").st_uid, os.stat(f"/proc/{app.pid}").st_gid}')
        actual = list(_RX_OWNER_SOURCE_ROUTE_RECORD.unpack(packet))
        status = actual[28]
        actual[28] = 0
        if tuple(actual) != _RX_OWNER_SOURCE_ROUTE_RECORD.unpack(expected_wire):
            raise PermissionError('source-route PREPARED identity/context mismatch')
        if status:
            raise PermissionError(f'C31 rejected source-route candidate: {status}')
        if (time.monotonic() >= deadline or process_start_ticks(app.pid) != app_start or
                process_start_ticks(supervisor) != supervisor_start or
                not all(nginx_companion.process_alive(fd) for fd in
                    (app_pidfd, supervisor_pidfd, candidate.owner_pidfd,
                     current.owner_pidfd, source_master.pidfd))):
            raise ProcessLookupError('source authority expired or actor died before PREPARED')
        print('KER_RX_OWNER_SOURCE_ROUTE_PREPARED ' + json.dumps({
            'current_pid': current.owner_pid, 'candidate_pid': candidate.owner_pid,
            'operation_id': operation_id, 'command_sequence': command_sequence,
            'authority_deadline_ns': authority_deadline_ns},
            sort_keys=True, separators=(',', ':')), flush=True)
        prepared = SimpleNamespace(fields=fields, operation_id=operation_id,
            command_sequence=command_sequence, master_start=master_start,
            master_pid=source_master.pid, source_epoch=source_epoch, app_pid=app.pid,
            app_start=app_start, app_pidfd=app_pidfd,
            supervisor_pid=supervisor, supervisor_start=supervisor_start,
            candidate_pidfd=candidate.owner_pidfd, aborted=False,
            committed=False, last_command_type=None, last_status=None)
        if any(value is not None for value in
                (source_context, source_park_evidence, source_cycle_proof)):
            factory = getattr(source_bootstrap, '_make_source_route_preparation', None)
            register = getattr(source_bootstrap, '_register_source_route_preparation', None)
            if not callable(factory) or not callable(register):
                raise PermissionError('source handoff lost the canonical bootstrap entrypoints')
            prepared._source_route_preparation = register(factory(source_context,
                None, prepared, tuple(fields), source_epoch,
                current_actor, candidate_actor, source_cycle_proof,
                endpoint, candidate_channel, actors, bytes(packet), bytes(expected_wire),
                tuple(credentials[0]), previous_aborted=previous_aborted,
                previous_committed=previous_committed, prepare_deadline_ns=prepare_deadline_ns))
            prepared._source_route_commit_receipt = None
            _SOURCE_ROUTE_PREPARATIONS[id(prepared)] = (prepared,
                source_context, prepared._source_route_preparation)
        return prepared
    finally:
        for fd in extra_fds:
            os.close(fd)


def rx_owner_source_route_successor_prepare(endpoint, candidate_channel, app,
                                            app_pidfd, supervisor_pidfd, current,
                                            candidate, source_master, nonce, epoch,
                                            authority_deadline_ns, operation_id,
                                            command_sequence, previous_committed):
    """Stage the one epoch-2 candidate after an acknowledged epoch-1 commit."""
    return rx_owner_source_route_prepare(endpoint, candidate_channel, app,
        app_pidfd, supervisor_pidfd, current, candidate, source_master, nonce,
        epoch, authority_deadline_ns, operation_id, command_sequence,
        source_epoch=2, previous_committed=previous_committed)


def send_source_route_command(endpoint, prepared, command_type, command_sequence,
                              operation_deadline_ns=None):
    """Send a bounded monotonic source-route terminal command.

    A late or missing ACK can follow a completed swap. After sending COMMIT,
    an exception requires quarantine; it never proves the old route survived.
    COMMIT_AFTER_FRAME may be accepted without an ACK while the receiver
    completes its already-pending packet; it never extends either deadline.
    """
    transitions = {
        _RX_OWNER_SOURCE_ROUTE_COMMIT: _RX_OWNER_SOURCE_ROUTE_COMMITTED,
        _RX_OWNER_SOURCE_ROUTE_ABORT: _RX_OWNER_SOURCE_ROUTE_ABORTED,
        _RX_OWNER_SOURCE_ROUTE_COMMIT_AFTER_FRAME:
            _RX_OWNER_SOURCE_ROUTE_COMMITTED_AFTER_FRAME,
    }
    registered_source = _SOURCE_ROUTE_PREPARATIONS.get(id(prepared))
    mutable_source = getattr(prepared, '_source_route_preparation', None)
    if registered_source is not None:
        if (registered_source[0] is not prepared or
                mutable_source is not registered_source[2]):
            raise PermissionError('source C31 typed preparation was deleted or replaced')
        source_base = registered_source[2]
    else:
        if mutable_source is not None:
            raise PermissionError('unregistered source C31 preparation cannot authorize commands')
        source_base = None
    source_preparation = source_base
    if source_base is not None:
        bootstrap = sys.modules.get(type(source_base.context).__module__)
        joins = getattr(source_base.context, '_source_route_park_joins', {})
        source_preparation = joins.get(id(prepared))
        if source_preparation is None:
            raise PermissionError('source C31 command requires the later exact C28 PARK join')
    previous_sequence = (source_preparation.command_sequence
        if source_preparation is not None else prepared.command_sequence)
    if (command_type not in transitions or command_sequence <= previous_sequence):
        raise ValueError('invalid source-route command type or sequence')
    if source_preparation is not None:
        bootstrap = sys.modules.get(type(source_preparation.context).__module__)
        validate_binding = getattr(bootstrap, '_validate_source_route_preparation', None)
        if not callable(validate_binding):
            raise PermissionError('source C31 preparation validator is unavailable')
        validate_binding(source_preparation, prepared, endpoint)
        if (operation_deadline_ns is not None and
                operation_deadline_ns != source_preparation.park.deadline_ns):
            raise TimeoutError('source C31 command must use the shared PARK deadline')
        command_deadline_ns = source_preparation.park.deadline_ns
    else:
        command_deadline_ns = min(time.monotonic_ns() + 5_000_000_000, prepared.fields[22])
        if operation_deadline_ns is not None:
            command_deadline_ns = min(command_deadline_ns, operation_deadline_ns)
    deadline = command_deadline_ns / 1e9
    # Keep a bounded local observation of the last attempt, including unknown
    # outcomes. Callers may record it; it conveys no authority or success.
    operation_id = (source_preparation.operation_id if source_preparation is not None
        else prepared.operation_id)
    source_epoch = (source_preparation.source_epoch if source_preparation is not None
        else prepared.source_epoch)
    observation = dict(command_type=command_type, command_sequence=command_sequence,
        operation_id=operation_id, source_epoch=source_epoch,
        deadline_ns=command_deadline_ns, started_ns=time.monotonic_ns())
    prepared.last_command_observation = observation
    if (time.monotonic() >= deadline or
            nginx_companion._pidfd_pid(prepared.app_pidfd) != prepared.app_pid or
            not nginx_companion.process_alive(prepared.app_pidfd) or
            process_start_ticks(prepared.app_pid) != prepared.app_start):
        raise TimeoutError('source-route command authority expired or C31 exited')
    fields = (list(source_preparation.fields) if source_preparation is not None
        else prepared.fields.copy())
    fields[2] = command_type
    payload = _RX_OWNER_SOURCE_ROUTE_RECORD.pack(*fields,
        operation_id, command_sequence,
        (source_preparation.actors[7] if source_preparation is not None else
            prepared.master_start),
        (source_preparation.actors[6] if source_preparation is not None else
            prepared.master_pid), source_epoch, 0, 0, command_deadline_ns)
    observation['send_started_ns'] = time.monotonic_ns()
    if source_preparation is not None:
        begin_attempt = getattr(bootstrap, '_begin_source_route_attempt', None)
        if not callable(begin_attempt):
            raise PermissionError('canonical C31 source sequence tracker is unavailable')
        begin_attempt(source_preparation, command_sequence)
    if endpoint.send(payload, getattr(socket, 'MSG_NOSIGNAL', 0) |
            getattr(socket, 'MSG_DONTWAIT', 0)) != len(payload):
        raise RuntimeError('short source-route COMMIT/ABORT send')
    observation['sent_ns'] = time.monotonic_ns()
    with selectors.DefaultSelector() as selector:
        selector.register(endpoint, selectors.EVENT_READ)
        if not selector.select(max(0, deadline - time.monotonic())):
            raise TimeoutError('C31 did not acknowledge source-route command')
    packet, ancillary, flags, _ = endpoint.recvmsg(_RX_OWNER_SOURCE_ROUTE_RECORD.size + 1,
        socket.CMSG_SPACE(struct.calcsize('=3i')) + socket.CMSG_SPACE(4 * 4),
        getattr(socket, 'MSG_CMSG_CLOEXEC', 0))
    observation['received_ns'] = time.monotonic_ns()
    credentials = []
    invalid = False
    extra_fds = []
    try:
        for level, kind, value in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(value) == 12:
                credentials.append(struct.unpack('=3i', value))
            elif level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                rights = array.array('i')
                rights.frombytes(value[:len(value) - len(value) % rights.itemsize])
                extra_fds.extend(rights)
                invalid = True
            else:
                invalid = True
        expected = (list(source_preparation.fields) if source_preparation is not None
            else list(prepared.fields))
        expected[2] = transitions[command_type]
        expected.extend((operation_id, command_sequence,
            (source_preparation.actors[7] if source_preparation is not None else
                prepared.master_start),
            (source_preparation.actors[6] if source_preparation is not None else
                prepared.master_pid), source_epoch, 0, 0, command_deadline_ns))
        allowed_flags = getattr(socket, 'MSG_CMSG_CLOEXEC', 0)
        if (invalid or flags & (getattr(socket, 'MSG_TRUNC', 0) |
                getattr(socket, 'MSG_CTRUNC', 0)) or
                (source_preparation is not None and flags & ~allowed_flags) or
                len(packet) != _RX_OWNER_SOURCE_ROUTE_RECORD.size or
                credentials != [((source_preparation.actors[0]
                    if source_preparation is not None else prepared.app_pid),
                    os.getuid(), os.getgid())]):
            raise PermissionError(f'source-route command ACK credentials or shape mismatch: '
                f'invalid={invalid} flags={flags} bytes={len(packet)} credentials={credentials}')
        actual = list(_RX_OWNER_SOURCE_ROUTE_RECORD.unpack(packet))
        status = actual[28]
        observation['status'] = status
        actual[28] = 0
        if tuple(actual) != tuple(expected):
            raise PermissionError('source-route command ACK identity/context mismatch')
        observation['correlated_ns'] = time.monotonic_ns()
        if (time.monotonic() >= deadline or
                not nginx_companion.process_alive(prepared.app_pidfd) or
                process_start_ticks(prepared.app_pid) != prepared.app_start):
            raise TimeoutError('source-route ACK arrived after authority/deadline')
        if source_preparation is not None:
            validate_binding(source_preparation, prepared, endpoint, False)
        observation['validated_ns'] = time.monotonic_ns()
        if observation['validated_ns'] >= command_deadline_ns:
            raise TimeoutError('source-route ACK proof completed after authority/deadline')
        if source_preparation is not None:
            finish_attempt = getattr(bootstrap, '_finish_source_route_attempt', None)
            if not callable(finish_attempt):
                raise PermissionError('canonical C31 source sequence tracker is unavailable')
            finish_attempt(source_preparation, command_sequence,
                command_type == _RX_OWNER_SOURCE_ROUTE_COMMIT and
                status == -errno.EBUSY,
                aborted=command_type == _RX_OWNER_SOURCE_ROUTE_ABORT and status == 0)
        prepared.command_sequence = command_sequence
        prepared.last_command_type = command_type
        prepared.last_status = status
        if command_type == _RX_OWNER_SOURCE_ROUTE_ABORT and status == 0:
            prepared.aborted = True
        committed = command_type in (_RX_OWNER_SOURCE_ROUTE_COMMIT,
            _RX_OWNER_SOURCE_ROUTE_COMMIT_AFTER_FRAME) and status == 0
        if committed:
            prepared.committed = True
        if source_preparation is not None and committed:
            mint = getattr(bootstrap, '_mint_source_route_commit_receipt', None)
            if not callable(mint):
                raise PermissionError('canonical source C31 receipt minter is unavailable')
            prepared._source_route_commit_receipt = mint(source_preparation,
                prepared, command_type, command_sequence, status,
                command_deadline_ns, observation['validated_ns'], bytes(packet),
                _RX_OWNER_SOURCE_ROUTE_RECORD.pack(*expected), credentials[0])
            register_receipt = getattr(bootstrap,
                '_register_source_route_commit_receipt', None)
            if not callable(register_receipt):
                prepared._source_route_commit_receipt = None
                raise PermissionError('canonical source C31 receipt registry is unavailable')
            prepared._source_route_commit_receipt = register_receipt(
                prepared._source_route_commit_receipt)
        return status
    finally:
        for fd in extra_fds:
            os.close(fd)


def wait_startup_marker(fd, data, marker, timeout, description):
    """Read complete startup bytes until marker; preserve all bytes for later checks."""
    deadline = time.monotonic() + timeout
    with selectors.DefaultSelector() as selector:
        selector.register(fd, selectors.EVENT_READ)
        while marker not in data:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                raise RuntimeError(f'{description} startup timed out')
            chunk = os.read(fd, 4096)
            if not chunk:
                raise RuntimeError(f'{description} exited before readiness marker; startup bytes={data!r}')
            data += chunk
    return data


def resolve_runtime_service_app_executable(command, search_path=None):
    """Resolve the exact direct ELF that ker-app will execute.

    execvp searches PATH for a bare command name; Path.resolve alone would
    incorrectly look for that name in the current working directory.
    """
    if not command:
        raise RuntimeError('runtime-service caller command is empty')
    if os.sep in command or (os.altsep is not None and os.altsep in command):
        candidate = command
    else:
        candidate = shutil.which(command, path=search_path)
        if candidate is None:
            raise RuntimeError('runtime-service caller executable was not found on PATH')
    try:
        executable = Path(candidate).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise RuntimeError(f'runtime-service caller executable cannot be resolved: {candidate!r}: {exc}') from exc
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise RuntimeError('runtime-service caller must be an executable file')
    with executable.open('rb') as executable_stream:
        if executable_stream.read(4) != b'\x7fELF':
            raise RuntimeError('runtime-service phase one requires a direct ELF application')
    return executable


def resolve_exit_code(exit_code, app_returncode, infrastructure_failure, preserve_signal):
    if infrastructure_failure and not preserve_signal:
        return 125
    if app_returncode is not None and app_returncode < 0 and preserve_signal:
        return 128 - app_returncode
    return exit_code if exit_code >= 0 else 128 - exit_code


def control_nginx_profile(args, *, private_c34_controller=False):
    fields = tuple(getattr(args, name, None) for name in
        ('control_nginx_binary', 'control_nginx_config', 'control_nginx_prefix'))
    supplied_env = getattr(args, 'control_nginx_env', None) or []
    owner_ready_required = bool(getattr(args, 'control_nginx_owner_ready', False))
    rx_owner_relay = bool(getattr(args, 'control_nginx_rx_relay', False))
    owner_module = getattr(args, 'control_nginx_owner_module', None)
    source_bootstrap_required = bool(getattr(args,
        'control_nginx_source_bootstrap_required', False))
    source_shell_profile = bool(getattr(args,
        'control_nginx_source_shell_profile', False))
    private_c34_profile = (bool(getattr(args,
        'control_nginx_source_private_c34_profile', False)) or
        private_c34_controller is True)
    requested = (any(value is not None for value in fields) or bool(supplied_env) or
        owner_ready_required or owner_module is not None or rx_owner_relay or
        source_bootstrap_required or source_shell_profile or private_c34_profile)
    if not requested:
        return None
    if (not args.broker_readiness or not args.runtime_service or
            (args.rx_decision != rx_owner_relay) or
            (rx_owner_relay and not owner_ready_required) or
            (source_bootstrap_required and
                (not rx_owner_relay or not owner_ready_required)) or
            (source_shell_profile and (not source_bootstrap_required or
                not rx_owner_relay or not owner_ready_required)) or
            (private_c34_profile and not source_shell_profile) or
            any(value is None for value in fields)):
        raise ValueError('Nginx RX relay requires RX-decision, broker-readiness, owner READY and a complete pinned profile')
    allowed = {'LD_PRELOAD', 'KER_SOCKET_BROKER_PATH',
        'KER_FSTACK_NGINX_INI', 'KER_FSTACK_RUNTIME_TRACE'}
    source_flowmap_test = any(
        item.partition('=')[0] == 'KER_NGINX_SOURCE_FLOWMAP_TEST'
        for item in supplied_env)
    source_admission_relay = any(
        item.partition('=')[0] == 'KER_NGINX_SOURCE_ADMISSION_RELAY'
        for item in supplied_env)
    if source_flowmap_test:
        if (not rx_owner_relay or owner_module is None or
                Path(owner_module).name !=
                    'ker-fstack-nginx-owner-activation-alias-test.so'):
            raise ValueError('source flow-map qualification requires the alias RX relay profile')
        allowed.add('KER_NGINX_SOURCE_FLOWMAP_TEST')
    if source_admission_relay:
        slot_values = [item.partition('=')[2] for item in supplied_env
            if item.partition('=')[0] == 'KER_NGINX_CANDIDATE_SLOT_FD']
        transfer_text = os.environ.get('KER_NGINX_CANDIDATE_SLOT_TRANSFER_FD')
        try:
            slot_fd = int(slot_values[0], 10) if len(slot_values) == 1 else -1
            transfer_fd = int(transfer_text, 10) if transfer_text is not None else -2
        except ValueError:
            slot_fd = transfer_fd = -3
        if (not rx_owner_relay or owner_module is None or
                Path(owner_module).name !=
                    'ker-fstack-nginx-owner-activation-alias-test.so' or
                source_flowmap_test or slot_fd < 3 or transfer_fd != slot_fd):
            raise ValueError('source-map admission requires the authenticated C16 candidate capability and RX relay profile')
        if next((item.partition('=')[2] for item in supplied_env
                if item.partition('=')[0] == 'KER_NGINX_SOURCE_ADMISSION_RELAY'), None) != '1':
            raise ValueError('source-map admission requires the explicit profile value 1')
        try:
            os.fstat(transfer_fd)
        except OSError as error:
            raise ValueError('candidate slot transfer endpoint is not an open descriptor') from error
        allowed.update({'KER_NGINX_SOURCE_ADMISSION_RELAY',
            'KER_NGINX_CANDIDATE_SLOT_FD'})
        if any(item.partition('=')[0] ==
                'KER_NGINX_SOURCE_ADMISSION_TEST_DELAY_US' for item in supplied_env):
            if next((item.partition('=')[2] for item in supplied_env
                    if item.partition('=')[0] ==
                        'KER_NGINX_SOURCE_ADMISSION_TEST_DELAY_US'), None) != '350000':
                raise ValueError('source-admission expiry control has an invalid bounded delay')
            allowed.add('KER_NGINX_SOURCE_ADMISSION_TEST_DELAY_US')
        if any(item.partition('=')[0] ==
                'KER_C16_TEST_PUMP_FAIL_AFTER_STEP' for item in supplied_env):
            if next((item.partition('=')[2] for item in supplied_env
                    if item.partition('=')[0] ==
                        'KER_C16_TEST_PUMP_FAIL_AFTER_STEP'), None) != '1':
                raise ValueError('source-admission failure injection has an invalid value')
            allowed.add('KER_C16_TEST_PUMP_FAIL_AFTER_STEP')
    env = {}
    for item in supplied_env:
        key, separator, value = item.partition('=')
        if (not separator or key not in allowed or key in env or not value or
                '\0' in value):
            raise ValueError('invalid/duplicate control-only Nginx environment entry')
        env[key] = value
    if not {'LD_PRELOAD', 'KER_SOCKET_BROKER_PATH',
            'KER_FSTACK_NGINX_INI'} <= env.keys():
        raise ValueError('control-only Nginx requires its F-Stack preload, broker path and INI')
    if source_shell_profile and (
            args.queues != 1 or args.rx_lcores != '1' or not args.rx_decision):
        raise ValueError('source-shell profile requires one native RX queue owned by EAL lcore 1 and RX-decision session identity')
    if 'libker-posix' in env['LD_PRELOAD']:
        raise ValueError('control-only Nginx cannot preload the native Linux runtime')
    preload_names = [Path(item).name for item in env['LD_PRELOAD'].split(':') if item]
    if (not any(name.startswith('libfstack.so') for name in preload_names) or
            not any(name.startswith('libker-socket-preload.so') for name in preload_names) or
            (any('nginx-worker-shim' in name for name in preload_names) and
             not owner_ready_required)):
        raise ValueError('control-only Nginx requires the pinned F-Stack socket preload profile')
    if owner_ready_required:
        shim_names = [name for name in preload_names
            if name == 'libker-fstack-nginx-worker-shim.so']
        if len(shim_names) != 1:
            raise ValueError('owner READY requires exactly one pinned Nginx worker shim')
        if owner_module is None and not private_c34_profile:
            raise ValueError('owner READY requires the C22 owner-activation module')
        if private_c34_profile and owner_module is not None:
            raise ValueError('private C34 built-in addon rejects an external owner module')
        if owner_module is not None:
            module = owner_module.resolve(strict=True)
            if not module.is_file():
                raise ValueError('owner READY activation module is not a regular file')
            import hashlib
            env['KER_NGINX_OWNER_MODULE_PATH'] = str(module)
            env['KER_NGINX_OWNER_MODULE_SHA256'] = hashlib.sha256(
                module.read_bytes()).hexdigest()
    elif getattr(args, 'control_nginx_owner_module', None) is not None:
        raise ValueError('owner activation module requires owner READY mode')
    binary, config, prefix = (value.resolve(strict=True) for value in fields)
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise ValueError('control-only Nginx binary is not an executable file')
    if not config.is_file() or not prefix.is_dir():
        raise ValueError('control-only Nginx config/prefix does not exist')
    return (binary, config, prefix, env, owner_ready_required,
        source_bootstrap_required, source_shell_profile, private_c34_profile)


def _is_private_c34_controller(controller):
    if controller is None:
        return False
    try:
        module = _load_source_shell_controller()
        return type(getattr(controller, 'profile', None)) is \
            module._c34_profile_module().PrivateNewC34InteropProfile
    except (ImportError, OSError, AttributeError):
        return False


def _bind_private_c34_runtime_artifacts(args, controller):
    """Join private CLI paths to the exact held POSIX/IO/app capture tuple."""
    if not _is_private_c34_controller(controller):
        raise PermissionError('private runtime artifact join requires the exact NEWC34 controller')
    controller_module = _load_source_shell_controller()
    if type(controller) is not controller_module.SourceShellController:
        raise PermissionError('private runtime artifact join requires the canonical source controller')
    capture = controller.profile.artifact_capture
    provider = controller_module._c34_profile_module()._provider()
    if type(capture) is not provider.PrivateC34ArtifactCapture:
        raise PermissionError('private runtime artifact join lacks its fixed held capture')
    deadline_ns = controller.profile.deadline_ns
    posix = capture.artifact('posix')
    io_worker = capture.artifact('io_worker')
    ker_app = capture.artifact('ker_app')
    held = (posix, io_worker, ker_app)
    for item in held:
        if (type(item) is not provider._HeldArtifact or
                not item.path.is_absolute() or
                item.path.resolve(strict=True) != item.path):
            raise PermissionError('private runtime capture has a noncanonical held artifact')
        item.verify(deadline_ns)
    explicit = frozenset(getattr(args, '_explicit_cli_overrides', ()))
    replacements = (('library', posix), ('io_worker', io_worker))
    bound_paths = {}
    for dest, item in replacements:
        supplied = getattr(args, dest, None)
        if dest in explicit:
            if not isinstance(supplied, Path) or supplied.resolve(strict=True) != item.path:
                raise PermissionError(f'explicit --{dest.replace("_", "-")} differs from the held private capture')
        bound_paths[dest] = item.path
    adjacent_app = (bound_paths['io_worker'].parent / 'ker-app').resolve(strict=True)
    if adjacent_app != ker_app.path:
        raise PermissionError('captured ker-app is not adjacent to the held private IO worker')
    binding = (capture, posix, io_worker, ker_app)
    previous = getattr(controller, '_private_runtime_artifacts', None)
    if previous is not None and previous != binding:
        raise PermissionError('private runtime artifact binding changed after capture')
    args.library = bound_paths['library']
    args.io_worker = bound_paths['io_worker']
    controller._private_runtime_artifacts = binding
    return binding


def _needs_nginx_companion(controller, control_nginx):
    """Private NEWC34 Origin owns its original Nginx shell directly."""
    return control_nginx is not None and not _is_private_c34_controller(controller)


def _new_private_c34_network_input(args, environ):
    """Render the original 13-key F-Stack input for this private CLI launch."""
    source = dict(environ)
    deadline_text = source.get(source_network_startup.BOOTSTRAP_DEADLINE_ENV)
    env_items = getattr(args, 'control_nginx_env', None) or []
    baseline = any(key == 'KER_FSTACK_NGINX_INI' and Path(value).name == 'fstack_base.ini'
        for key, _, value in (item.partition('=') for item in env_items))
    rv9 = any(key == 'KER_FSTACK_NGINX_INI' and Path(value).name == 'fstack_rv9.ini'
        for key, _, value in (item.partition('=') for item in env_items))
    # Cover startup, the unchanged probe, and the original cleanup window.
    budget_ns = (1_750_000_000_000 if rv9 else
        410_000_000_000 if baseline else 280_000_000_000)
    deadline = (int(deadline_text) if type(deadline_text) is str and
        deadline_text.isascii() and deadline_text.isdecimal() else
        time.monotonic_ns() + budget_ns)
    broker_values = [item.partition('=')[2] for item in env_items
        if item.partition('=')[0] == 'KER_SOCKET_BROKER_PATH']
    if len(broker_values) != 1:
        raise ValueError('private C34 needs one captured broker path to render source input')
    broker = broker_values[0]
    address = getattr(args, 'address', None)
    gateway = getattr(args, 'gateway', None)
    if not isinstance(address, ipaddress.IPv4Interface) or not isinstance(gateway, ipaddress.IPv4Address):
        raise ValueError('private C34 source input requires parsed IPv4 address and gateway')
    temporary = tempfile.TemporaryDirectory(prefix='ker-newc34-input-', dir='/dev/shm')
    captured = None
    try:
        root = Path(temporary.name)
        os.chmod(root, 0o700)
        path = root / 'fstack_rt01.ini'
        network = address.network
        run_id = 'kerC34_' + secrets.token_hex(8)
        text = (f'[ker_socket_broker]\nversion=1\npath={broker}\n'
            f'[dpdk]\ngraceful_reload=1\nlcore_mask=0x3\nprimary_slim=1\n'
            f'file_prefix={run_id}\nfstack_log_file_prefix={root}/fstack-\nfstack_log_level=0\n'
            f'[port0]\nlcore_list=1\naddr={address.ip}\nnetmask={network.netmask}\n'
            f'broadcast={network.broadcast_address}\ngateway={gateway}\n').encode('ascii')
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        try:
            with os.fdopen(fd, 'wb', closefd=False) as stream:
                stream.write(text)
                stream.flush()
                os.fsync(fd)
        finally:
            os.close(fd)
        origin = _load_source_origin_module()
        captured = (origin.capture_source_network_expectation(str(path), deadline, repeated=True)
            if rv9 else origin.capture_source_network_expectation(str(path), deadline))
        source[source_network_startup.PROFILE_ENV] = '1'
        source[source_network_startup.BOOTSTRAP_DEADLINE_ENV] = str(deadline)
        supplied_record = source.get(source_network_startup.READBACK_ENV)
        actual_record = captured.readback_setting()
        if supplied_record is not None and supplied_record != actual_record:
            raise ValueError('caller source readback differs from the rendered private input')
        source[source_network_startup.READBACK_ENV] = actual_record
        return source, temporary, captured
    except BaseException:
        if captured is not None:
            captured.template_file.close()
        temporary.cleanup()
        raise


def _capture_private_c34_source_controller(args, expected, control_profile,
        network_capture=None, network_temp=None, *, test_capture=None):
    """Capture the fixed NEWC34 tuple after bridging the native dict record."""
    if (expected is None or type(expected) is not dict or control_profile is None or
            len(control_profile) != 8 or control_profile[7] is not True or
            control_profile[6] is not True):
        raise ValueError('NEWC34_INTEROP selection requires its exact source-shell SDK profile')
    deadline = expected.get('deadline_ns')
    if type(deadline) is not int:
        raise ValueError('private C34 selector requires the parsed native deadline')
    command = getattr(args, 'command', None)
    if type(command) is not list or len(command) != 2 or any(type(v) is not str for v in command):
        raise ValueError('private C34 selector requires exactly [fixed backend, broker path]')
    broker_path = control_profile[3].get('KER_SOCKET_BROKER_PATH')
    if (type(broker_path) is not str or command[1] != broker_path or
            not Path(broker_path).is_absolute() or
            str(Path(broker_path).resolve(strict=False)) != broker_path or
            Path(broker_path).name in ('', '.', '..')):
        raise ValueError('private C34 selector requires the captured canonical broker run path')
    broker_parent = Path(broker_path).parent
    parent_info = os.stat(broker_parent, follow_symlinks=False)
    if (not broker_parent.is_dir() or parent_info.st_uid != os.geteuid() or
            stat.S_IMODE(parent_info.st_mode) != 0o700 or Path(broker_path).exists()):
        raise ValueError('private C34 broker path must be a fresh child of an owned 0700 run directory')
    if getattr(args, 'control_nginx_owner_module', None) is not None:
        raise ValueError('private C34 built-in addon rejects an external owner module')
    controller_module = _load_source_shell_controller()
    profile_module = controller_module._c34_profile_module()
    artifact_module = profile_module._provider()
    origin_module = _load_source_origin_module()
    if test_capture is not None and (os.getpid() != 1 or
            type(test_capture) is not artifact_module.PrivateC34ArtifactCapture or
            not test_capture.is_test_fixture):
        raise PermissionError('private C34 requires a captured repository test fixture')
    expected_nginx = (artifact_module._FIXED_ARTIFACTS['nginx'][0] if test_capture is None
        else test_capture.artifact('nginx').path)
    if Path(control_profile[0]).resolve(strict=False) != expected_nginx:
        raise ValueError('private C34 selector rejects a conflicting Nginx executable')
    output_ini = control_profile[3].get('KER_FSTACK_NGINX_INI')
    if type(output_ini) is not str or not output_ini:
        raise ValueError('private C34 selector requires the exact generated INI path')
    ini_path = Path(output_ini)
    case = origin_module.SOURCE_HUP_INI_CASES.get(ini_path.name)
    if case is None:
        raise ValueError('private C34 selector requires the INI of a supported HUP case')
    selected_fault = origin_module.SOURCE_HUP_FAULTS.get(case)
    captured_fault = artifact_module._SOURCE_FAULT if test_capture is None else test_capture.source_fault
    if selected_fault != captured_fault:
        raise ValueError('private C34 selector requires the matching pinned fault build')
    capture = None
    profile = None
    scope_temp = None
    try:
        # This is a per-run original F-Stack input rendered from the parsed
        # caller address, gateway, and broker path; generated output INI stays absent.
        if network_capture is None:
            _, network_temp, network_capture = _new_private_c34_network_input(
                args, os.environ)
        if (source_network_startup._captured_expectation_key(network_capture) !=
                source_network_startup._expected_key(expected)):
            raise ValueError('rendered original-case input differs from the parsed source network record')

        capture = (artifact_module.PrivateC34ArtifactCapture.capture(deadline)
            if test_capture is None else test_capture)
        nginx = capture.artifact('nginx')
        fixed_backend = capture.artifact('test_backend')
        if Path(command[0]).resolve(strict=True) != fixed_backend.path:
            raise ValueError('private C34 selector requires the fixed TEST_ONLY backend as args.command[0]')
        source_root = capture.source_root.resolve(strict=True)
        manifest = capture.artifact('build_manifest')
        manifest_path = manifest.path.resolve(strict=True)
        if test_capture is None and (manifest_path != artifact_module._BUILD_MANIFEST or
                manifest.sha256 != artifact_module._BUILD_MANIFEST_SHA256):
            raise ValueError('private C34 held build manifest differs from its frozen pin')
        output = ini_path.parent
        if (not output.is_absolute() or str(output.resolve(strict=False)) != str(output) or
                output.name in ('', '.', '..') or output.exists()):
            raise ValueError('private C34 selector requires a fresh canonical output path')
        scope_temp = tempfile.TemporaryDirectory(prefix='ker-newc34-origin-', dir='/dev/shm')
        scope = Path(scope_temp.name)
        os.chmod(scope, 0o700)
        environment = {key: control_profile[3][key] for key in
            ('KER_SOCKET_BROKER_PATH', 'KER_FSTACK_NGINX_INI',
                'KER_FSTACK_RUNTIME_TRACE') if key in control_profile[3]}
        environment.update({
            'KER_NGINX_SOURCE_SHELL_ENABLE': '1',
            'KER_NGINX_SOURCE_FIRST_HUP_ENABLE': '1',
            'KER_NGINX_SOURCE_BOOTSTRAP_NONCE': secrets.token_hex(16),
            'KER_NGINX_SOURCE_BOOTSTRAP_EPOCH': '1',
            source_network_startup.BOOTSTRAP_DEADLINE_ENV: str(deadline),
            'KER_NGINX_SOURCE_BOOTSTRAP_SUPERVISOR_PID': str(os.getpid()),
            'KER_NGINX_SOURCE_BOOTSTRAP_SUPERVISOR_START': str(process_start_ticks(os.getpid())),
            source_network_startup.READBACK_ENV: network_capture.readback_setting(),
        })
        if 'PATH' not in environment:
            environment['PATH'] = os.environ.get('PATH', os.defpath)
        arguments = ['--cases', f'precheck,{case}', '--workers', '1', '--graceful', '1',
            '--target-ip', network_capture.address, '--out', str(output), '--fstack-conf',
            network_capture.template_path, '--nginx', str(nginx.path), '--build-manifest',
            str(manifest_path)]
        if case == 'baseline':
            arguments.extend(('--baseline-duration', origin_module.SOURCE_BASELINE_SECONDS))
        if case == 'rv9':
            arguments.extend(('--rounds', '100', '--interval', '15'))
            environment['KER_NGINX_SOURCE_SUCCESSOR_ENABLE'] = '1'
        if case == 'rt25':
            environment[origin_module.SOURCE_UPGRADE_ENV] = '1'
        if case == 'rt12':
            filters = (args.exception_mode, args.exception_policy,
                args.exception_tcp_ports, args.exception_udp_ports, args.exception_iface)
            if filters != ('ports', 'reject', '80,443', '53', 'kerkni'):
                raise ValueError('source rt12 requires the original KNI port policy and private TAP')
            management = ipaddress.IPv4Address(int(ipaddress.IPv4Address(network_capture.address)) + 1)
            arguments.extend(('--kernel-nic-ip', str(management)))
            environment[origin_module.SOURCE_KNI_ENV] = '1'
        if selected_fault is not None:
            arguments.extend(('--fault', selected_fault))
            if case == 'rt20b':
                arguments.extend(('--fault-delay-ms', origin_module.SOURCE_READY_DELAY_MS))
            environment[origin_module.SOURCE_FAULT_SWITCHES[selected_fault]] = '1'
        profile = profile_module.PrivateNewC34InteropProfile.capture(
            origin_module, source_network_startup, source_root=source_root,
            arguments=arguments, environment=environment,
            network_expectation=network_capture, scope_directory=scope,
            stdout=None, stderr=None, port_name=args.port,
            artifact_capture=capture)
        network_capture = None
        capture = None
        controller = controller_module.SourceShellController(profile)
        profile = None
        controller._source_route_preparer = rx_owner_source_route_prepare
        controller._private_c34_scope_temp = scope_temp
        scope_temp = None
        controller._private_c34_network_temp = network_temp
        network_temp = None
        return controller
    finally:
        if profile is not None:
            profile.close()
        if capture is not None:
            capture.close()
        if network_capture is not None:
            network_capture.template_file.close()
        if scope_temp is not None:
            scope_temp.cleanup()
        if network_temp is not None:
            network_temp.cleanup()



def _close_private_c34_source_controller(controller):
    """Close only the captured private profile owned by this no-actor path."""
    if controller is None:
        return
    try:
        controller_module = _load_source_shell_controller()
        private_type = controller_module._c34_profile_module().PrivateNewC34InteropProfile
    except (ImportError, OSError, AttributeError):
        return
    if type(getattr(controller, 'profile', None)) is not private_type:
        return
    try:
        controller.profile.close()
    finally:
        scope_temp = getattr(controller, '_private_c34_scope_temp', None)
        if scope_temp is not None:
            scope_temp.cleanup()
        network_temp = getattr(controller, '_private_c34_network_temp', None)
        if network_temp is not None:
            network_temp.cleanup()


def _select_source_shell_controller(args, existing, expected, control_profile,
        network_capture=None, network_temp=None):
    """Resolve the exact private literal selector without weakening the old path."""
    if not bool(getattr(args, 'control_nginx_source_private_c34_profile', False)):
        return existing
    if existing is not None:
        raise ValueError('private C34 selector conflicts with an injected source controller')
    return _capture_private_c34_source_controller(args, expected, control_profile,
        network_capture, network_temp)


# CMake substitutes the relative library path for the installed launcher.
LIB_FROM_BIN = '@KER_POSIX_LIB_FROM_BIN@'
if LIB_FROM_BIN.startswith('@'):
    LIB_FROM_BIN = '../lib64'


TCP_ECN = {'off': 0, 'passive': 2, 'on': 1}


def vip_addresses(text):
    return [ipaddress.IPv4Interface(item.strip()) for item in text.split(',')] if text.strip() else []


def vip_addresses6(text):
    return [ipaddress.IPv6Interface(item.strip()) for item in text.split(',')] if text.strip() else []


def vlan_setting(text):
    tag, separator, addresses = text.partition('=')
    if not separator or not tag.isascii() or not tag.isdecimal() or not 1 <= int(tag) <= 4094:
        raise ValueError('VLAN requires ID=IP/PREFIX[,IP/PREFIX...] with ID 1..4094')
    values = [ipaddress.ip_interface(item.strip()) for item in addresses.split(',')] if addresses.strip() else []
    if not 1 <= len(values) <= 8:
        raise ValueError('VLAN requires 1..8 IPv4/IPv6 addresses')
    if any(value.ip.is_unspecified or value.ip.is_multicast for value in values):
        raise ValueError('VLAN addresses must be unicast and nonzero')
    if any(value.version == 6 and ('%' in str(value) or value.ip.is_loopback or
            value.ip.ipv4_mapped is not None) for value in values):
        raise ValueError('VLAN IPv6 addresses must be unscoped native unicast addresses')
    if len({value.ip for value in values}) != len(values):
        raise ValueError('duplicate VLAN address')
    return int(tag), values


def vlan_gateway(text):
    tag, separator, address = text.partition('=')
    if not separator or not tag.isascii() or not tag.isdecimal() or not 1 <= int(tag) <= 4094:
        raise ValueError('VLAN gateway requires ID=IPv4 with ID 1..4094')
    gateway = ipaddress.IPv4Address(address)
    if gateway.is_unspecified or gateway.is_multicast or gateway.is_loopback or int(gateway) == 0xffffffff:
        raise ValueError('VLAN gateway requires a nonzero unicast IPv4 address')
    return int(tag), gateway


def vlan_gateway6(text):
    tag, separator, address = text.partition('=')
    if not separator or not tag.isascii() or not tag.isdecimal() or not 1 <= int(tag) <= 4094:
        raise ValueError('VLAN gateway requires ID=IPv6 with ID 1..4094')
    gateway = ipaddress.IPv6Address(address)
    if ('%' in address or gateway.is_unspecified or gateway.is_multicast or
            gateway.is_loopback or gateway.ipv4_mapped is not None):
        raise ValueError('VLAN gateway requires an unscoped native unicast IPv6 address')
    return int(tag), gateway


def sysctl_setting(text):
    key, separator, value = text.partition('=')
    key, value = key.strip(), value.strip()
    if not separator or len(key) > 128 or not re.fullmatch(r'net(?:\.[A-Za-z0-9_-]+){2,}', key):
        raise ValueError('sysctl requires a dotted Linux net.* key and =VALUE')
    if not value or len(value.encode('utf-8')) > 256 or any(c in value for c in '\r\n\0'):
        raise ValueError('sysctl value must be 1..256 UTF-8 bytes without line breaks or NUL')
    return key, value


def ephemeral_ports(text):
    if not re.fullmatch(r'[0-9]{1,5}-[0-9]{1,5}', text):
        raise ValueError('ephemeral ports require FIRST-LAST in 1024..65535')
    first, last = map(int, text.split('-'))
    if not 1024 <= first <= last <= 65535:
        raise ValueError('ephemeral ports require 1024 <= FIRST <= LAST <= 65535')
    return first, last


def base_virtaddr(text):
    # Leave room for DPDK's upward 16 MiB alignment in its uint64 parser.
    if not re.fullmatch(r'0[xX][0-9a-fA-F]+', text):
        raise ValueError('base virtual address must be hexadecimal with a 0x prefix')
    value = int(text, 16)
    if not 1 <= value <= (1 << 64) - (1 << 24):
        raise ValueError('base virtual address must be positive and leave room for 16 MiB alignment in uint64')
    return value


TX_OFFLOADS = {'off': 0, 'checksum': 1, 'tso': 2}


def exception_ports(value):
    if value is None:
        return None
    if len(value) > 4096:
        raise ValueError('exception port list exceeds 4096 characters')
    if not value.strip():
        return ''
    result = []
    for item in value.split(','):
        item = item.strip()
        if not re.fullmatch(r'[0-9]+(?:-[0-9]+)?', item):
            raise ValueError('exception ports require decimal numbers or inclusive ranges')
        bounds = [int(part) for part in item.split('-')]
        if any(port > 65535 for port in bounds) or (len(bounds) == 2 and bounds[0] > bounds[1]):
            raise ValueError('exception port range must be ascending within 0..65535')
        result.append('-'.join(map(str, bounds)))
    return ','.join(result)


CONFIG_DEFAULTS = dict(rx_lcores=None, exception_mode='ethertype', exception_policy='accept', exception_tcp_ports=None, exception_udp_ports=None, exception_iface=None, exception_type=0, exception_queue=256, exception_rate=0, exception_console_rate=0, exception_general_rate=0, tx_offloads='off', rss=False, queues=1, interfaces=(), nb_bond=0, bonds=(), nb_vdev=0, vdevs=(), base_virtaddr=None, file_prefix=None, eal_log_level=None, memory_mb=None, no_huge=None, tx_delay_us=0, numa=True, memory_channels=None, idle_sleep_us=1000, promiscuous=None, vlan_gateways=(), vlan_gateways6=(), ephemeral_ports=None, vlans=(), mbuf_mode='large', sysctls=(), gateway6=None, address6=None, vip_addresses6=(), vip_addresses=(), lcore_mask=None, tcp_ecn=None, mtu=1500, max_mtu=9000, mtu_enable=True, address=None, gateway=None, port=None, eal=None,
    all_multicast=False, log_dir=None, log_level=None, pcap_dir=None,
    pcap_snaplen=65535, pcap_max_bytes=16 * 1024 * 1024, pcap_nsec=False,
    shutdown_timeout_ms=5000, stats=None, command=[])


class _LastOccurrenceDict(dict):
    """Preserve the final source position of repeated ConfigParser options."""

    def __setitem__(self, key, value):
        # ConfigParser stores parsed option values as lists, then joins them to
        # strings in _join_multiline_values. Move only during source parsing so
        # final-value order changes without mutating the mapping while joining.
        if isinstance(value, list) and key in self:
            del self[key]
        super().__setitem__(key, value)


CONFIG_SCHEMA = {
    'network': {'vip_addresses6': ('vip_addresses6', vip_addresses6), 'ephemeral_ports': ('ephemeral_ports', ephemeral_ports), 'gateway6': ('gateway6', ipaddress.IPv6Address), 'address6': ('address6', ipaddress.IPv6Interface), 'vip_addresses': ('vip_addresses', vip_addresses), 'tcp_ecn': ('tcp_ecn', str),
                'mtu': ('mtu', int), 'max_mtu': ('max_mtu', int), 'address': ('address', ipaddress.IPv4Interface),
                'gateway': ('gateway', ipaddress.IPv4Address)},
    'dpdk': {'mtu_enable': ('mtu_enable', bool), 'rx_lcores': ('rx_lcores', str), 'exception_mode': ('exception_mode', str), 'exception_policy': ('exception_policy', str), 'exception_tcp_ports': ('exception_tcp_ports', str), 'exception_udp_ports': ('exception_udp_ports', str), 'exception_iface': ('exception_iface', str), 'exception_type': ('exception_type', int), 'exception_queue': ('exception_queue', int), 'exception_rate': ('exception_rate', int), 'exception_console_rate': ('exception_console_rate', int), 'exception_general_rate': ('exception_general_rate', int), 'tx_offloads': ('tx_offloads', str), 'rss': ('rss', bool), 'queues': ('queues', int), 'nb_bond': ('nb_bond', int), 'nb_vdev': ('nb_vdev', int), 'base_virtaddr': ('base_virtaddr', base_virtaddr), 'file_prefix': ('file_prefix', str), 'log_level': ('eal_log_level', int), 'memory': ('memory_mb', int), 'no_huge': ('no_huge', bool), 'pkt_tx_delay': ('tx_delay_us', int), 'numa_on': ('numa', bool), 'channel': ('memory_channels', int), 'mbuf_mode': ('mbuf_mode', str), 'lcore_mask': ('lcore_mask', str), 'port': ('port', str), 'eal': ('eal', str),
             'idle_sleep': ('idle_sleep_us', int), 'all_multicast': ('all_multicast', bool), 'promiscuous': ('promiscuous', bool)},
    'logging': {'directory': ('log_dir', Path), 'level': ('log_level', int)},
    'capture': {'directory': ('pcap_dir', Path), 'snaplen': ('pcap_snaplen', int),
                'max_bytes': ('pcap_max_bytes', int), 'nsec': ('pcap_nsec', bool)},
    'runtime': {'shutdown_timeout_ms': ('shutdown_timeout_ms', int), 'stats': ('stats', Path)},
}


def virtual_devices(ini, directory):
    """Map F-Stack's indexed virtio-user sections to original DPDK options."""
    count = ini.getint('dpdk', 'nb_vdev', fallback=0)
    if not 0 <= count <= 16:
        raise ValueError('[dpdk] nb_vdev must be in 0..16')
    sections = [name for name in ini.sections() if name.startswith('vdev')]
    if sections and not count:
        raise ValueError('vdev sections require [dpdk] nb_vdev first')
    if set(sections) != {f'vdev{i}' for i in range(count)}:
        raise ValueError('vdev sections must exactly match indices 0..nb_vdev-1')
    devices = []
    allowed = {'iface', 'path', 'queues', 'queue_size', 'mac', 'cq'}
    for index in range(count):
        section = 'vdev' + str(index)
        entries = dict(ini.items(section, raw=True))
        if set(entries) - allowed or not entries.get('path'):
            raise ValueError(f'[{section}] requires path and only supports iface/path/queues/queue_size/mac/cq')
        device = {'name': 'net_virtio_user' + str(index)}
        for key, default in (('queues', 1), ('queue_size', 256), ('cq', 0)):
            device[key] = int(entries.get(key, default))
        if not 1 <= device['queues'] <= 128 or device['cq'] not in (0, 1):
            raise ValueError(f'[{section}] queues must be in 1..128 and cq must be 0 or 1')
        size = device['queue_size']
        if not 64 <= size <= 32768 or size & (size - 1):
            raise ValueError(f'[{section}] queue_size must be a power of two in 64..32768')
        if device['queues'] > 1 and not device['cq']:
            raise ValueError(f'[{section}] multiple queue pairs require cq=1')
        for key in ('iface', 'path', 'mac'):
            if key not in entries:
                continue
            value = entries[key]
            if not value or any(character in value for character in ',\x00\r\n'):
                raise ValueError(f'[{section}] invalid {key}')
            if key == 'iface' and not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', value):
                raise ValueError(f'[{section}] iface must be a Linux interface name of at most 15 characters')
            if key == 'mac':
                if not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', value):
                    raise ValueError(f'[{section}] invalid MAC address')
                octets = bytes.fromhex(value.replace(':', ''))
                if octets[0] & 1 or not any(octets):
                    raise ValueError(f'[{section}] MAC must be nonzero unicast')
                value = value.lower()
            if key == 'path':
                path = Path(value)
                value = str(path if path.is_absolute() else directory / path)
                if len(os.fsencode(value)) >= 4096:
                    raise ValueError(f'[{section}] path exceeds PATH_MAX')
            device[key] = value
        devices.append(device)
    return tuple(devices)


def virtual_device_argument(device):
    return '--vdev=' + device['name'] + ''.join(
        ',' + key + '=' + str(device[key]) for key in
        ('iface', 'path', 'queues', 'queue_size', 'mac', 'cq') if key in device)


def query_dpdk_max_numa_nodes(worker_path):
    worker_path = Path(worker_path).resolve(strict=True)
    try:
        result = subprocess.run([str(worker_path), '--dpdk-limits'], check=False,
            capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError(f'cannot query selected DPDK worker limits: {error}') from error
    if result.returncode != 0:
        raise ValueError('selected DPDK worker does not provide a successful --dpdk-limits query')
    try:
        limits = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ValueError('selected DPDK worker returned invalid --dpdk-limits JSON') from error
    if (not isinstance(limits, dict) or set(limits) != {'max_numa_nodes'} or
            type(limits['max_numa_nodes']) is not int or limits['max_numa_nodes'] <= 0):
        raise ValueError('selected DPDK worker returned an invalid positive max_numa_nodes limit')
    return limits['max_numa_nodes']


def validate_selected_bond_limits(args):
    """Query the selected worker once and validate configured bond sockets."""
    if not args.bonds:
        return
    max_numa_nodes = query_dpdk_max_numa_nodes(args.io_worker)
    for bond in args.bonds:
        if not -1 <= bond['socket_id'] < max_numa_nodes:
            raise ValueError(f'[bond0] socket_id must be -1 or in 0..{max_numa_nodes - 1}')


def validate_bond_member_name(member):
    # Pinned DPDK RTE_DEV_NAME_MAX_LEN is 64 bytes including the final NUL.
    if (not isinstance(member, str) or len(member) > 63 or
            not re.fullmatch(r'[A-Za-z0-9_.:-]{1,63}', member)):
        raise ValueError('[bond0] invalid member name/port (expected 1..63 ASCII characters)')
    return member


def bond_devices(ini, max_numa_nodes=None):
    count = ini.getint('dpdk', 'nb_bond', fallback=0)
    if count not in (0, 1):
        raise ValueError('[dpdk] nb_bond supports 0 or 1 selected bond')
    sections = [name for name in ini.sections() if name.startswith('bond')]
    if sections and not count:
        raise ValueError('bond sections require [dpdk] nb_bond first')
    if set(sections) != ({'bond0'} if count else set()):
        raise ValueError('bond section must be [bond0] for nb_bond=1')
    if not count:
        return ()
    fields = dict(ini.items('bond0', raw=True))
    allowed = {'mode', 'slave', 'primary', 'socket_id', 'mac', 'xmit_policy',
               'lsc_poll_period_ms', 'up_delay', 'down_delay'}
    if set(fields) - allowed or not {'mode', 'slave'} <= set(fields):
        raise ValueError('[bond0] requires mode/slave and only supports known bond options')
    bond = {'name': 'net_bonding0', 'mode': int(fields['mode']),
            'slave': fields['slave'].split(','), 'socket_id': int(fields.get('socket_id', 0)),
            'xmit_policy': fields.get('xmit_policy', 'l2')}
    if bond['mode'] not in range(7):
        raise ValueError('[bond0] invalid mode')
    if bond['socket_id'] < -1:
        raise ValueError('[bond0] socket_id must be -1 or nonnegative')
    if max_numa_nodes is not None and bond['socket_id'] >= max_numa_nodes:
        raise ValueError(f'[bond0] socket_id must be -1 or in 0..{max_numa_nodes - 1}')
    if not 1 <= len(bond['slave']) <= 16 or len(set(bond['slave'])) != len(bond['slave']):
        raise ValueError('[bond0] requires 1..16 distinct members')
    bond['slave'] = [validate_bond_member_name(member) for member in bond['slave']]
    if bond['name'] in bond['slave']:
        raise ValueError('[bond0] cannot contain itself')
    if 'primary' in fields:
        if fields['primary'] not in bond['slave']:
            raise ValueError('[bond0] primary must name a listed member')
        bond['primary'] = fields['primary']
    if bond['xmit_policy'] not in ('l2', 'l23', 'l34'):
        raise ValueError('[bond0] invalid xmit_policy')
    if 'mac' in fields:
        mac = fields['mac']
        if not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', mac):
            raise ValueError('[bond0] invalid MAC')
        octets = bytes.fromhex(mac.replace(':', ''))
        if octets[0] & 1 or not any(octets):
            raise ValueError('[bond0] MAC must be nonzero unicast')
        bond['mac'] = mac.lower()
    for key, default in (('lsc_poll_period_ms', 100), ('up_delay', 0), ('down_delay', 0)):
        value = int(fields.get(key, default))
        if not (1 if key == 'lsc_poll_period_ms' else 0) <= value <= 2147483647:
            raise ValueError('[bond0] invalid timing: ' + key)
        bond[key] = value
    return (bond,)


def bond_device_argument(bond):
    members = [validate_bond_member_name(member) for member in bond['slave']]
    return ('--vdev=' + bond['name'] + ',mode=' + str(bond['mode']) +
            ''.join(',member=' + member for member in members) +
            ''.join(',' + key + '=' + str(bond[key]) for key in
                    ('primary', 'socket_id', 'mac', 'xmit_policy') if key in bond))


def rx_lcore_list(value, queues):
    if value is None:
        return None
    parts = [part.strip() for part in value.split(',')]
    if not parts or len(parts) > queues or any(not re.fullmatch(r'[0-9]{1,4}', part) for part in parts):
        raise ValueError('RX lcores require decimal IDs, at most one selected core per active queue')
    cores = [int(part) for part in parts]
    if len(set(cores)) != len(cores):
        raise ValueError('RX lcores must be unique')
    return ','.join(str(core) for core in cores)


def reject_secondary_eal(tokens):
    """Reject an explicit unsupported secondary before any worker executes.

    The original EAL still validates unknown/auto modes. Tokens after its first
    separator belong to the driver/application suffix and are not mode options.
    """
    for index, token in enumerate(tokens):
        if token == '--':
            break
        mode = (token.split('=', 1)[1] if token.startswith('--proc-type=') else
                tokens[index + 1] if token == '--proc-type' and index + 1 < len(tokens) else None)
        if mode == 'secondary':
            raise ValueError('secondary EAL processes are unsupported; each Ker worker must own a primary device')


def additional_interfaces(ini):
    result = []
    convert = {'address': ipaddress.IPv4Interface, 'address6': ipaddress.IPv6Interface,
               'vip_addresses': vip_addresses, 'vip_addresses6': vip_addresses6,
               'rx_lcores': str, 'port': str, 'eal': str, 'tx_offloads': str, 'queues': int, 'rss': bool, 'mtu': int, 'max_mtu': int, 'mbuf_mode': str}
    for section in ini.sections():
        if not section.startswith('interface.'):
            continue
        name = section[10:]
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,32}', name):
            raise ValueError('invalid interface section name')
        fields = dict(ini.items(section, raw=True))
        if set(fields) - set(convert) or not {'address', 'port', 'eal'} <= set(fields):
            raise ValueError(f'[{section}] requires address/port/eal and only supported interface options')
        item = {'name': name}
        for key, value in fields.items():
            item[key] = ini.getboolean(section, key, raw=True) if key == 'rss' else convert[key](value)
        eal_tokens = shlex.split(item['eal'])
        if not item['port'] or not eal_tokens:
            raise ValueError(f'[{section}] empty port/eal')
        reject_secondary_eal(eal_tokens)
        result.append(item)
    if len(result) > 7:
        raise ValueError('at most seven additional native interfaces are supported')
    return result


def read_configuration(stream, directory, source='<stream>', worker_path=None,
                       eal_override=None, defer_worker_limits=False):
    # Match F-Stack's repeated-key precedence: convert only the final value.
    # A repeated section continues the same section; unknown names remain errors.
    ini = configparser.ConfigParser(interpolation=None, inline_comment_prefixes=(';',),
        empty_lines_in_values=False, strict=False, dict_type=_LastOccurrenceDict)
    ini.optionxform = str
    ini.read_string(stream.read().removeprefix('\ufeff'), source=str(source))
    if ini.defaults():
        raise ValueError('DEFAULT inheritance is unsupported')
    # Reject unsupported main EAL mode only after applying the CLI-over-INI
    # precedence, and before querying any worker capability. The suffix after
    # EAL's `--` remains application-owned and is deliberately ignored here.
    main_eal = eal_override if eal_override is not None else ini.get(
        'dpdk', 'eal', fallback=None)
    if main_eal is not None:
        try:
            main_eal_tokens = shlex.split(main_eal)
        except ValueError as error:
            raise ValueError(f'--eal: {error}') from error
        reject_secondary_eal(main_eal_tokens)
    devices = virtual_devices(ini, directory)
    values = {'vdevs': devices} if devices or ini.has_option('dpdk', 'nb_vdev') else {}
    bonds = bond_devices(ini)
    interfaces = additional_interfaces(ini)
    if interfaces:
        values['interfaces'] = interfaces
    if bonds or ini.has_option('dpdk', 'nb_bond'):
        values['bonds'] = bonds
    for section in ini.sections():
        if section.startswith(('vdev', 'bond', 'interface.')):
            continue
        if section.startswith('vlan.'):
            if 'addresses' not in ini[section] or set(ini[section]) - {'addresses', 'gateway', 'gateway6'}:
                raise ValueError('VLAN section requires addresses and optional gateway/gateway6')
            if 'gateway' in ini[section]:
                values.setdefault('vlan_gateways', []).append(vlan_gateway(section[5:] + '=' + ini[section]['gateway']))
            if 'gateway6' in ini[section]:
                values.setdefault('vlan_gateways6', []).append(vlan_gateway6(section[5:] + '=' + ini[section]['gateway6']))
            values.setdefault('vlans', []).append(vlan_setting(section[5:] + '=' + ini[section]['addresses']))
            continue
        if section == 'sysctl':
            values['sysctls'] = [sysctl_setting(name + '=' + text)
                                 for name, text in ini.items(section, raw=True)]
            continue
        if section not in CONFIG_SCHEMA:
            raise ValueError(f'unknown section [{section}]')
        for name, text in ini.items(section, raw=True):
            if name not in CONFIG_SCHEMA[section]:
                raise ValueError(f'unknown option [{section}] {name}')
            field, convert = CONFIG_SCHEMA[section][name]
            try:
                value = ini.getboolean(section, name) if convert is bool else convert(text)
            except ValueError as error:
                raise ValueError(f'[{section}] {name}: {error}') from error
            if convert is Path and not value.is_absolute():
                value = directory / value
            values[field] = value
    if bonds and not defer_worker_limits:
        if worker_path is None:
            raise ValueError('cannot validate [bond0] socket_id without the selected DPDK worker')
        # Standalone reader callers request selected-build bounds here. The
        # CLI defers this query until its final semantic checks have passed.
        bonds = bond_devices(ini, query_dpdk_max_numa_nodes(worker_path))
        values['bonds'] = bonds
    return values


def load_configuration(path, worker_path=None, eal_override=None, defer_worker_limits=False):
    path = path.resolve()
    with path.open(encoding='utf-8') as stream:
        return read_configuration(stream, path.parent, path, worker_path,
                                  eal_override, defer_worker_limits)


class _ExplicitPathArgument(argparse.Action):
    """Keep legacy path defaults while recording whether CLI supplied a path."""
    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, values)
        explicit = set(getattr(namespace, '_explicit_cli_overrides', ()))
        explicit.add(self.dest)
        setattr(namespace, '_explicit_cli_overrides', frozenset(explicit))


def parse_arguments(argv=None, *, defer_worker_limits=False):
    parser = argparse.ArgumentParser(description=__doc__, argument_default=argparse.SUPPRESS)
    parser.add_argument('--exception-mode', choices=('ethertype', 'ports'))
    parser.add_argument('--exception-policy', choices=('accept', 'reject'))
    parser.add_argument('--exception-tcp-ports', help='destination ports/ranges for unfragmented IP service steering')
    parser.add_argument('--exception-udp-ports', help='destination ports/ranges for unfragmented IP service steering')
    parser.add_argument('--exception-iface', help='new exclusive host TAP for EtherType or destination-port selection')
    parser.add_argument('--exception-type', type=int, help='outer EtherType in decimal, 1536..65535')
    parser.add_argument('--exception-queue', type=int)
    parser.add_argument('--exception-console-rate', type=int, help='control admission attempts per second; zero disables')
    parser.add_argument('--exception-general-rate', type=int, help='ordinary admission attempts per second; zero disables')
    parser.add_argument('--exception-rate', type=int, help='host-bound batch gate per second; zero disables')
    parser.add_argument('--config', type=Path, default=None, help='Ker INI configuration; explicit CLI options take precedence')
    parser.add_argument('--address', type=ipaddress.IPv4Interface)
    parser.add_argument('--address6', type=ipaddress.IPv6Interface,
        help='additional native IPv6 address/prefix; enables multicast reception for neighbor discovery')
    parser.add_argument('--vip-address', dest='vip_addresses', action='append', type=ipaddress.IPv4Interface,
        help='additional IPv4 address/prefix; repeat up to 32 times; replaces INI vip_addresses')
    parser.add_argument('--vip-address6', dest='vip_addresses6', action='append', type=ipaddress.IPv6Interface,
        help='additional IPv6 address/prefix; requires --address6; repeat up to 32 times; replaces INI vip_addresses6')
    parser.add_argument('--vlan', dest='vlans', action='append', type=vlan_setting,
        help='802.1Q ID=IP/PREFIX[,IP/PREFIX...]; repeat up to 16 VLANs; replaces INI VLAN sections')
    parser.add_argument('--vlan-gateway', dest='vlan_gateways', action='append', type=vlan_gateway,
        help='ID=IPv4 default gateway on a configured VLAN; replaces INI VLAN IPv4 gateways; one default allowed')
    parser.add_argument('--vlan-gateway6', dest='vlan_gateways6', action='append', type=vlan_gateway6,
        help='ID=IPv6 default gateway on a configured VLAN; replaces INI VLAN gateways; one default allowed')
    parser.add_argument('--tx-offloads', choices=tuple(TX_OFFLOADS), help='negotiate original PMD TX checksum/TSO metadata (default off)')
    parser.add_argument('--rss', action=argparse.BooleanOptionalAction, help='require original PMD RSS key and round-robin RETA readback; requires at least two queues')
    parser.add_argument('--queues', type=int, help='active DPDK RX/TX pairs, 1..16; all RX queues polled, application TX uses queue 0')
    parser.add_argument('--mbuf-mode', choices=('large', 'scatter'), help='DPDK packet storage; scatter uses chained standard-size mbufs')
    parser.add_argument('--mtu', type=int, help='native and DPDK interface MTU, 1280..9000 (default 1500)')
    parser.add_argument('--mtu-enable', action=argparse.BooleanOptionalAction,
        help='allow MTU above 1500; disabling caps startup/live MTU on every interface (default enabled)')
    parser.add_argument('--max-mtu', type=int, help='startup/live MTU ceiling and large-buffer capacity, 1280..9000 (default 9000)')
    parser.add_argument('--tcp-ecn', choices=tuple(TCP_ECN),
        help='off, passive acceptance, or active/passive ECN; default preserves Linux policy')
    parser.add_argument('--sysctl', dest='sysctls', action='append', type=sysctl_setting,
        help='Linux net.* KEY=VALUE; repeat up to 32 keys; overrides matching INI [sysctl] keys')
    parser.add_argument('--gateway6', type=ipaddress.IPv6Address,
        help='native IPv6 default gateway on this interface; requires --address6')
    parser.add_argument('--ephemeral-ports', type=ephemeral_ports, metavar='FIRST-LAST',
        help='native Linux automatic local port range for TCP/UDP and IPv4/IPv6')
    parser.add_argument('--gateway', type=ipaddress.IPv4Address)
    parser.add_argument('--numa', action=argparse.BooleanOptionalAction,
        help='use worker lcore NUMA socket for pool/queues (default); --no-numa uses socket 0')
    parser.add_argument('--base-virtaddr', type=base_virtaddr, help='hexadecimal EAL virtual-address hint (0x...); DPDK rounds up to 16 MiB and may choose another address')
    parser.add_argument('--file-prefix', help='EAL runtime namespace: 1..64 ASCII letters/digits/dot/underscore/hyphen, starting with a letter or digit')
    parser.add_argument('--eal-log-level', type=int, choices=range(1, 9),
        help='EAL startup global log level, 1..8; dpdk.log_level; later --log-level still overrides after initialization')
    parser.add_argument('--memory-mb', type=int, help='initial EAL memory in MiB, 1..2147483647; actual allocation remains subject to host capacity')
    huge_policy = parser.add_mutually_exclusive_group()
    huge_policy.add_argument('--no-huge', action='store_true', help='use regular pages for DPDK EAL memory')
    huge_policy.add_argument('--hugepages', dest='no_huge', action='store_false', help='require EAL hugepage mode; needs configured host hugepages')
    parser.add_argument('--memory-channels', type=int,
        help='DPDK memory channels per socket, 1..2147483647; omitted preserves EAL policy; conflicts with EAL -n/--memory-channels')
    parser.add_argument('--rx-lcores', help='comma-separated enabled EAL lcore IDs for this port; queues assigned round robin')
    parser.add_argument('--lcore-mask', help='nonzero hexadecimal DPDK lcore mask; conflicts with EAL -c/-l/--lcores')
    parser.add_argument('--port', help='DPDK ethdev name')
    parser.add_argument('--tx-delay-us', type=int, help='Ethernet TX batch wait, 0..100 microseconds; default 0 sends without intentional delay')
    parser.add_argument('--idle-sleep-us', type=int,
        help='worker idle wait in microseconds, 0..100000 (default 1000; 0 polls without sleeping)')
    parser.add_argument('--promiscuous', action=argparse.BooleanOptionalAction,
        help='enable or disable PMD promiscuous reception; omitted preserves the PMD state')
    parser.add_argument('--all-multicast', action=argparse.BooleanOptionalAction,
        help='receive all Ethernet multicast frames for native Linux membership filtering')
    parser.add_argument('--log-dir', type=Path, help='existing directory for append-only DPDK worker logs')
    parser.add_argument('--log-level', type=int, choices=range(1, 9), help='DPDK global and ker.io level (1=emergency, 8=debug); overrides EAL level after startup')
    parser.add_argument('--pcap-dir', type=Path, help='existing private capture directory; rotates ten files per direction')
    parser.add_argument('--pcap-snaplen', type=int)
    parser.add_argument('--pcap-max-bytes', type=int)
    parser.add_argument('--pcap-nsec', action=argparse.BooleanOptionalAction, help='write nanosecond PCAP timestamps')
    parser.add_argument('--eal', help='DPDK EAL arguments, parsed without a shell')
    parser.add_argument('--library', type=Path, action=_ExplicitPathArgument,
        default=Path(__file__).resolve().parent / LIB_FROM_BIN / 'libker-posix.so')
    parser.add_argument('--io-worker', type=Path, action=_ExplicitPathArgument,
        default=Path(__file__).resolve().parent / 'ker-io-worker')
    parser.add_argument('--shutdown-timeout-ms', type=int)
    parser.add_argument('--stats', type=Path, help='write Ethernet I/O counters at shutdown')
    parser.add_argument('--rx-decision', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--runtime-service', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--broker-readiness', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--control-nginx-binary', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--control-nginx-config', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--control-nginx-prefix', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--control-nginx-env', action='append', help=argparse.SUPPRESS)
    parser.add_argument('--control-nginx-owner-ready', action='store_true',
        help=argparse.SUPPRESS)
    parser.add_argument('--control-nginx-source-bootstrap-required', action='store_true',
        help=argparse.SUPPRESS)
    parser.add_argument('--control-nginx-source-shell-profile', action='store_true',
        help=argparse.SUPPRESS)
    parser.add_argument('--control-nginx-source-private-c34-profile', action='store_true',
        help=argparse.SUPPRESS)
    parser.add_argument('--control-nginx-rx-relay', action='store_true',
        help=argparse.SUPPRESS)
    parser.add_argument('--control-nginx-owner-module', type=Path,
        help=argparse.SUPPRESS)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    supplied = parser.parse_args(argv)
    values = dict(CONFIG_DEFAULTS)
    if supplied.config is not None:
        try:
            values.update(load_configuration(supplied.config, supplied.io_worker,
                                             getattr(supplied, 'eal', None),
                                             defer_worker_limits=True))
        except MemoryError:
            parser.error(f'{supplied.config}: configuration allocation failed')
        except (OSError, UnicodeError, configparser.Error, ValueError) as error:
            parser.error(f'{supplied.config}: {error}')
    sysctls = dict(values['sysctls'])
    for key, value in getattr(supplied, 'sysctls', ()):
        sysctls.pop(key, None)
        sysctls[key] = value
    values.update(vars(supplied))
    values.setdefault('rx_decision', False)
    values.setdefault('runtime_service', False)
    values.setdefault('broker_readiness', False)
    values['sysctls'] = sysctls
    args = argparse.Namespace(**values)
    missing = [name for name in ('address', 'port', 'eal') if getattr(args, name) is None]
    if missing:
        parser.error('required via CLI or --config: ' + ', '.join('--' + name for name in missing))
    if args.command[:1] == ['--']:
        args.command.pop(0)
    if not args.command:
        parser.error('an application command is required after --')
    if args.ephemeral_ports is not None:
        key = 'net.ipv4.ip_local_port_range'
        if key in args.sysctls:
            parser.error('--ephemeral-ports conflicts with sysctl ' + key)
        unprivileged_port_key = 'net.ipv4.ip_unprivileged_port_start'
        if unprivileged_port_key in args.sysctls:
            parser.error('--ephemeral-ports conflicts with sysctl ' + unprivileged_port_key +
                '; use generic sysctl settings for explicit kernel ordering')
        args.sysctls[key] = ' '.join(map(str, args.ephemeral_ports))
    if len(args.sysctls) > 32:
        parser.error('--sysctl supports at most 32 distinct keys')
    if args.tcp_ecn is not None and 'net.ipv4.tcp_ecn' in args.sysctls:
        parser.error('--tcp-ecn conflicts with sysctl net.ipv4.tcp_ecn')
    if args.address6 is not None and ('%' in str(args.address6) or
            args.address6.ip.is_unspecified or args.address6.ip.is_multicast or
            args.address6.ip.is_loopback or args.address6.ip.ipv4_mapped is not None):
        parser.error('--address6 requires an unscoped native unicast IPv6 interface address')
    args.vip_addresses6 = list(args.vip_addresses6)
    if args.vip_addresses6 and args.address6 is None:
        parser.error('--vip-address6 requires --address6')
    if len(args.vip_addresses6) > 32:
        parser.error('--vip-address6 supports at most 32 additional addresses')
    for value in args.vip_addresses6:
        if ('%' in str(value) or value.ip.is_unspecified or value.ip.is_multicast or
                value.ip.is_loopback or value.ip.ipv4_mapped is not None):
            parser.error('--vip-address6 requires unscoped native unicast IPv6 interface addresses')
    addresses6 = ([args.address6.ip] if args.address6 is not None else []) + [value.ip for value in args.vip_addresses6]
    if len(set(addresses6)) != len(addresses6):
        parser.error('--vip-address6 must not duplicate the primary or another VIP address')
    if args.gateway6 is not None and (args.address6 is None or '%' in str(args.gateway6) or
            args.gateway6.is_unspecified or args.gateway6.is_multicast or args.gateway6.is_loopback or
            args.gateway6.ipv4_mapped is not None):
        parser.error('--gateway6 requires --address6 and an unscoped unicast IPv6 gateway')
    args.vip_addresses = list(args.vip_addresses)
    if len(args.vip_addresses) > 32:
        parser.error('--vip-address supports at most 32 additional addresses')
    addresses = [args.address.ip] + [value.ip for value in args.vip_addresses]
    if len(set(addresses)) != len(addresses):
        parser.error('--vip-address must not duplicate the primary or another VIP address')
    if len(args.vlans) > 16 or len({tag for tag, _ in args.vlans}) != len(args.vlans):
        parser.error('--vlan requires at most 16 unique VLAN IDs')
    vlan_ips = [value.ip for _, entries in args.vlans for value in entries]
    all_ips = addresses + addresses6 + vlan_ips
    if len(set(all_ips)) != len(all_ips):
        parser.error('--vlan addresses must not duplicate primary, VIP, or other VLAN addresses')
    if len(args.vlan_gateways) > 1 or (args.vlan_gateways and args.gateway is not None):
        parser.error('only one IPv4 default gateway is supported across parent and VLAN interfaces')
    for tag, gateway in args.vlan_gateways:
        entries = [value for value in dict(args.vlans).get(tag, []) if value.version == 4]
        if not entries:
            parser.error('--vlan-gateway requires IPv4 addresses on the selected VLAN')
        if gateway in all_ips:
            parser.error('--vlan-gateway must not equal a local address')
        if any(value.network.prefixlen < 31 and gateway == value.network.broadcast_address for value in entries):
            parser.error('--vlan-gateway must not be a VLAN subnet broadcast address')
    if len(args.vlan_gateways6) > 1 or (args.vlan_gateways6 and args.gateway6 is not None):
        parser.error('only one IPv6 default gateway is supported across parent and VLAN interfaces')
    for tag, gateway in args.vlan_gateways6:
        entries = dict(args.vlans).get(tag, [])
        if not any(value.version == 6 for value in entries):
            parser.error('--vlan-gateway6 requires IPv6 addresses on the selected VLAN')
        if gateway in all_ips:
            parser.error('--vlan-gateway6 must not equal a local address')
    if args.exception_mode not in ('ethertype', 'ports') or args.exception_policy not in ('accept', 'reject'):
        parser.error('invalid exception mode or accept/reject policy')
    try:
        args.exception_tcp_ports = exception_ports(args.exception_tcp_ports)
        args.exception_udp_ports = exception_ports(args.exception_udp_ports)
    except ValueError as error:
        parser.error(str(error))
    if args.exception_mode == 'ports':
        if args.exception_type or args.exception_iface is None:
            parser.error('port mode requires an exception interface and no exception-type')
    elif args.exception_tcp_ports is not None or args.exception_udp_ports is not None or args.exception_policy != 'accept':
        parser.error('port lists and accept/reject policy require exception-mode=ports')
    if args.exception_iface is not None:
        if args.exception_iface in ('.', '..') or not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', args.exception_iface):
            parser.error('--exception-iface must be a Linux interface name of at most 15 characters')
        if args.exception_mode == 'ethertype' and not 1536 <= args.exception_type <= 65535:
            parser.error('--exception-type must be in 1536..65535 with --exception-iface')
        if not 4 <= args.exception_queue <= 65536 or args.exception_queue & (args.exception_queue - 1):
            parser.error('--exception-queue must be a power of two in 4..65536')
        for field in ('exception_rate', 'exception_console_rate', 'exception_general_rate'):
            if not 0 <= getattr(args, field) <= 2147483647:
                parser.error('--' + field.replace('_', '-') + ' must be in 0..2147483647')
    elif args.exception_type or args.exception_rate or args.exception_console_rate or args.exception_general_rate or args.exception_queue != 256:
        parser.error('exception options require --exception-iface')
    if not 0 <= args.idle_sleep_us <= 100000:
        parser.error('--idle-sleep-us must be in 0..100000 microseconds')
    if args.tx_offloads not in TX_OFFLOADS:
        parser.error('--tx-offloads must be off, checksum or tso')
    if args.rss and args.queues < 2:
        parser.error('--rss requires at least two queues')
    if not 1 <= args.queues <= 16:
        parser.error('--queues must be in 1..16')
    if args.mbuf_mode not in ('large', 'scatter'):
        parser.error('--mbuf-mode must be large or scatter')
    if not 1280 <= args.mtu <= 9000:
        parser.error('--mtu must be in 1280..9000')
    if not 1280 <= args.max_mtu <= 9000:
        parser.error('--max-mtu must be in 1280..9000')
    if not args.mtu_enable:
        args.max_mtu = min(args.max_mtu, 1500)
    if args.mtu > args.max_mtu:
        parser.error('--mtu must not exceed --max-mtu')
    if args.tcp_ecn is not None and args.tcp_ecn not in TCP_ECN:
        parser.error('--tcp-ecn must be off, passive or on')
    if not 0 <= args.shutdown_timeout_ms <= 60000:
        parser.error("--shutdown-timeout-ms must be in 0..60000")
    if not 1 <= args.pcap_snaplen <= 2147483647 or not 1 <= args.pcap_max_bytes <= 2147483647:
        parser.error('PCAP snaplen and max-bytes must be in 1..2147483647')
    if args.log_level is not None and not 1 <= args.log_level <= 8:
        parser.error('--log-level must be in 1..8')
    try:
        args.eal_args = shlex.split(args.eal)
    except ValueError as error:
        parser.error(f'--eal: {error}')
    try:
        separator = args.eal_args.index('--')
    except ValueError:
        eal_prefix, eal_remainder = list(args.eal_args), []
    else:
        eal_prefix, eal_remainder = args.eal_args[:separator], args.eal_args[separator:]
    raw_eal_options = list(eal_prefix)
    try:
        reject_secondary_eal(raw_eal_options)
    except ValueError as error:
        parser.error(str(error))
    if not 0 <= args.tx_delay_us <= 100:
        parser.error('--tx-delay-us must be in 0..100')
    if args.base_virtaddr is not None:
        if any(token.split('=', 1)[0] == '--base-virtaddr' for token in raw_eal_options):
            parser.error('--base-virtaddr conflicts with EAL --base-virtaddr')
        eal_prefix += ['--base-virtaddr=' + hex(args.base_virtaddr)]
    if args.file_prefix is not None:
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', args.file_prefix):
            parser.error('--file-prefix must be 1..64 ASCII letters/digits/dot/underscore/hyphen, starting with a letter or digit')
        if any(token.split('=', 1)[0] == '--file-prefix' for token in raw_eal_options):
            parser.error('--file-prefix conflicts with EAL --file-prefix')
        eal_prefix += ['--file-prefix=' + args.file_prefix]
    if args.eal_log_level is not None:
        if not 1 <= args.eal_log_level <= 8:
            parser.error('--eal-log-level must be in 1..8')
        raw_global_log_level = False
        index = 0
        while index < len(raw_eal_options):
            token = raw_eal_options[index]
            if token.startswith('--log-level='):
                value = token.split('=', 1)[1]
            elif token == '--log-level':
                value = raw_eal_options[index + 1] if index + 1 < len(raw_eal_options) else ''
                index += 1
            else:
                index += 1
                continue
            if ':' not in value and ',' not in value:
                raw_global_log_level = True
                break
            index += 1
        if raw_global_log_level:
            parser.error('--eal-log-level conflicts with EAL --log-level')
        eal_prefix += ['--log-level=' + str(args.eal_log_level)]
    if args.memory_mb is not None:
        if not 1 <= args.memory_mb <= 2147483647:
            parser.error('--memory-mb must be in 1..2147483647')
        if any(token.startswith('-m') or token.split('=', 1)[0] in
                ('--memory-size', '--numa-mem', '--socket-mem') for token in raw_eal_options):
            parser.error('--memory-mb conflicts with EAL -m/--memory-size/--numa-mem/--socket-mem')
        eal_prefix += ['-m', str(args.memory_mb)]
    if args.no_huge is not None:
        if any(token.split('=', 1)[0] == '--no-huge' for token in raw_eal_options):
            parser.error('typed hugepage policy conflicts with EAL --no-huge')
        if args.no_huge:
            if any(token.split('=', 1)[0] == '--in-memory' for token in raw_eal_options):
                parser.error('--no-huge conflicts with EAL --in-memory')
            eal_prefix.append('--no-huge')
    if args.memory_channels is not None:
        if not 1 <= args.memory_channels <= 2147483647:
            parser.error('--memory-channels must be in 1..2147483647')
        if any(token == '--memory-channels' or token.startswith(('--memory-channels=', '-n'))
                for token in raw_eal_options):
            parser.error('--memory-channels conflicts with EAL -n or --memory-channels')
        if any(token.split('=', 1)[0] in ('--no-shconf', '--in-memory') for token in raw_eal_options):
            parser.error('--memory-channels requires EAL shared configuration; --no-shconf/--in-memory skip channel initialization')
        eal_prefix += ['-n', str(args.memory_channels)]
    try:
        args.rx_lcores = rx_lcore_list(args.rx_lcores, args.queues)
    except ValueError as error:
        parser.error(str(error))
    if args.lcore_mask is not None:
        mask = args.lcore_mask.strip()
        if not re.fullmatch(r'(?:0[xX])?[0-9a-fA-F]+', mask) or int(mask, 16) == 0:
            parser.error('--lcore-mask must be a nonzero hexadecimal mask')
        # Keep one source of EAL CPU selection. Do not silently override or
        # remove caller-provided CPU mapping, especially --lcores remapping.
        if any(token in ('--lcores', '-c', '-l') or token.startswith(('--lcores=', '-c', '-l'))
                for token in raw_eal_options):
            parser.error('--lcore-mask conflicts with EAL -c, -l or --lcores')
        args.lcore_mask = format(int(mask, 16), 'x')
        eal_prefix += ['-c', args.lcore_mask]
    if args.vdevs:
        if any(token == '--vdev' or token.startswith('--vdev=') for token in raw_eal_options):
            parser.error('typed [vdevN] configuration conflicts with EAL --vdev')
        if not args.bonds and args.port not in {device['name'] for device in args.vdevs}:
            parser.error('--port must select a configured typed net_virtio_userN device')
        eal_prefix += [virtual_device_argument(device) for device in args.vdevs]
    if args.bonds:
        if args.port != args.bonds[0]['name']:
            parser.error('--port must select the configured net_bonding0')
        raw_devices = []
        for index, token in enumerate(raw_eal_options):
            if token.startswith('--vdev='):
                raw_devices.append(token.split('=', 1)[1].split(',', 1)[0])
            elif token == '--vdev' and index + 1 < len(raw_eal_options):
                raw_devices.append(raw_eal_options[index + 1].split(',', 1)[0])
        if any(name.startswith(('net_bonding', 'eth_bond')) for name in raw_devices):
            parser.error('typed bond conflicts with raw EAL bonding device')
        eal_prefix += [bond_device_argument(bond) for bond in args.bonds]
    args.eal_args = eal_prefix + eal_remainder
    seen = set(all_ips)
    networks = [value.network for value in (args.address, *args.vip_addresses)]
    networks6 = ([value.network for value in (args.address6, *args.vip_addresses6)]
                 if args.address6 is not None else [])
    for tag, entries in args.vlans:
        vlan_networks = [value.network for value in entries if value.version == 4]
        if any(network.overlaps(previous) for network in vlan_networks for previous in networks):
            parser.error('IPv4 networks must not overlap across interfaces')
        networks.extend(vlan_networks)
        vlan_networks6 = [value.network for value in entries if value.version == 6]
        if any(network.overlaps(previous) for network in vlan_networks6 for previous in networks6):
            parser.error('IPv6 networks must not overlap across interfaces')
        networks6.extend(vlan_networks6)
    for interface in args.interfaces:
        for key in ('mtu', 'max_mtu', 'mbuf_mode', 'queues', 'rss', 'tx_offloads'):
            interface.setdefault(key, getattr(args, key))
        # Validate the configured ceiling before deriving the global policy cap.
        if not 1280 <= interface['max_mtu'] <= 9000:
            parser.error('additional interface max_mtu must be in 1280..9000')
        if not args.mtu_enable:
            interface['max_mtu'] = min(interface['max_mtu'], 1500)
        if not 1280 <= interface['mtu'] <= interface['max_mtu'] <= 9000:
            parser.error('additional interface MTU must satisfy 1280 <= mtu <= max_mtu <= 9000')
        if interface['tx_offloads'] not in TX_OFFLOADS:
            parser.error('additional interface tx_offloads must be off, checksum or tso')
        if interface['rss'] and interface['queues'] < 2:
            parser.error('additional interface RSS requires at least two queues')
        if not 1 <= interface['queues'] <= 16:
            parser.error('additional interface queues must be in 1..16')
        if interface['mbuf_mode'] not in ('large', 'scatter'):
            parser.error('additional interface mbuf_mode must be large or scatter')
        try:
            interface['rx_lcores'] = rx_lcore_list(interface.get('rx_lcores'), interface['queues'])
        except ValueError as error:
            parser.error(str(error))
        interface.setdefault('address6', None)
        interface.setdefault('vip_addresses', ())
        interface.setdefault('vip_addresses6', ())
        if len(interface['vip_addresses']) > 32 or len(interface['vip_addresses6']) > 32:
            parser.error('each additional interface supports at most 32 IPv4/IPv6 VIPs')
        if interface['vip_addresses6'] and interface['address6'] is None:
            parser.error('additional IPv6 VIP requires its interface address6')
        addresses = [interface['address'], *interface['vip_addresses']]
        if interface['address6'] is not None:
            addresses += [interface['address6'], *interface['vip_addresses6']]
        for value in addresses:
            if '%' in str(value) or value.ip.is_unspecified or value.ip.is_multicast or value.ip.is_loopback or (
                    value.version == 6 and value.ip.ipv4_mapped is not None):
                parser.error('additional interfaces require unscoped native unicast addresses')
            if (value.version == 4 and value.network.prefixlen < 31 and
                    value.ip == value.network.broadcast_address):
                parser.error('additional IPv4 addresses must not be subnet broadcast addresses')
            if value.ip in seen:
                parser.error('additional interface address duplicates an existing address')
            seen.add(value.ip)
        interface_networks = [value.network for value in (interface['address'], *interface['vip_addresses'])]
        if any(network.overlaps(previous) for network in interface_networks for previous in networks):
            parser.error('IPv4 networks must not overlap across interfaces')
        networks.extend(interface_networks)
        if interface['address6'] is not None:
            interface_networks6 = [value.network for value in
                                    (interface['address6'], *interface['vip_addresses6'])]
            if any(network.overlaps(previous) for network in interface_networks6 for previous in networks6):
                parser.error('IPv6 networks must not overlap across interfaces')
            networks6.extend(interface_networks6)
    if args.rx_decision and args.interfaces:
        parser.error('--rx-decision currently supports only the primary I/O worker')
    if args.runtime_service and args.interfaces:
        parser.error('--runtime-service currently supports only the primary I/O worker')
    # The CLI must finish all pure validation, including CLI overrides and
    # auxiliary address/queue/MTU ownership, before executing the worker query.
    # Standalone reader callers retain their selected-build validation above.
    if args.bonds and not defer_worker_limits:
        try:
            validate_selected_bond_limits(args)
        except MemoryError:
            parser.error('configuration allocation failed')
        except (OSError, ValueError) as error:
            parser.error(str(error))
    return args


def worker_done_record(line):
    value = json.loads(line.removeprefix('KER_IO_DONE '))
    if (not isinstance(value, dict) or type(value.get('outstanding')) is not int or
            value['outstanding'] < 0):
        raise RuntimeError('invalid DPDK DONE outstanding-object count')
    return value


def _private_c31_json_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('private C31 shutdown JSON has duplicate keys')
        value[key] = item
    return value


def private_c31_shutdown_record(startup_status, io_stats, *, worker_identity,
                                supervisor_identity, nonce, epoch):
    """Decode and join the private C31 SETTLED receipt with held actors/IO_DONE."""
    if (type(startup_status) is not bytes or type(io_stats) is not dict or
            type(worker_identity) is not tuple or len(worker_identity) != 4 or
            type(supervisor_identity) is not tuple or len(supervisor_identity) != 4 or
            type(nonce) is not bytes or len(nonce) != 16 or
            type(epoch) is not int or epoch <= 0):
        raise ValueError('private C31 shutdown inputs are malformed')
    lines = startup_status.splitlines()
    prefix = b'KER_C31_SHUTDOWN '
    records = [(index, line[len(prefix):]) for index, line in enumerate(lines)
        if line.startswith(prefix)]
    required = (b'KER_NATIVE_READY', b'KER_NATIVE_STOPPING', b'KER_NATIVE_DONE')
    positions = {}
    for marker in required:
        matches = [index for index, line in enumerate(lines) if line == marker]
        if len(matches) != 1:
            raise ValueError('private C31 shutdown requires one ordered native lifecycle')
        positions[marker] = matches[0]
    if not positions[required[0]] < positions[required[1]] < positions[required[2]]:
        raise ValueError('private C31 shutdown native lifecycle order is invalid')
    if (len(records) != 1 or not positions[required[1]] < records[0][0] < positions[required[2]]):
        raise ValueError('private C31 shutdown receipt is missing, duplicate, or out of order')
    try:
        value = json.loads(records[0][1], object_pairs_hook=_private_c31_json_object)
    except json.JSONDecodeError as error:
        raise ValueError('private C31 shutdown JSON is malformed') from error
    except UnicodeError as error:
        raise ValueError('private C31 shutdown JSON is malformed') from error
    fields = {'record_hex', 'worker_pid', 'worker_uid', 'worker_gid',
        'worker_start_ticks', 'supervisor_pid', 'supervisor_uid', 'supervisor_gid',
        'supervisor_start_ticks', 'nonce', 'epoch', 'last_packet_id',
        'last_result_id', 'outstanding_count', 'status'}
    if type(value) is not dict or set(value) != fields:
        raise ValueError('private C31 shutdown JSON fields are invalid')
    integer_fields = fields - {'record_hex', 'nonce'}
    if any(type(value.get(key)) is not int or value[key] < 0
            for key in integer_fields):
        raise ValueError('private C31 shutdown numeric fields are invalid')
    raw_hex = value['record_hex']
    if type(raw_hex) is not str or not re.fullmatch(r'[0-9a-f]{160}', raw_hex):
        raise ValueError('private C31 shutdown wire receipt is malformed')
    if value['nonce'] != nonce.hex():
        raise ValueError('private C31 shutdown nonce differs from the run')
    raw = bytes.fromhex(raw_hex)
    header = struct.unpack('<IHHII16sQQQQ', raw[:64])
    body = struct.unpack('<QII', raw[64:])
    if header != (0x4b525844, 2, 7, 64, 80, nonce, epoch, 0, 3, 0):
        raise ValueError('private C31 shutdown wire header differs from the run')
    packet_id, outstanding, reserved = body
    settled_id = io_stats.get('rx_decision_last_settled_packet_id')
    io_outstanding = io_stats.get('outstanding')
    if (type(settled_id) is not int or settled_id < 0 or
            type(io_outstanding) is not int or io_outstanding < 0 or
            reserved or outstanding or value['status'] or value['outstanding_count'] or
            packet_id != value['last_packet_id'] or
            value['last_packet_id'] != value['last_result_id'] or
            value['epoch'] != epoch or value['last_packet_id'] !=
                settled_id or
            io_stats.get('rx_decision_enabled') is not True or
            io_stats.get('rx_decision_settled') is not True or
            io_stats.get('control_eof') is not True or
            io_outstanding != 0):
        raise ValueError('private C31 shutdown IDs or IO_DONE state do not join')
    expected_worker = ('worker_pid', 'worker_uid', 'worker_gid', 'worker_start_ticks')
    expected_supervisor = ('supervisor_pid', 'supervisor_uid', 'supervisor_gid',
        'supervisor_start_ticks')
    if tuple(value[name] for name in expected_worker) != worker_identity:
        raise ValueError('private C31 worker identity differs from the held IO actor')
    if tuple(value[name] for name in expected_supervisor) != supervisor_identity:
        raise ValueError('private C31 supervisor identity differs from the held supervisor')
    return value


def _private_io_done_record(raw_output):
    if (type(raw_output) is not bytes or len(raw_output) > 1024 * 1024 or
            not raw_output.endswith(b'\n')):
        raise ValueError('private I/O stdout is missing or exceeds its bound')
    records = [line[len(b'KER_IO_DONE '):] for line in raw_output.splitlines()
        if line.startswith(b'KER_IO_DONE ')]
    if len(records) != 1:
        raise ValueError('private I/O stdout must contain exactly one DONE record')
    lines = raw_output.splitlines()
    done_lines = [index for index, line in enumerate(lines)
        if line.startswith(b'KER_IO_DONE ')]
    if done_lines != [len(lines) - 1]:
        raise ValueError('private I/O DONE must be the final stdout record')
    value = json.loads(records[0], object_pairs_hook=_private_c31_json_object)
    if type(value) is not dict:
        raise ValueError('private I/O DONE JSON is not an object')
    for key in ('outstanding', 'rx_decision_last_settled_packet_id'):
        if type(value.get(key)) is not int or value[key] < 0:
            raise ValueError('private I/O DONE counter is not a nonnegative integer')
    if (value.get('rx_decision_enabled') is not True or
            value.get('rx_decision_settled') is not True or
            value.get('control_eof') is not True or value['outstanding'] != 0):
        raise ValueError('private I/O DONE lacks settled control EOF')
    return value


class _PrivateShutdownCollectionReceipt:
    __slots__ = ('controller', 'context', 'stop_receipt', 'startup_status',
        'io_stdout', 'startup_identity', 'io_stdout_identity', 'worker_identity',
        'io_executable_hash', 'app_identity', 'app_anchor',
        'backend_receipt', 'io_ready_proof',
        'supervisor_identity', 'parsed', 'collected_ns', '_sealed')

    def __init__(self, token, *, controller, context, stop_receipt, startup_status,
            io_stdout, startup_identity, io_stdout_identity, worker_identity,
            io_executable_hash, app_identity, app_anchor,
            backend_receipt, io_ready_proof,
            supervisor_identity, parsed, collected_ns):
        if token is not _PRIVATE_SHUTDOWN_COLLECTION_TOKEN:
            raise TypeError('private shutdown collection receipts are not caller-constructible')
        object.__setattr__(self, '_sealed', False)
        for name, value in locals().copy().items():
            if name in self.__slots__ and name != '_sealed':
                object.__setattr__(self, name, value)
        frozen = {name: _freeze_private_value(value) for name, value in parsed.items()}
        object.__setattr__(self, 'parsed', MappingProxyType(frozen))
        object.__setattr__(self, '_sealed', True)

    def __setattr__(self, name, value):
        if getattr(self, '_sealed', False):
            raise AttributeError('private shutdown collection receipt is immutable')
        object.__setattr__(self, name, value)


_PRIVATE_SHUTDOWN_COLLECTION_TOKEN = object()
_PRIVATE_RUNTIME_APP_ANCHOR_TOKEN = object()


class _PrivateRuntimeAppAnchor:
    __slots__ = ('controller', 'process', 'pidfd', 'identity', 'run_channel',
                 'run_channel_identity', '_sealed')

    def __init__(self, token, controller, process, pidfd, identity, run_channel):
        if token is not _PRIVATE_RUNTIME_APP_ANCHOR_TOKEN:
            raise TypeError('private runtime app anchors are not caller-constructible')
        object.__setattr__(self, 'controller', controller)
        object.__setattr__(self, 'process', process)
        object.__setattr__(self, 'pidfd', pidfd)
        object.__setattr__(self, 'identity', identity)
        object.__setattr__(self, 'run_channel', run_channel)
        object.__setattr__(self, 'run_channel_identity',
            _private_run_channel_identity(run_channel) if run_channel is not None else None)
        object.__setattr__(self, '_sealed', True)

    def __setattr__(self, name, value):
        if getattr(self, '_sealed', False):
            raise AttributeError('private runtime app anchor is immutable')
        object.__setattr__(self, name, value)


def _private_run_channel_identity(channel):
    if (type(channel) is not socket.socket or channel.family != socket.AF_UNIX or
            channel.gettimeout() != 0.0 or
            channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_SEQPACKET):
        raise PermissionError('private run control requires its nonblocking Unix seqpacket')
    info = os.fstat(channel.fileno())
    return channel.fileno(), info.st_dev, info.st_ino


def _bind_private_runtime_app(controller, process, pidfd, start_ticks, *, run_channel=None):
    module = sys.modules.get(type(controller).__module__)
    profile_module = sys.modules.get(type(getattr(controller, 'profile', None)).__module__)
    identity = (process.pid, os.getuid(), os.getgid(), start_ticks)
    if (type(controller) is not getattr(module, 'SourceShellController', None) or
            type(getattr(controller, 'profile', None)) is not
                getattr(profile_module, 'PrivateNewC34InteropProfile', None) or
            process.poll() is not None or pidfd < 0 or
            process_start_ticks(process.pid) != start_ticks or
            getattr(controller, '_private_runtime_app_anchor', None) is not None):
        raise PermissionError('private runtime app Popen does not match its retained C34 actor identity')
    anchor = _PrivateRuntimeAppAnchor(_PRIVATE_RUNTIME_APP_ANCHOR_TOKEN,
        controller, process, pidfd, identity, run_channel)
    if run_channel is not None:
        run_channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    controller._private_runtime_app_anchor = anchor
    return anchor


def _freeze_private_value(value):
    if type(value) is dict:
        return MappingProxyType({key: _freeze_private_value(item)
            for key, item in value.items()})
    if type(value) in (list, tuple):
        return tuple(_freeze_private_value(item) for item in value)
    return value


def _private_pipe_identity(fd):
    info = os.fstat(fd)
    identity = (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode))
    if not stat.S_ISFIFO(info.st_mode):
        raise ValueError('private shutdown stream is not a FIFO')
    return identity


def _private_pidfd_exited(pidfd):
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    events = poller.poll(0)
    if events and events[0][1] & (select.POLLERR | select.POLLNVAL):
        raise OSError(errno.EIO, 'cannot verify the held shutdown pidfd')
    return bool(events and events[0][1] & (select.POLLIN | select.POLLHUP))


def _read_private_shutdown_pipes(startup_read, io_fd, startup_prefix,
        startup_identity, io_stdout_identity, deadline):
    if (_private_pipe_identity(startup_read) != startup_identity or
            _private_pipe_identity(io_fd) != io_stdout_identity):
        raise PermissionError('private shutdown pipe identity changed before collection')
    startup = bytearray(startup_prefix)
    io_output = bytearray()
    startup_eof = io_eof = False
    selector = selectors.DefaultSelector()
    try:
        selector.register(startup_read, selectors.EVENT_READ, 'startup')
        selector.register(io_fd, selectors.EVENT_READ, 'io')
        while not startup_eof or not io_eof:
            remaining = deadline - time.monotonic_ns()
            if remaining <= 0:
                streams = [key.data for key in selector.get_map().values()]
                raise TimeoutError(
                    f'private shutdown pipe collection exceeded PREEXIT deadline awaiting {", ".join(streams)} EOF')
            events = selector.select(min(0.005, remaining / 1_000_000_000))
            for key, _ in events:
                target = startup if key.data == 'startup' else io_output
                limit = 1024 * 1024
                chunk = os.read(key.fd, min(4096, limit - len(target) + 1))
                if not chunk:
                    selector.unregister(key.fd)
                    if key.data == 'startup': startup_eof = True
                    else: io_eof = True
                    continue
                target.extend(chunk)
                if len(target) > limit:
                    raise ValueError('private shutdown pipe exceeded its byte bound')
    finally:
        selector.close()
    if (_private_pipe_identity(startup_read) != startup_identity or
            _private_pipe_identity(io_fd) != io_stdout_identity):
        raise PermissionError('private shutdown pipe identity changed during collection')
    if not startup_eof or not io_eof:
        raise RuntimeError('private shutdown streams did not reach EOF')
    return bytes(startup), bytes(io_output)


def _validate_private_startup_prefix(startup_prefix):
    if type(startup_prefix) is not bytes or len(startup_prefix) > 1024 * 1024:
        raise ValueError('private startup prefix is absent or over bound')
    forbidden = (b'KER_NATIVE_STOPPING', b'KER_NATIVE_STATS ',
        b'KER_C31_SHUTDOWN ', b'KER_NATIVE_DONE', b'KER_NATIVE_INCOMPLETE')
    if any(line.startswith(forbidden) for line in startup_prefix.splitlines()):
        raise PermissionError('private startup prefix already contains shutdown authority bytes')
    return True


def _validate_private_shutdown_markers(startup_status):
    lines = startup_status.splitlines()
    required = (b'KER_NATIVE_READY', b'KER_NATIVE_STOPPING',
        b'KER_NATIVE_STATS ', b'KER_C31_SHUTDOWN ', b'KER_NATIVE_DONE')
    positions = []
    for marker in required:
        matches = [i for i, line in enumerate(lines)
            if (line.startswith(marker) if marker.endswith(b' ') else line == marker)]
        if len(matches) != 1:
            raise ValueError('private shutdown status markers are missing or duplicated')
        positions.append(matches[0])
    if positions != sorted(positions):
        raise ValueError('private shutdown status order is invalid')


def _private_shutdown_remaining(deadline):
    remaining = (deadline - time.monotonic_ns()) / 1_000_000_000
    if remaining <= 0:
        raise TimeoutError('private run shutdown exceeded the original PREEXIT deadline')
    return remaining


def _wait_private_shutdown_exit(process, deadline):
    try:
        process.wait(timeout=_private_shutdown_remaining(deadline))
    except subprocess.TimeoutExpired as error:
        raise TimeoutError('private shutdown actor did not exit within the PREEXIT deadline') from error


def _receive_private_run_stop(anchor, deadline):
    channel = anchor.run_channel
    if (_private_run_channel_identity(channel) != anchor.run_channel_identity or
            channel.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) != 1):
        raise PermissionError('private run control socket identity changed')
    with selectors.DefaultSelector() as selector:
        selector.register(channel, selectors.EVENT_READ)
        selector.register(anchor.pidfd, selectors.EVENT_READ)
        ready = selector.select(_private_shutdown_remaining(deadline))
    if not ready:
        raise TimeoutError('private run STOP request exceeded the PREEXIT deadline')
    if any(key.fd == anchor.pidfd for key, _ in ready) or anchor.process.poll() is not None:
        raise ProcessLookupError('private runtime exited before the run STOP acknowledgement')
    packet, ancillary, flags, _ = channel.recvmsg(64,
        socket.CMSG_SPACE(12) + socket.CMSG_SPACE(4 * 4),
        socket.MSG_DONTWAIT | socket.MSG_CMSG_CLOEXEC)
    for level, kind, raw in ancillary:
        if (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS):
            fds = array.array('i')
            fds.frombytes(raw[:len(raw) - len(raw) % fds.itemsize])
            for fd in fds:
                os.close(fd)
    credentials = [(socket.SOL_SOCKET, socket.SCM_CREDENTIALS,
        struct.pack('=3i', *anchor.identity[:3]))]
    if (packet != b'KER_RUN_STOP\n' or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or
            ancillary != credentials):
        raise PermissionError('private run STOP request differs from the held runtime app')
    _private_shutdown_remaining(deadline)


def collect_private_shutdown_streams(controller, app, app_pidfd, worker, worker_pidfd,
        startup_read, startup_prefix, startup_identity, io_stdout_identity,
        worker_start_ticks, source_app_start_ticks, supervisor_start_ticks, nonce, epoch,
        *, release_worker=None):
    """Collect exactly the two held private shutdown pipes before generic collection."""
    run_stop = release_worker is not None
    transport = getattr(controller, 'initial_worker_binding', None)
    broker = getattr(controller, 'broker_readiness', None)
    context = getattr(controller, 'bootstrap_context', None)
    origin = getattr(controller, 'launch', None)
    backend_receipt = getattr(origin, 'backend_receipt', None)
    io_ready_proof = getattr(origin, 'native_io_ready', None)
    pending = getattr(controller, '_private_candidate_preexit_pending', None)
    authorization = getattr(broker, '_private_stop_authorization', None)
    app_anchor = getattr(controller, '_private_runtime_app_anchor', None)
    deadline = getattr(pending, 'deadline_ns', None)
    controller_module = sys.modules.get(type(controller).__module__)
    profile_module = sys.modules.get(type(getattr(controller, 'profile', None)).__module__)
    private_controller_type = getattr(controller_module, 'SourceShellController', None)
    private_profile_type = getattr(profile_module, 'PrivateNewC34InteropProfile', None)
    if (not _validate_private_startup_prefix(startup_prefix) or
            type(startup_identity) is not tuple or len(startup_identity) != 3 or
            type(io_stdout_identity) is not tuple or len(io_stdout_identity) != 3 or
            type(controller) is not private_controller_type or
            type(getattr(controller, 'profile', None)) is not private_profile_type or
            type(app_anchor) is not _PrivateRuntimeAppAnchor or
            app_anchor.controller is not controller or app_anchor.process is not app or
            app_anchor.pidfd != app_pidfd or app_anchor.identity !=
                (app.pid, os.getuid(), os.getgid(), source_app_start_ticks) or
            backend_receipt is None or backend_receipt.closed is not False or
            backend_receipt.process is not app or backend_receipt.pid != app.pid or
            backend_receipt.start_ticks != source_app_start_ticks or
            not startup_prefix.startswith(backend_receipt.prefix) or
            backend_receipt.pipe_identity != startup_identity or
            _private_pipe_identity(backend_receipt.startup_fd) != startup_identity or
            io_ready_proof is None or io_ready_proof.process is not worker or
            io_ready_proof.actor is not controller.io_actor or
            io_ready_proof.pid != worker.pid or
            io_ready_proof.start != worker_start_ticks or
            io_ready_proof.pipe_identity != io_stdout_identity[:2] or
            _private_pipe_identity(origin.native_io_stdout_fd) != io_stdout_identity or
            worker.stdout is None or worker.stdout.closed or deadline is None or
            authorization is None or authorization.deadline_ns != deadline or
            run_stop != (app_anchor.run_channel is not None) or
            getattr(controller, '_private_stop_ack_receipt', None) is None):
        raise PermissionError('private shutdown collector lacks its held pipes and STOP phase')
    stop_receipt = controller._validated_cached_private_stop_receipt(transport, broker)
    if (stop_receipt.authorization.pending is not pending or
            not controller._private_shutdown_binding_matches(context, pending.key,
                stop_receipt.authorization.retirement_proof) or
            context is None or
            getattr(broker, 'app', None) != (app.pid, os.getuid(), os.getgid(),
                source_app_start_ticks) or
            transport.app is not app or
            getattr(controller.io_actor, 'pid', None) != worker.pid or
            getattr(controller.io_actor, 'pidfd', None) != worker_pidfd or
            getattr(controller.io_actor, 'start_ticks', None) != worker_start_ticks or
            (not run_stop and (app.poll() != 0 or worker.poll() != 0 or
                not _private_pidfd_exited(broker.app_pidfd) or
                not _private_pidfd_exited(app_pidfd) or
                not _private_pidfd_exited(worker_pidfd))) or
            time.monotonic_ns() >= deadline):
        raise PermissionError('private shutdown actor/STOP bindings are not settled')
    registry = getattr(context, '_private_shutdown_collections', None)
    if (getattr(controller, '_private_shutdown_collection_receipt', None) is not None or
            getattr(controller, '_private_shutdown_collection_attempted', False) is True or
            (registry is not None and type(registry) is not dict) or
            (registry is not None and id(controller) in registry)):
        raise PermissionError('private shutdown collection is one-shot')
    io_fd = worker.stdout.fileno()
    controller._private_shutdown_collection_attempted = True
    controller._private_shutdown_collection_failed = True
    if run_stop:
        _receive_private_run_stop(app_anchor, deadline)
        release_worker(deadline)
    startup_raw, io_raw = _read_private_shutdown_pipes(startup_read, io_fd,
        startup_prefix, startup_identity, io_stdout_identity, deadline)
    if run_stop:
        _wait_private_shutdown_exit(worker, deadline)
    if worker.poll() != 0 or not _private_pidfd_exited(worker_pidfd):
        raise RuntimeError('private shutdown I/O worker did not settle')
    io_record = _private_io_done_record(io_raw)
    stats = dict(io_record)
    stats.update(shutdown_timed_out=False, worker_exit_code=worker.returncode)
    _validate_private_shutdown_markers(startup_raw)
    parsed = private_c31_shutdown_record(startup_raw, stats,
        worker_identity=(worker.pid, os.getuid(), os.getgid(), worker_start_ticks),
        supervisor_identity=(os.getpid(), os.getuid(), os.getgid(), supervisor_start_ticks),
        nonce=nonce, epoch=epoch)
    if not source_shutdown_evidence(startup_raw, True, stats):
        raise ValueError('private shutdown lacks native statistics and EOF evidence')
    if time.monotonic_ns() >= deadline:
        raise TimeoutError('private shutdown receipt completed after PREEXIT deadline')
    io_executable_hash = getattr(controller.io_actor, 'executable_hash', None)
    if (type(io_executable_hash) is not bytes or len(io_executable_hash) != 32 or
            getattr(controller.launch, 'context', None) is not context or
            getattr(controller.launch, 'native_io_pidfd', -1) < 0):
        raise PermissionError('private I/O executable and Origin context pins are missing')
    if run_stop:
        channel = app_anchor.run_channel
        if (_private_run_channel_identity(channel) != app_anchor.run_channel_identity or
                app.poll() is not None or _private_pidfd_exited(app_pidfd) or
                process_start_ticks(app.pid) != source_app_start_ticks):
            raise PermissionError('private run STOP lost its held runtime app before reply')
        _private_shutdown_remaining(deadline)
        if channel.send(b'OK\n', socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL) != 3:
            raise OSError(errno.EIO, 'short private run STOP acknowledgement')
        _wait_private_shutdown_exit(app, deadline)
    if (app.poll() != 0 or not _private_pidfd_exited(app_pidfd) or
            not _private_pidfd_exited(broker.app_pidfd)):
        raise RuntimeError('private shutdown runtime app did not settle')
    receipt = _PrivateShutdownCollectionReceipt(_PRIVATE_SHUTDOWN_COLLECTION_TOKEN,
        controller=controller, context=context, stop_receipt=stop_receipt,
        startup_status=startup_raw, io_stdout=io_raw, startup_identity=startup_identity,
        io_stdout_identity=io_stdout_identity,
        worker_identity=(worker.pid, os.getuid(), os.getgid(), worker_start_ticks),
        app_identity=(app.pid, os.getuid(), os.getgid(), source_app_start_ticks),
        app_anchor=app_anchor,
        io_executable_hash=io_executable_hash,
        backend_receipt=backend_receipt,
        io_ready_proof=io_ready_proof,
        supervisor_identity=(os.getpid(), os.getuid(), os.getgid(), supervisor_start_ticks),
        parsed={'c31': parsed, 'io': io_record,
            'native': native_statistics(startup_raw)},
        collected_ns=time.monotonic_ns())
    worker.stdout.close()
    worker.stdout = None
    if registry is None:
        registry = {}
        context._private_shutdown_collections = registry
    if time.monotonic_ns() >= deadline:
        raise TimeoutError('private shutdown collection expired before receipt registration')
    registry[id(controller)] = receipt
    try:
        controller._private_shutdown_collection_receipt = receipt
    except BaseException:
        del registry[id(controller)]
        raise
    controller._private_shutdown_collection_failed = False
    return startup_raw, stats, receipt


def _settle_private_source_shutdown(controller, collection):
    """Release the prepared relay and acknowledge the exact retained PREEXIT."""
    context = controller.bootstrap_context
    if (type(collection) is not _PrivateShutdownCollectionReceipt or
            collection.controller is not controller or collection.context is not context or
            getattr(controller, '_private_shutdown_collection_failed', True) or
            getattr(controller, '_private_shutdown_collection_receipt', None) is not collection or
            getattr(context, '_private_shutdown_collections', {}).get(id(controller)) is not collection or
            getattr(controller, '_private_source_settlement_attempted', False)):
        raise PermissionError('private source SETTLED requires an unused shutdown collection')
    stop = controller._validated_cached_private_stop_receipt(
        controller.initial_worker_binding, controller.broker_readiness)
    pending = stop.authorization.pending
    deadline = pending.deadline_ns
    _private_shutdown_remaining(deadline)
    if (stop is not collection.stop_receipt or
            not controller._private_shutdown_binding_matches(context, pending.key,
                stop.authorization.retirement_proof) or
            collection.collected_ns >= deadline or
            context.runtime is not controller.launch.backend_runtime_actor or
            context.io is not controller.io_actor or
            not _private_pidfd_exited(context.runtime.pidfd) or
            not _private_pidfd_exited(context.io.pidfd)):
        raise PermissionError('private source SETTLED lost its native actor or STOP authority')
    retirement = stop.authorization.retirement_proof
    channel = context._pending_preexits[pending.operation_id][2]
    c28_digest = None
    if pending.key == (0, 0):
        # The runtime holds the peer of the initial relay. Its exit delivered
        # EOF directly to the original worker; this SDK has no peer to release.
        relay = None
        controller_module = sys.modules[type(controller).__module__]
        if (retirement.initial_bootstrap_channel_identity !=
                controller_module._source_bootstrap_channel_identity(channel)):
            raise PermissionError('initial source SETTLED lost its granted channel')
    else:
        successive = getattr(context, 'allow_successor', False)
        retry = pending.key == (2, 1)
        if successive:
            prepared = controller._successive_candidate_prepared
            grant = controller._accepted_successive_worker_request
            relay = controller._successive_relays.get(pending.key[0])
        else:
            prepared = (controller._retry_candidate_prepared if retry else
                controller._first_candidate_source_prepared)
            grant = (controller._accepted_retry_worker_request if retry else
                controller._first_candidate_worker_grant)
            relay = (controller._retry_candidate_relay_anchor if retry else
                controller._first_candidate_relay_anchor)
        preparation = context._source_route_preparations.get(id(prepared))
        bootstrap = controller.profile.origin_module.bootstrap
        if (grant is None or grant.worker_key != pending.key or
                grant.channel_identity != controller._first_candidate_endpoint_identity(channel) or
                grant.channel_cookie != controller._first_candidate_socket_cookie(channel) or
                preparation is None or preparation.context is not context or
                type(relay) is not socket.socket or preparation.candidate_channel is not relay or
                preparation.candidate_channel_identity != bootstrap._source_socket_identity(relay)[:4]):
            raise PermissionError('private source SETTLED lost its granted channel or prepared relay')
        c28_response = json.dumps(dict(retirement.c28_response), sort_keys=True,
            separators=(',', ':')).encode('ascii')
        components = retirement.c28_request + c28_response
        if successive:
            final_round, retired_key, retire_ack, verify = controller.c22_provider._successor_retire_receipt
            expected_epoch = context.successor_final_epoch
            if (final_round, retired_key) != (expected_epoch, (expected_epoch - 1, 1)):
                raise PermissionError('final source settlement lacks the last predecessor receipt')
            components += retire_ack[3] + verify
        c28_digest = hashlib.sha256(components).digest()
    bootstrap = controller.profile.origin_module.bootstrap
    c31 = collection.parsed['c31']
    settlement = bootstrap.SourceRetirementProof(
        pending.operation_id, pending.request_sha256,
        stop.authorization.term_evidence.receipt_sha256,
        hashlib.sha256(stop.raw_ack).digest(),
        c28_digest,
        hashlib.sha256(bytes.fromhex(c31['record_hex']) + collection.io_stdout).digest(),
        c31['outstanding_count'], c31['last_packet_id'], c31['status'])
    controller._private_source_settlement_attempted = True
    try:
        controller._private_source_settlement = context._complete_worker_preexit(
            pending.operation_id, settlement, relay=relay)
    except BaseException:
        controller.unresolved = True
        raise
    return settlement


def _validate_run_stop_request(startup_read, startup_status, private_source_rx):
    """Keep private shutdown bytes owned by the private collector's sole reader."""
    if private_source_rx:
        return startup_status
    while True:
        try:
            pending = os.read(startup_read, 4096)
        except BlockingIOError:
            break
        if not pending:
            break
        startup_status += pending
    if (b'KER_NATIVE_DONE\n' not in startup_status and
            b'KER_NATIVE_INCOMPLETE\n' not in startup_status):
        raise RuntimeError('run requested EAL teardown before native kernel teardown')
    return startup_status


def worker_ready_record(line, *, expected_pid=None, expected_session=None,
                        require_queue_proof=False, expected_port_id=None,
                        expected_queue_lcores=None, expected_source_proc_id=None,
                        expected_queue_count=None):
    value = json.loads(line.removeprefix('KER_IO_READY '))
    if not isinstance(value, dict):
        raise RuntimeError('invalid DPDK READY object')
    mac, features = value.get('mac'), value.get('tx_offload_features')
    if not isinstance(mac, str) or not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', mac):
        raise RuntimeError('invalid DPDK READY MAC')
    # Match the actual native virtio consumer, including checksum dependency.
    if (type(features) is not int or features < 0 or features & ~0x1801 or
            features & 0x1800 and not features & 1):
        raise RuntimeError('invalid DPDK READY TX features')
    proof = value.get('queue_owner_proof')
    if proof is None:
        if require_queue_proof:
            raise RuntimeError('source profile requires native queue-owner READY proof')
        return value
    if (not isinstance(proof, dict) or
            set(proof) != {'version', 'worker_pid', 'session_nonce', 'session_epoch',
                'role', 'source_proc_id', 'port_id', 'queues'} or
            type(proof.get('version')) is not int or proof['version'] != 1 or
            type(proof.get('worker_pid')) is not int or not 0 < proof['worker_pid'] <= 2147483647 or
            type(proof.get('session_epoch')) is not int or not 0 < proof['session_epoch'] <= 0xffffffffffffffff or
            not isinstance(proof.get('session_nonce'), str) or
            not re.fullmatch(r'[0-9a-f]{32}', proof['session_nonce']) or
            proof['session_nonce'] == '0' * 32 or
            proof.get('role') != 'native-io-owner' or
            type(proof.get('source_proc_id')) is not int or
            proof['source_proc_id'] not in (0, 1) or
            type(proof.get('port_id')) is not int or not 0 <= proof['port_id'] <= 65535 or
            not isinstance(proof.get('queues'), list) or
            not 1 <= len(proof['queues']) <= 16):
        raise RuntimeError('invalid native queue-owner READY proof schema')
    if (expected_pid is None or proof['worker_pid'] != expected_pid or
            expected_session is None or
            (proof['session_nonce'], proof['session_epoch']) != expected_session):
        raise RuntimeError('native queue-owner READY proof process/session mismatch')
    if expected_port_id is not None and proof['port_id'] != expected_port_id:
        raise RuntimeError('native queue-owner READY proof port mismatch')
    if expected_source_proc_id is not None and (
            proof['source_proc_id'] != expected_source_proc_id or
            proof['role'] != 'native-io-owner'):
        raise RuntimeError('native queue-owner READY proof source role mismatch')
    queues = proof['queues']
    if expected_queue_count is not None and len(queues) != expected_queue_count:
        raise RuntimeError('native queue-owner READY proof queue count mismatch')
    expected_lcores = (None if expected_queue_lcores is None else
        list(expected_queue_lcores))
    if expected_lcores is not None and len(queues) != len(expected_lcores):
        raise RuntimeError('native queue-owner READY proof queue count mismatch')
    if expected_lcores is None:
        main_lcore = value.get('main_lcore')
        if type(main_lcore) is not int or not 0 <= main_lcore < 128:
            raise RuntimeError('native queue-owner READY lacks a bounded main EAL lcore')
        expected_lcores = [main_lcore] * len(queues)
    seen_queues = set()
    for index, item in enumerate(queues):
        if (not isinstance(item, dict) or
                set(item) != {'queue_id', 'owner_eal_lcore', 'observed_eal_lcore', 'allowed_cpus', 'actual_cpu'} or
                any(type(item.get(key)) is not int for key in
                    ('queue_id', 'owner_eal_lcore', 'observed_eal_lcore', 'actual_cpu')) or
                not 0 <= item['queue_id'] < 16 or not 0 <= item['owner_eal_lcore'] < 128 or
                item['observed_eal_lcore'] != item['owner_eal_lcore'] or
                not 0 <= item['actual_cpu'] <= 65535 or
                not isinstance(item.get('allowed_cpus'), list) or
                not 1 <= len(item['allowed_cpus']) <= 128 or
                any(type(cpu) is not int or not 0 <= cpu <= 65535
                    for cpu in item['allowed_cpus']) or
                len(set(item['allowed_cpus'])) != len(item['allowed_cpus']) or
                item['actual_cpu'] not in item['allowed_cpus'] or
                item['queue_id'] in seen_queues):
            raise RuntimeError('invalid or duplicate native queue-owner READY entry')
        if (expected_source_proc_id is not None and
                len(item['allowed_cpus']) != 1):
            raise RuntimeError('source-shell queue proof requires single-CPU EAL lcore affinity')
        if item['owner_eal_lcore'] != expected_lcores[index]:
            raise RuntimeError('native queue-owner READY proof lcore mismatch')
        seen_queues.add(item['queue_id'])
    if seen_queues != set(range(len(queues))):
        raise RuntimeError('native queue-owner READY proof queue IDs are incomplete')
    return value


def read_worker_startup(process, label, timeout=20, maximum=65536):
    """Bound the complete record, including a writer that stalls mid-line."""
    deadline = time.monotonic() + timeout
    data = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                raise RuntimeError(label + ' startup timed out')
            byte = os.read(process.stdout.fileno(), 1)
            if not byte:
                raise RuntimeError(label + ' exited before a complete startup record')
            data.extend(byte)
            if len(data) > maximum:
                raise RuntimeError(label + ' startup record exceeds limit')
            if byte == b'\n':
                return data.decode('utf-8').strip()


def _read_legacy_backend_ready(source_network_expected, startup_read,
        startup_status=b''):
    """Consume the one-line legacy marker only when source proof is absent."""
    if source_network_expected is not None:
        return startup_status
    with selectors.DefaultSelector() as selector:
        selector.register(startup_read, selectors.EVENT_READ)
        if selector.select(20):
            startup_status = os.read(startup_read, 128)
    if not startup_status.startswith(b'KER_NATIVE_READY\n'):
        raise RuntimeError('application did not initialize the native Linux backend')
    return startup_status


def _source_shell_eal_args(arguments, run_id):
    if (type(run_id) is not str or re.fullmatch(
            r'gr_[0-9]{8}_[0-9]{6}_[1-9][0-9]*_[0-9a-f]{8}', run_id) is None):
        raise ValueError('original supervisor did not provide a canonical run ID')
    expected = '--file-prefix=container-' + run_id
    result = []
    found = False
    index = 0
    while index < len(arguments):
        item = arguments[index]
        if item == '--file-prefix':
            if found or index + 1 >= len(arguments):
                raise ValueError('source-shell EAL file prefix is missing or duplicated')
            found = True
            value = arguments[index + 1]
            if value != expected[len('--file-prefix='):]:
                raise ValueError('caller EAL file prefix differs from authenticated run ID')
            result.append(expected)
            index += 2
            continue
        if item.startswith('--file-prefix='):
            if found or item != expected:
                raise ValueError('caller EAL file prefix differs from authenticated run ID')
            found = True
        result.append(item)
        index += 1
    if not found:
        result.append(expected)
    return result


def _finish_initial_backend_startup(source_network_expected,
        source_shell_controller, runtime_actor, startup_read, startup_status,
        broker_readiness_channel=None):
    if source_network_expected is None:
        return _read_legacy_backend_ready(None, startup_read, startup_status)
    if source_shell_controller is not None:
        context = source_shell_controller.accept_origin(runtime_actor)
        if (context is None or
                getattr(source_shell_controller, 'bootstrap_context', None) is not context):
            raise RuntimeError('source controller did not retain the authenticated Origin context')
    return startup_status


def _settle_source_shell_actors(controller, runtime_service_server,
        broker_readiness_channel, app, worker):
    """Revoke runtime/native paths while the original supervisor remains alive."""
    if controller is None or controller.launch is None:
        return None
    deadline_ns = controller.deadline_ns
    # Withdraw service authority and use the broker's authenticated STOP/C31
    # path even if a passive liveness check already found an actor failure.
    # Exact supervisor identity is revalidated immediately before TERM below.
    if runtime_service_server is not None:
        runtime_service_server.revoke('source-shell shutdown')
    if worker is not None or controller.io_actor is not None:
        if app is None:
            raise RuntimeError('source-shell worker has no captured runtime app for C31 shutdown')
        if app.poll() is not None:
            # The app may already have completed C31 STOP/SETTLED. The caller
            # must validate its native markers and worker receipt before TERM.
            return False
        if (broker_readiness_channel is None or
                not broker_readiness_channel.ready):
            raise RuntimeError('source-shell native authority has no authenticated broker STOP path')
        remaining_ns = deadline_ns - time.monotonic_ns()
        if remaining_ns <= 0:
            raise TimeoutError('source-shell broker STOP deadline expired')
        if not broker_readiness_channel.stopped:
            # The real broker STOP makes socket-broker-server stop its LKL run;
            # run-loop teardown invokes the C31 RX consumer STOP/SETTLED path.
            if getattr(broker_readiness_channel, '_stop', None) is None:
                if getattr(broker_readiness_channel, 'stop_attempted', False):
                    raise RuntimeError('source-shell broker STOP was attempted without a retained ACK wait')
                if not hasattr(broker_readiness_channel, 'begin_stop'):
                    broker_readiness_channel.stop(remaining_ns / 1_000_000_000)
                else:
                    broker_readiness_channel.begin_stop(remaining_ns / 1_000_000_000)
            if hasattr(broker_readiness_channel, 'poll_stop'):
                while not broker_readiness_channel.poll_stop():
                    if time.monotonic_ns() >= deadline_ns:
                        raise TimeoutError('source-shell broker STOP/ACK exceeded its immutable deadline')
                    time.sleep(0.001)
        if app is not None and app.poll() is None:
            remaining_ns = deadline_ns - time.monotonic_ns()
            if remaining_ns <= 0:
                raise TimeoutError('source-shell app settlement deadline expired')
            app.wait(timeout=remaining_ns / 1_000_000_000)
        if app.returncode != 0:
            raise RuntimeError('runtime app exited unsuccessfully during broker/C31 shutdown')
    return True


class AdditionalWorker:
    """Own one additional Ethernet/MTU channel and its separate EAL process."""

    def __init__(self, interface):
        self.interface = interface
        self.process = self.app_packet = self.io_packet = self.app_mtu = self.io_mtu = None
        self.stop_read = self.stop_write = -1
        self.info = self.stats = None
        self.finished_result = None

    def start(self, worker, args, rx_decision_fd=None):
        item = self.interface
        self.app_packet, self.io_packet = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM | socket.SOCK_NONBLOCK)
        self.app_mtu, self.io_mtu = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.stop_read, self.stop_write = os.pipe2(os.O_CLOEXEC)
        options = ['--tx-offloads', str(TX_OFFLOADS[item['tx_offloads']]), '--queues', str(item['queues']), '--mtu', str(item['mtu']), '--max-mtu', str(item['max_mtu']),
                   '--mbuf-mode', item['mbuf_mode'], '--idle-sleep-us', str(args.idle_sleep_us),
                   '--tx-delay-us', str(args.tx_delay_us), '--numa' if args.numa else '--no-numa']
        if item['rx_lcores'] is not None:
            options += ['--rx-lcores', item['rx_lcores']]
        if item['rss']:
            options.append('--rss')
        if args.all_multicast or item['address6'] is not None:
            options.append('--all-multicast')
        if args.promiscuous is not None:
            options.append('--promiscuous' if args.promiscuous else '--no-promiscuous')
        if args.log_dir is not None:
            directory = args.log_dir.resolve() / item['name']
            directory.mkdir(parents=True, exist_ok=True)
            options += ['--log-dir', str(directory)]
        if args.log_level is not None:
            options += ['--log-level', str(args.log_level)]
        if args.pcap_dir is not None:
            directory = args.pcap_dir.resolve() / item['name']
            directory.mkdir(parents=True, exist_ok=True)
            options += ['--pcap-dir', str(directory), '--pcap-snaplen', str(args.pcap_snaplen),
                        '--pcap-max-bytes', str(args.pcap_max_bytes)]
            if args.pcap_nsec:
                options.append('--pcap-nsec')
        self.process = subprocess.Popen([str(worker), '--packet-fd', str(self.io_packet.fileno()),
            '--mtu-fd', str(self.io_mtu.fileno()), '--control-fd', str(self.stop_read),
            '--port', item['port'], *options,
            *(['--rx-decision-fd', str(rx_decision_fd)] if rx_decision_fd is not None else []),
            '--', *shlex.split(item['eal'])],
            pass_fds=(self.io_packet.fileno(), self.io_mtu.fileno(), self.stop_read,
                *([rx_decision_fd] if rx_decision_fd is not None else [])),
            stdout=subprocess.PIPE, text=True)
        self.io_packet.close(); self.io_mtu.close(); os.close(self.stop_read); self.stop_read = -1
        line = read_worker_startup(self.process, 'additional DPDK worker ' + item['name'])
        if line.startswith('KER_IO_DONE '):
            self.stats = worker_done_record(line)
        if not line.startswith('KER_IO_READY '):
            raise RuntimeError('additional DPDK worker failed before READY: ' + item['name'])
        self.info = worker_ready_record(line)

    def app_fds(self):
        return self.app_packet.fileno(), self.app_mtu.fileno()

    def native_settings(self):
        item = self.interface
        values = [*self.app_fds(), item['max_mtu'], item['mtu'], self.info['mac'], item['address'],
                  item['address6'] or '-', ','.join(map(str, item['vip_addresses'])) or '-',
                  ','.join(map(str, item['vip_addresses6'])) or '-', self.info['tx_offload_features']]
        return '|'.join(map(str, values))

    def close_app_channels(self):
        if self.app_packet is not None: self.app_packet.close()
        if self.app_mtu is not None: self.app_mtu.close()

    def stop_channels(self):
        self.close_app_channels()
        for channel in (self.io_packet, self.io_mtu):
            if channel is not None: channel.close()
        for name in ('stop_read', 'stop_write'):
            fd = getattr(self, name)
            if fd >= 0: os.close(fd); setattr(self, name, -1)
    def finish(self):
        if self.finished_result is not None:
            return self.finished_result
        self.stop_channels()
        failed = timed_out = False
        if self.process is not None:
            try:
                output, _ = self.process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill(); output, _ = self.process.communicate(); failed = timed_out = True
            completions = int(self.stats is not None)
            for line in output.splitlines():
                if line.startswith('KER_IO_DONE '):
                    completions += 1
                    if completions > 1:
                        print(f'ker-run: duplicate additional DPDK worker completion record: {self.interface["name"]}',
                              file=sys.stderr)
                        failed = True
                    try:
                        self.stats = worker_done_record(line)
                    except (ValueError, RuntimeError) as error:
                        print(f'ker-run: additional worker completion: {error}', file=sys.stderr)
                        failed = True
            failed |= self.process.returncode != 0 or self.stats is None or self.stats.get('outstanding', 1) != 0
        if self.stats is not None:
            self.stats.update(name=self.interface['name'], io=self.info, pid=self.process.pid if self.process else None,
                              shutdown_timed_out=timed_out, worker_exit_code=self.process.returncode if self.process else None)
        self.finished_result = failed
        return failed


def unexpected_worker_exit(worker, additional):
    if worker.poll() is not None:
        return 'DPDK worker stopped while the application was running'
    return unexpected_additional_worker_exit(additional)


def unexpected_additional_worker_exit(additional):
    stopped = [extra.interface['name'] for extra in additional if extra.process.poll() is not None]
    if stopped:
        return 'additional DPDK worker stopped while the application was running: ' + ', '.join(stopped)
    return None


def drain_startup_status(startup_read, startup_status):
    while True:
        try:
            extra = os.read(startup_read, 4096)
        except BlockingIOError:
            break
        if not extra:
            break
        startup_status += extra
    return startup_status


def normal_native_shutdown_markers(startup_status):
    lines = startup_status.splitlines()
    if any(line == b'KER_NATIVE_INCOMPLETE' for line in lines):
        return False
    required = (b'KER_NATIVE_READY', b'KER_NATIVE_STOPPING', b'KER_NATIVE_DONE')
    positions = {}
    for marker in required:
        matches = [index for index, line in enumerate(lines) if line == marker]
        if len(matches) != 1:
            return False
        positions[marker] = matches[0]
    if not positions[required[0]] < positions[required[1]] < positions[required[2]]:
        return False
    for index, line in enumerate(lines):
        if line.startswith(b'KER_NATIVE_'):
            if line in required or line == b'KER_NATIVE_INCOMPLETE':
                continue
            if line.startswith(b'KER_NATIVE_STATS ') and positions[required[1]] < index < positions[required[2]]:
                continue
            return False
    return True



def native_statistics(startup_status):
    records = [line.removeprefix(b'KER_NATIVE_STATS ') for line in startup_status.splitlines()
               if line.startswith(b'KER_NATIVE_STATS ')]
    if not records:
        return None
    if len(records) != 1:
        raise ValueError('duplicate native statistics records')
    result = json.loads(records[0])
    if not isinstance(result, dict) or any(type(value) is not int or value < 0
                                           for value in result.values()):
        raise ValueError('native statistics must contain nonnegative integer counters')
    return result


def source_shutdown_evidence(startup_status, startup_eof, io_stats):
    """Require the complete native, C31/IO and pipe settlement before TERM."""
    if not startup_eof or not normal_native_shutdown_markers(startup_status):
        return False
    if (not isinstance(io_stats, dict) or io_stats.get('control_eof') is not True or
            io_stats.get('rx_decision_enabled') is not True or
            io_stats.get('rx_decision_settled') is not True or
            type(io_stats.get('outstanding')) is not int or io_stats['outstanding'] != 0):
        return False
    try:
        native = native_statistics(startup_status)
    except (ValueError, UnicodeError):
        return False
    required = {'buffer_allocations', 'buffer_releases', 'buffer_shutdown_releases',
        'buffers_live', 'buffer_bytes', 'buffer_option_guards_live'}
    return (isinstance(native, dict) and required <= native.keys() and
            all(type(native[key]) is int and native[key] >= 0 for key in required) and
            native['buffer_allocations'] == native['buffer_releases'] and
            native['buffer_shutdown_releases'] == 0 and
            native['buffers_live'] == 0 and native['buffer_bytes'] == 0 and
            native['buffer_option_guards_live'] == 0)

def collect_worker(process, stats):
    failed = timed_out = False
    completions = int(stats is not None)
    try:
        output, _ = process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill(); output, _ = process.communicate(); failed = timed_out = True
        print('ker-run: DPDK worker shutdown timed out', file=sys.stderr)
    for line in output.splitlines():
        if line.startswith('KER_IO_DONE '):
            completions += 1
            if completions > 1:
                print('ker-run: duplicate DPDK worker completion record', file=sys.stderr)
                failed = True
            try:
                stats = worker_done_record(line)
            except (ValueError, RuntimeError) as error:
                print(f'ker-run: DPDK worker completion: {error}', file=sys.stderr)
                failed = True
    if stats is not None:
        stats.update(shutdown_timed_out=timed_out, worker_exit_code=process.returncode)
    return stats, failed or process.returncode != 0 or stats is None


def finish_concurrently(operations):
    """Run bounded worker reaps together and return each result or exception."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(operations)) as pool:
        futures = [pool.submit(operation) for operation in operations]
        results = []
        for future in futures:
            try:
                results.append(future.result())
            except Exception as error:  # Keep reaping the remaining workers on one failure.
                results.append(error)
        return results



def write_statistics(path, stats):
    """Replace a complete report; never truncate an earlier successful report."""
    payload = json.dumps(stats, indent=2) + '\n'
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8',
                dir=path.parent, prefix='.' + path.name + '.', delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)

def primary_channels():
    """Transfer channels only after the complete IPC bundle is allocated."""
    with contextlib.ExitStack() as cleanup:
        pairs = []
        for kind in (socket.SOCK_DGRAM | socket.SOCK_NONBLOCK,
                     socket.SOCK_SEQPACKET, socket.SOCK_SEQPACKET):
            pair = socket.socketpair(socket.AF_UNIX, kind)
            for channel in pair:
                cleanup.callback(channel.close)
            pairs.extend(pair)
        pipes = []
        for flags in (os.O_CLOEXEC, os.O_CLOEXEC | os.O_NONBLOCK):
            pair = os.pipe2(flags)
            for fd in pair:
                cleanup.callback(os.close, fd)
            pipes.extend(pair)
        pairs[4].setblocking(False)
        cleanup.pop_all()
        return (*pairs, *pipes)


def main(*, retained_backend_handoff=None, source_shell_controller=None, c34_test_capture=None):
    global _COMPANION_RELOAD_REQUESTED
    try:
        args = parse_arguments(defer_worker_limits=True)
    except MemoryError:
        print('ker-run: configuration allocation failed', file=sys.stderr)
        return 2
    private_network_temp = None
    private_network_capture = None
    launch_environment = os.environ
    if (source_shell_controller is None and bool(getattr(args,
            'control_nginx_source_private_c34_profile', False))):
        try:
            launch_environment, private_network_temp, private_network_capture = (
                _new_private_c34_network_input(args, os.environ))
        except (OSError, UnicodeError, ValueError, PermissionError) as error:
            print(f'ker-run: private source network input: {error}', file=sys.stderr)
            return 125
    try:
        source_network_expected = source_network_startup.prepare_from_launch(
            args, launch_environment)
    except (OSError, UnicodeError, ValueError) as error:
        if private_network_capture is not None:
            private_network_capture.template_file.close()
        if private_network_temp is not None:
            private_network_temp.cleanup()
        _close_private_c34_source_controller(source_shell_controller)
        print(f'ker-run: source network startup profile: {error}', file=sys.stderr)
        return 2
    private_programmatic_controller = False
    if source_shell_controller is not None:
        try:
            controller_module = _load_source_shell_controller()
            if type(source_shell_controller) is not controller_module.SourceShellController:
                raise TypeError('source-shell controller must be the canonical typed controller')
            captured = source_shell_controller.profile.network_expectation
            private_profile_loader = getattr(controller_module, '_c34_profile_module', None)
            private_type = (private_profile_loader().PrivateNewC34InteropProfile
                if callable(private_profile_loader) else None)
            private_programmatic_controller = (private_type is not None and
                type(source_shell_controller.profile) is private_type)
            if (type(captured) is not source_network_startup.SourceNetworkExpectation or
                    source_network_expected is None or
                    source_network_startup._captured_expectation_key(captured) !=
                        source_network_startup._expected_key(source_network_expected)):
                raise ValueError('controller network capture differs from this parsed launch')
        except (ImportError, OSError, TypeError, ValueError) as error:
            _close_private_c34_source_controller(source_shell_controller)
            print(f'ker-run: source-shell captured network profile: {error}', file=sys.stderr)
            return 125
    if retained_backend_handoff is not None:
        if type(retained_backend_handoff) is not source_network_startup.RetainedBackendHandoff:
            print('ker-run: source startup handoff has an unsupported type', file=sys.stderr)
            return 2
        if (source_network_expected is None or
                source_network_startup._expected_key(source_network_expected) !=
                    retained_backend_handoff.expected):
            print('ker-run: source startup handoff differs from the parsed launch expectation',
                file=sys.stderr)
            retained_backend_handoff.fail(ValueError('source launch expectation mismatch'))
            return 2
    if source_shell_controller is not None and retained_backend_handoff is not None:
        print('ker-run: source-shell backend handoff is created by its original launch',
            file=sys.stderr)
        return 125
    try:
        control_nginx = control_nginx_profile(args,
            private_c34_controller=private_programmatic_controller)
    except (OSError, ValueError) as error:
        if private_network_capture is not None:
            private_network_capture.template_file.close()
        if private_network_temp is not None:
            private_network_temp.cleanup()
        _close_private_c34_source_controller(source_shell_controller)
        print(f'ker-run: {error}', file=sys.stderr)
        return 2
    try:
        if c34_test_capture is None:
            source_shell_controller = _select_source_shell_controller(args,
                source_shell_controller, source_network_expected, control_nginx,
                private_network_capture, private_network_temp)
        else:
            if (source_shell_controller is not None or retained_backend_handoff is not None or
                    not args.control_nginx_source_private_c34_profile):
                raise ValueError('C34 test fixture requires its own private controller')
            source_shell_controller = _capture_private_c34_source_controller(args,
                source_network_expected, control_nginx, private_network_capture,
                private_network_temp, test_capture=c34_test_capture)
        private_network_capture = None
        private_network_temp = None
    except (ImportError, OSError, PermissionError, TypeError, ValueError) as error:
        if private_network_capture is not None:
            private_network_capture.template_file.close()
        if private_network_temp is not None:
            private_network_temp.cleanup()
        _close_private_c34_source_controller(source_shell_controller)
        print(f'ker-run: source-shell profile selection: {error}', file=sys.stderr)
        return 2
    private_selected = bool(getattr(args, 'control_nginx_source_private_c34_profile', False))
    private_selected = private_selected or _is_private_c34_controller(
        source_shell_controller)
    if private_selected:
        try:
            _bind_private_c34_runtime_artifacts(args, source_shell_controller)
        except (OSError, PermissionError, TypeError, ValueError) as error:
            _close_private_c34_source_controller(source_shell_controller)
            print(f'ker-run: private runtime artifact join: {error}', file=sys.stderr)
            return 125
    if source_shell_controller is not None:
        try:
            source_shell_controller.validate_main(source_network_expected,
                control_nginx, args)
        except (OSError, TypeError, ValueError, PermissionError) as error:
            _close_private_c34_source_controller(source_shell_controller)
            print(f'ker-run: source-shell controller profile: {error}', file=sys.stderr)
            return 125
    elif source_network_expected is not None and os.environ.get(
            'KER_NGINX_SOURCE_SHELL_ENABLE') == '1':
        print('ker-run: source-shell startup requires its same-process controller',
            file=sys.stderr)
        return 125
    if private_selected and c34_test_capture is None:
        _close_private_c34_source_controller(source_shell_controller)
        print('ker-run: NEWC34_INTEROP held pending end-to-end qualification of original-shell '
            'ACTIVATE, master cutover, listener retirement, and STOP settlement',
            file=sys.stderr)
        return 125
    try:
        library = args.library.resolve(strict=True)
        worker_path = args.io_worker.resolve(strict=True)
        app_guard = (worker_path.parent / 'ker-app').resolve(strict=True)
        for artifact in (library, worker_path, app_guard):
            if not artifact.is_file():
                raise ValueError(f'{artifact}: runtime artifact must be a regular file')
        for artifact in (worker_path, app_guard):
            if not os.access(artifact, os.X_OK):
                raise ValueError(f'{artifact}: runtime artifact must be executable')
    except (OSError, ValueError) as error:
        print(f'ker-run: runtime artifact: {error}', file=sys.stderr)
        return 125
    if private_selected:
        try:
            _bind_private_c34_runtime_artifacts(args, source_shell_controller)
        except (OSError, PermissionError, TypeError, ValueError) as error:
            _close_private_c34_source_controller(source_shell_controller)
            print(f'ker-run: private runtime artifact revalidation: {error}',
                file=sys.stderr)
            return 125
    try:
        validate_selected_bond_limits(args)
    except MemoryError:
        print('ker-run: configuration allocation failed', file=sys.stderr)
        return 2
    except (OSError, ValueError) as error:
        print(f'ker-run: {error}', file=sys.stderr)
        return 2
    try:
        (channel_app, channel_io, mtu_app, mtu_io, run_parent, run_app,
         control_read, control_write, startup_read, startup_write) = primary_channels()
    except OSError as error:
        print(f'ker-run: IPC setup: {error}', file=sys.stderr)
        return 125
    source_startup_pipe_identity = None
    if source_network_expected is not None:
        try:
            source_startup_pipe_identity = source_network_startup.pipe_identity(
                startup_read, startup_write)
        except (OSError, ValueError) as error:
            for channel in (channel_app, channel_io, mtu_app, mtu_io, run_parent, run_app):
                channel.close()
            for descriptor in (control_read, control_write, startup_read, startup_write):
                os.close(descriptor)
            print(f'ker-run: source startup pipe: {error}', file=sys.stderr)
            return 125
    decision_app = decision_io = None
    owner_relay_app = owner_relay_owner = None
    owner_relay_app_auth = None
    owner_auth_app = owner_auth_supervisor = None
    supervisor_pidfd = worker_pidfd = app_pidfd = -1
    runtime_actor_pidfd = -1
    runtime_service_server = None
    runtime_service_directory = None
    app_executable = None
    app_executable_hash = None
    app_executable_identity = None
    app_executable_pin = None
    broker_readiness_channel = None
    run_control = None
    nginx_companion_server = None
    containment_unresolved = False
    decision_nonce = None
    decision_epoch = 0
    supervisor_identity = None
    if args.rx_decision:
        try:
            decision_app, decision_io = socket.socketpair(socket.AF_UNIX,
                socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK)
            # SO_PASSCRED is set on both receiving endpoints before any child
            # exists, so bootstrap messages cannot race credential collection.
            decision_app.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            decision_io.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            supervisor_pidfd = os.pidfd_open(os.getpid(), 0)
            if source_shell_controller is not None:
                decision_nonce = source_shell_controller.nonce
                decision_epoch = source_shell_controller.epoch
            else:
                decision_nonce = secrets.token_bytes(rx_decision_wire.NONCE_BYTES)
                decision_epoch = secrets.randbits(64) or 1
            supervisor_identity = rx_decision_identity(os.getpid(), supervisor_pidfd)
        except (AttributeError, OSError, RuntimeError, ValueError) as error:
            for channel in (decision_app, decision_io):
                if channel is not None:
                    channel.close()
            if supervisor_pidfd >= 0:
                os.close(supervisor_pidfd)
            for channel in (channel_app, channel_io, mtu_app, mtu_io, run_parent, run_app):
                channel.close()
            for descriptor in (control_read, control_write, startup_read, startup_write):
                os.close(descriptor)
            print(f'ker-run: RX decision setup is unavailable: {error}', file=sys.stderr)
            return 125
    if (source_shell_controller is None and
            getattr(args, 'control_nginx_rx_relay', False)):
        try:
            if control_nginx is None or not args.rx_decision:
                raise ValueError('owner RX relay requires the explicit C31 and C22 profile')
            owner_relay_app, owner_relay_owner = socket.socketpair(
                socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK)
            for endpoint in (owner_relay_app, owner_relay_owner):
                endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            owner_auth_app, owner_auth_supervisor = socket.socketpair(
                socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK)
            for endpoint in (owner_auth_app, owner_auth_supervisor):
                endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        except (OSError, ValueError) as error:
            for endpoint in (owner_relay_app, owner_relay_owner,
                    owner_auth_app, owner_auth_supervisor):
                if endpoint is not None:
                    endpoint.close()
            print(f'ker-run: RX owner relay setup is unavailable: {error}', file=sys.stderr)
            return 125
    elif source_shell_controller is not None:
        try:
            if not args.rx_decision:
                raise ValueError('source C31 channels require the captured RX-decision profile')
            source_controller_module = _load_source_shell_controller()
            (owner_relay_app, owner_relay_owner,
                owner_auth_app, owner_auth_supervisor) = \
                source_controller_module.create_source_c31_channels()
            # Keep an SDK-owned alias of the app-side endpoint.  APP_AUTH is
            # written from this side so the worker endpoint receives it; the
            # opposite owner endpoint remains exclusively the granted worker
            # relay capability.
            owner_relay_app_auth = owner_relay_app.dup()
            owner_relay_app_auth.setblocking(False)
        except (AttributeError, OSError, PermissionError, RuntimeError, ValueError) as error:
            for endpoint in (owner_relay_app, owner_relay_owner,
                    owner_relay_app_auth, owner_auth_app, owner_auth_supervisor):
                if endpoint is not None:
                    try:
                        endpoint.close()
                    except OSError:
                        pass
            # This setup block precedes the outer runtime try/finally.  On
            # failure, release every IPC descriptor already acquired by this
            # invocation, including primary channels and RX-decision state.
            for endpoint in (decision_app, decision_io, channel_app, channel_io,
                    mtu_app, mtu_io, run_parent, run_app):
                if endpoint is not None:
                    try:
                        endpoint.close()
                    except OSError:
                        pass
            for descriptor in (supervisor_pidfd, control_read, control_write,
                    startup_read, startup_write):
                if descriptor >= 0:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
            print(f'ker-run: source C31 transport setup is unavailable: {error}',
                file=sys.stderr)
            return 125
    worker_finished = run_finished = False
    pending_shutdown_signal = None
    pending_relay_stop = False
    def handle_shutdown_signal(signum, frame):
        nonlocal pending_shutdown_signal
        if args.broker_readiness:
            if pending_shutdown_signal is None:
                pending_shutdown_signal = signum
        else:
            interrupted(signum, frame)

    signal.signal(signal.SIGTERM, handle_shutdown_signal)
    if args.broker_readiness:
        signal.signal(signal.SIGINT, handle_shutdown_signal)
    if control_nginx is not None:
        signal.signal(signal.SIGHUP, companion_reload_requested)
    worker = app = None
    worker_start_ticks = None
    source_profile = getattr(source_shell_controller, 'profile', None)
    c34_module = sys.modules.get(type(source_profile).__module__) if source_profile is not None else None
    private_source_rx = (source_shell_controller is not None and args.rx_decision and
        type(getattr(source_shell_controller, 'profile', None)) is
            getattr(c34_module, 'PrivateNewC34InteropProfile', None))
    private_shutdown_receipt_valid = not private_source_rx
    supervisor_start_ticks = process_start_ticks(os.getpid())
    additional = []
    exit_code = 125
    stats = None
    info = None
    startup_status = b""
    worker_stdout_identity = None
    startup_eof = False
    source_startup_audit = None
    retained_backend_receipt = None
    retained_backend_transferred = False
    infrastructure_failure = False
    preserve_signal = False
    signal_exit_code = None
    stop_deadline = None

    def collect_and_settle_private_shutdown(*, release_worker=None):
        nonlocal containment_unresolved
        try:
            native_startup, native_stats, collection = collect_private_shutdown_streams(
                source_shell_controller, app, app_pidfd, worker, worker_pidfd,
                startup_read, startup_status, source_startup_pipe_identity,
                worker_stdout_identity, worker_start_ticks, source_app_start_ticks,
                supervisor_start_ticks, decision_nonce, decision_epoch,
                release_worker=release_worker)
            _settle_private_source_shutdown(source_shell_controller, collection)
        except (OSError, RuntimeError, ValueError, struct.error):
            source_shell_controller.unresolved = True
            containment_unresolved = True
            raise
        return native_startup, native_stats

    def stop_broker_for_signal():
        nonlocal exit_code, preserve_signal, signal_exit_code, stop_deadline
        nonlocal pending_shutdown_signal
        nonlocal containment_unresolved, infrastructure_failure
        if (pending_shutdown_signal is None or broker_readiness_channel is None or
                not broker_readiness_channel.ready or broker_readiness_channel.stopped):
            return
        signum = pending_shutdown_signal
        pending_shutdown_signal = None
        if run_control is not None:
            run_control._mark_unresolved('native shutdown signal arrived without relay STOP')
            containment_unresolved = True
            infrastructure_failure = True
            raise RuntimeError('relay profile requires authenticated STOP before native shutdown')
        preserve_signal = True
        signal_exit_code = 128 + signum
        exit_code = signal_exit_code
        if (nginx_companion_server is not None and nginx_companion_server.started and
                not nginx_companion_server.settled):
            nginx_companion_server.stop()
            if nginx_companion_server.unresolved or not nginx_companion_server.settled:
                containment_unresolved = True
                infrastructure_failure = True
                raise RuntimeError('Nginx companion did not settle before broker STOP')
        stop_deadline = time.monotonic() + 10.0
        broker_readiness_channel.stop()

    def request_relay_shutdown():
        nonlocal pending_relay_stop
        if pending_relay_stop:
            raise RuntimeError('duplicate shutdown request while relay stop is pending')
        pending_relay_stop = True

    def start_relay_shutdown():
        nonlocal pending_relay_stop, stop_deadline
        if not pending_relay_stop:
            return
        if (broker_readiness_channel is None or not broker_readiness_channel.ready or
                broker_readiness_channel.stopped):
            raise RuntimeError('relay STOP arrived outside broker READY lifecycle')
        pending_relay_stop = False
        stop_deadline = time.monotonic() + ker_run_control.STOP_ACK_TIMEOUT
        broker_readiness_channel.begin_stop(ker_run_control.STOP_ACK_TIMEOUT)

    try:
        run_control = ker_run_control.KerRunControl.from_environment()
        if run_control is not None and (
                not args.broker_readiness or not args.runtime_service or
                args.rx_decision or control_nginx is not None):
            run_control._mark_unresolved('relay requires the C34 broker-readiness runtime profile')
            containment_unresolved = True
            raise ValueError('ker-run relay requires the C34 profile without RX-decision or Nginx companion')
        vlan_ipv6 = any(value.version == 6 for _, entries in args.vlans for value in entries)
        multicast_options = ['--all-multicast'] if args.all_multicast or args.address6 is not None or vlan_ipv6 else []
        promiscuous_options = [] if args.promiscuous is None else [
            '--promiscuous' if args.promiscuous else '--no-promiscuous']
        log_options = []
        if args.log_dir is not None:
            log_options += ['--log-dir', str(args.log_dir.resolve())]
        if args.log_level is not None:
            log_options += ['--log-level', str(args.log_level)]
        capture_options = []
        if args.pcap_dir is not None:
            capture_options = ['--pcap-dir', str(args.pcap_dir.resolve()),
                '--pcap-snaplen', str(args.pcap_snaplen), '--pcap-max-bytes', str(args.pcap_max_bytes)]
            if args.pcap_nsec:
                capture_options.append('--pcap-nsec')
        bond_options = []
        if args.bonds:
            bond_options = ['--bond-policy', ','.join(str(args.bonds[0][key]) for key in
                            ('lsc_poll_period_ms', 'up_delay', 'down_delay'))]
        exception_options = []
        if args.exception_iface is not None:
            exception_options = ['--exception-iface', args.exception_iface, '--exception-mode', args.exception_mode,
                '--exception-policy', args.exception_policy, '--exception-type', str(args.exception_type),
                '--exception-queue', str(args.exception_queue), '--exception-rate', str(args.exception_rate),
                '--exception-console-rate', str(args.exception_console_rate), '--exception-general-rate', str(args.exception_general_rate)]
            for name in ('tcp', 'udp'):
                value = getattr(args, 'exception_' + name + '_ports')
                if value is not None:
                    exception_options += ['--exception-' + name + '-ports', value]
        rx_lcore_options = ['--rx-lcores', args.rx_lcores] if args.rx_lcores is not None else []
        worker_command = [str(worker_path), '--packet-fd', str(channel_io.fileno()),
            '--tx-offloads', str(TX_OFFLOADS[args.tx_offloads]), *(['--rss'] if args.rss else []),
            '--queues', str(args.queues), '--mtu-fd', str(mtu_io.fileno()), '--max-mtu', str(args.max_mtu),
            '--control-fd', str(control_read), '--idle-sleep-us', str(args.idle_sleep_us),
            '--tx-delay-us', str(args.tx_delay_us), '--port', args.port, '--mtu', str(args.mtu),
            '--mbuf-mode', args.mbuf_mode, '--numa' if args.numa else '--no-numa',
            *multicast_options, *promiscuous_options, *capture_options, *log_options,
            *bond_options, *exception_options, *rx_lcore_options,
            *(['--rx-decision-fd', str(decision_io.fileno())] if args.rx_decision else []),
            *(['--queue-proof-session', decision_nonce.hex(), '--queue-proof-epoch',
                str(decision_epoch)] if source_shell_controller is not None or
                (control_nginx is not None and control_nginx[6]) else []),
            *(['--queue-proof-source-proc-id', '1'] if source_shell_controller is not None or
                (control_nginx is not None and control_nginx[6]) else []),
            '--', *args.eal_args]
        worker_pass_fds = [channel_io.fileno(), mtu_io.fileno(), control_read]
        if args.rx_decision:
            worker_pass_fds.append(decision_io.fileno())
        worker_env = {key: value for key, value in os.environ.items()
            if not key.startswith('KER_RUN_CONTROL_')}
        if source_shell_controller is not None:
            source_shell_controller.start()
            retained_backend_handoff = source_shell_controller.launch.backend_handoff
            command_separator = worker_command.index('--')
            worker_command = (worker_command[:command_separator + 1] +
                _source_shell_eal_args(args.eal_args,
                    source_shell_controller.launch.run_id))
        worker = subprocess.Popen(worker_command,
            env=worker_env, pass_fds=tuple(worker_pass_fds),
            stdout=subprocess.PIPE, text=True)
        if private_source_rx:
            worker_stdout_identity = _private_pipe_identity(worker.stdout.fileno())
        worker_start_ticks = process_start_ticks(worker.pid)
        channel_io.close()
        mtu_io.close()
        os.close(control_read)
        control_read = -1
        source_queue_proof = (source_shell_controller is not None or
            bool(control_nginx is not None and control_nginx[6]))
        if source_shell_controller is not None:
            worker_pidfd = _retain_worker_pidfd(worker, worker_pidfd)
            executable_hash = runtime_service.process_executable_hash(worker.pid)
            info = source_shell_controller.observe_native_io_ready(
                worker, worker_pidfd, executable_hash)
            ready = None
        else:
            ready = read_worker_startup(worker, 'DPDK worker')
        if ready is not None and not ready.startswith('KER_IO_READY '):
            # A worker that fails after EAL initialization can emit its cleanup
            # snapshot as the first line. Preserve it for --stats: communicate()
            # below cannot read this already-consumed line again.
            if ready.startswith('KER_IO_DONE '):
                stats = worker_done_record(ready)
            raise RuntimeError('DPDK worker failed before packet I/O became ready: ' + ready)
        configured_rx_lcores = ([int(item) for item in args.rx_lcores.split(',')]
            if args.rx_lcores is not None else None)
        expected_rx_owners = ((1,) if source_queue_proof else
            ([configured_rx_lcores[index % len(configured_rx_lcores)]
                for index in range(args.queues)] if configured_rx_lcores else None))
        if source_shell_controller is None:
            info = worker_ready_record(ready, expected_pid=worker.pid,
            expected_session=(decision_nonce.hex(), decision_epoch)
                if control_nginx is not None and control_nginx[6] else None,
            require_queue_proof=source_queue_proof,
            expected_port_id=0 if source_queue_proof else None,
            expected_queue_lcores=expected_rx_owners,
            expected_source_proc_id=1 if source_queue_proof else None,
            expected_queue_count=args.queues)
        app_command = args.command
        if args.broker_readiness:
            if (not args.runtime_service or
                    (args.rx_decision and not getattr(args,
                        'control_nginx_rx_relay', False))):
                raise ValueError('broker readiness requires the authenticated runtime-service actor profile')
        if args.rx_decision:
            worker_pidfd = _retain_worker_pidfd(worker, worker_pidfd)
            worker_identity = rx_decision_identity(worker.pid, worker_pidfd)
        if args.runtime_service:
            worker_pidfd = _retain_worker_pidfd(worker, worker_pidfd)
            app_executable = resolve_runtime_service_app_executable(
                args.command[0], os.environ.get('PATH'))
            # Pass the resolved ELF path through ker-app so hashing and the
            # eventual exec use the same file, including for bare PATH names.
            app_command = [str(app_executable), *args.command[1:]]
            if source_network_expected is not None:
                app_executable_pin = source_network_startup.PinnedExecutable(
                    app_executable, source_network_expected['deadline_ns'])
                app_executable_hash = app_executable_pin.sha256
                app_executable_identity = app_executable_pin.metadata
            else:
                # Keep the established legacy launch path and its single hash
                # operation unchanged when source-shell proof is not enabled.
                app_executable_hash = runtime_service.sha256_file(app_executable)
            runtime_service_directory = tempfile.mkdtemp(prefix='ker-runtime-service-')
            os.chmod(runtime_service_directory, 0o700)
            app_profile_hash = hashlib.sha256(
                b'ker-runtime-service/slim-primary/v1\0' + app_executable_hash).digest()
            runtime_service_server = runtime_service.RuntimeServiceSupervisor(
                Path(runtime_service_directory) / 'service.sock', worker,
                worker_pidfd, runtime_service.process_start_ticks(worker.pid),
                runtime_service.process_executable_hash(worker.pid), info,
                app_executable_hash, app_profile_hash, control_write)
            runtime_service_server.start()
        if args.broker_readiness:
            broker_readiness_channel = broker_readiness.BrokerReadiness(
                worker_path, info, runtime_service_server.worker_profile_hash)
            if run_control is not None:
                run_control.bind_runtime(broker_readiness_channel, worker,
                    worker_pidfd, worker_path, app_executable_hash)
        if _needs_nginx_companion(source_shell_controller, control_nginx):
            nginx_companion_binary, nginx_companion_config, nginx_companion_prefix, \
                nginx_companion_env, nginx_owner_ready_required, \
                nginx_source_bootstrap_required, _source_shell_profile = (
                    control_nginx[:7])
            if owner_relay_owner is not None:
                nginx_companion_env.update(
                    KER_NGINX_RX_OWNER_RELAY_SUPERVISOR_PID=str(os.getpid()),
                    KER_NGINX_RX_OWNER_RELAY_FD=str(owner_relay_owner.fileno()),
                    KER_NGINX_RX_OWNER_RELAY_NONCE=decision_nonce.hex(),
                    KER_NGINX_RX_OWNER_RELAY_EPOCH=str(decision_epoch))
            nginx_companion_server = nginx_companion.NginxCompanion(
                nginx_companion_binary, nginx_companion_config,
                nginx_companion_prefix, nginx_companion_env,
                owner_ready_required=nginx_owner_ready_required,
                source_bootstrap_required=nginx_source_bootstrap_required,
                rx_owner_relay_fd=(owner_relay_owner.fileno()
                    if owner_relay_owner is not None else None),
                candidate_slot_transfer_fd=(int(os.environ['KER_NGINX_CANDIDATE_SLOT_TRANSFER_FD'])
                    if nginx_companion_env.get('KER_NGINX_SOURCE_ADMISSION_RELAY') == '1'
                    else None))
        for interface in args.interfaces:
            extra_worker = AdditionalWorker(interface)
            additional.append(extra_worker)
            extra_worker.start(worker_path, args)
        env = {key: value for key, value in launch_environment.items()
            if not key.startswith(('LKL_', 'KER_PACKET_', 'KER_RUNTIME_SERVICE_',
                                   'KER_BROKER_', 'KER_RUN_CONTROL_'))}
        env.pop('KER_NGINX_CANDIDATE_SLOT_TRANSFER_FD', None)
        env.pop('KER_NGINX_CANDIDATE_SLOT_FD', None)
        env.update(KER_PRELOAD_LIBRARY=(env.pop('LD_PRELOAD') + ':' if env.get('LD_PRELOAD') else '') + str(library),
            KER_NATIVE_TX_FEATURES=str(info['tx_offload_features']), KER_RUN_FD=str(run_app.fileno()), KER_STARTUP_FD=str(startup_write), KER_SHUTDOWN_TIMEOUT_MS=str(args.shutdown_timeout_ms),
            KER_PACKET_CONTROL_FD=str(mtu_app.fileno()), KER_PACKET_MAX_MTU=str(args.max_mtu),
            KER_PACKET_FD=str(channel_app.fileno()), KER_PACKET_MTU=str(args.mtu), LKL_HIJACK_NET_IFTYPE='ker-channel',
            LKL_HIJACK_NET_IP=str(args.address.ip), LKL_HIJACK_NET_NETMASK_LEN=str(args.address.network.prefixlen),
            LKL_HIJACK_NET_MAC=info['mac'], LKL_HIJACK_OFFLOAD='0')
        if args.rx_decision:
            env['KER_RX_DECISION_FD'] = str(decision_app.fileno())
        if owner_relay_app is not None:
            env['KER_RX_OWNER_RELAY_FD'] = str(owner_relay_app.fileno())
            env['KER_RX_OWNER_AUTH_FD'] = str(owner_auth_app.fileno())
            env['KER_RX_OWNER_RELAY_SUPERVISOR_PID'] = str(os.getpid())
            env['KER_RX_OWNER_RELAY_SUPERVISOR_START_TICKS'] = str(
                process_start_ticks(os.getpid()))
            env['KER_RX_OWNER_RELAY_NONCE'] = decision_nonce.hex()
            env['KER_RX_OWNER_RELAY_EPOCH'] = str(decision_epoch)
        if runtime_service_server is not None:
            env.update(runtime_service_server.env)
        if broker_readiness_channel is not None:
            env.update(broker_readiness_channel.environment())
        synack_evidence_var = 'KER_NATIVE_TEST_SYNACK_FAILURE_OUTPUT'
        env.pop(synack_evidence_var, None)
        env.pop('KER_RX_OWNER_SOURCE_SUCCESSIVE_ENABLE', None)
        if private_source_rx:
            if source_shell_controller.profile.network_expectation.repeated:
                env['KER_RX_OWNER_SOURCE_SUCCESSIVE_ENABLE'] = '1'
            env['KER_BROKER_SOURCE_SHELL_LISTENER'] = '1'
            if (source_shell_controller.profile.artifact_capture.source_fault == 'synack_fail'):
                env[synack_evidence_var] = source_shell_controller.profile.output
        if additional:
            env['KER_PACKET_INTERFACES'] = ';'.join(extra.native_settings() for extra in additional)
        env.pop('KER_NATIVE_VLANS', None)
        if args.vlans:
            env['KER_NATIVE_VLANS'] = ';'.join(str(tag) + '=' + ','.join(map(str, addresses))
                                               for tag, addresses in args.vlans)
        env.pop('KER_NATIVE_VLAN_GATEWAY', None)
        if args.vlan_gateways:
            tag, gateway = args.vlan_gateways[0]
            env['KER_NATIVE_VLAN_GATEWAY'] = f'{tag}={gateway}'
        env.pop('KER_NATIVE_VLAN_GATEWAY6', None)
        if args.vlan_gateways6:
            tag, gateway = args.vlan_gateways6[0]
            env['KER_NATIVE_VLAN_GATEWAY6'] = f'{tag}={gateway}'
        env.pop('KER_NATIVE_GATEWAY6', None)
        if args.gateway6 is not None:
            env['KER_NATIVE_GATEWAY6'] = str(args.gateway6)
        env.pop('KER_NATIVE_ADDRESS6', None)
        if args.address6 is not None:
            env['KER_NATIVE_ADDRESS6'] = str(args.address6)
        env.pop('KER_NATIVE_VIP_ADDRESSES6', None)
        if args.vip_addresses6:
            env['KER_NATIVE_VIP_ADDRESSES6'] = ','.join(map(str, args.vip_addresses6))
        env.pop('KER_NATIVE_VIP_ADDRESSES', None)
        if args.vip_addresses:
            env['KER_NATIVE_VIP_ADDRESSES'] = ','.join(map(str, args.vip_addresses))
        env.pop('KER_NATIVE_SYSCTLS', None)
        if args.sysctls:
            env['KER_NATIVE_SYSCTLS'] = '\n'.join(key + '=' + value for key, value in args.sysctls.items())
        env.pop('KER_NATIVE_TCP_ECN', None)
        if args.tcp_ecn is not None:
            env['KER_NATIVE_TCP_ECN'] = str(TCP_ECN[args.tcp_ecn])
        if args.gateway:
            env['LKL_HIJACK_NET_GATEWAY'] = str(args.gateway)
        app_pass_fds = [channel_app.fileno(), mtu_app.fileno(), startup_write, run_app.fileno(),
            *(fd for extra in additional for fd in extra.app_fds())]
        if args.rx_decision:
            app_pass_fds.append(decision_app.fileno())
        if owner_relay_app is not None:
            app_pass_fds.append(owner_relay_app.fileno())
            app_pass_fds.append(owner_auth_app.fileno())
        if broker_readiness_channel is not None:
            app_pass_fds.append(broker_readiness_channel.child_fd())
        app = subprocess.Popen([str(app_guard), *app_command], env=env,
            pass_fds=tuple(app_pass_fds))
        source_app_start_ticks = (process_start_ticks(app.pid)
            if source_network_expected is not None else None)
        if source_shell_controller is not None and owner_relay_app is not None:
            # The child has inherited the app endpoint. Retain only the SDK
            # duplicate used for APP_AUTH until that send; otherwise an SDK
            # copy would keep the worker peer alive after the app exits.
            owner_relay_app.close()
            owner_relay_app = None
        if owner_auth_app is not None:
            owner_auth_app.close()
            owner_auth_app = None
        if broker_readiness_channel is not None:
            broker_readiness_channel.child_started(app,
                runtime_service_server.app_executable_hash)
        if runtime_service_server is not None:
            runtime_actor_pidfd = os.pidfd_open(app.pid, 0)
            runtime_service_server.bind_actor(app, runtime_actor_pidfd)
        if args.rx_decision:
            app_pidfd = os.pidfd_open(app.pid, 0)
            app_identity = rx_decision_identity(app.pid, app_pidfd)
            if private_source_rx:
                _bind_private_runtime_app(source_shell_controller, app, app_pidfd,
                    source_app_start_ticks, run_channel=run_parent)
            # Worker-side bootstrap first: the worker must know the consumer
            # identity before the consumer can send HELLO. Then give the app
            # the worker identity so its HELLO is authenticated.
            rx_decision_bootstrap(decision_app, rx_decision_wire.TARGET_CONSUMER,
                app_identity, supervisor_identity, supervisor_pidfd,
                decision_nonce, decision_epoch)
            rx_decision_bootstrap(decision_io, rx_decision_wire.TARGET_WORKER,
                worker_identity, supervisor_identity, supervisor_pidfd,
                decision_nonce, decision_epoch)
            decision_app.close(); decision_app = None
            decision_io.close(); decision_io = None
        channel_app.close()
        mtu_app.close()
        run_app.close()
        for extra in additional:
            extra.close_app_channels()
        os.close(startup_write)
        startup_write = -1
        if source_network_expected is not None:
            if (runtime_actor_pidfd < 0 or app_executable_hash is None or
                    app_executable_identity is None or app_executable_pin is None or
                    source_app_start_ticks is None):
                raise RuntimeError('source startup lacks captured app pidfd/executable identity')
            def source_app_identity():
                poller = select.poll()
                poller.register(runtime_actor_pidfd,
                    select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL)
                if poller.poll(0) or app.poll() is not None:
                    raise RuntimeError('source startup application exited before proof validation')
                if process_start_ticks(app.pid) != source_app_start_ticks:
                    raise RuntimeError('source startup application PID was reused')
                if not source_network_startup.process_executable_matches(
                        app.pid, app_executable_pin,
                        source_network_expected['deadline_ns']):
                    return False
                if poller.poll(0) or app.poll() is not None:
                    raise RuntimeError('source startup application exited during identity check')
                if process_start_ticks(app.pid) != source_app_start_ticks:
                    raise RuntimeError('source startup application PID changed during identity check')
                return True

            while not source_app_identity():
                remaining_ns = source_network_expected['deadline_ns'] - time.monotonic_ns()
                if remaining_ns <= 0:
                    raise TimeoutError('source app did not reach its pinned executable before deadline')
                time.sleep(min(0.005, remaining_ns / 1_000_000_000))
            startup_status = source_network_startup.read_startup_prefix(
                startup_read, source_startup_pipe_identity,
                source_network_expected['deadline_ns'])
            parsed_source_startup = source_network_startup.parse_startup_prefix(
                startup_status, source_network_expected)
            if not source_app_identity():
                raise RuntimeError('source app executable changed during startup proof read')
            if source_network_startup.pipe_identity(startup_read) != source_startup_pipe_identity:
                raise RuntimeError('source startup pipe changed during proof validation')
            validated_monotonic_ns = time.monotonic_ns()
            if validated_monotonic_ns >= source_network_expected['deadline_ns']:
                raise TimeoutError('source startup validation completed after its immutable deadline')
            source_startup_audit = source_network_startup.startup_audit_record(
                parsed_source_startup, source_startup_pipe_identity, app.pid,
                source_app_start_ticks, app_executable_pin,
                validated_monotonic_ns, source_network_expected['deadline_ns'])
            if retained_backend_handoff is not None:
                retained_backend_receipt = source_network_startup._capture_retained_backend_receipt(
                    app, runtime_actor_pidfd, source_app_start_ticks,
                    app_executable_pin, startup_read, source_startup_pipe_identity,
                    source_network_expected, parsed_source_startup,
                    validated_monotonic_ns, runtime_service_server)
                retained_backend_receipt.validate_live(source_network_expected,
                    retained_backend_receipt.actor_identity,
                    source_network_expected['deadline_ns'])
                retained_backend_handoff.publish(retained_backend_receipt)
                retained_backend_transferred = True
                retained_backend_receipt = None
        runtime_actor = (SimpleNamespace(pid=app.pid, pidfd=runtime_actor_pidfd,
            start_ticks=source_app_start_ticks, executable_hash=app_executable_hash)
            if source_shell_controller is not None else None)
        startup_status = _finish_initial_backend_startup(source_network_expected,
            source_shell_controller, runtime_actor, startup_read, startup_status,
            broker_readiness_channel)
        if source_shell_controller is not None:
            if (owner_relay_owner is None or owner_auth_supervisor is None or
                    broker_readiness_channel is None or runtime_actor_pidfd < 0):
                raise RuntimeError('initial source owner binding lacks retained C31/C34 endpoints')

            def authenticate_initial_source_owner(owner_view, authority_deadline_ns):
                rx_owner_expected_auth(owner_auth_supervisor, app, runtime_actor_pidfd,
                    supervisor_pidfd, owner_view, decision_nonce, decision_epoch,
                    process_start_ticks(os.getpid()), authority_deadline_ns)
                rx_owner_relay_auth(owner_relay_app_auth, app, runtime_actor_pidfd,
                    supervisor_pidfd, owner_view, decision_nonce, decision_epoch,
                    authority_deadline_ns)

            def revoke_initial_source_owner():
                if broker_readiness_channel.stopped:
                    return
                if (not broker_readiness_channel.ready or
                        time.monotonic_ns() >= source_shell_controller.deadline_ns):
                    raise RuntimeError('initial source AUTH revoke lacks a live bounded C34 STOP path')
                if getattr(broker_readiness_channel, '_stop', None) is None:
                    if broker_readiness_channel.stop_attempted:
                        raise RuntimeError('initial source C34 STOP was already attempted without settlement')
                    remaining_ns = source_shell_controller.deadline_ns - time.monotonic_ns()
                    broker_readiness_channel.begin_stop(remaining_ns / 1_000_000_000)
                source_shell_controller.unresolved = True

            source_shell_controller.bind_initial_worker_transport(
                broker_readiness_channel, owner_relay_owner, owner_relay_app_auth,
                owner_auth_supervisor,
                app, runtime_actor_pidfd, supervisor_pidfd, decision_nonce,
                decision_epoch, authenticate_initial_source_owner,
                revoke_initial_source_owner)
        if args.rx_decision:
            try:
                if source_shell_controller is None:
                    startup_status = wait_startup_marker(startup_read, startup_status,
                        b'KER_RX_DECISION_READY\n', 20,
                        'RX decision consumer (handler/identity/worker handshake)')
                else:
                    startup_status = source_shell_controller.wait_startup_marker(
                        startup_read, startup_status, b'KER_RX_DECISION_READY\n', 20,
                        'RX decision consumer (handler/identity/worker handshake)',
                        app, runtime_actor_pidfd, broker_readiness_channel)
            except RuntimeError as error:
                if (source_shell_controller is not None and
                        isinstance(error, _load_source_shell_controller().SourceStartupMarkerError)):
                    startup_status = error.startup_bytes
                    raise
                raise RuntimeError(f'{error}; application poll status={app.poll()}') from error
        def release_private_worker(deadline):
            nonlocal control_write
            if control_write < 0 or runtime_service_server is None:
                raise RuntimeError('private run STOP lost the held I/O control writer or runtime service')
            if not runtime_service_server.prepare_worker_shutdown(
                    _private_shutdown_remaining(deadline)):
                raise RuntimeError('private run STOP could not release the I/O worker lease')
            _private_shutdown_remaining(deadline)
            os.close(control_write)
            control_write = -1

        stopping_at = None
        while True:
            try:
                if (source_shell_controller is not None and app.poll() is None and
                        not (private_source_rx and
                            source_shell_controller._private_stop_ack_receipt is not None)):
                    source_shell_controller.pump_source_requests(broker_readiness_channel)
                if (private_source_rx and not run_finished and
                        source_shell_controller._private_stop_ack_receipt is not None and
                        app.poll() is None):
                    startup_status, stats = collect_and_settle_private_shutdown(
                        release_worker=release_private_worker)
                    stats.update(run_shutdown=True, run_shutdown_workers=1, run_shutdown_ack=True)
                    worker_finished = run_finished = startup_eof = True
                if stop_deadline is not None and time.monotonic() >= stop_deadline:
                    raise TimeoutError('broker-requested native shutdown timed out')
                if run_control is not None:
                    run_control.poll(request_relay_shutdown)
                    start_relay_shutdown()
                    if broker_readiness_channel.stopped:
                        stop_deadline = None
                stop_broker_for_signal()
                if private_source_rx and run_finished:
                    app_returncode = app.returncode
                elif (source_shell_controller is not None and
                        source_shell_controller.bootstrap_context is not None):
                    worker_ready = source_shell_controller.wait_source_worker(
                        0.25, runtime_actor_pidfd)
                    if worker_ready and app.poll() is None:
                        source_shell_controller.pump_source_requests(
                            broker_readiness_channel)
                    app_returncode = app.poll()
                    if app_returncode is None:
                        continue
                else:
                    app_returncode = app.wait(timeout=0.25)
                if app_returncode and os.environ.get('KER_LINUX_SELFTEST_REPORT_EXIT') == '1':
                    print(f'ker-run: original selftest kernel owner exit status {app_returncode}', file=sys.stderr)
                if preserve_signal:
                    if app_returncode != 0:
                        infrastructure_failure = True
                    exit_code = signal_exit_code
                else:
                    exit_code = app_returncode
                # ker_posix_run can queue an authenticated private STOP_ACK
                # immediately before the bound app exits.  Drain it with the
                # broker's existing single reader and original PREEXIT
                # deadline before enforcing the READY/STOP lifecycle below.
                if (source_shell_controller is not None and
                        broker_readiness_channel is not None and
                        not broker_readiness_channel.stopped):
                    private_stop = getattr(broker_readiness_channel, '_stop', None)
                    private_authorization = getattr(
                        broker_readiness_channel, '_private_stop_authorization', None)
                    if (private_stop is not None and private_stop.get('private') is True and
                            private_stop.get('sent') is True and private_authorization is not None):
                        while not broker_readiness_channel.stopped:
                            source_shell_controller.poll_private_stop_after_app_exit(
                                broker_readiness_channel)
                            if broker_readiness_channel.stopped:
                                break
                            if time.monotonic_ns() >= private_authorization.deadline_ns:
                                raise TimeoutError(
                                    'private broker STOP_ACK was not received before the PREEXIT deadline')
                            time.sleep(0.001)
                stop_broker_for_signal()
                if run_control is not None and run_control.state == 'STOP_PENDING':
                    while run_control.state == 'STOP_PENDING':
                        run_control.poll(request_relay_shutdown)
                        if run_control.state == 'STOP_PENDING':
                            if (run_control.stop is None or
                                    time.monotonic() >= run_control.stop['deadline']):
                                raise TimeoutError('relay STOP acceptance timed out after app exit')
                            time.sleep(0.001)
                if (broker_readiness_channel is not None and
                        (not broker_readiness_channel.ready or
                         not broker_readiness_channel.stopped)):
                    raise RuntimeError('broker application exited outside authenticated READY/STOP lifecycle')
                if run_control is not None and run_control.state != 'STOP_ACCEPTED':
                    raise RuntimeError('broker application exited before relay STOP was accepted')
                if exit_code < 0:
                    preserve_signal = True
                elif not run_finished:
                    if not private_source_rx:
                        startup_status = drain_startup_status(startup_read, startup_status)
                    failure = unexpected_additional_worker_exit(additional)
                    if failure:
                        exit_code = 125
                        raise RuntimeError(failure)
                    if worker.poll() is not None:
                        if not private_source_rx and b'KER_NATIVE_STOPPING\n' not in startup_status:
                            exit_code = 125
                            raise RuntimeError('DPDK worker stopped while the application was running')
                        if not private_source_rx and not normal_native_shutdown_markers(startup_status):
                            exit_code = 125
                            raise RuntimeError('DPDK worker stopped with invalid native shutdown marker sequence')
                        if private_source_rx:
                            startup_status, stats = collect_and_settle_private_shutdown()
                            startup_eof = True
                            failed = worker.returncode != 0
                        else:
                            stats, failed = collect_worker(worker, stats)
                        worker_finished = True
                        infrastructure_failure |= failed or stats is None or stats.get('outstanding', 1) != 0
                    else:
                        failure = unexpected_worker_exit(worker, additional)
                        if failure:
                            exit_code = 125
                            raise RuntimeError(failure)
                if run_control is not None:
                    if (run_control.state != 'STOP_ACCEPTED' or not run_finished or
                            not worker_finished or app.returncode != 0 or
                            worker.returncode != 0 or stats is None or
                            stats.get('outstanding') != 0 or
                            not stats.get('control_eof') or
                            not normal_native_shutdown_markers(startup_status)):
                        run_control._mark_unresolved(
                            'native worker/app shutdown did not prove relay settlement')
                        containment_unresolved = True
                        infrastructure_failure = True
                        raise RuntimeError('native worker/app shutdown did not prove relay settlement')
                    run_control.send_settled(app.returncode, worker.returncode,
                        stats['outstanding'], ker_run_control.SETTLED_FLAGS)
                    while not run_control.flush_settled():
                        time.sleep(0.001)
                    run_control.close_after_settled()
                break
            except subprocess.TimeoutExpired as error:
                if private_source_rx:
                    raise TimeoutError('private source runtime actor wait exceeded its deadline') from error
                if stop_deadline is not None and time.monotonic() >= stop_deadline:
                    raise TimeoutError('broker-requested native shutdown timed out')
                stop_broker_for_signal()
                if broker_readiness_channel is not None and not broker_readiness_channel.ready:
                    if (broker_readiness_channel.poll_ready() and
                            nginx_companion_server is not None):
                        nginx_companion_server.start()
                        if owner_auth_supervisor is not None:
                            rx_owner_expected_auth(owner_auth_supervisor, app, app_pidfd,
                                supervisor_pidfd, nginx_companion_server,
                                decision_nonce, decision_epoch,
                                process_start_ticks(os.getpid()))
                            owner_auth_supervisor.close()
                            owner_auth_supervisor = None
                        if owner_relay_owner is not None:
                            owner_relay_owner.close()
                            owner_relay_owner = None
                        if owner_relay_app is not None:
                            rx_owner_relay_auth(owner_relay_app, app, app_pidfd,
                                supervisor_pidfd,
                                nginx_companion_server, decision_nonce, decision_epoch)
                            owner_relay_app.close()
                            owner_relay_app = None
                        if nginx_companion_server.owner_ready_required:
                            print('KER_NGINX_OWNER_READY ' + json.dumps({
                                'pid': nginx_companion_server.owner_pid,
                                'start_ticks': nginx_companion_server.owner_start,
                                'tid': nginx_companion_server.owner_tid,
                                'role': nginx_companion_server.owner_role,
                                'slot_device': nginx_companion_server.owner_slot_device,
                                'slot_inode': nginx_companion_server.owner_slot_inode,
                                'cookie': nginx_companion_server.owner_cookie,
                                'master_pid': nginx_companion_server.master_pid,
                                'master_start_ticks': nginx_companion_server.master_start,
                                'source': 'authenticated-C22-worker-READY'},
                                sort_keys=True, separators=(',', ':')), flush=True)
                if run_control is not None:
                    run_control.poll(request_relay_shutdown)
                    start_relay_shutdown()
                    run_control.poll(request_relay_shutdown)
                    if broker_readiness_channel.stopped:
                        stop_deadline = None
                if _COMPANION_RELOAD_REQUESTED:
                    _COMPANION_RELOAD_REQUESTED = False
                    if nginx_companion_server is None or not nginx_companion_server.started:
                        raise RuntimeError('Nginx reload requested before companion master readiness')
                    nginx_companion_server.reload()
                if nginx_companion_server is not None:
                    nginx_companion_server.check()
                if not private_source_rx:
                    try:
                        startup_status += os.read(startup_read, 4096)
                    except BlockingIOError:
                        pass
                try:
                    request = run_parent.recv(64)
                except BlockingIOError:
                    request = None
                if request:
                    if request != b'KER_RUN_STOP\n' or run_finished:
                        raise RuntimeError('invalid native run shutdown request')
                    startup_status = _validate_run_stop_request(startup_read,
                        startup_status, private_source_rx)
                    if (nginx_companion_server is not None and
                            nginx_companion_server.started and
                            not nginx_companion_server.settled):
                        containment_unresolved = True
                        raise RuntimeError('native runtime finished before companion SETTLED')
                    lease_release_ok = True
                    if runtime_service_server is not None:
                        lease_release_ok = runtime_service_server.prepare_worker_shutdown(1.0)
                        if not lease_release_ok:
                            print('ker-run: runtime-service lease was not released before worker shutdown',
                                file=sys.stderr)
                    os.close(control_write)
                    control_write = -1
                    for extra in additional:
                        extra.stop_channels()
                    operations = [lambda: collect_worker(worker, stats)]
                    operations.extend(extra.finish for extra in additional)
                    reaped = finish_concurrently(operations)
                    worker_finished = True
                    failed = not lease_release_ok
                    if not isinstance(reaped[0], Exception):
                        stats, worker_failed = reaped[0]
                        failed |= worker_failed
                    for result in reaped[1:]:
                        failed |= result if isinstance(result, bool) else True
                    if not normal_native_shutdown_markers(startup_status):
                        print('ker-run: invalid native run shutdown marker sequence', file=sys.stderr)
                        failed = True
                    failed |= stats is None or stats.get('outstanding', 1) != 0
                    if stats is not None:
                        stats['run_shutdown'] = True
                        stats['run_shutdown_workers'] = 1 + len(additional)
                        stats['run_shutdown_ack'] = not failed
                    infrastructure_failure |= failed
                    run_finished = True
                    run_parent.send(b'FAIL\n' if failed else b'OK\n')
                if b'KER_NATIVE_STOPPING\n' in startup_status and not run_finished:
                    if (nginx_companion_server is not None and
                            nginx_companion_server.started and
                            not nginx_companion_server.settled):
                        containment_unresolved = True
                        raise RuntimeError('native shutdown began before companion SETTLED')
                    failure = unexpected_additional_worker_exit(additional)
                    if failure:
                        raise RuntimeError(failure)
                    if stopping_at is None:
                        stopping_at = time.monotonic()
                    if time.monotonic() - stopping_at > 5:
                        raise RuntimeError('native kernel teardown timed out')
                else:
                    if not run_finished:
                        failure = unexpected_worker_exit(worker, additional)
                        if failure:
                            raise RuntimeError(failure)
    except (KeyboardInterrupt, Interrupted) as interruption:
        preserve_signal = True
        signum = interruption.signum if isinstance(interruption, Interrupted) else signal.SIGINT
        exit_code = 128 + signum
        if run_control is not None and run_control.state not in (
                'STARTING', 'SETTLED', 'FAILED'):
            run_control._mark_unresolved('local shutdown signal arrived without relay settlement')
            containment_unresolved = True
            infrastructure_failure = True
        elif (nginx_companion_server is not None and nginx_companion_server.unresolved):
            containment_unresolved = True
            infrastructure_failure = True
        elif broker_readiness_channel is not None and broker_readiness_channel.ready and app and app.poll() is None:
            try:
                if nginx_companion_server is not None and nginx_companion_server.started:
                    nginx_companion_server.stop()
                broker_readiness_channel.stop()
                app.wait(timeout=10)
                if app.returncode != 0:
                    raise RuntimeError(f'broker application exited with status {app.returncode} after STOP')
                if private_source_rx:
                    raise RuntimeError('private shutdown bytes remain assigned to the held collector')
                startup_status = drain_startup_status(startup_read, startup_status)
                if not normal_native_shutdown_markers(startup_status):
                    raise RuntimeError('broker STOP did not produce normal native shutdown markers')
            except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
                infrastructure_failure = True
                if nginx_companion_server is not None:
                    containment_unresolved = True
                print(f'ker-run: broker STOP failed: {error}', file=sys.stderr)
        elif app and app.poll() is None:
            app.send_signal(signum)
            try:
                app.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
    except (OSError, ValueError, RuntimeError, struct.error) as error:
        print(f'ker-run: {error}', file=sys.stderr)
        if broker_readiness_channel is not None:
            infrastructure_failure = True
        if run_control is not None and run_control.state not in ('SETTLED', 'FAILED'):
            run_control._mark_unresolved(str(error))
            containment_unresolved = True
            infrastructure_failure = True
    finally:
        if (retained_backend_handoff is not None and
                not retained_backend_transferred):
            retained_backend_handoff.fail(RuntimeError(
                'backend startup did not transfer a validated receipt'))
        if (nginx_companion_server is not None and
                (nginx_companion_server.unresolved or
                 (nginx_companion_server.started and not nginx_companion_server.settled))):
            containment_unresolved = True
        if run_control is not None and run_control.unresolved:
            containment_unresolved = True
        if (source_shell_controller is not None and source_shell_controller.launch is not None and
                not (private_source_rx and containment_unresolved)):
            try:
                _settle_source_shell_actors(source_shell_controller,
                    runtime_service_server, broker_readiness_channel, app, worker)
            except (OSError, RuntimeError, TimeoutError, ValueError,
                    subprocess.TimeoutExpired) as error:
                print(f'ker-run: source-shell actor settlement failed: {error}',
                    file=sys.stderr)
                source_shell_controller.unresolved = True
                containment_unresolved = True
        if containment_unresolved:
            if c34_test_capture is not None:
                raise RuntimeError('C34 test fixture did not settle before namespace teardown')
            print('ker-run: supervised source/companion shutdown UNRESOLVED; retaining native broker and worker resources',
                file=sys.stderr)
            while True:
                try:
                    signal.pause()
                except Interrupted:
                    break
            infrastructure_failure = True
        if nginx_companion_server is not None:
            nginx_companion_server.close()
        for endpoint in (owner_relay_app, owner_relay_owner, owner_relay_app_auth,
                owner_auth_app, owner_auth_supervisor):
            if endpoint is not None:
                try:
                    endpoint.close()
                except OSError:
                    pass
        if app and app.poll() is None:
            app.terminate()
            try:
                app.wait(timeout=5)
            except subprocess.TimeoutExpired:
                app.kill()
                app.wait()
        if retained_backend_receipt is not None:
            try:
                retained_backend_receipt.close()
            except (OSError, RuntimeError) as error:
                print(f'ker-run: retained backend receipt cleanup: {error}', file=sys.stderr)
                infrastructure_failure = True
        if runtime_service_server is not None:
            if runtime_service_server.active_count:
                infrastructure_failure = True
                runtime_service_server.revoke('ker-run explicit shutdown')
            runtime_service_server.close()
            runtime_service_server = None
        if runtime_service_directory is not None:
            try:
                os.rmdir(runtime_service_directory)
            except OSError as error:
                print(f'ker-run: runtime-service directory cleanup: {error}', file=sys.stderr)
                infrastructure_failure = True
            runtime_service_directory = None
        if app_executable_pin is not None and not private_source_rx:
            app_executable_pin.close()
            app_executable_pin = None
        if broker_readiness_channel is not None and not private_source_rx:
            broker_readiness_channel.close()
            broker_readiness_channel = None
        channel_app.close()
        channel_io.close()
        mtu_app.close()
        mtu_io.close()
        if decision_app is not None:
            decision_app.close()
        if decision_io is not None:
            decision_io.close()
        if control_read >= 0:
            os.close(control_read)
        if control_write >= 0:
            os.close(control_write)
        run_parent.close()
        run_app.close()
        if not private_source_rx:
            while True:
                try:
                    extra = os.read(startup_read, 1024)
                    if not extra:
                        break
                    startup_status += extra
                except BlockingIOError:
                    break
                except OSError as error:
                    print(f'ker-run: startup status drain: {error}', file=sys.stderr)
                    infrastructure_failure = True
                    break
        if source_shell_controller is None:
            os.close(startup_read)
        if (not private_source_rx and app and b'KER_NATIVE_READY\n' in startup_status and
                b'KER_NATIVE_DONE\n' not in startup_status):
            print('ker-run: native Linux shutdown did not complete', file=sys.stderr)
            infrastructure_failure = True
        if startup_write >= 0:
            os.close(startup_write)
        for extra in additional:
            extra.stop_channels()
        if worker:
            if not worker_finished:
                try:
                    if private_source_rx:
                        startup_status, stats = collect_and_settle_private_shutdown()
                        startup_eof = True
                        failed = worker.returncode != 0
                    else:
                        stats, failed = collect_worker(worker, stats)
                    infrastructure_failure |= failed
                except (OSError, ValueError, RuntimeError) as error:
                    print(f'ker-run: primary worker collection: {error}', file=sys.stderr)
                    infrastructure_failure = True
                    stats = None
                    # A failed read must not leave a live child or prevent the
                    # auxiliary workers from reaching their own teardown.
                    try:
                        if worker.poll() is None:
                            worker.kill()
                        worker.wait(timeout=10)
                    except (OSError, subprocess.TimeoutExpired) as reap_error:
                        print(f'ker-run: primary worker reap: {reap_error}', file=sys.stderr)
                    finally:
                        if (worker.stdout is not None and not (private_source_rx and
                                getattr(source_shell_controller,
                                    '_private_shutdown_collection_attempted', False))):
                            worker.stdout.close()
            if source_shell_controller is not None and startup_read >= 0:
                retain_private_streams = (private_source_rx and
                    getattr(source_shell_controller,
                        '_private_shutdown_collection_failed', False))
                if not startup_eof and not retain_private_streams:
                    while True:
                        try:
                            extra = os.read(startup_read, 1024)
                            if not extra:
                                startup_eof = True
                                break
                            startup_status += extra
                        except BlockingIOError:
                            break
                        except OSError as error:
                            print(f'ker-run: source startup EOF check: {error}', file=sys.stderr)
                            infrastructure_failure = True
                            break
                if not retain_private_streams:
                    os.close(startup_read)
                    startup_read = -1
                if not startup_eof:
                    print('ker-run: source startup pipe did not reach EOF after actor exit',
                        file=sys.stderr)
                    infrastructure_failure = True
            infrastructure_failure |= stats is None or stats.get('outstanding', 1) != 0
            if args.rx_decision:
                infrastructure_failure |= (stats is None or
                    stats.get('rx_decision_enabled') is not True or
                    stats.get('rx_decision_settled') is not True)
            if stats is not None:
                stats['io'] = info
                if source_startup_audit is not None:
                    stats['source_network_startup'] = source_startup_audit
            try:
                native = native_statistics(startup_status)
                if native is not None and stats is not None:
                    stats['native'] = native
            except (ValueError, UnicodeError) as error:
                print(f'ker-run: native statistics: {error}', file=sys.stderr)
                infrastructure_failure = True
            results = finish_concurrently([extra.finish for extra in additional]) if additional else []
            for result in results:
                if isinstance(result, Exception):
                    print(f'ker-run: additional worker cleanup: {result}', file=sys.stderr)
                    infrastructure_failure = True
                else:
                    infrastructure_failure |= result
            if stats is not None and additional:
                stats['interfaces'] = [extra.stats for extra in additional]
                stats['worker_pid'] = worker.pid
            if args.stats and stats:
                try:
                    write_statistics(args.stats, stats)
                except (OSError, ValueError, TypeError) as error:
                    print(f'ker-run: statistics output: {error}', file=sys.stderr)
                    infrastructure_failure = True
        if private_source_rx:
            try:
                if worker is None or stats is None or worker_start_ticks is None:
                    raise ValueError('held I/O worker identity or DONE record is missing')
                collection = getattr(source_shell_controller,
                    '_private_shutdown_collection_receipt', None)
                context = source_shell_controller.bootstrap_context
                if type(collection) is _PrivateShutdownCollectionReceipt:
                    retained_io = _private_io_done_record(collection.io_stdout)
                    stop = collection.stop_receipt
                    pending = stop.authorization.pending
                    settlement = getattr(source_shell_controller, '_private_source_settlement', None)
                    settled = (source_shell_controller.broker_readiness.private_stop_ack_receipt(
                            stop.authorization) is stop and settlement is not None and
                        context._completed_retirements.get(pending.key) is settlement and
                        settlement.operation_id == pending.operation_id and
                        settlement.broker_stop_sha256 ==
                            hashlib.sha256(collection.stop_receipt.raw_ack).digest())
                else:
                    retained_io = None
                    settled = False
                if (type(collection) is not _PrivateShutdownCollectionReceipt or
                        getattr(source_shell_controller,
                            '_private_shutdown_collection_failed', True) is not False or
                        collection.controller is not source_shell_controller or
                        collection.context is not context or
                        getattr(context, '_private_shutdown_collections', {}).get(
                            id(source_shell_controller)) is not collection or
                        collection.stop_receipt is not getattr(source_shell_controller,
                            '_private_stop_ack_receipt', None) or
                        collection.app_anchor is not getattr(source_shell_controller,
                            '_private_runtime_app_anchor', None) or
                        collection.backend_receipt is not getattr(
                            source_shell_controller.launch, 'backend_receipt', None) or
                        collection.io_ready_proof is not getattr(
                            source_shell_controller.launch, 'native_io_ready', None) or
                        collection.backend_receipt.closed is not False or
                        collection.backend_receipt.process is not app or
                        collection.backend_receipt.start_ticks != source_app_start_ticks or
                        not collection.startup_status.startswith(
                            collection.backend_receipt.prefix) or
                        _private_pipe_identity(collection.backend_receipt.startup_fd) !=
                            collection.startup_identity or
                        collection.io_ready_proof.process is not worker or
                        collection.io_ready_proof.start != worker_start_ticks or
                        _private_pipe_identity(
                            source_shell_controller.launch.native_io_stdout_fd) !=
                                collection.io_stdout_identity or
                        not settled or
                        collection.startup_status != startup_status or
                        collection.parsed.get('io') != _freeze_private_value(retained_io) or
                        any(stats.get(key) != retained_io.get(key) for key in
                            ('outstanding', 'rx_decision_last_settled_packet_id',
                             'rx_decision_enabled', 'rx_decision_settled', 'control_eof')) or
                        collection.io_executable_hash != getattr(
                            source_shell_controller.io_actor, 'executable_hash', None) or
                        collection.app_identity != getattr(
                            source_shell_controller.broker_readiness, 'app', None) or
                        collection.startup_identity != source_startup_pipe_identity or
                        collection.worker_identity != (worker.pid, os.getuid(), os.getgid(),
                            worker_start_ticks) or collection.collected_ns >=
                            getattr(getattr(collection.stop_receipt, 'authorization', None),
                                'deadline_ns', -1)):
                    raise PermissionError('private shutdown collection receipt lost its held registry joins')
                final_c31 = private_c31_shutdown_record(startup_status, stats,
                    worker_identity=(worker.pid, os.getuid(), os.getgid(), worker_start_ticks),
                    supervisor_identity=(os.getpid(), os.getuid(), os.getgid(),
                        supervisor_start_ticks), nonce=decision_nonce, epoch=decision_epoch)
                if (final_c31 != collection.parsed.get('c31') or
                        collection.supervisor_identity != (os.getpid(), os.getuid(),
                            os.getgid(), supervisor_start_ticks) or
                        collection.io_stdout_identity != worker_stdout_identity or
                        collection.parsed.get('native') != native_statistics(startup_status)):
                    raise PermissionError('private shutdown collector receipt fields changed')
                private_shutdown_receipt_valid = True
            except (OSError, RuntimeError, ValueError, TypeError, UnicodeError) as error:
                print(f'ker-run: private C31 shutdown receipt: {error}', file=sys.stderr)
                private_shutdown_receipt_valid = False
        retain_private_anchors = (private_source_rx and getattr(
            source_shell_controller, '_private_shutdown_collection_failed', False))
        if not retain_private_anchors:
            for pidfd in (supervisor_pidfd, worker_pidfd, app_pidfd, runtime_actor_pidfd):
                if pidfd >= 0:
                    os.close(pidfd)
        if app_executable_pin is not None:
            app_executable_pin.close()
            app_executable_pin = None
        if broker_readiness_channel is not None:
            broker_readiness_channel.close()
            broker_readiness_channel = None
        if source_shell_controller is not None and source_shell_controller.launch is not None:
            if (worker is None or app is None or app.returncode != 0 or
                    worker.returncode != 0 or
                    not private_shutdown_receipt_valid or
                    not source_shutdown_evidence(startup_status, startup_eof, stats)):
                print('ker-run: source actors remain retained; native broker/C31/IO settlement is unverified',
                    file=sys.stderr)
                source_shell_controller.unresolved = True
                infrastructure_failure = True
                while True:
                    try:
                        signal.pause()
                    except Interrupted:
                        break
            try:
                # The private PREEXIT already joins the original supervisor's
                # TERM. Let it finish recording the shell verdict and reaping.
                settlement = source_shell_controller.stop_original(
                    request_stop=not private_source_rx)
                if private_source_rx and exit_code == 0:
                    exit_code = settlement['result']
            except (OSError, RuntimeError, TimeoutError, ValueError,
                    subprocess.TimeoutExpired) as error:
                print(f'ker-run: source supervisor stop remains unresolved: {error}',
                    file=sys.stderr)
                source_shell_controller.unresolved = True
                infrastructure_failure = True
                while True:
                    try:
                        signal.pause()
                    except Interrupted:
                        break
        if source_shell_controller is not None and source_shell_controller.launch is not None:
            try:
                if (worker is None or
                        not private_shutdown_receipt_valid or
                        not source_shutdown_evidence(startup_status, startup_eof, stats)):
                    raise RuntimeError('native shutdown lacks EOF, counters, or authenticated RX STOP/SETTLED evidence')
                source_shell_controller.close_settled()
            except (OSError, RuntimeError, TimeoutError, ValueError) as error:
                print(f'ker-run: source-shell close remains unresolved: {error}',
                    file=sys.stderr)
                source_shell_controller.unresolved = True
                infrastructure_failure = True
                while True:
                    try:
                        signal.pause()
                    except Interrupted:
                        break
    if signal_exit_code is not None and infrastructure_failure:
        preserve_signal = False
    return resolve_exit_code(exit_code, app.returncode if app else None,
        infrastructure_failure, preserve_signal)


if __name__ == '__main__':
    sys.exit(main())
