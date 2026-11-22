"""Private source-bootstrap identity validation; not generation I/O authority.

The caller must obtain master identity from the pinned companion's process
publication and runtime/I/O identities from their authenticated launcher. This
module does not discover or grant actors from a caller-provided PID alone.
"""
import array
import errno
import hashlib
import importlib.util
import os
import fcntl
import stat
from pathlib import Path
import socket
import struct
import subprocess
import select
import sys
import threading
import time
from typing import NamedTuple
from types import SimpleNamespace

_SPEC = importlib.util.spec_from_file_location('_source_companion_identity',
    Path(__file__).with_name('nginx_companion_supervisor.py'))
identity = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(identity)
RECORD = struct.Struct('=IHH8I5Q16s4I8Q')
SHELL_RECORD = struct.Struct('=IHH8I5Q16s4I8QIIQQ32s32s')
MAGIC = 0x4b534247
SHELL_VERSION = 4
SHELL_PROOF_VERSION = 1
PREEXIT_MAGIC = MAGIC
PREEXIT_VERSION = 1
PREEXIT_REQUEST = 10
PREEXIT_SETTLED = 11
COMMIT_EVIDENCE = 12
# Match KER_NGINX_SOURCE_PREEXIT_BUDGET_NS for final native shutdown.
PREEXIT_BUDGET_NS = 1_000_000_000
PREEXIT_HEADER = struct.Struct('=IHHII')
PREEXIT_TAIL = struct.Struct('=IIQQQ')
SETTLED_TAIL = struct.Struct('=IIQQiI')
COMMIT_EVIDENCE_RECORD_BYTES = PREEXIT_HEADER.size + SHELL_RECORD.size + 8
PREEXIT_RECORD_BYTES = PREEXIT_HEADER.size + SHELL_RECORD.size + PREEXIT_TAIL.size
SETTLED_RECORD_BYTES = PREEXIT_HEADER.size + PREEXIT_RECORD_BYTES + SETTLED_TAIL.size
assert PREEXIT_RECORD_BYTES == 312
assert SETTLED_RECORD_BYTES == 360
assert COMMIT_EVIDENCE_RECORD_BYTES == 288
SOURCE_EXPORT_SIZES = {'ngx_ff_reload_shm': 8, 'ngx_ff_graceful_reload': 4,
    'ngx_ff_process': 8, 'ngx_process': 8, 'ngx_worker': 8, 'ngx_process_slot': 8}


class SourceCycleProof(NamedTuple):
    proof_version: int
    proof_flags: int
    adapter_cycle_serial: int
    opaque_cycle_token: int
    config_sha256: bytes
    ini_sha256: bytes


_SOURCE_HANDOFF_TOKEN = object()


class _SourceC28ParkEvidence(NamedTuple):
    """Immutable host-side snapshot of one authenticated C28 PARK ACK."""
    token: object
    context: object
    provider: object
    deadline_ns: int
    source_nonce: bytes
    source_epoch: int
    lease: int
    listener_cookie: int
    received: int
    accepted: int
    bundle_record: bytes
    bundle_credentials: tuple
    bundle_fds: tuple
    provider_actor: tuple
    helper_actor: tuple
    channel: object
    channel_identity: tuple


class _SourceRoutePreparation(NamedTuple):
    """Immutable join between C31 PREPARE, the source cycle, and exact PARK."""
    token: object
    context: object
    park: _SourceC28ParkEvidence
    prepared: object
    fields: tuple
    operation_id: int
    command_sequence: int
    source_epoch: int
    current_ref: object
    current: tuple
    current_worker_key: tuple
    current_cycle_proof: SourceCycleProof
    candidate_ref: object
    candidate: tuple
    candidate_worker_key: tuple
    candidate_cycle_proof: SourceCycleProof
    cycle_proof: SourceCycleProof
    endpoint: object
    endpoint_identity: tuple
    actors: tuple
    raw_prepared_ack: bytes
    expected_prepared_record: bytes
    prepared_credentials: tuple
    candidate_channel: object
    candidate_channel_identity: tuple


# Source route terminal request and ACK kinds from the C31 wire record.
_SOURCE_ROUTE_COMMIT_ACK_TYPES = {7: 8, 11: 12}


class _SourceRouteCommitReceipt(NamedTuple):
    """One-shot proof minted only after an authenticated C31 route COMMIT ACK."""
    token: object
    preparation: _SourceRoutePreparation
    command_type: int
    command_sequence: int
    status: int
    deadline_ns: int
    validated_ns: int
    endpoint_identity: tuple
    raw_ack: bytes
    expected_record: bytes
    credentials: tuple


def _source_socket_identity(channel):
    cookie_option = getattr(socket, 'SO_COOKIE', 57)
    cookie = struct.unpack('=Q', channel.getsockopt(socket.SOL_SOCKET,
        cookie_option, 8))[0]
    value = os.fstat(channel.fileno())
    return (cookie, value.st_dev, value.st_ino, value.st_mode,
        fcntl.fcntl(channel.fileno(), fcntl.F_GETFL),
        fcntl.fcntl(channel.fileno(), fcntl.F_GETFD))


def _source_actor_tuple(actor):
    pid = getattr(actor, 'pid', 0)
    start = getattr(actor, 'start_ticks', 0)
    pidfd = getattr(actor, 'pidfd', -1)
    if type(pid) is not int or pid <= 0 or type(start) is not int or start <= 0:
        raise PermissionError('source handoff actor identity is incomplete')
    return (pid, start, pidfd)


def _pidfd_identity(fd):
    value = os.fstat(fd)
    return (value.st_dev, value.st_ino, value.st_mode)


def _require_context_route_actors(context, actors):
    (app_pid, app_start, app_pidfd, supervisor_pid, supervisor_start,
        supervisor_pidfd, master_pid, master_start, master_pidfd) = actors
    runtime = getattr(context, 'runtime', None)
    master = getattr(context, 'master', None)
    require(runtime is not None and master is not None and
        (runtime.pid, runtime.start_ticks, runtime.pidfd) ==
            (app_pid, app_start, app_pidfd) and
        (master.pid, master.start_ticks, master.pidfd) ==
            (master_pid, master_start, master_pidfd) and
        supervisor_pid == os.getpid() and
        supervisor_start == context.supervisor_start and
        identity._pidfd_pid(app_pidfd) == app_pid and
        identity._pidfd_pid(master_pidfd) == master_pid and
        identity._pidfd_pid(supervisor_pidfd) == supervisor_pid and
        identity._start_ticks(app_pid) == app_start and
        identity._start_ticks(master_pid) == master_start and
        identity._start_ticks(supervisor_pid) == supervisor_start and
        _pidfd_identity(app_pidfd) == _pidfd_identity(runtime.pidfd) and
        _pidfd_identity(master_pidfd) == _pidfd_identity(master.pidfd),
        'C31 route app, SDK supervisor, or master differs from accepted context actors')
    return True


def _make_source_c28_park_evidence(context, provider, response, bundle,
                                   channel, provider_actor, helper_actor):
    if (type(context) is not SourceBootstrapSupervisor or
            type(response) is not dict or response.get('phase') != 1 or
            type(response.get('lease')) is not int or response['lease'] <= 0 or
            type(response.get('received')) is not int or response['received'] < 0 or
            response.get('accepted') != 0 or
            type(bundle) is not dict or type(bundle.get('record')) is not bytes or
            type(bundle.get('credentials')) is not tuple or
            type(bundle.get('fds')) is not tuple):
        raise PermissionError('C28 PARK evidence is not an authenticated PREPARED response')
    deadline = getattr(provider, '_source_park_deadline_ns', None)
    if (type(deadline) is not int or deadline <= 0 or deadline > context.deadline_ns or
            response.get('lease') == 0):
        raise PermissionError('C28 PARK evidence lacks the exact original deadline')
    return _SourceC28ParkEvidence(_SOURCE_HANDOFF_TOKEN, context, provider,
        deadline, bytes(context.nonce), context.epoch, response['lease'],
        response.get('listener_cookie', 0), response['received'], response['accepted'],
        bytes(bundle['record']), tuple(bundle['credentials']), tuple(bundle['fds']),
        tuple(provider_actor), tuple(helper_actor), channel,
        _source_socket_identity(channel))


def _route_worker_keys(context, source_epoch):
    if source_epoch > 1 and getattr(context, 'allow_successor', False):
        return ((source_epoch - 1, 1 - source_epoch % 2),
            (source_epoch, source_epoch % 2))
    return (0, 0), (source_epoch, 1)


def _make_source_route_preparation(context, park, prepared, fields, source_epoch,
                                   current, candidate, cycle_proof, endpoint,
                                   candidate_channel, actors, raw_prepared_ack,
                                   expected_prepared_record, prepared_credentials,
                                   previous_aborted=None, previous_committed=None,
                                   prepare_deadline_ns=None):
    require(type(context) is SourceBootstrapSupervisor and context.shell_mode,
        'C31 handoff needs the exact source-shell context')
    require(type(fields) is tuple and len(fields) == 23 and
        type(current) is tuple and len(current) == 9 and
        type(candidate) is tuple and len(candidate) == 9 and
        type(actors) is tuple and len(actors) == 9,
        'C31 handoff snapshot is incomplete')
    # C31 has received the candidate relay and may have changed the shared
    # open-file status flags; identity and SDK ownership remain stable.
    deadline_ns = prepare_deadline_ns
    if source_epoch == 2 and previous_committed is None:
        require(hasattr(context, '_source_retry_prepare_attempt'),
            'retry PREPARED ACK lacks its one-shot attempt')
        prior, operation_id, sequence, deadline_ns = context._source_retry_prepare_attempt
        require(previous_aborted is prior and prepared.operation_id == operation_id and
            prepared.command_sequence == sequence and time.monotonic_ns() < deadline_ns,
            'retry PREPARED ACK does not settle the one-shot retry attempt')
    _validate_source_route_prepare_inputs(context, fields, source_epoch,
        current, candidate, cycle_proof, endpoint, candidate_channel, actors,
        check_candidate_mode=False, previous_aborted=previous_aborted,
        previous_committed=previous_committed, prepare_deadline_ns=deadline_ns)
    require(type(raw_prepared_ack) is bytes and
        type(expected_prepared_record) is bytes and
        raw_prepared_ack == expected_prepared_record and
        type(prepared_credentials) is tuple and len(prepared_credentials) == 3 and
        prepared_credentials[0] == actors[0] and
        prepared_credentials[1:] == (os.getuid(), os.getgid()),
        'C31 PREPARED snapshot lacks its exact credentialed ACK')
    current_key, current_proof = _source_worker_join(context, current[1:])
    candidate_key, candidate_proof = _source_worker_join(context, candidate[1:])
    require((current_key, candidate_key) == _route_worker_keys(context, source_epoch) and
        current[3] == bool(previous_committed) and candidate[3] == 1 and
        type(cycle_proof) is SourceCycleProof and
        cycle_proof is candidate_proof,
        'C31 candidate cycle proof is not the exact retained candidate-worker proof')
    require(park is None or (type(park) is _SourceC28ParkEvidence and
        park.token is _SOURCE_HANDOFF_TOKEN and park.context is context and
        park.provider.context is context and park.deadline_ns <= context.deadline_ns),
        'invalid optional C31 PARK join')
    return _SourceRoutePreparation(_SOURCE_HANDOFF_TOKEN, context, park,
        prepared, tuple(fields), prepared.operation_id, prepared.command_sequence,
        source_epoch, current[0], tuple(current[1:]), current_key, current_proof,
        candidate[0], tuple(candidate[1:]), candidate_key, candidate_proof,
        cycle_proof, endpoint, _source_socket_identity(endpoint), tuple(actors),
        bytes(raw_prepared_ack), bytes(expected_prepared_record),
        tuple(prepared_credentials), candidate_channel,
        _source_socket_identity(candidate_channel)[:4])


def _validate_source_route_prepare_inputs(context, fields, source_epoch,
                                          current, candidate, cycle_proof,
                                          endpoint, candidate_channel, actors,
                                          check_candidate_mode=True, previous_aborted=None,
                                          previous_committed=None, prepare_deadline_ns=None):
    """Check source-bound PREPARE provenance before channel side effects."""
    require(type(context) is SourceBootstrapSupervisor and context.shell_mode and
        type(fields) is tuple and len(fields) == 23 and
        type(current) is tuple and len(current) == 9 and
        type(candidate) is tuple and len(candidate) == 9 and
        type(actors) is tuple and len(actors) == 9,
        'C31 pre-send binding is incomplete or noncanonical')
    successor = previous_committed is not None
    upgrade = successor and source_epoch == 2 and context.upgrade_scope
    require(type(source_epoch) is int and 1 <= source_epoch <= (100 if successor else 2) and
        fields[2] == (13 if successor else 5) and fields[8] == int(upgrade) and
        fields[9] == context.epoch and
        fields[15] == context.nonce and type(fields[22]) is int and
        0 < fields[22] <= context.deadline_ns and
        time.monotonic_ns() < fields[22],
        'source-bound PREPARE has an unsupported original epoch or grant')
    observation_deadline_ns = fields[22] if prepare_deadline_ns is None else prepare_deadline_ns
    require(type(observation_deadline_ns) is int and
        time.monotonic_ns() < observation_deadline_ns <= fields[22],
        'source-bound PREPARE setup deadline expired or exceeds its grant')
    context.live(observation_deadline_ns)
    require(time.monotonic_ns() < observation_deadline_ns,
        'source-bound PREPARE expired during context liveness validation')
    _require_context_route_actors(context, actors)
    require(type(endpoint) is socket.socket and endpoint.family == socket.AF_UNIX and
        endpoint.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_SEQPACKET and
        endpoint.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) == 1 and
        endpoint.gettimeout() == 0.0 and
        fcntl.fcntl(endpoint.fileno(), fcntl.F_GETFL) & os.O_NONBLOCK and
        fcntl.fcntl(endpoint.fileno(), fcntl.F_GETFD) & fcntl.FD_CLOEXEC and
        struct.unpack('=3i', endpoint.getsockopt(socket.SOL_SOCKET,
            socket.SO_PEERCRED, 12)) == (actors[3], os.getuid(), os.getgid()),
        'source C31 endpoint is not the nonblocking CLOEXEC SDK credentialed channel')
    require(type(candidate_channel) is socket.socket and
        candidate_channel.family == socket.AF_UNIX and
        candidate_channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) ==
            socket.SOCK_SEQPACKET,
        'source candidate relay is not a Unix seqpacket')
    require(fcntl.fcntl(candidate_channel.fileno(), fcntl.F_GETFD) & fcntl.FD_CLOEXEC,
        'source candidate relay descriptor lost CLOEXEC')
    if check_candidate_mode:
        require(fcntl.fcntl(candidate_channel.fileno(), fcntl.F_GETFL) & os.O_NONBLOCK,
            'source candidate relay must be nonblocking before PREPARE')
    endpoint_identity = _source_socket_identity(endpoint)
    candidate_identity = _source_socket_identity(candidate_channel)
    require(endpoint_identity[0] > 0 and candidate_identity[0] > 0 and
        endpoint_identity[0] != candidate_identity[0] and
        (endpoint_identity[1], endpoint_identity[2]) !=
            (candidate_identity[1], candidate_identity[2]) and
        struct.unpack('=3i', candidate_channel.getsockopt(socket.SOL_SOCKET,
            socket.SO_PEERCRED, 12)) == (actors[3], os.getuid(), os.getgid()),
        'source candidate relay aliases C31 endpoint or lacks SDK socket ownership')
    current_key, current_proof = _source_worker_join(context, current[1:])
    candidate_key, candidate_proof = _source_worker_join(context, candidate[1:])
    if upgrade:
        new_master = context._worker_master(candidate_key)
        require(identity.process_alive(new_master.pidfd) and
            context.workers[candidate_key][1][7] == new_master.pid and
            context._scalar(context.master.pid, 'ngx_new_binary', '=i') == new_master.pid,
            'C31 upgrade candidate lost the authenticated original exec master')
    require((current_key, candidate_key) == _route_worker_keys(context, source_epoch) and
        current[3] == int(successor) and candidate[3] == 1 and
        type(cycle_proof) is SourceCycleProof and
        (successor or current_proof is context.initial_cycle_proof) and
        candidate_proof is cycle_proof and
        context.workers[current_key][1][14:17] ==
            (context.epoch, context.deadline_ns, context.nonce) and
        context.workers[candidate_key][1][14:17] ==
            (context.epoch, context.deadline_ns, context.nonce) and
        fields[5:8] == candidate[1:4] and
        fields[11:15] == candidate[4:8] and
        fields[16:22] == (current[1], current[2], current[4], current[5],
            current[6], current[7]),
        'source-bound PREPARE does not join exact current/candidate worker proofs')
    if successor:
        _validate_source_route_successor(context, source_epoch, previous_committed,
            current[1:], endpoint)
    elif source_epoch == 2:
        _validate_source_route_retry(context, previous_aborted, endpoint, actors, current[1:],
            candidate[1:])
    else:
        require(previous_aborted is None, 'first source PREPARE cannot use retry lineage')
    require(type(getattr(context, '_source_route_preparations', None)) is dict and
        type(getattr(context, '_source_route_park_joins', None)) is dict,
        'source C31 preparation registries are unavailable')
    context.live(observation_deadline_ns)
    require(time.monotonic_ns() < observation_deadline_ns,
        'source-bound PREPARE expired during pre-send joins')
    return True


def _validate_source_route_successor(context, source_epoch, previous, current, endpoint):
    prior = context._source_route_park_joins.get(id(previous))
    receipt = context._source_route_commit_receipts.get(id(previous))
    require(context.allow_successor and source_epoch >= 2 and
        context._source_round(source_epoch) == (1 - source_epoch % 2, source_epoch % 2) and
        type(prior) is _SourceRoutePreparation and prior.context is context and
        prior.prepared is previous and prior.source_epoch == source_epoch - 1 and
        prior.endpoint is endpoint and prior.candidate == current and
        type(receipt) is _SourceRouteCommitReceipt and receipt.preparation is prior and
        id(previous) in context._source_route_commit_consumed and
        (prior.source_epoch, 6) in context._completed_master_barriers and
        context._source_shell_committed_plans.get(prior.candidate_worker_key, {}).get(
            'native_current_cookie') == context._native_committed_cookie and
        not identity.process_alive(prior.current[7]),
        'C31 successor did not join its acknowledged prior COMMIT and retired owner')


def _validate_source_route_retry(context, previous_aborted, endpoint, actors, current, candidate):
    acknowledged = getattr(context, '_source_route_abort_receipt', None)
    require(getattr(context, 'control_only', False) is True and
        getattr(context, 'allow_abort_retry', False) is True and
        getattr(context, '_completed_master_barriers', set()) == {(1, 5), (1, 9)} and
        getattr(context, '_native_retry_cookie', 0) > 0 and
        getattr(context, '_private_retry_grant_attempted', False) is True and
        acknowledged is not None and previous_aborted is not None,
        'typed C31 retry requires acknowledged original ABORT and native adoption')
    prior, sequence = acknowledged
    require(type(prior) is _SourceRoutePreparation and prior.source_epoch == 1 and
        prior.prepared is previous_aborted and prior.context is context and
        prior.park is not None and context._source_route_park_joins.get(id(previous_aborted)) is prior and
        context._source_route_sequences.get(id(previous_aborted)) == (sequence, None, True) and
        previous_aborted.command_sequence == sequence and
        prior.endpoint is endpoint and prior.actors == actors and prior.current == current and
        context.workers[(1, 1)][1][5] == prior.candidate[0] and
        not identity.process_alive(prior.candidate[7]) and
        not identity.process_alive(context.workers[(1, 1)][0]),
        'typed C31 retry changed the exact acknowledged predecessor or its actors')
    ready = getattr(context, '_private_retry_ready_identity', None)
    require(ready == (candidate[0], os.getuid(), os.getgid(), 1, candidate[1], 0,
        candidate[3], candidate[4], candidate[5], candidate[6]) and
        (candidate[4], candidate[5]) == context._retry_slot,
        'typed C31 retry lacks the credentialed epoch-2 READY and native FIFO')


def _begin_source_route_retry_prepare(context, previous_aborted, operation_id,
                                      command_sequence, deadline_ns):
    require(not hasattr(context, '_source_retry_prepare_attempt') and
        type(deadline_ns) is int and time.monotonic_ns() < deadline_ns <= context.deadline_ns,
        'typed C31 retry PREPARE was already attempted or expired')
    context._source_retry_prepare_attempt = (previous_aborted, operation_id,
        command_sequence, deadline_ns)


def _source_worker_join(context, actor):
    pid, tid, role, start, slot_device, slot_inode, cookie, pidfd = actor
    matches = []
    for key, entry in getattr(context, 'workers', {}).items():
        if (type(key) is tuple and len(key) == 2 and type(entry) is tuple and
                len(entry) == 2 and type(entry[1]) is tuple and len(entry[1]) >= 28):
            record = entry[1]
            if ((record[9], record[8]) == key and
                (record[5], record[6], record[11], record[24], record[25], record[27]) == (
                    pid, tid, start, slot_device, slot_inode, cookie)):
                proof = getattr(context, 'worker_proofs', {}).get(key)
                held_pidfd = entry[0]
                expected_role = (0 if key == (0, 0) else
                    1 if (key in ((1, 1), (2, 1)) or
                        (getattr(context, 'allow_successor', False) and
                         2 <= key[0] <= 100 and key[1] == key[0] % 2)) else -1)
                if (type(proof) is SourceCycleProof and role == expected_role and
                        identity._pidfd_pid(held_pidfd) == pid and
                        identity._start_ticks(pid) == start and
                        identity._pidfd_pid(pidfd) == pid and
                        (os.fstat(held_pidfd).st_dev, os.fstat(held_pidfd).st_ino,
                            os.fstat(held_pidfd).st_mode) ==
                        (os.fstat(pidfd).st_dev, os.fstat(pidfd).st_ino,
                            os.fstat(pidfd).st_mode)):
                    matches.append((key, proof))
    require(len(matches) == 1,
        'C31 route actor lacks one exact retained source-worker record and cycle proof')
    return matches[0]


def _validate_source_route_preparation(preparation, prepared, endpoint,
                                      check_mutable_prepared=True):
    require(type(preparation) is _SourceRoutePreparation and
        preparation.token is _SOURCE_HANDOFF_TOKEN and
        preparation.prepared is prepared and preparation.endpoint is endpoint and
        (not check_mutable_prepared or
            (type(prepared.fields) is list and tuple(prepared.fields) == preparation.fields and
             prepared.operation_id == preparation.operation_id and
             prepared.source_epoch == preparation.source_epoch)) and
        (preparation.park is None or
            (preparation.context is preparation.park.context and
             preparation.park.provider.context is preparation.context and
             preparation.park.provider._source_park_evidence is preparation.park)) and
        ((preparation.park is None and
            getattr(preparation.context, '_source_route_preparations', {}).get(
                id(prepared)) is preparation) or
         (preparation.park is not None and
            getattr(preparation.context, '_source_route_park_joins', {}).get(
                id(prepared)) is preparation)) and
        (preparation.park is None or
            (preparation.context.deadline_ns >= preparation.park.deadline_ns and
             preparation.park.deadline_ns <= preparation.fields[22])) and
        preparation.candidate_cycle_proof is preparation.cycle_proof and
        preparation.context.worker_proofs.get(preparation.current_worker_key) is
            preparation.current_cycle_proof and
        preparation.context.worker_proofs.get(preparation.candidate_worker_key) is
            preparation.candidate_cycle_proof,
        'C31 route preparation no longer matches its immutable source binding')
    _require_context_route_actors(preparation.context, preparation.actors)
    require(preparation.fields[5:8] == preparation.candidate[:3] and
        preparation.fields[11:15] == preparation.candidate[3:7] and
        preparation.fields[16:22] == (preparation.current[0],
            preparation.current[1], preparation.current[3], preparation.current[4],
            preparation.current[5], preparation.current[6]),
        'C31 route fields differ from the exact current/candidate proof records')
    require(_source_socket_identity(endpoint) == preparation.endpoint_identity and
        endpoint.gettimeout() == 0.0 and
        fcntl.fcntl(endpoint.fileno(), fcntl.F_GETFL) & os.O_NONBLOCK and
        fcntl.fcntl(endpoint.fileno(), fcntl.F_GETFD) & fcntl.FD_CLOEXEC,
        'C31 source endpoint identity or nonblocking/CLOEXEC mode changed')
    require(tuple((preparation.current_ref.owner_pid,
            preparation.current_ref.owner_tid, preparation.current_ref.owner_role,
            preparation.current_ref.owner_start,
            preparation.current_ref.owner_slot_device,
            preparation.current_ref.owner_slot_inode,
            preparation.current_ref.owner_cookie,
            preparation.current_ref.owner_pidfd)) == preparation.current and
        tuple((preparation.candidate_ref.owner_pid,
            preparation.candidate_ref.owner_tid, preparation.candidate_ref.owner_role,
            preparation.candidate_ref.owner_start,
            preparation.candidate_ref.owner_slot_device,
            preparation.candidate_ref.owner_slot_inode,
            preparation.candidate_ref.owner_cookie,
            preparation.candidate_ref.owner_pidfd)) == preparation.candidate,
        'C31 route actor records changed after PREPARE')
    require(_source_worker_join(preparation.context, preparation.current) ==
                (preparation.current_worker_key, preparation.current_cycle_proof) and
        _source_worker_join(preparation.context, preparation.candidate) ==
                (preparation.candidate_worker_key, preparation.candidate_cycle_proof),
        'C31 source-worker record or cycle proof changed after PREPARE')
    for pid, start, pidfd in (preparation.actors[0:3], preparation.actors[3:6],
            preparation.actors[6:9],
            (preparation.current[0], preparation.current[3], preparation.current[7]),
            (preparation.candidate[0], preparation.candidate[3],
                preparation.candidate[7])):
        require(identity._pidfd_pid(pidfd) == pid and identity.process_alive(pidfd) and
            identity._start_ticks(pid) == start,
            'C31 source actor identity expired during command')
    return True


def _join_source_route_park(preparation, park):
    _validate_source_route_preparation(preparation, preparation.prepared,
        preparation.endpoint)
    require(type(preparation) is _SourceRoutePreparation and
        preparation.token is _SOURCE_HANDOFF_TOKEN and preparation.park is None and
        type(park) is _SourceC28ParkEvidence and park.token is _SOURCE_HANDOFF_TOKEN and
        park.context is preparation.context and park.provider.context is preparation.context and
        park.provider._source_park_evidence is park and
        park.deadline_ns <= preparation.fields[22] and
        park.deadline_ns <= preparation.context.deadline_ns and
        time.monotonic_ns() < park.deadline_ns,
        'source C31 PREPARED snapshot cannot join this exact C28 PARK')
    joins = getattr(preparation.context, '_source_route_park_joins', None)
    require(type(joins) is dict and id(preparation.prepared) not in joins,
        'source C31 PARK join is unavailable or already used')
    joined = preparation._replace(park=park)
    joins[id(preparation.prepared)] = joined
    return joined


def _mint_source_route_commit_receipt(preparation, prepared, command_type,
                                      command_sequence, status, deadline_ns,
                                      validated_ns, raw_ack, expected_record,
                                      credentials):
    require(type(preparation) is _SourceRoutePreparation and
        preparation.token is _SOURCE_HANDOFF_TOKEN and preparation.prepared is prepared and
        command_type in _SOURCE_ROUTE_COMMIT_ACK_TYPES and status == 0 and
        type(command_sequence) is int and
        command_sequence > preparation.command_sequence and
        deadline_ns == preparation.park.deadline_ns and
        type(validated_ns) is int and time.monotonic_ns() < deadline_ns and
        validated_ns < deadline_ns and
        type(raw_ack) is bytes and type(expected_record) is bytes and
        len(raw_ack) >= 8 and raw_ack == expected_record and
        struct.unpack_from('=H', raw_ack, 6)[0] == _SOURCE_ROUTE_COMMIT_ACK_TYPES[command_type] and
        type(credentials) is tuple and len(credentials) == 3 and
        credentials == (preparation.actors[0], os.getuid(), os.getgid()) and
        _source_socket_identity(preparation.endpoint) == preparation.endpoint_identity,
        'C31 route COMMIT ACK does not satisfy the source receipt gate')
    return _SourceRouteCommitReceipt(_SOURCE_HANDOFF_TOKEN, preparation,
        command_type, command_sequence, status, deadline_ns, validated_ns,
        preparation.endpoint_identity, bytes(raw_ack), bytes(expected_record),
        tuple(credentials))


def _validate_source_route_commit_receipt(receipt, provider, deadline_ns):
    require(type(receipt) is _SourceRouteCommitReceipt and
        receipt.token is _SOURCE_HANDOFF_TOKEN and
        type(receipt.preparation) is _SourceRoutePreparation,
        'C28 COMMIT requires the private typed C31 ACK receipt')
    prep = receipt.preparation
    require(prep.token is _SOURCE_HANDOFF_TOKEN and prep.park.token is _SOURCE_HANDOFF_TOKEN and
        prep.context is provider.context and prep.park.context is provider.context and
        prep.park.provider is provider and provider._source_park_evidence is prep.park and
        provider._source_park_deadline_ns == prep.park.deadline_ns and
        receipt.command_type in _SOURCE_ROUTE_COMMIT_ACK_TYPES and receipt.status == 0 and
        type(receipt.raw_ack) is bytes and type(receipt.expected_record) is bytes and
        len(receipt.raw_ack) >= 8 and receipt.raw_ack == receipt.expected_record and
        struct.unpack_from('=H', receipt.raw_ack, 6)[0] ==
            _SOURCE_ROUTE_COMMIT_ACK_TYPES[receipt.command_type] and
        receipt.credentials == (prep.actors[0], os.getuid(), os.getgid()) and
        receipt.deadline_ns == deadline_ns == prep.park.deadline_ns and
        receipt.validated_ns < deadline_ns and time.monotonic_ns() < deadline_ns and
        receipt.endpoint_identity == prep.endpoint_identity and
        _source_socket_identity(prep.endpoint) == prep.endpoint_identity and
        _source_socket_identity(prep.park.channel) == prep.park.channel_identity and
        prep.candidate_cycle_proof is prep.cycle_proof and
        prep.context.worker_proofs.get(prep.current_worker_key) is prep.current_cycle_proof and
        prep.context.worker_proofs.get(prep.candidate_worker_key) is prep.candidate_cycle_proof and
        getattr(prep.context, '_source_route_park_joins', {}).get(
            id(prep.prepared)) is prep and
        prep.raw_prepared_ack == prep.expected_prepared_record and
        prep.prepared_credentials == (prep.actors[0], os.getuid(), os.getgid()) and
        _source_worker_join(prep.context, prep.current) ==
            (prep.current_worker_key, prep.current_cycle_proof) and
        _source_worker_join(prep.context, prep.candidate) ==
            (prep.candidate_worker_key, prep.candidate_cycle_proof),
        'C31 ACK receipt no longer matches context, PARK, route, or endpoint')
    require(tuple((prep.current_ref.owner_pid, prep.current_ref.owner_tid,
            prep.current_ref.owner_role, prep.current_ref.owner_start,
            prep.current_ref.owner_slot_device, prep.current_ref.owner_slot_inode,
            prep.current_ref.owner_cookie, prep.current_ref.owner_pidfd)) == prep.current and
        tuple((prep.candidate_ref.owner_pid, prep.candidate_ref.owner_tid,
            prep.candidate_ref.owner_role, prep.candidate_ref.owner_start,
            prep.candidate_ref.owner_slot_device, prep.candidate_ref.owner_slot_inode,
            prep.candidate_ref.owner_cookie, prep.candidate_ref.owner_pidfd)) == prep.candidate,
        'C31 current/candidate route identity changed after preparation')
    for pid, start, pidfd in (prep.actors[0:3], prep.actors[3:6],
            prep.actors[6:9], (prep.current[0], prep.current[3], prep.current[7]),
            (prep.candidate[0], prep.candidate[3], prep.candidate[7])):
        require(identity._pidfd_pid(pidfd) == pid and identity.process_alive(pidfd) and
            identity._start_ticks(pid) == start,
            'C31 route actor expired before C28 COMMIT')
    require(getattr(prep.context, '_source_route_commit_receipts', {}).get(
        id(prep.prepared)) is receipt,
        'C31 route preparation changed after its ACK receipt was minted')
    return prep


def _register_source_route_preparation(preparation):
    require(type(preparation) is _SourceRoutePreparation and
        preparation.token is _SOURCE_HANDOFF_TOKEN and
        preparation.context is not None and preparation.park is None,
        'invalid source C31 preparation registration')
    registry = getattr(preparation.context, '_source_route_preparations', None)
    require(type(registry) is dict and id(preparation.prepared) not in registry,
        'source C31 preparation registry is unavailable or already used')
    registry[id(preparation.prepared)] = preparation
    sequences = getattr(preparation.context, '_source_route_sequences', None)
    require(type(sequences) is dict,
        'source C31 sequence registry is unavailable')
    sequences[id(preparation.prepared)] = (preparation.command_sequence, None, False)
    return preparation


def _register_source_route_commit_receipt(receipt):
    require(type(receipt) is _SourceRouteCommitReceipt and
        receipt.token is _SOURCE_HANDOFF_TOKEN and
        type(receipt.preparation) is _SourceRoutePreparation,
        'invalid source C31 COMMIT receipt registration')
    preparation = receipt.preparation
    receipts = getattr(preparation.context, '_source_route_commit_receipts', None)
    require(type(receipts) is dict and
        getattr(preparation.context, '_source_route_park_joins', {}).get(
            id(preparation.prepared)) is preparation and
        id(preparation.prepared) not in receipts,
        'source C31 COMMIT receipt registry rejected producer')
    receipts[id(preparation.prepared)] = receipt
    return receipt


def _begin_source_route_attempt(preparation, command_sequence):
    _validate_source_route_preparation(preparation, preparation.prepared,
        preparation.endpoint)
    registry = preparation.context._source_route_sequences
    last, pending, terminal = registry[id(preparation.prepared)]
    require(pending is None and not terminal and type(command_sequence) is int and
        command_sequence > last,
        'source C31 command sequence is duplicate or has an unresolved attempt')
    registry[id(preparation.prepared)] = (last, command_sequence, False)


def _finish_source_route_attempt(preparation, command_sequence, retryable, *, aborted=False):
    registry = preparation.context._source_route_sequences
    last, pending, terminal = registry[id(preparation.prepared)]
    require(pending == command_sequence and command_sequence > last,
        'source C31 ACK does not settle the pending command sequence')
    registry[id(preparation.prepared)] = (command_sequence, None, not retryable)
    if aborted and preparation.source_epoch == 1:
        preparation.context._source_route_abort_receipt = (preparation, command_sequence)


def _consume_source_route_commit_receipt(receipt, provider, deadline_ns):
    preparation = _validate_source_route_commit_receipt(receipt, provider, deadline_ns)
    consumed = getattr(preparation.context, '_source_route_commit_consumed', None)
    require(type(consumed) is set and id(preparation.prepared) not in consumed,
        'source C31 COMMIT receipt was already consumed')
    consumed.add(id(preparation.prepared))
    return preparation


class SourceRetirementProof(NamedTuple):
    """Exact, already-verified receipt components for one owner retirement."""
    operation_id: int
    request_sha256: bytes
    supervisor_term_sha256: bytes
    broker_stop_sha256: bytes
    c28_drain_sha256: bytes | None
    native_shutdown_sha256: bytes
    c31_outstanding: int
    c31_last_packet_id: int
    c31_last_result: int


class SupervisorTermEvidence(NamedTuple):
    """Receipt parsed by the source-shell controller from its held output FD."""
    supervisor_pid: int
    supervisor_start_ticks: int
    supervisor_exe_sha256: bytes
    run_id: str
    controller: str
    stack: str
    phase: str
    worker_pid: int
    worker_start_ticks: int
    signal: str
    observed_ns: int
    receipt_device: int
    receipt_inode: int
    receipt_sha256: bytes


class PendingSourceRetirement(NamedTuple):
    key: tuple
    operation_id: int
    worker_pid: int
    worker_start_ticks: int
    worker_slot: int
    request_sha256: bytes
    deadline_ns: int


def required_source_exports(shell_mode, upgrade=False):
    result = dict(SOURCE_EXPORT_SIZES)
    if shell_mode:
        result['ngx_cycle'] = 8
    if upgrade:
        result.update(ngx_inherited=8, ngx_new_binary=4)
    return result


def _proof_from_record(record):
    return SourceCycleProof(*record[29:35])


def _validate_cycle_proof(proof, expected_config_sha256, expected_ini_sha256):
    require(type(proof) is SourceCycleProof and proof.proof_version == SHELL_PROOF_VERSION and
        proof.proof_flags == 0 and type(proof.adapter_cycle_serial) is int and
        proof.adapter_cycle_serial > 0 and type(proof.opaque_cycle_token) is int and
        proof.opaque_cycle_token > 0 and type(proof.config_sha256) is bytes and
        len(proof.config_sha256) == 32 and type(proof.ini_sha256) is bytes and
        len(proof.ini_sha256) == 32 and type(expected_config_sha256) is bytes and
        len(expected_config_sha256) == 32 and type(expected_ini_sha256) is bytes and
        len(expected_ini_sha256) == 32 and proof.config_sha256 == expected_config_sha256 and
        proof.ini_sha256 == expected_ini_sha256,
        'source worker cycle proof is malformed or differs from pinned transcript digests')
    return proof


def require(condition, message):
    if not condition:
        raise PermissionError(message)


def send_initial_worker_grant(channel, data, rights, deadline_ns):
    """Attempt one initial grant under its fixed absolute request deadline."""
    setblocking = getattr(channel, 'setblocking', None)
    if callable(setblocking):
        # Accepted Origin channels have a positive Python timeout while the
        # request is read. Python's timeout wrapper can poll before sendmsg,
        # even with MSG_DONTWAIT, so establish nonblocking mode explicitly.
        setblocking(False)
    if type(deadline_ns) is not int or time.monotonic_ns() >= deadline_ns:
        raise TimeoutError('initial worker grant expired before send')
    sent = channel.sendmsg([data], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)],
        getattr(socket, 'MSG_NOSIGNAL', 0) | getattr(socket, 'MSG_DONTWAIT', 0))
    completed_ns = time.monotonic_ns()
    if completed_ns >= deadline_ns:
        raise TimeoutError('initial worker grant send completed after its absolute deadline')
    if sent != len(data):
        raise OSError(errno.EIO, 'short initial source worker grant')
    return sent


def memory(pid, address, length):
    with open(f'/proc/{pid}/mem', 'rb', buffering=0) as stream:
        result = os.pread(stream.fileno(), length, address)
    require(len(result) == length, 'incomplete pinned process memory observation')
    return result


def shared_mapping(pid, address):
    for line in Path(f'/proc/{pid}/maps').read_text().splitlines():
        fields = line.split(maxsplit=5)
        first, last = (int(value, 16) for value in fields[0].split('-'))
        if first <= address < last:
            require(fields[1] == 'rw-s' and fields[2] == '00000000' and
                int(fields[4]) > 0, 'source block is not inherited shared anonymous memory')
            return first, last, fields[3], fields[4]
    raise PermissionError('source block is outside pinned process mappings')


def bounded_source_exports(fd, expected_hash, deadline_ns, *, require_cycle=False,
        require_upgrade=False):
    """Read only the fixed source data exports from the same hashed ELF FD.

    The origin startup path must not spawn a metadata helper whose teardown
    could exceed its original budget. This accepts the pinned x86-64 EXEC
    layout only; it is not a general ELF loader or symbol resolver.
    """
    before = os.fstat(fd)
    frozen = (before.st_dev, before.st_ino, before.st_size,
        before.st_mtime_ns, before.st_ctime_ns)
    size = before.st_size
    require(stat.S_ISREG(before.st_mode) and 64 <= size <= 64 * 1024 * 1024,
        'unsupported source ELF size/type')

    def within():
        require(time.monotonic_ns() < deadline_ns, 'source ELF observation expired')

    def read(offset, count, limit):
        within()
        require(0 <= count <= limit and 0 <= offset <= size and count <= size - offset,
            'source ELF range exceeds file')
        value = os.pread(fd, count, offset)
        within()
        require(len(value) == count, 'truncated source ELF metadata')
        return value

    def digest():
        value = hashlib.sha256()
        for offset in range(0, size, 65536):
            value.update(read(offset, min(65536, size - offset), 65536))
        return value.digest()

    require(digest() == expected_hash, 'source ELF content differs from pinned input')
    header = read(0, 64, 64)
    require(header[:7] == b'\x7fELF\x02\x01\x01' and
        struct.unpack_from('<HHI', header, 16) == (2, 62, 1) and
        struct.unpack_from('<H', header, 52)[0] == 64,
        'source observation requires little-endian x86-64 ELF EXEC')
    section_offset = struct.unpack_from('<Q', header, 40)[0]
    entry_size, count = struct.unpack_from('<HH', header, 58)
    require(entry_size == 64 and 0 < count <= 4096 and section_offset >= 64,
        'unsupported source ELF section table')
    table = read(section_offset, count * 64, 4096 * 64)
    sections = [struct.unpack_from('<IIQQQQIIQQ', table, offset)
        for offset in range(0, len(table), 64)]
    dynamic = [section for section in sections if section[1] == 11]
    require(len(dynamic) == 1, 'source ELF needs one dynamic symbol table')
    symbols = dynamic[0]
    require(symbols[9] == 24 and symbols[5] > 0 and symbols[5] % 24 == 0 and
        symbols[5] // 24 <= 65536 and symbols[6] < len(sections),
        'invalid source ELF dynamic symbol shape')
    strings_section = sections[symbols[6]]
    require(strings_section[1] == 3 and 0 < strings_section[5] <= 4 * 1024 * 1024,
        'invalid source ELF dynamic string table')
    names = read(strings_section[4], strings_section[5], 4 * 1024 * 1024)
    entries = read(symbols[4], symbols[5], 65536 * 24)
    require(names[0] == 0 and entries[:24] == bytes(24),
        'source ELF null string/symbol entry is malformed')
    result = {}
    export_sizes = required_source_exports(require_cycle, require_upgrade)
    wanted = {name.encode(): name for name in export_sizes}
    for offset in range(0, len(entries), 24):
        within()
        name_offset, info, visibility, section_index, address, symbol_size = \
            struct.unpack_from('<IBBHQQ', entries, offset)
        require(name_offset < len(names), 'source symbol name is outside string table')
        end = names.find(b'\0', name_offset, min(len(names), name_offset + 257))
        require(end >= 0, 'source symbol name is unbounded or unterminated')
        name = wanted.get(names[name_offset:end])
        if name is None:
            continue
        require(name not in result and info >> 4 == 1 and info & 15 == 1 and visibility == 0 and
            0 < section_index < len(sections) and symbol_size == export_sizes[name],
            'source export is duplicate, undefined, or has unsupported binding/type')
        target = sections[section_index]
        require(target[1] in (1, 8) and target[2] & 3 == 3 and target[3] <= address and
            target[5] >= symbol_size and address - target[3] <= target[5] - symbol_size,
            'source data export exceeds its allocated writable section')
        require(address + symbol_size <= 1 << 64 and target[3] + target[5] <= 1 << 64,
            'source data export virtual range overflows')
        result[name] = address
    require(result.keys() == export_sizes.keys(), 'source data exports are incomplete')
    require(digest() == expected_hash and
        (lambda value: (value.st_dev, value.st_ino, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns))(os.fstat(fd)) == frozen,
        'source ELF changed during observation')
    within()
    return result


def _source_provider_matches_context(context, provider, controller=None):
    """Exact old C22 or capture-bound private ABI1 provider for this Origin."""
    provider_module = sys.modules.get('_ker_nginx_source_c22_provider')
    origin = getattr(getattr(context, 'owner_live', None), '__self__', None)
    origin_module = sys.modules.get(type(origin).__module__) if origin is not None else None
    if provider_module is None:
        return False
    private_origin_type = (getattr(origin_module, 'PrivateC34OriginalShellLaunch', None)
        if origin_module is not None else None)
    old_pair = (type(provider) is getattr(provider_module, 'SourceShellC22Provider', None) and
        getattr(provider, '_private_c34_helper_capture', None) is None and
        (private_origin_type is None or type(origin) is not private_origin_type))
    private_pair = False
    if (origin_module is not None and
            Path(getattr(origin_module, '__file__', '')).resolve(strict=True) ==
                Path(__file__).with_name('nginx_source_origin.py').resolve(strict=True) and
            type(provider) is getattr(provider_module, 'SourceShellC34InteropProvider', None) and
            type(origin) is getattr(origin_module, 'PrivateC34OriginalShellLaunch', None)):
        artifacts = sys.modules.get('_ker_nginx_source_c34_artifacts')
        capture = getattr(origin, 'c34_artifact_capture', None)
        helper = getattr(capture, 'helper_capture', None)
        private_pair = (artifacts is not None and
            type(capture) is getattr(artifacts, 'PrivateC34ArtifactCapture', None) and
            type(helper) is getattr(artifacts, 'PrivateC34HelperCapture', None) and
            getattr(provider, '_private_c34_helper_capture', None) is helper and
            getattr(helper, 'source_command_abi', None) == 1 and
            getattr(provider, '_source_command_abi', None) == 1)
    if not (old_pair or private_pair) or provider.context is not context:
        return False
    if controller is not None:
        controller_module = sys.modules.get('_ker_nginx_source_shell_controller')
        profile_module = sys.modules.get('_ker_nginx_source_c34_profile')
        if (controller_module is None or
                Path(getattr(controller_module, '__file__', '')).resolve(strict=True) !=
                    Path(__file__).with_name('nginx_source_shell_controller.py').resolve(strict=True) or
                type(controller) is not getattr(controller_module, 'SourceShellController', None) or
                controller.bootstrap_context is not context or
                controller.launch is None or controller.launch.context is not context or
                controller.c22_provider is not provider):
            return False
        if private_pair:
            if (controller.launch is not origin or profile_module is None or type(controller.profile) is not
                    getattr(profile_module, 'PrivateNewC34InteropProfile', None) or
                    controller.profile.artifact_capture is not origin.c34_artifact_capture or
                    controller.profile.helper_capture is not provider._private_c34_helper_capture):
                return False
    return True


class SourceBootstrapSupervisor:
    """One exact master plus separately pinned live native runtime/I/O actors.

    Delegates finite slim control and exact initial/first-successor worker
    slots. Native route/selector work remains the caller's responsibility;
    authenticated master barriers certify only its checked, bounded outcome.
    """
    @classmethod
    def from_companion(cls, companion, runtime, io, nonce, epoch, deadline_ns):
        """Bind only after the companion client authenticated STARTED.

        Borrow the companion-owned pidfd; never discover a master by PID file
        or replace the companion's ownership/settlement responsibility.
        """
        require(companion.master_pidfd >= 0 and companion.master_pid > 0 and
            companion.helper is not None and companion.helper.poll() is None and
            not companion.unresolved and not companion.settled,
            'source bootstrap requires a live authenticated companion master')
        master = SimpleNamespace(pid=companion.master_pid,
            pidfd=companion.master_pidfd, start_ticks=companion.master_start,
            executable_hash=companion.binary_hash)
        fault_profile = companion.nginx_env.get('KER_NGINX_SOURCE_ABORT_RETRY_ENABLE')
        require(fault_profile is None or (fault_profile == '1' and
            companion.nginx_env.get('FF_FAULT') == 'flip_fail_once' and
            companion.nginx_env.get('KER_NGINX_SOURCE_FIRST_HUP_ENABLE') == '1'),
            'source abort test is not the exact companion launch profile')
        successor_profile = companion.nginx_env.get('KER_NGINX_SOURCE_SUCCESSOR_ENABLE')
        require(successor_profile is None or (successor_profile == '1' and
            fault_profile is None and 'FF_FAULT' not in companion.nginx_env and
            companion.nginx_env.get('KER_NGINX_SOURCE_FIRST_HUP_ENABLE') == '1'),
            'source successor is not the exact companion launch profile')
        return cls(master, runtime, io, companion.binary, companion.binary_hash,
            nonce, epoch, deadline_ns, allow_abort_retry=fault_profile == '1',
            allow_successor=successor_profile == '1')

    def __init__(self, master, runtime, io, binary, binary_hash, nonce, epoch, deadline_ns,
            *, allow_abort_retry=False, allow_successor=False, observation_deadline_ns=None,
            owner_live=None, initial_cycle_proof=None, expected_config_sha256=None,
            expected_ini_sha256=None, control_only=False):
        self.master, self.runtime, self.io = master, runtime, io
        self.binary = Path(binary).resolve(strict=True)
        self.binary_hash = bytes(binary_hash)
        self.nonce, self.epoch, self.deadline_ns = bytes(nonce), epoch, deadline_ns
        require(owner_live is None or callable(owner_live), 'invalid original owner observation')
        self.owner_live = owner_live
        require(type(control_only) is bool, 'invalid source bootstrap authority phase')
        self.control_only = control_only
        self.supervisor_start = identity._start_ticks(os.getpid())
        self.slim_pid = None
        self.slim_pidfd = -1
        self.slim_start_ticks = 0
        self.slim_reply = None
        self._upgrade_directory_fd = -1
        self._upgrade_master = None
        self.slim_channel = None
        self.slim_stop_sent = False
        self.workers = {}
        self.worker_channels = {}
        self.worker_ready_receivers = {}
        self.worker_process_slots = {}
        self._pending_preexits = {}
        self._authorized_preexits = {}
        self._completed_retirements = {}
        self._source_shell_committed_plans = {}
        self.original_supervisor_identity = None
        self._original_supervisor_pidfd = -1
        self._original_supervisor_output_fd = -1
        require((initial_cycle_proof is None and expected_config_sha256 is None and
                expected_ini_sha256 is None) or
            (initial_cycle_proof is not None and expected_config_sha256 is not None and
                expected_ini_sha256 is not None),
            'shell cycle proof requires the complete initial proof and digest pair')
        self.shell_mode = initial_cycle_proof is not None
        self.record_struct = SHELL_RECORD if self.shell_mode else RECORD
        self.expected_config_sha256 = expected_config_sha256
        self.expected_ini_sha256 = expected_ini_sha256
        self.initial_cycle_proof = None
        if self.shell_mode:
            self.initial_cycle_proof = _validate_cycle_proof(initial_cycle_proof,
                expected_config_sha256, expected_ini_sha256)
        self.slim_proof = None
        self.worker_proofs = {}
        self._source_route_preparations = {}
        self._source_route_park_joins = {}
        self._source_route_commit_receipts = {}
        self._source_route_commit_consumed = set()
        self._source_route_sequences = {}
        self._used_cycle_proofs = set()
        self._cycle_serial_highwater = (
            self.initial_cycle_proof.adapter_cycle_serial if self.shell_mode else 0)
        require(type(allow_abort_retry) is bool and type(allow_successor) is bool and
            not (allow_abort_retry and allow_successor), 'invalid source profile selectors')
        self.allow_abort_retry = allow_abort_retry
        self.allow_successor = allow_successor
        self._executable_files = {}
        require(len(self.nonce) == 16 and any(self.nonce) and epoch > 0 and
            time.monotonic_ns() < deadline_ns <= time.monotonic_ns() +
                (1_800_000_000_000 if self.shell_mode and self.allow_successor else 420_000_000_000),
            'invalid finite source-bootstrap launch context')
        require(len({master.pid, runtime.pid, io.pid, os.getpid()}) == 4,
            'source actors must be separate processes')
        require(observation_deadline_ns is None or
            (type(observation_deadline_ns) is int and
                time.monotonic_ns() < observation_deadline_ns <= deadline_ns),
            'invalid initial observation budget')
        if observation_deadline_ns is None:
            require(identity._sha256(self.binary) == self.binary_hash,
                'pinned Nginx executable changed')
        try:
            for actor in (self.master, self.runtime, self.io):
                self._pin_executable(actor.pid, actor.pidfd, actor.start_ticks,
                    actor.executable_hash, observation_deadline_ns)
            executable_fd = self._executable_files[self.master.pid][0]
            require(self._file_identity(os.stat(self.binary)) ==
                self._executable_files[self.master.pid][1],
                'pinned Nginx pathname does not identify the master executable')
            header = os.pread(executable_fd, 64, 0)
            require(header[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<H', header, 16)[0] == 2,
                'source observer supports the pinned little-endian ELF64 ET_EXEC build only')
            # Parse exports from the same open inode whose content was hashed,
            # even if the original launch pathname is subsequently replaced.
            if observation_deadline_ns is not None:
                self.symbols = bounded_source_exports(executable_fd,
                    self.binary_hash, observation_deadline_ns,
                    require_cycle=self.shell_mode, require_upgrade=self.upgrade_scope)
            else:
                exports = subprocess.run(['nm', '-D', '--defined-only',
                    f'/proc/self/fd/{executable_fd}'], pass_fds=(executable_fd,),
                    check=True, capture_output=True, text=True).stdout.splitlines()
                required_exports = required_source_exports(self.shell_mode)
                self.symbols = {fields[2]: int(fields[0], 16) for line in exports
                    if len(fields := line.split()) == 3 and fields[2] in required_exports}
                require(self.symbols.keys() == required_exports.keys(),
                    'source ABI exports are incomplete')
            self.live(observation_deadline_ns)
            require(observation_deadline_ns is None or
                time.monotonic_ns() < observation_deadline_ns,
                'initial source observation expired')
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _file_identity(value):
        return (value.st_dev, value.st_ino, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)

    @property
    def upgrade_scope(self):
        origin = getattr(getattr(self, 'owner_live', None), '__self__', None)
        return getattr(origin, 'source_case', None) == 'rt25'

    @property
    def successor_final_epoch(self):
        return 2 if self.upgrade_scope else 100

    def _worker_master(self, key):
        if self.upgrade_scope and key == (2, 0):
            require(self._upgrade_master is not None, 'upgrade master is not pinned')
            return self._upgrade_master
        return self.master

    def current_master(self):
        if self.upgrade_scope and (2, 0) in self._source_shell_committed_plans:
            return self._worker_master((2, 0))
        return self.master

    def _pin_upgrade_master(self, record, deadline):
        require(self.upgrade_scope and self._upgrade_directory_fd >= 0 and
            self._upgrade_master is None and record[8:10] == (0, 2),
            'upgrade candidate is outside its one-use source grant')
        pid, start = record[7], record[12]
        require(pid > 0 and pid != self.master.pid and
            self._scalar(self.master.pid, 'ngx_new_binary', '=i') == pid and
            self._scalar(pid, 'ngx_inherited', '=Q') == 1 and
            self._scalar(pid, 'ngx_process', '=Q') == 1,
            'candidate master is not the original USR2 exec child')
        pidfd = os.pidfd_open(pid)
        try:
            require(int(Path(f'/proc/{pid}/stat').read_text().rpartition(')')[2].split()[1]) ==
                self.master.pid, 'upgrade master lost its original parent')
            self._pin_executable(pid, pidfd, start, self.binary_hash, deadline)
            require(self._executable_files[pid][1] == self._executable_files[self.master.pid][1],
                'upgrade master did not exec the same original Nginx inode')
            self._upgrade_master = SimpleNamespace(pid=pid, pidfd=pidfd,
                start_ticks=start, executable_hash=self.binary_hash)
            pidfd = -1
        finally:
            if pidfd >= 0:
                os.close(pidfd)

    def _pin_executable(self, pid, pidfd, start, expected_hash, observation_deadline_ns=None):
        def within_observation():
            require(observation_deadline_ns is None or
                time.monotonic_ns() < observation_deadline_ns,
                'initial executable observation expired')

        within_observation()
        require(pid not in self._executable_files and
            identity._pidfd_pid(pidfd) == pid and identity.process_alive(pidfd) and
            identity._start_ticks(pid) == start, 'executable actor changed before pinning')
        fd = os.open(f'/proc/{pid}/exe', os.O_RDONLY | os.O_CLOEXEC)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode), 'actor executable is not a regular file')
            digest = hashlib.sha256()
            while True:
                within_observation()
                block = os.read(fd, 65536)
                if not block:
                    break
                digest.update(block)
            frozen = self._file_identity(before)
            require(digest.digest() == expected_hash and
                self._file_identity(os.fstat(fd)) == frozen and
                self._file_identity(os.stat(f'/proc/{pid}/exe')) == frozen and
                identity._pidfd_pid(pidfd) == pid and identity.process_alive(pidfd) and
                identity._start_ticks(pid) == start,
                'executable content or actor changed while pinning')
            within_observation()
            self._executable_files[pid] = (fd, frozen)
            fd = -1
        finally:
            if fd >= 0:
                os.close(fd)

    def _executable_live(self, pid):
        held = self._executable_files.get(pid)
        if held is None:
            return False
        fd, frozen = held
        # Keep the hashed inode open for the grant lifetime. Every observation
        # detects exec/replacement or changed metadata on that same inode;
        # active executable writes are additionally denied by Linux ETXTBSY.
        return (self._file_identity(os.fstat(fd)) == frozen and
            self._file_identity(os.stat(f'/proc/{pid}/exe')) == frozen)

    def live(self, observation_deadline_ns=None):
        owner_live = getattr(self, 'owner_live', None)
        if owner_live is not None:
            if observation_deadline_ns is None:
                owner_live()
            else:
                owner_live(observation_deadline_ns)
        require(observation_deadline_ns is None or
            time.monotonic_ns() < observation_deadline_ns,
            'source observation expired')
        require(time.monotonic_ns() < self.deadline_ns, 'source bootstrap authority expired')
        require(identity._start_ticks(os.getpid()) == self.supervisor_start,
            'source supervisor identity changed')
        current_master = self.current_master()
        for actor in (current_master, self.runtime, self.io):
            require(identity._pidfd_pid(actor.pidfd) == actor.pid and
                identity.process_alive(actor.pidfd) and
                identity._start_ticks(actor.pid) == actor.start_ticks and
                self._executable_live(actor.pid),
                'pinned source/native actor is no longer live')
        require(current_master.executable_hash == self.binary_hash, 'master executable is not pinned Nginx')
        if (current_master is not self.master and not identity.process_alive(self.master.pidfd) and
                not getattr(self, '_upgrade_original_term', None)):
            # WINCH drains the old worker. The old master is allowed to
            # exit only after the original supervisor requests final TERM.
            origin = self.owner_live.__self__
            deadline = min(observation_deadline_ns or self.deadline_ns,
                time.monotonic_ns() + PREEXIT_BUDGET_NS)
            self._upgrade_original_term = origin._observe_actor_term(self,
                self.master.pid, self.master.start_ticks, deadline, require_membership=False)
        if self.slim_pidfd >= 0:
            self.check_slim_live(observation_deadline_ns)

    def _abort_only(self):
        origin = getattr(getattr(self, 'owner_live', None), '__self__', None)
        return (getattr(self, 'control_only', False) is True and
            getattr(origin, 'source_case', None) == 'rt21' and
            getattr(getattr(origin, 'c34_artifact_capture', None), 'source_fault', None) == 'flip_fail')

    def _unparked_abort_profile(self):
        origin = getattr(getattr(self, 'owner_live', None), '__self__', None)
        case = getattr(origin, 'source_case', None)
        return (getattr(self, 'control_only', False) is True and case in ('rt20', 'rt22') and
            getattr(getattr(origin, 'c34_artifact_capture', None), 'source_fault', None) ==
                {'rt20': 'ready_never', 'rt22': 'park_never'}[case])

    def _observe_unparked_abort(self, prepared):
        """Retain the exact source timeout without granting a native cutover."""
        if not self._unparked_abort_profile():
            return False
        key = (1, 1)
        entry = self.workers.get(key)
        if entry is None or identity.process_alive(entry[0]):
            return False
        preparation = self._source_route_preparations.get(id(prepared))
        require(not getattr(self, '_master_barriers', set()) and
            not getattr(self, '_completed_master_barriers', set()) and
            not self._source_route_park_joins and not self._source_shell_committed_plans and
            getattr(self, '_activated_workers', set()) == {key} and
            preparation is not None and preparation.context is self and
            preparation.prepared is prepared and preparation.candidate_worker_key == key and
            not identity.process_alive(preparation.candidate[7]) and
            self._source_route_sequences[id(prepared)] == (preparation.command_sequence, None, False),
            'source timeout lost its never-parked C31 preparation')
        info = os.fstat(entry[0])
        joined = os.fstat(preparation.candidate[7])
        require((info.st_dev, info.st_ino) == (joined.st_dev, joined.st_ino),
            'source timeout candidate pidfds do not refer to the same process')
        binding = (entry[0], info.st_dev, info.st_ino, preparation)
        held = getattr(self, '_unparked_abort', None)
        if held is not None:
            require(held[0] == binding, 'source timeout candidate binding changed')
            return True
        deadline = min(self.deadline_ns, time.monotonic_ns() + PREEXIT_BUDGET_NS)
        origin = getattr(self.owner_live, '__self__', None)
        self.live(deadline)
        address = self._scalar(self.master.pid, 'ngx_ff_reload_shm', '=Q')
        values = struct.unpack('=8I', memory(self.master.pid, address, 32))
        markers = struct.unpack('=3I', memory(self.master.pid, address + 48 + 128 * 8, 12))
        require(values[3:7] == (1, 0, 1, 0) and markers == (0, 0, 0),
            'source timeout did not restore the original idle owner')
        digest = origin.observe_unparked_abort(self, deadline)
        self._unparked_abort = (binding, digest)
        return True

    def _can_observe_final_slim_term(self):
        if not self.control_only:
            return False
        origin = getattr(self.owner_live, '__self__', None)
        if getattr(origin, 'source_case', None) in ('rv9', 'rt25'):
            return self.allow_successor and (self.successor_final_epoch, 0) in self._source_shell_committed_plans
        if getattr(origin, 'source_case', None) == 'baseline':
            return (set(self.workers) == {(0, 0)} and
                not getattr(self, '_activated_workers', set()) and
                not getattr(self, '_completed_master_barriers', set()) and
                not self._source_shell_committed_plans)
        if self._unparked_abort_profile():
            return getattr(self, '_unparked_abort', None) is not None
        if self._abort_only():
            return (getattr(self, '_completed_master_barriers', set()) == {(1, 5), (1, 9)} and
                not identity.process_alive(self.workers[(1, 1)][0]))
        return (self.allow_abort_retry and
            self._completed_master_barriers == {(1, 5), (1, 9), (2, 5), (2, 6)} and
            (2, 1) in self._source_shell_committed_plans)

    def check_slim_live(self, observation_deadline_ns=None):
        if identity.process_alive(self.slim_pidfd):
            try:
                require(identity._pidfd_pid(self.slim_pidfd) == self.slim_pid and
                    identity._start_ticks(self.slim_pid) == self.slim_start_ticks and
                    self._executable_live(self.slim_pid),
                    'exact delegated slim actor changed identity')
                return
            except (FileNotFoundError, ProcessLookupError):
                if identity.process_alive(self.slim_pidfd):
                    raise
        require(self._can_observe_final_slim_term(),
            'exact delegated slim actor exited before current-owner shutdown')
        info = os.fstat(self.slim_pidfd)
        binding = (self.slim_pidfd, info.st_dev, info.st_ino,
            self.slim_pid, self.slim_start_ticks)
        held = getattr(self, '_final_slim_term', None)
        if held is not None:
            require(binding == held[0], 'retired slim pidfd changed identity')
            return
        deadline = min(self.deadline_ns, observation_deadline_ns or self.deadline_ns,
            time.monotonic_ns() + PREEXIT_BUDGET_NS)
        origin = getattr(self.owner_live, '__self__', None)
        evidence = origin.observe_final_slim_term(self, deadline)
        require(type(evidence) is SupervisorTermEvidence and
            (evidence.worker_pid, evidence.worker_start_ticks) == binding[3:] and
            evidence.phase == 'stopping' and evidence.signal == 'TERM',
            'original TERM evidence does not match the exact retired slim actor')
        self._final_slim_term = (binding, evidence)

    def _scalar(self, pid, name, code):
        size = struct.calcsize(code)
        return struct.unpack(code, memory(pid, self.symbols[name], size))[0]

    def _unpack_request(self, packet, expected_operation, expected_flags):
        record = self.record_struct
        expected_version = SHELL_VERSION if self.shell_mode else 3
        require(len(packet) == record.size,
            'source bootstrap request has invalid versioned record size')
        fields = list(record.unpack(packet))
        require(fields[:5] == [MAGIC, expected_version, expected_operation,
            record.size, expected_flags],
            'source bootstrap request has unsupported version or envelope')
        return fields

    def _require_full_authority(self, operation):
        if getattr(self, 'control_only', False):
            raise OSError(errno.ENOTSUP,
                f'{operation} requires a later authenticated source worker/cycle phase')

    def _cycle_token_live(self, pid, token):
        if not self.shell_mode:
            return
        require('ngx_cycle' in self.symbols and type(token) is int and token > 0 and
            self._scalar(pid, 'ngx_cycle', '=Q') == token,
            'pinned original ngx_cycle pointer differs from the authenticated proof token')

    def _record_cycle_proof(self, record):
        if not self.shell_mode:
            return None
        return _validate_cycle_proof(_proof_from_record(record),
            self.expected_config_sha256, self.expected_ini_sha256)

    def _initial_cycle_proof_matches(self, record):
        proof = self._record_cycle_proof(record)
        if self.shell_mode:
            require(proof == self.initial_cycle_proof,
                'initial slim/worker cycle proof differs from the accepted origin proof')
            return self.initial_cycle_proof
        return proof

    def _fresh_candidate_cycle_proof(self, record):
        proof = self._record_cycle_proof(record)
        if self.shell_mode:
            key = (proof.adapter_cycle_serial, proof.opaque_cycle_token)
            require(proof.adapter_cycle_serial > self._cycle_serial_highwater and
                key not in self._used_cycle_proofs,
                'candidate cycle serial is stale or its serial/token pair was replayed')
        return proof

    def validate_slim(self, channel, packet, credentials):
        self.live()
        r = self._unpack_request(packet, 1, 0)
        require(r[8:11] == [0, 0, 0] and
            r[14] == self.epoch and r[15] == self.deadline_ns and r[16] == self.nonce and
            not any(r[17:29]), 'source bootstrap request is outside the initial slim profile')
        peer = struct.unpack('=3i', channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        require(credentials == peer == (r[5], os.getuid(), os.getgid()) and
            r[5] == r[6] and r[7] == self.master.pid and r[12] == self.master.start_ticks and
            self.slim_pid is None, 'source bootstrap sender/master/role identity mismatch')
        require(r[5] not in (self.master.pid, self.runtime.pid, self.io.pid, os.getpid()),
            'source slim primary is not a separate actor')
        pidfd = os.pidfd_open(r[5])
        try:
            require(identity._pidfd_pid(pidfd) == r[5] and identity.process_alive(pidfd) and
                identity._start_ticks(r[5]) == r[11] and
                identity._sha256(f'/proc/{r[5]}/exe') == self.binary_hash,
                'source slim executable or process identity mismatch')
            address = self._scalar(self.master.pid, 'ngx_ff_reload_shm', '=Q')
            require(address and address == r[13] and
                self._scalar(r[5], 'ngx_ff_reload_shm', '=Q') == address,
                'source actor did not inherit the exact master reload block')
            mapping = shared_mapping(self.master.pid, address)
            require(shared_mapping(r[5], address) == mapping,
                'source reload block is not the same inherited mapping')
            prefix = memory(self.master.pid, address, 32)
            values = struct.unpack('=8I', prefix)
            require(values[0] == 0x46524c4d and values[1] == 1 and
                32 <= values[2] <= 16384 and address + values[2] <= mapping[1] and
                values[3:] == (0, 0, 0, 0, 0) and memory(r[5], address, 32) == prefix,
                'source reload block is outside the original initial steady state')
            require(self._scalar(self.master.pid, 'ngx_ff_graceful_reload', '=i') == 1 and
                self._scalar(r[5], 'ngx_ff_graceful_reload', '=i') == 1 and
                self._scalar(self.master.pid, 'ngx_process', '=Q') == 1 and
                self._scalar(r[5], 'ngx_process', '=Q') == 1 and
                self._scalar(r[5], 'ngx_ff_process', '=q') == 3,
                'caller is not the original source slim-primary branch')
            # At this exact preflight wait, original source close-all-FDs has
            # finished and the new transport has opened only a pidfd/socket.
            descriptors = {int(path.name): os.readlink(path) for path in
                Path(f'/proc/{r[5]}/fd').iterdir()}
            extra = [value for fd, value in descriptors.items() if fd >= 3]
            require(len(extra) == 2 and extra.count('anon_inode:[pidfd]') == 1 and
                sum(value.startswith('socket:[') for value in extra) == 1,
                'slim primary retained inherited descriptor authority')
            self.live()
            require(memory(self.master.pid, address, 32) == prefix and identity.process_alive(pidfd),
                'source state/actor changed during observation')
            proof = self._initial_cycle_proof_matches(r)
            if self.shell_mode:
                self._cycle_token_live(self.master.pid, proof.opaque_cycle_token)
                self._cycle_token_live(r[5], proof.opaque_cycle_token)
            pinned = pidfd
            pidfd = -1
            self.slim_proof = proof
            return r, pinned
        finally:
            if pidfd >= 0:
                os.close(pidfd)

    def reply_slim(self, channel, packet, credentials, *, control_only=False):
        if getattr(self, 'control_only', False) and not control_only:
            self._require_full_authority('full source slim grant')
        r, self.slim_pidfd = self.validate_slim(channel, packet, credentials)
        self.slim_start_ticks = r[11]
        r[2] = 2
        r[17], r[21] = os.getpid(), self.supervisor_start
        r[18], r[22] = self.runtime.pid, self.runtime.start_ticks
        r[19], r[23] = self.io.pid, self.io.start_ticks
        r[20] = 1 if control_only else 0
        data = self.record_struct.pack(*r)
        # An attempted grant consumes this launch role, including short sends.
        self.slim_pid = r[5]
        self._pin_executable(self.slim_pid, self.slim_pidfd, self.slim_start_ticks,
            self.binary_hash)
        self.live()
        if self.shell_mode:
            self._cycle_token_live(self.master.pid, self.slim_proof.opaque_cycle_token)
            self._cycle_token_live(self.slim_pid, self.slim_proof.opaque_cycle_token)
        rights = array.array('i', (self.runtime.pidfd, self.io.pidfd))
        origin = getattr(self.owner_live, '__self__', None)
        if getattr(origin, 'source_case', None) == 'rt25':
            require(self.shell_mode and self.control_only and control_only and
                origin.c34_artifact_capture is not None and
                getattr(origin, 'context', None) is self,
                'source upgrade requires the accepted private original shell')
            directory = os.memfd_create('ker-fstack-reload-directory',
                os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            self._upgrade_directory_fd = directory
            # Bound to the pinned ff_reload_gendir ABI in the C adapter.
            os.ftruncate(directory, 6424)
            fcntl.fcntl(directory, fcntl.F_ADD_SEALS, fcntl.F_SEAL_SEAL |
                fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK)
            rights.append(directory)
        require(channel.sendmsg([data], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)],
            getattr(socket, 'MSG_NOSIGNAL', 0)) == len(data), 'short source bootstrap grant')
        self.slim_reply, self.slim_channel = tuple(r), channel
        return {'master_pid': self.master.pid, 'slim_pid': self.slim_pid,
            'source_block_address': r[13], 'runtime_pid': self.runtime.pid,
            'io_pid': self.io.pid, 'scope': ('finite slim control only; no generation I/O'
                if control_only else 'transport proof; generation I/O not yet authorized')}

    def stop_slim(self, channel):
        self.live()
        require(channel is self.slim_channel and self.slim_reply is not None and
            self.slim_reply[20] == 1 and not self.slim_stop_sent,
            'no unused control-only slim grant on this exact channel')
        record = list(self.slim_reply)
        record[2] = 3
        self.slim_stop_sent = True
        data = self.record_struct.pack(*record)
        require(channel.send(data, getattr(socket, 'MSG_NOSIGNAL', 0)) == len(data),
            'short correlated source slim STOP')

    def prepare_aborted_retry(self, acquire_native_slot):
        """Adopt one acknowledged native retry plan after the original abort.

        Native RETRY must already have been acknowledged inside the first
        abort barrier while the original candidate was alive. The callback
        transfers that plan's fresh candidate FIFO only after source T0/death.
        It must not create a replacement plan or owner. No READY or selector
        is changed here.
        """
        self._require_full_authority('native retry slot adoption')
        self.live()
        require(self.allow_abort_retry and not hasattr(self, '_retry_slot') and
            getattr(self, '_completed_master_barriers', set()) == {(1, 5), (1, 9)} and
            getattr(self, '_native_retry_cookie', 0) > 0,
            'retry requires the acknowledged first pre-flip abort')
        require(self._aborted_retry_source_idle(),
            'retry requires original T0 and the exact dead aborted successor')
        # Consume before calling native code. Failure never enables another try.
        self._retry_slot = None
        fd = acquire_native_slot()
        try:
            slot = self._aborted_retry_fifo_identity(fd)
            self.live()
            require(self._aborted_retry_source_idle(), 'source/native retry identity changed')
            self._retry_slot = slot
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _aborted_retry_source_idle(self):
        old_pidfd, old = self.workers[(0, 0)]
        dead_pidfd, _ = self.workers[(1, 1)]
        require(identity.process_alive(old_pidfd) and identity._pidfd_pid(old_pidfd) == old[5] and
            identity._start_ticks(old[5]) == old[11], 'retry requires the same live original owner')
        if identity.process_alive(dead_pidfd):
            return False
        address = self.slim_reply[13]
        values = struct.unpack('=8I', memory(self.master.pid, address, 32))
        require(values[:2] == (0x46524c4d, 1) and 32 <= values[2] <= 16384,
            'original reload block changed before retry')
        return (values[3:7] == (1, 0, 1, 0) and struct.unpack('=3I', memory(self.master.pid,
            address + 48 + 128 * 8, 12)) == (0, 0, 0))

    def _aborted_retry_fifo_identity(self, fd):
        value = os.fstat(fd)
        slot = (value.st_dev, value.st_ino)
        require(stat.S_ISFIFO(value.st_mode) and
            fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_WRONLY and
            slot not in (self.workers[(0, 0)][1][24:26], self.workers[(1, 1)][1][24:26]),
            'native retry did not transfer a fresh candidate FIFO')
        return slot

    def _check_private_retry_controller(self, controller, provider, deadline_ns):
        require(threading.current_thread() is threading.main_thread() and
            self.control_only is True and self.shell_mode and self.allow_abort_retry is True and
            _source_provider_matches_context(self, provider, controller) and
            getattr(provider, '_source_retry_allowed', False) is True and not provider._closed and
            provider.broker_readiness is controller.broker_readiness and provider._used_slots == {0, 1} and
            controller._private_first_abort_acknowledged(self) and
            type(deadline_ns) is int and time.monotonic_ns() < deadline_ns <= self.deadline_ns,
            'private retry lacks the acknowledged original ABORT and exact C34 provider')
        self.live(deadline_ns)

    def poll_private_retry_slot(self, controller, provider, deadline_ns):
        """Claim the adopted plan once while the original master is back at T0."""
        self._check_private_retry_controller(controller, provider, deadline_ns)
        if getattr(self, '_private_retry_fds', None) is not None:
            return
        require(not hasattr(self, '_retry_slot'), 'private retry capability transfer already attempted')
        if not self._aborted_retry_source_idle():
            return
        self._retry_slot = None
        fds = provider.take_source_retry_slot(deadline_ns)
        try:
            slot = self._aborted_retry_fifo_identity(fds[0])
            self.live(deadline_ns)
            require(self._aborted_retry_source_idle() and time.monotonic_ns() < deadline_ns,
                'source/native retry identity changed during capability transfer')
            self._retry_slot = slot
            self._private_retry_fds = tuple(fds)
        except BaseException:
            for fd in fds:
                os.close(fd)
            raise

    def reply_private_retry_worker(self, controller, provider, request, relay):
        """Grant epoch 2 only on the exact worker connection read by the SDK."""
        module = sys.modules.get('_ker_nginx_source_shell_controller')
        require(type(request) is getattr(module, '_AcceptedCandidateWorkerRequest', None) and
            request is controller._accepted_retry_worker_request and
            request.token is getattr(module, '_ACCEPTED_CANDIDATE_REQUEST_TOKEN', None) and
            request.controller is controller and request.worker_key == (2, 1) and
            request.listener is controller.listener and
            controller._first_candidate_endpoint_identity(request.listener) == request.listener_identity and
            controller._first_candidate_socket_cookie(request.listener) == request.listener_cookie and
            controller._first_candidate_endpoint_identity(request.channel) == request.channel_identity and
            controller._first_candidate_socket_cookie(request.channel) == request.channel_cookie,
            'private retry grant lacks the exact owned-listener receive receipt')
        self._check_private_retry_controller(controller, provider, request.deadline_ns)
        fds = getattr(self, '_private_retry_fds', None)
        require(fds is not None and not getattr(self, '_private_retry_grant_attempted', False) and
            self._aborted_retry_fifo_identity(fds[0]) == self._retry_slot,
            'private retry grant lacks a fresh unused native FIFO')
        fields = self._unpack_request(request.packet, 1, 1)
        require(fields[8:10] == [1, 2], 'private retry grant expected source epoch 2, generation 1')
        self._private_retry_grant_attempted = True
        watch, receiver = self._reply_worker_impl(request.channel, request.packet, request.credentials,
            fds[0], relay, grant_deadline_ns=request.deadline_ns)
        self.worker_ready_receivers[(2, 1)] = receiver
        return watch

    def observe_private_retry_ready(self, controller, provider, watch, deadline_ns):
        """Authenticate the retry worker's READY on its retained grant socket."""
        self._check_private_retry_controller(controller, provider, deadline_ns)
        key = (2, 1)
        receiver = self.worker_ready_receivers.get(key)
        pidfd, record = self.workers[key]
        supervisor_pidfd = controller._initial_transport.supervisor_pidfd
        require(receiver is not None and watch is controller._retry_candidate_watch and
            (watch['pidfd'], watch['role'], watch['process_slot']) ==
                (pidfd, 1, self.worker_process_slots[key]) and
            (watch['pid'], watch['tid'], watch['start'], watch['slot_device'],
                watch['slot_inode'], watch['cookie']) ==
                (record[5], record[6], record[11], record[24], record[25], record[27]) and
            identity._pidfd_pid(supervisor_pidfd) == os.getpid() and
            receiver.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) == 1,
            'private retry READY changed its worker, slot or credentialed receiver')
        ready = self._receive_privately_granted_ready(receiver, key, supervisor_pidfd,
            deadline_ns)
        self.worker_ready_receivers.pop(key).close()
        self._private_retry_ready_identity = ready
        return ready

    def _receive_privately_granted_ready(self, receiver, key, supervisor_pidfd, deadline_ns):
        pidfd, record = self.workers[key]
        spec = importlib.util.spec_from_file_location('_ker_private_source_ready_verifier',
            Path(__file__).with_name('ker-nginx-companion.py'))
        require(spec is not None and spec.loader is not None, 'source READY verifier unavailable')
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        actor = self._worker_master(key)
        master = SimpleNamespace(pid=actor.pid,
            poll=lambda: None if identity.process_alive(actor.pidfd) else 0)
        ready, observed_pidfd = verifier.receive_owner_ready(receiver,
            expected_cookie=record[27], binary_hash=self.binary_hash,
            master=master, master_pidfd=actor.pidfd, master_start=actor.start_ticks,
            supervisor_pidfd=supervisor_pidfd, supervisor_pid=os.getpid(),
            supervisor_start=self.supervisor_start, expected_role=1, expected_slot=record[24:26],
            expected_worker_pidfd=pidfd, observation_deadline_ns=deadline_ns)
        try:
            require(ready == (record[5], os.getuid(), os.getgid(), 1, record[6], 0,
                record[11], *record[24:26], record[27]),
                'source candidate READY differs from its exact grant')
            self.live(deadline_ns)
            require(self._executable_live(record[5]) and identity.process_alive(pidfd) and
                time.monotonic_ns() < deadline_ns, 'source candidate READY lost live worker authority')
            return ready
        finally:
            os.close(observed_pidfd)

    def _private_successor_provider(self, controller):
        origin = getattr(self.owner_live, '__self__', None)
        provider = getattr(controller, 'c22_provider', None)
        require(self.control_only and self.shell_mode and self.allow_successor and
            getattr(origin, 'source_case', None) in ('rv9', 'rt25') and
            getattr(self, 'owner_live', None) is not None and
            _source_provider_matches_context(self, provider, controller) and
            provider._source_successor_allowed and
            controller._private_initial_retirement_proof is provider._initial_retirement_proof and
            provider._initial_retirement_proof is not None,
            'successor does not have the original rv9 launch and native retirement authority')
        return provider

    def grant_private_successive_worker(self, controller, request, relay):
        provider = self._private_successor_provider(controller)
        module = sys.modules['_ker_nginx_source_shell_controller']
        require(type(request) is module._AcceptedCandidateWorkerRequest and
            request.token is module._ACCEPTED_CANDIDATE_REQUEST_TOKEN and
            request.controller is controller and request.listener is controller.listener and
            request is controller._accepted_successive_worker_request and
            controller._first_candidate_endpoint_identity(request.listener) == request.listener_identity and
            controller._first_candidate_socket_cookie(request.listener) == request.listener_cookie and
            controller._first_candidate_endpoint_identity(request.channel) == request.channel_identity and
            controller._first_candidate_socket_cookie(request.channel) == request.channel_cookie,
            'successive worker lacks the exact owned-listener receive receipt')
        source_epoch, generation = request.worker_key
        require(2 <= source_epoch <= self.successor_final_epoch and generation == source_epoch % 2 and
            request.worker_key not in self.workers, 'successive worker key is stale')
        setup_deadline = request.deadline_ns
        if self.upgrade_scope:
            self._pin_upgrade_master(self.record_struct.unpack(request.packet), setup_deadline)
        slot = self.prepare_successful_successor(
            lambda: provider.take_successor_slot(source_epoch, setup_deadline),
            source_epoch=source_epoch, private_controller=controller)
        try:
            watch, receiver = self._reply_worker_impl(request.channel, request.packet,
                request.credentials, slot, relay, grant_deadline_ns=setup_deadline)
        finally:
            provider.close_successor_slot(slot)
        with receiver:
            self._receive_privately_granted_ready(receiver, request.worker_key,
                controller._initial_transport.supervisor_pidfd, setup_deadline)
        return watch

    def activate_private_successive_worker(self, controller, prepared, watch, deadline_ns):
        self._private_successor_provider(controller)
        key = (watch['source_epoch'], watch['generation'])
        request = controller._accepted_successive_worker_request
        preparation = self._source_route_preparations.get(id(prepared))
        attempted = getattr(self, '_source_prepared_activation_attempts', set())
        require(type(preparation) is _SourceRoutePreparation and
            preparation.context is self and preparation.prepared is prepared and
            preparation.park is None and preparation.candidate_worker_key == key and
            preparation.raw_prepared_ack == preparation.expected_prepared_record and
            self.worker_channels[key] is not None and request.worker_key == key and
            request.deadline_ns == deadline_ns and id(prepared) not in attempted,
            'successive ACTIVATE lacks its exact prepared role, channel and deadline')
        attempted.add(id(prepared))
        self._source_prepared_activation_attempts = attempted
        _validate_source_route_preparation(preparation, prepared, preparation.endpoint)
        self._activate_worker_body(self.worker_channels[key], watch,
            operation_deadline_ns=deadline_ns)

    def prepare_successful_successor(self, acquire_native_slot, *, source_epoch=2,
            private_controller=None):
        """Adopt a fresh FIFO after the preceding original COMMIT and owner exit."""
        if private_controller is None:
            self._require_full_authority('native successor slot adoption')
        else:
            self._private_successor_provider(private_controller)
        require(type(source_epoch) is int and 2 <= source_epoch <= 100,
            'candidate epoch is outside the original repeated reload')
        self.live()
        previous_epoch = source_epoch - 1
        previous_generation = previous_epoch % 2
        expected_previous = {(epoch, operation)
            for epoch in range(1, source_epoch) for operation in (5, 6)}
        require(self.allow_successor and 2 <= source_epoch <= 100 and
            getattr(self, '_successor_slot_epoch', 1) == previous_epoch and
            getattr(self, '_completed_master_barriers', set()) == expected_previous and
            getattr(self, '_native_committed_cookie', 0) > 0,
            'successor requires the preceding acknowledged original commit')
        retired_fd, retired = self.workers[(previous_epoch - 1, 1 - previous_generation)]
        current_fd, current = self.workers[(previous_epoch, previous_generation)]
        address = self.slim_reply[13]

        def original_phase_matches():
            round_state = struct.unpack('=8I', memory(self.master.pid, address, 32))[3:7]
            rx_state = struct.unpack('=3I', memory(self.master.pid,
                address + 48 + 128 * 8, 12))
            if private_controller is not None and not self.upgrade_scope:
                # The original shell starts this transaction only after the
                # requested worker reaches ff_init in T1_GNEW_SPAWN. The
                # predecessor's verified retirement and native receipt precede it.
                return (round_state == (source_epoch, previous_generation,
                    1 - previous_generation, 1) and rx_state == (previous_generation, 0, 1))
            return (round_state == (previous_epoch, previous_generation,
                previous_generation, 0) and rx_state == (previous_generation, 0, 0))

        require(original_phase_matches() and not identity.process_alive(retired_fd) and
            identity.process_alive(current_fd) and
            identity._start_ticks(current[5]) == current[11],
            'successor requires the exact original phase, retired predecessor and live committed owner')
        self._successor_slot_epoch = source_epoch
        self._successor_slot = None
        fd, cookie = acquire_native_slot()
        try:
            value = os.fstat(fd)
            require(type(cookie) is int and cookie == self._native_committed_cookie and
                stat.S_ISFIFO(value.st_mode) and
                fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_WRONLY and
                (value.st_dev, value.st_ino) not in (retired[24:26], current[24:26]),
                'native successor did not preserve the live listener and transfer a fresh FIFO')
            self.live()
            require(original_phase_matches() and not identity.process_alive(retired_fd) and
                identity.process_alive(current_fd) and
                identity._start_ticks(current[5]) == current[11],
                'original successor lineage changed during native adoption')
            self._successor_slot = (value.st_dev, value.st_ino)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _source_round(self, source_epoch):
        if source_epoch == 1:
            return 0, 1
        if source_epoch == 2 and self.allow_abort_retry and getattr(self, '_retry_slot', None):
            return 0, 1
        if (self.allow_successor and 2 <= source_epoch <= 100 and
                source_epoch == getattr(self, '_successor_slot_epoch', None) and
                getattr(self, '_successor_slot', None)):
            return 1 - source_epoch % 2, source_epoch % 2
        raise PermissionError('source round has no bounded acknowledged native lineage')

    def reply_worker(self, channel, packet, credentials, slot_fd, relay):
        """Delegate an exact FIFO slot plus fresh relay/READY to a source child.

        The caller retains slot/relay ownership. The returned receiver must be
        transferred to the contained companion; its queued READY credentials
        originate in the worker, never a copied supervisor message.
        """
        self._require_full_authority('source worker grant')
        return self._reply_worker_impl(channel, packet, credentials, slot_fd, relay)

    def reply_initial_worker(self, channel, packet, credentials, provider, relay,
            grant_deadline_ns):
        """Consume one provider-bound original (0, 0) source worker slot.

        This exception to the full-authority guard does not change
        ``control_only`` or enable master, candidate, or retirement APIs.  The
        exact typed C22 provider is the one-shot slot capability; the existing
        worker path below still performs all actor, cycle, slot, relay, and
        ``ngx_cycle`` validation.
        """
        valid_provider = _source_provider_matches_context(self, provider)
        if not (getattr(self, 'control_only', False) is True and self.shell_mode and
            valid_provider and
            provider.context is self and not provider._closed and
            provider._used_slots == {0} and provider.slot_identities is not None and
            len(provider.slots) == 2 and provider.slots[0] >= 0 and
            not getattr(self, '_initial_worker_grant_consumed', False) and
            not self.workers and not self.worker_channels and
            not getattr(self, '_completed_master_barriers', set()) and
            not getattr(self, '_source_shell_committed_plans', {})):
            raise OSError(errno.ENOTSUP,
                'initial source worker lacks the exact unused C22 provider phase')
        require(type(grant_deadline_ns) is int and
            time.monotonic_ns() < grant_deadline_ns <= self.deadline_ns,
            'initial-only grant deadline exceeds the original source grant')
        initial = self._unpack_request(packet, 1, 1)
        require(initial[8:10] == [0, 0] and
            initial[14:17] == [self.epoch, self.deadline_ns, self.nonce] and
            not any(initial[17:29]),
            'initial-only worker grant does not match source session/key (0, 0)')
        provider._check_actor(grant_deadline_ns)
        self.live()
        self._initial_worker_grant_consumed = True
        return self._reply_worker_impl(channel, packet, credentials,
            provider.slots[0], relay, grant_deadline_ns=grant_deadline_ns)

    def reply_first_candidate_worker(self, channel, packet, credentials,
            provider, relay, grant_deadline_ns, controller, grant):
        """Consume a controller-minted capability for only the first (1, 1) worker."""
        if threading.current_thread() is not threading.main_thread():
            raise PermissionError('first candidate Context grants require the SDK main thread')
        if (type(grant_deadline_ns) is not int or
                time.monotonic_ns() >= grant_deadline_ns or
                grant_deadline_ns > self.deadline_ns):
            raise TimeoutError('first candidate Context grant exceeded its immutable deadline')
        controller_module = sys.modules.get('_ker_nginx_source_shell_controller')
        provider_module = sys.modules.get('_ker_nginx_source_c22_provider')
        if (controller_module is None or provider_module is None or
                not _source_provider_matches_context(self, provider, controller) or
                controller.bootstrap_context is not self or
                controller.launch is None or controller.launch.context is not self or
                controller.c22_provider is not provider or provider.context is not self or
                self.control_only is not True or not self.shell_mode or
                provider._closed or provider._used_slots != {0, 1} or
                set(self.workers) != {(0, 0)} or
                set(self.worker_channels) != {(0, 0)} or
                set(self.worker_process_slots) != {(0, 0)} or
                set(self.worker_proofs) != {(0, 0)} or
                getattr(self, '_activated_workers', set()) or
                getattr(self, '_completed_master_barriers', set()) or
                getattr(self, '_source_shell_committed_plans', {})):
            raise OSError(errno.ENOTSUP,
                'first candidate grant lacks the exact control-only initial source phase')
        cap = controller._consume_first_candidate_worker_grant(grant, self,
            provider, channel, packet, credentials, relay, grant_deadline_ns)
        fields = self._unpack_request(packet, 1, 1)
        master = self.master
        require(time.monotonic_ns() < grant_deadline_ns <= self.deadline_ns and
            fields[8:10] == [1, 1] and fields[14:17] ==
                [self.epoch, self.deadline_ns, self.nonce] and
            controller._first_candidate_worker_grant_consumed and
            cap.worker_key == (1, 1) and cap.cycle_proof ==
                self._fresh_candidate_cycle_proof(fields) and
            cap.initial_cycle_proof == self.worker_proofs[(0, 0)] and
            cap.master_identity == (master.pid, master.start_ticks, master.pidfd),
            'first candidate request changed its key, cycle, master, or deadline')
        require(provider_module._validate_broker_fifo(provider.slots[1],
            'first candidate source slot') is not None and
            provider.slot_identities is not None and
            provider.slot_identities[1] == (os.fstat(provider.slots[1]).st_dev,
                os.fstat(provider.slots[1]).st_ino),
            'first candidate source FIFO identity changed before grant')
        self.live()
        return self._reply_worker_impl(channel, packet, credentials,
            provider.slots[1], relay, grant_deadline_ns=grant_deadline_ns,
            candidate_cycle_proof=cap.cycle_proof)

    def _reply_worker_impl(self, channel, packet, credentials, slot_fd, relay,
            grant_deadline_ns=None, candidate_cycle_proof=None):
        self.live()
        if grant_deadline_ns is not None:
            require(type(grant_deadline_ns) is int and
                time.monotonic_ns() < grant_deadline_ns <= self.deadline_ns,
                'initial worker grant deadline is outside the original source grant')
        require(self.slim_pidfd >= 0 and self.slim_reply[20] == 1,
            'worker grant requires the exact live control-only slim primary')
        record = self.record_struct
        r = self._unpack_request(packet, 1, 1)
        key = (r[9], r[8])
        upgrade = self.upgrade_scope and key == (2, 0)
        master = self._worker_master(key)
        require(not r[10] and
            r[14:17] == [self.epoch, self.deadline_ns, self.nonce] and not any(r[17:29]),
            'worker bootstrap context mismatch')
        peer = struct.unpack('=3i', channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        require(peer == credentials == (r[5], os.getuid(), os.getgid()) and r[5] == r[6] and
            r[7] == master.pid and r[12] == master.start_ticks,
            'worker sender/master identity mismatch')
        pidfd = os.pidfd_open(r[5])
        ready_receiver = ready_sender = None
        retained_channel = None
        try:
            require(identity._pidfd_pid(pidfd) == r[5] and identity.process_alive(pidfd) and
                identity._start_ticks(r[5]) == r[11], 'worker pidfd mismatch')
            fields = Path(f'/proc/{r[5]}/stat').read_text().rpartition(')')[2].split()
            require(int(fields[1]) == master.pid and
                self._scalar(r[5], 'ngx_process', '=Q') == 3 and
                self._scalar(r[5], 'ngx_worker', '=Q') == 0 and
                self._scalar(r[5], 'ngx_ff_process', '=q') == 2 and
                self._scalar(r[5], 'ngx_ff_graceful_reload', '=i') == 1,
                'caller is not source worker zero/secondary of exact master')
            address = self._scalar(master.pid, 'ngx_ff_reload_shm', '=Q')
            require(address == r[13] == self._scalar(r[5], 'ngx_ff_reload_shm', '=Q') and
                shared_mapping(master.pid, address) == shared_mapping(r[5], address),
                'worker does not share original master reload block')
            prefix = memory(master.pid, address, 32)
            values = struct.unpack('=8I', prefix)
            require(values[:2] == (0x46524c4d, 1) and 32 <= values[2] <= 16384 and
                (0 if upgrade else r[9]) == values[3] and values[4] in (0, 1) and values[5] in (0, 1) and
                values[6] in (0, 1) and r[8] == (values[5] if values[6] else values[4]),
                'worker generation does not match original source selection')
            # Native plan roles remain distinct from the source generation.
            # A later epoch needs one acknowledged native adoption, either
            # the first-round abort retry or the preceding committed owner.
            role = 0 if not upgrade and values[3:] == (0, 0, 0, 0, 0) else 1
            old_generation, target_generation = self._source_round(r[9]) if role else (0, 0)
            require((upgrade and values[3:] == (0, 0, 0, 0, 0)) or
                (role == 0 and r[8:10] == [0, 0]) or
                (role == 1 and values[4:7] == (old_generation, target_generation, 1) and
                    r[8] == target_generation),
                'worker is outside the bounded original source rounds')
            if self.shell_mode:
                cycle_proof = (self._record_cycle_proof(r) if upgrade else
                    self._initial_cycle_proof_matches(r) if role == 0 else
                    self._fresh_candidate_cycle_proof(r))
                if candidate_cycle_proof is not None:
                    require(role == 1 and cycle_proof == candidate_cycle_proof,
                        'worker cycle proof differs from the retained candidate grant')
                    cycle_proof = candidate_cycle_proof
                self._cycle_token_live(master.pid, cycle_proof.opaque_cycle_token)
                self._cycle_token_live(r[5], cycle_proof.opaque_cycle_token)
            else:
                cycle_proof = None
            require(key not in self.workers, 'source worker generation already delegated')
            process_slot = self._scalar(r[5], 'ngx_process_slot', '=q')
            require(0 <= process_slot < 128, 'source worker process slot is outside original READY array')
            slot = os.fstat(slot_fd)
            require(stat.S_ISFIFO(slot.st_mode) and
                fcntl.fcntl(slot_fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_WRONLY,
                'worker slot is not a write-only SDK FIFO capability')
            if r[9] > 1:
                if self.allow_successor:
                    current_pidfd, current = self.workers[(r[9] - 1, old_generation)]
                    dead_pidfd, dead = self.workers[(r[9] - 2, target_generation)]
                    require((slot.st_dev, slot.st_ino) == self._successor_slot and
                        r[5] not in (dead[5], current[5]) and
                        not identity.process_alive(dead_pidfd) and
                        identity.process_alive(current_pidfd) and
                        identity._start_ticks(current[5]) == current[11],
                        'successor candidate changed the committed source lineage')
                else:
                    dead_pidfd, dead = self.workers[(1, 1)]
                    require((slot.st_dev, slot.st_ino) == self._retry_slot and
                        r[5] != dead[5] and not identity.process_alive(dead_pidfd),
                        'retry candidate does not match fresh native slot/dead predecessor')
            require(relay.family == socket.AF_UNIX and relay.type & 15 == socket.SOCK_SEQPACKET,
                'worker relay is not Unix seqpacket')
            require(struct.unpack('=3i', relay.getsockopt(socket.SOL_SOCKET,
                socket.SO_PEERCRED, 12)) == (os.getpid(), os.getuid(), os.getgid()),
                'worker relay was not created by exact supervisor')
            ready_receiver, ready_sender = socket.socketpair(socket.AF_UNIX,
                socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
            ready_receiver.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            cookie_option = getattr(socket, 'SO_COOKIE', 57)
            relay_cookie = struct.unpack('=Q', relay.getsockopt(socket.SOL_SOCKET, cookie_option, 8))[0]
            ready_cookie = struct.unpack('=Q', ready_sender.getsockopt(socket.SOL_SOCKET, cookie_option, 8))[0]
            require(relay_cookie and ready_cookie and relay_cookie != ready_cookie,
                'source relay/READY channels are not distinct')
            r[2] = 2
            r[17], r[21] = os.getpid(), self.supervisor_start
            r[18], r[22] = self.runtime.pid, self.runtime.start_ticks
            r[19], r[23] = self.io.pid, self.io.start_ticks
            r[20] = 2 if role == 0 else 4
            r[24:28] = [slot.st_dev, slot.st_ino, relay_cookie, ready_cookie]
            self.live()
            require(memory(master.pid, address, 32) == prefix and identity.process_alive(pidfd),
                'source worker state changed before grant')
            if self.shell_mode:
                self._cycle_token_live(master.pid, cycle_proof.opaque_cycle_token)
                self._cycle_token_live(r[5], cycle_proof.opaque_cycle_token)
            self._pin_executable(r[5], pidfd, r[11], self.binary_hash,
                grant_deadline_ns if grant_deadline_ns is not None else self.deadline_ns)
            # Consume before sending; a short/error send cannot renew authority.
            self.workers[key] = (pidfd, tuple(r))
            pidfd = -1
            if self.shell_mode:
                self.worker_proofs[key] = cycle_proof
                if role and not upgrade:
                    self._used_cycle_proofs.add((cycle_proof.adapter_cycle_serial,
                        cycle_proof.opaque_cycle_token))
                    self._cycle_serial_highwater = cycle_proof.adapter_cycle_serial
            rights = array.array('i', (self.runtime.pidfd, self.io.pidfd, slot_fd,
                relay.fileno(), ready_sender.fileno()))
            if getattr(self, '_upgrade_directory_fd', -1) >= 0:
                rights.append(self._upgrade_directory_fd)
            data = record.pack(*r)
            if self.shell_mode:
                if hasattr(channel, 'setsockopt'):
                    channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                if channel.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) == 1:
                    retained_channel = channel.dup()
            if grant_deadline_ns is not None:
                # The nonblocking send may have an uncertain outcome. Retain
                # both receive endpoints and the process-slot proof before
                # making that one-shot effect attempt.
                require(retained_channel is not None,
                    'initial grant cannot proceed without its retained worker channel')
                self.worker_channels[key] = retained_channel
                self.worker_process_slots[key] = process_slot
                retained_channel = None
                self.worker_ready_receivers[key] = ready_receiver
                ready_receiver = None
                send_initial_worker_grant(channel, data, rights, grant_deadline_ns)
                result = self.worker_ready_receivers.pop(key)
            else:
                require(channel.sendmsg([data], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)],
                    getattr(socket, 'MSG_NOSIGNAL', 0)) == len(data), 'short source worker grant')
                if retained_channel is not None:
                    self.worker_channels[key] = retained_channel
                    self.worker_process_slots[key] = process_slot
                    retained_channel = None
                result = ready_receiver
                ready_receiver = None
            watch = dict(pid=r[5], tid=r[6], role=role, start=r[11],
                slot_device=r[24], slot_inode=r[25], cookie=r[27],
                pidfd=self.workers[key][0], source_epoch=r[9], generation=r[8],
                process_slot=process_slot)
            return watch, result
        finally:
            if pidfd >= 0: os.close(pidfd)
            if ready_receiver is not None: ready_receiver.close()
            if ready_sender is not None: ready_sender.close()
            if retained_channel is not None: retained_channel.close()

    def slim_exited(self):
        require(self.slim_pidfd >= 0, 'no exact slim actor was delegated')
        return not identity.process_alive(self.slim_pidfd)

    def observe_committed_current_owner(self, key, *, private_controller=None):
        """Capture the required live, idle source snapshot before shutdown."""
        retry = key == (2, 1) and private_controller is not None and self.allow_abort_retry
        if getattr(self, 'control_only', False):
            require(private_controller is not None and
                key == private_controller._private_committed_worker_key(self) and
                self._private_candidate_preexit_authority(private_controller),
                'private current-owner observation lacks the exact PREEXIT phase')
        else:
            self._require_full_authority('committed current-owner observation')
        repeated_final = self.allow_successor and key == (self.successor_final_epoch, 0)
        upgrade = self.upgrade_scope and key == (2, 0)
        require(self.shell_mode and (not self.allow_successor or repeated_final) and
            (retry or not self.allow_abort_retry) and key in self._source_shell_committed_plans,
            'current-owner proof requires the exact source-shell COMMIT profile')
        self.live()
        committed = self._source_shell_committed_plans[key]
        pidfd, worker = self.workers[key]
        require(identity._pidfd_pid(pidfd) == worker[5] and
            identity.process_alive(pidfd) and
            identity._start_ticks(worker[5]) == worker[11] and
            self.worker_proofs.get(key) == committed['cycle_proof'] and
            (retry or repeated_final or key[0] == 1) and (key[0], 9) not in self._completed_master_barriers and
            not any(epoch > key[0] for epoch, _ in self.workers),
            'committed current owner is stale, aborted, or has a successor')
        master = self._worker_master(key)
        address = self._scalar(master.pid, 'ngx_ff_reload_shm', '=Q')
        require(address == committed['source_block_address'],
            'current owner source block changed after COMMIT')
        values = struct.unpack('=8I', memory(master.pid, address, 32))
        owner, stopped, fsm = struct.unpack('=3I', memory(master.pid,
            address + 48 + 128 * 8, 12))
        require(values[3] == (0 if upgrade else key[0]) and values[4] == key[1] and values[6] == 0 and
            owner == key[1] and stopped == 0 and fsm == 0,
            'source master is not idle on the committed current generation')
        committed['idle_observation'] = {
            'observed_ns': time.monotonic_ns(),
            'source_snapshot': tuple(values[3:7]),
            'owner': owner,
            'stopped': stopped,
            'fsm': fsm,
            'master_pid': master.pid,
            'master_start_ticks': master.start_ticks,
            'slim_pid': self.slim_pid,
            'slim_start_ticks': self.slim_start_ticks,
        }
        return dict(committed['idle_observation'])

    def _private_candidate_preexit_authority(self, controller):
        """Require the exact committed private worker and native retirement proof."""
        if getattr(self, 'allow_successor', False):
            try:
                provider = self._private_successor_provider(controller)
                key = controller._private_committed_worker_key(self)
                final_epoch = self.successor_final_epoch
                predecessor = (final_epoch - 1, 1)
                expected = {(epoch, epoch % 2) for epoch in range(final_epoch + 1)}
                return (key == (final_epoch, 0) and set(self.workers) == expected and
                    provider._successor_retire_receipt is not None and
                    provider._successor_retire_receipt[:2] == (final_epoch, predecessor) and
                    provider._source_committed and provider._source_park_epoch == final_epoch and
                    all(not identity.process_alive(self.workers[retired][0])
                        for retired in expected - {key}) and
                    identity.process_alive(self.workers[key][0]))
            except (OSError, RuntimeError, AttributeError, KeyError):
                return False
        controller_module = sys.modules.get('_ker_nginx_source_shell_controller')
        profile_module = sys.modules.get('_ker_nginx_source_c34_profile')
        provider_module = sys.modules.get('_ker_nginx_source_c22_provider')
        origin = getattr(getattr(self, 'owner_live', None), '__self__', None)
        origin_module = sys.modules.get(type(origin).__module__) if origin is not None else None
        provider = getattr(controller, 'c22_provider', None)
        proof_type = getattr(provider_module, 'SourceInitialListenerRetirementProof', None)
        proof = getattr(provider, '_initial_retirement_proof', None)
        transport = getattr(controller, 'initial_worker_binding', None)
        cap = getattr(controller, '_first_candidate_worker_grant', None)
        if (getattr(self, 'control_only', False) is not True or
                getattr(self, 'shell_mode', False) is not True or
                controller_module is None or profile_module is None or
                provider_module is None or origin_module is None or
                Path(getattr(controller_module, '__file__', '')).resolve(strict=True) !=
                    Path(__file__).with_name('nginx_source_shell_controller.py').resolve(strict=True) or
                Path(getattr(origin_module, '__file__', '')).resolve(strict=True) !=
                    Path(__file__).with_name('nginx_source_origin.py').resolve(strict=True) or
                type(controller) is not getattr(controller_module, 'SourceShellController', None) or
                type(controller.profile) is not getattr(profile_module, 'PrivateNewC34InteropProfile', None) or
                type(origin) is not getattr(origin_module, 'PrivateC34OriginalShellLaunch', None) or
                controller.bootstrap_context is not self or controller.launch is not origin or
                origin.context is not self or controller.profile.artifact_capture is not
                    origin.c34_artifact_capture or controller.profile.helper_capture is not
                    getattr(provider, '_private_c34_helper_capture', None) or
                provider.context is not self or getattr(provider, '_closed', True) or
                not _source_provider_matches_context(self, provider, controller) or
                type(proof) is not proof_type or proof.provider is not provider or
                proof.context is not self or
                getattr(self, '_source_initial_listener_retirements', {}).get(id(provider)) is not proof or
                getattr(controller, '_private_initial_retirement_proof', None) is not proof or
                getattr(controller, '_valid_private_initial_exit_observation', lambda *_: False)(
                    transport, self) is not True or
                getattr(controller, '_first_candidate_worker_grant_consumed', False) is not True or
                getattr(controller, '_first_candidate_activation_delivered', False) is not True or
                type(cap) is not getattr(controller_module, '_FirstCandidateWorkerGrant', None) or
                cap is not getattr(controller, '_first_candidate_worker_grant', None) or
                cap.controller is not controller or cap.context is not self or cap.provider is not provider):
            return False
        key = controller._private_committed_worker_key(self)
        retry = key == (2, 1)
        keys = {(0, 0), (1, 1), (2, 1)} if retry else {(0, 0), (1, 1)}
        if (key is None or set(self.workers) != keys or set(self.worker_channels) != keys or
                (retry and not self.allow_abort_retry)):
            return False
        try:
            if retry:
                controller._check_private_initial_worker_exit_binding(transport, provider, self)
            else:
                controller._check_first_candidate_phase(transport)
            return True
        except (OSError, PermissionError, RuntimeError, TimeoutError, AttributeError, KeyError):
            return False

    def _private_preexit_authority(self, controller, key):
        if key != (0, 0):
            return self._private_candidate_preexit_authority(controller)
        origin = getattr(getattr(self, 'owner_live', None), '__self__', None)
        return (self.control_only and self.shell_mode and not self.allow_abort_retry and
            not self.allow_successor and
            (getattr(origin, 'source_case', None) == 'baseline' or self._abort_only() or
                self._unparked_abort_profile()) and
            getattr(controller, 'launch', None) is origin and
            getattr(origin, 'context', None) is self and
            getattr(controller, 'bootstrap_context', None) is self and
            getattr(controller, '_private_initial_shutdown_binding', lambda _: None)(self) is not None)

    def poll_private_candidate_preexit(self, controller):
        """Consume one exact PREEXIT from the current private worker."""
        if threading.current_thread() is not threading.main_thread():
            raise PermissionError('private candidate PREEXIT requires the SDK main thread')
        origin = getattr(getattr(self, 'owner_live', None), '__self__', None)
        if (getattr(origin, 'source_case', None) == 'baseline' or self._abort_only() or
                self._unparked_abort_profile()):
            key = (0, 0)
            require(self._private_preexit_authority(controller, key),
                'initial PREEXIT lacks the exact baseline authority')
        else:
            require(self._private_candidate_preexit_authority(controller),
                'candidate PREEXIT lacks the exact private post-COMMIT authority')
            key = controller._private_committed_worker_key(self)
        pending = getattr(controller, '_private_candidate_preexit_pending', None)
        if pending is not None:
            require(self._pending_preexits.get(pending.operation_id, (None,))[0] is pending and
                time.monotonic_ns() < pending.deadline_ns,
                'private candidate PREEXIT pending identity changed')
            return pending
        require(not getattr(self, '_private_candidate_preexit_consumed', False),
            'private candidate PREEXIT receive attempt was already consumed')
        channel = self.worker_channels[key]
        if not select.select([channel], [], [], 0)[0]:
            return None
        if key == (0, 0):
            address = self._scalar(self.master.pid, 'ngx_ff_reload_shm', '=Q')
            values = struct.unpack('=8I', memory(self.master.pid, address, 32))
            markers = struct.unpack('=3I', memory(self.master.pid, address + 48 + 128 * 8, 12))
            expected = ((1, 0, 1, 0) if self._abort_only() or self._unparked_abort_profile()
                else (0, 0, 0, 0))
            require(values[3:7] == expected and markers == (0, 0, 0),
                'source master is not idle on its initial worker')
        else:
            self.observe_committed_current_owner(key, private_controller=controller)
        self._private_candidate_preexit_consumed = True
        packet, ancillary, flags, _ = channel.recvmsg(PREEXIT_RECORD_BYTES + 1,
            socket.CMSG_SPACE(12) + socket.CMSG_SPACE(8 * 4),
            getattr(socket, 'MSG_CMSG_CLOEXEC', 0) | getattr(socket, 'MSG_DONTWAIT', 0))
        credentials = []
        invalid = False
        received_fds = []
        for level, kind, value in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(value) == 12:
                credentials.append(struct.unpack('=3i', value))
            elif level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                fds = array.array('i')
                fds.frombytes(value[:len(value) - len(value) % fds.itemsize])
                received_fds.extend(fds)
                invalid = True
            else:
                invalid = True
        for fd in received_fds:
            os.close(fd)
        require(not invalid and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) and
            len(packet) == PREEXIT_RECORD_BYTES and len(credentials) == 1,
            'malformed private candidate PREEXIT transport')
        pending = self._accept_worker_preexit(key, channel, packet, credentials[0],
            private_retry=key == (2, 1), private_initial=key == (0, 0))
        controller._private_candidate_preexit_pending = pending
        return pending

    def authorize_private_candidate_preexit(self, controller, pending):
        """Observe exact Origin TERM for the one retained private PREEXIT."""
        existing = getattr(self, '_authorized_preexits', {}).get(
            getattr(pending, 'operation_id', None))
        if existing is not None:
            require(type(existing) is SupervisorTermEvidence and
                getattr(controller, '_private_candidate_preexit_pending', None) is pending and
                getattr(controller, '_private_candidate_preexit_evidence', None) is existing and
                self._pending_preexits.get(pending.operation_id, (None,))[0] is pending and
                existing.worker_pid == pending.worker_pid and
                existing.worker_start_ticks == pending.worker_start_ticks and
                existing.phase == 'stopping' and existing.signal == 'TERM' and
                time.monotonic_ns() < pending.deadline_ns,
                'private TERM authorization already consumed or pending receipt changed')
            return pending
        require(self._private_preexit_authority(controller, pending.key) and
            getattr(controller, '_private_candidate_preexit_pending', None) is pending and
            self._pending_preexits.get(pending.operation_id, (None,))[0] is pending and
            time.monotonic_ns() < pending.deadline_ns,
            'private TERM observation lacks its exact controller-owned pending request')
        provider = getattr(self.owner_live, '__self__', None)
        evidence = provider.observe_worker_term(self, pending)
        require(type(evidence) is SupervisorTermEvidence and
            self.original_supervisor_identity is not None and
            evidence.phase == 'stopping' and evidence.signal == 'TERM' and
            evidence.worker_pid == pending.worker_pid and
            evidence.worker_start_ticks == pending.worker_start_ticks and
            evidence.supervisor_pid == self.original_supervisor_identity['pid'] and
            evidence.supervisor_start_ticks == self.original_supervisor_identity['start_ticks'] and
            evidence.supervisor_exe_sha256 == self.original_supervisor_identity['exe_sha256'] and
            evidence.run_id == self.original_supervisor_identity['run_id'] and
            evidence.controller == self.original_supervisor_identity['controller'] and
            evidence.stack == self.original_supervisor_identity['stack'] and
            evidence.receipt_device == self.original_supervisor_identity['output_device'] and
            evidence.receipt_inode == self.original_supervisor_identity['output_inode'] and
            type(evidence.receipt_sha256) is bytes and len(evidence.receipt_sha256) == 32 and
            time.monotonic_ns() < pending.deadline_ns,
            'Origin TERM evidence does not match the private candidate PREEXIT')
        self._authorized_preexits[pending.operation_id] = evidence
        controller._private_candidate_preexit_evidence = evidence
        return pending

    def poll_worker_preexit(self):
        """Consume one PREEXIT packet from a retained source-shell worker channel.

        This is the source-controller's nonblocking poll hook. It does not
        authorize native STOP; the caller must separately supply the parsed
        original-supervisor TERM evidence to authorize_worker_preexit().
        """
        self._require_full_authority('worker PREEXIT')
        if not self.shell_mode or not self.worker_channels:
            return None
        channels = list(self.worker_channels.items())
        readable, _, _ = select.select([channel for _, channel in channels], [], [], 0)
        if not readable:
            return None
        channel = readable[0]
        key = next(key for key, value in channels if value is channel)
        packet, ancillary, flags, _ = channel.recvmsg(PREEXIT_RECORD_BYTES + 1,
            socket.CMSG_SPACE(12) + socket.CMSG_SPACE(8 * 4),
            getattr(socket, 'MSG_CMSG_CLOEXEC', 0) | getattr(socket, 'MSG_DONTWAIT', 0))
        credentials = []
        invalid = False
        received_fds = []
        for level, kind, value in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(value) == 12:
                credentials.append(struct.unpack('=3i', value))
            elif level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                fds = array.array('i')
                fds.frombytes(value[:len(value) - len(value) % fds.itemsize])
                received_fds.extend(fds)
                invalid = True
            else:
                invalid = True
        for fd in received_fds:
            os.close(fd)
        require(not invalid and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) and
            len(packet) == PREEXIT_RECORD_BYTES and len(credentials) == 1,
            'malformed source worker PREEXIT transport')
        pending = self._accept_worker_preexit(key, channel, packet, credentials[0])
        return pending

    def _accept_worker_preexit(self, key, channel, packet, credentials, *,
            private_retry=False, private_initial=False):
        require(self.shell_mode and key in self.workers and
            self.worker_channels.get(key) is channel,
            'PREEXIT channel is not the retained source worker endpoint')
        header = PREEXIT_HEADER.unpack_from(packet)
        require(header == (PREEXIT_MAGIC, PREEXIT_VERSION, PREEXIT_REQUEST,
            PREEXIT_RECORD_BYTES, 0), 'unsupported source worker PREEXIT envelope')
        record = list(SHELL_RECORD.unpack_from(packet, PREEXIT_HEADER.size))
        offset = PREEXIT_HEADER.size + SHELL_RECORD.size
        slot, role, operation_id, operation_deadline_ns, native_commit_cookie = \
            PREEXIT_TAIL.unpack_from(packet, offset)
        pidfd, granted = self.workers[key]
        proof = self.worker_proofs.get(key)
        pid, start = granted[5], granted[11]
        master = self._worker_master(key)
        local_epoch = 0 if self.upgrade_scope and key == (2, 0) else key[0]
        peer = struct.unpack('=3i', channel.getsockopt(socket.SOL_SOCKET,
            socket.SO_PEERCRED, 12))
        committed = getattr(self, '_source_shell_committed_plans', {}).get(key)
        now = time.monotonic_ns()
        require(credentials == peer == (pid, os.getuid(), os.getgid()) and
            record[0:3] == [MAGIC, SHELL_VERSION, PREEXIT_REQUEST] and
            record[3:11] == [SHELL_RECORD.size, 1, pid, granted[6], master.pid,
                key[1], key[0], 0] and
            record[11:13] == [start, master.start_ticks] and
            record[13] == granted[13] and
            record[14:17] == [self.epoch, self.deadline_ns, self.nonce] and
            record[17:24] == list(granted[17:24]) and
            record[24:28] == list(granted[24:28]) and
            record[28] == 0,
            'PREEXIT source identity mismatch')
        actual_proof = _proof_from_record(record)
        expected_role = 2 if private_initial else 4
        current = (key == (0, 0) and native_commit_cookie == 0 and
            committed is None and proof is self.initial_cycle_proof) if private_initial else (
            committed is not None and committed['worker_pid'] == pid and
            committed['worker_start_ticks'] == start and committed['slot'] == slot and
            committed['ready_cookie'] == granted[27] and
            committed['native_current_cookie'] == native_commit_cookie and
            native_commit_cookie > 0 and committed['cycle_proof'] == proof and
            committed.get('idle_observation') is not None and
            committed['idle_observation']['source_snapshot'][0] == local_epoch and
            committed['idle_observation']['source_snapshot'][1] == key[1] and
            committed['idle_observation']['source_snapshot'][3] == 0)
        require(proof is not None and actual_proof == proof and current and
            record[20] == expected_role and record[27] == granted[27] and
            record[2] == PREEXIT_REQUEST and role == expected_role and
            slot == getattr(self, 'worker_process_slots', {}).get(key) and
            operation_id > 0 and operation_id not in getattr(self, '_seen_preexit_ids', set()) and
            now < operation_deadline_ns <= self.deadline_ns and
            operation_deadline_ns - now <= PREEXIT_BUDGET_NS and
            (not self.allow_successor or (self.control_only and
                key == (self.successor_final_epoch, 0))) and
            (not self.allow_abort_retry or (private_retry and key == (2, 1) and self.control_only is True and
                    self._completed_master_barriers == {(1, 5), (1, 9), (2, 5), (2, 6)})) and
            (key[0], 9) not in getattr(self, '_completed_master_barriers', set()) and
            identity._pidfd_pid(pidfd) == pid and identity.process_alive(pidfd) and
            identity._start_ticks(pid) == start,
            'PREEXIT is stale, uncommitted, non-current, or outside its bounded grant')
        seen = getattr(self, '_seen_preexit_ids', set())
        seen.add(operation_id)
        self._seen_preexit_ids = seen
        request_digest = hashlib.sha256(packet).digest()
        pending = PendingSourceRetirement(key, operation_id, pid, start, slot,
            request_digest, operation_deadline_ns)
        if not hasattr(self, '_pending_preexits'):
            self._pending_preexits = {}
        require(operation_id not in self._pending_preexits,
            'source worker PREEXIT operation is duplicated')
        self._pending_preexits[operation_id] = (pending, packet, channel)
        return pending

    def authorize_worker_preexit(self, operation_id):
        """Ask the captured Origin launch to produce exact original TERM proof.

        A caller cannot authorize cleanup by passing a boolean or constructing
        a receipt-shaped value. The provider is the bound Origin liveness
        callback retained when this source context was constructed.
        """
        self._require_full_authority('worker PREEXIT authorization')
        pending, _, _ = self._pending_preexits.get(operation_id, (None, None, None))
        provider = getattr(getattr(self, 'owner_live', None), '__self__', None)
        require(pending is not None and callable(getattr(provider,
            'observe_worker_term', None)),
            'original supervisor TERM receipt provider is not connected')
        evidence = provider.observe_worker_term(self, pending)
        require(type(evidence) is SupervisorTermEvidence and
            getattr(self, 'original_supervisor_identity', None) is not None,
            'original supervisor TERM provider returned no typed proof')
        require(pending is not None and evidence.phase == 'stopping' and
            evidence.signal == 'TERM' and evidence.observed_ns > 0 and
            len(evidence.receipt_sha256) == 32 and any(evidence.receipt_sha256) and
            evidence.worker_pid == pending.worker_pid and
            evidence.worker_start_ticks == pending.worker_start_ticks and
            evidence.supervisor_pid == self.original_supervisor_identity['pid'] and
            evidence.supervisor_start_ticks == self.original_supervisor_identity['start_ticks'] and
            evidence.supervisor_exe_sha256 == self.original_supervisor_identity['exe_sha256'] and
            evidence.run_id == self.original_supervisor_identity['run_id'] and
            evidence.controller == self.original_supervisor_identity['controller'] and
            evidence.stack == self.original_supervisor_identity['stack'] and
            evidence.receipt_device == self.original_supervisor_identity['output_device'] and
            evidence.receipt_inode == self.original_supervisor_identity['output_inode'] and
            identity._pidfd_pid(self._original_supervisor_pidfd) == evidence.supervisor_pid and
            identity.process_alive(self._original_supervisor_pidfd) and
            identity._start_ticks(evidence.supervisor_pid) == evidence.supervisor_start_ticks and
            time.monotonic_ns() < pending.deadline_ns,
            'original supervisor TERM evidence does not match pending owner exit')
        self._authorized_preexits[operation_id] = evidence
        return pending

    def bind_original_supervisor_identity(self, origin, controller, stack):
        """Bind exact launch-owned process and output-directory capabilities."""
        provider = getattr(self.owner_live, '__self__', None)
        require(self.shell_mode and origin is provider and
            type(controller) is int and controller > 0 and
            type(stack) is str and stack and
            getattr(origin, 'process', None) is not None and
            getattr(origin, 'pidfd', -1) >= 0 and getattr(origin, 'output_fd', -1) >= 0,
            'invalid original supervisor identity anchor')
        deadline = min(self.deadline_ns, origin.deadline_ns)
        origin.live_supervisor(deadline)
        pid = origin.process.pid
        start_ticks = origin.start
        run_id = origin.run_id
        pidfd = origin.pidfd
        output_fd = origin.output_fd
        require(type(run_id) is str and run_id and
            identity._pidfd_pid(pidfd) == pid and identity.process_alive(pidfd) and
            identity._start_ticks(pid) == start_ticks,
            'captured original supervisor identity changed')
        output_stat = os.fstat(output_fd)
        path_stat = os.stat(origin.output, follow_symlinks=False)
        require(stat.S_ISDIR(output_stat.st_mode) and output_stat.st_uid == os.getuid() and
            stat.S_IMODE(output_stat.st_mode) & 0o077 == 0 and
            (output_stat.st_dev, output_stat.st_ino) == origin.output_identity ==
                (path_stat.st_dev, path_stat.st_ino),
            'original supervisor output directory changed')
        python_identity = origin.python.frozen[:2]
        python_stat = os.stat(f'/proc/{pid}/exe')
        require((python_stat.st_dev, python_stat.st_ino) == python_identity and
            type(origin.python.sha256) is bytes and len(origin.python.sha256) == 32,
            'original supervisor Python inode is not the held interpreter')
        bound_identity = {
            'pid': pid,
            'start_ticks': start_ticks,
            'run_id': run_id,
            'controller': controller,
            'stack': stack,
            'exe_sha256': origin.python.sha256,
            'output_device': output_stat.st_dev,
            'output_inode': output_stat.st_ino,
            'python_device': python_identity[0],
            'python_inode': python_identity[1],
        }
        previous = getattr(self, 'original_supervisor_identity', None)
        if previous is not None:
            require(previous == bound_identity and
                self._original_supervisor_pidfd >= 0 and
                identity._pidfd_pid(self._original_supervisor_pidfd) == pid and
                identity.process_alive(self._original_supervisor_pidfd) and
                self._original_supervisor_output_fd >= 0 and
                (lambda held: (held.st_dev, held.st_ino))(os.fstat(
                    self._original_supervisor_output_fd)) ==
                    (output_stat.st_dev, output_stat.st_ino),
                'original supervisor identity changed after binding')
            return dict(previous)
        retained_pidfd = retained_output = -1
        try:
            retained_pidfd = os.dup(pidfd)
            retained_output = os.dup(output_fd)
        except BaseException:
            for fd in (retained_pidfd, retained_output):
                if fd >= 0:
                    os.close(fd)
            raise
        self._original_supervisor_pidfd = retained_pidfd
        self._original_supervisor_output_fd = retained_output
        self.original_supervisor_identity = bound_identity
        return dict(self.original_supervisor_identity)

    def complete_worker_preexit(self, operation_id, settlement):
        """Send SETTLED only for exact SDK shutdown evidence after native exit."""
        self._require_full_authority('worker SETTLED acknowledgement')
        return self._complete_worker_preexit(operation_id, settlement)

    def _complete_worker_preexit(self, operation_id, settlement, *, relay=None):
        require(type(settlement) is SourceRetirementProof,
            'source retirement needs a structured native settlement receipt')
        pending, packet, channel = self._pending_preexits.get(
            operation_id, (None, None, None))
        evidence = self._authorized_preexits.get(operation_id)
        require(pending is not None and evidence is not None and
            settlement.operation_id == operation_id and
            settlement.request_sha256 == pending.request_sha256 ==
                hashlib.sha256(packet).digest() and
            settlement.supervisor_term_sha256 == evidence.receipt_sha256 and
            all(type(value) is bytes and len(value) == 32 and any(value) for value in
                (settlement.request_sha256, settlement.supervisor_term_sha256,
                 settlement.broker_stop_sha256, settlement.native_shutdown_sha256)) and
            (settlement.c28_drain_sha256 is None if pending.key == (0, 0) else
                type(settlement.c28_drain_sha256) is bytes and
                len(settlement.c28_drain_sha256) == 32 and any(settlement.c28_drain_sha256)) and
            settlement.c31_outstanding == 0 and settlement.c31_last_result >= 0 and
            time.monotonic_ns() < pending.deadline_ns,
            'source native settlement receipt is incomplete or expired')
        key = pending.key
        pidfd, _ = self.workers[key]
        require(channel is self.worker_channels[key] and
            identity._pidfd_pid(pidfd) == pending.worker_pid and
            identity.process_alive(pidfd) and
            identity._start_ticks(pending.worker_pid) == pending.worker_start_ticks and
            not identity.process_alive(self.runtime.pidfd) and
            not identity.process_alive(self.io.pidfd),
            'retirement ACK requires the exact worker and settled native actors')
        request = packet
        response = (PREEXIT_HEADER.pack(PREEXIT_MAGIC, PREEXIT_VERSION,
            PREEXIT_SETTLED, SETTLED_RECORD_BYTES, 0) + request +
            SETTLED_TAIL.pack(0, 0, settlement.c31_outstanding,
                settlement.c31_last_packet_id, settlement.c31_last_result, 1))
        if relay is not None:
            require(time.monotonic_ns() < pending.deadline_ns,
                'source worker relay shutdown missed its original operation budget')
            # The runtime has exited. End the SDK's remaining write side while
            # holding the original descriptor until Origin confirms settlement.
            relay.shutdown(socket.SHUT_WR)
        sent = -1
        while time.monotonic_ns() < pending.deadline_ns:
            try:
                sent = channel.sendmsg([response], [],
                    getattr(socket, 'MSG_NOSIGNAL', 0) | getattr(socket, 'MSG_DONTWAIT', 0))
                break
            except InterruptedError:
                continue
            except BlockingIOError:
                remaining = max(0, (pending.deadline_ns - time.monotonic_ns()) /
                    1_000_000_000)
                if not remaining or not select.select([], [channel], [], remaining)[1]:
                    break
        require(len(response) == SETTLED_RECORD_BYTES and sent == len(response) and
            time.monotonic_ns() < pending.deadline_ns,
            'source worker SETTLED acknowledgement missed its original operation budget')
        self._completed_retirements[key] = settlement
        del self._pending_preexits[operation_id]
        del self._authorized_preexits[operation_id]
        return settlement

    def retirement_proof_for(self, key):
        """Return the immutable typed proof only after a correlated SETTLED ACK."""
        self._require_full_authority('worker retirement proof')
        require(key in getattr(self, '_completed_retirements', {}),
            'source owner retirement has no completed SDK settlement')
        return self._completed_retirements[key]

    def activate_worker(self, channel, watch):
        """Permit original READY only after caller verifies C31 PREPARED.

        This consumes the already granted first-HUP identity; it grants no
        new slot, deadline, generation, or process authority.
        """
        self._require_full_authority('source worker activation')
        self._activate_worker_body(channel, watch)

    def activate_prepared_first_candidate(self, prepared, channel, watch,
            controller, grant):
        """Activate role (1,1) only after the exact credentialed C31 PREPARED ACK."""
        controller_module = sys.modules.get('_ker_nginx_source_shell_controller')
        profile_module = sys.modules.get('_ker_nginx_source_c34_profile')
        artifacts_module = sys.modules.get('_ker_nginx_source_c34_artifacts')
        origin = getattr(getattr(self, 'owner_live', None), '__self__', None)
        origin_module = (sys.modules.get(type(origin).__module__)
            if origin is not None else None)
        private_controller = (controller_module is not None and
            Path(getattr(controller_module, '__file__', '')).resolve(strict=True) ==
                Path(__file__).with_name('nginx_source_shell_controller.py').resolve(strict=True) and
            type(controller) is getattr(controller_module, 'SourceShellController', None))
        private_profile = (private_controller and profile_module is not None and
            type(controller.profile) is getattr(profile_module, 'PrivateNewC34InteropProfile', None))
        private_origin = (private_profile and origin_module is not None and
            Path(getattr(origin_module, '__file__', '')).resolve(strict=True) ==
                Path(__file__).with_name('nginx_source_origin.py').resolve(strict=True) and
            type(origin) is getattr(origin_module, 'PrivateC34OriginalShellLaunch', None))
        require(self.control_only is True and self.shell_mode and private_origin and
            controller.bootstrap_context is self and controller.launch is origin and
            origin.context is self and controller.profile.origin_module is origin_module and
            artifacts_module is not None and
            Path(getattr(artifacts_module, '__file__', '')).resolve(strict=True) ==
                Path(__file__).with_name('nginx_source_c34_artifact_provider.py').resolve(strict=True) and
            type(origin.c34_artifact_capture) is
                getattr(artifacts_module, 'PrivateC34ArtifactCapture', None) and
            controller.profile.artifact_capture is origin.c34_artifact_capture and
            controller.profile.helper_capture is origin.c34_artifact_capture.helper_capture,
            'private source activation requires the exact NEWC34 profile and Origin launch')
        grant_type = getattr(controller_module, '_FirstCandidateWorkerGrant', None)
        accepted_type = getattr(controller_module, '_AcceptedCandidateWorkerRequest', None)
        accepted = getattr(controller, '_accepted_candidate_worker_request', None)
        provider = getattr(controller, 'c22_provider', None)
        observed = getattr(controller, '_first_candidate_observed_ready', None)
        require(type(grant_type) is type and type(grant) is grant_type and
            grant.token is getattr(controller_module, '_FIRST_CANDIDATE_GRANT_TOKEN', None) and
            grant.controller is controller and grant.context is self and
            grant.worker_key == (1, 1) and grant.cycle_proof is self.worker_proofs.get((1, 1)) and
            grant.initial_cycle_proof is self.initial_cycle_proof and
            grant is getattr(controller, '_first_candidate_worker_grant', None) and
            getattr(controller, '_first_candidate_worker_grant_consumed', False) is True and
            getattr(controller, '_first_candidate_prepare_attempted', False) is True and
            accepted is not None and type(accepted) is accepted_type and
            accepted is grant.accepted_request and accepted.controller is controller and
            accepted.token is getattr(controller_module, '_ACCEPTED_CANDIDATE_REQUEST_TOKEN', None) and
            accepted.worker_key == (1, 1) and accepted.channel is grant.channel and
            accepted.listener is controller.listener and
            accepted.packet == grant.packet and accepted.credentials == grant.credentials and
            accepted.deadline_ns == grant.grant_deadline_ns and
            accepted.listener_identity == controller._first_candidate_endpoint_identity(
                controller.listener) and
            accepted.listener_cookie == controller._first_candidate_socket_cookie(
                controller.listener) and
            accepted.channel_identity == grant.channel_identity and
            accepted.channel_cookie == grant.channel_cookie and
            grant.relay_identity[:3] == controller._first_candidate_endpoint_identity(grant.relay)[:3] and
            grant.relay_cookie == controller._first_candidate_socket_cookie(grant.relay) and
            grant.channel_identity == controller._first_candidate_endpoint_identity(grant.channel) and
            grant.channel_cookie == controller._first_candidate_socket_cookie(grant.channel) and
            grant.provider is provider and getattr(provider, '_closed', True) is False and
            callable(getattr(provider, '_check_actor', None)) and
            _source_provider_matches_context(self, provider, controller) and
            observed is not None and len(observed) == 10 and
            getattr(controller, '_first_candidate_observed_pidfd', -1) >= 0 and
            controller._first_candidate_source_prepared is prepared and
            controller.initial_worker_binding is grant.initial_transport,
            'private source activation lacks the consumed controller-minted candidate grant')
        # Reuse the existing provider's bounded actor/PIDFD/executable check;
        # this does not recapture artifacts inside any later 100 ms phase.
        provider._check_actor(self.deadline_ns)
        require(self.control_only is True and self.shell_mode and
            type(prepared) is SimpleNamespace and type(watch) is dict and
            type(channel) is socket.socket and self.live() is None,
            'private source activation requires its exact control-only context')
        registry = getattr(self, '_source_route_preparations', None)
        preparation = registry.get(id(prepared)) if type(registry) is dict else None
        require(type(preparation) is _SourceRoutePreparation and
            preparation.token is _SOURCE_HANDOFF_TOKEN and
            preparation.context is self and preparation.prepared is prepared and
            preparation.park is None and preparation.source_epoch == 1 and
            preparation.raw_prepared_ack == preparation.expected_prepared_record and
            preparation.prepared_credentials[0] == preparation.actors[0] and
            preparation.prepared_credentials[1:] == (os.getuid(), os.getgid()) and
            preparation.candidate_channel is controller._first_candidate_relay_anchor and
            preparation.candidate_channel_identity ==
                _source_socket_identity(preparation.candidate_channel)[:4] and
            preparation.candidate_channel_identity[0] != grant.relay_cookie and
            getattr(prepared, '_source_route_preparation', None) is preparation and
            preparation.cycle_proof is self.worker_proofs.get((1, 1)) and
            preparation.candidate_cycle_proof is preparation.cycle_proof and
            self.worker_proofs.get((0, 0)) is self.initial_cycle_proof and
            set(self.workers) == {(0, 0), (1, 1)} and
            set(self.worker_channels) == {(0, 0), (1, 1)} and
            self.worker_channels[(1, 1)] is channel and
            not getattr(self, '_completed_master_barriers', set()) and
            not getattr(self, '_source_shell_committed_plans', {}) and
            not getattr(self, '_source_route_park_joins', {}),
            'private source activation lacks its exact registered C31 PREPARED phase')
        expected = preparation.candidate
        identity = sys.modules[origin_module.__name__].identity
        require((observed[0], observed[3], observed[6], observed[7], observed[8], observed[9]) ==
                (expected[0], 1, expected[3], expected[4], expected[5], expected[6]) and
            identity._pidfd_pid(controller._first_candidate_observed_pidfd) == expected[0] and
            identity.process_alive(controller._first_candidate_observed_pidfd) and
            grant.channel_identity == controller._first_candidate_endpoint_identity(channel) and
            grant.channel_cookie == controller._first_candidate_socket_cookie(channel) and
            grant.cycle_proof is preparation.cycle_proof,
            'private source ACTIVATE is not bound to the retained role-1 READY and channel')
        require((watch.get('source_epoch'), watch.get('generation'), watch.get('role'),
                watch.get('pid'), watch.get('tid'), watch.get('start'),
                watch.get('slot_device'), watch.get('slot_inode'), watch.get('cookie')) ==
            (1, 1, 1, expected[0], expected[1], expected[3], expected[4],
                expected[5], expected[6]) and
            getattr(self, '_activated_workers', set()) == set() and
            preparation.fields[2] == 5 and preparation.fields[8:10] == (0, self.epoch) and
            preparation.source_epoch == 1 and
            preparation.fields[5:8] == expected[:3] and
            preparation.fields[11:15] == expected[3:7],
            'private source activation watch differs from the C31 PREPARED role-1 record')
        attempted = getattr(self, '_source_prepared_activation_attempts', set())
        require(id(prepared) not in attempted,
            'private source ACTIVATE was already attempted')
        attempted.add(id(prepared))
        self._source_prepared_activation_attempts = attempted
        _validate_source_route_preparation(preparation, prepared, preparation.endpoint)
        self.live()
        self._activate_worker_body(channel, watch)

    def activate_prepared_retry_candidate(self, controller, prepared, watch, deadline_ns):
        """Release original epoch-2 READY only after its credentialed C31 PREPARED."""
        provider = controller.c22_provider
        self._check_private_retry_controller(controller, provider, deadline_ns)
        key = (2, 1)
        channel = self.worker_channels[key]
        preparation = self._source_route_preparations.get(id(prepared))
        prior, operation_id, sequence, deadline = self._source_retry_prepare_attempt
        request = controller._accepted_retry_worker_request
        require(type(preparation) is _SourceRoutePreparation and
            preparation.context is self and preparation.prepared is prepared and
            preparation.candidate_worker_key == key and preparation.source_epoch == 2 and
            preparation.park is None and preparation.raw_prepared_ack == preparation.expected_prepared_record and
            preparation.candidate_channel is controller._retry_candidate_relay_anchor and
            _source_socket_identity(preparation.candidate_channel)[:4] ==
                preparation.candidate_channel_identity and
            preparation.candidate_cycle_proof is self.worker_proofs[key] and
            preparation.operation_id == operation_id and preparation.command_sequence == sequence and
            request.deadline_ns == deadline_ns == deadline and
            _source_socket_identity(channel)[0] == request.channel_cookie and
            getattr(controller, '_retry_candidate_prepared', None) is prepared and
            watch is controller._retry_candidate_watch and self._activated_workers == {(1, 1)},
            'retry ACTIVATE lacks its exact credentialed C31 PREPARED and retained worker')
        _validate_source_route_retry(self, prior, preparation.endpoint, preparation.actors,
            preparation.current, preparation.candidate)
        _validate_source_route_preparation(preparation, prepared, preparation.endpoint)
        self._activate_worker_body(channel, watch, operation_deadline_ns=deadline_ns)

    def _activate_worker_body(self, channel, watch, *, operation_deadline_ns=None):
        """Shared original-record send after one of the two exact gates."""
        if operation_deadline_ns is None:
            self.live()
        else:
            self.live(operation_deadline_ns)
        key = (watch['source_epoch'], watch['generation'])
        old_generation, target_generation = self._source_round(key[0])
        require(key[1] == target_generation and key in self.workers,
            'source activation is not an exact delegated bounded candidate')
        pidfd, granted = self.workers[key]
        record = list(granted)
        cycle_proof = self.worker_proofs.get(key) if self.shell_mode else None
        master = self._worker_master(key)
        activated = getattr(self, '_activated_workers', set())
        attempted = getattr(self, '_activation_attempts', set())
        require(key not in activated and (not self.shell_mode or key not in attempted) and
            record[20] == 4 and
            identity.process_alive(pidfd) and identity._pidfd_pid(pidfd) == watch['pid'] and
            identity._start_ticks(watch['pid']) == record[11] and
            struct.unpack('=3i', channel.getsockopt(socket.SOL_SOCKET,
                socket.SO_PEERCRED, 12)) == (watch['pid'], os.getuid(), os.getgid()),
            'source activation candidate/channel changed identity')
        if self.shell_mode:
            require(cycle_proof == self._record_cycle_proof(record),
                'source activation candidate proof changed after grant')
            self._cycle_token_live(master.pid, cycle_proof.opaque_cycle_token)
            self._cycle_token_live(watch['pid'], cycle_proof.opaque_cycle_token)
        values = struct.unpack('=8I', memory(master.pid, record[13], 32))
        expected = ((0, 0, 0, 0) if self.upgrade_scope and key == (2, 0) else
            (key[0], old_generation, target_generation, 1))
        require(values[3:7] == expected,
            'original source round changed before candidate activation')
        record[2] = 4
        if self.shell_mode:
            self._cycle_token_live(master.pid, cycle_proof.opaque_cycle_token)
            self._cycle_token_live(watch['pid'], cycle_proof.opaque_cycle_token)
        payload = self.record_struct.pack(*record)
        flags = getattr(socket, 'MSG_NOSIGNAL', 0)
        # Consume the one-shot attempt before send. In v4, only an exact
        # successful send may authorize a later master barrier; a short/error
        # send remains consumed but never masquerades as ACTIVATE delivery.
        if self.shell_mode:
            # A positive Python socket timeout can poll even with MSG_DONTWAIT.
            channel.setblocking(False)
            deadline_ns = min(self.deadline_ns, record[15],
                operation_deadline_ns if operation_deadline_ns is not None else self.deadline_ns)
            if time.monotonic_ns() >= deadline_ns:
                raise TimeoutError('source activation expired before send')
            flags |= getattr(socket, 'MSG_DONTWAIT', 0)
            attempted.add(key)
            self._activation_attempts = attempted
        else:
            activated.add(key)
            self._activated_workers = activated
        sent = channel.send(payload, flags)
        if self.shell_mode and time.monotonic_ns() >= deadline_ns:
            raise TimeoutError('source activation send completed after its deadline')
        require(sent == len(payload), 'short source activation send')
        if self.shell_mode:
            activated.add(key)
            self._activated_workers = activated

    def master_barrier(self, channel, packet, credentials, apply):
        """Bind an original master park/commit/pre-flip-abort to native work.

        ``apply`` must validate its original-SYN queue/route/containment proofs
        before returning. An exception sends no success receipt; post-swap
        uncertainty must be quarantined by the caller.
        """
        self._require_full_authority('source master barrier')
        return self._master_barrier_body(channel, packet, credentials, apply,
            private_source=False)

    def private_source_master_barrier(self, channel, packet, credentials,
            apply, controller, prepared, grant, provider):
        """Authorize a private cutover, including the one adopted retry."""
        require(type(packet) is bytes and len(packet) == self.record_struct.size,
            'invalid private source master barrier size')
        fields = self.record_struct.unpack(packet)
        operation, source_epoch = fields[2], fields[9]
        retry = source_epoch == 2
        candidate_key = (source_epoch, 1)
        prior_barriers = {(1, 5), (1, 9)} if retry else set()
        activated = {(1, 1), candidate_key}
        require(source_epoch in (1, 2) and (not retry or operation in (5, 6)),
            'unsupported private source cutover round or operation')
        controller_module = sys.modules.get('_ker_nginx_source_shell_controller')
        profile_module = sys.modules.get('_ker_nginx_source_c34_profile')
        origin = getattr(getattr(self, 'owner_live', None), '__self__', None)
        origin_module = sys.modules.get(type(origin).__module__) if origin is not None else None
        require(self.control_only is True and self.shell_mode and
            controller_module is not None and profile_module is not None and
            type(controller) is getattr(controller_module, 'SourceShellController', None) and
            controller.bootstrap_context is self and controller.launch is origin and
            origin_module is not None and
            type(origin) is getattr(origin_module, 'PrivateC34OriginalShellLaunch', None) and
            type(controller.profile) is getattr(profile_module, 'PrivateNewC34InteropProfile', None) and
            controller.profile.artifact_capture is origin.c34_artifact_capture and
            type(grant) is getattr(controller_module, '_FirstCandidateWorkerGrant', None) and
            grant is controller._first_candidate_worker_grant and
            grant.token is getattr(controller_module, '_FIRST_CANDIDATE_GRANT_TOKEN', None) and
            grant.context is self and grant.controller is controller and
            controller._first_candidate_worker_grant_consumed is True and
            controller._first_candidate_prepare_attempted is True and
            controller._first_candidate_activation_delivered is True and
            (getattr(controller, '_retry_candidate_prepared', None) if retry else
                controller._first_candidate_source_prepared) is prepared and
            grant.provider is provider and controller.c22_provider is provider and
            getattr(provider, '_closed', True) is False and
            _source_provider_matches_context(self, provider, controller) and
            controller._first_candidate_worker_pending is True and
            getattr(self, '_activated_workers', set()) == activated,
            'private source master barrier lacks the exact activated C34 controller/provider')
        if retry:
            require(controller._private_first_abort_acknowledged(self) and
                controller._retry_candidate_ready is self._private_retry_ready_identity and
                getattr(provider, '_source_retry_slot_delivered', False) is True,
                'private source cutover lacks the acknowledged adopted retry worker')
        preparation = getattr(self, '_source_route_preparations', {}).get(id(prepared))
        require(type(preparation) is _SourceRoutePreparation and
            preparation.context is self and preparation.prepared is prepared and
            preparation.park is None and preparation.source_epoch == source_epoch and
            preparation.raw_prepared_ack == preparation.expected_prepared_record and
            preparation.cycle_proof is self.worker_proofs.get(candidate_key),
            'private source master barrier lacks its registered PREPARED/ACTIVATE tuple')
        if operation == 5:
            joins = getattr(self, '_source_route_park_joins', {})
            park = getattr(provider, '_source_park_evidence', None)
            prior = self._source_route_abort_receipt[0] if retry else None
            require(getattr(self, '_completed_master_barriers', set()) == prior_barriers and
                id(prepared) not in joins and
                (type(park) is _SourceC28ParkEvidence and
                    joins.get(id(prior.prepared)) is prior and prior.park is park and
                    park.deadline_ns < fields[28] if retry else not joins and park is None),
                'private source PARK is repeated or already partially joined')
        elif operation in (6, 9):
            if operation == 9:
                fault = getattr(origin.c34_artifact_capture, 'source_fault', None)
                require(((self.allow_abort_retry and fault == origin_module.SOURCE_RETRY_FAULT) or
                            (self._abort_only() and fault == 'flip_fail')) and
                    getattr(controller.profile.helper_capture, 'source_fault', None) == fault,
                    'private source ABORT requires the captured fault profile')
            park = getattr(provider, '_source_park_evidence', None)
            joined = getattr(self, '_source_route_park_joins', {}).get(id(prepared))
            require(type(park) is _SourceC28ParkEvidence and
                type(joined) is _SourceRoutePreparation and
                joined.prepared is prepared and joined.park is park and
                joined.context is self and park.context is self and
                park.provider is provider and preparation.park is None and
                park.deadline_ns == fields[28] and
                getattr(provider, '_source_park_deadline_ns', None) == park.deadline_ns and
                getattr(self, '_completed_master_barriers', set()) == prior_barriers | {(source_epoch, 5)} and
                getattr(self, '_master_control_deadlines', {}).get(source_epoch) == park.deadline_ns and
                getattr(provider, '_source_committed', False) is False and
                getattr(provider, '_source_abort_result', None) is None,
                f"private source {'COMMIT' if operation == 6 else 'ABORT'} lacks "
                'the exact registered PARK/PREPARED join or deadline')
        else:
            raise OSError(errno.ENOTSUP, 'unsupported private source master operation')
        attempts = getattr(self, '_private_source_master_attempts', set())
        key = (source_epoch, operation)
        require(key not in attempts,
            'private source master operation already has an attempt')
        attempts.add(key)
        self._private_source_master_attempts = attempts
        provider._check_actor(fields[28] if retry or operation == 9 else self.deadline_ns)
        return self._master_barrier_body(channel, packet, credentials, apply,
            private_source=True)

    def private_successive_master_barrier(self, channel, packet, credentials, apply,
            controller, prepared):
        provider = self._private_successor_provider(controller)
        require(type(packet) is bytes and len(packet) == self.record_struct.size,
            'invalid successive master barrier envelope')
        fields = self.record_struct.unpack(packet)
        operation, epoch = fields[2], fields[9]
        key = (epoch, epoch % 2)
        prior = {(previous, step) for previous in range(1, epoch) for step in (5, 6)}
        preparation = self._source_route_preparations.get(id(prepared))
        require(2 <= epoch <= 100 and operation in (5, 6),
            'invalid successive master stage')
        require(type(preparation) is _SourceRoutePreparation and
            preparation.context is self and preparation.prepared is prepared and
            preparation.source_epoch == epoch and preparation.candidate_worker_key == key and
            preparation.cycle_proof is self.worker_proofs.get(key) and
            key in self._activated_workers and
            self._completed_master_barriers == (prior if operation == 5 else prior | {(epoch, 5)}),
            'successive master stage lacks its exact activated candidate and prior COMMIT')
        if operation == 6:
            join = self._source_route_park_joins.get(id(prepared))
            require(type(join) is _SourceRoutePreparation and
                join.park is provider._source_park_evidence and join.park.deadline_ns == fields[28],
                'successive COMMIT does not reuse the original PARK receipt')
        provider._check_actor(fields[28])
        return self._master_barrier_body(channel, packet, credentials, apply,
            private_source=True)

    def _master_barrier_body(self, channel, packet, credentials, apply,
            *, private_source):
        """Shared original Master barrier validation and one-shot native ACK."""
        record_struct = self.record_struct
        require(len(packet) == record_struct.size, 'invalid source master barrier size')
        record = list(record_struct.unpack(packet))
        operation = record[2]
        source_epoch = record[9]
        upgrade = self.upgrade_scope and source_epoch == 2
        source_markers = (1, 1, 1, 0) if upgrade else None
        old_generation, target_generation = self._source_round(source_epoch)
        expected_version = SHELL_VERSION if self.shell_mode else 3
        require(operation in (5, 6, 9) and (operation != 9 or self.allow_abort_retry or self._abort_only()) and
            record[:2] == [0x4b534247, expected_version] and
            record[3:11] == [record_struct.size, 2, self.master.pid, self.master.pid,
                self.master.pid, target_generation, source_epoch, 0] and
            record[11:13] == [self.master.start_ticks, self.master.start_ticks] and
            record[14:17] == [self.epoch, self.deadline_ns, self.nonce] and
            not any(record[17:28]) and
            time.monotonic_ns() < record[28] <= self.deadline_ns and
            record[28] - time.monotonic_ns() <= 100_000_000 and
            credentials == (self.master.pid, os.getuid(), os.getgid()) and
            struct.unpack('=3i', channel.getsockopt(socket.SOL_SOCKET,
                socket.SO_PEERCRED, 12)) == credentials,
            'source master barrier correlation/credentials mismatch')
        if private_source and source_epoch > 1:
            self.live(record[28])
        else:
            self.live()
        if self.shell_mode:
            barrier_proof = self._record_cycle_proof(record)
            accepted_proof = self.worker_proofs.get((1, 1) if upgrade else
                (source_epoch, target_generation))
            require(accepted_proof is not None and barrier_proof == accepted_proof,
                'source master barrier does not echo the accepted candidate cycle proof')
            self._cycle_token_live(self.master.pid, barrier_proof.opaque_cycle_token)
        address = self._scalar(self.master.pid, 'ngx_ff_reload_shm', '=Q')
        require(address == record[13] == self.slim_reply[13] and
            (source_epoch, target_generation) in getattr(self, '_activated_workers', set()),
            'source master barrier lacks activated exact candidate')
        values = struct.unpack('=8I', memory(self.master.pid, address, 32))
        owner, stopped, fsm = struct.unpack('=3I',
            memory(self.master.pid, address + 48 + 128 * 8, 12))
        expected_markers = {5: (old_generation, 0), 6: (target_generation, 0),
            9: (old_generation, 1)}
        if upgrade:
            require(self._scalar(self.master.pid, 'ngx_new_binary', '=i') ==
                self._worker_master((2, 0)).pid, 'original USR2 child changed before WINCH')
            expected_markers[6] = (target_generation, 1)
        else:
            source_markers = (source_epoch, old_generation, target_generation, 1)
        require(values[3:7] == source_markers and fsm == (0 if upgrade else 2) and
            (owner, stopped) == expected_markers[operation],
            'source master barrier does not match original T2 park/release state')
        if operation == 9:
            candidate_pidfd, candidate = self.workers[(source_epoch, 1)]
            require(identity.process_alive(candidate_pidfd) and
                identity._pidfd_pid(candidate_pidfd) == candidate[5] and
                identity._start_ticks(candidate[5]) == candidate[11],
                'pre-flip abort successor already exited; quarantine required')
        barriers = getattr(self, '_master_barriers', set())
        key = (source_epoch, operation)
        require(key not in barriers and (operation == 5 or
            ((source_epoch, 5) in barriers and (source_epoch, 6) not in barriers and
                (source_epoch, 9) not in barriers)),
            'source master barrier is repeated or out of order')
        if operation == 5:
            if not hasattr(self, '_master_control_deadlines'):
                self._master_control_deadlines = {}
            self._master_control_deadlines[source_epoch] = record[28]
        else:
            require(record[28] == self._master_control_deadlines[source_epoch],
                'source master attempted to renew the PARK deadline')
        barriers.add(key)
        self._master_barriers = barriers
        control_deadline = record[28]
        require(time.monotonic_ns() < control_deadline,
            'source operation expired before native barrier work')
        outcome = apply(operation, control_deadline)
        if operation == 9 and (private_source or outcome is not None) and not self._abort_only():
            require(type(outcome) is dict and set(outcome) == {'native_retry_cookie'} and
                type(outcome['native_retry_cookie']) is int and outcome['native_retry_cookie'] > 0,
                'native retry adoption receipt is malformed')
        if operation == 6 and self.allow_successor:
            require(type(outcome) is dict and set(outcome) == {'native_current_cookie'} and
                type(outcome['native_current_cookie']) is int and outcome['native_current_cookie'] > 0,
                'native successful commit lacks its preserved current-listener receipt')
        if operation == 6 and self.shell_mode:
            require(type(outcome) is dict and set(outcome) == {'native_current_cookie'} and
                type(outcome['native_current_cookie']) is int and
                outcome['native_current_cookie'] > 0,
                'source-shell COMMIT lacks its actual native current-plan cookie')
        committed_candidate = None
        if operation == 6 and self.shell_mode:
            plan_key = (source_epoch, target_generation)
            candidate_pidfd, candidate = self.workers[plan_key]
            candidate_proof = self.worker_proofs.get(plan_key)
            require((upgrade or candidate_proof == barrier_proof) and
                identity.process_alive(candidate_pidfd) and
                identity._pidfd_pid(candidate_pidfd) == candidate[5] and
                identity._start_ticks(candidate[5]) == candidate[11] and
                plan_key in self._activated_workers and
                (source_epoch, 5) in self._completed_master_barriers and
                self.worker_process_slots.get(plan_key) is not None,
                'source-shell COMMIT lacks its exact activated candidate endpoint')
            committed_candidate = (plan_key, candidate_pidfd, candidate,
                candidate_proof)
        require(time.monotonic_ns() < control_deadline,
            'native barrier exceeded original operation deadline; quarantine required')
        if private_source and source_epoch > 1:
            self.live(control_deadline)
        else:
            self.live()
        require(struct.unpack('=8I', memory(self.master.pid, address, 32))[3:7] ==
            source_markers,
            'source round changed during native barrier')
        if self.shell_mode:
            self._cycle_token_live(self.master.pid, barrier_proof.opaque_cycle_token)
        if operation == 9:
            require(identity.process_alive(candidate_pidfd) and
                identity._start_ticks(candidate[5]) == candidate[11] and
                struct.unpack('=3I', memory(self.master.pid,
                    address + 48 + 128 * 8, 12)) == (0, 1, 2),
                'pre-flip abort lost its live successor/parked source state')
        record[2] = operation + 2
        record[17], record[21] = os.getpid(), self.supervisor_start
        record[18], record[22] = self.runtime.pid, self.runtime.start_ticks
        record[19], record[23] = self.io.pid, self.io.start_ticks
        rights = array.array('i', (self.runtime.pidfd, self.io.pidfd))
        if self.shell_mode:
            self._cycle_token_live(self.master.pid, barrier_proof.opaque_cycle_token)
        payload = record_struct.pack(*record)
        flags = getattr(socket, 'MSG_NOSIGNAL', 0)
        if self.shell_mode:
            channel.setblocking(False)
            flags |= getattr(socket, 'MSG_DONTWAIT', 0)
        require(time.monotonic_ns() < control_deadline,
            'source operation expired before native receipt; quarantine required')
        sent = channel.sendmsg([payload], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)], flags)
        if self.shell_mode and time.monotonic_ns() >= control_deadline:
            raise TimeoutError('source master native barrier receipt completed after its deadline')
        require(sent == len(payload),
            'short source master native barrier receipt')
        if committed_candidate is not None:
            plan_key, candidate_pidfd, candidate, candidate_proof = committed_candidate
            retained = getattr(self, 'worker_channels', {}).get(plan_key)
            require(retained is not None and time.monotonic_ns() < candidate[15],
                'source-shell COMMIT cannot notify a retained in-grant candidate endpoint')
            evidence_record = list(candidate)
            evidence_record[2] = COMMIT_EVIDENCE
            evidence = (PREEXIT_HEADER.pack(PREEXIT_MAGIC, PREEXIT_VERSION,
                COMMIT_EVIDENCE, COMMIT_EVIDENCE_RECORD_BYTES, 0) +
                SHELL_RECORD.pack(*evidence_record) +
                struct.pack('=Q', outcome['native_current_cookie']))
            sent = -1
            evidence_deadline = control_deadline if private_source else candidate[15]
            while time.monotonic_ns() < evidence_deadline:
                try:
                    sent = retained.sendmsg([evidence], [],
                        getattr(socket, 'MSG_NOSIGNAL', 0) |
                        getattr(socket, 'MSG_DONTWAIT', 0))
                    break
                except InterruptedError:
                    continue
                except BlockingIOError:
                    remaining = max(0, (evidence_deadline - time.monotonic_ns()) /
                        1_000_000_000)
                    if not remaining or not select.select([], [retained], [], remaining)[1]:
                        break
            require(sent == len(evidence) and time.monotonic_ns() < evidence_deadline,
                'source-shell COMMIT evidence send failed or exceeded original worker grant')
        if not hasattr(self, '_completed_master_barriers'):
            self._completed_master_barriers = set()
        self._completed_master_barriers.add(key)
        if operation == 9 and outcome is not None:
            # The native callback certifies an acknowledged adoption while
            # the exact source candidate is still alive. After this receipt
            # the unchanged source failure path may terminate that candidate.
            self._native_retry_cookie = outcome['native_retry_cookie']
        if operation == 6 and self.allow_successor:
            self._native_committed_cookie = outcome['native_current_cookie']
        if operation == 6 and self.shell_mode:
            plan_key, candidate_pidfd, candidate, candidate_proof = committed_candidate
            candidate_master = self._worker_master(plan_key)
            self._source_shell_committed_plans[plan_key] = {
                'worker_pid': candidate[5],
                'worker_start_ticks': candidate[11],
                'slot': self.worker_process_slots.get(plan_key),
                'ready_cookie': candidate[27],
                'native_current_cookie': outcome['native_current_cookie'],
                'cycle_proof': candidate_proof,
                'barrier': (source_epoch, 6),
                'master_pid': candidate_master.pid,
                'master_start_ticks': candidate_master.start_ticks,
                'master_pidfd': candidate_master.pidfd,
                'slim_pid': self.slim_pid,
                'slim_start_ticks': self.slim_start_ticks,
                'slim_pidfd': self.slim_pidfd,
                'source_block_address': candidate[13],
                'source_idle_snapshot': tuple(values[3:7]),
            }

    def close(self):
        """Release observation handles; companion still owns subtree settlement."""
        if self.slim_pidfd >= 0:
            os.close(self.slim_pidfd)
            self.slim_pidfd = -1
        if getattr(self, '_upgrade_master', None) is not None:
            os.close(self._upgrade_master.pidfd)
            self._upgrade_master = None
        for pidfd, _ in self.workers.values():
            os.close(pidfd)
        self.workers.clear()
        for channel in getattr(self, 'worker_channels', {}).values():
            channel.close()
        self.worker_channels = {}
        for receiver in getattr(self, 'worker_ready_receivers', {}).values():
            receiver.close()
        self.worker_ready_receivers = {}
        for fd in getattr(self, '_private_retry_fds', None) or ():
            os.close(fd)
        self._private_retry_fds = None
        for fd_name in ('_original_supervisor_pidfd', '_original_supervisor_output_fd',
                '_upgrade_directory_fd'):
            fd = getattr(self, fd_name, -1)
            if fd >= 0:
                os.close(fd)
                setattr(self, fd_name, -1)
        for fd, _ in self._executable_files.values():
            os.close(fd)
        self._executable_files.clear()
