"""Private outer-to-inner ker-run relay wire codec (little-endian)."""
import struct

MAGIC = 0x4B524333  # KRC3
VERSION = 1
INNER_READY = 1
VERIFY = 2
VERIFY_RESULT = 3
STOP = 4
STOP_ACCEPTED = 5
SETTLED = 6

COMMON = struct.Struct('<IHHII16sQQ')
READY = struct.Struct('<IHHII16sQQ16sQ32s32s32sIIIIQIIIIQ')
VERIFY_REQUEST = struct.Struct('<IHHII16sQQ16s')
VERIFY_REPLY_PREFIX = COMMON
STOP_REQUEST = struct.Struct('<IHHII16sQQ16s')
STOP_REPLY = STOP_REQUEST
SETTLED_RECORD = struct.Struct('<IHHII16sQQIIQQiiII16sQ32s')

assert COMMON.size == 48
assert READY.size == 216
assert VERIFY_REQUEST.size == 64
assert VERIFY_REPLY_PREFIX.size + 128 == 176
assert STOP_REQUEST.size == STOP_REPLY.size == 64
assert SETTLED_RECORD.size == 144

NATIVE_DONE = 1 << 0
IO_DONE = 1 << 1
FINAL_STATS_VALID = 1 << 2
WORKER_CONTROL_EOF = 1 << 3
OUTSTANDING_ZERO = 1 << 4
SETTLED_FLAGS = NATIVE_DONE | IO_DONE | FINAL_STATS_VALID | WORKER_CONTROL_EOF | OUTSTANDING_ZERO


def _context(relay_nonce, relay_epoch):
    if len(relay_nonce) != 16 or not any(relay_nonce) or not 0 < relay_epoch < (1 << 64):
        raise ValueError('invalid relay context')


def _common(record_type, size, relay_nonce, relay_epoch, sequence):
    _context(relay_nonce, relay_epoch)
    if not 0 < sequence < (1 << 64):
        raise ValueError('invalid relay context')
    return COMMON.pack(MAGIC, VERSION, record_type, size, 0,
        relay_nonce, relay_epoch, sequence)


def pack_ready(relay_nonce, relay_epoch, broker_nonce, broker_epoch,
        worker_profile, app_exe_hash, worker_exe_hash, app_identity,
        worker_identity):
    _context(relay_nonce, relay_epoch)
    if (len(broker_nonce) != 16 or not any(broker_nonce) or
            not 0 < broker_epoch < (1 << 64) or
            any(len(value) != 32 or not any(value) for value in
                (worker_profile, app_exe_hash, worker_exe_hash))):
        raise ValueError('invalid READY hashes/context')
    app_pid, app_uid, app_gid, app_start = app_identity
    worker_pid, worker_uid, worker_gid, worker_start = worker_identity
    if any(value <= 0 for value in (app_pid, app_start, worker_pid, worker_start)):
        raise ValueError('invalid READY process identity')
    if any(value < 0 or value >= (1 << 32) for value in
            (app_pid, app_uid, app_gid, worker_pid, worker_uid, worker_gid)):
        raise ValueError('READY identity field out of range')
    return READY.pack(MAGIC, VERSION, INNER_READY, READY.size, 0,
        relay_nonce, relay_epoch, 0, broker_nonce, broker_epoch,
        worker_profile, app_exe_hash, worker_exe_hash,
        app_pid, app_uid, app_gid, 0, app_start,
        worker_pid, worker_uid, worker_gid, 0, worker_start)


def unpack_ready(packet):
    if len(packet) != READY.size:
        raise ValueError('invalid INNER_READY size')
    fields = READY.unpack(packet)
    (magic, version, record_type, size, reserved, relay_nonce, relay_epoch,
     sequence, broker_nonce, broker_epoch, profile, app_hash, worker_hash,
     app_pid, app_uid, app_gid, app_reserved, app_start, worker_pid,
     worker_uid, worker_gid, worker_reserved, worker_start) = fields
    if (magic != MAGIC or version != VERSION or record_type != INNER_READY or
            size != READY.size or reserved or sequence or app_reserved or
            worker_reserved or not relay_epoch or not any(relay_nonce) or
            not broker_epoch or not any(broker_nonce) or not any(profile) or
            not any(app_hash) or not any(worker_hash) or not app_pid or
            not app_start or not worker_pid or not worker_start):
        raise ValueError('invalid INNER_READY fields')
    return (relay_nonce, relay_epoch, broker_nonce, broker_epoch, profile,
        app_hash, worker_hash, (app_pid, app_uid, app_gid, app_start),
        (worker_pid, worker_uid, worker_gid, worker_start))


def pack_verify(nonce, epoch, sequence):
    return _common(VERIFY, VERIFY_REQUEST.size, nonce, epoch, sequence) + bytes(16)


def unpack_verify(packet):
    if len(packet) != VERIFY_REQUEST.size:
        raise ValueError('invalid VERIFY size')
    magic, version, kind, size, reserved, nonce, epoch, sequence, tail = \
        VERIFY_REQUEST.unpack(packet)
    if (magic != MAGIC or version != VERSION or kind != VERIFY or
            size != len(packet) or reserved or any(tail) or not any(nonce) or
            not epoch or not sequence):
        raise ValueError('invalid VERIFY fields')
    return nonce, epoch, sequence


def pack_verify_result(nonce, epoch, sequence, broker_result):
    _unpack_broker_result(broker_result, sequence)
    return (_common(VERIFY_RESULT, VERIFY_REPLY_PREFIX.size + len(broker_result),
        nonce, epoch, sequence) + broker_result)


def _unpack_broker_result(result, expected_sequence):
    if len(result) != 128:
        raise ValueError('invalid embedded broker result length')
    (magic, version, kind, size, status, nonce, epoch, sequence, owner_pid,
     reserved, owner_start, owner_token, claim_generation, mark, cookie,
     profile, state) = struct.unpack('<IHHII16sQQIIQQQIQ32sI', result)
    identity = (owner_pid > 0 and owner_start and owner_token and
        claim_generation and mark and cookie)
    if (magic != 0x4B425234 or version != 1 or kind != 5 or size != len(result) or
            status > 4095 or not any(nonce) or not epoch or
            sequence != expected_sequence or reserved or not any(profile) or
            state not in (0, 1) or
            (status == 0 and (state != 1 or not identity)) or
            (status != 0 and state != 0)):
        raise ValueError('invalid embedded broker VERIFY result')
    return (status, nonce, epoch, sequence, owner_pid, owner_start, owner_token,
        claim_generation, mark, cookie, profile, state)


def unpack_verify_result(packet, expected_nonce, expected_epoch, expected_sequence,
        broker_nonce, broker_epoch, worker_profile):
    if len(packet) != 176:
        raise ValueError('invalid VERIFY_RESULT size')
    fields = COMMON.unpack_from(packet)
    magic, version, kind, size, reserved, nonce, epoch, sequence = fields
    if (magic != MAGIC or version != VERSION or kind != VERIFY_RESULT or
            size != len(packet) or reserved or nonce != expected_nonce or
            epoch != expected_epoch or sequence != expected_sequence):
        raise ValueError('invalid VERIFY_RESULT relay correlation')
    result = packet[48:]
    (broker_status, got_nonce, got_epoch, _broker_sequence, _owner_pid,
     _owner_start, _owner_token, _generation, _mark, _cookie, profile,
     _state) = _unpack_broker_result(result, expected_sequence)
    if (got_nonce != broker_nonce or got_epoch != broker_epoch or
            _broker_sequence != expected_sequence or
            profile != worker_profile):
        raise ValueError('embedded broker result does not match pinned READY context')
    return broker_status, result


def pack_stop(nonce, epoch, sequence):
    return _common(STOP, STOP_REQUEST.size, nonce, epoch, sequence) + bytes(16)


def unpack_stop(packet):
    if len(packet) != STOP_REQUEST.size:
        raise ValueError('invalid STOP size')
    magic, version, kind, size, reserved, nonce, epoch, sequence, tail = \
        STOP_REQUEST.unpack(packet)
    if (magic != MAGIC or version != VERSION or kind != STOP or
            size != len(packet) or reserved or any(tail) or not any(nonce) or
            not epoch or not sequence):
        raise ValueError('invalid STOP fields')
    return nonce, epoch, sequence


def pack_stop_reply(kind, nonce, epoch, sequence):
    if kind not in (STOP_ACCEPTED,):
        raise ValueError('invalid stop reply type')
    return STOP_REPLY.pack(MAGIC, VERSION, kind, STOP_REPLY.size, 0,
        nonce, epoch, sequence, bytes(16))


def unpack_stop_reply(packet, expected_kind, nonce, epoch, sequence):
    if len(packet) != STOP_REPLY.size:
        raise ValueError('invalid stop reply size')
    magic, version, kind, size, reserved, got_nonce, got_epoch, got_sequence, tail = \
        STOP_REPLY.unpack(packet)
    if (magic != MAGIC or version != VERSION or kind != expected_kind or
            expected_kind != STOP_ACCEPTED or size != len(packet) or reserved or
            got_nonce != nonce or got_epoch != epoch or got_sequence != sequence or
            any(tail)):
        raise ValueError('invalid stop reply fields')
    return kind, nonce, epoch, sequence


def pack_settled(nonce, epoch, sequence, app_pid, worker_pid, app_start,
        worker_start, app_status, worker_status, outstanding, flags,
        broker_nonce, broker_epoch, profile):
    if (app_status or worker_status or outstanding or flags != SETTLED_FLAGS or
            app_pid <= 0 or worker_pid <= 0 or app_start <= 0 or worker_start <= 0 or
            len(broker_nonce) != 16 or not any(broker_nonce) or broker_epoch <= 0 or
            len(profile) != 32 or not any(profile)):
        raise ValueError('invalid settled lifecycle fields')
    _common(SETTLED, SETTLED_RECORD.size, nonce, epoch, sequence)
    return SETTLED_RECORD.pack(MAGIC, VERSION, SETTLED, SETTLED_RECORD.size, 0,
        nonce, epoch, sequence, app_pid, worker_pid, app_start, worker_start,
        app_status, worker_status, outstanding, flags, broker_nonce, broker_epoch,
        profile)


def unpack_settled(packet, ready, nonce, epoch, sequence):
    if len(packet) != SETTLED_RECORD.size:
        raise ValueError('invalid SETTLED size')
    fields = SETTLED_RECORD.unpack(packet)
    (magic, version, kind, size, reserved, got_nonce, got_epoch, got_sequence,
     app_pid, worker_pid, app_start, worker_start, app_status, worker_status,
     outstanding, flags, broker_nonce, broker_epoch, profile) = fields
    (ready_nonce, ready_epoch, ready_broker_nonce, ready_broker_epoch,
     ready_profile, _app_hash, _worker_hash, app_identity, worker_identity) = ready
    if (magic != MAGIC or version != VERSION or kind != SETTLED or
            size != len(packet) or reserved or got_nonce != nonce or
            got_epoch != epoch or got_sequence != sequence or flags != SETTLED_FLAGS or
            app_status or worker_status or outstanding or
            (app_pid, app_start) != (app_identity[0], app_identity[3]) or
            (worker_pid, worker_start) != (worker_identity[0], worker_identity[3]) or
            broker_nonce != ready_broker_nonce or broker_epoch != ready_broker_epoch or
            profile != ready_profile or ready_nonce != nonce or ready_epoch != epoch):
        raise ValueError('invalid SETTLED identity/status')
    return fields
