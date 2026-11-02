"""Private C34 socket-broker readiness/stop wire codec."""
import hashlib
import struct

MAGIC = 0x4B425234
VERSION = 1
READY = 1
STOP = 2
STOP_ACK = 3
VERIFY_RETIRE = 4
VERIFY_RETIRE_RESULT = 5
STOP_ID = 1
EMPTY_MANIFEST_DOMAIN = b'ker.socket-broker.bootstrap.empty/v1'
EMPTY_MANIFEST_SHA256 = hashlib.sha256(EMPTY_MANIFEST_DOMAIN).digest()

HEADER = struct.Struct('<IHHII')
READY_RECORD = struct.Struct('<IHHII16sQ32sQII32s')
STOP_RECORD = struct.Struct('<IHHII16sQ32sIIIIQQ')
VERIFY_REQUEST = struct.Struct('<IHHII16sQQ16s')
VERIFY_RESULT = struct.Struct('<IHHII16sQQIIQQQIQ32sI')

assert len(EMPTY_MANIFEST_DOMAIN) == 36
assert HEADER.size == 16
assert READY_RECORD.size == 120
assert STOP_RECORD.size == 104
assert VERIFY_REQUEST.size == 64
assert VERIFY_RESULT.size == 128


def _header(record_type, size):
    return HEADER.pack(MAGIC, VERSION, record_type, size, 0)


def pack_ready(nonce, epoch, worker_profile_sha256, broker_start_ticks,
               object_count=0, manifest_sha256=EMPTY_MANIFEST_SHA256):
    if (len(nonce) != 16 or len(worker_profile_sha256) != 32 or
            len(manifest_sha256) != 32 or epoch <= 0 or
            broker_start_ticks <= 0 or object_count != 0 or
            not any(nonce) or not any(worker_profile_sha256) or
            manifest_sha256 != EMPTY_MANIFEST_SHA256):
        raise ValueError('invalid empty-broker READY fields')
    return READY_RECORD.pack(MAGIC, VERSION, READY, READY_RECORD.size, 0,
        nonce, epoch, worker_profile_sha256, broker_start_ticks,
        object_count, 0, manifest_sha256)


def unpack_ready(packet):
    if len(packet) != READY_RECORD.size:
        raise ValueError('invalid READY size')
    (magic, version, record_type, size, reserved, nonce, epoch, profile,
     start_ticks, count, reserved2, manifest) = READY_RECORD.unpack(packet)
    if (magic != MAGIC or version != VERSION or record_type != READY or
            size != len(packet) or reserved or reserved2 or not epoch or
            not start_ticks or count != 0 or
            not any(nonce) or not any(profile) or
            manifest != EMPTY_MANIFEST_SHA256):
        raise ValueError('invalid READY fields')
    return nonce, epoch, profile, start_ticks, count, manifest


def pack_stop(record_type, nonce, epoch, supervisor_pid, supervisor_uid,
              supervisor_gid, supervisor_start_ticks, stop_id=STOP_ID,
              manifest_sha256=EMPTY_MANIFEST_SHA256):
    if (record_type not in (STOP, STOP_ACK) or len(nonce) != 16 or
            len(manifest_sha256) != 32 or
            manifest_sha256 != EMPTY_MANIFEST_SHA256 or not epoch or
            not any(nonce) or
            not supervisor_pid or not supervisor_start_ticks or
            stop_id != STOP_ID):
        raise ValueError('invalid STOP fields')
    return STOP_RECORD.pack(MAGIC, VERSION, record_type, STOP_RECORD.size, 0,
        nonce, epoch, manifest_sha256, supervisor_pid, supervisor_uid,
        supervisor_gid, 0, supervisor_start_ticks, stop_id)


def unpack_stop(packet, expected_type):
    if expected_type not in (STOP, STOP_ACK) or len(packet) != STOP_RECORD.size:
        raise ValueError('invalid STOP size or expected type')
    (magic, version, record_type, size, reserved, nonce, epoch, manifest,
     pid, uid, gid, reserved2, start_ticks, stop_id) = STOP_RECORD.unpack(packet)
    if (magic != MAGIC or version != VERSION or record_type != expected_type or
            size != len(packet) or reserved or reserved2 or not epoch or
            not pid or not start_ticks or stop_id != STOP_ID or
            not any(nonce) or
            manifest != EMPTY_MANIFEST_SHA256):
        raise ValueError('invalid STOP fields')
    return nonce, epoch, manifest, pid, uid, gid, start_ticks, stop_id


def pack_verify(nonce, epoch, sequence):
    if len(nonce) != 16 or not any(nonce) or not epoch or not sequence:
        raise ValueError('invalid VERIFY context')
    return VERIFY_REQUEST.pack(MAGIC, VERSION, VERIFY_RETIRE,
        VERIFY_REQUEST.size, 0, nonce, epoch, sequence, bytes(16))


def unpack_verify_result(packet, nonce, epoch, sequence):
    if len(packet) != VERIFY_RESULT.size:
        raise ValueError('invalid VERIFY result length')
    fields = VERIFY_RESULT.unpack(packet)
    (magic, version, record_type, size, status, got_nonce, got_epoch,
     got_sequence, owner_pid, owner_reserved, owner_start, owner_token,
     claim_generation, mark, cookie, profile, state) = fields
    identity = (owner_pid > 0 and owner_start and owner_token and
        claim_generation and mark and cookie)
    if (magic != MAGIC or version != VERSION or record_type != VERIFY_RETIRE_RESULT or
            size != len(packet) or got_nonce != nonce or got_epoch != epoch or
            not sequence or got_sequence != sequence or owner_reserved or
            status > 4095 or not any(profile) or state not in (0, 1) or
            (status == 0 and (state != 1 or not identity)) or
            (status != 0 and state != 0)):
        raise ValueError('invalid VERIFY result fields')
    return {'status': status, 'owner_pid': owner_pid,
        'owner_start_ticks': owner_start, 'owner_token': owner_token,
        'claim_generation': claim_generation, 'mark': mark,
        'listener_cookie': cookie, 'profile': profile, 'state': state,
        'sequence': got_sequence, 'nonce': got_nonce, 'epoch': got_epoch}


def pack_verify_result(nonce, epoch, sequence, status, owner_pid, owner_start,
        owner_token, claim_generation, mark, cookie, profile, state):
    identity = (owner_pid > 0 and owner_start and owner_token and
        claim_generation and mark and cookie)
    if (len(nonce) != 16 or not any(nonce) or not epoch or not sequence or
            len(profile) != 32 or not any(profile) or status < 0 or status > 4095 or
            state not in (0, 1) or (status == 0 and (state != 1 or not identity)) or
            (status != 0 and state != 0)):
        raise ValueError('invalid VERIFY result context')
    return VERIFY_RESULT.pack(MAGIC, VERSION, VERIFY_RETIRE_RESULT,
        VERIFY_RESULT.size, status, nonce, epoch, sequence, owner_pid, 0,
        owner_start, owner_token, claim_generation, mark, cookie, profile,
        state)
