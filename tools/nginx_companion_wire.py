"""Private wire codec for ker-run's control-only Nginx containment helper."""
import hashlib
import struct

MAGIC = 0x4B434834
VERSION = 1

HELLO = 1
START = 2
STARTED = 3
RELOAD = 4
RELOAD_RESULT = 5
STOP = 6
SETTLED = 7
ERROR = 8
OWNER_READY = 9
SOURCE_WATCH = 10
SOURCE_HUP = 11
SOURCE_HUP_DELIVERED = 12
SOURCE_CANDIDATE_WATCH = 13
SOURCE_CANDIDATE_READY = 14
SOURCE_CANDIDATE_FAILED = 15
SOURCE_PROMOTE = 16
SOURCE_PROMOTED = 17
SOURCE_ABORT_RETIRE = 18
SOURCE_ABORT_RETIRED = 19
SOURCE_RETRY_WATCH = 20
SOURCE_SUCCESSOR_WATCH = 21
MAX_RECORD_TYPE = SOURCE_SUCCESSOR_WATCH

CLEANUP_SETTLED = 0
CLEANUP_UNRESOLVED = 1

HEADER = struct.Struct('<IHHII16sQQ')
START_BODY = struct.Struct('<IIIIQ32s32s32s')
STARTED_BODY = struct.Struct('<IIIIQ32s32s')
RELOAD_RESULT_BODY = struct.Struct('<iIQ32s')
SETTLED_BODY = struct.Struct('<iIIIQ32s')
ERROR_BODY = struct.Struct('<iIIIQ32s')
OWNER_READY_BODY = struct.Struct('<IIIIIIQQQQ')
SOURCE_WATCH_BODY = struct.Struct('<IIIIQQQQ')
MAX_SEQUENCE = 0xffffffffffffffff

HELLO_BYTES = HEADER.size
START_BYTES = HEADER.size + START_BODY.size
STARTED_BYTES = HEADER.size + STARTED_BODY.size
RELOAD_BYTES = HEADER.size
RELOAD_RESULT_BYTES = HEADER.size + RELOAD_RESULT_BODY.size
STOP_BYTES = HEADER.size
SETTLED_BYTES = HEADER.size + SETTLED_BODY.size
ERROR_BYTES = HEADER.size + ERROR_BODY.size
OWNER_READY_BYTES = HEADER.size + OWNER_READY_BODY.size
SOURCE_WATCH_BYTES = HEADER.size + SOURCE_WATCH_BODY.size

assert HEADER.size == 48
assert START_BODY.size == 120 and START_BYTES == 168
assert STARTED_BODY.size == 88 and STARTED_BYTES == 136
assert RELOAD_RESULT_BODY.size == 48 and RELOAD_RESULT_BYTES == 96
assert SETTLED_BODY.size == 56 and SETTLED_BYTES == 104
assert ERROR_BODY.size == 56 and ERROR_BYTES == 104
assert OWNER_READY_BODY.size == 56 and OWNER_READY_BYTES == 104


def pack_header(record_type, size, nonce, epoch, sequence):
    if (record_type not in range(HELLO, MAX_RECORD_TYPE + 1) or len(nonce) != 16 or
            nonce == b'\0' * 16 or not epoch or sequence < 0 or
            (record_type == HELLO) != (sequence == 0) or
            sequence > MAX_SEQUENCE or size < HEADER.size):
        raise ValueError('invalid companion header fields')
    return HEADER.pack(MAGIC, VERSION, record_type, size, 0,
        nonce, epoch, sequence)


def unpack_header(packet):
    if len(packet) < HEADER.size:
        raise ValueError('short companion record header')
    magic, version, record_type, size, reserved, nonce, epoch, sequence = \
        HEADER.unpack_from(packet)
    if (magic != MAGIC or version != VERSION or
            record_type not in range(HELLO, MAX_RECORD_TYPE + 1) or
            reserved or size != len(packet) or nonce == b'\0' * 16 or
            not epoch or sequence > MAX_SEQUENCE or
            (record_type == HELLO) != (sequence == 0)):
        raise ValueError('invalid companion record header')
    return record_type, nonce, epoch, sequence


def pack_record(record_type, body, nonce, epoch, sequence):
    return pack_header(record_type, HEADER.size + len(body), nonce, epoch,
        sequence) + body


def unpack_record(packet, expected_type, expected_nonce, expected_epoch,
                  expected_sequence, body_struct):
    record_type, nonce, epoch, sequence = unpack_header(packet)
    if (record_type != expected_type or nonce != expected_nonce or
            epoch != expected_epoch or sequence != expected_sequence):
        raise ValueError('companion record correlation mismatch')
    body = packet[HEADER.size:]
    if len(body) != body_struct.size:
        raise ValueError('invalid companion record body size')
    return body_struct.unpack(body)


def validate_status(status):
    if type(status) is not int or status < 0 or status > 0x7fffffff:
        raise ValueError('status must be zero or a positive errno')


def validate_reload_result(fields, expected_start_ticks, expected_profile):
    status, reserved, start_ticks, profile = fields
    validate_status(status)
    if (reserved != 0 or start_ticks != expected_start_ticks or
            profile != expected_profile):
        raise ValueError('reload result identity/state mismatch')


def validate_settled(fields, expected_pid, expected_start_ticks,
                     expected_profile):
    status, cleanup_state, master_pid, descendants, start_ticks, profile = fields
    validate_status(status)
    if cleanup_state not in (CLEANUP_SETTLED, CLEANUP_UNRESOLVED):
        raise ValueError('unknown companion cleanup state')
    if (master_pid != expected_pid or start_ticks != expected_start_ticks or
            profile != expected_profile):
        raise ValueError('settlement does not match stored master identity')
    if status == 0 and (cleanup_state != CLEANUP_SETTLED or descendants != 0):
        raise ValueError('successful settlement requires zero unresolved descendants')
    if status != 0 and cleanup_state != CLEANUP_UNRESOLVED:
        raise ValueError('failed settlement must remain unresolved')


def validate_error(fields):
    status, phase, _master_pid, unresolved_descendants, start_ticks, profile = fields
    validate_status(status)
    if status == 0 or not phase:
        raise ValueError('ERROR requires a positive errno and nonzero phase')
    if unresolved_descendants and (not start_ticks or profile == bytes(32)):
        raise ValueError('unresolved descendants require a pinned master identity')


def validate_owner_ready(fields, *, expected_uid, expected_gid,
                         expected_role, expected_cookie=None):
    (pid, uid, gid, role, owner_tid, reserved, start_ticks,
     slot_device, slot_inode, endpoint_cookie) = fields
    if (pid <= 0 or uid != expected_uid or gid != expected_gid or
            role != expected_role or owner_tid <= 0 or reserved or
            not start_ticks or not slot_device or not slot_inode or
            not endpoint_cookie or
            (expected_cookie is not None and endpoint_cookie != expected_cookie)):
        raise ValueError('Nginx owner READY identity/slot mismatch')


def profile_hash(binary_hash, config_hash, ini_hash, prefix, env):
    if any(len(digest) != 32 for digest in (binary_hash, config_hash, ini_hash)):
        raise ValueError('Nginx binary/config/INI identity must be SHA-256')
    material = bytearray(b'ker.nginx.control-companion/v1\0')
    for value in (binary_hash, config_hash, ini_hash, prefix.encode()):
        material.extend(struct.pack('<I', len(value)))
        material.extend(value)
    for key, value in sorted(env.items()):
        key_bytes, value_bytes = key.encode(), value.encode()
        material.extend(struct.pack('<I', len(key_bytes)))
        material.extend(key_bytes)
        material.extend(struct.pack('<I', len(value_bytes)))
        material.extend(value_bytes)
    return hashlib.sha256(material).digest()


class RequestSequence:
    """Monotonic request IDs; exhaustion is terminal and never wraps."""
    def __init__(self):
        self._next = 1

    def take(self):
        if self._next > MAX_SEQUENCE:
            raise OverflowError('companion request sequence exhausted')
        result = self._next
        self._next += 1
        return result
