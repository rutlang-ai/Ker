"""Private little-endian KNGC cycle handoff codec."""
import struct

MAGIC = 0x43474E4B
VERSION = 1
HEADER = struct.Struct('<IHHIi16sQQQQ')
RUNTIME = struct.Struct('<16sQ32s')
HEADER_BYTES = 64
RUNTIME_BYTES = 56
WATCH_BYTES = 120
MAX_SEQUENCE = (1 << 64) - 1
WATCH_BOUND = 1
CYCLE_DRAINED = 2
CYCLE_READY = 3
CYCLE_ERROR = 4


def _nonzero(value, name):
    if not value or not any(value):
        raise ValueError(f'{name} must be nonzero')


def pack_header(kind, total_bytes, status, nonce, master_start, sequence, cycle):
    _nonzero(nonce, 'master nonce')
    if (len(nonce) != 16 or not master_start or not 0 < sequence < MAX_SEQUENCE or
            not cycle or status < 0 or
            (kind, total_bytes, status) not in (
                (WATCH_BOUND, WATCH_BYTES, 0),
                (CYCLE_DRAINED, HEADER_BYTES, 0),
                (CYCLE_READY, WATCH_BYTES, 0),
            ) and not (kind == CYCLE_ERROR and total_bytes == HEADER_BYTES and status > 0)):
        raise ValueError('invalid KNGC header fields')
    return HEADER.pack(MAGIC, VERSION, kind, total_bytes, status, nonce,
        master_start, sequence, cycle, 0)


def pack_runtime(nonce, epoch, profile):
    _nonzero(nonce, 'broker nonce')
    _nonzero(profile, 'worker profile hash')
    if len(nonce) != 16 or len(profile) != 32 or not epoch:
        raise ValueError('invalid KNGC runtime tuple')
    return RUNTIME.pack(nonce, epoch, profile)


def pack_watch_bound(nonce, master_start, sequence, cycle, runtime):
    if len(runtime) != 3:
        raise ValueError('invalid runtime tuple')
    return pack_header(WATCH_BOUND, WATCH_BYTES, 0, nonce, master_start,
        sequence, cycle) + pack_runtime(*runtime)


def pack_drained(nonce, master_start, sequence, cycle):
    return pack_header(CYCLE_DRAINED, HEADER_BYTES, 0, nonce, master_start,
        sequence, cycle)


def pack_cycle_ready(nonce, master_start, sequence, cycle, runtime):
    return pack_header(CYCLE_READY, WATCH_BYTES, 0, nonce, master_start,
        sequence, cycle) + pack_runtime(*runtime)


def unpack_record(packet):
    if len(packet) not in (HEADER_BYTES, WATCH_BYTES):
        raise ValueError('invalid KNGC record size')
    magic, version, kind, total, status, nonce, master_start, sequence, cycle, reserved = HEADER.unpack_from(packet)
    if (magic != MAGIC or version != VERSION or total != len(packet) or reserved or
            not any(nonce) or not master_start or not 0 < sequence < MAX_SEQUENCE or not cycle):
        raise ValueError('invalid KNGC header')
    if (kind, total, status) not in (
            (WATCH_BOUND, WATCH_BYTES, 0),
            (CYCLE_DRAINED, HEADER_BYTES, 0),
            (CYCLE_READY, WATCH_BYTES, 0),
    ) and not (kind == CYCLE_ERROR and total == HEADER_BYTES and status > 0):
        raise ValueError('invalid KNGC type/status/length')
    runtime = None
    if total == WATCH_BYTES:
        broker_nonce, epoch, profile = RUNTIME.unpack_from(packet, HEADER_BYTES)
        if not any(broker_nonce) or not epoch or not any(profile):
            raise ValueError('invalid KNGC runtime tuple')
        runtime = (broker_nonce, epoch, profile)
    return kind, status, nonce, master_start, sequence, cycle, runtime
