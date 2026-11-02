"""Private C34 socket-broker readiness/stop wire codec."""
import hashlib
import struct

MAGIC = 0x4B425234
VERSION = 1
READY = 1
STOP = 2
STOP_ACK = 3
STOP_ID = 1
EMPTY_MANIFEST_DOMAIN = b'ker.socket-broker.bootstrap.empty/v1'
EMPTY_MANIFEST_SHA256 = hashlib.sha256(EMPTY_MANIFEST_DOMAIN).digest()

HEADER = struct.Struct('<IHHII')
READY_RECORD = struct.Struct('<IHHII16sQ32sQII32s')
STOP_RECORD = struct.Struct('<IHHII16sQ32sIIIIQQ')

assert len(EMPTY_MANIFEST_DOMAIN) == 36
assert HEADER.size == 16
assert READY_RECORD.size == 120
assert STOP_RECORD.size == 104


def _header(record_type, size):
    return HEADER.pack(MAGIC, VERSION, record_type, size, 0)


def pack_ready(nonce, epoch, worker_profile_sha256, broker_start_ticks,
               object_count=0, manifest_sha256=EMPTY_MANIFEST_SHA256):
    if (len(nonce) != 16 or len(worker_profile_sha256) != 32 or
            len(manifest_sha256) != 32 or epoch <= 0 or
            broker_start_ticks <= 0 or object_count != 0 or
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
            manifest != EMPTY_MANIFEST_SHA256):
        raise ValueError('invalid READY fields')
    return nonce, epoch, profile, start_ticks, count, manifest


def pack_stop(record_type, nonce, epoch, supervisor_pid, supervisor_uid,
              supervisor_gid, supervisor_start_ticks, stop_id=STOP_ID,
              manifest_sha256=EMPTY_MANIFEST_SHA256):
    if (record_type not in (STOP, STOP_ACK) or len(nonce) != 16 or
            len(manifest_sha256) != 32 or
            manifest_sha256 != EMPTY_MANIFEST_SHA256 or not epoch or
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
            manifest != EMPTY_MANIFEST_SHA256):
        raise ValueError('invalid STOP fields')
    return nonce, epoch, manifest, pid, uid, gid, start_ticks, stop_id
