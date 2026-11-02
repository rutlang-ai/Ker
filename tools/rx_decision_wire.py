"""Private ker-run RX-decision seqpacket wire ABI.

This module mirrors the fixed-width, little-endian layouts in
``src/posix/rx-decision-wire.h``. It is internal to the launcher/worker
integration and is not a public Ker API.
"""

import struct

MAGIC = 0x4B525844
VERSION = 1
MAX_MESSAGE = 9216
MAX_FRAME = 9022
MAX_PENDING = 1
DEADLINE_NS = 100_000_000
NONCE_BYTES = 16

BOOTSTRAP = 1
HELLO = 2
READY = 3
DATA = 4
RESULT = 5
STOP = 6
SETTLED = 7

LOCAL = 1
DROP = 2

TARGET_WORKER = 1
TARGET_CONSUMER = 2

HEADER = struct.Struct("<IHHII16sQQQQ")
BOOTSTRAP_BODY = struct.Struct("<IIIIQIIIIQ")
DATA_BODY = struct.Struct("<IIHHHHHHQI")
RESULT_BODY = struct.Struct("<IIII")
SETTLED_BODY = struct.Struct("<QII")

HEADER_BYTES = 64
BOOTSTRAP_BYTES = 48
DATA_BYTES = 32
RESULT_BYTES = 16
SETTLED_BYTES = 16
MAX_SNAPSHOT = min(MAX_FRAME, MAX_MESSAGE - HEADER_BYTES - DATA_BYTES)

assert HEADER.size == HEADER_BYTES
assert BOOTSTRAP_BODY.size == BOOTSTRAP_BYTES
assert DATA_BODY.size == DATA_BYTES
assert RESULT_BODY.size == RESULT_BYTES
assert SETTLED_BODY.size == SETTLED_BYTES
assert HEADER_BYTES + DATA_BYTES + MAX_SNAPSHOT <= MAX_MESSAGE


def pack_header(message_type, nonce, worker_epoch, packet_id=0, control_id=0,
                deadline_ns=0, body_bytes=0):
    if len(nonce) != NONCE_BYTES:
        raise ValueError("run nonce must be 16 bytes")
    message_bytes = HEADER_BYTES + body_bytes
    if message_bytes > MAX_MESSAGE:
        raise ValueError("RX decision message exceeds the wire bound")
    return HEADER.pack(MAGIC, VERSION, message_type, HEADER_BYTES,
                       message_bytes, nonce, worker_epoch, packet_id,
                       control_id, deadline_ns)


def unpack_header(datagram):
    if len(datagram) < HEADER_BYTES or len(datagram) > MAX_MESSAGE:
        raise ValueError("invalid RX decision message size")
    fields = HEADER.unpack_from(datagram)
    magic, version, message_type, header_bytes, message_bytes = fields[:5]
    if (magic != MAGIC or version != VERSION or header_bytes != HEADER_BYTES
            or message_bytes != len(datagram)):
        raise ValueError("invalid RX decision header")
    return fields
