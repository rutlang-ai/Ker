"""Private C32 runtime-service protocol codec, shared with ker-run."""
import struct

MAGIC = 0x4B525356
VERSION = 1
CLAIM = 1
CHECK = 2
RELEASE = 3
NONCE_BYTES = 16
LEASE_BYTES = 16
TICKET_BYTES = 32
PROFILE_BYTES = 32

HEADER = struct.Struct('<IHHIiQQ16s16s')
CLAIM_BODY = struct.Struct('<32s32s')
CLAIM_RESULT = struct.Struct('<32s')

assert HEADER.size == 64
assert CLAIM_BODY.size == 64
assert CLAIM_RESULT.size == 32


def pack_header(operation, sequence, epoch, nonce, lease_id=b'\0' * LEASE_BYTES,
                status=0, packet_length=None):
    if len(nonce) != NONCE_BYTES or len(lease_id) != LEASE_BYTES:
        raise ValueError('invalid runtime-service nonce or lease length')
    if packet_length is None:
        packet_length = HEADER.size
    return HEADER.pack(MAGIC, VERSION, operation, packet_length, status,
        sequence, epoch, nonce, lease_id)


def unpack_header(packet):
    if len(packet) < HEADER.size:
        raise ValueError('short runtime-service header')
    fields = HEADER.unpack_from(packet)
    magic, version, operation, packet_length, status, sequence, epoch, nonce, lease_id = fields
    if (magic != MAGIC or version != VERSION or packet_length != len(packet) or
            sequence == 0 or epoch == 0):
        raise ValueError('invalid runtime-service header')
    return operation, status, sequence, epoch, nonce, lease_id
