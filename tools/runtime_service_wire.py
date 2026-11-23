"""Private C32 runtime-service protocol codec, shared with ker-run."""
import struct

MAGIC = 0x4B525356
VERSION = 1
CLAIM = 1
CHECK = 2
RELEASE = 3
DELEGATE_INTENT = 4
DELEGATE_BIND = 5
ROLE_SLIM_STAGE1 = 1
ROLE_SLIM_PRIMARY = 2
NONCE_BYTES = 16
LEASE_BYTES = 16
TICKET_BYTES = 32
PROFILE_BYTES = 32
INTENT_BYTES = 16

HEADER = struct.Struct('<IHHIiQQ16s16s')
CLAIM_BODY = struct.Struct('<32s32s')
CLAIM_RESULT = struct.Struct('<32s')
DELEGATE_INTENT_BODY = struct.Struct('<16sII')
DELEGATE_INTENT_RESULT = struct.Struct('<16s')
DELEGATE_BIND_BODY = struct.Struct('<16s')
DELEGATE_BIND_RESULT = struct.Struct('<32sI')

assert HEADER.size == 64
assert CLAIM_BODY.size == 64
assert CLAIM_RESULT.size == 32
assert DELEGATE_INTENT_BODY.size == 24
assert DELEGATE_INTENT_RESULT.size == 16
assert DELEGATE_BIND_BODY.size == 16
assert DELEGATE_BIND_RESULT.size == 36


def pack_delegate_intent(request_nonce, role):
    if len(request_nonce) != NONCE_BYTES or role not in (
            ROLE_SLIM_STAGE1, ROLE_SLIM_PRIMARY):
        raise ValueError('invalid runtime-service delegation intent')
    return DELEGATE_INTENT_BODY.pack(request_nonce, role, 0)


def unpack_delegate_intent(body):
    if len(body) != DELEGATE_INTENT_BODY.size:
        raise ValueError('invalid runtime-service delegation intent length')
    request_nonce, role, reserved = DELEGATE_INTENT_BODY.unpack(body)
    if role not in (ROLE_SLIM_STAGE1, ROLE_SLIM_PRIMARY) or reserved != 0:
        raise ValueError('invalid runtime-service delegation intent fields')
    return request_nonce, role


def pack_intent_result(intent_id):
    if len(intent_id) != INTENT_BYTES:
        raise ValueError('invalid runtime-service intent id length')
    return DELEGATE_INTENT_RESULT.pack(intent_id)


def unpack_intent_result(body):
    if len(body) != DELEGATE_INTENT_RESULT.size:
        raise ValueError('invalid runtime-service intent result length')
    return DELEGATE_INTENT_RESULT.unpack(body)[0]


def pack_delegate_bind(intent_id):
    if len(intent_id) != INTENT_BYTES:
        raise ValueError('invalid runtime-service intent id length')
    return DELEGATE_BIND_BODY.pack(intent_id)


def unpack_delegate_bind(body):
    if len(body) != DELEGATE_BIND_BODY.size:
        raise ValueError('invalid runtime-service delegation bind length')
    return DELEGATE_BIND_BODY.unpack(body)[0]


def pack_bind_result(ticket, role):
    if len(ticket) != TICKET_BYTES or role not in (
            ROLE_SLIM_STAGE1, ROLE_SLIM_PRIMARY):
        raise ValueError('invalid runtime-service delegation grant')
    return DELEGATE_BIND_RESULT.pack(ticket, role)


def unpack_bind_result(body):
    if len(body) != DELEGATE_BIND_RESULT.size:
        raise ValueError('invalid runtime-service delegation grant length')
    ticket, role = DELEGATE_BIND_RESULT.unpack(body)
    if role not in (ROLE_SLIM_STAGE1, ROLE_SLIM_PRIMARY):
        raise ValueError('invalid runtime-service delegation role')
    return ticket, role


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
