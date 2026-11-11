"""Validate one host-authenticated pinned Nginx worker loop READY record."""
import array
import os
from pathlib import Path
import select
import socket
import struct

MAGIC = 0x4B4E5244
WIRE = struct.Struct('=IHHIIQQQIIQQ')
SO_COOKIE = 57


def start_ticks(pid):
    return int(Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19])


def cookie(endpoint):
    return struct.unpack('=Q', endpoint.getsockopt(socket.SOL_SOCKET, SO_COOKIE, 8))[0]


def validate(data, ancillary, flags, *, pid, pidfd, slot_identity, endpoint_cookie,
             role, owner_tid=None):
    credentials = []
    invalid_ancillary = False
    for level, kind, body in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            fds = array.array('i')
            fds.frombytes(body[:len(body) // fds.itemsize * fds.itemsize])
            for fd in fds:
                os.close(fd)
            invalid_ancillary = True
        elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(body) == 12:
            credentials.append(struct.unpack('=3i', body))
        else:
            invalid_ancillary = True
    if flags or len(data) != WIRE.size or invalid_ancillary or credentials != [(pid, os.getuid(), os.getgid())]:
        raise RuntimeError('malformed or unauthenticated worker READY')
    magic, version, length, actual_role, reserved, device, inode, ticks, worker, actual_tid, actual_cookie, reserved3 = WIRE.unpack(data)
    if ((magic, version, length, actual_role, reserved, device, inode, worker, actual_cookie, reserved3) !=
            (MAGIC, 2, WIRE.size, role, 0, slot_identity.st_dev, slot_identity.st_ino, pid, endpoint_cookie, 0) or
            actual_tid <= 0 or (owner_tid is not None and actual_tid != owner_tid)):
        raise RuntimeError('worker READY identity/slot/frame mismatch')
    if select.select([pidfd], [], [], 0)[0] or start_ticks(pid) != ticks:
        raise RuntimeError('worker READY refers to an exited or replaced worker')
    if select.select([pidfd], [], [], 0)[0]:
        raise RuntimeError('worker exited during READY validation')
    if not Path(f'/proc/{pid}/task/{actual_tid}').exists():
        raise RuntimeError('worker READY owner thread is not live')
    return {'pid': pid, 'start_time': ticks, 'owner_tid': actual_tid, 'role': role,
        'slot_device': device, 'slot_inode': inode, 'endpoint_cookie': actual_cookie}


def receive(endpoint, *, timeout, **expected):
    if not select.select([endpoint], [], [], timeout)[0]:
        raise RuntimeError('worker loop READY timed out')
    data, ancillary, flags, _ = endpoint.recvmsg(WIRE.size,
        socket.CMSG_SPACE(12) + socket.CMSG_SPACE(32), socket.MSG_DONTWAIT)
    return validate(data, ancillary, flags, **expected)
