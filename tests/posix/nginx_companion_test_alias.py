"""Narrow validation for the test-only opaque broker member capability."""
import array
import fcntl
import json
import os
import socket
import stat
import struct
import sys


def validate_member_alias_fd(fd):
    """Require the opaque member capability shape returned by the broker API."""
    if type(fd) is not int or fd < 0:
        raise ValueError('member alias descriptor is invalid')
    identity = os.fstat(fd)
    if not stat.S_ISFIFO(identity.st_mode):
        raise PermissionError('member alias is not the broker capability FIFO')
    status_flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    descriptor_flags = fcntl.fcntl(fd, fcntl.F_GETFD)
    if status_flags & os.O_ACCMODE != os.O_WRONLY:
        raise PermissionError('member alias capability is not write-only')
    if not status_flags & os.O_NONBLOCK:
        raise PermissionError('member alias capability is not nonblocking')
    if not descriptor_flags & fcntl.FD_CLOEXEC:
        raise PermissionError('member alias capability is not close-on-exec')
    return {
        'device': identity.st_dev,
        'inode': identity.st_ino,
        'mode': identity.st_mode,
        'cloexec': True,
        'nonblocking': True,
        'access': 'write-only',
    }


def receive_member_alias(channel, expected_pid, label, control_size=None):
    """Receive one credentialed broker capability and close every rejected FD.

    Linux may report MSG_CMSG_CLOEXEC in recvmsg's returned flags when that
    input flag was used. That bit is expected; truncation and every other
    output flag remain errors. The optional control_size exists only so the
    socket tests can force ancillary truncation.
    """
    if control_size is None:
        control_size = (socket.CMSG_SPACE(3 * array.array('i').itemsize) +
            socket.CMSG_SPACE(12))
    received = []
    metadata = []
    credentials = []
    data = b''
    flags = 0
    try:
        data, ancillary, flags, _address = channel.recvmsg(1, control_size,
            socket.MSG_CMSG_CLOEXEC)
        malformed = False
        for level, kind, value in ancillary:
            metadata.append({'level': level, 'type': kind, 'length': len(value),
                'value_hex': value[:64].hex()})
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                itemsize = array.array('i').itemsize
                complete = len(value) - (len(value) % itemsize)
                descriptors = array.array('i')
                descriptors.frombytes(value[:complete])
                received.extend(descriptors)
                malformed |= complete != len(value)
            elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS:
                if len(value) == 12:
                    credentials.append(struct.unpack('=3i', value))
                else:
                    malformed = True
            else:
                malformed = True
        fd_details = []
        for descriptor in received:
            try:
                identity = os.fstat(descriptor)
                status_flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
                descriptor_flags = fcntl.fcntl(descriptor, fcntl.F_GETFD)
                fd_details.append({'fd': descriptor, 'device': identity.st_dev,
                    'inode': identity.st_ino, 'mode': identity.st_mode,
                    'status_flags': status_flags, 'descriptor_flags': descriptor_flags})
            except OSError as error:
                fd_details.append({'fd': descriptor, 'error': error.errno})
        diagnostic = {'event': 'member-alias-recvmsg', 'label': str(label)[:64],
            'data_hex': data[:16].hex(), 'flags': flags, 'ancillary': metadata,
            'credentials': [list(item) for item in credentials], 'fds': fd_details,
            'expected_pid': expected_pid, 'expected_uid': os.getuid(),
            'expected_gid': os.getgid()}
        print('MEMBER_ALIAS_DIAGNOSTIC ' + json.dumps(diagnostic, sort_keys=True),
            file=sys.stderr, flush=True)
        allowed_flags = getattr(socket, 'MSG_CMSG_CLOEXEC', 0)
        if (malformed or data != b'A' or len(received) != 1 or
                len(credentials) != 1 or
                credentials[0] != (expected_pid, os.getuid(), os.getgid()) or
                flags & ~allowed_flags):
            raise RuntimeError(f'{label} actual alias SCM credentials/FD/flags mismatch')
        descriptor = received[0]
        capability = validate_member_alias_fd(descriptor)
        received.clear()
        return descriptor, capability, diagnostic
    finally:
        for descriptor in received:
            try:
                os.close(descriptor)
            except OSError:
                pass
