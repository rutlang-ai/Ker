#!/usr/bin/env python3
"""Scaffold ip netns/sysctl commands for the unchanged upstream PM shell test.

No MPTCP request or response is interpreted here: pm_nl_ctl sends its own UAPI
through the test transport. Unsupported ip operations fail explicitly.
"""
import json
import os
from pathlib import Path
import socket
import struct
import sys
import time

MAGIC = 0x4b504d31
HEADER = struct.Struct('=IIIIqII')
MAX = 16384
NEWNS, DELNS, LISTNS, UP, SYSCTL, SOCK, SEND, RECV, NAMEINDEX, INDEXNAME, STOP, PROBE, STATUS = range(1, 14)


def rpc(operation, data=b'', argument=0):
    if len(data) > MAX:
        raise RuntimeError('PM fixture request too large')
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as channel:
        channel.settimeout(10)
        channel.connect(os.environ['KER_MPTCP_PM_SOCKET'])
        channel.sendall(HEADER.pack(MAGIC, operation, len(data), 0, 0, argument, 0) + data)
        packet, _, flags, _ = channel.recvmsg(HEADER.size + MAX)
    if flags & socket.MSG_TRUNC or len(packet) < HEADER.size:
        raise RuntimeError('truncated PM fixture response')
    magic, op, size, _, result, _, _ = HEADER.unpack_from(packet)
    if magic != MAGIC or op != operation or len(packet) != HEADER.size + size:
        raise RuntimeError('invalid PM fixture response')
    if result < 0:
        raise OSError(-result, os.strerror(-result))
    return packet[HEADER.size:]


def text(operation, value):
    return rpc(operation, value.encode() + b'\0')


def main():
    args = sys.argv[1:]
    if args == ['-Version']:
        os.execv(os.environ['KER_MPTCP_PM_REAL_IP'], [os.environ['KER_MPTCP_PM_REAL_IP'], *args])
    if len(args) == 3 and args[:2] in (['netns', 'add'], ['netns', 'delete']):
        text(NEWNS if args[1] == 'add' else DELNS, args[2]); return 0
    if args[:2] == ['netns', 'list']:
        sys.stdout.buffer.write(rpc(LISTNS)); return 0
    if len(args) == 3 and args[:2] == ['netns', 'pids']:
        # The PM program is synchronous; cleanup must observe no live client.
        deadline = time.monotonic() + 2
        while json.loads(rpc(STATUS))['live_netlink']:
            if time.monotonic() >= deadline:
                raise RuntimeError('native PM clients still active during namespace cleanup')
            time.sleep(0.005)
        return 0
    if len(args) == 6 and args[0] == '-n' and args[2:] == ['link', 'set', 'lo', 'up']:
        text(UP, args[1]); return 0
    if len(args) >= 5 and args[:2] == ['netns', 'exec']:
        namespace, command = args[2], args[3:]
        if command[0] == 'sysctl' and len(command) == 3 and command[1] == '-q':
            rpc(SYSCTL, namespace.encode() + b'\0' + command[2].encode() + b'\0'); return 0
        if command[0] == './pm_nl_ctl':
            environment = dict(os.environ, KER_MPTCP_PM_NAMESPACE=namespace)
            os.execve(str(Path(command[0]).absolute()), command, environment)
    raise RuntimeError('unsupported upstream PM fixture ip command: ' + repr(args))


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        print('native PM fixture: ' + str(error), file=sys.stderr)
        sys.exit(1)
