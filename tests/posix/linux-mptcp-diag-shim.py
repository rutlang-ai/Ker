#!/usr/bin/env python3
"""Namespace/proc transport for the unchanged upstream diag.sh and real ss."""
import os
from pathlib import Path
import shutil
import socket
import struct
import sys
import time

HEADER = struct.Struct('=IIIIIIq')
MAGIC, MAX = 0x4b4d5331, 131072
NEWNS, DELNS, UP, SYSCTL, FILE, PIDS, STATUS, LISTNS = range(19, 27)


def rpc(operation, namespace='', argument=None):
    data = namespace.encode() + b'\0'
    if argument is not None:
        data += argument.encode() + b'\0'
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as channel:
        channel.settimeout(5)
        # Timeout-mode AF_UNIX connect reports EAGAIN immediately when the
        # listener queue fills (diag creates hundreds of concurrent sockets).
        # Wait only for this host IPC queue; native RPC errno stays unchanged.
        deadline = time.monotonic() + 5
        while True:
            try:
                channel.connect(os.environ['KER_MPTCP_SOCKET_CHANNEL'])
                break
            except BlockingIOError:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('native fixture channel backlog remained full')
                time.sleep(min(0.005, remaining))
        channel.sendall(HEADER.pack(MAGIC, operation, len(data), 0, 0, 0, 0) + data)
        packet, _, flags, _ = channel.recvmsg(HEADER.size + MAX)
    if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or len(packet) < HEADER.size:
        raise RuntimeError('truncated native fixture reply')
    magic, op, length, _, _, _, result = HEADER.unpack_from(packet)
    if magic != MAGIC or op != operation or length != len(packet) - HEADER.size:
        raise RuntimeError('invalid native fixture reply')
    if result < 0:
        raise OSError(-result, os.strerror(-result))
    return packet[HEADER.size:]


def execute(namespace, command):
    environment = dict(os.environ, KER_MPTCP_SOCKET_NAMESPACE=namespace)
    if command[0] in ('ss', 'nstat'):
        program = os.environ['KER_MPTCP_DIAG_' + command[0].upper()]
        environment['LD_PRELOAD'] = os.environ['KER_MPTCP_DIAG_PRELOAD']
        os.execve(program, [program, *command[1:]], environment)
    if command[0] in ('./mptcp_connect', './reuseport_addr_any'):
        os.execve(str(Path(command[0]).resolve()), command, environment)
    if command[0] in ('cat', 'grep', 'awk'):
        mapped = []
        for argument in command[1:]:
            if argument.startswith('/proc/net/'):
                content = rpc(FILE, namespace, argument)
                # Original cat/grep/awk still parse real native proc bytes.
                fd = os.memfd_create('native-proc', flags=0)
                os.set_inheritable(fd, True)
                if os.write(fd, content) != len(content):
                    os.close(fd)
                    raise RuntimeError('incomplete native proc snapshot')
                os.lseek(fd, 0, 0)
                mapped.append('/proc/self/fd/' + str(fd))
            else:
                mapped.append(argument)
        program = shutil.which(command[0])
        os.execve(program, [program, *mapped], environment)
    raise RuntimeError('unsupported native namespace command: ' + repr(command))


def main():
    args = ['-n' if argument == '-netns' else argument for argument in sys.argv[1:]]
    if Path(sys.argv[0]).name == 'ss':
        namespace = os.environ.get('KER_MPTCP_SOCKET_NAMESPACE', '')
        rewritten = []
        while args:
            argument = args.pop(0)
            if argument.startswith('-') and 'N' in argument and not argument.startswith('--'):
                if not args:
                    raise RuntimeError('missing ss namespace')
                namespace = args.pop(0)
                argument = argument.replace('N', '', 1)
                if argument == '-':
                    continue
            rewritten.append(argument)
        execute(namespace, ['ss', *rewritten])
    if args == ['-Version']:
        program = os.environ['KER_MPTCP_DIAG_REAL_IP']; os.execv(program, [program, *args])
    if len(args) == 3 and args[:2] in (['netns', 'add'], ['netns', 'delete'], ['netns', 'del']):
        rpc(NEWNS if args[1] == 'add' else DELNS, args[2]); return 0
    if args[:2] == ['netns', 'list']:
        sys.stdout.buffer.write(rpc(LISTNS)); return 0
    if len(args) == 3 and args[:2] == ['netns', 'pids']:
        sys.stdout.buffer.write(rpc(PIDS, args[2])); return 0
    if len(args) == 6 and args[0] == '-n' and args[2:] == ['link', 'set', 'lo', 'up']:
        rpc(UP, args[1]); return 0
    if len(args) >= 4 and args[:2] == ['netns', 'exec']:
        namespace, command = args[2], args[3:]
        if len(command) == 3 and command[:2] == ['sysctl', '-q']:
            rpc(SYSCTL, namespace, command[2]); return 0
        execute(namespace, command)
    raise RuntimeError('unsupported diag fixture ip command: ' + repr(args))


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        sys.exit('native diag fixture: ' + str(error))
