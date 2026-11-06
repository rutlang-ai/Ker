#!/usr/bin/env python3
"""Translate shell topology operations to real imported-Linux rtnetlink UAPI.

No TCP/MPTCP behavior, filter results or counter values are implemented here.
The original pm_nl_ctl and iptables-legacy programs execute their own UAPI.
"""
import errno
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import sys

spec = importlib.util.spec_from_file_location('diag', Path(os.environ.get('KER_MPTCP_FIXTURE_SOURCE', str(Path(__file__).parent))) / 'linux-mptcp-diag-shim.py')
diag = importlib.util.module_from_spec(spec); spec.loader.exec_module(diag)
HEADER, MAX, MAGIC = diag.HEADER, diag.MAX, diag.MAGIC
NS_FD, IFINDEX, FILE_CHUNK = 27, 28, 29


def exchange(channel, op, data=b'', a=0, b=0, c=0):
    channel.sendall(HEADER.pack(MAGIC, op, len(data), a, b, c, 0) + data)
    packet, _, flags, _ = channel.recvmsg(HEADER.size + MAX)
    if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or len(packet) < HEADER.size:
        raise RuntimeError('truncated socket fixture response')
    magic, operation, size, a, b, c, result = HEADER.unpack_from(packet)
    if magic != MAGIC or operation != op or size != len(packet) - HEADER.size:
        raise RuntimeError('invalid socket fixture response')
    if result < 0:
        raise OSError(-result, os.strerror(-result))
    return result, packet[HEADER.size:]


def channel():
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    sock.settimeout(10)
    sock.connect(os.environ['KER_MPTCP_SOCKET_CHANNEL'])
    return sock


def control(op, namespace='', argument=None, offset=0):
    data = namespace.encode() + b'\0'
    if argument is not None:
        data += argument.encode() + b'\0'
    with channel() as sock:
        return exchange(sock, op, data, a=offset)


def attr(kind, data):
    size = len(data) + 4
    return struct.pack('HH', size, kind) + data + b'\0' * (-size % 4)


def integer(kind, value):
    return attr(kind, struct.pack('I', value))


def string(kind, value):
    return attr(kind, value.encode() + b'\0')


def ifindex(namespace, name):
    return control(IFINDEX, namespace, name)[0]


def netlink(namespace, kind, payload, flags=0x605):
    """Send native route request and require its actual kernel ACK."""
    with channel() as sock:
        exchange(sock, 1, namespace.encode() + b'\0', socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
        address = struct.pack('HHII', socket.AF_NETLINK, 0, 0, 0)
        exchange(sock, 2, address)
        request = struct.pack('IHHII', len(payload) + 16, kind, flags, 1, 0) + payload
        io = struct.pack('IIII', len(request), 0, len(address), 0)
        exchange(sock, 18, io + request + address)
        for _ in range(32):
            _, response = exchange(sock, 11, struct.pack('IIII', 65536, 0, 0, 0))
            length = struct.unpack_from('I', response)[0]
            data = response[16:16 + length]
            offset = 0
            while offset + 16 <= len(data):
                size, message, _, sequence, _ = struct.unpack_from('IHHII', data, offset)
                if size < 16 or offset + size > len(data):
                    raise RuntimeError('malformed native netlink response')
                if message == 2 and sequence == 1:
                    error = struct.unpack_from('i', data, offset + 16)[0]
                    if error:
                        raise OSError(-error, os.strerror(-error))
                    return
                offset += (size + 3) & ~3
        raise RuntimeError('missing native rtnetlink acknowledgment')


def topology(args):
    # Original shell's four veth pairs retain both real namespace endpoints.
    if len(args) == 12 and args[:2] == ['link', 'add'] and args[3] == 'netns' and args[5:9] == ['type', 'veth', 'peer', 'name'] and args[10] == 'netns':
        ns1, ns2 = args[4], args[11]
        peer = struct.pack('BBHiII', 0, 0, 0, 0, 0, 0) + string(3, args[9]) + integer(28, control(NS_FD, ns2)[0])
        link = string(1, 'veth') + attr(2 | 0x8000, attr(1 | 0x8000, peer))
        netlink(ns1, 16, struct.pack('BBHiII', 0, 0, 0, 0, 0, 0) + string(3, args[2]) + attr(18 | 0x8000, link))
        return True
    if len(args) < 3 or args[0] not in ('-net', '-n'):
        return False
    namespace, words = args[1], args[2:]
    if len(words) in (4, 6) and words[:2] == ['link', 'set'] and words[3] == 'up' and (len(words) == 4 or words[4] == 'mtu'):
        mtu = integer(4, int(words[5])) if len(words) == 6 else b''
        netlink(namespace, 16, struct.pack('BBHiII', 0, 0, 0, ifindex(namespace, words[2]), 1, 1) + mtu, flags=5)
    elif len(words) in (5, 6) and words[:2] == ['addr', 'add'] and words[3] == 'dev' and (len(words) == 5 or words[5] == 'nodad'):
        address, prefix = words[2].split('/')
        family = socket.AF_INET6 if ':' in address else socket.AF_INET
        value = socket.inet_pton(family, address)
        netlink(namespace, 20, struct.pack('BBBBI', family, int(prefix), 2 if len(words) == 6 else 0, 0, ifindex(namespace, words[4])) + attr(1, value) + attr(2, value))
    elif len(words) in (5, 7, 9) and words[:4] == ['route', 'add', 'default', 'via']:
        gateway = words[4]; family = socket.AF_INET6 if ':' in gateway else socket.AF_INET
        attributes = attr(5, socket.inet_pton(family, gateway))
        for option, value in zip(words[5::2], words[6::2]):
            if option == 'dev': attributes += integer(4, ifindex(namespace, value))
            elif option == 'metric': attributes += integer(6, int(value))
            else: raise RuntimeError('unsupported native route option: ' + option)
        netlink(namespace, 24, struct.pack('BBBBBBBBI', family, 0, 0, 0, 254, 3, 0, 1, 0) + attributes)
    else:
        return False
    return True


def execute(namespace, command):
    environment = dict(os.environ, KER_MPTCP_SOCKET_NAMESPACE=namespace)
    if command[0] in ('iptables', 'ip6tables'):
        program = os.environ['KER_MPTCP_' + command[0].upper()]
        environment['LD_PRELOAD'] = os.environ['KER_MPTCP_DIAG_PRELOAD']
        os.execve(program, [program, *command[1:]], environment)
    if command[0] in ('./mptcp_connect', './mptcp_sockopt', './mptcp_inq', './pm_nl_ctl'):
        os.execve(str(Path(command[0]).resolve()), command, environment)
    if command[0] == 'grep' and '/proc/kallsyms' in command:
        content = bytearray()
        while True:
            block = control(FILE_CHUNK, namespace, '/proc/kallsyms', len(content))[1]
            content.extend(block)
            if not block:
                break
            if len(content) > 16 * 1024 * 1024:
                raise RuntimeError('native kallsyms exceeds fixture limit')
        fd = os.memfd_create('native-kallsyms', flags=0); os.set_inheritable(fd, True)
        with os.fdopen(os.dup(fd), 'wb') as stream: stream.write(content)
        os.lseek(fd, 0, 0)
        command = [('/proc/self/fd/' + str(fd)) if x == '/proc/kallsyms' else x for x in command]
        program = os.environ['KER_MPTCP_REAL_GREP']; os.execve(program, [program, *command[1:]], environment)
    if command[0] == 'grep':
        program = os.environ['KER_MPTCP_REAL_GREP']; os.execve(program, [program, *command[1:]], environment)
    diag.execute(namespace, command)


def mark_negative_control(namespace, environment, preload):
    """An actual unmarked SYN must hit each real native DROP rule."""
    import subprocess
    diag.rpc(diag.UP, namespace)
    evidence = []
    for family, tool, address in ((socket.AF_INET, 'iptables', '127.0.0.1'), (socket.AF_INET6, 'ip6tables', '::1')):
        program = environment['KER_MPTCP_' + tool.upper()]
        env = dict(environment, LD_PRELOAD=str(preload), KER_MPTCP_SOCKET_NAMESPACE=namespace)
        setup = subprocess.run([program, '-A', 'OUTPUT', '-p', 'tcp', '-m', 'mark', '--mark', '0', '-j', 'DROP'],
            capture_output=True, text=True, env=env, timeout=10)
        if setup.returncode:
            raise RuntimeError('negative-control filter setup failed: ' + setup.stderr)
        with channel() as sock:
            exchange(sock, 1, namespace.encode() + b'\0', family, socket.SOCK_STREAM, socket.IPPROTO_MPTCP)
            exchange(sock, 15, a=fcntl.F_SETFL, b=os.O_NONBLOCK)
            if family == socket.AF_INET:
                target = struct.pack('=HH4s8x', family, socket.htons(19999), socket.inet_pton(family, address))
            else:
                target = struct.pack('=HHI16sI', family, socket.htons(19999), 0, socket.inet_pton(family, address), 0)
            try:
                exchange(sock, 5, target)
            except OSError as error:
                if error.errno != errno.EINPROGRESS:
                    raise
            else:
                raise RuntimeError('unmarked connection bypassed native DROP rule')
        query = subprocess.run([program, '-nvxL', 'OUTPUT'], capture_output=True, text=True, env=env, timeout=10)
        drops = [int(line.split()[0]) for line in query.stdout.splitlines() if len(line.split()) > 2 and line.split()[2] == 'DROP']
        if query.returncode or len(drops) != 1 or drops[0] < 1:
            raise RuntimeError('unmarked SYN did not increment actual native DROP counter: ' + query.stdout + query.stderr)
        evidence.append(dict(family=family, drop_packets=drops[0], stdout=query.stdout, stderr=query.stderr))
    return evidence


def main():
    args = sys.argv[1:]
    if Path(sys.argv[0]).name == 'grep':
        execute(os.environ.get('KER_MPTCP_SOCKET_NAMESPACE', ''), ['grep', *args])
    if args == ['-Version']:
        os.execv(os.environ['KER_MPTCP_DIAG_REAL_IP'], ['ip', *args])
    if len(args) >= 4 and args[:2] == ['netns', 'exec']:
        namespace, command = args[2], args[3:]
        if len(command) == 3 and command[:2] == ['sysctl', '-q']:
            diag.rpc(diag.SYSCTL, namespace, command[2]); return 0
        execute(namespace, command)
    if topology(args):
        # Append only after the imported kernel acknowledged the setup request.
        with open(os.environ['KER_MPTCP_TOPOLOGY_LOG'], 'a') as log:
            log.write(json.dumps(args) + '\n')
        return 0
    return diag.main()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        sys.exit('native sockopt fixture: ' + str(error))
