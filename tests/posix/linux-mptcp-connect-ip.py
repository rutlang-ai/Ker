#!/usr/bin/env python3
"""Private transport for the complete, unchanged MPTCP connect shell matrix.

Topology requests require native rtnetlink ACKs. External tools operate through
socket interposition in the resident imported Linux, including ICMP and nftables.
"""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys

root = Path(os.environ.get('KER_MPTCP_FIXTURE_SOURCE', str(Path(__file__).parent)))
spec = importlib.util.spec_from_file_location('connect_topology', root / 'linux-mptcp-sockopt-ip.py')
setup = importlib.util.module_from_spec(spec); spec.loader.exec_module(setup)
DIRECTORY = 34


def sysctl(namespace, name):
    if not name.startswith('net.') or any(not (c.isalnum() or c in '._-') for c in name):
        raise RuntimeError('unsupported native sysctl name: ' + name)
    path = '/proc/sys/' + name.replace('.', '/')
    try:
        value = setup.control(setup.diag.FILE, namespace, path)[1]
        print(name + ' = ' + value.decode().strip())
    except IsADirectoryError:
        data = setup.control(DIRECTORY, namespace, path)[1]
        offset = 0
        while offset < len(data):
            if len(data) - offset < 20:
                raise RuntimeError('truncated native directory entry')
            size = struct.unpack_from('H', data, offset + 16)[0]
            if size < 20 or offset + size > len(data):
                raise RuntimeError('invalid native directory entry')
            entry = data[offset + 19:offset + size].split(b'\0', 1)[0].decode()
            if entry not in ('.', '..'):
                sysctl(namespace, name + '.' + entry)
            offset += size


def execute(namespace, command):
    if command[0] == 'sysctl' and len(command) == 2:
        sysctl(namespace, command[1]); return 0
    if command[0] in ('ping', 'ethtool', 'nft'):
        program = os.environ['KER_MPTCP_CONNECT_' + command[0].upper()]
        env = dict(os.environ, KER_MPTCP_SOCKET_NAMESPACE=namespace,
                   LD_PRELOAD=os.environ['KER_MPTCP_DIAG_PRELOAD'])
        result = subprocess.run([program, *command[1:]], env=env)
        log(dict(namespace=namespace, tool=command[0], arguments=command[1:], returncode=result.returncode))
        return result.returncode
    return setup.execute(namespace, command)


def log(value):
    with open(os.environ['KER_MPTCP_CONNECT_LOG'], 'a') as stream:
        stream.write(json.dumps(value) + '\n')


def policy_route(args):
    if len(args) < 3 or args[0] not in ('-net', '-n'):
        return False
    namespace, words = args[1], args[2:]
    family = socket.AF_INET
    if words[0] == '-6':
        family = socket.AF_INET6; words = words[1:]
    if words[:1] == ['rule'] and len(words) == 6 and words[1] in ('add', 'del') and words[2::2] == ['fwmark', 'lookup']:
        payload = struct.pack('BBBBBBBBI', family, 0, 0, 0, int(words[5]), 0, 0, 1, 0)
        setup.netlink(namespace, 32 if words[1] == 'add' else 33,
                      payload + setup.integer(10, int(words[3])), flags=0x605 if words[1] == 'add' else 5)
    elif len(words) == 8 and words[0] == 'route' and words[1] in ('add', 'del') and words[2] == 'local' and words[4] == 'dev' and words[6] == 'table':
        address, prefix = words[3].split('/')
        family = socket.AF_INET6 if ':' in address else socket.AF_INET
        payload = struct.pack('BBBBBBBBI', family, int(prefix), 0, 0, int(words[7]), 3, 254, 2, 0)
        setup.netlink(namespace, 24 if words[1] == 'add' else 25,
                      payload + setup.attr(1, socket.inet_pton(family, address)) + setup.integer(4, setup.ifindex(namespace, words[5])),
                      flags=0x605 if words[1] == 'add' else 5)
    else:
        return False
    log(dict(namespace=namespace, acknowledged_policy=args)); return True


def validate_netem(command, objects):
    matches = [q for q in objects if q.get('kind') == 'netem']
    if len(matches) != 1:
        raise RuntimeError('native netem qdisc missing')
    options = matches[0].get('options', {})
    expected_delay = float(command[command.index('delay') + 1][:-2]) / 1000
    if abs(options.get('delay', {}).get('delay', 0) - expected_delay) > 0.000001:
        raise RuntimeError('native netem delay differs from original command')
    loss = float(command[command.index('random') + 1].rstrip('%')) / 100 if 'loss' in command else 0
    if abs(options.get('loss-random', {}).get('loss', 0) - loss) > 0.000001:
        raise RuntimeError('native netem loss differs from original command')
    for position, key in ((1, 'reorder'), (2, 'correlation')):
        expected = float(command[command.index('reorder') + position].rstrip('%')) / 100 if 'reorder' in command else 0
        if abs(options.get('reorder', {}).get(key, 0) - expected) > 0.000001:
            raise RuntimeError('native netem reordering differs from original command')
    if 'rate' in command:
        rate = command[command.index('rate') + 1]
        if not rate.endswith('mbit') or options.get('rate', {}).get('rate') != int(rate[:-4]) * 1000000 // 8:
            raise RuntimeError('native netem rate differs from original command')


def traffic_control(args):
    program = os.environ['KER_MPTCP_DIAG_TC']
    if args in (['-Version'], ['-V'], ['-help'], ['-h']):
        return subprocess.run([program, *args]).returncode
    if len(args) < 4 or args[0] not in ('-n', '-net'):
        raise RuntimeError('unsupported native tc command: ' + repr(args))
    namespace, command = args[1], args[2:]
    env = dict(os.environ, KER_MPTCP_SOCKET_NAMESPACE=namespace,
               LD_PRELOAD=os.environ['KER_MPTCP_DIAG_PRELOAD'])
    result = subprocess.run([program, *command], env=env)
    record = dict(namespace=namespace, tool='tc', arguments=command, returncode=result.returncode)
    if command[:2] == ['qdisc', 'add'] and 'netem' in command and result.returncode == 0:
        device = command[command.index('dev') + 1]
        snapshot = subprocess.run([program, '-j', 'qdisc', 'show', 'dev', device],
                                  env=env, capture_output=True, text=True, timeout=10, check=True)
        record['native_qdiscs'] = json.loads(snapshot.stdout)
        validate_netem(command, record['native_qdiscs'])
    log(record)
    return result.returncode


def main():
    args = sys.argv[1:]
    if Path(sys.argv[0]).name == 'cmp':
        result = subprocess.run([os.environ['KER_MPTCP_CONNECT_CMP'], *args])
        record = dict(tool='cmp', arguments=args, returncode=result.returncode)
        if result.returncode and len(args) == 2:
            record['files'] = []
            for name in args:
                content = Path(name).read_bytes()
                record['files'].append(dict(path=name, size=len(content), sha256=hashlib.sha256(content).hexdigest(),
                                            tail=content[-64:].hex()))
        log(record)
        return result.returncode
    if Path(sys.argv[0]).name == 'tc':
        return traffic_control(args)
    if len(args) >= 4 and args[:2] == ['netns', 'exec']:
        if args[3:5] == ['sysctl', '-q']:
            return setup.main()
        return execute(args[2], args[3:])
    if policy_route(args):
        return 0
    return setup.main()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        sys.exit('native connect fixture: ' + str(error))
