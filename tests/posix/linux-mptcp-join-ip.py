#!/usr/bin/env python3
"""Transport original join-matrix tools to the resident Linux namespace."""
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

root = Path(os.environ.get('KER_MPTCP_FIXTURE_SOURCE', str(Path(__file__).parent)))
spec = importlib.util.spec_from_file_location('join_connect_transport', root / 'linux-mptcp-connect-ip.py')
connect = importlib.util.module_from_spec(spec); spec.loader.exec_module(connect)
setup = connect.setup


def ip(namespace, arguments, capture=False):
    program = os.environ['KER_MPTCP_DIAG_IP']
    env = dict(os.environ, KER_MPTCP_SOCKET_NAMESPACE=namespace,
               LD_PRELOAD=os.environ['KER_MPTCP_DIAG_PRELOAD'])
    result = subprocess.run([program, *arguments], env=env, capture_output=capture, text=capture)
    connect.log(dict(namespace=namespace, tool='ip', arguments=arguments, returncode=result.returncode))
    return result


def execute(namespace, command):
    if command[:2] == ['sysctl', '-n'] and len(command) == 3:
        name = command[2]
        if not re.fullmatch(r'net\.[a-z0-9_.-]+', name):
            raise RuntimeError('unsupported native sysctl query')
        value = setup.control(setup.diag.FILE, namespace, '/proc/sys/' + name.replace('.', '/'))[1]
        sys.stdout.buffer.write(value); return 0
    if command[0] == 'ip':
        return ip(namespace, command[1:]).returncode
    if command[0] == 'cat' and len(command) == 2:
        match = re.fullmatch(r'/sys/class/net/([A-Za-z0-9_-]+)/statistics/tx_bytes', command[1])
        if match:
            # The host sysfs mount describes host devices. Transport this leaf
            # through the same native IFLA_STATS64 counter exposed by Linux
            # sysfs rather than mounting or consulting the host sysfs tree.
            result = ip(namespace, ['-j', '-s', 'link', 'show', 'dev', match[1]], capture=True)
            if result.returncode:
                raise RuntimeError('native link statistics query failed: ' + result.stderr)
            objects = json.loads(result.stdout)
            if len(objects) != 1 or objects[0].get('ifname') != match[1]:
                raise RuntimeError('native statistics interface mismatch')
            value = objects[0]['stats64']['tx']['bytes']
            if not isinstance(value, int) or value < 0:
                raise RuntimeError('invalid native byte counter')
            connect.log(dict(namespace=namespace, native_sysfs_path=command[1], native_link=objects[0]))
            print(value); return 0
    return connect.execute(namespace, command)


def main():
    args = sys.argv[1:]
    name = Path(sys.argv[0]).name
    if name == 'nstat':
        return setup.diag.execute(os.environ.get('KER_MPTCP_SOCKET_NAMESPACE', ''), ['nstat', *args])
    if name == 'tc':
        return connect.traffic_control(args)
    if len(args) >= 4 and args[:2] == ['netns', 'exec']:
        if args[3:5] == ['sysctl', '-q']:
            return setup.main()
        return execute(args[2], args[3:])
    if len(args) >= 3 and args[0] in ('-n', '-net'):
        return ip(args[1], args[2:]).returncode
    return connect.main()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        sys.exit('native join fixture: ' + str(error))
