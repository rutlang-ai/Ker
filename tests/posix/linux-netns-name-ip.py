#!/usr/bin/env python3
"""Namespace transport for unchanged netns-name.sh and pinned iproute2.

Only a destination namespace handle needs translation: host /run/netns paths
cannot name namespaces in the resident kernel. Linux handles the move, rename,
name conflicts and all alternative-name lookups itself.
"""
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys

root = Path(os.environ.get('KER_MPTCP_FIXTURE_SOURCE', str(Path(__file__).parent)))
spec = importlib.util.spec_from_file_location('netns_setup', root / 'linux-mptcp-sockopt-ip.py')
setup = importlib.util.module_from_spec(spec); spec.loader.exec_module(setup)


def log(record):
    with open(os.environ['KER_NETNS_NAME_LOG'], 'a') as stream:
        stream.write(json.dumps(record) + '\n')


def move(namespace, words):
    if len(words) not in (6, 8) or words[:3] != ['link', 'set', 'dev'] or words[4] != 'netns' or \
            (len(words) == 8 and words[6] != 'name'):
        raise RuntimeError('unsupported native namespace move: ' + repr(words))
    target = setup.control(setup.NS_FD, words[5])[0]
    payload = struct.pack('BBHiII', socket.AF_UNSPEC, 0, 0,
                          setup.ifindex(namespace, words[3]), 0, 0)
    payload += setup.integer(28, target)  # IFLA_NET_NS_FD: actual native fd
    if len(words) == 8:
        payload += setup.string(3, words[7])  # IFLA_IFNAME
    setup.netlink(namespace, 16, payload, flags=5)  # RTM_NEWLINK + ACK


def main():
    args = ['-n' if value == '-netns' else value for value in sys.argv[1:]]
    if len(args) >= 3 and args[0] == '-n':
        namespace, words = args[1], args[2:]
        if 'netns' in words:
            try:
                move(namespace, words)
            except OSError as error:
                log(dict(namespace=namespace, arguments=words, operation='move',
                         returncode=1, errno=error.errno))
                print(error.strerror, file=sys.stderr)
                return 1
            log(dict(namespace=namespace, arguments=words, operation='move', returncode=0))
            return 0
        result = subprocess.run([os.environ['KER_NETNS_NAME_IP'], *words],
            env=dict(os.environ, LD_PRELOAD=os.environ['KER_NETNS_NAME_PRELOAD'],
                     KER_MPTCP_SOCKET_NAMESPACE=namespace), capture_output=True, text=True, timeout=10)
        log(dict(namespace=namespace, arguments=words, operation='ip', returncode=result.returncode,
                 stdout=result.stdout, stderr=result.stderr))
        sys.stdout.write(result.stdout); sys.stderr.write(result.stderr)
        return result.returncode
    return setup.diag.main()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        sys.exit('native namespace-name fixture: ' + str(error))
