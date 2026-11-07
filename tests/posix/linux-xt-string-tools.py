#!/usr/bin/env python3
"""Process transport for original Linux string-match and UDP tools."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

root = Path(os.environ['KER_MPTCP_FIXTURE_SOURCE'])
spec = importlib.util.spec_from_file_location('xt_string_setup', root / 'linux-mptcp-sockopt-ip.py')
setup = importlib.util.module_from_spec(spec); spec.loader.exec_module(setup)


def main():
    tool, words = Path(sys.argv[0]).name, sys.argv[1:]
    namespace = ''
    record = dict(tool=tool, arguments=words, namespace=namespace)
    if tool == 'ip':
        if words[:1] and words[0] in ('-net', '-netns', '-n'):
            namespace, words = words[1], words[2:]
        elif words[:2] == ['netns', 'exec']:
            namespace, tool, words = words[2], words[3], words[4:]
        elif words[:1] == ['netns']:
            result = setup.diag.main()
            record.update(operation='namespace', returncode=result)
            with open(os.environ['KER_XT_STRING_LOG'], 'a') as stream:
                stream.write(json.dumps(record) + '\n')
            return result
        elif words[:2] == ['link', 'add'] and 'netns' in words:
            if not setup.topology(words):
                raise RuntimeError('unsupported namespace-fd translation: ' + repr(words))
            record.update(operation='namespace-veth', returncode=0)
            with open(os.environ['KER_XT_STRING_LOG'], 'a') as stream:
                stream.write(json.dumps(record) + '\n')
            return 0
    record.update(tool=tool, namespace=namespace, arguments=words)
    if tool == 'sysctl':
        if len(words) != 2 or words[0] != '-q':
            raise RuntimeError('unsupported native sysctl: ' + repr(words))
        setup.diag.rpc(setup.diag.SYSCTL, namespace, words[1])
        record.update(returncode=0, stdout='', stderr='')
    else:
        if tool not in ('ip', 'socat', 'iptables'):
            raise RuntimeError('unsupported native process: ' + tool)
        env = dict(os.environ, LD_PRELOAD=os.environ['KER_XT_STRING_PRELOAD'], KER_MPTCP_SOCKET_NAMESPACE=namespace)
        payload = sys.stdin.buffer.read() if tool == 'socat' and words == ['-t', '1', '-u', 'STDIN', 'UDP-SENDTO:10.1.2.2:27374'] else None
        if payload is not None:
            record['stdin'] = payload.decode('ascii')
        result = subprocess.run([os.environ['KER_XT_STRING_' + tool.upper()], *words], env=env,
            input=payload, capture_output=True, timeout=30)
        record.update(returncode=result.returncode, stdout=result.stdout.decode(errors='replace'), stderr=result.stderr.decode(errors='replace'))
    with open(os.environ['KER_XT_STRING_LOG'], 'a') as stream:
        stream.write(json.dumps(record) + '\n')
    if tool == 'sysctl':
        sys.stdout.write(record['stdout']); sys.stderr.write(record['stderr'])
    else:
        sys.stdout.buffer.write(result.stdout); sys.stderr.buffer.write(result.stderr)
    return record['returncode']


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        sys.exit('native XT_STRING transport: ' + str(error))
