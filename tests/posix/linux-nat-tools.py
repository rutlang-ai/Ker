#!/usr/bin/env python3
"""Process, namespace-fd and proc transport for original netfilter scripts."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

root = Path(os.environ['KER_MPTCP_FIXTURE_SOURCE'])
spec = importlib.util.spec_from_file_location('nat_setup', root / 'linux-mptcp-sockopt-ip.py')
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
            if len(words) == 3 and words[1] == 'delete' and words[2].startswith('nsrouter1-'):
                env = dict(os.environ, LD_PRELOAD=os.environ['KER_NAT_PRELOAD'], KER_MPTCP_SOCKET_NAMESPACE=words[2])
                record['nat_snapshots'] = []
                for family in ('ip', 'ip6'):
                    result = subprocess.run([os.environ['KER_NAT_NFT'], '-j', 'list', 'table', family, 'nat'],
                        env=env, capture_output=True, text=True, timeout=10, check=True)
                    record['nat_snapshots'].append(json.loads(result.stdout))
            result = setup.diag.main()
            record.update(operation='namespace', returncode=result)
            with open(os.environ['KER_NAT_LOG'], 'a') as stream:
                stream.write(json.dumps(record) + '\n')
            return result
        elif words[:2] == ['link', 'add'] and 'netns' in words:
            if not setup.topology(words):
                raise RuntimeError('unsupported namespace-fd translation: ' + repr(words))
            record.update(operation='namespace-veth', returncode=0)
            with open(os.environ['KER_NAT_LOG'], 'a') as stream:
                stream.write(json.dumps(record) + '\n')
            return 0
    record.update(tool=tool, namespace=namespace, arguments=words)
    if tool == 'sysctl':
        if len(words) != 2 or words[0] != '-q':
            raise RuntimeError('unsupported native sysctl: ' + repr(words))
        setup.diag.rpc(setup.diag.SYSCTL, namespace, words[1])
        record.update(returncode=0, stdout='', stderr='')
    else:
        if tool not in ('ip', 'ping', 'ping6', 'nft'):
            raise RuntimeError('unsupported native process: ' + tool)
        env = dict(os.environ, LD_PRELOAD=os.environ['KER_NAT_PRELOAD'], KER_MPTCP_SOCKET_NAMESPACE=namespace)
        source = sys.stdin.read() if tool == 'nft' and words == ['-f', '-'] else None
        result = subprocess.run([os.environ['KER_NAT_' + tool.upper()], *words], env=env,
            input=source, capture_output=True, text=True, timeout=30)
        record.update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
        if source is not None:
            record['ruleset'] = source
    with open(os.environ['KER_NAT_LOG'], 'a') as stream:
        stream.write(json.dumps(record) + '\n')
    sys.stdout.write(record['stdout']); sys.stderr.write(record['stderr'])
    return record['returncode']


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        sys.exit('native NAT transport: ' + str(error))
