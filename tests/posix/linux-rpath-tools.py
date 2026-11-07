#!/usr/bin/env python3
"""Process, namespace-fd and proc transport for original netfilter scripts."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

root = Path(os.environ['KER_MPTCP_FIXTURE_SOURCE'])
spec = importlib.util.spec_from_file_location('rpath_setup', root / 'linux-mptcp-sockopt-ip.py')
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
            with open(os.environ['KER_RPATH_LOG'], 'a') as stream:
                stream.write(json.dumps(record) + '\n')
            return result
        elif words[:2] == ['link', 'add'] and 'netns' in words:
            if not setup.topology(words):
                raise RuntimeError('unsupported namespace-fd translation: ' + repr(words))
            record.update(operation='namespace-veth', returncode=0)
            with open(os.environ['KER_RPATH_LOG'], 'a') as stream:
                stream.write(json.dumps(record) + '\n')
            return 0
    if tool == 'ip' and len(words) == 10 and words[:2] == ['link', 'add'] and words[3:7] == ['type', 'veth', 'peer', 'name'] and words[8] == 'netns':
        if not namespace:
            raise RuntimeError('missing first native veth namespace')
        translated = ['link', 'add', words[2], 'netns', namespace, 'type', 'veth', 'peer', 'name', words[7], 'netns', words[9]]
        if not setup.topology(translated):
            raise RuntimeError('unsupported cross-namespace veth')
        record.update(tool=tool, namespace=namespace, arguments=words, operation='namespace-veth', returncode=0, stdout='', stderr='')
        with open(os.environ['KER_RPATH_LOG'], 'a') as stream:
            stream.write(json.dumps(record) + '\n')
        return 0
    record.update(tool=tool, namespace=namespace, arguments=words)
    if tool == 'sysctl':
        if len(words) != 2 or words[0] != '-q':
            raise RuntimeError('unsupported native sysctl: ' + repr(words))
        setup.diag.rpc(setup.diag.SYSCTL, namespace, words[1])
        record.update(returncode=0, stdout='', stderr='')
    else:
        if tool not in ('ip', 'ping', 'nft', 'iptables-legacy', 'ip6tables-legacy'):
            raise RuntimeError('unsupported native process: ' + tool)
        env = dict(os.environ, LD_PRELOAD=os.environ['KER_RPATH_PRELOAD'], KER_MPTCP_SOCKET_NAMESPACE=namespace)
        native_time_log = None
        if tool == 'ping':
            native_time_log = os.environ['KER_RPATH_LOG'] + '.native-time-' + str(os.getpid())
            env['KER_MPTCP_NATIVE_REALTIME'] = '1'
            env['KER_MPTCP_NATIVE_TIME_LOG'] = native_time_log
        source = sys.stdin.read() if tool == 'nft' and words == ['-f', '-'] else None
        result = subprocess.run([os.environ['KER_RPATH_' + tool.upper().replace('-', '_')], *words], env=env,
            input=source, capture_output=True, text=True, timeout=30)
        record.update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
        if native_time_log:
            try:
                record['native_clock_reads'] = Path(native_time_log).stat().st_size
            except FileNotFoundError:
                record['native_clock_reads'] = 0
            Path(native_time_log).unlink(missing_ok=True)
        if source is not None:
            record['ruleset'] = source
    with open(os.environ['KER_RPATH_LOG'], 'a') as stream:
        stream.write(json.dumps(record) + '\n')
    sys.stdout.write(record['stdout']); sys.stderr.write(record['stderr'])
    return record['returncode']


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        sys.exit('native rpath transport: ' + str(error))
