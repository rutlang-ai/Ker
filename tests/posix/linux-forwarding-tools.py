#!/usr/bin/env python3
"""Host process/native network transport for the original forwarding scripts.

Ordinary ip commands use unmodified pinned iproute2. Only process VRF binding
and proc/sysctl access need translation between the two kernel instances.
"""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

root = Path(os.environ['KER_MPTCP_FIXTURE_SOURCE'])
spec = importlib.util.spec_from_file_location('forwarding_diag', root / 'linux-mptcp-diag-shim.py')
diag = importlib.util.module_from_spec(spec); spec.loader.exec_module(diag)


def main():
    tool, words = Path(sys.argv[0]).name, sys.argv[1:]
    record = dict(tool=tool, arguments=words)
    if tool == 'sysctl':
        if len(words) != 2 or words[0] not in ('-n', '-qw'):
            raise RuntimeError('unsupported native sysctl arguments: ' + repr(words))
        if words[0] == '-n':
            value = diag.rpc(diag.FILE, '', '/proc/sys/' + words[1].replace('.', '/')).decode()
            record.update(returncode=0, stdout=value, stderr='')
        else:
            diag.rpc(diag.SYSCTL, '', words[1])
            record.update(returncode=0, stdout='', stderr='')
    else:
        env = dict(os.environ, LD_PRELOAD=os.environ['KER_FORWARDING_PRELOAD'], KER_MPTCP_SOCKET_NAMESPACE='')
        if words[:2] == ['vrf', 'exec']:
            if tool != 'ip' or len(words) < 5 or words[3] not in ('ping', 'ping6'):
                raise RuntimeError('unsupported VRF process: ' + repr(words))
            vrf, program, arguments = words[2], words[3], words[4:]
            # Validate that the requested device really is a native Linux VRF.
            link = subprocess.run([os.environ['KER_FORWARDING_IP'], '-d', '-j', 'link', 'show', 'dev', vrf],
                                  env=env, capture_output=True, text=True, timeout=10, check=True)
            objects = json.loads(link.stdout)
            if len(objects) != 1 or objects[0]['linkinfo']['info_kind'] != 'vrf':
                raise RuntimeError('native VRF device missing: ' + vrf)
            env['KER_FORWARDING_VRF'] = vrf
            command = [os.environ['KER_FORWARDING_' + program.upper()], *arguments]
            record['vrf'] = objects[0]
        else:
            command = [os.environ['KER_FORWARDING_IP'], *words]
        result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=30)
        record.update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
    with open(os.environ['KER_FORWARDING_LOG'], 'a') as stream:
        stream.write(json.dumps(record) + '\n')
    sys.stdout.write(record['stdout']); sys.stderr.write(record['stderr'])
    return record['returncode']


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        sys.exit('native forwarding transport: ' + str(error))
