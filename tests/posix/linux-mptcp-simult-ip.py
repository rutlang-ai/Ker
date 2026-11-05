#!/usr/bin/env python3
"""Namespace transport for unchanged simult_flows.sh and original iproute2 tc."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

root = Path(os.environ.get('KER_MPTCP_FIXTURE_SOURCE', str(Path(__file__).parent)))
spec = importlib.util.spec_from_file_location('topology_fixture', root / 'linux-mptcp-sockopt-ip.py')
setup = importlib.util.module_from_spec(spec); spec.loader.exec_module(setup)


def validate_netem(arguments, objects):
    matches = [item for item in objects if item.get('kind') == 'netem']
    if len(matches) != 1:
        raise RuntimeError('actual native netem qdisc missing')
    options = matches[0].get('options', {})
    rate = arguments[arguments.index('rate') + 1]
    if not rate.endswith('mbit'):
        raise RuntimeError('unsupported original rate unit: ' + rate)
    expected = int(rate[:-4]) * 1000000 // 8
    delay = float(arguments[arguments.index('delay') + 1][:-2]) / 1000 if 'delay' in arguments else 0
    actual_delay = options.get('delay', {}).get('delay', 0)
    if options.get('rate', {}).get('rate') != expected or options.get('limit') != 50 or abs(actual_delay - delay) > 0.000001:
        raise RuntimeError('native netem readback differs from original rate/delay/limit: ' + repr(objects))


def main():
    arguments = sys.argv[1:]
    if Path(sys.argv[0]).name != 'tc':
        return setup.main()
    if arguments in (['-Version'], ['-V'], ['-help'], ['-h']):
        program = os.environ['KER_MPTCP_DIAG_TC']; os.execv(program, [program, *arguments])
    if len(arguments) < 4 or arguments[0] not in ('-n', '-net'):
        raise RuntimeError('unsupported native tc namespace command: ' + repr(arguments))
    namespace, command = arguments[1], arguments[2:]
    environment = dict(os.environ, KER_MPTCP_SOCKET_NAMESPACE=namespace, LD_PRELOAD=os.environ['KER_MPTCP_DIAG_PRELOAD'])
    program = os.environ['KER_MPTCP_DIAG_TC']
    result = subprocess.run([program, *command], env=environment)
    evidence = dict(namespace=namespace, arguments=command, returncode=result.returncode)
    if command[:2] == ['qdisc', 'add'] and result.returncode == 0:
        device = command[command.index('dev') + 1]
        snapshot = subprocess.run([program, '-j', 'qdisc', 'show', 'dev', device], env=environment,
            capture_output=True, text=True, timeout=10)
        if snapshot.returncode:
            raise RuntimeError('native netem readback failed: ' + snapshot.stderr)
        evidence['native_qdiscs'] = json.loads(snapshot.stdout)
        validate_netem(command, evidence['native_qdiscs'])
    with open(os.environ['KER_MPTCP_NETEM_LOG'], 'a') as stream:
        stream.write(json.dumps(evidence) + '\n')
    return result.returncode


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        sys.exit('native simultaneous-flows fixture: ' + str(error))
