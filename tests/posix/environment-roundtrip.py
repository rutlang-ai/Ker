#!/usr/bin/env python3
"""Run the host environment scenario through Ker's real launch/cleanup path."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('launcher', 'library', 'worker', 'app', 'probe'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    if not args.inside:
        command = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()), '--inside']
        for name in ('launcher', 'library', 'worker', 'app', 'probe'):
            command += ['--' + name, str(getattr(args, name).resolve())]
        return subprocess.run(command).returncode
    for scope in ('all', 'default'):
        Path('/proc/sys/net/ipv6/conf/' + scope + '/disable_ipv6').write_text('1\n')
    for command in (['ip', 'link', 'add', 'kerhost', 'type', 'veth', 'peer', 'name', 'kerlink'],
                    ['ip', 'link', 'set', 'kerhost', 'up'], ['ip', 'link', 'set', 'kerlink', 'up']):
        subprocess.run(command, check=True)
    cpu = min(os.sched_getaffinity(0))
    eal = (f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry '
           '--iova-mode=va -m 64 --vdev=net_tap0,iface=kerpeer,remote=kerlink')
    launcher = [sys.executable, str(args.launcher), '--library', str(args.library),
                '--io-worker', str(args.worker), '--address', '198.18.0.2/24',
                '--port', 'net_tap0', '--eal', eal]
    baseline = os.environ.copy()
    baseline.pop('KER_TEST_STARTUP_FAILURE', None)
    baseline['LD_PRELOAD'] = str(args.probe) + ' ' + baseline.get('LD_PRELOAD', '')
    key = 'FF_UNIT_TEST_VAR'
    with tempfile.TemporaryDirectory(prefix='ker-environment-') as directory:
        root = Path(directory)
        # Exercise both inherited and absent inputs, then repeat after a full
        # native/worker teardown. Each application removes its local key.
        for index, initial in enumerate(('inherited-value', None, 'inherited-value')):
            env = baseline.copy()
            env.pop(key, None)
            if initial is not None:
                env[key] = initial
            cleanup, stats = root / f'{index}.cleanup', root / f'{index}.json'
            env['KER_TEST_STARTUP_CLEANUP'] = str(cleanup)
            result = subprocess.run([*launcher, '--stats', str(stats), '--', str(args.app),
                                     initial if initial is not None else '--absent'],
                                    env=env, capture_output=True, text=True, timeout=40)
            require(result.returncode == 0, f'launch {index}: {result.stdout}\n{result.stderr}')
            require('PASS: inherited environment and POSIX set/get' in result.stdout,
                    f'launch {index}: application did not finish its checks')
            require(cleanup.is_file() and cleanup.read_text().strip() == '0',
                    f'launch {index}: actual EAL cleanup missing or failed')
            record = json.loads(stats.read_text())
            require(record['outstanding'] == 0 and record['io']['port_count'] == 1,
                    f'launch {index}: worker startup/cleanup mismatch: {record}')
            require('native' in record, f'launch {index}: native startup/shutdown proof missing')
            print(f'PASS: environment launch {index}, original Linux ready and real worker cleanup', flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
