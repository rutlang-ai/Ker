#!/usr/bin/env python3
"""Exercise real DPDK/native startup failure ordering and worker cleanup."""
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
    for name in ('launcher', 'library', 'worker', 'app', 'probe', 'failure-library'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    if not args.inside:
        command = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()), '--inside']
        for name in ('launcher', 'library', 'worker', 'app', 'probe', 'failure-library'):
            command += ['--' + name, str(getattr(args, name.replace('-', '_')).resolve())]
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
    environment = os.environ.copy()
    environment['LD_PRELOAD'] = str(args.probe) + ' ' + environment.get('LD_PRELOAD', '')
    with tempfile.TemporaryDirectory(prefix='ker-startup-failures-') as directory:
        root = Path(directory)
        cases = [
            ('success', [], None, 0, 'PASS: native interfaces ready'),
            ('native-clock', [], 'realtime', 125, 'native realtime clock initialization'),
            ('kernel-init', [], None, 125, 'kernel initialization (-5)'),
            ('device-register', [], None, 125, 'packet device registration (-5)'),
            ('kernel-boot', [], None, 125, 'kernel boot (-5)'),
            ('wrapped-success', [], None, 0, 'PASS: native interfaces ready'),
            ('loopback-up', [], None, 125, 'loopback activation (-5)'),
            ('interface-up', [], None, 125, 'interface activation (-5)'),
            ('native-route', ['--gateway', '203.0.113.1'], None, 125, 'default route'),
            ('worker-port', ['--port', 'missing-ethdev'], None, 125, 'unknown ethdev'),
        ]
        for name, options, failure, expected, diagnostic in cases:
            marker, stats, cleanup = [root / (name + suffix) for suffix in ('.app', '.json', '.cleanup')]
            env = environment.copy()
            env['KER_TEST_STARTUP_CLEANUP'] = str(cleanup)
            env.pop('KER_TEST_STARTUP_FAILURE', None)
            env.pop('KER_TEST_NATIVE_STAGE_FAILURE', None)
            env.pop('KER_TEST_NATIVE_STAGE_TRACE', None)
            selected_launcher = list(launcher)
            wrapped = name in ('wrapped-success', 'loopback-up', 'interface-up',
                'kernel-init', 'device-register', 'kernel-boot')
            trace = root / (name + '.trace')
            if wrapped:
                selected_launcher[selected_launcher.index('--library') + 1] = str(args.failure_library)
                env['KER_TEST_NATIVE_STAGE_TRACE'] = str(trace)
                if name != 'wrapped-success':
                    env['KER_TEST_NATIVE_STAGE_FAILURE'] = {'loopback-up': 'loopback',
                        'interface-up': 'interface', 'kernel-init': 'init',
                        'device-register': 'register', 'kernel-boot': 'boot'}[name]
            if failure:
                env['KER_TEST_STARTUP_FAILURE'] = failure
            result = subprocess.run([*selected_launcher, *options, '--stats', str(stats), '--',
                                     str(args.app), str(marker)], env=env,
                                    capture_output=True, text=True, timeout=40)
            require(result.returncode == expected, f'{name}: status={result.returncode} {result.stderr}')
            require(diagnostic in result.stdout + result.stderr, f'{name}: missing diagnostic {result.stderr}')
            require(marker.exists() == (expected == 0), f'{name}: application execution out of order')
            require(cleanup.is_file() and cleanup.read_text().strip() == '0',
                    f'{name}: actual EAL cleanup missing or failed')
            require(stats.is_file(), f'{name}: worker cleanup snapshot lost')
            record = json.loads(stats.read_text())
            require(record['outstanding'] == 0, f'{name}: worker leaked mbufs: {record}')
            if name in ('native-clock', 'native-route', 'loopback-up', 'interface-up',
                        'kernel-init', 'device-register', 'kernel-boot'):
                require('application did not initialize the native Linux backend' in result.stderr,
                        f'{name}: failed native startup unexpectedly sent READY')
            if name == 'worker-port':
                require(record['io'] is None and 'native' not in record,
                        'failed ethdev lookup reached later startup stages')
            else:
                require(record['io']['port_count'] == 1, f'{name}: EAL did not initialize')
                require(('native' in record) == (expected == 0),
                        f'{name}: failed native initialization was acknowledged as ready')
            if wrapped:
                lines = trace.read_text().splitlines() if trace.is_file() else []
                stages = ['init', 'register', 'boot', 'loopback', 'interface']
                stop = env.get('KER_TEST_NATIVE_STAGE_FAILURE')
                expected_stages = stages[:stages.index(stop) + 1] if stop else stages
                require(len(lines) == len(expected_stages), f'{name}: unexpected later startup stages: {lines}')
                for line, stage in zip(lines, expected_stages):
                    fields = line.split()
                    require(len(fields) == 3 and fields[:2] == [stage, 'injected' if stage == stop else 'real'],
                            f'{name}: startup trace mismatch: {lines}')
                    result_code = int(fields[2])
                    require(result_code == -5 if stage == stop else
                            (result_code >= 0 if stage == 'register' else result_code == 0),
                            f'{name}: stage result mismatch: {lines}')
            print('PASS: ' + name + ' startup order, application marker and worker/EAL cleanup', flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
