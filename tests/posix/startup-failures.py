#!/usr/bin/env python3
"""Exercise real DPDK/native startup failure ordering and worker cleanup."""
import argparse
import errno
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    paths = ('launcher', 'library', 'worker', 'app', 'probe')
    for name in paths:
        parser.add_argument('--' + name, type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--failure-library', type=Path)
    mode.add_argument('--port-allocation', action='store_true')
    mode.add_argument('--realtime-clock', action='store_true')
    parser.add_argument('--interface-recovery', action='store_true')
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    if args.interface_recovery and not args.failure_library:
        parser.error('--interface-recovery requires --failure-library')
    if not args.inside:
        command = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()), '--inside']
        for name in paths:
            command += ['--' + name, str(getattr(args, name).resolve())]
        if args.port_allocation:
            command += ['--port-allocation']
        elif args.realtime_clock:
            command += ['--realtime-clock']
        else:
            command += ['--failure-library', str(args.failure_library.resolve())]
        if args.interface_recovery:
            command += ['--interface-recovery']
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
            ('production-ignores-hook', [], None, 0, 'PASS: native interfaces ready'),
            ('native-clock', [], 'realtime', 125, 'native realtime clock initialization'),
            ('wrapped-success', [], None, 0, 'PASS: native interfaces ready'),
            ('loopback-up', [], None, 125, 'loopback activation (-5)'),
            ('interface-up', [], None, 125, 'interface activation (-5)'),
            ('native-route', ['--gateway', '203.0.113.1'], None, 125, 'default route'),
            ('worker-port', ['--port', 'missing-ethdev'], None, 125, 'unknown ethdev'),
        ]
        port_traces = {
            'rx': ['rx queue allocation injected ENOMEM'],
            'tx': ['rx queue allocation real ok', 'tx queue allocation injected ENOMEM',
                   'rx queue allocation released', 'rx queue allocation released before EAL cleanup'],
            'recovery': ['rx queue allocation real ok', 'tx queue allocation real ok'],
        }
        if args.port_allocation:
            cases = [
                ('rx', [], None, 125, 'ethdev initialization failed for net_tap0'),
                ('tx', [], None, 125, 'ethdev initialization failed for net_tap0'),
                ('recovery', [], None, 0, 'PASS: native interfaces ready'),
            ]
        if args.realtime_clock:
            cases = [
                ('native-clock', [], 'realtime', 125,
                 f'native realtime clock initialization ({-errno.EIO})'),
                ('clock-recovery', [], None, 0, 'PASS: native interfaces ready'),
            ]
        if args.interface_recovery:
            startup_cases = {case[0]: case for case in cases}
            cases = [startup_cases['interface-up'], startup_cases['wrapped-success']]
        for name, options, failure, expected, diagnostic in cases:
            marker, stats, cleanup = [root / (name + suffix) for suffix in ('.app', '.json', '.cleanup')]
            env = environment.copy()
            env['KER_TEST_STARTUP_CLEANUP'] = str(cleanup)
            env.pop('KER_TEST_STARTUP_FAILURE', None)
            env.pop('KER_TEST_STARTUP_REALTIME_TRACE', None)
            env.pop('KER_TEST_IF_UP_FAILURE', None)
            env.pop('KER_TEST_IF_UP_TRACE', None)
            env.pop('KER_TEST_PORT_QUEUE_ALLOCATION', None)
            if args.port_allocation:
                env['KER_TEST_PORT_QUEUE_ALLOCATION'] = name
            if args.realtime_clock:
                env['KER_TEST_STARTUP_REALTIME_TRACE'] = '1'
            selected_launcher = list(launcher)
            wrapped = name in ('wrapped-success', 'loopback-up', 'interface-up')
            trace = root / (name + '.trace')
            if wrapped:
                selected_launcher[selected_launcher.index('--library') + 1] = str(args.failure_library)
                env['KER_TEST_IF_UP_TRACE'] = str(trace)
                if name != 'wrapped-success':
                    env['KER_TEST_IF_UP_FAILURE'] = 'loopback' if name == 'loopback-up' else 'interface'
            if name == 'production-ignores-hook':
                env['KER_TEST_IF_UP_FAILURE'] = 'interface'
                env['KER_TEST_IF_UP_TRACE'] = str(trace)
            if failure:
                env['KER_TEST_STARTUP_FAILURE'] = failure
            app_options = ['--check-realtime'] if name == 'clock-recovery' else []
            result = subprocess.run([*selected_launcher, *options, '--stats', str(stats), '--',
                                     str(args.app), str(marker), *app_options], env=env,
                                    capture_output=True, text=True, timeout=40)
            require(result.returncode == expected, f'{name}: status={result.returncode} {result.stderr}')
            require(diagnostic in result.stdout + result.stderr, f'{name}: missing diagnostic {result.stderr}')
            require(marker.exists() == (expected == 0), f'{name}: application execution out of order')
            require(cleanup.is_file() and cleanup.read_text().strip() == '0',
                    f'{name}: actual EAL cleanup missing or failed')
            require(stats.is_file(), f'{name}: worker cleanup snapshot lost')
            record = json.loads(stats.read_text())
            require(record['outstanding'] == 0, f'{name}: worker leaked mbufs: {record}')
            if name in ('native-clock', 'native-route', 'loopback-up', 'interface-up'):
                require('application did not initialize the native Linux backend' in result.stderr,
                        f'{name}: failed native startup unexpectedly sent READY')
            if name == 'worker-port' or (args.port_allocation and expected != 0):
                require(record['io'] is None and 'native' not in record,
                        f'{name}: failed worker reached later startup stages')
            else:
                require(record['io']['port_count'] == 1, f'{name}: EAL did not initialize')
                require(('native' in record) == (expected == 0),
                        f'{name}: failed native initialization was acknowledged as ready')
            if name == 'production-ignores-hook':
                require(not trace.exists(), 'production library unexpectedly contains the test hook')
            if wrapped:
                expected_trace = {'wrapped-success': 'loopback real 0\ninterface real 0\n',
                    'loopback-up': 'loopback injected -5\n',
                    'interface-up': 'loopback real 0\ninterface injected -5\n'}[name]
                require(trace.is_file() and trace.read_text() == expected_trace,
                        f'{name}: interface activation stage trace mismatch')
            if args.port_allocation or args.interface_recovery:
                require('kerpeer' not in {interface for _, interface in socket.if_nameindex()},
                        f'{name}: TAP interface still present after worker exit')
            if args.port_allocation:
                prefix = 'ker-test: '
                observed = [line.removeprefix(prefix) for line in result.stderr.splitlines()
                            if line.startswith(prefix)]
                require(observed == port_traces[name],
                        f'{name}: ethdev allocation or rollback trace mismatch: {result.stderr}')
                if expected != 0:
                    require(f'eth_dev_{name}_queue_config = {-errno.ENOMEM}' in result.stderr,
                            f'{name}: original DPDK did not report configuration ENOMEM: {result.stderr}')
                    require('DPDK worker failed before packet I/O became ready' in result.stderr,
                            f'{name}: expected worker startup failure: {result.stderr}')
            if args.realtime_clock:
                prefix = 'ker-test: startup realtime '
                observed = [line.removeprefix(prefix) for line in result.stderr.splitlines()
                            if line.startswith(prefix)]
                expected_reads = ['injected EIO'] if failure else ['real ok'] * 3
                require(observed == expected_reads,
                        f'{name}: unexpected realtime clock trace: {result.stderr}')
                if name == 'clock-recovery':
                    require('PASS: native realtime seconds available to the application' in result.stdout,
                            f'{name}: native realtime API was not exercised: {result.stdout}')
            print('PASS: ' + name + ' startup order, application marker and worker/EAL cleanup', flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
