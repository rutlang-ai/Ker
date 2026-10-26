#!/usr/bin/env python3
"""Qualify optional native realtime outputs in the preloaded library.

Actual payload exchange uses original-Linux IPv4/IPv6 loopback; the null PMD
starts the real runtime and supplies no external-wire evidence.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

SOURCE_CASES = {
    'test_ff_get_current_time_null_sec',
    'test_ff_get_current_time_null_nsec',
}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('launcher', 'library', 'worker', 'app', 'pmd-root'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    modules = list(args.pmd_root.glob('dpdk/pmds-*/librte_net_null.so'))
    if not modules:
        print('SKIP: install the pinned original null PMD')
        return 77
    environment = dict(os.environ, LD_PRELOAD=str(modules[0]))
    if not args.inside:
        command = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()), '--inside']
        for name in ('launcher', 'library', 'worker', 'app', 'pmd-root'):
            command += ['--' + name, str(getattr(args, name.replace('-', '_')).resolve())]
        return subprocess.run(command, env=environment).returncode
    cpu = min(os.sched_getaffinity(0))
    with tempfile.TemporaryDirectory(prefix='ker-current-time-') as directory:
        root = Path(directory)
        config, stats = root / 'native.ini', root / 'stats.json'
        config.write_text('[network]\naddress=198.18.0.2/24\n'
            '[dpdk]\nport=net_null0\n'
            f'eal=--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry --iova-mode=va -m 96 '
            '--vdev=net_null0,no-rx=1\n')
        result = subprocess.run([sys.executable, str(args.launcher), '--config', str(config),
            '--library', str(args.library), '--io-worker', str(args.worker), '--stats', str(stats),
            '--', str(args.app)], env=environment, text=True, capture_output=True, timeout=30)
        require(result.returncode == 0, 'actual native contract run failed: ' + result.stdout + result.stderr)
        cases = [line.removeprefix('TIME_SOURCE_CASE ') for line in result.stdout.splitlines()
                 if line.startswith('TIME_SOURCE_CASE ')]
        require(len(cases) == len(SOURCE_CASES) and set(cases) == SOURCE_CASES,
                'missing/duplicate source acceptance markers: ' + result.stdout)
        families = [line.removeprefix('TIME_NATIVE_FAMILY ') for line in result.stdout.splitlines()
                    if line.startswith('TIME_NATIVE_FAMILY ')]
        require(families == ['0', '1'], 'missing/duplicate dual-stack native exchange: ' + result.stdout)
        record = json.loads(stats.read_text())
        native = record['native']
        require(record['run_shutdown'] and record['run_shutdown_ack'] and record['outstanding'] == 0,
                'native/EAL shutdown acknowledgement or mbuf reclamation missing')
        require(record['io']['driver'] == 'net_null', 'original null PMD did not run')
        require(native['buffer_allocations'] == native['buffer_releases'] == 0
                and native['buffer_shutdown_releases'] == 0
                and native['buffers_live'] == native['buffer_bytes'] == native['buffer_option_guards_live'] == 0,
                'native VMA/option-guard lifetime failure: ' + str(native))
        for case in cases:
            print('PASS: original Linux current-time ' + case)
        print('PASS: explicit runtime shutdown; no live mappings, option guards or mbufs')
    return 0


if __name__ == '__main__':
    sys.exit(main())
