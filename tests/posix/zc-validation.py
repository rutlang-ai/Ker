#!/usr/bin/env python3
"""Qualify source argument-validation cases against actual Linux VMAs/sockets.

The null PMD starts the real runtime; payload tests use original Linux loopback.
Wire/PMD offload acceptance is separately exercised by native-buffer tests.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

SOURCE_CASES = {
    'test_ff_zc_mbuf_get_negative_len_returns_error',
    'test_ff_zc_send_mb_null_returns_einval',
    'test_ff_zc_send_nbytes_overflow_returns_einval',
    'test_ff_zc_send_valid_args_proceeds',
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
    with tempfile.TemporaryDirectory(prefix='ker-zc-validation-') as directory:
        root = Path(directory)
        config, stats = root / 'native.ini', root / 'stats.json'
        config.write_text('[network]\naddress=198.18.0.2/24\n'
            '[dpdk]\nport=net_null0\n'
            f'eal=--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry --iova-mode=va -m 96 '
            '--vdev=net_null0,no-rx=1\n')
        result = subprocess.run([sys.executable, str(args.launcher), '--config', str(config),
            '--library', str(args.library), '--io-worker', str(args.worker), '--stats', str(stats),
            '--', str(args.app), 'contracts'], env=environment, text=True, capture_output=True, timeout=30)
        require(result.returncode == 0, 'actual native contract run failed: ' + result.stdout + result.stderr)
        cases = [line.removeprefix('BUFFER_SOURCE_CASE ') for line in result.stdout.splitlines()
                 if line.startswith('BUFFER_SOURCE_CASE ')]
        require(len(cases) == len(SOURCE_CASES) and set(cases) == SOURCE_CASES,
                'missing/duplicate source acceptance markers: ' + result.stdout)
        record = json.loads(stats.read_text())
        native = record['native']
        require(record['run_shutdown'] and record['run_shutdown_ack'] and record['outstanding'] == 0,
                'native/EAL shutdown acknowledgement or mbuf reclamation missing')
        require(record['io']['driver'] == 'net_null', 'original null PMD did not run')
        require(native['buffer_allocations'] >= 75 and native['buffer_allocations'] == native['buffer_releases']
                and native['buffer_shutdown_releases'] == 1
                and native['buffers_live'] == native['buffer_bytes'] == native['buffer_option_guards_live'] == 0,
                'native VMA/option-guard lifetime failure: ' + str(native))
        for case in cases:
            print('PASS: original Linux validation ' + case)
        print('PASS: explicit runtime shutdown; no live mappings, option guards or mbufs')
    return 0


if __name__ == '__main__':
    sys.exit(main())
