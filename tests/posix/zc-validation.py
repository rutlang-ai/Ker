#!/usr/bin/env python3
"""Qualify source argument-validation cases against actual Linux VMAs/sockets.

The original net_tap PMD starts the real launcher. Payload and completion
checks use original Linux loopback sockets.
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
    'test_ff_zc_mbuf_get_zero_len_returns_minimal_chain',
    'test_ff_zc_mbuf_write_accumulates_pkthdr_len',
    'test_ff_zc_mbuf_write_zero_len_noop',
    'test_ff_zc_mbuf_write_overflow_returns_error',
    'test_ff_zc_mbuf_write_null_data_returns_error',
    'test_ff_zc_send_mb_null_returns_einval',
    'test_ff_zc_send_nbytes_overflow_returns_einval',
    'test_ff_zc_send_valid_args_proceeds',
    'test_ff_zc_send_zero_nbytes_returns_einval',
}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('launcher', 'library', 'worker', 'app'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    if not args.inside:
        command = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()), '--inside']
        for name in ('launcher', 'library', 'worker', 'app'):
            command += ['--' + name, str(getattr(args, name.replace('-', '_')).resolve())]
        return subprocess.run(command).returncode
    subprocess.run(['ip', 'link', 'add', 'zcpeer', 'type', 'veth', 'peer', 'name', 'zclink'], check=True)
    subprocess.run(['ip', 'link', 'set', 'zcpeer', 'up'], check=True)
    subprocess.run(['ip', 'link', 'set', 'zclink', 'up'], check=True)
    cpu = min(os.sched_getaffinity(0))
    with tempfile.TemporaryDirectory(prefix='ker-zc-validation-') as directory:
        root = Path(directory)
        config, stats = root / 'native.ini', root / 'stats.json'
        config.write_text('[network]\naddress=198.18.0.2/24\n'
            '[dpdk]\nport=net_tap0\n'
            f'eal=--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry --iova-mode=va -m 96 '
            '--vdev=net_tap0,iface=zcwire,remote=zclink\n')
        result = subprocess.run([sys.executable, str(args.launcher), '--config', str(config),
            '--library', str(args.library), '--io-worker', str(args.worker), '--stats', str(stats),
            '--', str(args.app)], text=True, capture_output=True, timeout=30)
        require(result.returncode == 0, 'actual native contract run failed: ' + result.stdout + result.stderr)
        cases = [line.removeprefix('BUFFER_SOURCE_CASE ') for line in result.stdout.splitlines()
                 if line.startswith('BUFFER_SOURCE_CASE ')]
        require(len(cases) == len(SOURCE_CASES) and set(cases) == SOURCE_CASES,
                'missing/duplicate source acceptance markers: ' + result.stdout)
        record = json.loads(stats.read_text())
        native = record['native']
        require(record['outstanding'] == 0,
                'DPDK worker did not reclaim all mbufs')
        require(native['buffer_allocations'] >= 75 and native['buffer_allocations'] == native['buffer_releases']
                and native['buffer_shutdown_releases'] == 2
                and native['buffers_live'] == native['buffer_bytes'] == native['buffer_option_guards_live'] == 0,
                'native VMA/option-guard lifetime failure: ' + str(native))
        for case in cases:
            print('PASS: original Linux validation ' + case)
        print('PASS: launcher shutdown reclaimed all mappings, option guards and mbufs')
    return 0


if __name__ == '__main__':
    sys.exit(main())
