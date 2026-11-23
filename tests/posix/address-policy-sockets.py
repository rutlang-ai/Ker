#!/usr/bin/env python3
"""Qualify explicit caller address policy with the original Linux socket runtime.

Actual payload exchange uses original-Linux IPv4/IPv6 loopback; the null PMD
starts the real runtime and supplies no external-wire evidence.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

def require(value, message):
    if not value:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('launcher', 'library', 'worker', 'app', 'pmd-root'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--inside', action='store_true')
    parser.add_argument('--evidence', type=Path)
    args = parser.parse_args()
    modules = list(args.pmd_root.glob('dpdk/pmds-*/librte_net_null.so'))
    if not modules:
        print('SKIP: install the pinned original null PMD')
        return 77
    environment = dict(os.environ, LD_PRELOAD=str(modules[0]))
    environment['LD_LIBRARY_PATH'] = str(args.pmd_root.resolve()) + os.pathsep + environment.get('LD_LIBRARY_PATH', '')
    if not args.inside:
        command = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()), '--inside']
        for name in ('launcher', 'library', 'worker', 'app', 'pmd-root'):
            command += ['--' + name, str(getattr(args, name.replace('-', '_')).resolve())]
        if args.evidence:
            command += ['--evidence', str(args.evidence.resolve())]
        return subprocess.run(command, env=environment).returncode
    cpu = min(os.sched_getaffinity(0))
    with tempfile.TemporaryDirectory(prefix='ker-address-policy-') as directory:
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
        exchanges = [line.removeprefix('ADDRESS_NATIVE_EXCHANGE ') for line in result.stdout.splitlines()
                     if line.startswith('ADDRESS_NATIVE_EXCHANGE ')]
        require(exchanges == ['2 0', '10 0', '2 1', '10 1', '2 0', '10 0'],
                'incomplete source selection/default/unregister recovery: ' + result.stdout)
        require('PASS: original Linux source selection, exact dual-stack payloads and unregister recovery' in result.stdout,
                'missing native application acceptance: ' + result.stdout)
        releases = [line.removeprefix('ADDRESS_NATIVE_KERNEL ') for line in result.stdout.splitlines()
                    if line.startswith('ADDRESS_NATIVE_KERNEL ')]
        require(len(releases) == 1 and releases[0], 'missing original kernel release')
        record = json.loads(stats.read_text())
        native = record['native']
        require(record['run_shutdown'] and record['run_shutdown_ack'] and record['outstanding'] == 0,
                'native/EAL shutdown acknowledgement or mbuf reclamation missing')
        require(record['io']['driver'] == 'net_null', 'original null PMD did not run')
        require(native['buffer_allocations'] == native['buffer_releases'] == 0
                and native['buffer_shutdown_releases'] == 0
                and native['buffers_live'] == native['buffer_bytes'] == native['buffer_option_guards_live'] == 0,
                'native VMA/option-guard lifetime failure: ' + str(native))
        if args.evidence:
            inputs = {str(path.resolve()): hashlib.sha256(path.read_bytes()).hexdigest()
                      for path in (args.launcher, args.library, args.worker, args.app, modules[0], Path(__file__))}
            with args.evidence.open('x') as output:
                json.dump({'status': 'passed', 'inputs_sha256': inputs, 'stdout': result.stdout,
                           'stderr': result.stderr, 'stats': record, 'config': config.read_text(),
                           'kernel_release': releases[0], 'returncode': result.returncode}, output, indent=2)
                output.write('\n')
        print('PASS: six original-Linux TCP payload exchanges; selected source/port/peer; denial and unregister recovery')
        print('PASS: explicit runtime shutdown; no live mappings, option guards or mbufs')
    return 0


if __name__ == '__main__':
    sys.exit(main())
