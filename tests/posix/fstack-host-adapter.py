#!/usr/bin/env python3
"""Qualify actual Ker host mapping/realtime boundaries; no packet/offload evidence."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

CASES = {'shared': 'test_ff_mmap_map_shared_anon', 'file': 'test_ff_mmap_file_backed_no_anon',
         'clock': 'test_ff_update_current_ts_assert_fail_on_clock_error'}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('launcher', 'library', 'worker', 'app', 'pmd-root'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--profile', choices=CASES, required=True)
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    modules = list(args.pmd_root.glob('dpdk/pmds-*/librte_net_null.so'))
    require(len(modules) == 1, 'one original null PMD is required; no skip is counted')
    library_path = str(args.pmd_root)
    if os.environ.get('LD_LIBRARY_PATH'):
        library_path += ':' + os.environ['LD_LIBRARY_PATH']
    environment = dict(os.environ, LD_PRELOAD=str(modules[0]), LD_LIBRARY_PATH=library_path)
    environment.pop('KER_TEST_STARTUP_REALTIME_FAILURE', None)
    if not args.inside:
        command = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()),
                   '--inside', '--profile', args.profile]
        for name in ('launcher', 'library', 'worker', 'app', 'pmd-root'):
            command += ['--' + name, str(getattr(args, name.replace('-', '_')).resolve())]
        return subprocess.run(command, env=environment).returncode
    cpu = min(os.sched_getaffinity(0))
    with tempfile.TemporaryDirectory(prefix='ker-host-mapping-') as directory:
        root = Path(directory)
        config, stats = root / 'native.ini', root / 'stats.json'
        config.write_text('[network]\naddress=198.18.0.2/24\n'
            '[dpdk]\nport=net_null0\n'
            f'eal=--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry --iova-mode=va -m 96 '
            '--vdev=net_null0,no-rx=1\n')
        command = [sys.executable, str(args.launcher), '--config', str(config),
            '--library', str(args.library), '--io-worker', str(args.worker), '--stats', str(stats),
            '--', str(args.app), args.profile]
        if args.profile == 'clock':
            failed = subprocess.run(command, env=dict(environment, KER_TEST_STARTUP_REALTIME_FAILURE='1'),
                                    text=True, capture_output=True, timeout=30)
            detail = failed.stdout + failed.stderr
            require(failed.returncode == 125, 'clock failure did not terminate startup: ' + detail)
            require('TEST_REALTIME_CLOCK_EIO' in failed.stderr and
                    'native realtime clock initialization (-5)' in failed.stderr,
                    'actual native wall-clock refresh failure was not observed: ' + detail)
            require('TEST_APPLICATION_REACHED' not in detail and 'HOST_SOURCE_CASE ' not in detail,
                    'application ran despite rejected realtime refresh: ' + detail)
            failed_record = json.loads(stats.read_text())
            require(failed_record['outstanding'] == 0 and failed_record['io']['driver'] == 'net_null',
                    'failed-start worker reclamation missing: ' + str(failed_record))
            stats.unlink()
        result = subprocess.run(command, env=environment, text=True, capture_output=True, timeout=30)
        require(result.returncode == 0, 'actual native host-adapter run failed: ' + result.stdout + result.stderr)
        markers = [line.removeprefix('HOST_SOURCE_CASE ') for line in result.stdout.splitlines()
                   if line.startswith('HOST_SOURCE_CASE ')]
        require(markers == [CASES[args.profile]], 'missing/duplicate/wrong acceptance markers: ' + result.stdout)
        record = json.loads(stats.read_text())
        require(record['run_shutdown'] and record['run_shutdown_ack'] and record['outstanding'] == 0,
                'native/EAL shutdown or mbuf reclamation missing: ' + str(record))
        require(record['io']['driver'] == 'net_null', 'original null PMD did not run')
        print('PASS: active Ker host adapter ' + markers[0] + '; native shutdown and zero outstanding mbufs')
    return 0


if __name__ == '__main__':
    sys.exit(main())
