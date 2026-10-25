#!/usr/bin/env python3
"""Isolate real TAP PMD ownership fault tests from host network configuration."""
import argparse
import atexit
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from dpdk_runtime import private_runtime_environment

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--app', type=Path, required=True)
parser.add_argument('--failure-library', type=Path, required=True)
parser.add_argument('--pmd-root', type=Path, required=True)
parser.add_argument('--foreign-abi-library', type=Path, required=True)
parser.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
args = parser.parse_args()
cpu = min(os.sched_getaffinity(0))
environment = dict(os.environ)
modules = list(args.pmd_root.glob('dpdk/pmds-*/librte_net_tap.so'))
if not modules:
    print('SKIP: original TAP PMD is not installed')
    raise SystemExit(77)
environment['LD_PRELOAD'] = str(args.failure_library) + ':' + str(args.foreign_abi_library) + ':' + environment.get('LD_PRELOAD', '')
if not args.inside:
    command = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()),
        '--app', str(args.app.resolve()), '--failure-library', str(args.failure_library.resolve()),
        '--pmd-root', str(args.pmd_root.resolve()), '--foreign-abi-library',
        str(args.foreign_abi_library.resolve()), '--inside']
    raise SystemExit(subprocess.run(command, env=environment).returncode)

runtime = tempfile.TemporaryDirectory(prefix='ker-tap-retry-runtime-')
atexit.register(runtime.cleanup)
environment = private_runtime_environment(Path(runtime.name) / 'dpdk', environment)
raise SystemExit(subprocess.run([str(args.app), f'--lcores=0@{cpu}',
    '--no-huge', '--no-pci', '--no-shconf', '--no-telemetry', '--iova-mode=va', '-m', '96',
    '--vdev=net_tap0,iface=retrytap'], env=environment).returncode)
