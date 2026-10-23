#!/usr/bin/env python3
"""Isolate real TAP PMD ownership fault tests from host network configuration."""
import argparse
import os
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--app', type=Path, required=True)
parser.add_argument('--failure-library', type=Path, required=True)
parser.add_argument('--pmd-root', type=Path, required=True)
args = parser.parse_args()
cpu = min(os.sched_getaffinity(0))
environment = dict(os.environ)
modules = list(args.pmd_root.glob('dpdk/pmds-*/librte_net_tap.so'))
if not modules:
    print('SKIP: original TAP PMD is not installed')
    raise SystemExit(77)
environment['LD_PRELOAD'] = str(args.failure_library) + ':' + str(modules[0]) + ':' + environment.get('LD_PRELOAD', '')
raise SystemExit(subprocess.run(['unshare', '-Urn', str(args.app), f'--lcores=0@{cpu}',
    '--no-huge', '--no-pci', '--no-shconf', '--no-telemetry', '--iova-mode=va', '-m', '96',
    '--vdev=net_tap0,iface=retrytap'], env=environment).returncode)
