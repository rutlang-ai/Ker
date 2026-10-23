#!/usr/bin/env python3
"""Original null-PMD RSS control APIs; no hash math or packet landing substitute."""
import argparse
import os
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--probe', type=Path, required=True)
parser.add_argument('--failure-library', type=Path, required=True)
parser.add_argument('--pmd-root', type=Path, required=True)
args = parser.parse_args()
modules = list(args.pmd_root.glob('dpdk/pmds-*/librte_net_null.so'))
if not modules:
    print('SKIP: install the pinned DPDK net_null PMD for control-plane qualification')
    raise SystemExit(77)
env = dict(os.environ, LD_PRELOAD=str(modules[0]))
command = [str(args.probe), f'--lcores=0@{min(os.sched_getaffinity(0))}',
           '--no-huge', '--no-pci', '--no-shconf', '--no-telemetry', '--iova-mode=va',
           '-m', '32', '--vdev=net_null0,no-rx=1']
result = subprocess.run(command, env=env, timeout=20)
if result.returncode:
    raise SystemExit(result.returncode)
env['LD_PRELOAD'] = str(args.failure_library) + ':' + str(modules[0])
result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=20)
if result.returncode != 1 or 'INJECT: successful original RETA readback corrupted' not in result.stderr or 'PASS:' in result.stdout:
    raise RuntimeError('RSS accepted a mismatched original RETA readback: ' + result.stdout + result.stderr)
print('PASS: successful but mismatched original RETA readback is rejected')
