#!/usr/bin/env python3
"""Run the real original PMD caller without shared-hugepage requirements."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--app', type=Path, required=True)
parser.add_argument('--pmd-root', type=Path, required=True)
parser.add_argument('--evidence', type=Path)
args = parser.parse_args()
with tempfile.TemporaryDirectory(prefix='ker-dispatch-') as directory:
    environment = dict(os.environ, RUNTIME_DIRECTORY=directory,
        LD_LIBRARY_PATH=str(args.pmd_root.resolve()) + ':' + os.environ.get('LD_LIBRARY_PATH', ''))
    cpu = min(os.sched_getaffinity(0))
    command = [str(args.app.resolve()), '--proc-type=primary', f'--lcores=0@{cpu}',
               '--no-huge', '--no-pci', '--no-shconf', '--no-telemetry', '--iova-mode=va',
               '--file-prefix=dispatch-' + secrets.token_hex(8), '-m', '64']
    result = subprocess.run(command, env=environment, text=True, capture_output=True, timeout=30)
    expected = 'PASS: original PMD RX12/TX9, caller drop2/peer1, plain2/context7/replacement5, VLAN/length/default/precedence/unregister, pool127/127'
    if result.returncode or expected not in result.stdout.splitlines():
        raise RuntimeError('original PMD callback caller failed: ' + result.stdout + result.stderr)
    if args.evidence:
        with args.evidence.open('x') as output:
            json.dump({'status': 'passed', 'returncode': result.returncode, 'command': command,
                       'stdout': result.stdout, 'stderr': result.stderr,
                       'app_sha256': hashlib.sha256(args.app.read_bytes()).hexdigest(),
                       'harness_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}, output, indent=2)
            output.write('\n')
    print(expected)
