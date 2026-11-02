#!/usr/bin/env python3
"""Check the private launcher/helper modules work from a generated sibling bundle."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--launcher', type=Path, required=True)
    parser.add_argument('--companion', type=Path, required=True)
    parser.add_argument('--tools', type=Path, required=True)
    args = parser.parse_args()
    for name in ('rx_decision_wire.py', 'runtime_service.py',
                 'runtime_service_wire.py',
                 'broker_readiness_supervisor.py', 'broker_readiness_wire.py',
                 'ker_run_control.py', 'ker_run_control_wire.py',
                 'nginx_companion_supervisor.py', 'nginx_companion_wire.py'):
        if not (args.tools / name).is_file():
            raise RuntimeError(f'generated sibling module is missing: {name}')
    env = dict(os.environ)
    env.pop('PYTHONPATH', None)
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    with tempfile.TemporaryDirectory(prefix='ker-nginx-companion-bundle-') as cwd:
        launcher = subprocess.run([os.sys.executable, str(args.launcher), '--help'],
            cwd=cwd, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
        if launcher.returncode or 'Run a POSIX application' not in launcher.stdout:
            raise RuntimeError(f'generated ker-run bundle failed: {launcher.stderr}')
        companion = subprocess.run([os.sys.executable, str(args.companion), '--help'],
            cwd=cwd, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
        if companion.returncode or '--control-fd' not in companion.stdout:
            raise RuntimeError(f'generated companion bundle failed: {companion.stderr}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
