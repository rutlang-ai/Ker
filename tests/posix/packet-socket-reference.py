#!/usr/bin/env python3
"""Run the packet-socket host reference with private namespace capabilities."""
import argparse
import os
from pathlib import Path
import subprocess
import sys

parser = argparse.ArgumentParser()
parser.add_argument('--app', type=Path, required=True)
parser.add_argument('--inside', action='store_true')
args = parser.parse_args()
if not args.inside:
    command = ['unshare', '--user', '--map-root-user', '--net', sys.executable,
               str(Path(__file__).resolve()), '--inside', '--app', str(args.app.resolve())]
else:
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    command = [str(args.app.resolve())]
result = subprocess.run(command, env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
sys.exit(result.returncode)
