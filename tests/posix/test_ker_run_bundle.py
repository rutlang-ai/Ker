"""Exercise the actual generated or installed ker-run bundle in isolation."""
import argparse
from pathlib import Path
import subprocess
import sys
import tempfile


def run_launcher(launcher):
    launcher = Path(launcher).resolve(strict=True)
    siblings = ('rx_decision_wire.py', 'runtime_service.py',
        'runtime_service_wire.py')
    for name in siblings:
        if not launcher.with_name(name).is_file():
            raise AssertionError(f'ker-run sibling module is missing: {launcher.with_name(name)}')
    with tempfile.TemporaryDirectory(prefix='ker-run-bundle-cwd-') as cwd:
        result = subprocess.run([sys.executable, '-I', str(launcher), '--help'],
            cwd=cwd, text=True, capture_output=True, timeout=5)
    if result.returncode != 0:
        raise AssertionError(f'isolated ker-run --help failed: {result.stderr}')
    if 'usage:' not in result.stdout:
        raise AssertionError(f'isolated ker-run did not print help: {result.stdout!r}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--launcher', required=True)
    run_launcher(parser.parse_args().launcher)
