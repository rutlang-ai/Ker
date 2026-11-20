"""Exercise the legacy pool/cache policy through the original software PMD."""
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

with TemporaryDirectory(prefix='ker-pool-legacy-') as directory:
    nonce = os.urandom(5).hex()
    environment = dict(os.environ, KER_POOL_NONCE=nonce, RUNTIME_DIRECTORY=directory)
    cpu = min(os.sched_getaffinity(0))
    app = Path(sys.argv[1]).resolve()
    result = subprocess.run([str(app), 'legacy', f'--lcores=0@{cpu}', '--proc-type=primary',
                             '--no-huge', '--no-shconf', '--no-pci', '--no-telemetry',
                             '--iova-mode=va', '--file-prefix=ker-pool-' + nonce, '-m', '64'],
                            env=environment, text=True, capture_output=True, timeout=20)
    print(result.stdout, end='')
    if result.returncode or 'CLOSED {"packets":4,"outstanding":0}' not in result.stdout.splitlines() or (
            'CACHES {"legacy":[256,16,256],"used_and_flushed":true}' not in result.stdout.splitlines()):
        raise RuntimeError(result.stdout + result.stderr)
