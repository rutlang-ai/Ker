"""Helpers for isolated DPDK runtime directories in integration fixtures."""
import os
from pathlib import Path


def private_runtime_environment(directory, environ=None):
    runtime = Path(directory).resolve()
    runtime.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = runtime.stat()
    if not runtime.is_dir() or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise RuntimeError('DPDK runtime directory must be private and owned by this user: ' + str(runtime))
    child_env = dict(os.environ if environ is None else environ)
    # DPDK uses RUNTIME_DIRECTORY before XDG_RUNTIME_DIR and otherwise
    # selects /var/run when getuid() is zero (including a mapped user namespace).
    child_env['RUNTIME_DIRECTORY'] = str(runtime)
    child_env['XDG_RUNTIME_DIR'] = str(runtime)
    return child_env
