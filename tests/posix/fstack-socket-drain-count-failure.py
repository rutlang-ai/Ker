#!/usr/bin/env python3
import argparse
import errno
import os
import resource
import signal
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--client', required=True)
    args = parser.parse_args()

    environment = dict(os.environ)
    environment.pop('KER_SOCKET_BROKER_PATH', None)

    def disable_core_dumps():
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    try:
        result = subprocess.run([args.client, '--failure-census'], env=environment,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
            preexec_fn=disable_core_dumps, check=False)
    except subprocess.TimeoutExpired as error:
        raise SystemExit(f'census failure path did not terminate: {error}')

    diagnostic = result.stderr.decode('utf-8', errors='replace')
    if result.returncode != -signal.SIGABRT:
        raise SystemExit(f'census did not fail closed with SIGABRT: '
            f'returncode={result.returncode}; stderr={diagnostic!r}')
    if f'ker fstack socket census failed: errno={errno.ENOTCONN}' not in diagnostic:
        raise SystemExit(f'census failure diagnostic/ENOTCONN missing: {diagnostic!r}')
    print('PASS: missing broker returns ENOTCONN internally and aborts the FF hook')


if __name__ == '__main__':
    main()
