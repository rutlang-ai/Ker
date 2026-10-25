#!/usr/bin/env python3
"""Exercise the bounded startup gate used by the fault-injection client."""
import argparse
import errno
import os
from pathlib import Path
import subprocess
import tempfile
import time


def start(app, fifo):
    return subprocess.Popen([app, 'fault-gate-check', '127.0.0.1', '1', str(fifo), '100'],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def ready(process):
    line = process.stdout.readline().strip()
    if line != 'READY 1':
        raise RuntimeError(f'fault gate did not become ready: {line!r}')


def write_fifo(fifo, data):
    deadline = time.monotonic() + 2
    while True:
        try:
            fd = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
            break
        except OSError as error:
            if error.errno != errno.ENXIO or time.monotonic() >= deadline:
                raise
            time.sleep(0.005)
    try:
        if data:
            if os.write(fd, data) != len(data):
                raise RuntimeError('short test-token write')
    finally:
        os.close(fd)


def run_case(app, directory, name, *, token=None, create_fifo=True, expected=1):
    fifo = Path(directory) / (name + '.fifo')
    if create_fifo:
        os.mkfifo(fifo)
    process = start(app, fifo)
    try:
        ready(process)
        if token is not None:
            write_fifo(fifo, token)
        output, error = process.communicate(timeout=2)
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()
    if process.returncode != expected:
        raise RuntimeError(f'{name}: expected exit {expected}, got {process.returncode}: {error}')
    return output, error


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--app', required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='ker-tcp-fault-gate-') as directory:
        output, _ = run_case(args.app, directory, 'valid', token=b'\xa5', expected=0)
        if 'PASS: bounded TCP fault gate' not in output:
            raise RuntimeError('valid gate token did not pass')

        _, error = run_case(args.app, directory, 'bad-token', token=b'\x01')
        if 'token == 0xa5' not in error:
            raise RuntimeError('invalid gate token was not rejected')

        _, error = run_case(args.app, directory, 'eof', token=b'')
        if 'timeout > 0' not in error and 'result > 0' not in error:
            raise RuntimeError('empty FIFO close did not time out')

        _, error = run_case(args.app, directory, 'missing', create_fifo=False)
        if 'fd >= 0' not in error:
            raise RuntimeError('missing FIFO was not rejected')

        _, error = run_case(args.app, directory, 'timeout')
        if 'timeout > 0' not in error and 'result > 0' not in error:
            raise RuntimeError('no-writer FIFO did not time out')

    print('PASS: bounded TCP fault gate token, EOF, missing-path and timeout cases')


if __name__ == '__main__':
    main()
