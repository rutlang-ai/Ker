#!/usr/bin/env python3
"""Registration-only resident EAL session; does not execute applications or own a PMD."""
import argparse
import errno
import json
import os
from pathlib import Path
import shlex
import socket
import struct
import subprocess
import sys
import time

MAGIC = 0x4B45525345535331
VERSION = 1
FIELDS = ('magic', 'version', 'command', 'sequence', 'session', 'epoch',
          'generation', 'process', 'token', 'slot', 'status')
WIRE = struct.Struct('=10Qq')
MASTER, RESERVE, RELEASE, STATUS, ATTACHED = range(1, 6)


def packet(command, sequence=1, **values):
    result = dict.fromkeys(FIELDS, 0)
    result.update(magic=MAGIC, version=VERSION, command=command, sequence=sequence)
    result.update(values)
    return result


def encode(message):
    return WIRE.pack(*(message[name] for name in FIELDS))


class Connection:
    def __init__(self, path):
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.socket.settimeout(5)
        try:
            self.socket.connect(str(path))
        except BaseException:
            self.socket.close()
            raise
        self.sequence = 0

    def request(self, command, **values):
        self.sequence += 1
        request = packet(command, self.sequence, **values)
        self.socket.sendall(encode(request))
        data = self.socket.recv(WIRE.size + 1)
        if len(data) != WIRE.size:
            raise RuntimeError('session closed or returned a malformed frame')
        reply = dict(zip(FIELDS, WIRE.unpack(data)))
        if (reply['magic'] != MAGIC or reply['version'] != VERSION or
                reply['command'] != command or reply['sequence'] != self.sequence):
            raise RuntimeError('session reply identity mismatch')
        if reply['status']:
            raise OSError(-reply['status'], 'session request rejected')
        return reply

    def close(self):
        self.socket.close()


def role_arguments(eal, role):
    values = shlex.split(eal)
    if '--' in values or any(v == '--proc-type' or v.startswith('--proc-type=') for v in values):
        raise ValueError('the session owns --proc-type; --eal must contain only shared EAL options')
    if any(v == '--vdev' or v.startswith('--vdev=') or v == '--allow' or
           v.startswith('--allow=') or v.startswith('-a') for v in values):
        raise ValueError('registration stage does not admit devices')
    if '--no-pci' not in values:
        values.append('--no-pci')
    return [*values, '--proc-type=' + role]


def lease(args):
    connection = Connection(args.socket)
    worker = None
    read_fd = write_fd = -1
    try:
        ticket = connection.request(MASTER)
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
        control = sys.stdin.fileno()
        worker = subprocess.Popen([str(args.worker.resolve(strict=True)), '--role', 'secondary',
            '--socket', str(args.socket), '--control-fd', str(control), '--ticket-fd', str(read_fd),
            '--generation', str(args.generation), '--process', str(args.process), '--',
            *role_arguments(args.eal, 'secondary')], pass_fds=(read_fd, control))
        os.close(read_fd); read_fd = -1
        data = encode(ticket)
        if os.write(write_fd, data) != len(data):
            raise RuntimeError('short ticket write')
        os.close(write_fd); write_fd = -1
        result = worker.wait()
        # A child has completed EAL cleanup, but the resident pidfd census may
        # need its next poll. Only EBUSY is retried, with a new operation id.
        deadline = time.monotonic() + 5
        while True:
            try:
                connection.request(RELEASE, session=ticket['session'], epoch=ticket['epoch'],
                    token=ticket['token'], slot=ticket['slot'])
                break
            except OSError as error:
                if error.errno != errno.EBUSY or time.monotonic() >= deadline:
                    raise
                time.sleep(0.05)
        return result
    finally:
        for fd in (read_fd, write_fd):
            if fd >= 0:
                os.close(fd)
        if worker is not None and worker.poll() is None:
            worker.terminate()
            try:
                worker.wait(timeout=5)
            except subprocess.TimeoutExpired:
                worker.kill(); worker.wait()
        connection.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('serve', 'lease', 'status'))
    parser.add_argument('--socket', type=Path, required=True)
    parser.add_argument('--worker', type=Path, default=Path(__file__).resolve().parent / 'ker-io-session')
    parser.add_argument('--eal', default='')
    parser.add_argument('--generation', type=int, choices=range(2), default=0)
    parser.add_argument('--process', type=int, choices=range(4), default=0)
    args = parser.parse_args()
    args.socket = args.socket.absolute()
    try:
        if args.action == 'serve':
            args.socket.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            worker = str(args.worker.resolve(strict=True))
            os.execv(worker, [worker, '--role', 'primary', '--socket', str(args.socket),
                '--control-fd', str(sys.stdin.fileno()), '--', *role_arguments(args.eal, 'primary')])
        if args.action == 'lease':
            return lease(args)
        connection = Connection(args.socket)
        try:
            reply = connection.request(STATUS)
            print(json.dumps(dict(stage='registration-only', session=reply['session'],
                registered_epochs=reply['slot'], eal_processes=reply['process'],
                next_epoch=reply['epoch'])))
        finally:
            connection.close()
        return 0
    except (OSError, RuntimeError, ValueError) as error:
        print('ker-session: ' + str(error), file=sys.stderr)
        return 125


if __name__ == '__main__':
    raise SystemExit(main())
