#!/usr/bin/env python3
"""Resident EAL session with optional original ring-PMD single-consumer qualification."""
import argparse
import errno
import json
import os
from pathlib import Path
import shlex
import selectors
import signal
import socket
import struct
import subprocess
import sys
import time

MAGIC = 0x4B45525345535331
VERSION = 5
FIELDS = ('magic', 'version', 'command', 'sequence', 'session', 'epoch',
          'generation', 'process', 'token', 'slot', 'status')
WIRE = struct.Struct('=10Qq')
MASTER, RESERVE, RELEASE, STATUS, ATTACHED, PROBE, PMD_ACQUIRE, PMD_STATUS, EPOCH_LIVE = range(1, 10)


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


def role_arguments(eal, role, ring_pmd=False, paired_pmd=False):
    values = shlex.split(eal)
    if '--' in values or any(v == '--proc-type' or v.startswith('--proc-type=') for v in values):
        raise ValueError('the session owns --proc-type; --eal must contain only shared EAL options')
    if any(v == '--vdev' or v.startswith('--vdev=') or v == '--allow' or
           v.startswith('--allow=') or v.startswith('-a') for v in values):
        raise ValueError('registration stage does not admit devices')
    if '--no-pci' not in values:
        values.append('--no-pci')
    device = ['--vdev=net_ring_ker_packet'] if paired_pmd and role == 'secondary' else (['--vdev=net_ring_ker'] if ring_pmd else [])
    return [*values, *device, '--proc-type=' + role]


def lease(args):
    ring_pmd = getattr(args, 'ring_pmd', False)
    connection = Connection(args.socket)
    worker = None
    read_fd = write_fd = control_read = control_write = -1
    ticket = None
    released = False
    shutdown_escalated = False
    termination_signal = 0
    previous_handlers = {}

    def remember_signal(number, _frame):
        nonlocal termination_signal
        if not termination_signal:
            termination_signal = number

    def close_fd(name):
        nonlocal read_fd, write_fd, control_read, control_write
        if name == 'read_fd':
            fd = read_fd; read_fd = -1
        elif name == 'write_fd':
            fd = write_fd; write_fd = -1
        elif name == 'control_read':
            fd = control_read; control_read = -1
        else:
            fd = control_write; control_write = -1
        if fd >= 0:
            os.close(fd)

    def release_master():
        deadline = time.monotonic() + 5
        while True:
            try:
                connection.request(RELEASE, session=ticket['session'], epoch=ticket['epoch'],
                    token=ticket['token'], slot=ticket['slot'])
                return
            except OSError as error:
                if error.errno != errno.EBUSY or time.monotonic() >= deadline:
                    raise
                time.sleep(0.05)

    cleanup_error = None
    try:
        for number in (signal.SIGINT, signal.SIGTERM):
            previous_handlers[number] = signal.signal(number, remember_signal)
        ticket = connection.request(MASTER)
        if not termination_signal:
            read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
            control_read, control_write = os.pipe2(os.O_CLOEXEC)
            os.set_blocking(control_write, False)
            control = control_read
            worker = subprocess.Popen([str(args.worker.resolve(strict=True)), '--role', 'secondary',
                '--socket', str(args.socket), '--control-fd', str(control), '--ticket-fd', str(read_fd),
                '--generation', str(args.generation), '--process', str(args.process),
                *(['--ring-pmd'] if ring_pmd else []),
                *(['--standby'] if getattr(args, 'standby', False) else []),
                '--probe-count', str(args.probe_count),
                *(['--probe-only'] if args.action == 'probe' else []), '--',
                *role_arguments(args.eal, 'secondary', ring_pmd)], stdin=subprocess.DEVNULL,
                pass_fds=(read_fd, control_read))
            close_fd('read_fd'); close_fd('control_read')
            data = encode(ticket)
            if os.write(write_fd, data) != len(data):
                raise RuntimeError('short ticket write')
            close_fd('write_fd')

            # DPDK callers may redirect stdin to regular files or /dev/null.
            # epoll rejects those descriptors with EPERM; poll supports them
            # while retaining the bounded wait used to observe signals.
            selector = selectors.PollSelector()
            stdin_fd = sys.stdin.fileno()
            input_open = True
            stdin_eof = False
            pending = bytearray()
            input_abandoned = False
            forwarded_signal = 0
            escalation = 0
            termination_deadline = None
            selector.register(stdin_fd, selectors.EVENT_READ, 'input')

            def close_child_control():
                if control_write >= 0:
                    try: selector.unregister(control_write)
                    except KeyError: pass
                    close_fd('control_write')

            def forward_signal(number):
                nonlocal input_open
                pending.clear()
                input_open = False
                try: selector.unregister(stdin_fd)
                except KeyError: pass
                close_child_control()

            if termination_signal:
                forwarded_signal = termination_signal
                termination_deadline = time.monotonic() + 5
                forward_signal(forwarded_signal)
            try:
                while worker.poll() is None:
                    if termination_signal and not forwarded_signal:
                        forwarded_signal = termination_signal
                        termination_deadline = time.monotonic() + 5
                        forward_signal(forwarded_signal)
                    if pending and control_write >= 0:
                        try:
                            selector.get_key(control_write)
                        except KeyError:
                            selector.register(control_write, selectors.EVENT_WRITE, 'control')
                        try: selector.unregister(stdin_fd)
                        except KeyError: pass
                    else:
                        try: selector.unregister(control_write)
                        except (KeyError, ValueError): pass
                        if input_open:
                            try:
                                selector.get_key(stdin_fd)
                            except KeyError:
                                selector.register(stdin_fd, selectors.EVENT_READ, 'input')
                    for key, _events in selector.select(0.05):
                        if key.data == 'input':
                            try:
                                data = os.read(stdin_fd, 4096)
                            except InterruptedError:
                                continue
                            if data:
                                pending.extend(data)
                            else:
                                input_open = False; stdin_eof = True
                                try: selector.unregister(stdin_fd)
                                except KeyError: pass
                        elif key.data == 'control' and pending and control_write >= 0:
                            try:
                                count = os.write(control_write, pending[:4096])
                                del pending[:count]
                            except BlockingIOError:
                                pass
                            except BrokenPipeError:
                                # The secondary may consume only a readiness
                                # command and exit without draining redirected
                                # stdin. Stop forwarding and preserve its real
                                # exit status instead of treating EPIPE as a
                                # supervisor failure.
                                pending.clear()
                                input_abandoned = True
                                input_open = False
                                try: selector.unregister(stdin_fd)
                                except KeyError: pass
                                close_child_control()
                    if stdin_eof and not pending and args.action != 'probe':
                        close_child_control()
                    if forwarded_signal and worker.poll() is None and time.monotonic() >= termination_deadline:
                        if escalation == 0:
                            worker.terminate()
                            escalation = 1
                            shutdown_escalated = True
                            termination_deadline = time.monotonic() + 5
                        else:
                            worker.kill()
                            escalation = 2
                            shutdown_escalated = True
                            try:
                                worker.wait(timeout=2)
                            except subprocess.TimeoutExpired as error:
                                raise RuntimeError('secondary could not be reaped after bounded SIGKILL') from error
                            break
            finally:
                selector.close()
            result = worker.wait()
        else:
            result = 0

        if termination_signal:
            print('KER_SESSION_SUPERVISOR_STOP ' + json.dumps(dict(signal=termination_signal,
                worker_status=result, escalated=shutdown_escalated)), flush=True)
        if worker is not None:
            print('KER_SESSION_CHILD_REAP ' + json.dumps(dict(pid=worker.pid,
                status=result, escalated=shutdown_escalated,
                input_abandoned=input_abandoned)), flush=True)
        if control_write >= 0:
            close_fd('control_write')
        if ticket is not None:
            release_master()
            released = True
        if shutdown_escalated:
            raise RuntimeError('secondary required signal escalation; session cleanup was not graceful')
        if termination_signal:
            if result != 0:
                raise RuntimeError('secondary exited unsuccessfully during graceful signal shutdown: ' + str(result))
            return 128 + termination_signal
        return result
    finally:
        try:
            for name in ('read_fd', 'write_fd', 'control_read', 'control_write'):
                try:
                    close_fd(name)
                except OSError as error:
                    if cleanup_error is None:
                        cleanup_error = error
            if worker is not None and worker.poll() is None:
                try:
                    worker.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    worker.terminate(); shutdown_escalated = True
                    try:
                        worker.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        worker.kill(); shutdown_escalated = True
                        try: worker.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            cleanup_error = RuntimeError('secondary could not be reaped')
            if ticket is not None and not released and (worker is None or worker.poll() is not None):
                try:
                    release_master()
                    released = True
                except BaseException as error:
                    cleanup_error = error
        finally:
            try:
                connection.close()
            finally:
                for number, handler in previous_handlers.items():
                    signal.signal(number, handler)
        if shutdown_escalated and cleanup_error is None:
            cleanup_error = RuntimeError('secondary required signal escalation; session cleanup was not graceful')
        if cleanup_error is not None:
            raise cleanup_error


def bounded_probe_count(value):
    try:
        count = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError('probe count must be an integer') from error
    if not 0 <= count <= 4096:
        raise argparse.ArgumentTypeError('probe count must be between 0 and 4096')
    return count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('serve', 'lease', 'status', 'probe', 'device-status', 'epoch-status', 'run'))
    parser.add_argument('--socket', type=Path, required=True)
    parser.add_argument('--worker', type=Path, default=Path(__file__).resolve().parent / 'ker-io-session')
    parser.add_argument('--eal', default='')
    parser.add_argument('--standby', action='store_true', help='keep a refused consumer attached; lease retries on P, run retries before application launch')
    parser.add_argument('--epoch', type=int, help='epoch to query with epoch-status; 0 names the resident')
    parser.add_argument('--generation', type=int, choices=range(2), default=0)
    parser.add_argument('--process', type=int, choices=range(4), default=0)
    devices = parser.add_mutually_exclusive_group()
    devices.add_argument('--paired-pmd', action='store_true', help='separate original ring-PMD RX/TX with an external Ethernet endpoint')
    devices.add_argument('--ring-pmd', action='store_true', help='qualify the original shared ring PMD with an exclusive secondary consumer')
    parser.add_argument('--probe-count', type=bounded_probe_count, default=0)
    parser.add_argument('--wire-fd', type=int)
    parser.add_argument('--library', type=Path)
    parser.add_argument('--address')
    parser.add_argument('--stats', type=Path)
    parser.add_argument('--address6')
    values = sys.argv[1:]
    separator = values.index('--') if '--' in values else len(values)
    command = values[separator + 1:]
    args = parser.parse_args(values[:separator])
    args.command = command
    if args.action == 'run':
        if not args.paired_pmd or args.wire_fd is None or args.library is None or not command:
            parser.error('run requires --paired-pmd --wire-fd --library and -- COMMAND')
    elif command or args.wire_fd is not None or args.library is not None or args.stats is not None or args.address is not None or args.address6 is not None:
        parser.error('packet endpoints, library and command are only valid with run')
    if args.paired_pmd and args.action not in ('serve', 'run'):
        parser.error('--paired-pmd is only supported by serve and run')
    if args.standby and not ((args.action == 'lease' and args.ring_pmd) or
                             (args.action == 'run' and args.paired_pmd)):
        parser.error('--standby requires lease --ring-pmd or run --paired-pmd')
    if args.action == 'epoch-status' and (args.epoch is None or not 0 <= args.epoch < 2**64):
        parser.error('epoch-status requires --epoch in 0..2^64-1')
    if args.action != 'epoch-status' and args.epoch is not None:
        parser.error('--epoch is only valid with epoch-status')
    args.socket = args.socket.absolute()
    try:
        if args.action == 'run':
            from ker_session_run import run_session
            try:
                return run_session(args, sys.modules[__name__])
            except RuntimeError as error:
                print('ker-session: ' + str(error), file=sys.stderr)
                return 125
            except KeyboardInterrupt:
                return 130
        if args.action == 'serve':
            args.socket.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            worker = str(args.worker.resolve(strict=True))
            os.execv(worker, [worker, '--role', 'primary', '--socket', str(args.socket),
                '--control-fd', str(sys.stdin.fileno()), *(['--ring-pmd'] if args.ring_pmd else []), *(['--paired-pmd'] if args.paired_pmd else []), '--', *role_arguments(args.eal, 'primary', args.ring_pmd, args.paired_pmd)])
        if args.action in ('lease', 'probe'):
            if args.action == 'probe' and not args.probe_count:
                args.probe_count = 1
            return lease(args)
        connection = Connection(args.socket)
        try:
            if args.action == 'epoch-status':
                reply = connection.request(EPOCH_LIVE, epoch=args.epoch)
                print(json.dumps(dict(session=reply['session'], epoch=reply['epoch'],
                    live=bool(reply['token']), slot=reply['slot'])))
                return 0
            if args.action == 'device-status':
                reply = connection.request(PMD_STATUS)
                print(json.dumps(dict(stage='ring-pmd', session=reply['session'], owner=reply['token'],
                    epoch=reply['epoch'], slot=reply['slot'], generation=reply['generation'], process=reply['process'])))
                return 0
            reply = connection.request(STATUS)
            print(json.dumps(dict(stage='shared-control', session=reply['session'],
                registered_epochs=reply['slot'], eal_processes=reply['process'],
                registered_eal_users=reply['process'], outstanding=reply['token'],
                pool_available=reply['generation'], next_epoch=reply['epoch'])))
        finally:
            connection.close()
        return 0
    except (OSError, RuntimeError, ValueError) as error:
        print('ker-session: ' + str(error), file=sys.stderr)
        return 125


if __name__ == '__main__':
    raise SystemExit(main())
