#!/usr/bin/env python3
"""Run a POSIX application against imported Linux, with DPDK Ethernet I/O."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import selectors
import shlex
import signal
import socket
import subprocess
import sys
import time


class Interrupted(Exception):
    def __init__(self, signum):
        self.signum = signum


def interrupted(signum, _frame):
    raise Interrupted(signum)


# CMake substitutes the relative library path for the installed launcher.
LIB_FROM_BIN = '@KER_POSIX_LIB_FROM_BIN@'
if LIB_FROM_BIN.startswith('@'):
    LIB_FROM_BIN = '../lib64'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--address', required=True, type=ipaddress.IPv4Interface)
    parser.add_argument('--gateway', type=ipaddress.IPv4Address)
    parser.add_argument('--port', required=True, help='DPDK ethdev name')
    parser.add_argument('--eal', required=True, help='DPDK EAL arguments, parsed without a shell')
    parser.add_argument('--library', type=Path, default=Path(__file__).resolve().parent / LIB_FROM_BIN / 'libker-posix.so')
    parser.add_argument('--io-worker', type=Path, default=Path(__file__).resolve().parent / 'ker-io-worker')
    parser.add_argument('--shutdown-timeout-ms', type=int, default=5000)
    parser.add_argument('--stats', type=Path, help='write Ethernet I/O counters at shutdown')
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command[:1] == ['--']:
        args.command.pop(0)
    if not args.command:
        parser.error('an application command is required after --')
    if not 0 <= args.shutdown_timeout_ms <= 60000:
        parser.error("--shutdown-timeout-ms must be in 0..60000")
    library = args.library.resolve(strict=True)
    worker_path = args.io_worker.resolve(strict=True)
    channel_app, channel_io = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM | socket.SOCK_NONBLOCK)
    control_read, control_write = os.pipe2(os.O_CLOEXEC)
    startup_read, startup_write = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
    signal.signal(signal.SIGTERM, interrupted)
    worker = app = None
    exit_code = 125
    stats = None
    startup_status = b""
    try:
        worker = subprocess.Popen([str(worker_path), '--packet-fd', str(channel_io.fileno()),
            '--control-fd', str(control_read), '--port', args.port, '--', *shlex.split(args.eal)],
            pass_fds=(channel_io.fileno(), control_read), stdout=subprocess.PIPE, text=True)
        channel_io.close()
        os.close(control_read)
        control_read = -1
        with selectors.DefaultSelector() as selector:
            selector.register(worker.stdout, selectors.EVENT_READ)
            if not selector.select(20):
                raise RuntimeError('DPDK worker startup timed out')
            ready = worker.stdout.readline().strip()
        if not ready.startswith('KER_IO_READY '):
            raise RuntimeError('DPDK worker failed before packet I/O became ready: ' + ready)
        info = json.loads(ready.removeprefix('KER_IO_READY '))
        env = {key: value for key, value in os.environ.items() if not key.startswith(('LKL_', 'KER_PACKET_'))}
        env.update(KER_PRELOAD_LIBRARY=(env.pop('LD_PRELOAD') + ':' if env.get('LD_PRELOAD') else '') + str(library),
            KER_STARTUP_FD=str(startup_write), KER_SHUTDOWN_TIMEOUT_MS=str(args.shutdown_timeout_ms),
            KER_PACKET_FD=str(channel_app.fileno()), LKL_HIJACK_NET_IFTYPE='ker-channel',
            LKL_HIJACK_NET_IP=str(args.address.ip), LKL_HIJACK_NET_NETMASK_LEN=str(args.address.network.prefixlen),
            LKL_HIJACK_NET_MAC=info['mac'], LKL_HIJACK_OFFLOAD='0')
        if args.gateway:
            env['LKL_HIJACK_NET_GATEWAY'] = str(args.gateway)
        app_guard = worker_path.parent / 'ker-app'
        app = subprocess.Popen([str(app_guard), *args.command], env=env,
            pass_fds=(channel_app.fileno(), startup_write))
        channel_app.close()
        os.close(startup_write)
        startup_write = -1
        with selectors.DefaultSelector() as selector:
            selector.register(startup_read, selectors.EVENT_READ)
            if selector.select(20):
                startup_status = os.read(startup_read, 128)
            if not startup_status.startswith(b'KER_NATIVE_READY\n'):
                raise RuntimeError('application did not initialize the native Linux backend')
        stopping_at = None
        while True:
            try:
                exit_code = app.wait(timeout=0.25)
                break
            except subprocess.TimeoutExpired:
                try:
                    startup_status += os.read(startup_read, 4096)
                except BlockingIOError:
                    pass
                if b'KER_NATIVE_STOPPING\n' in startup_status:
                    if stopping_at is None:
                        stopping_at = time.monotonic()
                    if time.monotonic() - stopping_at > 5:
                        raise RuntimeError('native kernel teardown timed out')
                elif worker.poll() is not None:
                    raise RuntimeError('DPDK worker stopped while the application was running')
    except (KeyboardInterrupt, Interrupted) as interruption:
        signum = interruption.signum if isinstance(interruption, Interrupted) else signal.SIGINT
        exit_code = 128 + signum
        if app and app.poll() is None:
            app.send_signal(signum)
            try:
                app.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
    except (OSError, ValueError, RuntimeError) as error:
        print(f'ker-run: {error}', file=sys.stderr)
    finally:
        if app and app.poll() is None:
            app.terminate()
            try:
                app.wait(timeout=5)
            except subprocess.TimeoutExpired:
                app.kill()
                app.wait()
        channel_app.close()
        channel_io.close()
        if control_read >= 0:
            os.close(control_read)
        os.close(control_write)
        while True:
            try:
                extra = os.read(startup_read, 1024)
                if not extra:
                    break
                startup_status += extra
            except BlockingIOError:
                break
        os.close(startup_read)
        if app and exit_code == 0 and b'KER_NATIVE_DONE\n' not in startup_status:
            print('ker-run: native Linux shutdown did not complete', file=sys.stderr)
            exit_code = 125
        if startup_write >= 0:
            os.close(startup_write)
        if worker:
            try:
                output, _ = worker.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                worker.kill()
                output, _ = worker.communicate()
                print('ker-run: DPDK worker shutdown timed out', file=sys.stderr)
                exit_code = 125
            for line in output.splitlines():
                if line.startswith('KER_IO_DONE '):
                    stats = json.loads(line.removeprefix('KER_IO_DONE '))
            if worker.returncode and exit_code == 0:
                exit_code = 125
            if stats is not None:
                for line in startup_status.splitlines():
                    if line.startswith(b'KER_NATIVE_STATS '):
                        stats['native'] = json.loads(line.removeprefix(b'KER_NATIVE_STATS '))
            if args.stats and stats:
                args.stats.write_text(json.dumps(stats, indent=2) + '\n')
    return exit_code if exit_code >= 0 else 128 - exit_code


if __name__ == '__main__':
    sys.exit(main())
