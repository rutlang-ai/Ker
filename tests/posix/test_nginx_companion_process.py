#!/usr/bin/env python3
"""Test helper ownership/protocol using a tiny non-networking process fixture."""
import argparse
import array
import importlib.util
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time


def require(value, message):
    if not value:
        raise RuntimeError(message)


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f'cannot load {path}')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def wait_dead(pidfd, timeout):
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    return bool(poller.poll(int(timeout * 1000)))


def close_manager(manager):
    if manager.channel is not None:
        manager.channel.close()
        manager.channel = None
    for attribute in ('master_pidfd', 'supervisor_pidfd'):
        fd = getattr(manager, attribute)
        if fd >= 0:
            os.close(fd)
            setattr(manager, attribute, -1)


def cleanup_manager(manager):
    if manager is None:
        return
    if manager.settled:
        close_manager(manager)
        return
    if manager.channel is not None:
        manager.channel.close()
        manager.channel = None
    if manager.helper is not None and manager.helper.poll() is None:
        try:
            manager.helper.wait(timeout=12)
        except subprocess.TimeoutExpired:
            if manager.master_pidfd >= 0:
                try:
                    signal.pidfd_send_signal(manager.master_pidfd, signal.SIGQUIT)
                except OSError:
                    pass
            try:
                manager.helper.wait(timeout=3)
            except subprocess.TimeoutExpired:
                manager.helper.kill()
                manager.helper.wait(timeout=3)
    if manager.master_pidfd >= 0:
        try:
            signal.pidfd_send_signal(manager.master_pidfd, signal.SIGQUIT)
        except OSError:
            pass
    close_manager(manager)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', type=Path, required=True)
    parser.add_argument('--tools', type=Path, required=True)
    parser.add_argument('--helper', type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.tools))
    supervisor = load_module(args.tools / 'nginx_companion_supervisor.py',
        '_test_nginx_companion_supervisor')
    wire = load_module(args.tools / 'nginx_companion_wire.py',
        '_test_nginx_companion_wire')
    with tempfile.TemporaryDirectory(prefix='ker-nginx-companion-test-') as directory:
        root = Path(directory)
        prefix = root / 'prefix'
        prefix.mkdir()
        config = root / 'nginx.conf'
        config.write_text('daemon off;\nmaster_process on;\nworker_processes 1;\n',
            encoding='utf-8')
        ini = root / 'fstack.ini'
        broker_path = root / 'socket-broker.sock'
        ini.write_text(f'[ker_socket_broker]\nversion=1\npath={broker_path}\n'
            '[dpdk]\ngraceful_reload=0\n', encoding='utf-8')
        environment = {
            'LD_PRELOAD': 'libc.so.6',
            'KER_SOCKET_BROKER_PATH': str(broker_path),
            'KER_FSTACK_NGINX_INI': str(ini),
        }
        good = None
        try:
            good = supervisor.NginxCompanion(args.server, config, prefix, environment)
            good.helper_path = args.helper.resolve(strict=True)
            good.helper_script_hash = supervisor._sha256(good.helper_path)
            good.start(timeout=5)
            good.check()
            good.reload(timeout=5)
            good.reload(timeout=5)
            good.stop(timeout=5)
            require(good.started and good.settled and not good.unresolved,
                'valid START, consecutive RELOAD, STOP did not settle exactly')
        finally:
            cleanup_manager(good)

        malformed = None
        master_pidfd = -1
        try:
            malformed = supervisor.NginxCompanion(args.server, config, prefix, environment)
            malformed.helper_path = args.helper.resolve(strict=True)
            malformed.helper_script_hash = supervisor._sha256(malformed.helper_path)
            malformed.start(timeout=5)
            master_pidfd = os.dup(malformed.master_pidfd)
            fd = os.open('/dev/null', os.O_RDONLY | os.O_CLOEXEC)
            try:
                packet = wire.pack_record(wire.RELOAD, b'', malformed.nonce,
                    malformed.epoch, malformed.sequence)
                sent = malformed.channel.sendmsg([packet], [(socket.SOL_SOCKET,
                    socket.SCM_RIGHTS, array.array('i', (fd,)))],
                    getattr(socket, 'MSG_NOSIGNAL', 0))
                require(sent == len(packet), 'short malformed control injection')
            finally:
                os.close(fd)
            rejected = False
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                try:
                    malformed.check()
                except (OSError, RuntimeError, ValueError):
                    rejected = True
                    break
                time.sleep(0.01)
            require(rejected and malformed.unresolved,
                'unexpected SCM_RIGHTS did not fail closed after STARTED')
            require(wait_dead(master_pidfd, 5),
                'helper did not settle pinned child after malformed post-STARTED record')
            malformed.helper.wait(timeout=5)
            require(malformed.helper.returncode != 0,
                'helper treated malformed post-STARTED command as healthy')
        finally:
            if master_pidfd >= 0:
                os.close(master_pidfd)
            cleanup_manager(malformed)
    print('C34 helper control ownership fixture: PASS')
    return 0


if __name__ == '__main__':
    sys.exit(main())
