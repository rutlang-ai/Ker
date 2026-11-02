#!/usr/bin/env python3
"""Test helper ownership/protocol using a tiny non-networking process fixture."""
import argparse
import array
import ctypes
import importlib.machinery
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


def wait_marker_count(path, expected, timeout=2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists() and path.read_bytes().count(b'HUP\n') >= expected:
            return path.read_bytes().count(b'HUP\n')
        time.sleep(0.01)
    return path.read_bytes().count(b'HUP\n') if path.exists() else 0


def wait_handler_ready(path, timeout=2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.01)
    raise RuntimeError('test server did not publish its installed signal handlers')


def load_module(path, name):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
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


def new_manager(supervisor, server, helper_path, config, prefix, environment):
    (prefix / 'hup-observed').unlink(missing_ok=True)
    manager = supervisor.NginxCompanion(server, config, prefix, environment)
    manager.helper_path = helper_path
    manager.helper_script_hash = supervisor._sha256(helper_path)
    manager.start(timeout=5)
    wait_handler_ready(prefix / 'hup-observed')
    return manager


def exercise_profile_mutation(supervisor, server, helper_path, config, prefix,
                              environment, ini, mutate, label):
    marker = prefix / 'hup-observed'
    marker.unlink(missing_ok=True)
    manager = new_manager(supervisor, server, helper_path, config, prefix,
        environment)
    try:
        wait_handler_ready(marker)
        require(marker.read_bytes() == b'',
            f'{label} fixture began with unexpected HUP markers')
        mutate(config, ini)
        denied = False
        try:
            manager.reload(timeout=5)
        except (OSError, RuntimeError, ValueError, PermissionError):
            denied = True
        require(denied and manager.unresolved and not manager.settled,
            f'{label} mutation was not rejected as an unresolved profile change')
        require(not marker.exists() or marker.read_bytes() == b'',
            f'{label} profile mutation delivered SIGHUP before denial')
        manager.helper.wait(timeout=5)
        require(manager.helper.returncode != 0,
            f'{label} profile mutation did not fail closed')
        require(wait_dead(manager.master_pidfd, 0.1),
            f'{label} profile rejection did not stop the pinned master')
    finally:
        cleanup_manager(manager)


def signal_and_reap_master(manager, master_pidfd):
    try:
        signal.pidfd_send_signal(master_pidfd, signal.SIGQUIT)
    except ProcessLookupError:
        pass
    require(wait_dead(master_pidfd, 5), 'external recovery did not stop pinned master')
    try:
        os.waitpid(manager.master_pid, 0)
    except ChildProcessError:
        pass


def inject_bad_record(manager, wire, kind):
    if kind == 'eof':
        manager.channel.shutdown(socket.SHUT_WR)
        return
    fd = os.open('/dev/null', os.O_RDONLY | os.O_CLOEXEC)
    try:
        body = b'' if kind == 'rights' else b'x' * 5000
        packet = wire.pack_record(wire.RELOAD, body, manager.nonce,
            manager.epoch, manager.sequence)
        ancillary = ([(socket.SOL_SOCKET, socket.SCM_RIGHTS,
            array.array('i', (fd,)))] if kind == 'rights' else [])
        sent = manager.channel.sendmsg([packet], ancillary,
            getattr(socket, 'MSG_NOSIGNAL', 0))
        require(sent == len(packet), f'short malformed {kind} control injection')
    finally:
        os.close(fd)


def exercise_bad_receive(supervisor, wire, server, helper_path, config, prefix,
                         environment, kind):
    manager = new_manager(supervisor, server, helper_path, config, prefix,
        environment)
    master_pidfd = os.dup(manager.master_pidfd)
    try:
        inject_bad_record(manager, wire, kind)
        deadline = time.monotonic() + 5
        failure_seen = False
        while time.monotonic() < deadline:
            try:
                manager.check()
            except (OSError, RuntimeError, ValueError):
                failure_seen = True
                break
            time.sleep(0.01)
        require(failure_seen and manager.unresolved,
            f'{kind} receive failure did not mark containment unresolved')
        require(wait_dead(master_pidfd, 0.1),
            f'{kind} failure was reported before the owned child settled')
        manager.helper.wait(timeout=5)
        require(manager.helper.returncode != 0,
            f'{kind} receive failure returned a healthy helper status')
        require(not manager.settled,
            f'{kind} receive failure fabricated a SETTLED result')
    finally:
        os.close(master_pidfd)
        cleanup_manager(manager)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', type=Path, required=True)
    parser.add_argument('--tools', type=Path, required=True)
    parser.add_argument('--helper', type=Path, required=True)
    args = parser.parse_args()
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), 'test subreaper setup failed')
    sys.path.insert(0, str(args.tools))
    supervisor = load_module(args.tools / 'nginx_companion_supervisor.py',
        '_test_nginx_companion_supervisor')
    wire = load_module(args.tools / 'nginx_companion_wire.py',
        '_test_nginx_companion_wire')
    helper_module = load_module(args.helper,
        '_test_ker_nginx_companion')
    valid_profiles = (
        b'daemon off; master_process on; worker_processes 1; # include ignored\n',
        b'daemon off; master_process on; worker_processes 1; events { worker_connections 4; }\n',
        b'daemon off; master_process on; worker_processes 1; set $name "include";\n',
        b'daemon off; master_process on; worker_processes 1; set $name include;\n',
    )
    for profile_bytes in valid_profiles:
        helper_module.validate_control_nginx_config(profile_bytes)
    for profile_bytes in (
            b'daemon off; master_process on; worker_processes 1;\ninclude\t/escape.conf;\n',
            b'daemon off; master_process on; worker_processes 1; include /escape.conf;\n',
            b'daemon off; master_process on; worker_processes 1; "include" "/escape.conf";\n',
            b'daemon off; master_process on; worker_processes 1; "include" "/escape\\t.conf";\n'):
        try:
            helper_module.validate_control_nginx_config(profile_bytes)
        except ValueError as exc:
            require('include' in str(exc), 'include rejection did not identify unsupported directive')
        else:
            raise RuntimeError('Nginx include syntax escaped the bounded profile validator')
    try:
        helper_module.validate_control_nginx_config(
            b'daemon off; master_process on; worker_processes 1;\n' +
            b'#' + b'x' * helper_module.MAX_CONFIG_BYTES)
    except ValueError as exc:
        require('bounded profile size' in str(exc), 'oversize profile rejection was not bounded')
    else:
        raise RuntimeError('oversize Nginx profile escaped the bounded validator')
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
        helper_path = args.helper.resolve(strict=True)
        config_text = 'daemon off;\nmaster_process on;\nworker_processes 1;\n'
        ini_text = (f'[ker_socket_broker]\nversion=1\npath={broker_path}\n'
            '[dpdk]\ngraceful_reload=0\n')
        good = None
        try:
            good = new_manager(supervisor, args.server, helper_path, config,
                prefix, environment)
            good.check()
            wait_handler_ready(prefix / 'hup-observed')
            require((prefix / 'hup-observed').read_bytes() == b'',
                'test server received HUP before healthy reload began')
            good.reload(timeout=5)
            require(wait_marker_count(prefix / 'hup-observed', 1) == 1,
                'first healthy reload did not deliver exactly one SIGHUP')
            good.reload(timeout=5)
            require(wait_marker_count(prefix / 'hup-observed', 2) == 2,
                'second healthy reload did not deliver exactly two SIGHUP signals')
            good.stop(timeout=5)
            require(good.started and good.settled and not good.unresolved,
                'valid START, consecutive RELOAD, STOP did not settle exactly')
        finally:
            cleanup_manager(good)

        def change_worker_count(changed_config, _changed_ini):
            changed_config.write_text(
                'daemon off;\nmaster_process on;\nworker_processes 2;\n',
                encoding='utf-8')

        exercise_profile_mutation(supervisor, args.server, helper_path, config,
            prefix, environment, ini, change_worker_count, 'worker_processes=2')
        config.write_text(config_text, encoding='utf-8')
        (prefix / 'hup-observed').unlink(missing_ok=True)

        def change_graceful_reload(_changed_config, changed_ini):
            changed_ini.write_text(ini_text.replace('graceful_reload=0',
                'graceful_reload=1'), encoding='utf-8')

        exercise_profile_mutation(supervisor, args.server, helper_path, config,
            prefix, environment, ini, change_graceful_reload, 'graceful_reload=1')
        config.write_text(config_text, encoding='utf-8')
        ini.write_text(ini_text, encoding='utf-8')
        (prefix / 'hup-observed').unlink(missing_ok=True)

        for label, include_config in (
                ('tab include', config_text + 'include\t/escape.conf;\n'),
                ('inline include', config_text.rstrip() + ' include /escape.conf;\n'),
                ('quoted include', config_text + '"include" "/escape.conf";\n')):
            def add_include(changed_config, _changed_ini, text=include_config):
                changed_config.write_text(text, encoding='utf-8')
            exercise_profile_mutation(supervisor, args.server, helper_path,
                config, prefix, environment, ini, add_include, label)
            config.write_text(config_text, encoding='utf-8')
            (prefix / 'hup-observed').unlink(missing_ok=True)

        for label, include_config in (
                ('startup tab include', config_text + 'include\t/escape.conf;\n'),
                ('startup inline include', config_text.rstrip() + ' include /escape.conf;\n'),
                ('startup quoted include', config_text + '"include" "/escape.conf";\n')):
            config.write_text(include_config, encoding='utf-8')
            startup = supervisor.NginxCompanion(args.server, config, prefix, environment)
            startup.helper_path = helper_path
            startup.helper_script_hash = supervisor._sha256(helper_path)
            failed = False
            try:
                startup.start(timeout=5)
            except (OSError, RuntimeError, ValueError, PermissionError):
                failed = True
            require(failed and startup.unresolved,
                f'{label} was not rejected during helper startup')
            require(not (prefix / 'hup-observed').exists() or
                (prefix / 'hup-observed').read_bytes() == b'',
                f'{label} delivered a signal before startup rejection')
            if startup.helper is not None:
                startup.helper.wait(timeout=5)
                require(startup.helper.returncode != 0,
                    f'{label} did not fail closed in the helper')
            close_manager(startup)
        config.write_text(config_text, encoding='utf-8')
        (prefix / 'hup-observed').unlink(missing_ok=True)

        crashed = new_manager(supervisor, args.server, helper_path, config,
            prefix, environment)
        master_pidfd = os.dup(crashed.master_pidfd)
        try:
            helper_fd = crashed.channel.fileno()
            master_fd = crashed.master_pidfd
            supervisor_fd = crashed.supervisor_pidfd
            crashed.helper.kill()
            crashed.helper.wait(timeout=5)
            require(not wait_dead(master_pidfd, 0.1),
                'master unexpectedly exited with its helper killed')
            stop_failed = False
            try:
                crashed.stop(timeout=1)
            except (OSError, RuntimeError, ValueError, TimeoutError):
                stop_failed = True
            crashed.close()
            require(stop_failed and crashed.unresolved and not crashed.settled,
                'dead helper was reported as a settled companion')
            require(crashed.channel is not None and
                    crashed.channel.fileno() == helper_fd and
                    crashed.master_pidfd == master_fd and
                    crashed.supervisor_pidfd == supervisor_fd,
                'UNRESOLVED close discarded its channel/pidfd ownership records')
        finally:
            signal_and_reap_master(crashed, master_pidfd)
            os.close(master_pidfd)
            close_manager(crashed)

        for kind in ('rights', 'truncated', 'eof'):
            exercise_bad_receive(supervisor, wire, args.server, helper_path,
                config, prefix, environment, kind)
    print('C34 helper control ownership fixture: PASS')
    return 0


if __name__ == '__main__':
    sys.exit(main())
