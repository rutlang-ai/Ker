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
import threading
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


def wait_for_path(path, timeout=3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.005)
    raise RuntimeError(f'test fixture did not create {path.name}')


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


def process_alive(pidfd):
    return not wait_dead(pidfd, 0)


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


def _capture_start(manager, errors):
    try:
        manager.start(timeout=12)
    except BaseException as error:
        errors.append(error)


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
        b'daemon off; master_process on; worker_processes 1; fstack_conf /tmp/fstack.ini; # include ignored\n',
        b'daemon off; master_process on; worker_processes 1; fstack_conf /tmp/fstack.ini; events { worker_connections 4; }\n',
        b'daemon off; master_process on; worker_processes 1; fstack_conf /tmp/fstack.ini; set $name "include";\n',
        b'daemon off; master_process on; worker_processes 1; fstack_conf /tmp/fstack.ini; set $name include;\n',
    )
    for profile_bytes in valid_profiles:
        helper_module.validate_control_nginx_config(profile_bytes)
    for profile_bytes in (
            b'daemon off; master_process on; worker_processes 1; fstack_conf /tmp/fstack.ini;\ninclude\t/escape.conf;\n',
            b'daemon off; master_process on; worker_processes 1; fstack_conf /tmp/fstack.ini; include /escape.conf;\n',
            b'daemon off; master_process on; worker_processes 1; fstack_conf /tmp/fstack.ini; "include" "/escape.conf";\n',
            b'daemon off; master_process on; worker_processes 1; fstack_conf /tmp/fstack.ini; "include" "/escape\\t.conf";\n'):
        try:
            helper_module.validate_control_nginx_config(profile_bytes)
        except ValueError as exc:
            require('include' in str(exc), 'include rejection did not identify unsupported directive')
        else:
            raise RuntimeError('Nginx include syntax escaped the bounded profile validator')
    for label, profile_bytes in (
            ('missing', b'daemon off; master_process on; worker_processes 1;'),
            ('duplicate', b'daemon off; master_process on; worker_processes 1; fstack_conf /tmp/a.ini; fstack_conf /tmp/b.ini;'),
            ('nested', b'daemon off; master_process on; worker_processes 1; events { fstack_conf /tmp/a.ini; }'),
            ('dynamic', b'daemon off; master_process on; worker_processes 1; fstack_conf $ini;')):
        try:
            helper_module.validate_control_nginx_config(profile_bytes)
        except ValueError:
            pass
        else:
            raise RuntimeError(f'{label} fstack_conf selection was accepted')
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
        config.write_text('daemon off;\nmaster_process on;\nworker_processes 1;\n'
            'fstack_conf "fstack.ini";\n',
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
        directives = helper_module.validate_control_nginx_config(config.read_bytes())
        selected, selected_identity = helper_module.effective_fstack_ini(
            config, directives, ini)
        require(selected == ini.resolve() and selected_identity ==
            (ini.stat().st_dev, ini.stat().st_ino),
            'quoted relative fstack_conf did not resolve from the -c config directory')
        alias = root / 'fstack-alias.ini'
        alias.symlink_to(ini)
        alias_config = root / 'alias-nginx.conf'
        alias_config.write_text('daemon off;\nmaster_process on;\n'
            'worker_processes 1;\nfstack_conf fstack-alias.ini;\n',
            encoding='utf-8')
        alias_directives = helper_module.validate_control_nginx_config(
            alias_config.read_bytes())
        alias_selected, alias_identity = helper_module.effective_fstack_ini(
            alias_config, alias_directives, ini)
        require(alias_selected == ini.resolve() and alias_identity == selected_identity,
            'same-file symlink alias was not canonicalized to the pinned INI')
        other_ini = root / 'other.ini'
        other_ini.write_text('[ker_socket_broker]\nversion=1\n'
            f'path={broker_path}\n[dpdk]\ngraceful_reload=1\n', encoding='utf-8')
        try:
            helper_module.effective_fstack_ini(config, directives, other_ini)
        except ValueError:
            pass
        else:
            raise RuntimeError('different fstack_conf/env INI identities were accepted')
        helper_path = args.helper.resolve(strict=True)
        config_text = ('daemon off;\nmaster_process on;\nworker_processes 1;\n'
            'fstack_conf "fstack.ini";\n')
        ini_text = (f'[ker_socket_broker]\nversion=1\npath={broker_path}\n'
            '[dpdk]\ngraceful_reload=0\n')

        # Delay the test master's signal-handler installation. The helper must
        # withhold STARTED until the kernel reports HUP/QUIT as caught.
        delayed_prefix = root / 'delayed-prefix'
        delayed_prefix.mkdir()
        (delayed_prefix / 'delay-signal-handlers').touch()
        delayed_config = root / 'delayed-nginx.conf'
        delayed_config.write_text(config_text.replace('fstack.ini',
            'delayed-fstack.ini'), encoding='utf-8')
        delayed_ini = root / 'delayed-fstack.ini'
        delayed_ini.write_text(ini_text, encoding='utf-8')
        delayed_environment = dict(environment,
            KER_FSTACK_NGINX_INI=str(delayed_ini))
        delayed = supervisor.NginxCompanion(args.server, delayed_config,
            delayed_prefix, delayed_environment)
        delayed.helper_path = args.helper.resolve(strict=True)
        delayed.helper_script_hash = supervisor._sha256(delayed.helper_path)
        delayed_errors = []
        start_thread = threading.Thread(target=lambda: _capture_start(
            delayed, delayed_errors), daemon=True)
        start_thread.start()
        try:
            wait_for_path(delayed_prefix / 'signal-handler-waiting')
            delayed_master_pid = int((delayed_prefix /
                'signal-handler-waiting').read_text(encoding='ascii'))
            delayed_master_pidfd = os.pidfd_open(delayed_master_pid, 0)
            poller = select.poll()
            poller.register(delayed.channel.fileno(), select.POLLIN)
            require(not poller.poll(100) and not delayed.started,
                'helper published STARTED before test-master signal handlers were installed')
            require(process_alive(delayed_master_pidfd),
                'delayed test master exited before handler release')
            require(not (delayed_prefix / 'hup-observed').exists(),
                'test master received HUP before its handlers were installed')
            (delayed_prefix / 'release-signal-handlers').touch()
            start_thread.join(timeout=8)
            require(not start_thread.is_alive() and not delayed_errors and delayed.started,
                'helper did not publish STARTED after signal handlers became ready')
            delayed.reload(timeout=5)
            require(wait_marker_count(delayed_prefix / 'hup-observed', 1) == 1 and
                    process_alive(delayed.master_pidfd),
                'immediate post-STARTED reload did not reach a live handled master')
            delayed.stop(timeout=5)
            require(delayed.settled and not delayed.unresolved,
                'delayed-handler profile did not settle after STOP')
        finally:
            (delayed_prefix / 'release-signal-handlers').touch()
            start_thread.join(timeout=8)
            cleanup_manager(delayed)
            if 'delayed_master_pidfd' in locals():
                os.close(delayed_master_pidfd)

        # A master that never installs the required handlers must fail within
        # the fixed startup deadline and be reaped without a success receipt.
        never_prefix = root / 'never-ready-prefix'
        never_prefix.mkdir()
        (never_prefix / 'delay-signal-handlers').touch()
        never_config = root / 'never-ready-nginx.conf'
        never_config.write_text(config_text.replace('fstack.ini',
            'never-ready-fstack.ini'), encoding='utf-8')
        never_ini = root / 'never-ready-fstack.ini'
        never_ini.write_text(ini_text, encoding='utf-8')
        never_environment = dict(environment, KER_FSTACK_NGINX_INI=str(never_ini))
        never = supervisor.NginxCompanion(args.server, never_config,
            never_prefix, never_environment)
        never.helper_path = args.helper.resolve(strict=True)
        never.helper_script_hash = supervisor._sha256(never.helper_path)
        never_errors = []
        never_thread = threading.Thread(target=lambda: _capture_start(
            never, never_errors), daemon=True)
        never_thread.start()
        never_master_pidfd = -1
        try:
            wait_for_path(never_prefix / 'signal-handler-waiting')
            never_master_pid = int((never_prefix /
                'signal-handler-waiting').read_text(encoding='ascii'))
            never_master_pidfd = os.pidfd_open(never_master_pid, 0)
            poller = select.poll()
            poller.register(never.channel.fileno(), select.POLLIN)
            require(not poller.poll(100) and not never.started,
                'never-ready master produced a STARTED receipt')
            never_thread.join(timeout=12)
            require(not never_thread.is_alive() and bool(never_errors) and
                    never.unresolved and not never.started,
                'never-ready master was not rejected before STARTED')
            require(never_master_pidfd >= 0 and wait_dead(never_master_pidfd, 0.1),
                'never-ready master was not reaped within the bounded startup failure')
            require(not (never_prefix / 'hup-observed').exists(),
                'never-ready master received HUP')
            if never.helper is not None:
                never.helper.wait(timeout=8)
                require(never.helper.returncode != 0,
                    'never-ready helper returned success')
        finally:
            (never_prefix / 'release-signal-handlers').touch()
            never_thread.join(timeout=8)
            cleanup_manager(never)
            if never_master_pidfd >= 0:
                os.close(never_master_pidfd)

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
                'daemon off;\nmaster_process on;\nworker_processes 2;\n'
                'fstack_conf "fstack.ini";\n',
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

        def switch_effective_ini(changed_config, _changed_ini):
            changed_config.write_text(config_text.replace(
                'fstack_conf "fstack.ini";',
                f'fstack_conf "{other_ini}";'), encoding='utf-8')

        exercise_profile_mutation(supervisor, args.server, helper_path, config,
            prefix, environment, ini, switch_effective_ini,
            'effective fstack_conf changed to different graceful_reload=1 INI')
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

        startup_mismatch_config = config_text.replace('fstack.ini',
            str(other_ini))
        config.write_text(startup_mismatch_config, encoding='utf-8')
        startup_mismatch = supervisor.NginxCompanion(args.server, config,
            prefix, environment)
        startup_mismatch.helper_path = helper_path
        startup_mismatch.helper_script_hash = supervisor._sha256(helper_path)
        mismatch_failed = False
        try:
            startup_mismatch.start(timeout=5)
        except (OSError, RuntimeError, ValueError, PermissionError):
            mismatch_failed = True
        require(mismatch_failed and startup_mismatch.unresolved and
                not startup_mismatch.started,
            'alternate effective fstack_conf was not rejected before STARTED')
        require(not (prefix / 'hup-observed').exists() or
                (prefix / 'hup-observed').read_bytes() == b'',
            'alternate startup fstack_conf emitted a signal')
        if startup_mismatch.helper is not None:
            startup_mismatch.helper.wait(timeout=5)
            require(startup_mismatch.helper.returncode != 0,
                'alternate startup fstack_conf failed open')
        close_manager(startup_mismatch)
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
