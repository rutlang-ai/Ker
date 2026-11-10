#!/usr/bin/env python3
"""Real pinned Nginx traffic/HUP/settlement through ker-run's companion."""
import argparse
import json
import os
import shutil
from pathlib import Path
import select
import shlex
import signal
import socket
import subprocess
import sys
import tempfile
import time


BODY = b'ker-c35-companion-http\n'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def set_up_network():
    for command in (
        ['ip', 'link', 'set', 'lo', 'up'],
        ['ip', 'link', 'add', 'kerhost', 'type', 'veth', 'peer', 'name', 'kerlink'],
        ['ip', 'tuntap', 'add', 'dev', 'kerpeer', 'mode', 'tap', 'multi_queue'],
        ['ip', 'addr', 'add', '198.18.0.1/24', 'dev', 'kerhost'],
        ['ip', 'link', 'set', 'kerhost', 'up'],
        ['ip', 'link', 'set', 'kerlink', 'up'],
        ['ip', 'link', 'set', 'kerpeer', 'up'],
    ):
        subprocess.run(command, check=True)


def child_pids(pid):
    path = Path(f'/proc/{pid}/task/{pid}/children')
    try:
        return [int(value) for value in path.read_text().split()]
    except FileNotFoundError:
        return []


def process_command(pid):
    try:
        return Path(f'/proc/{pid}/cmdline').read_bytes().replace(b'\0', b' ').decode(
            errors='replace')
    except OSError:
        return ''


def wait_worker(master, previous, timeout):
    path = Path(f'/proc/{master}/task/{master}/children')
    deadline = time.monotonic() + timeout
    last = []
    while time.monotonic() < deadline:
        if not Path(f'/proc/{master}').exists():
            raise RuntimeError('pinned Nginx master exited before its worker was ready')
        try:
            last = [int(value) for value in path.read_text().split()]
        except FileNotFoundError:
            last = []
        if len(last) == 1 and (previous is None or last[0] != previous):
            return last[0]
        time.sleep(0.02)
    raise RuntimeError(f'Nginx did not publish the expected worker: {last!r}')


def http_get():
    connection = socket.create_connection(('198.18.0.2', 80), timeout=5)
    try:
        connection.sendall(b'GET / HTTP/1.1\r\nHost: ker.test\r\n'
            b'Connection: close\r\n\r\n')
        response = bytearray()
        while True:
            chunk = connection.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
        header, separator, body = bytes(response).partition(b'\r\n\r\n')
        require(separator and b' 200 ' in header.split(b'\r\n', 1)[0],
            f'original-Linux Nginx request did not return HTTP 200: {header!r}')
        require(body == BODY, f'original-Linux response body changed: {body!r}')
        return bytes(response)
    finally:
        connection.close()


def wait_http(timeout=20):
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            return http_get()
        except OSError as error:
            last_error = error
            time.sleep(0.05)
    raise RuntimeError(f'original-Linux Nginx did not serve HTTP before deadline: {last_error}')


def pidfd_dead(fd, timeout=0):
    poller = select.poll()
    poller.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR)
    return bool(poller.poll(int(timeout * 1000)))


def run(args):
    with tempfile.TemporaryDirectory(prefix='ker-c35-nginx-', dir='/dev/shm') as directory:
        root = Path(directory)
        rpc_path = root / 'broker.sock'
        stats_path = root / 'stats.json'
        prefix = root / 'nginx'
        logs = prefix / 'logs'
        html = prefix / 'html'
        logs.mkdir(parents=True)
        html.mkdir()
        (html / 'index.html').write_bytes(BODY)
        ini = prefix / 'fstack.ini'
        ini.write_text(f'[ker_socket_broker]\nversion=1\npath={rpc_path}\n\n'
            '[dpdk]\ngraceful_reload=0\n', encoding='utf-8')
        config = prefix / 'nginx.conf'
        module_config = (f'load_module {args.owner_activation_module.resolve()};\n'
            if args.owner_activation_module is not None else '')
        ready_environment = ('env KER_FSTACK_NGINX_INI;\n'
            if args.owner_activation_module is not None else '')
        config.write_text(f'''{module_config}daemon off;
master_process on;
worker_processes 1;
fstack_conf "fstack.ini";
timer_resolution 1ms;
pid {logs / 'nginx.pid'};
error_log {logs / 'error.log'} notice;
env LD_PRELOAD;
env KER_SOCKET_BROKER_PATH;
{ready_environment}events {{ worker_connections 256; use epoll; }}
http {{
    access_log off;
    sendfile off;
    tcp_nopush off;
    keepalive_timeout 0;
    server {{
        listen 198.18.0.2:80 reuseport;
        server_name ker.test;
        root {html};
        index index.html;
    }}
}}
''', encoding='utf-8')

        cpu = min(os.sched_getaffinity(0))
        plugin = args.dpdk_plugin_dir / 'librte_net_tap.so'
        eal = (f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry '
            f'--iova-mode=va -m 64 -d {plugin} '
            '--vdev=net_tap0,iface=kerpeer,remote=kerlink')
        control_env = (
            f'LD_PRELOAD={args.fstack_runtime.resolve()}:{args.preload_library.resolve()}',
            f'KER_SOCKET_BROKER_PATH={rpc_path}',
            f'KER_FSTACK_NGINX_INI={ini}',
        )
        if args.owner_activation_module is not None:
            require(args.worker_shim is not None,
                'owner READY integration requires the C22 worker activation shim')
            control_env = (f'LD_PRELOAD={args.worker_shim.resolve()}:'
                f'{args.fstack_runtime.resolve()}:{args.preload_library.resolve()}',
                f'KER_SOCKET_BROKER_PATH={rpc_path}', f'KER_FSTACK_NGINX_INI={ini}')
        command = [sys.executable, str(args.launcher.resolve()),
            '--library', str(args.library.resolve()),
            '--io-worker', str(args.worker.resolve()),
            '--address', '198.18.0.2/24', '--port', 'net_tap0', '--eal', eal,
            '--runtime-service', '--broker-readiness',
            '--control-nginx-binary', str(args.nginx.resolve()),
            '--control-nginx-config', str(config),
            '--control-nginx-prefix', str(prefix), '--stats', str(stats_path)]
        if args.owner_activation_module is not None:
            command += ['--control-nginx-owner-ready',
                '--control-nginx-owner-module', str(args.owner_activation_module.resolve())]
        for item in control_env:
            command += ['--control-nginx-env', item]
        command += ['--', str(args.broker.resolve()), str(rpc_path)]

        output_path = root / 'ker-run.log'
        pid_path = logs / 'nginx.pid'
        pidfds = []
        with output_path.open('wb') as output:
            supervisor = subprocess.Popen(command, stdout=output,
                stderr=subprocess.STDOUT, start_new_session=True)
            helper_pidfd = -1
            master_pidfd = -1
            worker_pidfds = []
            scenario_cleanup_complete = False
            try:
                deadline = time.monotonic() + 45
                while time.monotonic() < deadline:
                    if supervisor.poll() is not None:
                        output.flush()
                        raise RuntimeError('ker-run exited before the pinned Nginx master '
                            f'started: {output_path.read_text(errors="replace")}')
                    if pid_path.is_file() and pid_path.read_text().strip():
                        break
                    time.sleep(0.02)
                else:
                    raise RuntimeError('pinned Nginx did not publish its pidfile')
                master = int(pid_path.read_text().strip())
                master_pidfd = os.pidfd_open(master, 0)
                worker = wait_worker(master, None, 20)
                worker_pidfds.append(os.pidfd_open(worker, 0))
                # Record the dedicated helper as a direct ker-run child. It is
                # separate from the worker and application children.
                deadline = time.monotonic() + 2
                seen_direct_children = set()
                while time.monotonic() < deadline:
                    direct = child_pids(supervisor.pid)
                    for pid in direct:
                        if pid in seen_direct_children:
                            continue
                        try:
                            fd = os.pidfd_open(pid, 0)
                        except ProcessLookupError:
                            continue
                        pidfds.append(fd)
                        seen_direct_children.add(pid)
                    if len(pidfds) >= 3:
                        break
                    time.sleep(0.02)
                wait_http()

                # Exercise the launcher signal path: it must consume and clear
                # the pending flag, relay HUP through the pinned companion,
                # and leave the existing ker-run reactor available for STOP.
                if args.owner_activation_module is None:
                    os.kill(supervisor.pid, signal.SIGHUP)
                    replacement = wait_worker(master, worker, 30)
                    worker_pidfds.append(os.pidfd_open(replacement, 0))
                    wait_http()
                else:
                    ready_lines = []
                    ready_deadline = time.monotonic() + 5
                    while time.monotonic() < ready_deadline:
                        if supervisor.poll() is not None:
                            break
                        output.flush()
                        ready_lines = [line for line in output_path.read_text(
                            errors='replace').splitlines()
                            if line.startswith('KER_NGINX_OWNER_READY ')]
                        if ready_lines:
                            break
                        time.sleep(0.01)
                    require(len(ready_lines) == 1,
                        'ker-run did not publish exactly one authenticated owner READY record')
                    ready = json.loads(ready_lines[0].split(' ', 1)[1])
                    require(ready.get('pid') == worker and ready.get('master_pid') == master and
                        ready.get('tid', 0) > 0 and ready.get('role') == 0 and
                        ready.get('slot_device', 0) > 0 and ready.get('slot_inode', 0) > 0 and
                        ready.get('source') == 'authenticated-C22-worker-READY',
                        f'authenticated READY did not identify the actual ff_run worker: {ready!r}')

                if args.break_helper:
                    helper = None
                    for pid in child_pids(supervisor.pid):
                        if 'ker-nginx-companion' in process_command(pid):
                            helper = pid
                            break
                    require(helper is not None, 'could not identify the pinned companion helper')
                    helper_pidfd = os.pidfd_open(helper, 0)
                    pidfds.append(helper_pidfd)
                    io_worker = None
                    app_pid = None
                    for pid in child_pids(supervisor.pid):
                        command_line = process_command(pid)
                        if str(args.worker.resolve()) in command_line:
                            io_worker = pid
                        if str(args.broker.resolve()) in command_line:
                            app_pid = pid
                    require(io_worker is not None and app_pid is not None,
                        'could not identify live broker app and DPDK worker among ker-run children: '
                        f'{[(pid, process_command(pid)) for pid in child_pids(supervisor.pid)]!r}')
                    io_worker_pidfd = os.pidfd_open(io_worker, 0)
                    app_pidfd = os.pidfd_open(app_pid, 0)
                    pidfds.extend((io_worker_pidfd, app_pidfd))
                    signal.pidfd_send_signal(helper_pidfd, signal.SIGKILL)
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline:
                        output.flush()
                        if 'companion shutdown UNRESOLVED' in output_path.read_text(
                                errors='replace'):
                            break
                        time.sleep(0.02)
                    else:
                        raise RuntimeError('helper death did not put ker-run in unresolved retention')
                    require(pidfd_dead(helper_pidfd, 1), 'killed helper remained alive')
                    signal_number = signal.SIGINT if args.shutdown_signal == 'int' else signal.SIGTERM
                    os.kill(supervisor.pid, signal_number)
                    time.sleep(0.25)
                    require(supervisor.poll() is None,
                        'ker-run exited after companion loss instead of retaining native resources')
                    require(Path(f'/proc/{master}').exists() and
                        not pidfd_dead(master_pidfd) and not pidfd_dead(io_worker_pidfd) and
                        not pidfd_dead(app_pidfd) and
                        not pidfd_dead(worker_pidfds[-1]),
                        'native app/DPDK worker/Nginx workers stopped despite unresolved companion')
                    output.flush()
                    retained_log = output_path.read_text(errors='replace')
                    require('BROKER_DONE' not in retained_log and 'KER_NATIVE_DONE' not in retained_log and
                        'worker_exit_code' not in retained_log and not stats_path.exists(),
                        'native cleanup completed despite unresolved companion ownership')
                    # The test harness owns teardown after proving retention.
                    os.kill(supervisor.pid, signal.SIGKILL)
                    supervisor.wait(timeout=5)
                    for fd in worker_pidfds + [master_pidfd, io_worker_pidfd, app_pidfd]:
                        try:
                            signal.pidfd_send_signal(fd, signal.SIGTERM)
                        except OSError:
                            pass
                    time.sleep(0.2)
                    for fd in worker_pidfds + [master_pidfd, io_worker_pidfd, app_pidfd]:
                        if not pidfd_dead(fd):
                            try:
                                signal.pidfd_send_signal(fd, signal.SIGKILL)
                            except OSError:
                                pass
                    cleanup_targets = worker_pidfds + [master_pidfd, io_worker_pidfd,
                        app_pidfd, helper_pidfd]
                    cleanup_deadline = time.monotonic() + 3
                    while (time.monotonic() < cleanup_deadline and
                            any(not pidfd_dead(fd) for fd in cleanup_targets)):
                        time.sleep(0.02)
                    require(all(pidfd_dead(fd) for fd in cleanup_targets),
                        'test-owned teardown did not reap every pinned target')
                    scenario_cleanup_complete = True
                    print(f'C35 unresolved-companion retention with SIG{signal.Signals(signal_number).name}: '
                        'PASS; harness forcibly terminated retained processes (not normal shutdown)')
                    return

                if args.owner_death:
                    helper = next((pid for pid in child_pids(supervisor.pid)
                        if 'ker-nginx-companion' in process_command(pid)), None)
                    require(helper is not None, 'could not identify the pinned companion helper')
                    helper_pidfd = os.pidfd_open(helper, 0)
                    pidfds.append(helper_pidfd)
                    io_worker = app_pid = None
                    for pid in child_pids(supervisor.pid):
                        command_line = process_command(pid)
                        if str(args.worker.resolve()) in command_line:
                            io_worker = pid
                        if str(args.broker.resolve()) in command_line:
                            app_pid = pid
                    require(io_worker is not None and app_pid is not None,
                        'could not identify live native broker children for owner-death control')
                    io_worker_pidfd = os.pidfd_open(io_worker, 0)
                    app_pidfd = os.pidfd_open(app_pid, 0)
                    pidfds.extend((io_worker_pidfd, app_pidfd))
                    signal.pidfd_send_signal(worker_pidfds[-1], signal.SIGKILL)
                    deadline = time.monotonic() + 8
                    while time.monotonic() < deadline:
                        output.flush()
                        if 'companion shutdown UNRESOLVED' in output_path.read_text(
                                errors='replace'):
                            break
                        time.sleep(0.02)
                    else:
                        raise RuntimeError('delegated owner death did not trigger containment failure')
                    require(pidfd_dead(worker_pidfds[-1], 1) and
                        pidfd_dead(master_pidfd, 1) and pidfd_dead(helper_pidfd, 1),
                        'owner-death containment did not settle the pinned Nginx subtree')
                    signal_number = signal.SIGTERM
                    os.kill(supervisor.pid, signal_number)
                    time.sleep(0.25)
                    require(supervisor.poll() is None and
                        not pidfd_dead(io_worker_pidfd) and not pidfd_dead(app_pidfd),
                        'ker-run released native resources after owner-death containment failure')
                    output.flush()
                    retained_log = output_path.read_text(errors='replace')
                    require('BROKER_DONE' not in retained_log and
                        'KER_NATIVE_DONE' not in retained_log and
                        'worker_exit_code' not in retained_log and not stats_path.exists(),
                        'native cleanup completed despite unresolved owner-death containment')
                    os.kill(supervisor.pid, signal.SIGKILL)
                    supervisor.wait(timeout=5)
                    for fd in (io_worker_pidfd, app_pidfd):
                        try:
                            signal.pidfd_send_signal(fd, signal.SIGTERM)
                        except OSError:
                            pass
                    time.sleep(0.2)
                    for fd in (io_worker_pidfd, app_pidfd):
                        if not pidfd_dead(fd):
                            try:
                                signal.pidfd_send_signal(fd, signal.SIGKILL)
                            except OSError:
                                pass
                    deadline = time.monotonic() + 3
                    while time.monotonic() < deadline and any(
                            not pidfd_dead(fd) for fd in (io_worker_pidfd, app_pidfd)):
                        time.sleep(0.02)
                    require(all(pidfd_dead(fd) for fd in
                        (worker_pidfds[-1], master_pidfd, helper_pidfd,
                         io_worker_pidfd, app_pidfd)),
                        'owner-death fixture left a test-owned process alive')
                    scenario_cleanup_complete = True
                    print('C35 delegated owner idle-death containment: PASS; '
                        'helper detected pidfd death, settled Nginx, retained native resources')
                    return

                signal_number = signal.SIGINT if args.shutdown_signal == 'int' else signal.SIGTERM
                os.kill(supervisor.pid, signal_number)
                supervisor.wait(timeout=35)
                output.flush()
                log = output_path.read_text(errors='replace')
                nginx_log = (logs / 'error.log').read_text(errors='replace')
                if args.owner_activation_module is None:
                    require('signal 1 (SIGHUP) received' in nginx_log,
                        'actual pinned Nginx did not record the ker-run reload signal')
                else:
                    require('signal 1 (SIGHUP) received' not in nginx_log,
                        'owner READY opt-in unexpectedly delivered an unauthenticated reload')
                require(supervisor.returncode == 128 + signal_number,
                    f'ker-run exit status after orderly companion STOP: '
                    f'{supervisor.returncode}; {log}')
                require('BROKER_DONE' in log,
                    f'broker did not report native cleanup completion: {log}')
                stats = json.loads(stats_path.read_text(encoding='utf-8'))
                require(stats.get('outstanding') == 0 and stats.get('tx', 0) > 0 and
                    stats.get('rx', 0) > 0 and stats.get('control_eof') is True and
                    stats.get('worker_exit_code') == 0 and
                    stats.get('run_shutdown') is True and
                    stats.get('run_shutdown_ack') is True,
                    f'worker/native cleanup accounting was incomplete: {stats!r}')
                require(not Path(f'/proc/{master}').exists(),
                    'Nginx master remained alive after companion SETTLED')
                require(pidfd_dead(master_pidfd, 2),
                    'pinned Nginx master did not exit after companion SETTLED')
                for fd in worker_pidfds + pidfds:
                    require(pidfd_dead(fd, 2),
                        'Nginx worker/helper/runtime child remained alive after ker-run exit')
                scenario_cleanup_complete = True
            finally:
                if not scenario_cleanup_complete:
                    # Failure runs are unqualified. Stop the supervisor and
                    # then target its separately-sessioned helper/master by
                    # pidfd so a failed assertion cannot leak Nginx into later
                    # tests or leave a live child holding native resources.
                    if supervisor.poll() is None:
                        try:
                            supervisor.send_signal(signal.SIGTERM)
                            supervisor.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            os.killpg(supervisor.pid, signal.SIGKILL)
                            supervisor.wait(timeout=3)
                    targets = worker_pidfds + pidfds
                    if master_pidfd >= 0:
                        targets.append(master_pidfd)
                    for fd in targets:
                        try:
                            signal.pidfd_send_signal(fd, signal.SIGTERM)
                        except (OSError, ProcessLookupError):
                            pass
                    deadline = time.monotonic() + 2
                    while time.monotonic() < deadline and any(
                            not pidfd_dead(fd) for fd in targets):
                        time.sleep(0.02)
                    for fd in targets:
                        if not pidfd_dead(fd):
                            try:
                                signal.pidfd_send_signal(fd, signal.SIGKILL)
                            except (OSError, ProcessLookupError):
                                pass
                for fd in worker_pidfds + pidfds + ([master_pidfd] if master_pidfd >= 0 else []):
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                if not scenario_cleanup_complete:
                    archive = Path('/dev/shm/ker-c35-last-failure')
                    archive.mkdir(exist_ok=True)
                    if output_path.exists():
                        shutil.copy2(output_path, archive / 'ker-run.log')
                    error_log = logs / 'error.log'
                    if error_log.exists():
                        shutil.copy2(error_log, archive / 'nginx-error.log')
                    if stats_path.exists():
                        shutil.copy2(stats_path, archive / 'stats.json')
                    print(f'UNQUALIFIED diagnostic archive: {archive}', file=sys.stderr)
                    if (archive / 'nginx-error.log').exists():
                        print((archive / 'nginx-error.log').read_text(errors='replace')[-12000:],
                            file=sys.stderr)
        if args.owner_activation_module is None:
            print('C35 real pinned Nginx HTTP/HUP/worker-replacement/companion-SETTLED/native-DONE: PASS')
        else:
            print('C35 real pinned Nginx HTTP/C22 owner READY/companion-SETTLED/native-DONE: PASS')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--launcher', type=Path, required=True)
    parser.add_argument('--library', type=Path, required=True)
    parser.add_argument('--worker', type=Path, required=True)
    parser.add_argument('--broker', type=Path, required=True)
    parser.add_argument('--nginx', type=Path, required=True)
    parser.add_argument('--fstack-runtime', type=Path, required=True)
    parser.add_argument('--preload-library', type=Path, required=True)
    parser.add_argument('--dpdk-plugin-dir', type=Path, required=True)
    parser.add_argument('--inside', action='store_true')
    parser.add_argument('--shutdown-signal', choices=('term', 'int'), default='term')
    parser.add_argument('--break-helper', action='store_true')
    parser.add_argument('--owner-activation-module', type=Path)
    parser.add_argument('--worker-shim', type=Path)
    parser.add_argument('--owner-death', action='store_true')
    args = parser.parse_args()
    if not args.inside:
        command = ['unshare', '-Un', '--keep-caps',
            f'--map-user={os.getuid()}', f'--map-group={os.getgid()}',
            sys.executable, str(Path(__file__).resolve()), '--inside']
        for name in ('launcher', 'library', 'worker', 'broker', 'nginx',
                'fstack-runtime', 'preload-library', 'dpdk-plugin-dir'):
            command += ['--' + name, str(getattr(args, name.replace('-', '_')).resolve())]
        if args.owner_activation_module is not None:
            command += ['--owner-activation-module',
                str(args.owner_activation_module.resolve())]
        if args.owner_death:
            command.append('--owner-death')
        if args.worker_shim is not None:
            command += ['--worker-shim', str(args.worker_shim.resolve())]
        command += ['--shutdown-signal', args.shutdown_signal]
        if args.break_helper:
            command.append('--break-helper')
        subprocess.run(command, check=True)
        return 0
    if args.owner_death and args.owner_activation_module is None:
        raise ValueError('--owner-death requires the authenticated owner READY profile')
    set_up_network()
    run(args)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f'C35 Nginx companion TAP failed: {error}', file=sys.stderr)
        raise
