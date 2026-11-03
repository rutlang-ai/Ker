"""Two real Nginx callers over one original-Linux staged owner group."""
import array
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import select
import signal
import socket
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]


def require(value, message):
    if not value:
        raise RuntimeError(message)


def run(args, rpc_path, stop_path, stats, root, broker, environment, wait_line):
    transfer, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    controller = None
    processes, caps, pidfds = [], [], []
    held = None
    evidence = {'status': 'RUNNING', 'events': []}

    def record(event, **fields):
        evidence['events'].append({'event': event, 'monotonic_ns': time.monotonic_ns(), **fields})

    def command(value):
        controller.stdin.write((value + '\n').encode()); controller.stdin.flush()
        return wait_line(controller, 'OWNER_GROUP_OK ' + value, 15)

    probe_file = ROOT / 'tests/upstream/fstack/tests/integration/common/reload_probes/http_probe.py'
    spec = importlib.util.spec_from_file_location('nginx_overlap_http_probe', probe_file)
    probe = importlib.util.module_from_spec(spec); spec.loader.exec_module(probe)

    def http(connection, body, close=False):
        result = probe.response(connection, expect_eof=close,
            expect_md5=hashlib.md5(body).hexdigest())
        require(result[0] == len(body) and result[3] and result[4], 'original HTTP response oracle failed')

    def fresh(body):
        with socket.create_connection(('198.18.0.2', 4108), timeout=10) as connection:
            connection.settimeout(10); http(connection, body, True)

    def start_nginx(label, slot, candidate):
        prefix = root / label
        (prefix / 'logs').mkdir(parents=True); (prefix / 'html').mkdir()
        body = (label + '-nginx\n').encode()
        (prefix / 'html/index.html').write_bytes(body)
        ini = prefix / 'fstack.ini'
        ini.write_text(f'[ker_socket_broker]\nversion=1\npath={rpc_path}\n\n[dpdk]\ngraceful_reload=0\n')
        config = prefix / 'nginx.conf'
        config.write_text(f'''load_module {args.nginx_candidate_module};
daemon off; master_process on; worker_processes 1; user root;
fstack_conf "fstack.ini"; timer_resolution 1ms;
pid {prefix}/logs/nginx.pid; error_log {prefix}/logs/error.log notice;
env LD_PRELOAD; env KER_SOCKET_BROKER_PATH; env KER_FSTACK_NGINX_INI;
env KER_FSTACK_RUNTIME_TRACE;
events {{ worker_connections 256; use epoll; }}
http {{ access_log off; sendfile off; keepalive_timeout 300;
server {{ listen 198.18.0.2:4108 reuseport backlog=16; root {prefix}/html; index index.html; }} }}
''')
        trace = prefix / 'runtime.trace'
        env = environment | {'LD_PRELOAD': ':'.join(map(str, [args.nginx_candidate_shim,
            args.nginx_candidate_runtime, args.preload])), 'KER_FSTACK_NGINX_INI': str(ini),
            'KER_FSTACK_RUNTIME_TRACE': str(trace),
            ('KER_NGINX_CANDIDATE_SLOT_FD' if candidate else 'KER_NGINX_INITIAL_SLOT_FD'): str(slot)}
        process = subprocess.Popen([str(args.nginx_candidate_binary), '-p', str(prefix) + '/',
            '-c', str(config)], pass_fds=(slot,), env=env, start_new_session=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        processes.append(process)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            text = trace.read_text() if trace.exists() else ''
            if re.search(r'name=ff_listen .*result=0\b', text):
                if not candidate or 'NGINX_CANDIDATE_TASK_READY' in text: break
            if process.poll() is not None:
                raise RuntimeError(f'{label} Nginx exited: {process.communicate()!r}, '
                    f'{(prefix / "logs/error.log").read_text()!r}; {text!r}')
            time.sleep(.01)
        else:
            raise RuntimeError(f'{label} did not listen: {text!r}; {(prefix / "logs/error.log").read_text()!r}')
        worker_pids = Path(f'/proc/{process.pid}/task/{process.pid}/children').read_text().split()
        require(len(worker_pids) == 1, f'{label} has unexpected children {worker_pids!r}')
        worker_fd = os.pidfd_open(int(worker_pids[0])); pidfds.append(worker_fd)
        record(label.upper() + '_NGINX_READY', master=process.pid, worker=int(worker_pids[0]))
        return process, body, prefix, worker_fd

    def stop_nginx(process, worker_fd, label):
        process.send_signal(signal.SIGQUIT)
        _, errors = process.communicate(timeout=20)
        require(process.returncode == 0, f'{label} shutdown failed: {errors!r}')
        require(select.select([worker_fd], [], [], 0)[0], f'{label} worker is still alive')
        record(label.upper() + '_NGINX_RETIRED')

    try:
        controller = subprocess.Popen([str(args.nginx_overlap_controller), str(rpc_path),
            str(child.fileno())], pass_fds=(child.fileno(),), stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        child.close(); transfer.settimeout(10)
        message, ancillary, flags, _ = transfer.recvmsg(1, socket.CMSG_SPACE(16))
        for level, kind, data in ancillary:
            require(level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS, 'unexpected delegated authority')
            values = array.array('i'); values.frombytes(data); caps.extend(values)
        require(message == b'N' and not flags and len(caps) == 2, 'expected exactly two owner slots')
        old, old_body, old_prefix, old_fd = start_nginx('old', caps[0], False)
        command('CONTROL'); command('CENSUS0')
        held = socket.create_connection(('198.18.0.2', 4108), timeout=10)
        held.settimeout(10); http(held, old_body)
        new, new_body, new_prefix, new_fd = start_nginx('new', caps[1], True)
        command('CENSUS1'); command('EARLY_RETIRE'); command('WRONG_RETIRE'); fresh(old_body)
        record('BOTH_NGINX_LIVE_SELECTOR_ZERO')
        command('BEGIN'); record('CUTOVER_PREPARED')
        with ThreadPoolExecutor(max_workers=1) as executor:
            queued = executor.submit(socket.create_connection, ('198.18.0.2', 4108), 10)
            command('QUEUED')
            require(not queued.done(), 'queued SYN completed before cutover commit')
            command('COMMIT'); command('EARLY_RETIRE'); record('CUTOVER_COMMITTED_WITH_QUEUED_SYN')
            with queued.result(timeout=10) as connection:
                connection.settimeout(10); http(connection, new_body, True)
        http(held, old_body); record('OLD_KEEPALIVE_SURVIVED')
        held.close(); held = None
        stop_nginx(old, old_fd, 'old'); command('RETIRE0'); command('CLOSED0')
        fresh(new_body); record('NEW_HTTP_AFTER_OLD_EXIT')
        stop_nginx(new, new_fd, 'new'); command('CLOSED1')
        command_text = b'STOP\n'; controller.stdin.write(command_text); controller.stdin.flush()
        _, errors = controller.communicate(timeout=10)
        require(controller.returncode == 0, f'coordinator cleanup failed: {errors!r}')
        for cap in caps: os.close(cap)
        caps.clear()
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as stop:
            stop.sendto(b'STOP', str(stop_path))
        _, errors = broker.communicate(timeout=35)
        report = json.loads(stats.read_text())
        require(broker.returncode == 0 and report.get('outstanding') == 0,
            f'broker did not settle: {errors!r}; {report!r}')
        record('BROKER_SETTLED')
        evidence.update(status='PASS', stats=report, logs={
            label: {'trace': (prefix / 'runtime.trace').read_text(),
                'error_log': (prefix / 'logs/error.log').read_text()}
            for label, prefix in [('old', old_prefix), ('new', new_prefix)]})
        require('private candidate admission: allowed=1 created=1' in
            evidence['logs']['new']['error_log'], 'new Nginx did not consume original-map admission')
        print('NGINX_OVERLAP_PASS queued_syn=true old_keepalive=true old_exit=true outstanding=0')
        return 0
    except BaseException as error:
        evidence.update(status='FAIL', error=repr(error))
        raise
    finally:
        if held is not None: held.close()
        for process in processes:
            if process.poll() is None:
                try: os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                process.communicate()
        if controller is not None and controller.poll() is None:
            controller.kill(); controller.communicate()
        for cap in caps: os.close(cap)
        for fd in pidfds: os.close(fd)
        transfer.close(); child.close()
        if broker.poll() is None:
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as stop:
                    stop.sendto(b'STOP', str(stop_path))
                broker.communicate(timeout=35)
            except (OSError, subprocess.TimeoutExpired):
                broker.kill(); broker.communicate()
        evidence['logs'] = {
            label: {name: path.read_text(errors='replace')
                for name, path in [('trace', root / label / 'runtime.trace'),
                    ('error_log', root / label / 'logs/error.log')] if path.exists()}
            for label in ('old', 'new')}
        if args.nginx_candidate_evidence:
            args.nginx_candidate_evidence.parent.mkdir(parents=True, exist_ok=True)
            args.nginx_candidate_evidence.write_text(json.dumps(evidence, indent=2) + '\n')
