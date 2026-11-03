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
import sys
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
    held_alias = None
    alias_listener = None
    evidence = {'status': 'RUNNING', 'outcome': 'abort' if args.nginx_overlap_abort else 'commit', 'events': []}
    stream_probe = None
    stream_output = None
    stream_started = None
    stream_payload = bytes(8 * 1024 * 1024) if args.nginx_overlap_source_streams else None

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
        if stream_payload is not None:
            (prefix / 'html/dl').mkdir()
            (prefix / 'html/dl/big.bin').write_bytes(stream_payload)
        ini = prefix / 'fstack.ini'
        ini.write_text(f'[ker_socket_broker]\nversion=1\npath={rpc_path}\n\n[dpdk]\ngraceful_reload=0\n')
        config = prefix / 'nginx.conf'
        module = args.nginx_candidate_module
        user_directive = 'user root;'
        if args.nginx_overlap_alias_regression and not candidate:
            module = args.nginx_overlap_alias_module
        config.write_text(f'''load_module {module};
daemon off; master_process on; worker_processes 1; {user_directive}
fstack_conf "fstack.ini"; timer_resolution 1ms;
pid {prefix}/logs/nginx.pid; error_log {prefix}/logs/error.log notice;
env LD_PRELOAD; env KER_SOCKET_BROKER_PATH; env KER_FSTACK_NGINX_INI;
env KER_FSTACK_RUNTIME_TRACE; env KER_NGINX_TEST_INITIAL_ALIAS_SOCKET;
events {{ worker_connections 256; use epoll; }}
http {{ access_log off; sendfile off; keepalive_timeout 300;
server {{ listen 198.18.0.2:4108 reuseport backlog=16; root {prefix}/html; index index.html; }} }}
''')
        trace = prefix / 'runtime.trace'
        env = environment | {'LD_PRELOAD': ':'.join(map(str, [args.nginx_candidate_shim,
            args.nginx_candidate_runtime, args.preload])), 'KER_FSTACK_NGINX_INI': str(ini),
            'KER_FSTACK_RUNTIME_TRACE': str(trace),
            ('KER_NGINX_CANDIDATE_SLOT_FD' if candidate else 'KER_NGINX_INITIAL_SLOT_FD'): str(slot)}
        if not candidate and args.nginx_overlap_alias_regression:
            env['KER_NGINX_TEST_INITIAL_ALIAS_SOCKET'] = str(root / 'initial-alias.sock')
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
        _, errors = process.communicate(timeout=80 if stream_probe is not None else 20)
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
        if args.nginx_overlap_alias_regression:
            alias_listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            alias_listener.bind(str(root / 'initial-alias.sock'))
            alias_listener.listen(1); alias_listener.settimeout(15)
        old, old_body, old_prefix, old_fd = start_nginx('old', caps[0], False)
        if alias_listener is not None:
            alias_channel, _ = alias_listener.accept()
            message, ancillary, flags, _ = alias_channel.recvmsg(1, socket.CMSG_SPACE(4))
            alias_channel.close()
            for level, kind, data in ancillary:
                require(level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS,
                    'initial member alias transfer used unexpected authority')
                values = array.array('i'); values.frombytes(data)
                require(len(values) == 1 and held_alias is None, 'expected one initial member alias')
                held_alias = values[0]
            require(message == b'A' and not flags and held_alias is not None,
                'initial Nginx owner did not export its live member(0) alias')
            record('INITIAL_MEMBER_ALIAS_HELD_BY_COORDINATOR')
        command('CONTROL'); command('CENSUS0')
        held = socket.create_connection(('198.18.0.2', 4108), timeout=10)
        held.settimeout(10); http(held, old_body)
        if stream_payload is not None:
            stream_file = root / 'source-stream.log'
            stream_output = stream_file.open('w')
            stream_command = [sys.executable, str(probe_file.with_name('m4_stream.py')),
                '--server', '198.18.0.2', '--port', '4108', '--path', '/dl/big.bin',
                '--streams', '12', '--chunk', '16384', '--gap', '0.1',
                '--timeout', '5', '--stall', '3.0', '--duration', '120',
                '--expect-md5', hashlib.md5(stream_payload).hexdigest()]
            # A host TCP client: no FF runtime, preload or broker authority.
            stream_environment = os.environ.copy()
            stream_environment.pop('LD_PRELOAD', None)
            stream_environment['PYTHONDONTWRITEBYTECODE'] = '1'
            stream_started = time.monotonic()
            stream_probe = subprocess.Popen(stream_command, stdout=stream_output,
                stderr=subprocess.STDOUT, env=stream_environment, start_new_session=True)
            evidence['source_stream'] = {'command': stream_command,
                'source_hashes': {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in (probe_file, probe_file.with_name('m4_stream.py'),
                        probe_file.parent.parent / 'reload_checks.py')}}
            # Preserve the original shell's three-second pre-handoff interval,
            # and additionally prove all twelve connections reached old Linux.
            while time.monotonic() - stream_started < 3:
                require(stream_probe.poll() is None, 'source stream probe exited before handoff')
                time.sleep(.01)
            command('STREAMS0')
            record('TWELVE_SOURCE_STREAMS_ON_OLD_OWNER', elapsed=time.monotonic() - stream_started)
        new, new_body, new_prefix, new_fd = start_nginx('new', caps[1], True)
        command('CENSUS1'); command('EARLY_RETIRE'); command('WRONG_RETIRE'); fresh(old_body)
        record('BOTH_NGINX_LIVE_SELECTOR_ZERO')
        command('BEGIN'); record('CUTOVER_PREPARED')
        with ThreadPoolExecutor(max_workers=1) as executor:
            queued = executor.submit(socket.create_connection, ('198.18.0.2', 4108), 10)
            command('QUEUED')
            require(not queued.done(), 'queued SYN completed before cutover decision')
            if args.nginx_overlap_abort:
                # The native ingress freeze precedes socket/flow-map admission.
                # Abort must replay this real SYN to the unchanged old selector.
                command('ABORT'); command('EARLY_RETIRE'); record('CUTOVER_ABORTED_WITH_QUEUED_SYN')
            else:
                command('COMMIT'); command('EARLY_RETIRE'); record('CUTOVER_COMMITTED_WITH_QUEUED_SYN')
            with queued.result(timeout=10) as connection:
                connection.settimeout(10); http(connection, old_body if args.nginx_overlap_abort else new_body, True)
        http(held, old_body); record('OLD_KEEPALIVE_SURVIVED')
        if stream_probe is not None:
            command('STREAMS0')
        if args.nginx_overlap_abort:
            stop_nginx(new, new_fd, 'new'); command('CLOSED1')
            require(old.poll() is None and not select.select([old_fd], [], [], 0)[0],
                'old Nginx did not survive candidate retirement')
            command('EARLY_RETIRE')
            http(held, old_body); record('OLD_KEEPALIVE_AFTER_CANDIDATE_EXIT')
            fresh(old_body); record('OLD_HTTP_AFTER_CANDIDATE_EXIT')
            if stream_probe is not None:
                require(stream_probe.poll() is None, 'source probe did not survive candidate abort')
                record('SOURCE_PROBE_ALIVE_AFTER_CANDIDATE_EXIT', elapsed=time.monotonic() - stream_started)
            held.close(); held = None
        else:
            held.close(); held = None
            if stream_probe is not None:
                record('OLD_NGINX_DRAIN_BEGIN')
            stop_nginx(old, old_fd, 'old')
            if stream_probe is not None:
                require(stream_probe.poll() is None, 'source probe did not survive old-owner drain')
                record('SOURCE_PROBE_ALIVE_AFTER_OLD_EXIT', elapsed=time.monotonic() - stream_started)
            if held_alias is not None:
                command('ALIAS_RETIRE')
                os.close(held_alias); held_alias = None
                record('INITIAL_MEMBER_ALIAS_CLOSED')
            command('RETIRE0'); command('CLOSED0')
            fresh(new_body); record('NEW_HTTP_AFTER_OLD_EXIT')
        if stream_probe is not None:
            stream_probe.wait(timeout=max(.1, 300 - (time.monotonic() - stream_started)))
            stream_output.flush()
            text = stream_file.read_text()
            evidence['source_stream'].update(returncode=stream_probe.returncode, output=text)
            require(stream_probe.returncode == 0, 'original source stream probe failed: ' + text)
            checker_file = probe_file.parent.parent / 'reload_checks.py'
            check_spec = importlib.util.spec_from_file_location('nginx_overlap_source_checks', checker_file)
            checker = importlib.util.module_from_spec(check_spec); check_spec.loader.exec_module(checker)
            fields = checker.summary('stream', text)
            # Qualify both pre-cutover and post-retirement waves, independently
            # of the source summary's aggregate complete-response counters.
            rows = [re.fullmatch(r'STREAM wid=(\d+) wave=(\d+) bytes=(\d+) md5=([0-9a-f]+) '
                r'md5_ok=1 eof_clean=1 start=([0-9.]+) end=([0-9.]+)', line)
                for line in text.splitlines() if line.startswith('STREAM ')]
            require(rows and all(rows), 'incomplete source stream response evidence')
            cutover_at = next(e['monotonic_ns'] / 1e9 for e in evidence['events']
                if e['event'] == 'CUTOVER_PREPARED') - stream_started
            retired_at = next(e['monotonic_ns'] / 1e9 for e in evidence['events']
                if e['event'] == ('NEW_NGINX_RETIRED' if args.nginx_overlap_abort else 'OLD_NGINX_RETIRED')) - stream_started
            require({int(row[1]) for row in rows if float(row[5]) < cutover_at < float(row[6])}
                == set(range(12)), 'not all source workers crossed cutover in-flight')
            require({int(row[1]) for row in rows if float(row[6]) > retired_at and int(row[2]) >= 2}
                == set(range(12)), 'source workers did not continue past retired owner')
            require(all(int(row[3]) == len(stream_payload) for row in rows), 'source payload length changed')
            evidence['source_stream']['summary'] = fields
            record('ORIGINAL_STREAM_ORACLE_PASS', streams=int(fields['streams']),
                elapsed=time.monotonic() - stream_started)
        if args.nginx_overlap_abort:
            fresh(old_body)
            stop_nginx(old, old_fd, 'old')
            for cap in caps: os.close(cap)
            caps.clear()
            command('RELEASE'); command('CLOSED0')
        else:
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
        if not args.nginx_overlap_abort:
            require('private candidate admission: allowed=1 created=1' in
                evidence['logs']['new']['error_log'], 'new Nginx did not consume original-map admission')
        print('NGINX_OVERLAP_PASS outcome=' + evidence['outcome'] +
            ' queued_syn=true old_keepalive=true old_exit=true outstanding=0')
        return 0
    except BaseException as error:
        evidence.update(status='FAIL', error=repr(error))
        raise
    finally:
        if stream_probe is not None and stream_probe.poll() is None:
            try: os.killpg(stream_probe.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            stream_probe.wait()
        if stream_output is not None:
            stream_output.close()
            evidence.setdefault('source_stream', {}).update(
                returncode=stream_probe.returncode if stream_probe is not None else None,
                output=(root / 'source-stream.log').read_text(errors='replace'))
        if held is not None: held.close()
        if held_alias is not None: os.close(held_alias)
        if alias_listener is not None: alias_listener.close()
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
