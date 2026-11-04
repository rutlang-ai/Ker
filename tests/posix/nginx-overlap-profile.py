"""Explicit real Nginx callers over original-Linux staged owner groups."""
import array
import errno
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
import threading

ROOT = Path(__file__).resolve().parents[2]


def require(value, message):
    if not value:
        raise RuntimeError(message)


def validate_source_lc(checker, text, returncode, abort):
    # The original shell's perf LC case judges bounded old-connection closures
    # with its summary oracle even when the probe's strict verdict returns 1.
    require(returncode == 0 if abort else returncode in (0, 1),
        f'original LC probe exited unexpectedly: {returncode}')
    return checker.summary('lc', text, '' if abort else 'perf')


def run(args, rpc_path, stop_path, stats, root, broker, environment, wait_line):
    transfer, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    controller = None
    processes, caps, pidfds = [], [], []
    held = None
    held_alias = None
    alias_listener = None
    evidence = {'status': 'RUNNING', 'outcome': 'abort-retry-commit' if args.nginx_overlap_retry else 'abort' if args.nginx_overlap_abort else 'commit', 'events': []}
    source_probe = None
    source_output = None
    source_started = None
    source_key = 'source_lc' if args.nginx_overlap_source_lc else 'source_stream'
    source_log_name = 'source-lc.log' if args.nginx_overlap_source_lc else 'source-stream.log'
    source_budget = 240 if args.nginx_overlap_source_lc else 300
    census_command = 'ACTIVE0' if args.nginx_overlap_source_lc else 'STREAMS0'
    stream_payload = bytes(8 * 1024 * 1024) if args.nginx_overlap_source_streams else None

    broker_logs = {name: root / ('broker-' + name + '.log') for name in ('stdout', 'stderr')}
    broker_readers = []

    def capture_broker(pipe, path, initial):
        with path.open('wb') as output:
            output.write(initial)
            while True:
                data = os.read(pipe.fileno(), 65536)
                if not data: break
                output.write(data)
                output.flush()

    for name in ('stdout', 'stderr'):
        initial = b''
        if name == 'stdout':
            initial = ('\n'.join(getattr(broker, '_ker_recent_lines', [])) + '\n').encode()
            initial += bytes(getattr(broker, '_ker_line_buffer', b''))
        reader = threading.Thread(target=capture_broker,
            args=(getattr(broker, name), broker_logs[name], initial), daemon=True)
        reader.start(); broker_readers.append(reader)

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
        export_alias = args.nginx_overlap_alias_regression and (
            label == 'new' if (args.nginx_overlap_successor or args.nginx_overlap_retry) else not candidate)
        if export_alias:
            module = args.nginx_overlap_alias_module
        config.write_text(f'''load_module {module};
daemon off; master_process on; worker_processes 1; {user_directive}
fstack_conf "fstack.ini"; timer_resolution 1ms;
pid {prefix}/logs/nginx.pid; error_log {prefix}/logs/error.log notice;
env LD_PRELOAD; env KER_SOCKET_BROKER_PATH; env KER_FSTACK_NGINX_INI;
env KER_FSTACK_RUNTIME_TRACE; env KER_NGINX_TEST_INITIAL_ALIAS_SOCKET;
env KER_NGINX_TEST_REARM_TRIGGER;
events {{ worker_connections 256; use epoll; }}
http {{ access_log off; sendfile off; keepalive_timeout 300; keepalive_requests 100000;
server {{ listen 198.18.0.2:4108 reuseport backlog=16; root {prefix}/html; index index.html; }} }}
''')
        trace = prefix / 'runtime.trace'
        env = environment | {'LD_PRELOAD': ':'.join(map(str, [args.nginx_candidate_shim,
            args.nginx_candidate_runtime, args.preload])), 'KER_FSTACK_NGINX_INI': str(ini),
            'KER_FSTACK_RUNTIME_TRACE': str(trace),
            ('KER_NGINX_CANDIDATE_SLOT_FD' if candidate else 'KER_NGINX_INITIAL_SLOT_FD'): str(slot)}
        if export_alias:
            env['KER_NGINX_TEST_INITIAL_ALIAS_SOCKET'] = str(root / 'initial-alias.sock')
            if args.nginx_overlap_successor or args.nginx_overlap_retry:
                env['KER_NGINX_TEST_REARM_TRIGGER'] = str(root / 'rearm.trigger')
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

    def receive_candidate_slot():
        message, ancillary, flags, _ = transfer.recvmsg(1, socket.CMSG_SPACE(4))
        delegated = []
        for level, kind, data in ancillary:
            require(level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS,
                'unexpected candidate authority')
            values = array.array('i'); values.frombytes(data); delegated.extend(values)
        caps.extend(delegated)
        require(message == b'N' and not flags and len(delegated) == 1,
            'plan must delegate only one candidate slot')
        return delegated[0]

    def receive_alias():
        nonlocal held_alias
        alias_channel, _ = alias_listener.accept()
        message, ancillary, flags, _ = alias_channel.recvmsg(1, socket.CMSG_SPACE(4))
        alias_channel.close()
        for level, kind, data in ancillary:
            require(level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS,
                'member alias transfer used unexpected authority')
            values = array.array('i'); values.frombytes(data)
            require(len(values) == 1 and held_alias is None, 'expected one member alias')
            held_alias = values[0]
        require(message == b'A' and not flags and held_alias is not None,
            'Nginx owner did not export its live member alias')
        record('PREDECESSOR_MEMBER_ALIAS_HELD' if (args.nginx_overlap_successor or args.nginx_overlap_retry) else 'INITIAL_MEMBER_ALIAS_HELD_BY_COORDINATOR')

    def stop_nginx(process, worker_fd, label):
        process.send_signal(signal.SIGQUIT)
        _, errors = process.communicate(timeout=80 if source_probe is not None else 20)
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
        if alias_listener is not None and not (args.nginx_overlap_successor or args.nginx_overlap_retry):
            receive_alias()
        command('CONTROL'); command('CENSUS0')
        if args.nginx_overlap_successor:
            command('EARLY_NEXT'); command('WRONG_NEXT')
        if args.nginx_overlap_retry:
            command('EARLY_RETRY'); command('WRONG_RETRY')
        held = socket.create_connection(('198.18.0.2', 4108), timeout=10)
        held.settimeout(10); http(held, old_body)
        if args.nginx_overlap_source_streams or args.nginx_overlap_source_lc:
            source_file = root / source_log_name
            source_output = source_file.open('w')
            source_script = probe_file.with_name('m4_lc.py' if args.nginx_overlap_source_lc else 'm4_stream.py')
            if args.nginx_overlap_source_lc:
                source_command = [sys.executable, str(source_script),
                    '--server', '198.18.0.2', '--port', '4108', '--conns', '12',
                    '--interval', '0.1', '--duration', '180', '--fresh', '0.5', '--timeout', '2']
            else:
                source_command = [sys.executable, str(source_script),
                    '--server', '198.18.0.2', '--port', '4108', '--path', '/dl/big.bin',
                    '--streams', '12', '--chunk', '16384', '--gap', '0.1',
                    '--timeout', '5', '--stall', '3.0', '--duration', '120',
                    '--expect-md5', hashlib.md5(stream_payload).hexdigest()]
            # A host TCP client: no FF runtime, preload or broker authority.
            source_environment = os.environ.copy()
            source_environment.pop('LD_PRELOAD', None)
            source_environment['PYTHONDONTWRITEBYTECODE'] = '1'
            source_started = time.monotonic()
            source_probe = subprocess.Popen(source_command, stdout=source_output,
                stderr=subprocess.STDOUT, env=source_environment, start_new_session=True)
            evidence[source_key] = {'command': source_command,
                'source_hashes': {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in (probe_file, source_script,
                        probe_file.parent.parent / 'reload_checks.py')}}
            if args.nginx_overlap_source_lc:
                deadline = time.monotonic() + 60
                while True:
                    require(source_probe.poll() is None, 'LC probe exited before progress anchor')
                    rows = list(re.finditer(r'^LC_PROGRESS elapsed=([0-9.]+) n=(\d+) fail=(\d+)$',
                        source_file.read_text(), re.MULTILINE))
                    anchor = next((row for row in rows if float(row[1]) >= 3 and int(row[2]) >= 200), None)
                    if anchor is not None:
                        require(int(anchor[3]) == 0, 'LC failures before cutover')
                        evidence[source_key]['anchor'] = anchor[0]
                        record('ORIGINAL_LC_PROGRESS_ANCHOR', line=anchor[0])
                        break
                    require(time.monotonic() < deadline, 'LC source progress anchor timed out')
                    time.sleep(.01)
                command(census_command)
                record('LC_OLD_OWNER_CENSUS_CONFIRMED')
            else:
                # Preserve the original shell's three-second pre-handoff interval,
                # and additionally prove all twelve streams reached old Linux.
                while time.monotonic() - source_started < 3:
                    require(source_probe.poll() is None, 'source stream probe exited before handoff')
                    time.sleep(.01)
                command(census_command)
                record('TWELVE_SOURCE_STREAMS_ON_OLD_OWNER', elapsed=time.monotonic() - source_started)
        new, new_body, new_prefix, new_fd = start_nginx('new', caps[1], True)
        if alias_listener is not None and (args.nginx_overlap_successor or args.nginx_overlap_retry):
            receive_alias()
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
                command('ABORT'); command('ABORT_NEXT'); command('EARLY_RETIRE'); record('CUTOVER_ABORTED_WITH_QUEUED_SYN')
            else:
                command('COMMIT'); command('EARLY_RETIRE')
                if args.nginx_overlap_successor: command('EARLY_NEXT')
                record('CUTOVER_COMMITTED_WITH_QUEUED_SYN')
            with queued.result(timeout=10) as connection:
                connection.settimeout(10); http(connection, old_body if args.nginx_overlap_abort else new_body, True)
        http(held, old_body); record('OLD_KEEPALIVE_SURVIVED')
        if source_probe is not None:
            command(census_command)
        if args.nginx_overlap_retry:
            command('RETRY')
            cookies = [re.search(r'SUCCESSOR_COOKIE preserved=(\d+)', line)
                for line in getattr(controller, '_ker_recent_lines', [])]
            preserved = [int(match[1]) for match in cookies if match]
            require(len(preserved) == 1 and preserved[0], 'missing exact retry-listener cookie proof')
            record('ABORT_RETRY_PLAN_ADOPTED_INITIAL_LISTENER', cookie=preserved[0])
            http(held, old_body); fresh(old_body)
            command('RETRY_SLOT_BLOCKED')
            record('LIVE_REJECTED_CANDIDATE_BLOCKED_NEW_SLOT')
            if held_alias is not None:
                (root / 'rearm.trigger').touch()
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    text = (new_prefix / 'runtime.trace').read_text()
                    if f'NGINX_TEST_REARM_SEALED result=-1 error={errno.EOPNOTSUPP}' in text: break
                    time.sleep(.01)
                else: raise RuntimeError('aborted candidate REARM was not sealed: ' + text)
                record('ABORTED_CANDIDATE_REARM_REJECTED')
            stop_nginx(new, new_fd, 'new')
            if held_alias is not None:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if 'listener-ref-put-at-task-release' in broker_logs['stdout'].read_text(): break
                    time.sleep(.001)
                else: raise RuntimeError('aborted task did not release its listener reference')
                command('RETRY_SLOT_BLOCKED')
                record('DEAD_REJECTED_CANDIDATE_ALIAS_BLOCKED_NEW_SLOT')
                http(held, old_body); fresh(old_body)
                os.close(held_alias); held_alias = None
            command('RETRY_SLOT'); command('CLOSED_REJECTED')
            retry_slot = receive_candidate_slot()
            retry, retry_body, retry_prefix, retry_fd = start_nginx('retry', retry_slot, True)
            command('CENSUS1'); command('OLD_CAPS'); fresh(old_body)
            command('BEGIN'); record('RETRY_CUTOVER_PREPARED')
            with ThreadPoolExecutor(max_workers=1) as executor:
                queued = executor.submit(socket.create_connection, ('198.18.0.2', 4108), 10)
                command('QUEUED')
                require(not queued.done(), 'retry queued SYN completed before commit')
                command('COMMIT'); command('COMMITTED_RETRY')
                record('RETRY_CUTOVER_COMMITTED_WITH_QUEUED_SYN')
                with queued.result(timeout=10) as connection:
                    connection.settimeout(10); http(connection, retry_body, True)
            command('OLD_CAPS'); fresh(retry_body)
            record('ABORTED_CAPABILITIES_CANNOT_REDIRECT_RETRY')
            command('DROP_PARENT')
            for cap in caps[:2]: os.close(cap)
            del caps[:2]
            http(held, old_body); record('OLD_KEEPALIVE_SURVIVED_ABORT_AND_RETRY_COMMIT')
            held.close(); held = None
            stop_nginx(old, old_fd, 'old')
            command('RETIRE0'); command('CLOSED0')
            fresh(retry_body); record('RETRY_HTTP_AFTER_INITIAL_OWNER_EXIT')
            new, new_body, new_prefix, new_fd = retry, retry_body, retry_prefix, retry_fd
        elif args.nginx_overlap_abort:
            stop_nginx(new, new_fd, 'new'); command('CLOSED1'); command('DEAD_RETRY')
            require(old.poll() is None and not select.select([old_fd], [], [], 0)[0],
                'old Nginx did not survive candidate retirement')
            command('EARLY_RETIRE')
            http(held, old_body); record('OLD_KEEPALIVE_AFTER_CANDIDATE_EXIT')
            fresh(old_body); record('OLD_HTTP_AFTER_CANDIDATE_EXIT')
            if source_probe is not None:
                require(source_probe.poll() is None, 'source probe did not survive candidate abort')
                record('SOURCE_PROBE_ALIVE_AFTER_CANDIDATE_EXIT', elapsed=time.monotonic() - source_started)
            held.close(); held = None
        else:
            held.close(); held = None
            if source_probe is not None:
                record('OLD_NGINX_DRAIN_BEGIN')
            stop_nginx(old, old_fd, 'old')
            if source_probe is not None:
                require(source_probe.poll() is None, 'source probe did not survive old-owner drain')
                record('SOURCE_PROBE_ALIVE_AFTER_OLD_EXIT', elapsed=time.monotonic() - source_started)
            if held_alias is not None and not args.nginx_overlap_successor:
                command('ALIAS_RETIRE')
                os.close(held_alias); held_alias = None
                record('INITIAL_MEMBER_ALIAS_CLOSED')
            command('RETIRE0'); command('CLOSED0')
            fresh(new_body); record('NEW_HTTP_AFTER_OLD_EXIT')
            if args.nginx_overlap_successor:
                held = socket.create_connection(('198.18.0.2', 4108), timeout=10)
                held.settimeout(10); http(held, new_body)
                command('NEXT')
                delegated_slot = receive_candidate_slot()
                cookies = [re.search(r'SUCCESSOR_COOKIE preserved=(\d+)', line)
                    for line in getattr(controller, '_ker_recent_lines', [])]
                preserved = [int(match[1]) for match in cookies if match]
                require(len(preserved) == 1 and preserved[0], 'missing exact adopted-listener cookie proof')
                record('SUCCESSOR_ADOPTED_SAME_LISTENER', cookie=preserved[0])
                http(held, new_body); fresh(new_body)
                if held_alias is not None:
                    (root / 'rearm.trigger').touch()
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline:
                        text = (new_prefix / 'runtime.trace').read_text()
                        if f'NGINX_TEST_REARM_SEALED result=-1 error={errno.EOPNOTSUPP}' in text: break
                        time.sleep(.01)
                    else: raise RuntimeError('predecessor REARM was not permanently sealed: ' + text)
                    record('PREDECESSOR_REARM_REJECTED')
                third, third_body, third_prefix, third_fd = start_nginx('next', delegated_slot, True)
                command('CENSUS1'); command('OLD_CAPS'); fresh(new_body)
                record('OLD_CAPABILITIES_CANNOT_CHANGE_SUCCESSOR_SELECTOR')
                command('DROP_PARENT')
                for cap in caps[:2]: os.close(cap)
                del caps[:2]
                command('BEGIN'); record('SECOND_CUTOVER_PREPARED')
                with ThreadPoolExecutor(max_workers=1) as executor:
                    queued = executor.submit(socket.create_connection, ('198.18.0.2', 4108), 10)
                    command('QUEUED')
                    require(not queued.done(), 'second queued SYN completed before commit')
                    command('COMMIT'); record('SECOND_CUTOVER_COMMITTED_WITH_QUEUED_SYN')
                    with queued.result(timeout=10) as connection:
                        connection.settimeout(10); http(connection, third_body, True)
                http(held, new_body); record('PREDECESSOR_KEEPALIVE_SURVIVED_SECOND_COMMIT')
                held.close(); held = None
                stop_nginx(new, new_fd, 'new')
                if held_alias is not None:
                    # Wait for the predecessor task's independent ker_fd pin to
                    # be released. Its transient EBUSY must not mask an alias bug.
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline:
                        if 'listener-ref-put-at-task-release' in broker_logs['stdout'].read_text(): break
                        time.sleep(.001)
                    else: raise RuntimeError('predecessor task did not release its listener reference')
                    command('ALIAS_RETIRE')
                    record('PREDECESSOR_ALIAS_BLOCKED_SUCCESSOR_RETIREMENT')
                    os.close(held_alias); held_alias = None
                command('RETIRE0'); command('CLOSED0')
                fresh(third_body); record('THIRD_HTTP_AFTER_PREDECESSOR_EXIT')
                new, new_body, new_prefix, new_fd = third, third_body, third_prefix, third_fd
        if source_probe is not None:
            source_probe.wait(timeout=max(.1, source_budget - (time.monotonic() - source_started)))
            source_output.flush()
            text = source_file.read_text()
            evidence[source_key].update(returncode=source_probe.returncode, output=text)
            checker_file = probe_file.parent.parent / 'reload_checks.py'
            check_spec = importlib.util.spec_from_file_location('nginx_overlap_source_checks', checker_file)
            checker = importlib.util.module_from_spec(check_spec); check_spec.loader.exec_module(checker)
            if args.nginx_overlap_source_lc:
                fields = validate_source_lc(checker, text, source_probe.returncode, args.nginx_overlap_abort)
                retired_at = next(e['monotonic_ns'] / 1e9 for e in evidence['events']
                    if e['event'] == ('NEW_NGINX_RETIRED' if args.nginx_overlap_abort else 'OLD_NGINX_RETIRED')) - source_started
                progress = list(re.finditer(r'^LC_PROGRESS elapsed=([0-9.]+) n=(\d+) fail=(\d+)$', text, re.MULTILINE))
                anchor_count = int(evidence[source_key]['anchor'].split('n=')[1].split()[0])
                later = next((row for row in progress if float(row[1]) > retired_at + 1 and int(row[2]) > anchor_count), None)
                require(later is not None, 'LC requests did not progress after owner retirement')
                evidence[source_key].update(summary=fields, oracle_mode='' if args.nginx_overlap_abort else 'perf',
                    post_retirement_progress=later[0])
                record('ORIGINAL_LC_ORACLE_PASS', reqs=int(fields['reqs']), fresh_n=int(fields['fresh_n']),
                    strict_probe_returncode=source_probe.returncode, elapsed=time.monotonic() - source_started)
            else:
                require(source_probe.returncode == 0, 'original source stream probe failed: ' + text)
                fields = checker.summary('stream', text)
                # Qualify both pre-cutover and post-retirement waves, independently
                # of the source summary's aggregate complete-response counters.
                rows = [re.fullmatch(r'STREAM wid=(\d+) wave=(\d+) bytes=(\d+) md5=([0-9a-f]+) '
                    r'md5_ok=1 eof_clean=1 start=([0-9.]+) end=([0-9.]+)', line)
                    for line in text.splitlines() if line.startswith('STREAM ')]
                require(rows and all(rows), 'incomplete source stream response evidence')
                cutover_at = next(e['monotonic_ns'] / 1e9 for e in evidence['events']
                    if e['event'] == 'CUTOVER_PREPARED') - source_started
                retired_at = next(e['monotonic_ns'] / 1e9 for e in evidence['events']
                    if e['event'] == ('NEW_NGINX_RETIRED' if args.nginx_overlap_abort else 'OLD_NGINX_RETIRED')) - source_started
                require({int(row[1]) for row in rows if float(row[5]) < cutover_at < float(row[6])}
                    == set(range(12)), 'not all source workers crossed cutover in-flight')
                require({int(row[1]) for row in rows if float(row[6]) > retired_at and int(row[2]) >= 2}
                    == set(range(12)), 'source workers did not continue past retired owner')
                require(all(int(row[3]) == len(stream_payload) for row in rows), 'source payload length changed')
                evidence[source_key]['summary'] = fields
                record('ORIGINAL_STREAM_ORACLE_PASS', streams=int(fields['streams']),
                    elapsed=time.monotonic() - source_started)
        if args.nginx_overlap_retry:
            stop_nginx(new, new_fd, 'retry'); command('CLOSED1')
        elif args.nginx_overlap_abort:
            fresh(old_body)
            stop_nginx(old, old_fd, 'old')
            for cap in caps: os.close(cap)
            caps.clear()
            command('RELEASE'); command('CLOSED0')
        else:
            stop_nginx(new, new_fd, 'next' if args.nginx_overlap_successor else 'new'); command('CLOSED1')
        command_text = b'STOP\n'; controller.stdin.write(command_text); controller.stdin.flush()
        _, errors = controller.communicate(timeout=10)
        require(controller.returncode == 0, f'coordinator cleanup failed: {errors!r}')
        for cap in caps: os.close(cap)
        caps.clear()
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as stop:
            stop.sendto(b'STOP', str(stop_path))
        broker.wait(timeout=35)
        for reader in broker_readers: reader.join(timeout=2)
        require(all(not reader.is_alive() for reader in broker_readers),
            'broker output remained open after process exit')
        errors = broker_logs['stderr'].read_text(errors='replace')
        report = json.loads(stats.read_text())
        require(broker.returncode == 0 and report.get('outstanding') == 0,
            f'broker did not settle: {errors!r}; {report!r}')
        record('BROKER_SETTLED')
        evidence.update(status='PASS', stats=report, logs={
            label: {'trace': (prefix / 'runtime.trace').read_text(),
                'error_log': (prefix / 'logs/error.log').read_text()}
            for label in ('old', 'new', 'next', 'retry') if (prefix := root / label).exists()})
        if not args.nginx_overlap_abort:
            for label in (('new', 'next') if args.nginx_overlap_successor else ('new',)):
                require('private candidate admission: allowed=1 created=1' in
                    evidence['logs'][label]['error_log'],
                    label + ' Nginx did not consume original-map admission')
        if args.nginx_overlap_retry:
            require('private candidate admission: allowed=1 created=1' in
                evidence['logs']['retry']['error_log'], 'retry owner did not consume original-map admission')
        print('NGINX_OVERLAP_PASS outcome=' + evidence['outcome'] +
            ' successor=' + str(args.nginx_overlap_successor).lower() +
            ' retry=' + str(args.nginx_overlap_retry).lower() +
            ' queued_syn=true old_keepalive=true old_exit=true outstanding=0')
        return 0
    except BaseException as error:
        evidence.update(status='FAIL', error=repr(error))
        raise
    finally:
        if source_probe is not None and source_probe.poll() is None:
            try: os.killpg(source_probe.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            source_probe.wait()
        if source_output is not None:
            source_output.close()
            evidence.setdefault(source_key, {}).update(
                returncode=source_probe.returncode if source_probe is not None else None,
                output=(root / source_log_name).read_text(errors='replace'))
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
                broker.wait(timeout=35)
            except (OSError, subprocess.TimeoutExpired):
                broker.kill(); broker.wait()
        for reader in broker_readers: reader.join(timeout=2)
        evidence['controller_log'] = getattr(controller, '_ker_recent_lines', []) if controller is not None else []
        evidence['broker_logs'] = {name: path.read_text(errors='replace') for name, path in broker_logs.items()}
        evidence['logs'] = {
            label: {name: path.read_text(errors='replace')
                for name, path in [('trace', root / label / 'runtime.trace'),
                    ('error_log', root / label / 'logs/error.log')] if path.exists()}
            for label in ('old', 'new', 'next', 'retry')}
        if args.nginx_candidate_evidence:
            args.nginx_candidate_evidence.parent.mkdir(parents=True, exist_ok=True)
            args.nginx_candidate_evidence.write_text(json.dumps(evidence, indent=2) + '\n')
