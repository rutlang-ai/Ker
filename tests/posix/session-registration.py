#!/usr/bin/env python3
"""Real resident EAL registration; no PMD, packet landing or reload pass claim."""
import argparse
import ctypes
import errno
import importlib.util
import json
import os
import re
import stat
from pathlib import Path
import selectors
import signal
import socket
import subprocess
import sys
import tempfile
import time

from hugepage_preflight import hugepage_capacity_error


def require(value, message):
    if not value:
        raise RuntimeError(message)


def ready(process, prefix):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        require(selector.select(30), 'session readiness timed out')
    line = process.stdout.readline().decode().strip()
    if not line:
        try:
            _output, errors = process.communicate(timeout=2)
            line = 'process exited ' + str(process.returncode) + ': ' + errors.decode(errors='replace')
        except subprocess.TimeoutExpired:
            line = 'stdout closed while process remains alive; stderr pending'
    require(line.startswith(prefix + ' '), 'unexpected readiness: ' + line)
    return json.loads(line[len(prefix) + 1:])


def child_reap(output, expected_pid, input_abandoned=False):
    records = [line.removeprefix(b'KER_SESSION_CHILD_REAP ').decode()
        for line in output.splitlines() if line.startswith(b'KER_SESSION_CHILD_REAP ')]
    require(len(records) == 1, 'expected exactly one exact child reap record: ' + repr(output))
    record = json.loads(records[0])
    require(record.get('pid') == expected_pid and record.get('status') == 0 and
            record.get('escalated') is False and
            isinstance(record.get('input_abandoned'), bool) and
            (input_abandoned is None or record['input_abandoned'] is input_abandoned),
            'child reap record did not confirm successful exact child exit: ' + repr(record))
    return record


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', type=Path, required=True)
    parser.add_argument('--tool', type=Path, required=True)
    parser.add_argument('--huge-dir', type=Path, default=Path('/dev/hugepages'))
    args = parser.parse_args()
    reason = hugepage_capacity_error(args.huge_dir, 64 * 1024 * 1024)
    if reason:
        print('SKIP: ' + reason + '; no host settings changed')
        return 77
    spec = importlib.util.spec_from_file_location('ker_session_tool', args.tool)
    api = importlib.util.module_from_spec(spec); spec.loader.exec_module(api)
    # Reap exact orphan workers after killing their own test master.
    require(ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0, 'subreaper setup failed')
    processes, worker_pidfds = [], []
    run_id = f'{os.getpid()}-{os.urandom(6).hex()}'
    owned_pages = {}

    def record_pages(prefix):
        # DPDK's original hugepage backing-file names include the exact EAL
        # file prefix. Record identity before the intentional failed shutdown.
        pattern = re.compile(re.escape(prefix) + r'map_[0-9]+(?:_[0-9]+)?')
        for path in args.huge_dir.iterdir():
            if pattern.fullmatch(path.name):
                value = path.lstat()
                require(stat.S_ISREG(value.st_mode) and value.st_uid == os.getuid(),
                        'unexpected hugepage file identity')
                owned_pages[path] = (value.st_dev, value.st_ino, value.st_uid)
    with tempfile.TemporaryDirectory(prefix='ker-session-') as name:
        root = Path(name); path = root / 'control.sock'
        environment = dict(os.environ, RUNTIME_DIRECTORY=str(root))
        eal = (f'--lcores=0@{min(os.sched_getaffinity(0))} --no-pci --no-telemetry '
               f'--iova-mode=va -m 64 --huge-dir={args.huge_dir} --file-prefix=session-{run_id}')
        common = ['--socket', str(path), '--worker', str(args.worker), '--eal', eal]
        primary = subprocess.Popen([sys.executable, str(args.tool), 'serve', *common],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=environment, bufsize=0)
        processes.append(primary)
        try:
            info = ready(primary, 'KER_SESSION_READY')
            record_pages('session-' + run_id)
            require(info['rings'] == 128 and info['slots'] == 4 and info['stage'] == 'shared-control',
                    'finite geometry was not completely precreated')

            def status():
                connection = api.Connection(path)
                try:
                    return connection.request(api.STATUS)
                finally:
                    connection.close()

            def eventually(epochs, users):
                deadline = time.monotonic() + 10
                while True:
                    value = status()
                    if value['slot'] == epochs and value['process'] == users:
                        return value
                    require(time.monotonic() < deadline, 'session census did not converge: ' + str(value))
                    time.sleep(0.05)

            require(eventually(0, 0)['session'] == info['session'], 'session identity mismatch')
            master = api.Connection(path)
            ticket = master.request(api.MASTER)
            # An exact repeated operation returns its original result, rather
            # than allocating another epoch. A same-id changed body is rejected.
            master.socket.sendall(api.encode(api.packet(api.MASTER)))
            replay = dict(zip(api.FIELDS, api.WIRE.unpack(master.socket.recv(api.WIRE.size))))
            require(replay == ticket, 'master registration retry was not idempotent')
            master.socket.sendall(api.encode(api.packet(api.STATUS)))
            changed = dict(zip(api.FIELDS, api.WIRE.unpack(master.socket.recv(api.WIRE.size))))
            require(changed['status'] == -errno.EPROTO, 'changed request reused a sequence')
            coordinate = dict(session=ticket['session'], epoch=ticket['epoch'],
                              token=ticket['token'], slot=ticket['slot'])
            try:
                master.request(api.RELEASE, **dict(coordinate, session=ticket['session'] ^ 1))
                raise RuntimeError('foreign session was accepted')
            except OSError as error:
                require(error.errno == errno.ESTALE, 'wrong stale-session error')
            stranger = api.Connection(path)
            try:
                try:
                    stranger.request(api.RESERVE, **coordinate)
                    raise RuntimeError('a non-child registered against another master')
                except OSError as error:
                    require(error.errno == errno.ESTALE, 'wrong parent-identity error')
            finally:
                stranger.close()

            def direct_worker(extra_eal=()):
                read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
                try:
                    child = subprocess.Popen([str(args.worker), '--role', 'secondary', '--socket', str(path),
                        '--control-fd', '0', '--ticket-fd', str(read_fd), '--generation', '0', '--process', '0',
                        '--', *api.role_arguments(eal, 'secondary'), *extra_eal], pass_fds=(read_fd,),
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        env=environment, bufsize=0)
                    processes.append(child)
                    require(os.write(write_fd, api.encode(ticket)) == api.WIRE.size, 'short ticket')
                    return child
                finally:
                    os.close(read_fd); os.close(write_fd)

            child = direct_worker()
            ready(child, 'KER_SESSION_ATTACHED')
            eventually(1, 1)
            try:
                master.request(api.RELEASE, **coordinate)
                raise RuntimeError('live EAL borrower did not block slot release')
            except OSError as error:
                require(error.errno == errno.EBUSY, 'wrong live-borrower error')
            duplicate = direct_worker()
            output, errors = duplicate.communicate(timeout=20)
            require(duplicate.returncode == 1 and b'ker session reserve: -16' in errors and
                    b'KER_SESSION_ATTACHED' not in output, 'duplicate queue coordinate was admitted')
            child.stdin.write(b'x'); child.stdin.flush()
            child.communicate(timeout=20)
            require(child.returncode == 0, 'valid secondary did not cleanly detach')
            eventually(1, 0)
            failed = direct_worker(['--ker-invalid-eal-option'])
            output, errors = failed.communicate(timeout=20)
            require(failed.returncode != 0 and b'KER_SESSION_ATTACHED' not in output,
                    'invalid original EAL reached attachment')
            eventually(1, 0)
            master.request(api.RELEASE, **coordinate); master.close()
            eventually(0, 0)

            def redirected_stdin(label, source, input_abandoned=False):
                lease = subprocess.Popen([sys.executable, str(args.tool), 'lease', *common],
                    stdin=source, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    env=environment, bufsize=0)
                processes.append(lease)
                entry = ready(lease, 'KER_SESSION_ATTACHED')
                try:
                    pidfd = os.pidfd_open(entry['pid'])
                except ProcessLookupError:
                    pidfd = None
                try:
                    output, errors = lease.communicate(timeout=20)
                    require(lease.returncode == 0,
                            label + ' lease did not exit normally: ' + errors.decode() + output.decode())
                    child_reap(output, entry['pid'], input_abandoned)
                    if pidfd is not None:
                        with selectors.PollSelector() as selector:
                            selector.register(pidfd, selectors.EVENT_READ)
                            require(selector.select(5), label + ' left its exact EAL secondary alive')
                finally:
                    if pidfd is not None:
                        os.close(pidfd)
                after = eventually(0, 0)
                require(after['slot'] == 0 and after['epoch'] > entry['epoch'],
                        label + ' did not release and advance its exact lease epoch')
                print('PASS: ' + label + ' actual EAL secondary cleanup and lease release')

            redirected_stdin('/dev/null', subprocess.DEVNULL)
            empty_stdin = root / 'stdin-empty'
            empty_stdin.write_bytes(b'')
            with empty_stdin.open('rb') as source:
                redirected_stdin('empty regular-file stdin', source)
            binary_stdin = root / 'stdin-binary'
            binary_stdin.write_bytes(b'\x00\xff\ncontrol\x80\x00')
            with binary_stdin.open('rb') as source:
                redirected_stdin('binary regular-file stdin', source)
            large_stdin = root / 'stdin-large'
            large_stdin.write_bytes(bytes(index % 251 for index in range(1024 * 1024)))
            with large_stdin.open('rb') as source:
                redirected_stdin('1 MiB regular-file stdin', source, input_abandoned=None)

            leases, entries = [], []
            for gen, process_id in ((0, 0), (1, 3), (0, 0)):
                lease = subprocess.Popen([sys.executable, str(args.tool), 'lease', *common,
                    '--generation', str(gen), '--process', str(process_id), '--probe-count', '16'], stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, bufsize=0)
                processes.append(lease); leases.append(lease)
                entry = ready(lease, 'KER_SESSION_ATTACHED'); entries.append(entry)
                worker_pidfds.append(os.pidfd_open(entry['pid']))
            require(len({x['epoch'] for x in entries}) == 3 and len({x['slot'] for x in entries}) == 3,
                    'live masters shared an epoch slot')
            require(len({x['rings'][0] for x in entries}) == 3, 'masters looked up the same control ring')
            require(all(p.poll() is None for p in leases), 'master exited before simultaneous samples')
            eventually(3, 3)
            # All three masters and workers are alive before any shared mbuf probe.
            for lease in leases:
                lease.stdin.write(b'P'); lease.stdin.flush()
            for lease, entry in zip(leases, entries):
                reply = ready(lease, 'KER_SESSION_PROBED')
                require(all(reply[key] == entry[key] for key in ('epoch', 'slot', 'generation', 'process')) and
                        reply['count'] == 16 and reply['sequence'] == 16 and reply['primary_pid'] == primary.pid,
                        'shared reply crossed a live master namespace')
            leases[1].stdin.write(b'P'); leases[1].stdin.flush()
            require(ready(leases[1], 'KER_SESSION_PROBED')['sequence'] == 32, 'probe sequence reset')
            census = status()
            require(census['generation'] == 511 and census['token'] == 0, 'shared probes leaked mbufs')
            diagnostic = subprocess.run([sys.executable, str(args.tool), 'status', '--socket', str(path)],
                capture_output=True, env=environment, timeout=10)
            require(diagnostic.returncode == 0, 'production status failed: ' + diagnostic.stderr.decode())
            diagnostic = json.loads(diagnostic.stdout)
            require(diagnostic['registered_eal_users'] == 3 and diagnostic['outstanding'] == 0 and
                    diagnostic['pool_available'] == 511, 'production pool census is incorrect')
            # Stop the exact secondary before killing its supervisor. The
            # supervisor-owned control pipe closes on death, but the stopped
            # EAL process remains an exact live borrower until resumed.
            orphan_master = leases[0]
            orphan = entries[0]
            os.kill(orphan['pid'], signal.SIGSTOP)
            stop_deadline = time.monotonic() + 5
            while time.monotonic() < stop_deadline:
                state = Path('/proc', str(orphan['pid']), 'stat').read_text().rsplit(')', 1)[1].split()[0]
                if state in ('T', 't'):
                    break
                time.sleep(0.01)
            require(state in ('T', 't'), 'exact secondary did not stop before supervisor death')
            orphan_master.kill(); orphan_master.wait(timeout=10)
            eventually(3, 3)
            full = subprocess.run([sys.executable, str(args.tool), 'lease', *common],
                input=b'', env=environment, capture_output=True, timeout=20)
            require(full.returncode == 125 and b'Errno 28' in full.stderr and
                    b'KER_SESSION_ATTACHED' not in full.stdout, 'orphan epoch was unsafely reused')
            orphan_master.stdin.close(); orphan_master.stdin = None
            signal.pidfd_send_signal(worker_pidfds[0], signal.SIGCONT)
            with selectors.DefaultSelector() as selector:
                selector.register(worker_pidfds[0], selectors.EVENT_READ)
                require(selector.select(20), 'orphan secondary cleanup timed out after control EOF')
            waited, result = os.waitpid(orphan['pid'], 0)
            require(waited == orphan['pid'] and os.waitstatus_to_exitcode(result) == 0,
                    'orphan secondary did not complete original EAL cleanup')
            eventually(2, 2)
            reused = subprocess.Popen([sys.executable, str(args.tool), 'lease', *common],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=environment, bufsize=0)
            processes.append(reused); leases.append(reused)
            replacement = ready(reused, 'KER_SESSION_ATTACHED')
            worker_pidfds.append(os.pidfd_open(replacement['pid']))
            require(replacement['slot'] == orphan['slot'] and replacement['epoch'] > orphan['epoch'],
                    'slot recycling aliased an old epoch')
            stale = api.Connection(path)
            try:
                try:
                    stale.request(api.RESERVE, session=info['session'], epoch=orphan['epoch'],
                        slot=orphan['slot'], token=1)
                    raise RuntimeError('retired epoch admitted a delayed request')
                except OSError as error:
                    require(error.errno == errno.ESTALE, 'wrong retired-epoch error')
            finally:
                stale.close()
            for lease in leases[1:]:
                lease.stdin.write(b'x'); lease.stdin.flush()
                output, errors = lease.communicate(timeout=20)
                require(lease.returncode == 0, 'master/secondary cleanup failed: ' + errors.decode())
            eventually(0, 0)

            # Queue one real shared probe while the resident is stopped; the
            # borrower must time out, and the resident must reclaim the mbuf.
            timed = subprocess.Popen([sys.executable, str(args.tool), 'lease', *common, '--probe-count', '1'],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, bufsize=0)
            processes.append(timed)
            timed_info = ready(timed, 'KER_SESSION_ATTACHED')
            worker_pidfds.append(os.pidfd_open(timed_info['pid']))
            primary_pidfd = os.pidfd_open(primary.pid)
            try:
                signal.pidfd_send_signal(primary_pidfd, signal.SIGSTOP)
                deadline = time.monotonic() + 5
                while Path(f'/proc/{primary.pid}/stat').read_text().rsplit(')', 1)[1].split()[0] not in ('T', 't'):
                    require(time.monotonic() < deadline, 'resident did not actually stop')
                    time.sleep(0.01)
                timed.stdin.write(b'P'); timed.stdin.flush()
                output, errors = timed.communicate(timeout=20)
                require(timed.returncode == 125 and b'shared probe failed -110' in errors and
                        b'KER_SESSION_PROBED' not in output, 'unserved shared request did not time out safely: ' + errors.decode())
            finally:
                signal.pidfd_send_signal(primary_pidfd, signal.SIGCONT)
                os.close(primary_pidfd)
            census = eventually(0, 0)
            require(census['generation'] == 511 and census['token'] == 0,
                    'dead borrower queued request was not reclaimed')
            probe = subprocess.run([sys.executable, str(args.tool), 'probe', *common, '--probe-count', '4'],
                input=b'', capture_output=True, env=environment, timeout=20)
            require(probe.returncode == 0 and b'KER_SESSION_PROBED' in probe.stdout,
                    'production one-shot shared probe failed: ' + probe.stderr.decode())
            eventually(0, 0)
            # Signal only the lease supervisor. Keep its caller-owned stdin
            # writer open so the attached secondary cannot observe EOF there.
            signaled = subprocess.Popen([sys.executable, str(args.tool), 'lease', *common],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=environment, bufsize=0)
            processes.append(signaled)
            signaled_entry = ready(signaled, 'KER_SESSION_ATTACHED')
            signaled_pidfd = os.pidfd_open(signaled_entry['pid'])
            worker_pidfds.append(signaled_pidfd)
            eventually(1, 1)
            os.kill(signaled.pid, signal.SIGTERM)
            signal_status = signaled.wait(timeout=15)
            shutdown = ready(signaled, 'KER_SESSION_SUPERVISOR_STOP')
            require(signal_status == 128 + signal.SIGTERM and not signaled.stdin.closed and
                    shutdown['signal'] == signal.SIGTERM and shutdown['worker_status'] == 0 and
                    not shutdown['escalated'],
                    'SIGTERM did not gracefully stop only the supervisor/secondary with status 143 and stdin retained')
            with selectors.DefaultSelector() as selector:
                selector.register(signaled_pidfd, selectors.EVENT_READ)
                require(selector.select(15), 'supervisor left its exact EAL secondary alive')
            after_signal = eventually(0, 0)
            require(after_signal['slot'] == 0 and after_signal['process'] == 0 and
                    after_signal['epoch'] > signaled_entry['epoch'],
                    'SIGTERM cleanup did not release the exact supervisor epoch')
            signaled.stdin.close()
            recycled = subprocess.Popen([sys.executable, str(args.tool), 'lease', *common],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=environment, bufsize=0)
            processes.append(recycled)
            recycled_entry = ready(recycled, 'KER_SESSION_ATTACHED')
            worker_pidfds.append(os.pidfd_open(recycled_entry['pid']))
            require(recycled_entry['slot'] == signaled_entry['slot'] and
                    recycled_entry['epoch'] > signaled_entry['epoch'],
                    'released signal-terminated slot was not safely reusable')
            recycled.stdin.write(b'x'); recycled.stdin.flush()
            output, errors = recycled.communicate(timeout=20)
            require(recycled.returncode == 0, 'post-signal epoch cleanup failed: ' + errors.decode())
            eventually(0, 0)
            print('PASS: SIGTERM to the lease supervisor alone reaped its exact secondary, released/reused its epoch, and returned 143 with caller stdin still open')
            for _ in range(150):
                value = status()
                require(value['slot'] == 0 and value['process'] == 0, 'status query mutated registrations')
            # Cancel non-borrowing requests without reading their replies.
            # The live test process must not retain one server client per EOF.
            for _ in range(150):
                cancelled = api.Connection(path)
                cancelled.socket.sendall(api.encode(api.packet(api.STATUS)))
                cancelled.close()
                value = status()
                require(value['slot'] == 0, 'cancelled status leaked server clients')
            primary.stdin.write(b'x'); primary.stdin.flush()
            output, errors = primary.communicate(timeout=20)
            require(primary.returncode == 0 and not path.exists(), 'resident cleanup failed: ' + errors.decode())
            # Device admission is deliberately unavailable at this stage; a
            # bad control descriptor must also fail before original EAL starts.
            for options in (['--vdev=net_null0'], []):
                rejected = subprocess.run([str(args.worker), '--role', 'primary', '--socket', str(path),
                    '--control-fd', '0', '--', *options], input=b'', env=environment,
                    capture_output=True, timeout=5)
                require(rejected.returncode == 2 and b'KER_SESSION_READY' not in rejected.stdout,
                        'registration stage accepted a device or missing --no-pci')
            rejected = subprocess.run([str(args.worker), '--role', 'primary', '--socket', str(path),
                '--control-fd', '99999', '--', '--no-pci'], capture_output=True, env=environment, timeout=5)
            require(rejected.returncode == 2 and b'control descriptor' in rejected.stderr,
                    'invalid control descriptor reached EAL')

            # A live stopped secondary cannot be reclaimed even when its
            # master socket is closed. A primary stop must fail conservatively
            # rather than free shared EAL resources under that process.
            blocked_socket = root / 'blocked.sock'
            blocked_eal = eal.replace('session-' + run_id, 'blocked-' + run_id)
            blocked_common = ['--socket', str(blocked_socket), '--worker', str(args.worker), '--eal', blocked_eal]
            blocked = subprocess.Popen([sys.executable, str(args.tool), 'serve', *blocked_common],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=environment, bufsize=0)
            processes.append(blocked); ready(blocked, 'KER_SESSION_READY')
            record_pages('blocked-' + run_id)
            held = subprocess.Popen([sys.executable, str(args.tool), 'lease', *blocked_common],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=environment, bufsize=0)
            processes.append(held); held_info = ready(held, 'KER_SESSION_ATTACHED')
            held_pidfd = os.pidfd_open(held_info['pid']); worker_pidfds.append(held_pidfd)
            signal.pidfd_send_signal(held_pidfd, signal.SIGSTOP)
            # Sending SIGSTOP queues a signal; wait for the actual stopped
            # state before the resident starts closing the control connection.
            # Otherwise a running borrower may legitimately finish EAL cleanup.
            deadline = time.monotonic() + 5
            while True:
                state = Path(f"/proc/{held_info['pid']}/stat").read_text().rsplit(')', 1)[1].split()[0]
                if state in ('T', 't'):
                    break
                require(time.monotonic() < deadline, 'secondary did not actually stop')
                time.sleep(0.01)
            blocked.stdin.write(b'x'); blocked.stdin.flush()
            output, errors = blocked.communicate(timeout=20)
            require(blocked.returncode == 125 and b'live EAL users prevent cleanup' in errors,
                    'resident freed a stopped live EAL borrower')
            signal.pidfd_send_signal(held_pidfd, signal.SIGCONT)
            output, errors = held.communicate(timeout=20)
            require(held.returncode == 125 and b'primary process exited' in errors,
                    'secondary accepted a dead primary lifetime: ' + str(held.returncode) + ' ' + errors.decode() + ' ' + output.decode())
            require(blocked_socket.exists(), 'failed cleanup silently removed a live session namespace')
            print('PASS: device/descriptor preflight; stopped live borrower prevents cleanup; primary death is fatal')
            print('PASS: three live master namespaces exchange64-byte shared mbufs; monotonic sequences; timeout recovers after borrower death')
            print('PASS: resident precreates128rings; real EAL secondary lookup, identity/retry guards, '
                  'live-borrower release refusal, orphan liveness and epoch recycle; shared-control')
        finally:
            for process in reversed(processes):
                stop(process)
            for pidfd in worker_pidfds:
                try:
                    signal.pidfd_send_signal(pidfd, signal.SIGCONT)
                    signal.pidfd_send_signal(pidfd, signal.SIGTERM)
                    with selectors.DefaultSelector() as selector:
                        selector.register(pidfd, selectors.EVENT_READ)
                        if not selector.select(2):
                            signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                            selector.select(5)
                except ProcessLookupError:
                    pass
                with selectors.DefaultSelector() as selector:
                    selector.register(pidfd, selectors.EVENT_READ)
                    require(selector.select(5), 'test-owned EAL process still alive; refuse page cleanup')
                os.close(pidfd)
            # Reap only adopted descendants of this test; normal children were
            # already waited through their Popen handles above.
            while True:
                try:
                    pid, _ = os.waitpid(-1, os.WNOHANG)
                    if not pid:
                        break
                except ChildProcessError:
                    break
            # The fatal primary path intentionally leaves shared memory intact.
            # Only the test, after proving all its borrowers dead, reclaims its
            # own unchanged backing files. Never sweep the shared hugepage mount.
            for path, identity in owned_pages.items():
                try:
                    value = path.lstat()
                except FileNotFoundError:
                    continue
                require((value.st_dev, value.st_ino, value.st_uid) == identity and
                        stat.S_ISREG(value.st_mode), 'hugepage file identity changed')
                path.unlink()
            require(not any(path.exists() for path in owned_pages), 'test leaked hugepage files')
            print(f'PASS: reclaimed {len(owned_pages)} exact test-owned hugepage files after process death')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
