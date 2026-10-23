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


def require(value, message):
    if not value:
        raise RuntimeError(message)


def ready(process, prefix):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        require(selector.select(30), 'session readiness timed out')
    line = process.stdout.readline().decode().strip()
    require(line.startswith(prefix + ' '), 'unexpected readiness: ' + line)
    return json.loads(line[len(prefix) + 1:])


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
    fields = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
    if (int(fields.get('HugePages_Free', '0').split()[0]) < 32 or
            not args.huge_dir.is_dir() or not os.access(args.huge_dir, os.W_OK)):
        print('SKIP: writable hugetlbfs and at least64MiB free hugepages are required; no host settings changed')
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
            require(info['rings'] == 96 and info['slots'] == 4 and info['stage'] == 'registration-only',
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

            leases, entries = [], []
            for gen, process_id in ((0, 0), (1, 3), (0, 0)):
                lease = subprocess.Popen([sys.executable, str(args.tool), 'lease', *common,
                    '--generation', str(gen), '--process', str(process_id)], stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, bufsize=0)
                processes.append(lease); leases.append(lease)
                entry = ready(lease, 'KER_SESSION_ATTACHED'); entries.append(entry)
                worker_pidfds.append(os.pidfd_open(entry['pid']))
            require(len({x['epoch'] for x in entries}) == 3 and len({x['slot'] for x in entries}) == 3,
                    'live masters shared an epoch slot')
            require(len({x['rings'][0] for x in entries}) == 3, 'masters looked up the same control ring')
            require(all(p.poll() is None for p in leases), 'master exited before simultaneous samples')
            eventually(3, 3)
            # Kill only this master. Its actual secondary still has the test's
            # control pipe, and must protect its epoch until it leaves EAL.
            orphan_master = leases[0]; orphan_master.kill(); orphan_master.wait(timeout=10)
            orphan = entries[0]
            eventually(3, 3)
            full = subprocess.run([sys.executable, str(args.tool), 'lease', *common],
                input=b'', env=environment, capture_output=True, timeout=20)
            require(full.returncode == 125 and b'Errno 28' in full.stderr and
                    b'KER_SESSION_ATTACHED' not in full.stdout, 'orphan epoch was unsafely reused')
            orphan_master.stdin.write(b'x'); orphan_master.stdin.flush(); orphan_master.stdin.close()
            orphan_master.stdin = None
            with selectors.DefaultSelector() as selector:
                selector.register(worker_pidfds[0], selectors.EVENT_READ)
                require(selector.select(20), 'orphan secondary cleanup timed out')
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
            print('PASS: resident precreates96rings; real EAL secondary lookup, identity/retry guards, '
                  'live-borrower release refusal, orphan liveness and epoch recycle; registration-only')
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
