#!/usr/bin/env python3
"""Real resident EAL registration; no PMD, packet landing or reload pass claim."""
import argparse
import ctypes
import errno
import importlib.util
import json
import os
import re
import select
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

def ready_exact(process, expected):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        if not selector.select(30):
            raise RuntimeError('session marker timed out: ' + expected)
    line = process.stdout.readline().decode(errors='replace').strip()
    require(line == expected, 'unexpected session marker: ' + line)


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
        environment = dict(os.environ, RUNTIME_DIRECTORY=str(root),
                           KER_SESSION_TEST_DIRECTORY_HOOKS='1')
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

            def status(socket_path=path):
                connection = api.Connection(socket_path)
                try:
                    reply = connection.request(api.STATUS)
                    # Keep protocol fields for the detailed lease assertions,
                    # and expose the same names as the production status CLI.
                    reply.update(registered_epochs=reply['slot'],
                        eal_processes=reply['process'], outstanding=reply['token'],
                        pool_available=reply['generation'])
                    return reply
                finally:
                    connection.close()

            def eventually(epochs, users, socket_path=path):
                deadline = time.monotonic() + 10
                while True:
                    value = status(socket_path)
                    if value['slot'] == epochs and value['process'] == users:
                        return value
                    require(time.monotonic() < deadline, 'session census did not converge: ' + str(value))
                    time.sleep(0.05)

            def resident_record(prefix, resident=primary):
                deadline = time.monotonic() + 20
                with selectors.DefaultSelector() as selector:
                    selector.register(resident.stdout, selectors.EVENT_READ)
                    while time.monotonic() < deadline:
                        require(selector.select(max(0, deadline - time.monotonic())),
                                'resident record timed out: ' + prefix)
                        line = resident.stdout.readline().decode(errors='replace').strip()
                        if line.startswith(prefix + ' '):
                            return json.loads(line[len(prefix) + 1:])
                        if line.startswith('KER_SESSION_CHILD_REAP '):
                            continue
                        require(False, 'unexpected resident record while waiting for ' + prefix + ': ' + line)
                raise RuntimeError('resident record timed out: ' + prefix)

            def snapshot(resident=primary):
                resident.stdin.write(b'S'); resident.stdin.flush()
                return resident_record('KER_SESSION_TEST_SNAPSHOT', resident)

            def generation_directory_state(resident=primary):
                resident.stdin.write(b'G'); resident.stdin.flush()
                return resident_record('KER_SESSION_TEST_DIRECTORY_STATE', resident)

            def restore_directory_header():
                primary.stdin.write(b'R'); primary.stdin.flush()
                deadline = time.monotonic() + 20
                with selectors.DefaultSelector() as selector:
                    selector.register(primary.stdout, selectors.EVENT_READ)
                    while time.monotonic() < deadline:
                        require(selector.select(max(0, deadline - time.monotonic())),
                                'test directory header restore timed out')
                        line = primary.stdout.readline().decode(errors='replace').strip()
                        if line == 'KER_SESSION_TEST_DIRECTORY_RESTORED':
                            return
                        if line.startswith('KER_SESSION_CHILD_REAP '):
                            continue
                        require(False, 'unexpected resident line during restore: ' + line)
                raise RuntimeError('test directory header restore timed out')

            # With the opt-in generation adapter omitted, an ordinary real
            # secondary must still register through the generic Ker session.
            # Observe the actual generation memzone lookup used by
            # ker_generation_rings_attach(), while checking that the distinct
            # generic session memzone remains present and unchanged.
            disabled_before = generation_directory_state()
            require(disabled_before['generation_present'] is False and
                    disabled_before['session_present'] is True and
                    disabled_before['session_matches'] is True and
                    disabled_before['session'] == info['session'],
                    'default-off generation adapter namespace was not absent')
            disabled_snapshot = snapshot()
            disabled = subprocess.Popen([sys.executable, str(args.tool), 'lease', *common],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=environment, bufsize=0)
            processes.append(disabled)
            disabled_attached = ready(disabled, 'KER_SESSION_ATTACHED')
            require(disabled_attached['epoch'] != 0 and disabled_attached['slot'] != 0 and
                    disabled_attached['generation'] == 0 and disabled_attached['process'] == 0,
                    'default-off real secondary did not register normally')
            disabled_during = generation_directory_state()
            require(disabled_during == disabled_before,
                    'default-off secondary created or changed the generation namespace')
            disabled_census = status()
            require(disabled_census['registered_epochs'] == 1 and
                    disabled_census['eal_processes'] == 1 and
                    disabled_census['outstanding'] == 1 and
                    disabled_census['pool_available'] == disabled_snapshot['pool'][0] - 1,
                    'default-off registration did not use normal generic control accounting')
            disabled.stdin.write(b'x'); disabled.stdin.flush()
            disabled_output, disabled_errors = disabled.communicate(timeout=20)
            require(disabled.returncode == 0,
                    'default-off secondary cleanup failed: ' + disabled_errors.decode(errors='replace'))
            child_reap(disabled_output, disabled_attached['pid'])
            disabled_after = eventually(0, 0)
            require(disabled_after['pool_available'] == disabled_snapshot['pool'][0] and
                    disabled_after['outstanding'] == disabled_snapshot['pool'][1],
                    'default-off secondary leaked its generic session control lease')
            disabled_final = generation_directory_state()
            require(disabled_final == disabled_before,
                    'default-off namespace changed after secondary cleanup')
            disabled_final_snapshot = snapshot()
            for key in ('pool', 'pmd', 'slots', 'leases', 'peers'):
                require(disabled_final_snapshot[key] == disabled_snapshot[key],
                        'default-off session cleanup changed resident ' + key)
            print('PASS: default-off real EAL registration kept generation memzone absent and restored generic session accounting')

            def directory_case(field, case_eal=eal, mutate=True):
                before = snapshot()
                gate_read, gate_write = os.pipe()
                worker = subprocess.Popen([sys.executable, str(args.tool), 'lease',
                    *common, '--eal', case_eal, '--test-directory-gate-fd', str(gate_read)],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    pass_fds=(gate_read,), env=environment, bufsize=0)
                processes.append(worker)
                os.close(gate_read)
                try:
                    ready_exact(worker, 'KER_SESSION_TEST_RESERVED')
                    if mutate:
                        primary.stdin.write(b'M' + field.encode()); primary.stdin.flush()
                        mutated = resident_record('KER_SESSION_TEST_DIRECTORY_MUTATED')
                        require(mutated['field'] == field, 'wrong shared directory field was mutated')
                    os.write(gate_write, b'G')
                    output, errors = worker.communicate(timeout=30)
                    require(worker.returncode != 0 and b'KER_SESSION_ATTACHED ' not in output and
                            b'shared directory lookup/validation failed' in errors,
                            'malformed/missing directory reached ATTACHED: ' +
                            output.decode(errors='replace') + errors.decode(errors='replace'))
                except BaseException as error:
                    if worker.poll() is None:
                        worker.kill()
                    try:
                        output, errors = worker.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        output, errors = b'', b'worker output remained blocked after kill'
                    raise RuntimeError(str(error) + '; worker stdout=' +
                        output.decode(errors='replace') + ' stderr=' +
                        errors.decode(errors='replace')) from error
                finally:
                    os.close(gate_write)
                    if worker.poll() is None:
                        worker.kill(); worker.wait(timeout=5)
                if mutate:
                    restore_directory_header()
                after = snapshot()
                for key in ('header', 'pool', 'pmd', 'pmd_identity', 'slots', 'leases', 'peers'):
                    require(after[key] == before[key],
                            'directory rejection changed resident ' + key + ': ' + repr((before[key], after[key])))
                require(eventually(0, 0)['session'] == info['session'],
                        'directory rejection retained a registration')
                print('PASS: real secondary rejected directory case ' + field +
                      ' before ATTACHED without changing owner/lease/ring census')

            require(eventually(0, 0)['session'] == info['session'], 'session identity mismatch')
            for field in ('m', 'v', 'z', 's', 'g', 'c'):
                directory_case(field)

            # Create an actual unrelated EAL primary without the Ker resident
            # directory, then reserve through the real session and attach a
            # real secondary in that independent EAL namespace.
            missing_prefix = 'dir-missing-' + run_id[-8:]
            missing_eal = (f'--lcores=0@{min(os.sched_getaffinity(0))} --no-pci --no-telemetry '
                           f'--iova-mode=va -m 32 --huge-dir={args.huge_dir} '
                           f'--file-prefix={missing_prefix}')
            missing_primary = subprocess.Popen([str(args.worker), '--role', 'test-eal-primary',
                '--control-fd', '0', '--', *missing_eal.split(), '--proc-type=primary'],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, bufsize=0)
            processes.append(missing_primary)
            require(missing_primary.stdout.readline().decode().strip() ==
                    'KER_SESSION_TEST_EAL_PRIMARY_READY',
                    'independent EAL primary did not publish readiness')
            directory_case('absent', case_eal=missing_eal, mutate=False)
            missing_primary.stdin.close(); missing_primary.stdin = None
            missing_out, missing_err = missing_primary.communicate(timeout=20)
            require(missing_primary.returncode == 0,
                    'independent EAL primary cleanup failed: ' + missing_err.decode(errors='replace'))

            # A second primary cannot take the active resident's exact DPDK
            # file prefix; the original resident snapshot must remain intact.
            before_busy = snapshot()
            busy = subprocess.run([str(args.worker), '--role', 'test-eal-primary',
                '--control-fd', '0', '--', *eal.split(), '--proc-type=primary'],
                input=b'', stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=environment, timeout=20)
            require(busy.returncode != 0 and b'KER_SESSION_TEST_EAL_PRIMARY_READY' not in busy.stdout,
                    'second same-prefix EAL primary unexpectedly started')
            after_busy = snapshot()
            for key in ('header', 'next_epoch', 'pool', 'pmd', 'pmd_identity', 'slots', 'leases', 'peers'):
                require(after_busy[key] == before_busy[key],
                        'same-prefix primary collision changed resident ' + key)
            print('PASS: same-prefix primary collision failed while resident directory and owners stayed unchanged')

            # A valid secondary receives the same authenticated directory
            # attachment twice with the exact same request sequence; the
            # resident's normal idempotent reply cache must return the same
            # coordinate without advancing or reallocating its lease.
            before = snapshot()
            replay = subprocess.Popen([sys.executable, str(args.tool), 'lease',
                *common, '--test-directory-replay-attached'],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=environment, bufsize=0)
            processes.append(replay)
            replay_record = ready(replay, 'KER_SESSION_TEST_ATTACHED_REPLAY')
            attached = ready(replay, 'KER_SESSION_ATTACHED')
            require(replay_record['slot'] == attached['slot'] and
                    replay_record['epoch'] == attached['epoch'] and
                    replay_record['sequence'] > 0,
                    'identical ATTACHED replay changed its coordinate')
            replay.stdin.write(b'x'); replay.stdin.flush()
            replay_output, replay_errors = replay.communicate(timeout=20)
            require(replay.returncode == 0 and b'KER_SESSION_CHILD_REAP' in replay_output,
                    'idempotent ATTACHED replay cleanup failed: ' + replay_errors.decode(errors='replace'))
            after = snapshot()
            require(after['pool'] == before['pool'] and after['pmd'] == before['pmd'] and
                    after['leases'] == before['leases'] and after['peers'] == before['peers'] and
                    after['slots'] == before['slots'],
                    'same-sequence ATTACHED replay changed resident accounting')
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
            require(census['generation'] == 508 and census['token'] == 3, 'live control leases are not journaled')
            diagnostic = subprocess.run([sys.executable, str(args.tool), 'status', '--socket', str(path)],
                capture_output=True, env=environment, timeout=10)
            require(diagnostic.returncode == 0, 'production status failed: ' + diagnostic.stderr.decode())
            diagnostic = json.loads(diagnostic.stdout)
            require(diagnostic['registered_eal_users'] == 3 and diagnostic['outstanding'] == 3 and
                    diagnostic['pool_available'] == 508, 'production pool census is incorrect')
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

            # Exact A4/USR2-chain source scenario: all three master slots are
            # occupied, then every master dies without issuing RELEASE. Keep
            # their EAL workers alive until after that observation; only exact
            # borrower death may make room for the fourth master.
            abandoned = []
            for _ in range(3):
                owner = subprocess.Popen([sys.executable, str(args.tool), 'lease', *common],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, bufsize=0)
                processes.append(owner)
                entry = ready(owner, 'KER_SESSION_ATTACHED')
                pidfd = os.pidfd_open(entry['pid']); worker_pidfds.append(pidfd)
                abandoned.append((owner, entry, pidfd))
            require(len({entry['slot'] for _, entry, _ in abandoned}) == 3,
                    'chain masters did not occupy every reusable slot')
            eventually(3, 3)
            for owner, entry, pidfd in abandoned:
                signal.pidfd_send_signal(pidfd, signal.SIGSTOP)
                stop_deadline = time.monotonic() + 5
                while Path(f'/proc/{entry["pid"]}/stat').read_text().rsplit(')', 1)[1].split()[0] not in ('T', 't'):
                    require(time.monotonic() < stop_deadline, 'A4 secondary did not stop before master death')
                    time.sleep(0.01)
            for owner, _, _ in abandoned:
                owner.kill(); owner.wait(timeout=10)
            census = eventually(3, 3)
            require(census['generation'] == 508 and census['token'] == 3,
                    'dead masters prematurely released surviving borrowers')
            for owner, _, _ in abandoned:
                owner.stdin.close(); owner.stdin = None
            for _, entry, pidfd in abandoned:
                signal.pidfd_send_signal(pidfd, signal.SIGCONT)
                with selectors.DefaultSelector() as selector:
                    selector.register(pidfd, selectors.EVENT_READ)
                    require(selector.select(20), 'abandoned EAL worker did not exit')
                waited, result = os.waitpid(entry['pid'], 0)
                require(waited == entry['pid'] and os.waitstatus_to_exitcode(result) == 0,
                        'abandoned chain worker did not finish original EAL cleanup')
            census = eventually(0, 0)
            require(census['generation'] == 511 and census['token'] == 0, 'chain control leases leaked')
            fourth = subprocess.run([sys.executable, str(args.tool), 'probe', *common, '--probe-count', '4'],
                input=b'', capture_output=True, env=environment, timeout=20)
            require(fourth.returncode == 0, 'fourth master could not register: ' + fourth.stderr.decode())
            fourth_lines = fourth.stdout.decode().splitlines()
            attached = next(json.loads(line.split(' ', 1)[1]) for line in fourth_lines
                            if line.startswith('KER_SESSION_ATTACHED '))
            proved = next(json.loads(line.split(' ', 1)[1]) for line in fourth_lines
                          if line.startswith('KER_SESSION_PROBED '))
            require(attached['epoch'] > max(entry['epoch'] for _, entry, _ in abandoned) and
                    1 <= attached['slot'] < 4 and attached['epoch'] == proved['epoch'] and
                    attached['slot'] == proved['slot'] and proved['count'] == 4 and len(attached['rings']) == 4,
                    'fourth chain master aliased epoch zero or failed shared-object lookup')
            census = eventually(0, 0)
            require(census['generation'] == 511 and census['token'] == 0, 'fourth master leaked objects')
            # The resident assigned an mbuf before acknowledging reservation.
            # Kill a borrower without ever enqueueing it, and again after a
            # reply was dequeued, when neither control ring holds a reference.
            for after_reply in (False, True):
                killed = subprocess.Popen([sys.executable, str(args.tool), 'lease', *common, '--probe-count', '1'],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, bufsize=0)
                processes.append(killed)
                killed_info = ready(killed, 'KER_SESSION_ATTACHED')
                killed_pidfd = os.pidfd_open(killed_info['pid']); worker_pidfds.append(killed_pidfd)
                if after_reply:
                    killed.stdin.write(b'P'); killed.stdin.flush()
                    ready(killed, 'KER_SESSION_PROBED')
                census = eventually(1, 1)
                require(census['generation'] == 510 and census['token'] == 1,
                        'borrower has no pre-enqueue journaled mbuf lease')
                signal.pidfd_send_signal(killed_pidfd, signal.SIGKILL)
                output, errors = killed.communicate(timeout=20)
                require(killed.returncode != 0, 'killed borrower was reported successful')
                census = eventually(0, 0)
                require(census['generation'] == 511 and census['token'] == 0,
                        'unpublished or dequeued control lease leaked after borrower death')
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
                # Keep the caller's writer open so EOF cannot cancel the probe.
                # Once the child reports its timeout, resume the resident so the
                # supervisor can complete RELEASE before its own deadline.
                errors = bytearray()
                deadline = time.monotonic() + 12
                while b'shared probe failed -110' not in errors:
                    require(time.monotonic() < deadline, 'shared probe timeout was not reported')
                    ready_fds, _, _ = select.select([timed.stderr], [], [], 0.1)
                    if ready_fds:
                        chunk = os.read(timed.stderr.fileno(), 4096)
                        if not chunk:
                            break
                        errors.extend(chunk)
                signal.pidfd_send_signal(primary_pidfd, signal.SIGCONT)
                output = timed.stdout.read()
                errors.extend(timed.stderr.read())
                timed.wait(timeout=5)
                require(timed.returncode == 1 and b'shared probe failed -110' in errors and
                        b'KER_SESSION_PROBED' not in output, 'unserved shared request did not time out safely; stdout=' + output.decode(errors='replace') + ' stderr=' + errors.decode(errors='replace'))
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

            # The automatic --probe-only path has no consumed P whose outcome
            # can be deferred. Queue an ordinary cancellation before startup;
            # the worker must observe it inside the active probe loop and exit
            # cleanly without publishing a PROBED result or leaking its lease.
            automatic = subprocess.Popen([sys.executable, str(args.tool), 'probe', *common,
                '--probe-count', '4096'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, env=environment | {'KER_SESSION_TEST_PROBE_ONLY_CANCEL': '1'}, bufsize=0)
            processes.append(automatic)
            automatic.stdin.write(b'x'); automatic.stdin.flush(); automatic.stdin.close()
            automatic.stdin = None
            automatic_info = ready(automatic, 'KER_SESSION_ATTACHED')
            output, errors = automatic.communicate(timeout=20)
            require(automatic.returncode == 0 and
                    b'KER_SESSION_TEST_PROBE_ONLY_STARTED' in errors and
                    b'KER_SESSION_TEST_PROBE_ONLY_CANCELLED' in errors and
                    b'KER_SESSION_PROBED ' not in output,
                    'automatic probe-only cancellation lost its active-loop control semantics: ' +
                    output.decode(errors='replace') + errors.decode(errors='replace'))
            child_reap(output, automatic_info['pid'])
            census = eventually(0, 0)
            require(census['generation'] == 511 and census['token'] == 0,
                    'automatic probe-only cancellation leaked its control lease')
            print('PASS: automatic probe-only batch observed queued cancellation without publishing a probe result')

            # Cancel a deliberately large active batch after observing its
            # first published mbuf. The request remains ring-owned until the
            # exact secondary exits and the resident reclaims it.
            def cancel_large_batch(mode):
                batch = subprocess.Popen([sys.executable, str(args.tool), 'lease', *common,
                    '--probe-count', '4096'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, env=environment, bufsize=0)
                processes.append(batch)
                entry = ready(batch, 'KER_SESSION_ATTACHED')
                pidfd = os.pidfd_open(entry['pid'])
                worker_pidfds.append(pidfd)
                eventually(1, 1)
                batch.stdin.write(b'P'); batch.stdin.flush()
                active_deadline = time.monotonic() + 5
                while True:
                    active = status()
                    if active['generation'] == 510 and active['token'] == 1:
                        break
                    require(time.monotonic() < active_deadline,
                            'large probe batch never exposed an outstanding shared mbuf: ' + str(active))
                    time.sleep(0.001)
                started = time.monotonic()
                if mode == 'SIGTERM':
                    os.kill(batch.pid, signal.SIGTERM)
                else:
                    batch.stdin.write(b'x'); batch.stdin.flush()
                result = batch.wait(timeout=8)
                duration = time.monotonic() - started
                shutdown = None
                if mode == 'SIGTERM':
                    shutdown = ready(batch, 'KER_SESSION_SUPERVISOR_STOP')
                reap_record = ready(batch, 'KER_SESSION_CHILD_REAP')
                stdin_was_open = not batch.stdin.closed
                output, errors = batch.communicate(timeout=2)
                expected_status = 128 + signal.SIGTERM if mode == 'SIGTERM' else 0
                require(result == expected_status and stdin_was_open and duration < 5,
                        mode + ' did not stop the active batch promptly with stdin open: result=' + str(result) + ' expected=' + str(expected_status) + ' stdin_was_open=' + str(stdin_was_open) + ' duration=' + str(duration) + ' stdout=' + output.decode(errors='replace') + ' stderr=' + errors.decode(errors='replace'))
                if shutdown is not None:
                    require(shutdown['worker_status'] == 0 and shutdown['signal'] == signal.SIGTERM and
                            not shutdown['escalated'], 'SIGTERM cancellation escalated or failed: ' + repr(shutdown))
                require(reap_record == {'pid': entry['pid'], 'status': 0,
                                       'escalated': False, 'input_abandoned': False} and
                        b'KER_SESSION_PROBED' not in output,
                        'cancelled batch child status/output was not clean: ' + repr(reap_record))
                with selectors.DefaultSelector() as selector:
                    selector.register(pidfd, selectors.EVENT_READ)
                    require(selector.select(2), 'cancelled batch child remained alive')
                batch.stdin.close()
                deadline = time.monotonic() + 5
                while True:
                    reclaimed = status()
                    if (reclaimed['slot'] == 0 and reclaimed['process'] == 0 and
                            reclaimed['generation'] == 511 and reclaimed['token'] == 0):
                        break
                    require(time.monotonic() < deadline,
                            'cancelled published mbuf was not reclaimed after exact child death: ' + str(reclaimed))
                    time.sleep(0.01)
                print('PASS: ' + mode + ' cancels active 4096-probe batch, reaps child, and reclaims published mbuf')

            cancel_large_batch('non-P stop')
            cancel_large_batch('SIGTERM')

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

            # An explicitly enabled adapter uses a distinct EAL primary and
            # the same production generation-directory lookup on both sides.
            # The secondary repeats the real production attach in-process and
            # verifies the directory and all eight ring objects are identical.
            enabled_socket = root / 'enabled-control.sock'
            enabled_eal = eal.replace('session-' + run_id, 'enabled-' + run_id)
            enabled_common = ['--socket', str(enabled_socket), '--worker', str(args.worker),
                              '--eal', enabled_eal, '--generation-rings']
            enabled_primary = subprocess.Popen([sys.executable, str(args.tool), 'serve', *enabled_common],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=environment, bufsize=0)
            processes.append(enabled_primary)
            enabled_info = ready(enabled_primary, 'KER_SESSION_READY')
            require(enabled_info['rings'] == 128,
                    'enabled resident did not create all generic control rings: ' + repr(enabled_info))
            record_pages('enabled-' + run_id)
            enabled_before = generation_directory_state(enabled_primary)
            require(enabled_before['generation_present'] is True and
                    enabled_before['session_present'] is True and
                    enabled_before['session_matches'] is True and
                    enabled_before['session'] == enabled_info['session'],
                    'enabled primary did not create its generation adapter in the same session')
            enabled_snapshot = snapshot(enabled_primary)
            enabled_secondary = subprocess.Popen([sys.executable, str(args.tool), 'lease',
                *enabled_common, '--test-generation-rings-replay'], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, bufsize=0)
            processes.append(enabled_secondary)
            replay = ready(enabled_secondary, 'KER_SESSION_TEST_GENERATION_REPLAY')
            require(replay == {'directory_same': True, 'rings_same': True,
                    'session': enabled_info['session'], 'ports': 1, 'queues': 2},
                    'repeat generation attach changed its production namespace or rings: ' + repr(replay))
            enabled_attached = ready(enabled_secondary, 'KER_SESSION_ATTACHED')
            require(enabled_attached['generation'] == 0 and enabled_attached['process'] == 0 and
                    enabled_attached['epoch'] != 0 and enabled_attached['slot'] != 0 and
                    enabled_attached['validated_rings'] == enabled_info['rings'],
                    'enabled generation adapter did not validate all resident rings: ' + repr(enabled_attached))
            require(generation_directory_state(enabled_primary) == enabled_before,
                    'enabled secondary changed or replaced the resident generation directory')
            enabled_census = status(enabled_socket)
            require(enabled_census['registered_epochs'] == 1 and
                    enabled_census['eal_processes'] == 1 and enabled_census['outstanding'] == 1,
                    'enabled generation registration accounting was not singular')
            enabled_secondary.stdin.write(b'x'); enabled_secondary.stdin.flush()
            enabled_output, enabled_errors = enabled_secondary.communicate(timeout=20)
            require(enabled_secondary.returncode == 0,
                    'enabled generation secondary cleanup failed: ' + enabled_errors.decode(errors='replace'))
            child_reap(enabled_output, enabled_attached['pid'])
            enabled_final = eventually(0, 0, enabled_socket)
            require(enabled_final['pool_available'] == enabled_snapshot['pool'][0] and
                    enabled_final['outstanding'] == enabled_snapshot['pool'][1] and
                    generation_directory_state(enabled_primary) == enabled_before,
                    'enabled generation cleanup changed pool or directory identity')
            enabled_final_snapshot = snapshot(enabled_primary)
            for key in ('pool', 'pmd', 'pmd_identity', 'leases', 'peers'):
                require(enabled_final_snapshot[key] == enabled_snapshot[key],
                        'enabled registration cleanup changed resident ' + key)
            enabled_primary.stdin.write(b'x'); enabled_primary.stdin.flush()
            enabled_primary_output, enabled_primary_errors = enabled_primary.communicate(timeout=20)
            require(enabled_primary.returncode == 0 and not enabled_socket.exists(),
                    'enabled generation resident cleanup failed: ' + enabled_primary_errors.decode(errors='replace'))
            print('PASS: opted-in real EAL secondary repeated the production generation attach with the same directory/rings and clean accounting')

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
            print('PASS: source A4/USR2 chain: three unretired dead masters recycle for fourth real secondary, never epoch0')
            print('PASS: journal recovers control mbuf after death before enqueue and after reply dequeue')
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
