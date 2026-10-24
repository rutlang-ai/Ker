#!/usr/bin/env python3
"""Live secondary standby, coherent owner samples and exact-lifetime takeover."""
import argparse
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time

from hugepage_preflight import hugepage_capacity_error


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


support = load('ring_pmd_acceptance', Path(__file__).with_name('session-ring-pmd.py'))
require, ready, stop, dead = support.require, support.ready, support.stop, support.selectors_for_death


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
    api = load('ker_session_tool', args.tool)
    expected_frame_bytes = 14 + api.WIRE.size + 8 + 64
    require(ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0, 'subreaper setup')
    processes, workers = [], []
    resident_stopped = False
    with tempfile.TemporaryDirectory(prefix='ker-standby-') as directory:
        root = Path(directory); path = root / 'control.sock'
        eal = (f'--lcores=0@{min(os.sched_getaffinity(0))} --no-pci --no-telemetry --iova-mode=va '
               f'-m 64 --huge-dir={args.huge_dir} --file-prefix=standby-{os.getpid()}-{os.urandom(4).hex()}')
        common = ['--socket', str(path), '--worker', str(args.worker), '--eal', eal, '--ring-pmd']

        stderr_history = {}

        def stderr_marker(process, marker, timeout=10):
            history = stderr_history.setdefault(process, bytearray())
            deadline = time.monotonic() + timeout
            while marker.encode() not in history:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError('worker stderr marker timed out: ' + marker)
                readable, _, _ = select.select([process.stderr], [], [], remaining)
                if not readable:
                    raise RuntimeError('worker stderr marker timed out: ' + marker)
                chunk = os.read(process.stderr.fileno(), 4096)
                if not chunk:
                    raise RuntimeError('worker stderr closed before marker: ' + marker)
                history.extend(chunk)
            return bytes(history)

        def stderr_marker_count(process, marker, count, timeout=10):
            history = stderr_history.setdefault(process, bytearray())
            needle = marker.encode()
            deadline = time.monotonic() + timeout
            while history.count(needle) < count:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError('worker stderr marker count timed out: ' + marker +
                                       ' expected=' + str(count) +
                                       ' observed=' + str(history.count(needle)))
                readable, _, _ = select.select([process.stderr], [], [], remaining)
                if not readable:
                    raise RuntimeError('worker stderr marker count timed out: ' + marker +
                                       ' expected=' + str(count) +
                                       ' observed=' + str(history.count(needle)))
                chunk = os.read(process.stderr.fileno(), 4096)
                if not chunk:
                    raise RuntimeError('worker stderr closed before marker count: ' + marker +
                                       ' expected=' + str(count) +
                                       ' observed=' + str(history.count(needle)))
                history.extend(chunk)
            return bytes(history)

        def launch(action, *extra, ring_pmd=True, extra_env=None):
            options = common if ring_pmd else common[:-1]
            process = subprocess.Popen([sys.executable, str(args.tool), action, *options, *extra],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
                env=os.environ | {'RUNTIME_DIRECTORY': str(root),
                                  'KER_SESSION_TEST_DIRECTORY_HOOKS': '1'} | (extra_env or {}))
            processes.append(process)
            return process

        def query(command, **fields):
            connection = api.Connection(path)
            try: return connection.request(command, **fields)
            finally: connection.close()

        def live(epoch):
            response = query(api.EPOCH_LIVE, epoch=epoch)
            require(response['epoch'] == epoch and response['token'] in (0, 1), 'bad epoch reply')
            return bool(response['token'])

        def status(): return query(api.STATUS)

        def stop_resident():
            nonlocal resident_stopped
            os.kill(primary.pid, signal.SIGSTOP)
            deadline = time.monotonic() + 5
            while True:
                try:
                    state = Path('/proc', str(primary.pid), 'stat').read_text().rsplit(')', 1)[1].split()[0]
                except FileNotFoundError:
                    state = ''
                if state in ('T', 't'):
                    resident_stopped = True
                    return
                require(time.monotonic() < deadline, 'resident did not stop before pending-heartbeat fixture')
                time.sleep(0.01)

        def resume_resident():
            nonlocal resident_stopped
            if resident_stopped:
                os.kill(primary.pid, signal.SIGCONT)
                resident_stopped = False

        def wait_epoch_released(epoch):
            deadline = time.monotonic() + 6
            while live(epoch):
                require(time.monotonic() < deadline, 'test worker epoch was not released')
                time.sleep(0.02)

        def wait_worker_dead(fd):
            deadline = time.monotonic() + 5
            while not dead(fd):
                require(time.monotonic() < deadline, 'test worker pidfd did not become readable')
                time.sleep(0.01)

        def resident_snapshot():
            primary.stdin.write(b'S'); primary.stdin.flush()
            return ready(primary, 'KER_SESSION_TEST_SNAPSHOT')

        def round_sample(process, sequence, owns, owner_epoch):
            response = ready(process, 'KER_SESSION_PROBED')
            sample = ready(process, 'KER_SESSION_PMD_SAMPLED')
            require(response['sequence'] == sequence and sample['sequence'] == sequence and
                    sample['owns_device'] == owns and sample['owner_epoch'] == owner_epoch and
                    sample['owner_generation'] == 0 and sample['owner_process'] == 0,
                    'inconsistent live ownership sample: ' + str(sample))
            if owns:
                data = ready(process, 'KER_SESSION_PMD_PROBED')
                require(data['count'] == 16 and data['frame_bytes'] == expected_frame_bytes,
                        'actual PMD burst evidence missing')
                return sample, data
            return sample, None

        primary = launch('serve')
        try:
            require(ready(primary, 'KER_SESSION_READY')['ring_pmd'], 'PMD startup absent')
            require(live(0) and not live(2**64 - 1), 'resident/unknown epoch liveness wrong')
            first = launch('lease', '--standby', '--probe-count', '16')
            one = ready(first, 'KER_SESSION_ATTACHED'); ready(first, 'KER_SESSION_PMD_GRANTED')
            workers.append((one['pid'], os.pidfd_open(one['pid'])))
            second = launch('lease', '--standby', '--probe-count', '16')
            two = ready(second, 'KER_SESSION_ATTACHED'); ready(second, 'KER_SESSION_PMD_STANDBY')
            workers.append((two['pid'], os.pidfd_open(two['pid'])))
            require(one['epoch'] != two['epoch'] and one['slot'] != two['slot'] and one['rings'] != two['rings'],
                    'different masters shared their namespace')
            require(live(one['epoch']) and live(two['epoch']) and live(0), 'both live epochs not published')
            # Gate both live master/secondary chains before the same sample
            # round, then retain all four processes until both results arrive.
            for master in (first, second): master.stdin.write(b'P'); master.stdin.flush()
            a, data = round_sample(first, 16, True, one['epoch'])
            b, absent = round_sample(second, 16, False, one['epoch'])
            require(a['owner_slot'] == b['owner_slot'] == one['slot'] and data['sequence'] == 16 and absent is None,
                    'workers disagree on the sole real PMD consumer')
            require(all(p.poll() is None for p in (first, second)) and all(not dead(fd) for _, fd in workers),
                    'simultaneous sample was taken after a master/worker exited')
            census = status()
            require(census['process'] == 2 and census['generation'] == 508 and census['token'] == 3,
                    'standby allocated a PMD object or lost its control lease')
            # Default count zero still performs admission/owner control on P;
            # it must remain a live standby and never pretend frames were sent.
            zero = launch('lease', '--standby', extra_env={'KER_SESSION_TEST_DQ_PENDING_HB': '1'})
            zero_entry = ready(zero, 'KER_SESSION_ATTACHED'); ready(zero, 'KER_SESSION_PMD_STANDBY')
            workers.append((zero_entry['pid'], os.pidfd_open(zero_entry['pid'])))

            # With the owner and two real secondary standbys alive, repeated
            # fourth-MASTER denial must preserve the actual PMD grant, all
            # leases, mirrors, slot identities and resident pool accounting.
            full_before = resident_snapshot()
            require(full_before['pmd'][0] != 0 and full_before['pmd'][1] == 0 and
                    full_before['pmd'][4] == 0 and full_before['pmd'][5] == 0 and
                    status()['slot'] == 3 and status()['process'] == 3 and
                    all(p.poll() is None for p in (first, second, zero)),
                    'three live ring-PMD owner/standby chains or truthful exception-zero boundary absent')
            for attempt in range(2):
                denied = subprocess.run([sys.executable, str(args.tool), 'lease', *common],
                    input=b'x', stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
                    env=os.environ | {'RUNTIME_DIRECTORY': str(root),
                                      'KER_SESSION_TEST_DIRECTORY_HOOKS': '1'}, timeout=15)
                require(denied.returncode == 125 and b'KER_SESSION_ATTACHED ' not in denied.stdout,
                        'fourth MASTER was not refused before secondary attachment: ' +
                        denied.stdout.decode(errors='replace') + denied.stderr.decode(errors='replace'))
                full_after = resident_snapshot()
                for key in ('header', 'next_epoch', 'pool', 'pmd', 'pmd_identity', 'slots', 'leases', 'peers'):
                    require(full_after[key] == full_before[key],
                            'fourth MASTER denial mutated resident ' + key +
                            ': ' + repr((full_before[key], full_after[key])))
                require(status()['slot'] == 3 and status()['process'] == 3 and
                        all(p.poll() is None for p in (first, second, zero)),
                        'fourth MASTER denial changed the three live registrations')
            print('PASS: two full-directory denials preserved one live PMD owner, two standbys, leases, mirrors and pool')

            stderr_marker(zero, 'KER_SESSION_TEST_DQ_INITIAL_HEARTBEAT_ACKED')
            before_zero_status = status()
            before_zero_owner = query(api.PMD_STATUS)
            stop_resident()
            zero.stdin.write(b'h'); zero.stdin.flush()
            stderr_marker(zero, 'KER_SESSION_TEST_DQ_HEARTBEAT_REQUESTED')
            stderr_marker(zero, 'KER_SESSION_TEST_DQ_HEARTBEAT_PENDING')
            zero.stdin.write(b'PP'); zero.stdin.flush()
            stderr_marker(zero, 'KER_SESSION_TEST_DQ_P_CONSUMED')
            stderr_marker(zero, 'KER_SESSION_TEST_DQ_HEARTBEAT_DEFERRED')
            resume_resident()
            sample1, _ = round_sample(zero, 0, False, one['epoch'])
            sample2, _ = round_sample(zero, 0, False, one['epoch'])
            zero_errors = stderr_marker_count(zero, 'KER_SESSION_TEST_DQ_PROBE_PMD_ACQUIRE', 2)
            require(sample1['owner_slot'] == one['slot'] and sample2['owner_slot'] == one['slot'],
                    'zero-count P samples changed owner slot: expected=' + str(one['slot']) +
                    ' sample1=' + str(sample1['owner_slot']) + ' sample2=' + str(sample2['owner_slot']))
            acquire_count = zero_errors.count(b'KER_SESSION_TEST_DQ_PROBE_PMD_ACQUIRE')
            require(acquire_count == 2,
                    'zero-count P requests did not each reach PMD acquire: count=' + str(acquire_count))
            after_zero_status = status()
            require(after_zero_status == before_zero_status,
                    'zero-count P requests changed resident status: before=' + repr(before_zero_status) +
                    ' after=' + repr(after_zero_status))
            after_zero_owner = query(api.PMD_STATUS)
            require(after_zero_owner == before_zero_owner,
                    'zero-count P requests changed PMD owner: before=' + repr(before_zero_owner) +
                    ' after=' + repr(after_zero_owner))
            require(zero.poll() is None,
                    'zero-count standby exited before both ordered P outcomes were checked: ' +
                    str(zero.returncode))
            print('PASS: pending heartbeat with pipelined PP produced two ordered PROBED/PMD_SAMPLED outcomes without changing ownership', flush=True)
            zero.stdin.write(b'x'); zero.stdin.flush()
            output, errors = zero.communicate(timeout=15)
            require(zero.returncode == 0 and not live(zero_entry['epoch']), 'zero-count standby did not retire')

            # If a consumed P is followed by control EOF while its heartbeat
            # ACK is pending, it may emit PROBED but must not start PMD acquire
            # or observation. The resident is stopped to make the ordering
            # deterministic; the exact child and master lease are then reaped.
            before_hup_status = status(); before_hup_owner = query(api.PMD_STATUS)
            hup = launch('lease', '--standby', extra_env={'KER_SESSION_TEST_DQ_PENDING_HB': '1'})
            hup_entry = ready(hup, 'KER_SESSION_ATTACHED'); ready(hup, 'KER_SESSION_PMD_STANDBY')
            hup_pidfd = os.pidfd_open(hup_entry['pid']); workers.append((hup_entry['pid'], hup_pidfd))
            stderr_marker(hup, 'KER_SESSION_TEST_DQ_INITIAL_HEARTBEAT_ACKED')
            stop_resident()
            hup.stdin.write(b'h'); hup.stdin.flush()
            stderr_marker(hup, 'KER_SESSION_TEST_DQ_HEARTBEAT_REQUESTED')
            stderr_marker(hup, 'KER_SESSION_TEST_DQ_HEARTBEAT_PENDING')
            hup.stdin.write(b'P'); hup.stdin.flush()
            stderr_marker(hup, 'KER_SESSION_TEST_DQ_P_CONSUMED')
            hup.stdin.close()
            probed = ready(hup, 'KER_SESSION_PROBED')
            stderr_marker(hup, 'KER_SESSION_TEST_DQ_CONTROL_HUP')
            resume_resident()
            hup.wait(timeout=15)
            hup_tail = hup.stdout.read().decode(errors='replace')
            wait_worker_dead(hup_pidfd); wait_epoch_released(hup_entry['epoch'])
            hup_errors = bytes(stderr_history[hup]) + hup.stderr.read()
            require(hup.returncode != 0 and probed['count'] == 0 and
                    'KER_SESSION_PMD_SAMPLED ' not in hup_tail and
                    b'KER_SESSION_TEST_DQ_PROBE_PMD_ACQUIRE' not in hup_errors and
                    status()['generation'] == before_hup_status['generation'] and
                    status()['token'] == before_hup_status['token'] and
                    status()['slot'] == before_hup_status['slot'] and
                    status()['process'] == before_hup_status['process'] and
                    query(api.PMD_STATUS) == before_hup_owner,
                    'control EOF after consumed P acquired/observed PMD or leaked the lease/pool')
            print('PASS: consumed P plus control EOF rejected PMD acquire/observation and reaped the exact lease', flush=True)

            # A frozen orphan cannot heartbeat, but it is still an exact live
            # borrower and its grant must never be preempted by the standby.
            signal.pidfd_send_signal(workers[0][1], signal.SIGSTOP)
            deadline = time.monotonic() + 5
            state = ''
            while time.monotonic() < deadline:
                try:
                    state = Path('/proc', str(one['pid']), 'stat').read_text().rsplit(')', 1)[1].split()[0]
                except FileNotFoundError:
                    state = ''
                if state in ('T', 't'): break
                time.sleep(0.01)
            require(state in ('T', 't') and not dead(workers[0][1]), 'borrower did not stop before master death')
            first.kill(); first.wait(timeout=5)
            require(not dead(workers[0][1]) and live(one['epoch']), 'stopped orphan lost exact epoch liveness')
            second.stdin.write(b'P'); second.stdin.flush()
            sample, absent = round_sample(second, 32, False, one['epoch'])
            require(absent is None and not dead(workers[0][1]), 'standby preempted a stopped live consumer')
            signal.pidfd_send_signal(workers[0][1], signal.SIGKILL)
            require(os.waitpid(one['pid'], 0)[0] == one['pid'], 'exact orphan reap failed')
            deadline = time.monotonic() + 5
            while live(one['epoch']) and time.monotonic() < deadline: time.sleep(0.02)
            require(not live(one['epoch']) and live(two['epoch']) and live(0), 'dead/standby/resident epoch verdict wrong')
            require(query(api.PMD_STATUS)['token'] == 0, 'dead owner was not reclaimed before retry')
            # Same standby PID, EAL attachment and epoch take over: no restart
            # or independent primary can stand in for ownership transfer.
            second.stdin.write(b'P'); second.stdin.flush()
            sample, data = round_sample(second, 48, True, two['epoch'])
            require(sample['pid'] == two['pid'] and data['pid'] == two['pid'] and data['sequence'] == 16,
                    'takeover restarted the secondary or skipped actual PMD I/O')
            require(status()['generation'] == 509 and status()['token'] == 2, 'old PMD lease not replaced exactly once')
            # Recycle the former owner's exact slot while its old epoch must
            # remain dead. A coordinate match must never revive a retired epoch.
            third = launch('lease', '--standby', '--probe-count', '16')
            three = ready(third, 'KER_SESSION_ATTACHED'); ready(third, 'KER_SESSION_PMD_STANDBY')
            workers.append((three['pid'], os.pidfd_open(three['pid'])))
            require(three['slot'] == one['slot'] and three['epoch'] > two['epoch'] and
                    not live(one['epoch']) and live(three['epoch']), 'recycled slot revived a stale epoch')
            third.stdin.write(b'P'); third.stdin.flush()
            sample, absent = round_sample(third, 16, False, two['epoch'])
            require(absent is None, 'recycled standby consumed the active device')
            third.stdin.write(b'x'); third.stdin.flush()
            output, errors = third.communicate(timeout=15)
            require(third.returncode == 0, 'recycled standby cleanup failed: ' + errors.decode())
            second.stdin.write(b'P'); second.stdin.flush()
            sample, data = round_sample(second, 64, True, two['epoch'])
            require(data['sequence'] == 32, 'continued PMD sequence reset after takeover')
            second.stdin.write(b'x'); second.stdin.flush()
            output, errors = second.communicate(timeout=15)
            require(second.returncode == 0, 'standby cleanup failed: ' + errors.decode())
            deadline = time.monotonic() + 5
            while (live(two['epoch']) or status()['process']) and time.monotonic() < deadline: time.sleep(0.02)
            require(not live(one['epoch']) and not live(two['epoch']) and not live(three['epoch']) and live(0), 'retired epochs did not expire with resident alive')
            require(status()['generation'] == 511 and status()['token'] == 0, 'standby handover leaked original objects')
            diagnostic = subprocess.run([sys.executable, str(args.tool), 'epoch-status', '--socket', str(path),
                '--epoch', str(two['epoch'])], capture_output=True, timeout=5)
            require(diagnostic.returncode == 0 and json.loads(diagnostic.stdout)['live'] is False,
                    'production epoch-status tool verdict wrong')
            primary.stdin.close(); primary.stdin = None
            try:
                primary_output, primary_errors = primary.communicate(timeout=20)
            except subprocess.TimeoutExpired:
                primary.kill()
                primary_output, primary_errors = primary.communicate(timeout=5)
                raise RuntimeError('resident cleanup timed out: stdout=' + primary_output.decode(errors='replace') +
                    ' stderr=' + primary_errors.decode(errors='replace'))
            require(primary.returncode == 0, 'resident cleanup failed: ' + primary_errors.decode(errors='replace'))
            require(b'KER_SESSION_DRAINED' in primary_output, 'resident did not return all shared objects')
            print('PASS: two distinct live master/secondary chains sampled one coherent original-PMD consumer; standby controlled no data')
            print('PASS: frozen live orphan retains ownership; same standby PID/EAL/epoch takes over after exact borrower death')
            print('PASS: source A4 epoch liveness: dead masters with live workers stay live, retired epochs die, resident epoch0 stays live')
            print('PASS: original PMD frame/counter proof before and after takeover; all511 original objects restored')
            print('BOUNDARY: no fixed network dispatch, exception-owner routing, original-Linux delivery or full reload proof')
        finally:
            resume_resident()
            for process in reversed(processes): stop(process)
            for pid, fd in workers:
                if not dead(fd):
                    signal.pidfd_send_signal(fd, signal.SIGKILL)
                    os.waitpid(pid, 0)
                os.close(fd)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
