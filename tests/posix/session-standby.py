#!/usr/bin/env python3
"""Live secondary standby, coherent owner samples and exact-lifetime takeover."""
import argparse
import ctypes
import importlib.util
import json
import os
from pathlib import Path
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
    require(ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0, 'subreaper setup')
    processes, workers = [], []
    with tempfile.TemporaryDirectory(prefix='ker-standby-') as directory:
        root = Path(directory); path = root / 'control.sock'
        eal = (f'--lcores=0@{min(os.sched_getaffinity(0))} --no-pci --no-telemetry --iova-mode=va '
               f'-m 64 --huge-dir={args.huge_dir} --file-prefix=standby-{os.getpid()}-{os.urandom(4).hex()}')
        common = ['--socket', str(path), '--worker', str(args.worker), '--eal', eal, '--ring-pmd']

        def launch(action, *extra):
            process = subprocess.Popen([sys.executable, str(args.tool), action, *common, *extra],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
                env=os.environ | {'RUNTIME_DIRECTORY': str(root)})
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

        def round_sample(process, sequence, owns, owner_epoch):
            response = ready(process, 'KER_SESSION_PROBED')
            sample = ready(process, 'KER_SESSION_PMD_SAMPLED')
            require(response['sequence'] == sequence and sample['sequence'] == sequence and
                    sample['owns_device'] == owns and sample['owner_epoch'] == owner_epoch and
                    sample['owner_generation'] == 0 and sample['owner_process'] == 0,
                    'inconsistent live ownership sample: ' + str(sample))
            if owns:
                data = ready(process, 'KER_SESSION_PMD_PROBED')
                require(data['count'] == 16 and data['frame_bytes'] == 174, 'actual PMD burst evidence missing')
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
            zero = launch('lease', '--standby')
            zero_entry = ready(zero, 'KER_SESSION_ATTACHED'); ready(zero, 'KER_SESSION_PMD_STANDBY')
            workers.append((zero_entry['pid'], os.pidfd_open(zero_entry['pid'])))
            zero.stdin.write(b'P'); zero.stdin.flush()
            no_probe = ready(zero, 'KER_SESSION_PROBED'); census_only = ready(zero, 'KER_SESSION_PMD_SAMPLED')
            require(no_probe['count'] == 0 and no_probe['sequence'] == 0 and
                    not census_only['owns_device'] and census_only['owner_epoch'] == one['epoch'] and
                    zero.poll() is None, 'zero-count standby exited or fabricated traffic')
            zero.stdin.write(b'x'); zero.stdin.flush()
            output, errors = zero.communicate(timeout=15)
            require(zero.returncode == 0 and not live(zero_entry['epoch']), 'zero-count standby did not retire')
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
            for process in reversed(processes): stop(process)
            for pid, fd in workers:
                if not dead(fd):
                    signal.pidfd_send_signal(fd, signal.SIGKILL)
                    os.waitpid(pid, 0)
                os.close(fd)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
