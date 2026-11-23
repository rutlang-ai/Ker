#!/usr/bin/env python3
"""Original secondary net_ring bursts and resident single-consumer lease acceptance."""
import argparse
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import selectors
import signal
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
        require(selector.select(20), 'readiness timeout: ' + prefix)
    line = process.stdout.readline().decode().strip()
    if not line:
        process.wait(timeout=5)
        raise RuntimeError('premature exit: ' + process.stderr.read().decode())
    require(line.startswith(prefix + ' '), 'unexpected record: ' + line)
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
    reason = hugepage_capacity_error(args.huge_dir, 64 * 1024 * 1024)
    if reason:
        print('SKIP: ' + reason + '; no host settings changed')
        return 77
    spec = importlib.util.spec_from_file_location('ker_session_tool', args.tool)
    api = importlib.util.module_from_spec(spec); spec.loader.exec_module(api)
    expected_frame_bytes = 14 + api.WIRE.size + 8 + 64
    require(ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0, 'subreaper setup')
    processes, orphan_pidfds = [], []
    with tempfile.TemporaryDirectory(prefix='ker-pmd-') as directory:
        root = Path(directory); path = root / 'control.sock'
        eal = (f'--lcores=0@{min(os.sched_getaffinity(0))} --no-pci --no-telemetry --iova-mode=va '
               f'-m 64 --huge-dir={args.huge_dir} --file-prefix=pmd-{os.getpid()}-{os.urandom(4).hex()}')
        common = ['--socket', str(path), '--worker', str(args.worker), '--eal', eal, '--ring-pmd']

        def launch(action, *extra):
            process = subprocess.Popen([sys.executable, str(args.tool), action, *common, *extra],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
                env=os.environ | {'RUNTIME_DIRECTORY': str(root)})
            processes.append(process)
            return process

        def request(command):
            connection = api.Connection(path)
            try:
                return connection.request(command)
            finally:
                connection.close()

        def empty():
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                census, owner = request(api.STATUS), request(api.PMD_STATUS)
                if census['slot'] == 0 and census['process'] == 0 and owner['token'] == 0:
                    require(census['generation'] == 511 and census['token'] == 0, 'PMD/control leases leaked')
                    return
                time.sleep(0.02)
            raise RuntimeError('dead PMD owner not reclaimed')

        def borrower(count=64):
            process = launch('lease', '--probe-count', str(count))
            entry = ready(process, 'KER_SESSION_ATTACHED')
            require(entry['epoch'] > 0 and 1 <= entry['slot'] < 4 and entry['generation'] == 0 and entry['process'] == 0,
                    'secondary did not obtain its own nonresident coordinate')
            require(entry['rings'] == [f"ker_s{entry['slot']}_g0_p0_{channel}" for channel in ('ctl', 'rx', 'tx', 'reply')],
                    'actual looked-up rings do not belong to the secondary coordinate')
            grant = ready(process, 'KER_SESSION_PMD_GRANTED')
            require(grant['pid'] == entry['pid'] and grant['epoch'] == entry['epoch'] and grant['slot'] == entry['slot'],
                    'grant identity differs from real EAL borrower')
            orphan_pidfds.append((entry['pid'], os.pidfd_open(entry['pid'])))
            return process, entry

        def burst(process, sequence, count):
            process.stdin.write(b'P'); process.stdin.flush()
            control = ready(process, 'KER_SESSION_PROBED')
            data = ready(process, 'KER_SESSION_PMD_PROBED')
            require(control['sequence'] == sequence and data['sequence'] == sequence and
                    data['count'] == count and data['frame_bytes'] == expected_frame_bytes,
                    'original PMD frame/sequence evidence differs')

        primary = launch('serve')
        try:
            require(ready(primary, 'KER_SESSION_READY')['ring_pmd'], 'original PMD not configured')
            require(request(api.PMD_STATUS)['token'] == 0, 'resident started with active consumer')
            first, entry = borrower()
            owner = request(api.PMD_STATUS)
            require(owner['epoch'] == entry['epoch'] and owner['slot'] == entry['slot'] and owner['token'],
                    'owner query is not the active consumer')
            census = request(api.STATUS)
            require(census['generation'] == 509 and census['token'] == 2, 'PMD object not journaled before grant')
            # Another real EAL secondary may attach; only the granted process
            # may call bursts. Rejection must not disturb the existing owner.
            rejected = launch('probe', '--generation', '1', '--process', '1')
            output, errors = rejected.communicate(timeout=20)
            require(rejected.returncode != 0 and b'PMD consumer grant rejected -16' in errors and
                    b'KER_SESSION_PMD_PROBED' not in output, 'second live consumer was admitted: ' + errors.decode())
            require(request(api.PMD_STATUS) == owner, 'failed acquisition changed owner identity')
            burst(first, 64, 64); burst(first, 128, 64)
            # Master EOF/death cannot revoke a surviving secondary's grant.
            pidfd = orphan_pidfds[-1][1]
            signal.pidfd_send_signal(pidfd, signal.SIGSTOP)
            stop_deadline = time.monotonic() + 5
            while Path(f'/proc/{entry["pid"]}/stat').read_text().rsplit(')', 1)[1].split()[0] not in ('T', 't'):
                require(time.monotonic() < stop_deadline, 'PMD borrower did not stop before master death')
                time.sleep(0.01)
            first.kill(); first.wait(timeout=5)
            require(not selectors_for_death(pidfd), 'stopped secondary died with master')
            require(request(api.PMD_STATUS) == owner, 'dead master released a live PMD consumer')
            rejected = launch('probe')
            output, errors = rejected.communicate(timeout=20)
            require(rejected.returncode != 0 and b'PMD consumer grant rejected -16' in errors,
                    'orphan live consumer lost exclusivity')
            signal.pidfd_send_signal(pidfd, signal.SIGKILL)
            waited, status = os.waitpid(entry['pid'], 0)
            require(waited == entry['pid'] and os.WIFSIGNALED(status), 'exact orphan death not reaped')
            empty()
            replacement, newer = borrower(32)
            require(newer['epoch'] > entry['epoch'], 'consumer epoch was reused')
            burst(replacement, 32, 32)
            replacement.stdin.write(b'x'); replacement.stdin.flush()
            output, errors = replacement.communicate(timeout=20)
            require(replacement.returncode == 0, 'replacement EAL cleanup failed: ' + errors.decode())
            empty()
            # Crash before the first TX still owes its privately journaled object.
            idle, idle_entry = borrower()
            idle_pidfd = orphan_pidfds[-1][1]
            signal.pidfd_send_signal(idle_pidfd, signal.SIGSTOP)
            stop_deadline = time.monotonic() + 5
            while Path(f'/proc/{idle_entry["pid"]}/stat').read_text().rsplit(')', 1)[1].split()[0] not in ('T', 't'):
                require(time.monotonic() < stop_deadline, 'idle PMD borrower did not stop before master death')
                time.sleep(0.01)
            idle.kill(); idle.wait(timeout=5)
            require(not selectors_for_death(idle_pidfd), 'idle PMD borrower exited before exact-death reclamation')
            require(request(api.PMD_STATUS)['token'] != 0, 'master death released a stopped idle PMD lease')
            signal.pidfd_send_signal(idle_pidfd, signal.SIGKILL)
            require(os.waitpid(idle_entry['pid'], 0)[0] == idle_entry['pid'], 'idle orphan reap')
            empty()
            diagnostic = subprocess.run([sys.executable, str(args.tool), 'device-status', '--socket', str(path)],
                capture_output=True, timeout=5)
            require(diagnostic.returncode == 0 and json.loads(diagnostic.stdout)['owner'] == 0,
                    'production owner query failed')
            primary.stdin.close(); primary.stdin = None
            try:
                primary_output, primary_errors = primary.communicate(timeout=20)
            except subprocess.TimeoutExpired:
                primary.kill()
                primary_output, primary_errors = primary.communicate(timeout=5)
                raise RuntimeError('resident EAL/device cleanup timed out: stdout=' +
                    primary_output.decode(errors='replace') + ' stderr=' + primary_errors.decode(errors='replace'))
            require(primary.returncode == 0, 'resident EAL/device cleanup failed: ' + primary_errors.decode())
            require(b'KER_SESSION_DRAINED' in primary_output, 'pool cleanup proof missing')
            print('PASS: original secondary net_ring TX/RX frames with exact ABI-sized payloads and PMD counter deltas')
            print('PASS: single consumer, active owner query, dead-master/live-secondary exclusion, newer-epoch takeover')
            print('PASS: private PMD lease recovered after borrower death before TX and after RX;511 objects restored')
            print('BOUNDARY: ring PMD qualification; no physical NIC, imported-Linux delivery or full reload assertion')
        finally:
            for process in reversed(processes): stop(process)
            for pid, fd in orphan_pidfds:
                if not selectors_for_death(fd):
                    signal.pidfd_send_signal(fd, signal.SIGKILL)
                    os.waitpid(pid, 0)
                os.close(fd)
    return 0


def selectors_for_death(pidfd):
    with selectors.DefaultSelector() as selector:
        selector.register(pidfd, selectors.EVENT_READ)
        return bool(selector.select(0))


if __name__ == '__main__':
    raise SystemExit(main())
