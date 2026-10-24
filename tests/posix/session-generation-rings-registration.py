#!/usr/bin/env python3
"""Exercise generation-ring admission through the real resident ATTACHED path."""
import argparse
import errno
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


def read_record(process, prefix, timeout=30):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        if not selector.select(timeout):
            raise RuntimeError(prefix + ' timed out')
    line = process.stdout.readline().decode().strip()
    if not line.startswith(prefix + ' '):
        raise RuntimeError('unexpected worker output: ' + line)
    return json.loads(line[len(prefix) + 1:])


def stop_worker(worker):
    if worker.poll() is None:
        worker.stdin.write(b'x')
        worker.stdin.flush()
    out, err = worker.communicate(timeout=20)
    if worker.returncode:
        raise RuntimeError('secondary cleanup failed: ' + err.decode() + out.decode())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', type=Path, required=True)
    parser.add_argument('--tool', type=Path, required=True)
    parser.add_argument('--huge-dir', type=Path, default=Path('/dev/hugepages'))
    parser.add_argument('--tx-full-only', action='store_true')
    args = parser.parse_args()
    reason = hugepage_capacity_error(args.huge_dir, 64 * 1024 * 1024)
    if reason:
        print('SKIP: ' + reason + '; no host settings changed')
        return 77
    spec = importlib.util.spec_from_file_location('ker_session_tool', args.tool)
    api = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(api)
    run_id = f'{os.getpid()}-{os.urandom(6).hex()}'
    cpu = min(os.sched_getaffinity(0))
    eal = (f'--lcores=0@{cpu} --no-pci --no-telemetry --iova-mode=va -m 64 '
           f'--huge-dir={args.huge_dir} --file-prefix=genrings-{run_id}')
    workers = []
    masters = []
    resident = None
    with tempfile.TemporaryDirectory(prefix='ker-generation-rings-') as temporary:
        root = Path(temporary)
        socket_path = root / 'control.sock'
        env = dict(os.environ, RUNTIME_DIRECTORY=str(root))
        common = ['--socket', str(socket_path), '--worker', str(args.worker), '--eal', eal]
        resident = subprocess.Popen([sys.executable, str(args.tool), 'serve', '--generation-rings',
            *common], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, bufsize=0)
        try:
            ready = read_record(resident, 'KER_SESSION_READY')

            def start_worker(ticket, generation):
                read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
                try:
                    test_mode = '--generation-tx-full-test' if args.tx_full_only else '--generation-rings-test'
                    child = subprocess.Popen([str(args.worker), '--role', 'secondary',
                        '--socket', str(socket_path), '--control-fd', '0', '--ticket-fd', str(read_fd),
                        '--generation', str(generation), '--process', '0', '--generation-rings',
                        test_mode, '--',
                        *api.role_arguments(eal, 'secondary')], pass_fds=(read_fd,), stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, bufsize=0)
                    workers.append(child)
                    if os.write(write_fd, api.encode(ticket)) != api.WIRE.size:
                        raise RuntimeError('short master ticket write')
                    return child
                finally:
                    os.close(read_fd)
                    os.close(write_fd)

            def attach(ticket, generation):
                child = start_worker(ticket, generation)
                return child, read_record(child, 'KER_SESSION_ATTACHED')

            entries = []
            for generation in (0, 1):
                master = api.Connection(socket_path)
                masters.append(master)
                ticket = master.request(api.MASTER)
                child, attached = attach(ticket, generation)
                if (ticket['session'] != ready['session'] or attached['pid'] != child.pid or
                        attached['generation'] != generation or attached['process'] != 0 or
                        attached['slot'] != ticket['slot'] or attached['epoch'] != ticket['epoch']):
                    raise RuntimeError('ATTACHED identity did not match its master ticket')
                entries.append((master, child, ticket, attached))
            if (entries[0][3]['slot'] == entries[1][3]['slot'] or
                    entries[0][3]['epoch'] == entries[1][3]['epoch']):
                raise RuntimeError('fixture did not exercise independent registered slots/epochs')

            def probe(entry_index, expected_step):
                _master, child, _ticket, attached = entries[entry_index]
                child.stdin.write(b'G')
                child.stdin.flush()
                marker = read_record(child, 'KER_GENERATION_PROBED')
                if marker != {'generation': attached['generation'], 'step': expected_step}:
                    raise RuntimeError('authenticated generation ring operation marker mismatch: ' + repr(marker))

            def release(master, ticket):
                deadline = time.monotonic() + 10
                while True:
                    try:
                        master.request(api.RELEASE, session=ticket['session'], epoch=ticket['epoch'],
                            token=ticket['token'], slot=ticket['slot'])
                        return
                    except OSError as error:
                        if error.errno != errno.EBUSY or time.monotonic() >= deadline:
                            raise
                        time.sleep(0.05)

            # Each operation runs inside the actual EAL secondary only after
            # the resident accepted its ATTACHED identity and exact PIDFD.
            if args.tx_full_only:
                probe(0, 0); probe(1, 0)
            else:
                probe(0, 0); probe(1, 0)
                probe(0, 1); probe(1, 1)
                probe(0, 2); probe(1, 2)
                print('NR19_RESIDENT_G_PROBES_PASS count=6 gen0_steps=0,1,2 gen1_steps=0,1,2 distinct_slots_epochs=true', flush=True)

            duplicate_master = api.Connection(socket_path)
            masters.append(duplicate_master)
            duplicate_ticket = duplicate_master.request(api.MASTER)
            duplicate = start_worker(duplicate_ticket, 0)
            out, err = duplicate.communicate(timeout=20)
            if duplicate.returncode == 0 or b'KER_SESSION_ATTACHED' in out or b'KER_GENERATION_PROBED' in out:
                raise RuntimeError('second live owner for generation zero was admitted')
            release(duplicate_master, duplicate_ticket)
            masters.remove(duplicate_master)
            duplicate_master.close()

            for master, child, ticket, attached in entries:
                stop_worker(child)
                release(master, ticket)
                master.close()
                masters.remove(master)
            resident.stdin.write(b'x')
            resident.stdin.flush()
            output, errors = resident.communicate(timeout=20)
            if resident.returncode:
                raise RuntimeError('resident cleanup failed: ' + errors.decode() + output.decode())
            if args.tx_full_only:
                drained = [json.loads(line.removeprefix('KER_SESSION_DRAINED '))
                    for line in output.decode(errors='replace').splitlines()
                    if line.startswith('KER_SESSION_DRAINED ')]
                if len(drained) != 1:
                    raise RuntimeError('resident omitted exactly one final generation-ring stats summary')
                stats = drained[0]['generation_rings']
                expected_fields = {'rx_full', 'tx_full', 'tx_drop', 'rx_peak', 'tx_peak',
                    'rx_capacity', 'tx_capacity', 'rx_rings', 'tx_rings'}
                if (set(stats) != expected_fields or stats['rx_full'] != 0 or stats['tx_full'] != 1 or
                    stats['tx_drop'] != 0 or stats['rx_peak'] != 0 or stats['rx_rings'] != 4 or
                    stats['tx_rings'] != 4 or stats['rx_capacity'] != 64 or stats['tx_capacity'] != 64 or
                    stats['tx_peak'] < stats['tx_capacity']):
                    raise RuntimeError('TX full-ring visibility or ownership metrics differ: ' + repr(stats))
                print('FM4_1_TX_FULL_VISIBILITY_PASS tx_full=1 tx_drop=0 tx_peak=' +
                    str(stats['tx_peak']) + ' capacity=' + str(stats['tx_capacity']) + ' rx_peak=0', flush=True)
            print('PASS: exact resident ATTACHED admissions for two live generations with distinct slots/epochs; duplicate generation owner rejected; clean teardown')
            return 0
        finally:
            for child in workers:
                if child.poll() is None:
                    child.send_signal(signal.SIGTERM)
                    try:
                        child.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.communicate(timeout=5)
            for master in masters:
                master.close()
            if resident.poll() is None:
                resident.stdin.write(b'x')
                resident.stdin.flush()
                try:
                    resident.communicate(timeout=20)
                except subprocess.TimeoutExpired:
                    resident.kill()
                    resident.communicate(timeout=5)


if __name__ == '__main__':
    raise SystemExit(main())
