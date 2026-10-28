#!/usr/bin/env python3
"""Original EAL secondaries exercise exported IPC with actual shared ownership.

A host without usable shared hugepages explicitly skips. Such a skip is not
source completion evidence; the isolated guest supplies the required profile.
"""
import argparse
import json
import os
from pathlib import Path
import selectors
import subprocess
import tempfile
import time
from hugepage_preflight import hugepage_capacity_error


def require(value, message):
    if not value:
        raise RuntimeError(message)


class Process:
    def __init__(self, command, env, directory, name):
        self.error = (directory / (name + '.stderr')).open('wb')
        self.child = subprocess.Popen(command, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=self.error, bufsize=0)
        self.log = []

    def record(self, prefix, timeout=45):
        deadline, line = time.monotonic() + timeout, bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(self.child.stdout, selectors.EVENT_READ)
            while time.monotonic() < deadline:
                if not selector.select(max(0, deadline-time.monotonic())):
                    break
                byte = os.read(self.child.stdout.fileno(), 1)
                if not byte:
                    break
                if byte != b'\n':
                    line.extend(byte)
                    continue
                text = line.decode(); line.clear(); self.log.append(text)
                if text.startswith(prefix+' '):
                    return json.loads(text[len(prefix)+1:])
        raise RuntimeError(f'missing {prefix} from process {self.child.pid}: {self.log}')

    def command(self, text, prefix):
        self.child.stdin.write((text+'\n').encode()); self.child.stdin.flush()
        return self.record(prefix)

    def close(self):
        self.command('exit', 'CLOSED')
        require(self.child.wait(timeout=20) == 0, 'secondary cleanup failed')

    def stop(self):
        if self.child.poll() is None:
            self.child.terminate()
            try:
                self.child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.child.kill(); self.child.wait(timeout=5)
        self.error.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app', type=Path, required=True)
    parser.add_argument('--unit-app', type=Path, required=True)
    parser.add_argument('--huge-dir', type=Path, default=Path('/dev/hugepages'))
    parser.add_argument('--pmd-root', type=Path, required=True)
    parser.add_argument('--evidence', type=Path)
    args = parser.parse_args()
    reason = hugepage_capacity_error(args.huge_dir, 64*1024*1024)
    if reason:
        print('SKIP: '+reason+'; no host settings changed')
        return 77
    modules = list(args.pmd_root.glob('dpdk/pmds-*/librte_mempool_ring.so'))
    require(len(modules) == 1, 'exactly one selected original mempool_ring module is required')
    nonce = os.urandom(7).hex()
    evidence = {'profile': 'actual original EAL primary/secondaries, shared hugepages',
                'nonce': nonce, 'secondary_pids': [], 'cases': [], 'pool_reclaimed': False}
    with tempfile.TemporaryDirectory(prefix='ker-ipc-mp-') as temporary:
        root = Path(temporary)
        huge = args.huge_dir / ('ker-ipc-'+nonce); huge.mkdir(mode=0o700)
        processes = []
        env = dict(os.environ, KER_IPC_MP_NONCE=nonce, RUNTIME_DIRECTORY=str(root),
                   LD_LIBRARY_PATH=str(args.pmd_root)+':'+os.environ.get('LD_LIBRARY_PATH',''))
        cpu = min(os.sched_getaffinity(0))
        common = [f'--lcores=0@{cpu}', '--no-pci', '--no-telemetry', '--iova-mode=va',
                  '--file-prefix=ipc-'+nonce, '--huge-dir='+str(huge), '-d', str(modules[0])]
        try:
            primary = Process([str(args.app), 'primary', '--proc-type=primary', '-m', '64', *common], env, root, 'primary')
            processes.append(primary)
            ready = primary.record('READY')
            require(ready == {'pid': primary.child.pid, 'nonce': nonce, 'available': 64}, 'primary identity/census mismatch')
            evidence['primary_pid'] = primary.child.pid
            client_env = dict(env, KER_IPC_MP_PRIMARY_PID=str(primary.child.pid))

            def client(process='0:0', generation='-', legacy=False):
                child = Process([str(args.app), 'legacy' if legacy else 'client', process, generation, '--proc-type=secondary', *common],
                                client_env, root, 'client-'+str(len(processes)))
                processes.append(child)
                attached = child.record('ATTACHED')
                require(attached['pid'] == child.child.pid and attached['primary'] == primary.child.pid,
                        'secondary did not attach the actual primary identity')
                require(child.child.pid != primary.child.pid, 'not an independent process')
                evidence['secondary_pids'].append(child.child.pid)
                return child, attached

            def status(available, inputs=0, outputs=0):
                actual = primary.command('status', 'STATUS')
                require(actual == {'available': available, 'input': inputs, 'output': outputs}, 'shared pool/ring census mismatch: '+str(actual))

            def pump(count):
                require(primary.command('pump','PUMP') == {'handled': count}, 'provider did not consume expected actual requests')

            malformed = subprocess.run([str(args.unit_app), 'malformed'], env=env,
                                       text=True, capture_output=True, timeout=45)
            require(malformed.returncode == 0 and
                    'PASS: original IPC coordinate/ownership contract malformed' in malformed.stdout,
                    'actual malformed argument exits failed: '+malformed.stdout+malformed.stderr)
            status(64)
            evidence['cases'].append('test_ff_ipc_rejects_malformed')
            # Exact address outputs, in real secondary EAL contexts; AUTO stays
            # unspecified and is never guessed into a successful transport.
            addresses = [
                ('test_ff_ipc_proc_id_plain', '1', '-', 1, -1, 4294967295, None),
                ('test_ff_ipc_proc_id_gen', '1:0', '-', 1, 0, 4294967295, 'ff_msg_ring_in_1_g0'),
                ('test_ff_ipc_proc_id_gen_epoch', '1:0:3', '-', 1, 0, 3, 'ff_msg_ring_in_1_e3_g0'),
                ('test_ff_ipc_proc_id_full_coordinate', '2:1:1', '-', 2, 1, 1, 'ff_msg_ring_in_2_e1_g1'),
                ('test_ff_ipc_gen_str_epoch', '-', '1:2', 0, 1, 2, 'ff_msg_ring_in_0_e2_g1'),
                ('test_ff_ipc_gen_str_plain', '-', '0', 0, 0, 4294967295, 'ff_msg_ring_in_0_g0'),
            ]
            for name, process, generation, proc, gen, epoch, input_name in addresses:
                child, attached = client(process, generation)
                require((attached['process'],attached['generation'],attached['epoch'],attached['input']) ==
                        (proc,gen,epoch,input_name), 'exact source coordinate/name mismatch')
                if input_name:
                    child.command('send 1 0','SENT'); status(63,inputs=1)
                    pump(1)
                    require(child.command('recv 1','RECV')['result'] == 0, 'coordinate roundtrip failed')
                    status(64)
                child.close(); evidence['cases'].append(name)

            for mode, source in [('own','test_p4_recv_own_reply'), ('live','test_p4_recv_foreign_live_owner'),
                                 ('no-send','test_p4_recv_foreign_without_send'), ('orphan','test_p4_recv_orphan_dead_owner'),
                                 ('probe','test_p4_probe_is_non_destructive')]:
                owner, _ = client(); kind = 10 if mode == 'probe' else 1
                sent = owner.command(f'send {kind} {int(mode == "orphan")}', 'SENT')
                require(sent['pid'] == owner.child.pid and sent['cookie'] != 0, 'owner stamp missing')
                status(63, inputs=1); pump(1); status(63,outputs=1)
                if mode == 'own':
                    require(owner.command('recv 1','RECV')['result'] == 0, 'own reply not received')
                    status(64); owner.close()
                else:
                    if mode == 'orphan':
                        owner.child.stdin.write(b'crash\n'); owner.child.stdin.flush()
                        require(owner.child.wait(timeout=20) == 0, 'exact orphan owner death missing')
                    reader, _ = client()
                    if mode == 'live':
                        reader.command('send 1 0', 'SENT'); status(62, inputs=1, outputs=1)
                    result = reader.command('probe' if mode == 'probe' else 'recv 1',
                                            'PROBE' if mode == 'probe' else 'RECV')
                    require(result['result'] < 0 and result['lost'] == 0, 'foreign reply returned/lost')
                    if mode == 'orphan':
                        require(result['orphan'] == 1 and result['requeued'] >= 2, 'orphan was not repeatedly observed and reclaimed')
                        status(64); reader.close()
                    else:
                        require(result['orphan'] == 0 and result['requeued'] > 0, 'live reply not preserved')
                        if mode == 'probe':
                            require(result['epoch'] == 77 and result['generation'] == 77, 'failed probe published outputs')
                        # Two proc0 reload endpoints exist (slot0/gen0 and
                        # slot2/gen1); the original probe must query both.
                        pending = 2 if mode == 'probe' else int(mode == 'live')
                        status(63-pending, inputs=pending, outputs=1)
                        reader.command('busy', 'BUSY')
                        require(owner.command(f'recv {kind}', 'RECV')['result'] == 0, 'rightful owner lost exact reply/payload')
                        if mode == 'probe':
                            cancelled = primary.command(f'cancel {reader.child.pid}','CANCEL')
                            require(cancelled == {'cancelled':2}, 'actual abandoned QUERY objects not reclaimed')
                        elif mode == 'live':
                            pump(1)
                            late = reader.command(f'recv {kind}', 'RECV')
                            require(late['result'] < 0 and late['orphan'] == 0 and late['lost'] == 0,
                                    'late own reply not safely retired')
                        status(64); reader.close(); owner.close()
                evidence['cases'].append(source)
                # A new actual secondary must still use the same queues/pool.
                successor, _ = client(); successor.command('send 1 0','SENT'); pump(1)
                require(successor.command('recv 1','RECV')['result'] == 0, 'valid successor failed')
                status(64); successor.close()
            for profile in ['epoch-names', 'legacy-names']:
                checked = subprocess.run([str(args.unit_app), profile], env=env,
                                         text=True, capture_output=True, timeout=45)
                require(checked.returncode == 0 and
                        'PASS: original IPC coordinate/ownership contract '+profile in checked.stdout,
                        'source ring builder assertions failed: '+checked.stdout+checked.stderr)
            legacy, attached = client('1', '-', legacy=True)
            require(attached['generation'] == -1 and attached['epoch'] == 4294967295 and
                    attached['input'] == 'ff_msg_ring_in_1', 'legacy AUTO resolution changed coordinates/name')
            legacy.command('send 1 0','SENT'); status(63, inputs=1); pump(1)
            require(legacy.command('recv 1','RECV')['result'] == 0, 'actual legacy shared transport failed')
            status(64); legacy.close()
            evidence['cases'].extend(['test_ut_nr_m5_epoch_slot_and_ring_name',
                                      'test_ut_nr_m5_graceful_zero_epoch_invariance'])
            require(len(evidence['cases']) == 14, 'missing acceptance phase')
            require(all(p.child.poll() == 0 for p in processes[1:]), 'a secondary is still live or failed')
            require(primary.command('quit','CLOSED') == {'available':64,'outstanding':0}, 'primary failed full reclamation')
            require(primary.child.wait(timeout=20) == 0, 'primary EAL cleanup failed')
            evidence['pool_reclaimed'] = True
            if args.evidence:
                args.evidence.write_text(json.dumps(evidence,indent=2)+'\n')
            print('PASS: actual primary/secondary IPC ownership, coordinates and64/64 pool reclamation')
            for source in evidence['cases']:
                print('IPC_MP_SOURCE_CASE '+source)
            return 0
        except BaseException:
            for index, p in enumerate(processes):
                p.error.flush()
                print(f'PROCESS {index} pid={p.child.pid} records={p.log}', flush=True)
                path = root/('primary.stderr' if index == 0 else f'client-{index}.stderr')
                if path.exists(): print(path.read_text(errors='replace'), flush=True)
            raise
        finally:
            for process in reversed(processes): process.stop()
            # Only this private directory is cleaned, after exact children end.
            for path in huge.iterdir():
                require(path.is_file() and not path.is_symlink(), 'unexpected private backing entry')
                path.unlink()
            huge.rmdir()


if __name__ == '__main__':
    raise SystemExit(main())
