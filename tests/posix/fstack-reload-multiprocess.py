#!/usr/bin/env python3
"""Real original net_ring bursts under shared same-master ownership markers."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
from hugepage_preflight import hugepage_capacity_error

spec = importlib.util.spec_from_file_location('ipc_process_fixture', Path(__file__).with_name('fstack-ipc-multiprocess.py'))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
Process, require = fixture.Process, fixture.require


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app', type=Path, required=True)
    parser.add_argument('--unit-app', type=Path, required=True)
    parser.add_argument('--pmd-root', type=Path, required=True)
    parser.add_argument('--huge-dir', type=Path, default=Path('/dev/hugepages'))
    parser.add_argument('--evidence', type=Path)
    args = parser.parse_args()
    reason = hugepage_capacity_error(args.huge_dir, 64*1024*1024)
    if reason:
        print('SKIP: '+reason+'; no host settings changed')
        return 77
    modules = []
    for name in ['mempool_ring', 'net_ring']:
        found = list(args.pmd_root.glob('dpdk/pmds-*/librte_'+name+'.so'))
        require(len(found) == 1, 'exactly one selected original '+name+' module is required')
        modules.extend(['-d', str(found[0])])
    nonce = os.urandom(7).hex()
    evidence = {'profile': 'original EAL primary/secondaries, original net_ring RX/TX, same-master shared block',
                'nonce': nonce, 'secondary_pids': [], 'cases': [], 'pool_reclaimed': False}
    with tempfile.TemporaryDirectory(prefix='ker-reload-poll-') as temporary:
        root = Path(temporary); huge = args.huge_dir/('ker-poll-'+nonce); huge.mkdir(mode=0o700)
        processes = []
        env = dict(os.environ, KER_RELOAD_POLL_NONCE=nonce, RUNTIME_DIRECTORY=str(root),
                   LD_LIBRARY_PATH=str(args.pmd_root)+':'+os.environ.get('LD_LIBRARY_PATH',''))
        cpu = min(os.sched_getaffinity(0))
        common = [f'--lcores=0@{cpu}', '--no-pci', '--no-telemetry', '--iova-mode=va',
                  '--file-prefix=poll-'+nonce, '--huge-dir='+str(huge), *modules]
        try:
            for profile in ['markers', 'barrier']:
                checked = subprocess.run([str(args.unit_app),profile],env=env,text=True,capture_output=True,timeout=45)
                require(checked.returncode == 0 and 'PASS: original same-master poll '+profile in checked.stdout,
                        'exact source assertions failed: '+checked.stdout+checked.stderr)
            primary = Process([str(args.app),'primary','--proc-type=primary','-m','64',*common],env,root,'primary')
            processes.append(primary)
            require(primary.record('READY') == {'pid':primary.child.pid,'nonce':nonce,'available':63,'driver':'net_ring'},
                    'primary role/identity/driver/census mismatch')
            evidence['primary_pid'] = primary.child.pid
            worker_env = dict(env,KER_RELOAD_POLL_PRIMARY_PID=str(primary.child.pid))

            def worker(generation, slot):
                p = Process([str(args.app),'worker',str(generation),str(slot),'--proc-type=secondary',*common],
                            worker_env,root,'worker-'+str(len(processes)))
                processes.append(p)
                require(p.record('ATTACHED') == {'pid':p.child.pid,'primary':primary.child.pid,'generation':generation,'slot':slot},
                        'secondary did not attach the actual primary/state/PMD')
                evidence['secondary_pids'].append(p.child.pid)
                return p

            def poll(p, callbacks, received):
                r = p.command('poll','POLL')
                require(r == {'result':received,'callbacks':callbacks,'received':callbacks, 'completed':callbacks}, 'unexpected gated poll: '+str(r))
                return r

            def release(to, epoch, result):
                r = primary.command(f'release {to} {epoch}', 'RELEASE')
                require(r['result'] == result, 'release ignored park proof: '+str(r))
                return r

            def inject(sequence):
                require(primary.command(f'inject {sequence}','INJECTED') == {'sequence':sequence,'available':62}, 'actual mbuf allocation/enqueue failed')

            def collect(sequence):
                require(primary.command('collect','COLLECTED') == {'sequence':sequence,'available':63}, 'same mbuf/payload reclamation failed')

            old0, old1, new = worker(0,0), worker(0,1), worker(1,2)
            poll(new,0,0)
            require(new.command('claim 0','CLAIM') == {'result':-3,'owner':0,'stopped':0},
                    'new generation stole an unparked queue')
            inject(1)
            old0.child.stdin.write(b'poll hold\n'); old0.child.stdin.flush()
            require(old0.record('ENTERED') == {'slot':0,'generation':0}, 'old worker did not enter actual packet callback')
            before = primary.command('status','STATUS')
            require(before['inflight'] == [1,0] and before['rx'] == 1 and before['ipackets'] == 0, 'held callback consumed early')
            first = primary.command('park','PARK')['epoch']; require(first == 1, 'wrong initial park epoch')
            poll(old1,0,0); poll(new,0,0)
            require(primary.command(f'acks {first}','ACKS') == {'slots':[0,1,1]}, 'in-flight old callback acknowledged before return')
            release(1,first,-11)
            old0.child.stdin.write(b'continue\n'); old0.child.stdin.flush()
            require(old0.record('POLL') == {'result':1,'callbacks':1,'received':1,'completed':1}, 'old callback did not complete exact RX/TX pass')
            collect(1)
            release(1,first,-11)  # returned, but the old worker has not acknowledged yet
            poll(old0,1,0)
            require(primary.command(f'acks {first}','ACKS') == {'slots':[1,1,1]}, 'missing post-callback park proof')
            require(release(1,first,0) == {'result':0,'owner':1,'stopped':1}, 'release did not preserve park order')
            poll(new,0,0)
            require(new.command('claim 0','CLAIM') == {'result':0,'owner':1,'stopped':0}, 'new owner did not acquire')
            require(new.command('claim 0','CLAIM') == {'result':0,'owner':1,'stopped':0}, 'repeated claim not idempotent')
            inject(2); poll(old0,1,0); poll(old1,0,0); poll(new,1,1); collect(2)
            second = primary.command('park','PARK')['epoch']; require(second == first+1, 'park epoch did not advance')
            require(primary.command(f'acks {second}','ACKS') == {'slots':[0,0,0]}, 'stale epoch acknowledged the new round')
            release(0,second,-11); poll(old0,1,0); release(0,second,-11)
            poll(new,1,0)
            require(release(0,second,0) == {'result':0,'owner':0,'stopped':1}, 'reverse release failed')
            poll(old0,1,0)
            require(old0.command('claim 1','CLAIM') == {'result':0,'owner':0,'stopped':0}, 'old owner did not reacquire')
            inject(3); poll(new,1,0); poll(old1,1,1); collect(3)
            for p in [new,old1,old0]: p.close()
            successor = worker(0,0)
            inject(4)
            require(successor.command('poll','POLL') == {'result':1,'callbacks':2,'received':2,'completed':2}, 'same-slot successor failed original PMD reuse')
            collect(4); successor.close()
            final = primary.command('status','STATUS')
            require(final == {'available':63,'rx':0,'tx':0,'owner':0,'stopped':0,'inflight':[0,0],
                              'callbacks':[2,1,1,0],'ipackets':4,'opackets':4}, 'actual PMD/callback/census disagreement: '+str(final))
            require(all(p.child.poll() == 0 for p in processes[1:]), 'a secondary is still live or failed')
            require(primary.command('quit','CLOSED') == {'available':63,'outstanding':0}, 'primary reclamation failed')
            require(primary.child.wait(timeout=20) == 0, 'primary original EAL cleanup failed')
            evidence.update(pool_reclaimed=True, final=final,
                cases=['test_ut_nr_26_rx_handover_markers','test_ut_nr_11_handover_barrier'])
            if args.evidence: args.evidence.write_text(json.dumps(evidence,indent=2)+'\n')
            print('PASS: original net_ring RX/TX, exact park proof and reversible same-master ownership')
            for case in evidence['cases']: print('RELOAD_MP_SOURCE_CASE '+case)
            return 0
        except BaseException:
            for index,p in enumerate(processes):
                p.error.flush(); print(f'PROCESS {index} pid={p.child.pid} records={p.log}',flush=True)
            for path in root.glob('*.stderr'): print(str(path)+':\n'+path.read_text(errors='replace'),flush=True)
            raise
        finally:
            for p in reversed(processes): p.stop()
            for path in huge.iterdir():
                require(path.is_file() and not path.is_symlink(),'unexpected private backing entry'); path.unlink()
            huge.rmdir()


if __name__ == '__main__':
    raise SystemExit(main())
