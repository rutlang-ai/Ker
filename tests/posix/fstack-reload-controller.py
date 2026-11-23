#!/usr/bin/env python3
"""Actual caller-owned original FSM controls Ker/EAL/PMD lifetime."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
from hugepage_preflight import hugepage_capacity_error
spec=importlib.util.spec_from_file_location('ipc_process_fixture',Path(__file__).with_name('fstack-ipc-multiprocess.py'))
fixture=importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
Process,require=fixture.Process,fixture.require


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ['app','unit-app','pmd-root']: parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--huge-dir',type=Path,default=Path('/dev/hugepages'))
    parser.add_argument('--evidence',type=Path)
    args=parser.parse_args()
    reason=hugepage_capacity_error(args.huge_dir,64*1024*1024)
    if reason: print('SKIP: '+reason+'; no host settings changed'); return 77
    modules=[]
    for name in ['mempool_ring','net_ring']:
        paths=list(args.pmd_root.glob('dpdk/pmds-*/librte_'+name+'.so'))
        require(len(paths)==1,'one selected original '+name+' module required'); modules.extend(['-d',str(paths[0])])
    nonce=format(int.from_bytes(os.urandom(7), 'big') or 1, 'x')
    evidence={'profile':'caller original nginx FSM, Ker runtime, original EAL/net_ring','nonce':nonce,
              'secondary_pids':[],'cases':[],'events':[],'pool_reclaimed':False}
    with tempfile.TemporaryDirectory(prefix='ker-controller-') as temporary:
        root=Path(temporary); huge=args.huge_dir/('ker-controller-'+nonce); huge.mkdir(mode=0o700)
        env=dict(os.environ,KER_RELOAD_POLL_NONCE=nonce,RUNTIME_DIRECTORY=str(root),
                 LD_LIBRARY_PATH=str(args.pmd_root)+':'+os.environ.get('LD_LIBRARY_PATH',''))
        cpu=min(os.sched_getaffinity(0)); processes=[]
        common=[f'--lcores=0@{cpu}','--no-pci','--no-telemetry','--iova-mode=va',
                '--file-prefix=controller-'+nonce,'--huge-dir='+str(huge),*modules]
        try:
            for profile in ['transitions','legal','illegal','recovery']:
                checked=subprocess.run([str(args.unit_app),profile],env=env,text=True,capture_output=True,timeout=45)
                require(checked.returncode==0 and 'PASS: original caller reload FSM '+profile in checked.stdout,
                        'exact source FSM assertions failed: '+checked.stdout+checked.stderr)
            primary=Process([str(args.app),'primary','--proc-type=primary','-m','64',*common],env,root,'primary')
            processes.append(primary)
            require(primary.record('READY')=={'pid':primary.child.pid,'nonce':nonce,'available':63,'driver':'net_ring'},'actual primary mismatch')
            evidence['primary_pid']=primary.child.pid
            worker_env=dict(env,KER_RELOAD_POLL_PRIMARY_PID=str(primary.child.pid))

            def worker(generation,slot):
                p=Process([str(args.app),'worker',str(generation),str(slot),'--proc-type=secondary',*common],worker_env,root,'worker-'+str(len(processes)))
                processes.append(p)
                require(p.record('ATTACHED')=={'pid':p.child.pid,'primary':primary.child.pid,'generation':generation,'slot':slot},'actual secondary mismatch')
                require(primary.command(f'register {slot} {p.child.pid} {generation}','REGISTER')=={'result':0},'pidfd worker registration failed')
                evidence['secondary_pids'].append(p.child.pid); return p

            def event(value,result,state):
                actual=primary.command(f'event {value}','POLICY')
                require(actual['result']==result and actual['state']==state,'policy did not gate event: '+str(actual))
                evidence['events'].append(dict(event=value,**actual)); return actual

            def handover(result,state=2):
                actual=primary.command('handover','POLICY'); require(actual['result']==result and actual['state']==state,'handover bypassed policy/proof: '+str(actual)); return actual

            def poll(p,callbacks,result):
                require(p.command('poll','POLL')=={'result':result,'callbacks':callbacks,'received':callbacks,'completed':callbacks},'gated PMD callback mismatch')

            def inject(n): require(primary.command(f'inject {n}','INJECTED')=={'sequence':n,'available':62},'mbuf enqueue failed')
            def collect(n): require(primary.command('collect','COLLECTED')=={'sequence':n,'available':63},'same mbuf/payload reclamation failed')
            def retire(p):
                require(p.command('retire','CLOSED')=={'outstanding':0},'caller retirement was not acknowledged')
                require(p.child.wait(timeout=20)==0,'old worker EAL cleanup failed')

            old0,old1=worker(0,0),worker(0,1)
            event(8,-22,0)  # QUIT_GOLD is illegal while idle
            event(1,0,1); event(1,-22,1)
            refused=event(3,-11,1)  # READY_TIMEOUT first requests a safe park
            require(refused['rollback'] and refused['stopped']==1,'rollback did not request quiescence')
            poll(old0,0,0); poll(old1,0,0)
            rolled=event(3,0,6); require(rolled['window']==0 and rolled['owner']==0 and rolled['stopped']==0,'rollback did not restore active owner')
            event(1,-22,6); event(10,0,0)
            evidence['rollback_confirmed']=True
            inject(1)
            old0.child.stdin.write(b'poll hold\n'); old0.child.stdin.flush()
            require(old0.record('ENTERED')=={'slot':0,'generation':0},'old callback not held')
            event(1,0,1); event(2,-11,1)
            new1=worker(1,2); event(2,-11,1)
            require(new1.command('ready','WORKER_READY')=={'pid':new1.child.pid,'slot':2},'actual target READY failed')
            armed=event(2,0,2); require(armed['park']>refused['rollback'],'park epoch reused stale rollback proof')
            handover(-11); event(6,-11,2)
            poll(old1,0,0); poll(new1,0,0); handover(-11)
            old0.child.stdin.write(b'continue\n'); old0.child.stdin.flush()
            require(old0.record('POLL')=={'result':1,'callbacks':1,'received':1,'completed':1},'last old PMD pass failed')
            collect(1); handover(-11); poll(old0,1,0)
            require(handover(0)['stopped']==1,'release lost park order')
            require(new1.command('claim 0','CLAIM')=={'result':0,'owner':1,'stopped':0},'new owner claim failed')
            require(handover(0)['stopped']==0,'repeated release reparked the claimed owner')
            event(6,0,3); event(1,-22,3)
            inject(2); event(7,-11,3)
            poll(new1,1,1); event(7,-11,3); collect(2)
            event(7,0,4); event(8,0,5); event(1,-22,5); event(9,-11,5)
            retire(old0); retire(old1)
            complete=event(9,0,0); require(complete['window']==0 and complete['active']==1,'first full round failed')
            evidence['premature_exit_refused']=True
            event(1,0,1)
            new0=worker(0,0)
            require(new0.command('ready','WORKER_READY')=={'pid':new0.child.pid,'slot':0},'second target READY failed')
            again=event(2,0,2); require(again['park']>armed['park'],'second full round reused park epoch')
            handover(-11); poll(new1,1,0); handover(0)
            require(new0.command('claim 1','CLAIM')=={'result':0,'owner':0,'stopped':0},'reverse claim failed')
            event(6,0,3); inject(3); poll(new0,2,1); collect(3)
            event(7,0,4); event(8,0,5); event(9,-11,5); retire(new1)
            complete=event(9,0,0); require(complete['window']==0 and complete['active']==0,'second full round failed')
            inject(4); poll(new0,3,1); collect(4); new0.close()
            final=primary.command('status','STATUS')
            require(final=={'available':63,'rx':0,'tx':0,'owner':0,'stopped':0,'inflight':[0,0],
                            'callbacks':[3,0,1,0],'ipackets':4,'opackets':4},'PMD/pool/policy disagreement: '+str(final))
            require(all(p.child.poll()==0 for p in processes[1:]),'worker still live or failed')
            require(primary.command('quit','CLOSED')=={'available':63,'outstanding':0},'controller/PMD final reclamation failed')
            require(primary.child.wait(timeout=20)==0,'primary EAL cleanup failed')
            evidence.update(pool_reclaimed=True,policy_cycles=2,final=final,cases=[
                'test_ut_nr_10_reload_fsm_transitions','test_ut_nr_10_all_legal_transitions',
                'test_ut_nr_10_illegal_combinations_exhaustive','test_ut_nr_10_error_recovery_and_abort'])
            if args.evidence: args.evidence.write_text(json.dumps(evidence,indent=2)+'\n')
            print('PASS: caller policy gates actual READY, park, handover, drain and exact old-worker exit')
            for case in evidence['cases']: print('CONTROLLER_SOURCE_CASE '+case)
            return 0
        except BaseException:
            for i,p in enumerate(processes):
                p.error.flush(); print(f'PROCESS {i} pid={p.child.pid} records={p.log}',flush=True)
            for path in root.glob('*.stderr'): print(str(path)+':\n'+path.read_text(errors='replace'),flush=True)
            raise
        finally:
            for p in reversed(processes): p.stop()
            for path in huge.iterdir():
                require(path.is_file() and not path.is_symlink(),'unexpected private backing entry'); path.unlink()
            huge.rmdir()


if __name__=='__main__': raise SystemExit(main())
