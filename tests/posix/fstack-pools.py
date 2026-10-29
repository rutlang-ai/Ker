#!/usr/bin/env python3
"""Original pool selection/cache policy consumed by real net_ring packets."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
from hugepage_preflight import hugepage_capacity_error

spec=importlib.util.spec_from_file_location('ipc_fixture',Path(__file__).with_name('fstack-ipc-multiprocess.py'))
fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
Process,require=fixture.Process,fixture.require


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app',type=Path,required=True);parser.add_argument('--unit-app',type=Path,required=True)
    parser.add_argument('--pmd-root',type=Path,required=True);parser.add_argument('--huge-dir',type=Path,default=Path('/dev/hugepages'))
    parser.add_argument('--legacy-only',action='store_true');parser.add_argument('--evidence',type=Path);args=parser.parse_args()
    modules=[]
    for name in ['mempool_ring','net_ring']:
        found=list(args.pmd_root.glob('dpdk/pmds-*/librte_'+name+'.so'));require(len(found)==1,'one original '+name+' module required');modules+=['-d',str(found[0])]
    nonce=format(int.from_bytes(os.urandom(7),'big') or 1,'x');evidence={'profile':'actual original pool selectors/cache policy and original net_ring RX/TX','nonce':nonce,'cases':[],'pool_reclaimed':False}
    with tempfile.TemporaryDirectory(prefix='ker-pools-') as temporary:
        root=Path(temporary)
        env=dict(os.environ,KER_POOL_NONCE=nonce,RUNTIME_DIRECTORY=str(root),LD_LIBRARY_PATH=str(args.pmd_root)+':'+os.environ.get('LD_LIBRARY_PATH',''))
        cpu=min(os.sched_getaffinity(0));base=[f'--lcores=0@{cpu}','--no-pci','--no-telemetry','--iova-mode=va',*modules]
        checked=subprocess.run([str(args.unit_app)],env=env,text=True,capture_output=True,timeout=45)
        require(checked.returncode==0 and 'PASS: complete original generation-pool and cache-policy assertions' in checked.stdout,'original source assertions failed: '+checked.stdout+checked.stderr)
        legacy=subprocess.run([str(args.app),'legacy','--proc-type=primary','--no-huge','--no-shconf','--file-prefix=pool-legacy-'+nonce,'-m','64',*base],env=env,text=True,capture_output=True,timeout=45)
        require(legacy.returncode==0,'real cached legacy pipeline failed: '+legacy.stdout+legacy.stderr)
        lines=legacy.stdout.splitlines()
        require('CACHES '+json.dumps({'legacy':[256,16,256],'used_and_flushed':True},separators=(',',':')) in lines,'original legacy cache use/flush proof missing')
        require('CLOSED {"packets":4,"outstanding":0}' in lines,'legacy original PMD/pool cleanup failed')
        evidence['legacy_events']=lines
        if args.legacy_only:
            if args.evidence:args.evidence.write_text(json.dumps(evidence,indent=2)+'\n')
            print('PASS: original legacy caches256/16/256 consumed and flushed, real PMD4/4 and pools1023/1023')
            return 0
        reason=hugepage_capacity_error(args.huge_dir,64*1024*1024)
        if reason:print('SKIP: '+reason+'; legacy passed; no host settings changed');return 77
        huge=args.huge_dir/('ker-pools-'+nonce);huge.mkdir(mode=0o700);processes=[]
        common=[*base,'--file-prefix=pool-shared-'+nonce,'--huge-dir='+str(huge)]
        try:
            primary=Process([str(args.app),'primary','--proc-type=primary','-m','64',*common],env,root,'primary');processes.append(primary)
            require(primary.record('READY')=={'pid':primary.child.pid,'nonce':nonce,'count':63,'shared':1},'primary role/nonce mismatch')
            worker_env=dict(env,KER_POOL_PRIMARY_PID=str(primary.child.pid))
            def worker(generation):
                p=Process([str(args.app),'worker',str(generation),'--proc-type=secondary',*common],worker_env,root,'worker-'+str(generation));processes.append(p)
                require(p.record('ATTACHED')=={'pid':p.child.pid,'primary':primary.child.pid,'generation':generation},'actual secondary identity/pools mismatch');return p
            def counts(expected,rx=0,tx=0,control=0,completion=0,done=0):
                r=primary.command('counts','COUNTS')
                require(r=={'available':expected,'cache':[0,0,0,0,0],'rx':rx,'tx':tx,'control':control,'completion':completion,'inflight':0,'done':done},'original pool/cache census mismatch '+str(r));return r
            def inject(sequence,generation):require(primary.command(f'inject {sequence} {generation}','INJECTED')=={'sequence':sequence,'generation':generation},'RX metadata/frame enqueue failed')
            def process(p,sequence,generation):require(p.command('process','PROCESSED')=={'sequence':sequence,'selected':generation,'pid':p.child.pid},'actual original-selected response allocation failed')
            def finish(p,sequence,generation):require(p.command('finish','FINISHED')=={'sequence':sequence,'selected':generation,'pid':p.child.pid},'cross-generation return used wrong original pool')
            def complete(sequence):require(primary.command('complete '+str(sequence),'COMPLETE')=={'sequence':sequence},'completed objects were not all reclaimed')
            def select(p,value,expected):require(p.command('select '+str(value),'SELECTED')=={'generation':expected},'invalid generation changed original selection')
            a=worker(0);counts([63]*5)
            inject(1,0);counts([62,63,63,62,62],rx=1,control=1)
            process(a,1,0);counts([63,62,63,62,62],tx=1,completion=1)
            select(a,1,1);select(a,2,1);select(a,-1,1)
            # Join a real second EAL on the same lcore while gen0 still owns an
            # output mbuf and the original message/reference objects.
            b=worker(1);counts([63,62,63,62,62],tx=1,completion=1)
            finish(b,1,1);complete(1);counts([63]*5,done=1)
            inject(2,1);process(a,2,1);counts([63,63,62,62,62],tx=1,completion=1,done=1)
            finish(b,2,1);complete(2);counts([63]*5,done=2)
            select(b,0,0);inject(3,0);process(b,3,0);counts([63,62,63,62,62],tx=1,completion=1,done=2)
            finish(a,3,1);complete(3);counts([63]*5,done=3)
            select(b,1,1);inject(4,1);process(b,4,1);counts([63,63,62,62,62],tx=1,completion=1,done=3)
            select(primary,0,0);finish(primary,4,0);complete(4);final=counts([63]*5,done=4)
            a.close();b.close()
            require(primary.command('quit','CLOSED')=={'packets':4,'outstanding':0} and primary.child.wait(timeout=20)==0,'primary bank/pools/EAL cleanup failed')
            evidence.update(primary_pid=primary.child.pid,secondary_pids=[a.child.pid,b.child.pid],shared_lcore=0,joined_with_old_mbuf_outstanding=True,final=final,pool_reclaimed=True,cases=['test_ut_nr_18_gen_pool_config','test_ut_nr_21_shared_pool_cache_size'])
            evidence['events']=[p.log for p in processes]
            if args.evidence:args.evidence.write_text(json.dumps(evidence,indent=2)+'\n')
            print('PASS: original generation bank and all-three-role cache policy, actual PMD4/4, cross-process returns and five pools63/63')
            for case in evidence['cases']:print('POOL_MP_SOURCE_CASE '+case)
            return 0
        except BaseException:
            for p in processes:print('PROCESS '+str(p.child.pid)+' '+json.dumps(p.log),flush=True)
            for path in root.glob('*.stderr'):print(str(path)+':\n'+path.read_text(errors='replace'),flush=True)
            raise
        finally:
            for p in reversed(processes):p.stop()
            for path in huge.iterdir():
                if path.is_file():path.unlink()
            huge.rmdir()


if __name__=='__main__':raise SystemExit(main())
