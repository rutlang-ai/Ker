#!/usr/bin/env python3
"""Original bounded slot admission, real dead masters and surviving EAL workers."""
import argparse
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from hugepage_preflight import hugepage_capacity_error

spec=importlib.util.spec_from_file_location('directory_fixture',Path(__file__).with_name('fstack-reload-directory.py'))
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
Process,Master,Actor,require=f.Process,f.Master,f.Actor,f.require


def run(args,mode):
    nonce=format(int.from_bytes(os.urandom(7),'big') or 1,'x')
    modules=[]
    for name in ('mempool_ring','net_ring'):
        found=list(args.pmd_root.glob('dpdk/pmds-*/librte_'+name+'.so'))
        require(len(found)==1,'one original '+name+' module required');modules+=['-d',str(found[0])]
    with tempfile.TemporaryDirectory(prefix='ker-slot-window-') as temporary:
        root=Path(temporary);huge=args.huge_dir/('slot-window-'+nonce);huge.mkdir(mode=0o700)
        env=dict(os.environ,KER_DIRECTORY_NONCE=nonce,RUNTIME_DIRECTORY=str(root),
                 LD_LIBRARY_PATH=str(args.pmd_root)+':'+os.environ.get('LD_LIBRARY_PATH',''))
        common=[f'--lcores=0@{min(os.sched_getaffinity(0))}','--no-pci','--no-telemetry','--iova-mode=va',
                '--file-prefix=slot-window-'+nonce,'--huge-dir='+str(huge),*modules]
        masters=[];actors=[];primary=None
        try:
            unit=subprocess.run([str(args.unit_app),mode],env=env,text=True,capture_output=True,timeout=15)
            require(unit.returncode==0 and 'PASS: original transient slot' in unit.stdout,'original assertions failed: '+unit.stdout+unit.stderr)
            primary=Process([str(args.app),'primary','--proc-type=primary','-m','64',*common],env,root,'primary')
            require(primary.record('READY')=={'pid':primary.child.pid,'nonce':nonce,'available':63,'driver':'net_ring'},'real primary identity')
            worker_env=dict(env,KER_DIRECTORY_PRIMARY_PID=str(primary.child.pid))
            def group(gen,index,slot,name,collision=False):
                extra=dict(worker_env,KER_DIRECTORY_STATE_INDEX=str(index))
                executable=args.app
                failed=collision and mode=='exhausted'
                if collision:
                    extra['KER_DIRECTORY_ATTACH_TIMING']='1'
                    if failed:
                        executable=args.budget_app;extra['KER_DIRECTORY_TEST_BUDGET_MS']='50'
                plan={'root':str(root),'workers':[(slot,[str(executable),'worker',str(gen),str(slot),'--proc-type=secondary',*common])],
                      'expected_exits':{str(slot):int(failed)}}
                master=Master(plan,extra,root,name);masters.append(master)
                require(master.record('MASTER')=={'pid':master.child.pid},'real master identity')
                metadata,fds=master.receive();actor=Actor(master,metadata,fds);actors.append(actor)
                return master,actor
            def attached(actor,gen):
                row=actor.record('ATTACHED')
                require(row['pid']==actor.child.pid and row['parent']==actor.master.child.pid and row['primary']==primary.child.pid
                        and row['generation']==gen and row['slot']==actor.slot,'real secondary identity')
                return row
            ma,a=group(0,0,0,'master-a');old=attached(a,0)
            require((old['epoch'],old['directory_slot'])==(2,2),'first derived slot')
            # Advance the original mint counter; both alternate slots are then
            # genuinely reclaimable, so a faulty alternate-slot scan is visible.
            departed=[]
            for epoch in (3,4):
                require(primary.command('init-state 1 1','RESULT')=={'result':0},'reset caller state')
                m,b=group(1,1,2,'master-'+str(epoch));row=attached(b,1)
                require(row['epoch']==epoch,'mint sequence');b.close();m.close()
                primary.command('wait-stale '+str(epoch),'STALE');departed.append(row)
            require(a.command('poll','POLL')=={'result':0,'callbacks':1,'received':0,'completed':0},'old owner callback')
            require(a.command('stop','RESULT')=={'result':0},'quiesce old callback lease')
            before=primary.command('slot-state 2','SLOT')
            require(before['epoch']==2 and before['master']==ma.child.pid and ((before['now']-before['stamp'])&0xffffffff)<500,'real worker did not refresh stamp')
            ma.kill()
            require(a.command('parent','PARENT')=={'pid':os.getpid()},'surviving worker not adopted after real master death')
            require(primary.command('live 2','LIVE')=={'epoch':2,'live':1},'fresh orphan stamp did not retain liveness')
            alternate=[primary.command('slot-state '+str(i),'SLOT') for i in (1,3)]
            view=primary.command('view','VIEW')
            require(primary.command('init-state 1 1','RESULT')=={'result':0},'reset next caller state')
            md,d=group(1,1,2,'master-collision',True)
            begin=d.record('ATTACH_BEGIN')['now'];age=(begin-before['stamp'])&0xffffffff
            require(age<1000,'collision did not start in the transient window')
            if mode=='window':
                elapsed=d.record('ATTACH_END')['elapsed_ms'];row=attached(d,1)
                require((row['epoch'],row['directory_slot'])==(5,2),'recycled different derived slot')
                require(elapsed>=2000-age and elapsed<5000,'attach did not wait for exact stale window')
                after=primary.command('slot-state 2','SLOT')
                require(after['epoch']==5 and after['master']==md.child.pid and after['refused']==before['refused'],'successful wait mutated refusal counter')
                require(d.command('reclaim','RESULT')=={'result':0},'explicit proof-bearing hardware reclaim')
                require(primary.command('inject 1','INJECTED')=={'sequence':1,'available':62},'allocate real frame')
                require(a.command('poll','POLL')=={'result':0,'callbacks':1,'received':0,'completed':0},'old orphan stole hardware after recycle')
                require(d.command('poll','POLL')=={'result':1,'callbacks':1,'received':1,'completed':1},'new coordinate did not serve PMD')
                require(primary.command('collect','COLLECTED')=={'sequence':1,'available':63},'frame identity/reclamation')
                d.close();md.close()
            else:
                d.reap();md.close()
                failure=(root/'worker-2.stderr').read_text(errors='replace')
                require('cannot register this process' in failure and 'cross-master epoch isolation' in failure,'not original fatal admission refusal')
                require(not d.child.stdout.read(),'failed worker published success')
                after=primary.command('slot-state 2','SLOT')
                require(after['epoch']==2 and after['master']==ma.child.pid and after['stamp']==before['stamp']
                        and after['refused']==before['refused']+1,'failed admission altered slot or missed refusal')
                require(primary.command('view','VIEW')==dict(view,refused=view['refused']+1),'failed admission changed ownership')
                elapsed=None
            for old_alternate in alternate:
                observed=primary.command('slot-state '+str(old_alternate['slot']),'SLOT')
                require({k:v for k,v in observed.items() if k not in ('now','refused')}==
                        {k:v for k,v in old_alternate.items() if k not in ('now','refused')},'alternate slot changed')
            a.close()
            final=primary.command('status','STATUS')
            require(final['available']==63 and final['rx']==final['tx']==final['drain']==0 and final['inflight']==[0,0],'pool/ring reclamation')
            require(primary.command('quit','CLOSED')=={'available':63,'outstanding':0} and primary.child.wait(timeout=20)==0,'primary cleanup')
            return {'case':'test_p2_slot_transient_'+mode,'mode':mode,'nonce':nonce,'old':old,'before':before,'after':after,
                    'attach_stamp_age_ms':age,'elapsed_ms':elapsed,'orphan_adopted':True,'alternate_slots_unchanged':True,
                    'source_unit':unit.stdout,'final':final,'pool_reclaimed':True,'private_budget_ms':50 if mode=='exhausted' else None,
                    'primary_pid':primary.child.pid,'master_pids':[m.child.pid for m in masters],
                    'secondary_pids':[actor.child.pid for actor in actors],
                    'events':{'primary':primary.log,'masters':[m.log for m in masters],'workers':[a.log for a in actors]}}
        except BaseException:
            for path in root.glob('*.stderr'):print(str(path)+':\n'+path.read_text(errors='replace'),flush=True)
            raise
        finally:
            for m in masters:
                if m.child.poll() is None:m.kill()
            for a in actors:a.dispose()
            for m in masters:m.dispose()
            if primary:primary.stop()
            for path in huge.iterdir():
                if path.is_file():path.unlink()
            huge.rmdir()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('app','budget-app','unit-app','pmd-root'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--mode',choices=('both','window','exhausted'),default='both')
    parser.add_argument('--huge-dir',type=Path,default=Path('/dev/hugepages'));parser.add_argument('--evidence',type=Path)
    args=parser.parse_args();reason=hugepage_capacity_error(args.huge_dir,64*1024*1024)
    if reason:print('SKIP: '+reason+'; no host settings changed');return 77
    libc=ctypes.CDLL(None,use_errno=True);prior=ctypes.c_int()
    require(libc.prctl(37,ctypes.byref(prior),0,0,0)==0 and libc.prctl(36,1,0,0,0)==0,'subreaper setup')
    try:proof={'profiles':[run(args,mode) for mode in (('window','exhausted') if args.mode=='both' else (args.mode,))]}
    finally:require(libc.prctl(36,prior.value,0,0,0)==0,'subreaper restore')
    if args.evidence:
        with args.evidence.open('x') as output:json.dump(proof,output,indent=2);output.write('\n')
    print('PASS: original transient slot wait and bounded refusal with real EAL workers')
    return 0


if __name__=='__main__':sys.exit(main())
