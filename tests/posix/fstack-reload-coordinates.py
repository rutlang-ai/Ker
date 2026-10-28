#!/usr/bin/env python3
"""Original M5 locator, complete FF ring family sweep and same-gen handover."""
import argparse
import ctypes
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import time
from hugepage_preflight import hugepage_capacity_error

spec=importlib.util.spec_from_file_location('directory_fixture',Path(__file__).with_name('fstack-reload-directory.py'))
fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
Process,Master,Actor,require=fixture.Process,fixture.Master,fixture.Actor,fixture.require


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app',type=Path,required=True);parser.add_argument('--unit-app',type=Path,required=True)
    parser.add_argument('--pmd-root',type=Path,required=True);parser.add_argument('--huge-dir',type=Path,default=Path('/dev/hugepages'))
    parser.add_argument('--evidence',type=Path);args=parser.parse_args()
    reason=hugepage_capacity_error(args.huge_dir,64*1024*1024)
    if reason:print('SKIP: '+reason+'; no host settings changed');return 77
    modules=[]
    for name in ['mempool_ring','net_ring']:
        found=list(args.pmd_root.glob('dpdk/pmds-*/librte_'+name+'.so'));require(len(found)==1,'one original '+name+' module required');modules+=['-d',str(found[0])]
    libc=ctypes.CDLL(None,use_errno=True);prior=ctypes.c_int()
    require(libc.prctl(37,ctypes.byref(prior),0,0,0)==0 and libc.prctl(36,1,0,0,0)==0,'subreaper setup failed')
    nonce=format(int.from_bytes(os.urandom(7),'big') or 1,'x')
    evidence={'profile':'original M5 QUERY-routed FF IPC and same-generation distinct-master net_ring ownership','nonce':nonce,'cases':[],'pool_reclaimed':False,'locator_retries':[]}
    with tempfile.TemporaryDirectory(prefix='ker-coordinates-') as temporary:
        root=Path(temporary);huge=args.huge_dir/('ker-coordinates-'+nonce);huge.mkdir(mode=0o700)
        masters=[];actors=[];primary=None
        env=dict(os.environ,KER_DIRECTORY_NONCE=nonce,RUNTIME_DIRECTORY=str(root),LD_LIBRARY_PATH=str(args.pmd_root)+':'+os.environ.get('LD_LIBRARY_PATH',''))
        common=[f'--lcores=0@{min(os.sched_getaffinity(0))}','--no-pci','--no-telemetry','--iova-mode=va','--file-prefix=coordinates-'+nonce,'--huge-dir='+str(huge),*modules]
        try:
            checked=subprocess.run([str(args.unit_app)],env=env,text=True,capture_output=True,timeout=45)
            require(checked.returncode==0 and 'PASS: directory source assertions' in checked.stdout,'complete source assertions failed: '+checked.stdout+checked.stderr)
            primary=Process([str(args.app),'primary','--proc-type=primary','-m','64',*common],env,root,'primary')
            require(primary.record('READY')=={'pid':primary.child.pid,'nonce':nonce,'available':63,'driver':'net_ring'},'primary identity/PMD mismatch')
            def group(index,gen,slots,name,synchronized=False):
                worker_env=dict(env,KER_DIRECTORY_PRIMARY_PID=str(primary.child.pid),KER_DIRECTORY_STATE_INDEX=str(index))
                barrier=root/(name+'-attach-barrier')
                if synchronized:
                    barrier.mkdir()
                    worker_env['KER_DIRECTORY_ATTACH_BARRIER']=str(barrier)
                cpus=sorted(os.sched_getaffinity(0))
                if synchronized:require(len(cpus)>=2,'same-parent attach race regression requires two allowed CPUs')
                workers=[]
                for position,s in enumerate(slots):
                    worker_common=common
                    if synchronized:worker_common=[f'--lcores=0@{cpus[position]}',*common[1:]]
                    workers.append((s,[str(args.app),'worker',str(gen),str(s),'--proc-type=secondary',*worker_common]))
                plan={'root':str(root),'workers':workers}
                master=Master(plan,worker_env,root,name);masters.append(master);group=[]
                require(master.record('MASTER')=={'pid':master.child.pid},'actual master identity mismatch')
                for _ in slots:
                    metadata,fds=master.receive();actor=Actor(master,metadata,fds);actors.append(actor);group.append(actor)
                held_lock=None
                contention={}
                if synchronized:
                    # Hold the same production lock while both real secondary
                    # EALs reach the attach call boundary. Without adapter
                    # serialization they would attach and notify the broker.
                    runtime_dir=root/'dpdk'/('coordinates-'+nonce)
                    lock_path=runtime_dir/'ker-reload-gendir-register.lock'
                    held_lock=lock_path.open('a+b')
                    lock_stat=os.fstat(held_lock.fileno())
                    try:
                        fcntl.flock(held_lock.fileno(),fcntl.LOCK_EX)
                        deadline=time.monotonic()+10
                        while not all((barrier/f'slot-{s}').exists() for s in slots):
                            require(time.monotonic()<deadline,'siblings did not reach attach barrier')
                            time.sleep(.001)
                        (barrier/'go').touch()
                        go_released_at=time.monotonic()
                        while not all((barrier/f'attempt-{s}').exists() for s in slots):
                            require(time.monotonic()<deadline,'siblings did not reach attach call boundary')
                            time.sleep(.001)
                        readable,_,_=select.select([a.child.stdout for a in group],[],[],.1)
                        require(not readable,'worker attached while registration lock was held')
                        contention={'lock_path':str(lock_path),'lock_device':lock_stat.st_dev,
                            'lock_inode':lock_stat.st_ino,'go_released':True,
                            'attempt_slots':sorted(int(p.name.split('-')[1]) for p in barrier.glob('attempt-*')),
                            'no_attached_while_held':True,
                            'held_observation_ms':round((time.monotonic()-go_released_at)*1000,1),
                            'planned_cpus':cpus[:len(slots)]}
                    finally:
                        fcntl.flock(held_lock.fileno(),fcntl.LOCK_UN)
                        held_lock.close();held_lock=None
                for actor in group:
                    attached=actor.record('ATTACHED');require(attached['pid']==actor.child.pid and attached['parent']==master.child.pid and attached['primary']==primary.child.pid and attached['generation']==gen and attached['slot']==actor.slot,'real secondary parent/state/driver mismatch')
                    actor.epoch=attached['epoch'];actor.directory_slot=attached['directory_slot']
                if synchronized:
                    for marker in barrier.iterdir():marker.unlink()
                    barrier.rmdir()
                require(len({a.epoch for a in group})==1,'one master split into different epochs')
                if synchronized:
                    require(len({a.directory_slot for a in group})==1,'sibling attach split one parent across directory slots')
                    affinities=[{'pid':a.child.pid,'cpus':sorted(os.sched_getaffinity(a.child.pid))} for a in group]
                    for position,observed in enumerate(affinities):
                        require(observed['cpus']==[cpus[position]],
                            'sibling EAL worker did not run on its assigned CPU: '+str(observed))
                    contention['worker_affinities']=affinities
                    evidence['registration_contention']=contention
                return master,group
            def locate_after_retirement(epoch,gen):
                before=sum(line.startswith('LOCATOR_RETRY ') for line in primary.log)
                result=primary.command(f'locate-until {epoch} {gen}','LOCATED')
                require(result=={'epoch':epoch,'generation':gen},'QUERY locator did not converge after retired-master PID-cache TTL')
                retries=[json.loads(line[len('LOCATOR_RETRY '):]) for line in primary.log if line.startswith('LOCATOR_RETRY ')][before:]
                evidence['locator_retries'].extend(retries)
            def result(p,command,expected=0):require(p.command(command,'RESULT')=={'result':expected},'bad result for '+command)
            def locate(epoch,gen):require(primary.command('locate','LOCATED')=={'epoch':epoch,'generation':gen},'QUERY locator chose an unserved namespace')
            def names(epoch,create=True):require(primary.command(('names ' if create else 'drop ')+str(epoch),'NAMES')=={'epoch':epoch,'count':88,'created':int(create)},'complete FF family ring lifetime failed')
            sequence=0;roundtrips=[]
            def rpc(actor,gen,process,kind,probe=False):
                nonlocal sequence
                sequence+=1
                command=f'probe {process} {kind} {sequence}' if probe else f'send {actor.epoch} {gen} {process} {kind} {sequence}'
                require(primary.command(command,'SENT')=={'epoch':actor.epoch,'generation':gen,'process':process,'type':kind,'sequence':sequence,'available':62},'locator/address did not drive actual original IPC input')
                require(actor.command(f'serve {process} {gen} {kind}','SERVED')=={'epoch':actor.epoch,'generation':gen,'process':process,'type':kind,'sequence':sequence},'request reached wrong master/generation/type')
                require(primary.command('receive','RECEIVED')=={'sequence':sequence,'available':63},'actual typed output/payload/cookie reclamation failed')
                roundtrips.append([actor.epoch,gen,process,kind,sequence])
            # Real no-active mirror fallback: newest master, remaining master,
            # then epoch0 once both actual master lifetimes have ended.
            locate(0,0)
            ma,(a,)=group(0,0,[0],'probe-a');mb,(b,)=group(1,1,[2],'probe-b')
            require(a.epoch!=b.epoch and a.directory_slot!=b.directory_slot,'master namespace collision')
            names(a.epoch);names(b.epoch);locate(b.epoch,1);rpc(b,1,127,10,True)
            b.close();mb.close();primary.command(f'wait-stale {b.epoch}','STALE');locate_after_retirement(a.epoch,0);rpc(a,0,127,10,True)
            a.close();ma.close();primary.command(f'wait-stale {a.epoch}','STALE');locate_after_retirement(0,0)
            names(a.epoch,False);names(b.epoch,False)
            result(primary,'init-state 1 0')
            mc,(c,c1)=group(0,0,[0,1],'master-c',synchronized=True);md,(d,)=group(1,0,[2],'master-d')
            require(c.epoch!=d.epoch and c.directory_slot!=d.directory_slot and c.epoch<d.epoch,'actual same-gen master coordinates invalid')
            require([c.directory_slot,d.directory_slot]==[1,2],'real successive epochs did not reach original e1/e2 naming slots')
            require(c.epoch==c1.epoch and c.directory_slot==c1.directory_slot,'barrier-synchronized siblings did not share their parent coordinate')
            names(c.epoch);names(d.epoch);locate(d.epoch,0);rpc(d,0,127,10,True)
            # Every original source dimension traverses actual FF input/output
            # queues and typed pool, including same proc/gen under two masters.
            for actor in [c,d]:
                for gen in [0,1]:
                    for process in [0,1,7,127]:
                        for kind in range(1,11):rpc(actor,gen,process,kind)
            counts=[0]*4;received=[0]*4
            def poll(actor,packet=0,allowed=False):
                r=actor.command('poll','POLL');counts[actor.slot]+=int(allowed);received[actor.slot]+=packet
                require(r=={'result':packet,'callbacks':counts[actor.slot],'received':received[actor.slot],'completed':received[actor.slot]},'same-gen directory gate/PMD mismatch '+str(r))
            def inject(seq):require(primary.command(f'inject {seq}','INJECTED')=={'sequence':seq,'available':62},'actual hardware frame allocation failed')
            def collect(seq):require(primary.command('collect','COLLECTED')=={'sequence':seq,'available':63},'same exact PMD mbuf/payload did not return')
            inject(0);poll(c1,1,True);collect(0)
            evidence['sibling_registration']={'barrier_synchronized':True,'epoch':c.epoch,'directory_slot':c.directory_slot,'workers':[c.child.pid,c1.child.pid],'both_served_pmd':True}
            inject(1);c.child.stdin.write(b'poll hold\n');c.child.stdin.flush()
            require(c.record('ENTERED')=={'slot':0,'generation':0},'old same-gen owner did not hold real callback');counts[0]+=1
            poll(d);result(d,f'claim {c.epoch} 0',-3)
            peer=c1.command('peer','PEER');require(peer['epoch']==d.epoch and peer['generation']==0 and peer['foreign']==1,'release peer selection ignored actual same-gen foreign master')
            refusal=c1.command('release-peer','RELEASE');require(refusal['result']==-2 and 4500<=refusal['elapsed_ms']<20000 and refusal['local_owner']==0 and refusal['local_stopped']==0,'held callback did not prevent original bounded release')
            c.child.stdin.write(b'continue\n');c.child.stdin.flush();received[0]+=1
            require(c.record('POLL')=={'result':1,'callbacks':1,'received':1,'completed':1},'old callback did not complete real PMD pass');collect(1)
            locate(c.epoch,0);rpc(c,0,127,10,True) # active word beats newer live master D
            owner_peer=c.command('peer','PEER');require(owner_peer['observer_matches']==1 and owner_peer['published_epoch']==d.epoch and owner_peer['published_generation']==0 and owner_peer['published_foreign']==1,'owner/peer block mirror did not publish original coordinates')
            require(d.command('peer','PEER')['observer_matches']==0,'same-gen foreign observer also owned runtime')
            result(c,'stop');released=c1.command('release-peer','RELEASE');require(released['result']==0,'peer-directed transfer failed after proof')
            parked=primary.command('view','VIEW');require(parked['owner_epoch']==d.epoch and parked['owner_generation']==0 and parked['stopped']==1,'release lost cross-master park order')
            poll(c);poll(d)
            require(primary.command('view','VIEW')['stopped']==1,'target mirror unparked hardware before explicit claim')
            result(d,f'claim {c.epoch} 0');inject(2);poll(c);poll(d,1,True);collect(2)
            locate(d.epoch,0);rpc(d,0,127,10,True)
            require(d.command('peer','PEER')['observer_matches']==1,'new owner did not acquire observation coordinate')
            result(c,'reclaim',-2) # rollback forbidden while new master lives
            md.kill();require(d.command('parent','PARENT')=={'pid':os.getpid()},'live draining target was not actually orphaned')
            result(d,'stop');primary.command(f'wait-stale {d.epoch}','STALE');result(c,'reclaim')
            inject(3);poll(d);poll(c,1,True);collect(3)
            rolled=primary.command('view','VIEW');require(rolled['owner_epoch']==c.epoch and rolled['stopped']==0 and rolled['local_owner']==0 and rolled['local_stopped']==0,'rollback failed to clear the old hand-over target/block park')
            locate(c.epoch,0);rpc(c,0,127,10,True)
            d.close();c1.close();c.close();mc.close()
            primary.command(f'wait-stale {c.epoch}','STALE')
            names(c.epoch,False);names(d.epoch,False)
            final=primary.command('status','STATUS');require(final=={'available':63,'rx':0,'tx':0,'drain':0,'inflight':[0,0],'callbacks':counts,'received':received,'ipackets':4,'opackets':4},'final same-gen PMD/pool ownership disagreement '+str(final))
            require(primary.command('quit','CLOSED')=={'available':63,'outstanding':0} and primary.child.wait(timeout=20)==0,'original primary resources leaked')
            evidence.update(primary_pid=primary.child.pid,master_pids=[m.child.pid for m in masters],secondary_pids=[a.child.pid for a in actors],epochs=[a.epoch,b.epoch,c.epoch,d.epoch],same_generation=0,roundtrips=roundtrips,named_rings_per_epoch=88,final=final,pool_reclaimed=True,park_until_claim=True,rollback_after_dead_epoch=True,
                cases=['test_ut_nr_m5_gendir_arbitration','test_ut_nr_m5_probe_epoch_fallback','test_ut_nr_m5_cross_master_name_isolation','test_ut_nr_m5_cross_master_handover_sequence'])
            evidence['events']={'primary':primary.log,'masters':[m.log for m in masters],'workers':[a.log for a in actors]}
            if args.evidence:args.evidence.write_text(json.dumps(evidence,indent=2)+'\n')
            print('PASS: M5 QUERY-driven typed IPC, full FF family names and same-gen cross-master handover')
            for case in evidence['cases']:print('COORDINATE_MP_SOURCE_CASE '+case)
            return 0
        except BaseException:
            for p in ([primary] if primary else [])+masters+actors:print('PROCESS '+str(p.child.pid)+' '+json.dumps(p.log),flush=True)
            for path in root.glob('*.stderr'):print(str(path)+':\n'+path.read_text(errors='replace'),flush=True)
            raise
        finally:
            for m in masters:
                if m.child.poll() is None:m.kill()
            for p in actors:p.dispose()
            for m in masters:m.dispose()
            if primary:primary.stop()
            for path in huge.iterdir():
                if path.is_file():path.unlink()
            huge.rmdir();require(libc.prctl(36,prior.value,0,0,0)==0,'subreaper restore failed')


if __name__=='__main__':sys.exit(main())
