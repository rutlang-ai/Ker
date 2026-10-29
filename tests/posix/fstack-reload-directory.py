#!/usr/bin/env python3
"""Real distinct-master EAL/PMD ownership, orphan proof and ring purge."""
import argparse
import array
import ctypes
import errno
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
from hugepage_preflight import hugepage_capacity_error

spec = importlib.util.spec_from_file_location('ipc_process_fixture', Path(__file__).with_name('fstack-ipc-multiprocess.py'))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
Process, require = fixture.Process, fixture.require


def broker(fd, plan_path):
    """Real master parent; pass duplicate control FDs without owning the reader."""
    plan = json.loads(Path(plan_path).read_text())
    channel = socket.socket(fileno=fd)
    children = {}; expected_exits = {}
    print('MASTER '+json.dumps({'pid': os.getpid()}), flush=True)
    for slot, command in plan['workers']:
        with open(plan['root']+'/worker-'+str(slot)+'.stderr', 'wb') as error:
            child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=error, bufsize=0)
        children[child.pid] = child
        expected_exits[child.pid] = plan.get('expected_exits', {}).get(str(slot), 0)
        fds = array.array('i', [child.stdin.fileno(), child.stdout.fileno()])
        channel.sendmsg([json.dumps({'pid':child.pid,'slot':slot,'expected_exit':expected_exits[child.pid]}).encode()], [(socket.SOL_SOCKET,socket.SCM_RIGHTS,fds)])
        child.stdin.close(); child.stdout.close()
    channel.close()
    for line in sys.stdin:
        fields = line.split()
        if fields[0] == 'reap':
            pid = int(fields[1]); code = children[pid].wait(timeout=20)
            print('REAPED '+json.dumps({'pid':pid,'exit':code}),flush=True)
        elif fields == ['exit']:
            require(all(p.poll() == expected_exits[pid] for pid,p in children.items()), 'master still owns a live/unexpectedly failed worker')
            print('CLOSED '+json.dumps({'children':len(children)}),flush=True)
            return 0
        else:
            raise RuntimeError('invalid master command')
    raise RuntimeError('master control EOF')


class Master:
    record, command = Process.record, Process.command

    def __init__(self, plan, env, root, name):
        own, passed = socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        self.channel = own; own.settimeout(45)
        path = root/(name+'.json'); path.write_text(json.dumps(plan))
        self.error = (root/(name+'.stderr')).open('wb')
        self.child = subprocess.Popen([sys.executable,str(Path(__file__).resolve()),'--broker',str(passed.fileno()),str(path)],
            env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.error,pass_fds=(passed.fileno(),),bufsize=0)
        passed.close(); self.log=[]; self.pidfd=os.pidfd_open(self.child.pid); self.adopted=False; self.orphans=[]

    def receive(self):
        data, ancillary, flags, _ = self.channel.recvmsg(4096,socket.CMSG_SPACE(2*array.array('i').itemsize))
        require(not flags, 'truncated worker FD transfer')
        fds = array.array('i')
        for level,kind,payload in ancillary:
            require(level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS, 'unexpected master ancillary data')
            fds.frombytes(payload)
        require(len(fds) == 2, 'master did not transfer both worker controls')
        return json.loads(data),fds

    def kill(self):
        require(self.child.poll() is None, 'master already exited before orphan test')
        children=Path(f'/proc/{self.child.pid}/task/{self.child.pid}/children').read_text().split()
        for child in children:
            try:self.orphans.append((int(child),os.pidfd_open(int(child))))
            except ProcessLookupError:pass
        signal.pidfd_send_signal(self.pidfd,signal.SIGKILL)
        require(self.child.wait(timeout=20) == -signal.SIGKILL, 'master death was not reaped')
        self.adopted=True

    def close(self):
        self.command('exit','CLOSED');require(self.child.wait(timeout=20) == 0,'master exit failed')

    def dispose(self):
        if self.child.poll() is None: self.kill()
        for pid,fd in self.orphans:
            try:
                observed,_=os.waitpid(pid,os.WNOHANG)
                if not observed:
                    signal.pidfd_send_signal(fd,signal.SIGKILL)
                    ready=select.poll();ready.register(fd,select.POLLIN)
                    require(ready.poll(20000),'uncollected owned worker did not die')
                    os.waitpid(pid,0)
            except ChildProcessError:pass
            finally:os.close(fd)
        self.channel.close();self.error.close();os.close(self.pidfd)


class Actor:
    record, command = Process.record, Process.command

    def __init__(self, master, metadata, fds):
        self.master=master;self.child=SimpleNamespace(pid=metadata['pid'],stdin=os.fdopen(fds[0],'wb',buffering=0),stdout=os.fdopen(fds[1],'rb',buffering=0))
        self.slot=metadata['slot'];self.log=[];self.pidfd=os.pidfd_open(self.child.pid);self.reaped=False
        self.expected_exit=metadata.get('expected_exit',0)

    def reap(self):
        if self.reaped:return
        poll=select.poll();poll.register(self.pidfd,select.POLLIN)
        require(poll.poll(20000), 'worker did not exit before reap deadline')
        if self.master.adopted:
            pid,status=os.waitpid(self.child.pid,0)
            require(pid==self.child.pid and os.WIFEXITED(status) and os.WEXITSTATUS(status)==self.expected_exit,'adopted worker exit failed')
        else:
            require(self.master.command('reap '+str(self.child.pid),'REAPED')=={'pid':self.child.pid,'exit':self.expected_exit},'master did not reap actual worker')
        self.reaped=True

    def close(self):
        require(self.command('exit','CLOSED')=={'outstanding':0},'worker cleanup failed');self.reap()

    def dispose(self):
        if not self.reaped:
            try:signal.pidfd_send_signal(self.pidfd,signal.SIGKILL)
            except ProcessLookupError:pass
            poll=select.poll();poll.register(self.pidfd,select.POLLIN)
            require(poll.poll(20000), 'owned worker failed to die during cleanup')
            # All live masters are killed first, so this process is subreaper.
            try:os.waitpid(self.child.pid,0)
            except ChildProcessError:pass
        self.child.stdin.close();self.child.stdout.close();os.close(self.pidfd)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app',type=Path,required=True);parser.add_argument('--unit-app',type=Path,required=True)
    parser.add_argument('--pmd-root',type=Path,required=True);parser.add_argument('--huge-dir',type=Path,default=Path('/dev/hugepages'))
    parser.add_argument('--evidence',type=Path)
    parser.add_argument('--verify-reclaim-gate',action='store_true')
    parser.add_argument('--negative-control',action='store_true')
    args=parser.parse_args()
    reason=hugepage_capacity_error(args.huge_dir,64*1024*1024)
    if reason:print('SKIP: '+reason+'; no host settings changed');return 77
    modules=[]
    for name in ['mempool_ring','net_ring']:
        found=list(args.pmd_root.glob('dpdk/pmds-*/librte_'+name+'.so'));require(len(found)==1,'one original '+name+' module required');modules+=['-d',str(found[0])]
    libc=ctypes.CDLL(None,use_errno=True);prior=ctypes.c_int()
    require(libc.prctl(37,ctypes.byref(prior),0,0,0)==0 and libc.prctl(36,1,0,0,0)==0,'subreaper setup failed')
    nonce=format(int.from_bytes(os.urandom(7), 'big') or 1, 'x');evidence={'profile':'actual distinct-master original EAL/net_ring, pidfd orphan proof and original user tables','nonce':nonce,'cases':[],'pool_reclaimed':False}
    with tempfile.TemporaryDirectory(prefix='ker-directory-') as temporary:
        root=Path(temporary);huge=args.huge_dir/('ker-directory-'+nonce);huge.mkdir(mode=0o700)
        masters=[];actors=[];primary=None
        env=dict(os.environ,KER_DIRECTORY_NONCE=nonce,RUNTIME_DIRECTORY=str(root),LD_LIBRARY_PATH=str(args.pmd_root)+':'+os.environ.get('LD_LIBRARY_PATH',''))
        common=[f'--lcores=0@{min(os.sched_getaffinity(0))}','--no-pci','--no-telemetry','--iova-mode=va','--file-prefix=directory-'+nonce,'--huge-dir='+str(huge),*modules]
        try:
            checked=subprocess.run([str(args.unit_app)],env=env,text=True,capture_output=True,timeout=45)
            require(checked.returncode==0 and 'PASS: directory source assertions' in checked.stdout,'source assertions failed: '+checked.stdout+checked.stderr)
            primary=Process([str(args.app),'primary','--proc-type=primary','-m','64',*common],env,root,'primary')
            require(primary.record('READY')=={'pid':primary.child.pid,'nonce':nonce,'available':63,'driver':'net_ring'},'primary identity/PMD mismatch')
            worker_env=dict(env,KER_DIRECTORY_PRIMARY_PID=str(primary.child.pid))
            def group(gen,slots,name):
                plan={'root':str(root),'workers':[(s,[str(args.app),'worker',str(gen),str(s),'--proc-type=secondary',*common]) for s in slots]}
                master=Master(plan,dict(worker_env,KER_DIRECTORY_STATE_INDEX=str(gen)),root,name);masters.append(master);group=[]
                require(master.record('MASTER') == {'pid':master.child.pid}, 'master identity mismatch')
                for _ in slots:
                    metadata,fds=master.receive();actor=Actor(master,metadata,fds);actors.append(actor)
                    attached=actor.record('ATTACHED');require(attached['pid']==actor.child.pid and attached['parent']==master.child.pid and attached['primary']==primary.child.pid and attached['generation']==gen and attached['slot']==actor.slot,'actual worker identity/parent mismatch')
                    actor.epoch=attached['epoch'];actor.directory_slot=attached['directory_slot'];group.append(actor)
                require(len({a.epoch for a in group})==1,'same master workers did not share epoch')
                return master,group
            ma,(a0,a1)=group(0,[0,1],'master-a');mb,(b0,b1)=group(1,[2,3],'master-b')
            ae,be=a0.epoch,b0.epoch;aslot,bslot=a0.directory_slot,b0.directory_slot
            require(ma.child.pid!=mb.child.pid and ae!=be and aslot!=bslot and ae>0 and be>0,'masters collapsed into one epoch/slot')
            evidence.update(primary_pid=primary.child.pid,master_pids=[ma.child.pid,mb.child.pid],secondary_pids=[a.child.pid for a in actors],epochs=[ae,be],directory_slots=[aslot,bslot])
            def result(p,command,expected=0):
                require(p.command(command,'RESULT')=={'result':expected},'unexpected result: '+command)
            def users(epoch,gen,active):
                require(primary.command(f'users {epoch} {gen}','USERS')=={'active':active,'clear':int(active==0)},'hardware user proof/count mismatch')
            counts=[0]*4;received=[0]*4
            def poll(p,packet=0,allowed=False):
                r=p.command('poll','POLL');counts[p.slot]+=int(allowed);received[p.slot]+=packet
                require(r=={'result':packet,'callbacks':counts[p.slot],'received':received[p.slot],'completed':received[p.slot]},'callback gate/data mismatch '+str(r))
            def reclaim_race(claimant,orphan):
                gate=root/'reclaim-after-proof';gate.mkdir()
                callbacks_before=counts[orphan.slot]
                claimant.child.stdin.write(('reclaim-pause '+str(gate)+'\n').encode());claimant.child.stdin.flush()
                deadline=time.monotonic()+10
                while not (gate/'proof').exists():
                    require(time.monotonic()<deadline,'reclaim did not reach proof-before-CAS barrier')
                    time.sleep(.001)
                try:
                    orphan.child.stdin.write(b'poll hold\n');orphan.child.stdin.flush()
                    readable,_,_=select.select([orphan.child.stdout],[],[],.2)
                    require(not readable,'stopped orphan entered polling while reclaim held the proof/CAS boundary')
                finally:
                    (gate/'resume').touch()
                require(claimant.record('RESULT')=={'result':0},'proof-complete reclaim did not take ownership')
                r=orphan.record('POLL')
                require(r=={'result':0,'callbacks':counts[orphan.slot],
                    'received':received[orphan.slot],'completed':received[orphan.slot]},
                    'orphan resumed after reclaim but was not denied before callback')
                poll(orphan) # A subsequent foreign pass remains denied as well.
                evidence['reclaim_serialization']={'proof_before_cas_pause':True,
                    'orphan_poll_blocked_until_cas':True,'reclaim_result':0,
                    'callbacks_before_after':[callbacks_before,counts[orphan.slot]],
                    'resumed_orphan_denied':True}
            def reclaim_negative_control(claimant,orphan):
                gate=root/'reclaim-after-proof-negative';gate.mkdir()
                claimant.child.stdin.write(('reclaim-pause '+str(gate)+'\n').encode());claimant.child.stdin.flush()
                deadline=time.monotonic()+10
                while not (gate/'proof').exists():
                    require(time.monotonic()<deadline,'negative control reclaim missed proof/CAS barrier')
                    time.sleep(.001)
                orphan.child.stdin.write(b'poll hold\n');orphan.child.stdin.flush()
                entered=orphan.record('ENTERED',timeout=5)
                require(entered=={'slot':orphan.slot,'generation':0},'negative control orphan callback did not enter')
                (gate/'resume').touch()
                require(claimant.record('RESULT')=={'result':0},'negative control claimant CAS did not succeed')
                claimant.child.stdin.write(b'poll hold\n');claimant.child.stdin.flush()
                waiter=select.poll();waiter.register(claimant.pidfd,select.POLLIN)
                require(bool(waiter.poll(10000)),'negative control claimant callback did not observe the overlapping old callback')
                reaped=claimant.master.command('reap '+str(claimant.child.pid),'REAPED')
                stderr=(root/('worker-'+str(claimant.slot)+'.stderr')).read_text(errors='replace')
                require(reaped=={'pid':claimant.child.pid,'exit':1} and
                    'check failed: !atomic_load(&shared->active[1-generation])' in stderr,
                    'negative control did not capture claimant callback overlapping old callback')
                evidence['reclaim_negative_control']={'proof_sampled_before_orphan_resume':True,
                    'orphan_callback_entered':entered,'claimant_cas_succeeded':True,
                    'claimant_callback_detected_overlap':True,'claimant_exit':reaped['exit'],
                    'overlap_guard': 'active[1-generation]'}
            def inject(sequence):require(primary.command(f'inject {sequence}','INJECTED')=={'sequence':sequence,'available':62},'packet allocation failed')
            def collect(sequence):require(primary.command('collect','COLLECTED')=={'sequence':sequence,'available':63},'packet identity/payload/reclamation failed')
            refusals=0
            def release(p,e,g,expected):
                nonlocal refusals
                r=p.command(f'release {e} {g}','RELEASE');require(r['result']==expected,'release proof bypassed: '+str(r))
                if expected==-2:
                    require(4500<=r['elapsed_ms']<20000 and r['local_owner']==p.slot//2 and r['local_stopped']==0,'bounded release rollback failed')
                    refusals+=1
                require(primary.command('view','VIEW')['refused']==refusals,'release refusal counter changed incorrectly')
                return r
            users(ae,0,0);users(be,1,0)
            result(a0,'detach',-errno.EBUSY);result(a1,'detach',-errno.EBUSY)
            result(primary,'lock');result(primary,'lock');result(b0,'lock',-1);result(b0,'unlock',-errno.EPERM)
            result(b0,'ring-attach',-1)
            require(primary.command('census','CENSUS')['live'][bslot]==[0,0],'timed-out ring attach leaked an entry')
            result(primary,'unlock')
            for p in [a0,a1,b0]:result(p,'ring-attach');result(p,'ring-attach')
            census=primary.command('census','CENSUS');require(census['live'][aslot]==[2,0] and census['live'][bslot]==[0,1],'idempotent actual ring registrations failed')
            inject(1);a0.child.stdin.write(b'poll hold\n');a0.child.stdin.flush()
            require(a0.record('ENTERED')=={'slot':0,'generation':0},'held original PMD callback did not enter');counts[0]+=1
            users(ae,0,1);poll(b0)
            before=primary.command('status','STATUS');require(before['inflight']==[1,0] and before['rx']==1 and before['ipackets']==0,'held callback consumed/acknowledged early')
            refused=release(a1,be,1,-2)
            a0.child.stdin.write(b'continue\n');a0.child.stdin.flush();received[0]+=1
            require(a0.record('POLL')=={'result':1,'callbacks':counts[0],'received':1,'completed':1},'held PMD callback failed');collect(1)
            users(ae,0,1);release(a1,be,1,-2) # callback return is not stop proof
            result(a0,'stop');users(ae,0,0);result(a0,'detach',-errno.EBUSY);release(a1,be,1,0)
            result(b0,f'claim {ae} 0');result(b0,f'claim {ae} 0')
            inject(2);poll(a0);poll(a1);poll(b0,1,True);collect(2);users(ae,0,0);users(be,1,1)
            release(b1,ae,0,-2);result(b0,'stop');release(b1,ae,0,0);result(a0,f'claim {be} 1')
            inject(3);poll(b0);poll(a1,1,True);collect(3);poll(a0,0,True);users(ae,0,2)
            # Real master death with live inherited worker pipe FDs and subreaper adoption.
            ma.kill()
            for p in [a0,a1]:require(p.command('parent','PARENT')=={'pid':os.getpid()},'orphan was not adopted by exact coordinator')
            require(a0.command('refresh','REFRESHED')=={'passes':4},'orphan refresh failed');counts[0]+=4
            require(b0.command(f'live {ae}','LIVE')=={'epoch':ae,'live':1},'refreshing orphan epoch was considered dead')
            result(b0,'reclaim',-2)
            require(primary.command('view','VIEW')['refused']==refusals,'fresh orphan refusal incorrectly counted missing user proof')
            b0.command(f'wait-stale {ae}','STALE');users(ae,0,2)
            poll(b0) # automatic mirror must not steal from a stale master with live users
            require(b0.command('view','VIEW')['owner_epoch']==ae,'poll stole stale epoch without user proof')
            result(b0,'reclaim',-2)
            refusals+=1;require(primary.command('view','VIEW')['refused']==refusals,'stale active-user refusal was not counted')
            # A real dead hardware/ring user and dead purge holder; peer stays live.
            result(a0,'lock');a0.command('crash','CRASHED');a0.reap();users(ae,0,1)
            result(b0,'reclaim',-2);refusals+=1
            require(primary.command('view','VIEW')['refused']==refusals,'one surviving user did not retain proof refusal')
            result(b0,'ring-attach');result(b0,'lock')
            primary.command(f'queue {ae} 0 100 2','QUEUED')
            purged=b0.command('purge','PURGED');require(purged=={'count':0,'dead_markers':1,'available':61},'purge consumed a live peer ring or lost dead marker')
            require(primary.command('census','CENSUS')['dead'][aslot]==[1,0],'busy slot did not preserve dead user marker')
            require(a1.command('drain','DRAINED')=={'count':2,'available':63},'live-consumer FIFO/identity preservation failed')
            result(a1,'stop');users(ae,0,0)
            if args.negative_control:
                reclaim_negative_control(b0,a1)
                if args.evidence:args.evidence.write_text(json.dumps(evidence,indent=2)+'\n')
                print('PASS: negative control reproduced reclaim/orphan callback overlap')
                return 0
            if args.verify_reclaim_gate:reclaim_race(b0,a1)
            else:result(b0,'reclaim')
            require(primary.command('view','VIEW')['refused']==refusals,'successful proof changed refusal counter')
            inject(4);poll(a1);poll(b0,1,True);collect(4)
            require(b0.command('idle','IDLED')['elapsed_ms']>=2300,'live-master/stale-stamp interval was not observed')
            require(a1.command(f'live {be}','LIVE')=={'epoch':be,'live':1},'live master was invalidated by an old stamp')
            result(a1,'reclaim',-2) # live master B remains live independent of its stamp
            require(primary.command('view','VIEW')['refused']==refusals,'live-master refusal incorrectly counted user proof')
            primary.command(f'queue {ae} 0 200 2','QUEUED');result(a1,'ring-detach')
            require(b0.command('purge','PURGED')=={'count':2,'dead_markers':1,'available':63},'idle dead-slot object reclamation failed')
            require(b0.command('purge','PURGED')=={'count':0,'dead_markers':0,'available':63},'dead markers/double purge were not cleared')
            result(b0,'unlock')
            result(a1,'ring-attach');primary.command(f'queue {ae} 0 300 2','QUEUED')
            require(a1.command('drain','DRAINED')=={'count':2,'available':63},'same-ring re-admission failed')
            a1.close();b0.close();b1.close();mb.close()
            primary.command(f'wait-stale {be}','STALE')
            final=primary.command('status','STATUS')
            require(final=={'available':63,'rx':0,'tx':0,'drain':0,'inflight':[0,0],'callbacks':counts,'received':received,'ipackets':4,'opackets':4},'final original PMD/pool/callback census mismatch '+str(final))
            require(primary.command('quit','CLOSED')=={'available':63,'outstanding':0} and primary.child.wait(timeout=20)==0,'primary lifetime/reclamation failed')
            evidence.update(pool_reclaimed=True,final=final,orphan_master_reaped=True,orphan_workers_adopted=True,crashed_worker_reaped=a0.child.pid,
                bounded_release=refused,cases=['test_p2_hw_user_proof','test_p2_reclaim_needs_user_proof','test_p2_release_epoch_needs_proof','test_p2_orphan_workers_keep_epoch_live','test_rx15_ring_user_census_and_purge_lock'])
            evidence['events']={'primary':primary.log,'masters':[m.log for m in masters],'workers':[p.log for p in actors]}
            if args.evidence:args.evidence.write_text(json.dumps(evidence,indent=2)+'\n')
            print('PASS: distinct-master EAL/net_ring, orphan user proofs and ring FIFO/purge/re-admission')
            for case in evidence['cases']:print('DIRECTORY_MP_SOURCE_CASE '+case)
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
            huge.rmdir()
            require(libc.prctl(36,prior.value,0,0,0)==0,'subreaper restore failed')


if __name__=='__main__':
    if len(sys.argv)==4 and sys.argv[1]=='--broker':sys.exit(broker(int(sys.argv[2]),sys.argv[3]))
    sys.exit(main())
