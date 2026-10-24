#!/usr/bin/env python3
"""Prove empty primary cleanup selection retains real generation-ring leases."""
import argparse
import errno
import importlib.util
import os
from pathlib import Path
import select
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


def record(process, prefix, timeout=30):
    deadline = time.monotonic() + timeout
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while time.monotonic() < deadline and selector.select(max(0, deadline-time.monotonic())):
            line=process.stdout.readline().decode(errors='replace').strip()
            if line.startswith(prefix+' '):
                return json_record(line, prefix)
            if not line and process.poll() is not None:
                break
    try:
        out,err=process.communicate(timeout=1)
    except subprocess.TimeoutExpired:
        out=err=b''
    raise RuntimeError(prefix+' missing; rc='+str(process.poll())+' stdout='+
        out.decode(errors='replace')+' stderr='+err.decode(errors='replace'))


def json_record(line, prefix):
    import json
    return json.loads(line[len(prefix)+1:])


def capture_pidfd(process):
    process.pidfd=os.pidfd_open(process.pid,0)


def wait_pidfd(process, label):
    poller=select.poll(); poller.register(process.pidfd,select.POLLIN|select.POLLHUP|select.POLLERR)
    require(bool(poller.poll(10000)),label+' pidfd did not become readable')
    process.wait(timeout=2)
    require(process.returncode==0,label+' rc='+str(process.returncode))
    os.close(process.pidfd); process.pidfd=-1


def write_control(worker, command, capability=None):
    worker.stdin.write(command)
    if capability is not None:
        worker.stdin.write(int(capability).to_bytes(8,byteorder=sys.byteorder,signed=False))
    worker.stdin.flush()


def parser_rejections(worker, tool, socket_path):
    invalid = subprocess.run([sys.executable,str(tool),'serve','--socket',str(socket_path),
        '--worker',str(worker),'--generation-rings','--generation-cleanup-rx-mask','4',
        '--generation-cleanup-tx-mask','0'],capture_output=True,timeout=5)
    require(invalid.returncode!=0 and b'cleanup mask must select only queues 0..1' in invalid.stderr and
        b'KER_SESSION_READY' not in invalid.stdout,'Python parser accepted an out-of-range mask')
    direct = subprocess.run([str(worker),'--role','primary','--socket',str(socket_path),
        '--control-fd','0','--generation-rings','--generation-cleanup-rx-mask','4',
        '--generation-cleanup-tx-mask','0','--','--no-pci'],capture_output=True,timeout=5)
    require(direct.returncode==2 and b'invalid generation cleanup configuration' in direct.stderr and
        b'KER_SESSION_READY' not in direct.stdout,'native primary accepted an out-of-range mask before EAL/READY')
    partial = subprocess.run([sys.executable,str(tool),'serve','--socket',str(socket_path),
        '--worker',str(worker),'--generation-rings','--generation-cleanup-rx-mask','0'],
        capture_output=True,timeout=5)
    require(partial.returncode!=0 and b'both cleanup masks require serve --generation-rings' in partial.stderr,
        'Python parser accepted only one cleanup mask')



def invalid_selected_entry(args,api,eal,run_id):
    workers=[]; masters=[]; resident=None; resident_pidfd=-1
    with tempfile.TemporaryDirectory(prefix='ker-generation-invalid-selected-') as temporary:
        root=Path(temporary); socket_path=root/'control.sock'
        environment=dict(os.environ,RUNTIME_DIRECTORY=str(root))
        common=['--socket',str(socket_path),'--worker',str(args.worker),'--eal',eal]
        resident=subprocess.Popen([str(args.worker),'--role','primary','--socket',str(socket_path),
            '--control-fd','0','--generation-rings','--ring-pmd',
            '--generation-test-corrupt-after-collection','--',
            *api.role_arguments(eal,'primary',ring_pmd=True)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,env=environment,bufsize=0)
        resident_pidfd=os.pidfd_open(resident.pid,0); resident.pidfd=resident_pidfd

        def spawn(master,ticket,generation,standby=False):
            read_fd,write_fd=os.pipe2(os.O_CLOEXEC)
            try:
                command=[str(args.worker),'--role','secondary','--socket',str(socket_path),
                    '--control-fd','0','--ticket-fd',str(read_fd),'--generation',str(generation),
                    '--process','0','--generation-rings','--generation-detach-test','--ring-pmd']
                if standby: command.append('--standby')
                command += ['--',*api.role_arguments(eal,'secondary',ring_pmd=True)]
                child=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                    pass_fds=(read_fd,),env=environment,bufsize=0)
                child.pidfd=os.pidfd_open(child.pid,0); workers.append(child)
                blob=api.encode(ticket)
                require(os.write(write_fd,blob)==len(blob),'short ticket write')
                return child
            finally:
                os.close(read_fd); os.close(write_fd)

        def wait_dead(process,label):
            poller=select.poll(); poller.register(process.pidfd,select.POLLIN|select.POLLHUP|select.POLLERR)
            require(bool(poller.poll(10000)),label+' exact pidfd did not become readable')
            process.wait(timeout=1)
            os.close(process.pidfd); process.pidfd=-1

        try:
            record(resident,'KER_SESSION_READY')
            master=api.Connection(socket_path); masters.append(master)
            ticket=master.request(api.MASTER)
            owner=spawn(master,ticket,0)
            owner_ready=record(owner,'KER_SESSION_ATTACHED')
            require(owner_ready['generation']==0 and owner_ready['pid']==owner.pid,
                'invalid-entry owner was not the exact generation-zero worker')
            require(record(owner,'KER_SESSION_PMD_GRANTED')['queue_owner_key']>0,
                'invalid-entry owner did not hold the production PMD grant')
            standby=spawn(master,ticket,1,standby=True)
            standby_ready=record(standby,'KER_SESSION_ATTACHED')
            record(standby,'KER_SESSION_PMD_STANDBY')
            require(standby_ready['slot']==owner_ready['slot'] and standby_ready['epoch']==owner_ready['epoch'],
                'workers did not share the authenticated master coordinate')
            capability=master.request(api.RING_DETACH_ARM,session=ticket['session'],epoch=ticket['epoch'],
                token=ticket['token'],slot=ticket['slot'],generation=0,process=0)['capability']
            def status():
                connection=api.Connection(socket_path)
                try: return connection.request(api.STATUS)
                finally: connection.close()
            baseline=status()
            require(baseline['generation']==508 and baseline['token']==3 and
                baseline['generation']+baseline['token']==511 and baseline['slot']==1 and baseline['process']==2,
                'invalid-entry fixture did not start from the exact one-master/two-worker pool baseline: '+repr(baseline))
            print('CHECK: invalid-entry exact attached baseline available=508/in-use=3/slots=1/users=2',flush=True)
            for child in (owner,standby): write_control(child,b'T')
            for child,generation in ((owner,0),(standby,1)):
                write_control(child,b'G'); require(record(child,'KER_GENERATION_PROBED')==
                    {'generation':generation,'step':3},'sentinel seeding stage failed')
            for child,generation in ((owner,0),(standby,1)):
                write_control(child,b'G'); require(record(child,'KER_GENERATION_PROBED')==
                    {'generation':generation,'step':4},'sentinel identity stage failed')
            seeded=status()
            require(seeded['generation']==baseline['generation']-8 and
                seeded['token']==baseline['token']+8 and seeded['slot']==baseline['slot'] and
                seeded['process']==baseline['process'],
                'expected exactly eight production-journaled sentinels without changing attached users: '+repr(seeded))
            print('CHECK: invalid-entry eight-sentinel census available=500/in-use=11 unchanged slots/users',flush=True)
            write_control(owner,b'd',capability)
            resident.wait(timeout=10)
            require(resident.returncode==125,'selected invalid journal did not fail resident closed')
            resident_out,resident_err=resident.communicate(timeout=2)
            require(b'orderly generation detach failed -117' in resident_err,
                'resident did not report the selected journal invariant failure: '+resident_err.decode(errors='replace'))
            owner_out,owner_err=owner.communicate(timeout=10)
            standby_out,standby_err=standby.communicate(timeout=10)
            wait_dead(owner,'invalid-entry owner'); wait_dead(standby,'invalid-entry standby')
            require(owner.returncode!=0 and standby.returncode!=0,
                'worker unexpectedly completed after resident rejected detach')
            require(b'KER_SESSION_RING_DETACHED' not in owner_out and
                b'KER_SESSION_RING_DETACH {' not in resident_out,
                'resident acknowledged detach after selected-entry validation failed')
            require(b'KER_SESSION_DRAINED' not in resident_out+owner_out+standby_out,
                'fatal selected-entry path claimed complete cleanup')
            master.close(); masters.remove(master); master=None
            wait_dead(resident,'invalid-entry resident')
            resident_pidfd=-1  # wait_dead closed the process-owned pidfd
            print('PASS: a malformed later selected TX entry failed closed without a detach ACK or false DRAINED record')
            return 0
        finally:
            for child in workers:
                if child.poll() is None:
                    try: child.kill()
                    except ProcessLookupError: pass
                try: child.communicate(timeout=5)
                except BaseException: pass
                fd=getattr(child,'pidfd',-1)
                if fd>=0:
                    try: os.close(fd)
                    except OSError: pass
            for connection in masters:
                try: connection.close()
                except BaseException: pass
            if resident is not None and resident.poll() is None:
                try:
                    if resident.stdin is not None: resident.stdin.close(); resident.stdin=None
                    resident.communicate(timeout=15)
                except subprocess.TimeoutExpired:
                    resident.kill(); resident.communicate()
            if resident_pidfd>=0:
                try: os.close(resident_pidfd)
                except OSError: pass


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker',type=Path,required=True)
    parser.add_argument('--tool',type=Path,required=True)
    parser.add_argument('--huge-dir',type=Path,default=Path('/dev/hugepages'))
    parser.add_argument('--invalid-selected-entry',action='store_true')
    args=parser.parse_args()
    parser_rejections(args.worker,args.tool,Path('/tmp/ker-empty-config-invalid.sock'))
    reason=hugepage_capacity_error(args.huge_dir,64*1024*1024)
    if reason:
        print('SKIP: '+reason+'; no host settings changed'); return 77
    spec=importlib.util.spec_from_file_location('ker_session_tool',args.tool)
    api=importlib.util.module_from_spec(spec); spec.loader.exec_module(api)
    run_id=f'{os.getpid()}-{os.urandom(6).hex()}'
    cpu=min(os.sched_getaffinity(0))
    prefix='geninvalid' if args.invalid_selected_entry else 'genempty'
    eal=(f'--lcores=0@{cpu} --no-pci --no-telemetry --iova-mode=va -m 64 '
         f'--huge-dir={args.huge_dir} --file-prefix={prefix}-{run_id}')
    if args.invalid_selected_entry:
        return invalid_selected_entry(args,api,eal,run_id)
    workers=[]; master=None; resident=None; resident_pidfd=-1
    with tempfile.TemporaryDirectory(prefix='ker-generation-empty-') as temporary:
        root=Path(temporary); socket_path=root/'control.sock'
        environment=dict(os.environ,RUNTIME_DIRECTORY=str(root))
        common=['--socket',str(socket_path),'--worker',str(args.worker),'--eal',eal]
        resident=subprocess.Popen([sys.executable,str(args.tool),'serve','--generation-rings',
            '--generation-cleanup-rx-mask','0','--generation-cleanup-tx-mask','0',
            '--ring-pmd',*common],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            env=environment,bufsize=0)
        capture_pidfd(resident); resident_pidfd=resident.pidfd

        def status():
            connection=api.Connection(socket_path)
            try: return connection.request(api.STATUS)
            finally: connection.close()

        def pmd_status():
            connection=api.Connection(socket_path)
            try: return connection.request(api.PMD_STATUS)
            finally: connection.close()

        def start_master():
            nonlocal master
            master=api.Connection(socket_path)
            return master.request(api.MASTER)

        def start_worker(ticket,generation,standby=False):
            read_fd,write_fd=os.pipe2(os.O_CLOEXEC)
            command=[str(args.worker),'--role','secondary','--socket',str(socket_path),
                '--control-fd','0','--ticket-fd',str(read_fd),'--generation',str(generation),
                '--process','0','--generation-rings','--generation-detach-test',
                '--generation-empty-cleanup-test','--ring-pmd']
            if standby: command.append('--standby')
            command += ['--',*api.role_arguments(eal,'secondary',ring_pmd=True)]
            child=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                pass_fds=(read_fd,),env=environment,bufsize=0)
            capture_pidfd(child); workers.append(child)
            blob=api.encode(ticket)
            require(os.write(write_fd,blob)==len(blob),'short worker ticket write')
            os.close(read_fd); os.close(write_fd)
            return child

        def probe(worker,generation,step):
            write_control(worker,b'G')
            expected=record(worker,'KER_GENERATION_PROBED')
            require(expected=={'generation':generation,'step':step},'generation test step mismatch '+repr(expected))

        def arm(ticket):
            return master.request(api.RING_DETACH_ARM,session=ticket['session'],epoch=ticket['epoch'],
                token=ticket['token'],slot=ticket['slot'],generation=0,process=0)['capability']

        def release_master(ticket):
            deadline=time.monotonic()+10
            last_status=None; last_pmd=None; last_report=0.0
            while True:
                try:
                    master.request(api.RELEASE,session=ticket['session'],epoch=ticket['epoch'],
                        token=ticket['token'],slot=ticket['slot'])
                    print('CHECK: empty-cleanup master slot RELEASE succeeded',flush=True)
                    return
                except OSError as error:
                    if error.errno!=errno.EBUSY:
                        raise
                    last_status=status(); last_pmd=pmd_status()
                    now=time.monotonic()
                    if now>=deadline:
                        raise RuntimeError('master RELEASE remained EBUSY after bounded census polling: '+
                            repr({'status':last_status,'pmd_status':last_pmd}))
                    if now-last_report>=1.0:
                        print('CHECK: RELEASE EBUSY; polling resident census '+
                            repr({'status':last_status,'pmd_status':last_pmd}),flush=True)
                        last_report=now
                    time.sleep(0.05)

        def detach(worker,capability):
            write_control(worker,b'd',capability)
            result=record(worker,'KER_SESSION_RING_DETACHED')
            require(result=={'foreign_peer':False,'rx_reclaimed':0,'tx_reclaimed':0},
                'empty cleanup reclaimed a ring object: '+repr(result))
            return record(resident,'KER_SESSION_RING_DETACH')

        try:
            print('CHECK: empty-cleanup resident READY',flush=True)
            ready=record(resident,'KER_SESSION_READY')
            require(ready['ring_pmd'] is True and ready['session']>0,
                'resident did not publish ready state with the physical PMD/control queue')
            print('CHECK: empty-cleanup acquire master',flush=True)
            ticket=start_master()
            print('CHECK: empty-cleanup attach generation-0 owner',flush=True)
            source=start_worker(ticket,0)
            source_ready=record(source,'KER_SESSION_ATTACHED')
            granted=record(source,'KER_SESSION_PMD_GRANTED')
            require(granted['queue_owner_key']>0,'source failed to own required PMD/control queue')
            print('CHECK: empty-cleanup attach generation-1 standby',flush=True)
            peer=start_worker(ticket,1,standby=True)
            peer_ready=record(peer,'KER_SESSION_ATTACHED')
            record(peer,'KER_SESSION_PMD_STANDBY')
            require(peer_ready['slot']==source_ready['slot'] and peer_ready['epoch']==source_ready['epoch'],
                'generation workers do not share the exact master coordinate')
            print('CHECK: empty-cleanup arm first detach',flush=True)
            first_capability=arm(ticket)
            print('CHECK: empty-cleanup first detach armed',flush=True)
            baseline=status(); owner_before=pmd_status()
            require(baseline['generation']>=8,'invalid initial pool availability')
            for worker in (source,peer): write_control(worker,b'T')
            probe(source,0,3); probe(peer,1,3)
            probe(source,0,4); probe(peer,1,4)
            seeded=status()
            require(seeded['generation']==baseline['generation']-8,'NR19 production enqueue path did not seed all eight rings')
            print('CHECK: empty-cleanup first detach',flush=True)
            first=detach(source,first_capability)
            print('CHECK: empty-cleanup first detach completed',flush=True)
            require(first['rx_reclaimed']==0 and first['tx_reclaimed']==0,'resident reported cleanup under empty masks')
            after=status(); owner_after=pmd_status()
            require(after['generation']==seeded['generation'] and after['token']==seeded['token'],
                'empty detach changed pool counts')
            require(owner_after['token']==owner_before['token'] and owner_after['slot']==owner_before['slot'] and
                owner_after['epoch']==owner_before['epoch'],'empty detach changed PMD owner')
            print('CHECK: empty-cleanup arm repeated detach',flush=True)
            second_capability=arm(ticket)
            print('CHECK: empty-cleanup repeated detach armed',flush=True)
            print('CHECK: empty-cleanup repeated detach',flush=True)
            second=detach(source,second_capability)
            print('CHECK: empty-cleanup repeated detach completed',flush=True)
            require(second['rx_reclaimed']==0 and second['tx_reclaimed']==0,
                'repeated empty unregister changed counts')
            require(status()['generation']==seeded['generation'],'repeated empty detach changed pool availability')
            print('CHECK: empty-cleanup two-generation retained-object barrier',flush=True)
            for worker,generation in ((source,0),(peer,1)):
                write_control(worker,b'V')
                require(record(worker,'KER_GENERATION_EMPTY_CLEANUP_RETAINED')==
                    {'generation':generation,'rings':8,'owned_rings':4,'same_objects':True},
                    'retained object barrier failed for generation '+str(generation))
            print('CHECK: both generation-owned retained snapshots passed before any release',flush=True)
            require(status()['generation']==seeded['generation'],'retained NR19 objects changed before release')
            print('CHECK: empty-cleanup release generation-owned objects',flush=True)
            probe(source,0,5); require(record(source,'KER_GENERATION_EMPTY_CLEANUP_RELEASED')=={'generation':0},
                'generation-0 retained objects did not release')
            probe(peer,1,5); require(record(peer,'KER_GENERATION_EMPTY_CLEANUP_RELEASED')=={'generation':1},
                'generation-1 retained objects did not release')
            require(status()['generation']==baseline['generation'],'retained NR19 objects did not release exactly once')
            print('CHECK: empty-cleanup real API readmission roundtrip',flush=True)
            probe(source,0,0); probe(peer,1,0)
            require(status()['generation']==baseline['generation'],'same-ring readmission leaked or lost an object')
            for child in (source,peer):
                write_control(child,b'x')
                out,err=child.communicate(timeout=20)
                require(child.returncode==0,'secondary cleanup failed: '+out.decode(errors='replace')+' '+err.decode(errors='replace'))
                ready_events=select.poll(); ready_events.register(child.pidfd,select.POLLIN|select.POLLHUP|select.POLLERR)
                require(bool(ready_events.poll(10000)),'secondary pidfd did not become readable')
                os.close(child.pidfd); child.pidfd=-1
            print('CHECK: empty-cleanup both exact child pidfds readable and exits zero',flush=True)
            print('CHECK: empty-cleanup master slot RELEASE after exact child pidfd deaths',flush=True)
            release_master(ticket)
            master.close(); master=None
            final=status(); final_pmd=pmd_status()
            require(final['slot']==0 and final['process']==0,'resident still reports active slots/users after RELEASE: '+repr(final))
            require(final['generation']==511 and final['token']==0,'resident pool did not return to 511 available/0 in-use: '+repr(final))
            require(final_pmd['token']==0 and final_pmd['epoch']==0,'PMD owner survived final worker cleanup: '+repr(final_pmd))
            resident.stdin.close(); resident.stdin=None
            out,err=resident.communicate(timeout=30)
            require(resident.returncode==0,'resident shutdown failed: '+out.decode(errors='replace')+' '+err.decode(errors='replace'))
            ready_events=select.poll(); ready_events.register(resident_pidfd,select.POLLIN|select.POLLHUP|select.POLLERR)
            require(bool(ready_events.poll(10000)),'resident pidfd did not become readable')
            os.close(resident_pidfd); resident_pidfd=-1
            print('PASS: primary-private empty cleanup masks retained all eight exact ring objects, completed idempotent detach/readmission and returned the 511-object pool')
            return 0
        finally:
            if master is not None:
                try: master.close()
                except BaseException: pass
            for child in workers:
                try:
                    if child.poll() is None: child.kill()
                    child.communicate(timeout=5)
                except BaseException: pass
                fd=getattr(child,'pidfd',-1)
                if fd>=0:
                    try: os.close(fd)
                    except OSError: pass
            if resident is not None and resident.poll() is None:
                if resident.stdin is not None:
                    try: resident.stdin.close(); resident.stdin=None
                    except OSError: pass
                try: resident.communicate(timeout=20)
                except subprocess.TimeoutExpired:
                    resident.kill(); resident.communicate()
            if resident_pidfd>=0:
                try: os.close(resident_pidfd)
                except OSError: pass


if __name__=='__main__':
    try: raise SystemExit(main())
    except Exception as error:
        print('session-generation-empty-config: '+str(error),file=sys.stderr)
        raise SystemExit(1)
