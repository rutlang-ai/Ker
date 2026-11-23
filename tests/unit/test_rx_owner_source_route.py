#!/usr/bin/env python3
"""Real-process controls for C31's pending same-master source route."""
import argparse
import array
import copy
import errno
import fcntl
import importlib.util
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('ker_run_source_route_test', ROOT / 'tools/ker-run.py')
ker_run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ker_run)
RECEIVER = None
ACTIVATION_RECEIVER = os.environ.get('KER_FSTACK_ACTIVATION_RECEIVER')
NONCE = bytes(range(16))
bootstrap_spec = importlib.util.spec_from_file_location('c31_route_handoff_bootstrap',
    ROOT / 'tools/nginx_source_bootstrap_supervisor.py')
source_bootstrap = importlib.util.module_from_spec(bootstrap_spec)
sys.modules[bootstrap_spec.name] = source_bootstrap
bootstrap_spec.loader.exec_module(source_bootstrap)

ACTOR = r'''
import array, os, socket, struct, sys, time
s=socket.socket(fileno=int(sys.argv[1])); s.setblocking(True); mode=sys.argv[2]
if mode=='dead': sys.exit(0)
activation = None
if len(sys.argv) == 6:
 activation=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
 activation.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1)
 activation.connect(sys.argv[4])
w=struct.Struct('=IHHQQ16sQQQQIIIIIHHHHIiHBB')
p,anc,flags,_=s.recvmsg(w.size+1,socket.CMSG_SPACE(12)+socket.CMSG_SPACE(8))
fds=[]; creds=[]
for level,kind,data in anc:
 if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
  a=array.array('i'); a.frombytes(data); fds.extend(a)
 elif level==socket.SOL_SOCKET and kind==socket.SCM_CREDENTIALS: creds.append(struct.unpack('=3i',data))
h=list(w.unpack(p))
assert not flags & (socket.MSG_TRUNC|socket.MSG_CTRUNC)
assert len(fds)==2 and creds==[(int(os.environ.get('KER_TEST_SUPERVISOR_PID',os.getppid())),os.getuid(),os.getgid())]
assert h[2]==3 and h[11]==h[12]==os.getpid()
assert 'Pid:\t'+str(h[10])+'\n' in open('/proc/self/fdinfo/'+str(fds[0])).read()
assert 'Pid:\t'+str(h[13])+'\n' in open('/proc/self/fdinfo/'+str(fds[1])).read()
if mode=='no-ack':
 try: s.recv(1)
 except ConnectionResetError: pass
 sys.exit(0)
if mode=='late-ack': time.sleep(.5)
h[2]=5
me=os.pidfd_open(os.getpid())
try: s.sendmsg([w.pack(*h)],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[me]))])
except OSError: pass
os.close(me)
if activation is not None:
 # Exec preserves the candidate PID and both connected Unix channels.
 activation.set_inheritable(True)
 os.execv(sys.argv[3],[sys.argv[3],'--receive-activate-fd',str(activation.fileno()),sys.argv[5]])
if mode=='peer':
 p,anc,flags,_=s.recvmsg(w.size+9022,socket.CMSG_SPACE(12))
 h=list(w.unpack(p[:w.size])); frame=p[w.size:]
 assert h[2]==1 and len(frame)==64 and not flags & (socket.MSG_TRUNC|socket.MSG_CTRUNC)
 v=2166136261
 for b in frame: v=((v^b)*16777619)&0xffffffff
 h[2]=2; h[19]=v; h[20]=h[15]; h[23]=1
 s.sendmsg([w.pack(*h),frame])
 sys.exit(0)
try: s.recv(1)
except ConnectionResetError: pass
for f in fds: os.close(f)
'''

RETRY_GRANT_ACTOR = r'''
import array, os, socket, struct, sys
record = struct.Struct(sys.argv[2])
request = list(record.unpack(bytes.fromhex(sys.argv[3])))
pid = os.getpid()
request[5:7] = [pid, pid]
request[11] = int(open(f'/proc/{pid}/stat').read().rpartition(')')[2].split()[19])
channel = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
channel.settimeout(5)
channel.connect(sys.argv[1])
channel.send(record.pack(*request))
packet, ancillary, flags, _ = channel.recvmsg(record.size + 1,
    socket.CMSG_SPACE(5 * 4) + socket.CMSG_SPACE(12), socket.MSG_CMSG_CLOEXEC)
assert not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
fds = array.array('i')
for level, kind, data in ancillary:
    if (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS):
        fds.frombytes(data)
reply = record.unpack(packet)
assert reply[2] == 2 and reply[8:10] == (1, 2) and len(fds) == 5
slot = os.fstat(fds[2])
assert (slot.st_dev, slot.st_ino) == reply[24:26]
ready = struct.Struct('=IHHIIQQQIIQQ')
ready_channel = socket.socket(fileno=fds[4])
cookie = reply[27] ^ (1 if sys.argv[4] == 'bad-ready' else 0)
ready_channel.send(ready.pack(0x4B4E5244, 2, ready.size, 1, 0,
    slot.st_dev, slot.st_ino, request[11], pid, pid, cookie, 0))
activation = 0
if sys.argv[4] != 'bad-ready':
    relay = socket.socket(fileno=fds[3])
    relay.settimeout(5)
    relay.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    auth = struct.Struct('=IHHQQ16sQQQQIIIIIHHHHIiHBB')
    payload, ancillary, flags, _ = relay.recvmsg(auth.size + 1,
        socket.CMSG_SPACE(12) + socket.CMSG_SPACE(8), socket.MSG_CMSG_CLOEXEC)
    assert not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
    assert (socket.SOL_SOCKET, socket.SCM_CREDENTIALS,
        struct.pack('=3i', os.getppid(), os.getuid(), os.getgid())) in ancillary
    fields = list(auth.unpack(payload))
    assert fields[2] == 3 and fields[11:14] == [pid, pid, os.getppid()]
    fields[2] = 5
    pidfd = os.pidfd_open(pid)
    relay.sendmsg([auth.pack(*fields)], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
        array.array('i', [pidfd]))])
    os.close(pidfd)
    activated = record.unpack(channel.recv(record.size + 1))
    assert activated == (*reply[:2], 4, *reply[3:])
    activation = activated[2]
print(slot.st_dev, slot.st_ino, activation, flush=True)
if sys.argv[4] == 'success':
    header = struct.Struct('=IHHII')
    size = header.size + record.size + 8
    evidence = channel.recv(size + 1)
    assert header.unpack_from(evidence) == (0x4B534247, 1, 12, size, 0)
    assert record.unpack_from(evidence, header.size) == (*reply[:2], 12, *reply[3:])
    assert struct.unpack_from('=Q', evidence, size - 8) == (0x9922,)
sys.stdin.buffer.read(1)
'''

SOURCE_C31_MODEL_APP = r'''
import array, os, socket, struct, sys
import time
control_fd, marker_fd, release_fd = map(int, sys.argv[1:4])
s=socket.socket(fileno=control_fd)
s.setblocking(True)
import os
os.write(marker_fd,b'A')
w=struct.Struct('=IHHIIIIIIQQQQQQ16sIIQQQQQQQQIIiIQ')
request, anc, flags, _ = s.recvmsg(w.size+1, socket.CMSG_SPACE(12)+socket.CMSG_SPACE(4*4))
fds=[]
for level, kind, data in anc:
 if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
  a=array.array('i'); a.frombytes(data); fds.extend(a)
assert len(request)==w.size and len(fds)==3 and not flags & (socket.MSG_TRUNC|socket.MSG_CTRUNC)
fields=list(w.unpack(request)); assert fields[2]==5
candidate=socket.socket(fileno=fds[1]); fds[1]=-1
candidate.setblocking(True)
relay, relay_anc, relay_flags, _=candidate.recvmsg(1024, socket.CMSG_SPACE(12)+socket.CMSG_SPACE(4*4))
assert relay and not relay_flags & (socket.MSG_TRUNC|socket.MSG_CTRUNC)
candidate.close()
for fd in fds:
 if fd>=0: os.close(fd)
fields[2]=6
s.send(w.pack(*fields)); os.write(marker_fd,b'P')
command, anc, flags, _=s.recvmsg(w.size+1, socket.CMSG_SPACE(12)+socket.CMSG_SPACE(4*4))
assert len(command)==w.size and not flags & (socket.MSG_TRUNC|socket.MSG_CTRUNC)
fields=list(w.unpack(command)); op=fields[2]
assert op in (7,9,11)
fields[2]={7:8,9:10,11:12}[op]
fields[28]=int(os.environ.get('KER_TEST_TYPED_ACK_STATUS','0'))
fault=os.environ.get('KER_TEST_TYPED_ACK_FAULT','')
if fault=='eof':
 s.close(); sys.exit(0)
if fault=='late': time.sleep(.12)
ack=w.pack(*fields)
if fault=='short': s.send(ack[:-1])
elif fault=='extra-fd':
 fd=os.open('/dev/null',os.O_RDONLY)
 s.sendmsg([ack],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fd]))])
 os.close(fd)
elif fault=='wrong-sequence':
 fields[24]+=1; s.send(w.pack(*fields))
elif fault=='wrong-kind':
 fields[2]=8 if op==11 else 12; s.send(w.pack(*fields))
else: s.send(ack)
os.write(marker_fd,b'CL')
assert os.read(release_fd,1)==b'R'
'''


def pair():
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK)
    for s in (a, b):
        s.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    return a, b


def proof(process, slot, role):
    st = os.fstat(slot.fileno())
    return SimpleNamespace(owner_pid=process.pid, owner_tid=process.pid,
        owner_start=ker_run.process_start_ticks(process.pid), owner_role=role,
        owner_pidfd=os.pidfd_open(process.pid), owner_slot_device=st.st_dev,
        owner_slot_inode=st.st_ino, owner_cookie=struct.unpack('=Q',
            slot.getsockopt(socket.SOL_SOCKET, 57, 8))[0])


def foreign_created_socket():
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    release_read, release_write = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            parent.close()
            os.close(release_write)
            offered, peer = socket.socketpair(socket.AF_UNIX,
                socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
            child.sendmsg([b'F'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                array.array('i', [offered.fileno()]))])
            offered.close()
            os.read(release_read, 1)
            peer.close()
            os._exit(0)
        except BaseException:
            os._exit(90)
    child.close()
    os.close(release_read)
    _, ancillary, _, _ = parent.recvmsg(1, socket.CMSG_SPACE(4))
    received = []
    for level, kind, data in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            values = array.array('i'); values.frombytes(data[:len(data) - len(data) % 4])
            received.extend(values)
    parent.close()
    if len(received) != 1:
        os.write(release_write, b'R'); os.close(release_write)
        os.waitpid(pid, 0)
        raise AssertionError('foreign SDK-channel owner fixture failed')
    return socket.socket(fileno=received[0]), pid, release_write


OLD_ACTOR = r'''
import socket, struct, sys
s=socket.socket(fileno=int(sys.argv[1]))
s.setblocking(True)
w=struct.Struct('=IHHQQ16sQQQQIIIIIHHHHIiHBB')
p,anc,flags,_=s.recvmsg(w.size+9022,socket.CMSG_SPACE(12))
h=list(w.unpack(p[:w.size])); frame=p[w.size:]
assert h[2]==1 and len(frame)==64 and not flags & (socket.MSG_TRUNC|socket.MSG_CTRUNC)
v=2166136261
for b in frame: v=((v^b)*16777619)&0xffffffff
h[2]=2; h[19]=v; h[20]=h[15]; h[23]=1
s.sendmsg([w.pack(*h),frame])
'''

MASTER = r'''
import os, subprocess, sys, time
oldfd, candidatefd, reportfd = map(int, sys.argv[1:4])
old = subprocess.Popen([sys.executable, '-c', sys.argv[4], str(oldfd)],
    pass_fds=(oldfd,), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL)
candidate = subprocess.Popen([sys.executable, '-c', sys.argv[5],
    str(candidatefd), sys.argv[6]], pass_fds=(candidatefd,),
    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
os.write(reportfd, f'{old.pid} {candidate.pid}\n'.encode()); os.close(reportfd)
while True: time.sleep(1)
'''


class SourceRoute(unittest.TestCase):
    def setUp(self):
        if RECEIVER is None:
            self.skipTest('receiver path is supplied by the native CTest invocation')

    def run_case(self, abort=False, inflight=False, candidate_mode='valid',
                 short_deadline=False, kill_after_stage=False,
                 expire_after_commit=False, master_death_after_commit=False,
                 expired_commit=False, late_swap=False, late_route_arrival=False,
                 abort_retry=False, late_observation=False, deferred_commit=False,
                 deferred_expired=False, deferred_dead_candidate=False,
                 deferred_second_command=False, deferred_late_completion=False,
                 successor=False, successor_dead_current=False,
                 successor_second=False, successor_replay=False,
                 successor_inflight=False, typed_handoff=False,
                 production_private_controller=False,
                 drop_typed_binding=False, typed_command_type=7,
                 typed_ack_status=0, typed_bad_context_actor=False,
                 typed_context_tamper=None, typed_ack_fault=None,
                 typed_c28_counts=(3, 3),
                 copy_typed_binding=False, typed_post_ack_clear_cloexec=False,
                 private_master_park=False, private_master_fault=None,
                 private_master_commit=False, private_master_commit_fault=None,
                 private_master_abort=None,
                 native_activation=False):
        successor = (successor or successor_dead_current or successor_second or
            successor_replay or successor_inflight)
        control, app_control = pair()
        old_channel, old_worker_channel = pair()
        candidate_channel, candidate_worker_channel = pair()
        old_slot, candidate_slot = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        marker_read, marker_write = os.pipe()
        app = old = candidate_process = source_master_process = None
        processes = []
        foreign_children = []
        proofs = []
        sockets = [control, app_control, old_channel, old_worker_channel,
            candidate_channel, candidate_worker_channel, old_slot, candidate_slot]
        release_read, release_write = os.pipe()
        handles = [release_read, release_write]
        late_ready_read = late_ready_write = -1
        late_release_read = late_release_write = -1
        if late_route_arrival:
            late_ready_read, late_ready_write = os.pipe()
            late_release_read, late_release_write = os.pipe()
            handles.extend((late_ready_read, late_ready_write,
                late_release_read, late_release_write))
        try:
            if native_activation:
                directory = tempfile.TemporaryDirectory(prefix='ker-source-activate-')
                self.addCleanup(directory.cleanup)
                activation_path = str(Path(directory.name) / 'worker.sock')
                activation_listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                sockets.append(activation_listener)
                activation_listener.bind(activation_path)
                activation_listener.listen(1)
                activation_listener.settimeout(2)
            if master_death_after_commit:
                report_read, report_write = os.pipe()
                source_master_process = subprocess.Popen([sys.executable, '-c', MASTER,
                    str(old_worker_channel.fileno()), str(candidate_worker_channel.fileno()),
                    str(report_write), OLD_ACTOR, ACTOR, candidate_mode],
                    pass_fds=(old_worker_channel.fileno(), candidate_worker_channel.fileno(),
                        report_write), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                    env={**os.environ, 'KER_TEST_SUPERVISOR_PID': str(os.getpid())})
                os.close(report_write)
                report = os.read(report_read, 128).decode().split()
                os.close(report_read)
                if len(report) != 2:
                    _, error = source_master_process.communicate(timeout=2)
                    raise AssertionError(f'source master failed to start workers: {error!r}')
                old = SimpleNamespace(pid=int(report[0]))
                candidate_process = SimpleNamespace(pid=int(report[1]))
            else:
                old = subprocess.Popen([sys.executable, '-c', OLD_ACTOR,
                    str(old_worker_channel.fileno())], pass_fds=(old_worker_channel.fileno(),),
                    stderr=subprocess.PIPE)
                candidate_argv = [sys.executable, '-c', ACTOR,
                    str(candidate_worker_channel.fileno()), candidate_mode]
                if native_activation:
                    receiver_mode = 'activate'
                    if private_master_commit:
                        receiver_mode = ('reject-commit' if private_master_commit_fault == 'worker-proof'
                            else 'commit')
                    candidate_argv.extend((ACTIVATION_RECEIVER, activation_path, receiver_mode))
                candidate_process = subprocess.Popen(candidate_argv,
                    pass_fds=(candidate_worker_channel.fileno(),),
                    stdin=subprocess.PIPE if native_activation else None,
                    stdout=subprocess.PIPE if native_activation else None,
                    stderr=subprocess.PIPE)
            processes.extend(process for process in (old, candidate_process)
                if isinstance(process, subprocess.Popen))
            current = proof(old, old_slot, 0)
            candidate = proof(candidate_process, candidate_slot, 1)
            proofs.extend((current, candidate))
            supervisor = os.getpid()
            supervisor_start = ker_run.process_start_ticks(supervisor)
            app_pass_fds = [app_control.fileno(), old_channel.fileno(), marker_write,
                release_read]
            app_env = {
                    'KER_RX_OWNER_AUTH_FD': str(app_control.fileno()),
                    'KER_RX_OWNER_RELAY_FD': str(old_channel.fileno()),
                    'KER_TEST_SOURCE_SUPERVISOR_PID': str(supervisor),
                    'KER_TEST_SOURCE_CURRENT_PID': str(current.owner_pid),
                    'KER_TEST_SOURCE_CURRENT_START': str(current.owner_start),
                    'KER_TEST_SOURCE_CURRENT_COOKIE': str(current.owner_cookie),
                    'KER_TEST_SOURCE_CURRENT_DEVICE': str(current.owner_slot_device),
                    'KER_TEST_SOURCE_CURRENT_INODE': str(current.owner_slot_inode),
                    'KER_TEST_SOURCE_MARKER_FD': str(marker_write),
                    'KER_TEST_SOURCE_RELEASE_FD': str(release_read),
                    **({'KER_TEST_SOURCE_WAIT_MASTER_DEATH': '1'}
                        if master_death_after_commit else {}),
                    **({'KER_TEST_SOURCE_WAIT_AUTHORITY_EXPIRY': '1'}
                        if expire_after_commit else {}),
                    **({'KER_TEST_SOURCE_EXPIRED_COMMIT': '1'} if expired_commit else {}),
                    **({'KER_TEST_SOURCE_ROUTE_DELAY_SWAP': '1'} if late_swap else {}),
                    **({'KER_TEST_SOURCE_INFLIGHT': '1'} if inflight else {}),
                    **({'KER_TEST_SOURCE_ROUTE_RETRY': '1'}
                        if abort_retry or private_master_abort in ('success', 'retry-renewed',
                            'retry-c28-unknown') else {}),
                    **({'KER_TEST_SOURCE_RETURN_ON_RETRY_COMMIT': '1'}
                        if private_master_abort in ('success', 'retry-c28-unknown') else {}),
                    **({'KER_TEST_SOURCE_ROUTE_SUCCESSOR': '1'} if successor else {}),
                    **({'KER_TEST_SOURCE_ROUTE_DEAD_CURRENT': '1'}
                        if successor_dead_current else {}),
                    **({'KER_TEST_SOURCE_ROUTE_SECOND_SUCCESSOR': '1'}
                        if successor_second else {}),
                    **({'KER_TEST_SOURCE_ROUTE_REPLAY': '1'}
                        if successor_replay else {}),
                    **({'KER_TEST_SOURCE_ROUTE_SUCCESSOR_INFLIGHT': '1'}
                        if successor_inflight else {}),
                    **({'KER_TEST_SOURCE_DEFERRED_COMMIT': '1'} if deferred_commit else {}),
                    **({'KER_TEST_SOURCE_DEFERRED_EXPIRED': '1'} if deferred_expired else {}),
                    **({'KER_TEST_SOURCE_DEFERRED_DEAD': '1'} if deferred_dead_candidate else {}),
                    **({'KER_TEST_SOURCE_DEFERRED_SECOND': '1'} if deferred_second_command else {}),
                    **({'KER_TEST_SOURCE_DEFERRED_LATE_COMPLETION': '1'}
                        if deferred_late_completion else {})}
            if late_route_arrival:
                app_pass_fds.extend((late_ready_write, late_release_read))
                app_env.update({
                    'KER_TEST_SOURCE_LATE_ROUTE_AFTER_EMPTY': '1',
                    'KER_TEST_SOURCE_ROUTE_EMPTY_READY_FD': str(late_ready_write),
                    'KER_TEST_SOURCE_ROUTE_EMPTY_RELEASE_FD': str(late_release_read)})
            if typed_handoff:
                app_env['KER_TEST_TYPED_ACK_STATUS'] = str(typed_ack_status)
            if typed_ack_fault:
                app_env['KER_TEST_TYPED_ACK_FAULT'] = typed_ack_fault
            actual_private_c31 = production_private_controller and (
                private_master_commit or private_master_abort is not None or native_activation)
            if typed_handoff and not actual_private_c31:
                app = subprocess.Popen([sys.executable, '-c', SOURCE_C31_MODEL_APP,
                    str(app_control.fileno()), str(marker_write), str(release_read)],
                    pass_fds=tuple(set(app_pass_fds + [app_control.fileno()])),
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    env={**os.environ, **app_env})
            else:
                app = subprocess.Popen([RECEIVER], pass_fds=tuple(app_pass_fds),
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    env={**os.environ, **app_env})
            if typed_handoff and not actual_private_c31:
                self.assertEqual(os.read(marker_read, 1), b'A',
                    'C31 host model did not become ready before source PREPARE')
            os.close(marker_write); marker_write = -1
            app_control.close(); old_channel.close()
            if late_route_arrival:
                for fd in (late_ready_write, late_release_read):
                    os.close(fd)
                    handles.remove(fd)
                late_ready_write = -1
                late_release_read = -1
            app_pidfd = os.pidfd_open(app.pid)
            supervisor_pidfd = os.pidfd_open(supervisor)
            master_pid = source_master_process.pid if source_master_process else supervisor
            master_pidfd = os.pidfd_open(master_pid)
            handles.extend((app_pidfd, supervisor_pidfd, master_pidfd))
            source_master = SimpleNamespace(pid=master_pid, pidfd=master_pidfd,
                start_ticks=ker_run.process_start_ticks(master_pid))
            deadline = time.monotonic_ns() + (150_000_000 if short_deadline else
                500_000_000 if expire_after_commit else 10_000_000_000)
            source_context = None
            candidate_cycle_proof = None
            if typed_handoff:
                source_context = source_bootstrap.SourceBootstrapSupervisor.__new__(
                    source_bootstrap.SourceBootstrapSupervisor)
                source_context.shell_mode = True
                source_context.nonce = NONCE
                source_context.epoch = 77
                source_context.deadline_ns = deadline
                source_context.supervisor_start = supervisor_start
                source_context.master = source_master
                source_context.runtime = (SimpleNamespace(pid=current.owner_pid,
                    pidfd=current.owner_pidfd, start_ticks=current.owner_start)
                    if typed_bad_context_actor else SimpleNamespace(pid=app.pid,
                        pidfd=app_pidfd, start_ticks=ker_run.process_start_ticks(app.pid)))
                source_context.initial_cycle_proof = source_bootstrap.SourceCycleProof(
                    1, 0, 1, 10, b'a' * 32, b'b' * 32)
                candidate_cycle_proof = source_bootstrap.SourceCycleProof(
                    1, 0, 2, 20, b'a' * 32, b'b' * 32)
                source_context.worker_proofs = {(0, 0): source_context.initial_cycle_proof,
                    (1, 1): candidate_cycle_proof}
                source_context.live = lambda _observation_deadline_ns=None: None
                source_context.workers = {}
                for key, owner in (((0, 0), current), ((1, 1), candidate)):
                    record = [0] * 28
                    record[8], record[9] = (key[1], key[0])
                    record[5], record[6], record[11] = (owner.owner_pid,
                        owner.owner_tid, owner.owner_start)
                    record[14:17] = (77, deadline, NONCE)
                    record[24], record[25], record[27] = (
                        owner.owner_slot_device, owner.owner_slot_inode,
                        owner.owner_cookie)
                    source_context.workers[key] = (owner.owner_pidfd, tuple(record))
                if typed_context_tamper == 'candidate-proof-copy':
                    source_context.worker_proofs[(1, 1)] = source_bootstrap.SourceCycleProof(
                        *candidate_cycle_proof)
                elif typed_context_tamper == 'candidate-generation':
                    held_fd, record = source_context.workers.pop((1, 1))
                    record = list(record); record[8] = 2
                    source_context.workers[(1, 2)] = (held_fd, tuple(record))
                    source_context.worker_proofs[(1, 2)] = candidate_cycle_proof
                elif typed_context_tamper == 'candidate-source-epoch':
                    held_fd, record = source_context.workers.pop((1, 1))
                    record = list(record); record[9] = 2
                    source_context.workers[(2, 1)] = (held_fd, tuple(record))
                    source_context.worker_proofs[(2, 1)] = candidate_cycle_proof
                elif typed_context_tamper == 'wrong-master-actor':
                    source_context.master = SimpleNamespace(pid=current.owner_pid,
                        pidfd=current.owner_pidfd, start_ticks=current.owner_start)
                elif typed_context_tamper == 'wrong-supervisor-actor':
                    source_context.supervisor_start += 1
                elif typed_context_tamper == 'stale-live-callback':
                    source_context.live = lambda _deadline: (_ for _ in ()).throw(
                        ProcessLookupError('modeled source owner/slim liveness failure'))
                source_context._source_route_preparations = {}
                source_context._source_route_park_joins = {}
                source_context._source_route_commit_receipts = {}
                source_context._source_route_commit_consumed = set()
                source_context._source_route_sequences = {}
            if candidate_mode not in ('valid', 'peer'):
                try:
                    with self.assertRaises((PermissionError, BrokenPipeError,
                            ConnectionResetError, TimeoutError)):
                        ker_run.rx_owner_source_route_prepare(control,
                            candidate_channel, app, app_pidfd, supervisor_pidfd,
                            current, candidate, source_master, NONCE, 77, deadline,
                            operation_id=1234)
                except Exception:
                    raise
                marker = os.read(marker_read, 1)
                if marker != b'N':
                    os.write(release_write, b'R')
                    stdout, stderr = app.communicate(timeout=2)
                    raise AssertionError(f'candidate rejection did not preserve old route; '
                        f'marker={marker!r}, return={app.returncode}, stdout={stdout!r}, '
                        f'stderr={stderr!r}')
                os.write(release_write, b'R')
                stdout, stderr = app.communicate(timeout=2)
                self.assertEqual(app.returncode, 0, (stdout, stderr))
                return
            route_endpoint = control
            if late_route_arrival:
                self.assertEqual(os.read(late_ready_read, 1), b'E',
                    'receiver did not reach the common handler after an empty source-route read')

                class ReleaseAfterSend:
                    def sendmsg(self, *args):
                        sent = control.sendmsg(*args)
                        if sent > 0:
                            os.write(late_release_write, b'R')
                        return sent

                    def __getattr__(self, name):
                        return getattr(control, name)

                route_endpoint = ReleaseAfterSend()
            if typed_bad_context_actor or typed_context_tamper is not None:
                if typed_context_tamper == 'wrong-channel-owner':
                    foreign_channel, foreign_pid, foreign_release = foreign_created_socket()
                    sockets.append(foreign_channel)
                    foreign_children.append((foreign_pid, foreign_release))
                    candidate_channel = foreign_channel
                elif typed_context_tamper == 'candidate-endpoint-alias':
                    alias = socket.socket(fileno=os.dup(route_endpoint.fileno()))
                    alias.setblocking(False)
                    sockets.append(alias)
                    candidate_channel = alias
                else:
                    candidate_channel.setsockopt(socket.SOL_SOCKET,
                        socket.SO_PASSCRED, 0)
                if typed_context_tamper == 'blocking-candidate-channel':
                    candidate_channel.setblocking(True)
                original_mode = (candidate_channel.gettimeout(),
                    fcntl.fcntl(candidate_channel.fileno(), fcntl.F_GETFL),
                    fcntl.fcntl(candidate_channel.fileno(), fcntl.F_GETFD),
                    candidate_channel.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED))
                kwargs = {'source_context': source_context,
                    'source_cycle_proof': candidate_cycle_proof}
                if typed_context_tamper == 'missing-context':
                    kwargs['source_context'] = None
                elif typed_context_tamper == 'missing-proof':
                    kwargs['source_cycle_proof'] = None
                elif typed_context_tamper == 'pre-park':
                    kwargs['source_park_evidence'] = object()
                elif typed_context_tamper == 'park-only':
                    kwargs = {'source_park_evidence': object()}
                if typed_context_tamper == 'epoch-two':
                    kwargs['source_epoch'] = 2
                elif typed_context_tamper == 'retry-lineage':
                    kwargs['source_epoch'] = 2
                    kwargs['previous_aborted'] = SimpleNamespace()
                elif typed_context_tamper == 'successor':
                    kwargs['previous_committed'] = SimpleNamespace()
                elif typed_context_tamper == 'noncanonical-context':
                    kwargs['source_context'] = SimpleNamespace()
                elif typed_context_tamper == 'blocking-endpoint':
                    control.setblocking(True)
                original_candidate_role = candidate.owner_role
                if typed_context_tamper == 'candidate-role':
                    candidate.owner_role = 0
                original_candidate_pidfd = candidate.owner_pidfd
                if typed_context_tamper == 'candidate-pidfd':
                    candidate.owner_pidfd = current.owner_pidfd
                if typed_context_tamper == 'context-deadline-short':
                    source_context.deadline_ns = deadline - 1
                elif typed_context_tamper == 'expired-context-deadline':
                    source_context.deadline_ns = time.monotonic_ns() - 1
                if typed_context_tamper == 'overwide-route-deadline':
                    kwargs['authority_deadline_ns'] = deadline + 1
                authority_deadline = kwargs.pop('authority_deadline_ns', deadline)
                with self.assertRaises((PermissionError, ValueError, ProcessLookupError)):
                    ker_run.rx_owner_source_route_prepare(route_endpoint,
                        candidate_channel, app, app_pidfd, supervisor_pidfd,
                        current, candidate, source_master, NONCE, 77, authority_deadline,
                        operation_id=1234, **kwargs)
                self.assertFalse(__import__('select').select(
                    [marker_read], [], [], 0.02)[0],
                    'invalid typed PREPARE unexpectedly sent to C31')
                self.assertEqual((candidate_channel.gettimeout(),
                    fcntl.fcntl(candidate_channel.fileno(), fcntl.F_GETFL),
                    fcntl.fcntl(candidate_channel.fileno(), fcntl.F_GETFD),
                    candidate_channel.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED)),
                    original_mode, 'invalid typed PREPARE mutated candidate relay options')
                if typed_context_tamper == 'blocking-endpoint':
                    self.assertEqual(control.gettimeout(), None,
                        'invalid endpoint mode was mutated during preflight')
                    control.setblocking(False)
                if typed_context_tamper == 'blocking-candidate-channel':
                    self.assertEqual(candidate_channel.gettimeout(), None,
                        'invalid candidate relay mode was mutated during preflight')
                    candidate_channel.setblocking(False)
                candidate.owner_pidfd = original_candidate_pidfd
                candidate.owner_role = original_candidate_role
                app.kill()
                app.communicate(timeout=2)
                return
            try:
                if typed_post_ack_clear_cloexec:
                    factory = source_bootstrap._make_source_route_preparation
                    before_fd_flags = fcntl.fcntl(candidate_channel.fileno(), fcntl.F_GETFD)
                    def clear_sender_cloexec(*args, **kwargs):
                        current_fd_flags = fcntl.fcntl(candidate_channel.fileno(),
                            fcntl.F_GETFD)
                        fcntl.fcntl(candidate_channel.fileno(), fcntl.F_SETFD,
                            current_fd_flags & ~fcntl.FD_CLOEXEC)
                        return factory(*args, **kwargs)
                    try:
                        with mock.patch.object(source_bootstrap,
                                '_make_source_route_preparation', clear_sender_cloexec):
                            with self.assertRaises(PermissionError):
                                ker_run.rx_owner_source_route_prepare(route_endpoint,
                                    candidate_channel, app, app_pidfd, supervisor_pidfd,
                                    current, candidate, source_master, NONCE, 77, deadline,
                                    operation_id=1234, source_context=source_context,
                                    source_cycle_proof=candidate_cycle_proof)
                        self.assertEqual(os.read(marker_read, 1), b'P',
                            'C31 PREPARED ACK was not received before CLOEXEC rejection')
                        self.assertFalse(source_context._source_route_preparations)
                        self.assertFalse(any(entry[0].app_pid == app.pid
                            for entry in ker_run._SOURCE_ROUTE_PREPARATIONS.values()))
                    finally:
                        fcntl.fcntl(candidate_channel.fileno(), fcntl.F_SETFD,
                            before_fd_flags)
                    app.kill()
                    app.communicate(timeout=2)
                    return
                if production_private_controller:
                    controller_module = ker_run._load_source_shell_controller()
                    profile_module = controller_module._c34_profile_module()
                    origin_module = ker_run._load_source_origin_module()
                    artifacts_module = profile_module._provider()
                    provider_module = controller_module._c22_provider_module()
                    capture = object.__new__(artifacts_module.PrivateC34ArtifactCapture)
                    helper_capture = object.__new__(artifacts_module.PrivateC34HelperCapture)
                    helper_capture.source_command_abi = 1
                    capture.helper_capture = helper_capture
                    capture.source_fault = (None if private_master_abort in (None, 'production') else
                        origin_module.SOURCE_RETRY_FAULT)
                    helper_capture.source_fault = capture.source_fault
                    origin = object.__new__(origin_module.PrivateC34OriginalShellLaunch)
                    origin.context = source_context
                    origin.c34_artifact_capture = capture
                    source_context.owner_live = origin.live_supervisor
                    controller = object.__new__(controller_module.SourceShellController)
                    if native_activation:
                        listener_fixture = activation_listener
                        grant_channel, _ = listener_fixture.accept()
                        listener_fixture.setblocking(False)
                        grant_channel.setblocking(False)
                        sockets.append(grant_channel)
                        source_context.record_struct = source_bootstrap.SHELL_RECORD
                        source_context.symbols = {'ngx_cycle': 0x4000}
                        source_context.expected_config_sha256 = candidate_cycle_proof.config_sha256
                        source_context.expected_ini_sha256 = candidate_cycle_proof.ini_sha256
                        held_pidfd, record = source_context.workers[(1, 1)]
                        record = list(record) + [0] + list(candidate_cycle_proof)
                        record[:5] = [source_bootstrap.MAGIC, source_bootstrap.SHELL_VERSION,
                            2, source_bootstrap.SHELL_RECORD.size, 1]
                        record[7] = source_master.pid
                        record[12:14] = [source_master.start_ticks, 0x9000]
                        record[17:24] = [supervisor, app.pid, supervisor, 4,
                            supervisor_start, source_context.runtime.start_ticks, supervisor_start]
                        source_context.workers[(1, 1)] = (held_pidfd, tuple(record))
                        candidate_process.stdin.write(source_bootstrap.SHELL_RECORD.pack(*record))
                        candidate_process.stdin.flush()
                    else:
                        grant_channel, grant_peer = socket.socketpair(socket.AF_UNIX,
                            socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
                        listener_fixture, listener_peer = socket.socketpair(socket.AF_UNIX,
                            socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
                        sockets.extend((grant_channel, grant_peer, listener_fixture, listener_peer))
                    controller.profile = object.__new__(
                        profile_module.PrivateNewC34InteropProfile)
                    controller.profile.origin_module = origin_module
                    controller.profile.artifact_capture = capture
                    controller.profile.helper_capture = capture.helper_capture
                    controller.bootstrap_context = source_context
                    controller.launch = origin
                    provider = object.__new__(provider_module.SourceShellC34InteropProvider)
                    provider.context = source_context
                    provider._private_c34_helper_capture = helper_capture
                    provider._source_command_abi = 1
                    provider._closed = False
                    provider_checks = []
                    provider._check_actor = lambda deadline_ns: provider_checks.append(deadline_ns)
                    controller.c22_provider = provider
                    controller._first_candidate_worker_grant_consumed = True
                    controller._first_candidate_worker_pending = True
                    controller._first_candidate_observed_ready = (
                        candidate.owner_pid, candidate.owner_tid, 0, 1, 0, 0,
                        candidate.owner_start, candidate.owner_slot_device,
                        candidate.owner_slot_inode, candidate.owner_cookie)
                    controller._first_candidate_observed_pidfd = candidate.owner_pidfd
                    controller._first_candidate_relay_anchor = candidate_channel
                    controller._first_candidate_source_prepared = None
                    controller._first_candidate_activation_delivered = False
                    controller._check_first_candidate_phase = lambda _transport: True
                    controller._source_route_preparer = ker_run.rx_owner_source_route_prepare
                    source_context.control_only = True
                    retained_grant_channel = grant_channel.dup()
                    sockets.append(retained_grant_channel)
                    source_context.worker_channels = {(0, 0): old_channel,
                        (1, 1): retained_grant_channel}
                    source_context._activated_workers = set()
                    source_context._activation_attempts = set()
                    source_context._completed_master_barriers = set()
                    source_context._source_shell_committed_plans = {}
                    activation_dispatches = []
                    real_activation_body = source_context._activate_worker_body
                    def activation_body(channel, watch):
                        activation_dispatches.append((channel, watch))
                        if native_activation:
                            def source_memory(pid, address, size):
                                if address == 0x9000:
                                    self.assertEqual((pid, size), (source_master.pid, 32))
                                    return struct.pack('=8I', 0, 0, 0, 1, 0, 1, 1, 0)
                                self.assertEqual((address, size), (0x4000, 8))
                                self.assertIn(pid, (source_master.pid, candidate.owner_pid))
                                return struct.pack('=Q', candidate_cycle_proof.opaque_cycle_token)
                            with mock.patch.object(source_bootstrap, 'memory', side_effect=source_memory):
                                real_activation_body(channel, watch)
                        elif private_master_park:
                            source_context._activation_attempts.add((1, 1))
                            source_context._activated_workers.add((1, 1))
                    source_context._activate_worker_body = activation_body
                    real_activation_gate = source_bootstrap.SourceBootstrapSupervisor.activate_prepared_first_candidate
                    def activation_gate_with_provider_negatives(prepared, channel, watch,
                            source_controller, grant):
                        source_controller.c22_provider = SimpleNamespace()
                        with self.assertRaises(PermissionError):
                            real_activation_gate(source_context, prepared, channel,
                                watch, source_controller, grant)
                        self.assertEqual(activation_dispatches, [])
                        source_controller.c22_provider = provider
                        provider._closed = True
                        with self.assertRaises(PermissionError):
                            real_activation_gate(source_context, prepared, channel,
                                watch, source_controller, grant)
                        self.assertEqual(activation_dispatches, [])
                        provider._closed = False
                        source_controller._first_candidate_relay_anchor = candidate_worker_channel
                        with self.assertRaises(PermissionError):
                            real_activation_gate(source_context, prepared, channel,
                                watch, source_controller, grant)
                        self.assertEqual(activation_dispatches, [])
                        source_controller._first_candidate_relay_anchor = candidate_channel
                        return real_activation_gate(source_context, prepared, channel,
                            watch, source_controller, grant)
                    source_context.activate_prepared_first_candidate = \
                        activation_gate_with_provider_negatives
                    controller.listener = listener_fixture
                    controller._first_candidate_relay_anchor = candidate_channel
                    transport = SimpleNamespace(auth=route_endpoint, app=app,
                        app_pidfd=app_pidfd, supervisor_pidfd=supervisor_pidfd,
                        worker_view=current, nonce=NONCE, epoch=77)
                    controller.initial_worker_binding = transport
                    listener_identity = controller_module.SourceShellController._first_candidate_endpoint_identity(listener_fixture)
                    listener_cookie = controller_module.SourceShellController._first_candidate_socket_cookie(listener_fixture)
                    accepted_identity = controller_module.SourceShellController._first_candidate_endpoint_identity(grant_channel)
                    accepted_cookie = controller_module.SourceShellController._first_candidate_socket_cookie(grant_channel)
                    relay_identity = controller._first_candidate_endpoint_identity(candidate_worker_channel)
                    relay_cookie = controller._first_candidate_socket_cookie(candidate_worker_channel)
                    accepted = controller_module._AcceptedCandidateWorkerRequest(
                        controller_module._ACCEPTED_CANDIDATE_REQUEST_TOKEN,
                        controller, listener_fixture, listener_identity,
                        listener_cookie, grant_channel, accepted_identity,
                        accepted_cookie, b'candidate-request',
                        (candidate.owner_pid, os.getuid(), os.getgid()), deadline, (1, 1))
                    controller._accepted_candidate_worker_request = accepted
                    controller._first_candidate_worker_grant = \
                        controller_module._FirstCandidateWorkerGrant(
                            controller_module._FIRST_CANDIDATE_GRANT_TOKEN,
                            controller, source_context, provider, transport,
                            grant_channel, accepted_identity, accepted_cookie, b'candidate-request',
                            (candidate.owner_pid, os.getuid(), os.getgid()),
                            candidate_worker_channel, relay_identity, relay_cookie,
                            deadline, (1, 1),
                            candidate_cycle_proof,
                            (source_master.pid, source_master.start_ticks,
                                source_master.pidfd),
                            source_context.initial_cycle_proof, accepted)
                    controller._first_candidate_worker_grant_consumed = True
                    watch = {'source_epoch': 1, 'generation': 1, 'role': 1,
                        'pid': candidate.owner_pid, 'tid': candidate.owner_tid,
                        'start': candidate.owner_start,
                        'slot_device': candidate.owner_slot_device,
                        'slot_inode': candidate.owner_slot_inode,
                        'cookie': candidate.owner_cookie}
                    controller._prepare_and_activate_first_candidate(transport,
                        controller._first_candidate_worker_grant, watch)
                    prepared = controller._first_candidate_source_prepared
                    self.assertTrue(controller._first_candidate_activation_delivered)
                    self.assertEqual(source_context._source_prepared_activation_attempts,
                        {id(prepared)})
                    self.assertEqual(len(activation_dispatches), 1)
                    self.assertIs(activation_dispatches[0][0], retained_grant_channel)
                    self.assertTrue(source_context.control_only)
                    self.assertEqual(provider_checks, [source_context.deadline_ns] * 2)
                    if native_activation:
                        self.assertEqual(source_context._activation_attempts, {(1, 1)})
                        self.assertEqual(source_context._activated_workers, {(1, 1)})
                        if not private_master_commit:
                            stdout, stderr = candidate_process.communicate(timeout=3)
                            self.assertEqual(candidate_process.returncode, 0, (stdout, stderr))
                            self.assertEqual(stdout, b'RECEIVER_READY\nACTIVATE status=1 accepted=1\n')
                else:
                    prepared = ker_run.rx_owner_source_route_prepare(route_endpoint,
                        candidate_channel, app, app_pidfd, supervisor_pidfd,
                        current, candidate, source_master, NONCE, 77, deadline,
                        operation_id=1234,
                        **({'source_context': source_context,
                            'source_cycle_proof': candidate_cycle_proof}
                            if typed_handoff else {}))
            except BaseException:
                if typed_handoff and app.poll() is not None:
                    stdout, stderr = app.communicate(timeout=2)
                    print('C31 model PREPARE app exited:', app.returncode, stdout, stderr)
                raise
            self.assertEqual(os.read(marker_read, 1), b'P')
            if typed_handoff:
                self.assertIs(type(prepared._source_route_preparation),
                    source_bootstrap._SourceRoutePreparation)
                self.assertIsNone(prepared._source_route_preparation.park)
                self.assertEqual(prepared._source_route_preparation.raw_prepared_ack,
                    prepared._source_route_preparation.expected_prepared_record)
                self.assertEqual(prepared._source_route_preparation.prepared_credentials,
                    (app.pid, os.getuid(), os.getgid()))
                if production_private_controller:
                    self.assertIsNone(prepared._source_route_preparation.park)
                    self.assertEqual(prepared.source_epoch, 1)
                    if private_master_park:
                        # The test harness imported the bootstrap under a
                        # dedicated name; bind that exact module to the fake
                        # Origin so the production identity check remains real.
                        controller.profile.origin_module.bootstrap = source_bootstrap
                        start_ticks = ker_run.process_start_ticks(os.getpid())
                        io_pidfd = os.pidfd_open(os.getpid())
                        provider_pidfd = os.pidfd_open(os.getpid())
                        handles.extend((io_pidfd, provider_pidfd))
                        source_context.record_struct = source_bootstrap.SHELL_RECORD
                        source_context.io = SimpleNamespace(pid=os.getpid(),
                            start_ticks=start_ticks, pidfd=io_pidfd)
                        source_context.supervisor_start = start_ticks
                        source_context.allow_successor = False
                        source_context.allow_abort_retry = capture.source_fault is not None
                        source_context.slim_pid = source_context.io.pid
                        source_context.slim_start_ticks = source_context.io.start_ticks
                        source_context.slim_pidfd = io_pidfd
                        source_context.worker_process_slots = {(1, 1): 4}
                        if not native_activation:
                            held_pidfd, retained = source_context.workers[(1, 1)]
                            retained = list(retained) + [0] + list(candidate_cycle_proof)
                            retained[:5] = [source_bootstrap.MAGIC,
                                source_bootstrap.SHELL_VERSION, 2,
                                source_bootstrap.SHELL_RECORD.size, 1]
                            retained[7] = source_context.master.pid
                            retained[12:14] = [source_context.master.start_ticks, 0x9000]
                            retained[17:21] = [os.getpid(), source_context.runtime.pid,
                                source_context.io.pid, 4]
                            retained[21:24] = [start_ticks, source_context.runtime.start_ticks,
                                source_context.io.start_ticks]
                            source_context.workers[(1, 1)] = (held_pidfd, tuple(retained))
                        source_context.slim_reply = [0] * 35
                        shm_address = 0x9000
                        source_context.slim_reply[13] = shm_address
                        source_context._source_round = lambda _epoch: (0, 1)
                        source_context._record_cycle_proof = lambda _record: candidate_cycle_proof
                        source_context._cycle_token_live = lambda *_args: None
                        source_context._scalar = lambda _pid, _name, _fmt: shm_address
                        source_context._master_barriers = set()
                        source_context._completed_master_barriers = set()
                        source_context._master_control_deadlines = {}
                        source_context._private_source_master_attempts = set()
                        source_context._source_shell_committed_plans = {}
                        provider._source_command_abi = provider_module._C28_SOURCE_COMMAND_ABI
                        provider._source_park_deadline_ns = None
                        provider._source_park_result = None
                        provider._source_park_evidence = None
                        provider._source_command_unresolved = False
                        provider._source_route_receipt_consumed = False
                        provider._source_committed = False
                        provider._source_abort_result = None
                        provider._source_retry_cookie = None
                        provider._source_retry_allowed = capture.source_fault is not None
                        provider._source_retry_slot_attempted = False
                        provider._source_command_sequence = 0
                        provider._source_command_outstanding = None
                        provider.process = SimpleNamespace(pid=os.getpid())
                        provider.start_ticks = start_ticks
                        provider.pidfd = provider_pidfd
                        provider._helper_sha256 = b'h' * 32
                        provider._channel, provider_peer = socket.socketpair(
                            socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
                        sockets.extend((provider._channel, provider_peer))
                        provider._channel.setsockopt(socket.SOL_SOCKET,
                            socket.SO_PASSCRED, 1)
                        provider._last_received_bundle = {'record': b'r' * 108,
                            'credentials': (os.getpid(), os.getuid(), os.getgid()),
                            'fds': ((1, 2, 3), (4, 5, 6), (7, 8, 9))}
                        events = []
                        def modeled_c28(operation, operation_deadline):
                            events.append(('c28-command', operation, operation_deadline))
                            retry_plan = getattr(provider, '_source_retry_slot_delivered', False)
                            if private_master_fault == 'park-unknown':
                                provider._source_command_unresolved = True
                                raise TimeoutError('injected unknown C28 PARK result')
                            if operation == provider_module._C28_PARK:
                                return {'phase': provider_module._C28_PHASE_PREPARED,
                                    'lease': 0x8899 if retry_plan else 0x7788, 'listener_cookie': 0,
                                    'received': 0, 'accepted': 0}
                            if operation == provider_module._C28_COMMIT:
                                if private_master_abort == 'retry-c28-unknown':
                                    provider._source_command_unresolved = True
                                    raise TimeoutError('unknown retry C28 COMMIT')
                                return {'phase': provider_module._C28_PHASE_COMMITTED,
                                    'lease': 0x8899 if retry_plan else 0x7788,
                                    'listener_cookie': 0x9922 if retry_plan else 0x9911,
                                    'received': 0, 'accepted': 0}
                            if operation == provider_module._C28_ABORT:
                                return {'phase': provider_module._C28_PHASE_ABORTED,
                                    'lease': 0x7788, 'listener_cookie': 0,
                                    'received': 2, 'accepted': 2}
                            if operation == provider_module._C28_RETRY_ADOPT:
                                if private_master_abort == 'unknown-adoption':
                                    provider._source_command_unresolved = True
                                    raise TimeoutError('unknown C28 retry adoption outcome')
                                return {'phase': provider_module._C28_PHASE_ABORTED,
                                    'lease': 0x7788, 'listener_cookie': 0x9911,
                                    'received': 0, 'accepted': 0}
                            if operation == provider_module._C28_RETRY_SLOT:
                                return {'phase': 0, 'lease': 0, 'listener_cookie': 0x9911,
                                    'received': 0, 'accepted': 0,
                                    'fds': tuple(os.dup(fd) for fd in retry_fds)}
                            raise AssertionError(f'unexpected modeled C28 operation {operation}')
                        provider._source_c28_command = modeled_c28
                        self.assertTrue(source_bootstrap._source_provider_matches_context(
                            source_context, provider, controller),
                            'modeled private provider did not preserve the exact Origin/provider pair')
                        self.assertEqual(source_context._activated_workers, {(1, 1)})
                        controller._first_candidate_revoke_attempted = False
                        with tempfile.TemporaryDirectory(prefix='ker-private-master-') as directory:
                            listener = socket.socket(socket.AF_UNIX,
                                socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
                            sockets.append(listener)
                            listener.bind(str(Path(directory) / 'master.sock'))
                            listener.listen(1)
                            listener.setblocking(False)
                            controller.listener = listener
                            master_client = socket.socket(socket.AF_UNIX,
                                socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
                            sockets.append(master_client)
                            master_client.connect(str(Path(directory) / 'master.sock'))
                            master_client.settimeout(0.5)
                            operation_deadline = time.monotonic_ns() + (
                                200_000_000 if private_master_fault == 'deadline' else
                                99_000_000)
                            record = [0] * 35
                            record[:5] = [source_bootstrap.MAGIC,
                                source_bootstrap.SHELL_VERSION, 5,
                                source_bootstrap.SHELL_RECORD.size, 2]
                            record[3:11] = [source_bootstrap.SHELL_RECORD.size, 2,
                                source_context.master.pid, source_context.master.pid,
                                source_context.master.pid, 1, 1, 0]
                            record[11:13] = [source_context.master.start_ticks,
                                source_context.master.start_ticks]
                            record[13:17] = [shm_address, source_context.epoch,
                                source_context.deadline_ns, source_context.nonce]
                            record[28] = operation_deadline
                            record[29:35] = list(candidate_cycle_proof)
                            master_client.send(source_bootstrap.SHELL_RECORD.pack(*record))
                            values = (0x46524c4d, 1, 128, 1, 0, 1, 1, 0)
                            active_operation = {'value': 5}
                            def modeled_memory(_pid, _address, length):
                                markers = {5: (0, 0, 2), 6: (1, 0, 2),
                                    9: (0, 1, 2)}[active_operation['value']]
                                return (struct.pack('=8I', *values) if length == 32 else
                                    struct.pack('=3I', *markers))
                            real_private_barrier = source_context.private_source_master_barrier
                            def observe_private_barrier(*args):
                                events.append(('private-barrier-enter', time.monotonic_ns()))
                                with mock.patch.object(source_bootstrap, 'memory',
                                        side_effect=modeled_memory):
                                    result = real_private_barrier(*args)
                                events.append(('private-barrier-return', time.monotonic_ns()))
                                return result
                            source_context.private_source_master_barrier = observe_private_barrier
                            revoke_calls = []
                            transport.request_revoke = lambda: revoke_calls.append('revoke')
                            controller._initial_transport = transport
                            controller._first_candidate_revoke_attempted = False
                            if private_master_fault == 'setblocking':
                                with mock.patch.object(socket.socket, 'setblocking',
                                        side_effect=OSError(errno.EIO, 'injected setblocking failure')):
                                    with self.assertRaisesRegex(OSError,
                                            'injected setblocking failure'):
                                        controller.pump_bootstrap_listener()
                            elif private_master_fault == 'precheck':
                                controller._first_candidate_activation_delivered = False
                                with self.assertRaisesRegex(OSError,
                                        'not connected to the exact activated candidate'):
                                    controller.pump_bootstrap_listener()
                            elif private_master_fault == 'wrong-provider':
                                controller.c22_provider = SimpleNamespace()
                                with self.assertRaisesRegex(PermissionError,
                                        'exact activated C34 controller/provider'):
                                    controller.pump_bootstrap_listener()
                            elif private_master_fault == 'deadline':
                                with self.assertRaisesRegex(PermissionError,
                                        'correlation/credentials mismatch'):
                                    controller.pump_bootstrap_listener()
                            elif private_master_fault == 'park-unknown':
                                with self.assertRaisesRegex(TimeoutError,
                                        'injected unknown C28 PARK result'):
                                    controller.pump_bootstrap_listener()
                            elif private_master_fault == 'ack-error':
                                with mock.patch.object(socket.socket, 'sendmsg',
                                        side_effect=OSError(errno.EIO, 'injected master ACK failure')):
                                    with self.assertRaisesRegex(OSError,
                                            'injected master ACK failure'):
                                        controller.pump_bootstrap_listener()
                                second_client = socket.socket(socket.AF_UNIX,
                                    socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
                                sockets.append(second_client)
                                second_client.connect(str(Path(directory) / 'master.sock'))
                                second_client.send(source_bootstrap.SHELL_RECORD.pack(*record))
                                with self.assertRaisesRegex(PermissionError,
                                        'already consumed'):
                                    controller.pump_bootstrap_listener()
                                self.assertEqual(events.count(('c28-command',
                                    provider_module._C28_PARK,
                                    operation_deadline)), 1,
                                    f'unknown master ACK caused a second C28 PARK: {events!r}')
                                self.assertEqual(revoke_calls, ['revoke'])
                            elif private_master_fault == 'late-ack':
                                real_sendmsg = socket.socket.sendmsg
                                def late_master_send(channel, *args, **kwargs):
                                    sent = real_sendmsg(channel, *args, **kwargs)
                                    while time.monotonic_ns() < operation_deadline:
                                        time.sleep(.001)
                                    return sent
                                with mock.patch.object(socket.socket, 'sendmsg', new=late_master_send):
                                    with self.assertRaisesRegex(TimeoutError,
                                            'master native barrier receipt completed after its deadline'):
                                        controller.pump_bootstrap_listener()
                            else:
                                self.assertTrue(controller.pump_bootstrap_listener())
                            if private_master_fault is not None:
                                self.assertTrue(controller.unresolved)
                                self.assertEqual(revoke_calls, ['revoke'])
                                self.assertEqual(source_context._private_source_master_request_attempts,
                                    {(1, 5)})
                                self.assertEqual(len(controller._private_source_master_channels),
                                    2 if private_master_fault == 'ack-error' else 1)
                                self.assertTrue(all(channel.fileno() >= 0 for channel in
                                    controller._private_source_master_channels))
                                self.assertEqual(activation_dispatches,
                                    [(retained_grant_channel, watch)])
                                if private_master_fault == 'late-ack':
                                    # The kernel may have queued an ACK before the
                                    # sender resumed, so only claim local quarantine.
                                    self.assertIn((1, 5), source_context._master_barriers)
                                    self.assertNotIn((1, 5), source_context._completed_master_barriers)
                                    self.assertEqual(controller._private_source_master_timings[-1][-1],
                                        'unresolved')
                                else:
                                    self.assertFalse(__import__('select').select(
                                        [master_client], [], [], 0)[0],
                                        'failed consumed request emitted an ACK')
                                self.assertLessEqual(events.count(('c28-park',
                                    provider_module._C28_PARK,
                                    operation_deadline)), 1)
                                sockets.extend(controller._private_source_master_channels)
                                self.assertEqual(len(controller._private_source_master_channels),
                                    2 if private_master_fault == 'ack-error' else 1)
                                app.kill()
                                app.communicate(timeout=2)
                                return
                            reply, ancillary, flags, _ = master_client.recvmsg(
                                source_bootstrap.SHELL_RECORD.size + 1,
                                socket.CMSG_SPACE(8 * 4))
                            received = []
                            for level, kind, value in ancillary:
                                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                                    values_fd = array.array('i')
                                    values_fd.frombytes(value[:len(value) - len(value) % 4])
                                    received.extend(values_fd)
                            try:
                                self.assertEqual(len(received), 2)
                                self.assertEqual([source_bootstrap.identity._pidfd_pid(fd)
                                    for fd in received], [source_context.runtime.pid, source_context.io.pid])
                            finally:
                                for descriptor in received:
                                    os.close(descriptor)
                            self.assertFalse(flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC))
                            reply_fields = source_bootstrap.SHELL_RECORD.unpack(reply)
                            self.assertEqual(reply_fields[2], 7)
                            self.assertEqual(reply_fields[28:], tuple(record[28:]))
                            self.assertEqual(events[0][0], 'private-barrier-enter')
                            self.assertEqual(events[1][:2], ('c28-command', provider_module._C28_PARK))
                            self.assertEqual(events[-1][0], 'private-barrier-return')
                            self.assertEqual(events[1][2], operation_deadline)
                            self.assertEqual(source_context._completed_master_barriers,
                                {(1, 5)})
                            self.assertIn(id(prepared), source_context._source_route_park_joins)
                            self.assertTrue(provider._source_park_evidence)
                            timing = controller._private_source_master_timings[-1]
                            self.assertLess(timing[3] - timing[2], 100_000_000)
                            self.assertTrue(controller._first_candidate_worker_pending)
                            if private_master_abort is not None:
                                active_operation['value'] = 9
                                abort_record = list(record)
                                abort_record[2] = 9
                                abort_client = socket.socket(socket.AF_UNIX,
                                    socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
                                sockets.append(abort_client)
                                abort_client.connect(str(Path(directory) / 'master.sock'))
                                abort_client.settimeout(0.5)
                                abort_client.send(source_bootstrap.SHELL_RECORD.pack(*abort_record))
                                real_route_command = ker_run.send_source_route_command
                                def observe_route_command(*args, **kwargs):
                                    events.append(('c31-abort', args[2],
                                        kwargs['operation_deadline_ns']))
                                    if private_master_abort == 'unknown-c31':
                                        raise TimeoutError('unknown C31 ABORT outcome')
                                    return real_route_command(*args, **kwargs)
                                if private_master_abort not in ('success', 'bad-ready',
                                        'retry-renewed', 'retry-c28-unknown'):
                                    expected_error, detail = {
                                        'production': (PermissionError, 'parked master terminal operation'),
                                        'wrong-helper': (PermissionError, 'captured fault profile'),
                                        'unknown-adoption': (TimeoutError, 'unknown C28 retry adoption'),
                                        'unknown-c31': (TimeoutError, 'unknown C31 ABORT'),
                                    }[private_master_abort]
                                    if private_master_abort == 'wrong-helper':
                                        helper_capture.source_fault = None
                                    with mock.patch.object(ker_run, 'send_source_route_command',
                                            side_effect=observe_route_command):
                                        with self.assertRaisesRegex(expected_error, detail):
                                            controller._await_private_master_terminal(source_context)
                                    self.assertFalse(hasattr(prepared, 'last_command_observation'))
                                    self.assertIsNone(getattr(prepared, '_source_route_commit_receipt', None))
                                    self.assertFalse(hasattr(source_context, '_native_retry_cookie'))
                                    self.assertEqual(source_context._completed_master_barriers, {(1, 5)})
                                    self.assertTrue(controller.unresolved)
                                    self.assertEqual(revoke_calls, ['revoke'])
                                    self.assertEqual(source_context._private_source_master_attempts,
                                        {(1, 5), (1, 9)} if private_master_abort.startswith('unknown-') else
                                        {(1, 5)})
                                    self.assertEqual([event[1] for event in events
                                        if event[0] == 'c28-command'],
                                        [provider_module._C28_PARK, provider_module._C28_ABORT,
                                            provider_module._C28_RETRY_ADOPT]
                                        if private_master_abort.startswith('unknown-') else
                                        [provider_module._C28_PARK])
                                    # Envelope rejection may close the socket. A consumed
                                    # unknown outcome keeps the endpoint but emits no ACK.
                                    abort_client.settimeout(0.01)
                                    try:
                                        self.assertEqual(abort_client.recv(
                                            source_bootstrap.SHELL_RECORD.size), b'')
                                    except TimeoutError:
                                        pass
                                    sockets.extend(getattr(controller,
                                        '_private_source_master_channels', []))
                                    app.kill()
                                    app.communicate(timeout=2)
                                    return
                                with mock.patch.object(ker_run, 'send_source_route_command',
                                        side_effect=observe_route_command):
                                    controller._await_private_master_terminal(source_context)
                                reply, ancillary, flags, _ = abort_client.recvmsg(
                                    source_bootstrap.SHELL_RECORD.size + 1, socket.CMSG_SPACE(8))
                                abort_fds = array.array('i')
                                for level, kind, value in ancillary:
                                    if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                                        abort_fds.frombytes(value)
                                try:
                                    self.assertFalse(flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC))
                                    self.assertEqual([source_bootstrap.identity._pidfd_pid(fd)
                                        for fd in abort_fds],
                                        [source_context.runtime.pid, source_context.io.pid])
                                finally:
                                    for fd in abort_fds:
                                        os.close(fd)
                                reply_fields = source_bootstrap.SHELL_RECORD.unpack(reply)
                                self.assertEqual(reply_fields[2], 11)
                                self.assertEqual(reply_fields[28:], tuple(abort_record[28:]))
                                self.assertEqual(events[-4:-1], [
                                    ('c28-command', provider_module._C28_ABORT, operation_deadline),
                                    ('c28-command', provider_module._C28_RETRY_ADOPT, operation_deadline),
                                    ('c31-abort', ker_run._RX_OWNER_SOURCE_ROUTE_ABORT,
                                        operation_deadline)])
                                self.assertTrue(controller._private_first_abort_acknowledged(source_context))
                                self.assertEqual(source_context._native_retry_cookie, 0x9911)
                                self.assertFalse(source_context._source_shell_committed_plans)
                                self.assertFalse(revoke_calls)
                                current_control, current_control_peer = pair()
                                sockets.extend((current_control, current_control_peer))
                                source_context.worker_channels[(0, 0)] = current_control
                                controller._check_authenticated_initial_worker_core = mock.Mock()
                                controller.broker_readiness = SimpleNamespace(ready=True, stopped=False)
                                transport.context = source_context
                                transport.broker = provider.broker_readiness = controller.broker_readiness
                                provider._used_slots = {0, 1}
                                watch_read, provider.watch_fd = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
                                slot_read, retry_fifo = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
                                retry_watch_read, retry_watch_fd = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
                                retry_fds = retry_fifo, retry_watch_fd
                                handles.extend((watch_read, provider.watch_fd, slot_read,
                                    retry_fifo, retry_watch_read, retry_watch_fd))
                                provider.slot_identities = tuple(tuple(source_context.workers[key][1][24:26])
                                    for key in ((0, 0), (1, 1)))
                                with mock.patch.object(source_bootstrap, 'memory',
                                        side_effect=modeled_memory):
                                    self.assertIsNone(controller.poll_source_preexit())
                                    self.assertFalse(provider._source_retry_slot_attempted)
                                    candidate_process.kill()
                                    candidate_process.wait(timeout=2)
                                    grant_peer.close()
                                    self.assertIsNone(controller.poll_source_preexit())
                                    self.assertFalse(provider._source_retry_slot_attempted)
                                idle = (0x46524c4d, 1, 2160, 1, 0, 1, 0, 0)
                                with mock.patch.object(source_bootstrap, 'memory',
                                        side_effect=lambda _pid, _addr, size: struct.pack('=8I', *idle)
                                        if size == 32 else struct.pack('=3I', 0, 0, 0)):
                                    self.assertIsNone(controller.poll_source_preexit())
                                    self.assertIsNone(controller.poll_source_preexit())
                                self.assertTrue(provider._source_retry_slot_attempted)
                                self.assertEqual([event[:2] for event in events].count(
                                    ('c28-command', provider_module._C28_RETRY_SLOT)), 1)
                                handles.extend(source_context._private_retry_fds)
                                self.assertTrue(controller._private_first_abort_acknowledged(source_context))
                                self.assertEqual(set(source_context.workers), {(0, 0), (1, 1)})
                                self.assertFalse(revoke_calls)

                                retry_proof = candidate_cycle_proof._replace(
                                    adapter_cycle_serial=3, opaque_cycle_token=30)
                                retry_request = [0] * 35
                                retry_request[:5] = [source_bootstrap.MAGIC, source_bootstrap.SHELL_VERSION,
                                    1, source_bootstrap.SHELL_RECORD.size, 1]
                                retry_request[7:11] = [source_context.master.pid, 1, 2, 0]
                                retry_request[12:17] = [source_context.master.start_ticks,
                                    shm_address, source_context.epoch, source_context.deadline_ns,
                                    source_context.nonce]
                                retry_request[29:] = list(retry_proof)
                                retry_worker = subprocess.Popen([sys.executable, '-c', RETRY_GRANT_ACTOR,
                                    str(Path(directory) / 'master.sock'), source_bootstrap.SHELL_RECORD.format,
                                    source_bootstrap.SHELL_RECORD.pack(*retry_request).hex(),
                                    private_master_abort],
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                                processes.append(retry_worker)
                                self.assertTrue(select.select([listener], [], [], 2)[0])
                                source_context._scalar = lambda _pid, name, _fmt: {
                                    'ngx_ff_reload_shm': shm_address, 'ngx_process': 3,
                                    'ngx_worker': 0, 'ngx_ff_process': 2,
                                    'ngx_ff_graceful_reload': 1, 'ngx_process_slot': 4}[name]
                                source_context.expected_config_sha256 = retry_proof.config_sha256
                                source_context.expected_ini_sha256 = retry_proof.ini_sha256
                                source_context._record_cycle_proof = source_bootstrap.SourceBootstrapSupervisor._record_cycle_proof.__get__(
                                    source_context)
                                source_context._used_cycle_proofs = {(2, 20)}
                                source_context._cycle_serial_highwater = 2
                                source_context._activate_worker_body = real_activation_body
                                source_context.worker_ready_receivers = {}
                                source_context._executable_files = {}
                                source_context.binary_hash = source_bootstrap.identity._sha256(
                                    f'/proc/{retry_worker.pid}/exe')
                                source_context.slim_reply[20] = 1
                                prefix = struct.pack('=8I', 0x46524c4d, 1, 2160, 2, 0, 1, 1, 0)
                                def prepare_retry_with_lineage_checks(*args, **kwargs):
                                    self.assertIs(kwargs['previous_aborted'], prepared)
                                    wrong_prior = copy.copy(prepared)
                                    with self.assertRaisesRegex(PermissionError,
                                            'exact acknowledged predecessor'):
                                        ker_run.rx_owner_source_route_prepare(*args,
                                            **{**kwargs, 'previous_aborted': wrong_prior})
                                    expired = time.monotonic_ns() - 1
                                    with self.assertRaisesRegex(PermissionError, 'live setup deadline'):
                                        ker_run.rx_owner_source_route_prepare(*args,
                                            **{**kwargs, 'prepare_deadline_ns': expired})
                                    self.assertFalse(hasattr(source_context, '_source_retry_prepare_attempt'))
                                    result = ker_run.rx_owner_source_route_prepare(*args, **kwargs)
                                    with self.assertRaisesRegex(PermissionError, 'already attempted'):
                                        ker_run.rx_owner_source_route_prepare(*args, **kwargs)
                                    return result
                                controller._source_route_preparer = prepare_retry_with_lineage_checks
                                activate_retry = source_context.activate_prepared_retry_candidate
                                def activate_retry_with_replay_check(controller, staged, watch, deadline):
                                    with self.assertRaisesRegex(PermissionError, 'exact credentialed C31 PREPARED'):
                                        activate_retry(controller, copy.copy(staged), watch, deadline)
                                    activate_retry(controller, staged, watch, deadline)
                                    with self.assertRaisesRegex(PermissionError, 'exact credentialed C31 PREPARED'):
                                        activate_retry(controller, staged, watch, deadline)
                                source_context.activate_prepared_retry_candidate = activate_retry_with_replay_check
                                with mock.patch.object(source_bootstrap, 'memory', return_value=prefix), \
                                        mock.patch.object(source_bootstrap, 'shared_mapping',
                                            return_value=(shm_address, shm_address + 4096)):
                                    if private_master_abort == 'bad-ready':
                                        with self.assertRaisesRegex(PermissionError,
                                                'worker READY identity/slot/profile mismatch'):
                                            controller.pump_bootstrap_listener()
                                    else:
                                        self.assertTrue(controller.pump_bootstrap_listener())
                                handles.extend((source_context.workers[(2, 1)][0],
                                    source_context._executable_files[retry_worker.pid][0]))
                                sockets.extend((source_context.worker_channels[(2, 1)],
                                    controller._retry_candidate_relay_anchor))
                                self.assertTrue(select.select([retry_worker.stdout], [], [], 2)[0])
                                self.assertEqual(tuple(map(int, retry_worker.stdout.readline().split())),
                                    (*source_context._retry_slot, 0 if private_master_abort == 'bad-ready' else 4))
                                self.assertEqual(controller._retry_candidate_watch['pid'], retry_worker.pid)
                                if private_master_abort == 'bad-ready':
                                    sockets.append(source_context.worker_ready_receivers[(2, 1)])
                                    self.assertIsNone(getattr(controller, '_retry_candidate_ready', None))
                                    self.assertTrue(controller.unresolved)
                                else:
                                    self.assertEqual(controller._retry_candidate_ready[0], retry_worker.pid)
                                    self.assertNotIn((2, 1), source_context.worker_ready_receivers)
                                    staged = controller._retry_candidate_prepared
                                    self.assertEqual(staged.source_epoch, 2)
                                    self.assertEqual(staged.command_sequence,
                                        prepared.command_sequence + 1)
                                    self.assertIs(source_context._source_route_preparations[id(staged)],
                                        staged._source_route_preparation)
                                    self.assertIn((2, 1), source_context._activated_workers)
                                    source_context.private_source_master_barrier = real_private_barrier
                                    controller._source_route_preparer = ker_run.rx_owner_source_route_prepare
                                    controller.check_live = mock.Mock()
                                    controller.poll_source_preexit = mock.Mock()
                                    retry_deadline = time.monotonic_ns() + 99_000_000
                                    retry_park = list(record)
                                    retry_park[9] = 2
                                    retry_park[28] = retry_deadline
                                    retry_park[29:] = list(retry_proof)
                                    retry_commit = list(retry_park)
                                    retry_commit[2] = 6
                                    if private_master_abort == 'retry-renewed':
                                        retry_commit[28] += 1
                                    clients = []
                                    for message in (retry_park, retry_commit):
                                        client = socket.socket(socket.AF_UNIX,
                                            socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
                                        sockets.append(client)
                                        clients.append(client)
                                        client.settimeout(0.5)
                                        client.connect(str(Path(directory) / 'master.sock'))
                                        client.send(source_bootstrap.SHELL_RECORD.pack(*message))
                                    def retry_memory(_pid, _address, length):
                                        if length == 32:
                                            return prefix
                                        released = (2, 5) in source_context._completed_master_barriers
                                        return struct.pack('=3I', int(released), 0, 2)
                                    with mock.patch.object(source_bootstrap, 'memory', side_effect=retry_memory):
                                        if private_master_abort == 'retry-renewed':
                                            with self.assertRaisesRegex(PermissionError, 'parked master terminal'):
                                                controller.pump_source_requests()
                                        elif private_master_abort == 'retry-c28-unknown':
                                            with self.assertRaisesRegex(TimeoutError, 'unknown retry C28 COMMIT'):
                                                controller.pump_source_requests()
                                        else:
                                            self.assertTrue(controller.pump_source_requests())
                                    def verify_barrier(client, operation):
                                        reply, ancillary, flags, _ = client.recvmsg(
                                            source_bootstrap.SHELL_RECORD.size, socket.CMSG_SPACE(8))
                                        fds = array.array('i')
                                        for level, kind, value in ancillary:
                                            if (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS):
                                                fds.frombytes(value)
                                        try:
                                            self.assertEqual(len(fds), 2)
                                            self.assertFalse(flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC))
                                            reply = source_bootstrap.SHELL_RECORD.unpack(reply)
                                            self.assertEqual((reply[2], reply[9], reply[28]),
                                                (operation, 2, retry_deadline))
                                        finally:
                                            for fd in fds:
                                                os.close(fd)
                                    verify_barrier(clients[0], 7)
                                    self.assertEqual(source_context._master_control_deadlines,
                                        {1: operation_deadline, 2: retry_deadline})
                                    self.assertEqual(provider._source_park_evidence.lease, 0x8899)
                                    self.assertEqual(source_context._source_route_park_joins[id(prepared)].park.lease,
                                        0x7788)
                                    self.assertEqual(source_context._source_route_park_joins[id(staged)].park.lease,
                                        0x8899)
                                    if private_master_abort == 'success':
                                        verify_barrier(clients[1], 8)
                                        self.assertEqual(source_context._completed_master_barriers,
                                            {(1, 5), (1, 9), (2, 5), (2, 6)})
                                        self.assertEqual(source_context._source_shell_committed_plans[(2, 1)]
                                            ['native_current_cookie'], 0x9922)
                                        self.assertEqual(revoke_calls, [])
                                    else:
                                        clients[1].settimeout(0.01)
                                        try:
                                            self.assertEqual(clients[1].recv(1), b'')
                                        except TimeoutError:
                                            pass
                                        self.assertTrue(controller.unresolved)
                                        self.assertFalse(source_context._source_shell_committed_plans)
                                        self.assertEqual(revoke_calls, ['revoke'])
                                        sockets.extend(controller._private_source_master_channels)
                                        self.assertEqual(staged.committed, private_master_abort == 'retry-c28-unknown')
                                        if private_master_abort == 'retry-renewed':
                                            app.terminate()
                                            app.communicate(timeout=2)
                                            _, stderr = retry_worker.communicate(input=b'x', timeout=2)
                                            self.assertEqual(retry_worker.returncode, 0, stderr)
                                            return
                                if private_master_abort == 'bad-ready':
                                    self.assertTrue(controller._private_first_abort_acknowledged(source_context))
                                    self.assertNotIn((2, 1), source_context._activated_workers)
                                    self.assertEqual(revoke_calls, ['revoke'])
                                _, stderr = retry_worker.communicate(input=b'x', timeout=2)
                                self.assertEqual(retry_worker.returncode, 0, stderr)
                                os.write(release_write, b'R')
                                stdout, stderr = app.communicate(timeout=2)
                                self.assertEqual(app.returncode, 0, (stdout, stderr))
                                return
                            if private_master_commit:
                                active_operation['value'] = 6
                                commit_record = list(record)
                                commit_record[2] = 6
                                if private_master_commit_fault == 'deadline':
                                    commit_record[28] += 1
                                commit_client = socket.socket(socket.AF_UNIX,
                                    socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
                                sockets.append(commit_client)
                                commit_client.connect(str(Path(directory) / 'master.sock'))
                                commit_client.settimeout(0.5)
                                commit_client.send(source_bootstrap.SHELL_RECORD.pack(*commit_record))
                                if private_master_commit_fault == 'wrong-provider':
                                    controller.c22_provider = SimpleNamespace()
                                    with self.assertRaisesRegex(PermissionError,
                                            'exact activated C34 controller/provider'):
                                        controller.pump_bootstrap_listener()
                                    self.assertFalse(__import__('select').select(
                                        [provider_peer], [], [], 0)[0],
                                        'wrong provider reached the C31 COMMIT actor')
                                    self.assertFalse(provider._source_committed)
                                    self.assertEqual(revoke_calls, ['revoke'])
                                    self.assertTrue(controller.unresolved)
                                    self.assertEqual(source_context._private_source_master_request_attempts,
                                        {(1, 5), (1, 6)})
                                    self.assertFalse(hasattr(prepared, 'last_command_observation'))
                                    self.assertFalse(__import__('select').select(
                                        [commit_client], [], [], 0)[0],
                                        'rejected COMMIT emitted a master ACK')
                                    sockets.extend(controller._private_source_master_channels)
                                    app.kill()
                                    app.communicate(timeout=2)
                                    return
                                elif private_master_commit_fault == 'deadline':
                                    with self.assertRaisesRegex(PermissionError,
                                            'exact registered PARK/PREPARED join or deadline'):
                                        controller.pump_bootstrap_listener()
                                    self.assertFalse(__import__('select').select(
                                        [provider_peer], [], [], 0)[0],
                                        'mismatched COMMIT deadline reached the C31 actor')
                                    self.assertFalse(provider._source_committed)
                                    self.assertEqual(revoke_calls, ['revoke'])
                                    self.assertTrue(controller.unresolved)
                                    self.assertEqual(source_context._private_source_master_request_attempts,
                                        {(1, 5), (1, 6)})
                                    self.assertFalse(hasattr(prepared, 'last_command_observation'))
                                    self.assertFalse(__import__('select').select(
                                        [commit_client], [], [], 0)[0],
                                        'rejected COMMIT emitted a master ACK')
                                    sockets.extend(controller._private_source_master_channels)
                                    app.kill()
                                    app.communicate(timeout=2)
                                    return
                                elif private_master_commit_fault == 'evidence':
                                    retained_candidate = source_context.worker_channels[(1, 1)]
                                    real_sendmsg = socket.socket.sendmsg
                                    def fail_candidate_evidence(sock, *args, **kwargs):
                                        if sock is retained_candidate:
                                            raise OSError(errno.EIO,
                                                'injected candidate COMMIT_EVIDENCE failure')
                                        return real_sendmsg(sock, *args, **kwargs)
                                    with mock.patch.object(socket.socket, 'sendmsg',
                                            fail_candidate_evidence):
                                        with self.assertRaisesRegex(OSError,
                                                'injected candidate COMMIT_EVIDENCE failure'):
                                            controller.pump_bootstrap_listener()
                                    # The shared master ACK was sent before the candidate
                                    # evidence attempt. Preserve this partial result as an
                                    # unresolved operation, never as a completed commit join.
                                    partial, partial_ancillary, partial_flags, _ = commit_client.recvmsg(
                                        source_bootstrap.SHELL_RECORD.size + 1,
                                        socket.CMSG_SPACE(8 * 4))
                                    for level, kind, value in partial_ancillary:
                                        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                                            got = array.array('i')
                                            got.frombytes(value[:len(value) - len(value) % 4])
                                            for descriptor in got:
                                                os.close(descriptor)
                                    self.assertFalse(partial_flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC))
                                    self.assertEqual(source_bootstrap.SHELL_RECORD.unpack(partial)[2], 8)
                                    self.assertTrue(provider._source_committed)
                                    self.assertEqual(source_context._completed_master_barriers,
                                        {(1, 5)})
                                    self.assertNotIn((1, 1),
                                        source_context._source_shell_committed_plans)
                                    self.assertTrue(controller.unresolved)
                                    self.assertEqual(revoke_calls, ['revoke'])
                                    self.assertTrue(all(channel.fileno() >= 0 for channel in
                                        controller._private_source_master_channels))
                                    self.assertFalse(__import__('select').select(
                                        [grant_peer], [], [], 0)[0],
                                        'failed candidate evidence unexpectedly reached the worker')
                                    sockets.extend(controller._private_source_master_channels)
                                    app.kill()
                                    app.communicate(timeout=2)
                                    return
                                elif private_master_commit_fault == 'worker-proof':
                                    real_sendmsg = socket.socket.sendmsg

                                    def corrupt_worker_proof(sock, buffers, *args, **kwargs):
                                        if sock is retained_grant_channel:
                                            evidence = bytearray(buffers[0])
                                            self.assertEqual(len(evidence),
                                                source_bootstrap.COMMIT_EVIDENCE_RECORD_BYTES)
                                            proof_byte = (source_bootstrap.PREEXIT_HEADER.size +
                                                source_bootstrap.SHELL_RECORD.size -
                                                2 * len(candidate_cycle_proof.config_sha256))
                                            evidence[proof_byte] ^= 1
                                            buffers = [evidence]
                                        return real_sendmsg(sock, buffers, *args, **kwargs)

                                    with mock.patch.object(socket.socket, 'sendmsg', corrupt_worker_proof):
                                        self.assertTrue(controller.pump_bootstrap_listener())
                                else:
                                    self.assertTrue(controller.pump_bootstrap_listener())
                                commit_reply, commit_ancillary, commit_flags, _ = commit_client.recvmsg(
                                    source_bootstrap.SHELL_RECORD.size + 1,
                                    socket.CMSG_SPACE(8 * 4))
                                commit_fds = []
                                for level, kind, value in commit_ancillary:
                                    if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                                        got = array.array('i')
                                        got.frombytes(value[:len(value) - len(value) % 4])
                                        commit_fds.extend(got)
                                for descriptor in commit_fds:
                                    os.close(descriptor)
                                self.assertFalse(commit_flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC))
                                commit_fields = source_bootstrap.SHELL_RECORD.unpack(commit_reply)
                                self.assertEqual(commit_fields[2], 8)
                                self.assertTrue(provider._source_committed)
                                self.assertEqual(source_context._completed_master_barriers,
                                    {(1, 5), (1, 6)})
                                self.assertIn((1, 1), source_context._source_shell_committed_plans)
                                if native_activation:
                                    stdout, stderr = candidate_process.communicate(timeout=3)
                                    self.assertEqual(candidate_process.returncode, 0, (stdout, stderr))
                                    expected = b'RECEIVER_READY\nACTIVATE status=1 accepted=1\n'
                                    if private_master_commit_fault == 'worker-proof':
                                        expected += f'COMMIT_EVIDENCE status={-errno.EPROTO} accepted=0 cookie=0\n'.encode()
                                    else:
                                        expected += f'COMMIT_EVIDENCE status=0 accepted=1 cookie={0x9911}\n'.encode()
                                    self.assertEqual(stdout, expected)
                                else:
                                    evidence, evidence_ancillary, evidence_flags, _ = grant_peer.recvmsg(
                                        source_bootstrap.COMMIT_EVIDENCE_RECORD_BYTES + 1,
                                        socket.CMSG_SPACE(8 * 4))
                                    self.assertFalse(evidence_flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC))
                                    header = source_bootstrap.PREEXIT_HEADER.unpack_from(evidence)
                                    self.assertEqual(header[2], source_bootstrap.COMMIT_EVIDENCE)
                                    evidence_record = source_bootstrap.SHELL_RECORD.unpack_from(
                                        evidence, source_bootstrap.PREEXIT_HEADER.size)
                                    self.assertEqual(evidence_record[2],
                                        source_bootstrap.COMMIT_EVIDENCE)
                                    cookie = struct.unpack_from('=Q', evidence, len(evidence) - 8)[0]
                                    self.assertEqual(cookie, 0x9911)
                                    for level, kind, value in evidence_ancillary:
                                        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                                            got = array.array('i')
                                            got.frombytes(value[:len(value) - len(value) % 4])
                                            for descriptor in got:
                                                os.close(descriptor)
                                self.assertLess(controller._private_source_master_timings[-1][3] -
                                    controller._private_source_master_timings[-1][2],
                                    100_000_000)
                                if private_master_commit_fault == 'duplicate':
                                    duplicate_client = socket.socket(socket.AF_UNIX,
                                        socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
                                    sockets.append(duplicate_client)
                                    duplicate_client.connect(str(Path(directory) / 'master.sock'))
                                    duplicate_client.send(source_bootstrap.SHELL_RECORD.pack(*commit_record))
                                    with self.assertRaisesRegex(PermissionError,
                                            'already consumed'):
                                        controller.pump_bootstrap_listener()
                                    self.assertEqual(source_context._private_source_master_attempts,
                                        {(1, 5), (1, 6)})
                                    self.assertEqual(revoke_calls, ['revoke'])
                                    self.assertTrue(controller.unresolved)
                                    self.assertFalse(__import__('select').select(
                                        [provider_peer], [], [], 0)[0],
                                        'duplicate master COMMIT reached the C28 actor')
                                    self.assertFalse(__import__('select').select(
                                        [duplicate_client], [], [], 0)[0],
                                        'duplicate master COMMIT emitted an ACK')
                                    sockets.extend(controller._private_source_master_channels)
                                    app.kill()
                                    app.communicate(timeout=2)
                                    return
                                provider_peer.close()
                                os.close(provider.pidfd)
                                handles.remove(provider.pidfd)
                                os.write(release_write, b'R')
                                stdout, stderr = app.communicate(timeout=2)
                                self.assertEqual(app.returncode, 0, (stdout, stderr))
                                return
                        app.kill()
                        app.communicate(timeout=2)
                        return
                    app.kill()
                    app.communicate(timeout=2)
                    return
                provider_spec = importlib.util.spec_from_file_location(
                    'typed_source_c22_provider',
                    ROOT / 'tools/nginx_source_c22_provider.py')
                provider_module = importlib.util.module_from_spec(provider_spec)
                sys.modules[provider_spec.name] = provider_module
                provider_spec.loader.exec_module(provider_module)
                provider = provider_module.SourceShellC22Provider.__new__(
                    provider_module.SourceShellC22Provider)
                provider.context = source_context
                provider._source_command_abi = provider_module._C28_SOURCE_COMMAND_ABI
                provider._source_command_sequence = 0
                provider._source_command_outstanding = None
                provider._source_command_unresolved = False
                provider._source_park_deadline_ns = None
                provider._source_park_result = None
                provider._source_park_evidence = None
                provider._source_route_receipt_consumed = False
                provider._source_committed = False
                provider._closed = False
                provider.process = SimpleNamespace(pid=os.getpid())
                provider.pidfd = os.pidfd_open(os.getpid(), 0)
                handles.append(provider.pidfd)
                provider.start_ticks = ker_run.process_start_ticks(os.getpid())
                provider._helper_sha256 = bytes.fromhex('ab' * 32)
                provider._channel, provider_channel_peer = socket.socketpair(
                    socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
                sockets.extend((provider._channel, provider_channel_peer))
                provider._channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                provider._last_received_bundle = {'record': b'r' * 108,
                    'credentials': (os.getpid(), os.getuid(), os.getgid()),
                    'fds': ((1, 2, 3), (4, 5, 6), (7, 8, 9))}
                provider._check_actor = lambda _deadline: None
                park_deadline = min(deadline, time.monotonic_ns() + 80_000_000)
                park_response = {'phase': provider_module._C28_PHASE_PREPARED,
                    'lease': 0x7788, 'listener_cookie': 0,
                    'received': 2, 'accepted': 0}
                provider._source_c28_command = lambda operation, _deadline: park_response
                provider.park_source_group(park_deadline)
                joined = provider.bind_source_route_preparation(prepared)
                self.assertIs(joined,
                    source_context._source_route_park_joins[id(prepared)])
                commit_response = {'phase': provider_module._C28_PHASE_COMMITTED,
                    'lease': park_response['lease'], 'listener_cookie': 0x99,
                    'received': typed_c28_counts[0],
                    'accepted': typed_c28_counts[1]}
                if drop_typed_binding:
                    del prepared._source_route_preparation
                    with self.assertRaises(PermissionError):
                        ker_run.send_source_route_command(control, prepared,
                            ker_run._RX_OWNER_SOURCE_ROUTE_COMMIT,
                            prepared.command_sequence + 1,
                            operation_deadline_ns=park_deadline)
                    if __import__('select').select([marker_read], [], [], 0.02)[0]:
                        self.fail('typed binding deletion fell through to a legacy C31 send')
                    app.kill()
                    app.communicate(timeout=2)
                    return
                if copy_typed_binding:
                    original = prepared._source_route_preparation
                    prepared._source_route_preparation = original._replace()
                    with self.assertRaises(PermissionError):
                        ker_run.send_source_route_command(control, prepared,
                            ker_run._RX_OWNER_SOURCE_ROUTE_COMMIT,
                            prepared.command_sequence + 1,
                            operation_deadline_ns=park_deadline)
                    self.assertFalse(__import__('select').select(
                        [marker_read], [], [], 0.02)[0],
                        'copied typed binding produced a C31 command send')
                    prepared._source_route_preparation = original
                    app.kill()
                    app.communicate(timeout=2)
                    return
                if typed_ack_fault:
                    with self.assertRaises((PermissionError, TimeoutError,
                            ConnectionResetError, BrokenPipeError, OSError)):
                        ker_run.send_source_route_command(control, prepared,
                            typed_command_type, prepared.command_sequence + 1,
                            operation_deadline_ns=park_deadline)
                    self.assertIsNone(getattr(prepared,
                        '_source_route_commit_receipt', None))
                    self.assertFalse(provider._source_route_receipt_consumed)
                    provider_channel_peer.close()
                    os.close(provider.pidfd)
                    os.write(release_write, b'R')
                    stdout, stderr = app.communicate(timeout=2)
                    self.assertEqual(app.returncode, 0, (stdout, stderr))
                    return
                commit_status = ker_run.send_source_route_command(control, prepared,
                    typed_command_type, prepared.command_sequence + 1,
                    operation_deadline_ns=park_deadline)
                self.assertEqual(commit_status, typed_ack_status)
                receipt = prepared._source_route_commit_receipt
                if (typed_command_type == ker_run._RX_OWNER_SOURCE_ROUTE_ABORT or
                        typed_ack_status != 0):
                    self.assertIsNone(receipt)
                    self.assertFalse(provider._source_route_receipt_consumed)
                    provider_channel_peer.close()
                    os.close(provider.pidfd)
                    os.write(release_write, b'R')
                    stdout, stderr = app.communicate(timeout=2)
                    self.assertEqual(app.returncode, 0, (stdout, stderr))
                    return
                provider._source_c28_command = lambda operation, _deadline: commit_response
                if typed_c28_counts == (3, 3):
                    provider.commit_source_group_before(park_deadline, receipt)
                    self.assertTrue(provider._source_committed)
                else:
                    with self.assertRaisesRegex(PermissionError, 'did not settle the PARK lease and queue'):
                        provider.commit_source_group_before(park_deadline, receipt)
                    self.assertFalse(provider._source_committed)
                    self.assertTrue(provider._source_command_unresolved)
                self.assertTrue(provider._source_route_receipt_consumed)
                provider_channel_peer.close()
                os.close(provider.pidfd)
                os.write(release_write, b'R')
                stdout, stderr = app.communicate(timeout=2)
                self.assertEqual(app.returncode, 0, (stdout, stderr))
                return
            sequence = 2
            if not abort:
                repeated = prepared.fields.copy()
                repeated[2] = ker_run._RX_OWNER_SOURCE_ROUTE_PREPARE
                payload = ker_run._RX_OWNER_SOURCE_ROUTE_RECORD.pack(*repeated,
                    1235, sequence, prepared.master_start, prepared.master_pid,
                    prepared.source_epoch, 0, 0, 0)
                rights = array.array('i', (candidate.owner_pidfd,
                    candidate_channel.fileno(), source_master.pidfd))
                control.sendmsg([payload], [(socket.SOL_SOCKET,
                    socket.SCM_RIGHTS, rights)])
                import selectors
                with selectors.DefaultSelector() as selector:
                    selector.register(control, selectors.EVENT_READ)
                    self.assertTrue(selector.select(2), 'second PREPARE was not rejected')
                reply, ancillary, flags, _ = control.recvmsg(
                    ker_run._RX_OWNER_SOURCE_ROUTE_RECORD.size + 1,
                    socket.CMSG_SPACE(12) + socket.CMSG_SPACE(4 * 4))
                creds = [struct.unpack('=3i', data) for level, kind, data in ancillary
                    if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS]
                self.assertEqual(creds, [(app.pid, os.getuid(), os.getgid())])
                rejected = list(ker_run._RX_OWNER_SOURCE_ROUTE_RECORD.unpack(reply))
                self.assertEqual(rejected[2], ker_run._RX_OWNER_SOURCE_ROUTE_PREPARED)
                self.assertEqual(rejected[23], 1235)
                self.assertEqual(rejected[24], sequence)
                self.assertEqual(rejected[28], -116)
                sequence += 1
            if expired_commit:
                for expired, wanted_status in ((0, -errno.EINVAL), (time.monotonic_ns() - 1, -errno.ETIMEDOUT)):
                    fields = prepared.fields.copy()
                    fields[2] = ker_run._RX_OWNER_SOURCE_ROUTE_COMMIT
                    payload = ker_run._RX_OWNER_SOURCE_ROUTE_RECORD.pack(*fields,
                        prepared.operation_id, sequence, prepared.master_start,
                        prepared.master_pid, prepared.source_epoch, 0, 0, expired)
                    control.send(payload)
                    import selectors
                    with selectors.DefaultSelector() as selector:
                        selector.register(control, selectors.EVENT_READ)
                        self.assertTrue(selector.select(2), 'expired COMMIT was not rejected')
                    packet, ancillary, flags, _ = control.recvmsg(
                        ker_run._RX_OWNER_SOURCE_ROUTE_RECORD.size + 1, socket.CMSG_SPACE(12))
                    self.assertFalse(flags)
                    self.assertEqual([struct.unpack('=3i', value) for level, kind, value in ancillary
                        if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS],
                        [(app.pid, os.getuid(), os.getgid())])
                    rejected = ker_run._RX_OWNER_SOURCE_ROUTE_RECORD.unpack(packet)
                    self.assertEqual((rejected[2], rejected[24], rejected[28], rejected[30]),
                        (ker_run._RX_OWNER_SOURCE_ROUTE_COMMITTED, sequence, wanted_status, expired))
                    self.assertEqual(os.read(marker_read, 1), b'T')
                    sequence += 1
            if deferred_commit:
                self.assertTrue(inflight, 'deferred COMMIT requires an in-flight frame')
                if deferred_second_command:
                    results = []
                    errors = []
                    def send_first_deferred():
                        try:
                            results.append(ker_run.send_source_route_command(control,
                                prepared, ker_run._RX_OWNER_SOURCE_ROUTE_COMMIT_AFTER_FRAME,
                                sequence))
                        except Exception as exc:
                            errors.append(exc)
                    sender = threading.Thread(target=send_first_deferred, daemon=True)
                    sender.start()
                    import selectors
                    with selectors.DefaultSelector() as selector:
                        selector.register(marker_read, selectors.EVENT_READ)
                        self.assertTrue(selector.select(2), 'deferred command was not staged')
                    self.assertEqual(os.read(marker_read, 1), b'B')
                    fields = prepared.fields.copy()
                    fields[2] = ker_run._RX_OWNER_SOURCE_ROUTE_COMMIT_AFTER_FRAME
                    payload = ker_run._RX_OWNER_SOURCE_ROUTE_RECORD.pack(*fields,
                        prepared.operation_id, sequence + 1, prepared.master_start,
                        prepared.master_pid, prepared.source_epoch, 0, 0,
                        prepared.fields[22] - 1)
                    control.send(payload)
                    sender.join(timeout=2)
                    self.assertFalse(sender.is_alive(), 'deferred first command was not cancelled')
                    self.assertFalse(errors, errors)
                    self.assertEqual(results, [-errno.EALREADY])
                    self.assertEqual(os.read(marker_read, 1), b'T')
                else:
                    result = ker_run.send_source_route_command(control, prepared,
                        ker_run._RX_OWNER_SOURCE_ROUTE_COMMIT_AFTER_FRAME, sequence)
                    expected = (-errno.ETIMEDOUT if deferred_expired else
                        -errno.ESTALE if deferred_dead_candidate else
                        -errno.EPROTO if deferred_late_completion else 0)
                    if result != expected:
                        markers = bytearray()
                        while select.select([marker_read], [], [], .1)[0]:
                            chunk = os.read(marker_read, 64)
                            if not chunk: break
                            markers.extend(chunk)
                        os.write(release_write, b'R')
                        stdout, stderr = app.communicate(timeout=2)
                        raise AssertionError(f'deferred command status {result}, expected {expected}; '
                            f'markers={bytes(markers)!r}, stdout={stdout!r}, stderr={stderr!r}')
                    self.assertEqual(os.read(marker_read, 1), b'B')
                    marker = os.read(marker_read, 1)
                    if deferred_late_completion or deferred_dead_candidate:
                        self.assertEqual(marker, b'F')
                        marker = os.read(marker_read, 1)
                    if deferred_expired or deferred_dead_candidate or deferred_late_completion:
                        self.assertEqual(marker, b'T')
                    else:
                        self.assertEqual(marker, b'F')
                        self.assertEqual(os.read(marker_read, 1), b'C')
                        self.assertEqual(os.read(marker_read, 1), b'L')
                        self.assertEqual(prepared.last_command_type,
                            ker_run._RX_OWNER_SOURCE_ROUTE_COMMIT_AFTER_FRAME)
                        self.assertEqual(prepared.last_status, 0)
                os.write(release_write, b'R')
                stdout, stderr = app.communicate(timeout=2)
                self.assertEqual(app.returncode, 0, (stdout, stderr))
                return
            if kill_after_stage:
                candidate_process.kill()
                candidate_process.wait(timeout=2)
                self.assertEqual(ker_run.send_source_route_command(control,
                    prepared, ker_run._RX_OWNER_SOURCE_ROUTE_COMMIT, sequence), -116)
                self.assertEqual(os.read(marker_read, 1), b'A')
                os.write(release_write, b'R')
                stdout, stderr = app.communicate(timeout=2)
                self.assertEqual(app.returncode, 0, (stdout, stderr))
                return
            if late_swap:
                with self.assertRaises(TimeoutError):
                    ker_run.send_source_route_command(control, prepared,
                        ker_run._RX_OWNER_SOURCE_ROUTE_COMMIT, sequence,
                        operation_deadline_ns=time.monotonic_ns() + 50_000_000)
                self.assertEqual(os.read(marker_read, 1), b'Q')
                os.write(release_write, b'R')
                stdout, stderr = app.communicate(timeout=2)
                self.assertEqual(app.returncode, 0, (stdout, stderr))
                return
            if inflight:
                self.assertEqual(ker_run.send_source_route_command(control,
                    prepared, ker_run._RX_OWNER_SOURCE_ROUTE_COMMIT, sequence), -16)
                self.assertEqual(os.read(marker_read, 1), b'B')
                sequence += 1
            else:
                pass
            kind = (ker_run._RX_OWNER_SOURCE_ROUTE_ABORT if abort else
                ker_run._RX_OWNER_SOURCE_ROUTE_COMMIT)
            if late_observation:
                original_ticks = ker_run.process_start_ticks
                observations = 0
                def delayed_ticks(pid):
                    nonlocal observations
                    result = original_ticks(pid)
                    if pid == app.pid:
                        observations += 1
                        if observations == 2:
                            time.sleep(.08)
                    return result
                with mock.patch.object(ker_run, 'process_start_ticks', side_effect=delayed_ticks):
                    with self.assertRaises(TimeoutError):
                        ker_run.send_source_route_command(control, prepared, kind, sequence,
                            operation_deadline_ns=time.monotonic_ns() + 50_000_000)
                observation = prepared.last_command_observation
                self.assertEqual(observation['status'], 0)
                self.assertLess(observation['received_ns'], observation['deadline_ns'])
                self.assertGreaterEqual(observation['validated_ns'], observation['deadline_ns'])
                self.assertEqual(prepared.command_sequence, 1)
                # A completed swap plus delayed host proof is UNKNOWN to the
                # caller, never evidence of rejection or an old-route rollback.
                self.assertEqual(os.read(marker_read, 1), b'C')
                self.assertEqual(os.read(marker_read, 1), b'L')
                os.write(release_write, b'R')
                stdout, stderr = app.communicate(timeout=2)
                self.assertEqual(app.returncode, 0, (stdout, stderr))
                return
            result = ker_run.send_source_route_command(control, prepared, kind, sequence)
            if abort:
                self.assertEqual(result, 0)
                self.assertEqual(os.read(marker_read, 1), b'A')
                if abort_retry:
                    candidate_channel.close()
                    candidate_worker_channel.close()
                    candidate_process.wait(timeout=2)
                    self.assertFalse(ker_run.nginx_companion.process_alive(
                        candidate.owner_pidfd), 'aborted candidate pidfd did not become dead')
                    retry_channel, retry_worker_channel = pair()
                    retry_slot, retry_slot_peer = socket.socketpair(
                        socket.AF_UNIX, socket.SOCK_SEQPACKET)
                    sockets.extend((retry_channel, retry_worker_channel,
                        retry_slot, retry_slot_peer))
                    retry_process = subprocess.Popen([sys.executable, '-c', ACTOR,
                        str(retry_worker_channel.fileno()), 'valid'],
                        pass_fds=(retry_worker_channel.fileno(),), stderr=subprocess.PIPE)
                    processes.append(retry_process)
                    retry_candidate = proof(retry_process, retry_slot, 1)
                    proofs.append(retry_candidate)
                    with self.assertRaises(ValueError):
                        ker_run.rx_owner_source_route_prepare(control, retry_channel,
                            app, app_pidfd, supervisor_pidfd, current, retry_candidate,
                            source_master, NONCE, 77, deadline + 1,
                            operation_id=prepared.operation_id + 1,
                            command_sequence=prepared.command_sequence + 1,
                            source_epoch=2, previous_aborted=prepared)
                    for replay_operation, replay_sequence in (
                            (prepared.operation_id, prepared.command_sequence + 1),
                            (prepared.operation_id + 1, prepared.command_sequence)):
                        with self.assertRaises(ValueError):
                            ker_run.rx_owner_source_route_prepare(control, retry_channel,
                                app, app_pidfd, supervisor_pidfd, current, retry_candidate,
                                source_master, NONCE, 77, deadline,
                                operation_id=replay_operation,
                                command_sequence=replay_sequence,
                                source_epoch=2, previous_aborted=prepared)
                    try:
                        retry_prepared = ker_run.rx_owner_source_route_prepare(control,
                            retry_channel, app, app_pidfd, supervisor_pidfd, current,
                            retry_candidate, source_master, NONCE, 77, deadline,
                            operation_id=prepared.operation_id + 1,
                            command_sequence=prepared.command_sequence + 1,
                            source_epoch=2, previous_aborted=prepared)
                    except Exception as exc:
                        if app.poll() is not None:
                            stdout, stderr = app.communicate(timeout=2)
                            raise AssertionError(f'epoch-2 receiver exited: {app.returncode}, '
                                f'{stdout!r}, {stderr!r}') from exc
                        raise
                    self.assertEqual(retry_prepared.source_epoch, 2)
                    self.assertLessEqual(retry_prepared.fields[22], prepared.fields[22])
                    self.assertEqual(os.read(marker_read, 1), b'P')
                    self.assertEqual(ker_run.send_source_route_command(control,
                        retry_prepared, ker_run._RX_OWNER_SOURCE_ROUTE_COMMIT,
                        retry_prepared.command_sequence + 1), 0)
                    self.assertEqual(os.read(marker_read, 1), b'C')
                    self.assertEqual(os.read(marker_read, 1), b'L')
                    os.write(release_write, b'R')
                    stdout, stderr = app.communicate(timeout=2)
                    self.assertEqual(app.returncode, 0, (stdout, stderr))
                    return
            else:
                self.assertEqual(result, 0)
                marker = os.read(marker_read, 1)
                if marker != b'C':
                    os.write(release_write, b'R')
                    stdout, stderr = app.communicate(timeout=2)
                    raise AssertionError(f'committed route did not forward old LOCAL; '
                        f'marker={marker!r}, return={app.returncode}, stdout={stdout!r}, '
                        f'stderr={stderr!r}')
                self.assertEqual(os.read(marker_read, 1), b'L')
                if successor:
                    next_channel, next_worker_channel = pair()
                    next_slot, next_slot_peer = socket.socketpair(
                        socket.AF_UNIX, socket.SOCK_SEQPACKET)
                    sockets.extend((next_channel, next_worker_channel, next_slot, next_slot_peer))
                    next_process = subprocess.Popen([sys.executable, '-c', ACTOR,
                        str(next_worker_channel.fileno()), 'valid'],
                        pass_fds=(next_worker_channel.fileno(),), stderr=subprocess.PIPE)
                    processes.append(next_process)
                    next_candidate = proof(next_process, next_slot, 1)
                    proofs.append(next_candidate)
                    uncommitted = copy.copy(prepared)
                    uncommitted.committed = False
                    with self.assertRaises(ValueError):
                        ker_run.rx_owner_source_route_prepare(control, next_channel, app,
                            app_pidfd, supervisor_pidfd, candidate, next_candidate,
                            source_master, NONCE, 77, deadline,
                            operation_id=prepared.operation_id + 2,
                            command_sequence=prepared.command_sequence + 2,
                            source_epoch=2, previous_committed=uncommitted)
                    with self.assertRaises(ValueError):
                        ker_run.rx_owner_source_route_prepare(control, next_channel, app,
                            app_pidfd, supervisor_pidfd, current, next_candidate,
                            source_master, NONCE, 77, deadline,
                            operation_id=prepared.operation_id + 2,
                            command_sequence=prepared.command_sequence + 2,
                            source_epoch=2, previous_committed=prepared)
                    wrong_master = SimpleNamespace(pid=source_master.pid + 1,
                        pidfd=source_master.pidfd, start_ticks=source_master.start_ticks)
                    with self.assertRaises(ValueError):
                        ker_run.rx_owner_source_route_prepare(control, next_channel, app,
                            app_pidfd, supervisor_pidfd, candidate, next_candidate,
                            wrong_master, NONCE, 77, deadline,
                            operation_id=prepared.operation_id + 2,
                            command_sequence=prepared.command_sequence + 2,
                            source_epoch=2, previous_committed=prepared)
                    with self.assertRaises(ValueError):
                        ker_run.rx_owner_source_route_prepare(control, next_channel, app,
                            app_pidfd, supervisor_pidfd, candidate, next_candidate,
                            source_master, NONCE, 77, time.monotonic_ns() - 1,
                            operation_id=prepared.operation_id + 2,
                            command_sequence=prepared.command_sequence + 2,
                            source_epoch=2, previous_committed=prepared)
                    reused = copy.copy(next_candidate)
                    reused.owner_cookie = candidate.owner_cookie
                    with self.assertRaises(ValueError):
                        ker_run.rx_owner_source_route_prepare(control, next_channel, app,
                            app_pidfd, supervisor_pidfd, candidate, reused,
                            source_master, NONCE, 77, deadline,
                            operation_id=prepared.operation_id + 2,
                            command_sequence=prepared.command_sequence + 2,
                            source_epoch=2, previous_committed=prepared)
                    # The receiver rejects a correctly bound successor while
                    # the original peer is still live, then accepts one after
                    # that peer's pidfd settles.
                    def successor_fields():
                        fields = prepared.fields.copy()
                        fields[2] = ker_run._RX_OWNER_SOURCE_ROUTE_SUCCESSOR_PREPARE
                        fields[5:15] = [next_candidate.owner_pid, next_candidate.owner_tid,
                            next_candidate.owner_role, 0, prepared.fields[9],
                            prepared.fields[10], next_candidate.owner_start,
                            next_candidate.owner_slot_device, next_candidate.owner_slot_inode,
                            next_candidate.owner_cookie]
                        fields[16:22] = [candidate.owner_pid, candidate.owner_tid,
                            candidate.owner_start, candidate.owner_slot_device,
                            candidate.owner_slot_inode, candidate.owner_cookie]
                        fields[22] = prepared.fields[22]
                        return fields
                    operation = prepared.operation_id + 1
                    command_sequence = prepared.command_sequence + 1
                    def reject_successor(fields, wire_master=source_master.pid):
                        nonlocal operation, command_sequence
                        packet = ker_run._RX_OWNER_SOURCE_ROUTE_RECORD.pack(*fields,
                            operation, command_sequence, prepared.master_start,
                            wire_master, 2, 0, 0, 0)
                        rights = array.array('i', (next_candidate.owner_pidfd,
                            next_channel.fileno(), source_master.pidfd))
                        control.sendmsg([packet], [(socket.SOL_SOCKET,
                            socket.SCM_RIGHTS, rights)])
                        import selectors
                        with selectors.DefaultSelector() as selector:
                            selector.register(control, selectors.EVENT_READ)
                            if not selector.select(2):
                                if app.poll() is not None:
                                    stdout, stderr = app.communicate(timeout=2)
                                    raise AssertionError(f'invalid successor receiver exited '
                                        f'{app.returncode}: {stdout!r} {stderr!r}')
                                self.fail('invalid successor PREPARE did not receive rejection')
                        response, _, _, _ = control.recvmsg(
                            ker_run._RX_OWNER_SOURCE_ROUTE_RECORD.size + 1,
                            socket.CMSG_SPACE(12))
                        rejected = ker_run._RX_OWNER_SOURCE_ROUTE_RECORD.unpack(response)
                        self.assertEqual((rejected[2], rejected[23], rejected[24]),
                            (ker_run._RX_OWNER_SOURCE_ROUTE_SUCCESSOR_PREPARED,
                             operation, command_sequence))
                        self.assertLess(rejected[28], 0)
                        operation += 1
                        command_sequence += 1
                    if app.poll() is not None:
                        stdout, stderr = app.communicate(timeout=2)
                        raise AssertionError(f'receiver exited before live-peer control: '
                            f'{app.returncode} {stdout!r} {stderr!r}')
                    reject_successor(successor_fields())
                    old.kill(); old.wait(timeout=2)
                    self.assertEqual(os.read(marker_read, 1), b'D')
                    if successor_dead_current:
                        candidate_process.kill(); candidate_process.wait(timeout=2)
                        reject_successor(successor_fields())
                        self.assertEqual(os.read(marker_read, 1), b'R')
                        os.write(release_write, b'R')
                        stdout, stderr = app.communicate(timeout=2)
                        self.assertEqual(app.returncode, 0, (stdout, stderr))
                        return
                    fields = successor_fields(); fields[16:22] = [
                        current.owner_pid, current.owner_tid, current.owner_start,
                        current.owner_slot_device, current.owner_slot_inode,
                        current.owner_cookie]
                    reject_successor(fields)
                    fields = successor_fields(); fields[5:15] = [
                        current.owner_pid, current.owner_tid, current.owner_role, 0,
                        prepared.fields[9], prepared.fields[10], current.owner_start,
                        current.owner_slot_device, current.owner_slot_inode,
                        current.owner_cookie]
                    reject_successor(fields)
                    fields = successor_fields(); fields[5] = candidate.owner_pid
                    fields[6] = candidate.owner_tid
                    fields[11] = candidate.owner_start
                    fields[12] = candidate.owner_slot_device
                    fields[13] = candidate.owner_slot_inode
                    fields[14] = candidate.owner_cookie
                    reject_successor(fields)
                    fields = successor_fields(); fields[12:15] = prepared.fields[12:15]
                    reject_successor(fields)
                    fields = successor_fields(); fields[22] = time.monotonic_ns() - 1
                    reject_successor(fields)
                    reject_successor(successor_fields(), source_master.pid + 1)
                    with self.assertRaises(ValueError):
                        ker_run.rx_owner_source_route_prepare(control, next_channel, app,
                            app_pidfd, supervisor_pidfd, current, next_candidate,
                            source_master, NONCE, 77, deadline + 1,
                            operation_id=operation,
                            command_sequence=command_sequence,
                            source_epoch=2, previous_committed=prepared)
                    try:
                        successor_prepared = ker_run.rx_owner_source_route_successor_prepare(
                            control, next_channel, app, app_pidfd, supervisor_pidfd,
                            candidate, next_candidate, source_master, NONCE, 77,
                            deadline, operation, command_sequence, prepared)
                    except Exception as exc:
                        if app.poll() is not None:
                            stdout, stderr = app.communicate(timeout=2)
                            raise AssertionError(f'successor receiver exited {app.returncode}: '
                                f'{stdout!r} {stderr!r}') from exc
                        raise
                    self.assertEqual(successor_prepared.source_epoch, 2)
                    if successor_inflight:
                        # The shared app-loop handler authenticates the pending
                        # candidate before reporting that the old frame remains
                        # parked; both events precede the PREPARE marker here.
                        self.assertEqual(os.read(marker_read, 1), b'B')
                        self.assertEqual(os.read(marker_read, 1), b'P')
                    else:
                        self.assertEqual(os.read(marker_read, 1), b'P')
                    if successor_inflight:
                        self.assertEqual(ker_run.send_source_route_command(control,
                            successor_prepared, ker_run._RX_OWNER_SOURCE_ROUTE_COMMIT,
                            successor_prepared.command_sequence + 1), -errno.EBUSY)
                        self.assertEqual(ker_run.send_source_route_command(control,
                            successor_prepared,
                            ker_run._RX_OWNER_SOURCE_ROUTE_COMMIT_AFTER_FRAME,
                            successor_prepared.command_sequence + 1), 0)
                        self.assertEqual(os.read(marker_read, 1), b'F')
                        self.assertEqual(os.read(marker_read, 1), b'C')
                        self.assertEqual(os.read(marker_read, 1), b'L')
                        os.write(release_write, b'R')
                        stdout, stderr = app.communicate(timeout=2)
                        self.assertEqual(app.returncode, 0, (stdout, stderr))
                        return
                    try:
                        successor_result = ker_run.send_source_route_command(control,
                            successor_prepared, ker_run._RX_OWNER_SOURCE_ROUTE_COMMIT,
                            successor_prepared.command_sequence + 1)
                    except Exception as exc:
                        if app.poll() is not None:
                            stdout, stderr = app.communicate(timeout=2)
                            raise AssertionError(f'successor COMMIT receiver exited '
                                f'{app.returncode}: {stdout!r} {stderr!r}') from exc
                        raise
                    self.assertEqual(successor_result, 0)
                    self.assertEqual(os.read(marker_read, 1), b'C')
                    self.assertEqual(os.read(marker_read, 1), b'L')
                    if successor_replay:
                        fields = successor_prepared.fields.copy()
                        fields[2] = ker_run._RX_OWNER_SOURCE_ROUTE_COMMIT
                        replay = ker_run._RX_OWNER_SOURCE_ROUTE_RECORD.pack(*fields,
                            successor_prepared.operation_id,
                            successor_prepared.command_sequence + 2,
                            successor_prepared.master_start, successor_prepared.master_pid,
                            2, 0, 0, time.monotonic_ns() + 1_000_000_000)
                        control.send(replay)
                        self.assertEqual(os.read(marker_read, 1), b'R')
                        self.assertFalse(select.select([control], [], [], .05)[0],
                            'replayed COMMIT received a success response')
                        os.write(release_write, b'R')
                        stdout, stderr = app.communicate(timeout=2)
                        self.assertEqual(app.returncode, 0, (stdout, stderr))
                        return
                    if successor_second:
                        third_channel, third_worker_channel = pair()
                        third_slot, third_slot_peer = socket.socketpair(
                            socket.AF_UNIX, socket.SOCK_SEQPACKET)
                        sockets.extend((third_channel, third_worker_channel,
                            third_slot, third_slot_peer))
                        third_process = subprocess.Popen([sys.executable, '-c', ACTOR,
                            str(third_worker_channel.fileno()), 'valid'],
                            pass_fds=(third_worker_channel.fileno(),), stderr=subprocess.PIPE)
                        processes.append(third_process)
                        third_candidate = proof(third_process, third_slot, 1)
                        proofs.append(third_candidate)
                        fields = successor_prepared.fields.copy()
                        fields[2] = ker_run._RX_OWNER_SOURCE_ROUTE_SUCCESSOR_PREPARE
                        fields[5:15] = [third_candidate.owner_pid, third_candidate.owner_tid,
                            1, 0, fields[9], fields[10], third_candidate.owner_start,
                            third_candidate.owner_slot_device, third_candidate.owner_slot_inode,
                            third_candidate.owner_cookie]
                        fields[16:22] = [next_candidate.owner_pid, next_candidate.owner_tid,
                            next_candidate.owner_start, next_candidate.owner_slot_device,
                            next_candidate.owner_slot_inode, next_candidate.owner_cookie]
                        packet = ker_run._RX_OWNER_SOURCE_ROUTE_RECORD.pack(*fields,
                            successor_prepared.operation_id + 1,
                            successor_prepared.command_sequence + 1,
                            successor_prepared.master_start, successor_prepared.master_pid,
                            2, 0, 0, 0)
                        rights = array.array('i', (third_candidate.owner_pidfd,
                            third_channel.fileno(), source_master.pidfd))
                        control.sendmsg([packet], [(socket.SOL_SOCKET,
                            socket.SCM_RIGHTS, rights)])
                        import selectors
                        with selectors.DefaultSelector() as selector:
                            selector.register(control, selectors.EVENT_READ)
                            self.assertTrue(selector.select(2),
                                'second epoch-2 successor was not rejected')
                        response, _, _, _ = control.recvmsg(
                            ker_run._RX_OWNER_SOURCE_ROUTE_RECORD.size + 1,
                            socket.CMSG_SPACE(12))
                        rejected = ker_run._RX_OWNER_SOURCE_ROUTE_RECORD.unpack(response)
                        self.assertEqual(rejected[2],
                            ker_run._RX_OWNER_SOURCE_ROUTE_SUCCESSOR_PREPARED)
                        self.assertLess(rejected[28], 0)
                        self.assertEqual(os.read(marker_read, 1), b'R')
                        os.write(release_write, b'R')
                        stdout, stderr = app.communicate(timeout=2)
                        self.assertEqual(app.returncode, 0, (stdout, stderr))
                        return
                    os.write(release_write, b'R')
                    stdout, stderr = app.communicate(timeout=2)
                    self.assertEqual(app.returncode, 0, (stdout, stderr))
                    return
                if master_death_after_commit:
                    source_master_process.terminate()
                    source_master_process.wait(timeout=2)
                    self.assertEqual(os.read(marker_read, 1), b'D')
                if expire_after_commit:
                    self.assertEqual(os.read(marker_read, 1), b'X')
            os.write(release_write, b'R')
            stdout, stderr = app.communicate(timeout=2)
            self.assertEqual(app.returncode, 0, (stdout, stderr))
        finally:
            for s in sockets:
                s.close()
            for pid, release_fd in foreign_children:
                try:
                    os.write(release_fd, b'R')
                except OSError:
                    pass
                try:
                    os.close(release_fd)
                except OSError:
                    pass
                try:
                    os.waitpid(pid, 0)
                except ChildProcessError:
                    pass
            for fd in handles:
                try:
                    os.close(fd)
                except OSError:
                    pass
            os.close(marker_read)
            if marker_write >= 0:
                os.close(marker_write)
            for item in proofs:
                os.close(item.owner_pidfd)
            cleanup_processes = []
            for process in (app, source_master_process, *processes, candidate_process, old):
                if process is not None and not any(process is prior for prior in cleanup_processes):
                    cleanup_processes.append(process)
            for process in cleanup_processes:
                if process is None:
                    continue
                if not isinstance(process, subprocess.Popen):
                    try:
                        os.kill(process.pid, 9)
                    except ProcessLookupError:
                        pass
                    continue
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=2)
                if process.stdout is not None: process.stdout.close()
                if process.stderr is not None: process.stderr.close()

    def test_stage_then_atomic_commit_preserves_old_route_as_peer(self):
        self.run_case()

    def test_late_prepare_after_empty_source_poll_is_not_consumed_by_legacy_peer_reader(self):
        self.run_case(late_route_arrival=True)

    def test_abort_and_inflight_commit_keep_old_route(self):
        self.run_case(abort=True)
        self.run_case(inflight=True)

    def test_deferred_commit_waits_for_one_old_frame_then_commits_next_candidate(self):
        self.run_case(inflight=True, deferred_commit=True)

    def test_deferred_commit_expiry_or_dead_candidate_never_swaps(self):
        self.run_case(inflight=True, deferred_commit=True, deferred_expired=True)
        self.run_case(inflight=True, deferred_commit=True, deferred_dead_candidate=True)

    def test_late_old_frame_completion_cannot_authorize_source_route_swap(self):
        self.run_case(inflight=True, deferred_commit=True, deferred_late_completion=True)

    def test_second_deferred_terminal_cancels_first_without_replacing_proof(self):
        self.run_case(inflight=True, deferred_commit=True, deferred_second_command=True)

    def test_one_epoch2_retry_requires_aborted_epoch1_candidate_to_be_dead(self):
        self.run_case(abort=True, abort_retry=True)

    def test_one_epoch2_successor_requires_committed_lineage_and_dead_prior_peer(self):
        self.run_case(successor=True, candidate_mode='peer')

    def test_successor_prepare_preserves_inflight_frame_until_after_frame_commit(self):
        self.run_case(successor_inflight=True, candidate_mode='peer')

    def test_successor_prepare_rejects_dead_current_route(self):
        self.run_case(successor_dead_current=True, candidate_mode='peer')

    def test_second_successor_after_epoch2_commit_is_rejected(self):
        self.run_case(successor_second=True, candidate_mode='peer')

    def test_replayed_successor_commit_gets_no_ack_and_does_not_change_route(self):
        self.run_case(successor_replay=True, candidate_mode='peer')

    def test_missing_dead_and_expired_candidate_auth_preserve_old_route(self):
        self.run_case(candidate_mode='no-ack', short_deadline=True)
        self.run_case(candidate_mode='late-ack', short_deadline=True)
        self.run_case(kill_after_stage=True)

    def test_active_route_revokes_candidate_and_peer_at_finite_authority_deadline(self):
        self.run_case(expire_after_commit=True)

    def test_master_death_revokes_candidate_and_peer_while_workers_remain(self):
        self.run_case(master_death_after_commit=True)

    def test_expired_commit_preserves_old_route_before_valid_commit(self):
        self.run_case(expired_commit=True)

    def test_pause_across_commit_deadline_quarantines_both_routes(self):
        self.run_case(late_swap=True)

    def test_host_proof_delay_after_ack_is_unknown_even_after_completed_swap(self):
        self.run_case(late_observation=True)


class SourceRouteCommitReceiptModelTests(unittest.TestCase):
    """Host socketpair model only; it does not qualify OriginalShellLaunch."""

    def setUp(self):
        if RECEIVER is None:
            self.skipTest('receiver path is supplied by the native CTest invocation')

    def test_actual_prepare_ack_is_frozen_before_modeled_park_and_commit(self):
        SourceRoute.run_case(self, typed_handoff=True)

    def test_private_controller_activation_gate_with_modeled_worker_and_c31(self):
        SourceRoute.run_case(self, typed_handoff=True,
            production_private_controller=True)

    def test_private_controller_composes_c31_prepared_and_worker_activate(self):
        if not ACTIVATION_RECEIVER or RECEIVER is None:
            self.skipTest('compiled worker activation and C31 fixtures required')
        SourceRoute.run_case(self, typed_handoff=True,
            production_private_controller=True, native_activation=True)

    def test_owned_master_listener_parks_after_actual_c31_prepared_with_modeled_c28_reply(self):
        SourceRoute.run_case(self, typed_handoff=True,
            production_private_controller=True, private_master_park=True)

    def test_owned_master_listener_composes_real_c31_commit_ack_and_modeled_c28_commit(self):
        SourceRoute.run_case(self, typed_handoff=True,
            production_private_controller=True, private_master_park=True,
            private_master_commit=True)

    def test_worker_accepts_only_the_matching_commit_evidence_after_activation(self):
        if not ACTIVATION_RECEIVER or RECEIVER is None:
            self.skipTest('compiled worker activation and C31 fixtures required')
        for fault in (None, 'worker-proof'):
            with self.subTest(fault=fault):
                SourceRoute.run_case(self, typed_handoff=True,
                    production_private_controller=True, private_master_park=True,
                    private_master_commit=True, private_master_commit_fault=fault,
                    native_activation=True)

    def test_private_commit_rejects_deadline_and_provider_mismatch_before_c31(self):
        for fault in ('deadline', 'wrong-provider'):
            with self.subTest(fault=fault):
                SourceRoute.run_case(self, typed_handoff=True,
                    production_private_controller=True, private_master_park=True,
                    private_master_commit=True, private_master_commit_fault=fault)

    def test_private_commit_candidate_evidence_failure_is_partial_and_unresolved(self):
        SourceRoute.run_case(self, typed_handoff=True,
            production_private_controller=True, private_master_park=True,
            private_master_commit=True, private_master_commit_fault='evidence')

    def test_private_commit_replay_is_consumed_after_success(self):
        SourceRoute.run_case(self, typed_handoff=True,
            production_private_controller=True, private_master_park=True,
            private_master_commit=True, private_master_commit_fault='duplicate')

    def test_private_master_abort_requires_native_adoption_and_c31_ack(self):
        if RECEIVER is None:
            self.skipTest('compiled C31 fixture required')
        for outcome in ('success', 'retry-renewed', 'retry-c28-unknown', 'bad-ready',
                'production', 'wrong-helper', 'unknown-adoption', 'unknown-c31'):
            with self.subTest(outcome=outcome):
                SourceRoute.run_case(self, typed_handoff=True,
                    production_private_controller=True, private_master_park=True,
                    private_master_abort=outcome)

    def test_owned_master_listener_consumes_and_quarantines_postrecv_failures(self):
        for fault in ('setblocking', 'precheck', 'wrong-provider', 'deadline',
                'park-unknown', 'ack-error', 'late-ack'):
            with self.subTest(fault=fault):
                SourceRoute.run_case(self, typed_handoff=True,
                    production_private_controller=True, private_master_park=True,
                    private_master_fault=fault)

    def test_sender_cloexec_remains_required_after_prepared_ack(self):
        SourceRoute.run_case(self, typed_handoff=True,
            typed_post_ack_clear_cloexec=True)

    def test_deleted_typed_binding_cannot_fall_back_to_legacy_send(self):
        SourceRoute.run_case(self, typed_handoff=True, drop_typed_binding=True)

    def test_copied_typed_binding_cannot_authorize_source_send(self):
        SourceRoute.run_case(self, typed_handoff=True, copy_typed_binding=True)

    def test_live_but_wrong_context_runtime_is_rejected_before_any_send(self):
        SourceRoute.run_case(self, typed_handoff=True,
            typed_bad_context_actor=True)

    def test_wrong_candidate_cycle_object_and_context_key_are_rejected(self):
        for tamper in ('candidate-proof-copy', 'candidate-generation',
                'candidate-source-epoch', 'candidate-role', 'candidate-pidfd',
                'missing-context', 'missing-proof', 'pre-park', 'epoch-two',
                'retry-lineage', 'successor', 'wrong-master-actor', 'wrong-supervisor-actor',
                'noncanonical-context', 'blocking-endpoint',
                'blocking-candidate-channel', 'park-only',
                'context-deadline-short', 'expired-context-deadline',
                'overwide-route-deadline', 'stale-live-callback',
                'candidate-endpoint-alias', 'wrong-channel-owner'):
            SourceRoute.run_case(self, typed_handoff=True,
                typed_context_tamper=tamper)

    def test_after_frame_commit_authorizes_c28_with_its_correlated_ack(self):
        SourceRoute.run_case(self, typed_handoff=True,
            typed_command_type=ker_run._RX_OWNER_SOURCE_ROUTE_COMMIT_AFTER_FRAME)

    def test_c28_commit_requires_monotonic_receive_and_full_acceptance(self):
        for counts in ((1, 1), (3, 2)):
            with self.subTest(received=counts[0], accepted=counts[1]):
                SourceRoute.run_case(self, typed_handoff=True,
                    typed_c28_counts=counts)

    def test_abort_and_negative_ack_never_mint_receipts(self):
        SourceRoute.run_case(self, typed_handoff=True,
            typed_command_type=ker_run._RX_OWNER_SOURCE_ROUTE_ABORT)
        SourceRoute.run_case(self, typed_handoff=True, typed_ack_status=-errno.EBUSY)
        SourceRoute.run_case(self, typed_handoff=True, typed_ack_status=-errno.ETIMEDOUT,
            typed_command_type=ker_run._RX_OWNER_SOURCE_ROUTE_COMMIT_AFTER_FRAME)

    def test_malformed_or_late_commit_ack_never_mints_receipt(self):
        for fault in ('short', 'eof', 'extra-fd', 'wrong-sequence', 'late'):
            with self.subTest(fault=fault):
                SourceRoute.run_case(self, typed_handoff=True,
                    typed_ack_fault=fault)

    def test_ordinary_ack_cannot_settle_after_frame_commit(self):
        SourceRoute.run_case(self, typed_handoff=True, typed_ack_fault='wrong-kind',
            typed_command_type=ker_run._RX_OWNER_SOURCE_ROUTE_COMMIT_AFTER_FRAME)

    def test_credentialed_commit_ack_mints_and_consumes_once(self):
        provider_spec = importlib.util.spec_from_file_location(
            'c31_route_handoff_provider', ROOT / 'tools/nginx_source_c22_provider.py')
        provider_module = importlib.util.module_from_spec(provider_spec)
        sys.modules[provider_spec.name] = provider_module
        provider_spec.loader.exec_module(provider_module)

        candidate_process = subprocess.Popen([sys.executable, '-c',
            'import time; time.sleep(30)'], stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        current_pidfd = os.pidfd_open(os.getpid(), 0)
        candidate_pidfd = os.pidfd_open(candidate_process.pid, 0)
        sockets = []
        try:
            current_slot, current_slot_peer = socket.socketpair(
                socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
            candidate_slot, candidate_slot_peer = socket.socketpair(
                socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
            endpoint, responder = socket.socketpair(socket.AF_UNIX,
                socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
            candidate_relay, candidate_relay_peer = socket.socketpair(socket.AF_UNIX,
                socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
            park_channel, park_peer = socket.socketpair(socket.AF_UNIX,
                socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
            sockets.extend((current_slot, current_slot_peer, candidate_slot,
                candidate_slot_peer, endpoint, responder, candidate_relay,
                candidate_relay_peer, park_channel, park_peer))
            for channel in (endpoint, park_channel, park_peer):
                channel.setblocking(False)
            responder.setblocking(True)
            endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)

            context = source_bootstrap.SourceBootstrapSupervisor.__new__(
                source_bootstrap.SourceBootstrapSupervisor)
            context.shell_mode = True
            context.nonce = NONCE
            context.epoch = 77
            park_deadline = time.monotonic_ns() + 700_000_000
            context.deadline_ns = park_deadline + 5_000_000_000
            context.live = lambda _observation_deadline_ns=None: None
            self_start = ker_run.process_start_ticks(os.getpid())
            context.supervisor_start = self_start
            context.master = SimpleNamespace(pid=os.getpid(), start_ticks=self_start,
                pidfd=current_pidfd)
            context.runtime = SimpleNamespace(pid=os.getpid(), start_ticks=self_start,
                pidfd=current_pidfd)
            current_proof = source_bootstrap.SourceCycleProof(1, 0, 1, 2,
                b'a' * 32, b'b' * 32)
            cycle_proof = source_bootstrap.SourceCycleProof(1, 0, 2, 3,
                b'a' * 32, b'b' * 32)
            context.initial_cycle_proof = current_proof
            context.worker_proofs = {}
            context.workers = {}
            context._source_route_preparations = {}
            context._source_route_park_joins = {}
            context._source_route_commit_receipts = {}
            context._source_route_commit_consumed = set()
            context._source_route_sequences = {}

            provider = provider_module.SourceShellC22Provider.__new__(
                provider_module.SourceShellC22Provider)
            provider.context = context
            provider._source_park_deadline_ns = park_deadline
            provider._source_park_evidence = None
            current_start = self_start
            candidate_start = ker_run.process_start_ticks(candidate_process.pid)
            park_response = {'phase': 1, 'lease': 0x1234, 'listener_cookie': 0,
                'received': 3, 'accepted': 0}
            park_bundle = {'record': b'r' * 108,
                'credentials': (os.getpid(), os.getuid(), os.getgid()),
                'fds': ((1, 2, 3), (4, 5, 6), (7, 8, 9))}
            provider_actor = (os.getpid(), current_start)
            helper_actor = (candidate_process.pid, candidate_start,
                candidate_pidfd, b'h' * 32)
            park = source_bootstrap._make_source_c28_park_evidence(context, provider,
                park_response, park_bundle, park_channel, provider_actor, helper_actor)
            for bad_park_response in (
                    {**park_response, 'lease': 0},
                    {**park_response, 'accepted': 2}):
                with self.assertRaises(PermissionError):
                    source_bootstrap._make_source_c28_park_evidence(context, provider,
                        bad_park_response, park_bundle, park_channel,
                        provider_actor, helper_actor)
            original_park_deadline = provider._source_park_deadline_ns
            provider._source_park_deadline_ns = context.deadline_ns + 1
            with self.assertRaises(PermissionError):
                source_bootstrap._make_source_c28_park_evidence(context, provider,
                    park_response, park_bundle, park_channel,
                    provider_actor, helper_actor)
            provider._source_park_deadline_ns = original_park_deadline
            provider._source_park_evidence = park

            def slot_identity(channel):
                info = os.fstat(channel.fileno())
                cookie = struct.unpack('=Q', channel.getsockopt(socket.SOL_SOCKET,
                    getattr(socket, 'SO_COOKIE', 57), 8))[0]
                return info.st_dev, info.st_ino, cookie

            current_dev, current_ino, current_cookie = slot_identity(current_slot)
            candidate_dev, candidate_ino, candidate_cookie = slot_identity(candidate_slot)
            current = SimpleNamespace(owner_pid=os.getpid(), owner_tid=os.getpid(),
                owner_role=0, owner_start=current_start,
                owner_slot_device=current_dev, owner_slot_inode=current_ino,
                owner_cookie=current_cookie, owner_pidfd=current_pidfd)
            candidate = SimpleNamespace(owner_pid=candidate_process.pid,
                owner_tid=candidate_process.pid, owner_role=1,
                owner_start=candidate_start, owner_slot_device=candidate_dev,
                owner_slot_inode=candidate_ino, owner_cookie=candidate_cookie,
                owner_pidfd=candidate_pidfd)
            def source_worker_record(owner):
                record = [0] * 28
                record[8], record[9] = ((0, 0) if owner.owner_role == 0 else (1, 1))
                record[5], record[6], record[11] = (owner.owner_pid,
                    owner.owner_tid, owner.owner_start)
                record[14:17] = (context.epoch, context.deadline_ns, context.nonce)
                record[24], record[25], record[27] = (owner.owner_slot_device,
                    owner.owner_slot_inode, owner.owner_cookie)
                return tuple(record)
            context.workers = {(0, 0): (current_pidfd, source_worker_record(current)),
                (1, 1): (candidate_pidfd, source_worker_record(candidate))}
            context.worker_proofs = {(0, 0): current_proof, (1, 1): cycle_proof}
            fields = [ker_run._RX_OWNER_AUTH_MAGIC, ker_run._RX_OWNER_AUTH_VERSION,
                ker_run._RX_OWNER_SOURCE_ROUTE_PREPARE,
                ker_run._RX_OWNER_SOURCE_ROUTE_RECORD.size, os.getpid(),
                candidate.owner_pid, candidate.owner_tid, candidate.owner_role, 0,
                context.epoch, current_start, candidate_start, candidate_dev,
                candidate_ino, candidate_cookie, NONCE, current.owner_pid,
                current.owner_tid, current_start, current_dev, current_ino,
                current_cookie, context.deadline_ns]
            prepared = SimpleNamespace(fields=fields, operation_id=9001,
                command_sequence=1, master_start=current_start, master_pid=os.getpid(),
                source_epoch=1, app_pid=os.getpid(), app_start=current_start,
                app_pidfd=current_pidfd, supervisor_pid=os.getpid(),
                supervisor_start=current_start, candidate_pidfd=candidate_pidfd,
                aborted=False, committed=False, last_command_type=None,
                last_status=None)
            expected_prepared_fields = fields.copy()
            expected_prepared_fields[2] = ker_run._RX_OWNER_SOURCE_ROUTE_PREPARED
            expected_prepared = ker_run._RX_OWNER_SOURCE_ROUTE_RECORD.pack(
                *expected_prepared_fields, prepared.operation_id,
                prepared.command_sequence, current_start, os.getpid(), 1, 0, 0, 0)
            preparation = source_bootstrap._make_source_route_preparation(context,
                None, prepared, tuple(fields), 1,
                (current, current.owner_pid, current.owner_tid, current.owner_role,
                    current.owner_start, current.owner_slot_device,
                    current.owner_slot_inode, current.owner_cookie, current.owner_pidfd),
                (candidate, candidate.owner_pid, candidate.owner_tid,
                    candidate.owner_role, candidate.owner_start,
                    candidate.owner_slot_device, candidate.owner_slot_inode,
                    candidate.owner_cookie, candidate.owner_pidfd),
                cycle_proof, endpoint, candidate_relay,
                (os.getpid(), current_start, current_pidfd,
                    os.getpid(), current_start, current_pidfd,
                    os.getpid(), current_start, current_pidfd),
                expected_prepared, expected_prepared,
                (os.getpid(), os.getuid(), os.getgid()))
            prepared._source_route_preparation = \
                source_bootstrap._register_source_route_preparation(preparation)
            ker_run._SOURCE_ROUTE_PREPARATIONS[id(prepared)] = (
                prepared, context, prepared._source_route_preparation)
            prepared._source_route_commit_receipt = None
            provider_module.SourceShellC22Provider.bind_source_route_preparation(
                provider, prepared)

            def responder_loop():
                for status in (-errno.EBUSY, 0):
                    request = responder.recv(ker_run._RX_OWNER_SOURCE_ROUTE_RECORD.size)
                    record = list(ker_run._RX_OWNER_SOURCE_ROUTE_RECORD.unpack(request))
                    record[2] = ker_run._RX_OWNER_SOURCE_ROUTE_COMMITTED
                    record[28] = status
                    responder.send(ker_run._RX_OWNER_SOURCE_ROUTE_RECORD.pack(*record))

            responder_thread = threading.Thread(target=responder_loop, daemon=True)
            responder_thread.start()
            first = ker_run.send_source_route_command(endpoint, prepared,
                ker_run._RX_OWNER_SOURCE_ROUTE_COMMIT, 2, park_deadline)
            self.assertEqual(first, -errno.EBUSY)
            self.assertIsNone(prepared._source_route_commit_receipt)
            second = ker_run.send_source_route_command(endpoint, prepared,
                ker_run._RX_OWNER_SOURCE_ROUTE_COMMIT, 3, park_deadline)
            self.assertEqual(second, 0)
            responder_thread.join(timeout=1)
            self.assertFalse(responder_thread.is_alive())
            receipt = prepared._source_route_commit_receipt
            self.assertIs(type(receipt), source_bootstrap._SourceRouteCommitReceipt)
            self.assertEqual(receipt.raw_ack, receipt.expected_record)
            self.assertEqual(receipt.credentials,
                (os.getpid(), os.getuid(), os.getgid()))

            forged = receipt._replace(status=1)
            with self.assertRaises(PermissionError):
                source_bootstrap._consume_source_route_commit_receipt(
                    forged, provider, park_deadline)
            copied_receipt = receipt._replace()
            with self.assertRaises(PermissionError):
                source_bootstrap._consume_source_route_commit_receipt(
                    copied_receipt, provider, park_deadline)
            wrong_endpoint_receipt = receipt._replace(endpoint_identity=(0,))
            with self.assertRaises(PermissionError):
                source_bootstrap._consume_source_route_commit_receipt(
                    wrong_endpoint_receipt, provider, park_deadline)
            provider._source_command_abi = provider_module._C28_SOURCE_COMMAND_ABI
            provider._source_committed = False
            provider._source_route_receipt_consumed = False
            provider._source_command_unresolved = False
            provider._check_actor = lambda deadline: None
            def uncertain_native_commit(operation, deadline):
                raise TimeoutError('modeled unknown native outcome')
            provider._source_c28_command = uncertain_native_commit
            with self.assertRaises(TimeoutError):
                provider.commit_source_group_before(park_deadline, receipt)
            self.assertTrue(provider._source_route_receipt_consumed)
            with self.assertRaises(PermissionError):
                provider.commit_source_group_before(park_deadline, receipt)
        finally:
            candidate_process.kill()
            candidate_process.wait(timeout=2)
            for descriptor in (current_pidfd, candidate_pidfd):
                os.close(descriptor)
            for channel in sockets:
                channel.close()


def main():
    global RECEIVER
    parser = argparse.ArgumentParser()
    parser.add_argument('--receiver')
    args, remaining = parser.parse_known_args()
    RECEIVER = args.receiver
    unittest.main(argv=[sys.argv[0], *remaining])


if __name__ == '__main__':
    main()
