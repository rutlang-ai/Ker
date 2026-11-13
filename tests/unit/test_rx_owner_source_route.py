#!/usr/bin/env python3
"""Real-process controls for C31's pending same-master source route."""
import argparse
import array
import copy
import errno
import importlib.util
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
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
NONCE = bytes(range(16))

ACTOR = r'''
import array, os, socket, struct, sys, time
s=socket.socket(fileno=int(sys.argv[1])); s.setblocking(True); mode=sys.argv[2]
if mode=='dead': sys.exit(0)
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
                 successor_inflight=False):
        successor = (successor or successor_dead_current or successor_second or
            successor_replay or successor_inflight)
        control, app_control = pair()
        old_channel, old_worker_channel = pair()
        candidate_channel, candidate_worker_channel = pair()
        old_slot, candidate_slot = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        marker_read, marker_write = os.pipe()
        app = old = candidate_process = source_master_process = None
        processes = []
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
                candidate_process = subprocess.Popen([sys.executable, '-c', ACTOR,
                    str(candidate_worker_channel.fileno()), candidate_mode], pass_fds=(candidate_worker_channel.fileno(),),
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
                    **({'KER_TEST_SOURCE_ROUTE_RETRY': '1'} if abort_retry else {}),
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
            app = subprocess.Popen([RECEIVER], pass_fds=tuple(app_pass_fds),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env={**os.environ, **app_env})
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
            prepared = ker_run.rx_owner_source_route_prepare(route_endpoint,
                candidate_channel, app, app_pidfd, supervisor_pidfd,
                current, candidate, source_master, NONCE, 77, deadline,
                operation_id=1234)
            self.assertEqual(os.read(marker_read, 1), b'P')
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
                        import select
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
            for fd in handles:
                os.close(fd)
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


def main():
    global RECEIVER
    parser = argparse.ArgumentParser()
    parser.add_argument('--receiver')
    args, remaining = parser.parse_known_args()
    RECEIVER = args.receiver
    unittest.main(argv=[sys.argv[0], *remaining])


if __name__ == '__main__':
    main()
