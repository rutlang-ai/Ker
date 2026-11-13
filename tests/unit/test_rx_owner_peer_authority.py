#!/usr/bin/env python3
"""Real-process tests of the opt-in peer authority and relay wire boundary.

Workers model READY/relay messages only. No Nginx classifier or TCP behavior
is implemented or claimed by these transport/authority tests.
"""
import argparse
import array
import importlib.util
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('ker_run_peer_test', ROOT / 'tools/ker-run.py')
ker_run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ker_run)
RECEIVER = None
NONCE = bytes(range(16))

ACTOR = r'''
import array, os, socket, struct, sys
s=socket.socket(fileno=int(sys.argv[1])); mode=sys.argv[2]
w=struct.Struct('=IHHQQ16sQQQQIIIIIHHHHIiHBB')
p,anc,flags,_=s.recvmsg(w.size+1,socket.CMSG_SPACE(12)+socket.CMSG_SPACE(8))
fds=[]; creds=[]
for level,kind,data in anc:
 if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
  a=array.array('i'); a.frombytes(data); fds.extend(a)
 elif level==socket.SOL_SOCKET and kind==socket.SCM_CREDENTIALS: creds.append(struct.unpack('=3i',data))
h=list(w.unpack(p))
assert not flags & (socket.MSG_TRUNC|socket.MSG_CTRUNC)
assert len(fds)==2 and creds==[(os.getppid(),os.getuid(),os.getgid())]
assert h[2]==3 and h[11]==h[12]==os.getpid()
assert 'Pid:\t'+str(h[10])+'\n' in open('/proc/self/fdinfo/'+str(fds[0])).read()
assert 'Pid:\t'+str(h[13])+'\n' in open('/proc/self/fdinfo/'+str(fds[1])).read()
if len(sys.argv)>3: os.write(int(sys.argv[3]), b'R')
if mode=='no-ack':
 try: s.recv(1)
 except ConnectionResetError: pass
else:
 h[2]=5
 if mode=='bad-ack': h[7]+=1
 me=os.pidfd_open(os.getpid())
 s.sendmsg([w.pack(*h)],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[me]))]); os.close(me)
 if mode in ('valid','peer-loop'):
  try: p=s.recv(w.size+9022)
  except ConnectionResetError: p=b''
  if p:
   q=list(w.unpack(p[:w.size])); frame=p[w.size:]
   assert q[2]==1 and q[11]==q[12]==os.getpid() and q[3]==1 and q[14]==len(frame)==64
   assert q[5:14]==h[5:14] and frame==bytes(range(64))
   v=2166136261
   for b in frame: v=((v^b)*16777619)&0xffffffff
   q[2]=2; q[19]=v; q[20]=-3 if mode=='peer-loop' else 0; q[23]=1
   s.send(w.pack(*q)+frame)
 try: s.recv(1)
 except ConnectionResetError: pass
for f in fds: os.close(f)
'''


def pair():
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK)
    for s in (a, b): s.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    return a, b


def proof(process, slot, role):
    st = os.fstat(slot.fileno())
    return SimpleNamespace(owner_pid=process.pid, owner_tid=process.pid,
        owner_start=ker_run.process_start_ticks(process.pid), owner_role=role,
        owner_pidfd=os.pidfd_open(process.pid), owner_slot_device=st.st_dev,
        owner_slot_inode=st.st_ino, owner_cookie=struct.unpack('=Q',
            slot.getsockopt(socket.SOL_SOCKET, 57, 8))[0])


class CorruptAck:
    def __init__(self, endpoint): self.endpoint = endpoint
    def fileno(self): return self.endpoint.fileno()
    def sendmsg(self, *args): return self.endpoint.sendmsg(*args)
    def recvmsg(self, *args):
        packet, anc, flags, addr = self.endpoint.recvmsg(*args)
        fields = list(ker_run._RX_OWNER_PEER_AUTH_RECORD.unpack(packet))
        fields[21] ^= 1  # Current candidate cookie must be correlated too.
        return ker_run._RX_OWNER_PEER_AUTH_RECORD.pack(*fields), anc, flags, addr


class PeerAuthority(unittest.TestCase):
    def setUp(self):
        if RECEIVER is None:
            self.skipTest('receiver path is supplied by the native CTest invocation')

    def run_case(self, mode):
        control, app_control = pair()
        primary_channel, primary_worker = pair()
        old_channel, old_worker = pair()
        slot0, slot1 = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        old_ready_read, old_ready_write = os.pipe()
        primary = old = app = None
        proofs = []
        handles = []
        socks = [control, app_control, primary_channel, primary_worker,
            old_channel, old_worker, slot0, slot1]
        expected = -71 if mode in ('role', 'epoch', 'nonce', 'trailing', 'rights', 'bad-ack', 'foreign-supervisor') else (
            -91 if mode == 'stream-channel' else -110 if mode == 'no-ack' else
            -116 if mode not in ('valid', 'peer-loop', 'corrupt-control-ack', 'passcred') else 0)
        try:
            primary_worker.setblocking(True); old_worker.setblocking(True)
            primary = subprocess.Popen([sys.executable, '-c', ACTOR, str(primary_worker.fileno()), 'primary'],
                pass_fds=(primary_worker.fileno(),), stderr=subprocess.PIPE)
            actor_mode = mode if mode in ('bad-ack', 'no-ack', 'peer-loop') else 'valid'
            old = subprocess.Popen([sys.executable, '-c', ACTOR, str(old_worker.fileno()), actor_mode,
                    str(old_ready_write)], pass_fds=(old_worker.fileno(), old_ready_write),
                stderr=subprocess.PIPE)
            os.close(old_ready_write); old_ready_write = -1
            primary_worker.close(); old_worker.close()
            current = proof(primary, slot1, 1); previous = proof(old, slot0, 0)
            proofs.extend([current, previous])
            start = ker_run.process_start_ticks(os.getpid())
            app = subprocess.Popen([RECEIVER], pass_fds=(app_control.fileno(), primary_channel.fileno()),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={**os.environ,
                    'KER_RX_OWNER_AUTH_FD': str(app_control.fileno()),
                    'KER_RX_OWNER_RELAY_FD': str(primary_channel.fileno()),
                    'KER_TEST_PEER_SUPERVISOR_PID': str(os.getpid()),
                    'KER_TEST_PEER_SUPERVISOR_START': str(start),
                    'KER_TEST_PEER_EXPECT_STATUS': str(expected),
                    'KER_TEST_PEER_EXPECT_ACTION': '2' if mode == 'peer-loop' else '1',
                    **({'KER_TEST_PEER_DUPLICATE': '1'} if mode == 'duplicate' else {})})
            app_control.close()
            app_pidfd = os.pidfd_open(app.pid); supervisor_pidfd = os.pidfd_open(os.getpid())
            handles.extend([app_pidfd, supervisor_pidfd])
            ker_run.rx_owner_expected_auth(control, app, app_pidfd, supervisor_pidfd,
                current, NONCE, 77, start)
            ker_run.rx_owner_relay_auth(primary_channel, app, app_pidfd, supervisor_pidfd,
                current, NONCE, 77)
            primary_channel.close()
            if mode in ('valid', 'peer-loop', 'corrupt-control-ack', 'lease-expiry', 'duplicate', 'passcred'):
                if mode == 'passcred': old_channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 0)
                if mode == 'duplicate':
                    duplicate = socket.socket(fileno=os.dup(old_channel.fileno())); socks.append(duplicate)
                if mode == 'corrupt-control-ack':
                    with self.assertRaises(PermissionError):
                        ker_run.rx_owner_peer_auth(CorruptAck(control), old_channel, app, app_pidfd,
                            supervisor_pidfd, current, previous, NONCE, 77, time.monotonic_ns()+10_000_000_000)
                    self.assertGreaterEqual(old_channel.fileno(), 0)
                else:
                    ker_run.rx_owner_peer_auth(control, old_channel, app, app_pidfd, supervisor_pidfd,
                        current, previous, NONCE, 77, time.monotonic_ns()+
                            (700_000_000 if mode == 'lease-expiry' else 10_000_000_000))
                    self.assertEqual(old_channel.fileno(), -1)
                if mode == 'lease-expiry': time.sleep(.8)
                if mode == 'duplicate':
                    fields = [ker_run._RX_OWNER_AUTH_MAGIC, 1, 3, 144, os.getpid(), previous.owner_pid,
                        previous.owner_tid, 0, 0, 77, start, previous.owner_start,
                        previous.owner_slot_device, previous.owner_slot_inode, previous.owner_cookie, NONCE,
                        current.owner_pid, current.owner_tid, current.owner_start,
                        current.owner_slot_device, current.owner_slot_inode, current.owner_cookie,
                        time.monotonic_ns()+10_000_000_000]
                    control.sendmsg([ker_run._RX_OWNER_PEER_AUTH_RECORD.pack(*fields)],
                        [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i',
                            [previous.owner_pidfd, duplicate.fileno()]))])
                else: control.send(b'CONTINUE')
            else:
                fields = [ker_run._RX_OWNER_AUTH_MAGIC, 1, 3, 144, os.getpid(), previous.owner_pid,
                    previous.owner_tid, 0, 0, 77, start, previous.owner_start,
                    previous.owner_slot_device, previous.owner_slot_inode, previous.owner_cookie, NONCE,
                    current.owner_pid, current.owner_tid, current.owner_start,
                    current.owner_slot_device, current.owner_slot_inode, current.owner_cookie,
                    time.monotonic_ns() + (300_000_000 if mode == 'no-ack' else 10_000_000_000)]
                mutations = {'role': (7, 1), 'epoch': (9, 78), 'nonce': (15, b'x'*16),
                    'primary-pid': (16, current.owner_pid+1), 'primary-tid': (17, current.owner_tid+1),
                    'primary-start': (18, current.owner_start+1), 'primary-slot': (20, current.owner_slot_inode+1),
                    'primary-cookie': (21, current.owner_cookie+1), 'old-start': (11, previous.owner_start+1),
                    'old-tid': (6, 0xffffffff), 'same-cookie': (14, current.owner_cookie),
                    'expired': (22, time.monotonic_ns()-1), 'unbounded': (22, time.monotonic_ns()+301_000_000_000)}
                if mode in mutations:
                    index, value = mutations[mode]; fields[index] = value
                rights = [previous.owner_pidfd, old_channel.fileno()]
                if mode == 'wrong-pidfd': rights[0] = current.owner_pidfd
                if mode == 'rights': rights.append(supervisor_pidfd)
                if mode == 'stream-channel':
                    stream, stream_other = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
                    socks.extend([stream, stream_other]); rights[1] = stream.fileno()
                packet = ker_run._RX_OWNER_PEER_AUTH_RECORD.pack(*fields)
                if mode == 'trailing': packet += b'x'
                # Bootstrap first so immediate receiver rejection cannot race
                # the actor's pidfd identity assertion during teardown.
                ker_run.rx_owner_relay_auth(old_channel, app, app_pidfd, supervisor_pidfd,
                    previous, NONCE, 77)
                self.assertEqual(os.read(old_ready_read, 1), b'R')
                if mode == 'foreign-supervisor':
                    sender = os.fork()
                    if sender == 0:
                        control.sendmsg([packet], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', rights))])
                        os._exit(0)
                    self.assertEqual(os.waitpid(sender, 0), (sender, 0))
                else:
                    control.sendmsg([packet], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', rights))])
            stdout, stderr = app.communicate(timeout=6)
            self.assertEqual(app.returncode, 0, (stdout, stderr))
            self.assertIn(f'PEER_AUTH_RECEIVER status={expected}', stderr.decode())
        finally:
            for s in socks: s.close()
            for f in handles: os.close(f)
            os.close(old_ready_read)
            if old_ready_write >= 0: os.close(old_ready_write)
            for p in proofs: os.close(p.owner_pidfd)
            for process in (app, primary, old):
                if process is None: continue
                try: process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(timeout=2)
                if process.stderr is not None:
                    if process is not app:
                        errors = process.stderr.read()
                        self.assertEqual(process.returncode, 0, errors)
                    process.stderr.close()

    def test_real_binding_and_one_hop_dispositions(self):
        for mode in ('valid', 'peer-loop', 'corrupt-control-ack', 'lease-expiry', 'duplicate', 'passcred'):
            with self.subTest(mode=mode): self.run_case(mode)

    def test_authority_context_and_descriptor_controls(self):
        for mode in ('role', 'epoch', 'nonce', 'primary-pid', 'primary-tid', 'primary-start',
                'primary-slot', 'primary-cookie', 'old-start', 'old-tid', 'same-cookie',
                'wrong-pidfd', 'expired', 'unbounded', 'trailing', 'rights', 'stream-channel',
                'bad-ack', 'no-ack', 'foreign-supervisor'):
            with self.subTest(mode=mode): self.run_case(mode)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--receiver', required=True)
    args, rest = parser.parse_known_args()
    RECEIVER = args.receiver
    unittest.main(argv=[sys.argv[0], *rest])
