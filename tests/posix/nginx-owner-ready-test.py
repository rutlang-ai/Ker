"""Production sender integration and adversarial READY receiver checks."""
import array
import importlib.util
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import unittest

spec = importlib.util.spec_from_file_location('ready', Path(__file__).with_name('nginx-owner-ready.py'))
ready = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ready)
HELPER = sys.argv.pop() if len(sys.argv) > 1 else None


class Receiver(unittest.TestCase):
    def setUp(self):
        self.slot, self.slot_write = os.pipe()
        self.pidfd = os.pidfd_open(os.getpid())
        self.expected = dict(pid=os.getpid(), pidfd=self.pidfd,
            slot_identity=os.fstat(self.slot_write), endpoint_cookie=123, role=1,
            owner_tid=os.getpid())
        self.fields = [ready.MAGIC, 2, 64, 1, 0, self.expected['slot_identity'].st_dev,
            self.expected['slot_identity'].st_ino, ready.start_ticks(os.getpid()), os.getpid(), os.getpid(), 123, 0]
        self.credentials = [(socket.SOL_SOCKET, socket.SCM_CREDENTIALS,
            struct.pack('=3i', os.getpid(), os.getuid(), os.getgid()))]

    def tearDown(self):
        for fd in (self.slot, self.slot_write, self.pidfd): os.close(fd)

    def check(self, data=None, ancillary=None, flags=0):
        return ready.validate(ready.WIRE.pack(*self.fields) if data is None else data,
            self.credentials if ancillary is None else ancillary, flags, **self.expected)

    def test_valid(self):
        self.assertEqual(self.check()['pid'], os.getpid())

    def test_each_wrong_field(self):
        for index in range(len(self.fields)):
            with self.subTest(field=index):
                self.fields[index] += 1
                with self.assertRaises(RuntimeError): self.check()
                self.fields[index] -= 1

    def test_bad_frame_and_credentials(self):
        for data in (b'', ready.WIRE.pack(*self.fields)[:-1], ready.WIRE.pack(*self.fields) + b'x'):
            with self.assertRaises(RuntimeError): self.check(data=data)
        for ancillary in ([], self.credentials * 2,
                [(socket.SOL_SOCKET, socket.SCM_CREDENTIALS, b'x')],
                [(socket.SOL_SOCKET, socket.SCM_CREDENTIALS, struct.pack('=3i', os.getpid() + 1, os.getuid(), os.getgid()))],
                self.credentials + [(socket.SOL_SOCKET, 999, b'')]):
            with self.assertRaises(RuntimeError): self.check(ancillary=ancillary)
        for flag in (socket.MSG_TRUNC, socket.MSG_CTRUNC):
            with self.assertRaises(RuntimeError): self.check(flags=flag)

    def test_unexpected_rights_closed_even_on_bad_frame(self):
        fd = os.dup(self.slot)
        ancillary = self.credentials + [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [fd]).tobytes())]
        with self.assertRaises(RuntimeError): self.check(data=b'', ancillary=ancillary)
        with self.assertRaises(OSError): os.fstat(fd)

    def test_real_truncated_rights_do_not_leak(self):
        peer, endpoint = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            peer.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            baseline = len(os.listdir('/proc/self/fd'))
            endpoint.sendmsg([ready.WIRE.pack(*self.fields)], [(socket.SOL_SOCKET,
                socket.SCM_RIGHTS, array.array('i', [self.slot] * 20))])
            with self.assertRaises(RuntimeError):
                ready.receive(peer, timeout=1, **self.expected)
            self.assertEqual(len(os.listdir('/proc/self/fd')), baseline)
        finally:
            peer.close(); endpoint.close()

    def test_exited_worker(self):
        child = subprocess.Popen(['sleep', '10'])
        fd = os.pidfd_open(child.pid)
        try:
            child.terminate(); child.wait()
            self.expected.update(pid=child.pid, pidfd=fd)
            self.fields[8] = child.pid
            self.credentials = [(socket.SOL_SOCKET, socket.SCM_CREDENTIALS,
                struct.pack('=3i', child.pid, os.getuid(), os.getgid()))]
            with self.assertRaisesRegex(RuntimeError, 'exited'): self.check()
        finally:
            child.kill() if child.poll() is None else None
            child.wait(); os.close(fd)


class Transport(unittest.TestCase):
    def test_production_sender(self):
        for mode in ('valid', 'endpoint-reuse', 'pidfd-reuse', 'backpressure', 'dead-peer'):
            with self.subTest(mode=mode):
                peer, endpoint = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                peer.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                cookie = ready.cookie(endpoint)
                slot, writer = os.pipe()
                proc = subprocess.Popen([HELPER, str(endpoint.fileno()), str(writer), mode],
                    pass_fds=(endpoint.fileno(), writer), stdin=subprocess.PIPE, stdout=subprocess.PIPE)
                pidfd = None
                try:
                    endpoint.close()
                    self.assertTrue(select.select([proc.stdout], [], [], 5)[0])
                    line = proc.stdout.readline().decode()
                    self.assertTrue(line.startswith('WORKER '), line)
                    pid = int(line.split()[1]); pidfd = os.pidfd_open(pid)
                    if mode == 'dead-peer': peer.shutdown(socket.SHUT_RDWR)
                    proc.stdin.write(b'1'); proc.stdin.flush()
                    if mode == 'valid':
                        report = ready.receive(peer, timeout=5, pid=pid, pidfd=pidfd,
                            slot_identity=os.fstat(writer), endpoint_cookie=cookie, role=1,
                            owner_tid=pid)
                        self.assertEqual(report['pid'], pid)
                        self.assertEqual(proc.stdout.readline(), b'SENT\n')
                        self.assertEqual(peer.recv(64), b'')  # Exactly one packet, then EOF.
                        proc.stdin.write(b'2'); proc.stdin.flush()
                    self.assertEqual(proc.wait(timeout=5), 0)
                finally:
                    if proc.poll() is None: proc.kill(); proc.wait()
                    proc.stdin.close(); proc.stdout.close()
                    if pidfd is not None: os.close(pidfd)
                    peer.close(); endpoint.close(); os.close(slot); os.close(writer)


if __name__ == '__main__': unittest.main()
