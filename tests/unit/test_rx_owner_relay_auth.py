#!/usr/bin/env python3
import importlib.util
import array
import pathlib
import os
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import socket

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("ker_run_under_test", ROOT / "tools/ker-run.py")
ker_run = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(ker_run)


class Endpoint:
    def __init__(self):
        self.message = None
        self.ancillary = None

    def sendmsg(self, buffers, ancillary, flags):
        self.message = b"".join(buffers)
        self.ancillary = ancillary
        return len(self.message)

    def getblocking(self):
        return False


class RxOwnerRelayAuthTests(unittest.TestCase):
    def _run_c_owner_receiver_case(self, mode):
        fixture = os.environ.get("KER_RX_OWNER_RELAY_FIXTURE")
        if not fixture:
            self.skipTest("C relay fixture path is supplied by CTest")
        parent, child = socket.socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK)
        child.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        supervisor = os.getpid()
        expected_supervisor = supervisor + 1 if mode == "wrong-supervisor-cred" else supervisor
        start = ker_run.process_start_ticks(supervisor)
        nonce = bytes(range(16))
        child_proc = subprocess.Popen([fixture],
            pass_fds=(child.fileno(),), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={**os.environ,
                "KER_RX_OWNER_AUTH_FD": str(child.fileno()),
                "KER_TEST_OWNER_SUPERVISOR_PID": str(expected_supervisor),
                "KER_TEST_OWNER_SUPERVISOR_START": str(start),
                "KER_TEST_OWNER_EPOCH": "77",
                "KER_TEST_OWNER_NONCE": nonce.hex(),
                "KER_TEST_OWNER_EXPECT_STATUS": str(self._expected_c_status(mode))})
        child.close()
        owner_pidfd = os.pidfd_open(supervisor, 0)
        supervisor_pidfd = os.pidfd_open(supervisor, 0)
        other = None
        other_pidfd = -1
        if mode in ("wrong-pidfd", "wrong-supervisor-pidfd"):
            other = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(5)"])
            other_pidfd = os.pidfd_open(other.pid, 0)
        fields = [0x4b524f41, 1, 1, 96, supervisor, supervisor,
            threading.get_native_id(), 0, 0, 77, start, start, 16, 12345,
            67890, nonce]
        if mode == "wrong-supervisor": fields[4] += 1
        elif mode == "wrong-owner-pid": fields[5] += 1
        elif mode == "wrong-owner-tid": fields[6] = 0xffffffff
        elif mode == "wrong-role": fields[7] = 1
        elif mode == "wrong-epoch": fields[9] += 1
        elif mode == "wrong-supervisor-start": fields[10] += 1
        elif mode == "wrong-owner-start": fields[11] += 1
        elif mode == "zero-slot-device": fields[12] = 0
        elif mode == "zero-slot-inode": fields[13] = 0
        elif mode == "zero-cookie": fields[14] = 0
        elif mode == "bad-record-size": fields[3] -= 1
        packet = ker_run._RX_OWNER_AUTH_RECORD.pack(*fields)
        send_fd = other_pidfd if other_pidfd >= 0 else owner_pidfd
        ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
            array.array('i', [send_fd, supervisor_pidfd]))]
        payload = packet
        if mode == "truncated": payload = packet[:-1]
        elif mode == "trailing": payload = packet + b"x"
        if mode == "wrong-supervisor-pidfd":
            ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                array.array('i', [owner_pidfd, other_pidfd]))]
        elif mode == "rights":
            ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                array.array('i', [owner_pidfd, supervisor_pidfd, supervisor_pidfd]))]
        try:
            parent.sendmsg([payload], ancillary)
            parent.settimeout(2)
            if mode == "valid":
                try:
                    ack, ancillary, flags, _ = parent.recvmsg(97,
                        socket.CMSG_SPACE(12) + socket.CMSG_SPACE(8))
                except OSError as error:
                    _stdout, stderr = child_proc.communicate(timeout=2)
                    self.fail(f"valid C receiver closed without ACK: {error}; "
                        f"rc={child_proc.returncode} stderr={stderr!r}")
                self.assertEqual(len(ack), 96)
                self.assertEqual(ker_run._RX_OWNER_AUTH_RECORD.unpack(ack)[2], 2)
                self.assertFalse(flags)
            else:
                try:
                    self.assertEqual(parent.recv(1), b"")
                except ConnectionResetError:
                    pass
            child_proc.wait(timeout=2)
            _stdout, stderr = child_proc.communicate(timeout=2)
            self.assertEqual(child_proc.returncode, 0, stderr.decode(errors="replace"))
            line = next((value for value in stderr.decode().splitlines()
                if value.startswith("OWNER_AUTH_RECEIVER ")), "")
            self.assertIn(f"status={self._expected_c_status(mode)}", line)
            values = dict(part.split("=", 1) for part in line.split()[1:])
            self.assertEqual(values["fds_before"], values["fds_after"])
            self.assertEqual(values["status"], str(self._expected_c_status(mode)))
        finally:
            parent.close()
            os.close(owner_pidfd)
            os.close(supervisor_pidfd)
            if other_pidfd >= 0:
                os.close(other_pidfd)
            if other is not None:
                other.terminate()
                other.wait(timeout=2)
            if child_proc.poll() is None:
                child_proc.kill()
                child_proc.wait(timeout=2)

    @staticmethod
    def _expected_c_status(mode):
        if mode == "valid":
            return 0
        if mode in ("wrong-owner-pid", "wrong-owner-tid", "wrong-owner-start",
                "wrong-pidfd", "wrong-supervisor-pidfd"):
            return -116
        return -71

    def test_c_app_owner_auth_receiver_rejects_bad_identity_and_shape(self):
        modes = ('valid', 'wrong-supervisor-cred', 'wrong-supervisor',
            'wrong-owner-pid', 'wrong-owner-tid', 'wrong-role', 'wrong-epoch',
            'wrong-supervisor-start', 'wrong-owner-start', 'zero-slot-device',
            'zero-slot-inode', 'zero-cookie', 'bad-record-size', 'wrong-pidfd',
            'wrong-supervisor-pidfd', 'truncated', 'trailing', 'rights')
        for mode in modes:
            with self.subTest(mode=mode):
                self._run_c_owner_receiver_case(mode)

    def _run_expected_owner_ack_case(self, mode):
        parent, child = socket.socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK)
        parent.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        script = r'''import array, os, socket, struct, sys
s=socket.socket(fileno=int(sys.argv[1]))
wire=struct.Struct('=IHHIIIIIIQQQQQQ16s')
packet, ancillary, flags, address=s.recvmsg(97, socket.CMSG_SPACE(4))
fds=[]
for level, kind, data in ancillary:
    if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
        values=array.array('i'); values.frombytes(data[:len(data)-len(data)%values.itemsize]); fds.extend(values)
mode=sys.argv[2]
fields=list(wire.unpack(packet))
fields[2]=2
if mode=='cookie': fields[14] ^= 1
ack=wire.pack(*fields) + (b'x' if mode=='trailing' else b'')
if mode=='rights':
    s.sendmsg([ack], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i',[fds[-1]]))])
else: s.send(ack)
try: s.recv(1)
except OSError: pass
for fd in fds: os.close(fd)
'''
        child_proc = subprocess.Popen([sys.executable, "-c", script,
            str(child.fileno()), mode], pass_fds=(child.fileno(),),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        child.close()
        app_pidfd = os.pidfd_open(child_proc.pid, 0)
        supervisor_pidfd = os.pidfd_open(os.getpid(), 0)
        owner_pidfd = os.pidfd_open(os.getpid(), 0)
        supervisor_start = ker_run.process_start_ticks(os.getpid())
        owner_start = supervisor_start
        companion = type("Owner", (), {
            "owner_pidfd": owner_pidfd,
            "owner_pid": os.getpid(),
            "owner_tid": threading.get_native_id(),
            "owner_start": owner_start,
            "owner_role": 0,
            "owner_slot_device": 16,
            "owner_slot_inode": 12345,
            "owner_cookie": 67890,
        })()
        nonce = bytes(range(16))
        try:
            if mode == 'valid':
                ker_run.rx_owner_expected_auth(parent, child_proc, app_pidfd,
                    supervisor_pidfd, companion, nonce, 77, supervisor_start)
            else:
                with self.assertRaises((PermissionError, ValueError)):
                    ker_run.rx_owner_expected_auth(parent, child_proc, app_pidfd,
                        supervisor_pidfd, companion, nonce, 77, supervisor_start)
        finally:
            try:
                parent.send(b'x')
            except OSError:
                pass
            parent.close()
            for fd in (app_pidfd, supervisor_pidfd, owner_pidfd):
                os.close(fd)
            child_proc.wait(timeout=2)

    def test_app_auth_builder_matches_c_field_order_and_size(self):
        source = (ROOT / "src/posix/rx-owner-relay-wire.h").read_text(encoding="utf-8")
        self.assertIn("struct ker_rx_owner_relay_header", source)
        self.assertEqual(ker_run._RX_OWNER_RELAY_HEADER.size, 112)

        endpoint = Endpoint()
        app = type("App", (), {"pid": 0x11121314})()
        companion = type("Owner", (), {
            "owner_pid": 0x21222324,
            "owner_tid": 0x31323334,
            "owner_start": 0x4142434445464748,
        })()
        supervisor_pid = ker_run.os.getpid()
        starts = {
            app.pid: 0x5152535455565758,
            supervisor_pid: 0x7172737475767778,
        }
        original = ker_run.process_start_ticks
        ker_run.process_start_ticks = lambda pid: starts[pid]
        try:
            ker_run.rx_owner_relay_auth(endpoint, app, 0x101, 0x102,
                companion, bytes(range(16)), 0x8182838485868788)
        finally:
            ker_run.process_start_ticks = original

        fields = ker_run._RX_OWNER_RELAY_HEADER.unpack(endpoint.message)
        expected = (
            0x4B525852, 1, 3, 0, 0, bytes(range(16)),
            0x8182838485868788, 0x5152535455565758,
            0x4142434445464748, 0x7172737475767778,
            0x11121314, 0x21222324, 0x31323334, supervisor_pid, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0,
        )
        self.assertEqual(fields, expected)
        self.assertEqual(len(endpoint.message), 112)
        self.assertEqual(len(endpoint.ancillary), 1)
        self.assertEqual(endpoint.ancillary[0][0:2],
            (ker_run.socket.SOL_SOCKET, ker_run.socket.SCM_RIGHTS))

        c_source = r'''#include <stdio.h>
#include "rx-owner-relay-wire.h"
#include "rx-owner-auth-wire.h"
int main(void) {
    struct ker_rx_owner_relay_header h = {0};
    h.magic=0x4b525852; h.version=1; h.type=3;
    h.packet_id=0x0102030405060708ULL; h.deadline_ns=0x1112131415161718ULL;
    for (unsigned i=0; i<16; ++i) h.run_nonce[i]=(unsigned char)i;
    h.worker_epoch=0x8182838485868788ULL;
    h.app_start_ticks=0x5152535455565758ULL;
    h.owner_start_ticks=0x4142434445464748ULL;
    h.supervisor_start_ticks=0x7172737475767778ULL;
    h.app_pid=0x11121314; h.owner_pid=0x21222324; h.owner_tid=0x31323334;
    h.supervisor_pid=0x61626364; h.frame_bytes=0x71727374;
    h.queue_id=0x8182; h.queue_count=0x8384; h.action=0x8586; h.reserved=0x8788;
    h.frame_hash32=0x91929394; h.dispatcher_result=-1234567;
    h.vlan_tci=0xa1a2; h.vlan_stripped=0xb1; h.frame_unchanged=0xc1;
    _Static_assert(sizeof(h)==112, "wire header size");
    struct ker_rx_owner_auth_record a = {0};
    a.magic=0x4b524f41; a.version=1; a.type=1; a.record_bytes=96;
    a.supervisor_pid=0x11121314; a.owner_pid=0x21222324;
    a.owner_tid=0x31323334; a.owner_role=0x41424344; a.flags=0x51525354;
    a.worker_epoch=0x6162636465666768ULL;
    a.supervisor_start_ticks=0x7172737475767778ULL;
    a.owner_start_ticks=0x8182838485868788ULL;
    a.slot_device=0x9192939495969798ULL;
    a.slot_inode=0xa1a2a3a4a5a6a7a8ULL;
    a.cookie=0xb1b2b3b4b5b6b7b8ULL;
    for (unsigned i=0; i<16; ++i) a.run_nonce[i]=(unsigned char)(0xc0+i);
    _Static_assert(sizeof(a)==96, "owner auth record size");
    return fwrite(&h, sizeof(h), 1, stdout) == 1 &&
        fwrite(&a, sizeof(a), 1, stdout) == 1 ? 0 : 1;
}'''
        with tempfile.TemporaryDirectory(prefix="ker-rx-owner-wire-") as directory:
            source_path = pathlib.Path(directory) / "wire.c"
            binary_path = pathlib.Path(directory) / "wire"
            source_path.write_text(c_source, encoding="utf-8")
            subprocess.run([os.environ.get("CC", "cc"), "-std=c11",
                "-I", str(ROOT / "src/posix"), str(source_path), "-o",
                str(binary_path)], check=True, capture_output=True)
            c_bytes = subprocess.run([str(binary_path)], check=True,
                capture_output=True).stdout
        expected = ker_run._RX_OWNER_RELAY_HEADER.pack(
            0x4b525852, 1, 3, 0x0102030405060708, 0x1112131415161718,
            bytes(range(16)), 0x8182838485868788, 0x5152535455565758,
            0x4142434445464748, 0x7172737475767778,
            0x11121314, 0x21222324, 0x31323334, 0x61626364, 0x71727374,
            0x8182, 0x8384, 0x8586, 0x8788, 0x91929394, -1234567,
            0xa1a2, 0xb1, 0xc1)
        owner_auth_struct = struct.Struct('=IHHIIIIIIQQQQQQ16s')
        self.assertEqual(ker_run._RX_OWNER_AUTH_RECORD.format, owner_auth_struct.format)
        owner_auth_expected = owner_auth_struct.pack(
            0x4b524f41, 1, 1, 96, 0x11121314, 0x21222324, 0x31323334,
            0x41424344, 0x51525354, 0x6162636465666768,
            0x7172737475767778, 0x8182838485868788,
            0x9192939495969798, 0xa1a2a3a4a5a6a7a8,
            0xb1b2b3b4b5b6b7b8, bytes(range(0xc0, 0xd0)) )
        self.assertEqual(len(c_bytes), 112 + 96)
        self.assertEqual(c_bytes[:112], expected)
        self.assertEqual(c_bytes[112:], owner_auth_expected)

    def test_supervisor_owner_ack_receiver_validates_tuple_and_ancillary(self):
        for mode in ('valid', 'cookie', 'trailing', 'rights'):
            with self.subTest(mode=mode):
                self._run_expected_owner_ack_case(mode)


if __name__ == "__main__":
    unittest.main()
