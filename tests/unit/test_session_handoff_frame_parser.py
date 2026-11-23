#!/usr/bin/env python3
"""Exercise the exact IPv4/UDP frame parser used by the handoff fixture."""
import ast
import socket
import struct
import unittest
from pathlib import Path


SOURCE = Path(__file__).resolve().parents[1] / 'posix' / 'session-native-packets.py'


def checksum(data):
    if len(data) & 1:
        data += b'\x00'
    total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def valid_frame(payload=b'KER-A09-HANDOFF-UDP seq=2\n'):
    source = socket.inet_aton('198.18.0.2')
    destination = socket.inet_aton('198.18.0.1')
    udp_length = 8 + len(payload)
    udp = struct.pack('!HHHH', 45000, 45001, udp_length, 0) + payload
    pseudo = source + destination + b'\x00\x11' + struct.pack('!H', udp_length)
    udp_checksum = checksum(pseudo + udp) or 0xffff
    udp = udp[:6] + struct.pack('!H', udp_checksum) + udp[8:]
    ip_length = 20 + len(udp)
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, ip_length, 1, 0, 64, 17, 0, source, destination)
    ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
    return b'\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02\x08\x00' + ip + udp


def load_parser():
    tree = ast.parse(SOURCE.read_text())
    definition = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and
                      node.name == 'handoff_udp_payload')
    module = ast.Module(body=[definition], type_ignores=[])
    namespace = {'struct': struct, 'socket': socket}
    exec(compile(module, str(SOURCE), 'exec'), namespace)
    return namespace['handoff_udp_payload']


class HandoffFrameParserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parse = staticmethod(load_parser())

    def test_accepts_exact_checked_ipv4_udp_frame(self):
        frame = valid_frame()
        self.assertEqual(self.parse(frame), b'KER-A09-HANDOFF-UDP seq=2\n')

    def test_rejects_trailing_or_truncated_bytes(self):
        frame = valid_frame()
        self.assertIsNone(self.parse(frame + b'X'))
        self.assertIsNone(self.parse(frame[:-1]))

    def test_rejects_wrong_endpoint_or_port(self):
        frame = bytearray(valid_frame())
        wrong_ip = bytearray(frame)
        wrong_ip[30] ^= 1
        wrong_ip[24:26] = struct.pack('!H', checksum(bytes(wrong_ip[14:34])))
        self.assertIsNone(self.parse(bytes(wrong_ip)))
        wrong_port = bytearray(frame)
        wrong_port[34:36] = struct.pack('!H', 45002)
        self.assertIsNone(self.parse(bytes(wrong_port)))

    def test_rejects_bad_ip_and_udp_checksums(self):
        frame = bytearray(valid_frame())
        bad_ip = bytearray(frame)
        bad_ip[24] ^= 1
        self.assertIsNone(self.parse(bytes(bad_ip)))
        bad_udp = bytearray(frame)
        bad_udp[-1] ^= 1
        self.assertIsNone(self.parse(bytes(bad_udp)))


if __name__ == '__main__':
    unittest.main()
