import importlib.util
from pathlib import Path
import unittest

CODEC = Path(__file__).resolve().parents[2] / 'tools' / 'broker_readiness_wire.py'
SPEC = importlib.util.spec_from_file_location('broker_readiness_wire_test', CODEC)
wire = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(wire)


class BrokerReadinessWireTests(unittest.TestCase):
    def test_ready_round_trip_and_exact_size(self):
        nonce = bytes(range(16))
        profile = bytes(range(32))
        packet = wire.pack_ready(nonce, 7, profile, 1234)
        self.assertEqual(len(packet), 120)
        self.assertEqual(wire.unpack_ready(packet),
            (nonce, 7, profile, 1234, 0, wire.EMPTY_MANIFEST_SHA256))
        with self.assertRaises(ValueError):
            wire.unpack_ready(packet + b'\0')

    def test_ready_rejects_wrong_identity_count_manifest_and_reserved(self):
        packet = bytearray(wire.pack_ready(b'n' * 16, 1, b'p' * 32, 2))
        for offset, replacement in ((32, b'\0' * 8), (80, b'\1\0\0\0'),
                                    (84, b'\1\0\0\0'), (88, b'x' * 32)):
            bad = packet.copy()
            bad[offset:offset + len(replacement)] = replacement
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                wire.unpack_ready(bad)
        with self.assertRaises(ValueError):
            wire.pack_ready(b'\0' * 16, 1, b'p' * 32, 2)
        with self.assertRaises(ValueError):
            wire.pack_ready(b'n' * 16, 1, b'\0' * 32, 2)

    def test_stop_and_ack_are_exact_and_one_shot(self):
        fields = (b'n' * 16, 9, 123, 1000, 1001, 4567)
        for record_type in (wire.STOP, wire.STOP_ACK):
            packet = wire.pack_stop(record_type, *fields)
            self.assertEqual(len(packet), 104)
            self.assertEqual(wire.unpack_stop(packet, record_type),
                (fields[0], fields[1], wire.EMPTY_MANIFEST_SHA256,
                 fields[2], fields[3], fields[4], fields[5], 1))
            with self.assertRaises(ValueError):
                wire.unpack_stop(packet, wire.STOP_ACK if record_type == wire.STOP
                                 else wire.STOP)
            bad = bytearray(packet)
            bad[96:104] = (2).to_bytes(8, 'little')
            with self.assertRaises(ValueError):
                wire.unpack_stop(bad, record_type)
        with self.assertRaises(ValueError):
            wire.pack_stop(wire.STOP, b'\0' * 16, *fields[1:])

    def test_empty_manifest_digest_is_fixed_domain(self):
        self.assertEqual(len(wire.EMPTY_MANIFEST_DOMAIN), 36)
        self.assertEqual(wire.EMPTY_MANIFEST_SHA256,
                         __import__('hashlib').sha256(
                             b'ker.socket-broker.bootstrap.empty/v1').digest())
        with self.assertRaises(ValueError):
            wire.pack_ready(b'n' * 16, 1, b'p' * 32, 2,
                            manifest_sha256=b'x' * 32)


if __name__ == '__main__':
    unittest.main()
