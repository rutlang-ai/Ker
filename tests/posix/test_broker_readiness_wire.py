import ast
import importlib.util
import json
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

    def test_verify_result_accepts_partial_negative_but_not_false_retirement(self):
        nonce, epoch, sequence = b'n' * 16, 7, 1
        profile = b'p' * 32
        negative = wire.pack_verify_result(nonce, epoch, sequence, 16, 0, 0,
            0, 0, 0, 0, profile, 0)
        fields = wire.unpack_verify_result(negative, nonce, epoch, sequence)
        self.assertEqual(fields['status'], 16)
        self.assertEqual(fields['state'], 0)
        with self.assertRaises(ValueError):
            wire.pack_verify_result(nonce, epoch, sequence, 0, 0, 0,
                0, 0, 0, 0, profile, 0)
        with self.assertRaises(ValueError):
            wire.pack_verify_result(nonce, epoch, sequence, 16, 1, 2,
                3, 4, 5, 6, profile, 1)
        with self.assertRaises(ValueError):
            wire.unpack_verify_result(negative, nonce, epoch, sequence + 1)

    def test_verify_result_is_bound_to_readiness_not_rx_decision_session(self):
        readiness_nonce, readiness_epoch = b'b' * 16, 23
        rx_decision_nonce, rx_decision_epoch = b'r' * 16, 29
        profile = b'p' * 32
        packet = wire.pack_verify_result(readiness_nonce, readiness_epoch, 1,
            16, 0, 0, 0, 0, 0, 0, profile, 0)
        self.assertEqual(wire.unpack_verify_result(packet, readiness_nonce,
            readiness_epoch, 1)['status'], 16)
        with self.assertRaises(ValueError):
            wire.unpack_verify_result(packet, rx_decision_nonce,
                rx_decision_epoch, 1)

    def test_captured_native_c34_packets_round_trip_through_receipt_json(self):
        # Captured native attempt 003: sequence 1 returned EAGAIN before
        # retirement; sequence 2 returned success after RETIRE0. Keep these
        # fixed wire records as offline evidence, without rerunning native code.
        before_packet = bytes.fromhex(
            '3452424b01000500800000000b000000'
            '03fcd2de1320c77b9f12e21f35f3a5eca9c25a4503810aef'
            '01000000000000003f00000000000000fee4d30000000000'
            '010000000000000001000000000000000100000001000000'
            '000000009fc6627fa2965c026221cf1bc0c74582c90fc667'
            '58e9188b52d15ad136b90b6a00000000')
        after_packet = bytes.fromhex(
            '3452424b010005008000000000000000'
            '03fcd2de1320c77b9f12e21f35f3a5eca9c25a4503810aef'
            '02000000000000003f00000000000000fee4d30000000000'
            '010000000000000001000000000000000100000001000000'
            '000000009fc6627fa2965c026221cf1bc0c74582c90fc667'
            '58e9188b52d15ad136b90b6a01000000')
        readiness_nonce = bytes.fromhex('03fcd2de1320c77b9f12e21f35f3a5ec')
        readiness_epoch = 17224721575880344233
        before = wire.unpack_verify_result(before_packet,
            readiness_nonce, readiness_epoch, 1)
        after = wire.unpack_verify_result(after_packet,
            readiness_nonce, readiness_epoch, 2)
        self.assertEqual((before['status'], before['state']), (11, 0))
        self.assertEqual((after['status'], after['state']), (0, 1))
        self.assertEqual((before['owner_pid'], before['owner_start_ticks']),
            (63, 13886718))
        self.assertEqual((after['owner_pid'], after['owner_start_ticks']),
            (63, 13886718))
        self.assertEqual((before['listener_cookie'], after['listener_cookie']),
            (1, 1))

        fixture = Path(__file__).with_name('native-nginx-source-master.py')
        tree = ast.parse(fixture.read_text(), filename=str(fixture))
        funcs = [node for node in tree.body if isinstance(node, ast.FunctionDef)
            and node.name == 'c34_verify_result_json']
        self.assertEqual(len(funcs), 1)
        namespace = {}
        exec(compile(ast.Module(body=funcs, type_ignores=[]),
            str(fixture), 'exec'), namespace)
        receipt = {'status': 'PASS_ACTUAL_SOURCE_FIRST_HUP',
            'c34_verify_before_retire': namespace['c34_verify_result_json'](before),
            'c34_verify_after_retire': namespace['c34_verify_result_json'](after)}
        serialized = json.dumps(receipt)
        restored = json.loads(serialized)
        for key, original in (('c34_verify_before_retire', before),
                ('c34_verify_after_retire', after)):
            encoded = restored[key]
            self.assertEqual(bytes.fromhex(encoded['nonce']), original['nonce'])
            self.assertEqual(bytes.fromhex(encoded['profile']), original['profile'])
            self.assertEqual(encoded['status'], original['status'])
            self.assertEqual(encoded['owner_pid'], original['owner_pid'])
            self.assertEqual(encoded['owner_start_ticks'], original['owner_start_ticks'])
            self.assertEqual(encoded['listener_cookie'], original['listener_cookie'])


if __name__ == '__main__':
    unittest.main()
