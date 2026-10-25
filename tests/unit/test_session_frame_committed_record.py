import importlib.util
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'src/posix/io-session.c'
RUNNER_SOURCE = ROOT / 'tools/ker_session_run.py'
SPEC = importlib.util.spec_from_file_location('ker_session_run', ROOT / 'tools/ker_session_run.py')
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)

# Captured original-Linux post-PARKED U2 frame, used only as a valid unit input.
CAPTURED_U2 = bytes.fromhex(
    '024b45520001024b455200020800450000366c7b400040114214c6120002c6120001'
    'afc8afc9002214154b45522d4130392d48414e444f46462d554450207365713d320a')


class FrameCommittedRecordTests(unittest.TestCase):
    def test_actual_committed_schema_has_no_sequence_field(self):
        payload = b'KER-A09-HANDOFF-UDP seq=2\n'
        frame = CAPTURED_U2
        self.assertEqual(len(frame), 68)
        self.assertEqual(frame[:14], bytes.fromhex('024b45520001024b455200020800'))
        self.assertEqual(frame[26:30], bytes((198, 18, 0, 2)))
        self.assertEqual(frame[30:34], bytes((198, 18, 0, 1)))
        self.assertEqual(frame[34:38], bytes.fromhex('afc8afc9'))
        record = {
            'port': 0, 'queue': 0, 'generation': 0, 'object_index': 17, 'pool_tag': 901,
            'tx_lease_id': 31337,
            'packet_pointer': '0x1234', 'length': len(frame),
            'frame_hex': frame.hex(),
        }
        self.assertNotIn('sequence', record)
        self.assertIs(RUNNER.validate_frame_committed_record(record, payload), record)

    def test_schema_matches_current_c_printf_and_runner_callsite(self):
        c_source = SOURCE.read_text()
        marker_line = next((line for line in c_source.splitlines()
            if 'KER_SESSION_FRAME_COMMITTED ' in line), None)
        self.assertIsNotNone(marker_line)
        fields = set(re.findall(r'\\"([a-z_]+)\\":', marker_line))
        self.assertEqual(fields, {'port', 'queue', 'generation', 'length', 'object_index',
            'pool_tag', 'tx_lease_id', 'packet_pointer', 'frame_hex'})
        self.assertNotIn('sequence', fields)

        runner_source = RUNNER_SOURCE.read_text()
        self.assertIn('validate_frame_committed_record(record,payload)', runner_source)
        self.assertIn('validate_frame_committed_record(committed,payload)', runner_source)
        self.assertIn('frame_matches_expected_u2(frame, payload)', runner_source)

    def test_wrong_outer_port_and_udp_destination_port_are_rejected(self):
        payload = b'KER-A09-HANDOFF-UDP seq=2\n'
        frame = bytearray(CAPTURED_U2)
        record = {'port': 0, 'queue': 0, 'generation': 0, 'object_index': 17,
            'pool_tag': 901, 'tx_lease_id': 31337, 'packet_pointer': '0x1234',
            'length': len(frame), 'frame_hex': bytes(frame).hex()}
        with self.assertRaisesRegex(RuntimeError, 'exact second UDP frame'):
            RUNNER.validate_frame_committed_record(dict(record, port=1), payload)
        missing_port = dict(record)
        del missing_port['port']
        with self.assertRaisesRegex(RuntimeError, 'exact second UDP frame'):
            RUNNER.validate_frame_committed_record(missing_port, payload)
        frame[36:38] = (45002).to_bytes(2, 'big')
        record['frame_hex'] = frame.hex()
        with self.assertRaisesRegex(RuntimeError, 'exact second UDP frame'):
            RUNNER.validate_frame_committed_record(record, payload)
        frame = bytearray(CAPTURED_U2)
        frame[24] ^= 1
        record['frame_hex'] = frame.hex()
        with self.assertRaisesRegex(RuntimeError, 'exact second UDP frame'):
            RUNNER.validate_frame_committed_record(record, payload)

    def test_missing_or_invalid_tx_lease_is_rejected(self):
        payload = b'KER-A09-HANDOFF-UDP seq=2\n'
        frame = CAPTURED_U2
        record = {
            'port': 0, 'queue': 0, 'generation': 0, 'object_index': 17, 'pool_tag': 901,
            'packet_pointer': '0x1234', 'length': len(frame), 'frame_hex': frame.hex(),
        }
        with self.assertRaisesRegex(RuntimeError, 'did not commit the exact second UDP frame'):
            RUNNER.validate_frame_committed_record(record, payload)
        record['tx_lease_id'] = True
        with self.assertRaisesRegex(RuntimeError, 'did not commit the exact second UDP frame'):
            RUNNER.validate_frame_committed_record(record, payload)
        record['tx_lease_id'] = 0
        with self.assertRaisesRegex(RuntimeError, 'did not commit the exact second UDP frame'):
            RUNNER.validate_frame_committed_record(record, payload)

    def test_missing_identity_field_is_rejected(self):
        payload = b'KER-A09-HANDOFF-UDP seq=2\n'
        frame = CAPTURED_U2
        record = {
            'port': 0, 'queue': 0, 'pool_tag': 901,
            'tx_lease_id': 31337, 'packet_pointer': '0x1234', 'length': len(frame), 'frame_hex': frame.hex(),
        }
        with self.assertRaisesRegex(RuntimeError, 'did not commit the exact second UDP frame'):
            RUNNER.validate_frame_committed_record(record, payload)


if __name__ == '__main__':
    unittest.main()
