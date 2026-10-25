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


class FrameCommittedRecordTests(unittest.TestCase):
    def test_actual_committed_schema_has_no_sequence_field(self):
        payload = b'KER-A09-HANDOFF-UDP seq=2\n'
        record = {
            'port': 0, 'queue': 0, 'generation': 0, 'object_index': 17, 'pool_tag': 901,
            'tx_lease_id': 31337,
            'packet_pointer': '0x1234', 'length': 68,
            'frame_hex': '00' * 42 + payload.hex(),
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

    def test_missing_or_invalid_tx_lease_is_rejected(self):
        payload = b'packet'
        record = {
            'queue': 0, 'generation': 0, 'object_index': 17, 'pool_tag': 901,
            'packet_pointer': '0x1234', 'length': len(payload), 'frame_hex': payload.hex(),
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
        payload = b'packet'
        record = {
            'queue': 0, 'generation': 0, 'pool_tag': 901,
            'packet_pointer': '0x1234', 'length': 20, 'frame_hex': payload.hex(),
        }
        with self.assertRaisesRegex(RuntimeError, 'did not commit the exact second UDP frame'):
            RUNNER.validate_frame_committed_record(record, payload)


if __name__ == '__main__':
    unittest.main()
