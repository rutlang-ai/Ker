import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('ker_session_run', ROOT / 'tools/ker_session_run.py')
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class FrameCommittedRecordTests(unittest.TestCase):
    def test_actual_committed_schema_has_no_sequence_field(self):
        payload = b'KER-A09-HANDOFF-UDP seq=2\n'
        record = {
            'queue': 0, 'generation': 0, 'object_index': 17, 'pool_tag': 901,
            'packet_pointer': '0x1234', 'length': 68,
            'frame_hex': '00' * 42 + payload.hex(),
        }
        self.assertNotIn('sequence', record)
        self.assertIs(RUNNER.validate_frame_committed_record(record, payload), record)

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
