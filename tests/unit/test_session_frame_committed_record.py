import ast
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

    def test_active_consumer_selects_exact_u2_after_captured_mld_commit(self):
        payload = b'KER-A09-HANDOFF-UDP seq=2\n'
        unrelated = {
            'port': 0, 'queue': 0, 'generation': 0, 'object_index': 6,
            'pool_tag': 77, 'tx_lease_id': 88, 'packet_pointer': '0x1234',
            'length': len(RUNNER.CI_HANDOFF_MLD_FRAME),
            'frame_hex': RUNNER.CI_HANDOFF_MLD_FRAME.hex(),
        }
        expected = {
            'port': 0, 'queue': 0, 'generation': 0, 'object_index': 17,
            'pool_tag': 901, 'tx_lease_id': 31337, 'packet_pointer': '0x2345',
            'length': len(CAPTURED_U2), 'frame_hex': CAPTURED_U2.hex(),
        }
        records = [unrelated, expected]

        def ready(prefix, process=None):
            self.assertEqual(prefix, 'KER_SESSION_FRAME_COMMITTED')
            self.assertIsNotNone(process)
            if not records:
                raise RuntimeError('no committed frame remains')
            return records.pop(0)

        selected, skipped = RUNNER.read_expected_frame_commit(object(), ready, payload)
        self.assertIs(selected, expected)
        self.assertEqual(skipped, [unrelated])
        self.assertEqual(records, [])
        drain = {
            'object_index': unrelated['object_index'], 'lease_id': unrelated['tx_lease_id'],
            'pool_tag': unrelated['pool_tag'], 'packet_pointer': unrelated['packet_pointer'],
            'length': unrelated['length'], 'frame_hex': unrelated['frame_hex'],
        }
        self.assertIs(RUNNER.validate_unrelated_handoff_drain(drain), drain)

    def test_active_consumer_recovery_accounts_mld_before_exact_u2(self):
        payload = b'KER-A09-HANDOFF-UDP seq=2\n'
        mld_commit = {
            'port': 0, 'queue': 0, 'generation': 0, 'object_index': 6,
            'pool_tag': 77, 'tx_lease_id': 88, 'packet_pointer': '0x1234',
            'length': len(RUNNER.CI_HANDOFF_MLD_FRAME),
            'frame_hex': RUNNER.CI_HANDOFF_MLD_FRAME.hex(),
        }
        u2_commit = {
            'port': 0, 'queue': 0, 'generation': 0, 'object_index': 17,
            'pool_tag': 901, 'tx_lease_id': 31337, 'packet_pointer': '0x2345',
            'length': len(CAPTURED_U2), 'frame_hex': CAPTURED_U2.hex(),
        }
        mld_release = {
            'object_index': mld_commit['object_index'], 'lease_id': mld_commit['tx_lease_id'],
            'pool_tag': mld_commit['pool_tag'], 'packet_pointer': mld_commit['packet_pointer'],
            'length': mld_commit['length'], 'frame_hex': mld_commit['frame_hex'],
        }
        u2_release = {
            'sequence': 0, 'object_index': u2_commit['object_index'],
            'pool_tag': u2_commit['pool_tag'], 'packet_pointer': u2_commit['packet_pointer'],
            'length': u2_commit['length'], 'frame_hex': u2_commit['frame_hex'],
            'tx_before': 2, 'tx_resume': 0, 'tx_after': 0,
            'pool_in_use_before': 2, 'pool_in_use_resume': 1,
            'pool_in_use_after': 0, 'unrelated_count': 1,
        }
        # The previous one-packet equations reject this valid, exact two-object drain.
        self.assertNotEqual(u2_release['tx_before'], 1)
        self.assertNotEqual(u2_release['pool_in_use_after'] + 1,
            u2_release['pool_in_use_before'])
        self.assertIs(RUNNER.validate_active_consumer_frame_drain(
            u2_release, u2_commit, [mld_commit], [mld_release], payload), u2_release)
        with self.assertRaisesRegex(RuntimeError, 'evidence exceeded its bound or was incomplete'):
            RUNNER.validate_active_consumer_frame_drain(
                u2_release, u2_commit, [mld_commit], [], payload)
        with self.assertRaisesRegex(RuntimeError, 'bounded MLD accounting'):
            RUNNER.validate_active_consumer_frame_drain(
                dict(u2_release, tx_resume=1), u2_commit, [mld_commit], [mld_release], payload)
        tree = ast.parse(RUNNER_SOURCE.read_text())
        self.assertTrue(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and
            node.func.id == 'validate_active_consumer_frame_drain' and
            [argument.id for argument in node.args if isinstance(argument, ast.Name)] ==
                ['drained', 'committed', 'unrelated_commits', 'unrelated_drained', 'payload']
            for node in ast.walk(tree)))

    def test_active_consumer_releases_exact_mld_committed_after_held_u2(self):
        import json
        payload = b'KER-A09-HANDOFF-UDP seq=2\n'
        u2 = {'port': 0, 'queue': 0, 'generation': 0, 'object_index': 1,
            'pool_tag': 7, 'tx_lease_id': 101, 'packet_pointer': '0x1000',
            'length': len(CAPTURED_U2), 'frame_hex': CAPTURED_U2.hex()}
        mld = {'port': 0, 'queue': 0, 'generation': 0, 'object_index': 2,
            'pool_tag': 7, 'tx_lease_id': 102, 'packet_pointer': '0x2000',
            'length': len(RUNNER.CI_HANDOFF_MLD_FRAME),
            'frame_hex': RUNNER.CI_HANDOFF_MLD_FRAME.hex()}
        output = 'KER_SESSION_FRAME_COMMITTED ' + json.dumps(mld) + '\n'
        trailing = RUNNER.active_consumer_trailing_commits(output)
        self.assertEqual(trailing, [mld])
        release = {'object_index': 2, 'lease_id': 102, 'pool_tag': 7,
            'packet_pointer': '0x2000', 'length': mld['length'], 'frame_hex': mld['frame_hex']}
        drained = {'sequence': 0, 'object_index': 1, 'pool_tag': 7,
            'packet_pointer': '0x1000', 'length': u2['length'], 'frame_hex': u2['frame_hex'],
            'tx_before': 1, 'tx_resume': 1, 'tx_after': 0,
            'pool_in_use_before': 1, 'pool_in_use_resume': 2,
            'pool_in_use_after': 0, 'unrelated_count': 1}
        self.assertIs(RUNNER.validate_active_consumer_frame_drain(
            drained, u2, trailing, [release], payload, 1), drained)
        with self.assertRaisesRegex(RuntimeError, 'trailing MLD commit evidence'):
            RUNNER.active_consumer_trailing_commits('KER_SESSION_FRAME_COMMITTED {bad}\n')
        with self.assertRaisesRegex(RuntimeError, 'consumer changed unrelated committed frame'):
            RUNNER.validate_active_consumer_frame_drain(
                drained, u2, trailing, [dict(release, lease_id=999)], payload, 1)
        with self.assertRaisesRegex(RuntimeError, 'bounded MLD accounting'):
            RUNNER.validate_active_consumer_frame_drain(
                dict(drained, tx_resume=0), u2, trailing, [release], payload, 1)

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
