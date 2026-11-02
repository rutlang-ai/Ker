#!/usr/bin/env python3
"""Check exact consumption of queued generation-forward records."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest


FIXTURE = Path(__file__).resolve().parents[1] / 'posix' / 'session-native-packets.py'
sys.path.insert(0, str(FIXTURE.parent))
SPEC = importlib.util.spec_from_file_location('session_native_packets_forward_receipt', FIXTURE)
PROFILE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROFILE)


def run_output(lines):
    source = 'import sys; sys.stdout.write(' + repr(''.join(line + '\n' for line in lines)) + '); sys.stdout.flush()'
    return subprocess.Popen([sys.executable, '-c', source], stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)


def marker(prefix, value):
    return prefix + ' ' + json.dumps(value, sort_keys=True)


class GenerationForwardReceiptTests(unittest.TestCase):
    def setUp(self):
        self.frames = [b'\x01first-frame', b'\x02second-frame']
        self.enqueued = [dict(producer_generation=1, target_generation=0,
            length=len(frame), frame_hex=frame.hex()) for frame in self.frames]
        self.complete = dict(complete=True, forwarded_frames=len(self.frames),
            handoff_seen=True, tcp_accepted=True)

    def test_drains_correlated_enqueue_records_before_completion(self):
        process = run_output([
            marker('KER_SESSION_TEST_GENERATION_FORWARD_ENQUEUED', self.enqueued[0]),
            marker('KER_SESSION_TEST_GENERATION_FORWARD_ENQUEUED', self.enqueued[1]),
            marker('KER_SESSION_GENERATION_FORWARD_COMPLETE', self.complete)])
        try:
            result = PROFILE.wait_generation_forward_complete(process, self.frames, timeout=2)
            self.assertEqual(result, self.complete)
            self.assertEqual(process.wait(timeout=2), 0)
        finally:
            process.stdout.close()
            process.stderr.close()

    def test_rejects_enqueue_for_wrong_frame_or_order(self):
        process = run_output([
            marker('KER_SESSION_TEST_GENERATION_FORWARD_ENQUEUED', self.enqueued[1]),
            marker('KER_SESSION_GENERATION_FORWARD_COMPLETE', self.complete)])
        try:
            with self.assertRaisesRegex(RuntimeError, 'differs from the next captured frame'):
                PROFILE.wait_generation_forward_complete(process, self.frames, timeout=2)
            process.wait(timeout=2)
        finally:
            process.stdout.close()
            process.stderr.close()

    def test_rejects_receipt_missing_an_enqueue_record(self):
        process = run_output([
            marker('KER_SESSION_TEST_GENERATION_FORWARD_ENQUEUED', self.enqueued[0]),
            marker('KER_SESSION_GENERATION_FORWARD_COMPLETE', self.complete)])
        try:
            with self.assertRaisesRegex(RuntimeError, 'does not match all captured/enqueued'):
                PROFILE.wait_generation_forward_complete(process, self.frames, timeout=2)
            process.wait(timeout=2)
        finally:
            process.stdout.close()
            process.stderr.close()


if __name__ == '__main__':
    unittest.main()
