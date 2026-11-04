import importlib.util
from pathlib import Path
import tempfile
import unittest


path = Path(__file__).resolve().parents[1] / 'posix/linux-mptcp-selftest.py'
spec = importlib.util.spec_from_file_location('linux_mptcp_selftest', path)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class MptcpEvidenceTests(unittest.TestCase):
    def counters(self):
        return dict(mptcp_capable_syn_tx=1, mptcp_capable_syn_rx=1,
                    mptcp_capable_synack_rx=1, mptcp_capable_ack_rx=1,
                    mptcp_fallback_synack=0, mptcp_fallback_ack=0)

    def test_negotiated_requires_directional_handshake_and_complete_mib(self):
        for role, key in (('client', 'mptcp_capable_synack_rx'), ('server', 'mptcp_capable_ack_rx')):
            self.assertTrue(runner.negotiated(self.counters(), role))
            absent = self.counters()
            absent[key] = 0
            self.assertFalse(runner.negotiated(absent, role))
            for missing in self.counters():
                partial = self.counters()
                partial.pop(missing)
                self.assertFalse(runner.negotiated(partial, role))

    def test_tcp_fallback_is_not_mptcp_coverage(self):
        for role in ('client', 'server'):
            for key in ('mptcp_fallback_synack', 'mptcp_fallback_ack'):
                counters = self.counters()
                counters[key] = 1
                self.assertFalse(runner.negotiated(counters, role))

    def test_missing_or_truncated_capture_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(RuntimeError, 'missing native capture'):
                runner.packet_evidence(root, 29500)
            (root / 'ker-tx-0.pcap').write_bytes(b'\xd4\xc3\xb2\xa1' + bytes(20) + b'\0')
            with self.assertRaisesRegex(RuntimeError, 'truncated capture record'):
                runner.packet_evidence(root, 29500)


if __name__ == '__main__':
    unittest.main()
