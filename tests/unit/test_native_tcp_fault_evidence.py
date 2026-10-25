"""The loss/reorder test must observe both peer retransmission and native reassembly."""
import importlib.util
from pathlib import Path
import unittest


SOURCE = Path(__file__).resolve().parents[1] / 'posix' / 'tcp-interop.py'
SPEC = importlib.util.spec_from_file_location('tcp_interop', SOURCE)
tcp_interop = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tcp_interop)


class TcpFaultEvidenceTests(unittest.TestCase):
    def test_accepts_host_retransmission_and_native_out_of_order_reassembly(self):
        tcp_interop.validate_fault_evidence(
            'TCP_INFO total_retrans=10', {'out_of_order_queued': 237}, 'host')

    def test_rejects_zero_peer_retransmission(self):
        with self.assertRaisesRegex(RuntimeError, 'host TCP retransmission'):
            tcp_interop.validate_fault_evidence(
                'TCP_INFO total_retrans=0', {'out_of_order_queued': 237}, 'host')

    def test_rejects_missing_peer_retransmission_record(self):
        with self.assertRaisesRegex(RuntimeError, 'native TCP retransmission'):
            tcp_interop.validate_fault_evidence(
                'PASS: transfer', {'out_of_order_queued': 237}, 'native')

    def test_rejects_zero_native_reassembly(self):
        with self.assertRaisesRegex(RuntimeError, 'native TCP out-of-order'):
            tcp_interop.validate_fault_evidence(
                'TCP_INFO total_retrans=10', {'out_of_order_queued': 0}, 'host')


if __name__ == '__main__':
    unittest.main(verbosity=2)
