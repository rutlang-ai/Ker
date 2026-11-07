"""Reject partial IPIP PMTU evidence and host readiness substitutions."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('ipip', ROOT / 'tests/posix/linux-ipip-selftest.py')
contract = importlib.util.module_from_spec(spec); spec.loader.exec_module(contract)


class IpipContractTests(unittest.TestCase):
    def test_partial_or_false_native_success_is_rejected(self):
        original = json.loads(Path(__file__).with_name('ipip-mtu-transcript.json').read_text())
        for mutation in ('complete', 'missing-mode', 'wrong-bytes', 'missing-send', 'relaxed-timeout',
                         'missing-rule', 'adapter-error', 'unobserved-errno', 'unrecorded-stderr',
                         'host-fallback', 'host-control', 'missing-readiness', 'leaked-namespace', 'forced-shutdown'):
            with self.subTest(mutation=mutation):
                report = copy.deepcopy(original)
                listeners = [r for r in report['commands'] if r['tool'] == 'socat' and any('udp4-listen:' in a for a in r['arguments'])]
                senders = [r for r in report['commands'] if r['tool'] == 'socat' and 'UDP:192.168.20.2:5000' in r['arguments']]
                if mutation == 'missing-mode':
                    report['original']['stdout'] = 'OK: PMTU without connection tracking\n'
                elif mutation == 'wrong-bytes':
                    listeners[-1]['stdout'] = 'a' * 1399
                elif mutation == 'missing-send':
                    report['commands'].remove(senders[-1])
                elif mutation == 'relaxed-timeout':
                    senders[-1]['arguments'][1] = '5'
                elif mutation == 'missing-rule':
                    report['commands'] = [r for r in report['commands'] if r['tool'] != 'iptables']
                elif mutation == 'adapter-error':
                    senders[0]['stderr'] = 'Operation not supported\n'
                elif mutation == 'unobserved-errno':
                    report['native_fixture']['native_emsgsize'] = 0
                elif mutation == 'unrecorded-stderr':
                    report['original']['stderr'] += 'hidden error\n'
                elif mutation == 'host-fallback':
                    report['missing_backend_control']['returncode'] = 0
                elif mutation == 'host-control':
                    report['mixed_poll_missing_backend']['returncode'] = 0
                elif mutation == 'missing-readiness':
                    report.pop('mixed_poll_control')
                elif mutation == 'leaked-namespace':
                    report['native_fixture']['namespaces_deleted'] = 4
                elif mutation == 'forced-shutdown':
                    report['stats']['shutdown_timed_out'] = True
                if mutation == 'complete':
                    contract.validate_evidence(report)
                else:
                    with self.assertRaises(RuntimeError):
                        contract.validate_evidence(report)


if __name__ == '__main__':
    unittest.main()
