"""Reject partial or host-only success for the unchanged gateway shell."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('forwarding', ROOT / 'tests/posix/linux-forwarding-selftest.py')
contract = importlib.util.module_from_spec(spec); spec.loader.exec_module(contract)


class ForwardingContractTests(unittest.TestCase):
    def test_rejects_incomplete_native_forwarding_and_ineffective_vrf_binding(self):
        original = json.loads(Path(__file__).with_name('forwarding-router-vid1-transcript.json').read_text())
        for mutation in ('complete', 'missing-family', 'lost-packet', 'no-forwarding', 'partial-forwarding',
                         'missing-vlan', 'sysctl-not-restored', 'ignored-vrf', 'no-baseline',
                         'host-fallback', 'skipped', 'live-socket', 'outstanding-packet', 'forced-shutdown'):
            with self.subTest(mutation=mutation):
                report = copy.deepcopy(original)
                pings = [r for r in report['commands'] if 'vrf' in r]
                if mutation == 'missing-family':
                    report['commands'].remove(pings[-1])
                elif mutation == 'lost-packet':
                    pings[-1]['stdout'] = '10 packets transmitted, 9 received'
                elif mutation == 'no-forwarding':
                    report['mib_after'] = report['mib_before']
                elif mutation == 'partial-forwarding':
                    report['mib_after']['ipv6'] = 'Ip6OutForwDatagrams 1\n'
                elif mutation == 'missing-vlan':
                    report['commands'] = [r for r in report['commands'] if 'vlan' not in r['arguments']]
                elif mutation == 'sysctl-not-restored':
                    report['commands'] = [r for r in report['commands'] if r['tool'] != 'sysctl' or
                                          not r['arguments'][1].endswith('forwarding=0')]
                elif mutation == 'ignored-vrf':
                    report['vrf_binding_control']['unknown_vrf']['returncode'] = 0
                elif mutation == 'no-baseline':
                    report['vrf_binding_control']['baseline']['returncode'] = 1
                elif mutation == 'host-fallback':
                    report['missing_backend_control']['returncode'] = 0
                elif mutation == 'skipped':
                    report['original']['stdout'] = 'SKIP: tool missing'
                elif mutation == 'live-socket':
                    report['native_fixture']['live'] = 1
                elif mutation == 'outstanding-packet':
                    report['stats']['outstanding'] = 1
                elif mutation == 'forced-shutdown':
                    report['stats']['shutdown_timed_out'] = True
                if mutation == 'complete':
                    contract.validate_evidence(report)
                else:
                    with self.assertRaises(RuntimeError):
                        contract.validate_evidence(report)


if __name__ == '__main__':
    unittest.main()
