"""Require the full native ICMP RELATED, redirect and masquerade evidence."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('nat', ROOT / 'tests/posix/linux-nat-selftest.py')
contract = importlib.util.module_from_spec(spec); spec.loader.exec_module(contract)


class NatContractTests(unittest.TestCase):
    def test_partial_or_false_native_success_is_rejected(self):
        original = json.loads(Path(__file__).with_name('nat-icmp-related-transcript.json').read_text())
        for mutation in ('complete', 'missing-case', 'missing-counter', 'wrong-related-bytes', 'pmtu-succeeded',
                         'relaxed-timeout', 'filter-warning', 'missing-nat', 'zero-masquerade',
                         'host-fallback', 'leaked-namespace', 'live-socket', 'forced-shutdown'):
            with self.subTest(mutation=mutation):
                report = copy.deepcopy(original)
                pings = [r for r in report['commands'] if r['tool'] in ('ping', 'ping6')]
                counters = [r for r in report['commands'] if r['tool'] == 'nft' and r['arguments'][:2] == ['list', 'counter']]
                if mutation == 'missing-case':
                    report['original']['stdout'] = 'PASS: icmp mtu error had RELATED state\n'
                elif mutation == 'missing-counter':
                    report['commands'].remove(counters[-1])
                elif mutation == 'wrong-related-bytes':
                    counters[9]['stdout'] = counters[9]['stdout'].replace('bytes 576', 'bytes 575')
                elif mutation == 'pmtu-succeeded':
                    pings[2]['returncode'] = 0
                elif mutation == 'relaxed-timeout':
                    pings[2]['arguments'][1] = '5'
                elif mutation == 'filter-warning':
                    pings[-2]['stderr'] = 'WARNING: failed to install socket filter'
                elif mutation == 'missing-nat':
                    for record in report['commands']:
                        record.pop('nat_snapshots', None)
                elif mutation == 'zero-masquerade':
                    snapshots = next(r['nat_snapshots'] for r in report['commands'] if 'nat_snapshots' in r)
                    rule = next(item['rule'] for item in snapshots[0]['nftables'] if 'rule' in item)
                    next(e['counter'] for e in rule['expr'] if 'counter' in e)['packets'] = 0
                elif mutation == 'host-fallback':
                    report['missing_backend_control']['returncode'] = 0
                elif mutation == 'leaked-namespace':
                    report['native_fixture']['namespaces_deleted'] = 3
                elif mutation == 'live-socket':
                    report['native_fixture']['live'] = 1
                elif mutation == 'forced-shutdown':
                    report['stats']['shutdown_timed_out'] = True
                if mutation == 'complete':
                    contract.validate_evidence(report)
                else:
                    with self.assertRaises(RuntimeError):
                        contract.validate_evidence(report)


if __name__ == '__main__':
    unittest.main()
