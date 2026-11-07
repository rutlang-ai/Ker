"""Boundary failures and all six original MTU cases are required evidence."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('mtu', ROOT / 'tests/posix/linux-forwarding-mtu-contract.py')
contract = importlib.util.module_from_spec(spec); spec.loader.exec_module(contract)


class ForwardingMtuContractTests(unittest.TestCase):
    def test_dropped_cases_relaxed_limits_and_false_success_fail(self):
        original = json.loads(Path(__file__).with_name('forwarding-mtu-transcript.json').read_text())
        for mutation in ('complete', 'missing-case', 'xfail', 'lost-packet', 'missing-ping', 'missing-bounds',
                         'accepted-invalid-mtu', 'relaxed-payload', 'shortened-ping', 'leaked-socket', 'host-fallback'):
            with self.subTest(mutation=mutation):
                report = copy.deepcopy(original)
                pings = [r for r in report['commands'] if 'vrf' in r]
                if mutation == 'missing-case':
                    report['original']['stdout'] = '\n'.join(report['original']['stdout'].splitlines()[:-1])
                elif mutation == 'xfail':
                    report['original']['stdout'] = report['original']['stdout'].replace('[ OK ]', '[XFAIL]', 1)
                elif mutation == 'lost-packet':
                    pings[2]['stdout'] = '10 transmitted, 9 received'
                elif mutation == 'missing-ping':
                    report['commands'].remove(pings[-1])
                elif mutation == 'missing-bounds':
                    report['commands'] = [r for r in report['commands'] if r['arguments'][:2] != ['-d', '-j']]
                elif mutation == 'accepted-invalid-mtu':
                    next(r for r in report['commands'] if 'mtu' in r['arguments'] and r['returncode'])['returncode'] = 0
                elif mutation == 'relaxed-payload':
                    args = pings[2]['arguments']; args[args.index('-s') + 1] = '56'
                elif mutation == 'shortened-ping':
                    args = pings[0]['arguments']; args[args.index('-c') + 1] = '1'
                elif mutation == 'leaked-socket':
                    report['native_fixture']['live'] = 1
                elif mutation == 'host-fallback':
                    report['missing_backend_control']['returncode'] = 0
                if mutation == 'complete':
                    contract.validate_evidence(report)
                else:
                    with self.assertRaises(RuntimeError):
                        contract.validate_evidence(report)


if __name__ == '__main__':
    unittest.main()
