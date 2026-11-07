"""Reject incomplete reverse-path matrices and fabricated native success."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('rpath', ROOT / 'tests/posix/linux-rpath-selftest.py')
contract = importlib.util.module_from_spec(spec); spec.loader.exec_module(contract)


class RpathContractTests(unittest.TestCase):
    def test_partial_or_false_native_success_is_rejected(self):
        original = json.loads(Path(__file__).with_name('rpath-transcript.json').read_text())
        for mutation in ('complete', 'missing-probe', 'relaxed-timeout', 'martian-succeeds', 'missing-ipv6-tool',
                         'missing-legacy-counter', 'wrong-inverse', 'missing-nft-counter', 'wrong-nft-counter',
                         'missing-reset', 'missing-vrf', 'wrong-vrf-order', 'unexpected-warning',
                         'unrecorded-error', 'host-fallback', 'leaked-namespace', 'live-socket', 'forced-shutdown'):
            with self.subTest(mutation=mutation):
                report = copy.deepcopy(original); rows = report['commands']
                pings = [r for r in rows if r['tool'] == 'ping']
                legacy = [r for r in rows if r['arguments'] == ['-t', 'raw', '-vS']]
                nft = [r for r in rows if r['arguments'] == ['list', 'chain', 'inet', 't', 'c']]
                if mutation == 'missing-probe':
                    rows.remove(pings[-1])
                elif mutation == 'relaxed-timeout':
                    pings[0]['arguments'][5] = '5'
                elif mutation == 'martian-succeeds':
                    pings[0]['returncode'] = 0
                elif mutation == 'missing-ipv6-tool':
                    report['commands'] = [r for r in rows if r['tool'] != 'ip6tables-legacy']
                elif mutation == 'missing-legacy-counter':
                    rows.remove(legacy[-1])
                elif mutation == 'wrong-inverse':
                    legacy[-1]['stdout'] = legacy[-1]['stdout'].replace('--invert -c 0 0', '--invert -c 1 104')
                elif mutation == 'missing-nft-counter':
                    rows.remove(nft[-1])
                elif mutation == 'wrong-nft-counter':
                    nft[-1]['stdout'] = nft[-1]['stdout'].replace('packets 2 bytes 208', 'packets 0 bytes 0')
                elif mutation == 'missing-reset':
                    report['commands'] = [r for r in rows if r['arguments'] != ['-t', 'raw', '-Z']]
                elif mutation == 'missing-vrf':
                    report['commands'] = [r for r in rows if r['arguments'] != ['link', 'add', 'vrf0', 'type', 'vrf', 'table', '10']]
                elif mutation == 'wrong-vrf-order':
                    vrf = next(r for r in rows if r['arguments'] == ['link', 'add', 'vrf0', 'type', 'vrf', 'table', '10'])
                    rows.remove(vrf); rows.append(vrf)
                elif mutation == 'unexpected-warning':
                    pings[0]['stderr'] = 'WARNING: failed to install socket filter\n'
                elif mutation == 'unrecorded-error':
                    report['original']['stderr'] += 'hidden error\n'
                elif mutation == 'host-fallback':
                    report['missing_backend_control']['returncode'] = 0
                elif mutation == 'leaked-namespace':
                    report['native_fixture']['namespaces_deleted'] = 1
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
