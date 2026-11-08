"""Reject weakened isolation, missing transitions and incomplete bridge cleanup."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('bridge_contract', ROOT / 'tests/posix/linux-bridge-selftest.py')
contract = importlib.util.module_from_spec(spec); spec.loader.exec_module(contract)


class BridgeContractTests(unittest.TestCase):
    def test_original_bridge_isolation_and_cleanup_are_required(self):
        original = json.loads(Path(__file__).with_name('bridge-transcript.json').read_text())
        for mutation in ('complete', 'missing-family', 'lost-packet', 'isolation-bypass', 'warning',
                         'timeout', 'remaster-order', 'late-pvid', 'stale-pvid', 'wrong-port',
                         'no-forwarding', 'not-restored', 'leaked-bridge', 'failed-cleanup',
                         'ignored-vrf', 'host-fallback', 'outstanding-packet', 'forced-stop'):
            with self.subTest(mutation=mutation):
                report = copy.deepcopy(original); rows = report['commands']
                pings = [r for r in rows if r['arguments'][:2] == ['vrf','exec']]
                if mutation == 'missing-family': rows.remove(pings[-1])
                elif mutation == 'lost-packet': pings[0]['stdout'] = '10 packets transmitted, 9 received'
                elif mutation == 'isolation-bypass': pings[4]['returncode'] = 0
                elif mutation == 'warning': pings[0]['stderr'] = 'native filter warning'
                elif mutation == 'timeout': pings[0]['arguments'][-2] = '1'
                elif mutation == 'remaster-order':
                    row = next(r for r in rows if r['arguments'] == ['link','set','dev','veth1','nomaster'])
                    rows.remove(row); rows.append(row)
                elif mutation == 'late-pvid':
                    report['commands'] = [r for r in rows if 'vlan_default_pvid' not in r['arguments']]
                elif mutation == 'stale-pvid': pings[4]['bridge_state']['vlans'][0]['vlans'][0]['flags'] = ['PVID']
                elif mutation == 'wrong-port': pings[2]['bridge_state']['port'][0]['master'] = 'other'
                elif mutation == 'no-forwarding': report['mib_after'] = report['mib_before']
                elif mutation == 'not-restored': report['cleanup_state']['ipv6'] = '1\n'
                elif mutation == 'leaked-bridge': report['cleanup_state']['links'].append(dict(ifname='br1'))
                elif mutation == 'failed-cleanup': rows[-1]['returncode'] = 1
                elif mutation == 'ignored-vrf': report['vrf_binding_control']['unknown_vrf']['returncode'] = 0
                elif mutation == 'host-fallback': report['missing_backend_control']['returncode'] = 0
                elif mutation == 'outstanding-packet': report['stats']['outstanding'] = 1
                elif mutation == 'forced-stop': report['stats']['shutdown_timed_out'] = True
                if mutation == 'complete': contract.validate_evidence(report)
                else:
                    with self.assertRaises(RuntimeError): contract.validate_evidence(report)


if __name__ == '__main__': unittest.main()
