"""Reject incomplete two-bridge VLAN routing and ineffective native remastering."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('bridge_1d', ROOT / 'tests/posix/linux-bridge-1d-contract.py')
contract = importlib.util.module_from_spec(spec); spec.loader.exec_module(contract)


class Bridge1dContractTests(unittest.TestCase):
    def test_complete_original_topology_remaster_traffic_and_cleanup(self):
        original = json.loads(Path(__file__).with_name('bridge-1d-transcript.json').read_text())
        for mutation in ('complete','missing-family','lost-packet','wrong-destination','warning','timeout',
                         'vlan-aware-bridge','crossed-port','wrong-vlan','wrong-host-vrf','missing-detach',
                         'reordered-remaster','ineffective-detach','no-forwarding','not-restored','leaked-bridge',
                         'failed-cleanup','ignored-vrf','host-fallback','live-socket','outstanding-packet','forced-stop'):
            with self.subTest(mutation=mutation):
                r = copy.deepcopy(original); rows = r['commands']
                pings = [x for x in rows if x['arguments'][:2] == ['vrf','exec']]
                actions = [x for x in rows if 'port_after' in x]
                links = {x['ifname']:x for x in pings[0]['bridge_state']['links']}
                if mutation == 'missing-family': rows.remove(pings[-1])
                elif mutation == 'lost-packet': pings[0]['stdout'] = '10 packets transmitted, 9 received'
                elif mutation == 'wrong-destination': pings[1]['arguments'][-1] = '192.0.2.130'
                elif mutation == 'warning': pings[0]['stderr'] = 'native filter warning'
                elif mutation == 'timeout': pings[0]['arguments'][-2] = '1'
                elif mutation == 'vlan-aware-bridge': links['br2']['linkinfo']['info_data']['vlan_filtering'] = 1
                elif mutation == 'crossed-port': links['veth1.200']['master'] = 'br1'
                elif mutation == 'wrong-vlan': links['veth1.100']['linkinfo']['info_data']['id'] = 200
                elif mutation == 'wrong-host-vrf': links['veth0.100']['master'] = 'other'
                elif mutation == 'missing-detach': rows.remove(actions[2])
                elif mutation == 'reordered-remaster': rows.remove(actions[4]); rows.append(actions[4])
                elif mutation == 'ineffective-detach': actions[2]['port_after'][0]['master'] = 'br1'
                elif mutation == 'no-forwarding': r['mib_after'] = r['mib_before']
                elif mutation == 'not-restored': r['cleanup_state']['ipv6'] = '1\n'
                elif mutation == 'leaked-bridge': r['cleanup_state']['links'].append(dict(ifname='br2'))
                elif mutation == 'failed-cleanup': rows[-1]['returncode'] = 1
                elif mutation == 'ignored-vrf': r['vrf_binding_control']['unknown_vrf']['returncode'] = 0
                elif mutation == 'host-fallback': r['missing_backend_control']['returncode'] = 0
                elif mutation == 'live-socket': r['native_fixture']['live'] = 1
                elif mutation == 'outstanding-packet': r['stats']['outstanding'] = 1
                elif mutation == 'forced-stop': r['stats']['shutdown_timed_out'] = True
                if mutation == 'complete': contract.validate_evidence(r)
                else:
                    with self.assertRaises(RuntimeError): contract.validate_evidence(r)


if __name__ == '__main__': unittest.main()
