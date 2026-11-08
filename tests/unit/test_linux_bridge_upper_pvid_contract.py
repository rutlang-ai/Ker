"""Reject missing PVID transitions and loss of the persistent routed upper."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('bridge_upper_pvid', ROOT / 'tests/posix/linux-bridge-upper-pvid-contract.py')
contract = importlib.util.module_from_spec(spec); spec.loader.exec_module(contract)


class BridgeUpperPvidContractTests(unittest.TestCase):
    def test_actual_original_upper_pvid_set_unset_and_move(self):
        original = json.loads(Path(__file__).with_name('bridge-upper-pvid-transcript.json').read_text())
        mutations = ('complete', 'missing-ping', 'lost-packet', 'changed-timeout', 'warning', 'missing-clock',
                     'missing-outcome', 'wrong-default-pvid', 'wrong-upper-parent', 'wrong-upper-vid',
                     'upper-down', 'wrong-host-vrf', 'missing-upper-address', 'address-on-base',
                     'missing-upper-route', 'initial-pvid', 'missing-pvid-set', 'failed-pvid-unset',
                     'old-pvid-retained', 'missing-post-state', 'reordered-second-set',
                     'intermediate-upper-route-lost', 'port-vlan-lost', 'no-forwarding',
                     'sysctl-not-restored', 'leaked-device', 'failed-cleanup', 'host-fallback',
                     'ignored-vrf', 'live-socket', 'outstanding-packet', 'forced-stop')
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                r = copy.deepcopy(original); rows = r['commands']
                pings = [x for x in rows if x['arguments'][:2] == ['vrf', 'exec']]
                bridge = [x for x in rows if x['tool'] == 'bridge']
                state = pings[0]['bridge_state']
                links = {x['ifname']: x for x in state['links']}
                if mutation == 'missing-ping': rows.remove(pings[3])
                elif mutation == 'lost-packet': pings[0]['stdout'] = '10 packets transmitted, 9 received'
                elif mutation == 'changed-timeout': pings[0]['arguments'][-2] = '1'
                elif mutation == 'warning': pings[0]['stderr'] = 'time of day goes back'
                elif mutation == 'missing-clock': pings[0].pop('native_clock_reads')
                elif mutation == 'missing-outcome': r['original']['stdout'] = ''
                elif mutation == 'wrong-default-pvid': links['br1']['linkinfo']['info_data']['vlan_default_pvid'] = 1
                elif mutation == 'wrong-upper-parent': links['br1.10']['link'] = 'veth1'
                elif mutation == 'wrong-upper-vid': links['br1.10']['linkinfo']['info_data']['id'] = 20
                elif mutation == 'upper-down': links['br1.10']['flags'].remove('UP')
                elif mutation == 'wrong-host-vrf': links['veth0.10']['master'] = 'vveth3'
                elif mutation == 'missing-upper-address':
                    next(x for x in state['addresses'] if x['ifname'] == 'br1.10')['addr_info'] = []
                elif mutation == 'address-on-base':
                    next(x for x in state['addresses'] if x['ifname'] == 'br1')['addr_info'].append(
                        dict(local='192.0.2.2', prefixlen=28, scope='global'))
                elif mutation == 'missing-upper-route': state['ipv6_routes'] = []
                elif mutation == 'initial-pvid':
                    next(x for x in state['vlans'] if x['ifname'] == 'br1')['vlans'][0]['flags'] = ['PVID']
                elif mutation == 'missing-pvid-set': bridge[2]['bridge_vlans_after'] = bridge[1]['bridge_vlans_after']
                elif mutation == 'failed-pvid-unset': bridge[3]['bridge_vlans_after'] = bridge[2]['bridge_vlans_after']
                elif mutation == 'old-pvid-retained':
                    next(x for x in bridge[5]['bridge_vlans_after'] if x['ifname'] == 'br1')['vlans'][0]['flags'] = ['PVID']
                elif mutation == 'missing-post-state': bridge[4].pop('pvid_after')
                elif mutation == 'reordered-second-set':
                    index = next(i for i, x in enumerate(rows) if x is bridge[4]); rows.append(rows.pop(index))
                elif mutation == 'intermediate-upper-route-lost': bridge[4]['pvid_after']['ipv4_routes'] = []
                elif mutation == 'port-vlan-lost':
                    next(x for x in bridge[4]['pvid_after']['vlans'] if x['ifname'] == 'veth1')['vlans'] = []
                elif mutation == 'no-forwarding': r['mib_after'] = r['mib_before']
                elif mutation == 'sysctl-not-restored': r['cleanup_state']['ipv6'] = '1\n'
                elif mutation == 'leaked-device': r['cleanup_state']['links'].append(dict(ifname='br1.10'))
                elif mutation == 'failed-cleanup': rows[-1]['returncode'] = 1
                elif mutation == 'host-fallback': r['missing_backend_control']['returncode'] = 0
                elif mutation == 'ignored-vrf': r['vrf_binding_control']['unknown_vrf']['returncode'] = 0
                elif mutation == 'live-socket': r['native_fixture']['live'] = 1
                elif mutation == 'outstanding-packet': r['stats']['outstanding'] = 1
                elif mutation == 'forced-stop': r['stats']['shutdown_timed_out'] = True
                if mutation == 'complete': contract.validate_evidence(r)
                else:
                    with self.assertRaises(RuntimeError): contract.validate_evidence(r)


if __name__ == '__main__': unittest.main()
