"""Reject missing routed VLAN uppers and ineffective original port respins."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('bridge_vlan_upper', ROOT / 'tests/posix/linux-bridge-vlan-upper-contract.py')
contract = importlib.util.module_from_spec(spec); spec.loader.exec_module(contract)


class BridgeVlanUpperContractTests(unittest.TestCase):
    def test_actual_original_traffic_topology_respin_and_cleanup(self):
        original = json.loads(Path(__file__).with_name('bridge-vlan-upper-transcript.json').read_text())
        mutations = ('complete', 'missing-family', 'lost-packet', 'wrong-destination', 'changed-timeout',
                     'warning', 'missing-clock', 'missing-outcome', 'vlan-unaware', 'wrong-port',
                     'missing-port-vlan', 'wrong-upper-parent', 'wrong-upper-vid', 'wrong-host-vrf',
                     'missing-upper-address', 'missing-upper-route', 'missing-detach', 'ineffective-detach',
                     'reordered-remaster', 'missing-vlan-readd', 'ineffective-vlan-delete',
                     'no-forwarding', 'forwarding-not-restored', 'leaked-upper', 'failed-cleanup',
                     'ignored-vrf', 'host-fallback', 'live-socket', 'outstanding-packet', 'forced-stop')
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                r = copy.deepcopy(original); rows = r['commands']
                pings = [x for x in rows if x['arguments'][:2] == ['vrf', 'exec']]
                actions = [x for x in rows if 'port_after' in x]
                bridge = [x for x in rows if x['tool'] == 'bridge']
                state = pings[0]['bridge_state']
                links = {x['ifname']: x for x in state['links']}
                if mutation == 'missing-family': rows.remove(pings[-1])
                elif mutation == 'lost-packet': pings[0]['stdout'] = '10 packets transmitted, 9 received'
                elif mutation == 'wrong-destination': pings[0]['arguments'][-1] = '192.0.2.130'
                elif mutation == 'changed-timeout': pings[0]['arguments'][-2] = '1'
                elif mutation == 'warning': pings[0]['stderr'] = 'time of day goes back'
                elif mutation == 'missing-clock': pings[0].pop('native_clock_reads')
                elif mutation == 'missing-outcome': r['original']['stdout'] = ''
                elif mutation == 'vlan-unaware': links['br1']['linkinfo']['info_data']['vlan_filtering'] = 0
                elif mutation == 'wrong-port': links['veth2']['master'] = 'other'
                elif mutation == 'missing-port-vlan':
                    next(x for x in state['vlans'] if x['ifname'] == 'veth2')['vlans'] = []
                elif mutation == 'wrong-upper-parent': links['br1.555']['link'] = 'veth1'
                elif mutation == 'wrong-upper-vid': links['br1.777']['linkinfo']['info_data']['id'] = 555
                elif mutation == 'wrong-host-vrf': links['veth3.777']['master'] = 'vveth0'
                elif mutation == 'missing-upper-address':
                    next(x for x in state['addresses'] if x['ifname'] == 'br1.555')['addr_info'] = []
                elif mutation == 'missing-upper-route': state['ipv6_routes'] = []
                elif mutation == 'missing-detach': rows.remove(actions[2])
                elif mutation == 'ineffective-detach': actions[2]['port_after'][0]['master'] = 'br1'
                elif mutation == 'reordered-remaster': rows.remove(actions[4]); rows.append(actions[4])
                elif mutation == 'missing-vlan-readd':
                    index = next(i for i, x in enumerate(rows) if x is bridge[4]); rows.pop(index)
                elif mutation == 'ineffective-vlan-delete':
                    bridge[6]['bridge_vlans_after'] = bridge[5]['bridge_vlans_after']
                elif mutation == 'no-forwarding': r['mib_after'] = r['mib_before']
                elif mutation == 'forwarding-not-restored': r['cleanup_state']['ipv6'] = '1\n'
                elif mutation == 'leaked-upper': r['cleanup_state']['links'].append(dict(ifname='br1.555'))
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
