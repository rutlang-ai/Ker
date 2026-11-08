"""Reject ineffective PVID upper lifecycles and hidden base-route changes."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('bridge_pvid_upper', ROOT / 'tests/posix/linux-bridge-pvid-upper-contract.py')
contract = importlib.util.module_from_spec(spec); spec.loader.exec_module(contract)


class BridgePvidUpperContractTests(unittest.TestCase):
    def test_actual_original_upper_and_pvid_routing_lifecycle(self):
        original = json.loads(Path(__file__).with_name('bridge-pvid-upper-transcript.json').read_text())
        mutations = ('complete', 'missing-ping', 'lost-packet', 'changed-timeout', 'warning', 'missing-clock',
                     'missing-outcome', 'changed-pvid', 'wrong-upper-parent', 'wrong-upper-vid',
                     'upper-not-up', 'missing-upper-address', 'missing-upper-route', 'leaked-upper-route',
                     'base-address-lost', 'base-route-lost', 'pvid-lost-during-upper', 'missing-delete',
                     'reordered-delete', 'ineffective-vlan-delete', 'no-forwarding', 'sysctl-not-restored',
                     'leaked-device', 'failed-cleanup', 'host-fallback', 'ignored-vrf', 'live-socket',
                     'outstanding-packet', 'forced-stop')
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                r = copy.deepcopy(original); rows = r['commands']
                pings = [x for x in rows if x['arguments'][:2] == ['vrf', 'exec']]
                actions = [x for x in rows if 'upper_after' in x]
                added = actions[2]['upper_after']
                links = {x['ifname']: x for x in added['links']}
                if mutation == 'missing-ping': rows.remove(pings[-1])
                elif mutation == 'lost-packet': pings[0]['stdout'] = '10 packets transmitted, 9 received'
                elif mutation == 'changed-timeout': pings[0]['arguments'][-2] = '1'
                elif mutation == 'warning': pings[0]['stderr'] = 'time of day goes back'
                elif mutation == 'missing-clock': pings[0].pop('native_clock_reads')
                elif mutation == 'missing-outcome': r['original']['stdout'] = ''
                elif mutation == 'changed-pvid': links['br1']['linkinfo']['info_data']['vlan_default_pvid'] = 1
                elif mutation == 'wrong-upper-parent': links['br1.10']['link'] = 'veth1'
                elif mutation == 'wrong-upper-vid': links['br1.10']['linkinfo']['info_data']['id'] = 20
                elif mutation == 'upper-not-up': links['br1.10']['flags'].remove('UP')
                elif mutation == 'missing-upper-address':
                    next(x for x in added['addresses'] if x['ifname'] == 'br1.10')['addr_info'] = []
                elif mutation == 'missing-upper-route':
                    added['ipv4_routes'] = [x for x in added['ipv4_routes'] if x.get('dev') != 'br1.10']
                elif mutation == 'leaked-upper-route':
                    actions[3]['upper_after']['ipv4_routes'].extend(x for x in added['ipv4_routes'] if x.get('dev') == 'br1.10')
                elif mutation == 'base-address-lost':
                    next(x for x in added['addresses'] if x['ifname'] == 'br1')['addr_info'] = []
                elif mutation == 'base-route-lost': added['ipv6_routes'] = []
                elif mutation == 'pvid-lost-during-upper':
                    next(x for x in added['vlans'] if x['ifname'] == 'br1')['vlans'][0]['flags'] = []
                elif mutation == 'missing-delete': rows.remove(actions[-1])
                elif mutation == 'reordered-delete': rows.remove(actions[-1]); rows.append(actions[-1])
                elif mutation == 'ineffective-vlan-delete':
                    bridge = [x for x in rows if x['tool'] == 'bridge']
                    bridge[2]['bridge_vlans_after'] = bridge[1]['bridge_vlans_after']
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
