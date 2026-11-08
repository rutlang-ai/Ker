"""Reject ineffective VLAN switching, missing traffic and incomplete cleanup."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('bridge_vlan', ROOT / 'tests/posix/linux-bridge-vlan-contract.py')
contract = importlib.util.module_from_spec(spec); spec.loader.exec_module(contract)


class BridgeVlanContractTests(unittest.TestCase):
    def test_complete_original_switching_and_native_evidence_are_required(self):
        original = json.loads(Path(__file__).with_name('bridge-vlan-transcript.json').read_text())
        for mutation in ('complete', 'missing-family', 'lost-packet', 'isolation-bypass', 'warning', 'timeout',
                         'missing-vlan333', 'reordered-switch', 'missing-transient-vlan', 'stale-pvid',
                         'wrong-port-membership', 'wrong-host-vlan', 'no-forwarding', 'not-restored',
                         'leaked-vlan', 'failed-cleanup', 'ignored-vrf', 'host-fallback', 'live-socket',
                         'outstanding-packet', 'forced-stop', 'missing-clock'):
            with self.subTest(mutation=mutation):
                r = copy.deepcopy(original); rows = r['commands']
                pings = [x for x in rows if x['arguments'][:2] == ['vrf','exec']]
                bridge = [x for x in rows if x['tool'] == 'bridge']
                if mutation == 'missing-family': rows.remove(pings[-1])
                elif mutation == 'lost-packet': pings[0]['stdout'] = '10 packets transmitted, 9 received'
                elif mutation == 'isolation-bypass': pings[2]['returncode'] = 0
                elif mutation == 'warning': pings[0]['stderr'] = 'native filter warning'
                elif mutation == 'timeout': pings[0]['arguments'][-2] = '1'
                elif mutation == 'missing-vlan333': rows.remove(bridge[3])
                elif mutation == 'reordered-switch': rows.remove(bridge[5]); rows.append(bridge[5])
                elif mutation == 'missing-transient-vlan':
                    for x in bridge[3]['bridge_vlans_after']:
                        x['vlans'] = [v for v in x['vlans'] if v['vlan'] != 333]
                elif mutation == 'stale-pvid': pings[2]['bridge_state']['vlans'][0]['vlans'][0]['vlan'] = 555
                elif mutation == 'wrong-port-membership': pings[0]['bridge_state']['port_vlans'][0]['vlans'].pop()
                elif mutation == 'wrong-host-vlan': pings[0]['bridge_state']['host_vlans'][0]['linkinfo']['info_data']['id'] = 999
                elif mutation == 'no-forwarding': r['mib_after'] = r['mib_before']
                elif mutation == 'not-restored': r['cleanup_state']['ipv6'] = '1\n'
                elif mutation == 'leaked-vlan': r['cleanup_state']['links'].append(dict(ifname='veth0.555'))
                elif mutation == 'failed-cleanup': rows[-1]['returncode'] = 1
                elif mutation == 'ignored-vrf': r['vrf_binding_control']['unknown_vrf']['returncode'] = 0
                elif mutation == 'host-fallback': r['missing_backend_control']['returncode'] = 0
                elif mutation == 'live-socket': r['native_fixture']['live'] = 1
                elif mutation == 'outstanding-packet': r['stats']['outstanding'] = 1
                elif mutation == 'forced-stop': r['stats']['shutdown_timed_out'] = True
                elif mutation == 'missing-clock': pings[0].pop('native_clock_reads')
                if mutation == 'complete': contract.validate_evidence(r)
                else:
                    with self.assertRaises(RuntimeError): contract.validate_evidence(r)


if __name__ == '__main__': unittest.main()
