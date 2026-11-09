"""Require actual bridge host-port MAC/IPv4/IPv6 MDB add and delete effects."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('mdb_host', ROOT / 'tests/posix/linux-bridge-mdb-host-contract.py')
contract = importlib.util.module_from_spec(spec); spec.loader.exec_module(contract)


class BridgeMdbHostContractTests(unittest.TestCase):
    def test_complete_original_native_mdb_and_reject_incomplete_evidence(self):
        original = json.loads(Path(__file__).with_name('bridge-mdb-host-transcript.json').read_text())
        mutations = ('complete', 'missing-outcome', 'missing-group', 'wrong-order', 'explicit-ip-state',
                     'add-failed', 'delete-failed', 'show-wrong-state', 'show-after-delete-present',
                     'missing-before', 'missing-after', 'add-ineffective', 'delete-ineffective',
                     'wrong-port', 'wrong-device', 'wrong-group', 'wrong-state', 'wrong-index',
                     'prior-target-present', 'other-target-leaked', 'snooping-disabled', 'bridge-down',
                     'port-detached', 'port-blocked', 'wrong-peer', 'host-wrong-vrf', 'vrf-down',
                     'host-address-missing', 'address-on-bridge', 'ipv4-route-missing', 'ipv6-wrong-table',
                     'after-host-address-lost', 'bridge-leaked', 'vrf-leaked', 'veth-left-up',
                     'address-leaked', 'route-leaked', 'mdb-leaked', 'forwarding-changed',
                     'missing-teardown', 'cleanup-failed', 'host-fallback', 'ignored-vrf',
                     'live-socket', 'outstanding-packet', 'forced-stop')
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                r = copy.deepcopy(original); rows = r['commands']
                bridge = [x for x in rows if x['tool'] == 'bridge']
                state = bridge[0]['mdb_after']; links = {x['ifname']: x for x in state['links']}
                target = next(x for x in contract.entries(state['mdb']) if x['grp'] == contract.GROUPS[0][0])
                if mutation == 'missing-outcome': r['original']['stdout'] = ''
                elif mutation == 'missing-group': rows[:] = [x for x in rows if x not in bridge[4:8]]
                elif mutation == 'wrong-order':
                    i = rows.index(bridge[0]); rows[i:i+4] = bridge[1:4] + bridge[:1]
                elif mutation == 'explicit-ip-state': bridge[4]['arguments'].append('temp')
                elif mutation == 'add-failed': bridge[0]['returncode'] = 1
                elif mutation == 'delete-failed': bridge[2]['returncode'] = 1
                elif mutation == 'show-wrong-state': bridge[1]['stdout'] = bridge[1]['stdout'].replace('permanent', 'temp')
                elif mutation == 'show-after-delete-present': bridge[3]['stdout'] += 'dev br0 port br0 grp 01:00:01:c0:ff:ee permanent\n'
                elif mutation == 'missing-before': bridge[0].pop('mdb_before')
                elif mutation == 'missing-after': bridge[0].pop('mdb_after')
                elif mutation == 'add-ineffective': bridge[0]['mdb_after'] = bridge[0]['mdb_before']
                elif mutation == 'delete-ineffective': bridge[2]['mdb_after'] = bridge[2]['mdb_before']
                elif mutation == 'wrong-port': target['port'] = 'veth1'
                elif mutation == 'wrong-device': target['dev'] = 'other-bridge'
                elif mutation == 'wrong-group': target['grp'] = '225.1.2.3'
                elif mutation == 'wrong-state': target['state'] = 'temp'
                elif mutation == 'wrong-index': target['index'] += 1
                elif mutation == 'prior-target-present': bridge[0]['mdb_before']['mdb'][0]['mdb'].append(copy.deepcopy(target))
                elif mutation == 'other-target-leaked':
                    extra = copy.deepcopy(target); extra['grp'] = 'ff02::42'; state['mdb'][0]['mdb'].append(extra)
                elif mutation == 'snooping-disabled': links['br0']['linkinfo']['info_data']['mcast_snooping'] = 0
                elif mutation == 'bridge-down': links['br0']['flags'].remove('UP')
                elif mutation == 'port-detached': links['veth1'].pop('master')
                elif mutation == 'port-blocked': links['veth1']['linkinfo']['info_slave_data']['state'] = 'blocking'
                elif mutation == 'wrong-peer': links['veth1']['link'] = 'lo'
                elif mutation == 'host-wrong-vrf': links['veth0']['master'] = 'other-vrf'
                elif mutation == 'vrf-down': links['vveth0']['flags'].remove('UP')
                elif mutation == 'host-address-missing': next(x for x in state['addresses'] if x['ifname'] == 'veth0')['addr_info'] = []
                elif mutation == 'address-on-bridge': next(x for x in state['addresses'] if x['ifname'] == 'br0')['addr_info'].append(dict(scope='global'))
                elif mutation == 'ipv4-route-missing': state['ipv4_routes'] = []
                elif mutation == 'ipv6-wrong-table':
                    next(x for x in state['ipv6_routes'] if x.get('dst') == '2001:db8:1::/64')['table'] = 'main'
                elif mutation == 'after-host-address-lost':
                    next(x for x in bridge[5]['mdb_after']['addresses'] if x['ifname'] == 'veth0')['addr_info'] = []
                elif mutation == 'bridge-leaked': r['cleanup_state']['links'].append(dict(ifname='br0'))
                elif mutation == 'vrf-leaked': r['cleanup_state']['links'].append(dict(ifname='vveth0'))
                elif mutation == 'veth-left-up': next(x for x in r['cleanup_state']['links'] if x['ifname'] == 'veth0')['flags'].append('UP')
                elif mutation == 'address-leaked': next(x for x in r['cleanup_state']['addresses'] if x['ifname'] == 'veth0')['addr_info'].append(dict(scope='global'))
                elif mutation == 'route-leaked': r['cleanup_state']['ipv6_routes'].append(dict(dev='veth0'))
                elif mutation == 'mdb-leaked': r['cleanup_state']['mdb'][0]['mdb'].append(copy.deepcopy(target))
                elif mutation == 'forwarding-changed': r['cleanup_state']['ipv4'] = '1\n'
                elif mutation == 'missing-teardown': rows.remove(next(x for x in rows if x['arguments'] == ['link', 'del', 'dev', 'br0']))
                elif mutation == 'cleanup-failed': rows[-1]['returncode'] = 1
                elif mutation == 'host-fallback': r['missing_backend_control']['returncode'] = 0
                elif mutation == 'ignored-vrf': r['vrf_binding_control']['unknown_vrf']['returncode'] = 0
                elif mutation == 'live-socket': r['native_fixture']['live'] = 1
                elif mutation == 'outstanding-packet': r['stats']['outstanding'] = 1
                elif mutation == 'forced-stop': r['stats']['shutdown_timed_out'] = True
                if mutation == 'complete': contract.validate_evidence(r)
                else:
                    with self.assertRaises(RuntimeError): contract.validate_evidence(r)


if __name__ == '__main__': unittest.main()
