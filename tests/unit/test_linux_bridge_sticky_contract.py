"""Reject false sticky FDB success without actual spoofed source ingress."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('sticky', ROOT / 'tests/posix/linux-bridge-sticky-contract.py')
contract = importlib.util.module_from_spec(spec); spec.loader.exec_module(contract)


class BridgeStickyContractTests(unittest.TestCase):
    def test_actual_original_sticky_fdb_and_packet_proof(self):
        original = json.loads(Path(__file__).with_name('bridge-sticky-transcript.json').read_text())
        mutations = ('complete', 'missing-outcome', 'missing-add', 'missing-delete', 'add-failed',
                     'missing-mz', 'mz-failed', 'wrong-source-argument', 'wrong-count', 'wrong-interface',
                     'reordered-packet', 'missing-state', 'missing-sticky', 'wrong-state', 'fdb-moved',
                     'vlan0-lost', 'vlan1-retained', 'add-ineffective', 'final-query-empty',
                     'vlan-filtering', 'wrong-pvid', 'bridge-down', 'port-detached', 'port-blocked',
                     'learning-disabled', 'host-mastered', 'wrong-peer', 'missing-packet', 'duplicate-packet',
                     'short-send', 'wrong-family', 'wrong-ifindex', 'wrong-ether-source', 'wrong-ether-destination',
                     'wrong-protocol', 'wrong-arp-opcode', 'source-tx-missing', 'ingress-rx-missing',
                     'peer-tx-missing', 'destination-rx-missing', 'missing-packet-socket', 'wrong-send-count',
                     'wrong-send-bytes', 'trace-error', 'bridge-leaked', 'veth-left-up', 'fdb-leaked',
                     'route-leaked', 'missing-teardown', 'cleanup-failed', 'unexpected-diagnostic',
                     'host-fallback', 'ignored-vrf', 'live-socket', 'outstanding-packet', 'forced-stop')
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                r = copy.deepcopy(original); rows = r['commands']; bridge = [x for x in rows if x['tool'] == 'bridge']
                mz = next(x for x in rows if x['tool'] == 'mausezahn')
                state = mz['sticky_after']; links = {x['ifname']: x for x in state['links']}
                target = next(x for x in state['fdb'] if x['mac'] == contract.MAC)
                if mutation == 'missing-outcome': r['original']['stdout'] = ''
                elif mutation == 'missing-add': rows.remove(bridge[0])
                elif mutation == 'missing-delete': rows.remove(bridge[1])
                elif mutation == 'add-failed': bridge[0]['returncode'] = 1
                elif mutation == 'missing-mz': rows.remove(mz)
                elif mutation == 'mz-failed': mz['returncode'] = 1
                elif mutation == 'wrong-source-argument': mz['arguments'][4] = 'de:ad:be:ef:13:38'
                elif mutation == 'wrong-count': mz['arguments'][2] = '0'
                elif mutation == 'wrong-interface': mz['arguments'][0] = 'veth0'
                elif mutation == 'reordered-packet': rows.remove(mz); rows.append(mz)
                elif mutation == 'missing-state': bridge[1].pop('sticky_after')
                elif mutation == 'missing-sticky': target['flags'] = []
                elif mutation == 'wrong-state': target['state'] = 'permanent'
                elif mutation == 'fdb-moved': target['ifname'] = 'veth3'
                elif mutation == 'vlan0-lost': bridge[1]['sticky_after']['fdb'] = []
                elif mutation == 'vlan1-retained': bridge[1]['sticky_after'] = bridge[1]['sticky_before']
                elif mutation == 'add-ineffective': bridge[0]['sticky_after'] = bridge[0]['sticky_before']
                elif mutation == 'final-query-empty': bridge[2]['stdout'] = '[]'
                elif mutation == 'vlan-filtering': links['br0']['linkinfo']['info_data']['vlan_filtering'] = 1
                elif mutation == 'wrong-pvid': links['br0']['linkinfo']['info_data']['vlan_default_pvid'] = 0
                elif mutation == 'bridge-down': links['br0']['flags'].remove('UP')
                elif mutation == 'port-detached': links['veth3'].pop('master')
                elif mutation == 'port-blocked': links['veth3']['linkinfo']['info_slave_data']['state'] = 'blocking'
                elif mutation == 'learning-disabled': links['veth3']['linkinfo']['info_slave_data']['learning'] = False
                elif mutation == 'host-mastered': links['veth2']['master'] = 'br0'
                elif mutation == 'wrong-peer': links['veth2']['link'] = 'veth1'
                elif mutation == 'missing-packet': r['packet_trace'] = []
                elif mutation == 'duplicate-packet': r['packet_trace'].append(copy.deepcopy(r['packet_trace'][0]))
                elif mutation == 'short-send': r['packet_trace'][0]['result'] -= 1
                elif mutation == 'wrong-family': r['packet_trace'][0]['family'] = 2
                elif mutation == 'wrong-ifindex': r['packet_trace'][0]['ifindex'] = 1
                elif mutation in ('wrong-ether-source', 'wrong-ether-destination', 'wrong-protocol', 'wrong-arp-opcode'):
                    frame = bytearray.fromhex(r['packet_trace'][0]['frame_hex'])
                    frame[{'wrong-ether-source':6, 'wrong-ether-destination':0, 'wrong-protocol':12, 'wrong-arp-opcode':21}[mutation]] ^= 1
                    r['packet_trace'][0]['frame_hex'] = frame.hex()
                elif mutation in ('source-tx-missing', 'ingress-rx-missing', 'peer-tx-missing', 'destination-rx-missing'):
                    dev, direction = {'source-tx-missing':('veth2','tx'), 'ingress-rx-missing':('veth3','rx'),
                                      'peer-tx-missing':('veth1','tx'), 'destination-rx-missing':('veth0','rx')}[mutation]
                    first = next(x for x in mz['sticky_before']['links'] if x['ifname'] == dev)
                    links[dev]['stats64'][direction] = copy.deepcopy(first['stats64'][direction])
                elif mutation == 'missing-packet-socket': r['native_fixture']['bridge_packet_sockets'] = 0
                elif mutation == 'wrong-send-count': r['native_fixture']['bridge_packet_sends'] = 0
                elif mutation == 'wrong-send-bytes': r['native_fixture']['bridge_packet_bytes'] = 0
                elif mutation == 'trace-error': r['native_fixture']['bridge_packet_trace_errors'] = 1
                elif mutation == 'bridge-leaked': r['cleanup_state']['links'].append(dict(ifname='br0'))
                elif mutation == 'veth-left-up': next(x for x in r['cleanup_state']['links'] if x['ifname'] == 'veth2')['flags'].append('UP')
                elif mutation == 'fdb-leaked': r['cleanup_state']['fdb'].append(copy.deepcopy(target))
                elif mutation == 'route-leaked': r['cleanup_state']['ipv4_routes'].append(dict(dev='veth3'))
                elif mutation == 'missing-teardown': rows.remove(next(x for x in rows if x['arguments'] == ['link','del','dev','br0']))
                elif mutation == 'cleanup-failed': rows[-1]['returncode'] = 1
                elif mutation == 'unexpected-diagnostic': r['original']['stderr'] += 'unrelated failure'
                elif mutation == 'host-fallback': r['missing_backend_control']['returncode'] = 0
                elif mutation == 'ignored-vrf': r['vrf_binding_control']['unknown_vrf']['returncode'] = 0
                elif mutation == 'live-socket': r['native_fixture']['live'] = 1
                elif mutation == 'outstanding-packet': r['stats']['outstanding'] = 1
                elif mutation == 'forced-stop': r['stats']['shutdown_timed_out'] = True
                if mutation == 'complete': contract.validate_evidence(r)
                else:
                    with self.assertRaises(RuntimeError): contract.validate_evidence(r)


if __name__ == '__main__': unittest.main()
