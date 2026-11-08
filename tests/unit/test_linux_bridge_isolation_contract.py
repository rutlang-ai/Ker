"""Reject false original bridge isolation success and preserve delivery windows."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('isolation', ROOT / 'tests/posix/linux-bridge-isolation-contract.py')
contract = importlib.util.module_from_spec(spec); spec.loader.exec_module(contract)


class BridgeIsolationContractTests(unittest.TestCase):
    def test_native_isolated_and_nonisolated_matrix(self):
        fixture = json.loads(Path(__file__).with_name('bridge-isolation-transcript.json').read_text())
        cases = ('complete', 'delayed-flood', 'payload-variation', 'missing-outcome', 'skip', 'tc-unpinned',
                 'missing-capability', 'broken-capability', 'missing-isolation-setting', 'ineffective-setting',
                 'missing-ping', 'isolated-ping-succeeds', 'positive-ping-fails', 'wrong-ping-args', 'no-native-clock',
                 'missing-ping-state', 'port-not-isolated', 'nonisolated-port-isolated', 'port-blocked',
                 'same-vrf', 'wrong-peer', 'wrong-host-address', 'missing-tc-rule', 'tc-failed', 'wrong-filter-key',
                 'negative-flood-leaks', 'positive-flood-missing', 'wrong-byte-count', 'known-fdb-target',
                 'missing-frame', 'extra-frame', 'short-send', 'wrong-ether-source', 'wrong-ether-dest',
                 'wrong-ip-source', 'wrong-ip-dest', 'wrong-interface', 'wrong-mz-count', 'missing-query-proof',
                 'post-wait-traversal-missing', 'promisc-disabled', 'promisc-phase-missing', 'bridge-leaked',
                 'vrf-leaked', 'veth-up', 'promisc-leaked', 'route-leaked', 'missing-teardown', 'unexpected-error',
                 'host-fallback', 'ignored-vrf', 'wrong-send-count', 'wrong-send-bytes', 'live-socket',
                 'outstanding-packet', 'forced-stop')
        for case in cases:
            with self.subTest(case=case):
                r = copy.deepcopy(fixture); rows = r['commands']; pings = [x for x in rows if x['arguments'][:2] == ['vrf', 'exec']]
                mz = [x for x in rows if x['tool'] == 'mausezahn']; tc = [x for x in rows if x['tool'] == 'tc']
                query = [x for x in tc if x['arguments'] == contract.FSHOW]
                links = {x['ifname']: x for x in pings[0]['isolation_after']['links']}
                def rule(objects):return next(x for x in objects if x.get('options', {}).get('handle') == 101)
                def set_counter(q, key, value):
                    objects = json.loads(q['stdout']); rule(objects)['options']['actions'][0]['stats'][key] = value; q['stdout'] = json.dumps(objects)
                if case == 'delayed-flood':
                    immediate = mz[1]['isolation_after']; before = {x['ifname']: x for x in mz[1]['isolation_before']['links']}
                    for link in immediate['links']:
                        if link['ifname'] in ('veth5', 'veth4', 'veth2', 'veth3'):link['stats64'] = copy.deepcopy(before[link['ifname']]['stats64'])
                    rule(immediate['filters'])['options']['actions'][0]['stats'].update(packets=0, bytes=0, drops=0)
                elif case == 'payload-variation':
                    frame = bytearray.fromhex(r['packet_trace'][0]['frame_hex']); frame[-1] ^= 1; r['packet_trace'][0]['frame_hex'] = frame.hex()
                elif case in ('missing-outcome', 'skip'):r['original']['stdout'] = '' if case == 'missing-outcome' else 'SKIP: tc not available'
                elif case == 'tc-unpinned':r['tc_tool']['sha256'] = 'host-tool'
                elif case == 'missing-capability':rows.remove(tc[0])
                elif case == 'broken-capability':tc[0]['stderr'] = 'unknown option'
                elif case == 'missing-isolation-setting':rows.remove(next(x for x in rows if 'isolated' in x['arguments']))
                elif case == 'ineffective-setting':
                    setting = next(x for x in rows if 'isolated' in x['arguments']); next(x for x in setting['isolation_after']['links'] if x['ifname'] == 'veth1')['linkinfo']['info_slave_data']['isolated'] = False
                elif case == 'missing-ping':rows.remove(pings[0])
                elif case == 'isolated-ping-succeeds':pings[0]['returncode'] = 0
                elif case == 'positive-ping-fails':pings[1]['returncode'] = 1
                elif case == 'wrong-ping-args':pings[0]['arguments'][5] = '1'
                elif case == 'no-native-clock':pings[1]['native_clock_reads'] = 0
                elif case == 'missing-ping-state':pings[0].pop('isolation_after')
                elif case == 'port-not-isolated':links['veth1']['linkinfo']['info_slave_data']['isolated'] = False
                elif case == 'nonisolated-port-isolated':links['veth4']['linkinfo']['info_slave_data']['isolated'] = True
                elif case == 'port-blocked':links['veth2']['linkinfo']['info_slave_data']['state'] = 'blocking'
                elif case == 'same-vrf':links['vveth5']['linkinfo']['info_data']['table'] = links['vveth0']['linkinfo']['info_data']['table']
                elif case == 'wrong-peer':links['veth4']['link'] = 'veth0'
                elif case == 'wrong-host-address':next(x for x in pings[0]['isolation_after']['addresses'] if x['ifname'] == 'veth0')['addr_info'] = []
                elif case == 'missing-tc-rule':rows.remove(tc[2])
                elif case == 'tc-failed':tc[2]['returncode'] = 1
                elif case == 'wrong-filter-key':rule(mz[0]['isolation_before']['filters'])['options']['keys']['dst_mac'] = '00:00:00:00:00:00'
                elif case == 'negative-flood-leaks':set_counter(query[0], 'packets', 1)
                elif case == 'positive-flood-missing':set_counter(query[1], 'packets', 0)
                elif case == 'wrong-byte-count':set_counter(query[1], 'bytes', 98)
                elif case == 'known-fdb-target':mz[0]['isolation_before']['fdb'].append(dict(mac=contract.MAC))
                elif case == 'missing-frame':r['packet_trace'] = []
                elif case == 'extra-frame':r['packet_trace'].append(copy.deepcopy(r['packet_trace'][0]))
                elif case == 'short-send':r['packet_trace'][0]['result'] -= 1
                elif case in ('wrong-ether-source', 'wrong-ether-dest', 'wrong-ip-source', 'wrong-ip-dest'):
                    frame = bytearray.fromhex(r['packet_trace'][0]['frame_hex']); frame[{'wrong-ether-source':6,'wrong-ether-dest':0,'wrong-ip-source':29,'wrong-ip-dest':33}[case]] ^= 1; r['packet_trace'][0]['frame_hex'] = frame.hex()
                elif case == 'wrong-interface':r['packet_trace'][1]['ifindex'] = -1
                elif case == 'wrong-mz-count':mz[1]['arguments'][2] = '0'
                elif case == 'missing-query-proof':query[1].pop('isolation_after')
                elif case == 'post-wait-traversal-missing':
                    before = {x['ifname']:x for x in mz[1]['isolation_before']['links']}
                    for link in query[1]['isolation_after']['links']:
                        if link['ifname'] in ('veth2','veth3'):link['stats64'] = copy.deepcopy(before[link['ifname']]['stats64'])
                elif case == 'promisc-disabled':next(x for x in mz[0]['isolation_before']['links'] if x['ifname']=='veth3')['promiscuity']=0
                elif case == 'promisc-phase-missing':rows.remove(next(x for x in rows if 'promisc' in x['arguments']))
                elif case in ('bridge-leaked','vrf-leaked'):r['cleanup_state']['links'].append(dict(ifname='br0' if case=='bridge-leaked' else 'vveth5'))
                elif case == 'veth-up':next(x for x in r['cleanup_state']['links'] if x['ifname']=='veth5')['flags'].append('UP')
                elif case == 'promisc-leaked':next(x for x in r['cleanup_state']['links'] if x['ifname']=='veth3')['promiscuity']=1
                elif case == 'route-leaked':r['cleanup_state']['ipv6_routes'].append(dict(dev='veth4'))
                elif case == 'missing-teardown':rows.remove(next(x for x in rows if x['arguments']==['link','del','dev','br0']))
                elif case == 'unexpected-error':rows[-1]['returncode']=1
                elif case == 'host-fallback':r['missing_backend_control']['returncode']=0
                elif case == 'ignored-vrf':r['vrf_binding_control']['unknown_vrf']['returncode']=0
                elif case == 'wrong-send-count':r['native_fixture']['bridge_packet_sends']=0
                elif case == 'wrong-send-bytes':r['native_fixture']['bridge_packet_bytes']=0
                elif case == 'live-socket':r['native_fixture']['live']=1
                elif case == 'outstanding-packet':r['stats']['outstanding']=1
                elif case == 'forced-stop':r['stats']['shutdown_timed_out']=True
                if case in ('complete','delayed-flood','payload-variation'):contract.validate_evidence(r)
                else:
                    with self.assertRaises(RuntimeError):contract.validate_evidence(r)


if __name__ == '__main__':unittest.main()
