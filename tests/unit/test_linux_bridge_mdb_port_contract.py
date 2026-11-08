"""Reject false MDB port-down success without real native multicast counters."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('mdb_port', ROOT / 'tests/posix/linux-bridge-mdb-port-contract.py')
contract = importlib.util.module_from_spec(spec); spec.loader.exec_module(contract)


class BridgeMdbPortContractTests(unittest.TestCase):
    def test_native_port_down_membership_and_multicast_windows(self):
        fixture = json.loads(Path(__file__).with_name('bridge-mdb-port-transcript.json').read_text())
        cases = ('complete', 'asynchronous-first-send', 'payload-fill-variation', 'missing-outcome', 'skip', 'diagnostic', 'tc-unpinned',
                 'wrong-tc-source', 'missing-mdb-add', 'missing-mdb-delete', 'add-failed', 'add-while-up',
                 'delete-while-up', 'mdb-add-ineffective', 'mdb-delete-ineffective', 'wrong-mdb-port',
                 'wrong-mdb-index', 'temporary-mdb', 'flood-enabled', 'querier-disabled', 'snooping-disabled',
                 'wrong-peer', 'same-vrf', 'missing-state', 'missing-tc-rule', 'tc-rule-failed', 'tc-host-rule',
                 'wrong-flower-key', 'not-drop-action', 'missing-first-counter', 'negative-counter-nonzero',
                 'wrong-byte-counter', 'tc-delete-missing', 'missing-send', 'wrong-send-count', 'send-failed',
                 'missing-packet', 'duplicate-packet', 'short-packet-send', 'wrong-packet-source', 'wrong-packet-dest',
                 'wrong-packet-protocol', 'wrong-udp-port', 'wrong-ifindex', 'source-not-sent',
                 'query-missing-traversal', 'reordered-mdb-delete', 'bridge-leaked', 'vrf-leaked', 'veth-left-up',
                 'mdb-leaked', 'route-leaked', 'missing-cleanup', 'host-fallback', 'ignored-vrf', 'wrong-send-bytes',
                 'packet-trace-error', 'live-socket', 'outstanding-packet', 'forced-stop')
        for case in cases:
            with self.subTest(case=case):
                r = copy.deepcopy(fixture); rows = r['commands']; bridge = [x for x in rows if x['tool'] == 'bridge']
                mz = [x for x in rows if x['tool'] == 'mausezahn']; tc = [x for x in rows if x['tool'] == 'tc']
                queries = [x for x in tc if x['arguments'] == contract.FSHOW]
                after = mz[0]['mdb_port_after']; links = {x['ifname']: x for x in after['links']}
                def rule(row):
                    return next(x for x in row if x.get('options', {}).get('handle') == 101)
                def counter(query, field, value):
                    objects = json.loads(query['stdout']); rule(objects)['options']['actions'][0]['stats'][field] = value; query['stdout'] = json.dumps(objects)
                if case == 'asynchronous-first-send':
                    stats = rule(after['filters'])['options']['actions'][0]['stats']; stats.update(packets=0, bytes=0, drops=0)
                    for dev, direction in (('veth2', 'tx'), ('veth3', 'rx')):
                        links[dev]['stats64'][direction] = copy.deepcopy(
                            next(x for x in mz[0]['mdb_port_before']['links'] if x['ifname'] == dev)['stats64'][direction])
                elif case == 'payload-fill-variation':
                    frame = bytearray.fromhex(r['packet_trace'][0]['frame_hex']); frame[42] ^= 1
                    frame[40:42] = b'\x00\x00'  # IPv4 UDP permits an omitted checksum.
                    r['packet_trace'][0]['frame_hex'] = frame.hex()
                elif case in ('missing-outcome', 'skip'): r['original']['stdout'] = '' if case == 'missing-outcome' else 'SKIP: unsupported'
                elif case == 'diagnostic': r['original']['stderr'] = 'unrelated warning'
                elif case == 'tc-unpinned': r['tc_tool']['sha256'] = 'ambient-host-tc'
                elif case == 'wrong-tc-source': r['iproute2']['source_hashes']['tc/tc.c'] = 'other'
                elif case == 'missing-mdb-add': rows.remove(bridge[1])
                elif case == 'missing-mdb-delete': rows.remove(bridge[3])
                elif case == 'add-failed': bridge[1]['returncode'] = 1
                elif case in ('add-while-up', 'delete-while-up'):
                    operation = bridge[1 if case == 'add-while-up' else 3]
                    next(x for x in operation['mdb_port_before']['links'] if x['ifname'] == 'veth2')['flags'].append('UP')
                elif case == 'mdb-add-ineffective': bridge[1]['mdb_port_after']['mdb'] = copy.deepcopy(bridge[1]['mdb_port_before']['mdb'])
                elif case == 'mdb-delete-ineffective': bridge[3]['mdb_port_after']['mdb'] = copy.deepcopy(bridge[3]['mdb_port_before']['mdb'])
                elif case in ('wrong-mdb-port', 'wrong-mdb-index', 'temporary-mdb'):
                    record = contract.group_rows(bridge[1]['mdb_port_after'])[0]
                    record[{'wrong-mdb-port':'port','wrong-mdb-index':'index','temporary-mdb':'state'}[case]] = {'wrong-mdb-port':'veth1','wrong-mdb-index':-1,'temporary-mdb':'temp'}[case]
                elif case == 'flood-enabled': links['veth2']['linkinfo']['info_slave_data']['mcast_flood'] = True
                elif case in ('querier-disabled', 'snooping-disabled'): links['br0']['linkinfo']['info_data']['mcast_querier' if case == 'querier-disabled' else 'mcast_snooping'] = 0
                elif case == 'wrong-peer': links['veth2']['link'] = 'veth0'
                elif case == 'same-vrf': links['vveth3']['linkinfo']['info_data']['table'] = links['vveth0']['linkinfo']['info_data']['table']
                elif case == 'missing-state': mz[0].pop('mdb_port_after')
                elif case == 'missing-tc-rule': rows.remove(tc[1])
                elif case == 'tc-rule-failed': tc[1]['returncode'] = 1
                elif case in ('tc-host-rule', 'wrong-flower-key', 'not-drop-action'):
                    options = rule(mz[0]['mdb_port_before']['filters'])['options']
                    if case == 'tc-host-rule': options['not_in_hw'] = False
                    elif case == 'wrong-flower-key': options['keys']['dst_mac'] = '00:00:00:00:00:00'
                    else: options['actions'][0]['control_action']['type'] = 'pass'
                elif case == 'missing-first-counter': counter(queries[0], 'packets', 0)
                elif case == 'negative-counter-nonzero': counter(queries[1], 'packets', 1)
                elif case == 'wrong-byte-counter': counter(queries[0], 'bytes', 106)
                elif case == 'tc-delete-missing': rows.remove(tc[4])
                elif case == 'missing-send': rows.remove(mz[0])
                elif case == 'wrong-send-count': mz[0]['arguments'][2] = '0'
                elif case == 'send-failed': mz[0]['returncode'] = 1
                elif case == 'missing-packet': r['packet_trace'] = []
                elif case == 'duplicate-packet': r['packet_trace'].append(copy.deepcopy(r['packet_trace'][0]))
                elif case == 'short-packet-send': r['packet_trace'][0]['result'] -= 1
                elif case in ('wrong-packet-source', 'wrong-packet-dest', 'wrong-packet-protocol', 'wrong-udp-port'):
                    frame = bytearray.fromhex(r['packet_trace'][0]['frame_hex']); frame[{'wrong-packet-source':6,'wrong-packet-dest':0,'wrong-packet-protocol':23,'wrong-udp-port':36}[case]] ^= 1; r['packet_trace'][0]['frame_hex'] = frame.hex()
                elif case == 'wrong-ifindex': r['packet_trace'][0]['ifindex'] = -1
                elif case == 'source-not-sent':
                    dev, direction = 'veth0', 'tx'
                    next(x for x in queries[0]['mdb_port_after']['links'] if x['ifname'] == dev)['stats64'][direction] = copy.deepcopy(
                        next(x for x in mz[0]['mdb_port_before']['links'] if x['ifname'] == dev)['stats64'][direction])
                elif case == 'query-missing-traversal':
                    query_after = queries[0]['mdb_port_after']
                    query_links = {x['ifname']: x for x in query_after['links']}
                    before_links = {x['ifname']: x for x in mz[0]['mdb_port_before']['links']}
                    self.assertEqual(rule(json.loads(queries[0]['stdout']))['options']['actions'][0]['stats']['packets'], 1)
                    for dev, direction in (('veth2', 'tx'), ('veth3', 'rx')):
                        query_links[dev]['stats64'][direction] = copy.deepcopy(before_links[dev]['stats64'][direction])
                elif case == 'reordered-mdb-delete': rows.remove(bridge[3]); rows.append(bridge[3])
                elif case in ('bridge-leaked', 'vrf-leaked'): r['cleanup_state']['links'].append(dict(ifname='br0' if case == 'bridge-leaked' else 'vveth3'))
                elif case == 'veth-left-up': next(x for x in r['cleanup_state']['links'] if x['ifname'] == 'veth2')['flags'].append('UP')
                elif case == 'mdb-leaked': r['cleanup_state']['mdb'] = copy.deepcopy(bridge[1]['mdb_port_after']['mdb'])
                elif case == 'route-leaked': r['cleanup_state']['ipv4_routes'].append(dict(dev='veth2'))
                elif case == 'missing-cleanup': rows.remove(next(x for x in rows if x['arguments'] == ['link', 'del', 'dev', 'br0']))
                elif case == 'host-fallback': r['missing_backend_control']['returncode'] = 0
                elif case == 'ignored-vrf': r['vrf_binding_control']['unknown_vrf']['returncode'] = 0
                elif case == 'wrong-send-bytes': r['native_fixture']['bridge_packet_bytes'] = 0
                elif case == 'packet-trace-error': r['native_fixture']['bridge_packet_trace_errors'] = 1
                elif case == 'live-socket': r['native_fixture']['live'] = 1
                elif case == 'outstanding-packet': r['stats']['outstanding'] = 1
                elif case == 'forced-stop': r['stats']['shutdown_timed_out'] = True
                if case == 'asynchronous-first-send':
                    early = rule(after['filters'])['options']['actions'][0]['stats']
                    self.assertEqual((early['packets'], early['bytes'], early['drops']), (0, 0, 0))
                    for dev, direction in (('veth2', 'tx'), ('veth3', 'rx')):
                        self.assertEqual(links[dev]['stats64'][direction],
                                         next(x for x in mz[0]['mdb_port_before']['links'] if x['ifname'] == dev)['stats64'][direction])
                    contract.validate_evidence(r)
                elif case in ('complete', 'payload-fill-variation'): contract.validate_evidence(r)
                else:
                    with self.assertRaises(RuntimeError): contract.validate_evidence(r)


if __name__ == '__main__': unittest.main()
