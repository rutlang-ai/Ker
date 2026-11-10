"""Reject false original OK output without native multicast and expiry evidence."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('mcast', ROOT / 'tests/posix/linux-bridge-mcast-contract.py')
contract = importlib.util.module_from_spec(spec); spec.loader.exec_module(contract)


class BridgeMcastContractTests(unittest.TestCase):
    def test_complete_native_vlan_multicast_and_real_membership_expiry(self):
        fixture = json.loads(Path(__file__).with_name('bridge-mcast-transcript.json').read_text())
        cases = ('complete', 'expired-absent', 'delayed-send-observation', 'missing-outcome', 'skip', 'unpinned-tc',
                 'missing-command', 'wrong-command-order', 'unexpected-error', 'warning',
                 'wrong-default', 'ineffective-scalar', 'ineffective-router-set', 'missing-global-range',
                 'bridge-down', 'snooping-disabled', 'vlan-disabled', 'vlan-snooping-disabled', 'wrong-peer', 'port-detached', 'port-blocked',
                 'host-vrf-wrong', 'same-vrf', 'host-vlan-wrong', 'host-address-missing', 'vid11-missing',
                 'query-short-wait', 'query-zero-count', 'query-wrong-bytes', 'query-xstats-mismatch', 'query-wrong-version', 'query-stats-disabled',
                 'query-wrong-vlan', 'query-wrong-action', 'query-drops',
                 'join-short-wait', 'leave-short-wait', 'snoopoff-false-positive', 'join-false-negative', 'leave-entry-persists',
                 'mdb-wrong-port', 'mdb-wrong-bridge', 'mdb-wrong-state', 'mdb-disagrees',
                 'monitor-missing', 'monitor-error', 'monitor-late', 'monitor-early-stop', 'monitor-wrong-port', 'monitor-source-unbound',
                 'events-missing', 'packets-missing', 'event-truncated', 'event-length-invalid', 'netlink-error', 'netlink-overrun',
                 'expiry-missing', 'expiry-too-early', 'expiry-too-late', 'expiry-wrong-vid', 'expiry-wrong-port',
                 'refresh-report-missing', 'refresh-report-wrong-source', 'refresh-report-bad-checksum', 'refresh-new-missing',
                 'refresh-untimely', 'refresh-timer-too-long', 'refresh-timer-inconsistent', 'leave-packet-missing',
                 'outside-wrong-master', 'outside-short-wait', 'outside-bridge-leaked',
                 'router-wrong-default', 'router-enabled-other-port', 'router-counter-zero', 'nonrouter-counter-nonzero', 'router-bytes-wrong',
                 'router-filter-not-reset', 'router-wrong-filter', 'router-traversal-missing',
                 'missing-frame', 'short-send', 'wrong-frame-source', 'wrong-frame-vlan', 'wrong-frame-destination', 'wrong-frame-protocol', 'wrong-frame-udp-length',
                 'disable-vlan-snooping-ineffective', 'bridge-leaked', 'vrf-leaked', 'vlan-child-leaked', 'veth-up', 'master-leaked', 'mdb-leaked',
                 'fdb-leaked', 'address-leaked', 'route-leaked', 'forwarding-leaked', 'host-fallback', 'ignored-vrf',
                 'wrong-send-count', 'wrong-send-bytes', 'live-socket', 'packet-leaked', 'forced-stop')
        for case in cases:
            with self.subTest(case=case):
                r = copy.deepcopy(fixture); rows = r['commands']; monitor = r['mcast_monitor']
                join, query, leave, post = (rows[i] for i in (130, 131, 132, 133))
                def link(state, name): return contract.links(state)[name]
                def vg(state): return contract.vlan(state['vlan_global'], 'br0')
                def output(row, change):
                    data = json.loads(row['stdout']); change(data); row['stdout'] = json.dumps(data)
                def action(data): return next(x for x in data if 'options' in x)['options']['actions'][0]
                def rule(data): return next(x for x in data if 'options' in x)['options']
                def alter_events(kind, change):
                    for event in monitor['events']:
                        raw = bytearray.fromhex(event['data_hex'])
                        if struct.unpack_from('=H', raw, 4)[0] == kind and bytes([239, 10, 10, 10]) in raw and join['started_monotonic'] < event['monotonic'] < query['started_monotonic']:
                            change(event, raw); event['data_hex'] = raw.hex()
                def alter_packets(change, kinds=(0x16,)):
                    for packet in monitor['packets']:
                        raw = bytearray.fromhex(packet['data_hex'])
                        if raw[12:14] == b'\x08\x00' and raw[23] == 2 and raw[14 + (raw[14] & 15) * 4] in kinds and bytes([239, 10, 10, 10]) in raw:
                            change(packet, raw); packet['data_hex'] = raw.hex()
                if case == 'expired-absent':
                    # A coherent alternative native outcome: no unsolicited renewal.
                    for key in ('mdb', 'mdb_timers'):
                        for group in query['unaware_after'][key]: group['mdb'] = [x for x in group.get('mdb', []) if x.get('grp') != contract.GROUP]
                    output(query, lambda data: [group.update(mdb=[x for x in group.get('mdb', []) if x.get('grp') != contract.GROUP]) for group in data])
                    cutoff = join['finished_monotonic'] + 3
                    monitor['events'] = [e for e in monitor['events'] if not (bytes([239, 10, 10, 10]) in bytes.fromhex(e['data_hex']) and cutoff < e['monotonic'] < query['started_monotonic'])]
                    monitor['packets'] = [p for p in monitor['packets'] if not (bytes([239, 10, 10, 10]) in bytes.fromhex(p['data_hex']) and cutoff < p['monotonic'] < query['started_monotonic'])]
                elif case == 'delayed-send-observation': rows[180]['unaware_after'] = copy.deepcopy(rows[180]['unaware_before'])
                elif case == 'missing-outcome': r['original']['stdout'] = '\n'.join(r['original']['stdout'].splitlines()[:-1])
                elif case == 'skip': r['original']['stdout'] += 'SKIP unsupported\n'
                elif case == 'unpinned-tc': r['tc_tool']['sha256'] = 'host'
                elif case == 'missing-command': rows.pop(39)
                elif case == 'wrong-command-order': rows[39], rows[40] = rows[40], rows[39]
                elif case == 'unexpected-error': rows[39]['returncode'] = 1
                elif case == 'warning': rows[39]['stderr'] = 'unsupported boundary'
                elif case == 'wrong-default': output(rows[46], lambda d: contract.vlan(d, 'br0').update(mcast_membership_interval=200))
                elif case == 'ineffective-scalar': vg(rows[129]['unaware_after'])['mcast_membership_interval'] = 26000
                elif case == 'ineffective-router-set': contract.vlan(rows[174]['unaware_after']['vlan_details'], 'veth1')['mcast_router'] = 1
                elif case == 'missing-global-range': rows[46]['unaware_after']['vlan_global'] = []
                elif case in ('bridge-down', 'snooping-disabled', 'vlan-disabled', 'vlan-snooping-disabled'):
                    device = link(rows[63]['unaware_after'], 'br0')
                    if case == 'bridge-down': device['flags'].remove('UP')
                    else: device['linkinfo']['info_data'][{'snooping-disabled': 'mcast_snooping', 'vlan-disabled': 'vlan_filtering', 'vlan-snooping-disabled': 'mcast_vlan_snooping'}[case]] = 0
                elif case == 'wrong-peer': link(rows[63]['unaware_after'], 'veth1')['link'] = 'veth3'
                elif case == 'port-detached': link(rows[63]['unaware_after'], 'veth1')['master'] = 'other'
                elif case == 'port-blocked': link(rows[63]['unaware_after'], 'veth1')['linkinfo']['info_slave_data']['state'] = 'blocking'
                elif case == 'host-vrf-wrong': link(rows[63]['unaware_after'], 'veth0')['master'] = 'vveth3'
                elif case == 'same-vrf': link(rows[63]['unaware_after'], 'vveth3')['linkinfo']['info_data']['table'] = 1
                elif case == 'host-vlan-wrong': link(rows[63]['unaware_after'], 'veth0.10')['linkinfo']['info_data']['id'] = 11
                elif case == 'host-address-missing': next(x for x in rows[63]['unaware_after']['addresses'] if x['ifname'] == 'veth0')['addr_info'] = []
                elif case == 'vid11-missing': next(x for x in rows[63]['unaware_after']['vlans'] if x['ifname'] == 'veth1')['vlans'] = []
                elif case == 'query-short-wait': rows[63]['started_monotonic'] = rows[62]['finished_monotonic'] + 0.99
                elif case in ('query-zero-count', 'query-wrong-bytes', 'query-drops'):
                    key = {'query-zero-count': 'packets', 'query-wrong-bytes': 'bytes', 'query-drops': 'drops'}[case]
                    output(rows[63], lambda d: action(d)['stats'].update({key: 0 if key != 'drops' else 1}))
                elif case == 'query-xstats-mismatch': output(rows[64], lambda d: d[0]['multicast']['igmp_queries'].update(tx_v2=10))
                elif case == 'query-wrong-version': vg(rows[82]['unaware_after'])['mcast_igmp_version'] = 2
                elif case == 'query-stats-disabled': link(rows[62]['unaware_after'], 'br0')['linkinfo']['info_data']['mcast_stats_enabled'] = 0
                elif case == 'query-wrong-vlan': output(rows[63], lambda d: rule(d)['keys'].update(vlan_id=11))
                elif case == 'query-wrong-action': output(rows[63], lambda d: action(d)['control_action'].update(type='drop'))
                elif case == 'join-short-wait': query['started_monotonic'] = join['finished_monotonic'] + 4.99
                elif case == 'leave-short-wait': post['started_monotonic'] = leave['finished_monotonic'] + 4.99
                elif case in ('snoopoff-false-positive', 'leave-entry-persists'):
                    row = rows[53] if case == 'snoopoff-false-positive' else post; entry = copy.deepcopy(contract.target(json.loads(query['stdout']))[0])
                    for key in ('mdb', 'mdb_timers'): row['unaware_after'][key][0]['mdb'].append(copy.deepcopy(entry))
                    output(row, lambda d: d[0]['mdb'].append(copy.deepcopy(entry)))
                elif case == 'join-false-negative':
                    for group in rows[48]['unaware_after']['mdb']: group['mdb'] = [x for x in group['mdb'] if x.get('grp') != contract.GROUP]
                    output(rows[48], lambda d: [group.update(mdb=[x for x in group['mdb'] if x.get('grp') != contract.GROUP]) for group in d])
                elif case in ('mdb-wrong-port', 'mdb-wrong-bridge', 'mdb-wrong-state'):
                    key, value = {'mdb-wrong-port': ('port', 'veth1'), 'mdb-wrong-bridge': ('dev', 'br1'), 'mdb-wrong-state': ('state', 'permanent')}[case]
                    output(query, lambda d: contract.target(d)[0].update({key: value}))
                elif case == 'mdb-disagrees': query['unaware_after']['mdb'] = []
                elif case == 'monitor-missing': r.pop('mcast_monitor')
                elif case == 'monitor-error': monitor['error'] = 'ENOBUFS'
                elif case == 'monitor-late': monitor['packet_ready_monotonic'] = query['started_monotonic']
                elif case == 'monitor-early-stop': monitor['finished_monotonic'] = query['started_monotonic']
                elif case == 'monitor-wrong-port': monitor['packet_ifindex'] = -1
                elif case == 'monitor-source-unbound': r['mcast_monitor_sha256'] = 'different source'
                elif case == 'events-missing': monitor['events'] = []
                elif case == 'packets-missing': monitor['packets'] = []
                elif case == 'event-truncated': monitor['events'][0]['data_hex'] = '00'
                elif case == 'event-length-invalid':
                    raw = bytearray.fromhex(monitor['events'][0]['data_hex']); raw[:4] = (99999).to_bytes(4, 'little'); monitor['events'][0]['data_hex'] = raw.hex()
                elif case in ('netlink-error', 'netlink-overrun'):
                    raw = bytearray.fromhex(monitor['events'][0]['data_hex']); raw[4:6] = (2 if case == 'netlink-error' else 4).to_bytes(2, 'little'); monitor['events'][0]['data_hex'] = raw.hex()
                elif case == 'expiry-missing': alter_events(85, lambda e, b: b.__setitem__(slice(4, 6), (84).to_bytes(2, 'little')))
                elif case in ('expiry-too-early', 'expiry-too-late'):
                    alter_events(85, lambda e, b: e.update(monotonic=join['finished_monotonic'] + (1 if case == 'expiry-too-early' else 4.8)))
                elif case in ('expiry-wrong-vid', 'expiry-wrong-port'):
                    def corrupt(e, b):
                        pos = b.index(bytes([239, 10, 10, 10])); b[pos - (2 if case == 'expiry-wrong-vid' else 8)] ^= 1
                    alter_events(85, corrupt)
                elif case in ('refresh-report-missing', 'refresh-report-wrong-source', 'refresh-report-bad-checksum'):
                    def corrupt_packet(p, b):
                        if join['finished_monotonic'] + 3 < p['monotonic'] < query['started_monotonic']:
                            offset = 14 + (b[14] & 15) * 4
                            b[{'refresh-report-missing': offset, 'refresh-report-wrong-source': 6, 'refresh-report-bad-checksum': offset + 2}[case]] ^= 1
                    alter_packets(corrupt_packet)
                elif case == 'refresh-new-missing':
                    monitor['events'] = [e for e in monitor['events'] if not (join['finished_monotonic'] + 3 < e['monotonic'] < query['started_monotonic'] and bytes([239, 10, 10, 10]) in bytes.fromhex(e['data_hex']))]
                elif case == 'refresh-untimely': alter_packets(lambda p, b: p.update(monotonic=p['monotonic'] - 0.5) if join['finished_monotonic'] + 3 < p['monotonic'] < query['started_monotonic'] else None)
                elif case in ('refresh-timer-too-long', 'refresh-timer-inconsistent'): contract.target(query['unaware_after']['mdb_timers'])[0]['timer'] = '260' if case == 'refresh-timer-too-long' else '1.8'
                elif case == 'leave-packet-missing': alter_packets(lambda p, b: b.__setitem__(14 + (b[14] & 15) * 4, 0), (0x17,))
                elif case == 'outside-wrong-master': link(rows[143]['unaware_after'], 'veth0')['master'] = 'vveth0'
                elif case == 'outside-short-wait': rows[144]['started_monotonic'] = rows[143]['finished_monotonic'] + 1.99
                elif case == 'outside-bridge-leaked': rows[144]['unaware_after']['links'].append(copy.deepcopy(link(rows[143]['unaware_after'], 'br1')))
                elif case == 'router-wrong-default': output(rows[173], lambda d: contract.vlan(d, 'veth1').update(mcast_router=2))
                elif case == 'router-enabled-other-port': contract.vlan(rows[180]['unaware_before']['vlan_details'], 'veth2')['mcast_router'] = 2
                elif case in ('router-counter-zero', 'router-bytes-wrong', 'nonrouter-counter-nonzero'):
                    output(rows[182 if case == 'nonrouter-counter-nonzero' else 181], lambda d: action(d)['stats'].update({ 'bytes' if case == 'router-bytes-wrong' else 'packets': 1 if case == 'nonrouter-counter-nonzero' else 0}))
                elif case == 'router-filter-not-reset': action(rows[180]['unaware_before']['egress_filters']['veth1'])['stats']['packets'] = 1
                elif case == 'router-wrong-filter': output(rows[181], lambda d: rule(d)['keys'].update(dst_ip='239.1.1.2'))
                elif case == 'router-traversal-missing': link(rows[181]['unaware_after'], 'veth1')['stats64'] = copy.deepcopy(link(rows[180]['unaware_before'], 'veth1')['stats64'])
                elif case == 'missing-frame': r['packet_trace'].pop()
                elif case == 'short-send': r['packet_trace'][0]['result'] -= 1
                elif case.startswith('wrong-frame-'):
                    b = bytearray.fromhex(r['packet_trace'][0]['frame_hex']); b[{'wrong-frame-source': 6, 'wrong-frame-vlan': 15, 'wrong-frame-destination': 34, 'wrong-frame-protocol': 27, 'wrong-frame-udp-length': 43}[case]] ^= 1; r['packet_trace'][0]['frame_hex'] = b.hex()
                elif case == 'disable-vlan-snooping-ineffective': output(rows[190], lambda d: d[0]['linkinfo']['info_data'].update(mcast_vlan_snooping=1))
                elif case in ('bridge-leaked', 'vrf-leaked', 'vlan-child-leaked'): r['cleanup_state']['links'].append(dict(ifname={'bridge-leaked': 'br0', 'vrf-leaked': 'vveth0', 'vlan-child-leaked': 'veth0.10'}[case]))
                elif case == 'veth-up': link(r['cleanup_state'], 'veth0')['flags'].append('UP')
                elif case == 'master-leaked': link(r['cleanup_state'], 'veth0')['master'] = 'vveth0'
                elif case == 'mdb-leaked': r['cleanup_state']['mdb'][0]['mdb'].append(dict(grp=contract.GROUP))
                elif case == 'fdb-leaked': r['cleanup_state']['fdb'].append(dict(master='br0'))
                elif case == 'address-leaked': next(x for x in r['cleanup_state']['addresses'] if x['ifname'] == 'veth0')['addr_info'].append(dict(scope='global'))
                elif case == 'route-leaked': r['cleanup_state']['ipv4_routes'].append(dict(dev='veth0'))
                elif case == 'forwarding-leaked': r['cleanup_state']['ipv4'] = '1\n'
                elif case == 'host-fallback': r['missing_backend_control']['returncode'] = 0
                elif case == 'ignored-vrf': r['vrf_binding_control']['unknown_vrf']['returncode'] = 0
                elif case in ('wrong-send-count', 'wrong-send-bytes', 'live-socket'): r['native_fixture'][{'wrong-send-count': 'bridge_packet_sends', 'wrong-send-bytes': 'bridge_packet_bytes', 'live-socket': 'live'}[case]] = 1
                elif case == 'packet-leaked': r['stats']['outstanding'] = 1
                elif case == 'forced-stop': r['stats']['shutdown_timed_out'] = True
                if case in ('complete', 'expired-absent', 'delayed-send-observation'): contract.validate_evidence(r)
                else:
                    with self.assertRaises((RuntimeError, KeyError, ValueError, IndexError, TypeError)): contract.validate_evidence(r)


if __name__ == '__main__': unittest.main()
