"""Qualify the complete unchanged bridge VLAN multicast entry using native evidence.

The pinned vlmc_v2join_test tests the conditional's status instead of jq's status
for its join assertion. A real MDB expiry and any subsequent IGMP refresh must
therefore be proved independently; original OK output alone cannot qualify it.
The observer sends nothing and does not change the original five-second wait.
"""
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import struct

GROUP = '239.10.10.10'
DEFAULTS = dict(mcast_snooping=1, mcast_querier=0, mcast_igmp_version=2,
                mcast_mld_version=1, mcast_last_member_count=2, mcast_last_member_interval=100,
                mcast_startup_query_count=2, mcast_startup_query_interval=3125,
                mcast_membership_interval=26000, mcast_querier_interval=25500,
                mcast_query_interval=12500, mcast_query_response_interval=1000)


def require(value, message):
    if not value:
        raise RuntimeError(message)


def links(state):
    return {item['ifname']: item for item in state['links']}


def vlan(objects, device, vid=10):
    found = [v for item in objects if item['ifname'] == device for v in item['vlans']
             if v['vlan'] <= vid <= v.get('vlanEnd', v['vlan'])]
    require(len(found) == 1, 'native VLAN range missing or ambiguous')
    return found[0]


def target(objects):
    return [item for group in objects for item in group.get('mdb', [])
            if item.get('grp') == GROUP and item.get('vid') == 10]


def topology(state, outside=False):
    devices = links(state)
    bridge = devices['br0']['linkinfo']['info_data']
    require(devices['br0']['linkinfo']['info_kind'] == 'bridge' and
            all(bridge[k] == 1 for k in ('vlan_filtering', 'mcast_snooping', 'mcast_vlan_snooping')) and
            'UP' in devices['br0']['flags'], 'native VLAN multicast bridge disabled')
    tables = []
    for host, port, vrf, number in (('veth0', 'veth1', 'vveth0', 1), ('veth3', 'veth2', 'vveth3', 2)):
        require(devices[host]['link'] == port and devices[port]['link'] == host and
                devices[host]['linkinfo']['info_kind'] == devices[port]['linkinfo']['info_kind'] == 'veth' and
                all('UP' in devices[n]['flags'] for n in (host, port, vrf)) and
                devices[port].get('master') == 'br0' and
                devices[port]['linkinfo']['info_slave_data']['state'] == 'forwarding', 'native multicast peer/bridge path changed')
        require(devices[vrf]['linkinfo']['info_kind'] == 'vrf', 'native multicast host VRF missing')
        tables.append(devices[vrf]['linkinfo']['info_data']['table'])
        if not outside or host == 'veth3':
            require(devices[host].get('master') == vrf, 'native host VRF binding changed')
        child = devices[host + '.10']
        require(child['link'] == host and child['linkinfo']['info_kind'] == 'vlan' and
                child['linkinfo']['info_data']['id'] == 10 and child['linkinfo']['info_data']['protocol'] == '802.1Q' and
                'UP' in child['flags'], 'original host VLAN10 missing')
        addresses = next(a for a in state['addresses'] if a['ifname'] == host)['addr_info']
        require(all(any(a.get('local') == addr and a.get('prefixlen') == prefix for a in addresses)
                    for addr, prefix in ((f'192.0.2.{number}', 24), (f'2001:db8:1::{number}', 64))),
                'original multicast host address missing')
        require(all(vlan(state['vlans'], port, vid).get('state', 'forwarding') == 'forwarding' for vid in (10, 11)),
                'native multicast VLAN10/11 membership missing')
    require(len(set(tables)) == 2, 'multicast host VRFs share table')
    return devices


def flower(objects, family='igmp'):
    found = [item for item in objects if item.get('options', {}).get('handle') == 1]
    require(len(found) == 1 and found[0]['protocol'] == '802.1Q' and found[0]['kind'] == 'flower', 'native multicast flower missing')
    options = found[0]['options']
    expected = dict(vlan_id=10, vlan_ethtype='ipv6' if family == 'mld' else 'ip',
                    eth_type='ipv6' if family == 'mld' else 'ipv4',
                    ip_proto={'mld': 'icmpv6', 'igmp': '0x02', 'udp': 'udp'}[family],
                    dst_ip={'mld': 'ff02::1', 'igmp': '224.0.0.1', 'udp': '239.1.1.1'}[family])
    actions = options.get('actions', [])
    require(options.get('keys') == expected and options.get('not_in_hw') is True and len(actions) == 1 and
            actions[0].get('kind') == 'gact' and actions[0].get('control_action', {}).get('type') == 'pass',
            'actual native multicast classifier/action changed')
    stats = actions[0]['stats']
    require(stats['drops'] == 0, 'native multicast pass action dropped traffic')
    return stats


def attributes(data):
    offset = 0
    while offset < len(data):
        require(offset + 4 <= len(data), 'truncated native Netlink attribute')
        size, kind = struct.unpack_from('=HH', data, offset)
        require(size >= 4 and offset + size <= len(data), 'invalid native Netlink attribute')
        yield kind & 0x3fff, data[offset + 4:offset + size]
        offset += (size + 3) & ~3
    require(offset == len(data), 'native Netlink attribute alignment changed')


def notifications(monitor, bridge_index, port_index):
    result = []
    for event in monitor['events']:
        data = bytes.fromhex(event['data_hex']); offset = 0
        require(monitor['started_monotonic'] <= event['monotonic'] <= monitor['finished_monotonic'], 'MDB event outside native monitor lifetime')
        while offset < len(data):
            require(offset + 16 <= len(data), 'truncated native Netlink header')
            size, kind, _, _, _ = struct.unpack_from('=IHHII', data, offset)
            require(size >= 16 and offset + size <= len(data), 'invalid native Netlink message')
            payload = data[offset + 16:offset + size]; offset += (size + 3) & ~3
            require(kind not in (2, 4), 'native MDB monitor reported error or overrun')
            if kind not in (84, 85):
                continue
            require(len(payload) >= 8, 'truncated native bridge MDB message')
            index = struct.unpack_from('=I', payload, 4)[0]
            for a, first in attributes(payload[8:]):
                if a != 1:
                    continue
                for b, second in attributes(first):
                    if b != 1:
                        continue
                    for c, info in attributes(second):
                        if c != 1:
                            continue
                        require(len(info) >= 28, 'truncated native MDB entry')
                        port = struct.unpack_from('=I', info)[0]; vid = struct.unpack_from('=H', info, 6)[0]
                        if int.from_bytes(info[24:26], 'big') == 0x0800 and str(ipaddress.IPv4Address(info[8:12])) == GROUP:
                            require(index == bridge_index and port == port_index and vid == 10 and info[4] == 0,
                                    'target MDB event bridge/port/VID/state changed')
                            result.append((event['monotonic'], kind))
        require(offset == len(data), 'native Netlink message alignment changed')
    require(result == sorted(result), 'native target MDB event chronology changed')
    return result


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(int.from_bytes(data[i:i + 2], 'big') for i in range(0, len(data), 2))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return total == 65535


def reports(monitor, source_mac):
    result = []
    for packet in monitor['packets']:
        data = bytes.fromhex(packet['data_hex'])
        require(len(data) >= 14 and monitor['packet_ready_monotonic'] <= packet['monotonic'] <= monitor['finished_monotonic'],
                'truncated packet or packet outside native observer lifetime')
        kind = int.from_bytes(data[12:14], 'big'); offset = 14
        while kind in (0x8100, 0x88a8):
            require(offset + 4 <= len(data), 'truncated native VLAN packet')
            require(int.from_bytes(data[offset:offset + 2], 'big') & 4095 == 10, 'target observation has unexpected wire VLAN')
            kind = int.from_bytes(data[offset + 2:offset + 4], 'big'); offset += 4
        if kind != 0x0800:
            continue
        require(len(data) >= offset + 20 and data[offset] >> 4 == 4, 'truncated native IPv4 packet')
        if data[offset + 9] != 2:
            continue
        ihl = (data[offset] & 15) * 4; total = int.from_bytes(data[offset + 2:offset + 4], 'big')
        require(ihl >= 20 and total >= ihl + 8 and offset + total <= len(data), 'invalid native IGMP packet lengths')
        igmp = data[offset + ihl:offset + total]
        if igmp[0] not in (0x12, 0x16, 0x17) or str(ipaddress.IPv4Address(igmp[4:8])) != GROUP:
            continue
        require(data[6:12].hex() == source_mac.replace(':', '') and checksum(data[offset:offset + ihl]) and checksum(igmp),
                'target native IGMP source or checksum changed')
        result.append((packet['monotonic'], igmp[0]))
    return result


def membership(report, rows):
    queries = [r for r in rows if r['tool'] == 'bridge' and r['arguments'] == ['-j', 'mdb', 'show', 'dev', 'br0']]
    joins = [r for r in rows if 'autojoin' in r['arguments']]
    leaves = [r for r in rows if r['arguments'] == ['address', 'del', 'dev', 'veth3.10', GROUP + '/32']]
    require(len(queries) == 6 and len(joins) == len(leaves) == 3, 'original three join/leave cycles missing')
    devices = topology(joins[0]['unaware_before']); monitor = report['mcast_monitor']
    require(monitor.get('kind') == 'native_read_only_mdb_and_packet_monitor' and monitor.get('error') is None and
            monitor['packet_ifindex'] == devices['veth2']['ifindex'] and
            monitor['packet_ready_monotonic'] < joins[0]['started_monotonic'] and
            monitor['finished_monotonic'] > queries[-1]['finished_monotonic'] and monitor['events'] and monitor['packets'] and
            report.get('mcast_monitor_sha256') == hashlib.sha256(Path(__file__).with_name('linux-bridge-mcast-monitor.py').read_bytes()).hexdigest(),
            'native read-only membership monitor missing or incomplete')
    events = notifications(monitor, devices['br0']['ifindex'], devices['veth2']['ifindex'])
    packets = reports(monitor, devices['veth3.10']['address'])
    for i, (join, leave) in enumerate(zip(joins, leaves)):
        q, post = queries[2 * i:2 * i + 2]
        require(join['arguments'] == ['address', 'add', 'dev', 'veth3.10', GROUP + '/32', 'autojoin'] and
                rows.index(join) < rows.index(q) < rows.index(leave) < rows.index(post) and
                q['started_monotonic'] - join['finished_monotonic'] >= 5 and
                post['started_monotonic'] - leave['finished_monotonic'] >= 5, 'original multicast join/leave wait or ordering shortened')
        for query in (q, post):
            # Bind the original command's output to a second actual native dump.
            actual = target(json.loads(query['stdout'])); observed = target(query['unaware_after']['mdb'])
            require(bool(actual) == bool(observed) and len(actual) <= 1, 'original MDB result disagrees with native observation')
            if actual:
                require(actual[0]['dev'] == 'br0' and actual[0]['port'] == 'veth2' and actual[0]['state'] == 'temp' and
                        actual[0]['index'] == devices['br0']['ifindex'], 'actual native membership bridge/port/state changed')
        require(not target(json.loads(post['stdout'])), 'native IGMP leave did not remove target MDB entry')
        present = target(json.loads(q['stdout']))
        if i < 2:
            require(bool(present) == (i == 0), 'native VLAN snooping enable/disable failed despite original OK output')
            continue
        require(vlan(q['unaware_after']['vlan_global'], 'br0')['mcast_membership_interval'] == 200,
                'native membership interval not two seconds')
        window = [(t, k) for t, k in events if join['started_monotonic'] <= t <= q['started_monotonic']]
        require(window and window[0][1] == 84 and any(k == 85 for _, k in window),
                'actual target MDB expiry missing during unchanged original five-second window')
        # A repeat unsolicited report may legitimately recreate the membership.
        # It cannot excuse failure to expire the initial membership.
        expiry = next(t for t, k in window if k == 85)
        preceding = [t for t, k in packets if k == 0x16 and join['started_monotonic'] <= t < expiry]
        require(preceding and 1.75 <= expiry - max(preceding) <= 2.25, 'target expiry not bound to native two-second membership timer')
        later = [(t, k) for t, k in window if t > expiry]
        if present:
            require(later and later[-1][1] == 84, 'present target lacks post-expiry native MDB creation')
            renewal = later[-1][0]
            require(any(k == 0x16 and abs(t - renewal) <= 0.25 for t, k in packets) and
                    0 <= q['started_monotonic'] - renewal <= 2.25, 'target recreation lacks timely matching actual IGMPv2 report')
            timed = target(q['unaware_after']['mdb_timers'])
            require(len(timed) == 1 and timed[0].get('protocol') == 'kernel' and 0 <= float(timed[0]['timer']) <= 2 and
                    abs(float(timed[0]['timer']) - (2 - (q['unaware_after']['observed_monotonic'] - renewal))) <= 0.3,
                    'recreated target remaining native timer inconsistent with observed report')
        else:
            require(window[-1][1] == 85, 'absent target has an unaccounted later native creation')
        require(any(k == 0x17 and leave['started_monotonic'] <= t <= post['started_monotonic'] for t, k in packets),
                'original final membership leave lacks native IGMPv2 packet')


def validate_evidence(report):
    original = report.get('original', {})
    parsed = [re.fullmatch(r'TEST: (.*?)\s+\[ OK \]', line) for line in original.get('stdout', '').splitlines() if line.startswith('TEST:')]
    require(original.get('returncode') == 0 and not original.get('stderr') and len(parsed) == 36 and all(parsed) and
            [p[1] for p in parsed] == OUTCOMES and 'SKIP' not in original['stdout'], 'incomplete original multicast default entry')
    tools = report['iproute2']
    require(tools.get('version') == '6.12.0' and tools.get('archive_sha256') == 'bbd141ef7b5d0127cc2152843ba61f274dc32814fa3e0f13e7d07a080bef53d9' and
            bool(report.get('tc_tool', {}).get('sha256')) and report['tc_tool']['sha256'] == tools.get('binaries', {}).get('tc') and
            tools.get('source_hashes', {}).get('tc/tc.c') == 'e9b2e36053ee6e20f79d44a0cab3e1661300ecf9e9783c5fcd03357aa696a101', 'pinned native multicast tools missing')
    rows = report['commands']
    require([' '.join([r['tool'], *r['arguments']]) for r in rows] == COMMAND_PHASE.splitlines(), 'complete original multicast command phases changed')
    require([r['arguments'] for r in rows if r['returncode']] == [['link', 'show', 'dev', 'veth0'], ['link', 'show', 'dev', 'veth2']] and
            all(not r['stderr'] for r in rows if r['returncode'] == 0 and not (r['tool'] == 'tc' and r['arguments'] == ['-j']) and r['tool'] != 'mausezahn'),
            'unexpected original multicast tool/configuration/cleanup failure')
    for before, after in zip(rows, rows[1:]):
        require(before['started_monotonic'] <= before['finished_monotonic'] <= after['started_monotonic'], 'original command chronology changed')
    bridge = [r for r in rows if r['tool'] == 'bridge']
    globals_ = [r for r in bridge if r['arguments'] == ['-j', 'vlan', 'global', 'show']]
    require(len(globals_) == 9, 'original global multicast defaults probes missing')
    for i, row in enumerate(globals_):
        expected = dict(DEFAULTS, mcast_snooping=0 if i == 1 else 1)
        require(all(vlan(json.loads(row['stdout']), 'br0')[k] == v and vlan(row['unaware_after']['vlan_global'], 'br0')[k] == v
                    for k, v in expected.items()), 'native per-VLAN multicast defaults/restoration changed')
    for row in bridge:
        a = row['arguments']
        if a[:3] == ['vlan', 'global', 'set']:
            values = dict(zip(a[7::2], map(int, a[8::2])))
            require(all(vlan(row['unaware_after']['vlan_global'], a[6])[k] == v for k, v in values.items()), 'native multicast scalar update ineffective')
        if a[:2] == ['vlan', 'set']:
            require(vlan(row['unaware_after']['vlan_details'], a[5])['mcast_router'] == int(a[7]), 'native per-VLAN router-port update ineffective')
    queries = [r for r in rows if r['tool'] == 'tc' and r['arguments'][:4] == ['-j', '-s', 'filter', 'show']]
    xstats = [r for r in rows if r['arguments'][:4] == ['-j', 'link', 'xstats', 'type']]
    windows = [('igmp', 2, 1, 1, 46), ('mld', 1, 1, 1, 86), ('igmp', 3, 1, 1, 50), ('mld', 2, 1, 1, 90),
               ('igmp', 2, 2, 3, 92), ('igmp', 2, 3, 4, 138), ('igmp', 2, 1, 1, 46), ('igmp', 2, 3, 5, 138)]
    require(len(queries) == 10 and len(xstats) == 16, 'native query/router windows missing')
    for i, (family, version, count, seconds, bytecount) in enumerate(windows):
        q = queries[i]; first, last = xstats[2 * i:2 * i + 2]; index = rows.index(q); enable = rows[index - 1]
        require(rows[index - 2] is first and rows[index + 1] is last and
                q['started_monotonic'] - enable['finished_monotonic'] >= seconds, 'original native query window shortened/reordered')
        topology(q['unaware_after'], outside=i >= 6)
        data = vlan(enable['unaware_after']['vlan_global'], 'br0')
        require(data['mcast_querier'] == 1 and data['mcast_snooping'] == 1 and data['mcast_' + family + '_version'] == version and
                links(enable['unaware_after'])['br0']['linkinfo']['info_data']['mcast_stats_enabled'] == 1, 'native query generation/xstats disabled')
        stats = flower(json.loads(q['stdout']), family)
        field = family + '_queries'; counter = 'tx_v' + str(version)
        a, b = json.loads(first['stdout']), json.loads(last['stdout'])
        require(len(a) == len(b) == 1 and a[0]['ifname'] == b[0]['ifname'] == 'veth1' and
                b[0]['multicast'][field][counter] - a[0]['multicast'][field][counter] == count == stats['packets'] and
                stats['bytes'] == bytecount, 'native TC and Linux query xstats disagree with original counts')
    membership(report, rows)
    external = next(r for r in rows if r['arguments'] == ['vlan', 'global', 'set', 'vid', '10', 'dev', 'br1', 'mcast_snooping', '1', 'mcast_querier', '1'])
    state = links(external['unaware_after']); deleted = rows[rows.index(external) + 1]
    require(state['veth0'].get('master') == 'br1' and state['br1']['linkinfo']['info_kind'] == 'bridge' and
            all(state['br1']['linkinfo']['info_data'][k] == 1 for k in ('mcast_snooping', 'vlan_filtering', 'mcast_vlan_snooping')) and
            set(vlan(external['unaware_after']['vlans'], 'br1').get('flags', [])) == {'PVID', 'Egress Untagged'} and
            deleted['started_monotonic'] - external['finished_monotonic'] >= 2 and 'br1' not in links(deleted['unaware_after']),
            'original outside querier topology/wait/teardown missing')
    sender = next(r for r in rows if r['tool'] == 'mausezahn')
    require(re.fullmatch(r'Mausezahn will send 10 frames\.\.\. [0-9.]+ seconds \([0-9]+ packets per second\)\n', sender['stderr']), 'unexpected native packet tool warning')
    before = sender['unaware_before']; devices = topology(before, outside=True)
    require(vlan(before['vlan_details'], 'veth1')['mcast_router'] == 2 and vlan(before['vlan_details'], 'veth2')['mcast_router'] == 0 and
            vlan(before['vlan_global'], 'br0')['mcast_querier'] == 1 and vlan(before['vlan_global'], 'br0')['mcast_query_response_interval'] == 0,
            'actual multicast router-port admission flags changed')
    default_port = next(r for r in bridge if r['arguments'] == ['-j', '-d', 'vlan', 'show'])
    require(vlan(json.loads(default_port['stdout']), 'veth1')['mcast_router'] == 1, 'native default multicast router-port not automatic')
    for port, q, count in zip(('veth1', 'veth2'), queries[-2:], (10, 0)):
        stats = flower(json.loads(q['stdout']), 'udp'); initial = flower(before['egress_filters'][port], 'udp')
        require(initial['packets'] == initial['bytes'] == 0 and stats['packets'] == count and stats['bytes'] == count * 170,
                'original unknown multicast router-only forwarding failed')
        if count:
            for dev, direction in (('br0', 'tx'), ('veth1', 'tx'), ('veth0', 'rx')):
                a = devices[dev]['stats64'][direction]; b = links(q['unaware_after'])[dev]['stats64'][direction]
                require(b['packets'] - a['packets'] >= 10 and b['bytes'] - a['bytes'] >= 1700, 'native unknown multicast traversal absent at original query')
    packets = report['packet_trace']; require(len(packets) == 10, 'original ten native multicast frames missing')
    for packet in packets:
        frame = bytes.fromhex(packet['frame_hex'])
        require(packet.get('family') == 17 and packet.get('ifindex') == devices['br0']['ifindex'] and packet['length'] == packet['result'] == len(frame) == 174 and
                frame[:6].hex() == '01005e010101' and frame[6:12].hex() == devices['br0']['address'].replace(':', '') and
                frame[12:18].hex() == '8100000a0800' and frame[18] == 0x45 and frame[27] == 17 and
                frame[34:38] == bytes([239, 1, 1, 1]) and int.from_bytes(frame[20:22], 'big') == 156 and
                int.from_bytes(frame[40:42], 'big') == 1024 and int.from_bytes(frame[42:44], 'big') == 136,
                'actual native multicast frame/VLAN/source/UDP payload changed')
    disabled = next(r for r in rows if r['arguments'] == ['-j', '-d', 'link', 'show', 'dev', 'br0'])
    data = json.loads(disabled['stdout'])[0]['linkinfo']['info_data']
    require(data['vlan_filtering'] == data['mcast_vlan_snooping'] == 0, 'native VLAN filtering disable retained multicast VLAN snooping')
    clean = report['cleanup_state']; devices = links(clean); names = [f'veth{i}' for i in range(4)]
    require(not any(n in devices for n in ('br0', 'br1', 'vveth0', 'vveth3', 'veth0.10', 'veth3.10')) and
            all('UP' not in devices[n]['flags'] and 'master' not in devices[n] and devices[n].get('promiscuity', 0) == 0 for n in names) and
            not any(row.get('mdb') or row.get('router') for row in clean['mdb']) and not any(row.get('master') in ('br0', 'br1') for row in clean['fdb']),
            'native multicast bridge/VRF/VLAN/MDB/FDB leaked')
    require(not any(a.get('scope') == 'global' for row in clean['addresses'] if row['ifname'] in names for a in row.get('addr_info', [])) and
            not any(row.get('dev') in (*names, 'br0', 'br1', 'veth0.10', 'veth3.10') for family in ('ipv4_routes', 'ipv6_routes') for row in clean[family]) and
            all(clean[family].strip() == '0' for family in ('ipv4', 'ipv6')), 'native multicast addresses/routes/forwarding leaked')
    require(report.get('missing_backend_control', {}).get('returncode') not in (None, 0) and
            report.get('vrf_binding_control', {}).get('baseline', {}).get('returncode') == 0 and
            report.get('vrf_binding_control', {}).get('unknown_vrf', {}).get('returncode') not in (None, 0), 'native multicast boundary controls failed')
    native, stats = report['native_fixture'], report['stats']
    require(native.get('bridge_packet_sends') == 10 and native.get('bridge_packet_bytes') == 1740 and native.get('bridge_packet_trace_errors') == 0 and
            native.get('live') == 0 and stats.get('outstanding') == 0 and stats.get('worker_exit_code') == 0 and
            stats.get('control_eof') is True and stats.get('shutdown_timed_out') is False, 'native multicast resources did not stop normally')


OUTCOMES = ['Vlan multicast snooping enable', 'Vlan global options existence', 'Vlan mcast_snooping global option default value', 'Vlan 10 multicast snooping control', 'Vlan mcast_querier global option default value', 'Vlan 10 multicast querier enable', 'Vlan 10 tagged IGMPv2 general query sent', 'Vlan 10 tagged MLD general query sent', 'Vlan mcast_igmp_version global option default value', 'Vlan mcast_mld_version global option default value', 'Vlan 10 mcast_igmp_version option changed to 3', 'Vlan 10 tagged IGMPv3 general query sent', 'Vlan 10 mcast_mld_version option changed to 2', 'Vlan 10 tagged MLDv2 general query sent', 'Vlan mcast_last_member_count global option default value', 'Vlan mcast_last_member_interval global option default value', 'Vlan 10 mcast_last_member_count option changed to 3', 'Vlan 10 mcast_last_member_interval option changed to 200', 'Vlan mcast_startup_query_interval global option default value', 'Vlan mcast_startup_query_count global option default value', 'Vlan 10 mcast_startup_query_interval option changed to 100', 'Vlan 10 mcast_startup_query_count option changed to 3', 'Vlan mcast_membership_interval global option default value', 'Vlan 10 mcast_membership_interval option changed to 200', 'Vlan 10 mcast_membership_interval mdb entry expire', 'Vlan mcast_querier_interval global option default value', 'Vlan 10 mcast_querier_interval option changed to 100', 'Vlan 10 mcast_querier_interval expire after outside query', 'Vlan mcast_query_interval global option default value', 'Vlan 10 mcast_query_interval option changed to 200', 'Vlan mcast_query_response_interval global option default value', 'Vlan 10 mcast_query_response_interval option changed to 200', 'Port vlan 10 option mcast_router default value', 'Port vlan 10 mcast_router option changed to 2', 'Flood unknown vlan multicast packets to router port only', 'Disable multicast vlan snooping when vlan filtering is disabled']

# Exact pinned default command lifecycle; no reduced function selection.
COMMAND_PHASE = """tc -j
ip link show dev veth0
ip link add veth0 type veth peer name veth1
ip link show dev veth2
ip link add veth2 type veth peer name veth3
ip link show dev veth0
ip link show dev veth1
ip link show dev veth2
ip link show dev veth3
ip -4 rule add pref 32765 table local
ip -4 rule del pref 0
ip -6 rule add pref 32765 table local
ip -6 rule del pref 0
ip link add dev vveth0 type vrf table 1
ip -4 route add table 1 unreachable default metric 4278198272
ip -6 route add table 1 unreachable default metric 4278198272
ip link set dev vveth0 up
ip link set dev veth0 master vveth0
ip link set dev veth0 up
ip address add 192.0.2.1/24 dev veth0
ip address add 2001:db8:1::1/64 dev veth0
ip link add l veth0 veth0.10 up type vlan id 10
ip link add dev vveth3 type vrf table 2
ip -4 route add table 2 unreachable default metric 4278198272
ip -6 route add table 2 unreachable default metric 4278198272
ip link set dev vveth3 up
ip link set dev veth3 master vveth3
ip link set dev veth3 up
ip address add 192.0.2.2/24 dev veth3
ip address add 2001:db8:1::2/64 dev veth3
ip link add l veth3 veth3.10 up type vlan id 10
ip link add dev br0 type bridge mcast_snooping 1 mcast_querier 1 vlan_filtering 1
ip link set dev veth1 master br0
ip link set dev veth2 master br0
ip link set dev br0 up
ip link set dev veth1 up
ip link set dev veth2 up
tc qdisc add dev veth1 clsact
tc qdisc add dev veth2 clsact
bridge vlan add vid 10-11 dev veth1 master
bridge vlan add vid 10-11 dev veth2 master
ip link set dev br0 type bridge mcast_vlan_snooping 1
ip link show dev veth0 up
ip link show dev veth1 up
ip link show dev veth2 up
ip link show dev veth3 up
bridge -j vlan global show
ip address add dev veth3.10 239.10.10.10/32 autojoin
bridge -j mdb show dev br0
ip address del dev veth3.10 239.10.10.10/32
bridge -j mdb show dev br0
bridge vlan global set vid 10 dev br0 mcast_snooping 0
ip address add dev veth3.10 239.10.10.10/32 autojoin
bridge -j mdb show dev br0
ip address del dev veth3.10 239.10.10.10/32
bridge -j mdb show dev br0
bridge -j vlan global show
bridge vlan global set vid 10 dev br0 mcast_snooping 1 mcast_querier 1
bridge vlan global set vid 10 dev br0 mcast_snooping 1 mcast_querier 0
tc filter add dev veth1 egress pref 10 prot 802.1Q flower vlan_id 10 vlan_ethtype ipv4 dst_ip 224.0.0.1 ip_proto 2 action pass
ip link set dev br0 type bridge mcast_stats_enabled 1
ip -j link xstats type bridge_slave dev veth1
bridge vlan global set vid 10 dev br0 mcast_snooping 1 mcast_querier 1
tc -j -s filter show dev veth1 egress pref 10
ip -j link xstats type bridge_slave dev veth1
bridge vlan global set vid 10 dev br0 mcast_snooping 1 mcast_querier 0
ip link set dev br0 type bridge mcast_stats_enabled 0
tc filter del dev veth1 egress pref 10
tc filter add dev veth1 egress pref 10 prot 802.1Q flower vlan_id 10 vlan_ethtype ipv6 dst_ip ff02::1 ip_proto icmpv6 action pass
ip link set dev br0 type bridge mcast_stats_enabled 1
ip -j link xstats type bridge_slave dev veth1
bridge vlan global set vid 10 dev br0 mcast_snooping 1 mcast_querier 1
tc -j -s filter show dev veth1 egress pref 10
ip -j link xstats type bridge_slave dev veth1
bridge vlan global set vid 10 dev br0 mcast_snooping 1 mcast_querier 0
ip link set dev br0 type bridge mcast_stats_enabled 0
tc filter del dev veth1 egress pref 10
bridge -j vlan global show
bridge vlan global set vid 10 dev br0 mcast_snooping 1 mcast_igmp_version 3
tc filter add dev veth1 egress pref 10 prot 802.1Q flower vlan_id 10 vlan_ethtype ipv4 dst_ip 224.0.0.1 ip_proto 2 action pass
ip link set dev br0 type bridge mcast_stats_enabled 1
ip -j link xstats type bridge_slave dev veth1
bridge vlan global set vid 10 dev br0 mcast_snooping 1 mcast_querier 1
tc -j -s filter show dev veth1 egress pref 10
ip -j link xstats type bridge_slave dev veth1
bridge vlan global set vid 10 dev br0 mcast_snooping 1 mcast_querier 0
ip link set dev br0 type bridge mcast_stats_enabled 0
tc filter del dev veth1 egress pref 10
bridge vlan global set vid 10 dev br0 mcast_snooping 1 mcast_mld_version 2
tc filter add dev veth1 egress pref 10 prot 802.1Q flower vlan_id 10 vlan_ethtype ipv6 dst_ip ff02::1 ip_proto icmpv6 action pass
ip link set dev br0 type bridge mcast_stats_enabled 1
ip -j link xstats type bridge_slave dev veth1
bridge vlan global set vid 10 dev br0 mcast_snooping 1 mcast_querier 1
tc -j -s filter show dev veth1 egress pref 10
ip -j link xstats type bridge_slave dev veth1
bridge vlan global set vid 10 dev br0 mcast_snooping 1 mcast_querier 0
ip link set dev br0 type bridge mcast_stats_enabled 0
tc filter del dev veth1 egress pref 10
bridge vlan global set vid 10 dev br0 mcast_snooping 1 mcast_igmp_version 2
bridge vlan global set vid 10 dev br0 mcast_snooping 1 mcast_mld_version 1
bridge -j vlan global show
bridge vlan global set vid 10 dev br0 mcast_snooping 1 mcast_last_member_count 3
bridge vlan global set vid 10 dev br0 mcast_snooping 1 mcast_last_member_count 2
bridge vlan global set vid 10 dev br0 mcast_snooping 1 mcast_last_member_interval 200
bridge vlan global set vid 10 dev br0 mcast_snooping 1 mcast_last_member_interval 100
bridge -j vlan global show
bridge vlan global set vid 10 dev br0 mcast_snooping 1 mcast_startup_query_interval 100
tc filter add dev veth1 egress pref 10 prot 802.1Q flower vlan_id 10 vlan_ethtype ipv4 dst_ip 224.0.0.1 ip_proto 2 action pass
ip link set dev br0 type bridge mcast_stats_enabled 1
ip -j link xstats type bridge_slave dev veth1
bridge vlan global set vid 10 dev br0 mcast_snooping 1 mcast_querier 1
tc -j -s filter show dev veth1 egress pref 10
ip -j link xstats type bridge_slave dev veth1
bridge vlan global set vid 10 dev br0 mcast_snooping 1 mcast_querier 0
ip link set dev br0 type bridge mcast_stats_enabled 0
tc filter del dev veth1 egress pref 10
bridge vlan global set vid 10 dev br0 mcast_snooping 1 mcast_startup_query_count 3
tc filter add dev veth1 egress pref 10 prot 802.1Q flower vlan_id 10 vlan_ethtype ipv4 dst_ip 224.0.0.1 ip_proto 2 action pass
ip link set dev br0 type bridge mcast_stats_enabled 1
ip -j link xstats type bridge_slave dev veth1
bridge vlan global set vid 10 dev br0 mcast_snooping 1 mcast_querier 1
tc -j -s filter show dev veth1 egress pref 10
ip -j link xstats type bridge_slave dev veth1
bridge vlan global set vid 10 dev br0 mcast_snooping 1 mcast_querier 0
ip link set dev br0 type bridge mcast_stats_enabled 0
tc filter del dev veth1 egress pref 10
bridge vlan global set vid 10 dev br0 mcast_snooping 1 mcast_startup_query_interval 3125
bridge vlan global set vid 10 dev br0 mcast_snooping 1 mcast_startup_query_count 2
bridge -j vlan global show
bridge vlan global set vid 10 dev br0 mcast_snooping 1 mcast_membership_interval 200
ip address add dev veth3.10 239.10.10.10/32 autojoin
bridge -j mdb show dev br0
ip address del dev veth3.10 239.10.10.10/32
bridge -j mdb show dev br0
bridge vlan global set vid 10 dev br0 mcast_snooping 1 mcast_membership_interval 26000
bridge -j vlan global show
bridge vlan global set vid 10 dev br0 mcast_snooping 1 mcast_querier_interval 100
ip link add dev br1 type bridge mcast_snooping 1 mcast_querier 1 vlan_filtering 1 mcast_vlan_snooping 1
bridge vlan add vid 10 dev br1 self pvid untagged
ip link set dev veth0 master br1
ip link set dev br1 up
ip link show dev veth0 up
bridge vlan add vid 10 dev veth0 master
bridge vlan global set vid 10 dev br1 mcast_snooping 1 mcast_querier 1
ip link del dev br1
ip addr replace 2001:db8:1::1/64 dev veth0
tc filter add dev veth1 egress pref 10 prot 802.1Q flower vlan_id 10 vlan_ethtype ipv4 dst_ip 224.0.0.1 ip_proto 2 action pass
ip link set dev br0 type bridge mcast_stats_enabled 1
ip -j link xstats type bridge_slave dev veth1
bridge vlan global set vid 10 dev br0 mcast_snooping 1 mcast_querier 1
tc -j -s filter show dev veth1 egress pref 10
ip -j link xstats type bridge_slave dev veth1
bridge vlan global set vid 10 dev br0 mcast_snooping 1 mcast_querier 0
ip link set dev br0 type bridge mcast_stats_enabled 0
tc filter del dev veth1 egress pref 10
bridge vlan global set vid 10 dev br0 mcast_snooping 1 mcast_querier_interval 25500
bridge -j vlan global show
bridge vlan global set vid 10 dev br0 mcast_snooping 1 mcast_startup_query_count 0
bridge vlan global set vid 10 dev br0 mcast_snooping 1 mcast_query_interval 200
tc filter add dev veth1 egress pref 10 prot 802.1Q flower vlan_id 10 vlan_ethtype ipv4 dst_ip 224.0.0.1 ip_proto 2 action pass
ip link set dev br0 type bridge mcast_stats_enabled 1
ip -j link xstats type bridge_slave dev veth1
bridge vlan global set vid 10 dev br0 mcast_snooping 1 mcast_querier 1
tc -j -s filter show dev veth1 egress pref 10
ip -j link xstats type bridge_slave dev veth1
bridge vlan global set vid 10 dev br0 mcast_snooping 1 mcast_querier 0
ip link set dev br0 type bridge mcast_stats_enabled 0
tc filter del dev veth1 egress pref 10
bridge vlan global set vid 10 dev br0 mcast_snooping 1 mcast_startup_query_count 2
bridge vlan global set vid 10 dev br0 mcast_snooping 1 mcast_query_interval 12500
bridge -j vlan global show
bridge vlan global set vid 10 dev br0 mcast_snooping 1 mcast_query_response_interval 200
bridge vlan global set vid 10 dev br0 mcast_snooping 1 mcast_query_response_interval 1000
bridge -j -d vlan show
bridge vlan set vid 10 dev veth1 mcast_router 2
tc filter add dev veth1 egress pref 10 prot 802.1Q flower vlan_id 10 vlan_ethtype ipv4 dst_ip 239.1.1.1 ip_proto udp action pass
tc filter add dev veth2 egress pref 10 prot 802.1Q flower vlan_id 10 vlan_ethtype ipv4 dst_ip 239.1.1.1 ip_proto udp action pass
bridge vlan set vid 10 dev veth2 mcast_router 0
bridge vlan global set vid 10 dev br0 mcast_snooping 1 mcast_querier 1 mcast_query_response_interval 0
bridge vlan add vid 10 dev br0 self
mausezahn br0 -Q 10 -c 10 -p 128 -b 01:00:5e:01:01:01 -B 239.1.1.1 -t udp dp=1024
tc -j -s filter show dev veth1 egress pref 10
tc -j -s filter show dev veth2 egress pref 10
tc filter del dev veth2 egress pref 10
tc filter del dev veth1 egress pref 10
bridge vlan del vid 10 dev br0 self
bridge vlan global set vid 10 dev br0 mcast_snooping 1 mcast_query_response_interval 1000
bridge vlan set vid 10 dev veth2 mcast_router 1
bridge vlan set vid 10 dev veth1 mcast_router 1
ip link set dev br0 type bridge vlan_filtering 0
ip -j -d link show dev br0
tc qdisc del dev veth2 clsact
tc qdisc del dev veth1 clsact
ip link set dev veth2 down
ip link set dev veth1 down
ip link del dev br0
ip link del veth3.10
ip address del 192.0.2.2/24 dev veth3
ip address del 2001:db8:1::2/64 dev veth3
ip link set dev veth3 down
ip link set dev veth3 nomaster
ip -6 route del table 2 unreachable default metric 4278198272
ip -4 route del table 2 unreachable default metric 4278198272
ip link del dev vveth3
ip link del veth0.10
ip address del 192.0.2.1/24 dev veth0
ip address del 2001:db8:1::1/64 dev veth0
ip link set dev veth0 down
ip link set dev veth0 nomaster
ip -6 route del table 1 unreachable default metric 4278198272
ip -4 route del table 1 unreachable default metric 4278198272
ip link del dev vveth0
ip -6 rule add pref 0 table local
ip -6 rule del pref 32765
ip -4 rule add pref 0 table local
ip -4 rule del pref 32765"""
