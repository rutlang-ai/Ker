"""Independent native evidence for the complete pinned bridge_igmp.sh entry.

These tables express the original script's assertions, not protocol behavior.
The original inc_is_exclude caller has no X/Y arrays: its only UDP probe is
source100. Its MDB state is checked independently without inventing traffic.
"""
import hashlib
import ipaddress
import json
import re

GROUP = '239.10.10.10'
MAC = '01:00:5e:0a:0a:0a'
QUERY = ['-j', '-d', '-s', 'mdb', 'show', 'dev', 'br0']
STARTS = [56, 96, 141, 186, 218, 268, 347, 426, 478, 541, 578, 660, 717]
# Mode, active sources, blocked sources, and the actual original UDP probes.
CASES = [
    ('include', {1, 2, 3}, set(), [(1, 1), (2, 1), (3, 1), (100, 0)]),
    ('include', {1, 2, 3, 10, 11, 12}, set(), [(10, 1), (11, 1), (12, 1), (100, 0)]),
    ('include', {1, 2, 3, 10, 11, 12}, set(), [(10, 1), (11, 1), (12, 1), (100, 0)]),
    ('exclude', {1, 2}, {20, 21}, [(100, 1)]),
    ('exclude', {1}, {20, 30}, [(1, 1), (100, 1), (20, 0), (30, 0)]),
    ('exclude', {1, 2, 20, 30}, {21}, [(1, 1), (2, 1), (20, 1), (30, 1), (100, 1), (21, 0)]),
    ('exclude', {1, 2, 20, 30}, {21}, [(1, 1), (2, 1), (20, 1), (30, 1), (100, 1), (21, 0)]),
    ('exclude', {30}, {20}, [(30, 1), (100, 1), (20, 0)]),
    ('exclude', {1, 30}, {20}, [(1, 1), (30, 1), (100, 1), (20, 0)]),
    ('include', {2, 3}, set(), [(2, 1), (3, 1), (100, 0)]),
    ('exclude', {1, 2, 30}, {20, 21}, [(1, 1), (2, 1), (30, 1), (100, 1), (20, 0), (21, 0)]),
    ('include', {20, 30}, set(), [(20, 1), (30, 1), (100, 0)]),
    ('exclude', {1, 2}, {20, 21}, [(3, 1)]),
]
STAGE_COUNTS = [1, 2, 2, 2, 2, 3, 3, 3, 3, 2, 3, 3, 3]
QUERY_COUNTS = [12, 16, 16, 21, 19, 37, 37, 28, 31, 14, 37, 31, 23]
LABELS = ['IGMPv2 report ' + GROUP, 'IGMPv2 leave ' + GROUP,
          'IGMPv3 report ' + GROUP + ' is_include'] + [
    'IGMPv3 report ' + GROUP + ' ' + label for label in (
        'include -> allow', 'include -> is_include', 'include -> is_exclude',
        'include -> to_exclude', 'exclude -> allow', 'exclude -> is_include',
        'exclude -> is_exclude', 'exclude -> to_exclude', 'include -> block', 'exclude -> block')] + [
    'IGMPv3 group ' + GROUP + ' exclude timeout', 'IGMPv3 S,G port entry automatic add to a *,G port']
# Exact original setup, all report/query/filter windows, and teardown. Only
# tool names and argv are hashed; native results and state are checked below.
COMMAND_SHA256 = 'b96fd3e8893bb4cc7a4cbb19d7d761f11e8a654016b6a17c09804430b39cb831'


def require(value, message):
    if not value:
        raise RuntimeError(message)


def links(state):
    return {row['ifname']: row for row in state['links']}


def target(objects, port=None):
    return [row for group in objects for row in group.get('mdb', [])
            if row.get('grp') == GROUP and (port is None or row.get('port') == port)]


def topology(state):
    devices = links(state); br = devices['br0']; info = br['linkinfo']['info_data']
    require(br['linkinfo']['info_kind'] == 'bridge' and 'UP' in br['flags'] and
            info['vlan_filtering'] == 0 and info['mcast_snooping'] == info['mcast_querier'] == 1,
            'native IGMP bridge topology changed')
    tables = []
    for host, port, number in [('veth0', 'veth1', 1), ('veth3', 'veth2', 2)]:
        vrf = 'v' + host
        require(devices[host]['link'] == port and devices[port]['link'] == host and
                devices[host]['linkinfo']['info_kind'] == devices[port]['linkinfo']['info_kind'] == 'veth' and
                devices[host].get('master') == vrf and devices[vrf]['linkinfo']['info_kind'] == 'vrf' and
                devices[port].get('master') == 'br0' and
                devices[port]['linkinfo']['info_slave_data']['state'] == 'forwarding' and
                all('UP' in devices[n]['flags'] for n in (host, port, vrf)), 'native IGMP peer/VRF path missing')
        tables.append(devices[vrf]['linkinfo']['info_data']['table'])
        addresses = next(a for a in state['addresses'] if a['ifname'] == host)['addr_info']
        require(all(any(a.get('local') == addr and a.get('prefixlen') == prefix for a in addresses)
                    for addr, prefix in [(f'192.0.2.{number}', 24), (f'2001:db8:1::{number}', 64)]),
                'native IGMP host addresses changed')
    require(len(set(tables)) == 2 and not any(n.startswith(('veth0.', 'veth3.')) for n in devices),
            'native IGMP host VRF/VLAN topology changed')
    return devices


def mdb(objects, index, mode, active, blocked, port='veth1', auto=False):
    rows = target(objects, port); wildcard = [r for r in rows if 'src' not in r]
    require(len(wildcard) == 1, 'native IGMP wildcard MDB missing/duplicated')
    wildcard = wildcard[0]
    require(wildcard['filter_mode'] == mode and
            (float(wildcard['timer']) == 0 if mode == 'include' else float(wildcard['timer']) > 0),
            'native IGMP wildcard mode/timer changed')
    sources = wildcard.get('source_list', [])
    expected = {f'192.0.2.{n}' for n in active | blocked}
    require(len(sources) == len(expected) and {s['address'] for s in sources} == expected,
            'native IGMP wildcard source set changed')
    for source in sources:
        n = int(source['address'].split('.')[-1]); timer = float(source['timer'])
        require(timer > 0 if n in active else timer == 0, 'native IGMP source timer/block state changed')
    sg = [r for r in rows if 'src' in r]
    require(len(sg) == len(expected) + int(auto) and
            {r['src'] for r in sg} == expected | ({'192.0.2.3'} if auto else set()),
            'native IGMP S,G entry set changed')
    for row in rows:
        require(row.get('index') == index and row.get('dev') == 'br0' and row.get('state') == 'temp' and
                row.get('protocol') == 'kernel', 'native IGMP MDB provenance changed')
        if 'src' in row:
            n = int(row['src'].split('.')[-1])
            flags = {'blocked'} if n in blocked else ({'added_by_star_ex'} if auto and n == 3 else set())
            require(row.get('filter_mode') == 'include' and set(row.get('flags', [])) == flags,
                    'native IGMP S,G blocked/automatic flag changed')
        else:
            require(not row.get('flags'), 'unexpected native IGMP wildcard flag')


def flower(rows, count):
    found = [r for r in rows if r.get('options', {}).get('handle') == 101]
    require(len(found) == 1, 'native IGMP traffic classifier missing')
    row = found[0]; options = row['options']; actions = options.get('actions', [])
    require(row['protocol'] == 'ip' and row['pref'] == 1 and row['kind'] == 'flower' and
            options['keys'] == dict(dst_mac=MAC, eth_type='ipv4', ip_proto='udp') and
            options.get('not_in_hw') is True and len(actions) == 1 and actions[0]['kind'] == 'gact' and
            actions[0]['control_action']['type'] == 'drop', 'native IGMP flower match/action changed')
    stats = actions[0]['stats']
    require(stats['packets'] == stats['drops'] == count and stats['bytes'] == 92 * count,
            'native IGMP source-specific forwarding counter changed')


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(int.from_bytes(data[i:i+2], 'big') for i in range(0, len(data), 2))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return total == 65535


def validate_evidence(report):
    original = report.get('original', {})
    outcomes = [re.fullmatch(r'TEST: (.*?)\s+\[ OK \]', line) for line in original.get('stdout', '').splitlines()]
    require(original.get('returncode') == 0 and not original.get('stderr') and len(outcomes) == 15 and
            all(outcomes) and [m[1] for m in outcomes] == LABELS, 'complete original IGMP outcomes missing')
    rows = report['commands']
    require(len(rows) == 775 and hashlib.sha256(json.dumps([(r['tool'], r['arguments']) for r in rows],
            separators=(',', ':')).encode()).hexdigest() == COMMAND_SHA256, 'complete original IGMP command lifecycle changed')
    require([i for i, r in enumerate(rows) if r['returncode']] == [1, 3] and
            all(not r['stderr'] for i, r in enumerate(rows) if i not in (0, 1, 3)) and
            '-j[son]' in rows[0]['stdout'] + rows[0]['stderr'], 'original IGMP command failed unexpectedly')
    for row in rows:
        require(row['finished_monotonic'] >= row['started_monotonic'], 'native command chronology reversed')
    require(all(b['started_monotonic'] >= a['finished_monotonic'] for a, b in zip(rows, rows[1:])),
            'original IGMP commands overlapped/reordered')
    tools = report['iproute2']
    require(tools['version'] == '6.12.0' and tools['archive_sha256'] ==
            'bbd141ef7b5d0127cc2152843ba61f274dc32814fa3e0f13e7d07a080bef53d9' and
            report['tc_tool']['sha256'] == tools['binaries']['tc'] and bool(report['tc_tool']['sha256']) and
            tools['source_hashes']['tc/tc.c'] == 'e9b2e36053ee6e20f79d44a0cab3e1661300ecf9e9783c5fcd03357aa696a101',
            'pinned original tc provenance changed')
    expected_udp = [(1, 1), (1, 0)]
    # Check each original query against the latest original report, including
    # intermediate include/exclude preparation and the unchanged expiry waits.
    for phase, (start, end) in enumerate(zip(STARTS, STARTS[1:] + [754])):
        part = rows[start:end]; controls = [r for r in part if r['tool'] == 'mausezahn' and 'ip' in r['arguments']]
        queries = [r for r in part if r['tool'] == 'bridge' and r['arguments'] == QUERY]
        require(len(controls) == STAGE_COUNTS[phase] and len(queries) == QUERY_COUNTS[phase], 'original IGMP phase incomplete')
        for stage, control in enumerate(controls):
            next_time = controls[stage+1]['started_monotonic'] if stage+1 < len(controls) else float('inf')
            observations = [q for q in queries if control['finished_monotonic'] <= q['started_monotonic'] < next_time]
            require(observations, 'original IGMP report has no native MDB query')
            wait = 3 if phase == 9 and stage == 1 else 5 if phase == 11 and stage == 2 else 1
            require(observations[0]['started_monotonic'] - control['finished_monotonic'] >= wait,
                    'original IGMP delivery/expiry wait shortened')
            final = stage == len(controls)-1
            mode, active, blocked = CASES[phase][:3] if final else (
                ('include', {1, 2, 3}, set()) if stage == 0 else ('exclude', {1, 2}, {20, 21}))
            devices = topology(control['sg_before']); index = devices['br0']['ifindex']
            require(devices['br0']['linkinfo']['info_data']['mcast_igmp_version'] == 3, 'IGMPv3 not active')
            if phase == 11 and stage == 2:
                wildcard = [r for r in target(control['sg_before']['mdb']) if 'src' not in r]
                require(len(wildcard) == 1 and wildcard[0]['filter_mode'] == 'exclude', 'timeout phase did not start in EXCLUDE')
            for query in observations:
                objects = json.loads(query['stdout'])
                mdb(objects, index, mode, active, blocked, auto=phase == 12 and final)
                require({r['port'] for r in target(objects)} == ({'veth1', 'veth2'} if phase == 12 and final else {'veth1'}),
                        'native IGMP unexpected group port')
                if phase == 12 and final:
                    mdb(objects, index, 'include', {1, 2, 3}, set(), port='veth2')
        expected_udp.extend(CASES[phase][3])
    # Original v2 autojoin/leave is generated by native Linux, not by MZ.
    human = [r for r in rows if r['tool'] == 'bridge' and r['arguments'] == ['mdb', 'show', 'dev', 'br0']]
    require([any('grp ' + GROUP + ' ' in line for line in r['stdout'].splitlines()) for r in human] == [True, True, False],
            'native IGMPv2 join/leave MDB lifecycle changed')
    for operation, query in [(rows[39], human[0]), (rows[48], human[2])]:
        require(query['started_monotonic'] - operation['finished_monotonic'] >= 5, 'original IGMPv2 wait shortened')
    traffic = [r for r in rows if r['tool'] == 'mausezahn']; packets = report['packet_trace']
    require(len(traffic) == len(packets) == 83, 'complete native IGMP control/data frames missing')
    udp = 0; control_count = 0; total_bytes = 0
    for sender, packet in zip(traffic, packets):
        args = sender['arguments']; host = args[0]; devices = topology(sender['sg_before'])
        frame = bytes.fromhex(packet['frame_hex']); ip_size = int.from_bytes(frame[16:18], 'big')
        payload = frame[34:14+ip_size]; total_bytes += len(frame)
        require(packet['family'] == 17 and packet['ifindex'] == devices[host]['ifindex'] and
                packet['length'] == packet['result'] == len(frame) and frame[6:12].hex() == devices[host]['address'].replace(':', '') and
                frame[12:15] == bytes.fromhex('080045') and 20 <= ip_size <= len(frame)-14 and
                len(frame) <= max(60, 14+ip_size) and not any(frame[14+ip_size:]) and checksum(frame[14:34]), 'native IGMP frame interface/MAC/IPv4/checksum changed')
        if args[args.index('-t')+1] == 'ip':
            control_count += 1
            literal = args[args.index('-t')+2].split('p=', 1)[1].replace(':', '')
            require(frame[:6].hex() == '01005e000001' and frame[23] == 2 and payload.hex() == literal and checksum(payload) and
                    str(ipaddress.IPv4Address(frame[30:34])) == '224.0.0.1' and
                    str(ipaddress.IPv4Address(frame[26:30])) == ('192.0.2.1' if host == 'veth0' else '192.0.2.2'),
                    'actual native IGMP report bytes/checksum changed')
            continue
        source, seen = expected_udp[udp]; receiver = 'veth3' if udp < 2 else 'veth0'
        require(host == ('veth0' if udp < 2 else 'veth3') and frame[:6].hex() == MAC.replace(':', '') and
                len(frame) == 106 and frame[23] == 17 and frame[26:30] == bytes([192, 0, 2, source]) and
                frame[30:34] == ipaddress.IPv4Address(GROUP).packed and payload[:6] == bytes.fromhex('080010000048') and
                len(payload[8:]) == 64, 'original source-specific UDP frame changed')
        query = rows[rows.index(sender)+1]
        require(query['tool'] == 'tc' and query['arguments'] == ['-j', '-s', 'filter', 'show', 'dev', receiver, 'ingress'] and
                query['started_monotonic']-sender['finished_monotonic'] >= 1, 'original UDP wait/counter query missing')
        flower(sender['sg_before']['filters_by_device'][receiver], 0); flower(json.loads(query['stdout']), seen)
        after = topology(query['sg_after']); peer = 'veth1' if host == 'veth0' else 'veth2'
        path = [(host, 'tx'), (peer, 'rx')] + ([(('veth2' if receiver == 'veth3' else 'veth1'), 'tx'), (receiver, 'rx')] if seen else [])
        for name, direction in path:
            a, b = devices[name]['stats64'][direction], after[name]['stats64'][direction]
            require(b['packets']-a['packets'] >= 1 and b['bytes']-a['bytes'] >= len(frame), 'native UDP bridge traversal missing')
        if udp < 2:
            require(bool(target(sender['sg_before']['mdb'], 'veth2')) == bool(seen) and
                    devices['br0']['linkinfo']['info_data']['mcast_igmp_version'] == 2, 'native IGMPv2 traffic membership changed')
        udp += 1
    require(udp == 51 and control_count == 32, 'native IGMP packet inventory changed')
    reset = [r for r in rows if r['tool'] == 'ip' and r['arguments'][-2:] == ['mcast_igmp_version', '2']]
    require(len(reset) == 14, 'original IGMP phase cleanup missing')
    for i, row in enumerate(reset):
        require({r['port'] for r in target(row['sg_after']['mdb'])} == ({'veth2'} if i == 12 else set()),
                'native per-phase IGMP membership leaked')
    field = dict(mcast_last_member_interval='mcast_last_member_intvl', mcast_query_interval='mcast_query_intvl',
                 mcast_query_response_interval='mcast_query_response_intvl', mcast_membership_interval='mcast_membership_intvl')
    for row in rows:
        args = row['arguments']
        if len(args) == 8 and args[:6] == ['link', 'set', 'dev', 'br0', 'type', 'bridge']:
            key = field.get(args[6], args[6])
            require(links(row['sg_after'])['br0']['linkinfo']['info_data'][key] == int(args[7]), 'native IGMP scalar update ineffective')
    clean = report['cleanup_state']; remaining = links(clean); devices = [f'veth{i}' for i in range(4)]
    require(not any(n in remaining for n in ('br0', 'vveth0', 'vveth3')) and not target(clean['mdb']) and
            all('UP' not in remaining[n]['flags'] and 'master' not in remaining[n] and remaining[n]['promiscuity'] == 0 for n in devices) and
            not any(r.get('master') == 'br0' for r in clean['fdb']) and
            not any(a.get('scope') == 'global' for r in clean['addresses'] if r['ifname'] in devices for a in r.get('addr_info', [])) and
            not any(r.get('dev') in (*devices, 'br0') for f in ('ipv4_routes', 'ipv6_routes') for r in clean[f]) and
            all(clean[f].strip() == '0' for f in ('ipv4', 'ipv6')), 'native IGMP topology/address/route/MDB cleanup failed')
    require(report['missing_backend_control']['returncode'] not in (None, 0) and
            report['vrf_binding_control']['baseline']['returncode'] == 0 and
            report['vrf_binding_control']['unknown_vrf']['returncode'] not in (None, 0), 'native IGMP boundary control failed')
    native, stats = report['native_fixture'], report['stats']
    require(native['bridge_packet_sends'] == 83 and native['bridge_packet_bytes'] == total_bytes and
            native['bridge_packet_trace_errors'] == 0 and native['raw_sockets'] > 0 and native['live'] == 0 and
            stats['outstanding'] == 0 and stats['worker_exit_code'] == 0 and stats['control_eof'] is True and
            stats['shutdown_timed_out'] is False, 'native IGMP resource/shutdown proof failed')
