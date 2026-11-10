"""Native evidence for the complete pinned bridge_mld.sh source-filtering entry.

Static expected source sets express upstream assertions, not protocol behavior.
The original include->is_exclude caller has no X/Y arrays and sends source100
only; MDB state is checked independently without claiming unperformed traffic.
"""
import hashlib
import ipaddress
import json
import re

GROUP = 'ff02::cc'
MAC = '33:33:00:00:00:cc'
QUERY = ['-j', '-d', '-s', 'mdb', 'show', 'dev', 'br0']
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


def require(value, message):
    if not value:
        raise RuntimeError(message)


def links(state):
    return {row['ifname']: row for row in state['links']}


def target(objects, port=None):
    return [row for group in objects for row in group.get('mdb', [])
            if row.get('grp') == GROUP and (port is None or row.get('port') == port)]


def mdb(objects, index, mode, active, blocked, port='veth1', auto=False):
    rows = target(objects, port); wildcard = [r for r in rows if 'src' not in r]
    require(len(wildcard) == 1, 'native MLD wildcard MDB missing/duplicated')
    wildcard = wildcard[0]
    require(wildcard['filter_mode'] == mode and
            (float(wildcard['timer']) == 0 if mode == 'include' else float(wildcard['timer']) > 0),
            'native MLD wildcard mode/timer changed')
    sources = wildcard.get('source_list', [])
    expected = {f'2001:db8:1::{n}' for n in active | blocked}
    require(len(sources) == len(expected) and {s['address'] for s in sources} == expected,
            'native MLD wildcard source set changed')
    for source in sources:
        n = int(source['address'].split(':')[-1]); timer = float(source['timer'])
        require(timer > 0 if n in active else timer == 0, 'native MLD source timer/block state changed')
    sg = [r for r in rows if 'src' in r]
    require(len(sg) == len(expected) + int(auto) and
            {r['src'] for r in sg} == expected | ({'2001:db8:1::3'} if auto else set()),
            'native MLD S,G entry set changed')
    for row in rows:
        require(row.get('index') == index and row.get('dev') == 'br0' and row.get('state') == 'temp' and
                row.get('protocol') == 'kernel', 'native MLD MDB provenance changed')
        if 'src' in row:
            n = int(row['src'].split(':')[-1])
            flags = {'blocked'} if n in blocked else ({'added_by_star_ex'} if auto and n == 3 else set())
            require(row.get('filter_mode') == 'include' and set(row.get('flags', [])) == flags,
                    'native MLD S,G blocked/automatic flag changed')
        else:
            require(not row.get('flags'), 'unexpected native MLD wildcard flag')


def flower(rows, count):
    found = [r for r in rows if r.get('options', {}).get('handle') == 101]
    require(len(found) == 1, 'native MLD traffic classifier missing')
    row = found[0]; options = row['options']; actions = options.get('actions', [])
    require(row['protocol'] == 'ipv6' and row['pref'] == 1 and row['kind'] == 'flower' and
            options['keys'] == dict(dst_mac=MAC, eth_type='ipv6', ip_proto='udp') and
            options.get('not_in_hw') is True and len(actions) == 1 and actions[0]['kind'] == 'gact' and
            actions[0]['control_action']['type'] == 'drop', 'native MLD flower match/action changed')
    stats = actions[0]['stats']
    require(stats['packets'] == stats['drops'] == count and stats['bytes'] == 112 * count,
            'native MLD source-specific forwarding counter changed')


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(int.from_bytes(data[i:i+2], 'big') for i in range(0, len(data), 2))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return total == 65535


STARTS = [37, 77, 122, 167, 199, 249, 328, 407, 459, 522, 559, 641, 698]
COMMAND_SHA256 = "0356fcab2436814bec0ebfc8cb067c51e160423c797cdb88b183ecd0fdd460c3"
LABELS = ['MLDv2 report ff02::cc is_include', 'MLDv2 report ff02::cc include -> allow', 'MLDv2 report ff02::cc include -> is_include', 'MLDv2 report ff02::cc include -> is_exclude', 'MLDv2 report ff02::cc include -> to_exclude', 'MLDv2 report ff02::cc exclude -> allow', 'MLDv2 report ff02::cc exclude -> is_include', 'MLDv2 report ff02::cc exclude -> is_exclude', 'MLDv2 report ff02::cc exclude -> to_exclude', 'MLDv2 report ff02::cc include -> block', 'MLDv2 report ff02::cc exclude -> block', 'MLDv2 group ff02::cc exclude timeout', 'MLDv2 S,G port entry automatic add to a *,G port']

def topology(state):
    devices = links(state); br = devices['br0']; info = br['linkinfo']['info_data']
    require(br['linkinfo']['info_kind'] == 'bridge' and 'UP' in br['flags'] and
            info['vlan_filtering'] == 0 and info['mcast_snooping'] == info['mcast_querier'] == 1,
            'native MLD bridge topology changed')
    tables = []
    for host, port, number in [('veth0', 'veth1', 1), ('veth3', 'veth2', 2)]:
        vrf = 'v' + host
        require(devices[host]['link'] == port and devices[port]['link'] == host and
                devices[host]['linkinfo']['info_kind'] == devices[port]['linkinfo']['info_kind'] == 'veth' and
                devices[host].get('master') == vrf and devices[vrf]['linkinfo']['info_kind'] == 'vrf' and
                devices[port].get('master') == 'br0' and
                devices[port]['linkinfo']['info_slave_data']['state'] == 'forwarding' and
                all('UP' in devices[n]['flags'] for n in (host, port, vrf)), 'native MLD peer/VRF path missing')
        tables.append(devices[vrf]['linkinfo']['info_data']['table'])
        addresses = next(a for a in state['addresses'] if a['ifname'] == host)['addr_info']
        require(any(a.get('local') == f'2001:db8:1::{number}' and a.get('prefixlen') == 64 for a in addresses),
                'native MLD host IPv6 address changed')
    require(len(set(tables)) == 2 and not any(n.startswith(('veth0.', 'veth3.')) for n in devices),
            'native MLD host VRF/VLAN topology changed')
    return devices


def ipv6_checksum(frame, protocol, payload):
    return checksum(frame[22:54] + len(payload).to_bytes(4, 'big') + b'\0\0\0' + bytes([protocol]) + payload)


def validate_evidence(report):
    original = report.get('original', {})
    outcomes = [re.fullmatch(r'TEST: (.*?)\s+\[ OK \]', line) for line in original.get('stdout', '').splitlines()]
    require(original.get('returncode') == 0 and not original.get('stderr') and len(outcomes) == 13 and
            all(outcomes) and [m[1] for m in outcomes] == LABELS, 'complete original MLD outcomes missing')
    rows = report['commands']
    require(len(rows) == 754 and hashlib.sha256(json.dumps([(r['tool'], r['arguments']) for r in rows],
            separators=(',', ':')).encode()).hexdigest() == COMMAND_SHA256, 'complete original MLD command lifecycle changed')
    require([i for i, r in enumerate(rows) if r['returncode']] == [1, 3] and
            all(not r['stderr'] for i, r in enumerate(rows) if i not in (0, 1, 3)) and
            '-j[son]' in rows[0]['stdout'] + rows[0]['stderr'], 'original MLD command failed unexpectedly')
    for row in rows:
        require(row['finished_monotonic'] >= row['started_monotonic'], 'native command chronology reversed')
    require(all(b['started_monotonic'] >= a['finished_monotonic'] for a, b in zip(rows, rows[1:])),
            'original MLD commands overlapped/reordered')
    tools = report['iproute2']
    require(tools['version'] == '6.12.0' and tools['archive_sha256'] ==
            'bbd141ef7b5d0127cc2152843ba61f274dc32814fa3e0f13e7d07a080bef53d9' and
            report['tc_tool']['sha256'] == tools['binaries']['tc'] and bool(report['tc_tool']['sha256']) and
            tools['source_hashes']['tc/tc.c'] == 'e9b2e36053ee6e20f79d44a0cab3e1661300ecf9e9783c5fcd03357aa696a101',
            'pinned original tc provenance changed')
    expected_udp = []
    # Check each original query against the latest original report, including
    # intermediate include/exclude preparation and the unchanged expiry waits.
    for phase, (start, end) in enumerate(zip(STARTS, STARTS[1:] + [754])):
        part = rows[start:end]; controls = [r for r in part if r['tool'] == 'mausezahn' and 'udp' not in r['arguments']]
        queries = [r for r in part if r['tool'] == 'bridge' and r['arguments'] == QUERY]
        require(len(controls) == STAGE_COUNTS[phase] and len(queries) == QUERY_COUNTS[phase], 'original MLD phase incomplete')
        for stage, control in enumerate(controls):
            next_time = controls[stage+1]['started_monotonic'] if stage+1 < len(controls) else float('inf')
            observations = [q for q in queries if control['finished_monotonic'] <= q['started_monotonic'] < next_time]
            require(observations, 'original MLD report has no native MDB query')
            wait = 3 if phase == 9 and stage == 1 else 5 if phase == 11 and stage == 2 else 1
            require(observations[0]['started_monotonic'] - control['finished_monotonic'] >= wait,
                    'original MLD delivery/expiry wait shortened')
            final = stage == len(controls)-1
            mode, active, blocked = CASES[phase][:3] if final else (
                ('include', {1, 2, 3}, set()) if stage == 0 else ('exclude', {1, 2}, {20, 21}))
            devices = topology(control['sg_before']); index = devices['br0']['ifindex']
            require(devices['br0']['linkinfo']['info_data']['mcast_mld_version'] == 2, 'MLDv2 not active')
            if phase == 11 and stage == 2:
                wildcard = [r for r in target(control['sg_before']['mdb']) if 'src' not in r]
                require(len(wildcard) == 1 and wildcard[0]['filter_mode'] == 'exclude', 'timeout phase did not start in EXCLUDE')
            for query in observations:
                objects = json.loads(query['stdout'])
                mdb(objects, index, mode, active, blocked, auto=phase == 12 and final)
                require({r['port'] for r in target(objects)} == ({'veth1', 'veth2'} if phase == 12 and final else {'veth1'}),
                        'native MLD unexpected group port')
                if phase == 12 and final:
                    mdb(objects, index, 'include', {1, 2, 3}, set(), port='veth2')
        expected_udp.extend(CASES[phase][3])
    traffic = [r for r in rows if r['tool'] == 'mausezahn']; packets = report['packet_trace']
    require(len(traffic) == len(packets) == 81, 'complete native MLD control/data frames missing')
    udp = 0; control_count = 0; total_bytes = 0
    for sender, packet in zip(traffic, packets):
        args = sender['arguments']; host = args[0]; devices = topology(sender['sg_before'])
        frame = bytes.fromhex(packet['frame_hex']); total_bytes += len(frame)
        require(packet['family'] == 17 and packet['ifindex'] == devices[host]['ifindex'] and
                packet['length'] == packet['result'] == len(frame) and len(frame) >= 62 and
                frame[12:14] == bytes.fromhex('86dd') and frame[14] >> 4 == 6 and
                int.from_bytes(frame[18:20], 'big') == len(frame)-54, 'native MLD frame/interface/IPv6 length changed')
        if 'udp' not in args:
            control_count += 1
            literal = [a for a in args if re.fullmatch(r'(?:[0-9a-f]{2}:)+[0-9a-f]{2}', a)]
            # The original complete Ethernet reports intentionally spoof a
            # fixed link-local source/MAC; they are not the host's own MAC.
            require(len(literal) == 1 and frame.hex() == literal[0].replace(':', '') and
                    frame[:6].hex() == '333300000001' and frame[20:22] == bytes([0, 1]) and
                    frame[38:54] == ipaddress.IPv6Address('ff02::1').packed and
                    frame[54:62] == bytes.fromhex('3a00050200000000') and frame[62:64] == bytes([143, 0]) and
                    ipv6_checksum(frame, 58, frame[62:]), 'literal native MLD report/HBH/router-alert/checksum changed')
            continue
        # Original Mausezahn emits zero UDPv6 checksum in the captured run.
        # The original oracle is a bridge ingress flower counter, before UDP
        # validation; this is L2 forwarding evidence, not UDP socket delivery.
        source, seen = expected_udp[udp]; receiver = 'veth0'
        require(host == 'veth3' and '-6' in args and frame[:6].hex() == MAC.replace(':', '') and
                frame[6:12].hex() == devices[host]['address'].replace(':', '') and len(frame) == 126 and
                frame[20] == 17 and frame[22:38] == ipaddress.IPv6Address(f'2001:db8:1::{source}').packed and
                frame[38:54] == ipaddress.IPv6Address(GROUP).packed and frame[54:60] == bytes.fromhex('080010000048') and
                len(frame[62:]) == 64 and (frame[60:62] == b'\0\0' or ipv6_checksum(frame, 17, frame[54:])),
                'original native IPv6 multicast UDP frame changed')
        query = rows[rows.index(sender)+1]
        require(query['tool'] == 'tc' and query['arguments'] == ['-j', '-s', 'filter', 'show', 'dev', receiver, 'ingress'] and
                query['started_monotonic']-sender['finished_monotonic'] >= 1, 'original MLD UDP wait/counter query missing')
        flower(sender['sg_before']['filters_by_device'][receiver], 0); flower(json.loads(query['stdout']), seen)
        after = topology(query['sg_after'])
        for name, direction in [('veth3', 'tx'), ('veth2', 'rx')] + ([('veth1', 'tx'), ('veth0', 'rx')] if seen else []):
            a, b = devices[name]['stats64'][direction], after[name]['stats64'][direction]
            require(b['packets']-a['packets'] >= 1 and b['bytes']-a['bytes'] >= len(frame), 'native MLD UDP bridge traversal missing')
        udp += 1
    require(udp == 49 and control_count == 32, 'native MLD packet inventory changed')
    reset = [r for r in rows if r['tool'] == 'ip' and r['arguments'][-2:] == ['mcast_mld_version', '1']]
    require(len(reset) == 14, 'original MLD phase cleanup missing')
    for i, row in enumerate(reset):
        require({r['port'] for r in target(row['sg_after']['mdb'])} == ({'veth2'} if i == 12 else set()),
                'native per-phase MLD membership leaked')
    field = dict(mcast_last_member_interval='mcast_last_member_intvl', mcast_query_interval='mcast_query_intvl',
                 mcast_query_response_interval='mcast_query_response_intvl', mcast_membership_interval='mcast_membership_intvl')
    for row in rows:
        args = row['arguments']
        if len(args) >= 8 and args[:6] == ['link', 'set', 'dev', 'br0', 'type', 'bridge']:
            require(len(args[6:]) % 2 == 0, 'original native bridge scalar pairs malformed')
            info = links(row['sg_after'])['br0']['linkinfo']['info_data']
            for key, value in zip(args[6::2], args[7::2]):
                require(info[field.get(key, key)] == int(value), 'native MLD scalar update ineffective')
    clean = report['cleanup_state']; remaining = links(clean); devices = [f'veth{i}' for i in range(4)]
    require(not any(n in remaining for n in ('br0', 'vveth0', 'vveth3')) and not target(clean['mdb']) and
            all('UP' not in remaining[n]['flags'] and 'master' not in remaining[n] and remaining[n]['promiscuity'] == 0 for n in devices) and
            not any(r.get('master') == 'br0' for r in clean['fdb']) and
            not any(a.get('scope') == 'global' for r in clean['addresses'] if r['ifname'] in devices for a in r.get('addr_info', [])) and
            not any(r.get('dev') in (*devices, 'br0') for f in ('ipv4_routes', 'ipv6_routes') for r in clean[f]) and
            all(clean[f].strip() == '0' for f in ('ipv4', 'ipv6')), 'native MLD topology/address/route/MDB cleanup failed')
    require(report['missing_backend_control']['returncode'] not in (None, 0) and
            report['vrf_binding_control']['baseline']['returncode'] == 0 and
            report['vrf_binding_control']['unknown_vrf']['returncode'] not in (None, 0), 'native MLD boundary control failed')
    native, stats = report['native_fixture'], report['stats']
    require(native['bridge_packet_sends'] == 81 and native['bridge_packet_bytes'] == total_bytes and
            native['bridge_packet_trace_errors'] == 0 and native['raw_sockets'] > 0 and native['live'] == 0 and
            stats['outstanding'] == 0 and stats['worker_exit_code'] == 0 and stats['control_eof'] is True and
            stats['shutdown_timed_out'] is False, 'native MLD resource/shutdown proof failed')
