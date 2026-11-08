"""Require the complete original dual-stack bridge port isolation matrix."""
import json
import re

MAC = 'de:ad:be:ef:13:37'
QADD = ['qdisc', 'add', 'dev', 'veth3', 'ingress']
FADD = ['filter', 'add', 'dev', 'veth3', 'ingress', 'protocol', 'ip', 'pref', '1', 'handle', '101',
        'flower', 'dst_mac', MAC, 'action', 'drop']
FSHOW = ['-j', '-s', 'filter', 'show', 'dev', 'veth3', 'ingress']
FDEL = ['filter', 'del', 'dev', 'veth3', 'ingress', 'protocol', 'ip', 'pref', '1', 'handle', '101', 'flower']
QDEL = ['qdisc', 'del', 'dev', 'veth3', 'ingress']


def require(value, message):
    if not value:
        raise RuntimeError(message)


def topology(state):
    links = {r['ifname']: r for r in state['links']}
    require(links['br0']['linkinfo']['info_kind'] == 'bridge' and 'UP' in links['br0']['flags'] and
            links['br0']['linkinfo']['info_data']['vlan_filtering'] == 0, 'native isolation bridge missing')
    tables = []
    for host, port, vrf, isolated, number in (('veth0', 'veth1', 'vveth0', True, 1),
            ('veth3', 'veth2', 'vveth3', True, 2), ('veth5', 'veth4', 'vveth5', False, 3)):
        require(links[host]['linkinfo']['info_kind'] == links[port]['linkinfo']['info_kind'] == 'veth' and
                links[host]['link'] == port and links[port]['link'] == host and links[host].get('master') == vrf and
                links[vrf]['linkinfo']['info_kind'] == 'vrf' and links[port].get('master') == 'br0' and
                links[port]['linkinfo']['info_slave_data']['isolated'] is isolated and
                links[port]['linkinfo']['info_slave_data']['state'] == 'forwarding' and
                all('UP' in links[n]['flags'] for n in (host, port, vrf)), 'native per-port isolation or topology changed')
        tables.append(links[vrf]['linkinfo']['info_data']['table'])
        address = next(r for r in state['addresses'] if r['ifname'] == host)
        require(all(any(a.get('local') == local and a.get('prefixlen') == prefix for a in address['addr_info'])
                    for local, prefix in ((f'192.0.2.{number}', 24), (f'2001:db8:1::{number}', 64))),
                'original native host addresses changed')
    require(len(set(tables)) == 3, 'native isolated hosts share a VRF routing table')
    return links


def flower(rows, count):
    selected = [r for r in rows if r.get('options', {}).get('handle') == 101]
    require(len(selected) == 1, 'native isolation flower handle101 missing')
    row = selected[0]; opts = row['options']; actions = opts.get('actions', [])
    require(row.get('protocol') == 'ip' and row.get('pref') == 1 and row.get('kind') == 'flower' and
            opts.get('keys') == dict(dst_mac=MAC, eth_type='ipv4') and opts.get('not_in_hw') is True and
            len(actions) == 1 and actions[0].get('kind') == 'gact' and
            actions[0].get('control_action', {}).get('type') == 'drop', 'native isolation flower rule changed')
    stats = actions[0]['stats']
    require(stats.get('packets') == stats.get('drops') == count and stats.get('bytes') == 84 * count,
            'native isolated/nonisolated unknown-unicast counter mismatch')


def validate_evidence(report):
    original = report.get('original', {})
    results = [re.fullmatch(r'TEST: (.*?)\s+\[ OK \]', line)
               for line in original.get('stdout', '').splitlines() if line.startswith('TEST:')]
    require(original.get('returncode') == 0 and not original.get('stderr') and len(results) == 3 and
            all(results) and [r[1] for r in results] == ['Isolated port ping', 'Isolated port ping6', 'Isolated port flooding'] and
            'SKIP' not in original.get('stdout', ''), 'incomplete original isolation outcomes')
    tools = report.get('iproute2', {})
    require(tools.get('version') == '6.12.0' and tools.get('archive_sha256') ==
            'bbd141ef7b5d0127cc2152843ba61f274dc32814fa3e0f13e7d07a080bef53d9' and
            bool(report.get('tc_tool', {}).get('sha256')) and
            report['tc_tool']['sha256'] == tools.get('binaries', {}).get('tc') and
            tools.get('source_hashes', {}).get('tc/tc.c') ==
            'e9b2e36053ee6e20f79d44a0cab3e1661300ecf9e9783c5fcd03357aa696a101', 'original pinned tc provenance missing')
    rows = report['commands']; tc = [r for r in rows if r['tool'] == 'tc']
    require([r['arguments'] for r in tc] == [['-j']] + [QADD, FADD, FSHOW, FDEL, QDEL] * 2,
            'original tc capability probe or two complete flower windows changed')
    require(tc[0]['returncode'] == 0 and '-j[son]' in tc[0]['stdout'] + tc[0]['stderr'],
            'original tc JSON capability probe missing')
    settings = [r for r in rows if 'isolated' in r['arguments']]
    require([r['arguments'] for r in settings] == [
        ['link', 'set', 'dev', port, 'type', 'bridge_slave', 'isolated', setting]
        for port, setting in (('veth1', 'on'), ('veth2', 'on'), ('veth4', 'off'))], 'original isolation flags changed')
    for index, row in enumerate(settings):
        require('isolation_before' in row and 'isolation_after' in row, 'native isolation update proof missing')
        links = {r['ifname']: r for r in row['isolation_after']['links']}
        require(links[['veth1', 'veth2', 'veth4'][index]]['linkinfo']['info_slave_data']['isolated'] is (index < 2),
                'native isolation flag update ineffective')
    pings = [r for r in rows if r['arguments'][:2] == ['vrf', 'exec']]
    require(len(pings) == 4 and [r['returncode'] for r in pings] == [1, 0, 1, 0], 'original dual-stack isolation matrix changed')
    for index, row in enumerate(pings):
        positive = index % 2 == 1; host, port = ('veth5', 'veth4') if positive else ('veth0', 'veth1')
        program, address = ('ping', '192.0.2.2') if index < 2 else ('ping6', '2001:db8:1::2')
        require(row['arguments'] == ['vrf', 'exec', 'v' + host, program, '-c', '10', '-i', '0.1', '-w', '5', address] and
                not row['stderr'] and ('10 received' if positive else '0 received') in row['stdout'] and
                row.get('native_clock_reads', 0) > 0 and row['vrf']['ifname'] == 'v' + host,
                'original native ping args/outcome/clock or VRF changed')
        require('isolation_before' in row and 'isolation_after' in row, 'native ping isolation proof missing')
        a, b = topology(row['isolation_before']), topology(row['isolation_after'])
        for dev, direction in [(host, 'tx'), (port, 'rx')] + ([('veth2', 'tx'), ('veth3', 'rx')] if positive else []):
            require(b[dev]['stats64'][direction]['packets'] > a[dev]['stats64'][direction]['packets'],
                    'original native ping did not traverse expected source/peer')
    traffic = [r for r in rows if r['tool'] == 'mausezahn']; queries = [r for r in tc if r['arguments'] == FSHOW]
    packets = report.get('packet_trace', []); require(len(traffic) == len(queries) == len(packets) == 2, 'two native flood probes missing')
    promisc = [r for r in rows if 'promisc' in r['arguments']]
    require([r['arguments'] for r in promisc] == [
        ['link', 'set', 'veth3', 'promisc', mode] for mode in ('on', 'off', 'on', 'off')], 'original capture promisc lifecycle changed')
    for row in promisc:
        require('isolation_after' in row, 'native promisc state proof missing')
        link = next(r for r in row['isolation_after']['links'] if r['ifname'] == 'veth3')
        require(link['promiscuity'] == int(row['arguments'][-1] == 'on'), 'native promisc command ineffective')
    sequence = [r for r in rows if r['tool'] in ('tc', 'mausezahn')][1:]
    expected = []
    for host in ('veth0', 'veth5'):
        mz = [host, '-c', '1', '-p', '64', '-b', MAC, '-B', '192.0.2.100', '-t', 'ip', '-q']
        expected.extend([('tc', QADD), ('tc', FADD), ('mausezahn', mz), ('tc', FSHOW), ('tc', FDEL), ('tc', QDEL)])
    require([(r['tool'], r['arguments']) for r in sequence] == expected, 'original isolated flood phases reordered')
    for index, (sender, query, packet) in enumerate(zip(traffic, queries, packets)):
        positive = index == 1; host, port, number = ('veth5', 'veth4', 3) if positive else ('veth0', 'veth1', 1)
        require('isolation_before' in sender and 'isolation_after' in sender and 'isolation_after' in query,
                'native flood before/after-wait proof missing')
        before = sender['isolation_before']; decisive = query['isolation_after']
        a, b = topology(before), topology(decisive)
        require(not any(r.get('mac') == MAC for r in before['fdb']) and
                a['veth3']['promiscuity'] == b['veth3']['promiscuity'] == 1, 'flood destination known or capture port not promisc')
        flower(before['filters'], 0); flower(json.loads(query['stdout']), int(positive))
        frame = bytes.fromhex(packet['frame_hex'])
        require(packet.get('family') == 17 and packet.get('ifindex') == a[host]['ifindex'] and
                packet.get('length') == packet.get('result') == len(frame) == 98 and
                frame[:6].hex() == MAC.replace(':', '') and frame[6:12].hex() == a[host]['address'].replace(':', '') and
                frame[12:15] == bytes.fromhex('080045') and int.from_bytes(frame[16:18], 'big') == 84 and
                frame[26:34] == bytes([192, 0, 2, number, 192, 0, 2, 100]) and len(frame[34:]) == 64,
                'original unknown-unicast native frame/source/interface changed')
        for dev, direction in [(host, 'tx'), (port, 'rx')] + ([('veth2', 'tx'), ('veth3', 'rx')] if positive else []):
            x, y = a[dev]['stats64'][direction], b[dev]['stats64'][direction]
            require(y['packets'] - x['packets'] >= 1 and y['bytes'] - x['bytes'] >= len(frame),
                    'native flood traversal missing after original delivery wait')
    allowed = [['link', 'show', 'dev', f'veth{i}'] for i in (0, 2, 4)] + [pings[0]['arguments'], pings[2]['arguments']]
    require([r['arguments'] for r in rows if r['returncode']] == allowed and
            all(not r['stderr'] for r in rows if r['returncode'] == 0 and r is not tc[0]),
            'unexpected original native isolation configuration failure')
    clean = report['cleanup_state']; links = {r['ifname']: r for r in clean['links']}; devices = tuple(f'veth{i}' for i in range(6))
    require(not any(n in links for n in ('br0', 'vveth0', 'vveth3', 'vveth5')) and
            all('UP' not in links[n]['flags'] and 'master' not in links[n] and links[n]['promiscuity'] == 0 for n in devices) and
            not any(r.get('master') == 'br0' for r in clean['fdb']), 'native isolated bridge/VRF/port/promisc state leaked')
    require(not any(a.get('scope') == 'global' for r in clean['addresses'] if r['ifname'] in devices for a in r.get('addr_info', [])) and
            not any(r.get('dev') in (*devices, 'br0') for family in ('ipv4_routes', 'ipv6_routes') for r in clean[family]) and
            all(clean[f].strip() == '0' for f in ('ipv4', 'ipv6')) and not any(r['tool'] == 'sysctl' for r in rows), 'native isolation address/routes leaked')
    require(all(sum(r['arguments'] == ['link', 'del', 'dev', n] for r in rows) == 1 for n in ('br0', 'vveth0', 'vveth3', 'vveth5')),
            'original native isolation teardown missing')
    require(report.get('missing_backend_control', {}).get('returncode') not in (None, 0) and
            report.get('vrf_binding_control', {}).get('baseline', {}).get('returncode') == 0 and
            report.get('vrf_binding_control', {}).get('unknown_vrf', {}).get('returncode') not in (None, 0), 'native isolation boundary control failed')
    native, stats = report.get('native_fixture', {}), report.get('stats', {})
    require(native.get('bridge_packet_sends') == 2 and native.get('bridge_packet_bytes') == 196 and
            native.get('bridge_packet_trace_errors') == 0 and native.get('raw_sockets', 0) > 0 and
            native.get('live') == 0 and stats.get('outstanding') == 0 and stats.get('worker_exit_code') == 0 and
            stats.get('control_eof') is True and stats.get('shutdown_timed_out') is False, 'native isolation resources leaked')
