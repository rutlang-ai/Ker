"""Require original port-down MDB operations and real native flower counters."""
import json
import struct

GROUP = '239.10.10.10'
GROUP_MAC = '01:00:5e:0a:0a:0a'
MZ = ['veth0', '-c', '1', '-p', '64', '-b', GROUP_MAC, '-A', '192.0.2.1', '-B', GROUP,
      '-t', 'udp', 'dp=4096,sp=2048', '-q']
QADD = ['qdisc', 'add', 'dev', 'veth3', 'ingress']
FADD = ['filter', 'add', 'dev', 'veth3', 'ingress', 'protocol', 'ip', 'pref', '1', 'handle', '101',
        'flower', 'ip_proto', 'udp', 'dst_mac', GROUP_MAC, 'action', 'drop']
FSHOW = ['-j', '-s', 'filter', 'show', 'dev', 'veth3', 'ingress']
FDEL = ['filter', 'del', 'dev', 'veth3', 'ingress', 'protocol', 'ip', 'pref', '1', 'handle', '101', 'flower']
QDEL = ['qdisc', 'del', 'dev', 'veth3', 'ingress']


def require(value, message):
    if not value:
        raise RuntimeError(message)


def group_rows(state):
    return [r for br in state['mdb'] for r in br.get('mdb', []) if r.get('grp') == GROUP]


def state_proof(state, present, up):
    links = {r['ifname']: r for r in state['links']}
    br = links['br0']; config = br['linkinfo']['info_data']
    require(br['linkinfo']['info_kind'] == 'bridge' and 'UP' in br['flags'] and config['vlan_filtering'] == 0 and
            config['mcast_snooping'] == config['mcast_querier'] == 1, 'native snooping/querier bridge missing')
    for host, port, vrf in (('veth0', 'veth1', 'vveth0'), ('veth3', 'veth2', 'vveth3')):
        require(links[host]['linkinfo']['info_kind'] == links[port]['linkinfo']['info_kind'] == 'veth' and
                links[host]['link'] == port and links[port]['link'] == host and links[host].get('master') == vrf and
                links[vrf]['linkinfo']['info_kind'] == 'vrf' and links[port].get('master') == 'br0' and
                all('UP' in links[n]['flags'] for n in (host, vrf)), 'native multicast veth/VRF topology changed')
    require(links['veth1']['linkinfo']['info_slave_data']['state'] == 'forwarding' and
            ('UP' in links['veth2']['flags']) == up and
            links['veth2']['linkinfo']['info_slave_data']['state'] == ('forwarding' if up else 'disabled') and
            links['veth2']['linkinfo']['info_slave_data']['mcast_flood'] is False and
            links['vveth0']['linkinfo']['info_data']['table'] != links['vveth3']['linkinfo']['info_data']['table'],
            'native target bridge port state or multicast flood policy changed')
    rows = group_rows(state)
    require(len(rows) == int(present) and all(r.get('dev') == 'br0' and r.get('port') == 'veth2' and
            r.get('index') == br['ifindex'] and r.get('state') == 'permanent' for r in rows),
            'target permanent MDB row missing, leaked or bound to wrong native port')
    return links


def flower(rows, expected):
    selected = [r for r in rows if r.get('options', {}).get('handle') == 101]
    require(len(selected) == 1, 'native flower handle101 missing or duplicated')
    row = selected[0]; options = row['options']; actions = options.get('actions', [])
    require(row.get('protocol') == 'ip' and row.get('pref') == 1 and row.get('kind') == 'flower' and
            options.get('keys') == dict(dst_mac=GROUP_MAC, eth_type='ipv4', ip_proto='udp') and
            options.get('not_in_hw') is True and len(actions) == 1 and actions[0].get('kind') == 'gact' and
            actions[0].get('control_action', {}).get('type') == 'drop', 'native multicast flower/gact rule changed')
    stats = actions[0]['stats']
    require(stats.get('packets') == stats.get('drops') == expected and stats.get('bytes') == 92 * expected,
            'actual native multicast flower packet/byte/drop counter changed')


def validate_evidence(report):
    original = report.get('original', {})
    require(original.get('returncode') == 0 and not original.get('stderr') and
            original.get('stdout', '').split() == ['TEST:', 'MDB', 'add/del', 'entry', 'to', 'port', 'with', 'state', 'down', '[', 'OK', ']'],
            'incomplete original MDB port-down result')
    provenance = report.get('iproute2', {})
    require(provenance.get('version') == '6.12.0' and provenance.get('archive_sha256') ==
            'bbd141ef7b5d0127cc2152843ba61f274dc32814fa3e0f13e7d07a080bef53d9' and
            report.get('tc_tool', {}).get('sha256') == provenance.get('binaries', {}).get('tc') and
            bool(report.get('tc_tool', {}).get('sha256')) and provenance.get('source_hashes', {}).get('tc/tc.c') ==
            'e9b2e36053ee6e20f79d44a0cab3e1661300ecf9e9783c5fcd03357aa696a101', 'pinned original tc provenance missing')
    rows = report['commands']; bridge = [r for r in rows if r['tool'] == 'bridge']
    require([r['arguments'] for r in bridge] == [
        ['link', 'set', 'dev', 'veth2', 'mcast_flood', 'off'],
        ['mdb', 'add', 'dev', 'br0', 'port', 'veth2', 'grp', GROUP, 'permanent'],
        ['mdb', 'show', 'dev', 'br0'], ['mdb', 'del', 'dev', 'br0', 'port', 'veth2', 'grp', GROUP]],
        'original MDB operations or flood policy changed')
    for row, first, last in ((bridge[1], False, True), (bridge[2], True, True), (bridge[3], True, False)):
        require('mdb_port_before' in row and 'mdb_port_after' in row, 'native MDB operation proof missing')
        state_proof(row['mdb_port_before'], first, False); state_proof(row['mdb_port_after'], last, False)
    require(GROUP + ' permanent' in bridge[2]['stdout'], 'original permanent-MDB grep outcome missing')
    operations = [r for r in rows if r['tool'] in ('tc', 'mausezahn')]
    require([(r['tool'], r['arguments']) for r in operations] ==
            [('tc', QADD), ('tc', FADD), ('mausezahn', MZ), ('tc', FSHOW), ('tc', FDEL), ('tc', QDEL)] * 2,
            'original two complete multicast flower windows changed')
    traffic = [r for r in rows if r['tool'] == 'mausezahn']
    queries = [r for r in rows if r['tool'] == 'tc' and r['arguments'] == FSHOW]
    require(len(traffic) == len(queries) == 2, 'native multicast traffic/counter windows incomplete')
    packets = report.get('packet_trace', [])
    require(len(packets) == 2, 'two original native AF_PACKET frames missing')
    for index, (sender, query, packet) in enumerate(zip(traffic, queries, packets)):
        present = index == 0
        require('mdb_port_before' in sender and 'mdb_port_after' in sender, 'native multicast send state proof missing')
        before, after = sender['mdb_port_before'], sender['mdb_port_after']
        a, b = state_proof(before, present, True), state_proof(after, present, True)
        flower(before['filters'], 0)
        # The unchanged original sleep1 precedes its decisive tc query; no earlier
        # snapshot imposes an extra packet-delivery deadline.
        early = [r for r in after['filters'] if r.get('options', {}).get('handle') == 101]
        require(len(early) == 1, 'native multicast filter vanished during send')
        early_count = early[0]['options']['actions'][0]['stats']['packets']
        require(early_count in ((0, 1) if present else (0,)), 'unexpected early native multicast counter')
        flower(after['filters'], early_count); flower(json.loads(query['stdout']), int(present))
        frame = bytes.fromhex(packet['frame_hex'])
        require(packet.get('family') == 17 and packet.get('ifindex') == a['veth0']['ifindex'] and
                packet.get('length') == packet.get('result') == len(frame) == 106 and
                frame[:6].hex() == GROUP_MAC.replace(':', '') and
                frame[6:12].hex() == a['veth0']['address'].replace(':', '') and frame[12:15] == bytes.fromhex('080045') and
                int.from_bytes(frame[16:18], 'big') == 92 and frame[23] == 17 and
                frame[26:34] == bytes([192, 0, 2, 1, 239, 10, 10, 10]) and
                struct.unpack('!HHH', frame[34:40]) == (2048, 4096, 72) and len(frame[42:]) == 64,
                'original native multicast Ethernet/IP/UDP packet or sender changed')
        require('mdb_port_before' in query and 'mdb_port_after' in query, 'decisive native flower query state missing')
        state_proof(query['mdb_port_after'], present, True)
        for dev, direction in [('veth0', 'tx'), ('veth1', 'rx')] + ([('veth2', 'tx'), ('veth3', 'rx')] if present else []):
            x, y = a[dev]['stats64'][direction], b[dev]['stats64'][direction]
            require(y['packets'] - x['packets'] >= 1 and y['bytes'] - x['bytes'] >= len(frame),
                    'actual native multicast frame did not traverse expected bridge ingress/peer')
    downs = [r for r in rows if r['arguments'] == ['link', 'set', 'dev', 'veth2', 'down']]
    ups = [r for r in rows if r['arguments'] == ['link', 'set', 'dev', 'veth2', 'up']]
    require(len(downs) >= 3 and len(ups) == 2 and all('mdb_port_after' in r for r in downs + ups),
            'original native port-down/up phases missing')
    require(rows.index(bridge[1]) < rows.index(traffic[0]) < rows.index(bridge[2]) < rows.index(bridge[3]) < rows.index(traffic[1]),
            'original MDB add, first probe, persistence, delete, second probe reordered')
    require([r['arguments'] for r in rows if r['returncode']] ==
            [['link', 'show', 'dev', 'veth0'], ['link', 'show', 'dev', 'veth2']] and
            all(not r['stderr'] for r in rows if r['returncode'] == 0), 'native MDB/tc/MZ configuration or cleanup failed')
    clean = report['cleanup_state']; links = {r['ifname']: r for r in clean['links']}; devices = tuple(f'veth{i}' for i in range(4))
    require(not any(n in links for n in ('br0', 'vveth0', 'vveth3')) and
            all('UP' not in links[n]['flags'] and 'master' not in links[n] for n in devices) and not group_rows(clean),
            'native MDB bridge/VRF/port/membership state leaked')
    require(not any(br.get('mdb') for br in clean['mdb']) and
            not any(a.get('scope') == 'global' for r in clean['addresses'] if r['ifname'] in devices for a in r.get('addr_info', [])) and
            not any(r.get('dev') in (*devices, 'br0') for f in ('ipv4_routes', 'ipv6_routes') for r in clean[f]) and
            not any(r['tool'] == 'sysctl' for r in rows) and all(clean[f].strip() == '0' for f in ('ipv4', 'ipv6')),
            'native multicast address/route/forwarding cleanup incomplete')
    require(all(sum(r['arguments'] == ['link', 'del', 'dev', n] for r in rows) == 1 for n in ('br0', 'vveth0', 'vveth3')),
            'original native MDB/VRF teardown missing')
    require(report.get('missing_backend_control', {}).get('returncode') not in (None, 0) and
            report.get('vrf_binding_control', {}).get('baseline', {}).get('returncode') == 0 and
            report.get('vrf_binding_control', {}).get('unknown_vrf', {}).get('returncode') not in (None, 0), 'native backend/VRF control failed')
    native, stats = report.get('native_fixture', {}), report.get('stats', {})
    require(native.get('bridge_packet_sockets', 0) > 0 and native.get('bridge_packet_sends') == 2 and
            native.get('bridge_packet_bytes') == 212 and native.get('bridge_packet_trace_errors') == 0 and
            native.get('netlinks', 0) > 0 and native.get('live') == 0 and stats.get('outstanding') == 0 and
            stats.get('worker_exit_code') == 0 and stats.get('control_eof') is True and
            stats.get('shutdown_timed_out') is False, 'native multicast resources did not stop normally')
