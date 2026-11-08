"""Require the complete original sticky-FDB shell and actual native ARP send."""
import json


def require(value, message):
    if not value:
        raise RuntimeError(message)


MAC = 'de:ad:be:ef:13:37'


def topology(state):
    links = {r['ifname']: r for r in state['links']}
    bridge = links['br0']
    require(bridge['linkinfo']['info_kind'] == 'bridge' and 'UP' in bridge['flags'] and
            bridge['linkinfo']['info_data']['vlan_filtering'] == 0 and
            bridge['linkinfo']['info_data']['vlan_default_pvid'] == 1,
            'native sticky bridge type or default VLAN changed')
    for host, port in (('veth0', 'veth1'), ('veth2', 'veth3')):
        require(all(links[n]['linkinfo']['info_kind'] == 'veth' and 'UP' in links[n]['flags'] for n in (host, port)) and
                links[host]['link'] == port and links[port]['link'] == host and 'master' not in links[host] and
                links[port].get('master') == 'br0' and links[port]['linkinfo']['info_slave_kind'] == 'bridge' and
                links[port]['linkinfo']['info_slave_data']['state'] == 'forwarding' and
                links[port]['linkinfo']['info_slave_data']['learning'] is True,
                'native sticky bridge ports or source learning disabled')
    return links


def targets(rows, vlans, filtered=False):
    selected = [r for r in rows if r['mac'] == MAC]
    require(len(selected) == len(vlans) and {r.get('vlan', 0) for r in selected} == vlans and
            all((filtered or r.get('ifname') == 'veth1') and r.get('master') == 'br0' and
                r.get('state') == 'static' and 'sticky' in r.get('flags', []) for r in selected),
            'native sticky FDB entry moved, lost flags, or retained the wrong VID')


def validate_evidence(report):
    original = report.get('original', {})
    require(original.get('returncode') == 0 and original.get('stdout', '').split() ==
            ['TEST:', 'Sticky', 'fdb', 'entry', '[', 'OK', ']'], 'incomplete original sticky FDB test')
    rows = report['commands']
    bridge = [r for r in rows if r['tool'] == 'bridge']
    require([r['arguments'] for r in bridge] == [
        ['fdb', 'add', MAC, 'dev', 'veth1', 'master', 'static', 'sticky'],
        ['fdb', 'del', MAC, 'dev', 'veth1', 'vlan', '1', 'master', 'static', 'sticky'],
        ['-j', 'fdb', 'show', 'br', 'br0', 'brport', 'veth1']], 'original sticky FDB operations changed')
    mz = [r for r in rows if r['tool'] == 'mausezahn']
    require(len(mz) == 1 and mz[0]['arguments'] == ['veth2', '-c', '1', '-a', MAC, '-t', 'arp', 'request', '-q'] and
            mz[0]['returncode'] == 0, 'original sticky ARP sender failed or changed')
    # The original ignores the VLAN-1 delete and sender statuses. Preserve
    # those commands; prove actual effects and a successful native send here.
    require(bridge[0]['returncode'] == bridge[2]['returncode'] == 0 and
            not bridge[0]['stderr'] and not bridge[2]['stderr'], 'native sticky add/query failed')
    require(original.get('stderr') == bridge[1]['stderr'] + mz[0]['stderr'], 'unexpected original sticky FDB diagnostic')
    operations = [r for r in rows if r['tool'] in ('bridge', 'mausezahn')]
    require(operations == [bridge[0], bridge[1], mz[0], bridge[2]], 'original sticky traffic or VLAN delete reordered')
    for i, operation in enumerate(operations):
        require('sticky_before' in operation and 'sticky_after' in operation, 'native sticky state proof missing')
        for key, vlans in (('sticky_before', set() if i == 0 else {0, 1} if i == 1 else {0}),
                           ('sticky_after', {0, 1} if i == 0 else {0})):
            topology(operation[key])
            targets(operation[key]['fdb'], vlans)
    targets(json.loads(bridge[2]['stdout']), {0}, filtered=True)
    packets = report.get('packet_trace', [])
    require(len(packets) == 1 and packets[0]['result'] == packets[0]['length'] >= 42,
            'sticky FDB test did not send one complete native packet')
    packet = bytes.fromhex(packets[0]['frame_hex'])
    require(len(packet) == packets[0]['length'] and packet[:6] == b'\xff' * 6 and
            packet[6:12].hex() == MAC.replace(':', '') and packet[12:22] == bytes.fromhex('08060001080006040001'),
            'original native spoofed Ethernet-source ARP request missing')
    before, after = (topology(mz[0][key]) for key in ('sticky_before', 'sticky_after'))
    require(packets[0]['family'] == 17 and packets[0]['ifindex'] == before['veth2']['ifindex'],
            'native packet was sent through the wrong interface or address family')
    for device, direction in (('veth2', 'tx'), ('veth3', 'rx'), ('veth1', 'tx'), ('veth0', 'rx')):
        first, last = (state[device]['stats64'][direction] for state in (before, after))
        require(last['packets'] - first['packets'] >= 1 and last['bytes'] - first['bytes'] >= len(packet),
                'native spoofed frame did not traverse the original bridge ingress and peer')
    allowed = [['link', 'show', 'dev', 'veth0'], ['link', 'show', 'dev', 'veth2']]
    if bridge[1]['returncode']:
        allowed.append(bridge[1]['arguments'])
    require([r['arguments'] for r in rows if r['returncode']] == allowed and
            all(not r['stderr'] for r in rows if r['returncode'] == 0 and r['tool'] != 'mausezahn'),
            'unexpected native sticky configuration or cleanup failure')
    cleanup = report['cleanup_state']; remaining = {r['ifname']: r for r in cleanup['links']}
    devices = ('veth0', 'veth1', 'veth2', 'veth3')
    require('br0' not in remaining and all('UP' not in remaining[n]['flags'] and 'master' not in remaining[n]
                                        for n in devices), 'native sticky bridge or port state leaked')
    require(not any(r.get('mac') == MAC or r.get('master') == 'br0' for r in cleanup['fdb']) and
            not any(a.get('scope') == 'global' for r in cleanup['addresses'] if r['ifname'] in devices
                    for a in r.get('addr_info', [])) and
            not any(r.get('dev') in (*devices, 'br0') for family in ('ipv4_routes', 'ipv6_routes')
                    for r in cleanup[family]), 'native sticky FDB/address/route cleanup incomplete')
    require(any(r['arguments'] == ['link', 'del', 'dev', 'br0'] for r in rows) and
            not any(r['tool'] == 'sysctl' for r in rows) and
            all(cleanup[f].strip() == '0' for f in ('ipv4', 'ipv6')), 'original sticky teardown or forwarding state changed')
    require(report.get('missing_backend_control', {}).get('returncode') not in (None, 0), 'sticky host fallback accepted')
    binding = report.get('vrf_binding_control', {})
    require(binding.get('baseline', {}).get('returncode') == 0 and
            binding.get('unknown_vrf', {}).get('returncode') not in (None, 0), 'native fixture isolation control failed')
    native, stats = report.get('native_fixture', {}), report.get('stats', {})
    require(native.get('bridge_packet_sockets', 0) > 0 and native.get('bridge_packet_sends') == 1 and
            native.get('bridge_packet_bytes') == len(packet) and native.get('bridge_packet_trace_errors') == 0,
            'native packet transport proof incomplete')
    require(native.get('netlinks', 0) > 0 and native.get('live') == 0 and stats.get('outstanding') == 0 and
            stats.get('worker_exit_code') == 0 and stats.get('control_eof') is True and
            stats.get('shutdown_timed_out') is False, 'native sticky resources did not close normally')
