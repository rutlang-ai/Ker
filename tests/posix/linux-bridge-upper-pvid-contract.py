"""Require original VLAN upper routing across actual self-PVID transitions."""
import re


def require(value, message):
    if not value:
        raise RuntimeError(message)


def forwarding_counts(content):
    lines = content['ipv4'].splitlines()
    i = next(i for i, line in enumerate(lines) if line.startswith('Ip:'))
    ipv4 = dict(zip(lines[i].split()[1:], map(int, lines[i + 1].split()[1:])))
    ipv6 = dict(line.split() for line in content['ipv6'].splitlines())
    return dict(ipv4=ipv4['ForwDatagrams'], ipv6=int(ipv6['Ip6OutForwDatagrams']))


def memberships(rows):
    return {r['ifname']: {v['vlan']: set(v.get('flags', [])) for v in r['vlans']} for r in rows}


def check_topology(state, self_vlans):
    links = {x['ifname']: x for x in state['links']}
    bridge, port, upper, host = (links[n] for n in ('br1', 'veth1', 'br1.10', 'veth0.10'))
    require(bridge['linkinfo']['info_kind'] == 'bridge' and
            bridge['linkinfo']['info_data']['vlan_filtering'] == 1 and
            bridge['linkinfo']['info_data']['vlan_default_pvid'] == 0 and 'UP' in bridge['flags'],
            'native bridge filtering/default PVID changed')
    require(port.get('master') == 'br1' and port['linkinfo']['info_slave_kind'] == 'bridge' and
            port['linkinfo']['info_slave_data']['state'] == 'forwarding', 'native bridge port not forwarding')
    vlans = memberships(state['vlans'])
    require(vlans['br1'] == self_vlans and vlans['veth1'] == {10: set()},
            'native self PVID or tagged port membership incorrect')
    require(upper['link'] == 'br1' and 'master' not in upper and 'UP' in upper['flags'] and
            upper['linkinfo']['info_kind'] == 'vlan' and upper['linkinfo']['info_data']['id'] == 10,
            'native persistent VLAN upper incorrect')
    require(host['link'] == 'veth0' and host.get('master') == 'vveth0' and 'UP' in host['flags'] and
            host['linkinfo']['info_kind'] == 'vlan' and host['linkinfo']['info_data']['id'] == 10 and
            links['veth3'].get('master') == 'vveth3', 'native host VLAN/VRF incorrect')
    addresses = {x['ifname']: x.get('addr_info', []) for x in state['addresses']}
    for name, ipv4, ipv6 in (('br1.10', '192.0.2.2', '2001:db8:1::2'),
                            ('veth0.10', '192.0.2.1', '2001:db8:1::1'),
                            ('veth2', '192.0.2.129', '2001:db8:2::1'),
                            ('veth3', '192.0.2.130', '2001:db8:2::2')):
        configured = {(a['local'], a['prefixlen']) for a in addresses[name]}
        require((ipv4, 28) in configured and (ipv6, 64) in configured, 'native upper routing addresses changed')
    require(not any(a.get('scope') == 'global' for a in addresses['br1']),
            'original route addresses moved to base bridge instead of VLAN upper')
    for family, routes in (
        ('ipv4', [('192.0.2.0/28', 'br1.10'), ('192.0.2.128/28', 'veth2')]),
        ('ipv6', [('2001:db8:1::/64', 'br1.10'), ('2001:db8:2::/64', 'veth2')])):
        require(all(any(x.get('dst') == prefix and x.get('dev') == dev and x.get('protocol') == 'kernel'
                        for x in state[family + '_routes']) for prefix, dev in routes),
                'native VLAN upper connected routes changed')


def validate_evidence(report):
    original = report.get('original', {})
    results = [re.fullmatch(r'TEST: (.*?)\s+\[ OK \]', line)
               for line in original.get('stdout', '').splitlines() if line.startswith('TEST:')]
    require(original.get('returncode') == 0 and not original.get('stderr') and len(results) == 6 and
            all(results) and [r[1] for r in results] == ['ping', 'ping6'] * 3,
            'incomplete original upper PVID outcomes')
    rows = report.get('commands', [])
    traffic = [i for i, r in enumerate(rows) if r['arguments'][:2] == ['vrf', 'exec']]
    require(len(traffic) == 6, 'missing original upper PVID traffic')
    for n, i in enumerate(traffic):
        r = rows[i]
        require(r['arguments'] == ['vrf', 'exec', 'vveth0', 'ping' if n % 2 == 0 else 'ping6',
                '-c', '10', '-i', '0.1', '-w', '5', '192.0.2.130' if n % 2 == 0 else '2001:db8:2::2'] and
                r['returncode'] == 0 and '10 received' in r['stdout'] and not r['stderr'] and
                r['vrf']['linkinfo']['info_kind'] == 'vrf', 'modified or ineffective original upper PVID ping')
        require(r.get('native_clock_reads', 0) > 0, 'upper PVID ping did not read native realtime')
        check_topology(r['bridge_state'], {10: set()} if n < 4 else {10: set(), 20: {'PVID'}})
    bridge = [i for i, r in enumerate(rows) if r['tool'] == 'bridge']
    require([rows[i]['arguments'] for i in bridge] == [
        ['vlan', 'add', 'dev', 'br1', 'vid', '10', 'self'],
        ['vlan', 'add', 'dev', 'veth1', 'vid', '10'],
        ['vlan', 'add', 'dev', 'br1', 'vid', '10', 'pvid', 'self'],
        ['vlan', 'add', 'dev', 'br1', 'vid', '10', 'self'],
        ['vlan', 'add', 'dev', 'br1', 'vid', '10', 'pvid', 'self'],
        ['vlan', 'add', 'dev', 'br1', 'vid', '20', 'pvid', 'self'],
        ['vlan', 'del', 'dev', 'veth1', 'vid', '10'],
        ['vlan', 'del', 'dev', 'br1', 'vid', '10', 'self']], 'original self PVID operations changed')
    require([i for i, r in enumerate(rows) if 'pvid_after' in r] == bridge,
            'missing actual post-command PVID snapshots')
    self_states = [{10: set()}, {10: set()}, {10: {'PVID'}}, {10: set()},
                   {10: {'PVID'}}, {10: set(), 20: {'PVID'}},
                   {10: set(), 20: {'PVID'}}, {20: {'PVID'}}]
    for n, i in enumerate(bridge):
        r = rows[i]; table = memberships(r['bridge_vlans_after'])
        require(table.get('br1', {}) == self_states[n] and
                table.get('veth1', {}) == ({10: set()} if 1 <= n <= 5 else {}),
                'native self PVID set/unset/move or port VLAN operation ineffective')
        require(memberships(r['pvid_after']['vlans']) == table, 'native post-command VLAN observations disagree')
        if 2 <= n <= 5:
            check_topology(r['pvid_after'], self_states[n])
    sequence = bridge[:2] + traffic[:2] + bridge[2:4] + traffic[2:4] + bridge[4:6] + traffic[4:] + bridge[6:]
    require(sequence == sorted(sequence), 'original PVID transitions reordered around traffic')
    for family in ('ipv4', 'ipv6'):
        writes = [r['arguments'][1] for r in rows if r['tool'] == 'sysctl' and
                  r['arguments'][0] == '-qw' and r['arguments'][1].startswith('net.' + family + '.')]
        require(writes == ['net.' + family + '.conf.all.forwarding=1',
                          'net.' + family + '.conf.all.forwarding=0'] and
                report['cleanup_state'][family].strip() == '0', 'native upper PVID forwarding not restored')
    require(not any(x['ifname'] in ('br1', 'br1.10', 'veth0.10', 'vveth0', 'vveth3')
                    for x in report['cleanup_state']['links']), 'native upper PVID devices leaked')
    require([r['arguments'] for r in rows if r['returncode']] == [
        ['link', 'show', 'dev', 'veth0'], ['link', 'show', 'dev', 'veth2']], 'native upper PVID command failed')
    require(all(not r['stderr'] for r in rows if r['returncode'] == 0), 'native upper PVID command warning')
    before, after = map(forwarding_counts, (report['mib_before'], report['mib_after']))
    require(all(after[f] - before[f] >= 60 for f in ('ipv4', 'ipv6')), 'missing native routed upper PVID traffic')
    require(report.get('missing_backend_control', {}).get('returncode') not in (None, 0), 'host fallback accepted')
    binding = report.get('vrf_binding_control', {})
    require(binding.get('baseline', {}).get('returncode') == 0 and
            '1 received' in binding.get('baseline', {}).get('stdout', '') and
            binding.get('unknown_vrf', {}).get('returncode') not in (None, 0), 'native upper PVID VRF binding ineffective')
    native, stats = report.get('native_fixture', {}), report.get('stats', {})
    require(native.get('netlinks', 0) > 0 and native.get('raw_sockets', 0) > 0 and native.get('live') == 0 and
            stats.get('outstanding') == 0 and stats.get('worker_exit_code') == 0 and stats.get('control_eof') is True and
            stats.get('shutdown_timed_out') is False, 'native upper PVID resources did not stop normally')
