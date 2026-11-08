"""Require original routed VLAN uppers and real bridge port respin evidence."""
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


def vlan_memberships(rows):
    return {row['ifname']: {v['vlan']: set(v.get('flags', [])) for v in row['vlans']}
            for row in rows}


def validate_evidence(report):
    original = report.get('original', {})
    results = [re.fullmatch(r'TEST: (.*?)\s+\[ OK \]', line)
               for line in original.get('stdout', '').splitlines() if line.startswith('TEST:')]
    require(original.get('returncode') == 0 and not original.get('stderr') and
            len(results) == 4 and all(results) and [r[1] for r in results] == ['ping', 'ping6'] * 2,
            'incomplete original VLAN upper outcomes')
    rows = report.get('commands', [])
    traffic = [i for i, r in enumerate(rows) if r['arguments'][:2] == ['vrf', 'exec']]
    require(len(traffic) == 4, 'missing original VLAN upper traffic')
    for index in range(4):
        r = rows[traffic[index]]
        require(r['arguments'] == ['vrf', 'exec', 'vveth0', 'ping' if index % 2 == 0 else 'ping6',
                '-c', '10', '-i', '0.1', '-w', '5', '192.0.2.18' if index % 2 == 0 else '2001:db8:2::2'] and
                r['returncode'] == 0 and '10 received' in r['stdout'] and not r['stderr'] and
                r['vrf']['linkinfo']['info_kind'] == 'vrf', 'modified or ineffective original VLAN upper ping')
        require(r.get('native_clock_reads', 0) > 0, 'VLAN upper ping did not read native realtime')
        state = r['bridge_state']
        links = {x['ifname']: x for x in state['links']}
        br = links['br1']
        require(br['linkinfo']['info_kind'] == 'bridge' and
                br['linkinfo']['info_data']['vlan_filtering'] == 1 and 'UP' in br['flags'],
                'native VLAN-filtering bridge missing')
        vlans = vlan_memberships(state['vlans'])
        require(vlans['br1'] == {1: {'PVID', 'Egress Untagged'}, 555: set(), 777: set()} and
                vlans['veth1'] == {1: {'PVID', 'Egress Untagged'}, 555: set()} and
                vlans['veth2'] == {1: {'PVID', 'Egress Untagged'}, 777: set()},
                'native bridge self or two-port tagged VLAN memberships incorrect')
        for name in ('veth1', 'veth2'):
            port = links[name]
            require(port.get('master') == 'br1' and 'UP' in port['flags'] and
                    port['linkinfo']['info_slave_kind'] == 'bridge' and
                    port['linkinfo']['info_slave_data']['state'] == 'forwarding',
                    'native VLAN upper bridge port not forwarding')
        addresses = {x['ifname']: x.get('addr_info', []) for x in state['addresses']}
        for dev, parent, vid, master, ipv4, ipv6 in (
            ('br1.555', 'br1', 555, None, '192.0.2.2', '2001:db8:1::2'),
            ('br1.777', 'br1', 777, None, '192.0.2.17', '2001:db8:2::1'),
            ('veth0.555', 'veth0', 555, 'vveth0', '192.0.2.1', '2001:db8:1::1'),
            ('veth3.777', 'veth3', 777, 'vveth3', '192.0.2.18', '2001:db8:2::2')):
            link = links[dev]
            require(link['link'] == parent and link.get('master') == master and
                    link['linkinfo']['info_kind'] == 'vlan' and link['linkinfo']['info_data']['id'] == vid and
                    'UP' in link['flags'], 'native bridge/host VLAN upper or VRF incorrect')
            configured = {(a['local'], a['prefixlen']) for a in addresses[dev]}
            require((ipv4, 28) in configured and (ipv6, 64) in configured,
                    'native VLAN upper addresses missing')
        for family, routes in (
            ('ipv4', [('192.0.2.0/28', 'br1.555'), ('192.0.2.16/28', 'br1.777')]),
            ('ipv6', [('2001:db8:1::/64', 'br1.555'), ('2001:db8:2::/64', 'br1.777')])):
            require(all(any(x.get('dst') == prefix and x.get('dev') == dev and
                            x.get('protocol') == 'kernel' for x in state[family + '_routes'])
                        for prefix, dev in routes), 'native bridge VLAN upper connected FIB routes missing')
    actions = [i for i, r in enumerate(rows) if 'port_after' in r]
    expected = [
        ['link', 'set', 'dev', 'veth1', 'master', 'br1'],
        ['link', 'set', 'dev', 'veth2', 'master', 'br1'],
        ['link', 'set', 'dev', 'veth2', 'nomaster'],
        ['link', 'set', 'dev', 'veth1', 'nomaster'],
        ['link', 'set', 'dev', 'veth1', 'master', 'br1'],
        ['link', 'set', 'dev', 'veth2', 'master', 'br1'],
        ['link', 'set', 'dev', 'veth2', 'down', 'nomaster'],
        ['link', 'set', 'dev', 'veth1', 'down', 'nomaster']]
    require([rows[i]['arguments'] for i in actions] == expected,
            'missing original VLAN upper respin/cleanup operations')
    sequence = actions[:2] + traffic[:2] + actions[2:6] + traffic[2:] + actions[6:]
    require(sequence == sorted(sequence), 'original VLAN upper respin/traffic phases reordered')
    for i in actions:
        r = rows[i]; state = r['port_after']
        require(len(state) == 1 and state[0]['ifname'] == r['arguments'][3], 'native port transition missing')
        if 'nomaster' in r['arguments']:
            require('master' not in state[0] and 'info_slave_kind' not in state[0].get('linkinfo', {}),
                    'native bridge port stayed enslaved after nomaster')
        else:
            require(state[0].get('master') == 'br1' and
                    state[0]['linkinfo']['info_slave_kind'] == 'bridge', 'native bridge port not remastered')
    bridge = [i for i, r in enumerate(rows) if r['tool'] == 'bridge']
    expected_vlans = [
        ['vlan', 'add', 'dev', 'br1', 'vid', '555', 'self'],
        ['vlan', 'add', 'dev', 'br1', 'vid', '777', 'self'],
        ['vlan', 'add', 'dev', 'veth1', 'vid', '555'],
        ['vlan', 'add', 'dev', 'veth2', 'vid', '777'],
        ['vlan', 'add', 'dev', 'veth1', 'vid', '555'],
        ['vlan', 'add', 'dev', 'veth2', 'vid', '777'],
        ['vlan', 'del', 'dev', 'veth2', 'vid', '777'],
        ['vlan', 'del', 'dev', 'veth1', 'vid', '555'],
        ['vlan', 'del', 'dev', 'br1', 'vid', '777', 'self'],
        ['vlan', 'del', 'dev', 'br1', 'vid', '555', 'self']]
    require([rows[i]['arguments'] for i in bridge] == expected_vlans,
            'missing original bridge VLAN add/re-add/delete sequence')
    require(bridge[3] < traffic[0] and actions[5] < bridge[4] < bridge[5] < traffic[2] and
            traffic[-1] < bridge[6], 'VLAN re-add or cleanup reordered around original traffic')
    for i in bridge:
        r = rows[i]; words = r['arguments']; vid = int(words[5]); dev = words[3]
        table = vlan_memberships(r['bridge_vlans_after'])
        require((vid in table.get(dev, {})) == (words[1] == 'add'),
                'native VLAN operation ineffective')
    for family in ('ipv4', 'ipv6'):
        writes = [r['arguments'][1] for r in rows if r['tool'] == 'sysctl' and
                  r['arguments'][0] == '-qw' and r['arguments'][1].startswith('net.' + family + '.')]
        require(writes == ['net.' + family + '.conf.all.forwarding=1',
                          'net.' + family + '.conf.all.forwarding=0'] and
                report['cleanup_state'][family].strip() == '0', 'native forwarding not restored')
    devices = ('br1', 'br1.555', 'br1.777', 'veth0.555', 'veth3.777', 'vveth0', 'vveth3')
    require(not any(x['ifname'] in devices for x in report['cleanup_state']['links']),
            'native VLAN upper/bridge/VRF leaked')
    require([r['arguments'] for r in rows if r['returncode']] == [
        ['link', 'show', 'dev', 'veth0'], ['link', 'show', 'dev', 'veth2']],
        'native VLAN upper configuration or cleanup failed')
    require(all(not r['stderr'] for r in rows if r['returncode'] == 0), 'native command warning')
    before, after = map(forwarding_counts, (report['mib_before'], report['mib_after']))
    require(all(after[f] - before[f] >= 40 for f in ('ipv4', 'ipv6')), 'missing native routed VLAN upper traffic')
    require(report.get('missing_backend_control', {}).get('returncode') not in (None, 0), 'host fallback accepted')
    binding = report.get('vrf_binding_control', {})
    require(binding.get('baseline', {}).get('returncode') == 0 and
            '1 received' in binding.get('baseline', {}).get('stdout', '') and
            binding.get('unknown_vrf', {}).get('returncode') not in (None, 0), 'native VRF binding ineffective')
    native, stats = report.get('native_fixture', {}), report.get('stats', {})
    require(native.get('netlinks', 0) > 0 and native.get('raw_sockets', 0) > 0 and native.get('live') == 0 and
            stats.get('outstanding') == 0 and stats.get('worker_exit_code') == 0 and
            stats.get('control_eof') is True and stats.get('shutdown_timed_out') is False,
            'native VLAN upper resources did not stop normally')
