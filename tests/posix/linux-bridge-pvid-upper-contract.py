"""Require native PVID routing to survive an original VLAN upper lifecycle."""
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


def check_base(state):
    links = {x['ifname']: x for x in state['links']}
    bridge, port = links['br1'], links['veth1']
    require(bridge['linkinfo']['info_kind'] == 'bridge' and
            bridge['linkinfo']['info_data']['vlan_filtering'] == 1 and
            bridge['linkinfo']['info_data']['vlan_default_pvid'] == 0 and 'UP' in bridge['flags'] and
            port.get('master') == 'br1' and port['linkinfo']['info_slave_kind'] == 'bridge' and
            port['linkinfo']['info_slave_data']['state'] == 'forwarding', 'native PVID bridge/port incorrect')
    vlans = memberships(state['vlans'])
    require(vlans['br1'] == {10: {'PVID', 'Egress Untagged'}} and vlans['veth1'] == {10: set()},
            'native self PVID or tagged port VLAN changed')
    host = links['veth0.10']
    require(host['link'] == 'veth0' and host.get('master') == 'vveth0' and
            host['linkinfo']['info_kind'] == 'vlan' and host['linkinfo']['info_data']['id'] == 10 and
            'UP' in host['flags'] and links['veth3'].get('master') == 'vveth3', 'native host VLAN/VRF incorrect')
    addresses = {x['ifname']: {(a['local'], a['prefixlen']) for a in x.get('addr_info', [])}
                 for x in state['addresses']}
    for name, ipv4, ipv6 in (('br1', '192.0.2.2', '2001:db8:1::2'),
                            ('veth0.10', '192.0.2.1', '2001:db8:1::1'),
                            ('veth2', '192.0.2.129', '2001:db8:2::1'),
                            ('veth3', '192.0.2.130', '2001:db8:2::2')):
        require((ipv4, 28) in addresses[name] and (ipv6, 64) in addresses[name], 'native PVID routing addresses changed')
    for family, routes in (
        ('ipv4', [('192.0.2.0/28', 'br1'), ('192.0.2.128/28', 'veth2')]),
        ('ipv6', [('2001:db8:1::/64', 'br1'), ('2001:db8:2::/64', 'veth2')])):
        require(all(any(x.get('dst') == prefix and x.get('dev') == dev and x.get('protocol') == 'kernel'
                        for x in state[family + '_routes']) for prefix, dev in routes),
                'native base bridge connected routes changed')
    return links, addresses


def validate_evidence(report):
    original = report.get('original', {})
    results = [re.fullmatch(r'TEST: (.*?)\s+\[ OK \]', line)
               for line in original.get('stdout', '').splitlines() if line.startswith('TEST:')]
    require(original.get('returncode') == 0 and not original.get('stderr') and
            len(results) == 4 and all(results) and [r[1] for r in results] == ['ping', 'ping6'] * 2,
            'incomplete original PVID upper outcomes')
    rows = report.get('commands', [])
    traffic = [i for i, r in enumerate(rows) if r['arguments'][:2] == ['vrf', 'exec']]
    require(len(traffic) == 4, 'missing original PVID upper pings')
    for n, i in enumerate(traffic):
        r = rows[i]
        require(r['arguments'] == ['vrf', 'exec', 'vveth0', 'ping' if n % 2 == 0 else 'ping6',
                '-c', '10', '-i', '0.1', '-w', '5', '192.0.2.130' if n % 2 == 0 else '2001:db8:2::2'] and
                r['returncode'] == 0 and '10 received' in r['stdout'] and not r['stderr'] and
                r['vrf']['linkinfo']['info_kind'] == 'vrf', 'modified or ineffective original PVID upper traffic')
        require(r.get('native_clock_reads', 0) > 0, 'PVID upper ping did not read native realtime')
        links, _ = check_base(r['bridge_state'])
        require('br1.10' not in links, 'temporary PVID upper remained during original ping')
    changes = [i for i, r in enumerate(rows) if 'upper_after' in r]
    require([rows[i]['arguments'] for i in changes] == [
        ['link', 'add', 'name', 'br1.10', 'link', 'br1', 'type', 'vlan', 'id', '10'],
        ['link', 'set', 'dev', 'br1.10', 'up'],
        ['address', 'add', '192.0.2.33/28', 'dev', 'br1.10'],
        ['link', 'del', 'dev', 'br1.10']], 'missing original PVID upper create/up/address/delete lifecycle')
    sequence = traffic[:2] + changes + traffic[2:]
    require(sequence == sorted(sequence), 'PVID upper lifecycle reordered around original traffic')
    for n, i in enumerate(changes):
        state = rows[i]['upper_after']; links, addresses = check_base(state)
        extra_route = any(x.get('dst') == '192.0.2.32/28' and x.get('dev') == 'br1.10' and
                          x.get('protocol') == 'kernel' for x in state['ipv4_routes'])
        if n == 3:
            require('br1.10' not in links and 'br1.10' not in addresses and not extra_route,
                    'native temporary PVID upper or route not removed')
        else:
            upper = links['br1.10']
            require(upper['link'] == 'br1' and 'master' not in upper and
                    upper['linkinfo']['info_kind'] == 'vlan' and upper['linkinfo']['info_data']['id'] == 10,
                    'native temporary PVID VLAN upper incorrect')
            require(('UP' in upper['flags']) == (n > 0), 'native temporary VLAN upper state incorrect')
            require((('192.0.2.33', 28) in addresses['br1.10']) == (n == 2) and extra_route == (n == 2),
                    'native temporary VLAN upper address/route lifecycle incorrect')
    bridge = [r for r in rows if r['tool'] == 'bridge']
    require([r['arguments'] for r in bridge] == [
        ['vlan', 'add', 'dev', 'br1', 'vid', '10', 'pvid', 'untagged', 'self'],
        ['vlan', 'add', 'dev', 'veth1', 'vid', '10'],
        ['vlan', 'del', 'dev', 'veth1', 'vid', '10'],
        ['vlan', 'del', 'dev', 'br1', 'vid', '10', 'self']], 'original PVID VLAN operations changed')
    for r in bridge:
        words = r['arguments']; table = memberships(r['bridge_vlans_after'])
        require((10 in table.get(words[3], {})) == (words[1] == 'add'), 'native PVID VLAN operation ineffective')
    for family in ('ipv4', 'ipv6'):
        writes = [r['arguments'][1] for r in rows if r['tool'] == 'sysctl' and
                  r['arguments'][0] == '-qw' and r['arguments'][1].startswith('net.' + family + '.')]
        require(writes == ['net.' + family + '.conf.all.forwarding=1',
                          'net.' + family + '.conf.all.forwarding=0'] and
                report['cleanup_state'][family].strip() == '0', 'native PVID forwarding not restored')
    require(not any(x['ifname'] in ('br1', 'br1.10', 'veth0.10', 'vveth0', 'vveth3')
                    for x in report['cleanup_state']['links']), 'native PVID upper/bridge/VRF leaked')
    require([r['arguments'] for r in rows if r['returncode']] == [
        ['link', 'show', 'dev', 'veth0'], ['link', 'show', 'dev', 'veth2']], 'native PVID upper command failed')
    require(all(not r['stderr'] for r in rows if r['returncode'] == 0), 'native PVID upper command warning')
    before, after = map(forwarding_counts, (report['mib_before'], report['mib_after']))
    require(all(after[f] - before[f] >= 40 for f in ('ipv4', 'ipv6')), 'missing native PVID routed traffic')
    require(report.get('missing_backend_control', {}).get('returncode') not in (None, 0), 'host fallback accepted')
    binding = report.get('vrf_binding_control', {})
    require(binding.get('baseline', {}).get('returncode') == 0 and
            '1 received' in binding.get('baseline', {}).get('stdout', '') and
            binding.get('unknown_vrf', {}).get('returncode') not in (None, 0), 'native PVID VRF binding ineffective')
    native, stats = report.get('native_fixture', {}), report.get('stats', {})
    require(native.get('netlinks', 0) > 0 and native.get('raw_sockets', 0) > 0 and native.get('live') == 0 and
            stats.get('outstanding') == 0 and stats.get('worker_exit_code') == 0 and stats.get('control_eof') is True and
            stats.get('shutdown_timed_out') is False, 'native PVID upper resources did not stop normally')
