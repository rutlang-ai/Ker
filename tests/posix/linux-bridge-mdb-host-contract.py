"""Complete original bridge host MDB membership evidence contract."""
import re


def require(value, message):
    if not value:
        raise RuntimeError(message)


GROUPS = [('01:00:01:c0:ff:ee', 'permanent'), ('225.1.2.3', 'temp'), ('ff02::42', 'temp')]


def entries(snapshot):
    return [entry for table in snapshot for entry in table.get('mdb', [])]


def topology(state):
    links = {r['ifname']: r for r in state['links']}
    bridge, port, host, vrf = (links[n] for n in ('br0', 'veth1', 'veth0', 'vveth0'))
    require(bridge['linkinfo']['info_kind'] == 'bridge' and 'UP' in bridge['flags'] and
            bridge['linkinfo']['info_data']['mcast_snooping'] == 1,
            'native host MDB bridge or multicast snooping missing')
    require(port.get('master') == 'br0' and 'UP' in port['flags'] and
            port['linkinfo']['info_slave_kind'] == 'bridge' and
            port['linkinfo']['info_slave_data']['state'] == 'forwarding' and
            host['linkinfo']['info_kind'] == port['linkinfo']['info_kind'] == 'veth' and
            host['link'] == 'veth1' and port['link'] == 'veth0',
            'native host MDB bridge port or veth peer changed')
    require(host.get('master') == 'vveth0' and 'UP' in host['flags'] and
            vrf['linkinfo']['info_kind'] == 'vrf' and 'UP' in vrf['flags'],
            'native host MDB host VRF changed')
    table = str(vrf['linkinfo']['info_data']['table'])
    addresses = {r['ifname']: r.get('addr_info', []) for r in state['addresses']}
    require(all(any(a.get('local') == address and a.get('prefixlen') == prefix
                    for a in addresses['veth0'])
                for address, prefix in (('192.0.2.1', 24), ('2001:db8:1::1', 64))) and
            not any(a.get('scope') == 'global' for name in ('br0', 'veth1') for a in addresses[name]),
            'native host MDB host addresses changed')
    for family, prefix in (('ipv4', '192.0.2.0/24'), ('ipv6', '2001:db8:1::/64')):
        require(any(r.get('dst') == prefix and r.get('dev') == 'veth0' and
                    str(r.get('table')) == table and r.get('protocol') == 'kernel'
                    for r in state[family + '_routes']), 'native host MDB host connected route missing')
    return bridge['ifindex']


def validate_evidence(report):
    original = report.get('original', {})
    results = [re.fullmatch(r'TEST: (.*?)\s+\[ OK \]', line) for line in
               original.get('stdout', '').splitlines() if line.startswith('TEST:')]
    require(original.get('returncode') == 0 and not original.get('stderr') and len(results) == 3 and
            all(results) and [r[1] for r in results] == [
                'MDB add/del group ' + group + ' to bridge port br0' for group, _ in GROUPS],
            'incomplete original three-group host MDB matrix')
    rows = report['commands']
    bridge = [r for r in rows if r['tool'] == 'bridge']
    expected = []
    for group, flag in GROUPS:
        expected += [['mdb', 'add', 'dev', 'br0', 'port', 'br0', 'grp', group] +
                     (['permanent'] if flag == 'permanent' else []), ['mdb', 'show', 'dev', 'br0'],
                     ['mdb', 'del', 'dev', 'br0', 'port', 'br0', 'grp', group], ['mdb', 'show', 'dev', 'br0']]
    require([r['arguments'] for r in bridge] == expected and
            all(r['returncode'] == 0 and not r['stderr'] for r in bridge), 'original MDB operations changed or failed')
    for i, (group, flag) in enumerate(GROUPS):
        require('dev br0 port br0 grp ' + group + ' ' + flag in bridge[4*i+1]['stdout'] and
                group not in bridge[4*i+3]['stdout'], 'native original MDB show did not confirm add/delete')
        require(all('mdb_before' in r and 'mdb_after' in r for r in bridge[4*i:4*i+4]),
                'native MDB observations missing')
        for j, record in enumerate(bridge[4*i:4*i+4]):
            for position, expected_present in (('mdb_before', j in (1, 2)), ('mdb_after', j in (0, 1))):
                state = record[position]
                index = topology(state)
                targets = [e for e in entries(state['mdb']) if e.get('grp') in {g for g, _ in GROUPS}]
                require(len(targets) == int(expected_present) and all(
                    e.get('index') == index and e.get('dev') == e.get('port') == 'br0' and
                    e.get('grp') == group and e.get('state') == flag for e in targets),
                    'native host MDB mutation ineffective or wrong port/group/state')
    require([r['arguments'] for r in rows if r['returncode']] == [['link', 'show', 'dev', 'veth0']] and
            all(not r['stderr'] for r in rows if r['returncode'] == 0), 'native host MDB setup or cleanup failed')
    cleanup = report['cleanup_state']
    links = {r['ifname']: r for r in cleanup['links']}
    require('br0' not in links and 'vveth0' not in links and
            all('UP' not in links[n]['flags'] and 'master' not in links[n] for n in ('veth0', 'veth1')),
            'native host MDB bridge/VRF or interface state leaked')
    require(not any(a.get('scope') == 'global' for r in cleanup['addresses'] if r['ifname'] in ('veth0', 'veth1')
                    for a in r.get('addr_info', [])) and
            not any(r.get('dev') in ('veth0', 'veth1', 'br0', 'vveth0')
                    for family in ('ipv4_routes', 'ipv6_routes') for r in cleanup[family]) and
            not any(e.get('dev') == 'br0' or e.get('grp') in {g for g, _ in GROUPS}
                    for e in entries(cleanup['mdb'])), 'native host MDB addresses/routes/memberships leaked')
    require(all(cleanup[f].strip() == '0' for f in ('ipv4', 'ipv6')) and
            not any(r['tool'] == 'sysctl' for r in rows), 'host MDB entry unexpectedly changed native forwarding')
    require(all(any(r['arguments'] == ['link', 'del', 'dev', dev] for r in rows) for dev in ('br0', 'vveth0')),
            'original host MDB teardown commands missing')
    require(report.get('missing_backend_control', {}).get('returncode') not in (None, 0), 'MDB host fallback accepted')
    binding = report.get('vrf_binding_control', {})
    require(binding.get('baseline', {}).get('returncode') == 0 and
            '1 received' in binding.get('baseline', {}).get('stdout', '') and
            binding.get('unknown_vrf', {}).get('returncode') not in (None, 0), 'native MDB fixture VRF binding ineffective')
    native, stats = report.get('native_fixture', {}), report.get('stats', {})
    require(native.get('netlinks', 0) > 0 and native.get('raw_sockets', 0) > 0 and native.get('live') == 0 and
            stats.get('outstanding') == 0 and stats.get('worker_exit_code') == 0 and
            stats.get('control_eof') is True and stats.get('shutdown_timed_out') is False,
            'native MDB resources did not stop normally')
