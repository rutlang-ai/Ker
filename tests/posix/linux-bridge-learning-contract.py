"""Require complete original FDB accounting, native learning and limit behavior."""
import collections
import json
import re

PREFIX = 'de:ad:be:ef:42:'
MAC = PREFIX + '00'
DEFAULT_MAC = PREFIX + '2a'
TYPES = ('learned', 'static', 'user', 'extern_learn', 'local')
COUNT_QUERY = ['-d', '-j', 'link', 'show', 'dev', 'br0', 'type', 'bridge']
FDB_QUERY = ['-j', 'fdb', 'show', 'br', 'br0']


def require(value, message):
    if not value:
        raise RuntimeError(message)


def data(state):
    links = [r for r in state['links'] if r['ifname'] == 'br0']
    require(len(links) == 1 and links[0]['linkinfo']['info_kind'] == 'bridge', 'native FDB bridge missing')
    return links[0]['linkinfo']['info_data']


def target(rows, mac=MAC):
    # Match the original jq predicate, excluding even a VLAN 1 twin of this MAC.
    return [r for r in rows if r.get('mac') == mac and 'vlan' not in r]


def topology(state, source):
    links = {r['ifname']: r for r in state['links']}
    require(data(state)['vlan_filtering'] == 0 and 'UP' in links['br0']['flags'], 'native bridge mode changed')
    for host, port, vrf in (('veth0', 'veth1', 'vveth0'), ('veth2', 'veth3', 'vveth2')):
        require(links[host]['linkinfo']['info_kind'] == links[port]['linkinfo']['info_kind'] == 'veth' and
                links[host]['link'] == port and links[port]['link'] == host and links[host].get('master') == vrf and
                links[vrf]['linkinfo']['info_kind'] == 'vrf' and links[port].get('master') == 'br0' and
                links[port]['linkinfo']['info_slave_data']['state'] == 'forwarding' and
                all('UP' in links[n]['flags'] for n in (host, port, vrf)), 'native learning topology changed')
    require(links['vveth0']['linkinfo']['info_data']['table'] != links['vveth2']['linkinfo']['info_data']['table'] and
            links['veth1']['linkinfo']['info_slave_data']['learning'] is True and
            links['veth3']['linkinfo']['info_slave_data']['learning'] is False and
            links['veth0']['address'] == source, 'source MAC or native per-port learning policy changed')
    return links


def validate_evidence(report):
    original = report.get('original', {})
    names = (['FDB accounting'] + ['FDB accounting interacting with FDB type ' + t for t in TYPES] +
             ['FDB limits'] + ['FDB limits interacting with FDB type ' + t for t in TYPES])
    results = [re.fullmatch(r'TEST: (.*?)\s+\[ OK \]', line)
               for line in original.get('stdout', '').splitlines() if line.startswith('TEST:')]
    require(original.get('returncode') == 0 and not original.get('stderr') and len(results) == 12 and
            all(results) and [r[1] for r in results] == names and 'SKIP' not in original.get('stdout', ''),
            'incomplete original FDB accounting/limit outcomes')
    rows = report['commands']
    capability = [r for r in rows if r['arguments'] == ['link', 'help', 'bridge']]
    require(len(capability) == 1 and capability[0]['returncode'] == 0 and
            'fdb_max_learned' in capability[0]['stdout'] + capability[0]['stderr'], 'learning capability probe bypassed')
    queries = [r for r in rows if r['arguments'] == COUNT_QUERY]
    counts = []
    for row in queries:
        objects = json.loads(row['stdout'])
        require(row['returncode'] == 0 and not row['stderr'] and len(objects) == 1 and objects[0]['ifname'] == 'br0',
                'original native learned-count query failed')
        counts.append(objects[0]['linkinfo']['info_data']['fdb_n_learned'])
    require(counts == [0, 0, 16, 1, 0] + [0] * 12 + [8], 'native five-type accounting or limit 8 changed')
    cycle = list(range(1, 17))
    sources = cycle + [0] * 5 + cycle + cycle + [0] + cycle * 4
    transitions = ([(i - 1, i, 0) for i in cycle] + [(0, 1, 0)] * 5 +
                   [(min(i - 1, 8), min(i, 8), 8) for i in cycle] * 2 + [(8, 8, 8)] +
                   [(min(i - 1, 8), min(i, 8), 8) for i in cycle] * 4)
    pings = [r for r in rows if r['arguments'][:2] == ['vrf', 'exec']]
    require(len(pings) == len(sources) == 118, 'original 118 one-ping learned attempts missing')
    require(sum(r['arguments'] == ['link', 'set', 'veth0', 'addr', DEFAULT_MAC] for r in rows) == 119,
            'original default source setup or one of 118 restorations missing')
    for row, number, (first, last, limit) in zip(pings, sources, transitions):
        mac = PREFIX + f'{number:02x}'
        position = rows.index(row)
        require(rows[position - 2]['arguments'] == ['link', 'set', 'veth0', 'addr', mac] and
                rows[position - 1]['arguments'] == ['-j', 'link', 'show', 'dev', 'veth0'] and
                rows[position + 1]['arguments'] == ['link', 'set', 'veth0', 'addr', DEFAULT_MAC],
                'original source MAC change/ping/restore sequence changed')
        require(row['arguments'] == ['vrf', 'exec', 'vveth0', 'ping', '-c', '1', '-i', '0.1', '-w', '5', '192.0.2.2'] and
                row['returncode'] == 0 and not row['stderr'] and '1 packets transmitted, 1 received' in row['stdout'] and
                row.get('native_clock_reads', 0) > 0 and row['vrf']['linkinfo']['info_kind'] == 'vrf',
                'original native one-ping arguments, outcome or clock changed')
        require('learning_before' in row and 'learning_after' in row, 'native ping state proof missing')
        before, after = row['learning_before'], row['learning_after']
        a, b = topology(before, mac), topology(after, mac)
        # Native control traffic after the original MAC change can learn before ping.
        require(first <= data(before)['fdb_n_learned'] <= last and data(after)['fdb_n_learned'] == last and
                data(before)['fdb_max_learned'] == data(after)['fdb_max_learned'] == limit,
                'actual learned count or configured limit changed')
        learned = target(after['fdb'], mac)
        require(len(learned) == (1 if first < last else 0) and all(
            r.get('ifname') == 'veth1' and r.get('master') == 'br0' and r.get('state') == '' and
            'extern_learn' not in r.get('flags', []) for r in learned), 'VID0 learning did not honor native limit')
        for dev, direction in (('veth0', 'tx'), ('veth1', 'rx'), ('veth3', 'tx'), ('veth2', 'rx')):
            x, y = a[dev]['stats64'][direction], b[dev]['stats64'][direction]
            require(y['packets'] - x['packets'] >= 1 and y['bytes'] - x['bytes'] >= 98,
                    'original ICMP frame did not traverse native bridge')
    bridge = [r for r in rows if r['tool'] == 'bridge']
    require(collections.Counter(tuple(r['arguments'][:2]) for r in bridge) ==
            {('fdb', 'flush'): 16, ('fdb', 'add'): 16, ('fdb', 'replace'): 9, ('fdb', 'del'): 7, ('-j', 'fdb'): 5},
            'original FDB operation matrix changed')
    replacements = [r for r in bridge if r['arguments'][:2] == ['fdb', 'replace']]
    suffixes = [['static']] * 2 + [['static', 'use']] * 2 + [['extern_learn']] * 2 + [
        ['static'], ['static', 'use'], ['extern_learn']]
    require([r['arguments'] for r in replacements] == [
        ['fdb', 'replace', MAC, 'dev', 'veth1', 'master', *suffix] for suffix in suffixes],
        'original static/user/external replacement sequence changed')
    for row in bridge:
        args = row['arguments']
        if args == FDB_QUERY:
            continue
        require('learning_before' in row and 'learning_after' in row, 'native FDB mutation state proof missing')
        before = data(row['learning_before'])
        state = row['learning_after']; count = data(state)['fdb_n_learned']
        require(before['fdb_max_learned'] == data(state)['fdb_max_learned'], 'FDB mutation altered native learning limit')
        if args[:2] == ['fdb', 'flush']:
            require(args == ['fdb', 'flush', 'dev', 'br0'] and count == 0, 'native FDB flush failed')
        elif args[:2] == ['fdb', 'add']:
            require(args == ['fdb', 'add', DEFAULT_MAC, 'dev', 'veth1', 'master', 'static', 'use'] and
                    count == 0, 'original default source entry counted as learned')
        elif args[:2] == ['fdb', 'del']:
            require(args == ['fdb', 'del', MAC, 'dev', 'veth1', 'master'] and count == 0 and
                    not target(state['fdb']), 'original native FDB delete failed')
        else:
            records = target(state['fdb']); external = args[-1] == 'extern_learn'
            require(count == (8 if data(state)['fdb_max_learned'] else 0) and len(records) == 1 and
                    records[0].get('ifname') == 'veth1' and records[0].get('master') == 'br0' and
                    records[0].get('state') in (('static',) if args[-1] == 'static' else ('', 'static') if args[-1] == 'use' else ('',)) and
                    ('extern_learn' in records[0].get('flags', [])) == external,
                    'native static/user/external FDB accounting or flags changed')
    require([data(r['learning_before'])['fdb_n_learned'] for r in replacements] ==
            [0, 1, 0, 1, 0, 1, 8, 8, 8], 'original learned-to-nonlearned replacement phases missing')
    addresses = [r for r in rows if r['arguments'][:5] == ['link', 'set', 'dev', 'veth5', 'addr']]
    require(len(addresses) == 3, 'original local MAC assignments missing')
    for row in addresses:
        require(row['arguments'] == ['link', 'set', 'dev', 'veth5', 'addr', MAC], 'local MAC argument changed')
        require('learning_before' in row and 'learning_after' in row, 'local MAC native state proof missing')
        for key in ('learning_before', 'learning_after'):
            links = {r['ifname']: r for r in row[key]['links']}
            require('master' not in links['veth5'] and
                    (key != 'learning_after' or links['veth5']['address'] == MAC), 'local MAC set on wrong native port')
    local = [r for r in rows if r['arguments'][:3] == ['link', 'set', 'veth5']]
    require([r['arguments'][3:] for r in local] == [
        ['master', 'br0'], ['nomaster'], ['master', 'br0'], ['nomaster'], ['master', 'br0']],
        'original local FDB attachment/removal sequence changed')
    for row in local:
        require('learning_before' in row and 'learning_after' in row, 'local port native state proof missing')
        before_links = {r['ifname']: r for r in row['learning_before']['links']}
        state = row['learning_after']; links = {r['ifname']: r for r in state['links']}; records = target(state['fdb'])
        attached = row['arguments'][3] == 'master'
        require((before_links['veth5'].get('master') == 'br0') != attached and
                links['veth5']['address'] == MAC and (links['veth5'].get('master') == 'br0') == attached and
                len(records) == int(attached) and all(r.get('ifname') == 'veth5' and r.get('master') == 'br0' and
                    r.get('state') == 'permanent' for r in records) and
                data(state)['fdb_n_learned'] == (8 if data(state)['fdb_max_learned'] else 0),
                'local FDB entry, attachment or accounting changed')
    limited = [r for r in rows if r['arguments'] == FDB_QUERY]
    require(len(limited) == 5, 'original VID0 limit queries missing')
    for row, kind in zip(limited, TYPES):
        records = target(json.loads(row['stdout']))
        require(len(records) == (kind != 'learned') and all(r.get('master') == 'br0' for r in records),
                'VID0 admission of five FDB types at limit changed')
    require([r['arguments'] for r in rows if r['returncode']] ==
            [['link', 'show', 'dev', f'veth{i}'] for i in (0, 2, 4)] and
            all(not r['stderr'] for r in rows if r['returncode'] == 0 and r not in capability),
            'unexpected native configuration, ping or cleanup failure')
    clean = report['cleanup_state']; links = {r['ifname']: r for r in clean['links']}; devices = tuple(f'veth{i}' for i in range(6))
    require(not any(n in links for n in ('br0', 'vveth0', 'vveth2')) and
            all('UP' not in links[n]['flags'] and 'master' not in links[n] for n in devices), 'bridge/VRF/port state leaked')
    require(not any(r.get('mac', '').startswith(PREFIX) or r.get('master') == 'br0' for r in clean['fdb']) and
            not any(a.get('scope') == 'global' for r in clean['addresses'] if r['ifname'] in devices for a in r.get('addr_info', [])) and
            not any(r.get('dev') in (*devices, 'br0') for f in ('ipv4_routes', 'ipv6_routes') for r in clean[f]) and
            all(clean[f].strip() == '0' for f in ('ipv4', 'ipv6')) and not any(r['tool'] == 'sysctl' for r in rows),
            'native learning address/FDB/route/forwarding cleanup incomplete')
    require(all(sum(r['arguments'] == ['link', 'del', 'dev', n] for r in rows) == count
                for n, count in (('br0', 2), ('vveth0', 1), ('vveth2', 1))),
            'original probe or native bridge/VRF teardown missing')
    require(report.get('missing_backend_control', {}).get('returncode') not in (None, 0) and
            report.get('vrf_binding_control', {}).get('baseline', {}).get('returncode') == 0 and
            report.get('vrf_binding_control', {}).get('unknown_vrf', {}).get('returncode') not in (None, 0),
            'native backend/VRF isolation control failed')
    native, stats = report.get('native_fixture', {}), report.get('stats', {})
    require(native.get('raw_sockets', 0) >= 118 and native.get('netlinks', 0) > 0 and native.get('live') == 0 and
            stats.get('outstanding') == 0 and stats.get('worker_exit_code') == 0 and
            stats.get('control_eof') is True and stats.get('shutdown_timed_out') is False, 'native resources leaked')
