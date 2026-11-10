"""Bind original skbedit priorities to real Linux PRIO band observations.

Source AF_PACKET records establish the input, while the original PRIO child
qdisc queries establish classification. Neither is a socket-delivery claim.
"""
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import re

spec = importlib.util.spec_from_file_location('pedit', Path(__file__).with_name('linux-pedit-ip-contract.py'))
pedit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pedit)
require = pedit.require


def normalized(rows):
    result = []
    for row in rows:
        args = row['arguments'][:]
        if row['tool'] == 'mausezahn':
            args[args.index('-b') + 1] = '<native-h2-MAC>'
        item = [row['tool'], args]
        if (result and item == result[-1] and row['tool'] == 'tc' and
                args[:4] in (['-j', '-s', 'filter', 'show'], ['-j', '-s', 'qdisc', 'show'])):
            continue
        result.append(item)
    return hashlib.sha256(json.dumps(result, separators=(',', ':')).encode()).hexdigest()


def topology(state):
    devices = pedit.links(state)
    bridge = devices['br1']
    require(bridge['linkinfo']['info_kind'] == 'bridge' and 'UP' in bridge['flags'] and
            bridge['linkinfo']['info_data']['vlan_filtering'] == 1, 'native priority bridge missing')
    tables = []
    for host, port, vrf, number in (('veth0', 'veth1', 'vveth0', 1), ('veth3', 'veth2', 'vveth3', 2)):
        require(devices[host]['linkinfo']['info_kind'] == devices[port]['linkinfo']['info_kind'] == 'veth' and
                devices[host]['link'] == port and devices[port]['link'] == host and
                devices[host].get('master') == vrf and devices[port].get('master') == 'br1' and
                devices[port]['linkinfo']['info_slave_kind'] == 'bridge' and
                devices[port]['linkinfo']['info_slave_data']['state'] == 'forwarding' and
                devices[vrf]['linkinfo']['info_kind'] == 'vrf' and
                all('UP' in devices[n]['flags'] for n in (host, port, vrf)), 'native priority veth/VRF path changed')
        table = devices[vrf]['linkinfo']['info_data']['table']
        tables.append(table)
        require(any(a.get('local') == f'192.0.2.{number}' and a.get('prefixlen') == 28
                    for a in next(x['addr_info'] for x in state['addresses'] if x['ifname'] == host)) and
                any(r.get('dst') == '192.0.2.0/28' and r.get('dev') == host and str(r.get('table')) == str(table)
                    for r in state['ipv4_routes']), 'native priority address/VRF route missing')
        require(any(v['vlan'] == 1 and set(v.get('flags', [])) == {'PVID', 'Egress Untagged'}
                    for v in next(x['vlans'] for x in state['vlans'] if x['ifname'] == port)),
                'native priority bridge PVID missing')
    require(len(set(tables)) == 2, 'native priority hosts share a VRF')
    return devices


def counters(row):
    require(all(type(row[k]) is int and row[k] >= 0 for k in ('packets', 'bytes')),
            'invalid native priority counters')
    return row['packets'], row['bytes']


def advances(before, middle, after):
    require(all(a <= b <= c for a, b, c in zip(before, middle, after)),
            'original counter query contradicts causal native observations')


def action(rows, priority):
    detail = [x for x in rows if 'options' in x]
    require(len(rows) == 2 and len(detail) == 1, 'priority classifier missing/duplicated')
    row = detail[0]
    options = row['options']
    require(row['kind'] == 'flower' and row['protocol'] == 'all' and row['pref'] == 1 and row['chain'] == 0 and
            options['handle'] == 101 and options['keys'] == {} and options.get('not_in_hw') is True and
            len(options['actions']) == 1, 'native priority classifier identity/software execution changed')
    a = options['actions'][0]
    require(a['kind'] == 'skbedit' and a['order'] == 1 and a['priority'] == ('none' if priority == 0 else f':{priority:x}') and
            a['control_action'] == {'type': 'pipe'} and a['ref'] == a['bind'] == 1,
            'native priority action/value/verdict changed')
    require(all(a['stats'][k] == 0 for k in ('drops', 'overlimits', 'requeues', 'backlog', 'qlen')),
            'native priority action dropped/retained traffic')
    return counters(a['stats'])


def filters(state, locus=None, priority=None):
    values = pedit.all_filters(state)
    for key, rows in values.items():
        if key == locus:
            action(rows, priority)
        else:
            require(rows == [], 'priority classifier leaked onto another locus')
    return action(values[locus], priority) if locus else None


def bands(rows):
    roots = [x for x in rows if x.get('handle') == '10:']
    require(len(roots) == 1 and roots[0]['kind'] == 'prio' and roots[0].get('root') is True and
            roots[0]['options']['bands'] == 8 and roots[0]['options']['priomap'] == list(reversed(range(8))) + [1] * 8,
            'native eight-band PRIO map changed')
    children = {x['parent']: x for x in rows if x.get('parent', '').startswith('10:')}
    require(len([x for x in rows if x.get('parent', '').startswith('10:')]) == len(children) == 8 and set(children) == {f'10:{i}' for i in range(1, 9)},
            'native PRIO child band missing')
    for row in children.values():
        require(row['kind'] == 'pfifo' and all(type(row[k]) is int and row[k] >= 0 for k in ('drops', 'overlimits', 'requeues', 'backlog', 'qlen')),
                'invalid native priority child queue counters')
    return {key: counters(row) for key, row in children.items()}


def phase_observations(records, locus, priority):
    """Every original query lies between the surrounding native snapshots."""
    progress = None
    action_progress = (0, 0)
    for row in records:
        before = bands(row['pedit_before']['qdiscs'])
        after = bands(row['pedit_after']['qdiscs'])
        for key in before:
            advances(before[key] if progress is None else progress[key], before[key], after[key])
        initial = filters(row['pedit_before'], locus, priority)
        final = filters(row['pedit_after'], locus, priority)
        advances(action_progress, initial, final)
        if row['tool'] == 'tc' and row['arguments'][:4] == ['-j', '-s', 'filter', 'show']:
            advances(initial, action(json.loads(row['stdout']), priority), final)
        if row['tool'] == 'tc' and row['arguments'][:4] == ['-j', '-s', 'qdisc', 'show']:
            query = bands(json.loads(row['stdout']))
            for key in before:
                advances(before[key], query[key], after[key])
        progress, action_progress = after, final


def qdisc_lifecycle(rows):
    active = False
    progress = None
    creates = deletes = 0
    for row in rows:
        root = row['arguments'][:5] in (['qdisc', 'add', 'dev', 'veth2', 'root'],
                                       ['qdisc', 'del', 'dev', 'veth2', 'root'])
        for stage in ('before', 'after'):
            if stage == 'after' and root:
                active = row['arguments'][1] == 'add'
                creates += int(active)
                deletes += int(not active)
            table = row['pedit_' + stage]['qdiscs']
            if active:
                actual = bands(table)
                if progress is not None:
                    for key in actual:
                        require(all(b >= a for a, b in zip(progress[key], actual[key])),
                                'native PRIO band counter regressed without replacing the qdisc')
                progress = actual
            else:
                require(not any(x.get('handle') == '10:' or x.get('parent', '').startswith('10:') for x in table),
                        'native PRIO qdisc lifetime contradicts the original command')
    require(creates == deletes == 1 and not active, 'native PRIO root lifecycle incomplete')


def validate_evidence(report):
    original = report['original']
    labels = ['ping'] + [f'dev {dev} {direction} skbedit priority {prio} -> classid 10:{8-prio}'
                        for dev, direction in (('veth1', 'ingress'), ('veth2', 'egress')) for prio in range(8)]
    parsed = [re.fullmatch(r'TEST: (.*?)\s+\[ OK \]', x)
              for x in original['stdout'].splitlines() if x.startswith('TEST:')]
    require(original['returncode'] == 0 and not original['stderr'] and len(parsed) == 17 and all(parsed) and
            [x[1] for x in parsed] == labels and 'SKIP' not in original['stdout'] and '[FAIL]' not in original['stdout'],
            'complete original priority outcomes missing')
    rows = report['commands']
    require([i for i, row in enumerate(rows) if row['returncode']] == [0, 2] and
            all(rows[i]['returncode'] == 1 for i in (0, 2)), 'original priority setup/operation verdict changed')
    require(all(not x['stderr'] for x in rows if x['returncode'] == 0), 'original priority command warning')
    require(normalized(rows) == COMMAND_SHA and report['source_hashes'] == SOURCE_HASHES,
            'unchanged original priority command/source sequence missing')
    timed = [x for x in rows if x['tool'] in ('tc', 'mausezahn')]
    require(all(isinstance(x.get(k), dict) for x in timed for k in ('pedit_before', 'pedit_after')) and
            all(x['finished_monotonic'] >= x['started_monotonic'] for x in timed) and
            all(b['started_monotonic'] >= a['finished_monotonic'] for a, b in zip(timed, timed[1:])),
            'priority observations/chronology missing')
    qdisc_lifecycle(timed)
    traffic = [x for x in rows if x['tool'] == 'mausezahn']
    require(len(traffic) == 16 and len(report['packet_trace']) == 160, 'original priority traffic matrix incomplete')
    pings = [x for x in rows if x['arguments'][:2] == ['vrf', 'exec']]
    require(len(pings) == 1 and pings[0]['arguments'] ==
            ['vrf', 'exec', 'vveth0', 'ping', '-c', '10', '-i', '0.1', '-w', '5', '192.0.2.2'] and
            pings[0]['returncode'] == 0 and '10 received' in pings[0]['stdout'] and
            pings[0].get('native_clock_reads', 0) > 0, 'original native priority baseline ping/clock binding missing')
    for phase, sender in enumerate(traffic):
        priority = phase % 8
        locus = ('veth1', 'ingress') if phase < 8 else ('veth2', 'egress')
        target = f'10:{8-priority}'
        i = rows.index(sender)
        add, q0, a0 = rows[i-3:i]
        require(add['tool'] == 'tc' and add['arguments'] == ['filter', 'add', 'dev', *locus, 'handle', '101', 'pref', '1',
                'flower', 'action', 'skbedit', 'priority', str(priority)], 'original priority action installation changed')
        filters(add['pedit_before'])
        filters(add['pedit_after'], locus, priority)
        require(q0['arguments'] == ['-j', '-s', 'qdisc', 'show', 'dev', 'veth2', 'invisible'] and
                a0['arguments'] == ['-j', '-s', 'filter', 'show', 'dev', *locus], 'original priority baseline queries changed')
        for q in (q0, a0):
            before = bands(q['pedit_before']['qdiscs'])
            after = bands(q['pedit_after']['qdiscs'])
            if q is q0:
                actual = bands(json.loads(q['stdout']))
                for key in before:
                    advances(before[key], actual[key], after[key])
            else:
                advances(filters(q['pedit_before'], locus, priority), action(json.loads(q['stdout']), priority),
                         filters(q['pedit_after'], locus, priority))
        before_action = action(json.loads(a0['stdout']), priority)
        before_band = bands(json.loads(q0['stdout']))[target]
        devices = topology(sender['pedit_before'])
        topology(sender['pedit_after'])
        require(sender['arguments'] == ['veth0', '-t', 'udp', 'sp=54321,dp=12345', '-c', '10', '-d', '20msec',
                '-p', '100', '-a', 'own', '-b', devices['veth3']['address'], '-A', '192.0.2.1', '-B', '192.0.2.2', '-q'] and
                sender['finished_monotonic'] - sender['started_monotonic'] >= .18,
                'original priority sender arguments/pacing changed')
        j = i + 1
        queries = []
        while j < len(rows) and rows[j]['tool'] == 'tc' and rows[j]['arguments'][:2] == ['-j', '-s']:
            queries.append(rows[j])
            j += 1
        require(len(queries) >= 2 and all(q['arguments'] == q0['arguments'] for q in queries[:-1]) and
                queries[-1]['arguments'] == a0['arguments'], 'original priority decisive queries missing')
        phase_observations(rows[i-2:j], locus, priority)
        previous = bands(sender['pedit_before']['qdiscs'])
        for query in queries:
            before = bands(query['pedit_before']['qdiscs'])
            after = bands(query['pedit_after']['qdiscs'])
            for key in previous:
                advances(previous[key], before[key], after[key])
            if query is not queries[-1]:
                actual = bands(json.loads(query['stdout']))
                for key in before:
                    advances(before[key], actual[key], after[key])
            else:
                advances(filters(query['pedit_before'], locus, priority), action(json.loads(query['stdout']), priority),
                         filters(query['pedit_after'], locus, priority))
            previous = after
        final_band = bands(json.loads(queries[-2]['stdout']))[target]
        final_action = action(json.loads(queries[-1]['stdout']), priority)
        require(final_band[0] - before_band[0] >= 10 and final_band[1] - before_band[1] >= 1420 and
                final_action[0] - before_action[0] >= 10 and
                final_action[1] - before_action[1] >= 10 * (128 if phase < 8 else 142),
                'ten new original priority action/band hits missing')
        final = topology(queries[-1]['pedit_after'])
        for device, direction in (('veth0', 'tx'), ('veth1', 'rx'), ('veth2', 'tx'), ('veth3', 'rx')):
            a = devices[device]['stats64'][direction]
            b = final[device]['stats64'][direction]
            require(b['packets'] - a['packets'] >= 10 and b['bytes'] - a['bytes'] >= 1420,
                    'original priority probes lack native bridge traversal')
        delete = rows[j]
        require(delete['arguments'] == ['filter', 'del', 'dev', *locus, 'pref', '1'], 'original priority rule deletion changed')
        filters(delete['pedit_before'], locus, priority)
        filters(delete['pedit_after'])
        require(all(b >= a for a, b in zip(final_action, filters(delete['pedit_before'], locus, priority))),
                'native priority action counter regressed before deletion')
        for packet in report['packet_trace'][phase*10:(phase+1)*10]:
            frame = bytes.fromhex(packet['frame_hex'])
            h = frame[14:34]
            require(packet['family'] == 17 and packet['ifindex'] == devices['veth0']['ifindex'] and
                    packet['result'] == packet['length'] == len(frame) == 142 and
                    frame[:6] == bytes.fromhex(devices['veth3']['address'].replace(':', '')) and
                    frame[6:12] == bytes.fromhex(devices['veth0']['address'].replace(':', '')) and
                    frame[12:14] == b'\x08\x00' and h[0] == 0x45 and h[9] == 17 and
                    int.from_bytes(h[2:4], 'big') == 128 and int.from_bytes(h[6:8], 'big') & 0x3fff == 0 and
                    sum(int.from_bytes(h[k:k+2], 'big') for k in range(0, 20, 2)) % 65535 == 0 and
                    h[12:16] == ipaddress.ip_address('192.0.2.1').packed and
                    h[16:20] == ipaddress.ip_address('192.0.2.2').packed and
                    frame[34:40] == bytes.fromhex('d4313039006c'),
                    'original native priority frame/interface/IP/UDP input changed')
    remove = [x for x in rows if x['tool'] == 'tc' and x['arguments'] == ['qdisc', 'del', 'dev', 'veth2', 'root']]
    require(len(remove) == 1, 'original priority root qdisc removal missing')
    bands(remove[0]['pedit_before']['qdiscs'])
    require(not any(x.get('handle') == '10:' or x.get('parent', '').startswith('10:')
                    for x in remove[0]['pedit_after']['qdiscs']), 'native priority root/child qdisc leaked')
    # Reuse the established four-port cleanup and native backend/resource checks.
    pedit.validate_boundaries(report, rows, source_hashes=SOURCE_HASHES, expected_sends=160, expected_bytes=22720,
                              timeout_field='original_priority_hit_timeout_ms', hit_timeout_ms=2000)


COMMAND_SHA = 'fb56a41a65d8e371e74ae01b0865dd73484a71eba796298091df127cd4a3e1fb'
SOURCE_HASHES = {'forwarding/skbedit_priority.sh': 'ffc87ca88c1a11827fbd4c5becc79210cfb2ece265adc4b87bb825a993effc4b', 'forwarding/lib.sh': '8fb499582bb13c830e7fe9cbcb0baffc0bedf552d12c3c9241b65ecf14414537', 'lib.sh': '875a357f3264e3126af195e97a36217ba6e44c0812afc1b6b8a414f1984dcccd', 'forwarding/Makefile': '2c66e188a0a956c79dfbedd3a3449fd455e94e0a2a5b07550aaed0b79f745d96'}
