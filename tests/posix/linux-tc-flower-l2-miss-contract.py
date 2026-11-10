"""Original Linux bridge L2 miss metadata, native classifiers and forwarding.

Source AF_PACKET traces identify the injected frames. Native egress counters
and peer RX windows prove bridging, without claiming socket or wire delivery.
"""
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import re

spec = importlib.util.spec_from_file_location('pedit_ip', Path(__file__).with_name('linux-pedit-ip-contract.py'))
ip = importlib.util.module_from_spec(spec); spec.loader.exec_module(ip)
require = ip.require


def normalized(rows):
    result = []
    for row in rows:
        item = [row['tool'], row['arguments']]
        if result and item == result[-1] and row['tool'] == 'tc' and row['arguments'][:4] == ['-j','-s','filter','show']:
            continue
        result.append(item)
    return hashlib.sha256(json.dumps(result, separators=(',', ':')).encode()).hexdigest()


def flower(rows, keys, counts, size, protocol):
    require(len(rows) == len(counts) + 1 and sum('options' in r for r in rows) == len(counts),
            'native L2 miss rules missing, duplicated or polluted')
    actual = [r for r in rows if 'options' in r]
    require([r['options']['handle'] for r in actual] == [101 + i for i in range(len(counts))],
            'original L2 miss classifier generations changed')
    for index, (row, count) in enumerate(zip(actual, counts)):
        options = row['options']; actions = options['actions']
        require(row['protocol'] == protocol and row['pref'] == 1 and row['chain'] == 0 and row['kind'] == 'flower' and
                options.get('not_in_hw') is True and options['keys'] == dict(keys, l2_miss=1-index) and
                options.get('indev') == (None if protocol == 'all' else 'veth1') and len(actions) == 1,
                'native L2 miss/IP/MAC/indev/software match changed')
        a = actions[0]
        require(a['order'] == 1 and a['kind'] == 'gact' and a['control_action'] == {'type':'pass'} and
                a['ref'] == a['bind'] == 1 and a['prob'] == {'random_type':'none','control_action':{'type':'pass'},'val':0},
                'native L2 miss pass action/binding changed')
        stats = a['stats']
        require(stats['packets'] == count and stats['bytes'] == count*size and
                all(stats[k] == 0 for k in ('drops','overlimits','requeues','backlog','qlen')),
                'native exact L2 miss packet/byte/verdict counters changed')


def filters(state, keys, counts, size, protocol):
    for locus, rows in ip.all_filters(state).items():
        if locus == ('veth2','egress') and counts:
            flower(rows, keys, counts, size, protocol)
        else:
            require(rows == [], 'L2 miss classifier leaked onto another native locus')


def target_entry(state, group, present):
    if group == 0:
        entries = [x for x in state['fdb'] if x.get('mac') == '00:01:02:03:04:05']
        require(bool(entries) == present and all(x['ifname'] == 'veth2' and x.get('master') == 'br1' and
                x['state'] == 'static' and x.get('vlan') in (None,1) for x in entries),
                'native unknown/known unicast FDB binding changed')
    elif group in (1,2):
        address = '239.1.1.1' if group == 1 else 'ff0e::1'
        entries = [x for r in state['mdb'] for x in r['mdb'] if x.get('grp') == address]
        require(len(entries) == int(present) and all(x['dev'] == 'br1' and x['port'] == 'veth2' and
                x['state'] == 'permanent' and x['protocol'] == 'static' and not x.get('flags') for x in entries),
                'native unregistered/registered multicast MDB binding changed')


def validate_evidence(report):
    labels = ['L2 miss - Unicast', 'L2 miss - Multicast (IPv4)', 'L2 miss - Multicast (IPv6)',
              'L2 miss - Link-local multicast (IPv4)', 'L2 miss - Link-local multicast (IPv6)', 'L2 miss - Broadcast']
    original = report['original']; parsed = [re.fullmatch(r'TEST: (.*?)\s+\[ OK \]', x)
                                            for x in original['stdout'].splitlines() if x.startswith('TEST:')]
    require(original['returncode'] == 0 and not original['stderr'] and len(parsed) == 6 and all(parsed) and
            [x[1] for x in parsed] == labels and 'SKIP' not in original['stdout'] and '[FAIL]' not in original['stdout'],
            'complete unchanged original L2 miss outcomes missing')
    rows = report['commands']; require(normalized(rows) == COMMAND_SHA, 'original L2 miss commands/phases changed')
    require([i for i,x in enumerate(rows) if x['returncode']] == [0,2] and
            all(not x['stderr'] for x in rows if not x['returncode']), 'native L2 miss setup/probe/cleanup failed')
    timed = [x for x in rows if x['tool'] in ('tc','bridge','mausezahn')]
    require(all(isinstance(x.get('l2_before'),dict) and isinstance(x.get('l2_after'),dict) and
                x['finished_monotonic'] >= x['started_monotonic'] for x in timed) and
            all(b['started_monotonic'] >= a['finished_monotonic'] for a,b in zip(timed,timed[1:])),
            'native L2 miss observations/chronology missing')
    traffic = [x for x in rows if x['tool'] == 'mausezahn']; frames = report['packet_trace']
    require(len(traffic) == len(frames) == 12, 'complete original L2 miss probe matrix missing')
    phase = 0
    groups = ((4,'00:01:02:03:04:05','192.0.2.2',3), (4,'01:00:5e:01:01:01','239.1.1.1',3),
              (6,'33:33:00:00:00:01','ff0e::1',3), (4,'01:00:5e:00:00:01','224.0.0.1',1),
              (6,'33:33:00:00:00:01','ff02::1',1), (0,'ff:ff:ff:ff:ff:ff',None,1))
    for group,(family,dmac,dip,number) in enumerate(groups):
        sip = '192.0.2.1' if family == 4 else '2001:db8:1::1'
        size = 134 if family == 4 else 154 if family == 6 else 100
        protocol = 'ip' if family == 4 else 'ipv6' if family == 6 else 'all'
        keys = dict(eth_type='ipv'+str(family),src_ip=sip,dst_ip=dip) if family else dict(dst_mac=dmac,src_mac='00:01:02:03:04:05')
        if group in (0,3,4): keys['dst_mac'] = dmac
        senders = traffic[phase:phase+number]; first = rows.index(senders[0]); installs = rows[first-(1 if group in (3,4) else 2):first]
        filters(installs[0]['l2_before'], keys, (), size, protocol)
        filters(installs[0]['l2_after'], keys, (0,), size, protocol)
        if len(installs) == 2:
            filters(installs[1]['l2_before'], keys, (0,), size, protocol)
            filters(installs[1]['l2_after'], keys, (0,0), size, protocol)
        for local,sender in enumerate(senders):
            before = ((0,0),(1,0),(1,1))[local] if number == 3 else (0,) if group in (3,4) else (0,0)
            after = ((1,0),(1,1),(2,1))[local] if number == 3 else (1,) if group in (3,4) else (0,1)
            filters(sender['l2_before'],keys,before,size,protocol)
            target_entry(sender['l2_before'],group,local == 1)
            target_entry(sender['l2_after'],group,local == 1)
            devices = ip.topology(sender['l2_before'],vlan_filtering=0)
            ip.topology(sender['l2_after'],vlan_filtering=0)
            if group in (1,2):
                bridge = devices['br1']['linkinfo']['info_data']; port = devices['veth2']['linkinfo']['info_slave_data']
                require(bridge['mcast_querier'] == 1 and bridge['mcast_query_response_intvl'] == 100 and port['multicast_router'] == 2,
                        'original native querier/router multicast forwarding configuration changed')
            args = ([] if group in (0,5) else ['-4' if family == 4 else '-6']) + ['veth0','-a','00:01:02:03:04:05' if not family else 'own','-b',dmac]
            if family: args += ['-t','ip','-A',sip,'-B',dip]
            args += ['-c','1','-p','100','-q']
            require(sender['arguments'] == args, 'original L2 miss input command changed')
            packet = frames[phase+local]; data = bytes.fromhex(packet['frame_hex']); source = devices['veth0']
            require(packet['family'] == 17 and packet['ifindex'] == source['ifindex'] and
                    packet['length'] == packet['result'] == len(data) == size and
                    data[:6] == bytes.fromhex(dmac.replace(':','')) and
                    data[6:12] == bytes.fromhex(('00:01:02:03:04:05' if not family else source['address']).replace(':','')),
                    'native original L2 miss input frame/interface/MAC/length changed')
            if family == 4:
                h = data[14:34]
                require(data[12:14] == b'\x08\x00' and h[0] == 0x45 and int.from_bytes(h[2:4],'big') == 120 and
                        sum(int.from_bytes(h[k:k+2],'big') for k in range(0,20,2))%65535 == 0 and
                        h[12:] == ipaddress.ip_address(sip).packed+ipaddress.ip_address(dip).packed,
                        'native L2 miss original IPv4 input/header/checksum changed')
            elif family == 6:
                require(data[12:14] == b'\x86\xdd' and data[14]>>4 == 6 and int.from_bytes(data[18:20],'big') == 100 and
                        data[22:54] == ipaddress.ip_address(sip).packed+ipaddress.ip_address(dip).packed,
                        'native L2 miss original IPv6 input/header changed')
            end = rows.index(sender)+1; queries = []
            while end < len(rows) and rows[end]['tool'] == 'tc' and rows[end]['arguments'][:4] == ['-j','-s','filter','show']:
                queries.append(rows[end]);end += 1
            require(len(queries) >= len(after) and all(x['arguments'][-2:] == ['veth2','egress'] for x in queries),
                    'original L2 miss independent counter query windows missing')
            flower(json.loads(queries[-1]['stdout']),keys,after,size,protocol)
            filters(queries[-1]['l2_after'],keys,after,size,protocol)
            final = ip.topology(queries[-1]['l2_after'],vlan_filtering=0)
            for name,direction in (('veth0','tx'),('veth1','rx'),('veth2','tx'),('veth3','rx')):
                a=devices[name]['stats64'][direction]; b=final[name]['stats64'][direction]
                require(b['packets']-a['packets'] >= 1 and b['bytes']-a['bytes'] >= size,
                        'native L2 miss probe did not traverse real bridge/peer')
        # Require actual classifier removals, including intermediate generation.
        remaining = (2,1) if number == 3 else (1,) if group in (3,4) else (0,1)
        for remove in rows[end:end+len(remaining)]:
            filters(remove['l2_before'],keys,remaining,size,protocol)
            remaining = remaining[:-1]
            filters(remove['l2_after'],keys,remaining,size,protocol)
        phase += number
    ip.validate_boundaries(report,rows,source_hashes=SOURCE_HASHES,expected_sends=12,expected_bytes=1654,observation_key='l2_after')


COMMAND_SHA = '2d8c42b84e4ff48c270edf559e9474c93629918b0c80a9444c22d6407b0f725f'
SOURCE_HASHES = {'forwarding/tc_flower_l2_miss.sh': 'c5b7b64a21df39e1476857426e55ad8210cbbf4c0e2314603149939018867368', 'forwarding/lib.sh': '8fb499582bb13c830e7fe9cbcb0baffc0bedf552d12c3c9241b65ecf14414537', 'lib.sh': '875a357f3264e3126af195e97a36217ba6e44c0812afc1b6b8a414f1984dcccd', 'forwarding/Makefile': '2c66e188a0a956c79dfbedd3a3449fd455e94e0a2a5b07550aaed0b79f745d96', 'forwarding/tc_common.sh': '4aed88ec9b90364edf2fbd2611237cdc78d57a2e931280124bd750b3b26e0369'}
