"""Bind unchanged original PEDIT tests to native rules, counters and input frames.

Receiver ingress flower matches the edited header. Source packet traces are
pre-edit AF_PACKET injections, not a post-edit wire capture or socket oracle.
"""
import hashlib
import ipaddress
import json
import re


def require(value, message):
    if not value:
        raise RuntimeError(message)


def links(state):
    return {row['ifname']: row for row in state['links']}


def normalized(rows):
    result = []
    for row in rows:
        args = row['arguments'][:]
        if row['tool'] == 'mausezahn':
            args[args.index('-b') + 1] = '<native-h2-MAC>'
        item = [row['tool'], args]
        # Original busywait may read the same native counter more than once.
        if result and item == result[-1] and row['tool'] == 'tc' and args[:4] == ['-j','-s','filter','show']:
            continue
        result.append(item)
    return hashlib.sha256(json.dumps(result, separators=(',', ':')).encode()).hexdigest()


def topology(state):
    devices = links(state)
    bridge = devices['br1']
    require(bridge['linkinfo']['info_kind'] == 'bridge' and 'UP' in bridge['flags'] and
            bridge['linkinfo']['info_data']['vlan_filtering'] == 1 and
            bridge['linkinfo']['info_data']['vlan_protocol'] == '802.1Q', 'native PEDIT VLAN bridge missing')
    tables = []
    for host, port, vrf, number in (('veth0','veth1','vveth0',1), ('veth3','veth2','vveth3',2)):
        require(devices[host]['linkinfo']['info_kind'] == devices[port]['linkinfo']['info_kind'] == 'veth' and
                devices[host]['link'] == port and devices[port]['link'] == host and
                devices[host].get('master') == vrf and devices[port].get('master') == 'br1' and
                devices[port]['linkinfo']['info_slave_kind'] == 'bridge' and
                devices[port]['linkinfo']['info_slave_data']['state'] == 'forwarding' and
                devices[vrf]['linkinfo']['info_kind'] == 'vrf' and
                all('UP' in devices[n]['flags'] for n in (host,port,vrf)), 'native PEDIT veth/bridge/VRF path changed')
        table = devices[vrf]['linkinfo']['info_data']['table']; tables.append(table)
        addresses = next(x['addr_info'] for x in state['addresses'] if x['ifname'] == host)
        for address, prefix in ((f'192.0.2.{number}',28), (f'2001:db8:1::{number}',64)):
            require(any(a.get('local') == address and a.get('prefixlen') == prefix for a in addresses),
                    'original PEDIT native host address changed')
        for family, destination in (('ipv4','192.0.2.0/28'), ('ipv6','2001:db8:1::/64')):
            require(any(r.get('dst') == destination and r.get('dev') == host and str(r.get('table')) == str(table)
                        for r in state[family + '_routes']), 'native PEDIT VRF route missing')
        for device in (host,port):
            if device == host:
                continue
            vlans = next(x['vlans'] for x in state['vlans'] if x['ifname'] == device)
            require(any(v['vlan'] == 1 and set(v.get('flags',[])) == {'PVID','Egress Untagged'} for v in vlans),
                    'native PEDIT bridge PVID admission missing')
    require(len(set(tables)) == 2, 'PEDIT hosts share a native VRF table')
    return devices


def flower(rows, family, field, edit):
    require(len(rows) == 2 and sum('options' in r for r in rows) == 1,
            'native PEDIT filter missing, duplicated or polluted')
    row = next(r for r in rows if 'options' in r); options = row['options']
    require(row['kind'] == 'flower' and row['pref'] == 1 and row['chain'] == 0 and
            options['handle'] == 101 and options.get('not_in_hw') is True,
            'native PEDIT flower identity/software execution changed')
    actions = options['actions']
    require(len(actions) == 1, 'native PEDIT action chain changed')
    action = actions[0]
    require(action['order'] == 1 and action['control_action'] == {'type':'pass'} and
            action['ref'] == action['bind'] == 1, 'native PEDIT action verdict/binding changed')
    if edit:
        require(row['protocol'] == 'all' and options['keys'] == {} and action['kind'] == 'pedit',
                'original native pedit action/classifier substituted')
        offset = (12 if field == 'src' else 16) if family == 4 else (8 if field == 'src' else 24)
        address = ipaddress.ip_address('198.51.100.1' if family == 4 else '2001:db8:2::1').packed
        expected = [dict(htype='ipv'+str(family),offset=offset+i,cmd='set',val=format(int.from_bytes(address[i:i+4],'big'),'x'),mask='0')
                    for i in range(0,len(address),4)]
        actual = [dict(k, val=format(int(k['val'],16),'x')) for k in action['keys']]
        require(action['nkeys'] == len(expected) and actual == expected, 'native PEDIT header offsets/masks/set values changed')
    else:
        address = '198.51.100.1' if family == 4 else '2001:db8:2::1'
        require(row['protocol'] == ('ip' if family == 4 else 'ipv6') and options.get('skip_hw') is True and
                options['keys'] == {'eth_type':'ipv'+str(family),field+'_ip':address} and action['kind'] == 'gact' and
                action['prob'] == {'random_type':'none','control_action':{'type':'pass'},'val':0},
                'native receiver did not match the edited PEDIT address')
    stats = action['stats']
    require(all(isinstance(stats[k],int) and stats[k] >= 0 for k in ('packets','bytes')) and
            all(stats[k] == 0 for k in ('drops','overlimits','requeues','backlog','qlen')),
            'native PEDIT action dropped, queued or fabricated traffic')
    return stats


def all_filters(state):
    require(set(state['filters_by_device']) == {'veth0','veth1','veth2','veth3'} and
            set(state['egress_filters']) == {'veth1','veth2'}, 'native PEDIT filter loci missing')
    return {(device,'ingress'):value for device,value in state['filters_by_device'].items()} | {
            (device,'egress'):value for device,value in state['egress_filters'].items()}


def filters(state, family, field, locus, active):
    values = all_filters(state); answer = {}
    for key, rows in values.items():
        if key in active:
            answer[key] = flower(rows,family,field,key == locus)
        else:
            require(rows == [], 'native PEDIT rule leaked onto another locus')
    return answer


def validate_evidence(report):
    original = report['original']
    parsed = [re.fullmatch(r'TEST: (.*?)\s+\[ OK \]', line) for line in original['stdout'].splitlines() if line.startswith('TEST:')]
    labels = ['ping','ping6'] + [f'dev {dev} {direction} pedit {proto} {field} set {address}'
             for proto,address in (('ip','198.51.100.1'),('ip6','2001:db8:2::1'))
             for field in ('src','dst') for dev,direction in (('veth1','ingress'),('veth2','egress'))]
    require(original['returncode'] == 0 and not original['stderr'] and len(parsed) == 10 and all(parsed) and
            [x[1] for x in parsed] == labels and 'SKIP' not in original['stdout'] and '[FAIL]' not in original['stdout'],
            'complete unchanged original PEDIT outcomes missing')
    rows = report['commands']
    require(normalized(rows) == COMMAND_SHA, 'original PEDIT command/timing/phase sequence changed')
    require([i for i,x in enumerate(rows) if x['returncode']] == [0,2] and
            all(not x['stderr'] for x in rows if not x['returncode']), 'original PEDIT setup/probe/cleanup verdict changed')
    timed = [x for x in rows if x['tool'] in ('tc','mausezahn')]
    require(all(x['finished_monotonic'] >= x['started_monotonic'] for x in timed) and
            all(b['started_monotonic'] >= a['finished_monotonic'] for a,b in zip(timed,timed[1:])),
            'native PEDIT command chronology changed')
    require(all(isinstance(x.get('pedit_before'),dict) and isinstance(x.get('pedit_after'),dict) for x in timed),
            'native PEDIT command observation missing')
    pings = [x for x in rows if x['arguments'][:2] == ['vrf','exec']]
    require(len(pings) == 2, 'both original PEDIT baseline ping families required')
    for row, tool, address in zip(pings,('ping','ping6'),('192.0.2.2','2001:db8:1::2')):
        require(row['arguments'] == ['vrf','exec','vveth0',tool,'-c','10','-i','0.1','-w','5',address] and
                row['returncode'] == 0 and '10 received' in row['stdout'] and row.get('native_clock_reads',0) > 0 and
                row['vrf']['linkinfo']['info_kind'] == 'vrf', 'native PEDIT baseline reachability/clock binding changed')
    traffic = [x for x in rows if x['tool'] == 'mausezahn']
    require(len(traffic) == 8 and len(report['packet_trace']) == 80, 'complete original PEDIT packet matrix missing')
    for phase, row in enumerate(traffic):
        family = 4 if phase < 4 else 6; field = 'src' if phase % 4 < 2 else 'dst'
        locus = ('veth1','ingress') if phase % 2 == 0 else ('veth2','egress'); receiver = ('veth3','ingress')
        i = rows.index(row); add_edit, add_receiver = rows[i-2:i]
        require(add_edit['tool'] == add_receiver['tool'] == 'tc', 'original PEDIT rule setup missing')
        devices = topology(row['pedit_before']); topology(row['pedit_after'])
        for state, active in ((add_edit['pedit_before'],()),(add_edit['pedit_after'],(locus,)),
                              (add_receiver['pedit_before'],(locus,)),(add_receiver['pedit_after'],(locus,receiver))):
            filters(state,family,field,locus,active)
        initial = filters(row['pedit_before'],family,field,locus,(locus,receiver))
        filters(row['pedit_after'],family,field,locus,(locus,receiver))
        # The preceding absent->installed filter snapshots bind a fresh rule.
        # Source-address edits can make real background IPv6 control frames
        # match before the probe; the decisive oracle is ten NEW matches.
        j = i+1
        queries = []
        while j < len(rows) and rows[j]['tool'] == 'tc' and rows[j]['arguments'][:4] == ['-j','-s','filter','show']:
            queries.append(rows[j]); j += 1
        require(len(queries) >= 2 and queries[-1]['arguments'][-2:] == list(locus) and
                all(q['arguments'][-2:] == list(receiver) for q in queries[:-1]), 'original PEDIT receiver/action queries reordered')
        for query in queries:
            is_edit = query is queries[-1]
            stats = flower(json.loads(query['stdout']),family,field,is_edit)
            actual = filters(query['pedit_after'],family,field,locus,(locus,receiver))[locus if is_edit else receiver]
            require(actual['packets'] >= stats['packets'] and actual['bytes'] >= stats['bytes'],
                    'native PEDIT original counter query exceeds actual observed counter')
        for query, edit in ((queries[-2],False),(queries[-1],True)):
            stats = flower(json.loads(query['stdout']),family,field,edit)
            size = (134 if family == 4 else 154) - (0 if edit and locus[1] == 'egress' else 14)
            key = locus if edit else receiver
            require(stats['packets']-initial[key]['packets'] >= 10 and stats['bytes']-initial[key]['bytes'] >= 10*size,
                    'original native PEDIT edited-address reception/action count below ten')
        decisive = queries[-1]['pedit_after']; last = topology(decisive)
        for device,direction in (('veth0','tx'),('veth1','rx'),('veth2','tx'),('veth3','rx')):
            before = devices[device]['stats64'][direction]; after = last[device]['stats64'][direction]
            require(after['packets']-before['packets'] >= 10 and after['bytes']-before['bytes'] >= 10*134,
                    'original PEDIT traffic did not traverse the real bridge path')
        delete_receiver, delete_edit = rows[j:j+2]
        for command, before, after in ((delete_receiver,(locus,receiver),(locus,)),(delete_edit,(locus,),())):
            filters(command['pedit_before'],family,field,locus,before)
            filters(command['pedit_after'],family,field,locus,after)
        source = devices['veth0']; dest = devices['veth3']
        args = row['arguments']
        expected_args = (['-6'] if family == 6 else []) + ['-A','192.0.2.1' if family == 4 else '2001:db8:1::1',
                         '-B','192.0.2.2' if family == 4 else '2001:db8:1::2','veth0','-c','10','-d','20msec','-p','100',
                         '-a','own','-b',dest['address'],'-q','-t','ip']
        require(args == expected_args and row['finished_monotonic']-row['started_monotonic'] >= .18,
                'original PEDIT packet arguments/native destination MAC/pacing changed')
        for packet in report['packet_trace'][phase*10:(phase+1)*10]:
            data = bytes.fromhex(packet['frame_hex']); size = 134 if family == 4 else 154
            require(packet['family'] == 17 and packet['ifindex'] == source['ifindex'] and
                    packet['length'] == packet['result'] == len(data) == size and
                    data[:6] == bytes.fromhex(dest['address'].replace(':','')) and
                    data[6:12] == bytes.fromhex(source['address'].replace(':','')) and
                    data[12:14] == (b'\x08\x00' if family == 4 else b'\x86\xdd'), 'native PEDIT input frame/interface/MAC changed')
            if family == 4:
                header = data[14:34]
                require(header[0] == 0x45 and int.from_bytes(header[2:4], 'big') == 120 and
                        sum(int.from_bytes(header[k:k+2],'big') for k in range(0,20,2)) % 65535 == 0 and
                        header[12:] == ipaddress.ip_address('192.0.2.1').packed + ipaddress.ip_address('192.0.2.2').packed,
                        'original PEDIT IPv4 input/header checksum changed')
            else:
                require(data[14] >> 4 == 6 and int.from_bytes(data[18:20], 'big') == 100 and
                        data[22:54] == ipaddress.ip_address('2001:db8:1::1').packed + ipaddress.ip_address('2001:db8:1::2').packed,
                        'original PEDIT IPv6 input/header changed')
            # The original specifies payload length, not Mausezahn's fill bytes,
            # IPv4 ID/TTL or IPv6 traffic class/flow label/hop limit defaults.
    validate_boundaries(report,rows)


def validate_boundaries(report, rows):
    require(report['source_hashes'] == SOURCE_HASHES and report['original_tc_hit_timeout_ms'] == 1000,
            'pinned original PEDIT/helper source or busywait changed')
    tools = report['iproute2']
    require(tools['version'] == '6.12.0' and tools['archive_sha256'] ==
            'bbd141ef7b5d0127cc2152843ba61f274dc32814fa3e0f13e7d07a080bef53d9' and
            tools['source_hashes']['tc/tc.c'] == 'e9b2e36053ee6e20f79d44a0cab3e1661300ecf9e9783c5fcd03357aa696a101' and
            report['tc_tool']['sha256'] == tools['binaries']['tc'], 'pinned original PEDIT tc provenance missing')
    cleanup = report['cleanup_state']; devices = links(cleanup)
    require(not any(name in devices for name in ('br1','vveth0','vveth3')), 'native PEDIT bridge/VRF leaked')
    for name in ('veth0','veth1','veth2','veth3'):
        require(name in devices and 'UP' not in devices[name]['flags'] and not devices[name].get('master') and
                not next(x['addr_info'] for x in cleanup['addresses'] if x['ifname'] == name),
                'native PEDIT port/master/address leaked')
    require(not any(r.get('dev') in ('br1','veth0','veth1','veth2','veth3','vveth0','vveth3') or str(r.get('table')) in ('1','2')
                    for family in ('ipv4','ipv6') for r in cleanup[family+'_routes']) and
            all(cleanup[family].strip() == '0' for family in ('ipv4','ipv6')), 'native PEDIT routes/forwarding leaked')
    require(all(not value for value in all_filters(next(x for x in reversed(rows) if x['tool'] == 'tc')['pedit_after']).values()),
            'native PEDIT filter cleanup incomplete')
    require(report['missing_backend_control']['returncode'] != 0 and
            report['vrf_binding_control']['baseline']['returncode'] == 0 and
            '1 received' in report['vrf_binding_control']['baseline']['stdout'] and
            report['vrf_binding_control']['unknown_vrf']['returncode'] != 0, 'native PEDIT backend/VRF controls ineffective')
    native = report['native_fixture']; stats = report['stats']
    require(native['netlinks'] > 0 and native['raw_sockets'] > 0 and native['bridge_packet_sends'] == 80 and
            native['bridge_packet_bytes'] == 11520 and native['bridge_packet_trace_errors'] == 0 and native['live'] == 0 and
            stats['outstanding'] == stats['worker_exit_code'] == 0 and stats['control_eof'] is True and
            stats['shutdown_timed_out'] is False, 'native PEDIT packets/resources/shutdown incomplete')


COMMAND_SHA = '9074ff39da58d2737e668a067e55bcd19805bb8502e71ee5c7b111f948434c1b'
SOURCE_HASHES = {'forwarding/pedit_ip.sh': 'd2f6de9a45e9b878993069f3ebe4dbac85036bb1ee3873618773ef586eb8a183', 'forwarding/lib.sh': '8fb499582bb13c830e7fe9cbcb0baffc0bedf552d12c3c9241b65ecf14414537', 'lib.sh': '875a357f3264e3126af195e97a36217ba6e44c0812afc1b6b8a414f1984dcccd', 'forwarding/Makefile': '2c66e188a0a956c79dfbedd3a3449fd455e94e0a2a5b07550aaed0b79f745d96', 'forwarding/tc_common.sh': '4aed88ec9b90364edf2fbd2611237cdc78d57a2e931280124bd750b3b26e0369'}
