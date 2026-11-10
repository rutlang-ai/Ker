"""Independent evidence for the complete pinned bridge_mdb.sh entry.

Only original assertions are expressed here. All MDB configuration and packet
forwarding must be performed by the unmodified native Linux implementation.
"""
from collections import Counter
import hashlib
import ipaddress
import json
import re

COMMAND_SHA = 'b00fbd100d6d70c4359671bb073441aef23e06e4d294c1729836cfde7fc9c424'
LABELS = ['Common host entries configuration tests (IPv4)', 'Common host entries configuration tests (IPv6)', 'Common host entries configuration tests (L2)', 'Common port group entries configuration tests (IPv4 (*, G))', 'Common port group entries configuration tests (IPv6 (*, G))', 'IPv4 (*, G) port group entries configuration tests', 'IPv6 (*, G) port group entries configuration tests', 'Common port group entries configuration tests (IPv4 (S, G))', 'Common port group entries configuration tests (IPv6 (S, G))', 'IPv4 (S, G) port group entries configuration tests', 'IPv6 (S, G) port group entries configuration tests', 'Common port group entries configuration tests (L2 (*, G))', 'L2 (*, G) port group entries configuration tests', 'IPv4 large scale dump tests', 'IPv6 large scale dump tests', 'L2 large scale dump tests', 'Flush tests', 'IPv4 host entries forwarding tests', 'IPv6 host entries forwarding tests', 'L2 host entries forwarding tests', 'IPv4 port group "exclude" entries forwarding tests', 'IPv6 port group "exclude" entries forwarding tests', 'IPv4 port group "include" entries forwarding tests', 'IPv6 port group "include" entries forwarding tests', 'L2 port entries forwarding tests', 'IGMPv3 MODE_IS_INCLUDE tests', 'MLDv2 MODE_IS_INCLUDE tests']
NEGATIVE_POSITIONS = [0, 2, 8, 69, 70, 71, 72, 73, 74, 79, 80, 81, 82, 83, 84, 89, 90, 91, 92, 93, 94, 99, 109, 110, 114, 118, 121, 123, 128, 138, 139, 143, 147, 150, 152, 160, 161, 218, 231, 232, 233, 234, 236, 239, 244, 252, 253, 310, 323, 324, 325, 326, 328, 331, 336, 341, 351, 352, 356, 360, 363, 365, 370, 380, 381, 385, 389, 392, 394, 406, 407, 408, 410, 438, 439, 440, 442, 463, 473, 474, 478, 482, 485, 487, 488, 489, 490, 491, 922, 941, 947, 953, 963, 964, 965, 966, 1123, 1131]


def require(value, message):
    if not value:
        raise RuntimeError(message)


def address(value):
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return value.lower()


def entries(objects):
    return [row for group in objects for row in group.get('mdb', [])]


def scalar(args, key, default=None):
    return args[args.index(key)+1] if key in args else default


def links(state):
    return {row['ifname']: row for row in state['links']}


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(int.from_bytes(data[i:i+2], 'big') for i in range(0, len(data), 2))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return total == 65535


def normalized_rows(rows):
    result = []
    for row in rows:
        args = row['arguments'][:]
        if row['tool'] == 'bridge' and args[:1] == ['-b']:
            require(len(args) == 2, 'original MDB batch invocation changed')
            args[1] = '<original-batch>'
        item = [row['tool'], args]
        if result and item == result[-1][0] and row['tool'] == 'tc' and args[:4] == ['-j','-s','filter','show']:
            result[-1][1].append(row)
        else:
            result.append([item, [row]])
    require(len(result) == 1171 and hashlib.sha256(json.dumps([x[0] for x in result], separators=(',',':')).encode()).hexdigest() == COMMAND_SHA,
            'complete original MDB command phases changed')
    return result


def state_keys(objects, groups):
    def scrub(obj):
        if isinstance(obj, dict):
            return {k:scrub(v) for k,v in obj.items() if k != 'timer'}
        if isinstance(obj, list):
            return sorted((scrub(v) for v in obj), key=lambda x:json.dumps(x,sort_keys=True))
        return obj
    return Counter(json.dumps(scrub(r),sort_keys=True) for r in entries(objects) if address(r['grp']) in groups)


def batch_evidence(row, dumps, family):
    text = row.get('batch_text', '')
    require(hashlib.sha256(text.encode()).hexdigest() == row.get('batch_sha256'), 'actual original batch SHA missing/inconsistent')
    def group(n):
        return f'239.1.1.{n}' if family == 0 else f'ff0e::{n:x}' if family == 1 else f'01:00:00:00:00:{n:02x}'
    expected = [['mdb','add','dev',f'br-test{br}','port',f'br-test{br}-du{port}','grp',group(n),'permanent','vid','1']
                for br in (1,2) for port in range(1,33) for n in range(256)]
    require([line.split() for line in text.splitlines()] == expected and row['returncode'] == 0,
            'full original 16384-entry MDB batch was reduced/changed/failed')
    for br, query in zip((1,2), dumps):
        require(query['arguments'] == ['mdb','show','dev',f'br-test{br}'] and query['returncode'] == 0 and not query['stderr'],
                'real original large-scale MDB dump missing')
        actual = []
        for line in query['stdout'].splitlines():
            if 'permanent' not in line.split():
                continue
            match = re.fullmatch(r'dev (br-test[12]) port (br-test[12]-du\d+) grp (\S+) permanent vid 1',line)
            require(match is not None and match[1] == f'br-test{br}', 'large-scale native MDB entry bridge/VID/state malformed')
            actual.append((match[2],address(match[3])))
        wanted = [(f'br-test{br}-du{port}',address(group(n))) for port in range(1,33) for n in range(256)]
        require(len(actual) == 8192 and Counter(actual) == Counter(wanted),
                'native MDB dump is incomplete, duplicated or has wrong port/group')


def api_evidence(row, groups, bridge_index):
    args = row['arguments']; before, after = row.get('mdb_api_before'), row.get('mdb_api_after')
    require(isinstance(before,list) and isinstance(after,list), 'native MDB API before/after proof missing')
    if row['returncode']:
        require(state_keys(before,groups) == state_keys(after,groups), 'rejected original MDB mutation changed native entries')
        return
    operation = args[1]
    if operation == 'flush':
        wanted = []
        for item in entries(before):
            if address(item['grp']) not in groups:
                continue
            selected = (('port' not in args or item['port'] == scalar(args,'port')) and
                        ('vid' not in args or item.get('vid',0) == int(scalar(args,'vid'))) and
                        ('proto' not in args or item.get('protocol') == scalar(args,'proto')) and
                        ('permanent' not in args or item['state'] == 'permanent') and
                        ('nopermanent' not in args or item['state'] != 'permanent'))
            if not selected:
                wanted.append(item)
        require(state_keys([dict(mdb=wanted)],groups) == state_keys(after,groups), 'native MDB selective flush removed wrong entries')
        return
    group = address(scalar(args,'grp')); port = scalar(args,'port'); source = scalar(args,'src')
    require(state_keys(before,groups-{group}) == state_keys(after,groups-{group}),
            'successful MDB mutation altered an unrelated tracked group')
    vids = {int(scalar(args,'vid'))} if 'vid' in args and scalar(args,'vid') != '0' else {10,20}
    def outside_target(objects):
        return [dict(mdb=[r for r in entries(objects) if not (
            address(r['grp']) == group and r['port'] == port and r.get('vid',0) in vids and
            (source is None or r.get('src') == source)) and 'added_by_star_ex' not in r.get('flags',[])])]
    # A direct S,G operation can derive/remove kernel-owned automatic S,G
    # entries on another EXCLUDE port. Ordinary entries on other ports, VIDs
    # and sources must survive unchanged, including entries of the same group.
    require(state_keys(outside_target(before),groups) == state_keys(outside_target(after),groups),
            'successful MDB mutation altered another port/VID/source')
    for child in entries(after):
        if address(child['grp']) != group or 'added_by_star_ex' not in child.get('flags',[]):
            continue
        peers = [r for r in entries(after) if r['grp'] == child['grp'] and r.get('vid') == child.get('vid')]
        parent = [r for r in peers if r['port'] == child['port'] and 'src' not in r]
        require(child.get('protocol') == 'kernel' and set(child['flags']) == {'added_by_star_ex'} and
                child.get('filter_mode') == 'include' and len(parent) == 1 and parent[0].get('filter_mode') == 'exclude' and
                child['src'] not in {s['address'] for s in parent[0].get('source_list',[])} and
                any(r.get('src') == child['src'] and r['port'] != child['port'] and
                    not set(r.get('flags',[])) & {'blocked','added_by_star_ex'} for r in peers),
                'automatic native MDB peer source lacks its EXCLUDE parent/active source')
    selected = [r for r in entries(after) if address(r['grp']) == group and r['port'] == port and r.get('vid',0) in vids and
                (source is None or address(r.get('src','')) == address(source))]
    if operation == 'del':
        require(not selected, 'deleted original MDB entry still present')
        return
    require(operation in ('add','replace'), 'unexpected original MDB mutation')
    primary = [r for r in selected if ('src' in r) == (source is not None)]
    require(len(primary) == len(vids) and {r.get('vid',0) for r in primary} == vids, 'native MDB add/replace target missing/duplicated')
    for item in primary:
        require(item['dev'] == 'br0' and item['index'] == bridge_index and
                item['state'] == ('permanent' if 'permanent' in args else 'temp'), 'native MDB target/state/index changed')
        require(float(item['timer']) == 0 if item['state'] == 'permanent' or 'src' not in item and item.get('filter_mode') == 'include' else float(item['timer']) > 0,
                'native MDB permanence/lifetime mismatch')
        if port == 'br0' or re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}',group):
            continue
        require(item.get('protocol') == scalar(args,'proto','static'), 'native MDB protocol ownership changed')
        mode = 'include' if source is not None else scalar(args,'filter_mode','exclude')
        require(item.get('filter_mode') == mode, 'native MDB source filter mode changed')
        if source is not None:
            continue
        sources = {address(x) for x in scalar(args,'source_list','').split(',') if x}
        actual = item.get('source_list',[])
        require(len(actual) == len(sources) and {address(x['address']) for x in actual} == sources,
                'native MDB wildcard source list changed')
        for s in actual:
            timer = float(s['timer'])
            require(timer == 0 if mode == 'exclude' or item['state'] == 'permanent' else timer > 0,
                    'native MDB source lifetime/block state changed')
        children = [r for r in selected if r.get('vid',0) == item.get('vid',0) and 'src' in r]
        automatic = [r for r in children if 'added_by_star_ex' in r.get('flags',[])]
        children = [r for r in children if r not in automatic]
        for child in automatic:
            require(mode == 'exclude' and child.get('protocol') == 'kernel' and
                    set(child.get('flags',[])) == {'added_by_star_ex'} and child.get('filter_mode') == 'include' and
                    any(other.get('src') == child['src'] and other.get('grp') == child['grp'] and
                        other.get('vid') == child.get('vid') and other['port'] != child['port'] and
                        not set(other.get('flags',[])) & {'blocked','added_by_star_ex'} for other in entries(after)),
                    'automatic native MDB child lacks corresponding other-port source')
        require(len(children) == len(sources) and {address(r['src']) for r in children} == sources,
                'native MDB source forwarding entries changed')
        for child in children:
            require(child['filter_mode'] == 'include' and child['state'] == item['state'] and
                    child.get('protocol') == item['protocol'] and
                    set(child.get('flags',[])) == ({'blocked'} if mode == 'exclude' else set()),
                    'native MDB child forwarding/block/protocol state changed')


def validate_evidence(report):
    original = report.get('original',{})
    results = [re.fullmatch(r'TEST: (.*?)\s+\[ OK \]',line) for line in original.get('stdout','').splitlines() if line.startswith('TEST:')]
    require(original.get('returncode') == 0 and not original.get('stderr') and len(results) == 27 and all(results) and
            [x[1] for x in results] == LABELS and 'SKIP' not in original['stdout'] and '[FAIL]' not in original['stdout'],
            'complete unchanged original MDB outcomes missing')
    raw = report['commands']; phases = normalized_rows(raw); rows = [group[0] for _,group in phases]
    require([i for i,x in enumerate(rows) if x['returncode']] == NEGATIVE_POSITIONS and
            all(x['returncode'] == rows[i]['returncode'] for i,(_,group) in enumerate(phases) for x in group),
            'original MDB expected rejection/positive ACK positions changed')
    require(all(x['returncode'] or not x['stderr'] for x in raw), 'original positive MDB command warned')
    timed = [x for x in raw if x['tool'] != 'sysctl']
    require(all(x['finished_monotonic'] >= x['started_monotonic'] for x in timed) and
            all(b['started_monotonic'] >= a['finished_monotonic'] for a,b in zip(timed,timed[1:])), 'original MDB chronology changed')
    batches = [i for i,x in enumerate(rows) if 'batch_text' in x]
    require(batches == [558,693,828], 'original full scale MDB phases changed')
    for family,index in enumerate(batches):
        batch_evidence(rows[index], rows[index+1:index+3], family)
    dummy = [x for x in rows if x['tool'] == 'ip' and 'dummy' in x['arguments']]
    require(len(dummy) == 192 and all(x['returncode'] == 0 for x in dummy), 'original 192 real dummy ports missing')
    traffic = [x for x in rows if x['tool'] == 'mausezahn']
    require(len(traffic) == 51, 'complete original MDB traffic missing')
    bridge_index = links(traffic[0]['sg_before'])['br0']['ifindex']
    groups = {address(scalar(x['arguments'],'grp')) for x in rows if x['tool'] == 'bridge' and 'grp' in x['arguments']}
    mutations = [x for x in rows if x['tool'] == 'bridge' and x['arguments'][:2] in
                 (['mdb','add'],['mdb','replace'],['mdb','del'],['mdb','flush'])]
    require(len(mutations) == 321, 'original MDB API mutation coverage missing')
    for row in mutations:
        api_evidence(row,groups,bridge_index)
    validate_traffic(report, rows, phases, traffic)
    validate_boundaries(report,rows)


def topology(state, querier, router):
    devices = links(state); bridge = devices['br0']; info = bridge['linkinfo']['info_data']
    require(bridge['linkinfo']['info_kind'] == 'bridge' and 'UP' in bridge['flags'] and info['vlan_filtering'] == 1 and
            info['vlan_default_pvid'] == 0 and info['mcast_snooping'] == 1 and info['mcast_router'] == router and
            info['mcast_igmp_version'] == 3 and info['mcast_mld_version'] == 2 and info['mcast_querier'] == int(querier) and
            info['mcast_query_response_intvl'] == (100 if querier else 1000), 'native MDB bridge/querier state changed')
    tables = []
    for host,port,number in [('veth0','veth1',1),('veth3','veth2',2)]:
        vrf = 'v'+host
        require(devices[host]['linkinfo']['info_kind'] == devices[port]['linkinfo']['info_kind'] == 'veth' and
                devices[host]['link'] == port and devices[port]['link'] == host and devices[port].get('master') == 'br0' and
                devices[host].get('master') == vrf and devices[vrf]['linkinfo']['info_kind'] == 'vrf' and
                devices[port]['linkinfo']['info_slave_data']['state'] == 'forwarding' and
                all('UP' in devices[n]['flags'] for n in (host,port,vrf)), 'native MDB peer/VRF topology changed')
        tables.append(devices[vrf]['linkinfo']['info_data']['table'])
        for vid in (10,20):
            child = devices[f'{host}.{vid}']; data = child['linkinfo']['info_data']
            require(child['link'] == host and child.get('master') == vrf and child['linkinfo']['info_kind'] == 'vlan' and
                    data['id'] == vid and data['protocol'] == '802.1Q' and 'UP' in child['flags'], 'original native host VLAN missing')
            addr = next(x for x in state['addresses'] if x['ifname']==f'{host}.{vid}')['addr_info']
            v4,prefix = (f'192.0.2.{number}',28) if vid == 10 else (f'198.51.100.{number}',24)
            require(any(x.get('local')==v4 and x.get('prefixlen')==prefix for x in addr), 'original native VLAN IPv4 address missing')
            if host == 'veth0':
                require(any(x.get('local')==f'2001:db8:{1 if vid==10 else 2}::1' and x.get('prefixlen')==64 for x in addr),
                        'original native sender VLAN IPv6 address missing')
    require(len(set(tables))==2, 'native MDB hosts share VRF table')
    for name in ('br0','veth1','veth2'):
        vlans = next(x['vlans'] for x in state['vlans'] if x['ifname']==name)
        actual = {n for v in vlans for n in range(v['vlan'],v.get('vlanEnd',v['vlan'])+1)}
        require(actual == {10,20} and all(not set(v.get('flags',[])) & {'PVID','Egress Untagged'} for v in vlans),
                'native MDB bridge tagged VLAN10/20 membership changed')
    return devices


def flower(objects, family, counters, length):
    rows = [r for r in objects if 'options' in r]
    require(len(rows) == len(counters), 'native MDB classifier set missing/duplicated')
    for handle,count in enumerate(counters,1):
        selected = [r for r in rows if r['options'].get('handle') == handle]
        require(len(selected)==1, 'native MDB classifier handle changed')
        row = selected[0];opts = row['options'];actions = opts.get('actions',[])
        if family == 'l2':
            protocol = 'all'; keys = dict(dst_mac='01:02:03:04:05:06')
        else:
            protocol = '802.1Q'; keys = dict(vlan_id=10,vlan_ethtype='ip' if family=='v4' else 'ipv6',
                eth_type='ipv4' if family=='v4' else 'ipv6',dst_ip='239.1.1.1' if family=='v4' else 'ff0e::1',
                src_ip=f'192.0.2.{handle}' if family=='v4' else f'2001:db8:1::{handle}')
        require(row['protocol']==protocol and row['pref']==1 and row['kind']=='flower' and opts['keys']==keys and
                opts.get('not_in_hw') is True and len(actions)==1 and actions[0]['kind']=='gact' and
                actions[0]['control_action']['type']=='drop', 'actual original MDB classifier/action changed')
        stats = actions[0]['stats']
        require(stats['packets']==stats['drops']==count and stats['bytes']==count*(length-14),
                'native MDB forwarding/blocked packet or byte counter differs')


def ipv6_checksum(frame,protocol,payload):
    return checksum(frame[22:54]+len(payload).to_bytes(4,'big')+b'\0\0\0'+bytes([protocol])+payload)


def validate_traffic(report,rows,phases,traffic):
    packets = report.get('packet_trace',[])
    require(len(packets)==51, 'actual original MDB packet trace incomplete')
    # These are the original tc_check_packets assertions, including both
    # cumulative handles in each eight-probe source-filtering window.
    single = [(0,),(0,),(1,),(1,)]
    two = [(0,0),(0,0),(1,0),(1,0),(2,0),(2,1),(2,1),(2,1)]
    expected = single*2+[(1,),(1,),(2,),(2,)]+two*4+[(0,),(1,),(1,)]
    families = ['v4']*4+['v6']*4+['l2']*4+['v4']*8+['v6']*8+['v4']*8+['v6']*8+['l2']*3
    total = 0
    enable = next(x for x in rows if x['tool']=='ip' and x['arguments']==['link','set','dev','br0','type','bridge','mcast_querier','1'])
    require(traffic[0]['started_monotonic']-enable['finished_monotonic']>=10, 'original querier setup wait shortened')
    for i,(sender,packet) in enumerate(zip(traffic,packets)):
        args=sender['arguments'];before=sender['sg_before'];devices=topology(before,i<47,0 if i<12 else 1);frame=bytes.fromhex(packet['frame_hex']);total+=len(frame)
        require(packet['family']==17 and packet['ifindex']==devices['veth0.10']['ifindex'] and
                packet['length']==packet['result']==len(frame) and
                frame[6:12].hex()==devices['veth0.10']['address'].replace(':','') and
                frame[:6].hex()==scalar(args,'-b').replace(':',''), 'native MDB packet sender/MAC/interface changed')
        if i<47:
            family=families[i];length=128 if family=='l2' else 170 if family=='v4' else 190
            require(len(frame)==length, 'original MDB frame/payload size changed')
            if family == 'l2':
                require(frame[12:14] == b'\0\0', 'original raw L2 MDB frame type changed')
            if family!='l2':
                source=scalar(args,'-A');dest=scalar(args,'-B');offset=34 if family=='v4' else 54
                if family=='v4':
                    require(frame[12:15]==bytes.fromhex('080045') and int.from_bytes(frame[16:18],'big')==156 and
                            frame[23]==17 and checksum(frame[14:34]) and
                            frame[26:30]==ipaddress.IPv4Address(source).packed and frame[30:34]==ipaddress.IPv4Address(dest).packed,
                            'original MDB IPv4 packet/header/checksum changed')
                else:
                    require(frame[12:15]==bytes.fromhex('86dd60') and int.from_bytes(frame[18:20],'big')==136 and frame[20]==17 and
                            frame[22:38]==ipaddress.IPv6Address(source).packed and frame[38:54]==ipaddress.IPv6Address(dest).packed,
                            'original MDB IPv6 packet/header changed')
                udp=frame[offset:]
                require(udp[:6]==bytes.fromhex('000000000088') and len(udp[8:])==128,
                        'original MDB UDP ports/payload changed')
                # Original MZ emits zero UDPv6 checksum; this is the original
                # L2 flower oracle before UDP validation, not socket delivery.
                pseudo=(frame[26:34]+b'\0\x11'+len(udp).to_bytes(2,'big')) if family=='v4' else (
                    frame[22:54]+len(udp).to_bytes(4,'big')+b'\0\0\0\x11')
                require(udp[6:8]==b'\0\0' or checksum(pseudo+udp), 'native MDB UDP bytes/checksum inconsistent')
            position=rows.index(sender);query=rows[position+1];polls=phases[position+1][1];receiver='br0' if i<12 else 'veth3'
            require(query['tool']=='tc' and query['arguments']==['-j','-s','filter','show','dev',receiver,'ingress'],
                    'original MDB decisive classifier query missing')
            counts=expected[i]
            reset=i in (0,4,8,12,20,28,36,44)
            prior=tuple(0 for _ in counts) if reset else expected[i-1]
            flower(before['filters_by_device'][receiver],family,prior,length)
            for poll in polls:
                require(poll['started_monotonic']>=sender['finished_monotonic'], 'MDB classifier query precedes send')
                # Read-only retries may precede delivery. The complete original
                # tc_common busywait remains at its actual default 1000ms.
                objs=json.loads(poll['stdout'])
                if poll is polls[-1]: flower(objs,family,counts,length)
                else:
                    actual=tuple(next(x['options']['actions'][0]['stats']['packets'] for x in objs
                        if x.get('options',{}).get('handle')==h) for h in range(1,len(counts)+1))
                    require(all(a<=b<=c for a,b,c in zip(prior,actual,counts)), 'native MDB retry counters moved backwards/overshot')
                    flower(objs,family,actual,length)
            after=topology(polls[-1]['sg_after'],True,0 if i<12 else 1)
            seen=any(b>a for a,b in zip(prior,counts))
            path=[('veth0.10','tx',length),('veth0','tx',length),('veth1','rx',length)]
            if seen:path+= [('br0','rx',length-14)] if receiver=='br0' else [('veth2','tx',length),('veth3','rx',length)]
            for name,direction,size in path:
                a=devices[name]['stats64'][direction];b=after[name]['stats64'][direction]
                require(b['packets']-a['packets']>=1 and b['bytes']-a['bytes']>=size,
                        'original native MDB packet did not traverse expected Linux path')
        else:
            v4=i<49;offset=34 if v4 else 54;literal=scalar(args,'-t')
            require(literal=='ip', 'original MDB control report invocation changed')
            payload=args[args.index('-t')+2].split(',p=',1)[1].replace(':','')
            require(frame[offset:].hex()==payload, 'actual original MDB control report bytes changed')
            if v4:
                require(len(frame)==54 and frame[12:15]==bytes.fromhex('080045') and frame[23]==2 and checksum(frame[14:34]) and
                        checksum(frame[34:]) and frame[26:34]==ipaddress.IPv4Address('192.0.2.1').packed+ipaddress.IPv4Address('239.1.1.1').packed,
                        'literal original IGMP control checksum/header changed')
            else:
                require(len(frame)==106 and frame[12:15]==bytes.fromhex('86dd60') and frame[18:20]==b'\0\x34' and frame[20:22]==b'\0\1' and
                        frame[22:38]==ipaddress.IPv6Address('fe80::1').packed and frame[38:54]==ipaddress.IPv6Address('ff0e::1').packed and
                        frame[54:62]==bytes.fromhex('3a00000000000000') and ipv6_checksum(frame,58,frame[62:]),
                        'literal original MLD control checksum/HBH changed')
            following=rows[rows.index(sender)+1:];late=next(x for x in following if 'mdb_api_before' in x)
            group='239.1.1.1' if v4 else 'ff0e::1';s1='192.0.2.1' if v4 else '2001:db8:1::1';s2='192.0.2.2' if v4 else '2001:db8:1::2'
            target=[x for x in entries(late['mdb_api_before']) if x['grp']==group and x['port']=='veth1' and x.get('vid')==10]
            wildcard=[x for x in target if 'src' not in x];permanent=i%2==1
            require(len(wildcard)==1 and wildcard[0]['filter_mode']=='include' and
                    wildcard[0]['state']==('permanent' if permanent else 'temp') and
                    {x['address'] for x in wildcard[0]['source_list']}==({s1} if permanent else {s1,s2}) and
                    {x['src'] for x in target if 'src' in x}==({s1} if permanent else {s1,s2}),
                    'native permanent/temporary group report processing differs')
            require(following[0]['returncode']==(254 if permanent else 0), 'original control group lookup verdict differs')
    require(total==sum(x['length'] for x in packets), 'native packet lengths inconsistent')


def validate_boundaries(report, rows):
    require(report.get('original_tc_hit_timeout_ms') == 1000,
            'original tc_common default busywait changed')
    require(report['source_hashes'].get('forwarding/tc_common.sh') ==
            '4aed88ec9b90364edf2fbd2611237cdc78d57a2e931280124bd750b3b26e0369',
            'unchanged original tc_common source missing')
    provenance = report['iproute2']
    require(provenance['version'] == '6.12.0' and provenance['archive_sha256'] ==
            'bbd141ef7b5d0127cc2152843ba61f274dc32814fa3e0f13e7d07a080bef53d9' and
            provenance['source_hashes']['tc/tc.c'] ==
            'e9b2e36053ee6e20f79d44a0cab3e1661300ecf9e9783c5fcd03357aa696a101' and
            report['tc_tool']['sha256'] == provenance['binaries']['tc'],
            'original native iproute2/TC provenance inconsistent')
    clean = report['cleanup_state']; remaining = links(clean)
    devices = [f'veth{i}' for i in range(4)]
    require(not any(name in remaining for name in ('br0','vveth0','vveth3')) and
            not any(name.startswith(('br-test','veth0.','veth3.')) for name in remaining) and
            not entries(clean['mdb']) and
            all('UP' not in remaining[n]['flags'] and 'master' not in remaining[n] and
                remaining[n]['promiscuity'] == 0 for n in devices) and
            not any(r.get('master') == 'br0' for r in clean['fdb']) and
            not any(a.get('scope') == 'global' for r in clean['addresses'] if r['ifname'] in devices
                    for a in r.get('addr_info',[])) and
            not any(r.get('dev') in (*devices,'br0') for family in ('ipv4_routes','ipv6_routes')
                    for r in clean[family]) and
            all(clean[f].strip() == '0' for f in ('ipv4','ipv6')),
            'native MDB bridge/dummy/VLAN/VRF/address/route cleanup failed')
    require(report['missing_backend_control']['returncode'] not in (None,0) and
            report['vrf_binding_control']['baseline']['returncode'] == 0 and
            report['vrf_binding_control']['unknown_vrf']['returncode'] not in (None,0),
            'native MDB missing-backend/VRF boundary failed')
    native, stats = report['native_fixture'], report['stats']
    require(native['bridge_packet_sends'] == 51 and native['bridge_packet_bytes'] ==
            sum(x['length'] for x in report['packet_trace']) and native['bridge_packet_trace_errors'] == 0 and
            native['raw_sockets'] > 0 and native['netlinks'] > 0 and native['live'] == 0 and
            stats['outstanding'] == 0 and stats['worker_exit_code'] == 0 and
            stats['control_eof'] is True and stats['shutdown_timed_out'] is False,
            'native MDB packet/resource/shutdown proof failed')
