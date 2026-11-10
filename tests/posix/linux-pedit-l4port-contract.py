"""Complete original UDP/TCP port editing through imported Linux TC.

Source traces precede editing; receiver flower is the edited-port oracle.
Transport socket delivery and checksum repair are not part of this entry.
"""
import importlib.util
import ipaddress
import json
from pathlib import Path
import re

spec = importlib.util.spec_from_file_location('pedit_ip', Path(__file__).with_name('linux-pedit-ip-contract.py'))
ip = importlib.util.module_from_spec(spec); spec.loader.exec_module(ip)
require = ip.require


def flower(rows, protocol, field, port, edit):
    # Original act_pedit.c:488-491 increments overlimits for unparseable
    # background frames, then returns the configured action. No drop stub.
    require(len(rows) == 2 and sum('options' in x for x in rows) == 1, 'native L4 flower missing/duplicated/polluted')
    row = next(x for x in rows if 'options' in x); options = row['options']; actions = options['actions']
    require(row['kind'] == 'flower' and row['pref'] == 1 and row['chain'] == 0 and options['handle'] == 101 and
            options.get('not_in_hw') is True and len(actions) == 1, 'native L4 classifier identity/software path changed')
    action = actions[0]
    require(action['order'] == 1 and action['control_action'] == {'type':'pass'} and action['ref'] == action['bind'] == 1,
            'native L4 action binding/verdict changed')
    if edit:
        value, mask = (port << 16, 65535) if field == 'sport' else (port, 0xffff0000)
        require(row['protocol'] == 'all' and options['keys'] == {} and action['kind'] == 'pedit' and action['nkeys'] == 1 and
                len(action['keys']) == 1, 'native L4 PEDIT action substituted')
        key = action['keys'][0]
        require(key['htype'] == protocol and key['offset'] == 0 and key['cmd'] == 'set' and
                int(key['val'],16) == value and int(key['mask'],16) == mask, 'native L4 port value/halfword/mask/header type changed')
    else:
        require(row['protocol'] == 'ip' and options['keys'] == {'eth_type':'ipv4','ip_proto':protocol,
                ('src_port' if field == 'sport' else 'dst_port'):port} and options.get('skip_hw') is True and action['kind'] == 'gact' and
                action['prob'] == {'random_type':'none','control_action':{'type':'pass'},'val':0}, 'native L4 receiver did not match edited port/protocol')
    stats = action['stats']
    require(all(isinstance(stats[k],int) and stats[k] >= 0 for k in ('packets','bytes')) and
            all(stats[k] == 0 for k in ('drops','requeues','backlog','qlen')) and
            (0 <= stats['overlimits'] <= stats['packets'] if edit else stats['overlimits'] == 0), 'native L4 action dropped/queued or fabricated traffic')
    return stats


def filters(state, protocol, field, port, locus, active):
    answer = {}
    for key, rows in ip.all_filters(state).items():
        if key in active:
            answer[key] = flower(rows,protocol,field,port,key == locus)
        else:
            require(rows == [], 'native L4 rule leaked onto another locus')
    return answer


def validate_evidence(report):
    original = report['original']
    labels = ['ping'] + [f'dev {dev} {direction} pedit {protocol} {field} set {port}'
              for protocol in ('udp','tcp') for field in ('sport','dport')
              for dev,direction in (('veth1','ingress'),('veth2','egress')) for port in (1,11111,65535)]
    results = [re.fullmatch(r'TEST: (.*?)\s+\[ OK \]',line) for line in original['stdout'].splitlines() if line.startswith('TEST:')]
    require(original['returncode'] == 0 and not original['stderr'] and len(results) == 25 and all(results) and
            [x[1] for x in results] == labels and 'SKIP' not in original['stdout'] and '[FAIL]' not in original['stdout'],
            'complete unchanged original L4 port edit outcomes missing')
    rows = report['commands']
    require(ip.normalized(rows) == COMMAND_SHA and [i for i,x in enumerate(rows) if x['returncode']] == [0,2] and
            all(not x['stderr'] for x in rows if not x['returncode']), 'original L4 command/phase/probe/cleanup sequence changed')
    timed = [x for x in rows if x['tool'] in ('tc','mausezahn')]
    require(all(x['finished_monotonic'] >= x['started_monotonic'] for x in timed) and
            all(b['started_monotonic'] >= a['finished_monotonic'] for a,b in zip(timed,timed[1:])), 'native L4 chronology changed')
    require(all(isinstance(x.get('pedit_before'),dict) and isinstance(x.get('pedit_after'),dict) for x in timed),
            'native L4 command observations missing')
    pings = [x for x in rows if x['arguments'][:2] == ['vrf','exec']]
    require(len(pings) == 1 and pings[0]['arguments'] == ['vrf','exec','vveth0','ping','-c','10','-i','0.1','-w','5','192.0.2.2'] and
            pings[0]['returncode'] == 0 and not pings[0]['stderr'] and '10 received' in pings[0]['stdout'] and
            pings[0].get('native_clock_reads',0) > 0 and pings[0]['vrf']['linkinfo']['info_kind'] == 'vrf',
            'original L4 baseline ping/native clock/VRF binding changed')
    traffic = [x for x in rows if x['tool'] == 'mausezahn']
    require(len(traffic) == 24 and len(report['packet_trace']) == 240, 'complete original L4 packet matrix missing')
    for phase, sender in enumerate(traffic):
        protocol = 'udp' if phase < 12 else 'tcp'; field = 'sport' if phase%12 < 6 else 'dport'
        port = (1,11111,65535)[phase%3]; locus = ('veth1','ingress') if phase%6 < 3 else ('veth2','egress'); receiver = ('veth3','ingress')
        i = rows.index(sender); add_edit,add_receiver = rows[i-2:i]
        devices = ip.topology(sender['pedit_before']); ip.topology(sender['pedit_after'])
        for state,active in ((add_edit['pedit_before'],()),(add_edit['pedit_after'],(locus,)),
                             (add_receiver['pedit_before'],(locus,)),(add_receiver['pedit_after'],(locus,receiver))):
            filters(state,protocol,field,port,locus,active)
        initial = filters(sender['pedit_before'],protocol,field,port,locus,(locus,receiver))
        filters(sender['pedit_after'],protocol,field,port,locus,(locus,receiver))
        # Absent->installed observations bind a fresh rule. Real edited
        # background traffic may count before the original probe; require
        # ten new valid matches from this actual pre-send baseline.
        j = i+1; queries = []
        while j < len(rows) and rows[j]['tool'] == 'tc' and rows[j]['arguments'][:4] == ['-j','-s','filter','show']:
            queries.append(rows[j]); j += 1
        require(len(queries) >= 2 and queries[-1]['arguments'][-2:] == list(locus) and
                all(x['arguments'][-2:] == list(receiver) for x in queries[:-1]), 'original L4 receiver/PEDIT queries reordered')
        for query in queries:
            edit = query is queries[-1]; key = locus if edit else receiver
            counter = flower(json.loads(query['stdout']),protocol,field,port,edit)
            actual = filters(query['pedit_after'],protocol,field,port,locus,(locus,receiver))[key]
            require(actual['packets'] >= counter['packets'] and actual['bytes'] >= counter['bytes'], 'native L4 queried counter exceeds observed actual counter')
        size = 142 if protocol == 'udp' else 154
        for query,edit in ((queries[-2],False),(queries[-1],True)):
            counter = flower(json.loads(query['stdout']),protocol,field,port,edit); key = locus if edit else receiver
            counted_size = size if edit and locus[1] == 'egress' else size-14
            require(counter['packets']-counter['overlimits']-initial[key]['packets']+initial[key]['overlimits'] >= 10 and
                    counter['bytes']-initial[key]['bytes'] >= 10*counted_size,
                    'native L4 edited-port receiver/action valid count below ten')
        last = ip.topology(queries[-1]['pedit_after'])
        for device,direction in (('veth0','tx'),('veth1','rx'),('veth2','tx'),('veth3','rx')):
            before = devices[device]['stats64'][direction]; after = last[device]['stats64'][direction]
            require(after['packets']-before['packets'] >= 10 and after['bytes']-before['bytes'] >= 10*size,
                    'native L4 traffic did not traverse original bridge path')
        for command,active_before,active_after in ((rows[j],(locus,receiver),(locus,)),(rows[j+1],(locus,),())):
            filters(command['pedit_before'],protocol,field,port,locus,active_before)
            filters(command['pedit_after'],protocol,field,port,locus,active_after)
        source,dest = devices['veth0'],devices['veth3']
        require(sender['arguments'] == ['-A','192.0.2.1','-B','192.0.2.2','veth0','-c','10','-d','20msec','-p','100',
                '-a','own','-b',dest['address'],'-q','-t',protocol,'sp=54321,dp=12345'] and
                sender['finished_monotonic']-sender['started_monotonic'] >= .18, 'original L4 packet arguments/MAC/pacing changed')
        for packet in report['packet_trace'][phase*10:(phase+1)*10]:
            data = bytes.fromhex(packet['frame_hex']); header = data[14:34]; payload = data[34:]
            require(packet['family'] == 17 and packet['ifindex'] == source['ifindex'] and packet['result'] == packet['length'] == len(data) == size and
                    data[:6] == bytes.fromhex(dest['address'].replace(':','')) and data[6:12] == bytes.fromhex(source['address'].replace(':','')) and
                    data[12:14] == b'\x08\x00', 'native L4 input frame/interface/MAC changed')
            require(header[0] == 0x45 and int.from_bytes(header[2:4],'big') == size-14 and header[9] == (17 if protocol == 'udp' else 6) and
                    sum(int.from_bytes(header[k:k+2],'big') for k in range(0,20,2)) % 65535 == 0 and
                    header[12:] == ipaddress.ip_address('192.0.2.1').packed + ipaddress.ip_address('192.0.2.2').packed,
                    'original native L4 IPv4 header/address/protocol/checksum changed')
            require(payload[:4] == bytes.fromhex('d4313039') and
                    (int.from_bytes(payload[4:6],'big') == 108 if protocol == 'udp' else payload[12]>>4 == 5),
                    'original native source/destination ports or transport payload size changed')
    ip.validate_boundaries(report,rows,source_hashes=SOURCE_HASHES,expected_sends=240,expected_bytes=35520)


COMMAND_SHA = 'c43681f41efc95125ae4f6b1a960807ae768e8e28d880dab85d2b71bc73e793f'
SOURCE_HASHES = {'forwarding/pedit_l4port.sh': '46828353b5e5e9b24ece37ad105060bc78f95ad4a4c64efe2ddd90d7746f8f2d', 'forwarding/lib.sh': '8fb499582bb13c830e7fe9cbcb0baffc0bedf552d12c3c9241b65ecf14414537', 'lib.sh': '875a357f3264e3126af195e97a36217ba6e44c0812afc1b6b8a414f1984dcccd', 'forwarding/Makefile': '2c66e188a0a956c79dfbedd3a3449fd455e94e0a2a5b07550aaed0b79f745d96', 'forwarding/tc_common.sh': '4aed88ec9b90364edf2fbd2611237cdc78d57a2e931280124bd750b3b26e0369'}
