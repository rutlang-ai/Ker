"""Require the complete original VLAN-unaware learning/ageing/flood matrix."""
import json
import re

MAC = 'de:ad:be:ef:13:37'
MULTICAST = '01:00:5e:00:00:01'
FDB = ['-j', 'fdb', 'show', 'br', 'br0', 'brport', 'veth1']


def require(value, message):
    if not value:
        raise RuntimeError(message)


def target(rows):
    return [r for r in rows if r.get('mac') == MAC]


def topology(state):
    links = {r['ifname']: r for r in state['links']}; data = links['br0']['linkinfo']['info_data']
    require(links['br0']['linkinfo']['info_kind'] == 'bridge' and 'UP' in links['br0']['flags'] and
            data['vlan_filtering'] == 0 and data['mcast_snooping'] == 0 and data['ageing_time'] == 1000,
            'native VLAN-unaware bridge, snooping or ten-second ageing changed')
    tables = []
    for host, port, vrf, number in (('veth0', 'veth1', 'vveth0', 1), ('veth3', 'veth2', 'vveth3', 2)):
        require(links[host]['linkinfo']['info_kind'] == links[port]['linkinfo']['info_kind'] == 'veth' and
                links[host]['link'] == port and links[port]['link'] == host and links[host].get('master') == vrf and
                links[vrf]['linkinfo']['info_kind'] == 'vrf' and links[port].get('master') == 'br0' and
                links[port]['linkinfo']['info_slave_data']['state'] == 'forwarding' and
                all('UP' in links[n]['flags'] for n in (host, port, vrf)), 'native unaware bridge/VRF topology changed')
        tables.append(links[vrf]['linkinfo']['info_data']['table'])
        addresses = next(r for r in state['addresses'] if r['ifname'] == host)['addr_info']
        require(all(any(a.get('local') == address and a.get('prefixlen') == prefix for a in addresses)
                    for address, prefix in ((f'192.0.2.{number}',24), (f'2001:db8:1::{number}',64))), 'original unaware host addresses changed')
    require(len(set(tables)) == 2, 'unaware hosts share native VRF table')
    return links


def flower(rows, mac, count):
    detail = [r for r in rows if r.get('options', {}).get('handle') == 101]
    require(len(detail) == 1, 'native unaware flower handle101 missing')
    row = detail[0]; options = row['options']; actions = options.get('actions', [])
    require(row.get('protocol') == 'ip' and row.get('kind') == 'flower' and row.get('pref') == 1 and
            options.get('keys') == dict(dst_mac=mac, eth_type='ipv4') and options.get('not_in_hw') is True and
            len(actions) == 1 and actions[0].get('kind') == 'gact' and
            actions[0].get('control_action', {}).get('type') == 'drop', 'native unaware classifier/action changed')
    stats = actions[0]['stats']
    require(stats.get('packets') == stats.get('drops') == count and stats.get('bytes') == count * 84,
            'original native unaware flower packet/byte/drop counter changed')


def tc_commands(device, mac, queries=1):
    return [['qdisc','add','dev',device,'ingress'],
            ['filter','add','dev',device,'ingress','protocol','ip','pref','1','handle','101','flower','dst_mac',mac,'action','drop'],
            *[['-j','-s','filter','show','dev',device,'ingress'] for _ in range(queries)],
            ['filter','del','dev',device,'ingress','protocol','ip','pref','1','handle','101','flower'],
            ['qdisc','del','dev',device,'ingress']]


def validate_evidence(report):
    original = report.get('original', {})
    parsed = [re.fullmatch(r'TEST: (.*?)\s+\[ OK \]', line)
              for line in original.get('stdout','').splitlines() if line.startswith('TEST:')]
    require(original.get('returncode') == 0 and not original.get('stderr') and len(parsed) == 5 and all(parsed) and
            [m[1] for m in parsed] == ['ping','ping6','FDB learning','Unknown unicast flood','Unregistered multicast flood'] and
            'SKIP' not in original.get('stdout',''), 'incomplete original unaware entry outcomes')
    tools = report.get('iproute2', {})
    require(tools.get('version') == '6.12.0' and tools.get('archive_sha256') ==
            'bbd141ef7b5d0127cc2152843ba61f274dc32814fa3e0f13e7d07a080bef53d9' and
            bool(report.get('tc_tool',{}).get('sha256')) and report['tc_tool']['sha256'] == tools.get('binaries',{}).get('tc') and
            tools.get('source_hashes',{}).get('tc/tc.c') == 'e9b2e36053ee6e20f79d44a0cab3e1661300ecf9e9783c5fcd03357aa696a101',
            'pinned original unaware tc provenance missing')
    rows = report['commands']; bridge = [r for r in rows if r['tool'] == 'bridge']; traffic = [r for r in rows if r['tool']=='mausezahn']
    phase = [FDB, ['link','set','dev','veth1','flood','off'], FDB, FDB,
             ['link','set','dev','veth1','learning','off'], FDB, ['link','set','dev','veth1','learning','on'],
             ['link','set','dev','veth1','flood','on'], ['link','set','dev','veth2','flood','off'],
             ['link','set','dev','veth2','flood','on'], ['link','set','dev','veth2','mcast_flood','off'],
             ['link','set','dev','veth2','mcast_flood','on']]
    require([r['arguments'] for r in bridge] == phase, 'original native learning/flood command phases changed')
    fdb = [r for r in bridge if r['arguments'] == FDB]
    for row, present in zip(fdb, (False,True,False,False)):
        require('unaware_after' in row, 'native post-wait FDB observation missing')
        links = topology(row['unaware_after']); table = target(row['unaware_after']['fdb']); filtered = target(json.loads(row['stdout']))
        require(len(table) == len(filtered) == int(present) and all(r.get('ifname') == 'veth1' and
                r.get('master') == 'br0' and r.get('state') == '' and 'vlan' not in r for r in table),
                'actual dynamic VID0 FDB learning/ageing/off sequence changed')
    require(fdb[2]['started_monotonic'] - fdb[1]['finished_monotonic'] >= 20,
            'original ageing_time plus ten-second wait was shortened')
    for row in bridge:
        require('unaware_before' in row and 'unaware_after' in row, 'native bridge phase proof missing')
        if row['arguments'] != FDB:
            port, flag, value = row['arguments'][3:]
            before = topology(row['unaware_before']); after = topology(row['unaware_after'])
            require(after[port]['linkinfo']['info_slave_data'][flag] is (value=='on'), 'native bridge flag change ineffective')
    pings = [r for r in rows if r['arguments'][:2] == ['vrf','exec']]
    require(len(pings) == 2, 'both original unaware ping families required')
    for row, program, address in zip(pings, ('ping','ping6'), ('192.0.2.2','2001:db8:1::2')):
        require(row['arguments'] == ['vrf','exec','vveth0',program,'-c','10','-i','0.1','-w','5',address] and
                row['returncode'] == 0 and not row['stderr'] and '10 received' in row['stdout'] and
                row.get('native_clock_reads',0) > 0 and row['vrf']['ifname']=='vveth0', 'original unaware ping arguments/outcome/clock changed')
        require('unaware_before' in row and 'unaware_after' in row, 'native unaware ping state missing')
        topology(row['unaware_before']); topology(row['unaware_after'])
    expected_mz = [['veth3','-c','1','-p','64','-b',MAC,'-t','ip','-q'],
                   ['veth0','-c','1','-p','64','-a',MAC,'-t','ip','-q']] * 2
    expected_mz += [[ 'veth0','-c','1','-p','64','-b',mac,'-B',ip,'-t','ip','-q']
                    for mac,ip in ((MAC,'192.0.2.100'),(MAC,'192.0.2.100'),(MULTICAST,'239.0.0.1'),(MULTICAST,'239.0.0.1'))]
    require([r['arguments'] for r in traffic] == expected_mz, 'original eight MZ argument sequences changed')
    tc = [r for r in rows if r['tool']=='tc']
    require([r['arguments'] for r in tc] == tc_commands('veth0',MAC,2) +
            tc_commands('veth3',MAC)*2 + tc_commands('veth3',MULTICAST)*2, 'original native qdisc/filter lifecycle changed')
    queries = [r for r in tc if r['arguments'][:2] == ['-j','-s']]
    for row, mac, count in zip(queries, (MAC,MAC,MAC,MAC,MULTICAST,MULTICAST), (0,1,0,1,0,1)):
        flower(json.loads(row['stdout']),mac,count)
        require('unaware_after' in row, 'native post-wait flower state missing');topology(row['unaware_after'])
    packets = report.get('packet_trace',[]);require(len(packets)==8, 'eight native AF_PACKET frames required')
    # Each sender is judged at the unchanged script's later FDB/TC query.
    decisive = [queries[0],fdb[1],queries[1],fdb[3],*queries[2:]]
    for index,(sender,query,packet) in enumerate(zip(traffic,decisive,packets)):
        require('unaware_before' in sender and 'unaware_after' in sender, 'native unaware traffic state missing')
        a,b = topology(sender['unaware_before']),topology(query['unaware_after'])
        require(query['started_monotonic'] - sender['finished_monotonic'] >= 1,
                'original post-send one-second wait was shortened')
        host = sender['arguments'][0];source_mac = MAC if index in (1,3) else a[host]['address']
        frame = bytes.fromhex(packet['frame_hex'])
        require(packet.get('family')==17 and packet.get('ifindex')==a[host]['ifindex'] and
                packet.get('length')==packet.get('result')==len(frame)==98 and
                frame[6:12].hex()==source_mac.replace(':','') and frame[12:15]==bytes.fromhex('080045') and
                int.from_bytes(frame[16:18],'big')==84 and len(frame[34:])==64, 'original native unaware frame/source/interface changed')
        if index not in (1,3):
            mac = MAC if index<6 else MULTICAST
            require(frame[:6].hex()==mac.replace(':',''), 'original target Ethernet MAC changed')
        if index>=4:
            require(frame[30:34] == (bytes([192,0,2,100]) if index<6 else bytes([239,0,0,1])), 'original flood IPv4 destination changed')
        if index in (0,2):
            require(a['veth1']['linkinfo']['info_slave_data']['flood'] is False, 'unknown flood suppression missing during learning')
        if index==2:require(len(target(sender['unaware_before']['fdb']))==1,'known-unicast learned path was not native')
        if index==3:require(a['veth1']['linkinfo']['info_slave_data']['learning'] is False,'original learning-off probe ineffective')
        if index>=4:
            flag='flood' if index<6 else 'mcast_flood'
            require(a['veth2']['linkinfo']['info_slave_data'][flag] is (index%2==1), 'native flood off/on matrix changed')
            require(not target(sender['unaware_before']['fdb']), 'flood destination unexpectedly learned')
            flower(sender['unaware_before']['filters_by_device']['veth3'], MAC if index<6 else MULTICAST,0)
        source_port='veth2' if host=='veth3' else 'veth1'
        hops=[(host,'tx'),(source_port,'rx')]
        if index==2:hops += [('veth1','tx'),('veth0','rx')]
        elif index in (5,7):hops += [('veth2','tx'),('veth3','rx')]
        for dev,direction in hops:
            first,last=a[dev]['stats64'][direction],b[dev]['stats64'][direction]
            require(last['packets']-first['packets']>=1 and last['bytes']-first['bytes']>=98,
                    'native unaware frame did not traverse original post-wait path')
    require(rows.index(traffic[1]) < rows.index(fdb[1]) < rows.index(traffic[2]) < rows.index(fdb[2]) < rows.index(traffic[3]) < rows.index(fdb[3]),
            'original learn/forward/age/learning-off order changed')
    promisc=[r for r in rows if 'promisc' in r['arguments']]
    require([r['arguments'] for r in promisc] == [['link','set','veth0','promisc',v] for v in ('on','off')] +
            [['link','set','veth3','promisc',v] for v in ('on','off')]*4,'original unaware promisc lifecycle changed')
    for row in promisc:
        require('unaware_after' in row,'native promisc proof missing');link=next(r for r in row['unaware_after']['links'] if r['ifname']==row['arguments'][2])
        require(link['promiscuity']==int(row['arguments'][-1]=='on'),'native unaware promisc update ineffective')
    require([r['arguments'] for r in rows if r['returncode']] == [['link','show','dev','veth0'],['link','show','dev','veth2']] and
            all(not r['stderr'] for r in rows if r['returncode']==0),'unexpected unaware native setup/traffic/cleanup failure')
    clean=report['cleanup_state'];links={r['ifname']:r for r in clean['links']};devices=tuple(f'veth{i}' for i in range(4))
    require(not any(n in links for n in ('br0','vveth0','vveth3')) and
            all('UP' not in links[n]['flags'] and 'master' not in links[n] and links[n]['promiscuity']==0 for n in devices) and
            not any(r.get('mac')==MAC or r.get('master')=='br0' for r in clean['fdb']), 'native unaware bridge/VRF/FDB/promisc leaked')
    require(not any(a.get('scope')=='global' for r in clean['addresses'] if r['ifname'] in devices for a in r.get('addr_info',[])) and
            not any(r.get('dev') in (*devices,'br0') for f in ('ipv4_routes','ipv6_routes') for r in clean[f]) and
            not any(r['tool']=='sysctl' for r in rows) and all(clean[f].strip()=='0' for f in ('ipv4','ipv6')), 'native unaware address/routes/forwarding leaked')
    require(all(sum(r['arguments']==['link','del','dev',n] for r in rows)==1 for n in ('br0','vveth0','vveth3')), 'original unaware teardown missing')
    require(report.get('missing_backend_control',{}).get('returncode') not in (None,0) and
            report.get('vrf_binding_control',{}).get('baseline',{}).get('returncode')==0 and
            report.get('vrf_binding_control',{}).get('unknown_vrf',{}).get('returncode') not in (None,0), 'native unaware boundary control failed')
    native,stats=report.get('native_fixture',{}),report.get('stats',{})
    require(native.get('bridge_packet_sends')==8 and native.get('bridge_packet_bytes')==784 and
            native.get('bridge_packet_trace_errors')==0 and native.get('live')==0 and stats.get('outstanding')==0 and
            stats.get('worker_exit_code')==0 and stats.get('control_eof') is True and stats.get('shutdown_timed_out') is False,
            'native unaware resources did not shut down normally')
