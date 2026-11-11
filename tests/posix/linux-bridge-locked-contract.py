"""Require all original port-lock, MAB, roaming, flushing and MIRRED evidence."""
import json
import re

ROAM = 'a0:b0:c0:c0:b0:a0'
LOCK1, STATIC1, LOCK2, STATIC2 = ('00:01:02:03:04:05','00:01:02:03:04:06','00:01:02:03:04:07','00:01:02:03:04:08')
OUTCOMES = ['Locked port ipv4','Locked port ipv6','Locked port vlan','Locked port MAB','Locked port MAB roam',
            'Locked port MAB configuration','Locked port MAB FDB flush','Locked port MAB redirect']
TC = [['qdisc','add','dev','veth1','clsact'],
      ['filter','add','dev','veth1','ingress','protocol','all','pref','1','handle','101','flower','action','mirred','egress','redirect','dev','veth2'],
      ['filter','del','dev','veth1','ingress','protocol','all','pref','1','handle','101','flower'],
      ['qdisc','del','dev','veth1','clsact']]


def require(value,message):
    if not value:raise RuntimeError(message)


def links(state):return {r['ifname']:r for r in state['links']}


def entries(state,mac,vid=1):return [r for r in state['fdb'] if r.get('mac')==mac and r.get('vlan',0)==vid]


def fdb(state,mac,port=None,kind='dynamic',vid=1):
    found=entries(state,mac,vid)
    require(len(found)==int(port is not None),'native locked-port FDB presence changed')
    if port is not None:
        row=found[0]
        require(row.get('ifname')==port and row.get('master')=='br0' and
                row.get('state')==('static' if kind=='static' else '') and
                row.get('flags',[])==(['locked'] if kind=='locked' else []), 'native FDB port/VID/locked/authentication state changed')


def fdb_absent_or_locked(state,mac,port,vid=1):
    all_rows=[row for row in state['fdb'] if row.get('mac')==mac]
    found=entries(state,mac,vid)
    require(len(all_rows)<=1 and len(found)==len(all_rows),
            'native locked-port prelearned FDB entry duplicated or on wrong VID')
    if found:
        fdb(state,mac,port,'locked',vid)


def topology(state):
    devices=links(state);data=devices['br0']['linkinfo']['info_data']
    require(devices['br0']['linkinfo']['info_kind']=='bridge' and 'UP' in devices['br0']['flags'] and
            data['vlan_filtering']==1 and data['vlan_protocol']=='802.1Q', 'actual locked-port bridge missing')
    tables=[]
    for host,port,vrf,n in (('veth0','veth1','vveth0',1),('veth3','veth2','vveth3',2)):
        require(devices[host]['linkinfo']['info_kind']==devices[port]['linkinfo']['info_kind']=='veth' and
                devices[host]['link']==port and devices[port]['link']==host and devices[host].get('master')==vrf and
                devices[port].get('master')=='br0' and devices[port]['linkinfo']['info_slave_data']['state']=='forwarding' and
                all('UP' in devices[k]['flags'] for k in (host,port,vrf)), 'actual locked-port native path changed')
        require(devices[vrf]['linkinfo']['info_kind']=='vrf','native locked-port VRF missing');tables.append(devices[vrf]['linkinfo']['info_data']['table'])
        vlan=devices[host+'.100']
        require(vlan.get('link')==host and vlan.get('master')==vrf and vlan['linkinfo']['info_kind']=='vlan' and
                vlan['linkinfo']['info_data']['id']==100 and vlan['linkinfo']['info_data']['protocol']=='802.1Q' and
                'UP' in vlan['flags'], 'actual host VLAN100/VRF missing')
        for name,expected in ((host,((f'192.0.2.{n}',24),(f'2001:db8:1::{n}',64))), (host+'.100',((f'198.51.100.{n}',24),))):
            addresses=next(r for r in state['addresses'] if r['ifname']==name)['addr_info']
            require(all(any(a.get('local')==address and a.get('prefixlen')==prefix for a in addresses) for address,prefix in expected),
                    'original locked-port host addresses changed')
    require(len(set(tables))==2,'locked-port native VRFs share table')
    return devices


def traversal(before,after,hops,count=1,size=42):
    a,b=links(before),links(after)
    for dev,direction in hops:
        first,last=a[dev]['stats64'][direction],b[dev]['stats64'][direction]
        require(last['packets']-first['packets']>=count and last['bytes']-first['bytes']>=count*size,
                'native locked-port traffic missing at original observation boundary')


def mirred(objects):
    rows=[r for r in objects if r.get('options',{}).get('handle')==101]
    require(len(rows)==1 and rows[0].get('kind')=='flower' and rows[0].get('protocol')=='all' and rows[0].get('pref')==1,
            'actual native locked-port flower missing')
    options=rows[0]['options'];actions=options.get('actions',[])
    require(options.get('keys')=={} and options.get('not_in_hw') is True and len(actions)==1 and
            actions[0].get('kind')=='mirred' and actions[0].get('mirred_action')=='redirect' and
            actions[0].get('direction')=='egress' and actions[0].get('to_dev')=='veth2' and
            actions[0].get('control_action',{}).get('type')=='stolen', 'actual Linux MIRRED redirect action changed')
    return actions[0]['stats']


def validate_evidence(report):
    original=report.get('original',{});parsed=[re.fullmatch(r'TEST: (.*?)\s+\[ OK \]',line)
        for line in original.get('stdout','').splitlines() if line.startswith('TEST:')]
    require(original.get('returncode')==0 and not original.get('stderr') and len(parsed)==8 and all(parsed) and
            [p[1] for p in parsed]==OUTCOMES and 'SKIP' not in original.get('stdout',''),'incomplete original locked-port default entry')
    tools=report.get('iproute2',{})
    require(tools.get('version')=='6.12.0' and tools.get('archive_sha256')=='bbd141ef7b5d0127cc2152843ba61f274dc32814fa3e0f13e7d07a080bef53d9' and
            bool(report.get('tc_tool',{}).get('sha256')) and report['tc_tool']['sha256']==tools.get('binaries',{}).get('tc') and
            tools.get('source_hashes',{}).get('tc/tc.c')=='e9b2e36053ee6e20f79d44a0cab3e1661300ecf9e9783c5fcd03357aa696a101', 'pinned original locked-port tool provenance missing')
    rows=report['commands'];bridge=[r for r in rows if r['tool']=='bridge'];pings=[r for r in rows if r['arguments'][:2]==['vrf','exec']]
    sends=[r for r in rows if r['tool']=='mausezahn'];tc=[r for r in rows if r['tool']=='tc']
    require(len(pings)==18 and len(sends)==5 and [r['arguments'] for r in tc]==TC,'missing original ping/burst/TC lifecycle')
    host=topology(pings[0]['unaware_before'])['veth0']['address']
    expected_bridge=[[host if word=='$HOST' else word for word in line.split()] for line in BRIDGE_PHASE.splitlines() if line]
    require([r['arguments'] for r in bridge]==expected_bridge,'original locked-port/MAB command phases changed')
    outcomes=[0,1,0,0]*3+[0,1,1,0,0,1]
    for i,row in enumerate(pings):
        program='ping6' if 4<=i<8 else 'ping';destination='2001:db8:1::2' if program=='ping6' else '198.51.100.2' if 8<=i<12 else '192.0.2.2'
        require(row['arguments']==['vrf','exec','vveth0',program,'-c','10','-i','0.1','-w','5',destination] and
                row['returncode']==outcomes[i] and not row['stderr'] and ('10 received' if outcomes[i]==0 else '0 received') in row['stdout'] and
                row.get('native_clock_reads',0)>0 and row['vrf']['ifname']=='vveth0','original locked-port reachability/arguments/clock changed')
        a,b=topology(row['unaware_before']),topology(row['unaware_after']);flags=a['veth1']['linkinfo']['info_slave_data']
        require([flags[k] for k in ('learning','locked','mab')]==
                ([False,i%4 in (1,2),False] if i<12 else [[False,False,False],[True,True,False],[True,True,True],[True,True,True],[True,True,True],[True,True,True]][i-12]),
                'actual lock/learning/MAB reachability phase changed')
        require([a['veth2']['linkinfo']['info_slave_data'][k] for k in ('learning','locked','mab')]==[True,False,False],
                'original destination port admission flags changed')
        vid=100 if 8<=i<12 else 1
        if i in (2,6,10,15):fdb(row['unaware_before'],host,'veth1','static',vid)
        elif i==14:fdb_absent_or_locked(row['unaware_before'],host,'veth1',vid)
        else:fdb(row['unaware_before'],host,None,vid=vid)
        if i==14 or i==17:fdb(row['unaware_after'],host,'veth1','locked')
        if i==13 or i==16:fdb(row['unaware_after'],host)
        for port in ('veth1','veth2'):
            vlans=next(r['vlans'] for r in row['unaware_before']['vlans'] if r['ifname']==port)
            require(any(v['vlan']==1 and set(v.get('flags',[]))=={'PVID','Egress Untagged'} for v in vlans) and
                    any(v['vlan']==100 for v in vlans)==(8<=i<12),'native VLAN100 admission/PVID phase changed')
        if outcomes[i]==0:
            traversal(row['unaware_before'],row['unaware_after'],[(n,d) for n,d in
                (('veth0','tx'),('veth1','rx'),('veth2','tx'),('veth3','rx'),('veth3','tx'),('veth2','rx'),('veth1','tx'),('veth0','rx'))],10,98)
    invalid=[]
    for row in bridge:
        words=row['arguments'];before,after=links(row['unaware_before']),links(row['unaware_after'])
        if words[:2]==['link','set']:
            port=words[3];changes=dict(zip(words[4::2],words[5::2]));a=before[port]['linkinfo']['info_slave_data'];b=after[port]['linkinfo']['info_slave_data']
            if row['returncode']:
                require(row['returncode']==255 and 'must be locked and have learning enabled' in row['stderr'] and
                        all(a[k]==b[k] for k in ('learning','locked','mab')),'invalid MAB configuration silently succeeded/changed native flags');invalid.append(row)
            else:require(all(b[k] is (value=='on') for k,value in changes.items()),'native port flag update ineffective')
        elif words==['-d','link','show']:
            require(row['returncode']==0 and 'locked ' in row['stdout'] and 'mab ' in row['stdout'],'native locked/MAB feature probe skipped')
        elif words[:2] in (['fdb','add'],['fdb','replace']):
            mac=words[2];port=words[words.index('dev')+1];vid=int(words[words.index('vlan')+1]) if 'vlan' in words else 1
            fdb(row['unaware_after'],mac,port,'static',vid)
        elif words[:2]==['fdb','del']:
            mac=words[2];port=words[words.index('dev')+1];vid=int(words[words.index('vlan')+1]) if 'vlan' in words else None
            require(not any(e.get('mac')==mac and e.get('ifname')==port and (vid is None or e.get('vlan',0)==vid) for e in row['unaware_after']['fdb']),
                    'original native FDB deletion ineffective')
        elif words[:2] in (['vlan','add'],['vlan','del']):
            port=words[-1];table=next(r['vlans'] for r in row['unaware_after']['vlans'] if r['ifname']==port)
            require(any(v['vlan']==100 for v in table)==(words[1]=='add'),'native bridge VLAN100 update ineffective')
    require(len(invalid)==2,'both original invalid MAB combinations required')
    queries=[r for r in bridge if r['arguments'][:2]==['fdb','get']]
    expected=[(host,None,'dynamic'),(host,'veth1','locked'),(host,'veth1','static'),(ROAM,'veth1','locked'),
              (ROAM,'veth2','dynamic'),(ROAM,'veth2','dynamic'),(ROAM,'veth2','dynamic'),
              (LOCK1,'veth1','locked'),(LOCK2,'veth2','locked'),(STATIC1,'veth1','static'),(STATIC2,'veth2','static'),
              (LOCK1,None,'dynamic'),(LOCK2,'veth2','locked'),(host,None,'dynamic'),(host,'veth1','locked')]
    require(len(queries)==len(expected),'original locked FDB queries missing')
    for row,(mac,port,kind) in zip(queries,expected):
        fdb(row['unaware_after'],mac,port,kind)
        require(row['arguments']==['fdb','get',mac,'br','br0','vlan','1'] and row['returncode']==(0 if port else 254) and
                ((mac in row['stdout'] and 'dev '+port in row['stdout'] and ('locked' in row['stdout'])==(kind=='locked')) if port else
                 'Fdb entry not found' in row['stderr']), 'original native FDB query result changed')
    macs=(ROAM,ROAM,ROAM,LOCK1,LOCK2);devices=('veth0','veth3','veth0','veth0','veth3');decisive=(queries[3],queries[4],queries[6],queries[7],queries[8])
    packets=report.get('packet_trace',[]);require(len(packets)==25,'all five original five-frame bursts required')
    for i,(row,mac,dev,query) in enumerate(zip(sends,macs,devices,decisive)):
        require(row['arguments']==[dev,'-q','-c','5','-d','100msec','-t','udp','-a',mac,'-b','rand'] and
                row['returncode']==0 and not row['stderr'] and row['finished_monotonic']-row['started_monotonic']>=0.4 and
                rows.index(row)<rows.index(query) and (i==4 or rows.index(query)<rows.index(sends[i+1])), 'original MZ burst/order/spacing changed')
        a=topology(row['unaware_before']);topology(query['unaware_after']);port='veth1' if dev=='veth0' else 'veth2'
        if i in (0,2,3,4):require(all(a[port]['linkinfo']['info_slave_data'][k] is True for k in ('learning','locked','mab')),'native MAB burst ingress flags missing')
        else:require(a[port]['linkinfo']['info_slave_data']['locked'] is False,'roam destination unexpectedly locked')
        traversal(row['unaware_before'],query['unaware_after'],[(dev,'tx'),(port,'rx')],5,42)
        for packet in packets[i*5:i*5+5]:
            frame=bytes.fromhex(packet['frame_hex'])
            require(packet.get('family')==17 and packet.get('ifindex')==a[dev]['ifindex'] and packet.get('length')==packet.get('result')==len(frame) and len(frame)>=42 and
                    frame[6:12].hex()==mac.replace(':','') and frame[12:14]==bytes.fromhex('0800') and frame[14]>>4==4 and frame[23]==17 and
                    (frame[14]&15)*4>=20 and 14+int.from_bytes(frame[16:18],'big')<=len(frame) and
                    int.from_bytes(frame[16:18],'big')==(frame[14]&15)*4+int.from_bytes(frame[14+(frame[14]&15)*4+4:14+(frame[14]&15)*4+6],'big') and
                    int.from_bytes(frame[14+(frame[14]&15)*4+4:14+(frame[14]&15)*4+6],'big')>=8,'native original UDP burst frame/source/interface changed')
    # Disabling MAB must flush only the first port's locked entries, retaining
    # the other port's locked entry and both authenticated static entries.
    flush=next(r for r in bridge if r['arguments']==['link','set','dev','veth1','mab','off'])
    fdb(flush['unaware_before'],LOCK1,'veth1','locked');fdb(flush['unaware_before'],LOCK2,'veth2','locked')
    for key in ('unaware_before','unaware_after'):
        fdb(flush[key],STATIC1,'veth1','static');fdb(flush[key],STATIC2,'veth2','static')
    fdb(flush['unaware_after'],LOCK1);fdb(flush['unaware_after'],LOCK2,'veth2','locked')
    redirect=pings[16];a=mirred(redirect['unaware_before']['filters_by_device']['veth1']);b=mirred(redirect['unaware_after']['filters_by_device']['veth1'])
    require(b['packets']-a['packets']>=10 and b['bytes']-a['bytes']>=840,'actual native MIRRED action did not redirect original ping traffic')
    require(not any(r.get('options',{}).get('handle')==101 for key in ('unaware_before','unaware_after') for r in pings[17][key]['filters_by_device']['veth1']),
            'native redirect filter persisted after original deletion')
    require(rows.index(tc[1])<rows.index(redirect)<rows.index(queries[13])<rows.index(tc[2])<rows.index(pings[17])<rows.index(queries[14]),
            'original redirect/removal/locked learning phase reordered')
    expected_fail=[['link','show','dev','veth0'],['link','show','dev','veth2']]+[r['arguments'] for r in rows if r in pings and r['returncode'] or r in invalid or r in queries and r['returncode']]
    require([r['arguments'] for r in rows if r['returncode']]==expected_fail and all(not r['stderr'] for r in rows if r['returncode']==0),
            'unexpected original locked-port configuration/cleanup failure')
    clean=report['cleanup_state'];devices=links(clean);names=[f'veth{i}' for i in range(4)]
    require(not any(n in devices for n in ('br0','vveth0','vveth3','veth0.100','veth3.100')) and
            all('UP' not in devices[n]['flags'] and 'master' not in devices[n] and devices[n].get('promiscuity',0)==0 for n in names) and
            not any(r.get('master')=='br0' for r in clean['fdb']) and all(not row.get('mdb') and not row.get('router') for row in clean['mdb']),'native locked-port bridge/VRF/VLAN/FDB/MDB leaked')
    require(not any(a.get('scope')=='global' for r in clean['addresses'] if r['ifname'] in names for a in r.get('addr_info',[])) and
            not any(r.get('dev') in (*names,'br0','veth0.100','veth3.100') for family in ('ipv4_routes','ipv6_routes') for r in clean[family]) and
            all(clean[family].strip()=='0' for family in ('ipv4','ipv6')) and not any(r['tool']=='sysctl' for r in rows),'native locked-port address/route/forwarding leaked')
    require(all(sum(r['arguments']==['link','del','dev',n] for r in rows)==1 for n in ('br0','vveth0','vveth3')),'original locked-port teardown missing')
    require(report.get('missing_backend_control',{}).get('returncode') not in (None,0) and
            report.get('vrf_binding_control',{}).get('baseline',{}).get('returncode')==0 and
            report.get('vrf_binding_control',{}).get('unknown_vrf',{}).get('returncode') not in (None,0),'native locked-port boundary control failed')
    native,stats=report.get('native_fixture',{}),report.get('stats',{})
    require(native.get('bridge_packet_sends')==25 and native.get('bridge_packet_bytes')==sum(packet['result'] for packet in packets) and native.get('bridge_packet_trace_errors')==0 and
            native.get('live')==0 and stats.get('outstanding')==0 and stats.get('worker_exit_code')==0 and
            stats.get('control_eof') is True and stats.get('shutdown_timed_out') is False,'native locked-port resources did not stop normally')


# Pinned original command order, with only the actual host MAC substituted.
BRIDGE_PHASE = """link set dev veth1 learning off
-d link show
link set dev veth1 locked on
fdb add $HOST dev veth1 master static
link set dev veth1 locked off
fdb del $HOST dev veth1 master static
-d link show
link set dev veth1 locked on
fdb add $HOST dev veth1 master static
link set dev veth1 locked off
fdb del $HOST dev veth1 master static
-d link show
vlan add vid 100 dev veth1
vlan add vid 100 dev veth2
link set dev veth1 locked on
fdb add $HOST dev veth1 vlan 100 master static
link set dev veth1 locked off
fdb del $HOST dev veth1 vlan 100 master static
vlan del vid 100 dev veth1
vlan del vid 100 dev veth2
-d link show
link set dev veth1 learning on locked on
fdb get $HOST br br0 vlan 1
link set dev veth1 learning on locked on mab on
fdb get $HOST br br0 vlan 1
fdb replace $HOST dev veth1 master static
fdb get $HOST br br0 vlan 1
fdb del $HOST dev veth1 master
link set dev veth1 learning off locked off mab off
-d link show
link set dev veth1 learning on locked on mab on
fdb get a0:b0:c0:c0:b0:a0 br br0 vlan 1
fdb get a0:b0:c0:c0:b0:a0 br br0 vlan 1
fdb get a0:b0:c0:c0:b0:a0 br br0 vlan 1
fdb get a0:b0:c0:c0:b0:a0 br br0 vlan 1
fdb del a0:b0:c0:c0:b0:a0 vlan 1 dev veth2 master
link set dev veth1 learning off locked off mab off
-d link show
link set dev veth1 learning on locked off mab on
link set dev veth1 learning off locked on mab on
link set dev veth1 learning on locked on mab on
link set dev veth1 learning off locked off mab off
-d link show
link set dev veth1 learning on locked on mab on
link set dev veth2 learning on locked on mab on
fdb add 00:01:02:03:04:06 dev veth1 vlan 1 master static
fdb add 00:01:02:03:04:08 dev veth2 vlan 1 master static
fdb get 00:01:02:03:04:05 br br0 vlan 1
fdb get 00:01:02:03:04:07 br br0 vlan 1
link set dev veth1 mab off
fdb get 00:01:02:03:04:06 br br0 vlan 1
fdb get 00:01:02:03:04:08 br br0 vlan 1
fdb get 00:01:02:03:04:05 br br0 vlan 1
fdb get 00:01:02:03:04:07 br br0 vlan 1
fdb del 00:01:02:03:04:08 dev veth2 vlan 1 master static
fdb del 00:01:02:03:04:06 dev veth1 vlan 1 master static
link set dev veth2 learning on locked off mab off
link set dev veth1 learning off locked off mab off
-d link show
link set dev veth1 learning on locked on mab on
fdb get $HOST br br0 vlan 1
fdb get $HOST br br0 vlan 1
fdb del $HOST vlan 1 dev veth1 master
link set dev veth1 learning off locked off mab off"""
