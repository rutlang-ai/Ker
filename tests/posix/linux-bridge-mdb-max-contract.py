"""Independent complete original MDB limit/accounting evidence.

Count-derived limits and cross-VLAN branch choices are checked against the
original native queries, rather than fixing incidental background memberships.
"""
from collections import Counter
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import re

spec=importlib.util.spec_from_file_location('mdb_api',Path(__file__).with_name('linux-bridge-mdb-contract.py'))
mdb=importlib.util.module_from_spec(spec);spec.loader.exec_module(mdb)
require=mdb.require
entries=mdb.entries
scalar=mdb.scalar
links=mdb.links
address=mdb.address

LABELS = ['cfg4: port: ngroups reporting', 'ctl4: port: ngroups reporting', 'cfg6: port: ngroups reporting', 'ctl6: port: ngroups reporting', 'cfg4: port maxgroups: reporting and treatment of 0', 'cfg4: port maxgroups: configure below ngroups', 'cfg4: port maxgroups: add too many MDB entries', 'ctl4: port maxgroups: reporting and treatment of 0', 'ctl4: port maxgroups: configure below ngroups', 'ctl4: port maxgroups: add too many MDB entries', 'cfg6: port maxgroups: reporting and treatment of 0', 'cfg6: port maxgroups: configure below ngroups', 'cfg6: port maxgroups: add too many MDB entries', 'ctl6: port maxgroups: reporting and treatment of 0', 'ctl6: port maxgroups: configure below ngroups', 'ctl6: port maxgroups: add too many MDB entries', 'port_vlan: presence of ngroups and maxgroups attributes', 'cfg4: port: ngroups reporting', 'ctl4: port: ngroups reporting', 'cfg6: port: ngroups reporting', 'ctl6: port: ngroups reporting', 'cfg4: port maxgroups: reporting and treatment of 0', 'cfg4: port maxgroups: configure below ngroups', 'cfg4: port maxgroups: add too many MDB entries', 'ctl4: port maxgroups: reporting and treatment of 0', 'ctl4: port maxgroups: configure below ngroups', 'ctl4: port maxgroups: add too many MDB entries', 'cfg6: port maxgroups: reporting and treatment of 0', 'cfg6: port maxgroups: configure below ngroups', 'cfg6: port maxgroups: add too many MDB entries', 'ctl6: port maxgroups: reporting and treatment of 0', 'ctl6: port maxgroups: configure below ngroups', 'ctl6: port maxgroups: add too many MDB entries', 'port_vlan: presence of ngroups and maxgroups attributes', 'cfg4: port_vlan: ngroups reporting', 'cfg4: port_vlan: isolation of port and per-VLAN ngroups', 'ctl4: port_vlan: ngroups reporting', 'ctl4: port_vlan: isolation of port and per-VLAN ngroups', 'cfg6: port_vlan: ngroups reporting', 'cfg6: port_vlan: isolation of port and per-VLAN ngroups', 'ctl6: port_vlan: ngroups reporting', 'ctl6: port_vlan: isolation of port and per-VLAN ngroups', 'cfg4: port_vlan maxgroups: reporting and treatment of 0', 'cfg4: port_vlan maxgroups: isolation of port and per-VLAN maximums', 'cfg4: port_vlan maxgroups: configure below ngroups', 'cfg4: port_vlan maxgroups: add too many MDB entries', 'cfg4: port_vlan maxgroups: isolation of port and per-VLAN ngroups', 'ctl4: port_vlan maxgroups: reporting and treatment of 0', 'ctl4: port_vlan maxgroups: isolation of port and per-VLAN maximums', 'ctl4: port_vlan maxgroups: configure below ngroups', 'ctl4: port_vlan maxgroups: add too many MDB entries', 'ctl4: port_vlan maxgroups: isolation of port and per-VLAN ngroups', 'cfg6: port_vlan maxgroups: reporting and treatment of 0', 'cfg6: port_vlan maxgroups: isolation of port and per-VLAN maximums', 'cfg6: port_vlan maxgroups: configure below ngroups', 'cfg6: port_vlan maxgroups: add too many MDB entries', 'cfg6: port_vlan maxgroups: isolation of port and per-VLAN ngroups', 'ctl6: port_vlan maxgroups: reporting and treatment of 0', 'ctl6: port_vlan maxgroups: isolation of port and per-VLAN maximums', 'ctl6: port_vlan maxgroups: configure below ngroups', 'ctl6: port_vlan maxgroups: add too many MDB entries', 'ctl6: port_vlan maxgroups: isolation of port and per-VLAN ngroups', 'cfg4: port_vlan: temp: mcast_vlan_snooping toggle', 'cfg4: port_vlan: permanent: mcast_vlan_snooping toggle']
NEGATIVE = [0, 2, 8, 91, 98, 139, 146, 236, 243, 284, 291, 459, 466, 474, 476, 477, 578, 585, 593, 595, 596, 696, 697]

CROSS = [(469,482),(530,550),(588,601),(649,669)]
LOW = {90,112,138,160,235,257,283,305,458,512,577,631}
MANY = {97,123,145,171,242,268,290,316,465,523,584,642}
VLAN_CAP = {473:472,535:534,592:591,654:653}
PORT_CAP = {475:(469,470,472),538:(530,531,534),594:(588,589,591),657:(649,650,653)}
DERIVED = LOW | MANY | set(VLAN_CAP) | set(PORT_CAP)


def query_object(row):
    objects=json.loads(row['stdout'])
    require(row['returncode']==0 and not row['stderr'] and len(objects)==1, 'original limit query missing/duplicated/failed')
    if row['arguments'][2]=='vlan':
        require(len(objects[0]['vlans'])==1, 'original limit VLAN query ambiguous')
        return objects[0]['vlans'][0]
    return objects[0]


def normalized(rows):
    result=[]; contexts={}
    for start,end in CROSS:
        a=query_object(rows[start])['mcast_n_groups'];b=query_object(rows[start+1])['mcast_n_groups']
        lo,hi=(10,20) if a<=b else (20,10)
        for i in range(start+2,end+1):contexts[i]={str(lo):'<lower-count-VID>',str(hi):'<higher-count-VID>'}
    for i,row in enumerate(rows):
        args=row['arguments'][:]
        if i in DERIVED:args[-1]='<original-count-derived-limit>'
        if i in contexts:
            mapping=contexts[i]
            if 'vid'in args:args[args.index('vid')+1]=mapping[args[args.index('vid')+1]]
            for j,value in enumerate(args):
                if value in ('veth0.10','veth0.20'):args[j]='veth0.'+mapping[value.split('.')[1]]
        if i in (474,593):args[-1]='<original-count-derived-source-list>'
        if i in (536,655):args[args.index('-t')+2]='<original-count-derived-control-report>'
        result.append([row['tool'],args])
    return hashlib.sha256(json.dumps(result,separators=(',',':')).encode()).hexdigest()


def limits(state):
    result={}
    for row in state['port_details']:
        if row.get('master')=='br0':result[(row['ifname'],0)]=row['mcast_max_groups']
    bridge=links(state).get('br0')
    active=bridge and bridge['linkinfo']['info_data']['mcast_vlan_snooping']==1
    for port in state['vlan_details']:
        if port['ifname'] not in ('veth1','veth2'):continue
        for vlan in port['vlans']:
            if active:
                require('mcast_n_groups'in vlan and 'mcast_max_groups'in vlan, 'native per-VLAN group attributes missing')
                result[(port['ifname'],vlan['vlan'])]=vlan['mcast_max_groups']
            else:
                require('mcast_n_groups'not in vlan and 'mcast_max_groups'not in vlan, 'disabled VLAN snooping exposed group attributes')
    return result


def validate_queries(row):
    obj=query_object(row);args=row['arguments'];port=scalar(args,'dev');state=row['mdb_max_after']
    vid=int(scalar(args,'vid')) if args[2]=='vlan' else None
    records=[r for r in entries(state['mdb']) if r['port']==port and (vid is None or r.get('vid',0)==vid)]
    if obj.get('mcast_n_groups') is not None:
        require(obj['mcast_n_groups']==len(records), 'original native group count disagrees with complete MDB entries')
        require(obj['mcast_max_groups']==limits(state)[(port,vid or 0)], 'original native maximum query differs from actual state')
    else:
        require(vid is not None and 'mcast_max_groups'not in obj and not links(state)['br0']['linkinfo']['info_data']['mcast_vlan_snooping'],
                'original absent VLAN attribute boundary changed')


def validate_setters(rows):
    previous_counts={}
    for i,row in enumerate(rows):
        args=row['arguments']
        if row['tool']=='bridge' and args[:4] in (['-j','-d','link','show'],['-j','-d','vlan','show']):
            validate_queries(row)
            obj=query_object(row)
            if 'mcast_n_groups'in obj:previous_counts[(scalar(args,'dev'),int(scalar(args,'vid','0')) if args[2]=='vlan' else 0)]=obj['mcast_n_groups']
        if 'mcast_max_groups'not in args:continue
        port=scalar(args,'dev');vid=int(scalar(args,'vid','0'));value=int(args[-1]);key=(port,vid)
        if i in LOW:require(value==previous_counts[key]+2, 'original below-current maximum was not n+2')
        elif i in MANY:require(value==previous_counts[key]+1, 'original restrictive maximum was not n+1')
        elif i in VLAN_CAP:require(value==query_object(rows[VLAN_CAP[i]])['mcast_n_groups']-1, 'original cross-VLAN cap was not n2-1')
        elif i in PORT_CAP:
            a,b,c=PORT_CAP[i]
            require(value==min(query_object(rows[a])['mcast_n_groups'],query_object(rows[b])['mcast_n_groups'])+query_object(rows[c])['mcast_n_groups']+2,
                    'original total port cap was not n1+n2+2')
        else:require(value in (0,100), 'original literal zero/unlimited or 100 limit changed')
        before=limits(row['mdb_max_before']);after=limits(row['mdb_max_after'])
        require(row['returncode']==0 and not row['stderr'] and key in before and key in after and after[key]==value and
                all(after[k]==v for k,v in before.items() if k!=key), 'native limit setter ignored request or changed another locus')


def validate_evidence(report):
    original=report['original'];results=[re.fullmatch(r'TEST: (.*?)\s+\[ OK \]',x) for x in original['stdout'].splitlines() if x.startswith('TEST:')]
    require(original['returncode']==0 and not original['stderr'] and len(results)==64 and all(results) and [x[1]for x in results]==LABELS and
            'SKIP'not in original['stdout'] and '[FAIL]'not in original['stdout'], 'complete unchanged original MDB limit outcomes missing')
    rows=report['commands']
    require(len(rows)==718 and normalized(rows)==COMMAND_SHA, 'original MDB limit command/source-derived phase sequence changed')
    require([i for i,x in enumerate(rows)if x['returncode']]==NEGATIVE, 'original MDB admission/rejection or cleanup verdict changed')
    timed=[x for x in rows if x['tool']!='sysctl']
    require(all(x['finished_monotonic']>=x['started_monotonic']for x in timed) and
            all(b['started_monotonic']>=a['finished_monotonic']for a,b in zip(timed,timed[1:])), 'original MDB limits chronology changed')
    require(all(x['returncode'] or not x['stderr']for x in rows), 'successful original MDB limit command warned')
    bridge=[x for x in rows if x['tool']=='bridge']
    require(len(bridge)==506 and all(isinstance(x.get('mdb_max_before'),dict) and isinstance(x.get('mdb_max_after'),dict)for x in bridge),
            'complete native MDB limit observations missing')
    validate_setters(rows)
    groups={address(scalar(x['arguments'],'grp'))for x in rows if x['tool']=='bridge' and 'grp'in x['arguments']}
    api=[x for x in rows if 'mdb_api_after'in x]
    require(len(api)==84, 'original MDB limit API matrix incomplete')
    for row in api:
        br=links(row['mdb_max_before'])['br0'];implicit=(10,20) if br['linkinfo']['info_data']['vlan_filtering'] else (0,)
        mdb.api_evidence(row,groups,br['ifindex'],implicit)
    validate_admission(rows,groups)
    for row in bridge:
        if row['arguments']==['mdb','show','dev','br0']:validate_text_dump(row)
    validate_traffic(report,rows,groups)
    validate_toggles(rows,groups)
    mdb.validate_boundaries(report,rows,88)

COMMAND_SHA = '435bbad4fc2d54b83666ebb0ce3df87538f2672e9cfde568039e46ee6e6ba0a2'


def validate_admission(rows,groups):
    for position,query in ((474,472),(593,591)):
        n=query_object(rows[query])['mcast_n_groups'];args=rows[position]['arguments'];six=':'in scalar(args,'grp')
        require(scalar(args,'source_list')==','.join(f'2001:db8:1::{j:x}'if six else f'192.0.2.{j}'for j in range(1,n)),
                'original count-derived configuration source list changed')
    for row in rows:
        args=row['arguments']
        if row['tool']!='bridge' or args[:2]!=['mdb','add']:continue
        state=row['mdb_max_before'];caps=limits(state);port=scalar(args,'port');vid=int(scalar(args,'vid','0'))
        current=[e for e in entries(state['mdb']) if e['port']==port]
        wanted=1+len(scalar(args,'source_list','').split(',')) if 'source_list'in args else 1
        existing=[e for e in current if e['grp']==scalar(args,'grp') and e.get('vid',0)==vid]
        delta=max(0,wanted-len(existing))
        rejected=any(cap and sum(v==0 or e.get('vid',0)==v for e in current)+delta>cap
                     for (p,v),cap in caps.items() if p==port and v in (0,vid))
        require(bool(row['returncode'])==rejected, 'native MDB admission differs from actual port/VLAN capacity')
        if rejected:require('mcast_max_groups'in row['stderr'], 'native MDB rejection lacks original limit extack')


def validate_text_dump(row):
    actual=[]
    for line in row['stdout'].splitlines():
        words=line.split()
        require(words[:2]==['dev','br0'] and 'port'in words and 'grp'in words and
                any(x in words for x in ('temp','permanent')), 'original native MDB text dump malformed')
        actual.append((scalar(words,'port'),address(scalar(words,'grp')),scalar(words,'src'),
                       int(scalar(words,'vid','0')),'permanent' if 'permanent'in words else 'temp'))
    wanted=[(e['port'],address(e['grp']),e.get('src'),e.get('vid',0),e['state'])for e in entries(row['mdb_max_after']['mdb'])]
    require(row['returncode']==0 and not row['stderr'] and Counter(actual)==Counter(wanted),
            'original native MDB text count oracle differs from actual complete entries')


def topology(state,filtered,vlan_snooping):
    devices=links(state);br=devices['br0'];info=br['linkinfo']['info_data']
    require(br['linkinfo']['info_kind']=='bridge' and 'UP'in br['flags'] and info['vlan_filtering']==int(filtered) and
            info['vlan_default_pvid']==(0 if filtered else 1) and info['mcast_snooping']==1 and
            info['mcast_vlan_snooping']==int(vlan_snooping) and info['mcast_igmp_version']==3 and info['mcast_mld_version']==2 and info['mcast_querier']==0,
            'native MDB limit bridge/version/VLAN topology changed')
    tables=[]
    for host,port in (('veth0','veth1'),('veth3','veth2')):
        vrf='v'+host;tables.append(devices[vrf]['linkinfo']['info_data']['table'])
        require(devices[host].get('master')==vrf and devices[host]['link']==port and devices[port]['link']==host and
                devices[port].get('master')=='br0' and devices[port]['linkinfo']['info_slave_data']['state']=='forwarding' and
                all('UP'in devices[n]['flags']for n in (host,port,vrf)), 'native MDB limits peer/VRF path changed')
        for vid in (10,20):
            child=devices[f'{host}.{vid}']
            require(child['link']==host and child.get('master')==vrf and child['linkinfo']['info_kind']=='vlan' and
                    child['linkinfo']['info_data']['id']==vid and child['linkinfo']['info_data']['protocol']=='802.1Q' and
                    'UP'in child['flags'], 'original native MDB limits host VLAN missing')
            number=1 if host=='veth0' else 2
            expected=f'192.0.2.{number}'if vid==10 else f'198.51.100.{number}'
            addresses=next(r['addr_info']for r in state['addresses']if r['ifname']==f'{host}.{vid}')
            require(any(a.get('local')==expected and a.get('prefixlen')==(28 if vid==10 else 24)for a in addresses),
                    'original native MDB limits VLAN IPv4 address changed')
            if host=='veth0':require(any(a.get('local')==f'2001:db8:{1 if vid==10 else 2}::1' and a.get('prefixlen')==64 for a in addresses),
                    'original native MDB limits sender IPv6 address changed')
    require(len(set(tables))==2 and devices['veth1']['linkinfo']['info_slave_data']['fastleave'] is True,
            'native MDB limits VRF separation/fastleave changed')
    for name in ('br0','veth1','veth2'):
        vlans=next(x['vlans']for x in state['vlans']if x['ifname']==name)
        require({v['vlan']for v in vlans}==({10,20}if filtered else {1}) and
                all((not set(v.get('flags',[])) & {'PVID','Egress Untagged'})if filtered else
                    set(v.get('flags',[]))=={'PVID','Egress Untagged'}for v in vlans), 'native limits VLAN membership changed')
    return devices


def control_packet(sender,packet,devices):
    args=sender['arguments'];six=args[0]=='-6';interface=args[1]if six else args[0]
    frame=bytes.fromhex(packet['frame_hex']);payload_offset=54 if six else 34
    require(packet['family']==17 and packet['ifindex']==devices[interface]['ifindex'] and
            packet['result']==packet['length']==len(frame) and frame[:6].hex()==scalar(args,'-b').replace(':','') and
            frame[6:12].hex()==devices[interface]['address'].replace(':',''), 'actual native MDB limits control frame/interface/MAC changed')
    payload=bytes.fromhex(args[args.index('-t')+2].split(',p=',1)[1].replace(':',''))
    require(scalar(args,'-t')=='ip' and frame[payload_offset:]==payload, 'actual MDB limits frame differs from original literal payload')
    if six:
        require(frame[12:15]==bytes.fromhex('86dd60') and int.from_bytes(frame[18:20],'big')==len(frame)-54 and
                frame[20:22]==b'\0\1' and frame[22:38]==ipaddress.IPv6Address(scalar(args,'-A')).packed and
                frame[38:54]==ipaddress.IPv6Address(scalar(args,'-B')).packed and
                frame[54:62]==bytes.fromhex('3a00000000000000') and mdb.ipv6_checksum(frame,58,frame[62:]),
                'original MLD limits header/checksum/HBH changed')
        data=frame[62:];join=data[0]==143;require(data[0]in (132,143)and data[1]==0, 'original MLD report/done type changed')
        if join:
            require(data[4:8]==b'\0\0\0\1' and data[8:10]==b'\1\0', 'original MLD IS_IN record changed')
            n=int.from_bytes(data[10:12],'big');require(len(data)==28+16*n, 'original MLD source count differs from actual bytes')
            group=str(ipaddress.IPv6Address(data[12:28]));sources=[str(ipaddress.IPv6Address(data[i:i+16]))for i in range(28,len(data),16)]
        else:
            require(len(data)==24 and data[4:8]==b'\0'*4, 'original MLD done payload changed')
            group=str(ipaddress.IPv6Address(data[8:24]));sources=[]
    else:
        require(frame[12:15]==bytes.fromhex('080045') and int.from_bytes(frame[16:18],'big')==len(frame)-14 and frame[23]==2 and
                frame[26:30]==ipaddress.IPv4Address(scalar(args,'-A')).packed and
                frame[30:34]==ipaddress.IPv4Address(scalar(args,'-B')).packed and
                mdb.checksum(frame[14:34]) and mdb.checksum(frame[34:]), 'original IGMP limits header/checksum changed')
        data=frame[34:];join=data[0]==34;require(data[0]in (23,34)and data[1]==0, 'original IGMP report/leave type changed')
        if join:
            require(data[4:8]==b'\0\0\0\1' and data[8:10]==b'\1\0', 'original IGMP IS_IN record changed')
            n=int.from_bytes(data[10:12],'big');require(len(data)==16+4*n, 'original IGMP source count differs from actual bytes')
            group=str(ipaddress.IPv4Address(data[12:16]));sources=[str(ipaddress.IPv4Address(data[i:i+4]))for i in range(16,len(data),4)]
        else:
            require(len(data)==8, 'original IGMP leave payload changed');group=str(ipaddress.IPv4Address(data[4:8]));sources=[]
    if join:require(group==scalar(args,'-B'), 'original control membership group differs from destination')
    return interface,frame,group,sources,join


def validate_traffic(report,rows,groups):
    traffic=[(i,x)for i,x in enumerate(rows)if x['tool']=='mausezahn'];packets=report['packet_trace']
    require(len(traffic)==len(packets)==88, 'complete original MDB limits packet inventory missing')
    for number,((position,sender),packet)in enumerate(zip(traffic,packets)):
        before=sender['sg_before'];devices=topology(before,position>=184,position>=329)
        interface,frame,group,sources,join=control_packet(sender,packet,devices)
        query=rows[position+1]
        require(query['tool']=='bridge' and query['arguments']==['mdb','show','dev','br0'] and
                query['started_monotonic']-sender['finished_monotonic']>=1,
                'original complete control observation/wait missing')
        after=query['mdb_max_after'];vid=int(interface.split('.')[1])if '.'in interface and position>=184 else 0
        earlier=next(x['mdb_max_after']for x in reversed(rows[:position])if 'mdb_max_after'in x)
        caps=limits(earlier);old_all=entries(before['mdb']);new_all=entries(after['mdb'])
        def selected(e):return e['port']=='veth1' and e.get('vid',0)==vid and e['grp']==group
        old=[e for e in old_all if selected(e)];new=[e for e in new_all if selected(e)]
        require(mdb.state_keys([dict(mdb=[e for e in old_all if not selected(e)])],groups)==
                mdb.state_keys([dict(mdb=[e for e in new_all if not selected(e)])],groups),
                'control admission changed another native group/port/VLAN')
        if position in (536,655):
            query_index={536:534,655:653}[position];n=query_object(rows[query_index])['mcast_n_groups']
            require(sources==[f'2001:db8:1::{j:x}'if ':'in group else f'192.0.2.{j}'for j in range(1,n)],
                    'original count-derived control source list changed')
        if not join:require(not new, 'native fastleave did not remove the actual control group')
        else:
            old_sources={e['src']for e in old if 'src'in e};new_sources={e['src']for e in new if 'src'in e}
            space=[cap-sum(e['port']==p and (v==0 or e.get('vid',0)==v)for e in old_all)
                   for (p,v),cap in caps.items()if p=='veth1' and v in (0,vid) and cap]
            budget=max(0,min(space))if space else len(sources)+1
            create_parent=not any('src'not in e for e in old)
            accepted=min(len(set(sources)-old_sources),max(0,budget-int(create_parent)))
            parent=[e for e in new if 'src'not in e]
            require(len(parent)==int(bool(old)or budget>0) and old_sources<=new_sources<=old_sources|set(sources) and
                    len(new_sources)==len(old_sources)+accepted, 'native partial report admission violates actual source capacity')
            if parent:
                # Linux can retain logical source-list nodes even when the
                # group limit refuses their S,G forwarding entries. Validate
                # both representations and their distinct capacity semantics.
                e=parent[0]
                require(e['filter_mode']=='include' and e['state']=='temp' and e['protocol']=='kernel' and not e['flags'] and
                        {s['address']for s in e.get('source_list',[])}==set(sources)|{s['address']for p in old if 'src'not in p for s in p.get('source_list',[])} and
                        all(float(s['timer'])>0 for s in e.get('source_list',[])), 'native admitted wildcard/source-list state changed')
                require(len(new)==1+len(new_sources) and all(e['filter_mode']=='include' and e['state']=='temp' and
                        e['protocol']=='kernel' and not e['flags']for e in new), 'native control S,G state/ownership changed')
        for name,direction in ((interface,'tx'),('veth0','tx'),('veth1','rx')):
            a=devices[name]['stats64'][direction];b=links(after)[name]['stats64'][direction]
            require(b['packets']-a['packets']>=1 and b['bytes']-a['bytes']>=len(frame),
                    'original native control frame did not traverse the actual host/bridge port')


def validate_toggles(rows,groups):
    toggles=[x for x in rows if x['tool']=='ip' and 'mcast_vlan_snooping'in x['arguments'] and x['arguments'][:2]==['link','set']]
    require([x['arguments']for x in toggles]==[['link','set','dev','br0','type','bridge','mcast_vlan_snooping',str(n)]for n in (0,1,0,1)],
            'complete original temporary/permanent VLAN snooping toggles missing')
    for row in toggles:
        before,after=row['sg_before'],row['sg_after'];enabled=int(row['arguments'][-1])
        require(links(after)['br0']['linkinfo']['info_data']['mcast_vlan_snooping']==enabled,
                'actual native VLAN snooping switch ignored')
        survivors=[e for e in entries(before['mdb']) if e['grp']in groups and (enabled or e['state']=='permanent')]
        require(mdb.state_keys([dict(mdb=survivors)],groups)==mdb.state_keys(after['mdb'],groups),
                'native VLAN snooping toggle lost permanent or retained temporary groups')
        if enabled:
            previous=rows[rows.index(row)-1]
            require(row['started_monotonic']-previous['finished_monotonic']>=1, 'original snooping toggle wait shortened')
            following=rows[rows.index(row)+1:rows.index(row)+4]
            queries=[x for x in following if x['arguments'][:4]==['-j','-d','vlan','show']]
            require(len(queries)==2 and all(query_object(x)['mcast_max_groups']==100 for x in queries),
                    'original per-VLAN maximum did not survive snooping toggle')
            require(query_object(queries[0])['mcast_n_groups']==sum(e['port']=='veth1'for e in entries(queries[0]['mdb_max_after']['mdb'])),
                    'original restored per-VLAN group accounting differs from actual port entries')
