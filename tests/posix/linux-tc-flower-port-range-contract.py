"""Original inclusive TC port ranges, ingress pass and egress drop evidence."""
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import re

spec=importlib.util.spec_from_file_location('pedit_ip',Path(__file__).with_name('linux-pedit-ip-contract.py'))
ip=importlib.util.module_from_spec(spec);spec.loader.exec_module(ip)
require=ip.require
PORTS=((100,300),(150,350),(200,400),(99,300),(201,300),(100,299),(100,401),(201,401))


def normalized(rows):
    result=[]
    for row in rows:
        args=row['arguments'][:]
        if row['tool']=='mausezahn':
            args[args.index('-a')+1]='<native-h1-MAC>';args[args.index('-b')+1]='<native-h2-MAC>'
        item=[row['tool'],args]
        if result and item==result[-1]and row['tool']=='tc'and args[:4]==['-j','-s','filter','show']:continue
        result.append(item)
    return hashlib.sha256(json.dumps(result,separators=(',',':')).encode()).hexdigest()


def flower(rows,family,protocol,drop,count):
    require(len(rows)==2 and sum('options'in r for r in rows)==1,'native port-range rule missing/duplicated/polluted')
    row=next(r for r in rows if 'options'in r);options=row['options'];actions=options['actions']
    src='192.0.2.1'if family==4 else'2001:db8:1::1';dst='192.0.2.2'if family==4 else'2001:db8:1::2'
    keys=dict(eth_type='ipv'+str(family),ip_proto=protocol,src_ip=src,dst_ip=dst,
              src_port=dict(start=100,end=200),dst_port=dict(start=300,end=400))
    require(row['protocol']==('ip'if family==4 else'ipv6')and row['pref']==1 and row['chain']==0 and row['kind']=='flower'and
            options['handle']==101 and options.get('not_in_hw')is True and options['keys']==keys and len(actions)==1,
            'native inclusive port range/address/protocol/software classifier changed')
    action=actions[0];verdict='drop'if drop else'pass';size=(142 if protocol=='udp'else 154)+(20 if family==6 else 0)
    require(action['order']==1 and action['kind']=='gact'and action['control_action']=={'type':verdict}and
            action['ref']==action['bind']==1 and action['prob']=={'random_type':'none','control_action':{'type':'pass'},'val':0},
            'native port-range action/binding changed')
    stats=action['stats']
    require(stats['packets']==count and stats['bytes']==count*(size if drop else size-14)and stats['drops']==(count if drop else 0)and
            all(stats[k]==0 for k in ('overlimits','requeues','backlog','qlen')),'native exact port-range packet/byte/drop counters changed')


def filters(state,family,protocol,count,active):
    return filters_bounded(state,family,protocol,count,count,active)


def bounded_flower(rows,family,protocol,drop,minimum,maximum):
    require(len(rows)==2 and sum('options'in r for r in rows)==1,'native port-range rule missing/duplicated/polluted')
    rule=next(r for r in rows if 'options'in r);actions=rule['options']['actions']
    require(len(actions)==1,'native port-range action missing/duplicated')
    count=actions[0]['stats']['packets']
    require(type(count)is int and minimum<=count<=maximum,
            'native port-range counter regressed or exceeded the original polling target')
    flower(rows,family,protocol,drop,count)
    return count


def filters_bounded(state,family,protocol,minimum,maximum,active):
    counts={}
    for key,rows in ip.all_filters(state).items():
        if key in active:
            counts[key]=bounded_flower(rows,family,protocol,key[1]=='egress',minimum,maximum)
        else:require(rows==[],'native port-range classifier leaked onto another locus')
    require(set(counts)==set(active),'native port-range ingress/egress polling loci missing')
    return counts


def validate_evidence(report):
    original=report['original'];labels=['Port range matching - '+x for x in ('IPv4 UDP','IPv4 TCP','IPv6 UDP','IPv6 TCP')]
    parsed=[re.fullmatch(r'TEST: (.*?)\s+\[ OK \]',x)for x in original['stdout'].splitlines()if x.startswith('TEST:')]
    require(original['returncode']==0 and not original['stderr']and len(parsed)==4 and all(parsed)and
            [x[1]for x in parsed]==labels and 'SKIP'not in original['stdout']and '[FAIL]'not in original['stdout'],
            'complete unchanged original port-range outcomes missing')
    rows=report['commands'];require(normalized(rows)==COMMAND_SHA,'original port-range commands/phases changed')
    require([i for i,x in enumerate(rows)if x['returncode']]==[0,2]and all(not x['stderr']for x in rows if not x['returncode']),
            'native port-range probe/setup/cleanup verdict changed')
    timed=[x for x in rows if x['tool']in('tc','mausezahn')]
    require(all(isinstance(x.get('range_before'),dict)and isinstance(x.get('range_after'),dict)for x in timed)and
            all(x['finished_monotonic']>=x['started_monotonic']for x in timed)and
            all(b['started_monotonic']>=a['finished_monotonic']for a,b in zip(timed,timed[1:])),
            'native port-range command observations/chronology missing')
    traffic=[x for x in rows if x['tool']=='mausezahn'];require(len(traffic)==len(report['packet_trace'])==32,'complete original port-range packet matrix missing')
    ingress=('veth1','ingress');egress=('veth2','egress');active=(ingress,egress)
    for group,(family,protocol)in enumerate(((4,'udp'),(4,'tcp'),(6,'udp'),(6,'tcp'))):
        senders=traffic[group*8:(group+1)*8];start=rows.index(senders[0]);a,b=rows[start-2:start]
        for state,loci in ((a['range_before'],()),(a['range_after'],(ingress,)),(b['range_before'],(ingress,)),(b['range_after'],active)):
            filters(state,family,protocol,0,loci)
        source=ip.topology(senders[0]['range_before'],vlan_filtering=0)['veth0'];dest=ip.links(senders[0]['range_before'])['veth3']
        size=(142 if protocol=='udp'else 154)+(20 if family==6 else 0)
        queries=[]
        for phase,(sender,(sport,dport))in enumerate(zip(senders,PORTS)):
            devices=ip.topology(sender['range_before'],vlan_filtering=0);ip.topology(sender['range_after'],vlan_filtering=0)
            previous=min(phase,3);target=min(phase+1,3)if phase in(0,1,2)else 3
            filters(sender['range_before'],family,protocol,previous,active)
            if phase in(0,1,2):
                observed_counts=filters_bounded(sender['range_after'],family,protocol,previous,target,active)
            else:
                filters(sender['range_after'],family,protocol,target,active)
            i=rows.index(sender);last=i+1;observed=[]
            while last<len(rows)and rows[last]['tool']=='tc'and rows[last]['arguments'][:4]==['-j','-s','filter','show']:
                observed.append(rows[last]);last+=1
            if phase in (0,1,2,7):
                require(len(observed)>=2,'original port-range counter windows missing')
                query_counts={ingress:[],egress:[]};egress_started=False
                last_native=observed_counts if phase in(0,1,2)else {ingress:target,egress:target}
                for query in observed:
                    locus=tuple(query['arguments'][-2:]);require(locus in active,'original port-range query used wrong locus')
                    if locus==egress:egress_started=True
                    else:require(not egress_started,'original port-range ingress query followed egress polling')
                    drop=locus==egress
                    count=bounded_flower(json.loads(query['stdout']),family,protocol,drop,previous,target)
                    require(not query_counts[locus]or count>=query_counts[locus][-1],
                            'original port-range counter polling regressed')
                    query_counts[locus].append(count)
                    for key,state in (('before',query['range_before']),('after',query['range_after'])):
                        native=filters_bounded(state,family,protocol,previous,target,active)
                        for polled,value in native.items():
                            require(value>=last_native[polled],
                                    'native port-range before/after counter observation regressed')
                            last_native[polled]=value
                require(all(query_counts[locus]and query_counts[locus][-1]==target for locus in active),
                        'final original successful ingress/egress query missed its exact target')
                filters(observed[-1]['range_after'],family,protocol,target,active)
                queries.extend(observed)
            else:require(observed==[],'extra original port-range query window')
            src='192.0.2.1'if family==4 else'2001:db8:1::1';dst='192.0.2.2'if family==4 else'2001:db8:1::2'
            require(sender['arguments']==['-4'if family==4 else'-6','veth0','-c','1','-q','-p','100','-a',source['address'],'-b',dest['address'],
                    '-A',src,'-B',dst,'-t',protocol,f'sp={sport},dp={dport}'],'original range-boundary traffic/native MAC binding changed')
            packet=report['packet_trace'][group*8+phase];data=bytes.fromhex(packet['frame_hex']);offset=34 if family==4 else 54
            require(packet['family']==17 and packet['ifindex']==source['ifindex']and packet['length']==packet['result']==len(data)==size and
                    data[:6]==bytes.fromhex(dest['address'].replace(':',''))and data[6:12]==bytes.fromhex(source['address'].replace(':',''))and
                    data[12:14]==(b'\x08\x00'if family==4 else b'\x86\xdd'),'native port-range input frame/interface/MAC changed')
            if family==4:
                h=data[14:34]
                require(h[0]==0x45 and int.from_bytes(h[2:4],'big')==size-14 and h[9]==(17 if protocol=='udp'else 6)and
                        sum(int.from_bytes(h[k:k+2],'big')for k in range(0,20,2))%65535==0 and
                        h[12:]==ipaddress.ip_address(src).packed+ipaddress.ip_address(dst).packed,'native range IPv4 header/address/protocol/checksum changed')
            else:
                require(data[14]>>4==6 and int.from_bytes(data[18:20],'big')==size-54 and data[20]==(17 if protocol=='udp'else 6)and
                        data[22:54]==ipaddress.ip_address(src).packed+ipaddress.ip_address(dst).packed,'native range IPv6 header/address/protocol changed')
            payload=data[offset:]
            require(int.from_bytes(payload[:2],'big')==sport and int.from_bytes(payload[2:4],'big')==dport and
                    (int.from_bytes(payload[4:6],'big')==108 if protocol=='udp'else payload[12]>>4==5),
                    'native inclusive/out-of-range source/destination ports or payload length changed')
        # Positive probes are counted and dropped at egress; five negative
        # probes leave both filters at exactly3 and really reach the peer.
        final=ip.topology(queries[-1]['range_after'],vlan_filtering=0);before=ip.links(senders[0]['range_before'])
        for device,direction,count in (('veth0','tx',8),('veth1','rx',8),('veth2','tx',5),('veth3','rx',5)):
            old=before[device]['stats64'][direction];new=final[device]['stats64'][direction]
            require(new['packets']-old['packets']>=count and new['bytes']-old['bytes']>=count*size,
                    'native original range hits/drops/nonmatching delivery did not traverse real bridge')
        j=rows.index(queries[-1])+1
        for command,loci_before,loci_after in ((rows[j],active,(ingress,)),(rows[j+1],(ingress,),())):
            filters(command['range_before'],family,protocol,3,loci_before);filters(command['range_after'],family,protocol,3,loci_after)
    ip.validate_boundaries(report,rows,source_hashes=SOURCE_HASHES,expected_sends=32,expected_bytes=5056,observation_key='range_after')


COMMAND_SHA='1f4a0203a370bd20567e136a723fe6f1885229a9b14f18eed2c33e117028b411'
SOURCE_HASHES={'forwarding/tc_flower_port_range.sh': '719918a685ab91e34d15a107fd9908a5cf6583937977bf9aed4ee99d352c1637', 'forwarding/lib.sh': '8fb499582bb13c830e7fe9cbcb0baffc0bedf552d12c3c9241b65ecf14414537', 'lib.sh': '875a357f3264e3126af195e97a36217ba6e44c0812afc1b6b8a414f1984dcccd', 'forwarding/Makefile': '2c66e188a0a956c79dfbedd3a3449fd455e94e0a2a5b07550aaed0b79f745d96', 'forwarding/tc_common.sh': '4aed88ec9b90364edf2fbd2611237cdc78d57a2e931280124bd750b3b26e0369'}
