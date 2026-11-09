"""Bind all original DS field/DSCP/ECN tests to actual native TC evidence.

The two original compound cases install a second action after a terminating
pass. Its observed zero counters are preserved: these cases do not prove that
both actions executed. Do not change the original source to hide that boundary.
"""
import importlib.util
import ipaddress
import json
from pathlib import Path
import re

spec=importlib.util.spec_from_file_location('pedit_ip',Path(__file__).with_name('linux-pedit-ip-contract.py'))
ip=importlib.util.module_from_spec(spec);spec.loader.exec_module(ip)
require=ip.require


def phases():
    result=[]
    for family in (4,6):
        for kind,values in (('field',(0,1,2,3,128,252,253,254,255)),('dscp',(0,1,2,3,32,61,62,63)),('ecn',(0,1,2,3))):
            for locus in (('veth1','ingress'),('veth2','egress')):
                for value in values:
                    retain=255 if kind=='field' else 252 if kind=='dscp' else 3
                    value=value<<2 if kind=='dscp' else value
                    action=('ip dsfield' if family==4 else 'ip6 traffic_class')+' set '+str(value)
                    if kind!='field':action+=' retain '+('0xfc' if kind=='dscp' else '0x03' if family==4 else '0x3')
                    result.append((family,locus,[(value,retain)],action))
        if family==4:
            for locus in (('veth1','ingress'),('veth2','egress')):
                result.append((4,locus,[(124,252),(1,3)],'set DSCP + set ECN'))
    return result


PHASES=phases()


def flower(rows,family,steps,edit):
    require(len(rows)==2 and sum('options'in x for x in rows)==1,'native DS field filter missing/duplicated/polluted')
    row=next(x for x in rows if 'options'in x);options=row['options'];actions=options['actions']
    require(row['kind']=='flower'and row['pref']==1 and row['chain']==0 and options['handle']==101 and
            options.get('not_in_hw')is True,'native DS field classifier identity/software path changed')
    expected=125
    for value,retain in steps:expected=(expected&(~retain&255))|(value&retain)
    if edit:
        require(row['protocol']=='all'and options['keys']=={} and len(actions)==len(steps),'original DS field action list changed')
    else:
        require(row['protocol']==('ip'if family==4 else'ipv6') and options.get('skip_hw')is True and len(actions)==1 and
                options['keys']=={'eth_type':'ipv'+str(family),'ip_tos':expected},'native DSCP/ECN receiver did not match edited/preserved bits')
    result=[]
    for n,action in enumerate(actions):
        require(action['order']==n+1 and action['control_action']=={'type':'pass'} and action['ref']==action['bind']==1,
                'original DS field action binding/terminating verdict changed')
        if edit:
            value,retain=steps[n];shift=16 if family==4 else 20
            require(action['kind']=='pedit'and action['nkeys']==1 and len(action['keys'])==1,'native DS field PEDIT action substituted')
            key=action['keys'][0]
            require(key['htype']=='ipv'+str(family) and key['offset']==0 and key['cmd']=='set'and
                    int(key['val'],16)==(value&retain)<<shift and int(key['mask'],16)==(~(retain<<shift)&0xffffffff),
                    'native DS field mask/value/offset changed or non-target bits overwritten')
        else:
            require(action['kind']=='gact'and action['prob']=={'random_type':'none','control_action':{'type':'pass'},'val':0},
                    'native DS field receiver action changed')
        stats=action['stats']
        require(all(isinstance(stats[k],int)and stats[k]>=0 for k in ('packets','bytes','overlimits'))and
                stats['overlimits']<=stats['packets'] and all(stats[k]==0 for k in ('drops','requeues','backlog','qlen')) and
                (edit or stats['overlimits']==0),'native DS field action stats invalid')
        if n:
            require(stats['packets']==stats['bytes']==stats['overlimits']==0,
                    'original unreachable second PEDIT action acquired fabricated execution credit')
        result.append(stats)
    return result[0]


def filters(state,family,steps,locus,active):
    answer={}
    for key,rows in ip.all_filters(state).items():
        if key in active:answer[key]=flower(rows,family,steps,key==locus)
        else:require(rows==[],'native DS field rule leaked onto another locus')
    return answer


def validate_evidence(report):
    original=report['original'];labels=['ping','ping6']+[f'dev {locus[0]} {locus[1]} pedit {label}'for family,locus,steps,label in PHASES]
    results=[re.fullmatch(r'TEST: (.*?)\s+\[ OK \]',line)for line in original['stdout'].splitlines()if line.startswith('TEST:')]
    require(original['returncode']==0 and not original['stderr'] and len(results)==88 and all(results)and
            [x[1]for x in results]==labels and 'SKIP'not in original['stdout'] and '[FAIL]'not in original['stdout'],
            'complete unchanged original DS field outcomes missing')
    rows=report['commands']
    require(ip.normalized(rows)==COMMAND_SHA and [i for i,x in enumerate(rows)if x['returncode']]==[0,2]and
            all(not x['stderr']for x in rows if not x['returncode']),'original DS field command/probe/setup/cleanup sequence changed')
    timed=[x for x in rows if x['tool']in('tc','mausezahn')]
    require(all(x['finished_monotonic']>=x['started_monotonic']for x in timed)and
            all(b['started_monotonic']>=a['finished_monotonic']for a,b in zip(timed,timed[1:])),'native DS field chronology changed')
    require(all(isinstance(x.get('pedit_before'),dict)and isinstance(x.get('pedit_after'),dict)for x in timed),
            'native DS field command observations missing')
    pings=[x for x in rows if x['arguments'][:2]==['vrf','exec']]
    require(len(pings)==2,'both original DS field baseline ping families required')
    for row,tool,address in zip(pings,('ping','ping6'),('192.0.2.2','2001:db8:1::2')):
        require(row['arguments']==['vrf','exec','vveth0',tool,'-c','10','-i','0.1','-w','5',address]and
                row['returncode']==0 and '10 received'in row['stdout']and row.get('native_clock_reads',0)>0 and
                row['vrf']['linkinfo']['info_kind']=='vrf','original DS field baseline/clock/VRF binding changed')
    traffic=[x for x in rows if x['tool']=='mausezahn']
    require(len(traffic)==86 and len(report['packet_trace'])==860,'complete original DS field packet matrix missing')
    for phase,(sender,(family,locus,steps,label))in enumerate(zip(traffic,PHASES)):
        receiver=('veth3','ingress');i=rows.index(sender);add_edit,add_receiver=rows[i-2:i]
        devices=ip.topology(sender['pedit_before']);ip.topology(sender['pedit_after'])
        for state,active in ((add_edit['pedit_before'],()),(add_edit['pedit_after'],(locus,)),
                             (add_receiver['pedit_before'],(locus,)),(add_receiver['pedit_after'],(locus,receiver))):
            filters(state,family,steps,locus,active)
        initial=filters(sender['pedit_before'],family,steps,locus,(locus,receiver))
        filters(sender['pedit_after'],family,steps,locus,(locus,receiver))
        j=i+1;queries=[]
        while j<len(rows)and rows[j]['tool']=='tc'and rows[j]['arguments'][:4]==['-j','-s','filter','show']:
            queries.append(rows[j]);j+=1
        require(len(queries)>=2 and queries[-1]['arguments'][-2:]==list(locus)and
                all(x['arguments'][-2:]==list(receiver)for x in queries[:-1]),'original DS field receiver/action queries reordered')
        for query in queries:
            edit=query is queries[-1];key=locus if edit else receiver
            counter=flower(json.loads(query['stdout']),family,steps,edit)
            actual=filters(query['pedit_after'],family,steps,locus,(locus,receiver))[key]
            require(actual['packets']>=counter['packets']and actual['bytes']>=counter['bytes'],
                    'original DS field queried counter exceeds actual observation')
        size=154 if family==4 else 174
        for query,edit in ((queries[-2],False),(queries[-1],True)):
            counter=flower(json.loads(query['stdout']),family,steps,edit);key=locus if edit else receiver
            counted_size=size if edit and locus[1]=='egress'else size-14
            require(counter['packets']-counter['overlimits']-initial[key]['packets']+initial[key]['overlimits']>=10 and
                    counter['bytes']-initial[key]['bytes']>=10*counted_size,'native DS field receiver/action did not add ten probe packets')
        last=ip.topology(queries[-1]['pedit_after'])
        for device,direction in (('veth0','tx'),('veth1','rx'),('veth2','tx'),('veth3','rx')):
            before=devices[device]['stats64'][direction];after=last[device]['stats64'][direction]
            require(after['packets']-before['packets']>=10 and after['bytes']-before['bytes']>=10*size,
                    'native DS field probes did not traverse real bridge path')
        for command,a,b in ((rows[j],(locus,receiver),(locus,)),(rows[j+1],(locus,),())):
            filters(command['pedit_before'],family,steps,locus,a);filters(command['pedit_after'],family,steps,locus,b)
        source,dest=devices['veth0'],devices['veth3'];src='192.0.2.1'if family==4 else'2001:db8:1::1';dst='192.0.2.2'if family==4 else'2001:db8:1::2'
        require(sender['arguments']==(['-6']if family==6 else[])+['-A',src,'-B',dst,'veth0','-c','10','-d','20msec','-p','100',
                '-a','own','-b',dest['address'],'-q','-t','tcp','tos=0x7d,sp=54321,dp=12345']and
                sender['finished_monotonic']-sender['started_monotonic']>=.18,'original DS field traffic arguments/MAC/pacing changed')
        for packet in report['packet_trace'][phase*10:(phase+1)*10]:
            data=bytes.fromhex(packet['frame_hex']);offset=34 if family==4 else 54
            require(packet['family']==17 and packet['ifindex']==source['ifindex']and packet['result']==packet['length']==len(data)==size and
                    data[:6]==bytes.fromhex(dest['address'].replace(':',''))and data[6:12]==bytes.fromhex(source['address'].replace(':',''))and
                    data[12:14]==(b'\x08\x00'if family==4 else b'\x86\xdd'),'native DS field input frame/interface/MAC changed')
            if family==4:
                h=data[14:34]
                require(h[0]==0x45 and h[1]==125 and int.from_bytes(h[2:4],'big')==140 and h[9]==6 and
                        sum(int.from_bytes(h[k:k+2],'big')for k in range(0,20,2))%65535==0 and
                        h[12:]==ipaddress.ip_address(src).packed+ipaddress.ip_address(dst).packed,'native DS field IPv4 input/TOS/checksum changed')
            else:
                require(data[14]>>4==6 and ((data[14]&15)<<4|data[15]>>4)==125 and int.from_bytes(data[18:20],'big')==120 and
                        data[20]==6 and data[22:54]==ipaddress.ip_address(src).packed+ipaddress.ip_address(dst).packed,
                        'native DS field IPv6 input/traffic class changed')
            require(data[offset:offset+4]==bytes.fromhex('d4313039')and data[offset+12]>>4==5,
                    'native DS field TCP ports/header/payload size changed')
    ip.validate_boundaries(report,rows,source_hashes=SOURCE_HASHES,expected_sends=860,expected_bytes=140840)


COMMAND_SHA='727891a832c1936232e5b99af19dceb4553971ce2a70018b799c6388929fc041'
SOURCE_HASHES={'forwarding/pedit_dsfield.sh': '41e6e723e6eeb1d798792013b254d30e235a5b2bd9f4ab602c67272849a86c3f', 'forwarding/lib.sh': '8fb499582bb13c830e7fe9cbcb0baffc0bedf552d12c3c9241b65ecf14414537', 'lib.sh': '875a357f3264e3126af195e97a36217ba6e44c0812afc1b6b8a414f1984dcccd', 'forwarding/Makefile': '2c66e188a0a956c79dfbedd3a3449fd455e94e0a2a5b07550aaed0b79f745d96', 'forwarding/tc_common.sh': '4aed88ec9b90364edf2fbd2611237cdc78d57a2e931280124bd750b3b26e0369'}
