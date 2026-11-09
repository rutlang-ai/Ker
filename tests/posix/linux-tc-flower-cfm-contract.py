"""Unchanged original CFM opcode/maintenance-level ingress classification.

Native flower counters are the drop oracle. Source AF_PACKET inputs and link
statistics do not assert socket receipt or an Ethernet egress capture.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import re

spec=importlib.util.spec_from_file_location('pedit_ip',Path(__file__).with_name('linux-pedit-ip-contract.py'))
ip=importlib.util.module_from_spec(spec);spec.loader.exec_module(ip)
require=ip.require
GROUPS=(
    (({'op':47},{'op':43}),((7,47,0,32),(6,5,0,4),(0,43,0,12))),
    (({'mdl':5},{'mdl':3},{'mdl':0}),((5,42,0,12),(6,1,0,70),(0,1,0,70),(3,0,0,4))),
    (({'mdl':5,'op':41},{'mdl':7,'op':42}),((5,41,0,4),(7,3,0,4),(3,42,0,12),(7,42,0,12))))


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


def topology(state):
    devices=ip.links(state);tables=[]
    require(not any(x.get('linkinfo',{}).get('info_kind')=='bridge'for x in devices.values()),'CFM veth path replaced with a bridge')
    for host,peer in (('veth0','veth1'),('veth1','veth0')):
        device=devices[host];vrf=devices['v'+host]
        require(device['linkinfo']['info_kind']=='veth'and device['link']==peer and device.get('master')=='v'+host and
                vrf['linkinfo']['info_kind']=='vrf'and 'UP'in device['flags']and'UP'in vrf['flags'],
                'original native CFM peer/VRF path missing')
        tables.append(vrf['linkinfo']['info_data']['table'])
    require(tables==[1,2],'original native CFM VRF tables changed')
    return devices


def flower(rows,rules,counts,handles=None):
    handles=list(range(101,101+len(rules)))if handles is None else handles
    if not rules:require(rows==[],'native CFM rule generation leaked');return
    require(len(rows)==len(rules)+1 and sum('options'in x for x in rows)==len(rules),'native CFM classifier missing/duplicated/polluted')
    actual=[x for x in rows if'options'in x]
    for row,rule,count,handle in zip(actual,rules,counts,handles):
        o=row['options'];actions=o['actions']
        require(row['protocol']=='cfm'and row['kind']=='flower'and row['pref']==1 and row['chain']==0 and
                o['handle']==handle and o.get('not_in_hw')is True and o['keys']==dict(eth_type='8902',cfm=rule)and len(actions)==1,
                'native CFM opcode/level/software rule changed')
        a=actions[0];s=a['stats']
        require(a['order']==1 and a['kind']=='gact'and a['control_action']=={'type':'drop'}and a['ref']==a['bind']==1 and
                a['prob']=={'random_type':'none','control_action':{'type':'pass'},'val':0},'native CFM drop action/binding changed')
        require(s['packets']==s['drops']==count and s['bytes']==50*count and
                all(s[k]==0 for k in('overlimits','requeues','backlog','qlen')),'native CFM exact hit/drop/byte counters changed')


def filters(state,rules,counts,handles=None):
    require(set(state['filters_by_device'])==set(state['egress_filters'])=={'veth0','veth1'},'native CFM two-port observations missing')
    flower(state['filters_by_device']['veth1'],rules,counts,handles)
    require(state['filters_by_device']['veth0']==[]and all(x==[]for x in state['egress_filters'].values()),
            'native CFM classification leaked to another locus')


def validate_evidence(report):
    original=report['original'];labels=['CFM opcode match test','CFM level match test','CFM opcode and level match test']
    parsed=[re.fullmatch(r'TEST: (.*?)\s+\[ OK \]',x)for x in original['stdout'].splitlines()if x.startswith('TEST:')]
    require(original['returncode']==0 and not original['stderr']and len(parsed)==3 and all(parsed)and[x[1]for x in parsed]==labels and
            'SKIP'not in original['stdout']and'[FAIL]'not in original['stdout'],'complete original CFM results missing')
    rows=report['commands'];require(normalized(rows)==COMMAND_SHA,'original CFM commands/phases changed')
    require([i for i,x in enumerate(rows)if x['returncode']]==[1]and rows[0]['tool']=='tc'and rows[0]['arguments']==['-j']and
            rows[0]['returncode']==0 and not rows[0]['stdout']and'Usage:'in rows[0]['stderr']and'-j[son]'in rows[0]['stderr']and
            all(not x['stderr']for i,x in enumerate(rows)if i and not x['returncode']),
            'original native tc JSON capability/setup/cleanup result changed')
    observed=[x for x in rows if x['tool']in('tc','mausezahn')and x is not rows[0]]
    require(all(isinstance(x.get('range_before'),dict)and isinstance(x.get('range_after'),dict)and
                x['finished_monotonic']>=x['started_monotonic']for x in observed)and
            all(b['started_monotonic']>=a['finished_monotonic']for a,b in zip(observed,observed[1:])),
            'native CFM observation/chronology missing')
    traffic=[x for x in rows if x['tool']=='mausezahn'];frames=report['packet_trace']
    require(len(traffic)==len(frames)==11,'complete original CFM matrix missing')
    phase=0
    for rules,probes in GROUPS:
        senders=traffic[phase:phase+len(probes)];start=rows.index(senders[0]);installs=rows[start-len(rules):start];counts=[0]*len(rules)
        for index,command in enumerate(installs):
            filters(command['range_before'],rules[:index],counts[:index])
            filters(command['range_after'],rules[:index+1],counts[:index+1])
        for number,(sender,(level,opcode,flags,offset))in enumerate(zip(senders,probes)):
            # A previous send need not be processed before the next send's
            # observation. Decisive original query windows bind the counts.
            devices=topology(sender['range_before']);topology(sender['range_after'])
            header=bytes((0x89,0x02,level<<5,opcode,flags,offset));packet=frames[phase+number];data=bytes.fromhex(packet['frame_hex'])
            literal=f'89 02 {level<<5:02x}:{opcode:02x}:{flags:02x}:{offset:02x}'
            require(sender['arguments']==['veth0','-c','1','-p','64','-a',devices['veth0']['address'],'-b',devices['veth1']['address'],literal,'-q'],
                    'original CFM MD level/opcode/flags/TLV input changed')
            require(packet['family']==17 and packet['ifindex']==devices['veth0']['ifindex']and
                    packet['length']==packet['result']==len(data)==64 and data[12:18]==header and
                    data[:6]==bytes.fromhex(devices['veth1']['address'].replace(':',''))and
                    data[6:12]==bytes.fromhex(devices['veth0']['address'].replace(':','')),'native original CFM frame/header/interface changed')
            for index,rule in enumerate(rules):
                if all({'mdl':level,'op':opcode}[key]==value for key,value in rule.items()):counts[index]+=1
            end=rows.index(sender)+1;queries=[]
            while end<len(rows)and rows[end]['tool']=='tc'and rows[end]['arguments'][:4]==['-j','-s','filter','show']:
                queries.append(rows[end]);end+=1
            if number in(len(probes)-2,len(probes)-1):
                require(len(queries)>=len(rules)and all(x['arguments'][-2:]==['veth1','ingress']for x in queries),
                        'original CFM decisive counter query windows missing')
                flower(json.loads(queries[-1]['stdout']),rules,counts)
                filters(queries[-1]['range_after'],rules,counts)
            else:require(not queries,'extra original CFM counter window')
        handles=list(range(101,101+len(rules)));remaining=list(rules);left=list(counts)
        for remove in rows[end:end+len(rules)]:
            filters(remove['range_before'],remaining,left,handles);remaining.pop(0);left.pop(0);handles.pop(0)
            filters(remove['range_after'],remaining,left,handles)
        phase+=len(probes)
    final=next(x for x in reversed(rows)if x['tool']=='tc'and x['arguments'][:4]==['-j','-s','filter','show'])['range_after']
    initial=topology(traffic[0]['range_before']);last=topology(final)
    for device,direction in(('veth0','tx'),('veth1','rx')):
        a=initial[device]['stats64'][direction];b=last[device]['stats64'][direction]
        require(b['packets']-a['packets']>=11 and b['bytes']-a['bytes']>=704,'CFM probes did not traverse native veth path')
    validate_boundaries(report,rows)


def validate_boundaries(report,rows,*,source_hashes=None,expected_sends=11,expected_bytes=704):
    source_hashes=SOURCE_HASHES if source_hashes is None else source_hashes
    require(report['source_hashes']==source_hashes and report['original_tc_hit_timeout_ms']==1000,'pinned original CFM source/wait changed')
    tools=report['iproute2']
    require(tools['version']=='6.12.0'and tools['archive_sha256']=='bbd141ef7b5d0127cc2152843ba61f274dc32814fa3e0f13e7d07a080bef53d9'and
            tools['source_hashes']['tc/tc.c']=='e9b2e36053ee6e20f79d44a0cab3e1661300ecf9e9783c5fcd03357aa696a101'and
            report['tc_tool']['sha256']==tools['binaries']['tc'],'pinned native CFM tc provenance missing')
    cleanup=report['cleanup_state'];devices=ip.links(cleanup)
    require(not any(x in devices for x in('br1','vveth0','vveth1'))and cleanup['mdb']==[{'mdb':[],'router':{}}],'native CFM VRF/bridge/MDB leaked')
    for name in('veth0','veth1'):
        require('UP'not in devices[name]['flags']and not devices[name].get('master')and
                not next(x['addr_info']for x in cleanup['addresses']if x['ifname']==name),'native CFM address/master/port leaked')
    require(all(cleanup[f].strip()=='0'for f in('ipv4','ipv6'))and
            not any(x.get('dev')in('veth0','veth1','vveth0','vveth1')or str(x.get('table'))in('1','2')
                    for f in('ipv4','ipv6')for x in cleanup[f+'_routes']),'native CFM routes/forwarding leaked')
    filters(next(x for x in reversed(rows)if x['tool']=='tc')['range_after'],(),())
    require(report['missing_backend_control']['returncode']!=0 and report['vrf_binding_control']['baseline']['returncode']==0 and
            '1 received'in report['vrf_binding_control']['baseline']['stdout']and report['vrf_binding_control']['unknown_vrf']['returncode']!=0,
            'native CFM backend/VRF controls ineffective')
    native=report['native_fixture'];stats=report['stats']
    require(native['netlinks']>0 and native['raw_sockets']>0 and native['bridge_packet_sends']==expected_sends and native['bridge_packet_bytes']==expected_bytes and
            native['bridge_packet_trace_errors']==native['live']==stats['outstanding']==stats['worker_exit_code']==0 and
            stats['control_eof']is True and stats['shutdown_timed_out']is False,'native CFM packets/resources/shutdown incomplete')


COMMAND_SHA='bd475c49569dbc55e4e6185dcbdcd08570249760115ad0508017a1886766963c'
SOURCE_HASHES={'forwarding/tc_flower_cfm.sh': 'd70b939937717c3e5db85963596a4c5bf373c35fa9da07ff9068dc59b6424299', 'forwarding/lib.sh': '8fb499582bb13c830e7fe9cbcb0baffc0bedf552d12c3c9241b65ecf14414537', 'lib.sh': '875a357f3264e3126af195e97a36217ba6e44c0812afc1b6b8a414f1984dcccd', 'forwarding/Makefile': '2c66e188a0a956c79dfbedd3a3449fd455e94e0a2a5b07550aaed0b79f745d96', 'forwarding/tc_common.sh': '4aed88ec9b90364edf2fbd2611237cdc78d57a2e931280124bd750b3b26e0369'}
