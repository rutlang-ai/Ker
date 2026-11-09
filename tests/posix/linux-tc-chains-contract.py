"""Original software TC chains: unreachable, goto, lifecycle and templates."""
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import re

spec=importlib.util.spec_from_file_location('cfm',Path(__file__).with_name('linux-tc-flower-cfm-contract.py'))
cfm=importlib.util.module_from_spec(spec);spec.loader.exec_module(cfm)
ip=cfm.ip;require=cfm.require


def normalized(rows):
    result=[]
    for row in rows:
        args=row['arguments'][:]
        if row['tool']=='mausezahn':
            args[args.index('-a')+1]='<native-h1-MAC>';args[args.index('-b')+1]='<native-h2-MAC>'
        elif row['tool']=='tc'and'flower'in args:
            for key in('src_mac','dst_mac'):
                if key in args and '/'not in args[args.index(key)+1]:args[args.index(key)+1]='<native-h2-MAC>'
        item=[row['tool'],args]
        if result and item==result[-1]and row['tool']=='tc'and args[:4]==['-j','-s','filter','show']:continue
        result.append(item)
    return hashlib.sha256(json.dumps(result,separators=(',',':')).encode()).hexdigest()


def chains(actual,expected):
    require(len(actual)==len(expected)and len({x['chain']for x in actual})==len(actual),'native TC chain missing/duplicated')
    for row in actual:
        index=row['chain'];require(index in expected,'unexpected native TC chain')
        template=expected[index]
        require(row==dict(parent='ffff:',chain=index,**({}if template is None else
                dict(kind='flower',options=dict(keys={template:'00:00:00:00:00:00','eth_type':'ipv4'})))),
                'native TC chain/template key changed')


def filters(state,rules,counts,mac):
    require(set(state['filters_by_device'])==set(state['egress_filters'])=={'veth0','veth1'},'native chain two-port observation missing')
    require(state['filters_by_device']['veth0']==[]and all(x==[]for x in state['egress_filters'].values()),'native chain classifier leaked to another locus')
    rows=state['filters_by_device']['veth1'];detail=[x for x in rows if'options'in x]
    require(len(detail)==len(rules)and len(rows)==2*len(rules),'native TC chain classifier missing/duplicated/polluted')
    seen=set()
    for row in detail:
        o=row['options'];identity=(row['chain'],row['pref'],o['handle']);require(identity in rules and identity not in seen,'wrong native TC filter identity')
        seen.add(identity);key,verdict,software=rules[identity];actions=o['actions']
        require(row['protocol']=='ip'and row['kind']=='flower'and o['keys']=={key:mac,'eth_type':'ipv4'}and
                o.get('not_in_hw')is True and o.get('skip_hw',False)is software and len(actions)==1,'native TC template/MAC/software classifier changed')
        a=actions[0];s=a['stats'];count=counts.get(identity,0)
        require(a['order']==1 and a['kind']=='gact'and a['control_action']==verdict and a['bind']==a['ref']==1 and
                a['prob']=={'random_type':'none','control_action':{'type':'pass'},'val':0},'native chain goto/drop binding changed')
        require(s['packets']==count and s['bytes']==84*count and s['drops']==(count if verdict['type']=='drop'else 0)and
                all(s[k]==0 for k in('overlimits','requeues','backlog','qlen')),'native chain exact hit/drop/byte counters changed')


def validate_evidence(report):
    original=report['original'];labels=['unreachable chain (skip_hw)','gact goto chain (skip_hw)','create destroy chain','template filter fits']
    parsed=[re.fullmatch(r'TEST: (.*?)\s+\[ OK \]',x)for x in original['stdout'].splitlines()if x.startswith('TEST:')]
    require(original['returncode']==0 and not original['stderr']and len(parsed)==4 and all(parsed)and[x[1]for x in parsed]==labels and
            original['stdout'].splitlines()[-1]=='INFO: Could not test offloaded functionality'and'SKIP'not in original['stdout']and'[FAIL]'not in original['stdout'],
            'complete original software TC chain outcomes missing')
    rows=report['commands'];require(normalized(rows)==COMMAND_SHA,'original TC chain commands/phases changed')
    failures=[x for x in rows if x['returncode']];require(len(failures)==5 and failures[0]['arguments']==['link','show','dev','veth0']and
            failures[0]['returncode']==1 and all(x['returncode']==2 for x in failures[1:]),'native TC chain expected failure boundaries changed')
    for row in failures[1:]:
        require(('Mask does not fit the template'if row['arguments'][1]=='add'else'Specified filter handle not found')in row['stderr'],
                'original incompatible template/absent-handle error substituted')
    capability=[x for x in rows if x['tool']=='tc'and x['arguments']in(['-j'],['help'])]
    require(len(capability)==2 and all(x['returncode']==0 and'chain'in x['stderr']for x in capability),
            'native tc JSON/chain capability probe changed')
    observed=[x for x in rows if x['tool']in('tc','mausezahn')and x not in capability]
    require(all(isinstance(x.get('range_before'),dict)and isinstance(x.get('range_after'),dict)and
                isinstance(x.get('chains_before'),list)and isinstance(x.get('chains_after'),list)and
                x['finished_monotonic']>=x['started_monotonic']for x in observed)and
            all(b['started_monotonic']>=a['finished_monotonic']for a,b in zip(observed,observed[1:])),
            'native chain observations/chronology missing')
    traffic=[x for x in rows if x['tool']=='mausezahn'];frames=report['packet_trace']
    require(len(traffic)==len(frames)==2,'original unreachable/goto native probes missing')
    devices=cfm.topology(traffic[0]['range_before']);mac=devices['veth1']['address']
    for index,sender in enumerate(traffic):
        state=sender['range_before'];path=cfm.topology(state);cfm.topology(sender['range_after'])
        for host,address in(('veth0','192.0.2.1'),('veth1','192.0.2.2')):
            require(any(x.get('local')==address and x.get('prefixlen')==24 for x in next(x['addr_info']for x in state['addresses']if x['ifname']==host))and
                    any(x.get('dev')==host and x.get('dst')=='192.0.2.0/24'and str(x.get('table'))==str(path['v'+host]['linkinfo']['info_data']['table'])for x in state['ipv4_routes']),
                    'original native chain IPv4 address/VRF route missing')
        require(sender['arguments']==['veth0','-c','1','-p','64','-a',path['veth0']['address'],'-b',mac,'-A','192.0.2.1','-B','192.0.2.2','-t','ip','-q'],
                'original native chain traffic arguments changed')
        packet=frames[index];data=bytes.fromhex(packet['frame_hex']);h=data[14:34]
        require(packet['family']==17 and packet['ifindex']==path['veth0']['ifindex']and packet['length']==packet['result']==len(data)==98 and
                data[:6]==bytes.fromhex(mac.replace(':',''))and data[6:12]==bytes.fromhex(path['veth0']['address'].replace(':',''))and data[12:14]==b'\x08\x00'and
                h[0]==0x45 and int.from_bytes(h[2:4],'big')==84 and sum(int.from_bytes(h[k:k+2],'big')for k in range(0,20,2))%65535==0 and
                h[12:]==ipaddress.ip_address('192.0.2.1').packed+ipaddress.ip_address('192.0.2.2').packed,
                'native original chain input frame/interface/header/checksum changed')
    declared={};expected={};rules={};counts={};packet_number=0
    for row in observed:
        args=row['arguments'];chains(row['chains_before'],expected)
        # Counts before reads may lag only while the original busywait is active.
        if row['tool']=='mausezahn':
            filters(row['range_before'],rules,counts,mac)
            packet_number+=1
            if packet_number==2:counts.update({(1,1,1101):1,(0,1,101):1,(0,2,102):0})
        elif args[:2]==['qdisc','del']:
            require(not rules and not expected,'native chain/filter cleanup deferred until qdisc deletion')
        elif args[:2]in(['chain','add'],['chain','del']):
            chain=int(args[args.index('chain',1)+1])if'chain'in args[1:]else 0
            if args[1]=='add':
                require(chain not in expected,'duplicate original chain creation')
                template=next((key for key in('dst_mac','src_mac')if key in args),None)
                expected[chain]=template;declared[chain]=True
            else:
                require(chain in expected and not any(key[0]==chain for key in rules),'native chain removed with live filter')
                expected.pop(chain);declared.pop(chain,None)
        elif args[:2]in(['filter','add'],['filter','del']):
            filters(row['range_before'],rules,counts,mac)
            selector=args[:args.index('flower')]
            chain=int(selector[selector.index('chain')+1])if'chain'in selector else 0
            identity=(chain,int(args[args.index('pref')+1]),int(args[args.index('handle')+1]))
            if row['returncode']==0:
                if args[1]=='add':
                    key='src_mac'if'src_mac'in args else'dst_mac';verdict={'type':'goto','chain':1}if'goto'in args else{'type':'drop'}
                    rules[identity]=(key,verdict,'skip_hw'in args);counts[identity]=0;expected.setdefault(chain,None)
                else:
                    require(identity in rules,'original deletion lacks native filter generation');rules.pop(identity);counts.pop(identity)
                    if chain not in declared and not any(key[0]==chain for key in rules):expected.pop(chain)
            filters(row['range_after'],rules,counts,mac)
        elif args[:4]==['-j','-s','filter','show']:
            for snapshot in (json.loads(row['stdout']),row['range_after']['filters_by_device']['veth1']):
                actual_counts={(r['chain'],r['pref'],r['options']['handle']):r['options']['actions'][0]['stats']['packets']for r in snapshot if'options'in r}
                require(all(identity in counts and 0<=count<=counts[identity]for identity,count in actual_counts.items()),
                        'unreachable/wrong-priority native rule was hit or counter regressed')
                state=dict(row['range_after']);state['filters_by_device']=dict(state['filters_by_device'],veth1=snapshot)
                filters(state,rules,actual_counts,mac)
            # Every negative unreachable/wrong-priority query must remain zero;
            # the last original read after each probe must show the full matrix.
            next_row=rows[rows.index(row)+1]
            if next_row['arguments'][:4]!=['-j','-s','filter','show']:
                state=dict(row['range_after']);state['filters_by_device']=dict(state['filters_by_device'],veth1=json.loads(row['stdout']))
                filters(state,rules,counts,mac);filters(row['range_after'],rules,counts,mac)
        elif args[:2]==['-j','chain']:
            actual=json.loads(row['stdout']);target=int(args[args.index('chain',2)+1])if'chain'in args[2:]else 0
            chains(actual,{target:expected[target]}if args[2]=='get'else expected)
        chains(row['chains_after'],expected)
    require(not expected and not rules and packet_number==2,'original chain/template lifecycle incomplete')
    final=cfm.topology(next(x for x in reversed(rows)if x['tool']=='tc'and x['arguments'][:4]==['-j','-s','filter','show'])['range_after'])
    for name,direction in(('veth0','tx'),('veth1','rx')):
        before=devices[name]['stats64'][direction];after=final[name]['stats64'][direction]
        require(after['packets']-before['packets']>=2 and after['bytes']-before['bytes']>=196,'original TC chain probes did not traverse native veth path')
    offload=[x for x in rows if x['tool']=='ethtool']
    require(len(offload)==1 and offload[0]['arguments']==['-k','veth0']and offload[0]['returncode']==0 and not offload[0]['stderr']and
            'hw-tc-offload: off'in offload[0]['stdout']and all(len(offload[0][key])==1 and offload[0][key][0]['ifname']=='veth0'and
            offload[0][key][0]['hw-tc-offload']['active']is False for key in('ethtool_features_before','ethtool_features_after'))and
            report['ethtool_tool']['sha256']and report['ethtool_tool']['version'].startswith('ethtool version'),
            'original unavailable hardware offload boundary lacks real native evidence')
    cfm.validate_boundaries(report,rows,source_hashes=SOURCE_HASHES,expected_sends=2,expected_bytes=196)


COMMAND_SHA='fdc6fd96e7cf82f105bc06820c9a764142db8b8f2b3865697952835ea016c374'
SOURCE_HASHES={'forwarding/tc_chains.sh': '05789537a7a8b64f68f4bc454223ea4fa7e729ab5e72642ebfeeaa0f182e10ab', 'forwarding/lib.sh': '8fb499582bb13c830e7fe9cbcb0baffc0bedf552d12c3c9241b65ecf14414537', 'lib.sh': '875a357f3264e3126af195e97a36217ba6e44c0812afc1b6b8a414f1984dcccd', 'forwarding/Makefile': '2c66e188a0a956c79dfbedd3a3449fd455e94e0a2a5b07550aaed0b79f745d96', 'forwarding/tc_common.sh': '4aed88ec9b90364edf2fbd2611237cdc78d57a2e931280124bd750b3b26e0369'}
