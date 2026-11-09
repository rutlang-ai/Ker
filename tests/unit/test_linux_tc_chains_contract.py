"""Reject reachable dead chains, wrong goto, accepted bad templates and fake hardware."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('chains',ROOT/'tests/posix/linux-tc-chains-contract.py')
contract=importlib.util.module_from_spec(spec);spec.loader.exec_module(contract)


class TCChainsContractTests(unittest.TestCase):
    def test_query_counters_follow_native_causal_progress(self):
        fixture=json.loads(Path(__file__).with_name('tc-chains-transcript.json').read_text())
        for case in ('delayed-query','before-one-query-zero','query-one-after-zero','non-integer-counter'):
            with self.subTest(case=case):
                report=copy.deepcopy(fixture);rows=report['commands']
                sender=[x for x in rows if x['tool']=='mausezahn'][1]
                query=rows[rows.index(sender)+1]
                def zero(table):
                    for row in table:
                        if row.get('options',{}).get('handle')in(101,1101):
                            row['options']['actions'][0]['stats'].update(packets=0,bytes=0,drops=0)
                if case=='delayed-query':
                    zero(sender['range_after']['filters_by_device']['veth1'])
                    zero(query['range_before']['filters_by_device']['veth1'])
                    delayed=copy.deepcopy(query)
                    zero(delayed['range_after']['filters_by_device']['veth1'])
                    output=json.loads(delayed['stdout']);zero(output);delayed['stdout']=json.dumps(output)
                    delayed['finished_monotonic']=delayed['started_monotonic']
                    rows.insert(rows.index(query),delayed)
                    contract.validate_evidence(report)
                else:
                    if case=='before-one-query-zero':
                        output=json.loads(query['stdout']);zero(output);query['stdout']=json.dumps(output)
                    elif case=='query-one-after-zero':
                        zero(sender['range_after']['filters_by_device']['veth1'])
                        zero(query['range_before']['filters_by_device']['veth1'])
                        zero(query['range_after']['filters_by_device']['veth1'])
                    else:
                        output=json.loads(query['stdout'])
                        next(x['options']['actions'][0]['stats']for x in output if x.get('options',{}).get('handle')==101)['packets']=True
                        query['stdout']=json.dumps(output)
                    with self.assertRaises(RuntimeError):contract.validate_evidence(report)

    def test_complete_original_software_chain_matrix(self):
        fixture=json.loads(Path(__file__).with_name('tc-chains-transcript.json').read_text())
        cases=['complete','delayed-observation','unspecified-input-defaults','missing-result','original-fails','skip',
               'warning','offload-claim','missing-command','changed-command','missing-probe','wrong-probe-mac',
               'unreachable-hit','wrong-priority-hit','goto-wrong-chain','goto-not-hit','drop-not-hit','wrong-bytes',
               'wrong-drop','hardware-rule','skip-hw-lost','wrong-native-mac','wrong-handle','wrong-chain',
               'template-key-wrong','template-created-wrong-chain','template-unexpected-success','template-error-substituted',
               'missing-delete-error','create-get-wrong','chain-duplicate','chain-missing','chain-not-deleted',
               'other-locus','wrong-peer','wrong-master','shared-vrf','address-missing','route-missing','no-native-traversal',
               'offload-query-fails','offload-feature-lost','offload-feature-on','offload-json-wrong-device','ethtool-provenance-lost',
               'backend-succeeds','unknown-vrf-succeeds','wrong-send-count','wrong-byte-count','trace-errors','live-socket',
               'outstanding','worker-fails','forced-stop','missing-eof','bridge-leaked','vrf-leaked','mdb-leaked',
               'address-leaked','route-leaked','forwarding-leaked','master-leaked','port-up','wrong-source','wrong-tool','wrong-timeout','reversed-time']
        cases += [(kind,i)for i in range(2)for kind in('frame-missing','frame-interface','frame-mac','frame-header','frame-length')]
        cases += [('observation-missing',i,key)for i,x in enumerate(fixture['commands'])if x['tool']in('tc','mausezahn')and
                  x['arguments']not in(['-j'],['help'])for key in('range_before','range_after','chains_before','chains_after')]
        for case in cases:
            with self.subTest(case=case):
                r=copy.deepcopy(fixture);rows=r['commands'];traffic=[x for x in rows if x['tool']=='mausezahn'];first=traffic[0];second=traffic[1]
                def option(state,handle):return next(x['options']for x in state['filters_by_device']['veth1']if x.get('options',{}).get('handle')==handle)
                def command(prefix):return next(x for x in rows if x['tool']=='tc'and x['arguments'][:len(prefix)]==prefix)
                def last_query(sender):
                    i=rows.index(sender)+1
                    while i+1<len(rows)and rows[i+1]['tool']=='tc'and rows[i+1]['arguments'][:4]==['-j','-s','filter','show']:i+=1
                    return rows[i]
                def query_action(query,handle,fn):
                    out=json.loads(query['stdout']);fn(next(x['options']['actions'][0]for x in out if x.get('options',{}).get('handle')==handle));query['stdout']=json.dumps(out)
                def link(state,name):return contract.ip.links(state)[name]
                templates=[x for x in rows if x['tool']=='tc'and x['arguments'][:2]==['chain','add']and'flower'in x['arguments']]
                failed=[x for x in rows if x['returncode']==2];offload=next(x for x in rows if x['tool']=='ethtool')
                if isinstance(case,tuple):
                    kind,i=case[:2]
                    if kind=='observation-missing':rows[i].pop(case[2])
                    elif kind=='frame-missing':r['packet_trace'].pop(i)
                    elif kind=='frame-interface':r['packet_trace'][i]['ifindex']+=1
                    elif kind=='frame-length':r['packet_trace'][i]['result']-=1
                    else:
                        p=r['packet_trace'][i];b=bytearray.fromhex(p['frame_hex']);b[0 if kind=='frame-mac'else 27]^=1;p['frame_hex']=b.hex()
                elif case=='delayed-observation':
                    for x in traffic:x['range_after']=copy.deepcopy(x['range_before'])
                elif case=='unspecified-input-defaults':
                    for p in r['packet_trace']:
                        b=bytearray.fromhex(p['frame_hex']);b[15]=31;b[18:20]=b'\x12\x34';b[22]=64;b[23]=253;b[34:]=bytes(range(64));b[24:26]=b'\0\0'
                        checksum=sum(int.from_bytes(b[i:i+2],'big')for i in range(14,34,2))
                        while checksum>>16:checksum=(checksum&65535)+(checksum>>16)
                        b[24:26]=(checksum^65535).to_bytes(2,'big');p['frame_hex']=b.hex()
                elif case=='missing-result':r['original']['stdout']='\n'.join(r['original']['stdout'].splitlines()[1:])
                elif case=='original-fails':r['original']['returncode']=1
                elif case=='skip':r['original']['stdout']+='SKIP\n'
                elif case=='warning':r['original']['stderr']='unsupported'
                elif case=='offload-claim':r['original']['stdout']=r['original']['stdout'].replace('Could not test offloaded functionality','Hardware tests passed')
                elif case=='missing-command':rows.pop(rows.index(first)-1)
                elif case=='changed-command':first['arguments'][-2]='udp'
                elif case=='missing-probe':rows.remove(second)
                elif case=='wrong-probe-mac':first['arguments'][first['arguments'].index('-b')+1]='00:01:02:03:04:05'
                elif case=='unreachable-hit':query_action(last_query(first),1101,lambda a:a['stats'].update(packets=1,bytes=84,drops=1))
                elif case=='wrong-priority-hit':query_action(rows[rows.index(second)+1],102,lambda a:a['stats'].update(packets=1,bytes=84,drops=1))
                elif case=='goto-wrong-chain':option(second['range_before'],101)['actions'][0]['control_action']['chain']=2
                elif case=='goto-not-hit':query_action(last_query(second),101,lambda a:a['stats'].update(packets=0,bytes=0))
                elif case=='drop-not-hit':query_action(last_query(second),1101,lambda a:a['stats'].update(packets=0,bytes=0,drops=0))
                elif case=='wrong-bytes':query_action(last_query(second),101,lambda a:a['stats'].update(bytes=1))
                elif case=='wrong-drop':query_action(last_query(second),101,lambda a:a['stats'].update(drops=1))
                elif case=='hardware-rule':option(second['range_before'],101)['not_in_hw']=False
                elif case=='skip-hw-lost':option(second['range_before'],101)['skip_hw']=False
                elif case=='wrong-native-mac':option(second['range_before'],101)['keys']['dst_mac']='00:01:02:03:04:05'
                elif case=='wrong-handle':option(second['range_before'],101)['handle']=103
                elif case=='wrong-chain':next(x for x in second['range_before']['filters_by_device']['veth1']if x.get('options',{}).get('handle')==101)['chain']=1
                elif case=='template-key-wrong':templates[0]['chains_after'][0]['options']['keys']={'src_mac':'00:00:00:00:00:00','eth_type':'ipv4'}
                elif case=='template-created-wrong-chain':templates[0]['chains_after'][0]['chain']=2
                elif case=='template-unexpected-success':failed[0]['returncode']=0;failed[0]['stderr']=''
                elif case=='template-error-substituted':failed[0]['stderr']='Operation not supported'
                elif case=='missing-delete-error':failed[-1]['returncode']=0;failed[-1]['stderr']=''
                elif case=='create-get-wrong':command(['-j','chain','get'])['stdout']='[{"parent":"ffff:","chain":1}]'
                elif case=='chain-duplicate':second['chains_before'].append(copy.deepcopy(second['chains_before'][0]))
                elif case=='chain-missing':second['chains_before']=[]
                elif case=='chain-not-deleted':command(['chain','del'])['chains_after']=copy.deepcopy(command(['chain','del'])['chains_before'])
                elif case=='other-locus':first['range_before']['egress_filters']['veth0']=copy.deepcopy(first['range_before']['filters_by_device']['veth1'])
                elif case=='wrong-peer':link(first['range_before'],'veth0')['link']='lo'
                elif case=='wrong-master':link(first['range_before'],'veth1')['master']='vveth0'
                elif case=='shared-vrf':link(first['range_before'],'vveth1')['linkinfo']['info_data']['table']=1
                elif case=='address-missing':next(x for x in first['range_before']['addresses']if x['ifname']=='veth0')['addr_info']=[]
                elif case=='route-missing':first['range_before']['ipv4_routes']=[]
                elif case=='no-native-traversal':link(last_query(second)['range_after'],'veth1')['stats64']['rx']=copy.deepcopy(link(first['range_before'],'veth1')['stats64']['rx'])
                elif case=='offload-query-fails':offload['returncode']=1
                elif case=='offload-feature-lost':offload['stdout']='Features unavailable'
                elif case=='offload-feature-on':offload['ethtool_features_before'][0]['hw-tc-offload']['active']=True
                elif case=='offload-json-wrong-device':offload['ethtool_features_after'][0]['ifname']='eth0'
                elif case=='ethtool-provenance-lost':r['ethtool_tool']['sha256']=''
                elif case=='backend-succeeds':r['missing_backend_control']['returncode']=0
                elif case=='unknown-vrf-succeeds':r['vrf_binding_control']['unknown_vrf']['returncode']=0
                elif case=='wrong-send-count':r['native_fixture']['bridge_packet_sends']=1
                elif case=='wrong-byte-count':r['native_fixture']['bridge_packet_bytes']=195
                elif case=='trace-errors':r['native_fixture']['bridge_packet_trace_errors']=1
                elif case=='live-socket':r['native_fixture']['live']=1
                elif case=='outstanding':r['stats']['outstanding']=1
                elif case=='worker-fails':r['stats']['worker_exit_code']=1
                elif case=='forced-stop':r['stats']['shutdown_timed_out']=True
                elif case=='missing-eof':r['stats']['control_eof']=False
                elif case in('bridge-leaked','vrf-leaked'):r['cleanup_state']['links'].append(dict(ifname='br1'if case=='bridge-leaked'else'vveth1'))
                elif case=='mdb-leaked':r['cleanup_state']['mdb'][0]['mdb'].append(dict(grp='239.1.1.1'))
                elif case=='address-leaked':next(x for x in r['cleanup_state']['addresses']if x['ifname']=='veth0')['addr_info']=[dict(local='192.0.2.1')]
                elif case=='route-leaked':r['cleanup_state']['ipv4_routes'].append(dict(table='1',dst='default'))
                elif case=='forwarding-leaked':r['cleanup_state']['ipv4']='1'
                elif case=='master-leaked':link(r['cleanup_state'],'veth1')['master']='vveth1'
                elif case=='port-up':link(r['cleanup_state'],'veth0')['flags'].append('UP')
                elif case=='wrong-source':r['source_hashes']['forwarding/tc_chains.sh']='bad'
                elif case=='wrong-tool':r['iproute2']['source_hashes']['tc/tc.c']='bad'
                elif case=='wrong-timeout':r['original_tc_hit_timeout_ms']=100
                elif case=='reversed-time':second['finished_monotonic']=second['started_monotonic']-1
                if case in('complete','delayed-observation','unspecified-input-defaults'):contract.validate_evidence(r)
                else:
                    with self.assertRaises((RuntimeError,KeyError,ValueError,IndexError,StopIteration)):contract.validate_evidence(r)


if __name__=='__main__':unittest.main()
