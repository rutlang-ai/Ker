"""Reject substituted CFM matching, missing native frames and unsafe cleanup."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('cfm',ROOT/'tests/posix/linux-tc-flower-cfm-contract.py')
contract=importlib.util.module_from_spec(spec);spec.loader.exec_module(contract)


class FlowerCFMContractTests(unittest.TestCase):
    def test_complete_original_opcode_level_and_conjunction(self):
        fixture=json.loads(Path(__file__).with_name('tc-flower-cfm-transcript.json').read_text())
        cases=['complete','delayed-observation','unspecified-padding','missing-result','original-fails','skip','warning',
               'capability-fails','capability-warning','missing-command','changed-input-command','query-missing',
               'wrong-opcode','wrong-level','conjunction-lost','wrong-software','wrong-action','wrong-binding',
               'wrong-ethertype','wrong-handle','other-locus','install-not-empty','remove-not-empty',
               'wrong-peer','wrong-master','shared-vrf','port-down','bridge-substituted','no-native-path',
               'bridge-leaked','vrf-leaked','mdb-leaked','port-up','master-leaked','address-leaked','route-leaked','forwarding-leaked',
               'wrong-source','wrong-tool','wrong-timeout','backend-succeeds','unknown-vrf-succeeds','wrong-send-count',
               'wrong-byte-count','trace-errors','live-socket','outstanding','worker-fails','forced-stop','missing-eof','reversed-time']
        cases += [(kind,i)for i in range(11)for kind in('frame-missing','cfm-header','input-mac','input-interface')]
        windows=[i for i,x in enumerate(fixture['commands'])if x['tool']=='mausezahn'and fixture['commands'][i+1]['tool']=='tc']
        cases += [(kind,i)for i in windows for kind in('query-hit','query-byte','query-drop','query-native-actual')]
        cases += [('observation-missing',i,key)for i,x in enumerate(fixture['commands'])if x['tool']in('tc','mausezahn')and i
                  for key in('range_before','range_after')]
        for case in cases:
            with self.subTest(case=case):
                r=copy.deepcopy(fixture);rows=r['commands'];traffic=[x for x in rows if x['tool']=='mausezahn'];first=traffic[0];start=rows.index(first)
                def options(state):return next(x['options']for x in state['filters_by_device']['veth1']if'options'in x)
                def action(state):return options(state)['actions'][0]
                def link(state,name):return contract.ip.links(state)[name]
                if isinstance(case,tuple):
                    kind,i=case[:2]
                    if kind=='observation-missing':rows[i].pop(case[2])
                    elif kind=='frame-missing':r['packet_trace'].pop(i)
                    elif kind=='input-interface':r['packet_trace'][i]['ifindex']+=1
                    elif kind in('cfm-header','input-mac'):
                        p=r['packet_trace'][i];b=bytearray.fromhex(p['frame_hex']);b[15 if kind=='cfm-header'else 0]^=1;p['frame_hex']=b.hex()
                    else:
                        j=i+1
                        while j+1<len(rows)and rows[j+1]['tool']=='tc'and rows[j+1]['arguments'][:4]==['-j','-s','filter','show']:j+=1
                        q=rows[j]
                        if kind=='query-native-actual':action(q['range_after'])['stats']['packets']+=1
                        else:
                            out=json.loads(q['stdout']);a=next(x['options']['actions'][0]for x in out if'options'in x)
                            a['stats'][{'query-hit':'packets','query-byte':'bytes','query-drop':'drops'}[kind]]+=1;q['stdout']=json.dumps(out)
                elif case=='delayed-observation':
                    for x in traffic:x['range_after']=copy.deepcopy(x['range_before'])
                elif case=='unspecified-padding':
                    for p in r['packet_trace']:
                        b=bytearray.fromhex(p['frame_hex']);b[18:]=bytes(range(46));p['frame_hex']=b.hex()
                elif case=='missing-result':r['original']['stdout']='\n'.join(r['original']['stdout'].splitlines()[:-1])
                elif case=='original-fails':r['original']['returncode']=1
                elif case=='skip':r['original']['stdout']+='SKIP\n'
                elif case=='warning':r['original']['stderr']='unsupported'
                elif case=='capability-fails':rows[0]['returncode']=1
                elif case=='capability-warning':rows[0]['stderr']='unsupported'
                elif case=='missing-command':rows.pop(start)
                elif case=='changed-input-command':first['arguments'][-2]='89 02 00:00:00:00'
                elif case=='query-missing':rows.pop(windows[0]+1)
                elif case=='wrong-opcode':options(rows[start-2]['range_after'])['keys']['cfm']['op']=43
                elif case=='wrong-level':options(rows[rows.index(traffic[3])-3]['range_after'])['keys']['cfm']['mdl']=6
                elif case=='conjunction-lost':options(rows[rows.index(traffic[7])-2]['range_after'])['keys']['cfm'].pop('op')
                elif case=='wrong-software':options(rows[start-2]['range_after'])['not_in_hw']=False
                elif case=='wrong-action':action(rows[start-2]['range_after'])['control_action']['type']='pass'
                elif case=='wrong-binding':action(rows[start-2]['range_after'])['bind']=2
                elif case=='wrong-ethertype':options(rows[start-2]['range_after'])['keys']['eth_type']='ipv4'
                elif case=='wrong-handle':options(rows[start-2]['range_after'])['handle']=103
                elif case=='other-locus':rows[start-2]['range_after']['egress_filters']['veth0']=copy.deepcopy(rows[start-2]['range_after']['filters_by_device']['veth1'])
                elif case=='install-not-empty':rows[start-2]['range_before']['filters_by_device']['veth1']=copy.deepcopy(first['range_before']['filters_by_device']['veth1'])
                elif case=='remove-not-empty':
                    q=rows.index(traffic[2])+3;rows[q+1]['range_after']['filters_by_device']['veth1']=copy.deepcopy(first['range_before']['filters_by_device']['veth1'])
                elif case=='wrong-peer':link(first['range_before'],'veth0')['link']='lo'
                elif case=='wrong-master':link(first['range_before'],'veth1')['master']='vveth0'
                elif case=='shared-vrf':link(first['range_before'],'vveth1')['linkinfo']['info_data']['table']=1
                elif case=='port-down':link(first['range_before'],'veth0')['flags'].remove('UP')
                elif case=='bridge-substituted':first['range_before']['links'].append(dict(ifname='br1',linkinfo=dict(info_kind='bridge')))
                elif case=='no-native-path':
                    q=next(x for x in reversed(rows)if x['tool']=='tc'and x['arguments'][:4]==['-j','-s','filter','show']);link(q['range_after'],'veth1')['stats64']['rx']=copy.deepcopy(link(first['range_before'],'veth1')['stats64']['rx'])
                elif case in('bridge-leaked','vrf-leaked'):r['cleanup_state']['links'].append(dict(ifname='br1'if case=='bridge-leaked'else'vveth1'))
                elif case=='mdb-leaked':r['cleanup_state']['mdb'][0]['mdb'].append(dict(grp='239.1.1.1'))
                elif case=='port-up':link(r['cleanup_state'],'veth0')['flags'].append('UP')
                elif case=='master-leaked':link(r['cleanup_state'],'veth1')['master']='vveth1'
                elif case=='address-leaked':next(x for x in r['cleanup_state']['addresses']if x['ifname']=='veth0')['addr_info']=[dict(local='192.0.2.1')]
                elif case=='route-leaked':r['cleanup_state']['ipv4_routes'].append(dict(table='1',dst='default'))
                elif case=='forwarding-leaked':r['cleanup_state']['ipv4']='1'
                elif case=='wrong-source':r['source_hashes']['forwarding/tc_flower_cfm.sh']='bad'
                elif case=='wrong-tool':r['iproute2']['source_hashes']['tc/tc.c']='bad'
                elif case=='wrong-timeout':r['original_tc_hit_timeout_ms']=100
                elif case=='backend-succeeds':r['missing_backend_control']['returncode']=0
                elif case=='unknown-vrf-succeeds':r['vrf_binding_control']['unknown_vrf']['returncode']=0
                elif case=='wrong-send-count':r['native_fixture']['bridge_packet_sends']-=1
                elif case=='wrong-byte-count':r['native_fixture']['bridge_packet_bytes']-=1
                elif case=='trace-errors':r['native_fixture']['bridge_packet_trace_errors']=1
                elif case=='live-socket':r['native_fixture']['live']=1
                elif case=='outstanding':r['stats']['outstanding']=1
                elif case=='worker-fails':r['stats']['worker_exit_code']=1
                elif case=='forced-stop':r['stats']['shutdown_timed_out']=True
                elif case=='missing-eof':r['stats']['control_eof']=False
                elif case=='reversed-time':first['finished_monotonic']=first['started_monotonic']-1
                if case in('complete','delayed-observation','unspecified-padding'):contract.validate_evidence(r)
                else:
                    with self.assertRaises((RuntimeError,KeyError,ValueError,IndexError,StopIteration)):contract.validate_evidence(r)


if __name__=='__main__':unittest.main()
