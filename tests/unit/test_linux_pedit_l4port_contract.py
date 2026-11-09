"""Reject missing native header edits despite successful original shell output."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('pedit', ROOT/'tests/posix/linux-pedit-l4port-contract.py')
contract = importlib.util.module_from_spec(spec); spec.loader.exec_module(contract)


class PeditL4PortContractTests(unittest.TestCase):
    def test_complete_native_packet_edits(self):
        fixture = json.loads(Path(__file__).with_name('pedit-l4port-transcript.json').read_text())
        cases = ['complete','busywait-retry','background-action-packets','sender-default-variation','receiver-background-before-send','missing-result','original-fails','skip','warning',
                 'command-missing','command-reordered','short-pacing','wrong-command-mac','wrong-source-peer','wrong-master',
                 'port-blocked','wrong-pvid','wrong-address','wrong-route','shared-vrf','bridge-down','baseline-clock',
                 'baseline-output','wrong-header-offset','pedit-overlimits-hide-traffic','receiver-overlimits','wrong-header-type','wrong-header-mask','wrong-header-value',
                 'wrong-action-kind','wrong-action-verdict','receiver-old-address','receiver-wrong-field','hardware-rule',
                 'filter-duplicated','filter-other-locus','stale-receiver','receiver-counter-fake','counter-query-fake',
                 'rule-delete-ineffective','bridge-leaked','vrf-leaked','address-leaked','route-leaked','master-leaked',
                 'port-up','forwarding-leaked','backend-succeeds','unknown-vrf-succeeds','wrong-send-count','wrong-byte-count',
                 'trace-errors','live-socket','outstanding','worker-fails','forced-stop','missing-eof','wrong-source-hash',
                 'wrong-tool-source','wrong-timeout','chronology-reversed']
        cases += [('frame-missing',i) for i in range(240)]
        cases += [('frame-byte',i) for i in (0,6,12,14,16,23,24,26,33,34,35,36,37)]
        cases += [('missing-observation',i,key) for i,x in enumerate(fixture['commands']) if x['tool'] in ('tc','mausezahn')
                  for key in ('pedit_before','pedit_after')]
        cases += [('phase-no-traversal',i) for i in range(24)]
        cases += [('phase-no-edit',i) for i in range(24)]
        cases += [('phase-no-receive',i) for i in range(24)]
        for case in cases:
            with self.subTest(case=case):
                r=copy.deepcopy(fixture); rows=r['commands']; traffic=[x for x in rows if x['tool']=='mausezahn']
                sender=traffic[0]; before=sender['pedit_before']; query=rows[rows.index(sender)+2]
                def link(state,name):return contract.ip.links(state)[name]
                def action(state,device='veth1',direction='ingress'):
                    table=state['filters_by_device'] if direction=='ingress' else state['egress_filters']
                    return next(x for x in table[device] if 'options'in x)['options']['actions'][0]
                def receiver(state):return next(x for x in state['filters_by_device']['veth3'] if 'options'in x)['options']
                if isinstance(case,tuple):
                    kind,i=case[:2]
                    if kind=='frame-missing':r['packet_trace'].pop(i)
                    elif kind in ('frame-byte','ipv6-frame-byte'):
                        packet=r['packet_trace'][0 if kind=='frame-byte' else 40];b=bytearray.fromhex(packet['frame_hex']);b[i]^=1;packet['frame_hex']=b.hex()
                    elif kind=='missing-observation':rows[i].pop(case[2])
                    else:
                        send=traffic[i];dev,direction=('veth1','ingress')if i%6<3 else('veth2','egress');q=rows[rows.index(send)+2]
                        if kind=='phase-no-traversal':link(q['pedit_after'],'veth2')['stats64']['tx']=copy.deepcopy(link(send['pedit_before'],'veth2')['stats64']['tx'])
                        elif kind=='phase-no-edit':action(send['pedit_before'],dev,direction)['kind']='gact'
                        else:
                            q=rows[rows.index(send)+1];obj=json.loads(q['stdout']);next(x for x in obj if 'options'in x)['options']['actions'][0]['stats']['packets']=9;q['stdout']=json.dumps(obj)
                elif case=='busywait-retry':
                    retry=copy.deepcopy(rows[rows.index(sender)+1]);retry['finished_monotonic']=retry['started_monotonic'];rows.insert(rows.index(sender)+1,retry)
                elif case=='background-action-packets':
                    action(before)['stats']['packets']=2;action(before)['stats']['bytes']=92
                    for obj in (sender['pedit_after'],query['pedit_before'],query['pedit_after']):
                        st=action(obj)['stats'];st['packets']+=2;st['bytes']+=92
                    out=json.loads(query['stdout']);st=next(x for x in out if 'options'in x)['options']['actions'][0]['stats'];st['packets']+=2;st['bytes']+=92;query['stdout']=json.dumps(out)
                elif case=='receiver-background-before-send':
                    n=rows.index(sender);receiver_query=rows[n+1]
                    for obj in (rows[n-1]['pedit_after'],before,sender['pedit_after'],receiver_query['pedit_before'],receiver_query['pedit_after'],query['pedit_before'],query['pedit_after']):
                        st=receiver(obj)['actions'][0]['stats'];st['packets']+=1;st['bytes']+=56
                    out=json.loads(receiver_query['stdout']);st=next(x for x in out if 'options'in x)['options']['actions'][0]['stats'];st['packets']+=1;st['bytes']+=56;receiver_query['stdout']=json.dumps(out)
                elif case=='sender-default-variation':
                    for n,packet in enumerate(r['packet_trace']):
                        b=bytearray.fromhex(packet['frame_hex']);b[-100:]=bytes((i+n)%256 for i in range(100))
                        b[15]=0x28;b[18:20]=(n+100).to_bytes(2,'big');b[22]=64;b[24:26]=b'\0\0'
                        value=sum(int.from_bytes(b[i:i+2],'big')for i in range(14,34,2))
                        while value>>16:value=(value&65535)+(value>>16)
                        b[24:26]=(value^65535).to_bytes(2,'big')
                        packet['frame_hex']=b.hex()
                elif case=='missing-result':r['original']['stdout']='\n'.join(r['original']['stdout'].splitlines()[:-1])
                elif case=='original-fails':r['original']['returncode']=1
                elif case=='skip':r['original']['stdout']+='SKIP\n'
                elif case=='warning':r['original']['stderr']='unsupported'
                elif case=='command-missing':rows.pop(50)
                elif case=='command-reordered':rows[45],rows[46]=rows[46],rows[45]
                elif case=='short-pacing':sender['finished_monotonic']=sender['started_monotonic']+.05
                elif case=='wrong-command-mac':sender['arguments'][sender['arguments'].index('-b')+1]='00:00:00:00:00:01'
                elif case=='wrong-source-peer':link(before,'veth0')['link']='veth2'
                elif case=='wrong-master':link(before,'veth3')['master']='vveth0'
                elif case=='port-blocked':link(before,'veth1')['linkinfo']['info_slave_data']['state']='disabled'
                elif case=='wrong-pvid':next(x for x in before['vlans']if x['ifname']=='veth1')['vlans'][0]['vlan']=2
                elif case=='wrong-address':next(x for x in before['addresses']if x['ifname']=='veth0')['addr_info']=[]
                elif case=='wrong-route':before['ipv6_routes']=[]
                elif case=='shared-vrf':link(before,'vveth3')['linkinfo']['info_data']['table']=1
                elif case=='bridge-down':link(before,'br1')['flags'].remove('UP')
                elif case=='baseline-clock':next(x for x in rows if x['arguments'][:2]==['vrf','exec'])['native_clock_reads']=0
                elif case=='baseline-output':next(x for x in rows if x['arguments'][:2]==['vrf','exec'])['stdout']='0 received'
                elif case=='wrong-header-offset':action(before)['keys'][0]['offset']=4
                elif case=='pedit-overlimits-hide-traffic':
                    obj=json.loads(query['stdout']);st=next(x for x in obj if 'options'in x)['options']['actions'][0]['stats'];st['overlimits']=st['packets']-9;query['stdout']=json.dumps(obj)
                elif case=='receiver-overlimits':receiver(before)['actions'][0]['stats']['overlimits']=1
                elif case=='wrong-header-type':action(before)['keys'][0]['htype']='tcp'
                elif case=='wrong-header-mask':action(before)['keys'][0]['mask']='ffffffff'
                elif case=='wrong-header-value':action(before)['keys'][0]['val']='c0000201'
                elif case=='wrong-action-kind':action(before)['kind']='gact'
                elif case=='wrong-action-verdict':action(before)['control_action']['type']='drop'
                elif case=='receiver-old-address':receiver(before)['keys']['src_port']=54321
                elif case=='receiver-wrong-field':receiver(before)['keys']['dst_port']=receiver(before)['keys'].pop('src_port')
                elif case=='hardware-rule':receiver(before)['skip_hw']=False
                elif case=='filter-duplicated':before['filters_by_device']['veth1'].append(copy.deepcopy(before['filters_by_device']['veth1'][-1]))
                elif case=='filter-other-locus':before['filters_by_device']['veth2']=copy.deepcopy(before['filters_by_device']['veth1'])
                elif case=='stale-receiver':receiver(before)['actions'][0]['stats']['packets']=10
                elif case=='receiver-counter-fake':receiver(sender['pedit_after'])['actions'][0]['stats']['drops']=1
                elif case=='counter-query-fake':
                    obj=json.loads(query['stdout']);next(x for x in obj if 'options'in x)['options']['actions'][0]['stats']['packets']=999;query['stdout']=json.dumps(obj)
                elif case=='rule-delete-ineffective':rows[rows.index(sender)+3]['pedit_after']['filters_by_device']['veth3']=copy.deepcopy(before['filters_by_device']['veth3'])
                elif case in ('bridge-leaked','vrf-leaked'):r['cleanup_state']['links'].append(dict(ifname='br1'if case=='bridge-leaked'else'vveth0'))
                elif case=='address-leaked':next(x for x in r['cleanup_state']['addresses']if x['ifname']=='veth0')['addr_info']=[dict(local='192.0.2.1')]
                elif case=='route-leaked':r['cleanup_state']['ipv4_routes'].append(dict(dst='default',table='1'))
                elif case=='master-leaked':link(r['cleanup_state'],'veth1')['master']='br1'
                elif case=='port-up':link(r['cleanup_state'],'veth0')['flags'].append('UP')
                elif case=='forwarding-leaked':r['cleanup_state']['ipv4']='1'
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
                elif case=='wrong-source-hash':r['source_hashes']['forwarding/pedit_l4port.sh']='bad'
                elif case=='wrong-tool-source':r['iproute2']['source_hashes']['tc/tc.c']='bad'
                elif case=='wrong-timeout':r['original_tc_hit_timeout_ms']=100
                elif case=='chronology-reversed':query['finished_monotonic']=query['started_monotonic']-1
                if case in ('complete','busywait-retry','background-action-packets','sender-default-variation','receiver-background-before-send'):
                    contract.validate_evidence(r)
                else:
                    with self.assertRaises((RuntimeError,KeyError,ValueError,StopIteration,IndexError)):
                        contract.validate_evidence(r)


if __name__ == '__main__':
    unittest.main()
