"""Reject lost range boundaries, incorrect ingress/egress verdicts and fake counters."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('ranges',ROOT/'tests/posix/linux-tc-flower-port-range-contract.py')
contract=importlib.util.module_from_spec(spec);spec.loader.exec_module(contract)


class FlowerPortRangeContractTests(unittest.TestCase):
    def test_complete_original_ranges_and_negative_delivery(self):
        fixture=json.loads(Path(__file__).with_name('tc-flower-port-range-transcript.json').read_text())
        cases=['complete','delayed-observation','sender-default-variation','delayed-ingress-poll','delayed-egress-poll',
               'delayed-both-polls','poll-regression','poll-over-target','poll-final-not-reached','poll-nonmatching-hit',
               'missing-result','original-fails','skip','warning',
               'missing-command','reordered-command','query-missing','wrong-source-bound','wrong-destination-bound','scalar-range',
               'wrong-address','wrong-protocol','wrong-verdict','wrong-binding','hardware-rule','counter-not-hit','counter-out-of-range-hit',
               'wrong-bytes','wrong-drops','wrong-native-actual','other-locus','rule-leaks','query-stale','wrong-peer','wrong-master',
               'shared-vrf','wrong-bridge-mode','host-address-missing','route-missing','negative-no-delivery','positive-no-traversal',
               'bridge-leaked','vrf-leaked','address-leaked','route-leaked','master-leaked','port-up','forwarding-leaked',
               'backend-succeeds','unknown-vrf-succeeds','wrong-send-count','wrong-byte-count','trace-errors','live-socket','outstanding',
               'worker-fails','forced-stop','missing-eof','wrong-source-hash','wrong-tool-source','wrong-timeout','chronology-reversed']
        cases += [('frame-missing',i)for i in range(32)]
        cases += [('input-port',i)for i in range(32)]
        cases += [('rule-missing',i,key)for i,row in enumerate(fixture['commands'])if row['tool']in('tc','mausezahn')for key in ('range_before','range_after')]
        for case in cases:
            with self.subTest(case=case):
                r=copy.deepcopy(fixture);rows=r['commands'];traffic=[x for x in rows if x['tool']=='mausezahn'];first=traffic[0];idx=rows.index(first);q1,q2=rows[idx+1:idx+3]
                def link(state,name):return contract.ip.links(state)[name]
                def options(state,drop=False):
                    table=state['egress_filters']['veth2']if drop else state['filters_by_device']['veth1']
                    return next(x for x in table if 'options'in x)['options']
                def action(state,drop=False):return options(state,drop)['actions'][0]
                def output(row,fn):
                    obj=json.loads(row['stdout']);detail=next(x for x in obj if 'options'in x)['options'];fn(detail);row['stdout']=json.dumps(obj)
                def set_count(state,locus,count,protocol='udp',family=4):
                    table=state['filters_by_device']['veth1'] if locus=='ingress' else state['egress_filters']['veth2']
                    rule=next(x for x in table if 'options'in x);action=rule['options']['actions'][0]
                    action['stats'].update(packets=count,bytes=count*((142 if protocol=='udp' else 154)+(20 if family==6 else 0)-(0 if locus=='egress' else 14)),
                                           drops=count if locus=='egress' else 0)
                def set_output(row,locus,count):
                    size=142 if locus=='egress' else 128
                    output(row,lambda o:o['actions'][0]['stats'].update(packets=count,bytes=count*size,
                           drops=count if locus=='egress' else 0))
                def insert_delayed(loci):
                    # The first valid send is IPv4/UDP, target 1. Insert real
                    # repeated original tc-show commands with an intermediate
                    # counter, then retain the captured exact-target poll.
                    send=traffic[0];base=rows.index(send);q_ing,q_egr=rows[base+1:base+3]
                    sender=copy.deepcopy(send['range_after'])
                    set_count(sender,'ingress',0 if 'ingress' in loci else 1)
                    set_count(sender,'egress',0 if 'egress' in loci else 1)
                    send['range_after']=sender
                    for locus,q in (('ingress',q_ing),('egress',q_egr)):
                        for snapshot,state in (('before',q['range_before']),('after',q['range_after'])):
                            current=1 if locus not in loci or snapshot=='after' else 0
                            set_count(state,'ingress',current if locus=='ingress' else 1)
                            set_count(state,'egress',current if locus=='egress' else (0 if 'egress' in loci else 1))
                        if locus in loci:
                            prior=copy.deepcopy(q);set_output(prior,locus,0)
                            for state in (prior['range_before'],prior['range_after']):
                                set_count(state,'ingress',0 if locus=='ingress' else 1)
                                set_count(state,'egress',0 if locus=='egress' or 'egress' in loci else 1)
                            qindex=rows.index(q);previous=rows[qindex-1]
                            midpoint=(previous['finished_monotonic']+q['started_monotonic'])/2
                            prior['started_monotonic']=midpoint-0.0001;prior['finished_monotonic']=midpoint
                            rows.insert(qindex,prior)
                if isinstance(case,tuple):
                    if case[0]=='frame-missing':r['packet_trace'].pop(case[1])
                    elif case[0]=='rule-missing':rows[case[1]].pop(case[2])
                    else:
                        packet=r['packet_trace'][case[1]];data=bytearray.fromhex(packet['frame_hex']);data[34 if case[1]<16 else 54]^=1;packet['frame_hex']=data.hex()
                elif case=='delayed-observation':
                    for row in traffic:row['range_after']=copy.deepcopy(row['range_before'])
                elif case=='delayed-ingress-poll':insert_delayed({'ingress'})
                elif case=='delayed-egress-poll':insert_delayed({'egress'})
                elif case=='delayed-both-polls':insert_delayed({'ingress','egress'})
                elif case in ('poll-regression','poll-over-target','poll-final-not-reached','poll-nonmatching-hit'):
                    insert_delayed({'ingress'})
                    first=traffic[0];q=rows[rows.index(first)+1]
                    if case=='poll-regression':
                        output(q,lambda o:o['actions'][0]['stats'].update(packets=1,bytes=128))
                        set_count(q['range_after'],'ingress',1)
                        later=rows[rows.index(q)+1];output(later,lambda o:o['actions'][0]['stats'].update(packets=0,bytes=0))
                    elif case=='poll-over-target':output(q,lambda o:o['actions'][0]['stats'].update(packets=2,bytes=2*128))
                    elif case=='poll-final-not-reached':
                        later=rows[rows.index(q)+1];output(later,lambda o:o['actions'][0]['stats'].update(packets=0,bytes=0))
                        set_count(later['range_after'],'ingress',0)
                    else:output(q,lambda o:o['actions'][0]['stats'].update(packets=0,bytes=0,drops=1))
                elif case=='sender-default-variation':
                    for n,packet in enumerate(r['packet_trace']):
                        b=bytearray.fromhex(packet['frame_hex']);b[-100:]=bytes((x+n)%256 for x in range(100))
                        if n<16:
                            b[15]=40;b[18:20]=(100+n).to_bytes(2,'big');b[22]=64;b[24:26]=b'\0\0'
                            total=sum(int.from_bytes(b[i:i+2],'big')for i in range(14,34,2))
                            while total>>16:total=(total&65535)+(total>>16)
                            b[24:26]=(total^65535).to_bytes(2,'big')
                        else:b[14:18]=bytes.fromhex('62aabcde');b[21]=64
                        packet['frame_hex']=b.hex()
                elif case=='missing-result':r['original']['stdout']='\n'.join(r['original']['stdout'].splitlines()[:-1])
                elif case=='original-fails':r['original']['returncode']=1
                elif case=='skip':r['original']['stdout']+='SKIP\n'
                elif case=='warning':r['original']['stderr']='unsupported'
                elif case=='missing-command':rows.pop(idx)
                elif case=='reordered-command':rows[idx-1],rows[idx-2]=rows[idx-2],rows[idx-1]
                elif case=='query-missing':rows.pop(idx+1)
                elif case in ('wrong-source-bound','wrong-destination-bound','scalar-range'):
                    key='dst_port'if case=='wrong-destination-bound'else'src_port'
                    if case=='scalar-range':options(first['range_before'])['keys'][key]=100
                    else:options(first['range_before'])['keys'][key]['end']+=1
                elif case=='wrong-address':options(first['range_before'])['keys']['src_ip']='192.0.2.9'
                elif case=='wrong-protocol':options(first['range_before'])['keys']['ip_proto']='tcp'
                elif case=='wrong-verdict':action(first['range_before'],True)['control_action']['type']='pass'
                elif case=='wrong-binding':action(first['range_before'])['bind']=2
                elif case=='hardware-rule':options(first['range_before'])['not_in_hw']=False
                elif case=='counter-not-hit':output(q1,lambda o:o['actions'][0]['stats'].update(packets=0,bytes=0))
                elif case=='counter-out-of-range-hit':output(rows[rows.index(traffic[7])+1],lambda o:o['actions'][0]['stats'].update(packets=4))
                elif case=='wrong-bytes':output(q1,lambda o:o['actions'][0]['stats'].update(bytes=1))
                elif case=='wrong-drops':output(q2,lambda o:o['actions'][0]['stats'].update(drops=0))
                elif case=='wrong-native-actual':action(q2['range_after'],True)['stats']['packets']=0
                elif case=='other-locus':first['range_before']['filters_by_device']['veth3']=copy.deepcopy(first['range_before']['filters_by_device']['veth1'])
                elif case=='rule-leaks':rows[rows.index(traffic[7])+3]['range_after']['egress_filters']['veth2']=copy.deepcopy(first['range_before']['egress_filters']['veth2'])
                elif case=='query-stale':output(q1,lambda o:o['actions'][0]['stats'].update(packets=3))
                elif case=='wrong-peer':link(first['range_before'],'veth0')['link']='veth2'
                elif case=='wrong-master':link(first['range_before'],'veth2')['master']='vveth3'
                elif case=='shared-vrf':link(first['range_before'],'vveth3')['linkinfo']['info_data']['table']=1
                elif case=='wrong-bridge-mode':link(first['range_before'],'br1')['linkinfo']['info_data']['vlan_filtering']=1
                elif case=='host-address-missing':next(x for x in first['range_before']['addresses']if x['ifname']=='veth0')['addr_info']=[]
                elif case=='route-missing':first['range_before']['ipv6_routes']=[]
                elif case in ('negative-no-delivery','positive-no-traversal'):
                    final=rows[rows.index(traffic[7])+2]['range_after'];name,direction=('veth3','rx')if case=='negative-no-delivery'else('veth1','rx');link(final,name)['stats64'][direction]=copy.deepcopy(link(first['range_before'],name)['stats64'][direction])
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
                elif case=='wrong-source-hash':r['source_hashes']['forwarding/tc_flower_port_range.sh']='bad'
                elif case=='wrong-tool-source':r['iproute2']['source_hashes']['tc/tc.c']='bad'
                elif case=='wrong-timeout':r['original_tc_hit_timeout_ms']=100
                elif case=='chronology-reversed':q1['finished_monotonic']=q1['started_monotonic']-1
                if case in ('complete','delayed-observation','sender-default-variation','delayed-ingress-poll',
                            'delayed-egress-poll','delayed-both-polls'):contract.validate_evidence(r)
                else:
                    with self.assertRaises((RuntimeError,KeyError,ValueError,IndexError,StopIteration)):contract.validate_evidence(r)


if __name__=='__main__':unittest.main()
