"""Reject false complete MDB group-limit, partial-control and cleanup evidence."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('mdb_max',ROOT/'tests/posix/linux-bridge-mdb-max-contract.py')
contract=importlib.util.module_from_spec(spec);spec.loader.exec_module(contract)


class BridgeMdbMaxContractTests(unittest.TestCase):
    def test_complete_native_limits_and_control_contract(self):
        fixture=json.loads(Path(__file__).with_name('bridge-mdb-max-transcript.json').read_text())
        cases=['complete','source-order','delayed-delivery','missing-result','original-fails','original-warning','skip',
               'missing-command','reordered-command','unexpected-rejection','rejection-succeeds','positive-warning',
               'wrong-vlan-choice','wrong-derived-limit','wrong-derived-source-list','ignored-limit','other-port-limit',
               'other-vlan-limit','missing-port-count','wrong-port-count','wrong-port-limit-query','missing-vlan-attributes',
               'unexpected-vlan-attributes','wrong-text-dump','missing-api-proof','wrong-api-mode','rejected-mutates',
               'missing-frame','short-frame','short-result','wrong-ifindex','wrong-mac','bad-igmp-checksum',
               'bad-mld-checksum','bad-hbh','bad-ipv6-size','wrong-payload','short-control-wait','time-reversed',
               'wrong-peer','shared-vrf','wrong-vlan','wrong-address','wrong-version','fastleave-disabled',
               'source-no-traversal','ingress-no-traversal','control-ignored','control-leave-ignored',
               'partial-forwarding-over-cap','partial-logical-source-missing','partial-source-fabricated',
               'control-other-vlan-mutated','temp-survives-toggle','permanent-lost-toggle','toggle-ignored','toggle-short-wait',
               'maximum-reset-toggle','bridge-leaked','vlan-leaked','port-up','master-leaked','address-leaked','route-leaked',
               'mdb-leaked','forwarding-leaked','backend-succeeds','unknown-vrf-succeeds','wrong-send-count','wrong-byte-count',
               'trace-errors','live-socket','outstanding','worker-fails','forced-stop','missing-eof','wrong-helper-source','wrong-tool-source']
        for i,x in enumerate(fixture['commands']):
            if x['tool']=='bridge' and x['arguments'][:4]in (['-j','-d','link','show'],['-j','-d','vlan','show']):
                obj=contract.query_object(x)
                if 'mcast_n_groups'in obj:cases.append(('counter-missing',i))
        cases += [('api-before-missing',i)for i,x in enumerate(fixture['commands'])if 'mdb_api_before'in x]
        cases += [('api-after-missing',i)for i,x in enumerate(fixture['commands'])if 'mdb_api_after'in x]
        cases += [('frame-missing',i)for i in range(88)]
        for case in cases:
            with self.subTest(case=case):
                r=copy.deepcopy(fixture);rows=r['commands'];traffic=[x for x in rows if x['tool']=='mausezahn'];query=rows[rows.index(traffic[0])+1]
                partial_sender=rows[124];partial_query=rows[125]
                def link(state,name):return contract.links(state)[name]
                def output(row,fn):
                    obj=json.loads(row['stdout']);fn(obj);row['stdout']=json.dumps(obj)
                def scalar_object(obj):return obj[0]['vlans'][0]if 'vlans'in obj[0]else obj[0]
                def port(state,name='veth1'):return next(x for x in state['port_details']if x['ifname']==name)
                def vlan(state,vid=10):return next(v for x in state['vlan_details']if x['ifname']=='veth1'for v in x['vlans']if v['vlan']==vid)
                def group(state,g='239.1.1.1',vid=0):return [e for e in contract.entries(state['mdb'])if e['port']=='veth1'and e['grp']==g and e.get('vid',0)==vid]
                def wildcard(state,g='239.1.1.1',vid=0):return next(e for e in group(state,g,vid)if 'src'not in e)
                def frame(n,fn):
                    p=r['packet_trace'][n];b=bytearray.fromhex(p['frame_hex']);fn(b);p['frame_hex']=b.hex()
                if isinstance(case,tuple):
                    kind,i=case
                    if kind=='counter-missing':output(rows[i],lambda obj:scalar_object(obj).pop('mcast_n_groups'))
                    elif kind=='api-before-missing':rows[i].pop('mdb_api_before')
                    elif kind=='api-after-missing':rows[i].pop('mdb_api_after')
                    else:r['packet_trace'].pop(i)
                elif case=='source-order':
                    for row in rows:
                        for key,value in row.items():
                            if key.startswith('mdb_api_'):objects=value
                            elif key.startswith('mdb_max_')or key.startswith('sg_'):objects=value.get('mdb',[])
                            else:continue
                            for obj in objects:
                                obj.get('mdb',[]).reverse()
                                for e in obj.get('mdb',[]):e.get('source_list',[]).reverse()
                elif case=='delayed-delivery':
                    for x in traffic:x['sg_after']=copy.deepcopy(x['sg_before'])
                elif case=='missing-result':r['original']['stdout']='\n'.join(r['original']['stdout'].splitlines()[:-1])
                elif case=='original-fails':r['original']['returncode']=1
                elif case=='original-warning':r['original']['stderr']='unsupported'
                elif case=='skip':r['original']['stdout']+='SKIP unsupported\n'
                elif case=='missing-command':rows.pop(88)
                elif case=='reordered-command':rows[88],rows[89]=rows[89],rows[88]
                elif case=='unexpected-rejection':rows[59]['returncode']=1
                elif case=='rejection-succeeds':rows[91]['returncode']=0
                elif case=='positive-warning':rows[59]['stderr']='fallback'
                elif case=='wrong-vlan-choice':rows[471]['arguments'][7]='10'if rows[471]['arguments'][7]=='20'else'20'
                elif case=='wrong-derived-limit':
                    row=rows[90];value=int(row['arguments'][-1])+1;row['arguments'][-1]=str(value);port(row['mdb_max_after'])['mcast_max_groups']=value
                elif case=='wrong-derived-source-list':rows[474]['arguments'][-1]=rows[474]['arguments'][-1].rsplit(',',1)[0]+',192.0.2.99'
                elif case=='ignored-limit':port(rows[83]['mdb_max_after'])['mcast_max_groups']=0
                elif case=='other-port-limit':port(rows[83]['mdb_max_after'],'veth2')['mcast_max_groups']=1
                elif case=='other-vlan-limit':vlan(rows[433]['mdb_max_after'],20)['mcast_max_groups']=1
                elif case=='missing-port-count':output(rows[58],lambda obj:scalar_object(obj).pop('mcast_n_groups'))
                elif case=='wrong-port-count':output(rows[58],lambda obj:scalar_object(obj).update(mcast_n_groups=999))
                elif case=='wrong-port-limit-query':output(rows[58],lambda obj:scalar_object(obj).update(mcast_max_groups=999))
                elif case=='missing-vlan-attributes':
                    row=next(x for x in rows if x['arguments'][:4]==['-j','-d','vlan','show']and 'mcast_n_groups'in contract.query_object(x));output(row,lambda obj:scalar_object(obj).pop('mcast_n_groups'))
                elif case=='unexpected-vlan-attributes':
                    row=next(x for x in rows if x['arguments'][:4]==['-j','-d','vlan','show']and 'mcast_n_groups'not in contract.query_object(x));output(row,lambda obj:scalar_object(obj).update(mcast_n_groups=0,mcast_max_groups=0))
                elif case=='wrong-text-dump':query['stdout']=''
                elif case=='missing-api-proof':rows[59].pop('mdb_api_after')
                elif case=='wrong-api-mode':next(e for e in contract.entries(rows[59]['mdb_api_after'])if e.get('grp')=='239.1.1.1'and 'src'not in e)['filter_mode']='exclude'
                elif case=='rejected-mutates':rows[91]['mdb_api_after']=[]
                elif case=='missing-frame':r['packet_trace']=[]
                elif case=='short-frame':frame(0,lambda b:b.pop())
                elif case=='short-result':r['packet_trace'][0]['result']-=1
                elif case=='wrong-ifindex':r['packet_trace'][0]['ifindex']=999
                elif case=='wrong-mac':frame(0,lambda b:b.__setitem__(6,b[6]^2))
                elif case=='bad-igmp-checksum':frame(0,lambda b:b.__setitem__(36,b[36]^1))
                elif case=='bad-mld-checksum':frame(2,lambda b:b.__setitem__(64,b[64]^1))
                elif case=='bad-hbh':frame(2,lambda b:b.__setitem__(56,5))
                elif case=='bad-ipv6-size':frame(2,lambda b:b.__setitem__(19,b[19]^1))
                elif case=='wrong-payload':frame(0,lambda b:b.__setitem__(-1,99))
                elif case=='short-control-wait':query['started_monotonic']=traffic[0]['finished_monotonic']+.1
                elif case=='time-reversed':query['finished_monotonic']=query['started_monotonic']-1
                elif case=='wrong-peer':link(traffic[0]['sg_before'],'veth1')['link']='veth3'
                elif case=='shared-vrf':link(traffic[0]['sg_before'],'vveth3')['linkinfo']['info_data']['table']=link(traffic[0]['sg_before'],'vveth0')['linkinfo']['info_data']['table']
                elif case=='wrong-vlan':link(traffic[0]['sg_before'],'veth0.10')['linkinfo']['info_data']['id']=20
                elif case=='wrong-address':next(x for x in traffic[0]['sg_before']['addresses']if x['ifname']=='veth0.10')['addr_info']=[]
                elif case=='wrong-version':link(traffic[0]['sg_before'],'br0')['linkinfo']['info_data']['mcast_igmp_version']=2
                elif case=='fastleave-disabled':link(traffic[0]['sg_before'],'veth1')['linkinfo']['info_slave_data']['fastleave']=False
                elif case in ('source-no-traversal','ingress-no-traversal'):
                    name='veth0.10'if case=='source-no-traversal'else'veth1';link(query['mdb_max_after'],name)['stats64']=copy.deepcopy(link(traffic[0]['sg_before'],name)['stats64'])
                elif case=='control-ignored':
                    for g in query['mdb_max_after']['mdb']:g['mdb']=[e for e in g.get('mdb',[])if e['grp']!='239.1.1.1']
                elif case=='control-leave-ignored':
                    leave=rows[rows.index(traffic[1])+1];leave['mdb_max_after']['mdb']=copy.deepcopy(query['mdb_max_after']['mdb'])
                elif case=='partial-forwarding-over-cap':
                    original=next(e for e in group(query['mdb_max_after'])if 'src'in e);partial_query['mdb_max_after']['mdb'][0]['mdb'].append(copy.deepcopy(original))
                elif case=='partial-logical-source-missing':wildcard(partial_query['mdb_max_after'])['source_list'].pop()
                elif case=='partial-source-fabricated':wildcard(partial_query['mdb_max_after'])['source_list'].append(dict(address='192.0.2.99',timer='100'))
                elif case=='control-other-vlan-mutated':
                    target=rows[536];assert any(e.get('grp')=='239.1.1.112'for e in contract.entries(target['sg_before']['mdb']));q=rows[537]
                    for g in q['mdb_max_after']['mdb']:g['mdb']=[e for e in g.get('mdb',[])if e.get('grp')!='239.1.1.112']
                elif case=='temp-survives-toggle':rows[672]['sg_after']['mdb']=copy.deepcopy(rows[672]['sg_before']['mdb'])
                elif case=='permanent-lost-toggle':rows[680]['sg_after']['mdb']=[]
                elif case=='toggle-ignored':link(rows[672]['sg_after'],'br0')['linkinfo']['info_data']['mcast_vlan_snooping']=1
                elif case=='toggle-short-wait':rows[673]['started_monotonic']=rows[672]['finished_monotonic']+.1
                elif case=='maximum-reset-toggle':
                    for row in (rows[674],rows[676]):output(row,lambda obj:scalar_object(obj).update(mcast_max_groups=0));vlan(row['mdb_max_after'])['mcast_max_groups']=0
                elif case in ('bridge-leaked','vlan-leaked'):r['cleanup_state']['links'].append(dict(ifname='br0'if case=='bridge-leaked'else'veth0.10'))
                elif case=='port-up':link(r['cleanup_state'],'veth0')['flags'].append('UP')
                elif case=='master-leaked':link(r['cleanup_state'],'veth0')['master']='vveth0'
                elif case=='address-leaked':next(x for x in r['cleanup_state']['addresses']if x['ifname']=='veth0')['addr_info'].append(dict(local='192.0.2.1',scope='global'))
                elif case=='route-leaked':r['cleanup_state']['ipv4_routes'].append(dict(dev='veth0'))
                elif case=='mdb-leaked':r['cleanup_state']['mdb']=copy.deepcopy(query['mdb_max_after']['mdb'])
                elif case=='forwarding-leaked':r['cleanup_state']['ipv6']='1'
                elif case=='backend-succeeds':r['missing_backend_control']['returncode']=0
                elif case=='unknown-vrf-succeeds':r['vrf_binding_control']['unknown_vrf']['returncode']=0
                elif case in ('wrong-send-count','wrong-byte-count','trace-errors','live-socket'):r['native_fixture'][{'wrong-send-count':'bridge_packet_sends','wrong-byte-count':'bridge_packet_bytes','trace-errors':'bridge_packet_trace_errors','live-socket':'live'}[case]]=1
                elif case in ('outstanding','worker-fails','forced-stop','missing-eof'):r['stats'][{'outstanding':'outstanding','worker-fails':'worker_exit_code','forced-stop':'shutdown_timed_out','missing-eof':'control_eof'}[case]]=False if case=='missing-eof'else 1
                elif case=='wrong-helper-source':r['source_hashes']['forwarding/tc_common.sh']='host'
                elif case=='wrong-tool-source':r['iproute2']['source_hashes']['tc/tc.c']='host'
                if case in ('complete','source-order','delayed-delivery'):contract.validate_evidence(r)
                else:
                    with self.assertRaises((RuntimeError,KeyError,ValueError,IndexError)):contract.validate_evidence(r)
        print(f'MDB maximum scenarios: {len(cases)} total; 3 positive; {len(cases)-3} negative')


if __name__=='__main__':unittest.main()
