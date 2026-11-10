"""Reject missing original MDB API, scale, traffic, and resource evidence."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('mdb', ROOT / 'tests/posix/linux-bridge-mdb-contract.py')
contract = importlib.util.module_from_spec(spec); spec.loader.exec_module(contract)


class BridgeMdbContractTests(unittest.TestCase):
    def test_complete_original_mdb_contract(self):
        fixture = json.loads(Path(__file__).with_name('bridge-mdb-transcript.json').read_text())
        cases = ['complete', 'source-order', 'delayed-delivery', 'batch-path', 'read-only-retry', 'valid-udp-checksum',
                 'missing-result', 'skip', 'original-fails', 'original-warning', 'missing-command', 'reordered-command',
                 'positive-fails', 'negative-succeeds', 'positive-warning', 'time-reversed', 'short-querier-wait',
                 'short-busywait', 'helper-changed', 'tool-source-changed', 'tc-provenance-missing',
                 'wrong-peer', 'detached-vrf', 'shared-vrf', 'port-down', 'wrong-vlan', 'untagged-vlan',
                 'wrong-address', 'wrong-router', 'snooping-disabled', 'wrong-version',
                 'frame-short', 'frame-result-short', 'wrong-ifindex', 'wrong-mac', 'wrong-source',
                 'wrong-l2-type', 'wrong-ipv4-checksum', 'wrong-ipv6-length', 'wrong-udp-port', 'invalid-udp-checksum',
                 'igmp-corrupt', 'mld-corrupt', 'hbh-corrupt', 'filter-wrong-key', 'filter-not-drop',
                 'positive-not-forwarded', 'negative-forwarded', 'counter-wrong-bytes', 'second-handle-wrong',
                 'query-early', 'source-no-traversal', 'receiver-no-traversal', 'before-counter-not-zero',
                 'missing-api-proof', 'target-missing', 'wrong-mode', 'wrong-state', 'wrong-proto', 'wrong-index', 'source-missing',
                 'blocked-flag-missing', 'rejected-mutates', 'unrelated-group-deleted', 'same-group-other-port-deleted', 'flush-ineffective',
                 'permanent-report-mutates', 'temporary-report-ignored', 'control-lookup-succeeds',
                 'bridge-leaked', 'dummy-leaked', 'vlan-leaked', 'port-up', 'master-leaked', 'address-leaked',
                 'route-leaked', 'mdb-leaked', 'forwarding-leaked', 'backend-succeeds', 'unknown-vrf-succeeds',
                 'wrong-send-count', 'wrong-byte-count', 'trace-errors', 'live-socket', 'outstanding', 'worker-fails',
                 'forced-stop', 'control-eof-missing']
        cases += [('missing-api-before',i) for i,r in enumerate(fixture['commands']) if 'mdb_api_before' in r]
        cases += [('missing-api-after',i) for i,r in enumerate(fixture['commands']) if 'mdb_api_after' in r]
        cases += [('missing-frame',i) for i in range(51)]
        cases += [(mutation,i) for mutation in ('batch-reduced','batch-duplicated','dump-reduced','dump-duplicated','dump-wrong-port') for i,r in enumerate(fixture['commands']) if 'batch_text' in r]
        groups={contract.address(contract.scalar(x['arguments'],'grp')) for x in fixture['commands'] if x['tool']=='bridge' and 'grp'in x['arguments']}
        first_send=next(x for x in fixture['commands'] if x['tool']=='mausezahn')
        bridge_index=contract.links(first_send['sg_before'])['br0']['ifindex']
        for case in cases:
            with self.subTest(case=case):
                if isinstance(case,tuple) and case[0] in ('missing-api-before','missing-api-after'):
                    row=copy.deepcopy(fixture['commands'][case[1]])
                    row.pop('mdb_api_before' if case[0]=='missing-api-before' else 'mdb_api_after')
                    with self.assertRaises((RuntimeError,KeyError)):contract.api_evidence(row,groups,bridge_index)
                    continue
                r=copy.deepcopy(fixture);rows=r['commands'];traffic=[x for x in rows if x['tool']=='mausezahn']
                api=[x for x in rows if 'mdb_api_after' in x]
                positive=rows[rows.index(traffic[2])+1];negative=rows[rows.index(traffic[0])+1]
                def link(state,name):return contract.links(state)[name]
                def rule(obj,handle=1):return next(x['options'] for x in obj if x.get('options',{}).get('handle')==handle)
                def output(row,mutate):
                    obj=json.loads(row['stdout']);mutate(obj);row['stdout']=json.dumps(obj)
                def frame(index,mutate):
                    packet=r['packet_trace'][index];raw=bytearray.fromhex(packet['frame_hex']);mutate(raw);packet['frame_hex']=raw.hex()
                def primary(row):
                    args=row['arguments'];return next(x for x in contract.entries(row['mdb_api_after']) if x['grp']==contract.address(contract.scalar(args,'grp')) and x['port']==contract.scalar(args,'port') and ('src' in x)==('src' in args))
                populated=next(x for x in api if x['returncode']==0 and x['arguments'][1] in ('add','replace') and any(y.get('source_list') for y in contract.entries(x['mdb_api_after'])))
                if isinstance(case,tuple):
                    kind,i=case
                    if kind=='missing-api-before':rows[i].pop('mdb_api_before')
                    elif kind=='missing-api-after':rows[i].pop('mdb_api_after')
                    elif kind=='missing-frame':r['packet_trace'].pop(i)
                    elif kind.startswith('batch-'):
                        text=rows[i]['batch_text'].splitlines();text.pop() if kind=='batch-reduced' else text.__setitem__(-1,text[0]);rows[i]['batch_text']='\n'.join(text)+'\n';rows[i]['batch_sha256']=hashlib.sha256(rows[i]['batch_text'].encode()).hexdigest()
                    else:
                        text=rows[i+1]['stdout'].splitlines();j=next(j for j,line in enumerate(text) if 'permanent' in line)
                        if kind=='dump-reduced':text.pop(j)
                        elif kind=='dump-duplicated':text[j]=next(line for line in text[j+1:] if 'permanent' in line)
                        else:
                            fields=text[j].split();fields[3]='br-test1-du99';text[j]=' '.join(fields)
                        rows[i+1]['stdout']='\n'.join(text)+'\n'
                elif case=='source-order':
                    for x in api:
                        for key in ('mdb_api_before','mdb_api_after'):
                            for g in x[key]:
                                g.get('mdb',[]).reverse()
                                for e in g.get('mdb',[]):e.get('source_list',[]).reverse()
                elif case=='delayed-delivery':
                    for x in traffic:x['sg_after']=copy.deepcopy(x['sg_before'])
                elif case=='batch-path':
                    for x in rows:
                        if 'batch_text'in x:x['arguments'][1]='/tmp/independent-original-random-path'
                elif case=='read-only-retry':
                    query=copy.deepcopy(positive);moment=(traffic[2]['finished_monotonic']+positive['started_monotonic'])/2
                    query.update(started_monotonic=moment,finished_monotonic=moment)
                    output(query,lambda obj:rule(obj)['actions'][0]['stats'].update(packets=0,drops=0,bytes=0))
                    rows.insert(rows.index(positive),query)
                elif case=='valid-udp-checksum':
                    for index in (0,4):
                        def valid(raw):
                            offset=34 if index==0 else 54;udp=raw[offset:];udp[6:8]=b'\0\0'
                            pseudo=raw[26:34]+b'\0\x11'+len(udp).to_bytes(2,'big') if index==0 else raw[22:54]+len(udp).to_bytes(4,'big')+b'\0\0\0\x11'
                            total=sum(int.from_bytes((pseudo+udp)[j:j+2],'big') for j in range(0,len(pseudo+udp),2))
                            while total>>16:total=(total&65535)+(total>>16)
                            raw[offset+6:offset+8]=((~total&65535) or 65535).to_bytes(2,'big')
                        frame(index,valid)
                elif case=='missing-result':r['original']['stdout']='\n'.join(r['original']['stdout'].splitlines()[:-1])
                elif case=='skip':r['original']['stdout']+='SKIP no native MDB\n'
                elif case=='original-fails':r['original']['returncode']=1
                elif case=='original-warning':r['original']['stderr']='unsupported'
                elif case=='missing-command':rows.pop(40)
                elif case=='reordered-command':rows[40],rows[41]=rows[41],rows[40]
                elif case=='positive-fails':rows[1]['returncode']=1
                elif case=='negative-succeeds':rows[8]['returncode']=0
                elif case=='positive-warning':rows[1]['stderr']='fallback'
                elif case=='time-reversed':positive['finished_monotonic']=positive['started_monotonic']-1
                elif case=='short-querier-wait':traffic[0]['started_monotonic']-=10
                elif case=='short-busywait':r['original_tc_hit_timeout_ms']=100
                elif case=='helper-changed':r['source_hashes']['forwarding/tc_common.sh']='host'
                elif case=='tool-source-changed':r['iproute2']['source_hashes']['tc/tc.c']='host'
                elif case=='tc-provenance-missing':r['tc_tool']['sha256']=''
                elif case=='wrong-peer':link(traffic[0]['sg_before'],'veth3')['link']='veth1'
                elif case=='detached-vrf':link(traffic[0]['sg_before'],'veth3').pop('master')
                elif case=='shared-vrf':link(traffic[0]['sg_before'],'vveth3')['linkinfo']['info_data']['table']=link(traffic[0]['sg_before'],'vveth0')['linkinfo']['info_data']['table']
                elif case=='port-down':link(traffic[0]['sg_before'],'veth2')['flags'].remove('UP')
                elif case=='wrong-vlan':link(traffic[0]['sg_before'],'veth0.10')['linkinfo']['info_data']['id']=20
                elif case=='untagged-vlan':next(x for x in traffic[0]['sg_before']['vlans'] if x['ifname']=='br0')['vlans'][0]['flags']=['PVID']
                elif case=='wrong-address':next(x for x in traffic[0]['sg_before']['addresses'] if x['ifname']=='veth0.10')['addr_info']=[]
                elif case in ('wrong-router','snooping-disabled','wrong-version'):link(traffic[0]['sg_before'],'br0')['linkinfo']['info_data'][{'wrong-router':'mcast_router','snooping-disabled':'mcast_snooping','wrong-version':'mcast_igmp_version'}[case]]=2
                elif case=='frame-short':frame(0,lambda b:b.pop())
                elif case=='frame-result-short':r['packet_trace'][0]['result']-=1
                elif case=='wrong-ifindex':r['packet_trace'][0]['ifindex']=999
                elif case=='wrong-mac':frame(0,lambda b:b.__setitem__(6,b[6]^2))
                elif case=='wrong-source':frame(4,lambda b:b.__setitem__(37,99))
                elif case=='wrong-l2-type':frame(8,lambda b:b.__setitem__(12,8))
                elif case=='wrong-ipv4-checksum':frame(0,lambda b:b.__setitem__(24,b[24]^1))
                elif case=='wrong-ipv6-length':frame(4,lambda b:b.__setitem__(19,b[19]^1))
                elif case=='wrong-udp-port':frame(0,lambda b:b.__setitem__(35,1))
                elif case=='invalid-udp-checksum':frame(4,lambda b:b.__setitem__(60,1))
                elif case=='igmp-corrupt':frame(47,lambda b:b.__setitem__(35,b[35]^1))
                elif case=='mld-corrupt':frame(49,lambda b:b.__setitem__(64,b[64]^1))
                elif case=='hbh-corrupt':frame(49,lambda b:b.__setitem__(56,5))
                elif case=='filter-wrong-key':output(positive,lambda obj:rule(obj)['keys'].update(vlan_id=20))
                elif case=='filter-not-drop':output(positive,lambda obj:rule(obj)['actions'][0]['control_action'].update(type='pass'))
                elif case=='positive-not-forwarded':output(positive,lambda obj:rule(obj)['actions'][0]['stats'].update(packets=0,drops=0,bytes=0))
                elif case=='negative-forwarded':output(negative,lambda obj:rule(obj)['actions'][0]['stats'].update(packets=1,drops=1,bytes=156))
                elif case=='counter-wrong-bytes':output(positive,lambda obj:rule(obj)['actions'][0]['stats'].update(bytes=999))
                elif case=='second-handle-wrong':output(rows[rows.index(traffic[17])+1],lambda obj:rule(obj,2)['actions'][0]['stats'].update(packets=0,drops=0,bytes=0))
                elif case=='query-early':positive['started_monotonic']=traffic[2]['started_monotonic']
                elif case in ('source-no-traversal','receiver-no-traversal'):
                    name='veth0.10' if case=='source-no-traversal' else 'br0';link(positive['sg_after'],name)['stats64']=copy.deepcopy(link(traffic[2]['sg_before'],name)['stats64'])
                elif case=='before-counter-not-zero':rule(traffic[0]['sg_before']['filters_by_device']['br0'])['actions'][0]['stats']['packets']=1
                elif case=='missing-api-proof':api[-1].pop('mdb_api_after')
                elif case=='target-missing':next(x for x in api if x['returncode']==0 and x['arguments'][1]=='add')['mdb_api_after']=[]
                elif case in ('wrong-mode','wrong-state','wrong-proto','wrong-index'):
                    row=next(x for x in api if x['returncode']==0 and x['arguments'][1]=='add' and contract.scalar(x['arguments'],'port')=='veth1' and 'filter_mode'in primary(x));e=primary(row);e[{'wrong-mode':'filter_mode','wrong-state':'state','wrong-proto':'protocol','wrong-index':'index'}[case]]={'wrong-mode':'unsupported','wrong-state':'unsupported','wrong-proto':'kernel','wrong-index':999}[case]
                elif case=='source-missing':next(y for y in contract.entries(populated['mdb_api_after']) if y.get('source_list'))['source_list'].pop()
                elif case=='blocked-flag-missing':
                    row=next(x for x in api if x['returncode']==0 and any('blocked'in y.get('flags',[]) for y in contract.entries(x['mdb_api_after'])));next(y for y in contract.entries(row['mdb_api_after']) if 'blocked'in y.get('flags',[]))['flags']=[]
                elif case=='rejected-mutates':
                    row=next(x for x in api if x['returncode'] and any(y['grp'] in groups for y in contract.entries(x['mdb_api_before'])));row['mdb_api_after']=[]
                elif case=='unrelated-group-deleted':
                    row=next(x for x in api if x['returncode']==0 and x['arguments'][1] in ('add','replace','del') and any(y['grp'] in groups-{contract.address(contract.scalar(x['arguments'],'grp'))} for y in contract.entries(x['mdb_api_before'])));group=contract.address(contract.scalar(row['arguments'],'grp'))
                    for g in row['mdb_api_after']:g['mdb']=[e for e in g.get('mdb',[]) if e['grp']==group]
                elif case=='same-group-other-port-deleted':
                    row=rows[229];assert row['arguments']==['mdb','del','dev','br0','port','veth1','grp','239.1.1.1','vid','10']
                    for g in row['mdb_api_after']:
                        g['mdb']=[e for e in g.get('mdb',[]) if not (e.get('grp')=='239.1.1.1' and
                            e.get('port')=='veth2')]
                elif case=='flush-ineffective':
                    row=next(x for x in api if x['arguments'][1]=='flush' and x['mdb_api_before']!=x['mdb_api_after']);row['mdb_api_after']=copy.deepcopy(row['mdb_api_before'])
                elif case in ('permanent-report-mutates','temporary-report-ignored'):
                    sender=traffic[47 if case=='permanent-report-mutates' else 48];row=next(x for x in rows[rows.index(sender)+1:] if 'mdb_api_before'in x)
                    e=next(x for x in contract.entries(row['mdb_api_before']) if x.get('grp')=='239.1.1.1' and x.get('port')=='veth1' and x.get('vid')==10 and 'src'not in x);e['source_list']=[]
                elif case=='control-lookup-succeeds':rows[rows.index(traffic[47])+1]['returncode']=0
                elif case in ('bridge-leaked','dummy-leaked','vlan-leaked'):r['cleanup_state']['links'].append(dict(ifname={'bridge-leaked':'br0','dummy-leaked':'br-test1-du1','vlan-leaked':'veth0.10'}[case]))
                elif case=='port-up':link(r['cleanup_state'],'veth0')['flags'].append('UP')
                elif case=='master-leaked':link(r['cleanup_state'],'veth0')['master']='vveth0'
                elif case=='address-leaked':next(x for x in r['cleanup_state']['addresses'] if x['ifname']=='veth0')['addr_info'].append(dict(scope='global',local='192.0.2.1'))
                elif case=='route-leaked':r['cleanup_state']['ipv4_routes'].append(dict(dev='veth0'))
                elif case=='mdb-leaked':r['cleanup_state']['mdb']=copy.deepcopy(populated['mdb_api_after'])
                elif case=='forwarding-leaked':r['cleanup_state']['ipv6']='1'
                elif case=='backend-succeeds':r['missing_backend_control']['returncode']=0
                elif case=='unknown-vrf-succeeds':r['vrf_binding_control']['unknown_vrf']['returncode']=0
                elif case in ('wrong-send-count','wrong-byte-count','trace-errors','live-socket'):r['native_fixture'][{'wrong-send-count':'bridge_packet_sends','wrong-byte-count':'bridge_packet_bytes','trace-errors':'bridge_packet_trace_errors','live-socket':'live'}[case]]=1
                elif case in ('outstanding','worker-fails','forced-stop','control-eof-missing'):r['stats'][{'outstanding':'outstanding','worker-fails':'worker_exit_code','forced-stop':'shutdown_timed_out','control-eof-missing':'control_eof'}[case]]=False if case=='control-eof-missing' else 1
                if case in ('complete','source-order','delayed-delivery','batch-path','read-only-retry','valid-udp-checksum'):contract.validate_evidence(r)
                else:
                    with self.assertRaises((RuntimeError,KeyError,ValueError,IndexError)):contract.validate_evidence(r)
        print(f'MDB contract scenarios: {len(cases)} total, 6 positive, {len(cases)-6} negative')


if __name__=='__main__':unittest.main()
