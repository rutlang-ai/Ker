"""Reject fabricated bridge miss outcomes, stale generations and lost probes."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('l2miss', ROOT/'tests/posix/linux-tc-flower-l2-miss-contract.py')
contract = importlib.util.module_from_spec(spec); spec.loader.exec_module(contract)


class FlowerL2MissContractTests(unittest.TestCase):
    def test_complete_original_miss_and_no_miss_forwarding(self):
        fixture = json.loads(Path(__file__).with_name('tc-flower-l2-miss-transcript.json').read_text())
        cases = ['complete','delayed-observation','unspecified-input-defaults','missing-result','original-fails','skip','warning',
                 'missing-command','changed-command','query-missing','wrong-fdb-state','fdb-missing','fdb-not-deleted',
                 'mdb-missing','mdb-not-deleted','mdb-wrong-port','mdb-wrong-protocol','querier-disabled','wrong-router',
                 'wrong-bridge','wrong-peer','wrong-master','shared-vrf','address-missing','route-missing',
                 'other-filter-locus','install-not-empty','generation-not-removed','backend-succeeds','unknown-vrf-succeeds',
                 'wrong-send-count','wrong-byte-count','trace-errors','live-socket','outstanding','worker-fails','forced-stop',
                 'missing-eof','bridge-leaked','vrf-leaked','port-up','master-leaked','address-leaked','route-leaked',
                 'forwarding-leaked','wrong-source','wrong-tool','wrong-timeout','reversed-time']
        cases += [(kind,i) for i in range(12) for kind in ('frame-missing','wrong-frame-mac','wrong-frame-interface',
                                                        'query-count','query-bytes','query-miss','query-action','no-peer-delivery')]
        cases += [('observation-missing',i,key) for i,row in enumerate(fixture['commands'])
                  if row['tool'] in ('tc','bridge','mausezahn') for key in ('l2_before','l2_after')]
        for case in cases:
            with self.subTest(case=case):
                r = copy.deepcopy(fixture); rows = r['commands']; traffic = [x for x in rows if x['tool']=='mausezahn']
                first = traffic[0]; start = rows.index(first)
                def link(state,name):return contract.ip.links(state)[name]
                def last_query(sender):
                    i=rows.index(sender)+1
                    while i+1<len(rows) and rows[i+1]['tool']=='tc' and rows[i+1]['arguments'][:4]==['-j','-s','filter','show']:i+=1
                    return rows[i]
                def options(state):return next(x['options'] for x in state['egress_filters']['veth2'] if 'options'in x)
                if isinstance(case,tuple):
                    kind,i=case[:2]
                    if kind=='observation-missing':rows[i].pop(case[2])
                    elif kind=='frame-missing':r['packet_trace'].pop(i)
                    elif kind=='wrong-frame-interface':r['packet_trace'][i]['ifindex']+=1
                    elif kind=='wrong-frame-mac':
                        packet=r['packet_trace'][i];b=bytearray.fromhex(packet['frame_hex']);b[0]^=1;packet['frame_hex']=b.hex()
                    elif kind=='no-peer-delivery':
                        link(last_query(traffic[i])['l2_after'],'veth3')['stats64']['rx']=copy.deepcopy(link(traffic[i]['l2_before'],'veth3')['stats64']['rx'])
                    else:
                        query=last_query(traffic[i]);out=json.loads(query['stdout']);o=next(x['options']for x in out if 'options'in x);a=o['actions'][0]
                        if kind=='query-count':a['stats']['packets']+=1
                        elif kind=='query-bytes':a['stats']['bytes']+=1
                        elif kind=='query-miss':o['keys']['l2_miss']=0
                        elif kind=='query-action':a['control_action']['type']='drop'
                        query['stdout']=json.dumps(out)
                elif case=='delayed-observation':
                    for sender in traffic:sender['l2_after']=copy.deepcopy(sender['l2_before'])
                elif case=='unspecified-input-defaults':
                    for packet in r['packet_trace']:
                        b=bytearray.fromhex(packet['frame_hex']);b[-50:]=bytes(range(50))
                        if b[12:14]==b'\x08\x00':
                            b[15]=29;b[18:20]=b'\x01\x02';b[22]=32;b[23]=253;b[24:26]=b'\0\0'
                            checksum=sum(int.from_bytes(b[i:i+2],'big')for i in range(14,34,2))
                            while checksum>>16:checksum=(checksum&65535)+(checksum>>16)
                            b[24:26]=(checksum^65535).to_bytes(2,'big')
                        elif b[12:14]==b'\x86\xdd':b[14:18]=bytes.fromhex('62aabcde');b[20]=253;b[21]=32
                        else:b[12:14]=b'\x88\xb5'
                        packet['frame_hex']=b.hex()
                elif case=='missing-result':r['original']['stdout']='\n'.join(r['original']['stdout'].splitlines()[:-1])
                elif case=='original-fails':r['original']['returncode']=1
                elif case=='skip':r['original']['stdout']+='SKIP\n'
                elif case=='warning':r['original']['stderr']='unsupported'
                elif case=='missing-command':rows.pop(start)
                elif case=='changed-command':first['arguments'][-3]='200'
                elif case=='query-missing':rows.pop(start+1)
                elif case in ('wrong-fdb-state','fdb-missing'):
                    state=traffic[1]['l2_before']
                    if case=='fdb-missing':state['fdb']=[]
                    else:next(x for x in state['fdb']if x.get('mac')=='00:01:02:03:04:05')['state']='dynamic'
                elif case=='fdb-not-deleted':traffic[2]['l2_before']['fdb']=copy.deepcopy(traffic[1]['l2_before']['fdb'])
                elif case in ('mdb-missing','mdb-wrong-port','mdb-wrong-protocol'):
                    state=traffic[4]['l2_before'];entry=next(x for row in state['mdb']for x in row['mdb']if x['grp']=='239.1.1.1')
                    if case=='mdb-missing':state['mdb']=[]
                    elif case=='mdb-wrong-port':entry['port']='veth1'
                    else:entry['protocol']='kernel'
                elif case=='mdb-not-deleted':traffic[5]['l2_before']['mdb']=copy.deepcopy(traffic[4]['l2_before']['mdb'])
                elif case=='querier-disabled':link(traffic[3]['l2_before'],'br1')['linkinfo']['info_data']['mcast_querier']=0
                elif case=='wrong-router':link(traffic[3]['l2_before'],'veth2')['linkinfo']['info_slave_data']['multicast_router']=1
                elif case=='wrong-bridge':link(first['l2_before'],'br1')['linkinfo']['info_data']['vlan_filtering']=1
                elif case=='wrong-peer':link(first['l2_before'],'veth0')['link']='veth2'
                elif case=='wrong-master':link(first['l2_before'],'veth2')['master']='vveth3'
                elif case=='shared-vrf':link(first['l2_before'],'vveth3')['linkinfo']['info_data']['table']=1
                elif case=='address-missing':next(x for x in first['l2_before']['addresses']if x['ifname']=='veth0')['addr_info']=[]
                elif case=='route-missing':first['l2_before']['ipv6_routes']=[]
                elif case=='other-filter-locus':first['l2_before']['filters_by_device']['veth3']=copy.deepcopy(first['l2_before']['egress_filters']['veth2'])
                elif case=='install-not-empty':rows[start-2]['l2_before']['egress_filters']['veth2']=copy.deepcopy(first['l2_before']['egress_filters']['veth2'])
                elif case=='generation-not-removed':rows[rows.index(last_query(traffic[2]))+2]['l2_after']['egress_filters']['veth2']=copy.deepcopy(first['l2_before']['egress_filters']['veth2'])
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
                elif case in ('bridge-leaked','vrf-leaked'):r['cleanup_state']['links'].append(dict(ifname='br1'if case=='bridge-leaked'else'vveth0'))
                elif case=='port-up':link(r['cleanup_state'],'veth0')['flags'].append('UP')
                elif case=='master-leaked':link(r['cleanup_state'],'veth1')['master']='br1'
                elif case=='address-leaked':next(x for x in r['cleanup_state']['addresses']if x['ifname']=='veth0')['addr_info']=[dict(local='192.0.2.1')]
                elif case=='route-leaked':r['cleanup_state']['ipv4_routes'].append(dict(table='1',dst='default'))
                elif case=='forwarding-leaked':r['cleanup_state']['ipv6']='1'
                elif case=='wrong-source':r['source_hashes']['forwarding/tc_flower_l2_miss.sh']='bad'
                elif case=='wrong-tool':r['iproute2']['source_hashes']['tc/tc.c']='bad'
                elif case=='wrong-timeout':r['original_tc_hit_timeout_ms']=100
                elif case=='reversed-time':first['finished_monotonic']=first['started_monotonic']-1
                if case in ('complete','delayed-observation','unspecified-input-defaults'):contract.validate_evidence(r)
                else:
                    with self.assertRaises((RuntimeError,KeyError,ValueError,IndexError,StopIteration)):contract.validate_evidence(r)


if __name__=='__main__':unittest.main()
