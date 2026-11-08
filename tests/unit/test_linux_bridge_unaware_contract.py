"""Exercise original learning, ageing and flood evidence, including async delivery."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('unaware', ROOT / 'tests/posix/linux-bridge-unaware-contract.py')
contract = importlib.util.module_from_spec(spec); spec.loader.exec_module(contract)


class BridgeUnawareContractTests(unittest.TestCase):
    def test_complete_learning_ageing_flood_matrix(self):
        fixture = json.loads(Path(__file__).with_name('bridge-unaware-transcript.json').read_text())
        cases = ('complete', 'delayed-delivery', 'payload-variation', 'missing-outcome', 'skip', 'tc-unpinned',
                 'missing-phase', 'ineffective-flag', 'early-age-query', 'early-packet-query', 'swapped-fdb',
                 'missing-fdb-proof', 'learning-absent', 'wrong-fdb-port', 'aged-fdb-persists', 'learning-off-learns',
                 'missing-ping', 'ping-fails', 'short-ping', 'missing-clock', 'wrong-topology', 'same-vrf',
                 'wrong-age', 'snooping-enabled', 'vlan-enabled', 'missing-frame', 'extra-frame', 'short-send',
                 'wrong-ifindex', 'wrong-source-mac', 'wrong-dest-mac', 'wrong-dest-ip', 'wrong-mz-count',
                 'missing-tc', 'negative-leaks', 'positive-missing', 'wrong-byte-count', 'missing-query-proof',
                 'post-wait-traversal-missing', 'flood-disabled', 'known-flood-target', 'filter-not-reset',
                 'promisc-missing', 'promisc-ineffective', 'bridge-leaked', 'vrf-leaked', 'veth-up',
                 'route-leaked', 'fdb-leaked', 'missing-teardown', 'unexpected-error', 'host-fallback',
                 'ignored-vrf', 'wrong-send-count', 'wrong-send-bytes', 'live-socket', 'outstanding-packet', 'forced-stop')
        for case in cases:
            with self.subTest(case=case):
                r=copy.deepcopy(fixture);rows=r['commands']
                pings=[x for x in rows if x['arguments'][:2]==['vrf','exec']]
                mz=[x for x in rows if x['tool']=='mausezahn'];tc=[x for x in rows if x['tool']=='tc']
                queries=[x for x in tc if x['arguments'][:2]==['-j','-s']]
                fdb=[x for x in rows if x['tool']=='bridge' and x['arguments']==contract.FDB]
                def link(state,name):return next(x for x in state['links'] if x['ifname']==name)
                def rule(objects):return next(x for x in objects if x.get('options',{}).get('handle')==101)
                def counter(query,key,value):
                    obj=json.loads(query['stdout']);rule(obj)['options']['actions'][0]['stats'][key]=value;query['stdout']=json.dumps(obj)
                if case=='delayed-delivery':
                    for sender in mz:
                        sender['unaware_after']=copy.deepcopy(sender['unaware_before'])
                elif case=='payload-variation':
                    frame=bytearray.fromhex(r['packet_trace'][0]['frame_hex']);frame[-1]^=1;r['packet_trace'][0]['frame_hex']=frame.hex()
                elif case in ('missing-outcome','skip'):r['original']['stdout']='' if case=='missing-outcome' else 'SKIP: unavailable'
                elif case=='tc-unpinned':r['tc_tool']['sha256']='host-tool'
                elif case=='missing-phase':rows.remove(next(x for x in rows if x['tool']=='bridge' and 'learning' in x['arguments']))
                elif case=='ineffective-flag':
                    row=next(x for x in rows if x['tool']=='bridge' and x['arguments'][-2:]==['learning','off']);link(row['unaware_after'],'veth1')['linkinfo']['info_slave_data']['learning']=True
                elif case=='early-age-query':fdb[2]['started_monotonic']=fdb[1]['finished_monotonic']+19.9
                elif case=='early-packet-query':queries[0]['started_monotonic']=mz[0]['finished_monotonic']+0.99
                elif case=='swapped-fdb':
                    i,j=rows.index(fdb[1]),rows.index(fdb[2]);rows[i],rows[j]=rows[j],rows[i]
                elif case=='missing-fdb-proof':fdb[1].pop('unaware_after')
                elif case=='learning-absent':fdb[1]['unaware_after']['fdb']=[]
                elif case=='wrong-fdb-port':contract.target(fdb[1]['unaware_after']['fdb'])[0]['ifname']='veth2'
                elif case in ('aged-fdb-persists','learning-off-learns'):
                    fdb[2 if case=='aged-fdb-persists' else 3]['unaware_after']['fdb'].extend(copy.deepcopy(contract.target(fdb[1]['unaware_after']['fdb'])))
                elif case=='missing-ping':rows.remove(pings[0])
                elif case=='ping-fails':pings[0]['returncode']=1
                elif case=='short-ping':pings[0]['arguments'][5]='1'
                elif case=='missing-clock':pings[1]['native_clock_reads']=0
                elif case=='wrong-topology':link(pings[0]['unaware_after'],'veth1')['master']='other'
                elif case=='same-vrf':link(pings[0]['unaware_after'],'vveth3')['linkinfo']['info_data']['table']=link(pings[0]['unaware_after'],'vveth0')['linkinfo']['info_data']['table']
                elif case in ('wrong-age','snooping-enabled','vlan-enabled'):
                    data=link(pings[0]['unaware_after'],'br0')['linkinfo']['info_data'];data[{'wrong-age':'ageing_time','snooping-enabled':'mcast_snooping','vlan-enabled':'vlan_filtering'}[case]]=1
                elif case=='missing-frame':r['packet_trace']=[]
                elif case=='extra-frame':r['packet_trace'].append(copy.deepcopy(r['packet_trace'][0]))
                elif case=='short-send':r['packet_trace'][0]['result']-=1
                elif case=='wrong-ifindex':r['packet_trace'][0]['ifindex']=-1
                elif case in ('wrong-source-mac','wrong-dest-mac','wrong-dest-ip'):
                    i=4 if case=='wrong-dest-ip' else 0;frame=bytearray.fromhex(r['packet_trace'][i]['frame_hex']);frame[{'wrong-source-mac':6,'wrong-dest-mac':0,'wrong-dest-ip':33}[case]]^=1;r['packet_trace'][i]['frame_hex']=frame.hex()
                elif case=='wrong-mz-count':mz[0]['arguments'][2]='0'
                elif case=='missing-tc':rows.remove(tc[1])
                elif case=='negative-leaks':counter(queries[2],'packets',1)
                elif case=='positive-missing':counter(queries[3],'packets',0)
                elif case=='wrong-byte-count':counter(queries[1],'bytes',98)
                elif case=='missing-query-proof':queries[3].pop('unaware_after')
                elif case=='post-wait-traversal-missing':
                    for name in ('veth2','veth3'):link(queries[3]['unaware_after'],name)['stats64']=copy.deepcopy(link(mz[5]['unaware_before'],name)['stats64'])
                elif case=='flood-disabled':link(mz[5]['unaware_before'],'veth2')['linkinfo']['info_slave_data']['flood']=False
                elif case=='known-flood-target':mz[4]['unaware_before']['fdb'].append(dict(mac=contract.MAC))
                elif case=='filter-not-reset':rule(mz[4]['unaware_before']['filters_by_device']['veth3'])['options']['actions'][0]['stats']['packets']=1
                elif case=='promisc-missing':rows.remove(next(x for x in rows if 'promisc' in x['arguments']))
                elif case=='promisc-ineffective':
                    row=next(x for x in rows if 'promisc' in x['arguments']);link(row['unaware_after'],'veth0')['promiscuity']=0
                elif case in ('bridge-leaked','vrf-leaked'):r['cleanup_state']['links'].append(dict(ifname='br0' if case=='bridge-leaked' else 'vveth0'))
                elif case=='veth-up':link(r['cleanup_state'],'veth0')['flags'].append('UP')
                elif case=='route-leaked':r['cleanup_state']['ipv4_routes'].append(dict(dev='veth0'))
                elif case=='fdb-leaked':r['cleanup_state']['fdb'].append(dict(mac=contract.MAC))
                elif case=='missing-teardown':rows.remove(next(x for x in rows if x['arguments']==['link','del','dev','br0']))
                elif case=='unexpected-error':rows[-1]['returncode']=1
                elif case=='host-fallback':r['missing_backend_control']['returncode']=0
                elif case=='ignored-vrf':r['vrf_binding_control']['unknown_vrf']['returncode']=0
                elif case=='wrong-send-count':r['native_fixture']['bridge_packet_sends']=0
                elif case=='wrong-send-bytes':r['native_fixture']['bridge_packet_bytes']=0
                elif case=='live-socket':r['native_fixture']['live']=1
                elif case=='outstanding-packet':r['stats']['outstanding']=1
                elif case=='forced-stop':r['stats']['shutdown_timed_out']=True
                if case in ('complete','delayed-delivery','payload-variation'):contract.validate_evidence(r)
                else:
                    with self.assertRaises(RuntimeError):contract.validate_evidence(r)


if __name__=='__main__':unittest.main()
