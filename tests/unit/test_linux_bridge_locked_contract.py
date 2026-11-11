"""Reject incomplete native port-lock/MAB results and preserve original timing."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('locked',ROOT/'tests/posix/linux-bridge-locked-contract.py')
contract=importlib.util.module_from_spec(spec);spec.loader.exec_module(contract)


class BridgeLockedContractTests(unittest.TestCase):
    def test_complete_original_lock_mab_and_redirect(self):
        fixture=json.loads(Path(__file__).with_name('bridge-locked-transcript.json').read_text())
        cases=('complete','delayed-burst','random-dest-variation','default-payload-variation','redirect-background','mab-locked-prelearn',
               'missing-outcome','skip','unpinned-tc','missing-probe','missing-command','wrong-command-order',
               'missing-ping','locked-ping-succeeds','authenticated-ping-fails','wrong-ping-count','wrong-ping-output','clock-missing',
               'wrong-bridge','wrong-vlan-protocol','wrong-peer','same-vrf','wrong-host-address','wrong-host-vlan','wrong-vlan-master',
               'destination-locked','promisc-leaked','native-lock-off','native-mab-off','learning-off','static-auth-missing','static-auth-wrong-vid','locked-entry-unlocked',
               'negative-traversal-proof','ineffective-lock','invalid-config-succeeds','invalid-config-changes-state',
               'missing-query','wrong-query-result','query-locked-flag-missing','query-wrong-port','query-native-fdb-missing',
               'missing-burst','short-burst','wrong-burst-delay','short-burst-time','missing-frame','extra-frame','short-native-send',
               'wrong-frame-source','wrong-frame-protocol','wrong-udp-length','wrong-frame-interface','burst-ingress-missing',
               'roam-destination-locked','locked-roam-back','mab-prelearn-wrong-port','mab-prelearn-wrong-vid','mab-prelearn-static','mab-prelearn-unlocked','mab-prelearn-missing-state','mab-prelearn-duplicate','flush-static1-lost','flush-static2-lost','flush-other-locked-lost','flush-locked1-retained',
               'wrong-redirect-kind','wrong-redirect-direction','wrong-redirect-destination','redirect-counter-zero','redirect-byte-counter-zero',
               'redirect-filter-retained','redirect-learns-locked','missing-native-filter','missing-tc-command',
               'vlan100-admission-missing','vlan100-leaked','missing-ping-observation','missing-burst-query-proof',
               'bridge-leaked','vrf-leaked','vlan-device-leaked','veth-up','fdb-leaked','mdb-leaked','address-leaked','route-leaked',
               'missing-teardown','unexpected-error','host-fallback','ignored-vrf','wrong-send-count','wrong-send-bytes','live-socket','packet-leaked','forced-stop')
        for case in cases:
            with self.subTest(case=case):
                r=copy.deepcopy(fixture);rows=r['commands'];pings=[x for x in rows if x['arguments'][:2]==['vrf','exec']]
                bridge=[x for x in rows if x['tool']=='bridge'];queries=[x for x in bridge if x['arguments'][:2]==['fdb','get']]
                sends=[x for x in rows if x['tool']=='mausezahn'];tc=[x for x in rows if x['tool']=='tc']
                def link(state,name):return next(x for x in state['links'] if x['ifname']==name)
                def flags(state,name='veth1'):return link(state,name)['linkinfo']['info_slave_data']
                host=link(pings[0]['unaware_before'],'veth0')['address']
                flush=next(x for x in bridge if x['arguments']==['link','set','dev','veth1','mab','off'])
                def remove(state,mac):state['fdb']=[x for x in state['fdb'] if x.get('mac')!=mac]
                def rule(state):return next(x for x in state['filters_by_device']['veth1'] if x.get('options',{}).get('handle')==101)
                if case=='delayed-burst':
                    for row in sends:row['unaware_after']=copy.deepcopy(row['unaware_before'])
                elif case=='random-dest-variation':
                    frame=bytearray.fromhex(r['packet_trace'][0]['frame_hex']);frame[0]^=2;r['packet_trace'][0]['frame_hex']=frame.hex()
                elif case=='default-payload-variation':
                    frame=bytearray.fromhex(r['packet_trace'][0]['frame_hex']);frame.extend(b'body');frame[16:18]=(32).to_bytes(2,'big');frame[38:40]=(12).to_bytes(2,'big');r['packet_trace'][0].update(frame_hex=frame.hex(),length=46,result=46);r['native_fixture']['bridge_packet_bytes']+=4
                elif case=='mab-locked-prelearn':
                    pings[14]['unaware_before']['fdb'].extend(copy.deepcopy(contract.entries(pings[14]['unaware_after'],host)))
                elif case=='mab-prelearn-wrong-port':
                    entry=copy.deepcopy(contract.entries(pings[14]['unaware_after'],host)[0]);entry['ifname']='veth2'
                    pings[14]['unaware_before']['fdb'].append(entry)
                elif case=='mab-prelearn-wrong-vid':
                    entry=copy.deepcopy(contract.entries(pings[14]['unaware_after'],host)[0]);entry['vlan']=2
                    pings[14]['unaware_before']['fdb'].append(entry)
                elif case=='mab-prelearn-static':
                    entry=copy.deepcopy(contract.entries(pings[14]['unaware_after'],host)[0]);entry['state']='static';entry['flags']=[]
                    pings[14]['unaware_before']['fdb'].append(entry)
                elif case=='mab-prelearn-unlocked':
                    entry=copy.deepcopy(contract.entries(pings[14]['unaware_after'],host)[0]);entry['flags']=[]
                    pings[14]['unaware_before']['fdb'].append(entry)
                elif case=='mab-prelearn-missing-state':
                    entry=copy.deepcopy(contract.entries(pings[14]['unaware_after'],host)[0]);entry.pop('state')
                    pings[14]['unaware_before']['fdb'].append(entry)
                elif case=='mab-prelearn-duplicate':
                    pings[14]['unaware_before']['fdb'].extend(copy.deepcopy(contract.entries(pings[14]['unaware_after'],host))*2)
                elif case=='redirect-background':
                    a=rule(pings[16]['unaware_before'])['options']['actions'][0]['stats'];b=rule(pings[16]['unaware_after'])['options']['actions'][0]['stats']
                    for stats in (a,b):stats['packets']+=5;stats['bytes']+=500
                elif case in ('missing-outcome','skip'):r['original']['stdout']='' if case=='missing-outcome' else 'SKIP: no MAB'
                elif case=='unpinned-tc':r['tc_tool']['sha256']='host'
                elif case=='missing-probe':rows.remove(next(x for x in bridge if x['arguments']==['-d','link','show']))
                elif case=='missing-command':rows.remove(bridge[1])
                elif case=='wrong-command-order':
                    i,j=rows.index(bridge[1]),rows.index(bridge[2]);rows[i],rows[j]=rows[j],rows[i]
                elif case=='missing-ping':rows.remove(pings[0])
                elif case=='locked-ping-succeeds':pings[1]['returncode']=0
                elif case=='authenticated-ping-fails':pings[2]['returncode']=1
                elif case=='wrong-ping-count':pings[0]['arguments'][5]='1'
                elif case=='wrong-ping-output':pings[0]['stdout']='0 received'
                elif case=='clock-missing':pings[0]['native_clock_reads']=0
                elif case=='wrong-bridge':link(pings[0]['unaware_before'],'br0')['linkinfo']['info_data']['vlan_filtering']=0
                elif case=='wrong-vlan-protocol':link(pings[0]['unaware_before'],'br0')['linkinfo']['info_data']['vlan_protocol']='802.1ad'
                elif case=='wrong-peer':link(pings[0]['unaware_before'],'veth1')['link']='veth3'
                elif case=='same-vrf':link(pings[0]['unaware_before'],'vveth3')['linkinfo']['info_data']['table']=1
                elif case=='wrong-host-address':next(x for x in pings[0]['unaware_before']['addresses'] if x['ifname']=='veth0')['addr_info']=[]
                elif case=='wrong-host-vlan':link(pings[8]['unaware_before'],'veth0.100')['linkinfo']['info_data']['id']=101
                elif case=='wrong-vlan-master':link(pings[8]['unaware_before'],'veth0.100')['master']='vveth3'
                elif case=='destination-locked':flags(pings[0]['unaware_before'],'veth2')['locked']=True
                elif case=='promisc-leaked':link(r['cleanup_state'],'veth0')['promiscuity']=1
                elif case=='native-lock-off':flags(pings[1]['unaware_before'])['locked']=False
                elif case=='native-mab-off':flags(pings[14]['unaware_before'])['mab']=False
                elif case=='learning-off':flags(pings[14]['unaware_before'])['learning']=False
                elif case=='static-auth-missing':remove(pings[2]['unaware_before'],host)
                elif case=='static-auth-wrong-vid':next(x for x in pings[10]['unaware_before']['fdb'] if x.get('mac')==host)['vlan']=1
                elif case=='locked-entry-unlocked':contract.entries(pings[14]['unaware_after'],host)[0]['flags']=[]
                elif case=='negative-traversal-proof':link(pings[0]['unaware_after'],'veth2')['stats64']=copy.deepcopy(link(pings[0]['unaware_before'],'veth2')['stats64'])
                elif case=='ineffective-lock':flags(next(x for x in bridge if x['arguments'][-2:]==['locked','on'])['unaware_after'])['locked']=False
                elif case in ('invalid-config-succeeds','invalid-config-changes-state'):
                    row=next(x for x in bridge if x['returncode']==255)
                    if case=='invalid-config-succeeds':row['returncode']=0
                    else:flags(row['unaware_after'])['learning']=True
                elif case=='missing-query':rows.remove(queries[3])
                elif case=='wrong-query-result':queries[0]['returncode']=0
                elif case=='query-locked-flag-missing':queries[3]['stdout']=queries[3]['stdout'].replace('locked','')
                elif case=='query-wrong-port':contract.entries(queries[4]['unaware_after'],contract.ROAM)[0]['ifname']='veth1'
                elif case=='query-native-fdb-missing':remove(queries[1]['unaware_after'],host)
                elif case=='missing-burst':rows.remove(sends[0])
                elif case=='short-burst':sends[0]['arguments'][3]='1'
                elif case=='wrong-burst-delay':sends[0]['arguments'][5]='1msec'
                elif case=='short-burst-time':sends[0]['finished_monotonic']=sends[0]['started_monotonic']+0.399
                elif case=='missing-frame':r['packet_trace'].pop()
                elif case=='extra-frame':r['packet_trace'].append(copy.deepcopy(r['packet_trace'][0]))
                elif case=='short-native-send':r['packet_trace'][0]['result']-=1
                elif case in ('wrong-frame-source','wrong-frame-protocol','wrong-udp-length'):
                    frame=bytearray.fromhex(r['packet_trace'][0]['frame_hex']);frame[{'wrong-frame-source':6,'wrong-frame-protocol':23,'wrong-udp-length':39}[case]]^=1;r['packet_trace'][0]['frame_hex']=frame.hex()
                elif case=='wrong-frame-interface':r['packet_trace'][0]['ifindex']=-1
                elif case=='burst-ingress-missing':link(queries[3]['unaware_after'],'veth1')['stats64']=copy.deepcopy(link(sends[0]['unaware_before'],'veth1')['stats64'])
                elif case=='roam-destination-locked':flags(sends[1]['unaware_before'],'veth2')['locked']=True
                elif case=='locked-roam-back':contract.entries(queries[6]['unaware_after'],contract.ROAM)[0]['ifname']='veth1'
                elif case in ('flush-static1-lost','flush-static2-lost','flush-other-locked-lost'):remove(flush['unaware_after'],{'flush-static1-lost':contract.STATIC1,'flush-static2-lost':contract.STATIC2,'flush-other-locked-lost':contract.LOCK2}[case])
                elif case=='flush-locked1-retained':flush['unaware_after']['fdb'].extend(copy.deepcopy(contract.entries(flush['unaware_before'],contract.LOCK1)))
                elif case in ('wrong-redirect-kind','wrong-redirect-direction','wrong-redirect-destination'):
                    rule(pings[16]['unaware_after'])['options']['actions'][0][{'wrong-redirect-kind':'kind','wrong-redirect-direction':'direction','wrong-redirect-destination':'to_dev'}[case]]='invalid'
                elif case in ('redirect-counter-zero','redirect-byte-counter-zero'):
                    key='packets' if case=='redirect-counter-zero' else 'bytes';rule(pings[16]['unaware_after'])['options']['actions'][0]['stats'][key]=rule(pings[16]['unaware_before'])['options']['actions'][0]['stats'][key]
                elif case=='redirect-filter-retained':pings[17]['unaware_before']['filters_by_device']['veth1']=copy.deepcopy(pings[16]['unaware_after']['filters_by_device']['veth1'])
                elif case=='redirect-learns-locked':pings[16]['unaware_after']['fdb'].extend(copy.deepcopy(contract.entries(pings[17]['unaware_after'],host)))
                elif case=='missing-native-filter':pings[16]['unaware_after']['filters_by_device']['veth1']=[]
                elif case=='missing-tc-command':rows.remove(tc[1])
                elif case in ('vlan100-admission-missing','vlan100-leaked'):
                    table=next(x for x in pings[8 if case=='vlan100-admission-missing' else 12]['unaware_before']['vlans'] if x['ifname']=='veth1')
                    if case=='vlan100-admission-missing':table['vlans']=[x for x in table['vlans'] if x['vlan']!=100]
                    else:table['vlans'].append(dict(vlan=100))
                elif case=='missing-ping-observation':pings[0].pop('unaware_before')
                elif case=='missing-burst-query-proof':queries[3].pop('unaware_after')
                elif case in ('bridge-leaked','vrf-leaked','vlan-device-leaked'):r['cleanup_state']['links'].append(dict(ifname={'bridge-leaked':'br0','vrf-leaked':'vveth0','vlan-device-leaked':'veth0.100'}[case]))
                elif case=='veth-up':link(r['cleanup_state'],'veth0')['flags'].append('UP')
                elif case=='fdb-leaked':r['cleanup_state']['fdb'].append(dict(master='br0'))
                elif case=='mdb-leaked':r['cleanup_state']['mdb'].append(dict(mdb=[dict(grp='239.1.1.1')]))
                elif case=='address-leaked':next(x for x in r['cleanup_state']['addresses'] if x['ifname']=='veth0')['addr_info'].append(dict(scope='global'))
                elif case=='route-leaked':r['cleanup_state']['ipv4_routes'].append(dict(dev='veth0'))
                elif case=='missing-teardown':rows.remove(next(x for x in rows if x['arguments']==['link','del','dev','br0']))
                elif case=='unexpected-error':rows[-1]['returncode']=1
                elif case=='host-fallback':r['missing_backend_control']['returncode']=0
                elif case=='ignored-vrf':r['vrf_binding_control']['unknown_vrf']['returncode']=0
                elif case=='wrong-send-count':r['native_fixture']['bridge_packet_sends']=0
                elif case=='wrong-send-bytes':r['native_fixture']['bridge_packet_bytes']=0
                elif case=='live-socket':r['native_fixture']['live']=1
                elif case=='packet-leaked':r['stats']['outstanding']=1
                elif case=='forced-stop':r['stats']['shutdown_timed_out']=True
                if case in ('complete','delayed-burst','random-dest-variation','default-payload-variation','redirect-background','mab-locked-prelearn'):contract.validate_evidence(r)
                else:
                    with self.assertRaises((RuntimeError,KeyError,StopIteration)):contract.validate_evidence(r)


if __name__=='__main__':unittest.main()
