"""Reject incomplete native MLD transitions, original packet and cleanup evidence."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('mld', ROOT / 'tests/posix/linux-bridge-mld-contract.py')
contract = importlib.util.module_from_spec(spec); spec.loader.exec_module(contract)


class BridgeMldContractTests(unittest.TestCase):
    def test_complete_original_mld_source_filtering_and_native_boundaries(self):
        fixture = json.loads(Path(__file__).with_name('bridge-mld-transcript.json').read_text())
        cases = ['complete', 'source-order', 'delayed-delivery', 'valid-udp-checksum',
                 'missing-result', 'skip', 'original-fails', 'original-warning', 'missing-command', 'reordered-command',
                 'command-fails', 'command-warning', 'short-wait', 'time-reversed', 'wrong-tool-source', 'missing-tc-provenance',
                 'wrong-peer', 'vrf-detached', 'vrfs-share-table', 'port-down', 'wrong-address', 'snooping-disabled', 'wrong-version',
                 'missing-frame', 'frame-short', 'frame-result-short', 'wrong-ifindex', 'wrong-source-mac', 'wrong-destination-mac',
                 'wrong-ipv6-size', 'wrong-next-header', 'wrong-control-frame', 'wrong-udp-source', 'wrong-udp-port', 'wrong-payload-size', 'invalid-udp-checksum',
                 'filter-not-zero', 'filter-wrong-key', 'filter-not-drop', 'positive-not-forwarded', 'negative-forwarded',
                 'counter-wrong-bytes', 'counter-query-early', 'source-no-traversal', 'receiver-no-traversal',
                 'timeout-not-exclude', 'timeout-wait-short', 'blocked-timer-positive', 'active-timer-zero',
                 'blocked-flag-missing', 'active-flag-blocked', 'source-list-incomplete', 'extra-source', 'wrong-port',
                 'wrong-index', 'wrong-protocol', 'wrong-wildcard-mode', 'wrong-wildcard-timer',
                 'star-auto-flag-missing', 'star-wrong-port', 'star-source-listed', 'star-second-port-missing',
                 'phase-cleanup-leaked', 'scalar-ineffective', 'query-interval-ineffective', 'response-interval-ineffective', 'membership-interval-ineffective',
                 'bridge-leaked', 'port-up', 'master-leaked', 'address-leaked', 'route-leaked', 'mdb-leaked', 'forwarding-leaked',
                 'backend-succeeds', 'unknown-vrf-succeeds', 'wrong-send-count', 'wrong-byte-count', 'live-socket', 'outstanding', 'worker-fails', 'forced-stop']
        cases += [('query-missing-wildcard', i) for i, x in enumerate(fixture['commands']) if x['arguments'] == contract.QUERY]
        for case in cases:
            with self.subTest(case=case):
                r = copy.deepcopy(fixture); rows = r['commands']; traffic = [x for x in rows if x['tool'] == 'mausezahn']
                controls = [x for x in traffic if 'udp' not in x['arguments']]; data = [x for x in traffic if 'udp' in x['arguments']]
                queries = [x for x in rows if x['arguments'] == contract.QUERY]
                positive, negative = rows[rows.index(data[0])+1], rows[rows.index(data[3])+1]
                def link(state, name): return contract.links(state)[name]
                def rule(items): return next(x['options'] for x in items if x.get('options', {}).get('handle') == 101)
                def output(row, mutate):
                    obj = json.loads(row['stdout']); mutate(obj); row['stdout'] = json.dumps(obj)
                def wildcard(obj, port='veth1'): return next(x for x in contract.target(obj, port) if 'src' not in x)
                def sg(obj, number, port='veth1'): return next(x for x in contract.target(obj, port) if x.get('src') == f'2001:db8:1::{number}')
                def frame(sender, mutate):
                    packet = r['packet_trace'][traffic.index(sender)]; raw = bytearray.fromhex(packet['frame_hex']); mutate(raw); packet['frame_hex'] = raw.hex()
                excluded = next(q for q in queries if any(x.get('filter_mode') == 'exclude' for x in contract.target(json.loads(q['stdout']))))
                final_star = queries[-1]
                timeout = [x for x in rows[641:698] if x['tool']=='mausezahn' and 'udp' not in x['arguments']][-1]
                if case == 'source-order':
                    for q in queries: output(q, lambda obj: [x['source_list'].reverse() for x in contract.target(obj) if 'source_list' in x])
                elif case == 'delayed-delivery':
                    for x in traffic: x['sg_after'] = copy.deepcopy(x['sg_before'])
                elif case == 'valid-udp-checksum':
                    for sender in data:
                        def valid_checksum(raw):
                            raw[60:62] = b'\0\0'; pseudo=raw[22:54]+len(raw[54:]).to_bytes(4,'big')+b'\0\0\0\x11'+raw[54:]
                            total=sum(int.from_bytes(pseudo[i:i+2],'big') for i in range(0,len(pseudo),2))
                            while total>>16:total=(total&65535)+(total>>16)
                            raw[60:62]=((~total&65535) or 65535).to_bytes(2,'big')
                        frame(sender,valid_checksum)
                elif isinstance(case, tuple): output(rows[case[1]], lambda obj: [g.update(mdb=[x for x in g['mdb'] if x.get('grp') != contract.GROUP or 'src' in x]) for g in obj])
                elif case == 'missing-result': r['original']['stdout'] = '\n'.join(r['original']['stdout'].splitlines()[:-1])
                elif case == 'skip': r['original']['stdout'] += 'SKIP no native MLD\n'
                elif case == 'original-fails': r['original']['returncode'] = 1
                elif case == 'original-warning': r['original']['stderr'] = 'unsupported'
                elif case == 'missing-command': rows.pop(39)
                elif case == 'reordered-command': rows[37],rows[38]=rows[38],rows[37]
                elif case == 'command-fails': queries[0]['returncode'] = 1
                elif case == 'command-warning': queries[0]['stderr'] = 'fallback'
                elif case == 'short-wait': queries[0]['started_monotonic'] = controls[0]['finished_monotonic']+.1
                elif case == 'time-reversed': queries[0]['finished_monotonic'] = queries[0]['started_monotonic']-1
                elif case == 'wrong-tool-source': r['iproute2']['source_hashes']['tc/tc.c'] = 'host'
                elif case == 'missing-tc-provenance': r['tc_tool']['sha256'] = ''
                elif case == 'wrong-peer': link(data[0]['sg_before'],'veth3')['link'] = 'veth1'
                elif case == 'vrf-detached': link(data[0]['sg_before'],'veth3').pop('master')
                elif case == 'vrfs-share-table': link(data[0]['sg_before'],'vveth3')['linkinfo']['info_data']['table'] = 1
                elif case == 'port-down': link(data[0]['sg_before'],'veth2')['flags'].remove('UP')
                elif case == 'wrong-address': next(x for x in data[0]['sg_before']['addresses'] if x['ifname']=='veth0')['addr_info'] = []
                elif case == 'snooping-disabled': link(data[0]['sg_before'],'br0')['linkinfo']['info_data']['mcast_snooping'] = 0
                elif case == 'wrong-version': link(controls[0]['sg_before'],'br0')['linkinfo']['info_data']['mcast_mld_version'] = 1
                elif case == 'missing-frame': r['packet_trace'].pop()
                elif case == 'frame-short': frame(data[0],lambda b:b.pop())
                elif case == 'frame-result-short': r['packet_trace'][1]['result'] -= 1
                elif case == 'wrong-ifindex': r['packet_trace'][1]['ifindex'] = 999
                elif case == 'wrong-source-mac': frame(data[0],lambda b:b.__setitem__(6,b[6]^2))
                elif case == 'wrong-destination-mac': frame(data[0],lambda b:b.__setitem__(0,0))
                elif case == 'wrong-ipv6-size': frame(data[0],lambda b:b.__setitem__(19,b[19]^1))
                elif case == 'wrong-next-header': frame(data[0],lambda b:b.__setitem__(20,6))
                elif case == 'wrong-control-frame': frame(controls[0],lambda b:b.__setitem__(64,b[64]^1))
                elif case == 'wrong-udp-source': frame(data[0],lambda b:b.__setitem__(37,99))
                elif case == 'wrong-udp-port': frame(data[0],lambda b:b.__setitem__(55,1))
                elif case == 'wrong-payload-size': frame(data[0],lambda b:b.extend(b'junk'))
                elif case == 'invalid-udp-checksum': frame(data[0],lambda b:b.__setitem__(60,1))
                elif case == 'filter-not-zero': rule(data[0]['sg_before']['filters_by_device']['veth0'])['actions'][0]['stats']['packets'] = 1
                elif case == 'filter-wrong-key': output(positive,lambda obj:rule(obj)['keys'].update(ip_proto='tcp'))
                elif case == 'filter-not-drop': output(positive,lambda obj:rule(obj)['actions'][0]['control_action'].update(type='pass'))
                elif case == 'positive-not-forwarded': output(positive,lambda obj:rule(obj)['actions'][0]['stats'].update(packets=0,drops=0,bytes=0))
                elif case == 'negative-forwarded': output(negative,lambda obj:rule(obj)['actions'][0]['stats'].update(packets=1,drops=1,bytes=112))
                elif case == 'counter-wrong-bytes': output(positive,lambda obj:rule(obj)['actions'][0]['stats'].update(bytes=126))
                elif case == 'counter-query-early': positive['started_monotonic'] = data[0]['finished_monotonic']+.1
                elif case in ('source-no-traversal','receiver-no-traversal'):
                    name='veth3' if case=='source-no-traversal' else 'veth0';link(positive['sg_after'],name)['stats64']=copy.deepcopy(link(data[0]['sg_before'],name)['stats64'])
                elif case == 'timeout-not-exclude': wildcard(timeout['sg_before']['mdb'])['filter_mode'] = 'include'
                elif case == 'timeout-wait-short': next(q for q in rows[641:698] if q['arguments']==contract.QUERY and q['started_monotonic']>timeout['finished_monotonic'])['started_monotonic']=timeout['finished_monotonic']+1
                elif case == 'blocked-timer-positive': output(excluded,lambda obj:next(s for s in wildcard(obj)['source_list'] if s['address']=='2001:db8:1::20').update(timer='1'))
                elif case == 'active-timer-zero': output(queries[0],lambda obj:wildcard(obj)['source_list'][0].update(timer='0'))
                elif case == 'blocked-flag-missing': output(excluded,lambda obj:sg(obj,20).update(flags=[]))
                elif case == 'active-flag-blocked': output(queries[0],lambda obj:sg(obj,1).update(flags=['blocked']))
                elif case == 'source-list-incomplete': output(queries[0],lambda obj:wildcard(obj)['source_list'].pop())
                elif case == 'extra-source': output(queries[0],lambda obj:wildcard(obj)['source_list'].append(dict(address='2001:db8:1::99',timer='10')))
                elif case == 'wrong-port': output(queries[0],lambda obj:sg(obj,1).update(port='veth2'))
                elif case == 'wrong-index': output(queries[0],lambda obj:wildcard(obj).update(index=999))
                elif case == 'wrong-protocol': output(queries[0],lambda obj:wildcard(obj).update(protocol='static'))
                elif case == 'wrong-wildcard-mode': output(queries[0],lambda obj:wildcard(obj).update(filter_mode='exclude'))
                elif case == 'wrong-wildcard-timer': output(queries[0],lambda obj:wildcard(obj).update(timer='10'))
                elif case == 'star-auto-flag-missing': output(final_star,lambda obj:sg(obj,3).update(flags=[]))
                elif case == 'star-wrong-port': output(final_star,lambda obj:sg(obj,3).update(port='veth2'))
                elif case == 'star-source-listed': output(final_star,lambda obj:wildcard(obj)['source_list'].append(dict(address='2001:db8:1::3',timer='10')))
                elif case == 'star-second-port-missing': output(final_star,lambda obj:[g.update(mdb=[x for x in g['mdb'] if x.get('port')!='veth2']) for g in obj])
                elif case == 'phase-cleanup-leaked': rows[76]['sg_after']['mdb']=copy.deepcopy(json.loads(queries[0]['stdout']))
                elif case == 'scalar-ineffective': link(rows[37]['sg_after'],'br0')['linkinfo']['info_data']['mcast_mld_version']=1
                elif case in ('query-interval-ineffective','response-interval-ineffective','membership-interval-ineffective'):
                    row=next(x for x in rows if len(x['arguments'])>8 and x['arguments'][:6]==['link','set','dev','br0','type','bridge'])
                    field={'query-interval-ineffective':'mcast_query_intvl','response-interval-ineffective':'mcast_query_response_intvl','membership-interval-ineffective':'mcast_membership_intvl'}[case];link(row['sg_after'],'br0')['linkinfo']['info_data'][field]+=1
                elif case == 'bridge-leaked': r['cleanup_state']['links'].append(dict(ifname='br0'))
                elif case == 'port-up': link(r['cleanup_state'],'veth0')['flags'].append('UP')
                elif case == 'master-leaked': link(r['cleanup_state'],'veth0')['master']='vveth0'
                elif case == 'address-leaked': next(x for x in r['cleanup_state']['addresses'] if x['ifname']=='veth0')['addr_info'].append(dict(scope='global',local='2001:db8:1::1'))
                elif case == 'route-leaked': r['cleanup_state']['ipv6_routes'].append(dict(dev='veth0'))
                elif case == 'mdb-leaked': r['cleanup_state']['mdb']=copy.deepcopy(json.loads(queries[0]['stdout']))
                elif case == 'forwarding-leaked': r['cleanup_state']['ipv6']='1'
                elif case == 'backend-succeeds': r['missing_backend_control']['returncode']=0
                elif case == 'unknown-vrf-succeeds': r['vrf_binding_control']['unknown_vrf']['returncode']=0
                elif case in ('wrong-send-count','wrong-byte-count','live-socket'): r['native_fixture'][{'wrong-send-count':'bridge_packet_sends','wrong-byte-count':'bridge_packet_bytes','live-socket':'live'}[case]]=1
                elif case in ('outstanding','worker-fails','forced-stop'): r['stats'][{'outstanding':'outstanding','worker-fails':'worker_exit_code','forced-stop':'shutdown_timed_out'}[case]]=1
                if case in ('complete','source-order','delayed-delivery','valid-udp-checksum'): contract.validate_evidence(r)
                else:
                    with self.assertRaises((RuntimeError,KeyError,ValueError,IndexError)): contract.validate_evidence(r)


if __name__ == '__main__': unittest.main()
