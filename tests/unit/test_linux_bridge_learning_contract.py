"""Reject false complete FDB-learning success using recorded native evidence."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('learning', ROOT / 'tests/posix/linux-bridge-learning-contract.py')
contract = importlib.util.module_from_spec(spec); spec.loader.exec_module(contract)


class BridgeLearningContractTests(unittest.TestCase):
    def test_initial_default_source_observation_is_bounded(self):
        fixture = json.loads(Path(__file__).with_name('bridge-learning-transcript.json').read_text())
        cases = ('complete', 'split-zero-default', 'target-mac', 'other-mac', 'extra-row', 'wrong-port',
                 'wrong-master', 'wrong-vlan', 'wrong-state', 'wrong-flags', 'wrong-count', 'zero-count',
                 'later-flush', 'baseline-not-zero', 'baseline-command-changed', 'split-zero-foreign',
                 'split-zero-target', 'split-zero-extra', 'split-zero-wrong-port', 'split-zero-wrong-master',
                 'split-zero-vlan', 'split-zero-wrong-state', 'split-zero-wrong-flags',
                 'split-zero-higher-count', 'split-zero-baseline-not-zero')
        accepted = ('complete', 'split-zero-default', 'zero-count')
        for case in cases:
            with self.subTest(case=case):
                r=copy.deepcopy(fixture); rows=r['commands']
                flushes=[x for x in rows if x['arguments'][:2]==['fdb','flush']]
                row=flushes[1] if case=='later-flush' else flushes[0]; state=row['learning_after']
                entry=dict(mac=contract.DEFAULT_MAC,ifname='veth1',flags=[],master='br0',state='')
                state['fdb'].append(entry); contract.data(state)['fdb_n_learned']=1
                baseline=rows[rows.index(flushes[0])+1]
                if case.startswith('split-zero-'):
                    contract.data(state)['fdb_n_learned']=0
                if case in ('target-mac', 'split-zero-target'):entry['mac']=contract.MAC
                elif case in ('other-mac', 'split-zero-foreign'):entry['mac']='de:ad:be:ef:42:99'
                elif case in ('extra-row', 'split-zero-extra'):state['fdb'].append(copy.deepcopy(entry))
                elif case in ('wrong-port', 'split-zero-wrong-port'):entry['ifname']='veth3'
                elif case == 'wrong-master':entry['master']='other'
                elif case == 'wrong-vlan':entry['vlan']=1
                elif case == 'wrong-state':entry['state']='static'
                elif case == 'wrong-flags':entry['flags']=['extern_learn']
                elif case == 'wrong-count':contract.data(state)['fdb_n_learned']=2
                elif case == 'zero-count':contract.data(state)['fdb_n_learned']=0
                elif case == 'split-zero-wrong-master':entry['master']='other'
                elif case == 'split-zero-vlan':entry['vlan']=1
                elif case == 'split-zero-wrong-state':entry['state']='static'
                elif case == 'split-zero-wrong-flags':entry['flags']=['extern_learn']
                elif case == 'split-zero-higher-count':contract.data(state)['fdb_n_learned']=2
                elif case in ('baseline-not-zero', 'split-zero-baseline-not-zero'):
                    contract.data(baseline['learning_after'])['fdb_n_learned']=1
                elif case == 'baseline-command-changed':baseline['arguments'][-1]='extern_learn'
                if case in accepted:contract.validate_evidence(r)
                else:
                    with self.assertRaises(RuntimeError) as raised:
                        contract.validate_evidence(r)
                    if case == 'split-zero-higher-count':
                        self.assertIn('fdb_n_learned=2', str(raised.exception))
                        self.assertIn('dynamic_entries=', str(raised.exception))

    def test_native_five_type_accounting_and_limit(self):
        original = json.loads(Path(__file__).with_name('bridge-learning-transcript.json').read_text())
        mutations = ('complete', 'missing-outcome', 'skip', 'diagnostic', 'missing-capability', 'missing-count',
                     'wrong-count', 'missing-ping', 'wrong-count-argument', 'wrong-ping-destination', 'ping-failed',
                     'no-clock', 'no-state', 'wrong-source', 'wrong-peer', 'same-vrf', 'reply-learning-enabled',
                     'source-learning-disabled', 'bridge-vlan-aware', 'port-blocked', 'wrong-after-count',
                     'limit-not-set', 'limit-exceeded', 'limited-mac-learned', 'only-vlan1-learned', 'source-not-sent',
                     'ingress-not-seen', 'destination-not-reached', 'missing-restore', 'missing-flush', 'wrong-user-command',
                     'missing-external-flag', 'static-counted', 'local-attached-wrong', 'local-state-wrong',
                     'local-mac-wrong', 'missing-local-removal', 'missing-local-snapshot', 'limit-query-wrong',
                     'limit-query-only-vlan1', 'cleanup-failed', 'bridge-leaked', 'vrf-leaked', 'veth-up',
                     'fdb-leaked', 'route-leaked', 'missing-teardown', 'host-fallback', 'ignored-vrf',
                     'live-socket', 'outstanding-packet', 'forced-stop')
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                r = copy.deepcopy(original); rows = r['commands']
                pings = [x for x in rows if x['arguments'][:2] == ['vrf', 'exec']]
                first = pings[0]; after = first['learning_after']; before = first['learning_before']
                links = {x['ifname']: x for x in after['links']}
                bridge = next(x for x in after['links'] if x['ifname'] == 'br0')['linkinfo']['info_data']
                limited = pings[29]; limited_bridge = next(x for x in limited['learning_after']['links'] if x['ifname'] == 'br0')['linkinfo']['info_data']
                learned = contract.target(after['fdb'], contract.PREFIX + '01')[0]
                local = next(x for x in rows if x['arguments'][:4] == ['link', 'set', 'veth5', 'master'])
                if mutation == 'missing-outcome': r['original']['stdout'] = ''
                elif mutation == 'skip': r['original']['stdout'] += 'SKIP: unsupported\n'
                elif mutation == 'diagnostic': r['original']['stderr'] = 'unrelated failure'
                elif mutation == 'missing-capability': rows.remove(next(x for x in rows if x['arguments'] == ['link', 'help', 'bridge']))
                elif mutation in ('missing-count', 'wrong-count'):
                    q = next(x for x in rows if x['arguments'] == contract.COUNT_QUERY)
                    if mutation == 'missing-count': rows.remove(q)
                    else:
                        objects = json.loads(q['stdout']); objects[0]['linkinfo']['info_data']['fdb_n_learned'] = 1; q['stdout'] = json.dumps(objects)
                elif mutation == 'missing-ping': rows.remove(first)
                elif mutation == 'wrong-count-argument': first['arguments'][5] = '0'
                elif mutation == 'wrong-ping-destination': first['arguments'][-1] = '127.0.0.1'
                elif mutation == 'ping-failed': first['returncode'] = 1
                elif mutation == 'no-clock': first['native_clock_reads'] = 0
                elif mutation == 'no-state': first.pop('learning_after')
                elif mutation == 'wrong-source': links['veth0']['address'] = contract.MAC
                elif mutation == 'wrong-peer': links['veth1']['link'] = 'veth2'
                elif mutation == 'same-vrf': links['vveth2']['linkinfo']['info_data']['table'] = links['vveth0']['linkinfo']['info_data']['table']
                elif mutation == 'reply-learning-enabled': links['veth3']['linkinfo']['info_slave_data']['learning'] = True
                elif mutation == 'source-learning-disabled': links['veth1']['linkinfo']['info_slave_data']['learning'] = False
                elif mutation == 'bridge-vlan-aware': bridge['vlan_filtering'] = 1
                elif mutation == 'port-blocked': links['veth1']['linkinfo']['info_slave_data']['state'] = 'blocking'
                elif mutation == 'wrong-after-count': bridge['fdb_n_learned'] = 0
                elif mutation == 'limit-not-set': limited_bridge['fdb_max_learned'] = 0
                elif mutation == 'limit-exceeded': limited_bridge['fdb_n_learned'] = 9
                elif mutation == 'limited-mac-learned':
                    entry = copy.deepcopy(learned); entry['mac'] = contract.PREFIX + '09'; limited['learning_after']['fdb'].append(entry)
                elif mutation == 'only-vlan1-learned': learned['vlan'] = 1
                elif mutation in ('source-not-sent', 'ingress-not-seen', 'destination-not-reached'):
                    dev, direction = {'source-not-sent':('veth0', 'tx'), 'ingress-not-seen':('veth1', 'rx'), 'destination-not-reached':('veth2', 'rx')}[mutation]
                    links[dev]['stats64'][direction] = copy.deepcopy(next(x for x in before['links'] if x['ifname'] == dev)['stats64'][direction])
                elif mutation == 'missing-restore': rows.remove(rows[rows.index(first) + 1])
                elif mutation == 'missing-flush': rows.remove(next(x for x in rows if x['arguments'][:2] == ['fdb', 'flush']))
                elif mutation == 'wrong-user-command': next(x for x in rows if x['arguments'][:2] == ['fdb', 'replace'] and x['arguments'][-1] == 'use')['arguments'].pop()
                elif mutation in ('missing-external-flag', 'static-counted'):
                    row = next(x for x in rows if x['arguments'][:2] == ['fdb', 'replace'] and (x['arguments'][-1] == 'extern_learn' if mutation == 'missing-external-flag' else x['arguments'][-1] == 'static'))
                    if mutation == 'missing-external-flag': contract.target(row['learning_after']['fdb'])[0]['flags'] = []
                    else: next(x for x in row['learning_after']['links'] if x['ifname'] == 'br0')['linkinfo']['info_data']['fdb_n_learned'] = 1
                elif mutation == 'local-attached-wrong': next(x for x in local['learning_after']['links'] if x['ifname'] == 'veth5')['master'] = 'other'
                elif mutation == 'local-state-wrong': contract.target(local['learning_after']['fdb'])[0]['state'] = 'static'
                elif mutation == 'local-mac-wrong': next(x for x in local['learning_after']['links'] if x['ifname'] == 'veth5')['address'] = contract.DEFAULT_MAC
                elif mutation == 'missing-local-removal': rows.remove(next(x for x in rows if x['arguments'] == ['link', 'set', 'veth5', 'nomaster']))
                elif mutation == 'missing-local-snapshot': local.pop('learning_after')
                elif mutation in ('limit-query-wrong', 'limit-query-only-vlan1'):
                    q = [x for x in rows if x['arguments'] == contract.FDB_QUERY][1]; objects = json.loads(q['stdout'])
                    q['stdout'] = json.dumps([] if mutation == 'limit-query-wrong' else [x for x in objects if x.get('vlan') == 1])
                elif mutation == 'cleanup-failed': rows[-1]['returncode'] = 1
                elif mutation in ('bridge-leaked', 'vrf-leaked'): r['cleanup_state']['links'].append(dict(ifname='br0' if mutation == 'bridge-leaked' else 'vveth0'))
                elif mutation == 'veth-up': next(x for x in r['cleanup_state']['links'] if x['ifname'] == 'veth0')['flags'].append('UP')
                elif mutation == 'fdb-leaked': r['cleanup_state']['fdb'].append(copy.deepcopy(learned))
                elif mutation == 'route-leaked': r['cleanup_state']['ipv4_routes'].append(dict(dev='veth0'))
                elif mutation == 'missing-teardown': rows.remove(next(x for x in rows if x['arguments'] == ['link', 'del', 'dev', 'br0']))
                elif mutation == 'host-fallback': r['missing_backend_control']['returncode'] = 0
                elif mutation == 'ignored-vrf': r['vrf_binding_control']['unknown_vrf']['returncode'] = 0
                elif mutation == 'live-socket': r['native_fixture']['live'] = 1
                elif mutation == 'outstanding-packet': r['stats']['outstanding'] = 1
                elif mutation == 'forced-stop': r['stats']['shutdown_timed_out'] = True
                if mutation == 'complete': contract.validate_evidence(r)
                else:
                    with self.assertRaises(RuntimeError): contract.validate_evidence(r)


if __name__ == '__main__': unittest.main()
