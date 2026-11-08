"""Reject incomplete original broadcast phases, source predicates and native state."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('broadcast', ROOT / 'tests/posix/linux-broadcast-contract.py')
contract = importlib.util.module_from_spec(spec); spec.loader.exec_module(contract)


class BroadcastContractTests(unittest.TestCase):
    def test_complete_original_and_incomplete_native_evidence(self):
        original = json.loads(Path(__file__).with_name('broadcast-transcript.json').read_text())
        mutations = ('complete', 'missing-outcome', 'missing-ping', 'missing-grep', 'wrong-target',
                     'changed-timeout', 'wrong-vrf', 'no-clock', 'clock-backward', 'wrong-predicate',
                     'wrong-grep-input', 'wrong-grep-result', 'positive-source-missing', 'negative-source-present',
                     'wrong-phase', 'echo-disabled', 'forwarding-disabled', 'missing-forwarding',
                     'unexpected-forwarding', 'wrong-peer', 'router-mastered', 'host-wrong-master',
                     'interface-down', 'vrf-same-table', 'missing-address', 'missing-connected-route',
                     'missing-host-route', 'wrong-gateway', 'missing-restore', 'reordered-phase',
                     'sysctl-not-restored', 'vrf-leaked', 'interface-left-up', 'address-leaked', 'route-leaked',
                     'cleanup-failed', 'no-total-forwarding', 'host-fallback', 'ignored-vrf',
                     'live-socket', 'outstanding-packet', 'forced-stop')
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                r = copy.deepcopy(original); rows = r['commands']
                pings = [x for x in rows if x['arguments'][:2] == ['vrf', 'exec']]
                greps = [x for x in rows if x['tool'] == 'grep']
                state = pings[0]['broadcast_before']
                links = {x['ifname']: x for x in state['links']}
                if mutation == 'missing-outcome': r['original']['stdout'] = ''
                elif mutation == 'missing-ping': rows.remove(pings[3])
                elif mutation == 'missing-grep': rows.remove(greps[3])
                elif mutation == 'wrong-target': pings[0]['arguments'][6] = '127.0.0.1'
                elif mutation == 'changed-timeout': pings[0]['arguments'][-2] = '1'
                elif mutation == 'wrong-vrf': pings[0]['vrf']['ifname'] = 'vrf-h2'
                elif mutation == 'no-clock': pings[0].pop('native_clock_reads')
                elif mutation in ('clock-backward', 'positive-source-missing', 'negative-source-present'):
                    n = 10 if mutation == 'negative-source-present' else 0
                    if mutation == 'clock-backward': pings[n]['stdout'] += 'Warning: time of day goes back (-42us), taking countermeasures\n'
                    elif mutation == 'positive-source-missing': pings[n]['stdout'] = 'PING: no reply\n'
                    else: pings[n]['stdout'] += '64 bytes from 192.0.2.1: icmp_seq=1\n'
                    greps[n]['input'] = pings[n]['stdout']
                    greps[n]['input_sha256'] = hashlib.sha256(greps[n]['input'].encode()).hexdigest()
                    if mutation == 'positive-source-missing': greps[n]['returncode'] = 1
                    elif mutation == 'negative-source-present': greps[n]['returncode'] = 0
                elif mutation == 'wrong-predicate': greps[0]['arguments'] = ['bytes from 127.0.0.1']
                elif mutation == 'wrong-grep-input': greps[0]['input'] = ''
                elif mutation == 'wrong-grep-result': greps[0]['returncode'] = 1
                elif mutation == 'wrong-phase': state['sysctls'][contract.BC_KEYS[0]] = '1'
                elif mutation == 'echo-disabled': state['sysctls']['net.ipv4.icmp_echo_ignore_broadcasts'] = '1'
                elif mutation == 'forwarding-disabled': state['sysctls']['net.ipv4.conf.all.forwarding'] = '0'
                elif mutation == 'missing-forwarding': pings[8]['broadcast_after']['snmp'] = pings[8]['broadcast_before']['snmp']
                elif mutation == 'unexpected-forwarding': pings[0]['broadcast_after']['snmp'] = pings[8]['broadcast_after']['snmp']
                elif mutation == 'wrong-peer': links['veth4']['link'] = 'veth1'
                elif mutation == 'router-mastered': links['veth1']['master'] = 'vrf-h1'
                elif mutation == 'host-wrong-master': links['veth5']['master'] = 'vrf-h1'
                elif mutation == 'interface-down': links['veth3']['flags'].remove('UP')
                elif mutation == 'vrf-same-table': links['vrf-h2']['linkinfo']['info_data']['table'] = 1
                elif mutation == 'missing-address': next(x for x in state['addresses'] if x['ifname'] == 'veth4')['addr_info'] = []
                elif mutation == 'missing-connected-route': state['routes'] = [x for x in state['routes'] if not (x.get('dev') == 'veth1' and x.get('protocol') == 'kernel')]
                elif mutation == 'missing-host-route': state['routes'] = [x for x in state['routes'] if x.get('gateway') != '192.0.2.1']
                elif mutation == 'wrong-gateway': next(x for x in state['routes'] if x.get('gateway') == '192.0.2.1')['gateway'] = '192.0.2.3'
                elif mutation == 'missing-restore': rows.remove(next(x for x in rows if x['tool'] == 'sysctl' and x['arguments'] == ['-qw', 'net.ipv4.icmp_echo_ignore_broadcasts=1']))
                elif mutation == 'reordered-phase':
                    n = next(i for i, x in enumerate(rows) if x['arguments'] == ['-qw', 'net.ipv4.conf.all.bc_forwarding=1']); rows.append(rows.pop(n))
                elif mutation == 'sysctl-not-restored': r['cleanup_state']['sysctls']['net.ipv4.conf.all.bc_forwarding'] = '1'
                elif mutation == 'vrf-leaked': r['cleanup_state']['links'].append(dict(ifname='vrf-h3'))
                elif mutation == 'interface-left-up': next(x for x in r['cleanup_state']['links'] if x['ifname'] == 'veth5')['flags'].append('UP')
                elif mutation == 'address-leaked': next(x for x in r['cleanup_state']['addresses'] if x['ifname'] == 'veth0')['addr_info'].append(dict(scope='global'))
                elif mutation == 'route-leaked': r['cleanup_state']['routes'].append(dict(dev='veth0'))
                elif mutation == 'cleanup-failed': rows[-1]['returncode'] = 1
                elif mutation == 'no-total-forwarding': r['mib_after'] = r['mib_before']
                elif mutation == 'host-fallback': r['missing_backend_control']['returncode'] = 0
                elif mutation == 'ignored-vrf': r['vrf_binding_control']['unknown_vrf']['returncode'] = 0
                elif mutation == 'live-socket': r['native_fixture']['live'] = 1
                elif mutation == 'outstanding-packet': r['stats']['outstanding'] = 1
                elif mutation == 'forced-stop': r['stats']['shutdown_timed_out'] = True
                if mutation == 'complete': contract.validate_evidence(r)
                else:
                    with self.assertRaises(RuntimeError): contract.validate_evidence(r)


if __name__ == '__main__': unittest.main()
