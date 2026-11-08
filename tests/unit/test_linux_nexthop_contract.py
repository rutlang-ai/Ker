"""Require real shared nexthops, actual traffic and the original route precedence."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('nh_contract', ROOT / 'tests/posix/linux-nexthop-selftest.py')
contract = importlib.util.module_from_spec(spec); spec.loader.exec_module(contract)


class NexthopContractTests(unittest.TestCase):
    def test_native_fib_traffic_and_cleanup_are_required(self):
        original = json.loads(Path(__file__).with_name('nexthop-transcript.json').read_text())
        for mutation in ('complete', 'missing-family', 'lost-packet', 'substituted-tool-output', 'warning',
                         'timeout', 'wrong-nh-family', 'missing-route', 'reordered-route', 'missing-native-nh',
                         'wrong-fib-reference', 'no-clsact', 'wrong-ipv4-selection', 'changed-ipv6-precedence',
                         'no-forwarding', 'not-restored', 'leaked-vrf', 'leaked-clsact', 'failed-cleanup',
                         'ignored-vrf', 'host-fallback', 'live-socket', 'outstanding-packet', 'forced-stop'):
            with self.subTest(mutation=mutation):
                r = copy.deepcopy(original); rows = r['commands']
                pings = [x for x in rows if x['arguments'][:2] == ['vrf','exec']]
                nh = [x for x in rows if x['arguments'][1:2] == ['nexthop']]
                routes = [x for x in rows if 'nhid' in x['arguments']]
                if mutation == 'missing-family': rows.remove(pings[-1])
                elif mutation == 'lost-packet': pings[0]['stdout'] = '10 packets transmitted, 9 received'
                elif mutation == 'substituted-tool-output': pings[0]['stdout'] = '[{"kind":"clsact"}]\n'
                elif mutation == 'warning': pings[0]['stderr'] = 'native filter warning'
                elif mutation == 'timeout': pings[0]['arguments'][-2] = '1'
                elif mutation == 'wrong-nh-family': nh[0]['arguments'][0] = '-4'
                elif mutation == 'missing-route': rows.remove(routes[0])
                elif mutation == 'reordered-route': rows.remove(routes[0]); rows.append(routes[0])
                elif mutation == 'missing-native-nh': pings[0]['routing_state']['nexthops'].pop()
                elif mutation == 'wrong-fib-reference': pings[0]['routing_state']['ipv4'][0]['nhid'] = 999
                elif mutation == 'no-clsact': pings[0]['routing_state']['qdisc'] = []
                elif mutation == 'wrong-ipv4-selection': pings[0]['routing_state']['lookup4'][0]['nhid'] = 101
                elif mutation == 'changed-ipv6-precedence': pings[0]['routing_state']['lookup6'][0]['nhid'] = 102
                elif mutation == 'no-forwarding': r['mib_after'] = r['mib_before']
                elif mutation == 'not-restored': r['cleanup_state']['ipv6'] = '1\n'
                elif mutation == 'leaked-vrf': r['cleanup_state']['links'].append(dict(ifname='vrf-h1'))
                elif mutation == 'leaked-clsact': r['cleanup_state']['qdisc'].append(dict(kind='clsact'))
                elif mutation == 'failed-cleanup': rows[-1]['returncode'] = 1
                elif mutation == 'ignored-vrf': r['vrf_binding_control']['unknown_vrf']['returncode'] = 0
                elif mutation == 'host-fallback': r['missing_backend_control']['returncode'] = 0
                elif mutation == 'live-socket': r['native_fixture']['live'] = 1
                elif mutation == 'outstanding-packet': r['stats']['outstanding'] = 1
                elif mutation == 'forced-stop': r['stats']['shutdown_timed_out'] = True
                if mutation == 'complete': contract.validate_evidence(r)
                else:
                    with self.assertRaises(RuntimeError): contract.validate_evidence(r)


if __name__ == '__main__': unittest.main()
