"""Require native IPv6 error attribution and complete original tool execution."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('instats', ROOT / 'tests/posix/linux-forwarding-instats-contract.py')
contract = importlib.util.module_from_spec(spec); spec.loader.exec_module(contract)


def counter(text, field, value):
    return '\n'.join(name + '\t' + str(value if name == field else count) for name, count in contract.mib(text).items()) + '\n'


class ForwardingInstatsContractTests(unittest.TestCase):
    def test_complete_original_ipv6_ingress_and_native_boundaries(self):
        fixture = json.loads(Path(__file__).with_name('forwarding-instats-transcript.json').read_text())
        cases = ('complete', 'numeric-route-tables', 'nonzero-counter-baseline', 'one-error-probe',
                 'missing-outcome', 'skip', 'original-failure', 'original-warning', 'unpinned-tools',
                 'missing-command', 'reordered-phase', 'unexpected-command-failure', 'warning',
                 'tool-exits-early', 'tool-no-destination', 'wrong-traceroute-arguments', 'missing-tool-provenance',
                 'poll-control-fails', 'poll-control-missing-case', 'poll-control-host-fallback', 'missing-control-provenance',
                 'proc-host-fallback', 'proc-traversal-accepted', 'proc-loopback-invalid',
                 'vrf-missing', 'vrf-down', 'router-master-up', 'vrfs-share-table', 'wrong-peer', 'port-detached', 'device-down',
                 'wrong-mtu', 'wrong-address', 'host-route-missing', 'router-route-missing',
                 'forwarding-stays-enabled', 'forwarding-never-enabled', 'wrong-vrf-binding', 'clock-missing',
                 'ping-replies-missing', 'negative-ping-succeeds', 'negative-ping-output-missing', 'native-traversal-missing',
                 'proc-read-missing', 'proc-read-wrong-device', 'proc-read-wrong-ifindex', 'proc-delta-zero', 'proc-delta-inconsistent',
                 'native-delta-zero', 'wrong-error-class', 'wrong-ping-accounting',
                 'policy-missing', 'policy-wrong-destination', 'policy-wrong-direction', 'policy-allows', 'policy-extra',
                 'policy-not-removed', 'policy-add-silent-failure', 'policy-delete-silent-failure',
                 'forwarding-restore-missing', 'native-ipv4-forwarding-leaked',
                 'vrf-leaked', 'device-up', 'master-leaked', 'mtu-leaked', 'address-leaked', 'route-leaked', 'policy-leaked', 'forwarding-leaked',
                 'missing-backend-succeeds', 'unknown-vrf-succeeds', 'live-socket', 'packet-leaked', 'worker-fails', 'forced-stop')
        for case in cases:
            with self.subTest(case=case):
                r = copy.deepcopy(fixture); rows = r['commands']; traffic = [x for x in rows if x['arguments'][:2] == ['vrf', 'exec']]
                reads = [x for x in rows if x['tool'] == 'cat']; xfrm = [x for x in rows if x['arguments'][:1] == ['xfrm']]
                def link(state, name): return contract.links(state)[name]
                def change_mib(state, field, value, device='veth1'): state['ipv6_mib'][device] = counter(state['ipv6_mib'][device], field, value)
                if case == 'numeric-route-tables':
                    for x in traffic:
                        for key in ('instats_before', 'instats_after'):
                            for route in x[key]['ipv6_routes']:
                                if str(route.get('table', '')).isdigit(): route['table'] = int(route['table'])
                elif case in ('nonzero-counter-baseline', 'one-error-probe'):
                    for row in rows:
                        for key in ('instats_before', 'instats_after'):
                            if key not in row: continue
                            for dev, text in row[key]['ipv6_mib'].items():
                                values = contract.mib(text)
                                for field in contract.FIELDS:
                                    value = values[field]
                                    if case == 'nonzero-counter-baseline': value += 100
                                    elif field != 'Ip6InHdrErrors' and value == 5: value = 1
                                    text = counter(text, field, value)
                                row[key]['ipv6_mib'][dev] = text
                    for row in reads:
                        values = contract.mib(row['stdout'])
                        for field in contract.FIELDS:
                            value = values[field]
                            if case == 'nonzero-counter-baseline': value += 100
                            elif field != 'Ip6InHdrErrors' and value == 5: value = 1
                            row['stdout'] = counter(row['stdout'], field, value)
                    if case == 'one-error-probe':
                        for row in (traffic[1], traffic[3], traffic[4]): row['stdout'] = row['stdout'].replace('5 packets transmitted', '1 packets transmitted')
                elif case == 'missing-outcome': r['original']['stdout'] = '\n'.join(r['original']['stdout'].splitlines()[:-1])
                elif case == 'skip': r['original']['stdout'] += 'SKIP no XFRM\n'
                elif case == 'original-failure': r['original']['returncode'] = 1
                elif case == 'original-warning': r['original']['stderr'] = 'unsupported'
                elif case == 'unpinned-tools': r['iproute2']['archive_sha256'] = 'host'
                elif case == 'missing-command': rows.remove(xfrm[0])
                elif case == 'reordered-phase': i = rows.index(xfrm[0]); rows[i], rows[i + 1] = rows[i + 1], rows[i]
                elif case == 'unexpected-command-failure': reads[0]['returncode'] = 1
                elif case == 'warning': reads[0]['stderr'] = 'host proc fallback'
                elif case == 'tool-exits-early': traffic[2]['returncode'] = 1; traffic[2]['stderr'] = 'poll: Operation not supported'
                elif case == 'tool-no-destination': traffic[2]['stdout'] = traffic[2]['stdout'].splitlines()[0]
                elif case == 'wrong-traceroute-arguments': traffic[2]['arguments'].insert(-1, '-m1')
                elif case == 'missing-tool-provenance': r['traceroute_tool']['sha256'] = ''
                elif case == 'poll-control-fails': r['mixed_poll_control']['returncode'] = 1
                elif case == 'poll-control-missing-case': r['mixed_poll_control']['stdout'] = contract.CONTROL.replace(' EINTR', '')
                elif case == 'poll-control-host-fallback': r['mixed_poll_missing_backend']['returncode'] = 0
                elif case == 'missing-control-provenance': r['poll_control_sha256'] = ''
                elif case == 'proc-host-fallback': r['native_proc_control']['missing_device']['errno'] = 0
                elif case == 'proc-traversal-accepted': r['native_proc_control']['path_escape']['errno'] = 0
                elif case == 'proc-loopback-invalid': r['native_proc_control']['loopback'] = counter(r['native_proc_control']['loopback'], 'ifIndex', 4)
                elif case == 'vrf-missing': traffic[0]['instats_before']['links'] = [x for x in traffic[0]['instats_before']['links'] if x['ifname'] != 'router']
                elif case == 'vrf-down': link(traffic[0]['instats_before'], 'vveth0')['flags'].remove('UP')
                elif case == 'router-master-up': link(traffic[0]['instats_before'], 'router')['flags'].append('UP')
                elif case == 'vrfs-share-table': link(traffic[0]['instats_before'], 'router')['linkinfo']['info_data']['table'] = 1
                elif case == 'wrong-peer': link(traffic[0]['instats_before'], 'veth1')['link'] = 'veth3'
                elif case == 'port-detached': link(traffic[0]['instats_before'], 'veth1')['master'] = 'vveth0'
                elif case == 'device-down': link(traffic[0]['instats_before'], 'veth1')['flags'].remove('UP')
                elif case == 'wrong-mtu': link(traffic[0]['instats_before'], 'veth2')['mtu'] = 1500
                elif case == 'wrong-address': next(x for x in traffic[0]['instats_before']['addresses'] if x['ifname'] == 'veth1')['addr_info'] = []
                elif case in ('host-route-missing', 'router-route-missing'):
                    dev = 'veth0' if case == 'host-route-missing' else 'veth1'; state = traffic[0]['instats_before']; state['ipv6_routes'] = [x for x in state['ipv6_routes'] if x.get('dev') != dev]
                elif case == 'forwarding-stays-enabled': traffic[3]['instats_before']['forwarding'] = '1'
                elif case == 'forwarding-never-enabled': traffic[0]['instats_before']['forwarding'] = '0'
                elif case == 'wrong-vrf-binding': traffic[0]['vrf']['ifname'] = 'router'
                elif case == 'clock-missing': traffic[2]['native_clock_reads'] = 0
                elif case == 'ping-replies-missing': traffic[0]['stdout'] = traffic[0]['stdout'].replace('10 received', '0 received')
                elif case == 'negative-ping-succeeds': traffic[1]['returncode'] = 0
                elif case == 'negative-ping-output-missing': traffic[1]['stdout'] = 'no transmission'
                elif case == 'native-traversal-missing': link(traffic[0]['instats_after'], 'veth2')['stats64'] = copy.deepcopy(link(traffic[0]['instats_before'], 'veth2')['stats64'])
                elif case == 'proc-read-missing': rows.remove(reads[0])
                elif case == 'proc-read-wrong-device': reads[0]['arguments'] = ['/proc/net/dev_snmp6/veth2']
                elif case == 'proc-read-wrong-ifindex': reads[0]['stdout'] = counter(reads[0]['stdout'], 'ifIndex', -1)
                elif case == 'proc-delta-zero': reads[1]['stdout'] = counter(reads[1]['stdout'], 'Ip6InTooBigErrors', contract.mib(reads[0]['stdout'])['Ip6InTooBigErrors'])
                elif case == 'proc-delta-inconsistent': reads[1]['stdout'] = counter(reads[1]['stdout'], 'Ip6InTooBigErrors', 100)
                elif case == 'native-delta-zero': change_mib(traffic[1]['instats_after'], 'Ip6InTooBigErrors', 0)
                elif case == 'wrong-error-class': change_mib(traffic[1]['instats_after'], 'Ip6InHdrErrors', 1)
                elif case == 'wrong-ping-accounting': traffic[1]['stdout'] = traffic[1]['stdout'].replace('5 packets transmitted', '3 packets transmitted')
                elif case in ('policy-missing', 'policy-wrong-destination', 'policy-wrong-direction', 'policy-allows', 'policy-extra'):
                    state = traffic[4]['instats_before']; text = state['xfrm']
                    state['xfrm'] = {'policy-missing': '', 'policy-wrong-destination': text.replace('2001:1:2::2', '2001:1:2::3'), 'policy-wrong-direction': text.replace('dir fwd', 'dir out'), 'policy-allows': text.replace('action block', 'action allow'), 'policy-extra': text + text}[case]
                elif case == 'policy-not-removed': xfrm[1]['instats_after']['xfrm'] = xfrm[1]['instats_before']['xfrm']
                elif case == 'policy-add-silent-failure': xfrm[0]['instats_after']['xfrm'] = ''
                elif case == 'policy-delete-silent-failure': xfrm[1]['returncode'] = 1
                elif case == 'forwarding-restore-missing': rows.remove(next(x for x in rows if x['tool'] == 'sysctl' and x['arguments'] == ['-qw', 'net.ipv6.conf.all.forwarding=1']))
                elif case == 'native-ipv4-forwarding-leaked': r['mib_after']['ipv4'] = r['mib_after']['ipv4'].replace('Ip: 2 ', 'Ip: 1 ')
                elif case == 'vrf-leaked': r['cleanup_state']['links'].append(dict(ifname='router'))
                elif case == 'device-up': link(r['cleanup_state'], 'veth0')['flags'].append('UP')
                elif case == 'master-leaked': link(r['cleanup_state'], 'veth0')['master'] = 'vveth0'
                elif case == 'mtu-leaked': link(r['cleanup_state'], 'veth2')['mtu'] = 1280
                elif case == 'address-leaked': next(x for x in r['cleanup_state']['addresses'] if x['ifname'] == 'veth0')['addr_info'].append(dict(scope='global'))
                elif case == 'route-leaked': r['cleanup_state']['ipv6_routes'].append(dict(dev='veth0'))
                elif case == 'policy-leaked': r['cleanup_state']['xfrm'] = traffic[4]['instats_before']['xfrm']
                elif case == 'forwarding-leaked': r['cleanup_state']['forwarding'] = '1'
                elif case == 'missing-backend-succeeds': r['missing_backend_control']['returncode'] = 0
                elif case == 'unknown-vrf-succeeds': r['vrf_binding_control']['unknown_vrf']['returncode'] = 0
                elif case == 'live-socket': r['native_fixture']['live'] = 1
                elif case == 'packet-leaked': r['stats']['outstanding'] = 1
                elif case == 'worker-fails': r['stats']['worker_exit_code'] = 1
                elif case == 'forced-stop': r['stats']['shutdown_timed_out'] = True
                if case in ('complete', 'numeric-route-tables', 'nonzero-counter-baseline', 'one-error-probe'): contract.validate_evidence(r)
                else:
                    with self.assertRaises((RuntimeError, KeyError, ValueError, IndexError, TypeError)): contract.validate_evidence(r)


if __name__ == '__main__': unittest.main()
