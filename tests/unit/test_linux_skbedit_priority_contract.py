"""Reject false priority/band results using a recorded native execution."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('priority', ROOT / 'tests/posix/linux-skbedit-priority-contract.py')
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)


class PriorityContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads(Path(__file__).with_name('skbedit-priority-transcript.json').read_text())

    def test_complete_original_and_unspecified_payload(self):
        contract.validate_evidence(self.fixture)
        report = copy.deepcopy(self.fixture)
        for packet in report['packet_trace']:
            frame = bytearray.fromhex(packet['frame_hex'])
            frame[40:42] = b'\0\0'  # Valid IPv4 UDP checksum-omitted input.
            frame[42:] = bytes([0x63]) * 100
            packet['frame_hex'] = frame.hex()
        contract.validate_evidence(report)

    def test_original_busywait_accepts_delayed_native_classification(self):
        report = copy.deepcopy(self.fixture)
        rows = report['commands']
        sender = next(x for x in rows if x['tool'] == 'mausezahn')
        i = rows.index(sender)
        query = rows[i + 1]
        delayed = copy.deepcopy(query)
        baseline = sender['pedit_before']['qdiscs']
        sender['pedit_after']['qdiscs'] = copy.deepcopy(baseline)
        for key in ('pedit_before', 'pedit_after'):
            delayed[key]['qdiscs'] = copy.deepcopy(baseline)
        delayed['stdout'] = json.dumps(baseline)
        delayed['started_monotonic'] = delayed['finished_monotonic'] = sender['finished_monotonic']
        rows.insert(i + 1, delayed)
        contract.validate_evidence(report)

    def test_reject_incomplete_or_substituted_native_evidence(self):
        cases = ['original-failed', 'missing-result', 'warning', 'skip', 'missing-command', 'changed-count',
                 'source', 'tool', 'timeout', 'ping', 'backend', 'vrf', 'live', 'outstanding', 'worker',
                 'shutdown', 'eof', 'native-sends', 'native-bytes', 'trace-error', 'bridge', 'address', 'route']
        for phase in range(16):
            cases += [(kind, phase) for kind in ('frame', 'ifindex', 'mac', 'ip', 'udp', 'length', 'priority',
                                                'verdict', 'hardware', 'band-map', 'missing-band', 'band-count',
                                                'query-regression', 'action-count', 'other-locus', 'traversal')]
        cases += [('observation', i, key) for i, row in enumerate(self.fixture['commands'])
                  if row['tool'] in ('tc', 'mausezahn') for key in ('pedit_before', 'pedit_after')]
        for case in cases:
            with self.subTest(case=case):
                report = copy.deepcopy(self.fixture)
                rows = report['commands']
                traffic = [x for x in rows if x['tool'] == 'mausezahn']
                if isinstance(case, tuple):
                    kind, phase, *rest = case
                    if kind == 'observation':
                        rows[phase].pop(rest[0])
                    else:
                        sender = traffic[phase]
                        state = sender['pedit_before']
                        device = 'veth1' if phase < 8 else 'veth2'
                        table = state['filters_by_device'][device] if phase < 8 else state['egress_filters'][device]
                        action = next(x['options']['actions'][0] for x in table if 'options' in x)
                        packet = report['packet_trace'][phase * 10]
                        if kind == 'frame': report['packet_trace'].pop(phase * 10)
                        elif kind == 'ifindex': packet['ifindex'] = 9999
                        elif kind == 'length': packet['length'] -= 1
                        elif kind in ('mac', 'ip', 'udp'):
                            frame = bytearray.fromhex(packet['frame_hex'])
                            frame[{'mac': 0, 'ip': 26, 'udp': 34}[kind]] ^= 1
                            packet['frame_hex'] = frame.hex()
                        elif kind == 'priority': action['priority'] = ':ff'
                        elif kind == 'verdict': action['control_action'] = {'type': 'drop'}
                        elif kind == 'hardware': next(x['options'] for x in table if 'options' in x)['not_in_hw'] = False
                        elif kind == 'band-map': next(x for x in state['qdiscs'] if x['kind'] == 'prio')['options']['priomap'][0] = 0
                        elif kind == 'missing-band': state['qdiscs'] = [x for x in state['qdiscs'] if x.get('parent') != '10:1']
                        elif kind == 'other-locus': state['filters_by_device']['veth3'] = copy.deepcopy(table)
                        elif kind == 'traversal': next(x for x in state['links'] if x['ifname'] == 'veth0')['stats64']['tx']['packets'] += 1000
                        else:
                            i = rows.index(sender) + 1
                            queries = []
                            while rows[i]['tool'] == 'tc' and rows[i]['arguments'][:2] == ['-j', '-s']:
                                queries.append(rows[i]); i += 1
                            query = queries[-1] if kind == 'action-count' else queries[-2]
                            output = json.loads(query['stdout'])
                            if kind == 'action-count':
                                next(x['options']['actions'][0]['stats'] for x in output if 'options' in x)['packets'] = 0
                            else:
                                child = next(x for x in output if x.get('parent') == f'10:{8-phase%8}')
                                child['packets'] = 0 if kind == 'band-count' else child['packets'] + 1000
                            query['stdout'] = json.dumps(output)
                elif case == 'original-failed': report['original']['returncode'] = 1
                elif case == 'missing-result': report['original']['stdout'] = '\n'.join(report['original']['stdout'].splitlines()[:-1])
                elif case == 'warning': report['original']['stderr'] = 'unexpected warning'
                elif case == 'skip': report['original']['stdout'] += 'SKIP\n'
                elif case == 'missing-command': rows.pop(10)
                elif case == 'changed-count': traffic[0]['arguments'][traffic[0]['arguments'].index('-c') + 1] = '9'
                elif case == 'source': report['source_hashes']['forwarding/skbedit_priority.sh'] = 'wrong'
                elif case == 'tool': report['tc_tool']['sha256'] = 'wrong'
                elif case == 'timeout': report['original_priority_hit_timeout_ms'] = 1000
                elif case == 'ping': next(x for x in rows if x['arguments'][:2] == ['vrf', 'exec'])['native_clock_reads'] = 0
                elif case == 'backend': report['missing_backend_control']['returncode'] = 0
                elif case == 'vrf': report['vrf_binding_control']['unknown_vrf']['returncode'] = 0
                elif case == 'live': report['native_fixture']['live'] = 1
                elif case == 'outstanding': report['stats']['outstanding'] = 1
                elif case == 'worker': report['stats']['worker_exit_code'] = 125
                elif case == 'shutdown': report['stats']['shutdown_timed_out'] = True
                elif case == 'eof': report['stats']['control_eof'] = False
                elif case == 'native-sends': report['native_fixture']['bridge_packet_sends'] -= 1
                elif case == 'native-bytes': report['native_fixture']['bridge_packet_bytes'] -= 1
                elif case == 'trace-error': report['native_fixture']['bridge_packet_trace_errors'] = 1
                elif case == 'bridge': report['cleanup_state']['links'].append({'ifname': 'br1'})
                elif case == 'address': next(x for x in report['cleanup_state']['addresses'] if x['ifname'] == 'veth0')['addr_info'].append({'local': '192.0.2.1'})
                elif case == 'route': report['cleanup_state']['ipv4_routes'].append({'dev': 'veth0'})
                with self.assertRaises(RuntimeError):
                    contract.validate_evidence(report)


if __name__ == '__main__':
    unittest.main()
