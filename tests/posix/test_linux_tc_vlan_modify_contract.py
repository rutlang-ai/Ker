#!/usr/bin/env python3
"""Focused negative and boundary checks for the VLAN evidence oracle."""
import importlib.util
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

CONTRACT = Path(__file__).with_name('linux-tc-vlan-modify-contract.py')
SPEC = importlib.util.spec_from_file_location('tc_vlan_modify_contract', CONTRACT)
CONTRACT_MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTRACT_MODULE)
RUNNER_SPEC = importlib.util.spec_from_file_location(
    'linux_bridge_selftest', Path(__file__).with_name('linux-bridge-selftest.py'))
RUNNER_MODULE = importlib.util.module_from_spec(RUNNER_SPEC)
RUNNER_SPEC.loader.exec_module(RUNNER_MODULE)


def action_filter(vid):
    return {'protocol': 'all', 'pref': 1, 'kind': 'flower', 'chain': 0,
            'options': {'handle': 1, 'not_in_hw': True,
                        'actions': [{'order': 1, 'kind': 'vlan', 'vlan_action': 'modify',
                                     'protocol': '802.1Q', 'id': vid,
                                     'control_action': {'type': 'pipe'},
                                     'stats': {'bytes': 0, 'packets': 0, 'drops': 0,
                                               'overlimits': 0, 'requeues': 0,
                                               'backlog': 0, 'qlen': 0}}]}}


def empty_filter():
    return {'protocol': 'all', 'pref': 1, 'kind': 'flower', 'chain': 0}


def snapshot(mode='ingress', veth1=65, veth2=85):
    active = f'veth1:{mode}'
    second = f'veth2:{mode}'
    return {'filters': {
        'veth1:ingress': [empty_filter(), action_filter(veth1)] if active == 'veth1:ingress' else [empty_filter()],
        'veth1:egress': [empty_filter(), action_filter(veth1)] if active == 'veth1:egress' else [empty_filter()],
        'veth2:ingress': [empty_filter(), action_filter(veth2)] if second == 'veth2:ingress' else [empty_filter()],
        'veth2:egress': [empty_filter(), action_filter(veth2)] if second == 'veth2:egress' else [empty_filter()]}}


def query(start, finish):
    return {'started_monotonic_ns': start, 'finished_monotonic_ns': finish}


class VLANContractTest(unittest.TestCase):
    def test_failure_path_archives_partial_packet_and_stats_before_validation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / 'build' / 'linux-original-forwarding-tc-vlan-modify.json'
            evidence.parent.mkdir()
            output = root / 'temp' / 'observer.jsonl'
            output.parent.mkdir()
            output.write_bytes(b'{"type":"ready"}\nmalformed frame record\n')
            stats = output.with_suffix(output.suffix + '.stats.json')
            stats.write_bytes(b'{"packets":0,"drops":1}\n')
            ready = output.with_suffix('.ready.json')
            ready.write_text('{"type":"error","error":"controlled validation failure"}\n')
            report = {}
            with self.assertRaisesRegex(RuntimeError, 'controlled failure'):
                capture, ready_record = RUNNER_MODULE.archive_vlan_observer_evidence(
                    report, evidence, output, stats, ready, 0)
                raise RuntimeError('controlled failure after capture archival')
            self.assertEqual(Path(capture['archive']).read_bytes(), output.read_bytes())
            self.assertEqual(Path(capture['stats_archive']).read_bytes(), stats.read_bytes())
            self.assertEqual(ready_record['type'], 'error')
            self.assertEqual(capture['bytes'], len(output.read_bytes()))
            self.assertEqual(capture['stats_bytes'], len(stats.read_bytes()))
            report = {}
            with mock.patch.object(RUNNER_MODULE.shutil, 'copyfile',
                                   side_effect=OSError('controlled archive copy failure')):
                with self.assertRaisesRegex(RuntimeError, 'observer did not stop normally'):
                    RUNNER_MODULE.archive_vlan_observer_evidence(
                        report, evidence, output, stats, ready, 1)
            self.assertEqual(report['vlan_packet_observer_archive_error'],
                             'controlled archive copy failure')

    def test_exact_native_ingress_and_egress_ids(self):
        CONTRACT_MODULE._rules(snapshot(), 'ingress')
        CONTRACT_MODULE._rules(snapshot('egress', veth1=85, veth2=65), 'egress')

    def test_wrong_id_or_duplicate_action_fails_closed(self):
        with self.assertRaises(RuntimeError):
            CONTRACT_MODULE._rules(snapshot(veth1=64), 'ingress')
        duplicate = snapshot()
        duplicate['filters']['veth1:ingress'].append(action_filter(65))
        with self.assertRaises(RuntimeError):
            CONTRACT_MODULE._rules(duplicate, 'ingress')

    def test_native_action_counter_requires_an_ordered_prefix(self):
        rows = [
            {'low': 10, 'high': 10, 'size': 40},
            {'low': 20, 'high': 20, 'size': 60},
        ]
        before = query(0, 1)
        after_between = query(15, 15)
        after_end = query(30, 31)
        self.assertTrue(CONTRACT_MODULE._counter_delta_matches(rows, before, after_between, 1, 40))
        self.assertTrue(CONTRACT_MODULE._counter_delta_matches(rows, before, after_end, 2, 100))
        # An arbitrary subset could select the later 60-byte frame while
        # skipping the earlier 40-byte one. A cumulative action counter cannot.
        self.assertFalse(CONTRACT_MODULE._counter_delta_matches(rows, before, after_end, 1, 60))

    def test_auxdata_requires_8021q_and_full_tci(self):
        ip = bytearray(20)
        ip[0], ip[2:4], ip[9] = 0x45, (28).to_bytes(2, 'big'), 1
        ip[12:16], ip[16:20] = bytes((192, 0, 2, 17)), bytes((192, 0, 2, 18))
        icmp = bytes((8, 0, 0, 0, 0x12, 0x34, 0, 1))
        packet = bytes.fromhex('00112233445566778899aabb0800') + ip + icmp
        row = {'frame_hex': packet.hex(), 'frame_length': len(packet),
               'vlan_auxdata': {'status': (1 << 4) | (1 << 6), 'length': len(packet),
                                'snaplen': len(packet), 'vlan_tci': 85, 'vlan_tpid': 0x8100}}
        parsed = CONTRACT_MODULE._frame_packet(row)
        self.assertEqual(parsed['vlans'], (85,))
        self.assertEqual(parsed['vlan_tags'], ((0x8100, 85),))
        bad = dict(row, vlan_auxdata=dict(row['vlan_auxdata'], vlan_tpid=0x88a8))
        with self.assertRaises(RuntimeError):
            CONTRACT_MODULE._frame_packet(bad)
        bad = dict(row, vlan_auxdata=dict(row['vlan_auxdata'], status=1 << 4))
        with self.assertRaises(RuntimeError):
            CONTRACT_MODULE._frame_packet(bad)

    def test_fresh_native_report_rejects_contract_mutations(self):
        fixture = Path(__file__).parents[1] / 'unit' / 'tc-vlan-modify-transcript.json'
        original = json.loads(fixture.read_text())
        self.assertEqual(original.get('status'), 'PASS_IMPORTED_LINUX')

        def first_success_ping(report):
            return next(row for row in report['commands']
                        if row.get('arguments', [])[:2] == ['vrf', 'exec'] and row['returncode'] == 0)

        def first_icmp(report, iface='veth1', direction='ingress'):
            for frame in report['vlan_packet_observer']['frames']:
                if frame.get('ifname') != iface or frame.get('direction') != direction:
                    continue
                packet = CONTRACT_MODULE._frame_packet(frame)
                if packet['icmp_type'] in (8, 128):
                    return frame
            raise AssertionError('fixture has no original successful echo request')

        def mutate_frame_word(report, relative_offset, value):
            frame = first_icmp(report)
            packet = bytearray.fromhex(frame['frame_hex'])
            offset = 14
            if packet[offset] >> 4 == 4:
                offset += (packet[offset] & 0x0f) * 4
            else:
                offset += 40
            packet[offset + relative_offset:offset + relative_offset + 2] = value.to_bytes(2, 'big')
            frame['frame_hex'] = packet.hex()

        def mutate_action_id(report):
            ping = first_success_ping(report)
            ping['vlan_modify_after']['filters']['veth1:ingress'][1]['options']['actions'][0]['id'] = 64

        def mutate_sequence(report):
            mutate_frame_word(report, 6, 11)

        def mutate_payload(report):
            frame = first_icmp(report)
            packet = bytearray.fromhex(frame['frame_hex'])
            packet[-1] ^= 1
            frame['frame_hex'] = packet.hex()

        def mutate_native_time(report):
            first_icmp(report)['native_timestamp_ns'] += 5_000_000_000

        def mutate_phase_time(report):
            first_success_ping(report)['started_monotonic_ns'] = 0

        def mutate_interface(report):
            first_icmp(report)['native_ifindex'] = 999

        def mutate_vlan_tag(report):
            first_icmp(report)['vlan_auxdata']['vlan_tci'] = 64

        def mutate_byte_counter(report):
            ping = first_success_ping(report)
            ping['vlan_modify_after']['filters']['veth1:ingress'][1]['options']['actions'][0]['stats']['bytes'] += 1

        def mutate_packet_counter(report):
            ping = first_success_ping(report)
            ping['vlan_modify_after']['filters']['veth1:ingress'][1]['options']['actions'][0]['stats']['packets'] += 1

        def mutate_vlan_membership(report):
            ping = first_success_ping(report)
            port = ping['bridge_state']['port_vlans_veth1'][0]
            port['vlans'] = [entry for entry in port['vlans'] if entry['vlan'] != 85]

        def mutate_vrf(report):
            ping = first_success_ping(report)
            next(row for row in ping['bridge_state']['host_vlans'] if row['ifname'] == 'veth0.85')\
                ['linkinfo']['info_slave_data']['table'] = 99

        def mutate_global_address(report):
            ping = first_success_ping(report)
            ping['bridge_state']['host_addresses_veth0_85'][0]['addr_info'].pop(0)

        def mutate_cleanup(report):
            report['cleanup_state']['links'].append({'ifname': 'br0'})

        def mutate_backend(report):
            report['missing_backend_control']['returncode'] = 0

        def mutate_capture_artifact(report):
            report['vlan_packet_observer_capture'].pop('stats_sha256')

        mutations = (mutate_action_id, mutate_sequence, mutate_payload, mutate_native_time,
                     mutate_phase_time, mutate_interface, mutate_vlan_tag, mutate_byte_counter,
                     mutate_packet_counter, mutate_vlan_membership, mutate_vrf,
                     mutate_global_address, mutate_cleanup, mutate_backend,
                     mutate_capture_artifact)
        for mutate in mutations:
            with self.subTest(mutation=mutate.__name__):
                candidate = copy.deepcopy(original)
                mutate(candidate)
                with self.assertRaises(RuntimeError):
                    CONTRACT_MODULE.validate_evidence(candidate)
if __name__ == '__main__':
    unittest.main()
