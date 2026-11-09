import copy
import base64
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest


CONTRACT = Path(__file__).with_name('linux-pedit-ip-contract.py')
SPEC = importlib.util.spec_from_file_location('linux_pedit_ip_contract', CONTRACT)
CONTRACT_MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTRACT_MODULE)


def arp_frame():
    ethernet = bytes.fromhex('ffffffffffff0200000000010806')
    arp = bytes.fromhex('0001080006040001') + bytes.fromhex('020000000001c0000201') + bytes(6) + bytes.fromhex('c0000202')
    return ethernet + arp


def frame(timestamp=1_000_150, packet=None):
    packet = arp_frame() if packet is None else packet
    return {
        'type': 'frame', 'ifname': 'veth1', 'ifindex': 5, 'native_ifindex': 5,
        'direction': 'ingress', 'pkttype': 1, 'protocol': int.from_bytes(packet[12:14], 'big'),
        'frame_hex': packet.hex(), 'frame_length': len(packet), 'native_timestamp_ns': timestamp,
        'host_recv_before_ns': 51, 'host_recv_after_ns': 61,
        'native_clock_pair': {'native_realtime_ns': 1_000_200,
                              'host_monotonic_before_ns': 100,
                              'host_monotonic_after_ns': 110},
    }


def stats(packets=0, byte_count=0, overlimits=0, drops=0):
    return {'packets': packets, 'bytes': byte_count, 'overlimits': overlimits,
            'drops': drops, 'requeues': 0, 'backlog': 0, 'qlen': 0}


class PeditActionWindowTests(unittest.TestCase):
    def setUp(self):
        self.action = {'kind': 'pedit', 'keys': [{'offset': 36}]}
        self.before = stats()
        self.after = stats(1, 28, 1)
        self.packet = frame()

    def validate(self, **changes):
        options = dict(allow_arp_overlimit=True, uncertain_windows=())
        options.update(changes)
        return CONTRACT_MODULE.validate_action_window(
            self.before, self.after, self.action, [self.packet], 40, 70, **options)

    def test_captured_short_arp_explains_one_pass_overlimit(self):
        result = self.validate()
        self.assertEqual((result['packets'], result['bytes'], result['short_arp'], result['overlimits']),
                         (1, 28, 1, 1))

    def test_original_probe_minimum_remains_ten_packets_and_bytes(self):
        CONTRACT_MODULE.require_original_probe_delta(stats(), stats(10, 1200), 120)
        with self.assertRaisesRegex(RuntimeError, 'count below ten'):
            CONTRACT_MODULE.require_original_probe_delta(stats(), stats(9, 1080), 120)
        with self.assertRaisesRegex(RuntimeError, 'count below ten'):
            CONTRACT_MODULE.require_original_probe_delta(stats(), stats(10, 1199), 120)

    def test_ten_original_raw_probe_frames_must_be_present_in_generation_window(self):
        probe = bytearray(134)
        probe[:14] = bytes.fromhex('deaf1e67e364cabda26a4d730800')
        probe[14:34] = bytes.fromhex('4500007800000000ff003782c0000201c0000202')
        probe[34:] = bytes([0x42]) * (len(probe) - 34)
        expected = [{'frame_hex': bytes(probe).hex()} for _ in range(10)]
        captured = [frame(packet=bytes(probe)) for _ in range(10)]
        result = CONTRACT_MODULE.validate_action_window(
            stats(), stats(10, 1200), {'kind': 'pedit', 'keys': [{'offset': 20}]},
            captured, 40, 70, expected_probe_frames=expected)
        self.assertEqual(result['packets'], 10)
        altered = copy.deepcopy(captured)
        changed = bytearray(probe); changed[-1] ^= 1
        altered[-1] = frame(packet=bytes(changed))
        with self.assertRaisesRegex(RuntimeError, 'missing or changed original MZ probe frames'):
            CONTRACT_MODULE.validate_action_window(
                stats(), stats(10, 1200), {'kind': 'pedit', 'keys': [{'offset': 20}]},
                altered, 40, 70, expected_probe_frames=expected)

    def test_overlimit_without_captured_packet_fails(self):
        with self.assertRaisesRegex(RuntimeError, 'counters do not match'):
            CONTRACT_MODULE.validate_action_window(self.before, self.after, self.action, [], 40, 70,
                                                   allow_arp_overlimit=True)

    def test_non_arp_short_packet_cannot_explain_overlimit(self):
        packet = bytearray(arp_frame())
        packet[12:14] = bytes.fromhex('0800')
        with self.assertRaisesRegex(RuntimeError, 'unexplained too-short'):
            CONTRACT_MODULE.validate_action_window(self.before, self.after, self.action,
                [frame(packet=bytes(packet))], 40, 70, allow_arp_overlimit=True)

    def test_arp_cannot_explain_overlimit_on_unapproved_action(self):
        with self.assertRaisesRegex(RuntimeError, 'unexplained too-short'):
            self.validate(allow_arp_overlimit=False)

    def test_short_arp_without_matching_overlimit_fails(self):
        with self.assertRaisesRegex(RuntimeError, 'overlimits or drops'):
            CONTRACT_MODULE.validate_action_window(self.before, stats(1, 28, 0), self.action,
                [self.packet], 40, 70, allow_arp_overlimit=True)

    def test_excess_overlimit_and_wrong_interface_fail(self):
        with self.assertRaisesRegex(RuntimeError, 'overlimits or drops'):
            CONTRACT_MODULE.validate_action_window(self.before, stats(1, 28, 2), self.action,
                [self.packet], 40, 70, allow_arp_overlimit=True)
        wrong = copy.deepcopy(self.packet)
        wrong['ifname'] = 'veth2'
        with self.assertRaisesRegex(RuntimeError, 'frame identity or packet direction'):
            CONTRACT_MODULE.validate_action_window(self.before, self.after, self.action,
                [wrong], 40, 70, allow_arp_overlimit=True)

    def test_frame_outside_window_fails_counter_binding(self):
        outside = frame(timestamp=1_000_250)
        outside['native_clock_pair']['native_realtime_ns'] = 1_000_250
        with self.assertRaisesRegex(RuntimeError, 'counters do not match'):
            CONTRACT_MODULE.validate_action_window(self.before, self.after, self.action,
                [outside], 40, 70, allow_arp_overlimit=True)

    def test_frame_from_another_action_generation_fails(self):
        other_generation = frame()
        with self.assertRaisesRegex(RuntimeError, 'counters do not match'):
            CONTRACT_MODULE.validate_action_window(self.before, self.after, self.action,
                [other_generation], 200, 300, allow_arp_overlimit=True)

    def test_frame_on_rule_transition_is_ambiguous(self):
        with self.assertRaisesRegex(RuntimeError, 'transition boundary'):
            self.validate(uncertain_windows=((50, 70),))

    def test_action_drop_stays_forbidden(self):
        with self.assertRaisesRegex(RuntimeError, 'overlimits or drops'):
            CONTRACT_MODULE.validate_action_window(self.before, stats(1, 28, 1, 1), self.action,
                [self.packet], 40, 70, allow_arp_overlimit=True)

    def test_observer_requires_native_backend_capture_clock_and_complete_frames(self):
        packet = arp_frame()
        with tempfile.TemporaryDirectory() as directory:
            clock_file = Path(directory) / 'native-clock.log'
            native_frame = frame()
            native_frame.update(native_ifindex=5, native_hatype=1, native_address_hex='020000000001')
            report = {
                'packet_observer_source_sha256': 'a' * 64,
                'packet_observer': {
                    'ready': {
                        'type': 'ready',
                        'backend_control': {'missing_channel_errno': CONTRACT_MODULE.errno.ENOENT,
                                            'host_fallback': False},
                        'socket': {'family': 'AF_PACKET', 'type': 'SOCK_RAW', 'protocol': 3,
                                   'native_family': 17, 'native_protocol': 768,
                                   'ifindex': 5, 'native_ifindex': 5},
                        'interfaces': [{'name': 'veth1', 'direction': 'ingress', 'ifindex': 5}],
                    },
                    'frames': [native_frame], 'frame_count': 1,
                    'statistics': {'packets': 1, 'drops': 0, 'link_down_events': [],
                                   'clock_pairs': [
                                       {'native_realtime_ns': 1_000_200, 'host_monotonic_before_ns': 100,
                                        'host_monotonic_after_ns': 110},
                                       {'native_realtime_ns': 1_000_200, 'host_monotonic_before_ns': 100,
                                        'host_monotonic_after_ns': 110},
                                       {'native_realtime_ns': 1_000_200, 'host_monotonic_before_ns': 100,
                                        'host_monotonic_after_ns': 110}]},
                    'native_clock_reads': 3,
                    'native_clock_archive_bytes': 3,
                    'native_clock_archive_base64': base64.b64encode(b'111').decode('ascii'),
                    'native_clock_archive_sha256': hashlib.sha256(b'111').hexdigest(),
                },
            }
            self.assertEqual(len(CONTRACT_MODULE.validate_packet_observer(report)), 1)
            for mutate, message in (
                (lambda item: item['packet_observer']['ready']['backend_control'].__setitem__('host_fallback', True),
                 'observer did not prove'),
                (lambda item: item['packet_observer']['ready']['socket'].__setitem__('native_ifindex', 9),
                 'observer did not prove'),
                (lambda item: item['packet_observer']['statistics'].__setitem__('drops', 1),
                 'incomplete, dropped frames'),
                (lambda item: item['packet_observer']['frames'][0].__setitem__('native_timestamp_ns', 0),
                 'frame metadata'),
                (lambda item: item['packet_observer'].__setitem__('native_clock_archive_base64', ''),
                 'incomplete, dropped frames'),
                (lambda item: item['packet_observer'].__setitem__('native_clock_archive_base64', base64.b64encode(b'112').decode('ascii')),
                 'incomplete, dropped frames'),
            ):
                changed = copy.deepcopy(report)
                mutate(changed)
                with self.assertRaisesRegex(RuntimeError, message):
                    CONTRACT_MODULE.validate_packet_observer(changed)

    def test_invalid_clock_relation_fails(self):
        bad = frame(timestamp=1_000_250)
        with self.assertRaisesRegex(RuntimeError, 'valid native/host clock bracket'):
            CONTRACT_MODULE.packet_time_interval(bad)


if __name__ == '__main__':
    unittest.main()
