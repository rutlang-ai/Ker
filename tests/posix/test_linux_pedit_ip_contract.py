import copy
import base64
import hashlib
import ipaddress
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


def ipv4_probe_frame():
    packet = bytearray(134)
    packet[:14] = bytes.fromhex('deaf1e67e364cabda26a4d730800')
    packet[14:34] = bytes.fromhex('4500007800000000ff003782c0000201c0000202')
    packet[34:] = bytes([0x42]) * (len(packet) - 34)
    return bytes(packet)


def ndp_ns_frame():
    ethernet = bytes.fromhex('3333ff00000202000000000186dd')
    source = ipaddress.IPv6Address('fe80::1').packed
    destination = ipaddress.IPv6Address('ff02::1:ff00:2').packed
    target = ipaddress.IPv6Address('2001:db8::2').packed
    ipv6 = bytes.fromhex('6000000000183aff') + source + destination
    icmp = bytearray(bytes.fromhex('8700000000000000') + target)
    pseudo = source + destination + len(icmp).to_bytes(4, 'big') + bytes(3) + b'\x3a'
    checksum_data = pseudo + icmp
    if len(checksum_data) % 2:
        checksum_data += b'\x00'
    words = [int.from_bytes(checksum_data[i:i + 2], 'big')
             for i in range(0, len(checksum_data), 2)]
    total = sum(words)
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    checksum = ~total & 0xffff
    icmp[2:4] = checksum.to_bytes(2, 'big')
    return ethernet + ipv6 + icmp


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


def frame_window(low, high, packet):
    native = 1_000_000_000 + low
    return {
        'type': 'frame', 'ifname': 'veth1', 'ifindex': 5, 'native_ifindex': 5,
        'direction': 'ingress', 'pkttype': 1, 'protocol': int.from_bytes(packet[12:14], 'big'),
        'frame_hex': packet.hex(), 'frame_length': len(packet), 'native_timestamp_ns': native,
        'host_recv_before_ns': low, 'host_recv_after_ns': low + 1,
        'native_clock_pair': {'native_realtime_ns': native,
                              'host_monotonic_before_ns': low,
                              'host_monotonic_after_ns': high},
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
        self.baseline_sample = {'command': ['-j','-s','filter','show','dev','veth1','ingress'],
                                'qstart_monotonic_ns': 45, 'qend_monotonic_ns': 48}
        self.sample = {'command': ['-j','-s','filter','show','dev','veth1','ingress'],
                       'qstart_monotonic_ns': 65, 'qend_monotonic_ns': 68}

    def validate(self, **changes):
        options = dict(allow_arp_overlimit=True, uncertain_windows=(),
                       baseline_sample=self.baseline_sample, counter_sample=self.sample)
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
        probe = ipv4_probe_frame()
        expected = [{'frame_hex': probe.hex()} for _ in range(10)]
        captured = [frame(packet=probe) for _ in range(10)]
        result = CONTRACT_MODULE.validate_action_window(
            stats(), stats(10, 1200), {'kind': 'pedit', 'keys': [{'offset': 20}]},
            captured, 40, 70, expected_probe_frames=expected, baseline_sample=self.baseline_sample, counter_sample=self.sample)
        self.assertEqual(result['packets'], 10)
        altered = copy.deepcopy(captured)
        changed = bytearray(probe); changed[-1] ^= 1
        altered[-1] = frame(packet=bytes(changed))
        with self.assertRaisesRegex(RuntimeError, 'baseline/final counter samples'):
            CONTRACT_MODULE.validate_action_window(
                stats(), stats(10, 1200), {'kind': 'pedit', 'keys': [{'offset': 20}]},
                altered, 40, 70, expected_probe_frames=expected, baseline_sample=self.baseline_sample, counter_sample=self.sample)

    def test_query_bracket_accounts_for_all_frames_with_exact_prefix(self):
        probe = ipv4_probe_frame()
        expected = [{'frame_hex': probe.hex()} for _ in range(10)]
        probes = [frame(packet=probe) for _ in range(10)]
        background_arp = frame(timestamp=1_000_190, packet=arp_frame())
        sample = dict(self.sample, qstart_monotonic_ns=65, qend_monotonic_ns=95)
        result = CONTRACT_MODULE.validate_action_window(
            stats(), stats(10, 1200), self.action, [*probes, background_arp], 40, 120,
            allow_arp_overlimit=True, expected_probe_frames=expected, baseline_sample=self.baseline_sample, counter_sample=sample)
        self.assertEqual((result['packets'], result['bytes'], result['sample_overlap_frames'],
                          result['sample_suffix_frames'], result['overlimits']), (10, 1200, 1, 1, 0))
        self.assertEqual(result['original_probe_frames'], 10)

        sample_after_arp = dict(self.sample, qstart_monotonic_ns=105, qend_monotonic_ns=110)
        after = CONTRACT_MODULE.validate_action_window(
            stats(), stats(11, 1228, 1), self.action, [*probes, background_arp], 40, 120,
            allow_arp_overlimit=True, expected_probe_frames=expected, baseline_sample=self.baseline_sample, counter_sample=sample_after_arp)
        self.assertEqual((after['packets'], after['bytes'], after['sample_suffix_frames'], after['overlimits']),
                         (11, 1228, 0, 1))

    def test_nonzero_ndp_baseline_requires_an_exact_post_add_prefix(self):
        probe = ipv4_probe_frame(); expected = [{'frame_hex': probe.hex()} for _ in range(10)]
        ndp = ndp_ns_frame()
        self.assertEqual(len(ndp), 78)
        ndp_packet = frame_window(50, 60, ndp)
        probes = [frame_window(70 + i, 71 + i, probe) for i in range(10)]
        baseline = dict(self.baseline_sample, qstart_monotonic_ns=65, qend_monotonic_ns=68)
        final = dict(self.sample, qstart_monotonic_ns=105, qend_monotonic_ns=110)
        result = CONTRACT_MODULE.validate_action_window(
            stats(1, 64), stats(11, 1264), self.action, [ndp_packet, *probes], 40, 120,
            expected_probe_frames=expected, baseline_sample=baseline, counter_sample=final)
        self.assertEqual((result['baseline_prefix_frames'], result['baseline_prefix_bytes'],
                          result['packets'], result['bytes']), (1, 64, 10, 1200))

    def test_original_probe_frames_must_follow_nonzero_baseline(self):
        probe = ipv4_probe_frame(); expected = [{'frame_hex': probe.hex()} for _ in range(10)]
        baseline_probe = frame_window(50, 60, probe)
        post_baseline_probes = [frame_window(70 + i, 71 + i, probe) for i in range(9)]
        baseline = dict(self.baseline_sample, qstart_monotonic_ns=65, qend_monotonic_ns=68)
        final = dict(self.sample, qstart_monotonic_ns=105, qend_monotonic_ns=110)
        with self.assertRaisesRegex(RuntimeError, 'baseline/final counter samples'):
            CONTRACT_MODULE.validate_action_window(
                stats(1, 120), stats(10, 1200), self.action,
                [baseline_probe, *post_baseline_probes], 40, 120,
                expected_probe_frames=expected, baseline_sample=baseline, counter_sample=final)

    def test_nonzero_baseline_rejects_missing_extra_and_mismatched_frames(self):
        probe = ipv4_probe_frame(); expected = [{'frame_hex': probe.hex()} for _ in range(10)]
        ndp = ndp_ns_frame()
        ndp_packet = frame_window(50, 60, ndp)
        probes = [frame_window(70 + i, 71 + i, probe) for i in range(10)]
        baseline = dict(self.baseline_sample, qstart_monotonic_ns=65, qend_monotonic_ns=68)
        final = dict(self.sample, qstart_monotonic_ns=105, qend_monotonic_ns=110)
        scenarios = (
            (stats(1, 64), probes, stats(10, 1200)),
            (stats(1, 64), [ndp_packet, frame_window(55, 62, ndp), *probes], stats(12, 1328)),
            (stats(1, 65), [ndp_packet, *probes], stats(11, 1265)),
        )
        for baseline_stats, frames, final_stats in scenarios:
            with self.subTest(baseline=baseline_stats, frames=len(frames)):
                with self.assertRaisesRegex(RuntimeError, 'baseline/final counter samples'):
                    CONTRACT_MODULE.validate_action_window(
                        baseline_stats, final_stats, self.action, frames, 40, 120,
                        expected_probe_frames=expected, baseline_sample=baseline, counter_sample=final)

    def test_definitely_before_or_after_sample_frames_cannot_be_omitted_or_added(self):
        probe = ipv4_probe_frame(); expected = [{'frame_hex': probe.hex()} for _ in range(10)]
        probes = [frame(packet=probe) for _ in range(10)]
        background_arp = frame(packet=arp_frame())
        sample_after = dict(self.sample, qstart_monotonic_ns=65, qend_monotonic_ns=68)
        with self.assertRaisesRegex(RuntimeError, 'baseline/final counter samples'):
            CONTRACT_MODULE.validate_action_window(
                stats(), stats(10, 1200), self.action, [*probes, background_arp], 40, 120,
                allow_arp_overlimit=True, expected_probe_frames=expected, baseline_sample=self.baseline_sample, counter_sample=sample_after)

        arp_after = frame(timestamp=1_000_190, packet=arp_frame())
        sample_before = dict(self.sample, qstart_monotonic_ns=65, qend_monotonic_ns=68)
        with self.assertRaisesRegex(RuntimeError, 'baseline/final counter samples'):
            CONTRACT_MODULE.validate_action_window(
                stats(), stats(11, 1228, 1), self.action, [*probes, arp_after], 40, 120,
                allow_arp_overlimit=True, expected_probe_frames=expected, baseline_sample=self.baseline_sample, counter_sample=sample_before)

    def test_frame_definitely_after_counter_sample_cannot_pollute_action_generation(self):
        probe = ipv4_probe_frame(); expected = [{'frame_hex': probe.hex()} for _ in range(10)]
        probes = [frame(packet=probe) for _ in range(10)]
        late_arp = frame(timestamp=1_000_210, packet=arp_frame())
        late_arp['native_clock_pair'] = {'native_realtime_ns': 1_000_210,
                                         'host_monotonic_before_ns': 200,
                                         'host_monotonic_after_ns': 210}
        late_arp['host_recv_before_ns'], late_arp['host_recv_after_ns'] = 190, 200
        result = CONTRACT_MODULE.validate_action_window(
            stats(), stats(10, 1200), self.action, [*probes, late_arp], 40, 220,
            allow_arp_overlimit=True, uncertain_windows=((205, 215),),
            expected_probe_frames=expected, baseline_sample=self.baseline_sample, counter_sample=self.sample)
        self.assertEqual((result['packets'], len(result['post_sample_frames'])), (10, 1))
        self.assertEqual(result['post_sample_frames'][0]['classification'], 'definitely-after-counter-query')
        self.assertEqual(result['post_sample_frames'][0]['frame_sha256'],
                         CONTRACT_MODULE.hashlib.sha256(arp_frame()).hexdigest())

    def test_unexplained_sampling_window_and_sample_identity_fail_closed(self):
        probe = ipv4_probe_frame(); expected = [{'frame_hex': probe.hex()} for _ in range(10)]
        probes = [frame(packet=probe) for _ in range(10)]
        arp_during = frame(timestamp=1_000_190, packet=arp_frame())
        sample = dict(self.sample, qstart_monotonic_ns=65, qend_monotonic_ns=95)
        with self.assertRaisesRegex(RuntimeError, 'baseline/final counter samples'):
            CONTRACT_MODULE.validate_action_window(
                stats(), stats(10, 1201), self.action, [*probes, arp_during], 40, 120,
                allow_arp_overlimit=True, expected_probe_frames=expected, baseline_sample=self.baseline_sample, counter_sample=sample)
        bad_sample = dict(sample, command=['-j','-s','filter','show','dev','veth2','ingress'])
        with self.assertRaisesRegex(RuntimeError, 'lack ordered in-generation sample brackets'):
            CONTRACT_MODULE.validate_action_window(
                stats(), stats(10, 1200), self.action, probes, 40, 120,
                expected_probe_frames=expected, baseline_sample=self.baseline_sample, counter_sample=bad_sample)
        bad_sample = dict(sample, qstart_monotonic_ns=95, qend_monotonic_ns=65)
        with self.assertRaisesRegex(RuntimeError, 'lack ordered in-generation sample brackets'):
            CONTRACT_MODULE.validate_action_window(
                stats(), stats(10, 1200), self.action, probes, 40, 120,
                expected_probe_frames=expected, baseline_sample=self.baseline_sample, counter_sample=bad_sample)

    def test_overlimit_without_captured_packet_fails(self):
        with self.assertRaisesRegex(RuntimeError, 'baseline/final counter samples'):
            CONTRACT_MODULE.validate_action_window(self.before, self.after, self.action, [], 40, 70,
                                                   allow_arp_overlimit=True, baseline_sample=self.baseline_sample, counter_sample=self.sample)

    def test_non_arp_short_packet_cannot_explain_overlimit(self):
        packet = bytearray(arp_frame())
        packet[12:14] = bytes.fromhex('0800')
        with self.assertRaisesRegex(RuntimeError, 'unexplained too-short'):
            CONTRACT_MODULE.validate_action_window(self.before, self.after, self.action,
                [frame(packet=bytes(packet))], 40, 70, allow_arp_overlimit=True, baseline_sample=self.baseline_sample, counter_sample=self.sample)

    def test_arp_cannot_explain_overlimit_on_unapproved_action(self):
        with self.assertRaisesRegex(RuntimeError, 'unexplained too-short'):
            self.validate(allow_arp_overlimit=False)

    def test_short_arp_without_matching_overlimit_fails(self):
        with self.assertRaisesRegex(RuntimeError, 'baseline/final counter samples'):
            CONTRACT_MODULE.validate_action_window(self.before, stats(1, 28, 0), self.action,
                [self.packet], 40, 70, allow_arp_overlimit=True, baseline_sample=self.baseline_sample, counter_sample=self.sample)

    def test_excess_overlimit_and_wrong_interface_fail(self):
        with self.assertRaisesRegex(RuntimeError, 'baseline/final counter samples'):
            CONTRACT_MODULE.validate_action_window(self.before, stats(1, 28, 2), self.action,
                [self.packet], 40, 70, allow_arp_overlimit=True, baseline_sample=self.baseline_sample, counter_sample=self.sample)
        wrong = copy.deepcopy(self.packet)
        wrong['ifname'] = 'veth2'
        with self.assertRaisesRegex(RuntimeError, 'frame identity or packet direction'):
            CONTRACT_MODULE.validate_action_window(self.before, self.after, self.action,
                [wrong], 40, 70, allow_arp_overlimit=True, baseline_sample=self.baseline_sample, counter_sample=self.sample)

    def test_frame_outside_window_fails_counter_binding(self):
        outside = frame(timestamp=1_000_250)
        outside['native_clock_pair']['native_realtime_ns'] = 1_000_250
        with self.assertRaisesRegex(RuntimeError, 'baseline/final counter samples'):
            CONTRACT_MODULE.validate_action_window(self.before, self.after, self.action,
                [outside], 40, 70, allow_arp_overlimit=True, baseline_sample=self.baseline_sample, counter_sample=self.sample)

    def test_frame_from_another_action_generation_fails(self):
        other_generation = frame()
        sample = dict(self.sample, qstart_monotonic_ns=220, qend_monotonic_ns=225)
        baseline = dict(self.baseline_sample, qstart_monotonic_ns=205, qend_monotonic_ns=208)
        with self.assertRaisesRegex(RuntimeError, 'native PEDIT baseline/final counter samples do not match'):
            CONTRACT_MODULE.validate_action_window(self.before, self.after, self.action,
                [other_generation], 200, 300, allow_arp_overlimit=True, baseline_sample=baseline, counter_sample=sample)

    def test_frame_on_rule_transition_is_ambiguous(self):
        with self.assertRaisesRegex(RuntimeError, 'transition boundary'):
            self.validate(uncertain_windows=((50, 70),))

    def test_action_drop_stays_forbidden(self):
        with self.assertRaisesRegex(RuntimeError, 'baseline/final counter samples'):
            CONTRACT_MODULE.validate_action_window(self.before, stats(1, 28, 1, 1), self.action,
                [self.packet], 40, 70, allow_arp_overlimit=True, baseline_sample=self.baseline_sample, counter_sample=self.sample)

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
