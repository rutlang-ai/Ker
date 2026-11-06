import importlib.util
from pathlib import Path
import unittest

root = Path(__file__).resolve().parents[1] / 'posix'
spec = importlib.util.spec_from_file_location('userspace_runner', root / 'linux-mptcp-diag-selftest.py')
runner = importlib.util.module_from_spec(spec); spec.loader.exec_module(runner)


class UserspacePMEvidenceTests(unittest.TestCase):
    def counts(self):
        return dict(live=0, namespaces_created=3, namespaces_deleted=3,
            sendfile_calls=2, imported_files=2, negotiated=4, accepts=2,
            fallback=0, mp_join_syn_rx=8, mp_join_ack_rx=8, netlinks=69)

    def topology(self):
        return [['link', 'add', 'veth']] + [['-net', 'ns', 'addr', 'add']] * 8 + [['-net', 'ns', 'link', 'set']] * 4

    def test_native_observations_are_complete(self):
        runner.validate_userspace_counts(self.counts(), self.topology())

    def test_fallback_missing_sendfile_subflows_and_leaks_are_rejected(self):
        for field, value in (('live', 1), ('namespaces_deleted', 2), ('sendfile_calls', 0),
            ('imported_files', 1), ('negotiated', 3), ('accepts', 1), ('fallback', 1),
            ('mp_join_syn_rx', 7), ('mp_join_ack_rx', 7), ('netlinks', 68)):
            with self.subTest(field=field):
                counts = self.counts(); counts[field] = value
                with self.assertRaises(RuntimeError): runner.validate_userspace_counts(counts, self.topology())

    def test_same_length_but_wrong_topology_is_rejected(self):
        topology = self.topology(); topology[1] = ['-net', 'ns', 'link', 'set']
        with self.assertRaises(RuntimeError): runner.validate_userspace_counts(self.counts(), topology)

    def test_all_37_original_cases_required_without_skips(self):
        tap = '1..37\n' + ''.join(f'ok {i} - event {i} # time=500ms\n' for i in range(1, 38))
        self.assertEqual(len(runner.tap_result(tap, 37)), 37)
        for output in (tap.replace('ok 25 -', 'not ok 25 -'), tap.replace('time=500ms','SKIP'), tap.replace('1..37','1..36')):
            with self.assertRaises(RuntimeError): runner.tap_result(output, 37)


if __name__ == '__main__': unittest.main()
