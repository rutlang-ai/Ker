import importlib.util
from pathlib import Path
import unittest
from unittest import mock

root = Path(__file__).resolve().parents[1] / 'posix'
spec = importlib.util.spec_from_file_location('simult_fixture', root / 'linux-mptcp-simult-ip.py')
fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
spec = importlib.util.spec_from_file_location('simult_runner', root / 'linux-mptcp-diag-selftest.py')
runner = importlib.util.module_from_spec(spec); spec.loader.exec_module(runner)


class SimultaneousFlowsTests(unittest.TestCase):
    def command(self):
        return ['qdisc', 'add', 'dev', 'ns1eth2', 'root', 'netem', 'rate', '3mbit', 'delay', '25ms', 'limit', '50']

    def readback(self):
        # Real pinned tc JSON encodes rate and delay as nested objects.
        return [{'kind':'netem', 'options':{'limit':50, 'rate':{'rate':375000}, 'delay':{'delay':0.025}}}]

    def test_actual_nested_tc_readback_matches_original_parameters(self):
        fixture.validate_netem(self.command(), self.readback())

    def test_wrong_actual_rate_delay_or_limit_is_rejected(self):
        for field, value in (('rate', {'rate':1250000}), ('delay', {'delay':0.001}), ('limit', 1000)):
            record = self.readback(); record[0]['options'][field] = value
            with self.assertRaises(RuntimeError): fixture.validate_netem(self.command(), record)

    def test_missing_netem_or_rate_is_rejected(self):
        for record in ([], [{'kind':'fq_codel'}], [{'kind':'netem','options':{'limit':50}}]):
            with self.assertRaises(RuntimeError): fixture.validate_netem(self.command(), record)

    def test_zero_delay_does_not_require_missing_json_object(self):
        command = ['qdisc','add','dev','veth','root','netem','rate','10mbit','limit','50']
        fixture.validate_netem(command, [{'kind':'netem','options':{'limit':50,'rate':{'rate':1250000}}}])

    def test_multihop_default_route_and_mtu_keep_native_attributes(self):
        with mock.patch.object(fixture.setup, 'ifindex', return_value=9), mock.patch.object(fixture.setup, 'netlink') as native:
            self.assertTrue(fixture.setup.topology(['-net','ns','link','set','veth','up','mtu','1500']))
            self.assertIn(fixture.setup.integer(4, 1500), native.call_args.args[2])
            self.assertTrue(fixture.setup.topology(['-net','ns','route','add','default','via','10.0.3.2']))
            self.assertEqual(native.call_args.args[:2], ('ns', 24))

    def test_complete_tap_matrix_does_not_accept_flaky_ignores(self):
        tap = '1..10\n' + ''.join(f'ok {i} - transfer {i} # time=7500ms\n' for i in range(1, 11))
        self.assertEqual(len(runner.tap_result(tap, 10)), 10)
        for output in (tap.replace('ok 5 -','not ok 5 -'), tap.replace('time=7500ms','IGNORE'), tap.replace('1..10','1..8')):
            with self.assertRaises(RuntimeError): runner.tap_result(output, 10)


if __name__ == '__main__': unittest.main()
