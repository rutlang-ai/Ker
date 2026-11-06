import importlib.util
from pathlib import Path
import unittest

path = Path(__file__).resolve().parents[1] / 'posix/linux-mptcp-connect-ip.py'
spec = importlib.util.spec_from_file_location('connect_fixture', path)
fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)


class ConnectShellTests(unittest.TestCase):
    def test_random_loss_and_reordering_must_match_native_readback(self):
        loss = ['qdisc', 'add', 'dev', 'veth', 'root', 'netem', 'loss', 'random', '0.12%', 'delay', '38ms']
        reorder = ['qdisc', 'add', 'dev', 'veth', 'root', 'netem', 'delay', '9ms', 'reorder', '96%', '64%']
        cases = [(loss, {'delay': {'delay': .038}, 'loss-random': {'loss': .0012}}),
                 (reorder, {'delay': {'delay': .009}, 'reorder': {'reorder': .96, 'correlation': .64}})]
        for command, options in cases:
            fixture.validate_netem(command, [{'kind': 'netem', 'options': options}])
            for field in options:
                wrong = dict(options); wrong.pop(field)
                with self.assertRaises(RuntimeError):
                    fixture.validate_netem(command, [{'kind': 'netem', 'options': wrong}])

    def test_zero_netem_parameters_allow_omitted_zero_fields(self):
        fixture.validate_netem(['delay', '0ms', 'loss', 'random', '0%'], [{'kind': 'netem', 'options': {}}])
        with self.assertRaises(RuntimeError):
            fixture.validate_netem(['delay', '0ms'], [])


if __name__ == '__main__': unittest.main()
