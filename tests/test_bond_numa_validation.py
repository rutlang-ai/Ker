import importlib.util
import io
import os
from pathlib import Path
import tempfile
from unittest.mock import patch
import unittest


LAUNCHER = Path(__file__).resolve().parents[1] / 'tools' / 'ker-run.py'
WORKER = Path(os.environ['KER_TEST_IO_WORKER'])
SPEC = importlib.util.spec_from_file_location('ker_run', LAUNCHER)
ker_run = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ker_run)


class BondNumaValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.max_numa_nodes = ker_run.query_dpdk_max_numa_nodes(WORKER)

    def config(self, socket_id):
        return io.StringIO(
            '[dpdk]\nnb_bond=1\n'
            '[bond0]\nmode=4\nslave=eth0,eth1\n'
            f'socket_id={socket_id}\n'
        )

    def parse(self, socket_id):
        return ker_run.read_configuration(
            self.config(socket_id), Path('.'), worker_path=WORKER)

    def test_selected_worker_reports_positive_build_limit(self):
        self.assertGreater(self.max_numa_nodes, 0)

    def test_highest_supported_socket_id_is_accepted(self):
        self.assertEqual(self.parse(str(self.max_numa_nodes - 1))['bonds'][0]['socket_id'],
            self.max_numa_nodes - 1)

    def test_socket_id_equal_to_build_limit_is_rejected(self):
        with self.assertRaisesRegex(ValueError, f'0..{self.max_numa_nodes - 1}'):
            self.parse(str(self.max_numa_nodes))

    def test_negative_socket_id_other_than_any_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'socket_id'):
            self.parse('-2')

    def test_non_numeric_socket_id_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'invalid literal'):
            self.parse('not-a-number')

    def test_socket_id_any_remains_accepted(self):
        self.assertEqual(self.parse('-1')['bonds'][0]['socket_id'], -1)

    def test_invalid_socket_id_stops_before_runtime_or_application_start(self):
        config = ('[dpdk]\nnb_bond=1\n[bond0]\nmode=4\n'
            'slave=eth0,eth1\nsocket_id=' + str(self.max_numa_nodes) + '\n')
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / 'ker.ini'
            config_path.write_text(config)
            selected_limit = ker_run.query_dpdk_max_numa_nodes(WORKER)
            with patch.object(ker_run, 'query_dpdk_max_numa_nodes',
                    return_value=selected_limit), \
                    patch.object(ker_run.sys, 'argv', [
                    str(LAUNCHER), '--config', str(config_path), '--address', '192.0.2.1/24',
                    '--port', 'net_bonding0', '--eal', '', '--io-worker', str(WORKER),
                    '--', '/bin/true']), \
                    patch.object(ker_run.subprocess, 'Popen') as popen:
                with self.assertRaises(SystemExit):
                    ker_run.main()
                popen.assert_not_called()


if __name__ == '__main__':
    unittest.main()
