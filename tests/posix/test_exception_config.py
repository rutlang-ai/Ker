import contextlib
import importlib.util
import io
from pathlib import Path
import sys
import tempfile
import unittest
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('exception_config', ROOT / 'tools/ker-run.py')
launcher = importlib.util.module_from_spec(spec); spec.loader.exec_module(launcher)
BASE = '[network]\naddress=198.18.0.2/24\n[dpdk]\nport=net_tap0\neal=--no-pci\n'
class ExceptionConfigTests(unittest.TestCase):
    def parse(self, options='', cli=()):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'bridge.ini'; path.write_text(BASE + options)
            return launcher.parse_arguments(['--config', str(path), *cli, '--', '/bin/true'])
    def test_default_and_precedence(self):
        self.assertIsNone(self.parse().exception_iface)
        value = self.parse('exception_iface=except0\nexception_type=1\nexception_type=34997\nexception_rate=10\n',
                           ['--exception-rate', '2'])
        self.assertEqual((value.exception_iface, value.exception_type, value.exception_queue, value.exception_rate),
                         ('except0', 34997, 256, 2))
    def test_port_mode_and_atomic_precedence(self):
        value = self.parse('exception_iface=except0\nexception_mode=ports\nexception_policy=accept\n'
                           'exception_tcp_ports=bad\nexception_tcp_ports=80,443,8000-8002\nexception_udp_ports=53\n',
                           ['--exception-policy', 'reject', '--exception-udp-ports', ' 53, 5060 '])
        self.assertEqual((value.exception_mode, value.exception_policy, value.exception_tcp_ports, value.exception_udp_ports),
                         ('ports', 'reject', '80,443,8000-8002', '53,5060'))
        empty = self.parse('exception_iface=except0\nexception_mode=ports\n')
        self.assertIsNone(empty.exception_tcp_ports)
    def test_invalid_port_selection(self):
        for value in ('-1', '65536', '80-1', '80,', '1--2', 'a', '1' * 4097):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                self.parse('exception_iface=except0\nexception_mode=ports\nexception_tcp_ports=' + value + '\n')
        for value in ('exception_mode=ports\n', 'exception_iface=except0\nexception_type=34997\nexception_mode=ports\n',
                      'exception_iface=except0\nexception_type=34997\nexception_tcp_ports=80\n',
                      'exception_iface=except0\nexception_mode=ports\nexception_policy=garbage\n'):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit): self.parse(value)
    def test_invalid_resource_configuration(self):
        for text in ('exception_type=34997\n', 'exception_rate=1\n', 'exception_queue=4\n',
                     'exception_iface=except0\n', 'exception_iface=..\nexception_type=34997\n', 'exception_iface=../other\nexception_type=34997\n',
                     'exception_iface=' + 'a' * 16 + '\nexception_type=34997\n',
                     'exception_iface=except0\nexception_type=65536\n',
                     'exception_iface=except0\nexception_type=34997\nexception_queue=3\n',
                     'exception_iface=except0\nexception_type=34997\nexception_rate=-1\n'):
            with self.subTest(text=text), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                self.parse(text)
if __name__ == '__main__':
    unittest.main()
