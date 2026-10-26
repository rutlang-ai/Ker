"""Selected-worker NUMA bounds, error normalization and query lifetime.

The executable fixtures implement only the limits protocol, not an EAL/PMD.
"""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'tools/ker-run.py'
spec = importlib.util.spec_from_file_location('bond_worker_limits', SOURCE)
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)
CONFIG = ('[network]\naddress=198.18.0.2/24\n[dpdk]\nport=net_bonding0\n'
          'eal=--no-huge --no-pci --vdev=net_tap0 --vdev=net_tap1\nnb_bond=1\n'
          '[bond0]\nmode=4\nslave=0,1\nsocket_id=0\n')


class WorkerLimitsTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.config = self.root/'native.ini'
        self.worker = self.root/'worker'
        self.log = self.root/'queries'
        self.pid = self.root/'worker.pid'
        self.application = self.root/'application'
        self.executed = self.root/'application-executed'
        self.stats = self.root/'stats.json'
        self.application.write_text('#!/bin/sh\ntouch "' + str(self.executed) + '"\n')
        self.application.chmod(0o700)
        self.respond()

    def respond(self, body=None):
        self.worker.write_text('#!' + sys.executable + '\nimport json, os, sys, time\nfrom pathlib import Path\n'
            + 'Path(' + repr(str(self.pid)) + ').write_text(str(os.getpid()))\n'
            + 'with Path(' + repr(str(self.log)) + ').open("a") as log:\n'
            + '    log.write(" ".join(sys.argv[1:]) + "\\n")\n'
            + (body if body is not None else 'print(json.dumps({"max_numa_nodes": 3}))\n'))
        self.worker.chmod(0o700)

    def text(self, socket_id):
        return CONFIG.replace('socket_id=0', 'socket_id='+str(socket_id))

    def parse(self, socket_id):
        self.config.write_text(self.text(socket_id))
        return launcher.parse_arguments(['--config', str(self.config),
            '--io-worker', str(self.worker), '--', str(self.application)])

    def cli(self, socket_id=0):
        self.config.write_text(self.text(socket_id))
        return subprocess.run([sys.executable, str(SOURCE), '--config', str(self.config),
            '--io-worker', str(self.worker), '--library', '/missing-native-library',
            '--stats', str(self.stats), '--', str(self.application)],
            capture_output=True, text=True, timeout=15)

    def assert_error(self, result, diagnostic):
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(diagnostic, result.stderr.splitlines()[-1])
        self.assertNotIn('Traceback', result.stderr)
        self.assertFalse(self.executed.exists())
        self.assertFalse(self.stats.exists())

    def consume_query(self):
        self.assertEqual(self.log.read_text().splitlines(), ['--dpdk-limits'])
        self.log.unlink()

    def test_impossible_negative_socket_ids_reject_without_query(self):
        for socket_id in (-2, -65536, -10**30):
            with self.subTest(socket_id=socket_id):
                self.config.write_text(self.text(socket_id))
                with self.assertRaisesRegex(ValueError, 'socket_id must be -1 or nonnegative'):
                    launcher.load_configuration(self.config, self.worker)
                self.assert_error(self.cli(socket_id), 'socket_id must be -1 or nonnegative')
                self.assertFalse(self.log.exists())
                self.assertFalse(self.pid.exists())

    def test_selected_upper_bound_and_any_socket_are_preserved(self):
        for socket_id in (-1, 0, 2):
            with self.subTest(socket_id=socket_id):
                args = self.parse(socket_id)
                self.assertEqual(args.bonds[0]['socket_id'], socket_id)
                self.assertIn('socket_id='+str(socket_id), args.eal_args[-1])
                self.consume_query()
        self.assert_error(self.cli(3), 'socket_id must be -1 or in 0..2')
        self.consume_query()
        self.assertEqual(self.parse(2).bonds[0]['socket_id'], 2)
        self.consume_query()

    def test_malformed_or_failed_query_never_starts_application_and_recovers(self):
        cases = (
            ('sys.exit(23)\n', 'successful --dpdk-limits query'),
            ('os.kill(os.getpid(), 15)\n', 'successful --dpdk-limits query'),
            ('print("not JSON")\n', 'invalid --dpdk-limits JSON'),
            ('print("[]")\n', 'invalid positive max_numa_nodes'),
            ('print("{}")\n', 'invalid positive max_numa_nodes'),
            ('print(json.dumps({"max_numa_nodes":0}))\n', 'invalid positive max_numa_nodes'),
            ('print(json.dumps({"max_numa_nodes":-1}))\n', 'invalid positive max_numa_nodes'),
            ('print(json.dumps({"max_numa_nodes":True}))\n', 'invalid positive max_numa_nodes'),
            ('print(json.dumps({"max_numa_nodes":"3"}))\n', 'invalid positive max_numa_nodes'),
            ('print(json.dumps({"max_numa_nodes":3.0}))\n', 'invalid positive max_numa_nodes'),
            ('print(json.dumps({"max_numa_nodes":3,"extra":1}))\n', 'invalid positive max_numa_nodes'),
            ('sys.stdout.buffer.write(bytes([255]))\n', 'decode'),
        )
        for body, diagnostic in cases:
            with self.subTest(body=body):
                self.respond(body)
                self.assert_error(self.cli(), diagnostic)
                self.consume_query()
                self.respond()
                self.assertEqual(self.parse(0).bonds[0]['socket_id'], 0)
                self.consume_query()

    def test_query_timeout_reaps_worker_and_next_query_recovers(self):
        # The real subprocess timeout must terminate and reap the exact worker.
        # Even a regression that waits for normal exit has a bounded8s fixture.
        self.respond('time.sleep(8)\nprint(json.dumps({"max_numa_nodes":3}))\n')
        self.assert_error(self.cli(), 'timed out')
        self.consume_query()
        pid = int(self.pid.read_text())
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)
        self.respond()
        self.assertEqual(self.parse(-1).bonds[0]['socket_id'], -1)
        self.consume_query()


if __name__ == '__main__':
    unittest.main()
