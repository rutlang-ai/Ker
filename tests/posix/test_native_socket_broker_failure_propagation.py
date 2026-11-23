"""Keep late reuseport-client failures visible after child cleanup."""
import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).with_name('native-socket-broker.py')
SPEC = importlib.util.spec_from_file_location('native_socket_broker_failure_test', SOURCE)
BROKER_TEST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BROKER_TEST)


class FakeClient:
    def __init__(self):
        self.stdout = object()
        self.returncode = None
        self.killed = False
        self.waited = False

    def poll(self):
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -9

    def wait(self):
        self.waited = True
        return self.returncode


class ReuseportFailurePropagationTests(unittest.TestCase):
    def test_late_assertion_survives_child_cleanup(self):
        client = FakeClient()
        read_failure = AssertionError('injected late client assertion')
        capability_read, capability_write = os.pipe()
        try:
            args = type('Args', (), {
                'reuseport_group_client': Path('/fake/client'),
                'inherited_group_probe': Path('/fake/probe'),
                'preload_library': Path('/fake/preload.so'),
            })()
            with patch.object(BROKER_TEST.subprocess, 'Popen', return_value=client), \
                    patch.object(BROKER_TEST, 'read_line', side_effect=read_failure):
                with self.assertRaisesRegex(AssertionError, 'injected late client assertion'):
                    BROKER_TEST.run_reuseport_group_client(args, Path('/fake/rpc.sock'),
                        None, capability_read)
            self.assertTrue(client.killed)
            self.assertTrue(client.waited)
        finally:
            try:
                os.close(capability_write)
            except OSError:
                pass


if __name__ == '__main__':
    unittest.main()
