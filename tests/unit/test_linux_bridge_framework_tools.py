"""Check original bridge entries' required host tools and recorded provenance."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    'linux_bridge_selftest', ROOT / 'tests/posix/linux-bridge-selftest.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class BridgeFrameworkToolsTests(unittest.TestCase):
    def test_mdb_requires_dc_and_records_exact_tool_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for name in ('mausezahn', 'jq', 'dc'):
                (directory / name).write_bytes(name.encode())

            def which(name):
                path = directory / name
                return str(path) if path.exists() else None

            tools, missing = runner.framework_tool_provenance('bridge_mdb.sh', which)
            self.assertEqual(missing, [])
            self.assertEqual(tools['dc']['path'], str(directory / 'dc'))
            self.assertEqual(tools['dc']['sha256'], 'abecdf3503635c0be9eca61cddf5b25c7f8380d5aae7d73d0f62e9a38c87b70d')
            self.assertIsNone(runner.missing_framework_tools_message('bridge_mdb.sh', missing))

    def test_mdb_fails_clearly_before_launch_when_dc_is_missing(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for name in ('mausezahn', 'jq'):
                (directory / name).write_bytes(name.encode())
            available = {'mausezahn': str(directory / 'mausezahn'), 'jq': str(directory / 'jq')}
            tools, missing = runner.framework_tool_provenance(
                'bridge_mdb.sh', lambda name: available.get(name))
        self.assertEqual(missing, ['dc'])
        self.assertEqual(tools['dc'], {'path': None, 'sha256': None})
        self.assertEqual(
            runner.missing_framework_tools_message('bridge_mdb.sh', missing),
            'original bridge_mdb.sh requires dc (GNU dc) for the pinned Linux IGMPv3/MLDv2 checksum calculation')

    def test_future_mdb_max_entry_also_requires_dc(self):
        self.assertIn('dc', runner.framework_tool_names('bridge_mdb_max.sh'))
        self.assertNotIn('dc', runner.framework_tool_names('bridge_mdb_host.sh'))


if __name__ == '__main__':
    unittest.main()
