"""All-skipped exit zero and partial native zone traffic are not coverage."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('network', ROOT / 'tests/posix/linux-network-selftest.py')
contract = importlib.util.module_from_spec(spec); spec.loader.exec_module(contract)


class ConntrackContractTests(unittest.TestCase):
    def test_original_requires_three_exact_passing_zone_cases(self):
        report = json.loads(Path(__file__).with_name('conntrack-dump-flush-transcript.json').read_text())
        contract.validate_original('conntrack_dump_flush', report['original'])
        contract.validate_missing_backend('conntrack_dump_flush', report['original_missing_backend_control'])
        # The original harness deliberately returns zero for its all-skip path.
        self.assertEqual(report['original_missing_backend_control']['returncode'], 0)
        with self.assertRaises(RuntimeError):
            contract.validate_original('conntrack_dump_flush', report['original_missing_backend_control'])
        with self.assertRaises(RuntimeError):
            contract.validate_missing_backend('conntrack_dump_flush', report['original'])
        for mutation in ('missing-case', 'duplicate-zone-case', 'failed'):
            result = copy.deepcopy(report['original'])
            if mutation == 'missing-case':
                result['stdout'] = result['stdout'].replace('ok 3 conntrack_dump_flush.test_flush_by_zone_default\n', '')
            elif mutation == 'duplicate-zone-case':
                result['stdout'] = result['stdout'].replace('ok 3 conntrack_dump_flush.test_flush_by_zone_default',
                                                            'ok 3 conntrack_dump_flush.test_dump_by_zone')
            else:
                result['returncode'] = 1
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                contract.validate_original('conntrack_dump_flush', result)

    def test_native_insert_dump_and_zone_flush_requests_are_required(self):
        native = json.loads(Path(__file__).with_name('conntrack-dump-flush-transcript.json').read_text())['native_fixture']
        contract.validate_conntrack(native)
        for key, value in (('netlinks', 0), ('writes', 40), ('sent', 0), ('reads', 0), ('live', 1)):
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                contract.validate_conntrack(dict(native, **{key: value}))


if __name__ == '__main__':
    unittest.main()
