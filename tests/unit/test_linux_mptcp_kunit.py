import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('mptcp_kunit_runner', ROOT / 'tools/run-linux-mptcp-kunit.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class MptcpKunitEvidenceTests(unittest.TestCase):
    def tree(self):
        def node(name, children, count):
            return SimpleNamespace(name=name, status='SUCCESS', subtests=children, expected_count=count,
                                   counts=SimpleNamespace(errors=0, passed=5, failed=0, crashed=0, skipped=0))
        suites = [node(name, [node(case, [], 0) for case in cases], len(cases))
                  for name, cases in runner.EXPECTED.items()]
        return node('main', suites, 2)

    def test_complete_original_case_set_required(self):
        tree = self.tree()
        self.assertEqual(runner.validate_tree(tree, 'SUCCESS'), runner.EXPECTED)
        for mutation in ('missing_suite', 'missing_case', 'duplicate_suite', 'bad_plan', 'extra_case', 'wrong_case'):
            tree = self.tree()
            if mutation == 'missing_suite': tree.subtests.pop()
            elif mutation == 'missing_case': tree.subtests[1].subtests.pop()
            elif mutation == 'duplicate_suite': tree.subtests[1].name = tree.subtests[0].name
            elif mutation == 'bad_plan': tree.subtests[1].expected_count = 3
            elif mutation == 'extra_case': tree.subtests[1].subtests.append(tree.subtests[1].subtests[0])
            elif mutation == 'wrong_case': tree.subtests[1].subtests[0].name = 'replacement_test'
            with self.subTest(mutation=mutation), self.assertRaises(runner.EvidenceError):
                runner.validate_tree(tree, 'SUCCESS')

    def test_skip_failure_crash_and_parser_errors_never_pass(self):
        for status in ('SKIPPED', 'FAILURE', 'TEST_CRASHED'):
            for level in (0, 1, 2):
                tree = self.tree()
                target = tree if level == 0 else tree.subtests[0] if level == 1 else tree.subtests[0].subtests[0]
                target.status = status
                with self.subTest(status=status, level=level), self.assertRaises(runner.EvidenceError):
                    runner.validate_tree(tree, 'SUCCESS')
        tree = self.tree(); tree.subtests[1].subtests[0].counts.errors = 1
        with self.assertRaises(runner.EvidenceError): runner.validate_tree(tree, 'SUCCESS')

    def test_successful_host_exit_does_not_prove_kernel_lifecycle(self):
        complete = 'KER_MPTCP_KUNIT_BOOTED\nKER_MPTCP_KUNIT_HALTED\n'
        runner.check_execution(SimpleNamespace(returncode=0, stdout=complete, stderr=''))
        for output in ('', 'KER_MPTCP_KUNIT_BOOTED\n', complete + complete):
            with self.subTest(output=output), self.assertRaises(runner.EvidenceError):
                runner.check_execution(SimpleNamespace(returncode=0, stdout=output, stderr=''))
        with self.assertRaises(runner.EvidenceError):
            runner.check_execution(SimpleNamespace(returncode=1, stdout=complete, stderr='halt failed'))

    def test_test_profile_must_enable_exact_kunit_selection(self):
        valid = 'CONFIG_KUNIT=y\nCONFIG_MPTCP_KUNIT_TEST=y\nCONFIG_MPTCP=y\nCONFIG_MPTCP_IPV6=y\n'
        runner.check_config(valid)
        for invalid in (valid.replace('CONFIG_KUNIT=y\n', ''), valid.replace('CONFIG_MPTCP_KUNIT_TEST=y', 'CONFIG_MPTCP_KUNIT_TEST=m'),
                        valid + 'CONFIG_KUNIT_ALL_TESTS=y\n', valid + 'CONFIG_KUNIT_DEFAULT_ENABLED=y\n'):
            with self.subTest(config=invalid), self.assertRaises(runner.EvidenceError):
                runner.check_config(invalid)

    def test_profile_staging_preserves_production_inputs_and_fingerprints_test_seed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'repo'; destination = Path(temporary) / 'build/inputs'
            for directory in ('config', 'tools', 'src/posix/lkl-overlay'):
                (root / directory).mkdir(parents=True)
            files = {'config/native-linux.json': '{}', 'config/native-linux.defconfig': 'CONFIG_INET=y\n',
                     'config/native-linux-mptcp-kunit.config': 'CONFIG_KUNIT=y\n',
                     'tools/build-native-linux.py': 'unchanged builder', 'src/posix/lkl-overlay/adapter.c': 'adapter'}
            for name, value in files.items(): (root / name).write_text(value)
            runner.stage_inputs(root, destination)
            self.assertEqual((destination / 'config/native-linux.defconfig').read_text(), 'CONFIG_INET=y\n\nCONFIG_KUNIT=y\n')
            self.assertEqual((destination / 'tools/build-native-linux.py').read_text(), 'unchanged builder')
            for name, value in files.items(): self.assertEqual((root / name).read_text(), value)
            runner.stage_inputs(root, destination)  # owned input snapshot can be rebuilt
            (destination / '.ker-mptcp-kunit-inputs').unlink()
            with self.assertRaisesRegex(runner.EvidenceError, 'foreign input directory'):
                runner.stage_inputs(root, destination)
