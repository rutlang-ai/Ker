import importlib.util
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

spec = importlib.util.spec_from_file_location('udp_validation', Path(__file__).resolve().parents[1] / 'tools/validate-udp.py')
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


class ReportGuards(unittest.TestCase):
    def matrix(self, kind='functional'):
        return {'scope': 'fixture', 'features': [{'id': 'one', 'kind': kind, 'ctests': ['test-a'], 'note': 'fixture'}]}

    def registered(self, *names):
        return {'tests': [{'name': name, 'properties': [{'name': 'LABELS', 'value': ['native-udp']}]} for name in names]}

    def test_registered_membership_is_exact(self):
        self.assertEqual(validator.selected_tests(self.matrix(), self.registered('test-a')), ['test-a'])
        for registered in (self.registered(), self.registered('test-a', 'test-b')):
            with self.assertRaises(ValueError):
                validator.selected_tests(self.matrix(), registered)

    def test_no_testless_or_duplicate_feature_passes(self):
        matrix = self.matrix(); matrix['features'][0]['ctests'] = []
        with self.assertRaises(ValueError):
            validator.selected_tests(matrix, self.registered())
        matrix = self.matrix(); matrix['features'] *= 2
        with self.assertRaises(ValueError):
            validator.selected_tests(matrix, self.registered('test-a'))

    def test_unsupported_probe_is_not_compatibility_pass(self):
        report = validator.report(self.matrix('unsupported-boundary'), {'test-a': 'passed'}, 0)
        self.assertEqual(report['features'][0]['status'], 'unsupported-confirmed')
        self.assertTrue(report['automated_checks_passed'])
        self.assertFalse(report['all_features_supported_and_validated'])

    def test_manual_gap_remains_unvalidated(self):
        matrix = self.matrix('manual'); matrix['features'][0]['ctests'] = []
        report = validator.report(matrix, {}, 0)
        self.assertEqual(report['features'][0]['status'], 'not-validated')
        self.assertFalse(report['all_features_supported_and_validated'])

    def test_infrastructure_failure_cannot_be_green(self):
        report = validator.report(self.matrix(), {'test-a': 'passed'}, 1)
        self.assertFalse(report['automated_checks_passed'])
        self.assertFalse(report['all_features_supported_and_validated'])

    def test_foreign_or_stale_junit_cannot_be_imported_as_tested_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            build = root / 'build'
            build.mkdir()
            report = root / 'report.json'
            for name, xml in (
                ('foreign', '<testsuite><testcase name="unrelated"/><testcase name="test-a"/></testsuite>'),
                ('stale', '<testsuite><testcase name="test-a"/></testsuite>'),
            ):
                with self.subTest(name=name):
                    path = root / (name + '.xml')
                    path.write_text(xml)
                    result = subprocess.run([
                        sys.executable, str(Path(validator.__file__)),
                        '--build-dir', str(build), '--report', str(report),
                        '--from-junit', str(path), '--ctest-returncode', '0',
                    ], capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn('cannot establish tested-binary provenance', result.stderr)
                    self.assertFalse(report.exists())

    def test_test_artifact_hashes_cover_selected_command_dependencies(self):
        with tempfile.TemporaryDirectory() as directory:
            build = Path(directory) / 'build'
            build.mkdir()
            names = ('ker-posix-fstack-udp-test', 'ker-posix-fstack-jumbo-test',
                     'ker-ipv6-interop-test', 'ker-ipv6-route-test')
            paths = []
            for name in names:
                path = build / name
                path.write_bytes(('artifact:' + name).encode())
                path.chmod(0o755)
                paths.append(str(path))
            app_guard = build / 'ker-app'
            app_guard.write_bytes(b'implicit ker-run guard')
            registered = {'tests': [{'name': 'test-a', 'command': [
                sys.executable, str(Path(__file__).resolve().parents[1] / 'tools/ker-run.py'),
                '--app', *paths],
                'properties': [{'name': 'LABELS', 'value': ['native-udp']}]}]}
            hashes = validator.test_artifacts(build, registered, ['test-a'])
            for name in names:
                self.assertIn('build/' + name, hashes)
                self.assertEqual(hashes['build/' + name], hashlib.sha256(
                    (build / name).read_bytes()).hexdigest())
            self.assertIn('source/tools/ker-run.py', hashes)
            self.assertTrue(any(key.startswith('external/') for key in hashes))
            self.assertIn('build/ker-app', hashes)
            app_guard.unlink()
            with self.assertRaisesRegex(ValueError, 'missing local test artifact used by ker-run.py'):
                validator.test_artifacts(build, registered, ['test-a'])

    def test_report_xml_and_log_suffixes_keep_three_valid_artifacts_distinct(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            build = root / 'build'
            build.mkdir()
            matrix = root / 'matrix.json'
            matrix.write_text(json.dumps({'scope': 'fixture', 'features': [
                {'id': 'one', 'kind': 'functional', 'ctests': ['test-a'], 'note': 'fixture'}]}))
            app = build / 'test-app'
            app.write_text('fixture executable')
            registered = {'tests': [{'name': 'test-a', 'command': [str(app)],
                'properties': [{'name': 'LABELS', 'value': ['native-udp']}]}]}

            def run_ctest(command, stdout, stderr):
                junit = Path(command[command.index('--output-junit') + 1])
                junit.write_text('<testsuite><testcase name="test-a"/></testsuite>')
                stdout.write('fake ctest passed\n')
                return SimpleNamespace(returncode=0)

            for suffix in ('.xml', '.log'):
                with self.subTest(suffix=suffix):
                    report_path = root / ('report' + suffix)
                    with mock.patch.object(sys, 'argv', [
                            str(Path(validator.__file__)), '--build-dir', str(build),
                            '--matrix', str(matrix), '--report', str(report_path)]), \
                         mock.patch.object(validator.subprocess, 'check_output',
                                           return_value=json.dumps(registered)), \
                         mock.patch.object(validator.subprocess, 'run', side_effect=run_ctest):
                        self.assertEqual(validator.main(), 0)
                    report = json.loads(report_path.read_text())
                    junit_path, log_path = Path(report['junit']), Path(report['log'])
                    self.assertEqual(len({report_path.resolve(), junit_path.resolve(), log_path.resolve()}), 3)
                    self.assertEqual(json.loads(report_path.read_text())['tests'], {'test-a': 'passed'})
                    self.assertIn('<testcase name="test-a"/>', junit_path.read_text())
                    self.assertIn('fake ctest passed', log_path.read_text())
                    self.assertIn('build/test-app', report['test_artifacts_sha256'])

    def test_matrix_or_binary_drift_during_ctest_rejects_report_and_clears_old_success(self):
        for drift in ('matrix', 'binary'):
            with self.subTest(drift=drift), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                build = root / 'build'
                build.mkdir()
                matrix = root / 'matrix.json'
                original_matrix = json.dumps({'scope': 'fixture', 'features': [
                    {'id': 'one', 'kind': 'functional', 'ctests': ['test-a'], 'note': 'fixture'}]})
                matrix.write_text(original_matrix)
                app = build / 'test-app'
                app.write_text('before')
                registered = {'tests': [{'name': 'test-a', 'command': [str(app)],
                    'properties': [{'name': 'LABELS', 'value': ['native-udp']}]}]}
                report_path = root / 'report.json'
                report_path.write_text('{"automated_checks_passed": true}')

                def mutate_during_ctest(command, stdout, stderr):
                    junit = Path(command[command.index('--output-junit') + 1])
                    junit.write_text('<testsuite><testcase name="test-a"/></testsuite>')
                    if drift == 'matrix':
                        matrix.write_text(original_matrix + '\n')
                    else:
                        app.write_text('after')
                    return SimpleNamespace(returncode=0)

                with mock.patch.object(sys, 'argv', [
                        str(Path(validator.__file__)), '--build-dir', str(build),
                        '--matrix', str(matrix), '--report', str(report_path)]), \
                     mock.patch.object(validator.subprocess, 'check_output',
                                       return_value=json.dumps(registered)), \
                     mock.patch.object(validator.subprocess, 'run', side_effect=mutate_during_ctest):
                    with self.assertRaisesRegex(RuntimeError, 'changed while'):
                        validator.main()
                self.assertFalse(report_path.exists())


    def test_ctest_registration_drift_rejects_report_and_clears_old_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            build = root / 'build'
            build.mkdir()
            matrix = root / 'matrix.json'
            matrix.write_text(json.dumps({'scope': 'fixture', 'features': [
                {'id': 'one', 'kind': 'functional', 'ctests': ['test-a'], 'note': 'fixture'}]}))
            first, second = build / 'first-app', build / 'second-app'
            first.write_text('first')
            second.write_text('second')
            registered = lambda app: {'tests': [{'name': 'test-a', 'command': [str(app)],
                'properties': [{'name': 'LABELS', 'value': ['native-udp']},
                               {'name': 'WORKING_DIRECTORY', 'value': str(build)}]}]}
            report_path = root / 'report.json'
            report_path.write_text('{"automated_checks_passed": true}')

            def run_ctest(command, stdout, stderr):
                junit = Path(command[command.index('--output-junit') + 1])
                junit.write_text('<testsuite><testcase name="test-a"/></testsuite>')
                return SimpleNamespace(returncode=0)

            with mock.patch.object(sys, 'argv', [
                    str(Path(validator.__file__)), '--build-dir', str(build),
                    '--matrix', str(matrix), '--report', str(report_path)]), \
                 mock.patch.object(validator.subprocess, 'check_output', side_effect=[
                     json.dumps(registered(first)), json.dumps(registered(second))]), \
                 mock.patch.object(validator.subprocess, 'run', side_effect=run_ctest):
                with self.assertRaisesRegex(RuntimeError, 'registration changed'):
                    validator.main()
            self.assertFalse(report_path.exists())

    def test_skips_missing_and_failures_do_not_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'results.xml'
            for child in ('<skipped/>', '<failure/>', '<error/>'):
                path.write_text('<testsuite><testcase name="test-a">' + child + '</testcase></testsuite>')
                self.assertEqual(validator.junit_results(path, ['test-a']), {'test-a': 'failed'})
            path.write_text('<testsuite/>')
            self.assertEqual(validator.junit_results(path, ['test-a']), {'test-a': 'missing'})
            path.write_text('<testsuite><testcase name="test-a"/><testcase name="test-a"/></testsuite>')
            with self.assertRaises(ValueError):
                validator.junit_results(path, ['test-a'])


if __name__ == '__main__':
    unittest.main()
