#!/usr/bin/env python3
"""Mutation tests for omissions, fabricated coverage and modified snapshots."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import fstack_migration as audit

ROOT = Path(__file__).resolve().parents[1]


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'tests').mkdir()
        for name in ('fstack-migration.json', 'fstack-provenance.json', 'CMakeLists.txt'):
            shutil.copyfile(ROOT / 'tests' / name, self.root / 'tests' / name)
        shutil.copyfile(ROOT / 'CMakeLists.txt', self.root / 'CMakeLists.txt')
        shutil.copytree(ROOT / 'cmake', self.root / 'cmake')
        shutil.copytree(ROOT / 'tests/upstream', self.root / 'tests/upstream')
        self.path = self.root / 'tests/fstack-migration.json'
        self.provenance_path = self.root / 'tests/fstack-provenance.json'
        self.manifest = json.loads(self.path.read_text())

    def save(self):
        self.path.write_text(json.dumps(self.manifest))

    def test_valid_snapshot_reports_remaining_work(self):
        manifest, counts = audit.validate(self.root)
        self.assertEqual(len(manifest['files']), 106)
        self.assertEqual(len(manifest['cases']), 433)
        self.assertGreater(counts['blocked'], 0)

    def test_omitted_case_is_rejected(self):
        self.manifest['cases'].pop()
        self.save()
        with self.assertRaisesRegex(ValueError, 'Case mismatch'):
            audit.validate(self.root)

    def test_modified_upstream_bytes_are_rejected(self):
        path = self.root / 'tests/upstream/fstack/tests/unit/test_ff_epoll.c'
        path.write_text(path.read_text() + '\n')
        with self.assertRaisesRegex(ValueError, 'Git blob mismatch'):
            audit.validate(self.root)

    def test_fabricated_pass_without_test_is_rejected(self):
        item = next(v for v in self.manifest['cases'] if v['status'] == 'blocked')
        item['status'] = 'scenario-adapted'
        self.save()
        with self.assertRaisesRegex(ValueError, 'no runnable Ker test'):
            audit.validate(self.root)

    def test_nonexistent_ctest_is_rejected(self):
        item = next(v for v in self.manifest['cases'] if v['status'] == 'scenario-adapted')
        item['ker_tests'][0]['ctest'] = 'fabricated-test'
        self.save()
        with self.assertRaisesRegex(ValueError, 'Missing CTest'):
            audit.validate(self.root)

    def test_unrelated_provenance_source_file_is_rejected(self):
        item = next(v for v in self.manifest['cases']
                    if v['id'].endswith('test_ff_epoll_wait_evfilt_read_data_zero_no_eof_yields_in'))
        item['status'] = 'scenario-adapted'
        item['ker_tests'] = [{'ctest': 'native-fstack-udp-interop',
                              'provenance_case': 'native-fstack-udp-interop'}]
        self.save()
        with self.assertRaisesRegex(ValueError, 'Provenance source file mismatch'):
            audit.validate(self.root)

    def test_unrelated_provenance_source_case_is_rejected(self):
        item = next(v for v in self.manifest['cases']
                    if v['id'].endswith('test_ff_epoll_wait_evfilt_read_data_zero_no_eof_yields_in'))
        item['status'] = 'scenario-adapted'
        item['ker_tests'] = [{'ctest': 'native-fstack-epoll',
                              'provenance_case': 'native-fstack-epoll'}]
        self.save()
        with self.assertRaisesRegex(ValueError, 'Provenance source case mismatch'):
            audit.validate(self.root)

    def test_unrelated_existing_ctest_is_rejected_for_exact_provenance(self):
        item = next(v for v in self.manifest['cases']
                    if v['id'].endswith('test_ff_epoll_wait_ev_eof_read_to_hup_in'))
        self.assertEqual(item['ker_tests'][0]['provenance_case'], 'native-fstack-epoll')
        item['ker_tests'][0]['ctest'] = 'udp-ip-options'
        self.save()
        with self.assertRaisesRegex(ValueError, 'CTest/provenance mismatch'):
            audit.validate(self.root)

    def test_missing_provenance_ctest_binding_is_rejected(self):
        provenance = json.loads(self.provenance_path.read_text())
        provenance['cases']['native-fstack-epoll'].pop('ker_ctests')
        self.provenance_path.write_text(json.dumps(provenance))
        with self.assertRaisesRegex(ValueError, 'Invalid provenance CTest binding'):
            audit.validate(self.root)

    def test_invalid_provenance_ctest_binding_type_is_rejected(self):
        provenance = json.loads(self.provenance_path.read_text())
        provenance['cases']['native-fstack-epoll']['ker_ctests'] = 'native-fstack-epoll'
        self.provenance_path.write_text(json.dumps(provenance))
        with self.assertRaisesRegex(ValueError, 'Invalid provenance CTest binding'):
            audit.validate(self.root)

    def test_extra_snapshot_file_is_rejected(self):
        (self.root / 'tests/upstream/fstack/tests/unknown.c').write_text('test')
        with self.assertRaisesRegex(ValueError, 'Snapshot file mismatch'):
            audit.validate(self.root)

    def test_completion_gate_fails_while_cases_are_incomplete(self):
        result = subprocess.run([sys.executable, str(ROOT / 'tests/fstack_migration.py'),
                                 '--root', str(self.root), '--require-complete'],
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('blocked + 10 partial cases', result.stderr)


if __name__ == '__main__':
    unittest.main()
