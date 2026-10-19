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
