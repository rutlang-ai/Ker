"""Model-only validation controls; no memfd or proc-root reads are performed."""
import importlib.util
import os
from pathlib import Path
import unittest
from unittest import mock
from types import SimpleNamespace

READER = Path(__file__).resolve().parents[2] / 'tools' / 'ker-source-shell-wrapper.py'
SPEC = importlib.util.spec_from_file_location('scope_reader_draft', READER)
reader = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reader)


class DescriptorSchemaControls(unittest.TestCase):
    def setUp(self):
        self.actual = {
            'root_pid': 1,
            'root_start_time': 123456,
            'root_exe': '/usr/bin/python3',
            'root_exe_device': 2049,
            'root_exe_inode': 991122,
            'uid': os.geteuid(),
            'pid_namespace': [4, 55],
            'mount_namespace': [4, 66],
        }
        self.value = {
            'schema': 'ker-source-helper-scope-descriptor-v1',
            'role': 'bootstrap-capabilities',
            'scope_path': '/run/ker-source-shell/bootstrap-scope.json',
            'scope_device': 4,
            'scope_inode': 7788,
            'scope_sha256': 'a' * 64,
            'run_id': '',
            **self.actual,
        }
        self.fake_ns = {
            '/proc/self/ns/pid': SimpleNamespace(st_dev=4, st_ino=55),
            '/proc/self/ns/mnt': SimpleNamespace(st_dev=4, st_ino=66),
        }
        self.real_stat = reader.os.stat

    def validate(self, value, role='bootstrap-capabilities'):
        def fake_stat(path, *args, **kwargs):
            key = str(path)
            if key in self.fake_ns:
                return self.fake_ns[key]
            raise AssertionError('unexpected proc/filesystem access: ' + key)
        with mock.patch.object(reader.os, 'stat', side_effect=fake_stat):
            reader.validate_descriptor(value, role, self.actual)

    def test_exact_15_field_bootstrap_descriptor_is_accepted(self):
        self.assertEqual(len(self.value), 15)
        self.validate(self.value)

    def test_omitting_any_required_descriptor_field_is_rejected(self):
        for key in reader.DESCRIPTOR_KEYS:
            with self.subTest(key=key):
                value = dict(self.value)
                del value[key]
                with self.assertRaises(reader.ScopeError):
                    self.validate(value)

    def test_any_extra_descriptor_field_is_rejected(self):
        value = dict(self.value, ignored=True)
        with self.assertRaises(reader.ScopeError):
            self.validate(value)

    def test_boolean_is_not_accepted_as_integer_identity(self):
        for key in ('scope_device', 'scope_inode', 'root_pid', 'root_start_time',
                    'root_exe_device', 'root_exe_inode', 'uid'):
            with self.subTest(key=key):
                value = dict(self.value)
                value[key] = True
                with self.assertRaises(reader.ScopeError):
                    self.validate(value)
        value = dict(self.value)
        value['mount_namespace'] = [4, True]
        with self.assertRaises(reader.ScopeError):
            self.validate(value)

    def test_final_descriptor_requires_exact_run_role_and_identity(self):
        value = dict(self.value)
        value['role'] = 'run-cleanup'
        value['run_id'] = 'gr_20261113_134500_12345_deadbeef'
        self.validate(value, 'run-cleanup')
        for bad in ('', 'gr_20261113_134500_0_deadbeef',
                    'gr_20261113_134500_12345_DEADBEEF'):
            with self.subTest(run_id=bad):
                candidate = dict(value, run_id=bad)
                with self.assertRaises(reader.ScopeError):
                    self.validate(candidate, 'run-cleanup')

    def test_root_and_namespace_mismatch_is_rejected(self):
        for key in ('root_start_time', 'root_exe_inode', 'pid_namespace', 'mount_namespace'):
            with self.subTest(key=key):
                value = dict(self.value)
                value[key] = [9, 9] if key.endswith('namespace') else value[key] + 1
                with self.assertRaises(reader.ScopeError):
                    self.validate(value)

    def test_pinned_helper_hash_matches_product_helper_bytes(self):
        helper = READER.with_name('nginx-source-shell-helper.py')
        self.assertEqual(reader.HELPER_SHA256,
            __import__('hashlib').sha256(helper.read_bytes()).hexdigest())

    def test_exact_wrapper_roles_and_helper_argv(self):
        self.assertEqual(reader.helper_argv('kill_process.sh', ['--capabilities'],
            self.value, 'bootstrap-capabilities'), ['signal', '--capabilities'])
        run = dict(self.value, role='run-cleanup',
            run_id='gr_20261113_134500_12345_deadbeef')
        self.assertEqual(reader.helper_argv('rm_tmp_file.sh',
            ['/tmp/' + run['run_id']], run, 'run-cleanup'),
            ['remove', '/tmp/' + run['run_id']])
        self.assertEqual(reader.helper_argv('chmod_modify.sh',
            ['0640', '/var/run/ker/file'], run, 'run-cleanup'),
            ['chmod', '0640', '/var/run/ker/file'])
        with self.assertRaises(reader.ScopeError):
            reader.helper_argv('chmod_modify.sh',
                ['+x', '/var/run/ker/file'], run, 'run-cleanup')
        with self.assertRaises(reader.ScopeError):
            reader.helper_argv('rm_tmp_file.sh',
                ['/tmp/not-' + run['run_id']], run, 'run-cleanup')


if __name__ == '__main__':
    unittest.main()
