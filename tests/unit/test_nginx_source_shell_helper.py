import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


REPO = Path(__file__).resolve().parents[2]
HELPER_PATH = REPO / 'tools/nginx-source-shell-helper.py'
SPEC = importlib.util.spec_from_file_location('nginx_source_shell_helper', HELPER_PATH)
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)


class OwnedHelperFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ker-shell-helper-')
        self.base = Path(self.tmp.name)
        self.scope_dir = self.base / 'control'
        self.scope_dir.mkdir(mode=0o700)
        self.scope_path = self.scope_dir / 'scope.json'
        self.root = self.base / 'owned'
        self.root.mkdir(mode=0o700)
        self.children = []
        self.write_scope()

    def tearDown(self):
        for child in self.children:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=2)
        self.tmp.cleanup()

    def supervisor(self, pid=None):
        identity = helper.process_identity(os.getpid() if pid is None else pid)
        return {'pid': os.getpid() if pid is None else pid,
                'start_time': identity[0], 'exe': identity[1],
                'device': identity[2], 'inode': identity[3]}

    def scope_record(self, supervisors=None, namespace=None, root=None):
        directory = self.root if root is None else Path(root)
        info = directory.stat()
        return {'version': 1, 'uid': os.geteuid(),
                'pid_namespace': (helper.namespace_identity() if namespace is None else namespace),
                'roots': [{'path': str(directory), 'device': info.st_dev, 'inode': info.st_ino}],
                'supervisors': [self.supervisor()] if supervisors is None else supervisors}

    def write_scope(self, record=None):
        data = (json.dumps(self.scope_record() if record is None else record,
                           sort_keys=True, separators=(',', ':')) + '\n').encode()
        self.scope_path.write_bytes(data)
        self.scope_path.chmod(0o600)
        self.scope_data = data
        info = self.scope_path.stat()
        self.scope_identity = (info.st_dev, info.st_ino)
        self.scope_digest = hashlib.sha256(data).hexdigest()

    def argv(self, operation, *args, identity=None, scope_identity=None, digest=None):
        device, inode = self.scope_identity if scope_identity is None else scope_identity
        return [sys.executable, str(HELPER_PATH), '--scope', str(self.scope_path),
                '--scope-device', str(device), '--scope-inode', str(inode),
                '--scope-sha256', self.scope_digest if digest is None else digest,
                operation, *map(str, args)]

    def invoke(self, operation, *args, timeout=5, scope_identity=None, digest=None):
        return subprocess.run(self.argv(operation, *args, scope_identity=scope_identity,
                                        digest=digest), capture_output=True,
                             text=True, timeout=timeout)

    def start_target(self, body=None):
        body = body or (
            'import signal,time; '
            'signal.signal(signal.SIGTERM, lambda *_: exit(0)); '
            'print("READY", flush=True); time.sleep(60)')
        child = subprocess.Popen([sys.executable, '-c', body], stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True)
        self.children.append(child)
        self.assertEqual(child.stdout.readline().strip(), 'READY')
        child.stdout.close()
        child.stderr.close()
        return child

    def signal_args(self, child, sig='TERM', wait='2', **overrides):
        identity = helper.process_identity(child.pid)
        values = {'pid': child.pid, 'start_time': identity[0], 'exe': identity[1],
                  'device': identity[2], 'inode': identity[3], 'signal': sig, 'wait': wait}
        values.update(overrides)
        return ('signal', '--pid', values['pid'], '--start-time', values['start_time'],
                '--exe', values['exe'], '--device', values['device'], '--inode', values['inode'],
                '--signal', values['signal'], '--wait', values['wait'])

class OwnedHelperControls(OwnedHelperFixture):
    def test_signals_owned_child_via_pidfd_and_waits(self):
        child = self.start_target()
        result = self.invoke(*self.signal_args(child))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(child.wait(timeout=2), 0)

    def test_wrong_identity_and_supervisor_target_are_denied(self):
        child = self.start_target()
        result = self.invoke(*self.signal_args(child, start_time='1'))
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(child.poll())
        own = helper.process_identity(os.getpid())
        result = self.invoke('signal', '--pid', os.getpid(), '--start-time', own[0],
            '--exe', own[1], '--device', own[2], '--inode', own[3], '--signal', 'TERM')
        self.assertNotEqual(result.returncode, 0)

    def test_unlisted_supervisor_ancestry_is_denied(self):
        supervisor = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
        self.children.append(supervisor)
        self.write_scope(self.scope_record(supervisors=[self.supervisor(supervisor.pid)]))
        child = self.start_target()
        result = self.invoke(*self.signal_args(child))
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(child.poll())

    def test_broken_process_ancestry_returns_denial(self):
        class ProcPath:
            def __init__(self, value):
                self.value = str(value)

            def __truediv__(self, other):
                return ProcPath(self.value + '/' + str(other))

            def read_text(self):
                fields = ['0'] * 20
                fields[1] = '0'
                return '999 (test) ' + ' '.join(fields)

        loaded = helper.load_scope(str(self.scope_path), *self.scope_identity,
                                   self.scope_digest)
        try:
            with mock.patch.object(helper, 'Path', ProcPath):
                self.assertIsNone(helper.owned_descendant(999, loaded))
        finally:
            os.close(loaded['_fd'])
            os.close(loaded['_parent'])

    def test_pid_namespace_mismatch_is_denied(self):
        namespace = helper.namespace_identity()
        namespace[1] += 1
        self.write_scope(self.scope_record(namespace=namespace))
        result = self.invoke('remove', str(self.root / 'missing'))
        self.assertNotEqual(result.returncode, 0)

    def test_signal_timeout_returns_three_and_does_not_claim_exit(self):
        child = self.start_target('import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); print("READY", flush=True); time.sleep(60)')
        result = self.invoke(*self.signal_args(child, wait='0.05'))
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertIsNone(child.poll())

    def test_cleanup_rejects_outside_path(self):
        outside = self.base / 'outside.txt'
        outside.write_text('keep')
        result = self.invoke('remove', str(outside))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(outside.read_text(), 'keep')

    def test_cleanup_unlinks_symlink_without_following_it(self):
        outside = self.base / 'outside.txt'
        outside.write_text('keep')
        link = self.root / 'link'
        link.symlink_to(outside)
        result = self.invoke('remove', str(link))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(link.is_symlink())
        self.assertEqual(outside.read_text(), 'keep')

    def test_recursive_remove_is_bounded_by_depth_and_entry_count(self):
        cursor = self.root
        for index in range(33):
            cursor = cursor / f'd{index}'
            cursor.mkdir(mode=0o700)
        (cursor / 'leaf').write_text('bounded')
        too_deep = self.invoke('remove', str(self.root))
        self.assertNotEqual(too_deep.returncode, 0)
        self.assertTrue(self.root.exists())

        exact_root = self.base / 'entry-bound'
        exact_root.mkdir(mode=0o700)
        self.write_scope(self.scope_record(root=exact_root))
        for index in range(4095):
            (exact_root / f'f{index:04d}').touch()
        at_bound = self.invoke('remove', str(exact_root))
        self.assertEqual(at_bound.returncode, 0, at_bound.stderr)
        self.assertFalse(exact_root.exists())

        over_root = self.base / 'entry-over-bound'
        over_root.mkdir(mode=0o700)
        self.write_scope(self.scope_record(root=over_root))
        for index in range(4096):
            (over_root / f'f{index:04d}').touch()
        over_bound = self.invoke('remove', str(over_root))
        self.assertNotEqual(over_bound.returncode, 0)
        self.assertTrue(over_root.exists())

    def test_symlink_directory_component_is_not_traversed(self):
        outside = self.base / 'outside'
        outside.mkdir(mode=0o700)
        victim = outside / 'victim'
        victim.write_text('keep')
        (self.root / 'jump').symlink_to(outside, target_is_directory=True)
        result = self.invoke('remove', str(self.root / 'jump' / 'victim'))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(victim.read_text(), 'keep')

    def test_scope_content_change_and_same_path_inode_swap_fail(self):
        loaded = helper.load_scope(str(self.scope_path), *self.scope_identity, self.scope_digest)
        try:
            self.scope_path.write_text('{"changed":true}\n')
            with self.assertRaises(ValueError):
                helper.verify_scope(loaded)
        finally:
            os.close(loaded['_fd'])
            os.close(loaded['_parent'])
        self.write_scope()
        old_identity, old_digest, old_data = self.scope_identity, self.scope_digest, self.scope_data
        saved = self.scope_dir / 'old.json'
        os.replace(self.scope_path, saved)
        self.scope_path.write_bytes(old_data)
        self.scope_path.chmod(0o600)
        result = self.invoke('remove', str(self.root / 'missing'),
                             scope_identity=old_identity, digest=old_digest)
        self.assertNotEqual(result.returncode, 0)

    def test_scope_parent_rename_invalidates_held_scope(self):
        loaded = helper.load_scope(str(self.scope_path), *self.scope_identity, self.scope_digest)
        moved = self.base / 'control-moved'
        os.rename(self.scope_dir, moved)
        self.scope_dir.mkdir(mode=0o700)
        self.scope_path.write_bytes(self.scope_data)
        self.scope_path.chmod(0o600)
        try:
            with self.assertRaises((OSError, ValueError)):
                helper.verify_scope(loaded)
        finally:
            os.close(loaded['_fd'])
            os.close(loaded['_parent'])

    def test_scope_failure_paths_do_not_leak_fds(self):
        def count_fds():
            return len(os.listdir('/proc/self/fd'))
        before = count_fds()
        for _ in range(20):
            loaded = helper.load_scope(str(self.scope_path), *self.scope_identity, self.scope_digest)
            os.close(loaded['_fd'])
            os.close(loaded['_parent'])
            with self.assertRaises(ValueError):
                helper.load_scope(str(self.scope_path), *self.scope_identity, '0' * 64)
        self.assertEqual(count_fds(), before)

    def test_chmod_refuses_symlinks_and_allows_regular_file(self):
        target = self.root / 'mode-target'
        target.write_text('x')
        link = self.root / 'mode-link'
        link.symlink_to(target)
        rejected = self.invoke('chmod', '0600', str(link))
        self.assertNotEqual(rejected.returncode, 0)
        accepted = self.invoke('chmod', '0600', str(target))
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

    def test_chmod_rejects_hardlink_to_outside_file(self):
        outside = self.base / 'outside-mode-target'
        outside.write_text('keep mode')
        os.chmod(outside, 0o644)
        alias = self.root / 'outside-alias'
        os.link(outside, alias)
        result = self.invoke('chmod', '0600', str(alias))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0o644)

    def test_root_replacement_and_nonprivate_root_are_denied(self):
        os.chmod(self.root, 0o755)
        result = self.invoke('remove', str(self.root / 'missing'))
        self.assertNotEqual(result.returncode, 0)
        os.chmod(self.root, 0o700)
        original = self.root
        moved = self.base / 'owned-old'
        os.rename(original, moved)
        original.mkdir(mode=0o700)
        result = self.invoke('remove', str(original / 'missing'))
        self.assertNotEqual(result.returncode, 0)
        self.root = moved


class VersionTwoExactChildControls(OwnedHelperFixture):
    RUN_ID = 'gr_20261113_134500_12345_deadbeef'

    def v2_record(self, children=None):
        info = self.root.stat()
        base = self.scope_record()
        base['version'] = 2
        base['run_id'] = self.RUN_ID
        base['roots'] = [{'path': str(self.root), 'device': info.st_dev,
                          'inode': info.st_ino,
                          'children': [self.RUN_ID] if children is None else children}]
        return base

    def write_v2_scope(self, record=None):
        self.write_scope(self.v2_record() if record is None else record)

    def test_exact_child_and_descendants_are_removable_but_parent_survives(self):
        child = self.root / self.RUN_ID
        nested = child / 'nested'
        nested.mkdir(parents=True, mode=0o700)
        (nested / 'owned').write_text('owned')
        self.write_v2_scope()
        result = self.invoke('remove', str(child))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(child.exists())
        self.assertTrue(self.root.is_dir())

    def test_container_and_decimal_map_children_are_exactly_accepted(self):
        accepted = ['container-' + self.RUN_ID,
                    'container-' + self.RUN_ID + 'map_17']
        self.write_v2_scope(self.v2_record(children=accepted))
        for child_name in accepted:
            with self.subTest(child=child_name):
                child = self.root / child_name
                child.mkdir(mode=0o700)
                (child / 'file').write_text('owned')
                result = self.invoke('remove', str(child))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(child.exists())

    def test_future_exact_child_can_be_scoped_before_it_exists(self):
        self.write_v2_scope()
        future = self.root / self.RUN_ID
        result = self.invoke('remove', str(future))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(future.exists())
        future.mkdir(mode=0o700)
        (future / 'later').write_text('later')
        result = self.invoke('remove', str(future))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(future.exists())
        self.assertTrue(self.root.is_dir())

    def test_parent_sibling_and_prefix_sibling_are_denied(self):
        sibling = self.root / 'sibling'
        sibling.mkdir(mode=0o700)
        (sibling / 'keep').write_text('keep')
        prefix = self.root / (self.RUN_ID + '-extra')
        prefix.mkdir(mode=0o700)
        (prefix / 'keep').write_text('keep')
        self.write_v2_scope()
        for target in (self.root, sibling, prefix):
            with self.subTest(target=target):
                result = self.invoke('remove', str(target))
                self.assertNotEqual(result.returncode, 0)
        self.assertTrue((sibling / 'keep').exists())
        self.assertTrue((prefix / 'keep').exists())
        self.assertTrue(self.root.is_dir())

    def test_child_allowlist_requires_exact_run_specific_names(self):
        for child in ('unrelated', self.RUN_ID + '-sibling',
                      'container-' + self.RUN_ID + 'map_*',
                      'container-' + self.RUN_ID + 'map_1x'):
            with self.subTest(child=child):
                self.write_v2_scope(self.v2_record(children=[child]))
                result = self.invoke('remove', str(self.root / child))
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(self.root.is_dir())

    def test_v2_rejects_symlink_and_hardlink_entries(self):
        outside_dir = self.base / 'outside-dir'
        outside_dir.mkdir(mode=0o700)
        outside = outside_dir / 'keep'
        outside.write_text('outside')
        link = self.root / self.RUN_ID
        link.symlink_to(outside_dir, target_is_directory=True)
        self.write_v2_scope()
        symlink_result = self.invoke('remove', str(link))
        self.assertNotEqual(symlink_result.returncode, 0)
        self.assertTrue(link.is_symlink())
        self.assertEqual(outside.read_text(), 'outside')

        link.unlink()
        child = self.root / self.RUN_ID
        child.mkdir(mode=0o700)
        alias = child / 'alias'
        os.link(outside, alias)
        hardlink_result = self.invoke('remove', str(child))
        self.assertNotEqual(hardlink_result.returncode, 0)
        self.assertTrue(alias.exists())
        self.assertEqual(outside.read_text(), 'outside')

    def test_v2_chmod_is_limited_to_exact_child(self):
        child = self.root / self.RUN_ID
        child.mkdir(mode=0o700)
        target = child / 'mode-target'
        target.write_text('owned')
        sibling = self.root / (self.RUN_ID + '-sibling')
        sibling.write_text('keep')
        os.chmod(target, 0o644)
        os.chmod(sibling, 0o644)
        self.write_v2_scope()
        accepted = self.invoke('chmod', '0600', str(target))
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        rejected = self.invoke('chmod', '0600', str(sibling))
        self.assertNotEqual(rejected.returncode, 0)
        self.assertEqual(stat.S_IMODE(sibling.stat().st_mode), 0o644)

    def test_v2_scope_mutation_invalidates_open_scope(self):
        self.write_v2_scope()
        loaded = helper.load_scope(str(self.scope_path), *self.scope_identity,
                                   self.scope_digest)
        try:
            changed = self.scope_data.replace(self.RUN_ID.encode(),
                                              (self.RUN_ID + 'x').encode())
            self.scope_path.write_bytes(changed)
            self.scope_path.chmod(0o600)
            with self.assertRaises(ValueError):
                helper.verify_scope(loaded)
        finally:
            os.close(loaded['_fd'])
            os.close(loaded['_parent'])

    def test_v2_rejects_invalid_run_id_syntax(self):
        for bad in ('gr_20261113_134500_0_deadbeef',
                    'gr_2026_134500_12345_deadbeef',
                    'gr_20261113_134500_12345_DEADBEEF',
                    'gr_20261113_134500_12345_deadbeef/child'):
            with self.subTest(run_id=bad):
                record = self.v2_record()
                record['run_id'] = bad
                record['roots'][0]['children'] = [bad]
                self.write_v2_scope(record)
                result = self.invoke('remove', str(self.root / bad))
                self.assertNotEqual(result.returncode, 0)

    def test_v2_rejects_nested_scoped_parents(self):
        extra = self.base / 'owned' / 'nested-parent'
        extra.mkdir(mode=0o700)
        info = extra.stat()
        record = self.v2_record()
        record['roots'].append({'path': str(extra), 'device': info.st_dev,
                                'inode': info.st_ino, 'children': [self.RUN_ID]})
        self.write_v2_scope(record)
        result = self.invoke('remove', str(self.root / self.RUN_ID))
        self.assertNotEqual(result.returncode, 0)

    def test_v2_rejects_duplicate_scoped_parents(self):
        record = self.v2_record()
        record['roots'].append(dict(record['roots'][0]))
        self.write_v2_scope(record)
        result = self.invoke('remove', str(self.root / self.RUN_ID))
        self.assertNotEqual(result.returncode, 0)

    def test_v2_parent_replacement_is_denied(self):
        child = self.root / self.RUN_ID
        child.mkdir(mode=0o700)
        (child / 'keep').write_text('keep')
        self.write_v2_scope()
        moved = self.base / 'owned-v2-old'
        os.rename(self.root, moved)
        self.root.mkdir(mode=0o700)
        result = self.invoke('remove', str(self.root / self.RUN_ID))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((moved / self.RUN_ID / 'keep').read_text(), 'keep')

    def test_v2_rejects_noncanonical_target_path(self):
        child = self.root / self.RUN_ID
        child.mkdir(mode=0o700)
        self.write_v2_scope()
        result = self.invoke('remove', str(self.root) + '/./' + self.RUN_ID)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(child.exists())


class CapabilityOnlyV1Controls(OwnedHelperFixture):
    def test_empty_v1_scope_is_only_accepted_for_capability_probe(self):
        record = self.scope_record()
        record['roots'] = []
        record['supervisors'] = []
        self.write_scope(record)
        capability = self.invoke('signal', '--capabilities')
        self.assertEqual(capability.returncode, 0, capability.stderr)
        self.assertEqual(capability.stdout.strip(), 'pidfd-identity-v1')
        remove = self.invoke('remove', str(self.root / 'anything'))
        self.assertNotEqual(remove.returncode, 0)
        child = self.start_target()
        signal_result = self.invoke(*self.signal_args(child))
        self.assertNotEqual(signal_result.returncode, 0)
        self.assertIsNone(child.poll())

    def test_scope_json_must_be_utf8(self):
        record = self.scope_record()
        data = json.dumps(record, sort_keys=True, separators=(',', ':')).encode('utf-16')
        self.scope_path.write_bytes(data)
        self.scope_path.chmod(0o600)
        info = self.scope_path.stat()
        self.scope_identity = (info.st_dev, info.st_ino)
        self.scope_digest = hashlib.sha256(data).hexdigest()
        result = self.invoke('signal', '--capabilities')
        self.assertNotEqual(result.returncode, 0)

    def test_empty_v1_scope_cannot_be_loaded_as_general_authority(self):
        record = self.scope_record()
        record['roots'] = []
        record['supervisors'] = []
        self.write_scope(record)
        with self.assertRaises(ValueError):
            helper.load_scope(str(self.scope_path), *self.scope_identity,
                              self.scope_digest)


if __name__ == '__main__':
    unittest.main()
