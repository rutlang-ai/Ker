"""Model controls for the sealed PID-1 source-helper capsule adapter.

The positive producer/reader test patches the fixed-root constant to this test
process so it can exercise real memfd seals and /proc fd reopening. It is not
evidence for a private PID namespace, original shell, or source authority.
"""
import errno
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock


REPO = Path(__file__).resolve().parents[2]
SCOPE_PATH = REPO / 'tools/nginx_source_scope.py'
ORIGIN_PATH = REPO / 'tools/nginx_source_origin.py'
HELPER_PATH = REPO / 'tools/nginx-source-shell-helper.py'


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


scope_api = load_module('test_nginx_source_scope_impl', SCOPE_PATH)
origin = load_module('test_nginx_source_scope_origin', ORIGIN_PATH)
helper = load_module('test_nginx_source_scope_helper', HELPER_PATH)


class ScopeCapsuleControls(unittest.TestCase):
    def setUp(self):
        for descriptor in (scope_api.BOOTSTRAP_FD, scope_api.RUN_FD):
            try:
                fcntl.fcntl(descriptor, fcntl.F_GETFD)
            except OSError as error:
                self.assertEqual(error.errno, errno.EBADF)
            else:
                self.skipTest('fixed capsule fd slot is occupied in this test runner')
        self.tmp = tempfile.TemporaryDirectory(prefix='ker-source-scope-')
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.directory.chmod(0o700)

    def owner(self):
        # Explicitly model PID 1 in this process only to exercise fd mechanics.
        patcher = mock.patch.object(scope_api, 'ROOT_PID', os.getpid())
        patcher.start()
        self.addCleanup(patcher.stop)
        return scope_api.SourceScopeCapsules(origin)

    def test_real_memfd_bootstrap_round_trip_is_capability_only(self):
        publisher = self.owner()
        self.addCleanup(lambda: publisher.close() if not publisher.closed else None)
        path = self.directory / 'bootstrap.json'
        publisher.publish_bootstrap(path)
        self.assertTrue(publisher.bootstrap_published)
        self.assertFalse(publisher.run_published)
        capsule = scope_api.read_capsule(scope_api.BOOTSTRAP_FD,
            scope_api.BOOTSTRAP_ROLE, deadline_ns=time.monotonic_ns() + 1_000_000_000)
        self.addCleanup(lambda: capsule.close() if not capsule.closed else None)
        self.assertEqual(capsule.descriptor['schema'], scope_api.SCHEMA)
        self.assertEqual(capsule.descriptor['run_id'], '')
        self.assertEqual(capsule.scope['version'], 1)
        self.assertEqual(capsule.scope['roots'], ())
        self.assertEqual(capsule.scope['supervisors'], ())
        with self.assertRaises(TypeError):
            capsule.scope['roots'] = ('/tmp',)
        with self.assertRaises(TypeError):
            capsule.descriptor['run_id'] = 'gr_20261113_161115_1234_0123abcd'
        capsule.verify_live()

    def test_descriptor_rejects_extra_missing_and_boolean_identity(self):
        with mock.patch.object(scope_api, 'ROOT_PID', os.getpid()):
            root, root_fd = scope_api._root_record()
        os.close(root_fd)
        base = {'schema': scope_api.SCHEMA, 'role': scope_api.BOOTSTRAP_ROLE,
            'scope_path': '/tmp/scope.json', 'scope_device': 1, 'scope_inode': 2,
            'scope_sha256': 'a' * 64, 'run_id': '', **root}
        bad_values = []
        missing = dict(base); del missing['mount_namespace']; bad_values.append(missing)
        extra = dict(base, surprise=1); bad_values.append(extra)
        boolean = dict(base, root_start_time=True); bad_values.append(boolean)
        role = dict(base, role=scope_api.RUN_ROLE); bad_values.append(role)
        for value in bad_values:
            with self.subTest(value=value):
                with self.assertRaises((ValueError, PermissionError)):
                    scope_api._validate_descriptor(value, scope_api.BOOTSTRAP_ROLE,
                        root, '')

    def test_run_descriptor_requires_exact_authenticated_run_id(self):
        with mock.patch.object(scope_api, 'ROOT_PID', os.getpid()):
            root, root_fd = scope_api._root_record()
            os.close(root_fd)
            run_id = 'gr_20261113_161115_1234_0123abcd'
            descriptor = {'schema': scope_api.SCHEMA, 'role': scope_api.RUN_ROLE,
                'scope_path': '/run/private/run.json', 'scope_device': 1,
                'scope_inode': 2, 'scope_sha256': 'b' * 64, 'run_id': run_id, **root}
            scope_api._validate_descriptor(descriptor, scope_api.RUN_ROLE, root, run_id)
            for wrong in ('', run_id + 'x', 'gr_20261113_161115_0_0123abcd',
                          'gr_20261113_161115_1234_0123ABCD'):
                with self.subTest(run_id=wrong):
                    bad = dict(descriptor, run_id=wrong)
                    with self.assertRaises((ValueError, PermissionError)):
                        scope_api._validate_descriptor(bad, scope_api.RUN_ROLE, root, run_id)

    def test_run_scope_rejects_sibling_and_foreign_cleanup_children(self):
        run_id = 'gr_20261113_161115_1234_0123abcd'
        with mock.patch.object(scope_api, 'ROOT_PID', os.getpid()):
            root, root_fd = scope_api._root_record()
            os.close(root_fd)
            run_scope = {'version': 2, 'uid': root['uid'],
                'pid_namespace': root['pid_namespace'], 'run_id': run_id,
                'roots': [
                    {'path': '/tmp', 'device': 1, 'inode': 2, 'children': [run_id]},
                    {'path': '/var/run/dpdk', 'device': 3, 'inode': 4,
                        'children': ['container-' + run_id]}],
                'supervisors': [{'pid': root['root_pid'],
                'start_time': root['root_start_time'], 'exe': root['root_exe'],
                'device': root['root_exe_device'], 'inode': root['root_exe_inode']}]}
            scope_api._validate_run_scope(run_scope, root, run_id)
            bad = json.loads(json.dumps(run_scope))
            bad['roots'][0]['children'] = [run_id + 'sibling']
            with self.assertRaises(PermissionError):
                scope_api._validate_run_scope(bad, root, run_id)
            bad = json.loads(json.dumps(run_scope))
            bad['roots'][1]['children'] = ['container-' + run_id + 'extra']
            with self.assertRaises(PermissionError):
                scope_api._validate_run_scope(bad, root, run_id)

    def test_role_and_fixed_slot_must_match(self):
        with self.assertRaises(ValueError):
            scope_api.read_capsule(scope_api.BOOTSTRAP_FD, scope_api.RUN_ROLE,
                deadline_ns=time.monotonic_ns() + 100_000_000,
                expected_run_id='gr_20261113_161115_1234_0123abcd')
        with self.assertRaises(ValueError):
            scope_api.read_capsule(202, scope_api.BOOTSTRAP_ROLE,
                deadline_ns=time.monotonic_ns() + 100_000_000)

    def test_expired_descriptor_wait_fails_without_changing_slots(self):
        with self.assertRaises(TimeoutError):
            scope_api.read_capsule(scope_api.RUN_FD, scope_api.RUN_ROLE,
                deadline_ns=time.monotonic_ns() - 1,
                expected_run_id='gr_20261113_161115_1234_0123abcd')
        with self.assertRaises(OSError) as raised:
            fcntl.fcntl(scope_api.RUN_FD, fcntl.F_GETFD)
        self.assertEqual(raised.exception.errno, errno.EBADF)

    def test_missing_final_run_capsule_wait_is_absolute_and_bounded(self):
        start = time.monotonic_ns()
        with mock.patch.object(scope_api, 'ROOT_PID', os.getpid()):
            with self.assertRaises(TimeoutError):
                scope_api.read_capsule(scope_api.RUN_FD, scope_api.RUN_ROLE,
                    deadline_ns=start + 30_000_000,
                    expected_run_id='gr_20261113_161115_1234_0123abcd')
        self.assertLess(time.monotonic_ns() - start, 250_000_000)
        with self.assertRaises(OSError) as raised:
            fcntl.fcntl(scope_api.RUN_FD, fcntl.F_GETFD)
        self.assertEqual(raised.exception.errno, errno.EBADF)

    def test_unsealed_memfd_is_rejected_and_reader_closes_its_duplicate(self):
        with mock.patch.object(scope_api, 'ROOT_PID', os.getpid()):
            root, root_pidfd = scope_api._root_record()
            os.close(root_pidfd)
            value = {'schema': scope_api.SCHEMA, 'role': scope_api.BOOTSTRAP_ROLE,
                'scope_path': '/tmp/scope.json', 'scope_device': 1, 'scope_inode': 2,
                'scope_sha256': 'a' * 64, 'run_id': '', **root}
            raw = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
            fd = os.memfd_create('unsealed-capsule', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            try:
                os.write(fd, raw)
                self.assertEqual(fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC,
                    scope_api.BOOTSTRAP_FD), scope_api.BOOTSTRAP_FD)
                with self.assertRaises(PermissionError):
                    scope_api.read_capsule(scope_api.BOOTSTRAP_FD,
                        scope_api.BOOTSTRAP_ROLE,
                        deadline_ns=time.monotonic_ns() + 1_000_000_000)
            finally:
                os.close(scope_api.BOOTSTRAP_FD)
                os.close(fd)

    def test_occupied_slot_is_never_replaced(self):
        before = len(os.listdir('/proc/self/fd'))
        occupied = os.open('/dev/null', os.O_RDONLY | os.O_CLOEXEC)
        try:
            if occupied != scope_api.BOOTSTRAP_FD:
                os.dup2(occupied, scope_api.BOOTSTRAP_FD, inheritable=False)
            publisher = None
            with mock.patch.object(scope_api, 'ROOT_PID', os.getpid()):
                with self.assertRaises(FileExistsError):
                    publisher = scope_api.SourceScopeCapsules(origin)
            self.assertIsNone(publisher)
            self.assertTrue(os.fstat(scope_api.BOOTSTRAP_FD))
        finally:
            if occupied != scope_api.BOOTSTRAP_FD:
                os.close(scope_api.BOOTSTRAP_FD)
            os.close(occupied)
        self.assertEqual(len(os.listdir('/proc/self/fd')), before)

    def test_run_publication_rejects_untyped_launch_without_fd201(self):
        publisher = self.owner()
        self.addCleanup(lambda: publisher.close() if not publisher.closed else None)
        publisher.publish_bootstrap(self.directory / 'bootstrap.json')
        with self.assertRaises(PermissionError):
            publisher.publish_run(object(), ())
        with self.assertRaises(OSError) as raised:
            fcntl.fcntl(scope_api.RUN_FD, fcntl.F_GETFD)
        self.assertEqual(raised.exception.errno, errno.EBADF)

    def test_private_scope_file_uses_exclusive_nofollow_creation(self):
        path = self.directory / 'bootstrap.json'
        path.symlink_to(self.directory / 'target')
        with self.assertRaises(FileExistsError):
            scope_api._write_scope_file(path, {'version': 1})
        self.assertTrue(path.is_symlink())

    def test_scope_file_write_failure_unlinks_only_created_inode(self):
        path = self.directory / 'failed.json'
        before = set(os.listdir('/proc/self/fd'))
        with mock.patch.object(scope_api.os, 'write', side_effect=OSError(errno.EIO, 'injected')):
            with self.assertRaises(OSError):
                scope_api._write_scope_file(path, {'version': 1})
        self.assertFalse(path.exists())
        self.assertEqual(set(os.listdir('/proc/self/fd')), before)

    def test_memfd_allocated_at_reserved_slot_is_moved_and_owned(self):
        fd_baseline = len(os.listdir('/proc/self/fd'))
        publisher = self.owner()
        self.addCleanup(lambda: publisher.close() if not publisher.closed else None)
        path = self.directory / 'bootstrap-at-slot.json'
        real_create = os.memfd_create

        def create_at_slot(name, flags):
            temporary = real_create(name, flags)
            os.dup2(temporary, scope_api.BOOTSTRAP_FD, inheritable=False)
            os.close(temporary)
            return scope_api.BOOTSTRAP_FD

        with mock.patch.object(scope_api.os, 'memfd_create', side_effect=create_at_slot):
            publisher.publish_bootstrap(path)
        self.assertEqual(publisher.slot_identities[scope_api.BOOTSTRAP_FD],
            (os.fstat(scope_api.BOOTSTRAP_FD).st_dev,
             os.fstat(scope_api.BOOTSTRAP_FD).st_ino,
             os.fstat(scope_api.BOOTSTRAP_FD).st_size))
        capsule = scope_api.read_capsule(scope_api.BOOTSTRAP_FD,
            scope_api.BOOTSTRAP_ROLE,
            deadline_ns=time.monotonic_ns() + 1_000_000_000)
        self.addCleanup(lambda: capsule.close() if not capsule.closed else None)
        self.assertTrue(capsule.verify_live())
        capsule.close()
        publisher.close()
        self.assertEqual(len(os.listdir('/proc/self/fd')), fd_baseline)

    def test_descriptor_duplication_exhaustion_closes_temp_and_rolls_back_file(self):
        publisher = self.owner()
        self.addCleanup(lambda: publisher.close() if not publisher.closed else None)
        path = self.directory / 'exhausted.json'
        real_fcntl = scope_api.fcntl.fcntl
        duplicate_calls = 0

        def exhausted(fd, command, *args):
            nonlocal duplicate_calls
            if command == fcntl.F_DUPFD_CLOEXEC:
                duplicate_calls += 1
                if duplicate_calls == 2:
                    raise OSError(errno.EMFILE, 'injected fd exhaustion')
            return real_fcntl(fd, command, *args)

        before = len(os.listdir('/proc/self/fd'))
        real_create = os.memfd_create

        def create_at_slot(name, flags):
            temporary = real_create(name, flags)
            os.dup2(temporary, scope_api.BOOTSTRAP_FD, inheritable=False)
            os.close(temporary)
            return scope_api.BOOTSTRAP_FD

        with mock.patch.object(scope_api.os, 'memfd_create', side_effect=create_at_slot), \
                mock.patch.object(scope_api.fcntl, 'fcntl', side_effect=exhausted):
            with self.assertRaises(OSError) as raised:
                publisher.publish_bootstrap(path)
        self.assertEqual(raised.exception.errno, errno.EMFILE)
        self.assertFalse(path.exists())
        self.assertEqual(len(os.listdir('/proc/self/fd')), before)
        for slot in (scope_api.BOOTSTRAP_FD, scope_api.RUN_FD):
            with self.assertRaises(OSError) as slot_error:
                fcntl.fcntl(slot, fcntl.F_GETFD)
            self.assertEqual(slot_error.exception.errno, errno.EBADF)

    def test_future_tmp_child_is_exactly_derived_from_run_id(self):
        run_id = 'gr_20261113_161115_1234_0123abcd'
        self.assertEqual(scope_api.CapturedScopeRoot._children_for('/tmp', [], run_id),
            [run_id])
        self.assertEqual(scope_api.CapturedScopeRoot._children_for('/tmp',
            ['foreign-child'], run_id), [run_id])

    def test_run_capsule_close_requires_same_launch_and_fresh_settlement(self):
        publisher = self.owner()
        launch = object.__new__(origin.OriginalShellLaunch)
        wrong_launch = object.__new__(origin.OriginalShellLaunch)

        class Exited:
            returncode = 0
            def poll(self):
                return 0

        launch.process = Exited()
        launch.settlement = None
        publisher.run_published = True
        publisher.run_launch = launch
        publisher._live = lambda: None
        called = []

        def observe(actual):
            called.append(actual)
            actual.settlement = {'settled': True, 'result': 0}
            return dict(actual.settlement)

        with mock.patch.object(origin.OriginalShellLaunch, 'observe_settlement', observe):
            with self.assertRaises(RuntimeError):
                publisher.close(wrong_launch)
            self.assertFalse(publisher.closed)
            publisher.close(launch)
        self.assertEqual(called, [launch])
        self.assertTrue(publisher.closed)

    def test_var_run_alias_scope_authorizes_real_argv_and_rejects_changed_link(self):
        run_id = 'gr_20261113_161115_1234_0123abcd'
        for link_text in ('/run', '../run'):
            with self.subTest(link_text=link_text), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                (root / 'var').mkdir()
                (root / 'run').mkdir()
                dpdk = root / 'run' / 'dpdk'
                child = dpdk / ('container-' + run_id)
                child.mkdir(parents=True)
                dpdk.chmod(0o700)
                (root / 'var' / 'run').symlink_to(link_text)
                root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                var_fd = os.open(root / 'var', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                target_fd = os.open(root / 'run', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                try:
                    link_info = os.stat('run', dir_fd=var_fd, follow_symlinks=False)
                    target_info = os.fstat(target_fd)
                    alias = {'path': '/var/run', 'target': link_text,
                        'normalized_target': '/run', 'device': link_info.st_dev,
                        'inode': link_info.st_ino, 'target_device': target_info.st_dev,
                        'target_inode': target_info.st_ino,
                        'target_mount_id': helper._mount_id(target_fd)}
                    dpdk_info = os.stat(dpdk)
                    root_entry = {'path': '/var/run/dpdk', 'device': dpdk_info.st_dev,
                        'inode': dpdk_info.st_ino, 'children': ['container-' + run_id],
                        'alias': alias}
                    scope = {'_capability_only': False, '_version': 2,
                        'uid': os.geteuid(), 'roots': [root_entry]}
                    open_directory = helper.open_directory

                    def rooted(path, *, var_run_alias=None):
                        return open_directory(path, var_run_alias=var_run_alias,
                            _root_fd=root_fd)

                    with mock.patch.object(helper, 'open_directory', side_effect=rooted):
                        parent, name = helper.scoped_parent(
                            '/var/run/dpdk/container-' + run_id + '/cleanup.log', scope)
                        try:
                            self.assertEqual(name, 'cleanup.log')
                            self.assertEqual((os.fstat(parent).st_dev, os.fstat(parent).st_ino),
                                (os.stat(child).st_dev, os.stat(child).st_ino))
                        finally:
                            os.close(parent)
                        with self.assertRaises(ValueError):
                            helper.scoped_parent('/var/run/dpdk/container-' + run_id +
                                '-sibling/cleanup.log', scope)
                    with mock.patch.object(scope_api, 'ROOT_PID', os.getpid()):
                        root_identity, root_pidfd = scope_api._root_record()
                    os.close(root_pidfd)
                    scope_api._validate_run_scope({'run_id': run_id,
                        'supervisors': [{'pid': root_identity['root_pid'],
                            'start_time': root_identity['root_start_time'],
                            'exe': root_identity['root_exe'],
                            'device': root_identity['root_exe_device'],
                            'inode': root_identity['root_exe_inode']}],
                        'roots': [{'path': '/tmp', 'device': 1, 'inode': 2,
                            'children': [run_id]}, root_entry]}, root_identity, run_id)
                    # A different allowed-looking link spelling is still a mutation.
                    (root / 'var' / 'run').unlink()
                    (root / 'var' / 'run').symlink_to('../run' if link_text == '/run' else '/run')
                    with self.assertRaises(ValueError):
                        helper.open_directory('/var/run/dpdk', var_run_alias=alias,
                            _root_fd=root_fd)
                    with self.assertRaises(PermissionError):
                        scope_api._validate_run_scope({'run_id': run_id,
                            'supervisors': [{'pid': 1, 'start_time': 1, 'exe': '/x',
                                'device': 1, 'inode': 1}], 'roots': [
                                {'path': '/tmp', 'device': 1, 'inode': 1,
                                    'children': [run_id]},
                                dict(root_entry, alias=dict(alias, target='/elsewhere'))]},
                            {'root_pid': 1, 'root_start_time': 1, 'root_exe': '/x',
                                'root_exe_device': 1, 'root_exe_inode': 1}, run_id)
                finally:
                    os.close(var_fd)
                    os.close(target_fd)
                    os.close(root_fd)

    def test_read_capsule_reopens_aliased_run_root_through_validated_alias(self):
        run_id = 'gr_20261113_161115_1234_0123abcd'
        with tempfile.TemporaryDirectory(prefix='ker-scope-reader-', dir='/dev/shm') as temp:
            model_root = Path(temp)
            model_root.chmod(0o700)
            (model_root / 'var').mkdir()
            (model_root / 'run').mkdir()
            dpdk = model_root / 'run' / 'dpdk'
            (dpdk / ('container-' + run_id)).mkdir(parents=True)
            dpdk.chmod(0o700)
            (model_root / 'var' / 'run').symlink_to('../run')
            tmp_root = model_root / 'private-tmp'
            tmp_root.mkdir(mode=0o700)
            root_fd = os.open(model_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            tmp_fd = os.open(tmp_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            var_fd = os.open(model_root / 'var', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            target_fd = os.open(model_root / 'run', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            memfd = -1
            scope_file = None
            capsule = None
            try:
                with mock.patch.object(scope_api, 'ROOT_PID', os.getpid()):
                    root, root_pidfd = scope_api._root_record()
                os.close(root_pidfd)
                link = os.stat('run', dir_fd=var_fd, follow_symlinks=False)
                target = os.fstat(target_fd)
                alias = {'path': '/var/run', 'target': '../run',
                    'normalized_target': '/run', 'device': link.st_dev,
                    'inode': link.st_ino, 'target_device': target.st_dev,
                    'target_inode': target.st_ino,
                    'target_mount_id': helper._mount_id(target_fd)}
                dpdk_info = os.stat(dpdk)
                tmp_info = os.fstat(tmp_fd)
                scope = {'version': 2, 'uid': root['uid'],
                    'pid_namespace': root['pid_namespace'], 'run_id': run_id,
                    'roots': [
                        {'path': '/tmp', 'device': tmp_info.st_dev,
                            'inode': tmp_info.st_ino, 'children': [run_id]},
                        {'path': '/var/run/dpdk', 'device': dpdk_info.st_dev,
                            'inode': dpdk_info.st_ino, 'children': ['container-' + run_id],
                            'alias': alias}],
                    'supervisors': [{'pid': root['root_pid'],
                        'start_time': root['root_start_time'], 'exe': root['root_exe'],
                        'device': root['root_exe_device'], 'inode': root['root_exe_inode']}]}
                scope_file = scope_api._write_scope_file(
                    model_root / 'run-scope.json', scope)
                descriptor = scope_api.SourceScopeCapsules._descriptor(
                    scope_api.RUN_ROLE, scope_file, run_id, root)
                raw = (json.dumps(descriptor, sort_keys=True,
                    separators=(',', ':')) + '\n').encode('utf-8')
                memfd = os.memfd_create('read-capsule-run',
                    os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
                os.write(memfd, raw)
                seals = (fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
                    fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
                fcntl.fcntl(memfd, fcntl.F_ADD_SEALS, seals)
                os.dup2(memfd, scope_api.RUN_FD, inheritable=False)
                original_open = scope_api._open_directory_nofollow

                def mapped_open(path, *, var_run_alias=None):
                    if str(path) == '/tmp':
                        return os.dup(tmp_fd)
                    if str(path) == '/var/run/dpdk':
                        return helper.open_directory(path,
                            var_run_alias=var_run_alias, _root_fd=root_fd)
                    return original_open(path, var_run_alias=var_run_alias)

                with mock.patch.object(scope_api, 'ROOT_PID', os.getpid()), \
                        mock.patch.object(scope_api, '_open_directory_nofollow',
                            side_effect=mapped_open):
                    capsule = scope_api.read_capsule(scope_api.RUN_FD,
                        scope_api.RUN_ROLE,
                        deadline_ns=time.monotonic_ns() + 1_000_000_000,
                        expected_run_id=run_id)
                    self.assertEqual(capsule.scope['roots'][1]['alias']['target'], '../run')
                    self.assertTrue(capsule.verify_live())
            finally:
                if capsule is not None and not capsule.closed:
                    capsule.close()
                try:
                    os.close(scope_api.RUN_FD)
                except OSError:
                    pass
                if memfd >= 0:
                    os.close(memfd)
                if scope_file is not None and not scope_file.closed:
                    scope_file.close(unlink=True)
                for descriptor in (var_fd, target_fd, tmp_fd, root_fd):
                    os.close(descriptor)

    def test_host_var_run_alias_observation_is_read_only_and_bounded(self):
        alias = scope_api._capture_var_run_alias()
        if alias is None:
            self.skipTest('/var/run is a real directory in this environment')
        self.assertEqual(alias['path'], '/var/run')
        self.assertIn(alias['target'], ('/run', '../run'))
        self.assertEqual(alias['normalized_target'], '/run')
        self.assertGreater(alias['target_inode'], 0)

    def test_capsule_constructor_cannot_be_called_without_reader_token(self):
        with self.assertRaises(TypeError):
            scope_api.ScopeCapsule(object(), scope_api.BOOTSTRAP_ROLE, '', {}, {}, -1, -1, {})


if __name__ == '__main__':
    unittest.main()
