"""Typed, fail-closed PID-1 scope capsules for the original shell helpers.

This module only publishes and consumes the reviewed FD 200/201 descriptor
format.  It does not launch helpers, SSH, Nginx, or the native backend.
"""
import errno
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import threading
import time
from types import MappingProxyType

ROOT_PID = 1
BOOTSTRAP_FD = 200
RUN_FD = 201
MAX_DESCRIPTOR = 16384
MAX_SCOPE = 16384
SCHEMA = 'ker-source-helper-scope-descriptor-v1'
BOOTSTRAP_ROLE = 'bootstrap-capabilities'
RUN_ROLE = 'run-cleanup'
RUN_ID_RE = re.compile(r'gr_[0-9]{8}_[0-9]{6}_[1-9][0-9]*_[0-9a-f]{8}')
DESCRIPTOR_KEYS = frozenset((
    'schema', 'role', 'scope_path', 'scope_device', 'scope_inode', 'scope_sha256',
    'run_id', 'root_pid', 'root_start_time', 'root_exe', 'root_exe_device',
    'root_exe_inode', 'uid', 'pid_namespace', 'mount_namespace'))
_ROOT_TOKEN = object()
_ROOT_CAPTURE_TOKEN = object()
_CAPSULE_TOKEN = object()
_HELPER_SHA256 = '50aca8722f22c03930d3da3c950638db8be879f9250b26914f8445c7b460857b'
_HELPER_MODULE = None


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate scope descriptor key')
        value[key] = item
    return value


def _freeze(value):
    if type(value) is dict:
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if type(value) is list:
        return tuple(_freeze(item) for item in value)
    return value


def _proc_start_ticks(pid):
    raw = Path('/proc/%d/stat' % pid).read_bytes()
    fields = raw.rsplit(b')', 1)[1].split()
    if len(fields) < 20:
        raise ValueError('process start record is truncated')
    return int(fields[19])


def _root_record(*, require_self=False):
    if require_self and (os.getpid() != ROOT_PID or
            threading.current_thread() is not threading.main_thread()):
        raise PermissionError(errno.ENOTSUP, 'scope capsules require the SDK process to be PID 1')
    pidfd = os.pidfd_open(ROOT_PID, 0)
    try:
        proc = Path('/proc') / str(ROOT_PID)
        status = (proc / 'status').read_text(encoding='ascii')
        uid_line = next((line for line in status.splitlines() if line.startswith('Uid:')), None)
        if uid_line is None:
            raise ValueError('PID 1 UID record is missing')
        uid_fields = uid_line.split()
        if len(uid_fields) < 2:
            raise ValueError('PID 1 UID record is truncated')
        exe = os.readlink(proc / 'exe')
        image = os.stat(proc / 'exe')
        pidns = os.stat(proc / 'ns/pid')
        mntns = os.stat(proc / 'ns/mnt')
        record = {
            'root_pid': ROOT_PID,
            'root_start_time': _proc_start_ticks(ROOT_PID),
            'root_exe': exe,
            'root_exe_device': image.st_dev,
            'root_exe_inode': image.st_ino,
            'uid': int(uid_fields[1]),
            'pid_namespace': [pidns.st_dev, pidns.st_ino],
            'mount_namespace': [mntns.st_dev, mntns.st_ino],
        }
        if exe.endswith(' (deleted)') or record['root_start_time'] <= 0:
            raise ValueError('PID 1 executable or start identity is invalid')
        if _pidfd_exited(pidfd):
            raise ProcessLookupError('PID 1 exited during identity capture')
        return record, pidfd
    except BaseException:
        os.close(pidfd)
        raise


def _pidfd_exited(pidfd):
    import select
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL)
    return bool(poller.poll(0))


def _root_matches(expected, pidfd):
    if _pidfd_exited(pidfd):
        return False
    try:
        current, check_fd = _root_record()
    except (OSError, ValueError, StopIteration):
        return False
    try:
        return current == expected and not _pidfd_exited(check_fd)
    finally:
        os.close(check_fd)


def _helper_module():
    global _HELPER_MODULE
    path = Path(__file__).with_name('nginx-source-shell-helper.py').resolve(strict=True)
    helper_fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(helper_fd)
        named_before = os.stat(path, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or
                before.st_mode & 0o022 or before.st_nlink != 1 or
                (named_before.st_dev, named_before.st_ino) != (before.st_dev, before.st_ino)):
            raise PermissionError('scope helper is not a protected regular file')
        data = os.pread(helper_fd, before.st_size + 1, 0)
        after = os.fstat(helper_fd)
        named_after = os.stat(path, follow_symlinks=False)
        if (len(data) != before.st_size or not _stable_stat(before, after) or
                (named_after.st_dev, named_after.st_ino) != (after.st_dev, after.st_ino) or
                hashlib.sha256(data).hexdigest() != _HELPER_SHA256):
            raise PermissionError('scope helper source differs from its reviewed implementation')
    finally:
        os.close(helper_fd)
    if _HELPER_MODULE is None:
        spec = importlib.util.spec_from_file_location('_ker_nginx_source_shell_helper', path)
        if spec is None or spec.loader is None:
            raise ImportError('cannot load pinned source-shell helper validator')
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        try:
            spec.loader.exec_module(module)
        except BaseException:
            if sys.modules.get(spec.name) is module:
                del sys.modules[spec.name]
            raise
        _HELPER_MODULE = module
    elif Path(_HELPER_MODULE.__file__).resolve(strict=True) != path:
        raise ImportError('cached source-shell helper validator belongs to another path')
    return _HELPER_MODULE


def _free_slot(fd):
    try:
        fcntl.fcntl(fd, fcntl.F_GETFD)
    except OSError as error:
        if error.errno == errno.EBADF:
            return
        raise
    raise FileExistsError(errno.EEXIST, 'fixed source helper descriptor slot is occupied', fd)


def _private_parent(path):
    path = Path(path)
    if (not path.is_absolute() or str(path) != str(path.resolve(strict=True)) or
            '..' in path.parts or len(path.parts) > 64):
        raise ValueError('scope directory must be canonical absolute')
    fd = _open_directory_nofollow(path)
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or
            info.st_mode & 0o077):
        os.close(fd)
        raise PermissionError('scope directory must be owned and private')
    return fd, (info.st_dev, info.st_ino, _fd_mount_id(fd))


def _capture_var_run_alias():
    """Capture only the conventional /var/run -> /run alias, never a generic link."""
    parent = _open_directory_nofollow('/var')
    target_fd = -1
    try:
        link = os.stat('run', dir_fd=parent, follow_symlinks=False)
        if stat.S_ISDIR(link.st_mode):
            return None
        link_text = os.readlink('run', dir_fd=parent)
        if not stat.S_ISLNK(link.st_mode) or link_text not in ('/run', '../run'):
            raise PermissionError('unsupported /var/run alias')
        target_fd = _open_directory_nofollow('/run')
        target = os.fstat(target_fd)
        again = os.stat('run', dir_fd=parent, follow_symlinks=False)
        if ((link.st_dev, link.st_ino) != (again.st_dev, again.st_ino) or
                os.readlink('run', dir_fd=parent) != link_text):
            raise PermissionError('conventional /var/run alias changed during capture')
        return {'path': '/var/run', 'target': link_text, 'normalized_target': '/run',
            'device': link.st_dev, 'inode': link.st_ino,
            'target_device': target.st_dev, 'target_inode': target.st_ino,
            'target_mount_id': _fd_mount_id(target_fd)}
    finally:
        os.close(parent)
        if target_fd >= 0:
            os.close(target_fd)


def _open_directory_nofollow(path, *, var_run_alias=None):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts or len(path.parts) > 64:
        raise ValueError('directory path must be bounded and absolute')
    current = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for index, component in enumerate(path.parts[1:], 1):
            if str(path).startswith('/var/run') and index == 2 and component == 'run':
                var_fd = current
                link = os.stat('run', dir_fd=var_fd, follow_symlinks=False)
                if stat.S_ISLNK(link.st_mode):
                    if (var_run_alias is None or var_run_alias.get('path') != '/var/run' or
                            var_run_alias.get('target') not in ('/run', '../run') or
                            var_run_alias.get('normalized_target') != '/run' or
                            (link.st_dev, link.st_ino) !=
                                (var_run_alias.get('device'), var_run_alias.get('inode')) or
                            os.readlink('run', dir_fd=var_fd) != var_run_alias.get('target')):
                        raise PermissionError('unapproved or changed /var/run alias')
                    root_fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                    try:
                        following = os.open('run', os.O_RDONLY | os.O_DIRECTORY |
                            os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root_fd)
                    finally:
                        os.close(root_fd)
                    target = os.fstat(following)
                    again = os.stat('run', dir_fd=var_fd, follow_symlinks=False)
                    if ((target.st_dev, target.st_ino) !=
                            (var_run_alias.get('target_device'), var_run_alias.get('target_inode')) or
                            _fd_mount_id(following) != var_run_alias.get('target_mount_id') or
                            (again.st_dev, again.st_ino) != (link.st_dev, link.st_ino) or
                            os.readlink('run', dir_fd=var_fd) != var_run_alias.get('target')):
                        os.close(following)
                        raise PermissionError('conventional /var/run target changed')
                    os.close(current)
                    current = following
                    continue
                if var_run_alias is not None:
                    raise PermissionError('captured /var/run alias was replaced by a directory')
            following = os.open(component, os.O_RDONLY | os.O_DIRECTORY |
                os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=current)
            os.close(current)
            current = following
        return current
    except BaseException:
        os.close(current)
        raise


def _fd_mount_id(fd):
    with open('/proc/self/fdinfo/%d' % fd, 'rt', encoding='ascii') as stream:
        values = [line.split(':', 1)[1].strip() for line in stream
            if line.startswith('mnt_id:')]
    if len(values) != 1 or not values[0].isdigit():
        raise ValueError('directory descriptor has no unique mount identity')
    return int(values[0])


def _write_scope_file(path, record):
    path = Path(path)
    if (path.is_relative_to(Path(__file__).parent) or
            any(path.is_relative_to(Path(root)) for root in ('/proc', '/sys', '/dev/fd'))):
        raise ValueError('scope metadata must remain outside protected code and virtual filesystems')
    parent_fd, parent_identity = _private_parent(path.parent)
    fd = -1
    created_identity = None
    try:
        fd = os.open(path.name, os.O_RDWR | os.O_CREAT | os.O_EXCL |
            os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=parent_fd)
        # Record ownership before any operation that can fail.  Rollback may
        # unlink only this exact inode, including a write or fsync failure.
        created = os.fstat(fd)
        created_identity = (created.st_dev, created.st_ino)
        data = (json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n').encode('utf-8')
        if not 0 < len(data) <= MAX_SCOPE:
            raise ValueError('scope record exceeds its byte bound')
        view = memoryview(data)
        offset = 0
        while offset < len(view):
            written = os.write(fd, view[offset:])
            if written <= 0:
                raise OSError(errno.EIO, 'short scope file write')
            offset += written
        os.fsync(fd)
        info = os.fstat(fd)
        named = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                info.st_nlink != 1 or info.st_mode & 0o077 or
                (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino) or
                (os.fstat(parent_fd).st_dev, os.fstat(parent_fd).st_ino,
                    _fd_mount_id(parent_fd)) != parent_identity):
            raise PermissionError('new scope file identity or mode is invalid')
        return ScopeFile(_ROOT_TOKEN, path, fd, info, data, parent_fd, parent_identity)
    except BaseException:
        # Remove only the file this call created, and only while its inode still matches.
        try:
            named = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
            if created_identity is not None and (named.st_dev, named.st_ino) == created_identity:
                os.unlink(path.name, dir_fd=parent_fd)
        except (OSError, ValueError):
            pass
        if fd >= 0:
            os.close(fd)
        os.close(parent_fd)
        raise


class ScopeFile:
    __slots__ = ('path', 'fd', 'device', 'inode', 'sha256', 'data', 'parent_fd',
        'parent_identity', 'closed')

    def __init__(self, token, path, fd, info, data, parent_fd, parent_identity):
        if token is not _ROOT_TOKEN:
            raise TypeError('scope files are created by the scope publisher')
        self.path = str(path)
        self.fd = fd
        self.device, self.inode = info.st_dev, info.st_ino
        self.sha256 = hashlib.sha256(data).hexdigest()
        self.data = bytes(data)
        self.parent_fd = parent_fd
        self.parent_identity = parent_identity
        self.closed = False

    def __setattr__(self, name, value):
        if not hasattr(self, name) or name in ('fd', 'parent_fd', 'closed'):
            if name == 'closed' and hasattr(self, name) and (self.closed or value is not True):
                raise AttributeError('scope file closed state is one-way')
            if name in ('fd', 'parent_fd') and hasattr(self, name) and value != -1:
                raise AttributeError('scope file descriptors cannot be replaced')
            object.__setattr__(self, name, value)
            return
        raise AttributeError('captured scope file identity is immutable')

    def verify(self):
        if self.closed or self.fd < 0:
            raise ValueError('scope file is closed')
        info = os.fstat(self.fd)
        named = os.stat(Path(self.path).name, dir_fd=self.parent_fd, follow_symlinks=False)
        parent = os.fstat(self.parent_fd)
        data = os.pread(self.fd, MAX_SCOPE + 1, 0)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                info.st_nlink != 1 or info.st_mode & 0o077 or len(data) != len(self.data) or
                hashlib.sha256(data).hexdigest() != self.sha256 or
                (info.st_dev, info.st_ino) != (self.device, self.inode) or
                (named.st_dev, named.st_ino) != (self.device, self.inode) or
                (parent.st_dev, parent.st_ino, _fd_mount_id(self.parent_fd)) != self.parent_identity):
            raise PermissionError('captured scope file changed')
        return data

    def close(self, *, unlink=False):
        if self.closed:
            return
        self.verify()
        if unlink:
            os.unlink(Path(self.path).name, dir_fd=self.parent_fd)
        os.close(self.fd)
        os.close(self.parent_fd)
        self.fd = self.parent_fd = -1
        self.closed = True


class CapturedScopeRoot:
    """Held exact parent-directory observation; no arbitrary JSON roots."""
    __slots__ = ('path', 'device', 'inode', 'uid', 'mode', 'mount_id', 'fd',
        'children', 'run_id', 'alias', 'closed')
    ALLOWED_PATHS = frozenset(('/tmp', '/var/run/dpdk', '/dev/hugepages'))

    @staticmethod
    def _children_for(path, names, run_id):
        if path == '/tmp':
            return [run_id]
        if path == '/var/run/dpdk':
            name = 'container-' + run_id
            return [name] if name in names else []
        prefix = 'container-' + run_id + 'map_'
        return sorted(name for name in names if name.startswith(prefix) and
            name[len(prefix):].isascii() and name[len(prefix):].isdecimal())

    def __init__(self, token, path, fd, info, children, run_id, alias=None):
        if token is not _ROOT_CAPTURE_TOKEN:
            raise TypeError('scope roots must be captured from an allowed live directory')
        self.path = str(path)
        self.device, self.inode = info.st_dev, info.st_ino
        self.uid, self.mode = info.st_uid, stat.S_IMODE(info.st_mode)
        self.mount_id = _fd_mount_id(fd)
        self.fd = fd
        self.children = tuple(children)
        self.run_id = run_id
        self.alias = None if alias is None else MappingProxyType(dict(alias))
        self.closed = False

    def __setattr__(self, name, value):
        if not hasattr(self, name) or name in ('fd', 'closed'):
            if name == 'closed' and hasattr(self, name) and (self.closed or value is not True):
                raise AttributeError('captured scope root closed state is one-way')
            if name == 'fd' and hasattr(self, name) and value != -1:
                raise AttributeError('captured scope root descriptor cannot be replaced')
            object.__setattr__(self, name, value)
            return
        raise AttributeError('captured scope root identity is immutable')

    @classmethod
    def capture(cls, path, run_id):
        if type(run_id) is not str or RUN_ID_RE.fullmatch(run_id) is None:
            raise ValueError('scope root capture requires the observed run id')
        path = Path(path)
        if str(path) not in cls.ALLOWED_PATHS:
            raise ValueError('scope root path is outside the fixed helper policy')
        if str(path) != str(path.resolve(strict=True)) and str(path) != '/var/run/dpdk':
            raise ValueError('scope root path is not canonical')
        alias = _capture_var_run_alias() if str(path) == '/var/run/dpdk' else None
        fd = _open_directory_nofollow(path, var_run_alias=alias)
        try:
            info = os.fstat(fd)
            if (info.st_uid != os.geteuid() or info.st_mode & 0o077 or
                    stat.S_IMODE(info.st_mode) != 0o700):
                raise PermissionError('scope parent is not an owned private directory')
            names = os.listdir(fd)
            # The original shell may create /tmp/<run_id> after the supervisor
            # has been authenticated. Publication later binds this exact name.
            wanted = cls._children_for(str(path), names, run_id)
            if not wanted or len(wanted) > 128 or len(wanted) != len(set(wanted)):
                raise ValueError('scope root has no bounded exact run children')
            # The downstream helper validates each child against the same closed name grammar.
            if str(path) == '/dev/hugepages' and any(
                    name != 'container-' + run_id + 'map_' + name.rsplit('_', 1)[-1]
                    for name in wanted):
                raise ValueError('hugepage child name is malformed')
            again = os.fstat(fd)
            if (again.st_dev, again.st_ino, again.st_uid, again.st_mode) != (
                    info.st_dev, info.st_ino, info.st_uid, info.st_mode):
                raise PermissionError('scope parent changed during capture')
            return cls(_ROOT_CAPTURE_TOKEN, path, fd, info, wanted, run_id, alias)
        except BaseException:
            os.close(fd)
            raise

    def record(self):
        if self.closed or self.fd < 0:
            raise ValueError('captured scope parent is closed')
        info = os.fstat(self.fd)
        named = os.stat(self.path, follow_symlinks=True)
        if ((info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode)) !=
                (self.device, self.inode, self.uid, self.mode) or
                (named.st_dev, named.st_ino) != (self.device, self.inode)):
            raise PermissionError('captured scope parent identity changed')
        alias = _capture_var_run_alias() if self.path == '/var/run/dpdk' else None
        if alias != (None if self.alias is None else dict(self.alias)):
            raise PermissionError('captured /var/run alias identity changed')
        fd = _open_directory_nofollow(self.path, var_run_alias=alias)
        try:
            if _fd_mount_id(fd) != self.mount_id:
                raise PermissionError('captured scope parent mount identity changed')
        finally:
            os.close(fd)
        result = {'path': self.path, 'device': self.device, 'inode': self.inode,
            'children': list(self.children)}
        if self.alias is not None:
            result['alias'] = dict(self.alias)
        return result

    def close(self):
        if not self.closed:
            self.record()
            os.close(self.fd)
            self.fd = -1
            self.closed = True


class ScopeCapsule:
    __slots__ = ('role', 'run_id', 'descriptor', 'scope', '_scope', 'fd', 'pidfd',
        'root', 'fd_identity', 'closed')

    def __init__(self, token, role, run_id, descriptor, scope, fd, pidfd, root):
        if token is not _CAPSULE_TOKEN:
            raise TypeError('scope capsules are created only by the sealed descriptor reader')
        self.role, self.run_id = role, run_id
        self.descriptor = _freeze(dict(descriptor))
        self._scope = scope
        self.scope = _freeze({key: value for key, value in scope.items()
            if not key.startswith('_')})
        self.fd, self.pidfd, self.root = fd, pidfd, dict(root)
        info = os.fstat(fd)
        self.fd_identity = info.st_dev, info.st_ino, info.st_size
        self.closed = False

    def __setattr__(self, name, value):
        if not hasattr(self, name) or name == 'closed':
            if name == 'closed' and hasattr(self, name) and (self.closed or value is not True):
                raise AttributeError('scope capsule closed state is one-way')
            object.__setattr__(self, name, value)
            return
        raise AttributeError('sealed scope capsule identity is immutable')

    def verify_live(self):
        if self.closed or not _root_matches(self.root, self.pidfd):
            raise ProcessLookupError('captured PID 1 capsule owner is no longer live')
        seals = (fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
                 fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        info = os.fstat(self.fd)
        if ((info.st_dev, info.st_ino, info.st_size) != self.fd_identity or
                fcntl.fcntl(self.fd, fcntl.F_GET_SEALS) != seals):
            raise PermissionError('scope capsule seals changed')
        helper = _helper_module()
        helper.verify_scope(self._scope)
        return True

    def close(self):
        if self.closed:
            return
        helper = _helper_module()
        helper.verify_scope(self._scope)
        for fd in (self._scope.get('_fd', -1), self._scope.get('_parent', -1),
                self.fd, self.pidfd):
            if type(fd) is int and fd >= 0:
                os.close(fd)
        self.closed = True


class SourceScopeCapsules:
    """PID-1 owner of the fixed, non-overwritable scope capsule slots."""
    def __init__(self, origin_module):
        if (not hasattr(origin_module, 'OriginalShellLaunch') or
                Path(getattr(origin_module, '__file__', '')).resolve(strict=True) !=
                    Path(__file__).with_name('nginx_source_origin.py').resolve(strict=True)):
            raise TypeError('scope publisher requires the canonical source-origin module')
        self.origin_module = origin_module
        self.root, self.pidfd = _root_record(require_self=True)
        try:
            _free_slot(BOOTSTRAP_FD)
            _free_slot(RUN_FD)
        except BaseException:
            os.close(self.pidfd)
            self.pidfd = -1
            raise
        self.bootstrap_file = None
        self.run_file = None
        self.slot_identities = {}
        self.captured_roots = ()
        self.run_launch = None
        self.bootstrap_published = False
        self.run_published = False
        self.closed = False

    def _live(self):
        if self.closed or not _root_matches(self.root, self.pidfd):
            raise ProcessLookupError('scope publisher PID 1 identity changed')
        for root in self.captured_roots:
            root.record()

    @staticmethod
    def _descriptor(role, scope_file, run_id, root):
        return {'schema': SCHEMA, 'role': role, 'scope_path': scope_file.path,
            'scope_device': scope_file.device, 'scope_inode': scope_file.inode,
            'scope_sha256': scope_file.sha256, 'run_id': run_id, **root}

    def _publish(self, slot, role, scope_file, run_id):
        self._live()
        _free_slot(slot)
        descriptor = self._descriptor(role, scope_file, run_id, self.root)
        raw = (json.dumps(descriptor, sort_keys=True, separators=(',', ':')) + '\n').encode('utf-8')
        if not 0 < len(raw) <= MAX_DESCRIPTOR:
            raise ValueError('scope descriptor exceeds its byte bound')
        fd = os.memfd_create('ker-source-scope', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        # A process with unusually high descriptor use can allocate a memfd at
        # 200/201. Move that owned temporary descriptor above both reserved
        # slots before any publication attempt; never leak it as an untracked
        # fixed-slot capsule.
        if fd in (BOOTSTRAP_FD, RUN_FD):
            try:
                moved = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, RUN_FD + 1)
            except BaseException:
                os.close(fd)
                raise
            os.close(fd)
            fd = moved
        try:
            view = memoryview(raw)
            offset = 0
            while offset < len(view):
                count = os.write(fd, view[offset:])
                if count <= 0:
                    raise OSError(errno.EIO, 'short scope descriptor write')
                offset += count
            seals = (fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
                     fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 0 or
                    info.st_uid != self.root['uid'] or info.st_size != len(raw) or
                    fcntl.fcntl(fd, fcntl.F_GET_SEALS) != seals):
                raise PermissionError('new scope capsule is not an exact sealed memfd')
            self._live()
            # F_DUPFD_CLOEXEC returns the requested slot only if still free;
            # unlike dup2, it cannot replace a concurrently occupied slot.
            duplicate = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, slot)
            if duplicate != slot:
                os.close(duplicate)
                raise FileExistsError(errno.EEXIST,
                    'fixed source helper descriptor slot was concurrently occupied', slot)
            published = os.fstat(slot)
            self.slot_identities[slot] = (published.st_dev, published.st_ino, published.st_size)
            return descriptor
        finally:
            if fd != slot:
                os.close(fd)

    def publish_bootstrap(self, scope_path):
        self._live()
        if self.bootstrap_published or self.run_published:
            raise RuntimeError('bootstrap scope capsule may be published only once, before run scope')
        record = {'version': 1, 'uid': self.root['uid'],
            'pid_namespace': list(self.root['pid_namespace']), 'roots': [], 'supervisors': []}
        scope_file = _write_scope_file(scope_path, record)
        try:
            self._publish(BOOTSTRAP_FD, BOOTSTRAP_ROLE, scope_file, '')
        except BaseException:
            scope_file.close(unlink=True)
            raise
        self.bootstrap_file = scope_file
        self.bootstrap_published = True

    def publish_run(self, launch, captured_roots):
        self._live()
        if not self.bootstrap_published or self.run_published:
            raise RuntimeError('run scope requires one bootstrap capsule and an unused FD 201')
        # Bind to the same canonical Origin class and captured live launch.  The
        # caller cannot supply run_id or supervisor identity as data.
        private_launch = type(launch) is getattr(self.origin_module,
            'PrivateC34OriginalShellLaunch', None)
        serial_launch = type(launch) is getattr(self.origin_module,
            'OriginalSerialShellLaunch', None)
        if (type(launch) is not self.origin_module.OriginalShellLaunch and
                not private_launch and not serial_launch or
                launch.creator_pid != ROOT_PID or launch.creator_start != self.root['root_start_time'] or
                not callable(getattr(launch, 'live_supervisor', None)) or
                type(captured_roots) is not tuple or not captured_roots or
                (not serial_launch and getattr(launch, 'native_io_ready', None) is None) or
                any(type(item) is not CapturedScopeRoot for item in captured_roots)):
            raise PermissionError('run scope requires the actual same-process original launch and held roots')
        if private_launch:
            import sys
            artifacts = sys.modules.get('_ker_nginx_source_c34_artifacts')
            capture = getattr(launch, 'c34_artifact_capture', None)
            if (artifacts is None or type(capture) is not
                    getattr(artifacts, 'PrivateC34ArtifactCapture', None) or
                    capture.profile_id != 'NEWC34_INTEROP'):
                raise PermissionError('private C34 scope requires its exact fixed capture')
            capture.verify(launch.deadline_ns)
        if time.monotonic_ns() >= launch.deadline_ns:
            raise TimeoutError('original launch observation deadline expired')
        launch.live_supervisor(launch.deadline_ns)
        if serial_launch:
            launch.live_initial_runtime()
        else:
            launch._native_io_ready_live(launch.native_io_ready.actor, launch.deadline_ns)
        if time.monotonic_ns() >= launch.deadline_ns:
            raise TimeoutError('original launch expired after identity validation')
        run_id = launch.run_id
        if type(run_id) is not str or RUN_ID_RE.fullmatch(run_id) is None:
            raise PermissionError('original supervisor did not authenticate an exact run id')
        if any(item.run_id != run_id for item in captured_roots):
            raise PermissionError('captured scope roots belong to another run id')
        if launch.process is None or launch.process.poll() is not None:
            raise ProcessLookupError('original supervisor exited before scope publication')
        roots = [item.record() for item in captured_roots]
        if time.monotonic_ns() >= launch.deadline_ns:
            raise TimeoutError('scope root capture exceeded original launch deadline')
        root_paths = [Path(entry['path']) for entry in roots]
        if (len(roots) > 8 or len(set(root_paths)) != len(roots) or
                any(Path(entry['path']).is_relative_to(Path(__file__).parent) for entry in roots)):
            raise ValueError('captured cleanup roots are duplicated, oversized, or include source code')
        if serial_launch:
            if root_paths != [Path('/tmp')]:
                raise ValueError('serial source scope only owns the original probe directory')
        elif not {'/tmp', '/var/run/dpdk'} <= {str(path) for path in root_paths}:
            raise ValueError('run scope requires captured original-shell and DPDK runtime parents')
        if any(left in right.parents or right in left.parents
                for index, left in enumerate(root_paths) for right in root_paths[index + 1:]):
            raise ValueError('nested cleanup roots are ambiguous')
        supervisors = [{'pid': ROOT_PID, 'start_time': self.root['root_start_time'],
            'exe': self.root['root_exe'], 'device': self.root['root_exe_device'],
            'inode': self.root['root_exe_inode']}]
        record = {'version': 2, 'uid': self.root['uid'],
            'pid_namespace': list(self.root['pid_namespace']), 'run_id': run_id,
            'roots': roots, 'supervisors': supervisors}
        if self.bootstrap_file is None:
            raise RuntimeError('bootstrap scope file is unavailable')
        scope_path = Path(self.bootstrap_file.path).parent / ('run-' + run_id + '.json')
        if any(scope_path.is_relative_to(Path(item.path)) for item in captured_roots):
            raise ValueError('scope metadata file cannot be inside a cleanup root')
        if any(Path(self.bootstrap_file.path).is_relative_to(Path(item.path))
                for item in captured_roots):
            raise ValueError('bootstrap metadata file cannot be inside a cleanup root')
        if time.monotonic_ns() >= launch.deadline_ns:
            raise TimeoutError('run scope preparation exceeded original launch deadline')
        # Keep the held roots under continuous publisher validation before the
        # final capsule becomes visible to wrappers.
        self.captured_roots = captured_roots
        scope_file = _write_scope_file(scope_path, record)
        try:
            if time.monotonic_ns() >= launch.deadline_ns:
                raise TimeoutError('run scope write exceeded original launch deadline')
            self._publish(RUN_FD, RUN_ROLE, scope_file, run_id)
        except BaseException:
            scope_file.close(unlink=True)
            raise
        self.run_file = scope_file
        self.run_launch = launch
        self.run_published = True
        self._live()
        launch.live_supervisor(launch.deadline_ns)
        if time.monotonic_ns() >= launch.deadline_ns:
            raise TimeoutError('run capsule publication exceeded original launch deadline')
        return run_id

    def close(self, launch=None):
        if self.closed:
            return
        self._live()
        if self.run_published:
            if (launch is None or launch is not self.run_launch or
                    (type(launch) is not self.origin_module.OriginalShellLaunch and
                     type(launch) not in (getattr(self.origin_module,
                        'PrivateC34OriginalShellLaunch', None), getattr(self.origin_module,
                        'OriginalSerialShellLaunch', None))) or
                    launch.process is None or launch.process.poll() is None):
                raise RuntimeError('run capsules remain owned until original launch settlement')
            settlement = launch.observe_settlement()
            if (type(settlement) is not dict or settlement.get('settled') is not True or
                    settlement.get('result') != launch.process.returncode or
                    launch.settlement != settlement):
                raise RuntimeError('original launch settlement was not freshly verified')
            for root in self.captured_roots:
                root.record()
        for slot in (RUN_FD, BOOTSTRAP_FD):
            expected = self.slot_identities.get(slot)
            if expected is None:
                continue
            info = os.fstat(slot)
            if (info.st_dev, info.st_ino, info.st_size) != expected:
                raise PermissionError('fixed scope slot was replaced; retaining the untrusted descriptor')
            try:
                os.close(slot)
            except OSError as error:
                if error.errno != errno.EBADF:
                    raise
            self.slot_identities.pop(slot, None)
        for scope_file in (self.run_file, self.bootstrap_file):
            if scope_file is not None:
                scope_file.close(unlink=True)
        for root in self.captured_roots:
            root.close()
        self.captured_roots = ()
        os.close(self.pidfd)
        self.pidfd = -1
        self.closed = True


def read_capsule(slot, role, *, deadline_ns, expected_run_id=None):
    """Read one sealed descriptor from PID 1 and validate its exact scope."""
    if slot not in (BOOTSTRAP_FD, RUN_FD) or role not in (BOOTSTRAP_ROLE, RUN_ROLE):
        raise ValueError('unsupported source scope slot or role')
    if (slot, role) not in ((BOOTSTRAP_FD, BOOTSTRAP_ROLE), (RUN_FD, RUN_ROLE)):
        raise ValueError('source scope role does not match fixed descriptor slot')
    if type(deadline_ns) is not int or time.monotonic_ns() >= deadline_ns:
        raise TimeoutError('scope descriptor read deadline expired')
    if role == BOOTSTRAP_ROLE:
        if expected_run_id not in (None, ''):
            raise ValueError('bootstrap capsule cannot carry a run id')
    elif type(expected_run_id) is not str or RUN_ID_RE.fullmatch(expected_run_id) is None:
        raise ValueError('run capsule requires the independently observed run id')
    root, pidfd = _root_record()
    fd = scope_fd = scope_parent_fd = -1
    scope = None
    try:
        path = f'/proc/{ROOT_PID}/fd/{slot}'
        while True:
            if time.monotonic_ns() >= deadline_ns or not _root_matches(root, pidfd):
                raise TimeoutError('scope descriptor unavailable within original deadline')
            try:
                fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
                break
            except FileNotFoundError:
                # FD 201 is intentionally absent until the real launch RUN_ID is authenticated.
                import select
                poller = select.poll()
                poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
                remaining_ms = max(1, min(25, (deadline_ns - time.monotonic_ns()) // 1_000_000))
                if poller.poll(remaining_ms):
                    raise ProcessLookupError('PID 1 exited while waiting for scope capsule')
        before = os.fstat(fd)
        named_before = os.stat(path)
        seals = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
        required_seals = (fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
                          fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 0 or
                before.st_uid != root['uid'] or not 0 < before.st_size <= MAX_DESCRIPTOR or
                seals != required_seals or
                (named_before.st_dev, named_before.st_ino) != (before.st_dev, before.st_ino)):
            raise PermissionError('scope capsule is not the exact sealed PID 1 memfd')
        raw = os.pread(fd, MAX_DESCRIPTOR + 1, 0)
        after = os.fstat(fd)
        named_after = os.stat(path)
        if (len(raw) != before.st_size or
                _stable_stat(before, after) is False or
                (named_after.st_dev, named_after.st_ino) != (after.st_dev, after.st_ino) or
                not _root_matches(root, pidfd) or time.monotonic_ns() >= deadline_ns):
            raise PermissionError('scope capsule changed during bounded read')
        value = json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=_unique_object)
        _validate_descriptor(value, role, root, expected_run_id)
        scope_path = Path(value['scope_path'])
        scope_parent_fd = _open_directory_nofollow(scope_path.parent)
        scope_parent_before = os.fstat(scope_parent_fd)
        scope_parent_identity = (scope_parent_before.st_dev, scope_parent_before.st_ino,
            _fd_mount_id(scope_parent_fd))
        if (scope_parent_before.st_uid != root['uid'] or
                scope_parent_before.st_mode & 0o077):
            raise PermissionError('scope metadata parent is not owned and private')
        scope_fd = os.open(scope_path.name, os.O_RDONLY | os.O_CLOEXEC |
            os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=scope_parent_fd)
        scope_before = os.fstat(scope_fd)
        scope_named_before = os.stat(scope_path.name, dir_fd=scope_parent_fd,
            follow_symlinks=False)
        if (not stat.S_ISREG(scope_before.st_mode) or scope_before.st_uid != root['uid'] or
                scope_before.st_mode & 0o077 or scope_before.st_nlink != 1 or
                not 0 < scope_before.st_size <= MAX_SCOPE or
                (scope_before.st_dev, scope_before.st_ino) !=
                    (value['scope_device'], value['scope_inode']) or
                (scope_named_before.st_dev, scope_named_before.st_ino) !=
                    (scope_before.st_dev, scope_before.st_ino)):
            raise PermissionError('scope data file is not the captured private regular file')
        helper = _helper_module()
        scope = helper.parse_scope(value['scope_path'], value['scope_device'],
            value['scope_inode'], value['scope_sha256'], scope_fd,
            allow_capability_scope=(role == BOOTSTRAP_ROLE))
        scope_fd = -1  # parse_scope owns the descriptor after success
        scope_after = os.fstat(scope['_fd'])
        named_after = os.stat(scope_path.name, dir_fd=scope_parent_fd,
            follow_symlinks=False)
        scope_parent_after = os.fstat(scope_parent_fd)
        reopened_parent = _open_directory_nofollow(scope_path.parent)
        try:
            reopened_info = os.fstat(reopened_parent)
            reopened_identity = (reopened_info.st_dev, reopened_info.st_ino,
                _fd_mount_id(reopened_parent))
        finally:
            os.close(reopened_parent)
        if (not _stable_stat(scope_before, scope_after) or
                (named_after.st_dev, named_after.st_ino) !=
                    (scope_after.st_dev, scope_after.st_ino) or
                (scope_parent_after.st_dev, scope_parent_after.st_ino,
                    _fd_mount_id(scope_parent_fd)) != scope_parent_identity or
                reopened_identity != scope_parent_identity or
                scope.get('version') != (1 if role == BOOTSTRAP_ROLE else 2) or
                scope.get('uid') != root['uid'] or
                scope.get('pid_namespace') != root['pid_namespace']):
            raise PermissionError('scope file contents differ from the sealed descriptor identity')
        if role == BOOTSTRAP_ROLE:
            if scope.get('roots') != [] or scope.get('supervisors') != []:
                raise PermissionError('bootstrap capsule is not capability-only')
        else:
            _validate_run_scope(scope, root, expected_run_id)
            for item in scope['roots']:
                root_fd = _open_directory_nofollow(item['path'],
                    var_run_alias=item.get('alias'))
                try:
                    root_info = os.fstat(root_fd)
                    if ((root_info.st_dev, root_info.st_ino, root_info.st_uid,
                            stat.S_IMODE(root_info.st_mode)) !=
                            (item['device'], item['inode'], root['uid'], 0o700)):
                        raise PermissionError('scope cleanup parent no longer matches captured private root')
                finally:
                    os.close(root_fd)
            helper_path = Path(_helper_module().__file__).resolve(strict=True)
            if any(helper_path.is_relative_to(Path(item['path'])) or
                    Path(__file__).resolve(strict=True).is_relative_to(Path(item['path']))
                    for item in scope['roots']):
                raise PermissionError('run cleanup scope includes source/helper code')
        if time.monotonic_ns() >= deadline_ns or not _root_matches(root, pidfd):
            raise TimeoutError('scope capsule validation exceeded its immutable deadline')
        os.close(scope_parent_fd)
        scope_parent_fd = -1
        capsule = ScopeCapsule(_CAPSULE_TOKEN, role, value['run_id'], value, scope,
            fd, pidfd, root)
        fd = pidfd = -1
        scope = None
        return capsule
    except BaseException:
        if scope is not None:
            for descriptor in (scope.get('_fd', -1), scope.get('_parent', -1)):
                if type(descriptor) is int and descriptor >= 0:
                    os.close(descriptor)
        for descriptor in (scope_fd, fd, pidfd):
            if descriptor >= 0:
                os.close(descriptor)
        if scope_parent_fd >= 0:
            os.close(scope_parent_fd)
        raise


def _stable_stat(left, right):
    return (left.st_dev, left.st_ino, left.st_mode, left.st_nlink, left.st_uid,
        left.st_size, left.st_mtime_ns, left.st_ctime_ns) == (
        right.st_dev, right.st_ino, right.st_mode, right.st_nlink, right.st_uid,
        right.st_size, right.st_mtime_ns, right.st_ctime_ns)


def _validate_descriptor(value, role, root, expected_run_id):
    if type(value) is not dict or set(value) != DESCRIPTOR_KEYS:
        raise ValueError('scope descriptor has missing or extra keys')
    if value.get('schema') != SCHEMA or value.get('role') != role:
        raise ValueError('scope descriptor schema or role mismatch')
    integer_fields = ('scope_device', 'scope_inode', 'root_pid', 'root_start_time',
        'root_exe_device', 'root_exe_inode', 'uid')
    if any(type(value.get(field)) is not int for field in integer_fields):
        raise ValueError('scope descriptor numeric field has wrong type')
    for field in ('scope_device', 'root_exe_device'):
        if value[field] < 0:
            raise ValueError('scope descriptor device is negative')
    for field in ('scope_inode', 'root_start_time', 'root_exe_inode'):
        if value[field] <= 0:
            raise ValueError('scope descriptor identity is invalid')
    if (value['root_pid'] != ROOT_PID or value['uid'] != root['uid'] or
            value['uid'] != os.geteuid() or
            any(value.get(field) != root.get(field) for field in (
                'root_pid', 'root_start_time', 'root_exe', 'root_exe_device',
                'root_exe_inode', 'uid', 'pid_namespace', 'mount_namespace'))):
        raise PermissionError('scope descriptor differs from live PID 1 identity')
    self_pidns = os.stat('/proc/self/ns/pid')
    self_mntns = os.stat('/proc/self/ns/mnt')
    if ([self_pidns.st_dev, self_pidns.st_ino] != value['pid_namespace'] or
            [self_mntns.st_dev, self_mntns.st_ino] != value['mount_namespace']):
        raise PermissionError('scope descriptor belongs to another PID or mount namespace')
    path = value.get('scope_path')
    if (type(path) is not str or not path.startswith('/') or str(Path(path)) != path or
            '..' in Path(path).parts or len(Path(path).parts) > 64 or
            any(Path(path).is_relative_to(Path(root)) for root in
                ('/proc', '/sys', '/dev/fd'))):
        raise ValueError('scope descriptor path is not canonical absolute')
    if type(value.get('scope_sha256')) is not str or not re.fullmatch(
            '[0-9a-f]{64}', value['scope_sha256']):
        raise ValueError('scope descriptor digest is malformed')
    for field in ('pid_namespace', 'mount_namespace'):
        item = value.get(field)
        if (type(item) is not list or len(item) != 2 or
                any(type(number) is not int or number < 0 for number in item)):
            raise ValueError('scope descriptor namespace identity is invalid')
    if role == BOOTSTRAP_ROLE:
        if value['run_id'] != '':
            raise ValueError('bootstrap descriptor must have an empty run id')
    elif (type(value['run_id']) is not str or RUN_ID_RE.fullmatch(value['run_id']) is None or
            value['run_id'] != expected_run_id):
        raise ValueError('run descriptor does not match authenticated run id')


def _validate_run_scope(scope, root, expected_run_id):
    if (type(scope) is not dict or scope.get('run_id') != expected_run_id or
            not any(item == {'pid': root['root_pid'],
                'start_time': root['root_start_time'], 'exe': root['root_exe'],
                'device': root['root_exe_device'], 'inode': root['root_exe_inode']}
                for item in scope.get('supervisors', []))):
        raise PermissionError('run scope does not bind exact run ID and PID 1 supervisor')
    roots = scope.get('roots')
    if type(roots) is not list or not roots:
        raise PermissionError('run scope has no captured cleanup parents')
    paths = [Path(item['path']) for item in roots]
    if (not {'/tmp', '/var/run/dpdk'} <= {str(path) for path in paths} or
            any(str(path) not in CapturedScopeRoot.ALLOWED_PATHS for path in paths) or
            len(paths) != len(set(paths)) or
            any(left in right.parents or right in left.parents
                for index, left in enumerate(paths) for right in paths[index + 1:])):
        raise PermissionError('run scope includes unsupported, missing, or ambiguous roots')
    for item in roots:
        if (type(item) is not dict or
                set(item) not in ({'path', 'device', 'inode', 'children'},
                    {'path', 'device', 'inode', 'children', 'alias'})):
            raise PermissionError('run scope root is not an exact record')
        if item['path'] == '/tmp' and item['children'] != [expected_run_id]:
            raise PermissionError('temporary cleanup child differs from exact run id')
        if (item['path'] == '/var/run/dpdk' and
                item['children'] != ['container-' + expected_run_id]):
            raise PermissionError('DPDK cleanup child differs from exact run id')
        if 'alias' in item and (item['path'] != '/var/run/dpdk' or
                type(item['alias']) is not dict or set(item['alias']) != {
                    'path', 'target', 'normalized_target', 'device', 'inode', 'target_device',
                    'target_inode', 'target_mount_id'} or
                item['alias'].get('path') != '/var/run' or
                item['alias'].get('target') not in ('/run', '../run') or
                item['alias'].get('normalized_target') != '/run' or
                any(type(item['alias'].get(key)) is not int or item['alias'][key] < 0
                    for key in ('device', 'inode', 'target_device', 'target_inode',
                        'target_mount_id')) or item['alias']['inode'] == 0 or
                item['alias']['target_inode'] == 0):
            raise PermissionError('run scope /var/run alias is malformed')
        if item['path'] == '/dev/hugepages':
            prefix = 'container-' + expected_run_id + 'map_'
            children = item['children']
            if (not children or any(not child.startswith(prefix) or
                    not child[len(prefix):].isascii() or
                    not child[len(prefix):].isdecimal() for child in children)):
                raise PermissionError('hugepage scope children are outside exact EAL run prefix')
