#!/usr/bin/python3
"""DRAFT ONLY: consume Root's sealed scope descriptor and exec the scoped helper."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import select
import stat
import sys
import time

HELPER = '/data/workspace/nginx-source-shell-helper.py'
HELPER_SHA256 = '50aca8722f22c03930d3da3c950638db8be879f9250b26914f8445c7b460857b'
MINIMAL_ENV = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}
ROOT_PID = 1
BOOTSTRAP_FD = 200
FINAL_FD = 201
MAX_RECORD = 16384
FINAL_WAIT_SECONDS = 5.0
DESCRIPTOR_KEYS = {
    'schema', 'role', 'scope_path', 'scope_device', 'scope_inode', 'scope_sha256',
    'run_id', 'root_pid', 'root_start_time', 'root_exe', 'root_exe_device',
    'root_exe_inode', 'uid', 'pid_namespace', 'mount_namespace',
}
RUN_ID_RE = re.compile(r'gr_[0-9]{8}_[0-9]{6}_[1-9][0-9]*_[0-9a-f]{8}')


class ScopeError(Exception):
    pass


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ScopeError('duplicate JSON key')
        value[key] = item
    return value


def pollfd(fd):
    poller = select.poll()
    poller.register(fd, select.POLLIN | select.POLLERR | select.POLLHUP | select.POLLNVAL)
    return bool(poller.poll(0))


def proc_stat(pid):
    fields = Path('/proc/%d/stat' % pid).read_text().rsplit(')', 1)[1].split()
    if len(fields) <= 19:
        raise ScopeError('short proc stat')
    return int(fields[19])


def root_identity():
    status = Path('/proc/1/status').read_text()
    uid_line = next(line for line in status.splitlines() if line.startswith('Uid:'))
    uid_fields = uid_line.split()
    if len(uid_fields) < 2:
        raise ScopeError('short root UID record')
    exe = os.readlink('/proc/1/exe')
    image = os.stat('/proc/1/exe')
    pidns = os.stat('/proc/1/ns/pid')
    mntns = os.stat('/proc/1/ns/mnt')
    return {
        'root_pid': 1,
        'root_start_time': proc_stat(1),
        'root_exe': exe,
        'root_exe_device': image.st_dev,
        'root_exe_inode': image.st_ino,
        'uid': int(uid_fields[1]),
        'pid_namespace': [pidns.st_dev, pidns.st_ino],
        'mount_namespace': [mntns.st_dev, mntns.st_ino],
    }


def stable_stat(before, after):
    return (before.st_dev, before.st_ino, before.st_mode, before.st_nlink,
            before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (
            after.st_dev, after.st_ino, after.st_mode, after.st_nlink,
            after.st_size, after.st_mtime_ns, after.st_ctime_ns)


def open_pinned_helper():
    fd = os.open(HELPER, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        named_before = os.stat(HELPER, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or before.st_mode & 0o022 or before.st_nlink != 1
                or not 0 < before.st_size <= 1024 * 1024
                or (named_before.st_dev, named_before.st_ino) != (before.st_dev, before.st_ino)):
            raise ScopeError('helper is not the protected private code file')
        data = os.pread(fd, 1024 * 1024 + 1, 0)
        after = os.fstat(fd)
        named_after = os.stat(HELPER, follow_symlinks=False)
        if (len(data) != before.st_size or not stable_stat(before, after)
                or (named_after.st_dev, named_after.st_ino) != (after.st_dev, after.st_ino)
                or hashlib.sha256(data).hexdigest() != HELPER_SHA256):
            raise ScopeError('helper hash or identity differs from pinned code')
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_descriptor(slot, deadline):
    path = '/proc/1/fd/%d' % slot
    pidfd = os.pidfd_open(ROOT_PID, 0)
    fd = None
    try:
        root_before = root_identity()
        while True:
            if pollfd(pidfd) or root_identity() != root_before:
                raise ScopeError('Root identity changed before descriptor read')
            try:
                fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
                break
            except FileNotFoundError:
                if deadline is None or time.monotonic() >= deadline:
                    raise ScopeError('Root scope descriptor is not published')
                time.sleep(min(0.025, max(0, deadline - time.monotonic())))
        info = os.fstat(fd)
        named_before = os.stat(path)
        required_seals = (fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
                          fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        seals = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 0
                or info.st_uid != root_before['uid']
                or not 0 < info.st_size <= MAX_RECORD or seals != required_seals
                or (named_before.st_dev, named_before.st_ino) != (info.st_dev, info.st_ino)):
            raise ScopeError('Root descriptor is not the sealed captured memfd')
        raw = os.pread(fd, MAX_RECORD + 1, 0)
        after = os.fstat(fd)
        named_after = os.stat(path)
        root_after = root_identity()
        if (len(raw) != info.st_size or not stable_stat(info, after)
                or (named_after.st_dev, named_after.st_ino) != (after.st_dev, after.st_ino)
                or root_before != root_after or pollfd(pidfd)):
            raise ScopeError('Root identity or descriptor changed during read')
        try:
            value = json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=unique_object)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ScopeError('Root descriptor JSON is invalid') from error
        if type(value) is not dict or set(value) != DESCRIPTOR_KEYS:
            raise ScopeError('Root descriptor has unexpected fields')
        return value, fd, pidfd
    except BaseException:
        if fd is not None:
            os.close(fd)
        os.close(pidfd)
        raise


def validate_descriptor(value, role, actual_root):
    if type(value) is not dict or set(value) != DESCRIPTOR_KEYS:
        raise ScopeError('Root descriptor has unexpected fields')
    if value['schema'] != 'ker-source-helper-scope-descriptor-v1' or value['role'] != role:
        raise ScopeError('wrong Root descriptor role')
    if any(type(value[key]) is not int for key in (
            'scope_device', 'scope_inode', 'root_pid', 'root_start_time',
            'root_exe_device', 'root_exe_inode', 'uid')):
        raise ScopeError('Root descriptor integer has wrong type')
    if (value['scope_device'] < 0 or value['scope_inode'] <= 0
            or value['root_pid'] != ROOT_PID or value['root_start_time'] <= 0
            or value['root_exe_device'] < 0 or value['root_exe_inode'] <= 0
            or value['uid'] != os.geteuid()):
        raise ScopeError('Root descriptor identity is invalid')
    if (not isinstance(value['scope_path'], str) or not value['scope_path'].startswith('/')
            or str(Path(value['scope_path'])) != value['scope_path']
            or '..' in Path(value['scope_path']).parts
            or len(Path(value['scope_path']).parts) > 64
            or not isinstance(value['root_exe'], str) or not value['root_exe'].startswith('/')
            or str(Path(value['root_exe'])) != value['root_exe']
            or value['root_exe'].endswith(' (deleted)')):
        raise ScopeError('Root descriptor path is invalid')
    if (not isinstance(value['scope_sha256'], str)
            or not re.fullmatch(r'[0-9a-f]{64}', value['scope_sha256'])):
        raise ScopeError('Root descriptor digest is invalid')
    for key in ('pid_namespace', 'mount_namespace'):
        item = value[key]
        if (not isinstance(item, list) or len(item) != 2
                or any(type(number) is not int or number < 0 for number in item)):
            raise ScopeError('Root namespace identity is invalid')
    if any(value[key] != actual_root[key] for key in actual_root):
        raise ScopeError('Root descriptor does not match live PID 1')
    self_pidns = os.stat('/proc/self/ns/pid')
    self_mntns = os.stat('/proc/self/ns/mnt')
    if ([self_pidns.st_dev, self_pidns.st_ino] != value['pid_namespace']
            or [self_mntns.st_dev, self_mntns.st_ino] != value['mount_namespace']):
        raise ScopeError('wrapper is outside Root namespaces')
    if role == 'bootstrap-capabilities':
        if value['run_id'] != '':
            raise ScopeError('bootstrap descriptor must not carry a run id')
    elif (not isinstance(value['run_id'], str)
          or not RUN_ID_RE.fullmatch(value['run_id'])):
        raise ScopeError('run descriptor id is invalid')


def read_scope(value, role):
    path = value['scope_path']
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or before.st_mode & 0o077 or before.st_nlink != 1
                or before.st_size > MAX_RECORD
                or (before.st_dev, before.st_ino) !=
                   (value['scope_device'], value['scope_inode'])):
            raise ScopeError('scope file is not the captured private object')
        named_before = os.stat(path, follow_symlinks=False)
        raw = os.pread(fd, MAX_RECORD + 1, 0)
        after = os.fstat(fd)
        named_after = os.stat(path, follow_symlinks=False)
        if (len(raw) > MAX_RECORD or not stable_stat(before, after)
                or (named_before.st_dev, named_before.st_ino) != (before.st_dev, before.st_ino)
                or (named_after.st_dev, named_after.st_ino) != (after.st_dev, after.st_ino)
                or hashlib.sha256(raw).hexdigest() != value['scope_sha256']):
            raise ScopeError('scope file changed or does not match sealed descriptor')
        try:
            scope = json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=unique_object)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ScopeError('scope JSON is invalid') from error
        if type(scope) is not dict:
            raise ScopeError('scope record is not an object')
        if role == 'bootstrap-capabilities':
            if (set(scope) != {'version', 'uid', 'pid_namespace', 'roots', 'supervisors'}
                    or type(scope.get('version')) is not int or scope['version'] != 1
                    or scope.get('uid') != value['uid']
                    or scope.get('pid_namespace') != value['pid_namespace']
                    or scope.get('roots') != [] or scope.get('supervisors') != []):
                raise ScopeError('bootstrap scope must be no-filesystem v1')
        else:
            if (set(scope) != {'version', 'uid', 'pid_namespace', 'run_id', 'roots', 'supervisors'}
                    or type(scope.get('version')) is not int or scope['version'] != 2
                    or scope.get('uid') != value['uid']
                    or scope.get('pid_namespace') != value['pid_namespace']
                    or scope.get('run_id') != value['run_id']):
                raise ScopeError('run scope differs from sealed run id or identity')
            expected = {'pid': value['root_pid'],
                        'start_time': value['root_start_time'],
                        'exe': value['root_exe'],
                        'device': value['root_exe_device'],
                        'inode': value['root_exe_inode']}
            if expected not in scope.get('supervisors', []):
                raise ScopeError('run scope does not bind Root as supervisor')
            code_paths = (Path(HELPER), Path(__file__))
            roots = scope.get('roots')
            if not isinstance(roots, list):
                raise ScopeError('run scope roots are invalid')
            for root in roots:
                if not isinstance(root, dict) or not isinstance(root.get('path'), str):
                    raise ScopeError('run scope root entry is invalid')
                parent = Path(root['path'])
                if any(code.is_relative_to(parent) for code in code_paths):
                    raise ScopeError('cleanup scope includes private wrapper code')
        return raw
    finally:
        os.close(fd)


def exact_remove_target(path, run_id):
    if path in ('/tmp/' + run_id, '/var/run/dpdk/container-' + run_id):
        return True
    prefix = '/dev/hugepages/container-' + run_id + 'map_'
    suffix = path[len(prefix):] if path.startswith(prefix) else ''
    return bool(suffix) and suffix.isascii() and suffix.isdecimal()


def helper_argv(tool, args, descriptor, role):
    if tool == 'kill_process.sh':
        if role == 'bootstrap-capabilities':
            return ['signal', '--capabilities']
        return ['signal', *args]
    if role != 'run-cleanup':
        raise ScopeError('filesystem helper requires final run descriptor')
    if tool == 'rm_tmp_file.sh':
        if len(args) != 1 or not exact_remove_target(args[0], descriptor['run_id']):
            raise ScopeError('remove target differs from exact run id')
        return ['remove', args[0]]
    if tool == 'chmod_modify.sh':
        if len(args) != 2 or args[0] == '+x':
            raise ScopeError('symbolic chmod +x remains unsupported')
        return ['chmod', *args]
    raise ScopeError('unknown wrapper')


def main(argv):
    if not argv:
        raise ScopeError('missing wrapper name')
    tool, *args = argv
    if tool not in ('kill_process.sh', 'rm_tmp_file.sh', 'chmod_modify.sh'):
        raise ScopeError('unknown wrapper name')
    is_caps = tool == 'kill_process.sh' and args == ['--capabilities']
    role = 'bootstrap-capabilities' if is_caps else 'run-cleanup'
    slot = BOOTSTRAP_FD if is_caps else FINAL_FD
    deadline = None if is_caps else time.monotonic() + FINAL_WAIT_SECONDS
    descriptor, fd, pidfd = read_descriptor(slot, deadline)
    try:
        actual_root = root_identity()
        validate_descriptor(descriptor, role, actual_root)
        read_scope(descriptor, role)
        if deadline is not None and time.monotonic() >= deadline:
            raise ScopeError('final scope publication budget expired')
        actual_root = root_identity()
        validate_descriptor(descriptor, role, actual_root)
        if pollfd(pidfd):
            raise ScopeError('Root exited during scope validation')
        command = helper_argv(tool, args, descriptor, role)
        helper_fd = open_pinned_helper()
        helper_script = '/proc/self/fd/%d' % helper_fd
        os.set_inheritable(helper_fd, True)
        os.close(fd)
        fd = -1
        os.close(pidfd)
        pidfd = -1
        os.execve('/usr/bin/python3', ['/usr/bin/python3', '-I', helper_script,
            '--scope', descriptor['scope_path'],
            '--scope-device', str(descriptor['scope_device']),
            '--scope-inode', str(descriptor['scope_inode']),
            '--scope-sha256', descriptor['scope_sha256'], *command], MINIMAL_ENV)
    finally:
        if fd >= 0:
            os.close(fd)
        if pidfd >= 0:
            os.close(pidfd)


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except (OSError, ValueError, ScopeError, TypeError, KeyError, IndexError) as error:
        print('source-shell wrapper: %s' % error, file=sys.stderr)
        raise SystemExit(1)
