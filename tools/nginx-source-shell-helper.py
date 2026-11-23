#!/usr/bin/env python3
"""Identity-scoped workspace tools for the unchanged reload shell.

The deployment controller supplies a private scope file in the test's PID and
mount namespace. This program never selects processes by name or follows a
cleanup path through a symlink.
"""
import argparse
import hashlib
import json
import math
import os
import re
from pathlib import Path
import select
import signal
import stat
import sys


def v2_child_name(name, run_id):
    if name in (run_id, 'container-' + run_id):
        return True
    prefix = 'container-' + run_id + 'map_'
    suffix = name[len(prefix):] if name.startswith(prefix) else ''
    return bool(suffix) and suffix.isascii() and suffix.isdecimal()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate scope field')
        result[key] = value
    return result


def namespace_identity(path='/proc/self/ns/pid'):
    value = os.stat(path)
    return [value.st_dev, value.st_ino]


def load_scope(path, device, inode, digest, allow_capability_scope=False):
    scope_path = Path(path)
    if not scope_path.is_absolute() or '..' in scope_path.parts or len(scope_path.parts) > 64:
        raise ValueError('scope path must be a bounded absolute path')
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        return parse_scope(path, device, inode, digest, descriptor, allow_capability_scope)
    except BaseException:
        os.close(descriptor)
        raise


def parse_scope(path, device, inode, digest, descriptor, allow_capability_scope=False):
    identity = os.fstat(descriptor)
    data = os.pread(descriptor, 16385, 0)
    if (not stat.S_ISREG(identity.st_mode) or identity.st_uid != os.geteuid()
            or identity.st_mode & 0o077 or identity.st_nlink != 1
            or len(data) > 16384 or (identity.st_dev, identity.st_ino) != (device, inode)
            or hashlib.sha256(data).hexdigest() != digest):
        raise ValueError('scope file is not the captured private object')
    try:
        scope = json.loads(data.decode('utf-8', 'strict'), object_pairs_hook=unique_object)
    except UnicodeDecodeError as error:
        raise ValueError('scope is not strict UTF-8 JSON') from error
    if not isinstance(scope, dict):
        raise ValueError('invalid execution scope')
    version = scope.get('version')
    if type(version) is not int or version not in (1, 2):
        raise ValueError('unsupported execution scope version')
    expected_keys = ({'version', 'uid', 'pid_namespace', 'roots', 'supervisors'}
                     if version == 1 else
                     {'version', 'uid', 'pid_namespace', 'run_id', 'roots', 'supervisors'})
    if set(scope) != expected_keys:
        raise ValueError('invalid execution scope fields')
    if (type(scope['uid']) is not int or scope['uid'] != os.geteuid()
            or not isinstance(scope['pid_namespace'], list)
            or len(scope['pid_namespace']) != 2
            or any(type(value) is not int or value < 0 for value in scope['pid_namespace'])
            or scope['pid_namespace'] != namespace_identity()
            or not isinstance(scope['roots'], list)
            or not isinstance(scope['supervisors'], list)):
        raise ValueError('invalid execution scope identity')
    capability_only = (version == 1 and allow_capability_scope
                       and scope['roots'] == [] and scope['supervisors'] == [])
    if version == 1:
        if capability_only:
            pass
        elif not (1 <= len(scope['roots']) <= 8
                  and 1 <= len(scope['supervisors']) <= 4):
            raise ValueError('invalid v1 execution scope size')
    else:
        if (not isinstance(scope['run_id'], str)
                or not re.fullmatch(r'gr_[0-9]{8}_[0-9]{6}_[1-9][0-9]*_[0-9a-f]{8}',
                                    scope['run_id'])
                or not 1 <= len(scope['roots']) <= 8
                or not 1 <= len(scope['supervisors']) <= 4):
            raise ValueError('invalid v2 execution scope identity')
    if not capability_only and version == 1 and (not scope['roots'] or not scope['supervisors']):
        raise ValueError('empty v1 scope is capability-only')
    if not capability_only and version == 1:
        valid_root_keys = {'path', 'device', 'inode'}
    elif version == 2:
        valid_root_keys = {'path', 'device', 'inode', 'children'}
    else:
        valid_root_keys = {'path', 'device', 'inode'}
    root_paths = []
    for root in scope['roots']:
        keys = set(root) if isinstance(root, dict) else set()
        alias_root_keys = valid_root_keys | {'alias'}
        if (not isinstance(root, dict) or keys not in (valid_root_keys, alias_root_keys)
                or not isinstance(root['path'], str) or not root['path'].startswith('/')
                or root['path'] == '/' or '..' in root['path'].split('/')
                or str(Path(root['path'])) != root['path']
                or Path(root['path']).is_relative_to('/proc')
                or Path(root['path']).is_relative_to('/sys')
                or Path(root['path']).is_relative_to('/dev/fd')
                or type(root['device']) is not int or root['device'] < 0
                or type(root['inode']) is not int or root['inode'] <= 0):
            raise ValueError('invalid scoped root')
        alias = root.get('alias')
        if alias is not None:
            if (version != 2 or root['path'] != '/var/run/dpdk' or
                    type(alias) is not dict or set(alias) != {
                        'path', 'target', 'normalized_target', 'device', 'inode', 'target_device',
                        'target_inode', 'target_mount_id'} or
                    alias.get('path') != '/var/run' or
                    alias.get('target') not in ('/run', '../run') or
                    alias.get('normalized_target') != '/run' or
                    any(type(alias.get(key)) is not int or alias[key] < 0 for key in
                        ('device', 'inode', 'target_device', 'target_inode', 'target_mount_id')) or
                    alias['inode'] == 0 or alias['target_inode'] == 0):
                raise ValueError('invalid fixed /var/run alias identity')
        root_paths.append(Path(root['path']))
        if version == 2:
            children = root['children']
            if (not isinstance(children, list) or not 1 <= len(children) <= 128
                    or any(not isinstance(child, str) or not child or child in ('.', '..')
                           or '/' in child or '\\' in child or '\x00' in child
                           or len(os.fsencode(child)) > 255
                           for child in children)
                    or len(children) != len(set(children))
                    or any(not v2_child_name(child, scope['run_id']) for child in children)):
                raise ValueError('invalid exact scoped children')
    if version == 2:
        if len(root_paths) != len(set(root_paths)):
            raise ValueError('duplicate scoped parent')
        for index, left in enumerate(root_paths):
            for right in root_paths[index + 1:]:
                if left in right.parents or right in left.parents:
                    raise ValueError('nested scoped parents are ambiguous')
    for supervisor in scope['supervisors']:
        if (not isinstance(supervisor, dict) or
                set(supervisor) != {'pid', 'start_time', 'exe', 'device', 'inode'}
                or type(supervisor['pid']) is not int or supervisor['pid'] < 1
                or type(supervisor['start_time']) is not int or supervisor['start_time'] <= 0
                or not isinstance(supervisor['exe'], str) or not supervisor['exe'].startswith('/')
                or supervisor['exe'].endswith(' (deleted)')
                or type(supervisor['device']) is not int or supervisor['device'] < 0
                or type(supervisor['inode']) is not int or supervisor['inode'] <= 0):
            raise ValueError('invalid supervising process')
    supervisor_pids = [item['pid'] for item in scope['supervisors']]
    if len(supervisor_pids) != len(set(supervisor_pids)):
        raise ValueError('duplicate supervising process')
    parent = open_directory(Path(path).parent)
    parent_stat = os.fstat(parent)
    if (not stat.S_ISDIR(parent_stat.st_mode) or parent_stat.st_uid != scope['uid']
            or parent_stat.st_mode & 0o077):
        os.close(parent)
        raise ValueError('scope parent is not private')
    scope.update(_fd=descriptor, _parent=parent, _name=Path(path).name,
                 _parent_path=str(Path(path).parent),
                 _parent_device=parent_stat.st_dev, _parent_inode=parent_stat.st_ino,
                 _device=device, _inode=inode, _digest=digest,
                 _version=version, _capability_only=capability_only)
    try:
        verify_scope(scope)
    except BaseException:
        os.close(parent)
        raise
    return scope


def verify_scope(scope):
    identity = os.fstat(scope['_fd'])
    parent_identity = os.fstat(scope['_parent'])
    named = os.stat(scope['_name'], dir_fd=scope['_parent'], follow_symlinks=False)
    data = os.pread(scope['_fd'], 16385, 0)
    current_parent = open_directory(scope['_parent_path'])
    try:
        current_parent_identity = os.fstat(current_parent)
    finally:
        os.close(current_parent)
    if (not stat.S_ISREG(identity.st_mode)
            or (identity.st_dev, identity.st_ino) != (scope['_device'], scope['_inode'])
            or (named.st_dev, named.st_ino) != (identity.st_dev, identity.st_ino)
            or identity.st_uid != scope['uid']
            or identity.st_nlink != 1 or identity.st_mode & 0o077
            or not stat.S_ISDIR(parent_identity.st_mode)
            or (parent_identity.st_dev, parent_identity.st_ino) !=
                (scope['_parent_device'], scope['_parent_inode'])
            or (current_parent_identity.st_dev, current_parent_identity.st_ino) !=
                (scope['_parent_device'], scope['_parent_inode'])
            or current_parent_identity.st_uid != scope['uid']
            or current_parent_identity.st_mode & 0o077
            or len(data) > 16384 or hashlib.sha256(data).hexdigest() != scope['_digest']):
        raise ValueError('scope identity or contents changed')


def process_identity(pid):
    base = Path('/proc') / str(pid)
    fields = (base / 'stat').read_text().rsplit(')', 1)[1].split()
    executable = os.readlink(base / 'exe')
    if executable.endswith(' (deleted)'):
        raise ValueError('signal executable was deleted')
    image = (base / 'exe').stat()
    uid = next(line.split()[1] for line in (base / 'status').read_text().splitlines()
               if line.startswith('Uid:'))
    return (int(fields[19]), executable, image.st_dev, image.st_ino,
            int(uid), namespace_identity(base / 'ns/pid'))


def owned_descendant(pid, scope):
    if pid == os.getpid() or any(pid == root['pid'] for root in scope['supervisors']):
        return None
    descriptors = []
    authorized = False
    try:
        for _ in range(128):
            fields = (Path('/proc') / str(pid) / 'stat').read_text().rsplit(')', 1)[1].split()
            parent = int(fields[1])
            if parent < 1 or parent == pid:
                return None
            descriptor = os.pidfd_open(parent)
            descriptors.append(descriptor)
            again = (Path('/proc') / str(pid) / 'stat').read_text().rsplit(')', 1)[1].split()
            if again[1] != fields[1] or again[19] != fields[19]:
                return None
            for root in scope['supervisors']:
                if root['pid'] == parent:
                    expected = (root['start_time'], root['exe'], root['device'], root['inode'],
                                scope['uid'], scope['pid_namespace'])
                    authorized = process_identity(parent) == expected
                    return (descriptors, root) if authorized else None
            pid = parent
        return None
    finally:
        if not authorized:
            for descriptor in descriptors:
                os.close(descriptor)


def signal_owned(args, scope):
    if args.pid <= 1 or args.start_time <= 0 or not 0 <= args.wait <= 10 or not math.isfinite(args.wait):
        raise ValueError('invalid signal target or deadline')
    signals = {'HUP', 'TERM', 'KILL', 'QUIT', 'INT', 'USR2', 'WINCH'}
    if args.signal not in signals:
        raise ValueError('unsupported signal')
    expected = (args.start_time, args.exe, args.device, args.inode,
                scope['uid'], scope['pid_namespace'])
    # Pin the process instance between both identity observations. A PID reuse
    # cannot redirect the signal to another instance.
    before = process_identity(args.pid)
    descriptor = os.pidfd_open(args.pid)
    ancestry = None
    try:
        ownership = owned_descendant(args.pid, scope)
        if before != expected or ownership is None or process_identity(args.pid) != expected:
            raise ValueError('signal target identity changed')
        ancestry, supervisor = ownership
        verify_scope(scope)
        supervisor_expected = (supervisor['start_time'], supervisor['exe'],
            supervisor['device'], supervisor['inode'], scope['uid'], scope['pid_namespace'])
        if (process_identity(args.pid) != expected or
                process_identity(supervisor['pid']) != supervisor_expected):
            raise ValueError('signal ownership changed')
        ancestry_poll = select.poll()
        for ancestor_fd in ancestry:
            ancestry_poll.register(ancestor_fd, select.POLLIN)
        if ancestry_poll.poll(0):
            raise ValueError('supervisor ancestry changed')
        signal.pidfd_send_signal(descriptor, getattr(signal, 'SIG' + args.signal))
        if not args.wait:
            return 0
        poller = select.poll()
        poller.register(descriptor, select.POLLIN)
        events = poller.poll(math.ceil(args.wait * 1000))
        if not events:
            return 3
        if any((flags & (select.POLLERR | select.POLLNVAL) or
                not flags & select.POLLIN) for _, flags in events):
            raise ValueError('unverifiable pidfd result')
        return 0
    finally:
        if ancestry is not None:
            for ancestor_fd in ancestry:
                os.close(ancestor_fd)
        os.close(descriptor)


def _mount_id(fd):
    with open('/proc/self/fdinfo/%d' % fd, 'rt', encoding='ascii') as stream:
        values = [line.split(':', 1)[1].strip() for line in stream
            if line.startswith('mnt_id:')]
    if len(values) != 1 or not values[0].isdigit():
        raise ValueError('directory descriptor has no unique mount identity')
    return int(values[0])


def open_directory(path, *, var_run_alias=None, _root_fd=None):
    """Open an absolute directory without resolving any symlink component."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts or len(path.parts) > 64:
        raise ValueError('directory path must be bounded and absolute')
    base_fd = (os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        if _root_fd is None else os.dup(_root_fd))
    current = os.dup(base_fd)
    try:
        for index, component in enumerate(path.parts[1:], 1):
            if str(path).startswith('/var/run') and index == 2 and component == 'run':
                parent = current
                link = os.stat('run', dir_fd=parent, follow_symlinks=False)
                if stat.S_ISLNK(link.st_mode):
                    if (type(var_run_alias) is not dict or
                            var_run_alias.get('path') != '/var/run' or
                            var_run_alias.get('target') not in ('/run', '../run') or
                            var_run_alias.get('normalized_target') != '/run' or
                            (link.st_dev, link.st_ino) !=
                                (var_run_alias.get('device'), var_run_alias.get('inode')) or
                            os.readlink('run', dir_fd=parent) != var_run_alias.get('target')):
                        raise ValueError('unapproved or changed /var/run alias')
                    following = os.open('run', os.O_RDONLY | os.O_DIRECTORY |
                        os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=base_fd)
                    target = os.fstat(following)
                    again = os.stat('run', dir_fd=parent, follow_symlinks=False)
                    if ((target.st_dev, target.st_ino) !=
                            (var_run_alias.get('target_device'), var_run_alias.get('target_inode')) or
                            _mount_id(following) != var_run_alias.get('target_mount_id') or
                            (again.st_dev, again.st_ino) != (link.st_dev, link.st_ino) or
                            os.readlink('run', dir_fd=parent) != var_run_alias.get('target')):
                        os.close(following)
                        raise ValueError('fixed /var/run target changed')
                    os.close(current)
                    current = following
                    continue
                if var_run_alias is not None:
                    raise ValueError('captured /var/run alias was replaced by a directory')
            following = os.open(component, os.O_RDONLY | os.O_DIRECTORY |
                                os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=current)
            os.close(current)
            current = following
        os.close(base_fd)
        return current
    except BaseException:
        os.close(current)
        os.close(base_fd)
        raise


def scoped_parent(path, scope):
    if not path.startswith('/') or '..' in path.split('/'):
        raise ValueError('cleanup path must be absolute and beneath a scoped root')
    target = Path(path)
    if scope['_capability_only']:
        raise ValueError('capability-only scope cannot authorize filesystem operations')
    if scope['_version'] == 1:
        roots = [root for root in scope['roots'] if target.is_relative_to(Path(root['path']))]
        if not roots:
            raise ValueError('path is outside the owned scope')
        root = max(roots, key=lambda item: len(Path(item['path']).parts))
        root_path = Path(root['path'])
        root_fd = open_directory(root_path, var_run_alias=root.get('alias'))
        try:
            info = os.fstat(root_fd)
            if (not stat.S_ISDIR(info.st_mode) or info.st_dev != root['device'] or
                    info.st_ino != root['inode'] or info.st_uid != scope['uid'] or
                    info.st_mode & 0o077):
                raise ValueError('scoped root identity changed')
            relative = target.relative_to(root_path)
            if not relative.parts:
                parent = open_directory(root_path.parent, var_run_alias=root.get('alias'))
                named = os.stat(root_path.name, dir_fd=parent, follow_symlinks=False)
                if (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino):
                    os.close(parent)
                    raise ValueError('scoped root was renamed')
                return parent, root_path.name
            parent = os.dup(root_fd)
            try:
                for component in relative.parts[:-1]:
                    following = os.open(component, os.O_RDONLY | os.O_DIRECTORY |
                                        os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                    os.close(parent)
                    parent = following
                    if os.fstat(parent).st_uid != scope['uid']:
                        raise ValueError('foreign cleanup directory')
                return parent, relative.name
            except BaseException:
                os.close(parent)
                raise
        finally:
            os.close(root_fd)

    if str(target) != path:
        raise ValueError('v2 cleanup path must be canonical')
    for root in scope['roots']:
        root_path = Path(root['path'])
        if not target.is_relative_to(root_path):
            continue
        relative = target.relative_to(root_path)
        if not relative.parts or relative.parts[0] not in root['children']:
            raise ValueError('path is outside exact v2 child scope')
        root_fd = open_directory(root_path, var_run_alias=root.get('alias'))
        try:
            info = os.fstat(root_fd)
            if (not stat.S_ISDIR(info.st_mode) or info.st_dev != root['device'] or
                    info.st_ino != root['inode'] or info.st_uid != scope['uid'] or
                    info.st_mode & 0o077):
                raise ValueError('scoped parent identity changed')
            parent = os.dup(root_fd)
            try:
                for component in relative.parts[:-1]:
                    following = os.open(component, os.O_RDONLY | os.O_DIRECTORY |
                                        os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                    opened = os.fstat(following)
                    if opened.st_uid != scope['uid']:
                        os.close(following)
                        raise ValueError('foreign cleanup directory')
                    os.close(parent)
                    parent = following
                return parent, relative.name
            except BaseException:
                os.close(parent)
                raise
        finally:
            os.close(root_fd)
    raise ValueError('path is outside exact v2 child scope')


def remove_entry(parent, name, scope, budget, depth=0):
    verify_scope(scope)
    if depth > 32 or budget[0] >= 4096:
        raise ValueError('cleanup exceeds bounded tree')
    budget[0] += 1
    try:
        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return
    if info.st_uid != scope['uid']:
        raise ValueError('foreign cleanup object')
    strict_v2 = scope['_version'] == 2
    if strict_v2 and stat.S_ISLNK(info.st_mode):
        raise ValueError('symlink cleanup objects are unsupported in v2 scope')
    if strict_v2 and stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
        raise ValueError('hardlinked cleanup objects are unsupported in v2 scope')
    if stat.S_ISDIR(info.st_mode):
        descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC |
                             os.O_NOFOLLOW, dir_fd=parent)
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                raise ValueError('cleanup directory changed')
            for child in os.listdir(descriptor):
                remove_entry(descriptor, child, scope, budget, depth + 1)
        finally:
            os.close(descriptor)
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino):
            raise ValueError('cleanup directory was renamed')
        os.rmdir(name, dir_fd=parent)
    else:
        os.unlink(name, dir_fd=parent)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scope', required=True)
    parser.add_argument('--scope-device', type=int, required=True)
    parser.add_argument('--scope-inode', type=int, required=True)
    parser.add_argument('--scope-sha256', required=True)
    commands = parser.add_subparsers(dest='operation', required=True)
    kill = commands.add_parser('signal')
    kill.add_argument('--capabilities', action='store_true')
    for name, kind in (('pid', int), ('start-time', int), ('exe', str),
                       ('device', int), ('inode', int), ('signal', str)):
        kill.add_argument('--' + name, type=kind)
    kill.add_argument('--wait', type=float, default=0)
    remove = commands.add_parser('remove')
    remove.add_argument('path')
    mode = commands.add_parser('chmod')
    mode.add_argument('mode')
    mode.add_argument('path')
    args = parser.parse_args()
    capability_only = args.operation == 'signal' and args.capabilities
    scope = load_scope(args.scope, args.scope_device, args.scope_inode, args.scope_sha256,
                       allow_capability_scope=capability_only)
    try:
        return execute(args, scope)
    finally:
        os.close(scope['_fd'])
        os.close(scope['_parent'])


def execute(args, scope):
    if args.operation == 'signal':
        if args.capabilities:
            descriptor = os.pidfd_open(os.getpid())
            try:
                signal.pidfd_send_signal(descriptor, 0)
            finally:
                os.close(descriptor)
            print('pidfd-identity-v1')
            return 0
        if any(getattr(args, name) is None for name in
               ('pid', 'start_time', 'exe', 'device', 'inode', 'signal')):
            raise ValueError('complete captured signal identity required')
        return signal_owned(args, scope)
    parent, name = scoped_parent(args.path, scope)
    try:
        if args.operation == 'remove':
            remove_entry(parent, name, scope, [0])
        else:
            if not args.mode or any(value not in '01234567' for value in args.mode):
                raise ValueError('numeric permission mode required')
            mode_value = int(args.mode, 8)
            if not 0 <= mode_value <= 0o777:
                raise ValueError('special permission bits are unsupported')
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if not (stat.S_ISREG(named.st_mode) or stat.S_ISDIR(named.st_mode)):
                raise ValueError('permission target is not a regular file or directory')
            if stat.S_ISREG(named.st_mode) and named.st_nlink != 1:
                raise ValueError('multiply-linked permission target is outside the owned scope')
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                                 dir_fd=parent)
            try:
                opened = os.fstat(descriptor)
                if (opened.st_uid != scope['uid'] or
                        (opened.st_dev, opened.st_ino, opened.st_mode) !=
                        (named.st_dev, named.st_ino, named.st_mode)):
                    raise ValueError('foreign permission target')
                if stat.S_ISREG(opened.st_mode) and opened.st_nlink != 1:
                    raise ValueError('multiply-linked permission target is outside the owned scope')
                verify_scope(scope)
                os.fchmod(descriptor, mode_value)
            finally:
                os.close(descriptor)
        return 0
    finally:
        os.close(parent)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, TypeError) as error:
        print(f'owned reload helper: {error}', file=sys.stderr)
        sys.exit(1)
