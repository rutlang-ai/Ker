"""Pinned external C22 provider for the source-shell integration harness.

The provider owns a genuine C22 staged-plan client process. It hands source
workers only the plan's two FIFO slot capabilities and retains the preclaim
C34 generation-watch capability for the SDK broker-readiness channel.
"""
import array
import errno
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
from types import MappingProxyType

_MAGIC = b'KERSC22P'
_VERSION = 1
_RECORD = struct.Struct('=8sIIQQ16s16sIIIQQQQ')
_UCRED = struct.Struct('=3i')
_MAX_RECORD = 256
_C28_MAGIC = b'KERSC28Q'
_C28_VERSION = 1
_C28_REQUEST = struct.Struct('<8sHHIQQII108s')
_C28_RESULT = struct.Struct('<iIQQII')
_C28_REPLY_BYTES = _C28_REQUEST.size + _C28_RESULT.size
_C28_PARK = 1
_C28_COMMIT = 2
_C28_ABORT = 3
_C28_CURRENT_CENSUS = 4
_C28_RETIRE_INITIAL_LISTENER = 5
_C28_CLOSE = 6
_C28_RETRY_ADOPT = 7
_C28_RETRY_SLOT = 8
_C28_ADOPT_SUCCESSOR = 9
_C28_PHASE_PREPARED = 1
_C28_PHASE_COMMITTED = 4
_C28_PHASE_ABORTED = 5
_C28_SOURCE_COMMAND_ABI = 1
_C28_CUTOVER_BUDGET_NS = 100_000_000
_C28_RETIRE_MAX_ATTEMPTS = 1000
assert _C28_REQUEST.size == 148 and _C28_RESULT.size == 32 and _C28_REPLY_BYTES == 180
_STARTUP_NS = 5_000_000_000
_MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024
_CLOSE_WRITE_NS = 100_000_000
_TERM_GRACE_NS = 100_000_000
_KILL_GRACE_NS = 100_000_000
_CAPTURE_TOKEN = object()
_INITIAL_RETIREMENT_PROOF_TOKEN = object()
_VERIFY_WIRE_NAME = '_ker_nginx_source_verify_wire'
_VERIFY_WIRE_PATH = Path(__file__).with_name('broker_readiness_wire.py').resolve(strict=True)


def _verify_wire_module():
    cached = sys.modules.get(_VERIFY_WIRE_NAME)
    if cached is not None:
        if Path(cached.__file__).resolve(strict=True) != _VERIFY_WIRE_PATH:
            raise ImportError('cached C34 VERIFY codec belongs to another path')
        return cached
    spec = importlib.util.spec_from_file_location(_VERIFY_WIRE_NAME, _VERIFY_WIRE_PATH)
    if spec is None or spec.loader is None:
        raise ImportError('cannot load the pinned C34 VERIFY codec')
    module = importlib.util.module_from_spec(spec)
    sys.modules[_VERIFY_WIRE_NAME] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        if sys.modules.get(_VERIFY_WIRE_NAME) is module:
            del sys.modules[_VERIFY_WIRE_NAME]
        raise
    return module
_BUILD_ROOT = Path('/home/hurricane/.local/state/ker-fstack-source-shell/c22-helper-build-capture-v3')
_RECEIPT_PATH = _BUILD_ROOT / 'build-receipt.json'
_FREEZE_PATH = _BUILD_ROOT / 'root-freeze.json'
_HELPER_PATH = _BUILD_ROOT / 'build/ker-nginx-owner-group-controller'
_ARCHIVE_PATH = _BUILD_ROOT / 'build/libker-socket-client.a'
_RECEIPT_SHA256 = 'c3123ee03544dbeda3c134ffbf129aea26a6e9de143354a0b6ab779de6bc957e'
_FREEZE_SHA256 = '2817e0c205ebfaef83b74c13c1581893abda01cafb8097b9ce4d42287ea2bcf9'
_HELPER_SHA256 = '8257c18d705e45248bab4bd8d41b0b89188bedc406ad2fa19b5cd79dc6c73f10'
_HELPER_BUILD_ID = '8672c45c71065c706bb54779307851cb83551136'
_ARCHIVE_SHA256 = '538740472cf1dea2937e5cf1421ddd3663561b96cf3f62e290cf1fa602672a34'
_CLIENT_SOURCE = Path('/home/hurricane/.local/state/ker-fstack-source-shell/integration-worktree/src/posix/socket-broker-client.c')
_HELPER_SOURCE = Path('/home/hurricane/.local/state/ker-fstack-source-shell/integration-worktree/tests/posix/nginx-owner-group-controller.c')
_CMAKE_SOURCE = Path('/home/hurricane/.local/state/ker-fstack-source-shell/integration-worktree/cmake/NativeRequestRevoke.cmake')
_SOURCE_HASHES = {
    str(_CLIENT_SOURCE): '5af64b555c597a8ac7f1f9bf343e0c497534640cbee986414451170cc66d6d0d',
    str(_HELPER_SOURCE): '00db8d0061bea3650fc2852ddb5c35d68301ac5f950f42293e17b656fa3484e1',
    str(_CMAKE_SOURCE): '9b117d52e5baf12082c73d57008db80da34024d7845ca5034b425d57f47f073b',
}


def _encode_source_c28_request(operation, sequence, deadline_ns, bundle):
    if (type(operation) is not int or operation not in range(_C28_PARK, _C28_ADOPT_SUCCESSOR + 1) or
            type(sequence) is not int or sequence <= 0 or
            type(deadline_ns) is not int or deadline_ns <= 0 or
            type(bundle) is not bytes or len(bundle) != _RECORD.size):
        raise ValueError('invalid bounded C28 command request fields')
    return _C28_REQUEST.pack(_C28_MAGIC, _C28_VERSION, operation,
        _C28_REQUEST.size, sequence, deadline_ns, 0, 0, bundle)


def _decode_source_c28_reply(packet, request, credentials, expected_credentials,
        flags, ancillary_error=False):
    if (type(packet) is not bytes or type(request) is not bytes or
            len(packet) != _C28_REPLY_BYTES or len(request) != _C28_REQUEST.size or
            flags & (getattr(socket, 'MSG_TRUNC', 0) | getattr(socket, 'MSG_CTRUNC', 0)) or
            flags & ~getattr(socket, 'MSG_CMSG_CLOEXEC', 0) or ancillary_error or
            credentials != expected_credentials or packet[:_C28_REQUEST.size] != request):
        raise PermissionError('C28 helper reply is malformed, unauthenticated, or not correlated')
    error, phase, lease, listener_cookie, received, accepted = _C28_RESULT.unpack(
        packet[_C28_REQUEST.size:])
    if error < 0 or accepted > received:
        raise PermissionError('C28 helper returned an impossible errno or packet count')
    return {'errno': error, 'phase': phase, 'lease': lease,
        'listener_cookie': listener_cookie, 'received': received,
        'accepted': accepted}


def _exchange_source_c28(channel, request, expected_credentials, deadline_ns,
        check_actor, *, allow_helper_exit=False):
    """One correlated transport exchange; this proves framing only, not C28 success."""
    if (type(channel) is not socket.socket or channel.type & 15 != socket.SOCK_SEQPACKET or
            type(request) is not bytes or len(request) != _C28_REQUEST.size or
            type(expected_credentials) is not tuple or len(expected_credentials) != 3 or
            type(deadline_ns) is not int or not callable(check_actor)):
        raise TypeError('C28 exchange requires the retained seqpacket actor channel')
    channel.setblocking(False)
    retry_slot = struct.unpack_from('<H', request, 10)[0] in (
        _C28_RETRY_SLOT, _C28_ADOPT_SUCCESSOR)
    peer = _UCRED.unpack(channel.getsockopt(socket.SOL_SOCKET,
        socket.SO_PEERCRED, _UCRED.size))
    if peer != (os.getpid(), os.getuid(), os.getgid()):
        raise PermissionError('C28 channel SO_PEERCRED differs from the SDK creator')
    sent = False
    while not sent:
        if time.monotonic_ns() >= deadline_ns:
            raise TimeoutError('C28 request deadline expired before send')
        check_actor(deadline_ns)
        try:
            count = channel.sendmsg([request], [],
                getattr(socket, 'MSG_NOSIGNAL', 0) | getattr(socket, 'MSG_DONTWAIT', 0))
            if count != len(request):
                raise OSError(errno.EIO, 'short C28 command send has unknown outcome')
            sent = True
        except InterruptedError:
            continue
        except BlockingIOError:
            remaining = (deadline_ns - time.monotonic_ns()) / 1_000_000_000
            if remaining <= 0 or not select.select([], [channel], [], remaining)[1]:
                raise TimeoutError('C28 command send missed its absolute deadline')
    while True:
        if time.monotonic_ns() >= deadline_ns:
            raise TimeoutError('C28 reply deadline expired after command send; outcome unknown')
        # CLOSE can finish and exit before the SDK reaches this poll. The
        # exact socket credentials and correlated reply remain authoritative.
        if not allow_helper_exit:
            check_actor(deadline_ns)
        remaining = (deadline_ns - time.monotonic_ns()) / 1_000_000_000
        if not select.select([channel], [], [], remaining)[0]:
            raise TimeoutError('C28 helper reply missed its absolute deadline; outcome unknown')
        packet, ancillary, flags, _ = channel.recvmsg(_C28_REPLY_BYTES + 1,
            socket.CMSG_SPACE(_UCRED.size) + socket.CMSG_SPACE(4 * 16),
            getattr(socket, 'MSG_CMSG_CLOEXEC', 0) | getattr(socket, 'MSG_DONTWAIT', 0))
        credentials, received_fds, rights_seen, invalid = [], [], False, False
        for level, kind, payload in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(payload) == _UCRED.size:
                credentials.append(_UCRED.unpack(payload))
            elif level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                invalid |= rights_seen
                rights_seen = True
                values = array.array('i')
                usable = len(payload) - len(payload) % values.itemsize
                if usable:
                    values.frombytes(payload[:usable]); received_fds.extend(values)
                invalid |= usable != len(payload)
            else:
                invalid = True
        try:
            if (len(credentials) != 1 or invalid or
                    time.monotonic_ns() >= deadline_ns):
                raise PermissionError('C28 helper reply credentials/rights/deadline are invalid')
            reply = _decode_source_c28_reply(packet, request, credentials[0],
                expected_credentials, flags)
            if len(received_fds) != (2 if retry_slot and not reply['errno'] else 0):
                raise PermissionError('C28 reply has the wrong descriptor count')
            if time.monotonic_ns() >= deadline_ns:
                raise TimeoutError('C28 helper reply arrived after its immutable deadline')
            if not allow_helper_exit:
                check_actor(deadline_ns)
            if received_fds:
                reply['fds'] = tuple(received_fds)
                received_fds.clear()
            return reply
        finally:
            for fd in received_fds:
                os.close(fd)


def _capture_deadline(deadline_ns):
    if (type(deadline_ns) is not int or deadline_ns <= 0 or
            time.monotonic_ns() >= deadline_ns):
        raise TimeoutError('C22 build capture exceeded its immutable source deadline')


def _open_absolute_nofollow(path, flags, deadline_ns=None):
    """Open a fixed absolute path while refusing symlinked path components."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise PermissionError('C22 build capture path is not a canonical absolute path')
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            if deadline_ns is not None:
                _capture_deadline(deadline_ns)
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC |
                getattr(os, 'O_NOFOLLOW', 0), dir_fd=directory)
            os.close(directory)
            directory = child
        if deadline_ns is not None:
            _capture_deadline(deadline_ns)
        fd = os.open(path.parts[-1], flags | os.O_CLOEXEC |
            getattr(os, 'O_NOFOLLOW', 0), dir_fd=directory)
        try:
            if deadline_ns is not None:
                _capture_deadline(deadline_ns)
            return fd
        except BaseException:
            os.close(fd)
            raise
    finally:
        os.close(directory)


def _stable_hash_fd(fd, deadline_ns, limit):
    _capture_deadline(deadline_ns)
    before = os.fstat(fd)
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or
            before.st_nlink != 1 or before.st_size <= 0 or before.st_size > limit):
        raise PermissionError('C22 build capture input is not one bounded owned regular file')
    digest = hashlib.sha256()
    offset = 0
    while offset < before.st_size:
        _capture_deadline(deadline_ns)
        chunk = os.pread(fd, min(1024 * 1024, before.st_size - offset), offset)
        if not chunk:
            break
        digest.update(chunk)
        offset += len(chunk)
    after = os.fstat(fd)
    _capture_deadline(deadline_ns)
    if (offset != before.st_size or
            any(getattr(before, name) != getattr(after, name) for name in
                ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))):
        raise PermissionError('C22 build capture input changed while being read')
    return digest.hexdigest(), before


def _read_anchor(path, deadline_ns, limit, expected_sha256):
    fd = _open_absolute_nofollow(path, os.O_RDONLY | os.O_NONBLOCK,
        deadline_ns)
    try:
        digest, info = _stable_hash_fd(fd, deadline_ns, limit)
        if digest != expected_sha256:
            raise PermissionError('C22 build capture anchor digest mismatch')
        raw = os.pread(fd, info.st_size, 0)
        _capture_deadline(deadline_ns)
        if len(raw) != info.st_size or hashlib.sha256(raw).hexdigest() != expected_sha256:
            raise PermissionError('C22 build capture anchor was short-read')
        return raw
    finally:
        os.close(fd)


def _unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key in C22 build receipt')
        result[key] = value
    return result


def _elf_build_id(fd, size, deadline_ns):
    header = os.pread(fd, 64, 0)
    _capture_deadline(deadline_ns)
    if (len(header) != 64 or header[:4] != b'\x7fELF' or
            header[4:6] != b'\x02\x01'):
        raise PermissionError('C22 helper is not the pinned ELF64 little-endian artifact')
    phoff = struct.unpack_from('<Q', header, 32)[0]
    phentsize, phnum = struct.unpack_from('<HH', header, 54)
    if phentsize != 56 or phnum > 1024 or phoff + phentsize * phnum > size:
        raise PermissionError('C22 helper ELF program-header table is invalid')
    for index in range(phnum):
        _capture_deadline(deadline_ns)
        phdr = os.pread(fd, phentsize, phoff + index * phentsize)
        if len(phdr) != phentsize:
            raise PermissionError('C22 helper ELF program header is truncated')
        kind = struct.unpack_from('<I', phdr, 0)[0]
        file_offset = struct.unpack_from('<Q', phdr, 8)[0]
        # p_filesz is the fifth 64-bit word in Elf64_Phdr.
        file_size = struct.unpack_from('<Q', phdr, 32)[0]
        if kind != 4:
            continue
        if file_offset + file_size > size or file_size > 4 * 1024 * 1024:
            raise PermissionError('C22 helper ELF note segment is outside bounds')
        data = os.pread(fd, file_size, file_offset)
        _capture_deadline(deadline_ns)
        cursor = 0
        while cursor + 12 <= len(data):
            namesz, descsz, note_type = struct.unpack_from('<III', data, cursor)
            cursor += 12
            name_end = cursor + ((namesz + 3) & ~3)
            desc_start = name_end
            desc_end = desc_start + descsz
            next_note = desc_start + ((descsz + 3) & ~3)
            if next_note > len(data):
                break
            name = data[cursor:cursor + namesz]
            desc = data[desc_start:desc_end]
            if name == b'GNU\0' and note_type == 3:
                _capture_deadline(deadline_ns)
                return desc.hex()
            cursor = next_note
    raise PermissionError('C22 helper ELF has no GNU build ID')


def _verify_client_archive(fd, size, receipt_members, deadline_ns):
    if os.pread(fd, 8, 0) != b'!<arch>\n':
        raise PermissionError('C22 client archive has an invalid ar header')
    _capture_deadline(deadline_ns)
    cursor = 8
    found = {}
    string_table = b''
    while cursor + 60 <= size:
        _capture_deadline(deadline_ns)
        header = os.pread(fd, 60, cursor)
        if len(header) != 60 or header[58:60] != b'`\n':
            raise PermissionError('C22 client archive member header is malformed')
        try:
            name = header[:16].decode('ascii').strip()
            member_size = int(header[48:58].decode('ascii').strip())
        except (UnicodeDecodeError, ValueError) as error:
            raise PermissionError('C22 client archive member fields are malformed') from error
        data_offset = cursor + 60
        next_cursor = data_offset + member_size + (member_size & 1)
        if member_size < 0 or next_cursor > size:
            raise PermissionError('C22 client archive member exceeds bounded archive size')
        if name == '//':
            string_table = os.pread(fd, member_size, data_offset)
        resolved_name = name
        if name.startswith('/') and name[1:].isdigit():
            name_offset = int(name[1:])
            if name_offset >= len(string_table):
                raise PermissionError('C22 client archive long member name is invalid')
            name_end = string_table.find(b'/\n', name_offset)
            if name_end < 0:
                raise PermissionError('C22 client archive long member name is truncated')
            resolved_name = string_table[name_offset:name_end].decode('ascii') + '/'
        if resolved_name == 'socket-broker-client.c.o/':
            data = os.pread(fd, member_size, data_offset)
            if len(data) != member_size:
                raise PermissionError('C22 client archive object was short-read')
            found[resolved_name] = (member_size, hashlib.sha256(data).hexdigest())
        cursor = next_cursor
    if cursor != size:
        raise PermissionError('C22 client archive has trailing malformed bytes')
    _capture_deadline(deadline_ns)
    expected = {'socket-broker-client.c.o/': (92336,
        '064168dbba9c0ec32c736e9ed39c00ab8cc29a64496fa3e14508fdad3547beb9')}
    if found != expected or receipt_members != [{
            'name': 'socket-broker-client.c.o',
            'sha256': expected['socket-broker-client.c.o/'][1],
            'size': expected['socket-broker-client.c.o/'][0]}]:
        raise PermissionError('C22 client archive member differs from accepted build receipt')


class C22HelperBuildCapture:
    """One fixed-review C22 helper build capture; it grants no worker authority."""
    __slots__ = ('_fd', '_metadata', '_sha256', '_build_id', '_receipt_sha256',
        '_deadline_ns', '_consumed', '_sealed')

    def __setattr__(self, name, value):
        if getattr(self, '_sealed', False):
            raise AttributeError('C22 build capture fields are immutable')
        object.__setattr__(self, name, value)

    def __init__(self, token, fd, metadata, build_id, deadline_ns):
        if token is not _CAPTURE_TOKEN:
            raise TypeError('C22 build captures are created only by the fixed receipt validator')
        self._fd = fd
        self._metadata = metadata
        self._sha256 = bytes.fromhex(_HELPER_SHA256)
        self._build_id = build_id
        self._receipt_sha256 = bytes.fromhex(_RECEIPT_SHA256)
        self._deadline_ns = deadline_ns
        self._consumed = False
        self._sealed = True

    @property
    def sha256(self):
        return self._sha256

    @property
    def build_id(self):
        return self._build_id

    @property
    def receipt_sha256(self):
        return self._receipt_sha256

    @classmethod
    def capture(cls, deadline_ns):
        """Capture only the reviewed receipt/artifacts; callers supply no paths or digests."""
        _capture_deadline(deadline_ns)
        receipt_raw = _read_anchor(_RECEIPT_PATH, deadline_ns, 64 * 1024,
            _RECEIPT_SHA256)
        receipt = json.loads(receipt_raw, object_pairs_hook=_unique_json_object)
        _capture_deadline(deadline_ns)
        if (receipt.get('schema') != 'c22-helper-build-receipt-v1' or
                receipt.get('build_exit') != 0 or receipt.get('configure_exit') != 0 or
                receipt.get('binary_execution') != 'not run' or
                receipt.get('integration_head') != '594261e97604062d0772c29748d9aa2cfb668f98' or
                receipt.get('freeze_path') != str(_FREEZE_PATH) or
                receipt.get('freeze_sha256') != _FREEZE_SHA256 or
                receipt.get('config_fragment') != 'config/native-linux-bridge-selftests.config' or
                receipt.get('scope') != ('fresh host helper/client build only; helper not executed; '
                    'no native/Nginx/backend execution; not Source Origin/worker authority') or
                receipt.get('helper_elf', {}).get('path') != str(_HELPER_PATH) or
                receipt.get('helper_elf', {}).get('sha256') != _HELPER_SHA256 or
                receipt.get('client_archive', {}).get('path') != str(_ARCHIVE_PATH) or
                receipt.get('client_archive', {}).get('sha256') != _ARCHIVE_SHA256 or
                receipt.get('elf_build_id') != [f'Build ID: {_HELPER_BUILD_ID}']):
            raise PermissionError('C22 build receipt differs from the fixed reviewed recipe')
        build_argv = receipt.get('build_argv')
        if (not isinstance(build_argv, list) or '--target' not in build_argv or
                build_argv[build_argv.index('--target') + 1] != 'ker-nginx-owner-group-controller'):
            raise PermissionError('C22 build receipt does not name the reviewed helper target')
        if (build_argv[build_argv.index('--build') + 1] != str(_BUILD_ROOT / 'build') or
                '--verbose' not in build_argv):
            raise PermissionError('C22 build receipt uses an unsupported build recipe')
        configure_argv = receipt.get('configure_argv')
        required_configure = {
            '-S', '/home/hurricane/.local/state/ker-fstack-source-shell/integration-worktree',
            '-B', str(_BUILD_ROOT / 'build'), '-DBUILD_TESTING=ON',
            '-DKER_BUILD_FSTACK_NGINX_RUNTIME=ON', '-DKER_WITH_DPDK=ON',
            '-DKER_WITH_NATIVE_TCP=ON', '-DKER_FSTACK_NGINX_BINARY=',
        }
        if (not isinstance(configure_argv, list) or
                not required_configure <= set(configure_argv) or
                '--build' in configure_argv):
            raise PermissionError('C22 build receipt configure recipe differs from accepted host profile')
        compiled = receipt.get('compiled_objects')
        expected_sources = {str(_CLIENT_SOURCE), str(_HELPER_SOURCE)}
        if (not isinstance(compiled, list) or
                {entry.get('compile_command', {}).get('file') for entry in compiled
                    if isinstance(entry, dict)} != expected_sources):
            raise PermissionError('C22 build receipt source set differs from accepted target')
        for entry in compiled:
            command = entry['compile_command']
            if (command.get('directory') != str(_BUILD_ROOT / 'build') or
                    '-Wall -Wextra -Werror' not in command.get('command', '')):
                raise PermissionError('C22 compiled object lacks the reviewed host warning profile')
        freeze_raw = _read_anchor(_FREEZE_PATH, deadline_ns, 128 * 1024,
            _FREEZE_SHA256)
        freeze = json.loads(freeze_raw, object_pairs_hook=_unique_json_object)
        _capture_deadline(deadline_ns)
        if len(freeze.get('inputs', ())) != 85:
            raise PermissionError('C22 source freeze input count changed')
        frozen = {entry.get('path'): entry for entry in freeze['inputs']
            if isinstance(entry, dict)}
        for source, expected_digest in _SOURCE_HASHES.items():
            entry = frozen.get(source)
            if (not isinstance(entry, dict) or entry.get('resolved') != source or
                    entry.get('sha256') != expected_digest):
                raise PermissionError('C22 build source pin differs from accepted freeze')
            source_fd = _open_absolute_nofollow(source,
                os.O_RDONLY | os.O_NONBLOCK, deadline_ns)
            try:
                digest, info = _stable_hash_fd(source_fd, deadline_ns, 16 * 1024 * 1024)
                if (digest != expected_digest or info.st_size != entry.get('size') or
                        info.st_dev != entry.get('device') or info.st_ino != entry.get('inode')):
                    raise PermissionError('C22 build source changed since accepted freeze')
            finally:
                os.close(source_fd)
        archive_fd = _open_absolute_nofollow(_ARCHIVE_PATH,
            os.O_RDONLY | os.O_NONBLOCK, deadline_ns)
        try:
            archive_digest, archive_info = _stable_hash_fd(archive_fd, deadline_ns,
                16 * 1024 * 1024)
            archive = receipt['client_archive']
            if (archive_digest != _ARCHIVE_SHA256 or archive_info.st_dev != archive.get('device') or
                    archive_info.st_ino != archive.get('inode') or
                    archive_info.st_size != archive.get('size') or
                    stat.S_IMODE(archive_info.st_mode) != int(archive.get('mode'), 8)):
                raise PermissionError('C22 client archive differs from accepted build receipt')
            _verify_client_archive(archive_fd, archive_info.st_size,
                receipt.get('archive_members'), deadline_ns)
        finally:
            os.close(archive_fd)
        helper_fd = _open_absolute_nofollow(_HELPER_PATH,
            os.O_RDONLY | os.O_NONBLOCK, deadline_ns)
        try:
            helper_digest, helper_info = _stable_hash_fd(helper_fd, deadline_ns,
                _MAX_EXECUTABLE_BYTES)
            helper = receipt['helper_elf']
            if (helper_digest != _HELPER_SHA256 or not helper_info.st_mode & 0o111 or
                    helper_info.st_dev != helper.get('device') or
                    helper_info.st_ino != helper.get('inode') or
                    helper_info.st_size != helper.get('size') or
                    stat.S_IMODE(helper_info.st_mode) != int(helper.get('mode'), 8) or
                    _elf_build_id(helper_fd, helper_info.st_size, deadline_ns) != _HELPER_BUILD_ID):
                raise PermissionError('C22 helper ELF differs from accepted build receipt')
            os.lseek(helper_fd, 0, os.SEEK_SET)
            capture = cls(_CAPTURE_TOKEN, helper_fd,
                (helper_info.st_dev, helper_info.st_ino, helper_info.st_size,
                    helper_info.st_mtime_ns, helper_info.st_ctime_ns),
                _HELPER_BUILD_ID, deadline_ns)
            helper_fd = -1
            return capture
        finally:
            if helper_fd >= 0:
                os.close(helper_fd)

    def _verify_live(self, deadline_ns):
        if self._consumed or self._fd < 0:
            raise PermissionError('C22 build capture was already consumed or closed')
        if deadline_ns != self._deadline_ns:
            raise PermissionError('C22 build capture deadline differs from its profile')
        _capture_deadline(deadline_ns)
        digest, info = _stable_hash_fd(self._fd, deadline_ns, _MAX_EXECUTABLE_BYTES)
        if (digest != _HELPER_SHA256 or
                (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) !=
                self._metadata):
            raise PermissionError('retained C22 helper capture changed before transfer')

    def _take_helper_fd(self, deadline_ns):
        self._verify_live(deadline_ns)
        fd = self._fd
        # Keep the capture as owner until every operation that can fail has
        # completed.  The caller owns the FD only after this seek succeeds.
        os.lseek(fd, 0, os.SEEK_SET)
        _capture_deadline(deadline_ns)
        object.__setattr__(self, '_fd', -1)
        object.__setattr__(self, '_consumed', True)
        return fd, self._metadata, self.sha256

    def close(self):
        if self._fd >= 0:
            os.close(self._fd)
            object.__setattr__(self, '_fd', -1)


class C22ProviderCleanupPending(RuntimeError):
    """Construction failed while its helper remains owned and unsettled."""
    def __init__(self, provider, primary_error, cleanup_error):
        self.provider = provider
        self.primary_error = primary_error
        self.cleanup_error = cleanup_error
        super().__init__('C22 provider construction failed; bounded helper cleanup is pending')


class SourceInitialListenerRetirementProof:
    """Provider-minted proof after exact C28 retire and C34 VERIFY receipts."""
    __slots__ = ('token', 'provider', 'context', 'old_exit', 'park',
        'c28_sequence', 'c28_operation', 'c28_deadline_ns', 'c28_request',
        'c28_response', 'c34_raw', 'c34_result', 'created_ns')

    def __init__(self, token, provider, context, old_exit, park, command,
            c34_raw, c34_result, created_ns):
        if token is not _INITIAL_RETIREMENT_PROOF_TOKEN:
            raise TypeError('initial listener retirement proof is provider-owned')
        names = self.__slots__
        values = (token, provider, context, old_exit, park, command[0],
            command[1], command[2], command[3], MappingProxyType(dict(command[4])),
            bytes(c34_raw), MappingProxyType(dict(c34_result)), created_ns)
        for name, value in zip(names, values):
            object.__setattr__(self, name, value)

    def __setattr__(self, _name, _value):
        raise AttributeError('initial listener retirement proof is immutable')


def _identity(pid):
    data = Path(f'/proc/{pid}/stat').read_text(encoding='ascii')
    close = data.rfind(')')
    if close < 0:
        raise RuntimeError('malformed provider process stat')
    fields = data[close + 2:].split()
    if len(fields) <= 19:
        raise RuntimeError('short provider process stat')
    start = int(fields[19], 10)
    info = os.stat(f'/proc/{pid}')
    return pid, info.st_uid, info.st_gid, start


def _pidfd_alive(pidfd):
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR |
        select.POLLNVAL)
    events = poller.poll(0)
    if not events:
        return True
    if events[0][1] & select.POLLNVAL:
        raise OSError(errno.EBADF, 'provider pidfd is invalid')
    if events[0][1] & select.POLLERR:
        raise OSError(errno.EIO, 'provider pidfd poll failed')
    return False


def _validate_broker_fifo(fd, description):
    info = os.fstat(fd)
    status_flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    descriptor_flags = fcntl.fcntl(fd, fcntl.F_GETFD)
    if (not stat.S_ISFIFO(info.st_mode) or status_flags & os.O_ACCMODE != os.O_WRONLY or
            not status_flags & os.O_NONBLOCK or not descriptor_flags & fcntl.FD_CLOEXEC):
        raise PermissionError(f'{description} is not a write-only nonblocking FIFO capability')
    return info


def _open_pinned_executable(path, deadline_ns):
    flags = (os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK |
        getattr(os, 'O_NOFOLLOW', 0))
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or
                before.st_nlink != 1 or not before.st_mode & 0o111 or
                before.st_size <= 0 or before.st_size > _MAX_EXECUTABLE_BYTES):
            raise PermissionError('C22 provider binary is not one owned executable file')
        digest = hashlib.sha256()
        offset = 0
        while True:
            if time.monotonic_ns() >= deadline_ns:
                raise TimeoutError('C22 provider hash exceeded the source grant')
            chunk = os.pread(fd, min(1024 * 1024, before.st_size - offset + 1), offset)
            if not chunk:
                break
            offset += len(chunk)
            if offset > before.st_size:
                raise PermissionError('C22 provider binary grew while hashing')
            digest.update(chunk)
        after = os.fstat(fd)
        if time.monotonic_ns() >= deadline_ns:
            raise TimeoutError('C22 provider hash exceeded the source grant')
        if (offset != before.st_size or any(getattr(before, name) != getattr(after, name)
                for name in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))):
            raise PermissionError('C22 provider binary changed while hashing')
        os.lseek(fd, 0, os.SEEK_SET)
        return fd, (before.st_dev, before.st_ino, before.st_size,
            before.st_mtime_ns, before.st_ctime_ns), digest.digest()
    except BaseException:
        os.close(fd)
        raise


def _hash_proc_executable(pid, deadline_ns):
    fd = os.open(f'/proc/{pid}/exe', os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or
                before.st_size > _MAX_EXECUTABLE_BYTES):
            raise PermissionError('C22 helper executable size/type is outside bound')
        digest = hashlib.sha256()
        offset = 0
        while True:
            if time.monotonic_ns() >= deadline_ns:
                raise TimeoutError('C22 helper identity hash exceeded the source grant')
            chunk = os.pread(fd, min(1024 * 1024, before.st_size - offset + 1), offset)
            if not chunk:
                break
            offset += len(chunk)
            if offset > before.st_size:
                raise PermissionError('C22 helper executable grew while hashing')
            digest.update(chunk)
        after = os.fstat(fd)
        if time.monotonic_ns() >= deadline_ns:
            raise TimeoutError('C22 helper identity hash exceeded the source grant')
        if (offset != before.st_size or
                (before.st_dev, before.st_ino, before.st_size,
                 before.st_mtime_ns, before.st_ctime_ns) !=
                (after.st_dev, after.st_ino, after.st_size,
                 after.st_mtime_ns, after.st_ctime_ns)):
            raise PermissionError('provider executable changed while hashing')
        return (before.st_dev, before.st_ino), digest.digest()
    finally:
        os.close(fd)


def _source_listener_tuple(context):
    """Derive the rt01 listener from the exact Origin-validated config bytes."""
    origin = getattr(getattr(context, 'owner_live', None), '__self__', None)
    origin_module = sys.modules.get(type(origin).__module__) if origin is not None else None
    canonical_origin = Path(__file__).with_name('nginx_source_origin.py').resolve(strict=True)
    old_launch = (origin_module is not None and
        type(origin) is getattr(origin_module, 'OriginalShellLaunch', None))
    private_launch = (origin_module is not None and
        type(origin) is getattr(origin_module, 'PrivateC34OriginalShellLaunch', None))
    if (origin is None or origin_module is None or
            Path(getattr(origin_module, '__file__', '')).resolve(strict=True) != canonical_origin or
            not (old_launch or private_launch) or getattr(origin, 'context', None) is not context or
            type(context) is not origin_module.bootstrap.SourceBootstrapSupervisor):
        raise PermissionError('C22 provider requires the exact accepted Origin context')
    if private_launch:
        artifacts = sys.modules.get('_ker_nginx_source_c34_artifacts')
        capture = getattr(origin, 'c34_artifact_capture', None)
        helper = getattr(capture, 'helper_capture', None)
        if (artifacts is None or type(capture) is not getattr(artifacts, 'PrivateC34ArtifactCapture', None) or
                capture.profile_id != 'NEWC34_INTEROP' or
                type(helper) is not getattr(artifacts, 'PrivateC34HelperCapture', None) or
                helper.source_command_abi != _C28_SOURCE_COMMAND_ABI):
            raise PermissionError('private C34 listener is not bound to the fixed ABI1 capture')
        capture.verify(context.deadline_ns)
    proof = getattr(origin, 'origin_proof', None)
    cycle = getattr(context, 'initial_cycle_proof', None)
    artifact = getattr(origin, 'artifact_binding', None)
    if proof is None or cycle is None or artifact is None:
        raise PermissionError('C22 provider has no authenticated origin/cycle artifact proof')
    deadline_ns = min(context.deadline_ns, origin.deadline_ns)
    origin.live_supervisor(deadline_ns)
    origin._original_artifacts_live(deadline_ns)
    context.live()
    if (cycle.adapter_cycle_serial != proof.adapter_cycle_serial or
            cycle.opaque_cycle_token != proof.opaque_cycle_token or
            cycle.config_sha256.hex() != artifact.config_sha256 or
            cycle.ini_sha256.hex() != artifact.ini_sha256 or
            context.expected_config_sha256.hex() != artifact.config_sha256 or
            context.expected_ini_sha256.hex() != artifact.ini_sha256 or
            context.deadline_ns != origin.deadline_ns or
            (context.epoch, context.nonce) != (origin.epoch, origin.nonce)):
        raise PermissionError('C22 provider proof differs from accepted OriginalShellLaunch')
    config = getattr(artifact, 'config', None)
    data = getattr(config, 'data', None)
    if (type(data) is not bytes or
            hashlib.sha256(data).hexdigest() != artifact.config_file_sha256):
        raise PermissionError('C22 listener input lacks the exact Origin-validated config')
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError as error:
        raise PermissionError('Origin config is not UTF-8') from error
    directives = re.findall(r'(?m)^[ \t]*listen[ \t]+([^;]+);[ \t]*$', text)
    if directives != ['80']:
        raise PermissionError('C22 provider requires the single parsed rt01 listen 80 directive')
    # Origin accepts the worker only after the original master completed C22
    # validate_profile() over its live ngx_listening_t. The exact config bytes
    # and the pinned Linux Nginx build bind this parsed profile to this tuple.
    return '0.0.0.0', 80, 511


class SourceShellC22Provider:
    """Run and pin one real C22 helper for one accepted source context."""
    def __init__(self, context, broker_readiness, helper_capture):
        if threading.current_thread() is not threading.main_thread():
            raise PermissionError('C22 provider must be launched by the SDK main thread')
        if (not getattr(context, 'shell_mode', False) or
                type(getattr(context, 'nonce', None)) is not bytes or
                len(context.nonce) != 16 or not any(context.nonce) or
                type(getattr(context, 'epoch', None)) is not int or context.epoch <= 0):
            raise PermissionError('C22 provider needs one typed source-shell session')
        if type(self) is SourceShellC34InteropProvider:
            import sys
            c34_module = sys.modules.get('_ker_nginx_source_c34_artifacts')
            if (c34_module is None or
                    Path(c34_module.__file__).resolve(strict=True) !=
                        Path(__file__).with_name('nginx_source_c34_artifact_provider.py').resolve(strict=True) or
                    type(helper_capture) is not c34_module.PrivateC34HelperCapture or
                    helper_capture.source_command_abi != _C28_SOURCE_COMMAND_ABI):
                raise TypeError('private C34 provider requires its exact ABI1 helper capture')
        elif type(helper_capture) is not C22HelperBuildCapture:
            raise TypeError('C22 provider requires the captured fixed-receipt build artifact')
        origin = getattr(getattr(context, 'owner_live', None), '__self__', None)
        if (origin is None or getattr(origin, 'context', None) is not context or
                getattr(context, 'original_supervisor_identity', None) is None):
            raise PermissionError('C22 provider is not bound to the accepted OriginalShellLaunch')
        fault = getattr(helper_capture, 'source_fault', None)
        retry_allowed = type(self) is SourceShellC34InteropProvider and fault == 'flip_fail_once'
        source_case = getattr(origin, 'source_case', None)
        successor_flag = {
            'rv9': 'KER_NGINX_SOURCE_SUCCESSOR_ENABLE',
            'rt25': 'KER_NGINX_SOURCE_UPGRADE_ENABLE',
        }.get(source_case)
        successor_allowed = (type(self) is SourceShellC34InteropProvider and
            successor_flag is not None and fault is None and
            origin.environment.get(successor_flag) == '1')
        if successor_allowed != getattr(context, 'allow_successor', False):
            raise PermissionError('C22 successor helper requires its captured original source context')
        if (retry_allowed != getattr(context, 'allow_abort_retry', False) or
                (retry_allowed and (
                    getattr(origin.c34_artifact_capture, 'source_fault', None) != fault or
                    origin.environment.get('KER_NGINX_SOURCE_ABORT_RETRY_ENABLE') != '1'))):
            raise PermissionError('C22 retry helper requires the accepted fault launch and context')
        self.listener = _source_listener_tuple(context)
        if (not getattr(broker_readiness, 'ready', False) or
                getattr(broker_readiness, 'stopped', True) or
                type(getattr(broker_readiness, 'nonce', None)) is not bytes or
                len(broker_readiness.nonce) != 16 or not any(broker_readiness.nonce) or
                type(getattr(broker_readiness, 'epoch', None)) is not int or
                broker_readiness.epoch <= 0):
            raise PermissionError('C22 C34 watch needs the exact live broker-readiness session')
        self.context = context
        self.broker_readiness = broker_readiness
        self.source_nonce = context.nonce
        self.source_epoch = context.epoch
        self.broker_nonce = broker_readiness.nonce
        self.broker_epoch = broker_readiness.epoch
        self.slots = [-1, -1]
        self.watch_fd = -1
        self._used_slots = set()
        self._first_candidate_pending_watch = None
        self._first_candidate_pending_ready = None
        self._first_candidate_pending_error = None
        self.slot_identities = None
        self._verify_sequence = 0
        self._watch_fd_identity = None
        self._initial_retire_started_ns = None
        self._initial_retire_deadline_ns = None
        self._initial_retire_attempts = 0
        self._initial_retire_next_retry_ns = 0
        self._initial_retire_ack = None
        self._initial_retire_command = None
        self._initial_verify_started = False
        self._initial_retirement_proof = None
        self.process = None
        self.pidfd = -1
        self._helper_fd = -1
        self.start_ticks = 0
        self._channel = None
        self._closed = False
        # The reviewed build capture does not yet attest the new command ABI.
        # It remains None until a fresh helper receipt explicitly opts in.
        self._source_command_abi = getattr(helper_capture, 'source_command_abi', None)
        self._private_c34_helper_capture = (helper_capture
            if type(self) is SourceShellC34InteropProvider else None)
        self._source_command_sequence = 0
        self._source_command_outstanding = None
        self._source_command_unresolved = False
        self._source_park_deadline_ns = None
        self._source_park_result = None
        self._source_park_evidence = None
        self._source_abort_result = None
        self._source_retry_allowed = retry_allowed
        self._source_successor_allowed = successor_allowed
        self._successor_adoption_epoch = 1
        self._successor_watch = None
        self._successor_slot = -1
        self._successor_retire_by = None
        self._successor_retire_ack = None
        self._successor_retire_receipt = None
        self._source_retry_cookie = None
        self._source_retry_slot_attempted = False
        self._source_commit_result = None
        self._source_route_receipt_consumed = False
        self._source_committed = False
        self._source_retired_initial_listener = False
        self._source_close_authorized = None
        self._source_close_commanded = False
        if type(self) is SourceShellC34InteropProvider:
            existing_gate = getattr(broker_readiness,
                '_private_initial_retirement_provider', None)
            if existing_gate not in (None, self):
                raise PermissionError('broker is already bound to another private initial retirement provider')
            # Bind before helper launch or worker authentication so no private
            # shutdown path can issue C34 STOP without the later typed proof.
            broker_readiness._private_initial_retirement_provider = self

        try:
            self._helper_fd, metadata, digest = helper_capture._take_helper_fd(
                context.deadline_ns)
            if digest != helper_capture.sha256 or helper_capture.build_id != _HELPER_BUILD_ID and type(helper_capture) is C22HelperBuildCapture:
                raise PermissionError('C22 provider capture differs from its fixed ELF receipt')
            broker_path = getattr(origin, 'environment', {}).get('KER_SOCKET_BROKER_PATH')
            if (type(broker_path) is not str or not broker_path.startswith('/') or
                    broker_path != origin.artifact_binding.broker_path):
                raise PermissionError('C22 provider has no Origin-bound broker path')
            parent, child = socket.socketpair(socket.AF_UNIX,
                socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
            self._channel = parent
            parent.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            parent_pidfd = os.pidfd_open(os.getpid(), 0)
            parent_start = _identity(os.getpid())[3]
            mode = ('--source-shell-abort-retry' if retry_allowed else
                '--source-shell-successive' if successor_allowed else '--source-shell')
            command = [f'/proc/self/fd/{self._helper_fd}', broker_path,
                str(child.fileno()), mode, self.listener[0],
                str(self.listener[1]), str(self.listener[2]), context.nonce.hex(),
                str(context.epoch), broker_readiness.nonce.hex(),
                str(broker_readiness.epoch), str(os.getpid()), str(parent_start),
                str(context.deadline_ns), str(parent_pidfd)]
            if time.monotonic_ns() >= context.deadline_ns:
                raise TimeoutError('C22 provider launch exceeded the source grant')
            self.process = subprocess.Popen(command,
                executable=f'/proc/self/fd/{self._helper_fd}',
                stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, close_fds=True,
                pass_fds=(child.fileno(), self._helper_fd, parent_pidfd))
            self._helper_metadata = metadata
            self._helper_sha256 = digest
            self.pidfd = os.pidfd_open(self.process.pid, 0)
            actor = _identity(self.process.pid)
            self.start_ticks = actor[3]
            self._check_actor(context.deadline_ns)
            self._receive_bundle(min(context.deadline_ns,
                time.monotonic_ns() + _STARTUP_NS))
            self._check_actor(context.deadline_ns)
        except BaseException as primary_error:
            try:
                self.close(abort=True)
            except BaseException as cleanup_error:
                if not self._closed:
                    raise C22ProviderCleanupPending(self, primary_error,
                        cleanup_error) from primary_error
                try:
                    primary_error.c22_cleanup_error = cleanup_error
                except BaseException:
                    pass
            raise
        finally:
            if 'child' in locals():
                child.close()
            if 'parent_pidfd' in locals():
                os.close(parent_pidfd)

    def _check_actor(self, deadline_ns=None):
        if deadline_ns is None:
            deadline_ns = self.context.deadline_ns
        if time.monotonic_ns() >= deadline_ns:
            raise TimeoutError('C22 provider actor validation exceeded the source grant')
        if self.process is None or self.pidfd < 0:
            raise ProcessLookupError('C22 provider has no pinned helper actor')
        actor = _identity(self.process.pid)
        exe_identity, exe_digest = _hash_proc_executable(self.process.pid, deadline_ns)
        held = os.fstat(self._helper_fd)
        if (not _pidfd_alive(self.pidfd) or actor[3] != self.start_ticks or
                exe_identity != self._helper_metadata[:2] or
                (held.st_dev, held.st_ino) != self._helper_metadata[:2] or
                exe_digest != self._helper_sha256):
            raise PermissionError('C22 provider helper identity changed')

    def _receive_bundle(self, deadline_ns):
        grant_deadline = getattr(self.context, 'deadline_ns', 0)
        if (type(deadline_ns) is not int or type(grant_deadline) is not int or
                deadline_ns > grant_deadline):
            raise PermissionError('C22 handshake deadline exceeds the immutable source grant')
        if time.monotonic_ns() >= deadline_ns:
            raise TimeoutError('C22 provider handshake expired')
        ready, _, _ = select.select([self._channel], [], [],
            max(0, (deadline_ns - time.monotonic_ns()) / 1_000_000_000))
        if not ready:
            raise TimeoutError('C22 provider did not send its capability bundle')
        packet, ancillary, flags, _ = self._channel.recvmsg(_MAX_RECORD,
            socket.CMSG_SPACE(_UCRED.size) + socket.CMSG_SPACE(4 * 4),
            getattr(socket, 'MSG_CMSG_CLOEXEC', 0))
        creds, received, invalid = [], [], False
        for level, kind, payload in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(payload) == _UCRED.size:
                creds.append(_UCRED.unpack(payload))
            elif level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                usable = len(payload) - len(payload) % array.array('i').itemsize
                if usable:
                    values = array.array('i'); values.frombytes(payload[:usable])
                    received.extend(values)
                invalid |= usable != len(payload)
            else:
                invalid = True
        received_ns = time.monotonic_ns()
        self._last_bundle_attempt = {
            'record': bytes(packet),
            'flags': flags,
            'received_ns': received_ns,
            'deadline_ns': deadline_ns,
            'credentials': tuple(creds),
            'ancillary': tuple((level, kind, bytes(payload))
                for level, kind, payload in ancillary),
            'received_fd_count': len(received),
            'fd_metadata': tuple(self._fd_diagnostic(fd) for fd in received),
        }
        try:
            allowed_flags = getattr(socket, 'MSG_CMSG_CLOEXEC', 0)
            if (invalid or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or
                    flags & ~allowed_flags or received_ns >= deadline_ns or
                    len(packet) != _RECORD.size or len(creds) != 1 or len(received) != 3 or
                    creds[0] != (self.process.pid, os.getuid(), os.getgid())):
                raise PermissionError('C22 provider record or SCM_RIGHTS bundle is malformed')
            peer = _UCRED.unpack(self._channel.getsockopt(socket.SOL_SOCKET,
                socket.SO_PEERCRED, _UCRED.size))
            if peer != (os.getpid(), os.getuid(), os.getgid()):
                raise PermissionError('C22 provider channel was not created by this SDK process')
            fields = _RECORD.unpack(packet)
            (magic, version, size, source_epoch, broker_epoch, source_nonce,
                broker_nonce, address, port, backlog, *slot_ids) = fields
            if (magic != _MAGIC or version != _VERSION or size != _RECORD.size or
                    (source_epoch, source_nonce) != (self.source_epoch, self.source_nonce) or
                    (broker_epoch, broker_nonce) != (self.broker_epoch, self.broker_nonce) or
                    (address, port, backlog) != (0, 80, 511) or
                    time.monotonic_ns() >= deadline_ns):
                raise PermissionError('C22 provider capability record does not match both sessions')
            for index, fd in enumerate(received[:2]):
                info = _validate_broker_fifo(fd, 'C22 slot')
                expected = tuple(slot_ids[index * 2:index * 2 + 2])
                if (info.st_uid != os.geteuid() or
                        (info.st_dev, info.st_ino) != expected):
                    raise PermissionError('C22 slot FD differs from the provider record')
            watch = received[2]
            watch_info = _validate_broker_fifo(watch, 'C34 generation-watch')
            if watch_info.st_uid != os.geteuid():
                raise PermissionError('C34 generation-watch owner differs from SDK UID')
            if time.monotonic_ns() >= deadline_ns:
                raise TimeoutError('C22 provider descriptor validation exceeded the grant')
            self._last_received_bundle = {
                'record': bytes(packet),
                'credentials': tuple(creds[0]),
                'fds': tuple((os.fstat(fd).st_dev, os.fstat(fd).st_ino,
                    os.fstat(fd).st_mode,
                    fcntl.fcntl(fd, fcntl.F_GETFL),
                    fcntl.fcntl(fd, fcntl.F_GETFD)) for fd in received),
            }
            if time.monotonic_ns() >= deadline_ns:
                self._last_received_bundle = None
                raise TimeoutError('C22 provider acceptance exceeded the immutable grant')
            self.slots = received[:2]
            self.watch_fd = watch
            watch_status = fcntl.fcntl(watch, fcntl.F_GETFL)
            watch_descriptor = fcntl.fcntl(watch, fcntl.F_GETFD)
            self._watch_fd_identity = (watch, watch_info.st_dev, watch_info.st_ino,
                watch_info.st_mode, watch_status, watch_descriptor)
            self.slot_identities = (tuple(slot_ids[:2]), tuple(slot_ids[2:4]))
            received = []
        finally:
            for fd in received:
                os.close(fd)

    @staticmethod
    def _fd_diagnostic(fd):
        try:
            info = os.fstat(fd)
            return (info.st_dev, info.st_ino, info.st_mode,
                fcntl.fcntl(fd, fcntl.F_GETFL),
                fcntl.fcntl(fd, fcntl.F_GETFD))
        except OSError as error:
            return ('error', error.errno)

    def _slot_index(self, packet):
        record = self.context._unpack_request(packet, 1, 1)
        key = (record[9], record[8])
        if key == (0, 0):
            index = 0
        elif key == (1, 1):
            index = 1
        else:
            raise PermissionError('C22 provider only covers original and first committed HUP slots')
        if index in self._used_slots:
            raise PermissionError('C22 source slot was already delegated')
        return index

    def reply_worker(self, channel, packet, credentials, relay):
        """Pass an exact C22 slot through the existing source worker grant."""
        if self._closed or self.context is None:
            raise RuntimeError('C22 provider is closed')
        if getattr(self.context, 'control_only', False) is True:
            raise OSError(errno.ENOTSUP,
                'generic source worker grants remain closed during control-only bootstrap')
        self._check_actor()
        index = self._slot_index(packet)
        # A reply attempt is one-shot even if the existing grant send is lost.
        self._used_slots.add(index)
        result = self.context.reply_worker(channel, packet, credentials,
            self.slots[index], relay)
        watch, ready = result
        if ((watch['source_epoch'], watch['generation']) != ((0, 0) if index == 0 else (1, 1)) or
                (watch['slot_device'], watch['slot_inode']) != self.slot_identities[index]):
            # The worker grant itself already consumed authority; report an
            # unresolved mismatch rather than trying to delegate again.
            ready.close()
            raise PermissionError('source worker grant no longer matches its C22 slot')
        return watch, ready

    def reply_first_candidate_worker(self, controller, grant, channel,
            packet, credentials, relay, grant_deadline_ns):
        """Consume only the Controller's exact first-candidate capability."""
        if threading.current_thread() is not threading.main_thread():
            raise PermissionError('first candidate grants require the SDK main thread')
        if self._closed or self.context is None or self.broker_readiness is None:
            raise RuntimeError('C22 provider is closed or unbound')
        controller_module = sys.modules.get('_ker_nginx_source_shell_controller')
        if (controller_module is None or type(controller) is not getattr(
                controller_module, 'SourceShellController', None) or
                self.context.control_only is not True):
            raise OSError(errno.ENOTSUP,
                'first candidate grant requires the canonical control-only controller')
        if (type(grant_deadline_ns) is not int or
                time.monotonic_ns() >= grant_deadline_ns or
                grant_deadline_ns > self.context.deadline_ns):
            raise TimeoutError('first candidate worker request exceeded its immutable grant')
        index = self._slot_index(packet)
        if index != 1 or self._used_slots != {0}:
            raise PermissionError('first candidate grant requires the unused slot-1 FIFO')
        self._check_actor(grant_deadline_ns)
        controller._validate_first_candidate_worker_grant(grant, self,
            channel, packet, credentials, relay, grant_deadline_ns)
        if (type(grant_deadline_ns) is not int or
                time.monotonic_ns() >= grant_deadline_ns or
                grant_deadline_ns > self.context.deadline_ns):
            raise TimeoutError('first candidate grant expired before slot-1 consumption')
        # Burn slot 1 before Context's nonblocking SCM_RIGHTS attempt. Errors
        # after this point are unresolved and cannot be retried with a new key.
        self._used_slots.add(1)
        try:
            watch, ready = self.context.reply_first_candidate_worker(channel,
                packet, credentials, self, relay, grant_deadline_ns, controller, grant)
            controller._first_candidate_worker_pending = True
            controller._first_candidate_pending_watch = watch
            controller._first_candidate_pending_ready = ready
            self._first_candidate_pending_watch = watch
            self._first_candidate_pending_ready = ready
            if ((watch['source_epoch'], watch['generation']) != (1, 1) or
                    (watch['slot_device'], watch['slot_inode']) != self.slot_identities[1]):
                raise PermissionError('first candidate source grant changed its retained slot/cycle')
        except BaseException as error:
            controller.unresolved = True
            controller._first_candidate_worker_pending = True
            controller._first_candidate_pending_error = error
            self._first_candidate_pending_error = error
            # Keep the exact capability and any Context-retained worker/READY
            # descriptors anchored until the normal settlement path exists.
            raise
        return watch, ready

    def reply_initial_worker(self, channel, packet, credentials, relay,
            grant_deadline_ns):
        """Pass only the unused original (0, 0) FIFO through the narrow phase."""
        if self._closed or self.context is None or self.broker_readiness is None:
            raise RuntimeError('C22 provider is closed or unbound')
        if (type(grant_deadline_ns) is not int or
                time.monotonic_ns() >= grant_deadline_ns or
                grant_deadline_ns > self.context.deadline_ns):
            raise TimeoutError('initial worker request exceeded its immutable grant deadline')
        self._check_actor(grant_deadline_ns)
        index = self._slot_index(packet)
        if index != 0:
            self._used_slots.add(index)
            raise PermissionError('control-only provider can delegate only original slot (0, 0)')
        # Consume before validation/send; a failed initial attempt cannot be
        # retried with a different actor or C22 capability.
        self._used_slots.add(index)
        watch, ready = self.context.reply_initial_worker(
            channel, packet, credentials, self, relay, grant_deadline_ns)
        if ((watch['source_epoch'], watch['generation']) != (0, 0) or
                (watch['slot_device'], watch['slot_inode']) != self.slot_identities[0]):
            ready.close()
            raise PermissionError('initial source worker grant changed its C22 slot identity')
        return watch, ready

    def begin_c34_verify(self, sequence):
        if type(self) is SourceShellC34InteropProvider:
            if (self._initial_retire_ack is None or
                    self._initial_verify_started or sequence != 1 or
                    self._initial_retire_command is None):
                raise PermissionError('private C34 VERIFY requires the one actual C28 retirement ACK')
            self._initial_verify_started = True
        if (self._closed or self.watch_fd < 0 or type(sequence) is not int or
                sequence != self._verify_sequence + 1 or
                (self.broker_readiness.nonce, self.broker_readiness.epoch) !=
                    (self.broker_nonce, self.broker_epoch)):
            raise PermissionError('C34 generation-watch request is stale or out of sequence')
        self._check_actor()
        remaining = (self.context.deadline_ns - time.monotonic_ns()) / 1_000_000_000
        if remaining <= 0:
            raise TimeoutError('C34 verification exceeded the immutable source grant')
        watch_fd = self.watch_fd
        if getattr(self, '_source_park_epoch', 1) == 2:
            watch_fd = self._initial_retirement_watch()[0]
        duplicate = os.dup(watch_fd)
        try:
            self.broker_readiness.begin_verify(duplicate, sequence,
                min(6.0, remaining))
        except BaseException:
            os.close(duplicate)
            raise
        self._verify_sequence = sequence

    def _source_c28_command(self, operation, deadline_ns):
        if getattr(self, '_source_command_abi', None) != _C28_SOURCE_COMMAND_ABI:
            raise OSError(errno.ENOTSUP,
                'pinned C22 build receipt does not authorize the quiet C28 command ABI')
        if (operation in (_C28_RETRY_ADOPT, _C28_RETRY_SLOT) and
                not getattr(self, '_source_retry_allowed', False)):
            raise OSError(errno.ENOTSUP, 'C28 retry requires the fault-only helper mode')
        if (operation == _C28_ADOPT_SUCCESSOR and
                not self._source_successor_allowed):
            raise OSError(errno.ENOTSUP, 'C28 successor requires the captured repeated source profile')
        if (self._source_command_unresolved or self._source_command_outstanding is not None or
                self._closed or self._channel is None):
            raise OSError(errno.EBUSY,
                'C22 command channel has an unresolved one-shot operation')
        if (type(deadline_ns) is not int or time.monotonic_ns() >= deadline_ns or
                deadline_ns > self.context.deadline_ns):
            raise TimeoutError('C28 operation exceeds the immutable source grant')
        bundle = getattr(self, '_last_received_bundle', {}).get('record')
        if type(bundle) is not bytes or len(bundle) != _RECORD.size:
            raise PermissionError('C28 command lacks the exact retained C22 bundle')
        self._check_actor(deadline_ns)
        self._source_command_sequence += 1
        sequence = self._source_command_sequence
        request = _encode_source_c28_request(operation, sequence, deadline_ns, bundle)
        self._source_command_outstanding = (sequence, operation, deadline_ns)
        try:
            response = _exchange_source_c28(self._channel, request,
                (self.process.pid, os.getuid(), os.getgid()), deadline_ns,
                self._check_actor, allow_helper_exit=(operation == _C28_CLOSE))
        except BaseException:
            self._source_command_unresolved = True
            raise
        self._source_command_outstanding = None
        if response['errno']:
            if operation == _C28_RETIRE_INITIAL_LISTENER and response['errno'] == errno.EAGAIN:
                if any(response.get(name) != 0 for name in
                        ('phase', 'lease', 'listener_cookie', 'received', 'accepted')):
                    self._source_command_unresolved = True
                    raise PermissionError('C28 RETIRE EAGAIN has a malformed nonzero reply tail')
                self._source_last_command = (sequence, operation, deadline_ns,
                    bytes(request), dict(response))
                return response
            # A returned native error can follow a partial/unknown cutover.
            # Keep all capabilities pinned; caller must quarantine/STOP.
            self._source_command_unresolved = True
            raise OSError(response['errno'],
                f'C28 helper returned error for operation {operation}')
        self._source_last_command = (sequence, operation, deadline_ns,
            bytes(request), dict(response))
        return response

    def park_source_group(self, deadline_ns, *, source_epoch=1):
        if source_epoch == 2 and not getattr(self, '_source_successor_allowed', False):
            if (getattr(self, '_source_park_epoch', 1) != 1 or
                    self._source_park_evidence is None or
                    self._source_abort_result is None or
                    getattr(self, '_source_retry_slot_delivered', False) is not True or
                    self._source_retry_cookie != getattr(self.context, '_native_retry_cookie', None) or
                    self.context._completed_master_barriers != {(1, 5), (1, 9)} or
                    self.context._activated_workers != {(1, 1), (2, 1)} or
                    (2, 5) not in self.context._master_barriers or
                    self._source_committed or self._source_route_receipt_consumed):
                raise PermissionError('retry C28 PARK lacks the adopted, activated second plan')
        elif ((source_epoch != 1 and not (getattr(self, '_source_successor_allowed', False)
                and source_epoch == self._successor_adoption_epoch)) or
                self._source_park_deadline_ns is not None):
            raise OSError(errno.EALREADY, 'source C28 PARK is one-shot')
        if (type(deadline_ns) is not int or
                deadline_ns > min(self.context.deadline_ns,
                    time.monotonic_ns() + _C28_CUTOVER_BUDGET_NS)):
            raise TimeoutError('C28 PARK deadline exceeds the original 100 ms operation budget')
        response = self._source_c28_command(_C28_PARK, deadline_ns)
        if (response['phase'] != _C28_PHASE_PREPARED or not response['lease'] or
                response['accepted'] != 0):
            self._source_command_unresolved = True
            raise PermissionError('C28 PARK returned no PREPARED lease or had accepted packets')
        self._source_park_epoch = source_epoch
        self._source_park_deadline_ns = deadline_ns
        self._source_park_result = response
        if source_epoch == 2 and not getattr(self, '_source_successor_allowed', False):
            self._source_abort_result = None
        bootstrap = sys.modules.get(type(self.context).__module__)
        evidence_factory = getattr(bootstrap, '_make_source_c28_park_evidence', None)
        if not callable(evidence_factory):
            self._source_command_unresolved = True
            raise OSError(errno.ENOTSUP,
                'source C28 PARK lacks the canonical immutable evidence type')
        try:
            self._source_park_evidence = evidence_factory(self.context, self,
                response, self._last_received_bundle, self._channel,
                (os.getpid(), _identity(os.getpid())[3]),
                (self.process.pid, self.start_ticks, self.pidfd,
                    self._helper_sha256))
        except BaseException:
            self._source_command_unresolved = True
            raise
        return response

    def bind_source_route_preparation(self, prepared):
        """Join one exact C31 PREPARED ACK to this provider's actual PARK ACK."""
        if self._source_park_evidence is None or self._source_park_deadline_ns is None:
            raise PermissionError('source route binding requires the actual C28 PARK ACK')
        preparation = getattr(prepared, '_source_route_preparation', None)
        if (getattr(preparation, 'source_epoch', None) !=
                getattr(self, '_source_park_epoch', 1)):
            raise PermissionError('source PREPARED and C28 PARK came from different rounds')
        bootstrap = sys.modules.get(type(self.context).__module__)
        join = getattr(bootstrap, '_join_source_route_park', None)
        if not callable(join):
            raise OSError(errno.ENOTSUP,
                'canonical source C31/C28 one-shot join is unavailable')
        return join(preparation, self._source_park_evidence)

    def commit_source_group_before(self, deadline_ns, route_commit_receipt=None):
        if (self._source_park_deadline_ns is None or
                deadline_ns != self._source_park_deadline_ns or self._source_committed or
                getattr(self, '_source_abort_result', None) is not None):
            raise PermissionError('C28 COMMIT must reuse its exact PARK deadline')
        if getattr(self, '_source_command_abi', None) != _C28_SOURCE_COMMAND_ABI:
            raise OSError(errno.ENOTSUP,
                'pinned C22 build receipt does not authorize the quiet C28 command ABI')
        if self._source_route_receipt_consumed:
            raise PermissionError('C31 route-COMMIT ACK receipt was already consumed')
        bootstrap = sys.modules.get(type(self.context).__module__)
        consume_receipt = getattr(bootstrap,
            '_consume_source_route_commit_receipt', None)
        if not callable(consume_receipt) or route_commit_receipt is None:
            raise OSError(errno.ENOTSUP,
                'C28 COMMIT awaits the authenticated typed C31 route-COMMIT ACK')
        self._check_actor(deadline_ns)
        consume_receipt(route_commit_receipt, self, deadline_ns)
        # Burn the one-shot handoff before entering the native client. An
        # errno, timeout, or lost reply can follow an applied selector change.
        self._source_route_receipt_consumed = True
        response = self._source_c28_command(_C28_COMMIT, deadline_ns)
        park = self._source_park_evidence
        if (response['phase'] != _C28_PHASE_COMMITTED or park is None or
                response['lease'] != park.lease or
                response['received'] < park.received or
                response['accepted'] != response['received'] or
                response['listener_cookie'] <= 0):
            self._source_command_unresolved = True
            raise PermissionError('C28 COMMIT did not settle the PARK lease and queue or lacks a listener cookie')
        self._source_committed = True
        self._source_command_unresolved = False
        self._source_commit_result = dict(response)
        return response

    def abort_source_group_before(self, deadline_ns):
        park = self._source_park_evidence
        if (park is None or deadline_ns != self._source_park_deadline_ns or
                self._source_committed or self._source_abort_result is not None):
            raise PermissionError('C28 ABORT requires one pending PARK lease and its original deadline')
        response = self._source_c28_command(_C28_ABORT, deadline_ns)
        if (response['phase'] != _C28_PHASE_ABORTED or response['lease'] != park.lease or
                response['listener_cookie'] != 0 or response['received'] < park.received or
                response['accepted'] != response['received']):
            self._source_command_unresolved = True
            raise PermissionError('C28 ABORT did not settle the PARK lease and queue')
        self._source_abort_result = dict(response)
        return response

    def adopt_source_retry_before(self, deadline_ns):
        """Adopt the original listener before releasing the abort barrier."""
        abort = self._source_abort_result
        if (abort is None or self._source_retry_cookie is not None or
                deadline_ns != self._source_park_deadline_ns):
            raise PermissionError('C28 RETRY adoption requires the acknowledged original ABORT')
        response = self._source_c28_command(_C28_RETRY_ADOPT, deadline_ns)
        if (response['phase'] != _C28_PHASE_ABORTED or response['lease'] != abort['lease'] or
                response['listener_cookie'] <= 0 or response['received'] or response['accepted']):
            self._source_command_unresolved = True
            raise PermissionError('C28 RETRY did not preserve the original abort lineage')
        self._source_retry_cookie = response['listener_cookie']
        return self._source_retry_cookie

    def take_source_retry_slot(self, deadline_ns):
        """Return one fresh candidate FIFO and generation watch to the caller."""
        if self._source_retry_cookie is None or self._source_retry_slot_attempted:
            raise PermissionError('C28 retry capabilities require one acknowledged adoption')
        self._source_retry_slot_attempted = True
        response = self._source_c28_command(_C28_RETRY_SLOT, deadline_ns)
        fds = response['fds']
        try:
            old_watch = os.fstat(self.watch_fd)
            original = set(self.slot_identities) | {(old_watch.st_dev, old_watch.st_ino)}
            acquired = []
            for fd in fds:
                info = _validate_broker_fifo(fd, 'C28 retry capability')
                if info.st_uid != os.geteuid():
                    raise PermissionError('C28 retry descriptor has a different owner')
                acquired.append((info.st_dev, info.st_ino))
            if (response['listener_cookie'] != self._source_retry_cookie or
                    any(response[key] for key in ('phase', 'lease', 'received', 'accepted')) or
                    len(set(acquired)) != 2 or original.intersection(acquired)):
                raise PermissionError('C28 retry descriptors do not match the adopted listener')
            self._source_retry_watch_identity = (fds[1], *self._fd_diagnostic(fds[1]))
            self._source_retry_slot_delivered = True
            return fds
        except BaseException:
            for fd in fds:
                os.close(fd)
            self._source_command_unresolved = True
            raise

    def take_successor_slot(self, source_epoch, deadline_ns):
        """Obtain the staged slot and generation watch after predecessor retirement."""
        previous_epoch = source_epoch - 1
        if (not self._source_successor_allowed or
                not 2 <= source_epoch <= 100 or self._successor_adoption_epoch != previous_epoch or
                self._source_park_epoch != previous_epoch or not self._source_committed or
                (self._initial_retirement_proof is None if previous_epoch == 1 else
                    self._successor_retire_receipt is None)):
            raise PermissionError('C28 successor requires the preceding native retirement')
        self._successor_adoption_epoch = source_epoch
        response = self._source_c28_command(_C28_ADOPT_SUCCESSOR, deadline_ns)
        slot, watch = response['fds']
        try:
            identities = []
            for fd in (slot, watch):
                value = _validate_broker_fifo(fd, 'C28 native successor capability')
                if value.st_uid != os.geteuid():
                    raise PermissionError('C28 successor descriptor owner changed')
                identities.append((value.st_dev, value.st_ino))
            if (response['listener_cookie'] != self._source_commit_result['listener_cookie'] or
                    any(response[key] for key in ('phase', 'lease', 'received', 'accepted')) or
                    len(set(identities)) != 2 or set(identities).intersection(self.slot_identities) or
                    self._successor_watch is not None or self._successor_slot >= 0):
                raise PermissionError('C28 successor capabilities differ from the adopted listener')
            self._successor_slot = slot
            self._successor_watch = (watch, self._fd_diagnostic(watch), response['listener_cookie'])
            self._source_park_deadline_ns = self._source_park_evidence = self._source_park_result = None
            self._source_commit_result = None
            self._source_committed = self._source_route_receipt_consumed = False
            self._successor_retire_by = self._successor_retire_ack = self._successor_retire_receipt = None
            return slot, response['listener_cookie']
        except BaseException:
            os.close(slot)
            os.close(watch)
            self._source_command_unresolved = True
            raise

    def close_successor_slot(self, slot):
        if slot != self._successor_slot:
            raise PermissionError('C28 successor slot differs from its one-use grant')
        os.close(slot)
        self._successor_slot = -1

    def retire_successive_predecessor(self, source_epoch):
        """Prove that the preceding owner is dead and its native listener retired."""
        if (not self._source_successor_allowed or not self._source_committed or
                source_epoch != self._successor_adoption_epoch or source_epoch <= 1 or
                self._source_park_epoch != source_epoch):
            raise PermissionError('successive retirement is outside its committed round')
        if self._successor_retire_receipt is not None:
            return self._successor_retire_receipt
        if self._successor_watch is None:
            raise PermissionError('successive retirement lost the native generation watch')
        key = (source_epoch - 1, 1 - source_epoch % 2)
        old_fd, old = self.context.workers[key]
        bootstrap = sys.modules[type(self.context).__module__]
        if bootstrap.identity.process_alive(old_fd):
            return None
        now = time.monotonic_ns()
        if self._successor_retire_by is None:
            self._successor_retire_by = min(self.context.deadline_ns, now + 5_000_000_000)
        deadline = self._successor_retire_by
        if now >= deadline:
            raise TimeoutError('successive native retirement deadline expired')
        watch, identity, cookie = self._successor_watch
        if self._fd_diagnostic(watch) != identity:
            raise PermissionError('successive retirement watch descriptor changed')
        if self._successor_retire_ack is None:
            result = self._source_c28_command(_C28_RETIRE_INITIAL_LISTENER,
                min(deadline, now + _C28_CUTOVER_BUDGET_NS))
            if result['errno'] == errno.EAGAIN:
                return None
            if any(result.get(name) for name in ('phase', 'lease', 'listener_cookie',
                    'received', 'accepted')):
                raise PermissionError('successive native retirement returned a malformed ACK')
            self._successor_retire_ack = self._source_last_command
            duplicate = os.dup(watch)
            try:
                self.broker_readiness.begin_verify(duplicate, self._verify_sequence + 1,
                    (deadline - time.monotonic_ns()) / 1_000_000_000)
            except BaseException:
                os.close(duplicate)
                raise
            self._verify_sequence += 1
        packet = self.broker_readiness.poll_verify()
        if packet is None:
            return None
        result = self.broker_readiness.last_verify_result
        if (bootstrap.identity.process_alive(old_fd) or
                result['owner_pid'] != old[5] or result['owner_start_ticks'] != old[11] or
                result['listener_cookie'] != cookie or result['status'] != 0 or
                result['state'] != 1 or result['profile'] != self.broker_readiness.profile):
            raise PermissionError('successive C34 watch does not prove the exact retired owner')
        self._successor_retire_receipt = (source_epoch, key, self._successor_retire_ack,
            bytes(packet))
        os.close(watch)
        self._successor_watch = None
        return self._successor_retire_receipt

    def current_source_census(self, deadline_ns):
        return self._source_c28_command(_C28_CURRENT_CENSUS, deadline_ns)

    def retire_initial_listener(self, old_exit_observation, deadline_ns):
        """Attempt one correlated C28 RETIRE_INITIAL_LISTENER command.

        A fully correlated EAGAIN is definitive and retryable within one fixed
        five-second phase window. Every transport or other native error remains
        one-shot and unresolved.
        """
        if type(self) is not SourceShellC34InteropProvider:
            raise OSError(errno.ENOTSUP, 'initial listener retirement is private to the exact C34 provider')
        controller_module = sys.modules.get('_ker_nginx_source_shell_controller')
        observation_type = getattr(controller_module,
            '_PrivateInitialWorkerExitObservation', None)
        controller = getattr(old_exit_observation, 'controller', None)
        context = self.context
        candidate_key = (getattr(self, '_source_park_epoch', 1), 1)
        if (observation_type is None or type(old_exit_observation) is not observation_type or
                getattr(old_exit_observation, 'provider', None) is not self or
                getattr(old_exit_observation, 'context', None) is not context or
                controller is None or getattr(controller, 'c22_provider', None) is not self or
                not controller._valid_private_initial_exit_observation(
                    old_exit_observation.transport, context) or
                getattr(context, '_source_shell_committed_plans', {}).get(candidate_key, {}).get(
                    'native_current_cookie', 0) <= 0 or
                not self._source_committed or self._source_park_evidence is None or
                getattr(self, '_source_commit_result', None) is None):
            raise PermissionError('C28 retirement lacks the exact pending private old-exit and committed plan')
        if self._initial_retire_ack is not None:
            return dict(self._initial_retire_ack)
        now = time.monotonic_ns()
        if self._initial_retire_started_ns is None:
            self._initial_retire_started_ns = now
            self._initial_retire_deadline_ns = min(context.deadline_ns,
                now + 5_000_000_000)
            existing_gate = getattr(self.broker_readiness,
                '_private_initial_retirement_provider', None)
            if existing_gate is not self:
                raise PermissionError('broker is already held by another initial retirement phase')
        phase_deadline = self._initial_retire_deadline_ns
        if (type(deadline_ns) is not int or now >= deadline_ns or
                now >= phase_deadline or self._initial_retire_attempts >=
                    _C28_RETIRE_MAX_ATTEMPTS):
            raise TimeoutError('C28 initial listener retirement exhausted its fixed phase budget')
        if now < self._initial_retire_next_retry_ns:
            return None
        command_deadline = min(deadline_ns, phase_deadline, now + _C28_CUTOVER_BUDGET_NS)
        self._check_actor(command_deadline)
        self._initial_retire_attempts += 1
        response = self._source_c28_command(_C28_RETIRE_INITIAL_LISTENER,
            command_deadline)
        if response.get('errno') == errno.EAGAIN:
            self._initial_retire_next_retry_ns = time.monotonic_ns() + 5_000_000
            return None
        park = self._source_park_evidence
        commit = self._source_commit_result
        planned_cookie = context._source_shell_committed_plans[candidate_key]['native_current_cookie']
        if (response.get('errno') != 0 or
                commit.get('phase') != _C28_PHASE_COMMITTED or
                commit.get('lease') != park.lease or
                type(commit.get('received')) is not int or commit['received'] < park.received or
                commit.get('received') != commit.get('accepted') or
                commit.get('listener_cookie') != planned_cookie or planned_cookie <= 0 or
                response.get('phase') != 0 or response.get('lease') != 0 or
                response.get('listener_cookie') != 0 or response.get('received') != 0 or
                response.get('accepted') != 0):
            self._source_command_unresolved = True
            raise PermissionError('C28 initial retirement ACK differs from the committed native plan')
        self._initial_retire_ack = dict(response)
        self._initial_retire_command = self._source_last_command
        self._initial_retire_exit = old_exit_observation
        return dict(response)

    def finish_initial_listener_retirement(self, c34_raw, c34_result):
        if type(self) is not SourceShellC34InteropProvider:
            raise OSError(errno.ENOTSUP, 'initial listener proof is private to the exact C34 provider')
        if self._initial_retirement_proof is not None:
            return self._initial_retirement_proof
        command = self._initial_retire_command
        exit_observation = getattr(self, '_initial_retire_exit', None)
        context = self.context
        controller = getattr(exit_observation, 'controller', None)
        if (type(c34_raw) is not bytes or type(c34_result) is not dict or
                c34_raw != getattr(self.broker_readiness, 'last_verify_packet', None) or
                c34_result is not getattr(self.broker_readiness, 'last_verify_result', None)):
            raise PermissionError('C34 VERIFY raw packet/result is not the retained broker response')
        try:
            decoded_result = _verify_wire_module().unpack_verify_result(
                c34_raw, self.broker_nonce, self.broker_epoch, 1)
        except (ValueError, TypeError, struct.error) as error:
            raise PermissionError('C34 VERIFY raw packet failed the pinned wire decoder') from error
        if decoded_result != c34_result:
            raise PermissionError('C34 VERIFY decoded result differs from the retained raw packet')
        if (self._initial_retire_ack is None or command is None or
                type(command) is not tuple or len(command) != 5 or
                command[1] != _C28_RETIRE_INITIAL_LISTENER or command[0] <= 0 or
                command[4] != self._initial_retire_ack or
                not self._initial_verify_started or len(c34_raw) != 128 or
                exit_observation is None or controller is None or
                not controller._valid_private_initial_exit_observation(
                    exit_observation.transport, context) or
                c34_result.get('sequence') != 1 or
                c34_result.get('nonce') != self.broker_nonce or
                c34_result.get('epoch') != self.broker_epoch or
                c34_result.get('profile') != self.broker_readiness.profile or
                c34_result.get('owner_pid') != exit_observation.ready_identity[0] or
                c34_result.get('owner_start_ticks') != exit_observation.ready_identity[6] or
                c34_result.get('status') != 0 or c34_result.get('state') != 1 or
                (getattr(self, '_source_park_epoch', 1) == 2 and
                    c34_result.get('listener_cookie') != self._source_retry_cookie) or
                any(type(c34_result.get(name)) is not int or c34_result[name] <= 0
                    for name in ('owner_token', 'claim_generation', 'mark', 'listener_cookie'))):
            raise PermissionError('C34 VERIFY did not prove the exact retired initial native listener')
        self._initial_retirement_watch()
        proof = SourceInitialListenerRetirementProof(
            _INITIAL_RETIREMENT_PROOF_TOKEN, self, context, exit_observation,
            self._source_park_evidence, command, c34_raw, c34_result,
            time.monotonic_ns())
        registry = getattr(context, '_source_initial_listener_retirements', None)
        if registry is None:
            registry = {}
            context._source_initial_listener_retirements = registry
        if type(registry) is not dict or id(self) in registry:
            raise PermissionError('initial listener retirement proof registry is already occupied')
        registry[id(self)] = proof
        self._initial_retirement_proof = proof
        self._source_retired_initial_listener = True
        return proof

    def _initial_retirement_watch(self):
        if getattr(self, '_source_park_epoch', 1) == 2:
            identity = getattr(self, '_source_retry_watch_identity', None)
            fds = getattr(self.context, '_private_retry_fds', None)
            fd = fds[1] if fds is not None else -1
        else:
            identity = self._watch_fd_identity
            fd = self.watch_fd
        if (type(identity) is not tuple or fd < 0 or fd != identity[0] or
                self._fd_diagnostic(fd) != identity[1:]):
            raise PermissionError('C34 generation-watch descriptor changed before VERIFY proof')
        return identity

    def close_source_capabilities_after_settlement(self, settlement_proof, deadline_ns):
        bootstrap = sys.modules.get(type(self.context).__module__)
        proof_type = getattr(bootstrap, 'SourceRetirementProof', None)
        initial_slots = (self._used_slots == {0} or
            (self._used_slots == {0, 1} and
                ((self.context._abort_only() and self._source_abort_result is not None) or
                 (self.context._unparked_abort_profile() and self._source_park_evidence is None and
                    getattr(self.context, '_unparked_abort', None) is not None))))
        initial_settled = (initial_slots and not self._source_committed and
            not self._source_retired_initial_listener and
            self.context._completed_retirements.get((0, 0)) is settlement_proof)
        committed_settled = self._source_retired_initial_listener and self._source_committed
        if (proof_type is None or type(settlement_proof) is not proof_type or
                not (initial_settled or committed_settled)):
            raise PermissionError('C22 CLOSE needs real retirement and settled C31/C28 proof')
        self._source_close_authorized = settlement_proof
        return self.close(abort=False)

    def _close_command(self, deadline_ns):
        if self.process is None or self.process.poll() is not None or self.process.stdin is None:
            return False
        fd = self.process.stdin.fileno()
        os.set_blocking(fd, False)
        payload = b'CLOSE\n'
        sent = 0
        poller = select.poll()
        poller.register(fd, select.POLLOUT | select.POLLERR | select.POLLHUP | select.POLLNVAL)
        while sent < len(payload) and time.monotonic_ns() < deadline_ns:
            try:
                count = os.write(fd, payload[sent:])
                if count <= 0:
                    return False
                sent += count
                continue
            except InterruptedError:
                continue
            except BlockingIOError:
                remaining = deadline_ns - time.monotonic_ns()
                if remaining <= 0:
                    break
                events = poller.poll(max(1, (remaining + 999_999) // 1_000_000))
                if not events or events[0][1] & (select.POLLERR | select.POLLHUP | select.POLLNVAL):
                    return False
        return sent == len(payload) and time.monotonic_ns() < deadline_ns

    def _wait_helper_until(self, deadline_ns):
        if self.process is None or self.process.poll() is not None:
            return True
        if self.pidfd < 0:
            return False
        poller = select.poll()
        poller.register(self.pidfd, select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL)
        while time.monotonic_ns() < deadline_ns:
            if self.process.poll() is not None:
                return True
            remaining = deadline_ns - time.monotonic_ns()
            events = poller.poll(max(1, (remaining + 999_999) // 1_000_000))
            if events:
                return self.process.poll() is not None
        return self.process.poll() is not None

    def close(self, abort=False):
        if self._closed:
            return True
        if getattr(self, '_source_command_abi', None) == _C28_SOURCE_COMMAND_ABI:
            if self._source_command_unresolved or self._source_command_outstanding is not None:
                raise TimeoutError('C28 command outcome is unknown; retain helper and capabilities')
            if not abort:
                if self._source_close_authorized is None:
                    raise PermissionError('C22 CLOSE cannot substitute for STOP/SETTLED proof')
                if not self._source_close_commanded:
                    close_deadline = min(self.context.deadline_ns,
                        time.monotonic_ns() + _CLOSE_WRITE_NS)
                    self._source_c28_command(_C28_CLOSE, close_deadline)
                    self._source_close_commanded = True
                if not self._wait_helper_until(min(self.context.deadline_ns,
                        time.monotonic_ns() + _TERM_GRACE_NS)):
                    raise TimeoutError('C22 helper did not exit after capability CLOSE')
                if self.process is None or self.process.returncode != 0:
                    raise RuntimeError('C22 helper did not complete capability CLOSE successfully')
        cleanup_error = None
        for fd in self.slots:
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError as error:
                    cleanup_error = cleanup_error or error
        self.slots = [-1, -1]
        if self.watch_fd >= 0:
            try:
                os.close(self.watch_fd)
            except OSError as error:
                cleanup_error = cleanup_error or error
            self.watch_fd = -1

        settled = self.process is None or self.process.poll() is not None
        if self.process is not None and not settled:
            close_sent = False
            if not abort:
                try:
                    close_deadline = time.monotonic_ns() + _CLOSE_WRITE_NS
                    if getattr(self, 'context', None) is not None:
                        close_deadline = min(close_deadline, self.context.deadline_ns)
                    close_sent = self._close_command(close_deadline)
                    if not close_sent:
                        abort = True
                except BaseException as error:
                    cleanup_error = cleanup_error or error
                    abort = True
            if close_sent:
                settled = self._wait_helper_until(time.monotonic_ns() + _TERM_GRACE_NS)
                if not settled:
                    abort = True
                if not settled:
                    abort = True
            if not settled and abort:
                try:
                    self.process.terminate()
                except ProcessLookupError:
                    pass
                except BaseException as error:
                    cleanup_error = cleanup_error or error
                settled = self._wait_helper_until(time.monotonic_ns() + _TERM_GRACE_NS)
            if not settled:
                try:
                    self.process.kill()
                except ProcessLookupError:
                    pass
                except BaseException as error:
                    cleanup_error = cleanup_error or error
                settled = self._wait_helper_until(time.monotonic_ns() + _KILL_GRACE_NS)

        if not settled:
            # Keep pidfd, executable inode, and control channel attached so
            # the owner can retry cleanup or observe eventual settlement.
            if cleanup_error is not None:
                raise cleanup_error
            raise TimeoutError('C22 helper did not settle within bounded cleanup')

        self._closed = True
        try:
            if self.process is not None and self.process.stdin is not None:
                self.process.stdin.close()
        except OSError as error:
            cleanup_error = cleanup_error or error
        for name in ('pidfd', '_helper_fd'):
            fd = getattr(self, name, -1)
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError as error:
                    cleanup_error = cleanup_error or error
                setattr(self, name, -1)
        if self._channel is not None:
            try:
                self._channel.close()
            except OSError as error:
                cleanup_error = cleanup_error or error
            self._channel = None
        if cleanup_error is not None:
            raise cleanup_error
        return True


class SourceShellC34InteropProvider(SourceShellC22Provider):
    """Private NEWC34_INTEROP dispatch for the exact fresh ABI1 helper."""
    def __init__(self, context, broker_readiness, helper_capture):
        import sys
        c34_module = sys.modules.get('_ker_nginx_source_c34_artifacts')
        if (c34_module is None or
                Path(c34_module.__file__).resolve(strict=True) !=
                    Path(__file__).with_name('nginx_source_c34_artifact_provider.py').resolve(strict=True) or
                type(helper_capture) is not c34_module.PrivateC34HelperCapture or
                helper_capture.source_command_abi != _C28_SOURCE_COMMAND_ABI or
                helper_capture.sha256.hex() != c34_module._HELPER_SHA256 or
                helper_capture.build_id != c34_module._HELPER_BUILD_ID):
            raise TypeError('private C34 provider requires the fixed helper and reviewed ABI1 capture')
        super().__init__(context, broker_readiness, helper_capture)
