"""Private, fixed-input captures for the new matched C34 interop build.

This module deliberately exposes no caller-selected artifact path or digest.
Captures are build evidence only; they do not grant Source Origin authority.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import time
from types import MappingProxyType

_TOKEN = object()
_BASE = Path('/home/hurricane/.local/state/ker-fstack-source-shell/source-original-case-build-20261114T122801Z')
_STAGE = Path('/home/hurricane/.local/state/ker-fstack-source-shell/source-original-case-test-stage-20261114T124842Z')
_SOURCE_ROOT = _BASE / 'fstack-646a-shallow'
_INTEGRATION = _BASE / 'integration'
_HELPER_INPUT_BASE = Path('/home/hurricane/.local/state/ker-fstack-source-shell/source-c34-production-20261114T0510')
_BUILD_MANIFEST = _BASE / 'artifacts/original-source-build-manifest.json'
_BUILD_MANIFEST_SHA256 = '9d90e32fd4343e1da0a34aa7777e9a3d68a62e14029a20ba790ab6d10784c7d8'
_GRAPH_PACKET = _STAGE / 'static-graphs/per-root-candidate-graphs.json'
_GRAPH_SHA256 = 'a5c101d4208cff6bd116be8f83c4bdddb7dc34f32e8437e6017a36a278e23618'
_ALIAS_PACKET = _STAGE / 'static-graphs/alias-identities.json'
_ALIAS_SHA256 = '2a61859225b9adbaea336e46fcfe2be63520f108861dcb3efe3d042dd8ea3ba0'
_STAGE_MANIFEST = _STAGE / 'stage-manifest.json'
_STAGE_MANIFEST_SHA256 = '0d8675ffc12a299095c98d639cc2b5260f5ef9282340a87f5f5b08aa5e27044a'
_STAGE_FILES = _STAGE / 'stage-files.sha256'
_STAGE_FILES_SHA256 = 'e81f38632bdf37d37c51b0266b53679a7c7cb2d38188dbc4f9e339ece199dc8e'
_RUNNER_PREP = _STAGE / 'nginx-v-runner-prep-v2-20261114T130926Z'
_RUNNER_MANIFEST_SHA256 = '859a1f1a2ff90baaed6bce5f5995d4809aa12def9ae0f7e38d22f05858959c59'
_RUNNER_ALIASES_SHA256 = '0d622b570629827664d12f921a86f199f9ba4e4189c276a2f8d64a15599fd914'
_OBJECT_UNION_SHA256 = '6ce48fc952108fee789214a5cefbf726971e1811486cef2ec549f791cb808778'
_RUNNER_PREFLIGHT_SHA256 = '05bffc8dc504f8f49195644954676a552fc61dd29fdcb9818bc5f84da1710b05'
_RUNNER_INDEX_SHA256 = '735d25f9a910c366ff6c674c91ba5c0bc969c85e7b0839ac1af95583b93e8ca1'
_SOURCE_HEAD_SHA256 = '3c8409ef273ad8f76e5998b6a315f58883c42253b2bac3dfbdf8d18263b63c8c'
_NGINX_NM_SHA256 = 'a27db210180ef3372f71407b916a042ff455ab90f91b15533defa2d661c04ac8'
_INPUT_PROVENANCE_SHA256 = 'ce9fdd0e0565fe32278148231efcc46000e1d37ee5c70a0eaffc10bcb992b2d9'
_NATIVE_METADATA = Path('/home/hurricane/.local/state/ker-fstack-source-shell/native-linux-event-shutdown-v2/native-linux.json')
_NATIVE_METADATA_SHA256 = '3d94920d2b102b2dd289022095410e049a3430b3b1e569004b28d0890743a631'
_DPDK_MANIFEST = Path('/home/hurricane/.local/state/ker-native-linux/source-original-case-deps-20261114T121007Z/artifact-manifest.json')
_DPDK_MANIFEST_SHA256 = '351fde78fc42956485402a830b286cf7f435338cc4f86a0321a00b7efc9bd5ed'
_SOURCE_EXPORT_NAMES = frozenset(('ngx_cycle', 'ngx_ff_reload_shm',
    'ngx_ff_graceful_reload', 'ngx_ff_process', 'ngx_process',
    'ngx_worker', 'ngx_process_slot'))
_EVIDENCE = Path('/home/hurricane/.local/state/ker-fstack-source-shell/review-evidence')
_PROFILE_PACKET = _EVIDENCE / 'newc34-private-interop-profile-preflight-20261114T075000Z/newc34-private-interop-profile-preflight.json'
_PROFILE_PACKET_SHA256 = 'abf442bdf0fb676373d5ce1f699193b9aae3d9add48b6842144ab8c99f7e9ed8'
_ALIAS_SUPPLEMENT = _EVIDENCE / 'newc34-nginx-v-root-execution-20261114T1153Z/offline-alias-review-supplement.json'
_ALIAS_SUPPLEMENT_SHA256 = '77995766a8a0c12e7fe6f53360b19dadda396b193860d57c39758de89b4a0da7'
_GRAPH_ADDENDUM = _EVIDENCE / 'abi-aware-per-root-static-resolver-20261114T071641Z/newc34-profile-static-graph-addendum.json'
_GRAPH_ADDENDUM_SHA256 = '2b6eae0581e2c71d70f9c9df0723191810f6d02c18d19da48b1568585fa0e352'
_HELPER_PACKET = _EVIDENCE / 'nginx-owner-group-helper-capture-20261114T062500Z/helper-capture-packet.json'
_HELPER_PACKET_SHA256 = 'c2163307217ca4cfd22124cf11805f1253c4d0b688dee5f3a36c141e761ff72e'
_HELPER = _EVIDENCE / 'nginx-owner-group-helper-capture-20261114T062500Z/ker-nginx-owner-group-controller'
_HELPER_SHA256 = 'ac3b9a8dd1754e169ec89632a02d8854c529388e3298d939a3de01e102449310'
_HELPER_BUILD_ID = '8de64befb2531f8af86217930097ffa4668d1f82'
_HELPER_SOURCE = _EVIDENCE / 'nginx-owner-group-helper-capture-20261114T062500Z/nginx-owner-group-controller.c'
_HELPER_SOURCE_SHA256 = 'c4db25b14f85ec1bd3b31d3ee9b75fce6a01d479a8d87d25282d09195bbed781'
_HEADER = _INTEGRATION / 'include/ker/socket-broker.h'
_HEADER_SHA256 = '3627dccff64f30101c377543ca6866054c20023c2c51c4357da40eaf6b04197b'
_CLIENT_ARCHIVE = _HELPER_INPUT_BASE / 'cmake-host-runtime/libker-socket-client.a'
_CLIENT_ARCHIVE_SHA256 = '07df2365339b6bb44614c89c621425c9666e0b1e6fa06fdcce39c135e0b5a9cd'
_HELPER_OBJECT = _EVIDENCE / 'nginx-owner-group-helper-capture-20261114T062500Z/helper.o'
_HELPER_OBJECT_SHA256 = 'bf0dcfa5fdc41199b3d6045687daf0d724b98e9c4a52ceab902287b1cefb43f7'

# Entries are fixed by the accepted compile packet. Archives are hashed but have
# no ELF Build ID. Nginx aliases are checked separately by device/inode.
_FIXED_ARTIFACTS = {
    'nginx': (_SOURCE_ROOT / 'app/nginx-1.28.0/objs/nginx', 'f9e1e4d01720f1050e6521e22d7d1dc10dd4aaadab62448aac83a4e51dfa4c10', '562529554981f479becf542d6c09133f2ebf9c07'),
    'first_builtin_elf': (_BASE / 'artifacts/nginx-first-addon.elf', 'f9e1e4d01720f1050e6521e22d7d1dc10dd4aaadab62448aac83a4e51dfa4c10', '562529554981f479becf542d6c09133f2ebf9c07'),
    'build_manifest': (_BUILD_MANIFEST, _BUILD_MANIFEST_SHA256, None),
    'input_provenance': (_BASE / 'artifacts/input-provenance.json', _INPUT_PROVENANCE_SHA256, None),
    'native_metadata': (_NATIVE_METADATA, _NATIVE_METADATA_SHA256, None),
    'dpdk_manifest': (_DPDK_MANIFEST, _DPDK_MANIFEST_SHA256, None),
    'source_git_head': (_SOURCE_ROOT / '.git/HEAD', _SOURCE_HEAD_SHA256, None),
    'source_network_template': (_SOURCE_ROOT / 'config.ini', '3816714811480c9b7bf52e4658bfc5d69dbcdf0e9f3c11f2c17f491e90a3a77f', None),
    'nginx_symbols': (_BASE / 'artifacts/nginx-relinked.nm.txt', _NGINX_NM_SHA256, None),
    'stage_manifest': (_STAGE_MANIFEST, _STAGE_MANIFEST_SHA256, None),
    'stage_file_index': (_STAGE_FILES, _STAGE_FILES_SHA256, None),
    'static_graphs': (_GRAPH_PACKET, _GRAPH_SHA256, None),
    'alias_identities': (_ALIAS_PACKET, _ALIAS_SHA256, None),
    'runner_manifest': (_RUNNER_PREP / 'runner-manifest.json', _RUNNER_MANIFEST_SHA256, None),
    'runner_aliases': (_RUNNER_PREP / 'alias-identities.json', _RUNNER_ALIASES_SHA256, None),
    'runner_object_union': (_RUNNER_PREP / 'expected-filebacked-object-union.json', _OBJECT_UNION_SHA256, None),
    'runner_static_preflight': (_RUNNER_PREP / 'static-preflight.json', _RUNNER_PREFLIGHT_SHA256, None),
    'runner_index': (_RUNNER_PREP / 'v2-index.json', _RUNNER_INDEX_SHA256, None),
    'abi2_ini_header': (_INTEGRATION / 'src/posix/source-native-ini.h', 'acd7345019b57d5bfa8cccb532459c64fb330196de5f22b7a72ad57c608f52fa', None),
    'shim': (_BASE / 'ff-prefix/lib/libker-fstack-nginx-worker-shim.so', 'b2938bfe9123ddb5a49f5ef20729422215580cd5ebd52702150d2854a57112cb', '374ac412831ba78b3d66c9be43e8e1df0214e60f'),
    'runtime': (_BASE / 'cmake-host-runtime/libfstack.so', '7d6dee57d8e9a7c105fd475067171e1bfa8a9952804e2134a84c459ece722714', 'f03f9a8bef45a74a1908eecbc3968e0e14b5d24a'),
    'runtime_ff_alias': (_BASE / 'ff-prefix/lib/libfstack.so', '7d6dee57d8e9a7c105fd475067171e1bfa8a9952804e2134a84c459ece722714', 'f03f9a8bef45a74a1908eecbc3968e0e14b5d24a'),
    'posix': (_BASE / 'cmake-host-runtime/libker-posix.so', '3abb8494b61959aa735e5989dfa494e9e383d7154c4d6b46eae12df21155dbfe', '6854764d3dd6c01b2b8c626b4622ea13f526c565'),
    'bridge': (_BASE / 'cmake-host-runtime/libker-fstack-socket-bridge.so', 'f2adaf726d4153cb1c77f1629178ba67d1081dea8a93740b6dc6f78079e613ac', '9239bc2675d651d61ab29ea4a77826f71296d7cb'),
    'preload': (_BASE / 'cmake-host-runtime/libker-socket-preload.so', '7d29bcb208cf53a441ca76eb8994bc648c0a866495cabda59b0fa01aff2ba58c', 'fdc415981a6cc1217748e2540515a052fb4910a3'),
    'io_worker': (_BASE / 'cmake-host-runtime/ker-io-worker', 'e0de9fa36ca4055a0d2b221f7434d55440f61893f46774a8f0b28b0f8b53816e', '35ea605dfb66f83c7935d58728e09410fe9fefe5'),
    'ker_app': (_BASE / 'cmake-host-runtime/ker-app', '7ef9c610fa7a8cf69bfd041380f8f40e0d3749772cb2b7fd1ce8c40bc942d316', '9c2c382b6b03496c6297df98014f35d566f05682'),
    'client_archive': (_BASE / 'cmake-host-runtime/libker-socket-client.a', '3a7da37e611eb9b4d6c936cb5ff7eacc2bd3d0620df48933480f9f2c7ecc9d9e', None),
    'ini_archive': (_BASE / 'cmake-host-runtime/libker-ini.a', '8ffab90829bee26a00ce82f73672d08f995fea1cee3e924959b8c2928a0457d4', None),
    'test_backend': (_STAGE / 'test-backend/ker-socket-broker-rx-owner-relay-fixture', '18a432bdf8e0ef65b5f7e9df59d2022568cd41607d4813f9d2b765c0bc726e25', '51a16634e617bf5d1a4e343ddd92d288110a9b40'),
    'test_backend_readiness_archive': (_STAGE / 'test-backend/libker-socket-broker-readiness-test-server.a', '119d9b8f86de5b00fac0f14736ea36fd04ff304e1ac3507fe1d978f3fa5b1756', None),
}


def _deadline(deadline_ns):
    if type(deadline_ns) is not int or deadline_ns <= time.monotonic_ns():
        raise TimeoutError('private C34 capture deadline expired')


def _open_nofollow(path, deadline_ns):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise PermissionError('private C34 capture path is not canonical absolute')
    _deadline(deadline_ns)
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            _deadline(deadline_ns)
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC |
                getattr(os, 'O_NOFOLLOW', 0), dir_fd=directory)
            os.close(directory)
            directory = child
        return os.open(path.parts[-1], os.O_RDONLY | os.O_CLOEXEC |
            getattr(os, 'O_NOFOLLOW', 0), dir_fd=directory)
    finally:
        os.close(directory)


def _read_fixed(path, expected, deadline_ns, limit=2 * 1024 * 1024):
    fd = _open_nofollow(path, deadline_ns)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                info.st_nlink != 1 or info.st_size <= 0 or info.st_size > limit):
            raise PermissionError('private C34 evidence is not one bounded owned regular file')
        data = os.pread(fd, info.st_size + 1, 0)
        after = os.fstat(fd)
        if (len(data) != info.st_size or hashlib.sha256(data).hexdigest() != expected or
                any(getattr(info, k) != getattr(after, k) for k in
                    ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))):
            raise PermissionError('private C34 evidence hash/identity changed')
        return data
    finally:
        os.close(fd)


def _elf_build_id(fd, size, deadline_ns):
    header = os.pread(fd, 64, 0)
    _deadline(deadline_ns)
    if len(header) != 64 or header[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', header, 18)[0] != 62:
        raise PermissionError('private C34 executable is not little-endian x86-64 ELF')
    phoff = struct.unpack_from('<Q', header, 32)[0]
    entsize, count = struct.unpack_from('<HH', header, 54)
    if entsize != 56 or count > 1024 or phoff + entsize * count > size:
        raise PermissionError('private C34 ELF program header table is invalid')
    for i in range(count):
        _deadline(deadline_ns)
        ph = os.pread(fd, entsize, phoff + i * entsize)
        if len(ph) != entsize or struct.unpack_from('<I', ph)[0] != 4:
            continue
        off = struct.unpack_from('<Q', ph, 8)[0]
        n = struct.unpack_from('<Q', ph, 32)[0]
        if off + n > size:
            raise PermissionError('private C34 ELF note exceeds file bounds')
        raw = os.pread(fd, n, off)
        at = 0
        while at + 12 <= len(raw):
            namesz, descsz, kind = struct.unpack_from('<III', raw, at)
            at += 12
            name_end = at + namesz
            desc_at = (name_end + 3) & ~3
            desc_end = desc_at + descsz
            next_at = (desc_end + 3) & ~3
            if next_at > len(raw):
                break
            if kind == 3 and raw[at:name_end].rstrip(b'\0') == b'GNU':
                return raw[desc_at:desc_end].hex()
            at = next_at
    raise PermissionError('private C34 ELF Build ID is missing')


class _HeldArtifact:
    __slots__ = ('_sealed', 'name', 'path', 'alias', 'alias_target', 'alias_identity', 'fd', 'sha256', 'build_id', 'identity')

    def __setattr__(self, name, value):
        if getattr(self, '_sealed', False):
            raise AttributeError('held private C34 artifact metadata is immutable')
        object.__setattr__(self, name, value)

    def __init__(self, token, name, path, fd, digest, build_id, info, alias=None, alias_target=None, alias_identity=None):
        if token is not _TOKEN:
            raise TypeError('private C34 artifacts are fixed-factory objects')
        self._sealed = False
        self.name, self.path, self.fd = name, Path(path), fd
        self.alias, self.alias_target, self.alias_identity = alias, alias_target, alias_identity
        self.sha256, self.build_id = digest, build_id
        self.identity = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, stat.S_IMODE(info.st_mode), info.st_uid, info.st_nlink)
        self._sealed = True

    def verify(self, deadline_ns):
        _deadline(deadline_ns)
        info = os.fstat(self.fd)
        ident = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, stat.S_IMODE(info.st_mode), info.st_uid, info.st_nlink)
        if ident != self.identity:
            raise PermissionError('held private C34 artifact identity changed')
        h = hashlib.sha256()
        off = 0
        while off < info.st_size:
            _deadline(deadline_ns)
            block = os.pread(self.fd, min(1 << 20, info.st_size - off), off)
            if not block:
                raise PermissionError('held private C34 artifact truncated')
            h.update(block); off += len(block)
        if h.hexdigest() != self.sha256:
            raise PermissionError('held private C34 artifact digest changed')
        if self.build_id is not None and _elf_build_id(self.fd, info.st_size, deadline_ns) != self.build_id:
            raise PermissionError('held private C34 artifact Build ID changed')
        named = os.stat(self.path, follow_symlinks=False)
        if (named.st_dev, named.st_ino) != self.identity[:2]:
            raise PermissionError('private C34 artifact pathname no longer names held inode')
        if self.alias is not None:
            link = os.lstat(self.alias)
            if (not stat.S_ISLNK(link.st_mode) or
                    (link.st_dev, link.st_ino, link.st_mtime_ns, link.st_ctime_ns) != self.alias_identity or
                    os.readlink(self.alias) != self.alias_target or
                    self.alias.resolve(strict=True) != self.path):
                raise PermissionError('private C34 artifact symlink alias changed')

    def close(self):
        if self.fd >= 0:
            fd = self.fd
            object.__setattr__(self, 'fd', -1)
            os.close(fd)


class PrivateC34HelperCapture:
    """Fixed ac3b helper capture with reviewed source-command ABI 1."""
    __slots__ = ('_sealed', '_artifacts', 'sha256', 'build_id', 'source_command_abi', '_deadline_ns', '_consumed')

    def __setattr__(self, name, value):
        if getattr(self, '_sealed', False):
            raise AttributeError('private C34 helper capture is immutable')
        object.__setattr__(self, name, value)

    def __init__(self, token, artifacts, deadline_ns):
        if token is not _TOKEN:
            raise TypeError('private C34 helper captures require capture()')
        self._sealed = False
        self._artifacts = artifacts
        self.sha256 = bytes.fromhex(_HELPER_SHA256)
        self.build_id = _HELPER_BUILD_ID
        self.source_command_abi = 1
        self._deadline_ns = deadline_ns
        self._consumed = False
        self._sealed = True

    @classmethod
    def _capture(cls, deadline_ns):
        _read_fixed(_HELPER_PACKET, _HELPER_PACKET_SHA256, deadline_ns)
        artifact_specs = (
            ('helper', _HELPER, _HELPER_SHA256, _HELPER_BUILD_ID),
            ('source', _HELPER_SOURCE, _HELPER_SOURCE_SHA256, None),
            ('header', _HEADER, _HEADER_SHA256, None),
            ('client_archive', _CLIENT_ARCHIVE, _CLIENT_ARCHIVE_SHA256, None),
            ('object', _HELPER_OBJECT, _HELPER_OBJECT_SHA256, None),
        )
        held = []
        try:
            for name, path, expected, build_id in artifact_specs:
                fd = _open_nofollow(path, deadline_ns)
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                        info.st_nlink != 1 or info.st_size <= 0 or info.st_size > 512 * 1024 * 1024):
                    os.close(fd)
                    raise PermissionError('private C34 helper input is not one bounded owned regular file')
                digest = hashlib.sha256(os.pread(fd, info.st_size + 1, 0)).hexdigest()
                if digest != expected:
                    os.close(fd)
                    raise PermissionError('private C34 helper input differs from reviewed digest')
                item = _HeldArtifact(_TOKEN, name, path, fd, digest, build_id, info)
                item.verify(deadline_ns)
                held.append(item)
            return cls(_TOKEN, tuple(held), deadline_ns)
        except BaseException:
            for item in held:
                item.close()
            raise

    def _take_helper_fd(self, deadline_ns):
        if self._consumed or deadline_ns != self._deadline_ns:
            raise PermissionError('private C34 helper capture is consumed or has another deadline')
        _deadline(deadline_ns)
        item = self._artifacts[0]
        item.verify(deadline_ns)
        fd = os.dup(item.fd)
        try:
            os.set_inheritable(fd, False)
            os.lseek(fd, 0, os.SEEK_SET)
        except BaseException:
            os.close(fd)
            raise
        object.__setattr__(self, '_consumed', True)
        return fd, item.identity, self.sha256

    def close(self):
        for item in self._artifacts:
            item.close()


class PrivateC34ArtifactCapture:
    """Immutable capture of fixed production roots, test actor, and helper."""
    __slots__ = ('_sealed', '_artifacts', 'helper_capture', 'profile_id', 'test_backend_role', 'source_root', 'source_head', 'source_symbols')

    def __setattr__(self, name, value):
        if getattr(self, '_sealed', False):
            raise AttributeError('private C34 artifact capture is immutable')
        object.__setattr__(self, name, value)

    def __init__(self, token, artifacts, helper_capture, source_symbols):
        if token is not _TOKEN:
            raise TypeError('private C34 artifact captures require capture()')
        self._sealed = False
        self._artifacts = MappingProxyType(dict(artifacts))
        self.helper_capture = helper_capture
        self.profile_id = 'NEWC34_INTEROP'
        self.source_root = _SOURCE_ROOT
        self.source_head = '646a641cfff77f4815e1e29829a09e1ed15a2999'
        self.source_symbols = MappingProxyType(dict(source_symbols))
        self.test_backend_role = 'TEST_ONLY_RX_OWNER_RELAY_CONTROL_ADAPTER'
        self._sealed = True

    @classmethod
    def capture(cls, deadline_ns):
        _deadline(deadline_ns)
        held = {}
        helper = None
        source_symbols = {}
        try:
            for name, (path, expected, build_id) in _FIXED_ARTIFACTS.items():
                _deadline(deadline_ns)
                alias = None
                alias_target = None
                alias_identity = None
                open_path = path
                if path.is_symlink():
                    expected_target = ('libker-posix.so.0' if name == 'posix' else
                        str(_BASE / 'cmake-host-runtime/libfstack.so') if name == 'runtime_ff_alias' else None)
                    if expected_target is None or os.readlink(path) != expected_target:
                        raise PermissionError('private C34 artifact has an unreviewed symlink alias')
                    link = os.lstat(path)
                    alias = path
                    alias_target = expected_target
                    alias_identity = (link.st_dev, link.st_ino, link.st_mtime_ns, link.st_ctime_ns)
                    open_path = path.resolve(strict=True)
                    expected_path = (_BASE / 'cmake-host-runtime/libker-posix.so.0.1.0'
                        if name == 'posix' else _BASE / 'cmake-host-runtime/libfstack.so')
                    if open_path != expected_path:
                        raise PermissionError('private C34 DSO alias resolves outside fixed output')
                fd = _open_nofollow(open_path, deadline_ns)
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                        info.st_nlink != 1 or info.st_size <= 0 or info.st_size > 512 * 1024 * 1024):
                    os.close(fd)
                    raise PermissionError('private C34 production artifact is not one bounded owned regular file')
                digest = hashlib.sha256(os.pread(fd, info.st_size + 1, 0)).hexdigest()
                if digest != expected:
                    os.close(fd)
                    raise PermissionError('private C34 production artifact differs from accepted digest')
                if alias is not None:
                    after_link = os.lstat(alias)
                    if ((after_link.st_dev, after_link.st_ino, after_link.st_mtime_ns, after_link.st_ctime_ns) != alias_identity or
                            alias.resolve(strict=True) != open_path):
                        os.close(fd)
                        raise PermissionError('private C34 POSIX DSO alias changed during capture')
                item = _HeldArtifact(_TOKEN, name, open_path, fd, digest, build_id, info,
                    alias, alias_target, alias_identity)
                item.verify(deadline_ns)
                held[name] = item
            if (held['nginx'].identity[1] != 6160153816 or
                    held['first_builtin_elf'].identity[1] != 6160164062 or
                    held['nginx'].sha256 != held['first_builtin_elf'].sha256 or
                    held['nginx'].build_id != '562529554981f479becf542d6c09133f2ebf9c07'):
                raise PermissionError('private C34 first and relinked fresh Nginx evidence differs')
            manifest = json.loads(os.pread(held['build_manifest'].fd, held['build_manifest'].identity[2] + 1, 0))
            if (manifest.get('source_head') != '646a641cfff77f4815e1e29829a09e1ed15a2999' or
                    manifest.get('nginx') != {'path': str(held['nginx'].path), 'sha256': held['nginx'].sha256} or
                    manifest.get('libfstack', {}).get('path') != str(held['runtime'].path) or
                    manifest.get('libfstack', {}).get('sha256') != held['runtime'].sha256):
                raise PermissionError('private C34 held build manifest does not describe its fixed fresh Nginx/runtime pair')
            provenance = json.loads(os.pread(held['input_provenance'].fd,
                held['input_provenance'].identity[2] + 1, 0))
            native = json.loads(os.pread(held['native_metadata'].fd,
                held['native_metadata'].identity[2] + 1, 0))
            dpdk = json.loads(os.pread(held['dpdk_manifest'].fd,
                held['dpdk_manifest'].identity[2] + 1, 0))
            if (provenance.get('artifact_root') != str(_BASE) or
                    provenance.get('fstack', {}).get('head') != '646a641cfff77f4815e1e29829a09e1ed15a2999' or
                    provenance.get('dpdk_adaptation', {}).get('head') != 'd129414711aa7c4954f997acf4c54338574a7d92' or
                    provenance.get('dpdk_adaptation', {}).get('manifest_sha256') != _DPDK_MANIFEST_SHA256 or
                    provenance.get('native_lkl', {}).get('metadata_sha256') != _NATIVE_METADATA_SHA256 or
                    provenance.get('native_lkl', {}).get('library_sha256') != native.get('library_sha256') or
                    native.get('fingerprint') != 'e0fec088f79096f4c4ea563d8f6b9714a8b39e567b64d83549c8829a70ed2262' or
                    native.get('library_sha256') != '17acd98ca13300253f417da61cab161baf28e8fdb18e1df2825bdd36ad15c9c1' or
                    dpdk.get('root') != str(_DPDK_MANIFEST.parent) or
                    dpdk.get('source', {}).get('head', {}).get('output') != 'd129414711aa7c4954f997acf4c54338574a7d92'):
                raise PermissionError('private C34 frozen native/DPDK provenance differs from the fresh build')
            graph_data = json.loads(os.pread(held['static_graphs'].fd, held['static_graphs'].identity[2] + 1, 0))
            if len(graph_data.get('roots', [])) != 11 or len(graph_data.get('graphs', [])) != 11 or any(
                    row.get('candidate_graph_status') != 'complete_static_candidate_only' for row in graph_data.get('graphs', [])):
                raise PermissionError('private C34 static dependency graph is incomplete or claims loader proof')
            runner_manifest = json.loads(os.pread(held['runner_manifest'].fd,
                held['runner_manifest'].identity[2] + 1, 0))
            if (runner_manifest.get('execution_authorized') is not False or
                    runner_manifest.get('prepared_only') is not True or
                    runner_manifest.get('object_union_sha256') != _OBJECT_UNION_SHA256 or
                    runner_manifest.get('nginx', {}).get('sha256') != held['nginx'].sha256):
                raise PermissionError('private C34 runner preparation is stale or claims execution')
            runner_preflight = json.loads(os.pread(held['runner_static_preflight'].fd,
                held['runner_static_preflight'].identity[2] + 1, 0))
            if (runner_preflight.get('execution_performed') is not False or
                    runner_preflight.get('actual_loader_choice_or_maps_proven') is not False or
                    runner_preflight.get('object_union_sha256') != _OBJECT_UNION_SHA256):
                raise PermissionError('private C34 static runner preparation claims runtime proof')
            alias_data = json.loads(os.pread(held['runner_aliases'].fd,
                held['runner_aliases'].identity[2] + 1, 0))
            alias_matches = []
            for group in alias_data.get('groups', []):
                for record in group.get('alias_records', []):
                    if record.get('input_path') == str(_BASE / 'ff-prefix/lib/libfstack.so'):
                        alias_matches.append((group, record))
            if len(alias_matches) != 1:
                raise PermissionError('private C34 runtime symlink alias is missing or ambiguous')
            alias_group, alias_record = alias_matches[0]
            if (alias_record.get('target_sha256') != held['runtime'].sha256 or
                    (alias_record.get('target_device'), alias_record.get('target_inode')) != held['runtime'].identity[:2] or
                    alias_record.get('realpath') != str(held['runtime'].path) or
                    held['runtime_ff_alias'].identity[:3] != held['runtime'].identity[:3] or
                    alias_record.get('lstat_device') != held['runtime_ff_alias'].alias_identity[0] or
                    alias_record.get('lstat_inode') != held['runtime_ff_alias'].alias_identity[1]):
                raise PermissionError('private C34 runtime symlink alias does not name the captured runtime')
            helper = PrivateC34HelperCapture._capture(deadline_ns)
            graph_roots = {row.get('root_name'): row.get('root', {}) for row in graph_data['graphs']}
            graph_bindings = {
                'nginx-relinked': 'nginx', 'matched-worker-shim': 'shim',
                'ker-fstack-nginx-runtime': 'runtime', 'ker-socket-preload': 'preload',
                'ker-fstack-socket-bridge': 'bridge', 'ker-posix': 'posix',
                'ker-io-worker': 'io_worker', 'ker-app': 'ker_app',
                'owner-group-helper-candidate': None,
                'test-only-rx-owner-relay-fixture': 'test_backend',
            }
            head_text = os.pread(held['source_git_head'].fd,
                held['source_git_head'].identity[2] + 1, 0).decode('ascii').strip()
            if head_text != '646a641cfff77f4815e1e29829a09e1ed15a2999':
                raise PermissionError('private C34 source root HEAD differs from fresh build manifest')
            symbols = {}
            nm_data = os.pread(held['nginx_symbols'].fd,
                held['nginx_symbols'].identity[2] + 1, 0).decode('ascii')
            for line in nm_data.splitlines():
                fields = line.split()
                if len(fields) == 3 and fields[2] in _SOURCE_EXPORT_NAMES:
                    if fields[2] in symbols or len(fields[1]) != 1 or not all(
                            ch in '0123456789abcdefABCDEF' for ch in fields[0]):
                        raise PermissionError('private C34 Nginx symbol inventory is ambiguous')
                    symbols[fields[2]] = (int(fields[0], 16), fields[1])
            if (symbols.keys() != _SOURCE_EXPORT_NAMES or any(
                    symbols[name][1] not in ('B', 'D') for name in _SOURCE_EXPORT_NAMES)):
                raise PermissionError('private C34 Nginx lacks its fixed source observer export inventory')
            source_symbols = symbols
            for graph_name, artifact_name in graph_bindings.items():
                root = graph_roots.get(graph_name)
                if root is None:
                    raise PermissionError('private C34 static graph lacks a captured root')
                item = (None if artifact_name is None else held[artifact_name])
                if item is None:
                    helper_item = helper._artifacts[0]
                    if (root.get('sha256') != helper_item.sha256 or
                            root.get('build_id') != helper_item.build_id or
                            root.get('inode') != helper_item.identity[1] or
                            root.get('device') != helper_item.identity[0]):
                        raise PermissionError('private C34 static graph helper candidate differs from reviewed helper')
                elif (root.get('sha256') != item.sha256 or root.get('build_id') != item.build_id or
                        root.get('inode') != item.identity[1] or root.get('device') != item.identity[0]):
                    raise PermissionError('private C34 static graph root differs from held artifact')
            return cls(_TOKEN, held, helper, source_symbols)
        except BaseException:
            for item in held.values(): item.close()
            if helper is not None: helper.close()
            raise

    def verify(self, deadline_ns):
        _deadline(deadline_ns)
        for item in self._artifacts.values(): item.verify(deadline_ns)
        for item in self.helper_capture._artifacts: item.verify(deadline_ns)

    def artifact(self, name):
        return self._artifacts[name]

    def close(self):
        for item in self._artifacts.values(): item.close()
        self.helper_capture.close()

    def __del__(self):
        try: self.close()
        except BaseException: pass
