"""Observe the unchanged shell supervisor and one original daemon fork.

The origin ACK correlates actor identities and pinned config/INI transcript
digests. It is neither source READY nor a generation/packet grant. The
upstream supervisor retains process ownership.
"""
import array
import errno
import hashlib
import importlib.util
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import select
import shutil
import socket
import stat
import struct
import subprocess
import sys
import time
from types import SimpleNamespace

_BOOTSTRAP_NAME = '_source_origin_bootstrap'
_BOOTSTRAP_PATH = Path(__file__).with_name('nginx_source_bootstrap_supervisor.py').resolve(strict=True)
bootstrap = sys.modules.get(_BOOTSTRAP_NAME)
if bootstrap is None:
    _SPEC = importlib.util.spec_from_file_location(_BOOTSTRAP_NAME, _BOOTSTRAP_PATH)
    bootstrap = importlib.util.module_from_spec(_SPEC)
    sys.modules[_BOOTSTRAP_NAME] = bootstrap
    try:
        _SPEC.loader.exec_module(bootstrap)
    except BaseException:
        del sys.modules[_BOOTSTRAP_NAME]
        raise
elif Path(getattr(bootstrap, '__file__', '')).resolve() != _BOOTSTRAP_PATH:
    raise ImportError('cached Origin bootstrap module belongs to another path')
identity = bootstrap.identity

_LAUNCHER_SPEC = importlib.util.spec_from_file_location('_source_origin_launcher',
    Path(__file__).with_name('ker-run.py'))
launcher = importlib.util.module_from_spec(_LAUNCHER_SPEC)
# Execute exactly the source bytes whose digest will be pinned by each launch.
# Reopening the pathname after module execution could hash a replacement.
with open(_LAUNCHER_SPEC.origin, 'rb') as _launcher_input:
    _launcher_before = os.fstat(_launcher_input.fileno())
    _launcher_source = _launcher_input.read(4 * 1024 * 1024 + 1)
    _launcher_after = os.fstat(_launcher_input.fileno())
    if (not stat.S_ISREG(_launcher_before.st_mode) or
            len(_launcher_source) > 4 * 1024 * 1024 or
            any(getattr(_launcher_before, field) != getattr(_launcher_after, field)
                for field in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))):
        raise RuntimeError('launcher source changed or exceeded its input limit')
_LAUNCHER_SHA256 = hashlib.sha256(_launcher_source).hexdigest()
exec(compile(_launcher_source, _LAUNCHER_SPEC.origin, 'exec'), launcher.__dict__)
del _launcher_source
_SOURCE_NETWORK_STARTUP = launcher.source_network_startup

ORIGIN_PREFIX = struct.Struct('=IHH6I7Q16s2Q')
ORIGIN = struct.Struct('=IHH6I7Q16s2QIIQQ32s32s')
ORIGIN_MAGIC = 0x4b534f41
ORIGIN_VERSION = 2
ORIGIN_PROOF_VERSION = 1
ORIGIN_REQUEST = 1
ORIGIN_ACK = 2
ORIGIN_MAX_STARTUP_NS = 5_000_000_000
SOURCE_CONFIG_MAX_BYTES = 64 * 1024
SOURCE_INI_MAX_BYTES = 16 * 1024
SOURCE_INI_LINE_MAX = 2047
SOURCE_RETRY_FAULT = 'flip_fail_once'
SOURCE_RETRY_ENV = 'KER_NGINX_SOURCE_ABORT_RETRY_ENABLE'
SOURCE_READY_DELAY_ENV = 'KER_NGINX_SOURCE_READY_DELAY_ENABLE'
SOURCE_READY_DELAY_MS = '15000'
SOURCE_ABORT_ENV = 'KER_NGINX_SOURCE_ABORT_ENABLE'
SOURCE_SYNACK_FAULT_ENV = 'KER_NGINX_SOURCE_SYNACK_FAULT_ENABLE'
SOURCE_HUP_FAULTS = {'rt20': 'ready_never', 'rt20b': 'ready_delay',
    'rt21': 'flip_fail', 'rt22': 'park_never', 'rt24': SOURCE_RETRY_FAULT,
    'rt26': 'synack_fail'}
SOURCE_UNPARKED_ABORT = {
    'rt20': ('READY wait timed out', 60_000),
    'rt22': ('G_old park confirmation timed out', 100),
}
SOURCE_FAULT_SWITCHES = {'ready_delay': SOURCE_READY_DELAY_ENV,
    'flip_fail': SOURCE_ABORT_ENV, 'ready_never': SOURCE_ABORT_ENV,
    'park_never': SOURCE_ABORT_ENV, SOURCE_RETRY_FAULT: SOURCE_RETRY_ENV,
    'synack_fail': SOURCE_SYNACK_FAULT_ENV}
SOURCE_KNI_ENV = 'KER_NGINX_SOURCE_KNI_ENABLE'
SOURCE_KNI_OPTIONS = {'enable': '1', 'method': 'reject', 'owner_proc_id': '1',
    'tcp_port': '80,443', 'udp_port': '53'}
SOURCE_BASELINE_SECONDS = '330'
SOURCE_BASELINE_AUTHORITY_NS = 420_000_000_000
SOURCE_RV9_AUTHORITY_NS = 1_800_000_000_000
SOURCE_UPGRADE_ENV = 'KER_NGINX_SOURCE_UPGRADE_ENABLE'
SOURCE_HUP_CASES = ('rt01', 'rt02', 'rv9', 'rt12', 'rt20', 'rt20b', 'rt21', 'rt22',
    'rt23', 'rt24', 'rt25', 'rt26', 'rt30', 'rt31')
SOURCE_CASE_TAGS = {'baseline': 'base', **{case: case for case in SOURCE_HUP_CASES}}
SOURCE_HUP_INI_CASES = {f'fstack_{tag}.ini': case for case, tag in SOURCE_CASE_TAGS.items()}
SOURCE_HUP_ARTIFACTS = frozenset(SOURCE_HUP_INI_CASES) | {
    f'ngx_{tag}.conf' for tag in SOURCE_CASE_TAGS.values()}
SHELL_SHA256 = '7efd3e0d10e584daa57377915da0ba2a9d1f67bebbcd2f512298230d71f35203'
SUPERVISOR_SHA256 = '901e5ab1acff7110621a205786bf349cb8085a9f8e6c8549d9901e2449fd5d74'
CHECKS_SHA256 = '686a57c12981af7be78a24f2f8e94e0070e456ee5042fe0f528b200bfc37bb7d'
RUNTIME_SHA256 = 'af7961ecd6bf9bf3d9e9a924c5cec94ca4ce1ae0d07ee2f40e4712d11d2e7841'
# Exact plain80 ELF observed by one accepted -V loader probe. The receipt
# confirms the loaded main image, shim providers, owner ABI callback, and
# pre-module-init snapshot boundary only; it does not qualify source authority
# or a source grant. Evidence: review-evidence/observational-constructor-probe-20261113/
# observer-run-nkjg44xj/receipt.json (SHA-256 42137f5618b220e4831e174aaa01d9959710fb1948c31b5656c60bbb91489759).
# Keep the unconditional ENOTSUP boundary below until worker/cycle proof exists.
NGINX_SHA256 = '0bce08a71c79cdf6be2164e935b4893a4857831c53017847d6b7efd544109a4c'
MIME_SHA256 = '6f95d1d7d75e3c072907d845622a69d23110d1266c16ff122b3109b8b21f3ae9'
MIME_CONFIG_PATH = '/usr/local/nginx_fstack/conf/mime.types'
SOURCE_NETWORK_READBACK_ENV = 'KER_SOURCE_NETWORK_READBACK'
SourceNetworkExpectation = _SOURCE_NETWORK_STARTUP.SourceNetworkExpectation


def _read_pinned(pinned, deadline_ns=None, maximum=4 * 1024 * 1024):
    pinned.live(deadline_ns)
    require(0 <= pinned.frozen[2] <= maximum,
        'pinned source input exceeds its byte limit')
    data = os.pread(pinned.fd, pinned.frozen[2] + 1, 0)
    require(len(data) == pinned.frozen[2], 'pinned source input was truncated')
    pinned.live(deadline_ns)
    return data


def source_hup_case(cases):
    prefix, _, case = cases.partition(',')
    require(prefix == 'precheck' and case in SOURCE_CASE_TAGS,
        'source observer requires precheck followed by one supported HUP case')
    return case


def validate_source_hup_fault(case, arguments, environment, captured_fault):
    """Match the exact original fault case to the frozen launch artifacts."""
    fault = SOURCE_HUP_FAULTS.get(case)
    require(captured_fault == fault, 'source HUP case and captured fault build differ')
    options = [index for index, arg in enumerate(arguments) if arg == '--fault']
    delays = [index for index, arg in enumerate(arguments) if arg == '--fault-delay-ms']
    explicit_delay = (len(delays) == 1 and delays[0] + 1 < len(arguments) and
        arguments[delays[0] + 1] == SOURCE_READY_DELAY_MS)
    fault_switches = {key: environment[key] for key in
        SOURCE_FAULT_SWITCHES.values() if key in environment}
    expected_switches = {SOURCE_FAULT_SWITCHES[fault]: '1'} if fault is not None else {}
    baseline = [index for index, arg in enumerate(arguments) if arg == '--baseline-duration']
    require((len(baseline) == 1 and
                arguments[baseline[0] + 1:baseline[0] + 2] == [SOURCE_BASELINE_SECONDS])
            if case == 'baseline' else not baseline,
            'source baseline requires its original duration')
    require((environment.get(SOURCE_KNI_ENV) == '1' and
                arguments.count('--kernel-nic-ip') == 1)
            if case == 'rt12' else (SOURCE_KNI_ENV not in environment and
                '--kernel-nic-ip' not in arguments),
            'source KNI configuration is scoped to the original rt12 case')
    repeated = environment.get('KER_NGINX_SOURCE_SUCCESSOR_ENABLE')
    round_args = [arg for arg in arguments if arg in ('--rounds', '-r', '--interval', '-i')]
    if case == 'rv9':
        require(repeated == '1' and round_args == ['--rounds', '--interval'] and
            arguments[arguments.index('--rounds') + 1:arguments.index('--rounds') + 2] == ['100'] and
            arguments[arguments.index('--interval') + 1:arguments.index('--interval') + 2] == ['15'],
            'rv9 requires the original 100 rounds at 15-second intervals')
    else:
        require(repeated is None and not round_args,
            'committed successor authority is scoped to the original rv9 case')
    require((case == 'rt25' and environment.get(SOURCE_UPGRADE_ENV) == '1') or
        (case != 'rt25' and SOURCE_UPGRADE_ENV not in environment),
        'cross-master generation directory is scoped to the original rt25 case')
    require('--baseline' not in arguments and
        (explicit_delay if fault == 'ready_delay' else not delays) and
        fault_switches == expected_switches and
        ((fault is None and not options) or
         (fault is not None and len(options) == 1 and options[0] + 1 < len(arguments) and
            arguments[options[0] + 1] == fault)) and
        'FF_FAULT' not in environment and 'FF_FAULT_DELAY_MS' not in environment,
        'source HUP fault arguments or environment differ from the captured case')


def render_source_hup_config(shell_bytes, output, case='rt01'):
    """Render only the pinned shell's gen_nginx_conf here-doc, without a shell."""
    require(type(shell_bytes) is bytes and len(shell_bytes) <= 4 * 1024 * 1024 and
        b'\0' not in shell_bytes and b'\r' not in shell_bytes,
        'pinned shell source is malformed or oversized')
    require(case in SOURCE_CASE_TAGS, 'unsupported source HUP config case')
    output = os.fspath(output)
    encoded_output = os.fsencode(output)
    require(len(encoded_output) <= 200 and re.fullmatch(
        rb'/[A-Za-z0-9._/-]+', encoded_output) is not None and
        all(part not in (b'', b'.', b'..') for part in encoded_output.split(b'/')[1:]),
        'source HUP output path contains unsafe template bytes')
    source = shell_bytes.decode('ascii', errors='strict')
    starts = list(re.finditer(r'(?m)^gen_nginx_conf\(\) \{[^\n]*\n', source))
    all_functions = list(re.finditer(r'(?m)^[A-Za-z_][A-Za-z0-9_]*\(\) \{', source))
    require(len(starts) == 1 and len(all_functions) >= 2 and
        sum(match.start() == starts[0].start() for match in all_functions) == 1,
        'pinned shell has an ambiguous source HUP template function')
    following = [match.start() for match in all_functions if match.start() > starts[0].start()]
    require(following, 'pinned source HUP template function has no closing boundary')
    function = source[starts[0].start():following[0]]
    heredocs = re.findall(r'(?m)^    cat > "\$conf" <<CONF\n(.*?)^CONF\n',
        function, re.S)
    require(len(heredocs) == 1 and function.count('<<') == 1 and
        len(re.findall(r'(?m)^CONF$', function)) == 1,
        'pinned shell has an ambiguous source HUP template here-doc')
    template = heredocs[0].encode('ascii')
    require(b'`' not in template and b'\\' not in template and b'$(' not in template,
        'source HUP template contains shell expansion syntax outside the closed substitutions')
    values = {b'WORKERS': b'1', b'stline': (b'worker_shutdown_timeout  15s;'
        if case == 'rv9' else b''), b'OUT': encoded_output,
        b'tag': SOURCE_CASE_TAGS[case].encode('ascii'), b'listen': b'80'}
    def substitute(match):
        name = match.group(1)
        require(name in values, 'source HUP template contains an unknown shell variable')
        return values[name]
    rendered = re.sub(rb'\$([A-Za-z_][A-Za-z0-9_]*)', substitute, template)
    require(not re.search(rb'\$|`|\x00', rendered),
        'source HUP rendered config retains expansion or control syntax')
    require(rendered.count(b'include       ' + MIME_CONFIG_PATH.encode() + b';\n') == 1 and
        len(re.findall(rb'(?m)^\s*include\s+', rendered)) == 1,
        'source HUP rendered config does not have exactly its pinned MIME include')
    return rendered


def config_dump_transcript_sha256(main_path, main_bytes, mime_bytes):
    """Match source_dump_hash: domain-NUL, count, ordered names and contents."""
    entries = ((os.fsencode(main_path), main_bytes),
        (MIME_CONFIG_PATH.encode(), mime_bytes))
    digest = hashlib.sha256()
    digest.update(b'ker-nginx-config-dump-v1\0')
    digest.update(struct.pack('>Q', len(entries)))
    for name, content in entries:
        require(type(content) is bytes and name and b'\0' not in name,
            'invalid config-dump transcript field')
        digest.update(struct.pack('>Q', len(name)))
        digest.update(name)
        digest.update(struct.pack('>Q', len(content)))
        digest.update(content)
    return digest.digest()


def ini_transcript_sha256(data):
    require(type(data) is bytes, 'invalid source INI transcript')
    return hashlib.sha256(b'ker-source-native-ini-v1\0' +
        struct.pack('>Q', len(data)) + data).digest()


def validate_origin_proof(fields, binding):
    """Correlate the appended adapter-cycle proof with independently pinned bytes."""
    require(type(fields) is list and len(fields) == 25 and binding is not None,
        'origin proof or pinned artifact binding is unavailable')
    proof_version, proof_flags, serial, cycle_token, config_digest, ini_digest = fields[19:25]
    require(proof_version == ORIGIN_PROOF_VERSION and proof_flags == 0 and
        type(serial) is int and serial > 0 and type(cycle_token) is int and cycle_token > 0 and
        type(config_digest) is bytes and len(config_digest) == 32 and
        type(ini_digest) is bytes and len(ini_digest) == 32 and
        re.fullmatch(r'[0-9a-f]{64}', getattr(binding, 'config_sha256', '')) is not None and
        re.fullmatch(r'[0-9a-f]{64}', getattr(binding, 'ini_sha256', '')) is not None and
        config_digest.hex() == binding.config_sha256 and ini_digest.hex() == binding.ini_sha256,
        'origin adapter-cycle proof does not match pinned config/INI transcripts')
    # Serial and token are opaque adapter-cycle correlation values. They are
    # deliberately not interpreted as source epochs or imported generations.
    return SimpleNamespace(proof_version=proof_version, proof_flags=proof_flags,
        adapter_cycle_serial=serial, opaque_cycle_token=cycle_token,
        config_sha256=config_digest.hex(), ini_sha256=ini_digest.hex())


def require(condition, message):
    if not condition:
        raise PermissionError(message)


def file_identity(value):
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns


def _read_original_output_receipt(launch, name, limit, deadline_ns):
    held = os.fstat(launch.output_fd)
    path = os.stat(launch.output, follow_symlinks=False)
    require(stat.S_ISDIR(held.st_mode) and held.st_uid == os.getuid() and
        stat.S_IMODE(held.st_mode) & 0o077 == 0 and
        (held.st_dev, held.st_ino) == launch.output_identity ==
            (path.st_dev, path.st_ino),
        'original supervisor output directory changed')
    try:
        fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=launch.output_fd)
    except FileNotFoundError as exc:
        raise BlockingIOError(errno.EAGAIN,
            'original supervisor receipt is not published yet') from exc
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and
            stat.S_IMODE(before.st_mode) & 0o077 == 0 and
            before.st_nlink == 1 and before.st_size <= limit,
            'invalid original supervisor receipt file')
        data = bytearray()
        while len(data) <= limit:
            require(time.monotonic_ns() < deadline_ns,
                'original supervisor receipt observation expired')
            chunk = os.read(fd, min(65536, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(fd)
        try:
            current = os.stat(name, dir_fd=launch.output_fd, follow_symlinks=False)
        except FileNotFoundError as exc:
            raise BlockingIOError(errno.EAGAIN,
                'original supervisor receipt was atomically replaced') from exc
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_nlink', 'st_size',
            'st_mtime_ns', 'st_ctime_ns')
        if not all(getattr(before, field) == getattr(after, field) ==
                getattr(current, field) for field in fields):
            raise BlockingIOError(errno.EAGAIN,
                'original supervisor receipt changed during observation')
        require(len(data) <= limit and len(data) == before.st_size,
            'original supervisor receipt is truncated or oversized')
        return bytes(data), (before.st_dev, before.st_ino)
    finally:
        os.close(fd)


def namespace_identity(pid):
    value = os.stat(f'/proc/{pid}/ns/pid')
    return value.st_dev, value.st_ino


def parent_pid(pid):
    value = Path(f'/proc/{pid}/stat').read_text()
    fields = value[value.rfind(')') + 2:].split()
    require(len(fields) >= 20, 'incomplete process identity')
    return int(fields[1])


def actor_namespaces(pid):
    result = []
    for name in ('pid', 'net', 'mnt'):
        value = os.stat(f'/proc/{pid}/ns/{name}')
        result.append((name, value.st_dev, value.st_ino))
    return tuple(result)


def bounded_cmdline(pid, deadline_ns):
    result = bytearray()
    fd = os.open(f'/proc/{pid}/cmdline', os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        while True:
            require(time.monotonic_ns() < deadline_ns, 'native I/O argv observation expired')
            block = os.read(fd, min(8192, 65537 - len(result)))
            if not block:
                break
            result.extend(block)
            require(len(result) <= 65536, 'native I/O command line exceeds limit')
    finally:
        os.close(fd)
    require(time.monotonic_ns() < deadline_ns and result and result[-1] == 0,
        'native I/O command line is incomplete or expired')
    return bytes(result)


class PinnedFile:
    def __init__(self, path, expected_hash=None, deadline_ns=None, maximum=None,
            nonblocking=False):
        if deadline_ns is not None:
            require(time.monotonic_ns() < deadline_ns, 'origin observation deadline expired')
        self.path = Path(path).resolve(strict=True)
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        if nonblocking:
            flags |= os.O_NONBLOCK
        self.fd = os.open(self.path, flags)
        self.maximum = maximum
        self.nonblocking = bool(nonblocking)
        try:
            value = os.fstat(self.fd)
            require(stat.S_ISREG(value.st_mode) and
                (maximum is None or (value.st_size >= 0 and value.st_size <= maximum)),
                'pinned input is not regular or exceeds its byte limit')
            self.frozen = file_identity(value)
            self.sha256 = self.digest(deadline_ns)
            require(expected_hash is None or self.sha256.hex() == expected_hash,
                'pinned original input hash mismatch')
            self.live(deadline_ns)
        except BaseException:
            self.close()
            raise

    def digest(self, deadline_ns=None):
        digest = hashlib.sha256()
        offset = 0
        while True:
            if deadline_ns is not None:
                require(time.monotonic_ns() < deadline_ns, 'origin observation deadline expired')
            block = os.pread(self.fd, 65536, offset)
            if not block:
                break
            require(self.maximum is None or offset + len(block) <= self.maximum,
                'pinned source input exceeds its byte limit')
            digest.update(block)
            offset += len(block)
        if deadline_ns is not None:
            require(time.monotonic_ns() < deadline_ns, 'origin observation deadline expired')
        return digest.digest()

    def live(self, deadline_ns=None):
        require(self.fd >= 0 and file_identity(os.fstat(self.fd)) == self.frozen and
            file_identity(os.stat(self.path, follow_symlinks=False)) == self.frozen and
            self.digest(deadline_ns) == self.sha256 and
            file_identity(os.fstat(self.fd)) == self.frozen,
            'pinned input changed')

    def matches_process(self, pid, deadline_ns=None):
        self.live(deadline_ns)
        value = os.stat(f'/proc/{pid}/exe')
        require((value.st_dev, value.st_ino) == self.frozen[:2],
            'process executable inode mismatch')

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


class PinnedOutputArtifact:
    """Hold one generated regular file relative to the captured output dir."""
    def __init__(self, directory_fd, name, maximum, deadline_ns):
        self.name = name
        self.fd = -1
        require(name in SOURCE_HUP_ARTIFACTS and
            type(maximum) is int and maximum > 0 and
            time.monotonic_ns() < deadline_ns,
            'invalid generated source artifact request')
        self.fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=directory_fd)
        try:
            before = os.fstat(self.fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and
                before.st_nlink == 1 and before.st_size >= 0 and
                before.st_size <= maximum and before.st_mode & 0o022 == 0,
                'generated source artifact is not a bounded owned regular file')
            self.frozen = file_identity(before)
            chunks = bytearray()
            offset = 0
            while offset <= maximum:
                require(time.monotonic_ns() < deadline_ns,
                    'generated source artifact observation expired')
                block = os.pread(self.fd, min(8192, maximum + 1 - offset), offset)
                if not block:
                    break
                chunks.extend(block)
                offset += len(block)
            require(len(chunks) <= maximum and time.monotonic_ns() < deadline_ns,
                'generated source artifact exceeded its observation bound')
            self.data = bytes(chunks)
            self.sha256 = hashlib.sha256(self.data).digest()
            self.live(directory_fd, deadline_ns)
        except BaseException:
            self.close()
            raise

    def live(self, directory_fd, deadline_ns):
        require(time.monotonic_ns() < deadline_ns and self.fd >= 0,
            'generated source artifact observation expired')
        held = os.fstat(self.fd)
        entry = os.stat(self.name, dir_fd=directory_fd, follow_symlinks=False)
        require(stat.S_ISREG(held.st_mode) and stat.S_ISREG(entry.st_mode) and
            held.st_uid == os.getuid() and held.st_nlink == 1 and
            file_identity(held) == self.frozen and file_identity(entry) == self.frozen,
            'generated source artifact identity changed')
        digest = hashlib.sha256()
        offset = 0
        while offset < len(self.data):
            require(time.monotonic_ns() < deadline_ns,
                'generated source artifact recheck expired')
            block = os.pread(self.fd, min(8192, len(self.data) - offset), offset)
            require(block, 'generated source artifact became truncated')
            digest.update(block)
            offset += len(block)
        require(time.monotonic_ns() < deadline_ns and digest.digest() == self.sha256 and
            file_identity(os.fstat(self.fd)) == self.frozen and
            file_identity(os.stat(self.name, dir_fd=directory_fd,
                follow_symlinks=False)) == self.frozen,
            'generated source artifact changed while observed')

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


class OriginalLaunchUnsettled(RuntimeError):
    def __init__(self, launch, cause):
        super().__init__('original launch failed without verified settlement: ' + str(cause))
        self.launch = launch


class OriginalShellLaunch:
    """A captured child launch, never an authority discovered from a pidfile.

    The original shell must perform its own exec into its original supervisor.
    Exact input files stay open and unchanged through origin observation.
    Callers must retain this object and settle the original supervisor before
    closing it; this observer never takes over its descendant cleanup.
    Capture the source network template first and pass its expectation here;
    this constructor takes ownership of that pinned descriptor immediately.
    """
    def __init__(self, source_root, arguments, environment, nginx, nginx_hash,
            *, network_expectation, stdout, stderr, cwd=None,
            _private_c34_capture=None):
        require(type(network_expectation) is SourceNetworkExpectation and
            type(network_expectation.template_file) is PinnedFile,
            'original shell launch requires a captured source network template')
        self.process = None
        try:
            self._initialize(source_root, arguments, environment, nginx, nginx_hash,
                network_expectation=network_expectation, stdout=stdout, stderr=stderr,
                cwd=cwd, private_c34_capture=_private_c34_capture)
        except BaseException:
            if self.process is None:
                network_expectation.template_file.close()
            raise

    def _initialize(self, source_root, arguments, environment, nginx, nginx_hash,
            *, network_expectation, stdout, stderr, cwd=None, private_c34_capture=None):
        require(sys.byteorder == 'little', 'origin wire requires little-endian host')
        require(type(arguments) is list and all(type(arg) is str for arg in arguments),
            'invalid original shell arguments')
        if private_c34_capture is None:
            require(bytes(nginx_hash).hex() == NGINX_SHA256,
                'original daemon observer supports only its observed pinned Nginx build')
        else:
            require(type(self) is PrivateC34OriginalShellLaunch,
                'private C34 capture is accepted only by its exact private launch type')
            c34_module = sys.modules.get('_ker_nginx_source_c34_artifacts')
            require(c34_module is not None and
                Path(c34_module.__file__).resolve(strict=True) ==
                    Path(__file__).with_name('nginx_source_c34_artifact_provider.py').resolve(strict=True) and
                type(private_c34_capture) is c34_module.PrivateC34ArtifactCapture,
                'private C34 Origin requires its exact fixed artifact capture')
            require(bytes(nginx_hash).hex() == private_c34_capture.artifact('nginx').sha256 and
                Path(nginx).resolve(strict=True) == private_c34_capture.artifact('nginx').path and
                Path(source_root).resolve(strict=True) == private_c34_capture.source_root and
                private_c34_capture.source_head == '646a641cfff77f4815e1e29829a09e1ed15a2999' and
                private_c34_capture.source_fault == c34_module._SOURCE_FAULT and
                private_c34_capture.artifact('build_manifest').sha256 ==
                    c34_module._BUILD_MANIFEST_SHA256 and
                frozenset(private_c34_capture.source_symbols) == frozenset((
                    'ngx_cycle', 'ngx_ff_reload_shm', 'ngx_ff_graceful_reload',
                    'ngx_ff_process', 'ngx_process', 'ngx_worker', 'ngx_process_slot')),
                'private C34 source root/Nginx/build manifest differs from captured artifact map')
            private_c34_capture.verify(int(environment.get('KER_NGINX_SOURCE_BOOTSTRAP_DEADLINE_NS', '0')))
            self.c34_artifact_capture = private_c34_capture
        self.files = []
        self.process = None
        self.pidfd = -1
        self.master_pidfd = -1
        self.origin_pidfd = -1
        self.output_fd = -1
        self.context = None
        self.origin_channel = None
        self.consumed = False
        self.native_io_observation_started = False
        self.native_io_ready = None
        self.native_io_pidfd = self.native_io_stdout_fd = -1
        self.source_root = None
        self.settlement = None
        self.creator_pid = os.getpid()
        self.creator_start = identity._start_ticks(self.creator_pid)
        self.arguments = list(arguments)
        self.nginx_argument = os.fspath(nginx)
        self.environment = dict(environment)
        require(not any(key.startswith(('GR_SUPERVISOR_', 'BASH_FUNC_'))
                for key in self.environment) and
            not any(self.environment.get(key) for key in ('LD_PRELOAD', 'LD_AUDIT',
                'BASH_ENV', 'ENV')) and
            not any(key.startswith('PYTHON') and key != 'PYTHONDONTWRITEBYTECODE'
                for key in self.environment),
            'original shell launch has an alternate loader, startup, or supervisor context')
        require(self.environment.get('KER_NGINX_SOURCE_SHELL_ENABLE') == '1' and
            self.environment.get('KER_NGINX_SOURCE_FIRST_HUP_ENABLE') == '1' and
            self.environment.get('KER_NGINX_SOURCE_BOOTSTRAP_SUPERVISOR_PID') == str(self.creator_pid) and
            self.environment.get('KER_NGINX_SOURCE_BOOTSTRAP_SUPERVISOR_START') == str(self.creator_start),
            'source launch is not bound to this supervisor')
        nonce = self.environment.get('KER_NGINX_SOURCE_BOOTSTRAP_NONCE', '')
        require(re.fullmatch('[0-9a-f]{32}', nonce) is not None and any(bytes.fromhex(nonce)),
            'invalid immutable launch nonce')
        self.nonce = bytes.fromhex(nonce)
        self.epoch = int(self.environment['KER_NGINX_SOURCE_BOOTSTRAP_EPOCH'])
        self.deadline_ns = int(self.environment['KER_NGINX_SOURCE_BOOTSTRAP_DEADLINE_NS'])
        now = time.monotonic_ns()
        baseline_scope = (private_c34_capture is not None and
            self._option_value(('--cases', '-c'), 'cases') == 'precheck,baseline')
        rv9_scope = (private_c34_capture is not None and
            self._option_value(('--cases', '-c'), 'cases') == 'precheck,rv9')
        authority = (SOURCE_RV9_AUTHORITY_NS if rv9_scope else
            SOURCE_BASELINE_AUTHORITY_NS if baseline_scope else 300_000_000_000)
        require(self.epoch > 0 and now < self.deadline_ns <= now + authority,
            'invalid immutable launch lifetime')
        require(type(network_expectation) is SourceNetworkExpectation and
            network_expectation.deadline_ns == self.deadline_ns and
            network_expectation.repeated == rv9_scope and
            network_expectation.template_file.nonblocking and
            network_expectation.template_file.maximum == SOURCE_INI_MAX_BYTES,
            'captured source network template has a different lifetime or open mode')
        self.network_expectation = network_expectation
        self.network_template = network_expectation.template_file
        self.files.append(self.network_template)
        self.backend_handoff = _SOURCE_NETWORK_STARTUP.RetainedBackendHandoff.for_network_expectation(
            network_expectation, self.creator_pid, self.creator_start)
        self.backend_receipt = None
        self.backend_runtime_actor = None
        require(self.arguments.count('--out') == 1,
            'original shell needs one explicit private output directory')
        self.output_argument = self.arguments[self.arguments.index('--out') + 1]
        self.output = str(Path(self.output_argument).resolve())
        require(self.output_argument == self.output and not any(ch.isspace()
            for ch in self.output),
            'original output directory must be canonical and contain no whitespace')
        require(not Path(self.output).exists(), 'original output directory must be fresh')
        self.source_case = self._validate_source_launch_scope()
        tag = SOURCE_CASE_TAGS[self.source_case]
        self.expected_ini = f'{self.output}/fstack_{tag}.ini'
        self.expected_config = f'{self.output}/ngx_{tag}.conf'
        require(len(os.fsencode(self.expected_ini)) <= 107 and
            len(os.fsencode(self.output + '/fstack-')) < 4096,
            'original HUP output path exceeds the native INI limits')
        require(self.environment.get('KER_FSTACK_NGINX_INI') == self.expected_ini,
            'source launch INI path is not bound to the original HUP output')
        require(self._option_value(('--fstack-conf',), 'f-stack config template') ==
            network_expectation.template_path and
            str(self.network_template.path) == network_expectation.template_path,
            'original shell option differs from the captured source network template')
        self.run_id = None
        self.artifact_binding = None
        self.origin_proof = None
        try:
            source_root = Path(source_root).resolve(strict=True)
            self.source_root = source_root
            self.shell = self.pin(source_root / 'tests/integration/test_graceful_reload.sh', SHELL_SHA256)
            self.mime_source = self.pin(source_root / 'app/nginx-1.28.0/conf/mime.types',
                MIME_SHA256)
            template_stat = os.fstat(self.network_template.fd)
            require(template_stat.st_uid == os.getuid() and template_stat.st_nlink == 1 and
                template_stat.st_size <= SOURCE_INI_MAX_BYTES and
                stat.S_IMODE(template_stat.st_mode) & 0o022 == 0,
                'source network template is not a private bounded owned regular file')
            self.network_template.live(self.deadline_ns)
            template_bytes = _read_pinned(self.network_template, self.deadline_ns,
                SOURCE_INI_MAX_BYTES)
            template_sections = self._source_ini_values(template_bytes)
            network = template_sections['port0']
            require(self.network_template.sha256.hex() ==
                    network_expectation.template_sha256 and
                network_expectation.template_path == str(self.network_template.path) and
                (network['addr'], network['netmask'], network['broadcast'], network['gateway']) ==
                    (network_expectation.address, network_expectation.netmask,
                        network_expectation.broadcast, network_expectation.gateway),
                'captured source network expectation differs from its pinned template bytes')
            expected_readback = self.network_expectation.readback_setting()
            supplied_readback = self.environment.get(SOURCE_NETWORK_READBACK_ENV)
            require(supplied_readback in (None, expected_readback),
                'source network readback setting differs from the pinned template')
            self.environment[SOURCE_NETWORK_READBACK_ENV] = expected_readback
            self.supervisor_script = self.pin(source_root / 'tests/integration/common/reload_supervisor.py',
                SUPERVISOR_SHA256)
            self.checks_script = self.pin(source_root / 'tests/integration/common/reload_checks.py',
                CHECKS_SHA256)
            self.runtime_script = self.pin(source_root / 'tests/integration/common/reload_runtime.sh',
                RUNTIME_SHA256)
            self.launcher_script = self.pin(Path(__file__).with_name('ker-run.py'),
                _LAUNCHER_SHA256)
            self.common = source_root / 'tests/integration/common'
            require(not (self.common / '__pycache__').exists(),
                'original supervisor source requires an uncached private import directory')
            python = shutil.which('python3', path=self.environment.get('PATH', os.defpath))
            require(python is not None, 'original supervisor interpreter unavailable')
            self.python = self.pin(python)
            self.bash = self.pin('/bin/bash')
            if private_c34_capture is not None:
                private_c34_capture.verify(self.deadline_ns)
            self.nginx = self.pin(nginx, bytes(nginx_hash).hex())
            if private_c34_capture is not None:
                expected_identity = private_c34_capture.artifact('nginx').identity
                require(self.nginx.frozen[:3] == expected_identity[:3],
                    'private C34 pinned Nginx descriptor differs from held artifact')
            self.pid_namespace = namespace_identity(os.getpid())
            self.network_template.live(self.deadline_ns)
            require(self.environment.get(SOURCE_NETWORK_READBACK_ENV) ==
                    self.network_expectation.readback_setting() and
                self._option_value(('--fstack-conf',), 'f-stack config template') ==
                    self.network_expectation.template_path,
                'pinned source network template changed before original launch')
            if private_c34_capture is not None:
                private_c34_capture.verify(self.deadline_ns)
            self.process = subprocess.Popen([str(self.bash.path), str(self.shell.path), *self.arguments],
                env=self.environment, cwd=cwd, stdout=stdout, stderr=stderr,
                close_fds=True)
            self.pidfd = os.pidfd_open(self.process.pid)
            self.start = identity._start_ticks(self.process.pid)
            require(parent_pid(self.process.pid) == self.creator_pid,
                'original shell is not this captured child')
        except BaseException as error:
            if self.process is not None and self.process.poll() is None:
                # Retain this object and its identity proofs if the original
                # supervisor cannot settle. Never report a timed-out TERM as
                # cleanup or throw away an unknown live subtree.
                try:
                    self.cleanup_deadline_ns = time.monotonic_ns() + 15_000_000_000
                    self.process.terminate()
                    remaining = (self.cleanup_deadline_ns - time.monotonic_ns()) / 1_000_000_000
                    require(remaining > 0, 'original launch cleanup deadline expired')
                    self.process.wait(timeout=remaining)
                except BaseException as cleanup_error:
                    raise OriginalLaunchUnsettled(self, cleanup_error) from error
            if self.process is not None:
                raise OriginalLaunchUnsettled(self, error) from error
            self.close()
            raise

    def pin(self, path, expected_hash=None, deadline_ns=None, maximum=None):
        value = PinnedFile(path, expected_hash, deadline_ns, maximum)
        self.files.append(value)
        return value

    def _option_value(self, aliases, label):
        found = []
        index = 0
        while index < len(self.arguments):
            if self.arguments[index] in aliases:
                require(index + 1 < len(self.arguments),
                    'original shell ' + label + ' option lacks a value')
                found.append(self.arguments[index + 1])
                index += 2
            else:
                index += 1
        require(len(found) == 1,
            'original shell requires exactly one ' + label + ' option')
        return found[0]

    def _validate_source_launch_scope(self):
        case = source_hup_case(self._option_value(('-c', '--cases'), 'cases'))
        capture = getattr(self, 'c34_artifact_capture', None)
        validate_source_hup_fault(case, self.arguments, getattr(self, 'environment', {}),
            getattr(capture, 'source_fault', None))
        if capture is not None:
            require(self._option_value(('--build-manifest',), 'build manifest') ==
                str(capture.artifact('build_manifest').path),
                'original build manifest differs from the held artifact')
        require((case == 'rt01' or type(self) is PrivateC34OriginalShellLaunch) and
            self._option_value(('--workers',), 'workers') == '1' and
            self._option_value(('--graceful',), 'graceful') == '1' and
            self._option_value(('-t', '--target-ip'), 'target') != '' and
            self._option_value(('-o', '--out'), 'output') == self.output and
            self.arguments.count('--out') == 1,
            'source observer requires the matching one-worker graceful HUP profile')
        template_path = self._option_value(('--fstack-conf',), 'f-stack config template')
        require(Path(template_path).is_absolute() and
            str(Path(template_path).resolve(strict=False)) == template_path and
            self.arguments.count('--fstack-conf') == 1,
            'source observer requires one canonical absolute --fstack-conf template')
        expectation = getattr(self, 'network_expectation', None)
        if expectation is not None:
            require(template_path == expectation.template_path and
                self._option_value(('-t', '--target-ip'), 'target') == expectation.address,
                'original target or f-stack template differs from pinned source network')
            if case == 'rt12':
                target = ipaddress.IPv4Address(expectation.address)
                management = ipaddress.IPv4Address(int(target) + 1)
                require(self._option_value(('--kernel-nic-ip',), 'management address') ==
                    str(management) and str(management) != expectation.gateway and
                    management < ipaddress.IPv4Address(expectation.broadcast),
                    'source management address differs from the captured subnet')
        nginx_options = [self.arguments[index + 1]
            for index, value in enumerate(self.arguments[:-1]) if value == '--nginx']
        require(len(nginx_options) <= 1 and
            (not nginx_options or nginx_options[0] == self.nginx_argument),
            'original shell Nginx option differs from the pinned launch executable')
        return case

    @staticmethod
    def _source_ini_values(data, *, kni=False):
        require(type(data) is bytes and 0 < len(data) <= SOURCE_INI_MAX_BYTES and
            b'\0' not in data, 'source INI is empty, oversized, or contains NUL')
        sections = {}
        current = None
        for number, raw_line in enumerate(data.splitlines(), 1):
            require(len(raw_line) <= SOURCE_INI_LINE_MAX,
                'source INI line exceeds the original parser bound')
            line = raw_line.strip()
            if number == 1 and line.startswith(b'\xef\xbb\xbf'):
                line = line[3:].lstrip()
            if not line or line.startswith((b'#', b';')):
                continue
            if line.startswith(b'['):
                close = line.find(b']')
                require(close > 1, 'source INI has a malformed section')
                tail = line[close + 1:].strip()
                require(not tail or tail.startswith((b'#', b';')),
                    'source INI section has trailing data')
                try:
                    name = line[1:close].decode('ascii')
                except UnicodeDecodeError as error:
                    raise PermissionError('source INI section is not ASCII') from error
                require((name in ('ker_socket_broker', 'dpdk', 'port0') or
                    (name == 'kni' and kni)) and name not in sections, 'source INI has an unknown or duplicate section')
                sections[name] = {}
                current = name
                continue
            require(current is not None and b'=' in line,
                'source INI has a key outside a section or malformed record')
            key_bytes, value_bytes = line.split(b'=', 1)
            try:
                key = key_bytes.strip().decode('ascii')
                value = value_bytes.strip().decode('ascii')
            except UnicodeDecodeError as error:
                raise PermissionError('source INI key/value is not ASCII') from error
            require(key and value and key not in sections[current] and
                '#' not in value and ';' not in value,
                'source INI has an empty, duplicate, or commented value')
            sections[current][key] = value
        expected = {
            'ker_socket_broker': {'version', 'path'},
            'dpdk': {'graceful_reload', 'lcore_mask', 'primary_slim',
                'file_prefix', 'fstack_log_file_prefix', 'fstack_log_level'},
            'port0': {'lcore_list', 'addr', 'netmask', 'broadcast', 'gateway'},
        }
        if kni:
            expected['kni'] = set(SOURCE_KNI_OPTIONS)
        require(set(sections) == set(expected) and
            all(set(sections[name]) == keys for name, keys in expected.items()),
            'source INI does not contain the exact three-section, thirteen-key schema')
        if kni:
            require(sections['kni'] == SOURCE_KNI_OPTIONS,
                'source INI KNI options differ from the original management profile')
        try:
            address = ipaddress.IPv4Address(sections['port0']['addr'])
            mask = ipaddress.IPv4Address(sections['port0']['netmask'])
            broadcast = ipaddress.IPv4Address(sections['port0']['broadcast'])
            gateway = ipaddress.IPv4Address(sections['port0']['gateway'])
            network = ipaddress.IPv4Network(
                sections['port0']['addr'] + '/' + sections['port0']['netmask'],
                strict=False)
        except ValueError as error:
            raise PermissionError('source INI port0 network value is not IPv4') from error
        address_first_octet = int(address) >> 24
        gateway_first_octet = int(gateway) >> 24
        require(1 <= network.prefixlen <= 30 and
            mask == network.netmask and
            address not in (network.network_address, network.broadcast_address) and
            broadcast == network.broadcast_address and
            1 <= address_first_octet <= 223 and address_first_octet != 127 and
            not address.is_unspecified and not address.is_loopback and
            not address.is_multicast and
            gateway in network and gateway not in (network.network_address,
                network.broadcast_address, address) and
            1 <= gateway_first_octet <= 223 and gateway_first_octet != 127 and
            not gateway.is_unspecified and not gateway.is_loopback and
            not gateway.is_multicast,
            'source INI port0 network is unsupported or inconsistent')
        return sections

    @staticmethod
    def _config_directive(data, name):
        try:
            text = data.decode('utf-8')
        except UnicodeDecodeError as error:
            raise PermissionError('generated Nginx config is not UTF-8') from error
        pattern = re.compile(r'^[ \t]*' + re.escape(name) +
            r'[ \t]+([^;]+);[ \t]*$', re.MULTILINE)
        values = [match.group(1).strip() for match in pattern.finditer(text)]
        require(len(values) == 1,
            'generated Nginx config does not have exactly one ' + name + ' directive')
        return values[0]

    def _bind_original_artifacts(self, origin_pid, child_pid, deadline_ns, io):
        """Bind generated config and INI before creating a source context."""
        case = self._validate_source_launch_scope()
        tag = SOURCE_CASE_TAGS[case]
        config_name, ini_name = f'ngx_{tag}.conf', f'fstack_{tag}.ini'
        ini_path = self.output + '/' + ini_name
        require(self.environment.get('KER_FSTACK_NGINX_INI') == self.expected_ini == ini_path and
            self.expected_config == self.output + '/' + config_name,
            'source launch INI path is not bound to the original HUP output')
        self.live_supervisor(deadline_ns)
        self._native_io_ready_live(io, deadline_ns)
        require(self.run_id is not None and self.output_fd >= 0 and
            time.monotonic_ns() < deadline_ns,
            'original run/output identity is not available for artifact binding')
        held_dir = os.fstat(self.output_fd)
        named_dir = os.stat(self.output, follow_symlinks=False)
        require(stat.S_ISDIR(held_dir.st_mode) and stat.S_ISDIR(named_dir.st_mode) and
            (held_dir.st_dev, held_dir.st_ino) == self.output_identity ==
                (named_dir.st_dev, named_dir.st_ino) and
            held_dir.st_uid == os.getuid() and
            stat.S_IMODE(held_dir.st_mode) & 0o077 == 0,
            'original output directory identity is not private and stable')

        # Both sides of the fork are still blocked in the origin shim before
        # returning to Nginx. Their original argv therefore still contains the
        # actual -c path; do not rely on the later rewritten process title.
        expected_argv = [os.fsencode(self.nginx_argument), b'-c',
            os.fsencode(self.expected_config)]
        for pid in (origin_pid, child_pid):
            command_line = bounded_cmdline(pid, deadline_ns)
            require(command_line.endswith(b'\0') and
                command_line[:-1].split(b'\0') == expected_argv,
                'authenticated original Nginx argv is not the exact HUP -c launch')

        config = PinnedOutputArtifact(self.output_fd, config_name,
            SOURCE_CONFIG_MAX_BYTES, deadline_ns)
        self.files.append(config)
        ini = PinnedOutputArtifact(self.output_fd, ini_name,
            SOURCE_INI_MAX_BYTES, deadline_ns)
        self.files.append(ini)
        shell_bytes = _read_pinned(self.shell, deadline_ns)
        mime_bytes = _read_pinned(self.mime_source, deadline_ns, 1024 * 1024)
        require(self.network_expectation is not None and self.network_template is not None,
            'pinned source network expectation is unavailable')
        self.network_template.live(deadline_ns)
        require(self.environment.get(SOURCE_NETWORK_READBACK_ENV) ==
                self.network_expectation.readback_setting(),
            'source network readback setting changed after launch')
        expected_config = render_source_hup_config(shell_bytes, self.output, case)
        require(hashlib.sha256(mime_bytes).hexdigest() == MIME_SHA256 and
            config.data == expected_config,
            'generated main config differs from the exact pinned HUP template or MIME source')
        output_prefix = self.output + '/'
        error_log = f'{output_prefix}err_{tag}.log'
        pid_file = output_prefix + 'nginx.pid'
        require(self._config_directive(config.data, 'daemon') == 'on' and
            self._config_directive(config.data, 'master_process') == 'on' and
            self._config_directive(config.data, 'worker_processes') == '1' and
            self._config_directive(config.data, 'error_log') == error_log + '  notice' and
            self._config_directive(config.data, 'pid') == pid_file and
            self._config_directive(config.data, 'fstack_conf') == ini_path,
            'generated HUP config differs from the original one-worker artifact paths')

        sections = self._source_ini_values(ini.data, kni=case == 'rt12')
        expected_network = self.network_expectation
        require(tuple(sections['port0'][key] for key in
                ('addr', 'netmask', 'broadcast', 'gateway')) ==
                (expected_network.address, expected_network.netmask,
                    expected_network.broadcast, expected_network.gateway) and
            expected_network.template_sha256 == self.network_template.sha256.hex() and
            expected_network.template_path == str(self.network_template.path),
            'generated HUP INI network differs from the pinned original template')
        broker_path = self.environment.get('KER_SOCKET_BROKER_PATH', '')
        require(broker_path.startswith('/') and len(os.fsencode(broker_path)) <= 107 and
            sections['ker_socket_broker']['version'] == '1' and
            sections['ker_socket_broker']['path'] == broker_path and
            sections['dpdk']['graceful_reload'] == '1' and
            sections['dpdk']['lcore_mask'] == '3' and
            sections['dpdk']['primary_slim'] == '1' and
            sections['dpdk']['file_prefix'] == self.run_id and
            sections['dpdk']['fstack_log_file_prefix'] == output_prefix + 'fstack-' and
            sections['dpdk']['fstack_log_level'] == '0' and
            sections['port0']['lcore_list'] == '1',
            'generated HUP INI differs from the authenticated source/native topology')

        proof = self.native_io_ready
        require(proof.actor is io and proof.nonce == self.nonce and
            proof.epoch == self.epoch and proof.run_id == self.run_id and
            proof.grant_deadline == self.deadline_ns and
            hashlib.sha256(proof.record_bytes).hexdigest() == proof.record_sha256,
            'source artifacts lack this launch\'s captured native I/O proof')
        record = json.loads(proof.record_bytes)
        queue_proof = record.get('queue_owner_proof')
        queues = queue_proof.get('queues') if type(queue_proof) is dict else None
        queue = queues[0] if type(queues) is list and len(queues) == 1 else None
        main_lcore = 1 if case == 'rt12' else 0
        require(record.get('process_type') == 'primary' and
            type(record.get('main_lcore')) is int and record['main_lcore'] == main_lcore and
            type(record.get('lcore_count')) is int and record['lcore_count'] == 2 and
            type(record.get('port_id')) is int and record['port_id'] == 0 and
            type(record.get('port_count')) is int and record['port_count'] == 1 and
            type(record.get('queues')) is int and record['queues'] == 1 and
            type(queue_proof) is dict and
            set(queue_proof) == {'version', 'worker_pid', 'session_nonce',
                'session_epoch', 'role', 'source_proc_id', 'port_id', 'queues'} and
            type(queue_proof.get('version')) is int and queue_proof['version'] == 1 and
            type(queues) is list and len(queues) == 1 and type(queue) is dict and
            set(queue) == {'queue_id', 'owner_eal_lcore', 'observed_eal_lcore',
                'allowed_cpus', 'actual_cpu'} and
            type(queue_proof.get('worker_pid')) is int and
            queue_proof['worker_pid'] == io.pid and
            type(queue_proof.get('session_nonce')) is str and
            queue_proof.get('session_nonce') == self.nonce.hex() and
            type(queue_proof.get('session_epoch')) is int and
            queue_proof.get('session_epoch') == self.epoch and
            queue_proof.get('role') == 'native-io-owner' and
            type(queue_proof.get('source_proc_id')) is int and
            queue_proof.get('source_proc_id') == 1 and
            type(queue_proof.get('port_id')) is int and
            queue_proof.get('port_id') == 0 and
            type(queue.get('queue_id')) is int and queue['queue_id'] == 0 and
            type(queue.get('owner_eal_lcore')) is int and queue['owner_eal_lcore'] == 1 and
            type(queue.get('observed_eal_lcore')) is int and queue['observed_eal_lcore'] == 1 and
            type(queue.get('allowed_cpus')) is list and len(queue['allowed_cpus']) == 1 and
            type(queue.get('actual_cpu')) is int and
            type(queue['allowed_cpus'][0]) is int and
            queue['actual_cpu'] == queue['allowed_cpus'][0] and
            proof.argv.split(b'\0').count(
                b'--file-prefix=container-' + self.run_id.encode()) == 1,
            'captured native I/O queue proof does not match source-shell INI topology')
        self.live_supervisor(deadline_ns)
        config.live(self.output_fd, deadline_ns)
        ini.live(self.output_fd, deadline_ns)
        self.network_template.live(deadline_ns)
        require(self.environment.get(SOURCE_NETWORK_READBACK_ENV) ==
                self.network_expectation.readback_setting(),
            'source network expectation changed during generated artifact binding')
        binding = SimpleNamespace(config=config, ini=ini, sections=sections,
            run_id=self.run_id, output_identity=self.output_identity,
            network_expectation=self.network_expectation,
            network_template_sha256=self.network_template.sha256.hex(),
            network_template_path=str(self.network_template.path),
            config_sha256=config_dump_transcript_sha256(
                self.expected_config, expected_config, mime_bytes).hex(),
            ini_sha256=ini_transcript_sha256(ini.data).hex(),
            config_file_sha256=config.sha256.hex(), ini_file_sha256=ini.sha256.hex(),
            mime_sha256=hashlib.sha256(mime_bytes).hexdigest(),
            broker_path=broker_path, nginx_argv=tuple(expected_argv),
            io_record_sha256=proof.record_sha256)
        return binding

    def _original_artifacts_live(self, deadline_ns):
        binding = getattr(self, 'artifact_binding', None)
        if binding is None:
            return
        require(binding.run_id == self.run_id and
            binding.output_identity == self.output_identity and
            time.monotonic_ns() < deadline_ns,
            'original generated artifact binding changed')
        directory = os.fstat(self.output_fd)
        named = os.stat(self.output, follow_symlinks=False)
        require((directory.st_dev, directory.st_ino) == self.output_identity ==
            (named.st_dev, named.st_ino),
            'original generated artifact directory changed')
        binding.config.live(self.output_fd, deadline_ns)
        binding.ini.live(self.output_fd, deadline_ns)
        self.shell.live(deadline_ns)
        self.mime_source.live(deadline_ns)
        require(self.network_template is not None and self.network_expectation is not None,
            'pinned source network template is unavailable')
        self.network_template.live(deadline_ns)
        require(self.environment.get(SOURCE_NETWORK_READBACK_ENV) ==
                self.network_expectation.readback_setting() and
            binding.network_expectation == self.network_expectation and
            binding.network_template_sha256 == self.network_template.sha256.hex() and
            binding.network_template_path == str(self.network_template.path),
            'pinned source network expectation changed')

    @staticmethod
    def _require_preparse_artifact_attestation(binding):
        # Full source authority remains fail-closed: parsed bytes and an
        # adapter-cycle token alone do not authorize worker/native grants.
        require(binding is not None,
            'origin parsed-config proof is unavailable')
        raise OSError(errno.ENOTSUP,
            'source bootstrap requires authenticated worker and cycle proof transport')

    @staticmethod
    def _require_control_origin_attestation(binding):
        """Allow only the bounded Origin ACK phase after authentic artifact checks."""
        require(binding is not None and
            re.fullmatch(r'[0-9a-f]{64}', getattr(binding, 'config_sha256', '')) is not None and
            re.fullmatch(r'[0-9a-f]{64}', getattr(binding, 'ini_sha256', '')) is not None and
            re.fullmatch(r'[0-9a-f]{64}', getattr(binding, 'config_file_sha256', '')) is not None and
            re.fullmatch(r'[0-9a-f]{64}', getattr(binding, 'ini_file_sha256', '')) is not None,
            'control-only Origin ACK lacks the exact parsed artifact binding')

    def wait_supervisor(self):
        """Observe the original Bash child's one exec into the pinned supervisor."""
        deadline = min(self.deadline_ns, time.monotonic_ns() + ORIGIN_MAX_STARTUP_NS)
        poller = select.poll()
        poller.register(self.pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        ready_file = Path(self.output) / 'supervisor.json'
        while time.monotonic_ns() < deadline:
            self._require_supervisor_child(deadline)
            value = os.stat(f'/proc/{self.process.pid}/exe')
            executable = (value.st_dev, value.st_ino)
            # /proc may expose the new executable during exec. Wait for the
            # original supervisor's startup file before validating its argv.
            if executable == self.python.frozen[:2] and ready_file.is_file():
                return self.live_supervisor(deadline)
            require(executable in (self.bash.frozen[:2], self.python.frozen[:2]),
                'captured child entered an unexpected executable before supervisor startup')
            poller.poll(2)
        raise TimeoutError('original shell did not enter its supervisor within the startup deadline')

    def _require_supervisor_child(self, deadline_ns):
        require(os.getpid() == self.creator_pid and
            identity._start_ticks(self.creator_pid) == self.creator_start and
            time.monotonic_ns() < deadline_ns and
            self.process is not None and self.process.poll() is None and
            identity._pidfd_pid(self.pidfd) == self.process.pid and
            identity.process_alive(self.pidfd) and
            identity._start_ticks(self.process.pid) == self.start and
            parent_pid(self.process.pid) == self.creator_pid and
            namespace_identity(self.process.pid) == self.pid_namespace,
            'captured original supervisor is no longer live')

    def live_supervisor(self, deadline_ns=None):
        deadline_ns = min(self.deadline_ns, deadline_ns or self.deadline_ns)
        self._require_supervisor_child(deadline_ns)
        self.shell.live(deadline_ns)
        self.supervisor_script.live(deadline_ns)
        self.checks_script.live(deadline_ns)
        self.runtime_script.live(deadline_ns)
        self.launcher_script.live(deadline_ns)
        require(not (self.common / '__pycache__').exists(),
            'original supervisor import cache appeared')
        self.python.matches_process(self.process.pid, deadline_ns)
        arguments = Path(f'/proc/{self.process.pid}/cmdline').read_bytes().split(b'\0')
        require(arguments[-1:] == [b''], 'unterminated original supervisor argv')
        arguments = [arg.decode() for arg in arguments[:-1]]
        require(len(arguments) == 10 + len(self.arguments) and
            arguments[1:5] == ['-B', str(self.supervisor_script.path), 'run', self.output] and
            arguments[6:10] == ['14400', '--', '/bin/bash', str(self.shell.path)] and
            arguments[10:] == self.arguments,
            'captured child did not enter the exact original supervisor')
        run_id = arguments[5]
        require(re.fullmatch(r'gr_[0-9]{8}_[0-9]{6}_' + str(self.process.pid) + r'_[0-9a-f]{8}',
            run_id) is not None and (self.run_id is None or self.run_id == run_id),
            'original supervisor run identity changed')
        self.run_id = run_id
        if self.output_fd < 0:
            self.output_fd = os.open(self.output,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
            value = os.fstat(self.output_fd)
            require(value.st_uid == os.getuid() and stat.S_IMODE(value.st_mode) & 0o077 == 0,
                'original output directory is not private')
            self.output_identity = value.st_dev, value.st_ino
        require(time.monotonic_ns() < deadline_ns, 'original supervisor observation expired')
        if getattr(self, 'native_io_ready', None) is not None:
            self._native_io_ready_live(self.native_io_ready.actor, deadline_ns)
        self._original_artifacts_live(deadline_ns)
        receipt = getattr(self, 'backend_receipt', None)
        runtime_actor = getattr(self, 'backend_runtime_actor', None)
        if receipt is not None and runtime_actor is not None:
            receipt.validate_live(self._backend_expected(), runtime_actor, deadline_ns)

    def _native_io_ready_live(self, io, deadline_ns):
        proof = getattr(self, 'native_io_ready', None)
        require(proof is not None and proof.actor is io and
            os.getpid() == self.creator_pid and
            identity._start_ticks(self.creator_pid) == self.creator_start and
            self.nonce == proof.nonce and self.epoch == proof.epoch and
            self.run_id == proof.run_id and self.deadline_ns == proof.grant_deadline and
            actor_namespaces(self.creator_pid) == proof.namespaces and
            hashlib.sha256(proof.record_bytes).hexdigest() == proof.record_sha256 and
            time.monotonic_ns() < min(deadline_ns, proof.grant_deadline),
            'origin requires its captured native I/O READY observation')
        require(proof.process.poll() is None and proof.process.pid == proof.pid == io.pid and
            identity._pidfd_pid(self.native_io_pidfd) == proof.pid and
            identity.process_alive(self.native_io_pidfd) and
            identity._pidfd_pid(io.pidfd) == proof.pid and
            identity.process_alive(io.pidfd) and
            identity._start_ticks(proof.pid) == proof.start == io.start_ticks and
            parent_pid(proof.pid) == self.creator_pid and
            actor_namespaces(proof.pid) == proof.namespaces and
            bytes(io.executable_hash) == proof.executable.sha256,
            'captured native I/O process identity changed')
        proof.executable.matches_process(proof.pid, deadline_ns)
        require(bounded_cmdline(proof.pid, deadline_ns) == proof.argv,
            'native I/O executable arguments changed after READY')
        require(proof.process.stdout is not None and
            (lambda value: (value.st_dev, value.st_ino))(os.fstat(
                proof.process.stdout.fileno())) == proof.pipe_identity and
            (lambda value: (value.st_dev, value.st_ino))(os.fstat(
                self.native_io_stdout_fd)) == proof.pipe_identity and
            (lambda value: (value.st_dev, value.st_ino))(os.stat(
                f'/proc/{proof.pid}/fd/1')) == proof.pipe_identity and
            time.monotonic_ns() < deadline_ns,
            'native I/O READY pipe or observation lifetime changed')

    def _backend_expected(self):
        expectation = self.network_expectation
        return {'record': expectation.readback_setting(),
            'template_sha256': expectation.template_sha256,
            'address': expectation.address, 'netmask': expectation.netmask,
            'broadcast': expectation.broadcast, 'gateway': expectation.gateway,
            'deadline_ns': expectation.deadline_ns}

    def attach_retained_backend_receipt(self, receipt):
        require(type(receipt) is _SOURCE_NETWORK_STARTUP.RetainedBackendReceipt,
            'source launch accepts only the exact retained-backend receipt type')
        require(getattr(self, 'backend_receipt', None) is None and
            receipt.creator_pid == self.creator_pid and
            receipt.creator_start_ticks == self.creator_start and
            receipt.expected == _SOURCE_NETWORK_STARTUP._expected_key(self._backend_expected()),
            'retained backend receipt belongs to another source launch')
        self.backend_receipt = receipt
        self.backend_runtime_actor = None

    def _require_retained_backend(self, runtime, deadline_ns):
        receipt = getattr(self, 'backend_receipt', None)
        if receipt is None:
            handoff = getattr(self, 'backend_handoff', None)
            if type(handoff) is not _SOURCE_NETWORK_STARTUP.RetainedBackendHandoff:
                raise OSError(errno.ENOTSUP,
                    'source launch has no retained backend startup receipt')
            receipt = handoff.take(deadline_ns)
            self.attach_retained_backend_receipt(receipt)
        receipt.validate_live(self._backend_expected(), runtime, deadline_ns)
        current_actor = getattr(self, 'backend_runtime_actor', None)
        if current_actor is None:
            self.backend_runtime_actor = runtime
        elif current_actor is not runtime:
            # Distinct wrappers may be supplied by a caller; accept only if
            # they still prove the same exact pidfd/start/executable identity.
            receipt.validate_live(self._backend_expected(), current_actor, deadline_ns)
        return receipt

    def observe_native_io_ready(self, process, io, *, expected_port_name):
        """Read one READY from the directly launched, pinned native I/O actor.

        The new original-shell controller deliberately uses this launch's
        nonce/epoch for both RX-decision and queue-proof correlation. Legacy
        ker-run sessions remain independent. The record is an observation;
        source slots and original Nginx READY still require their own grants.
        expected_port_name comes from the controller's launch configuration;
        READY's numeric port_id is checked independently after resolution.
        """
        require(isinstance(expected_port_name, str) and
            1 <= len(expected_port_name) <= 63 and expected_port_name.isascii() and
            all(character.isalnum() or character in '_.-'
                for character in expected_port_name),
            'native I/O requires the controller configured ethdev name')
        deadline = min(self.deadline_ns,
            time.monotonic_ns() + ORIGIN_MAX_STARTUP_NS)
        self.live_supervisor(deadline)
        require(not getattr(self, 'native_io_observation_started', False) and
            getattr(self, 'native_io_ready', None) is None and
            self.run_id is not None and isinstance(process, subprocess.Popen) and
            process.stdout is not None and process.poll() is None and
            process.pid == io.pid and parent_pid(io.pid) == self.creator_pid and
            identity._pidfd_pid(io.pidfd) == io.pid and identity.process_alive(io.pidfd) and
            identity._start_ticks(io.pid) == io.start_ticks and
            actor_namespaces(io.pid) == actor_namespaces(self.creator_pid),
            'native I/O must be this controller\'s exact live captured child')
        # A partial/failed read is not renewable on the same launch.
        self.native_io_observation_started = True
        executable = self.pin(f'/proc/{io.pid}/exe', bytes(io.executable_hash).hex(), deadline)
        executable.matches_process(io.pid, deadline)
        pipe = os.fstat(process.stdout.fileno())
        require(stat.S_ISFIFO(pipe.st_mode) and
            (lambda value: (value.st_dev, value.st_ino))(os.stat(
                f'/proc/{io.pid}/fd/1')) == (pipe.st_dev, pipe.st_ino),
            'native I/O stdout is not the captured child pipe')
        self.native_io_pidfd = os.dup(io.pidfd)
        os.set_inheritable(self.native_io_pidfd, False)
        self.native_io_stdout_fd = os.dup(process.stdout.fileno())
        os.set_inheritable(self.native_io_stdout_fd, False)
        remaining = (deadline - time.monotonic_ns()) / 1_000_000_000
        require(remaining > 0, 'native I/O observation expired before READY')
        line = launcher.read_worker_startup(process, 'original-shell native I/O',
            timeout=remaining, maximum=65536)
        require(line.startswith('KER_IO_READY '), 'native I/O did not publish READY')

        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                require(key not in result, 'duplicate native I/O READY key')
                result[key] = value
            return result

        json.loads(line[len('KER_IO_READY '):], object_pairs_hook=unique_object)
        record = launcher.worker_ready_record(line, expected_pid=io.pid,
            expected_session=(self.nonce.hex(), self.epoch), require_queue_proof=True,
            expected_port_id=0, expected_queue_count=1, expected_queue_lcores=[1],
            expected_source_proc_id=1)
        kni = getattr(self, 'source_case', None) == 'rt12'
        require(record.get('process_type') == 'primary' and
            all(type(record.get(name)) is int and record[name] == value
                for name, value in (('port_id', 0), ('port_count', 1),
                    ('queues', 1), ('main_lcore', int(kni)), ('lcore_count', 2))),
            'native I/O READY is outside the one-port, two-lcore source profile')
        command_line = bounded_cmdline(io.pid, deadline)
        arguments = command_line[:-1].split(b'\0')
        require(arguments.count(b'--') == 1, 'native I/O requires one EAL delimiter')
        split = arguments.index(b'--')
        application, eal = arguments[1:split], arguments[split + 1:]
        expected = {
            b'--queues': b'1', b'--rx-lcores': b'1',
            b'--port': expected_port_name.encode('ascii'),
            b'--queue-proof-session': self.nonce.hex().encode(),
            b'--queue-proof-epoch': str(self.epoch).encode(),
            b'--queue-proof-source-proc-id': b'1', b'--rx-decision-fd': None,
        }
        for name, value in expected.items():
            positions = [index for index, argument in enumerate(application)
                if argument.split(b'=', 1)[0] == name]
            require(len(positions) == 1 and application[positions[0]] == name and
                positions[0] + 1 < len(application),
                'native I/O proof option is missing, repeated, or noncanonical')
            actual = application[positions[0] + 1]
            if value is not None:
                require(actual == value, 'native I/O arguments differ from the READY session/topology')
            else:
                require(actual.isdigit() and 3 <= int(actual) <= 2147483647,
                    'native I/O decision channel descriptor is invalid')
        prefixes = [argument for argument in eal
            if argument.split(b'=', 1)[0] == b'--file-prefix']
        require(prefixes == [('--file-prefix=container-' + self.run_id).encode()],
            'native I/O EAL namespace differs from the original supervisor run')
        devices = []
        for index, argument in enumerate(eal):
            if argument == b'--vdev':
                require(index + 1 < len(eal), 'native I/O vdev value is missing')
                devices.append(eal[index + 1])
            elif argument.startswith(b'--vdev='):
                devices.append(argument[len(b'--vdev='):])
        require(len(devices) == 1 and devices[0].split(b',', 1)[0] ==
            expected_port_name.encode('ascii'),
            'native I/O requires its exact configured single virtual ethdev')
        canonical = json.dumps(record, sort_keys=True, separators=(',', ':')).encode()
        self.native_io_ready = SimpleNamespace(actor=io, process=process, pid=io.pid,
            start=io.start_ticks, namespaces=actor_namespaces(io.pid), executable=executable,
            nonce=self.nonce, epoch=self.epoch, run_id=self.run_id,
            grant_deadline=self.deadline_ns,
            pipe_identity=(pipe.st_dev, pipe.st_ino), record_bytes=canonical,
            argv=command_line,
            record_sha256=hashlib.sha256(canonical).hexdigest(),
            raw_sha256=hashlib.sha256(line.encode()).hexdigest())
        try:
            self._native_io_ready_live(io, deadline)
            self.live_supervisor(deadline)
        except BaseException:
            self.native_io_ready = None
            raise
        return json.loads(canonical)

    def accept_origin(self, channel, runtime, io):
        """Consume one credentialed origin request and return its bound observer.

        Request rights: exact live original launcher pidfd, then child pidfd.
        ACK rights: this bootstrap supervisor pidfd only. All source, slot,
        READY, native route and packet authority is established separately.
        """
        received_fds = []
        supervisor_pidfd = -1
        candidate_context = None
        receive_deadline = min(self.deadline_ns, time.monotonic_ns() + ORIGIN_MAX_STARTUP_NS)
        deadline = receive_deadline
        try:
            if getattr(self, 'c34_artifact_capture', None) is not None:
                self.c34_artifact_capture.verify(deadline)
            self.live_supervisor(deadline)
            self._native_io_ready_live(io, deadline)
            require(not self.consumed and self.context is None, 'daemon origin already consumed')
            require(channel.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) == 1,
                'origin listener must enable credentials before a request can be queued')
            remaining = deadline - time.monotonic_ns()
            require(remaining > 0, 'origin receive budget expired')
            channel.settimeout(remaining / 1_000_000_000)
            packet, ancillary, flags, _ = channel.recvmsg(ORIGIN.size + 1,
                socket.CMSG_SPACE(12) + socket.CMSG_SPACE(4 * 4),
                getattr(socket, 'MSG_CMSG_CLOEXEC', 0))
            credentials = []
            invalid = False
            for level, kind, value in ancillary:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    values = array.array('i')
                    values.frombytes(value[:len(value) - len(value) % values.itemsize])
                    received_fds.extend(values)
                    for fd in values:
                        os.set_inheritable(fd, False)
                    invalid |= len(value) % values.itemsize != 0
                elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(value) == 12:
                    credentials.append(struct.unpack('=3i', value))
                else:
                    invalid = True
            require(not invalid and len(received_fds) == 2 and
                not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) and len(packet) == ORIGIN.size,
                'malformed origin request')
            fields = list(ORIGIN.unpack(packet))
            (magic, version, operation, record_bytes, record_flags, origin_pid, child_pid,
                child_tid, supervisor_pid, origin_start, child_start, supervisor_start,
                epoch, grant_deadline, deadline, operation_id, nonce, ns_device, ns_inode,
                proof_version, proof_flags, adapter_cycle_serial, opaque_cycle_token,
                config_digest, ini_digest) = fields
            now = time.monotonic_ns()
            require((magic, version, operation, record_bytes, record_flags) ==
                (ORIGIN_MAGIC, ORIGIN_VERSION, ORIGIN_REQUEST, ORIGIN.size, 0) and
                credentials == [(child_pid, os.getuid(), os.getgid())] and
                child_pid > 0 and child_tid == child_pid and origin_pid > 0 and
                len({origin_pid, child_pid, self.process.pid, self.creator_pid}) == 4 and
                supervisor_pid == self.creator_pid and supervisor_start == self.creator_start and
                epoch == self.epoch and nonce == self.nonce and grant_deadline == self.deadline_ns and
                now < deadline <= min(grant_deadline, receive_deadline) and
                deadline - now <= ORIGIN_MAX_STARTUP_NS and
                operation_id > 0 and (ns_device, ns_inode) == self.pid_namespace,
                'origin context or credentials mismatch')
            for fd, pid, start in ((received_fds[0], origin_pid, origin_start),
                    (received_fds[1], child_pid, child_start)):
                require(identity._pidfd_pid(fd) == pid and identity.process_alive(fd) and
                    identity._start_ticks(pid) == start and
                    namespace_identity(pid) == self.pid_namespace,
                    'origin actor pidfd or namespace changed')
                self.nginx.matches_process(pid, deadline)
            require(parent_pid(origin_pid) == self.process.pid and parent_pid(child_pid) == origin_pid,
                'daemon is not the live original launcher child')
            # The parent remains alive behind the private fork synchronization
            # pipe until the child validates this ACK. Consume this lineage
            # before constructing any later source observer; never renew it.
            self.consumed = True
            # Retain actor proofs before *any* fallible context construction.
            # A rejected lineage still has to be settled by its real owner.
            self.origin_pidfd, self.master_pidfd = received_fds
            received_fds = []
            master = SimpleNamespace(pid=child_pid, pidfd=self.master_pidfd,
                start_ticks=child_start, executable_hash=self.nginx.sha256)
            require(time.monotonic_ns() < deadline, 'origin construction budget expired')
            self.artifact_binding = self._bind_original_artifacts(
                origin_pid, child_pid, deadline, io)
            if getattr(self, 'c34_artifact_capture', None) is not None:
                self.c34_artifact_capture.verify(deadline)
            self.origin_proof = validate_origin_proof(fields, self.artifact_binding)
            self._require_retained_backend(runtime, deadline)
            # The initial authenticated ACK only releases the original fork
            # barrier. Full source/worker authority stays disabled in this
            # context until a separate proven cycle/provider phase exists.
            self._require_control_origin_attestation(self.artifact_binding)
            expected_config_sha256 = bytes.fromhex(self.artifact_binding.config_sha256)
            expected_ini_sha256 = bytes.fromhex(self.artifact_binding.ini_sha256)
            initial_cycle_proof = bootstrap.SourceCycleProof(
                self.origin_proof.proof_version, self.origin_proof.proof_flags,
                self.origin_proof.adapter_cycle_serial,
                self.origin_proof.opaque_cycle_token,
                expected_config_sha256, expected_ini_sha256)
            candidate_context = bootstrap.SourceBootstrapSupervisor(master, runtime, io,
                self.nginx.path, self.nginx.sha256, self.nonce, self.epoch, self.deadline_ns,
                observation_deadline_ns=deadline, owner_live=self.live_supervisor,
                allow_abort_retry=(getattr(getattr(self, 'c34_artifact_capture', None),
                    'source_fault', None) == SOURCE_RETRY_FAULT),
                allow_successor=self.source_case in ('rv9', 'rt25'),
                initial_cycle_proof=initial_cycle_proof,
                expected_config_sha256=expected_config_sha256,
                expected_ini_sha256=expected_ini_sha256, control_only=True)
            self.capture_source_supervisor_identity(candidate_context, deadline,
                origin_pid=origin_pid, origin_start=origin_start,
                child_pid=child_pid, child_start=child_start)
            self.live_supervisor(deadline)
            self._require_retained_backend(runtime, deadline)
            require(time.monotonic_ns() < deadline and
                parent_pid(child_pid) == origin_pid and identity.process_alive(self.origin_pidfd) and
                identity.process_alive(self.master_pidfd), 'origin expired during observation')
            self._require_retained_backend(runtime, deadline)
            supervisor_pidfd = os.pidfd_open(self.creator_pid)
            fields[2] = ORIGIN_ACK
            # Retain exact actor identities even if ACK delivery becomes
            # indeterminate. Only the child can accept an on-time exact ACK;
            # the original supervisor still owns failure settlement.
            self.context = candidate_context
            candidate_context = None
            self.origin_channel = channel
            origin_fd_stat = os.fstat(self.origin_pidfd)
            parent_pin = (self.context, self.origin_pidfd,
                origin_fd_stat.st_dev, origin_fd_stat.st_ino)
            remaining = deadline - time.monotonic_ns()
            require(remaining > 0, 'origin ACK budget expired')
            channel.settimeout(remaining / 1_000_000_000)
            require(time.monotonic_ns() < deadline and
                channel.sendmsg([ORIGIN.pack(*fields)], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                    array.array('i', [supervisor_pidfd]))]) == ORIGIN.size and
                time.monotonic_ns() < deadline, 'origin ACK missed the original startup budget')
            self._origin_ack_parent_pin = parent_pin
            return self.context
        finally:
            if candidate_context is not None:
                candidate_context.close()
            for fd in received_fds:
                os.close(fd)
            if supervisor_pidfd >= 0:
                os.close(supervisor_pidfd)

    def check_origin_parent(self, context):
        """Retain the exact daemon parent pin across its normal post-ACK exit."""
        fd = self.origin_pidfd
        acknowledged = getattr(self, '_origin_ack_parent_pin', None)
        if acknowledged is None:
            if not identity.process_alive(fd) or identity._pidfd_pid(fd) <= 0:
                raise ProcessLookupError('captured origin actor is no longer live before ACK')
            return
        info = os.fstat(fd)
        require(context is self.context is acknowledged[0] and
            (fd, info.st_dev, info.st_ino) == acknowledged[1:],
            'acknowledged daemon parent pidfd binding changed')

    def observe_unparked_abort(self, context, deadline):
        """Confirm that the original master completed its selected timeout."""
        reason, minimum_ms = SOURCE_UNPARKED_ABORT[self.source_case]
        require(self.context is context and context._unparked_abort_profile(),
            'unparked timeout receipt requires the exact original profile')
        self.live_supervisor(deadline)
        log, _ = _read_original_output_receipt(
            self, f'err_{self.source_case}.log', 2 * 1024 * 1024, deadline)
        actor = str(context.master.pid).encode('ascii') + b'#0: '
        own = [entry.split(actor, 1)[1] for entry in log.splitlines()
            if actor in entry and actor in entry[:100]]
        before = b'T1_GNEW_SPAWN' if self.source_case == 'rt20' else b'T2_HANDOVER'
        failure = b'graceful reload aborted: ' + reason.encode('ascii') + b' (old generation untouched)'
        elapsed = [re.fullmatch(rb'graceful reload fsm: ' + before +
            rb' -> T_ERROR \(transition [0-9]+, elapsed ([0-9]+) ms\)', entry)
            for entry in own]
        require(own.count(failure) == 1 and
            any(match and int(match[1]) >= minimum_ms for match in elapsed),
            'original master did not record the expected bounded timeout')
        return hashlib.sha256(log).digest()

    def observe_worker_term(self, context, pending):
        """Produce typed TERM proof from this captured original supervisor.

        Receipts are read through the launch's held output-directory FD. This
        observes the original supervisor's request; it does not infer a KILL
        deadline or alter its existing cleanup policy.
        """
        require(type(context) is bootstrap.SourceBootstrapSupervisor and
            type(pending) is bootstrap.PendingSourceRetirement and
            getattr(context.owner_live, '__self__', None) is self and
            context._pending_preexits.get(pending.operation_id, (None,))[0] is pending,
            'worker TERM observation is not bound to this exact pending Origin request')
        deadline = min(self.deadline_ns, context.deadline_ns, pending.deadline_ns)
        now = time.monotonic_ns()
        require(now < deadline and self.process is not None and
            self.process.poll() is None and self.run_id is not None and
            self.output_fd >= 0 and self.pidfd >= 0,
            'original supervisor TERM observation is outside its live deadline')
        self.live_supervisor(deadline)
        worker_pidfd, grant = context.workers.get(pending.key, (-1, ()))
        require(len(grant) == 35 and grant[5] == pending.worker_pid and
            grant[11] == pending.worker_start_ticks and
            identity._pidfd_pid(worker_pidfd) == pending.worker_pid and
            identity.process_alive(worker_pidfd) and
            identity._start_ticks(pending.worker_pid) == pending.worker_start_ticks,
            'pending TERM worker no longer matches its exact live grant')

        return self._observe_actor_term(context, pending.worker_pid,
            pending.worker_start_ticks, deadline, require_membership=True)

    def observe_final_slim_term(self, context, deadline):
        """Check original-supervisor TERM for the exact retired slim actor."""
        require(self.context is context and context._can_observe_final_slim_term() and
            not identity.process_alive(context.slim_pidfd),
            'slim TERM observation is outside the current-owner shutdown')
        return self._observe_actor_term(context, context.slim_pid,
            context.slim_start_ticks, deadline, require_membership=False)

    def _observe_actor_term(self, context, pid, start_ticks, deadline, *,
            require_membership):
        self.live_supervisor(deadline)
        snapshot_bytes, snapshot_inode = _read_original_output_receipt(
            self, 'supervisor.json', 65536, deadline)
        events_bytes, events_inode = _read_original_output_receipt(
            self, 'ownership-events.jsonl', 8 * 1024 * 1024, deadline)
        if not events_bytes.endswith(b'\n'):
            raise BlockingIOError(errno.EAGAIN,
                'original supervisor event append is incomplete')
        try:
            snapshot = json.loads(snapshot_bytes)
            events = [json.loads(line) for line in events_bytes.splitlines()]
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PermissionError('original TERM receipts are malformed') from exc
        require(type(snapshot) is dict and type(events) is list and
            all(type(event) is dict for event in events),
            'original TERM receipts have invalid shape')
        actor = snapshot.get('supervisor')
        python_dev, python_ino = self.python.frozen[:2]
        require(snapshot.get('version') == 1 and type(snapshot.get('version')) is int and
            snapshot.get('run_id') == self.run_id and type(actor) is dict and
            (actor.get('pid'), actor.get('start_time'), actor.get('device'), actor.get('inode')) ==
                (self.process.pid, self.start, python_dev, python_ino),
            'original TERM snapshot belongs to another supervisor or interpreter')
        phase = snapshot.get('phase')
        if phase != 'stopping':
            if phase in ('idle', 'starting', 'running'):
                raise BlockingIOError(errno.EAGAIN,
                    'original supervisor has not published stopping state yet')
            raise PermissionError('original supervisor is no longer stopping')
        controller, stack = snapshot.get('controller'), snapshot.get('stack')
        require(type(controller) is int and controller > 0 and
            type(stack) is str and stack,
            'original stopping snapshot lacks exact controller/stack identity')
        if require_membership:
            members = snapshot.get('members')
            require(type(members) is list and all(type(member) is dict for member in members),
                'original stopping snapshot members are malformed')
            member_matches = [member for member in members if
                member.get('pid') == pid and member.get('start_time') == start_ticks]
            if not member_matches:
                raise BlockingIOError(errno.EAGAIN,
                    'original supervisor has not published the exact worker membership')
            require(len(member_matches) == 1 and
                member_matches[0].get('role') in ('target', 'orphan'),
                'original supervisor worker membership is ambiguous or not a target')
        actor_events = [event for event in events if
            event.get('pid') == pid and
            event.get('start_time') == start_ticks and
            event.get('signal') in ('TERM', 'KILL')]
        require(not any(event.get('signal') == 'KILL' for event in actor_events),
            'original supervisor has already escalated this worker to KILL')
        term_candidates = [event for event in actor_events if
            event.get('event') == 'signal_requested' and event.get('signal') == 'TERM']
        require(all(event.get('run_id') == self.run_id for event in term_candidates),
            'original supervisor TERM event belongs to another run')
        term_events = term_candidates
        if not term_events:
            raise BlockingIOError(errno.EAGAIN,
                'original supervisor TERM receipt is not published yet')
        require(len(term_events) == 1 and
            all(event.get('run_id') == self.run_id for event in actor_events),
            'original supervisor TERM event is duplicated or belongs to another run')
        observed = term_events[0].get('monotonic')
        require(type(observed) in (int, float) and math.isfinite(observed) and
            observed > 0 and observed <= time.monotonic(),
            'original supervisor TERM event timestamp is invalid')
        self.live_supervisor(deadline)
        held_directory = os.fstat(self.output_fd)
        path_directory = os.stat(self.output, follow_symlinks=False)
        directory_identity = (held_directory.st_dev, held_directory.st_ino)
        require(time.monotonic_ns() < deadline and
            directory_identity == self.output_identity ==
                (path_directory.st_dev, path_directory.st_ino) and
            snapshot_inode[0] == directory_identity[0] and
            events_inode[0] == directory_identity[0],
            'original TERM observation exceeded its immutable identity/deadline')
        context.bind_original_supervisor_identity(self, controller, stack)
        receipt_hash = hashlib.sha256(b'ker-original-term-v1\0' +
            snapshot_bytes + b'\0' + events_bytes).digest()
        return bootstrap.SupervisorTermEvidence(self.process.pid, self.start,
            self.python.sha256, self.run_id, controller, stack, 'stopping',
            pid, start_ticks, 'TERM',
            int(observed * 1_000_000_000), directory_identity[0],
            directory_identity[1], receipt_hash)

    def capture_source_supervisor_identity(self, context, deadline_ns, *,
            origin_pid=None, origin_start=None, child_pid=None, child_start=None):
        """Bind controller/stack from the captured run without granting STOP."""
        deadline = min(self.deadline_ns, deadline_ns)
        require(time.monotonic_ns() < deadline,
            'source supervisor identity capture exceeded its deadline')
        self.live_supervisor(deadline)
        data, _ = _read_original_output_receipt(self, 'supervisor.json', 65536,
            deadline)
        try:
            snapshot = json.loads(data)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PermissionError('original supervisor snapshot is malformed') from exc
        actor = snapshot.get('supervisor') if type(snapshot) is dict else None
        require(type(actor) is dict and snapshot.get('version') == 1 and
            type(snapshot.get('version')) is int and snapshot.get('run_id') == self.run_id and
            (actor.get('pid'), actor.get('start_time'), actor.get('device'), actor.get('inode')) ==
                (self.process.pid, self.start, *self.python.frozen[:2]),
            'original supervisor identity snapshot does not match captured launch')
        phase = snapshot.get('phase')
        if phase not in ('starting', 'running', 'stopping'):
            raise BlockingIOError(errno.EAGAIN,
                'original supervisor has not published its active stack snapshot')
        controller, stack = snapshot.get('controller'), snapshot.get('stack')
        require(type(controller) is int and controller > 0 and
            type(stack) is str and stack,
            'original supervisor lacks controller/stack identity')
        lineage = (origin_pid, origin_start, child_pid, child_start)
        has_lineage = all(type(value) is int and value > 0 for value in lineage)
        if phase == 'starting' and not has_lineage:
            raise BlockingIOError(errno.EAGAIN,
                'starting snapshot needs the authenticated Origin parent/child lineage')
        if any(value is not None for value in lineage):
            require(has_lineage and getattr(self, 'origin_pidfd', -1) >= 0 and
                getattr(self, 'master_pidfd', -1) >= 0 and
                identity._pidfd_pid(self.origin_pidfd) == origin_pid and
                identity.process_alive(self.origin_pidfd) and
                identity._start_ticks(origin_pid) == origin_start and
                identity._pidfd_pid(self.master_pidfd) == child_pid and
                identity.process_alive(self.master_pidfd) and
                identity._start_ticks(child_pid) == child_start and
                parent_pid(origin_pid) == self.process.pid and
                parent_pid(child_pid) == origin_pid,
                'starting Origin parent/child lineage changed')
            members = snapshot.get('members')
            require(type(members) is list and all(type(item) is dict for item in members),
                'starting supervisor member list is malformed')
            origin_members = [item for item in members if
                item.get('pid') == origin_pid and item.get('start_time') == origin_start]
            if not origin_members:
                raise BlockingIOError(errno.EAGAIN,
                    'starting supervisor has not published its exact launcher member')
            require(len(origin_members) == 1 and origin_members[0].get('role') == 'target',
                'starting supervisor launcher membership is ambiguous or not a target')
            child_members = [item for item in members if item.get('pid') == child_pid]
            if child_members:
                require(len(child_members) == 1 and
                    child_members[0].get('start_time') == child_start and
                    child_members[0].get('parent') == origin_pid,
                    'starting supervisor child membership differs from Origin lineage')
        context.bind_original_supervisor_identity(self, controller, stack)
        return dict(controller=controller, stack=stack, phase=phase)

    def observe_settlement(self):
        """Check original ECHILD evidence plus the observer's exact pidfds.

        A settled failure remains a failure. These receipts are never used to
        grant origin/source authority, and supervisor exit alone is insufficient.
        """
        require(self.process is not None and self.process.poll() is not None and
            self.run_id is not None and self.output_fd >= 0,
            'original supervisor execution/exit was not fully observed')
        known_actors = [self.pidfd, self.master_pidfd, self.origin_pidfd]
        if self.context is not None:
            known_actors.extend([self.context.slim_pidfd,
                *(fd for fd, _ in self.context.workers.values())])
            successor = getattr(self.context, '_upgrade_master', None)
            if successor is not None:
                known_actors.append(successor.pidfd)
        require(all(fd < 0 or not identity.process_alive(fd) for fd in known_actors),
            'original/delegated actors still live')
        value = os.stat(self.output, follow_symlinks=False)
        held_directory = os.fstat(self.output_fd)
        require((value.st_dev, value.st_ino) == self.output_identity and
            (held_directory.st_dev, held_directory.st_ino) == self.output_identity and
            value.st_uid == os.getuid() and stat.S_IMODE(value.st_mode) & 0o077 == 0,
            'original output directory changed')
        deadline = time.monotonic_ns() + ORIGIN_MAX_STARTUP_NS

        def read_receipt(name, limit):
            fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=self.output_fd)
            try:
                before = os.fstat(fd)
                require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and
                    before.st_nlink == 1 and before.st_size <= limit,
                    'invalid original settlement receipt')
                data = bytearray()
                while len(data) <= limit:
                    require(time.monotonic_ns() < deadline, 'settlement observation expired')
                    chunk = os.read(fd, min(65536, limit + 1 - len(data)))
                    if not chunk:
                        break
                    data.extend(chunk)
                require(len(data) <= limit and file_identity(os.fstat(fd)) == file_identity(before),
                    'original settlement receipt changed')
                return bytes(data)
            finally:
                os.close(fd)

        snapshot_bytes = read_receipt('supervisor.json', 65536)
        events_bytes = read_receipt('ownership-events.jsonl', 8 * 1024 * 1024)
        snapshot = json.loads(snapshot_bytes)
        events = [json.loads(line) for line in events_bytes.splitlines()]
        require(type(snapshot) is dict and all(type(event) is dict for event in events),
            'original settlement records have invalid shape')
        endings = [event for event in events if event.get('event') == 'run_finished']
        require(type(snapshot.get('version')) is int and snapshot['version'] == 1 and
            snapshot.get('run_id') == self.run_id and
            snapshot.get('phase') in ('finished', 'failed') and snapshot.get('members') == [] and
            len(endings) == 1 and events[-1] == endings[0] and
            endings[0].get('run_id') == self.run_id and endings[0].get('echild') is True,
            'original supervisor did not certify complete settlement')
        actor = snapshot.get('supervisor', {})
        require(type(actor) is dict and
            (actor.get('pid'), actor.get('start_time'), actor.get('device'), actor.get('inode')) ==
            (self.process.pid, self.start, *self.python.frozen[:2]),
            'settlement belongs to another supervisor')
        result = endings[0].get('result')
        require(type(result) is int and self.process.returncode ==
            (result if result >= 0 else 128 - result) and
            snapshot['phase'] == ('finished' if result == 0 else 'failed') and
            (result != 0 or snapshot.get('failure') is None),
            'original exit/settlement result mismatch')
        self.settlement = dict(result=result, phase=snapshot['phase'], settled=True,
            snapshot_sha256=hashlib.sha256(snapshot_bytes).hexdigest(),
            events_sha256=hashlib.sha256(events_bytes).hexdigest())
        return dict(self.settlement)

    def close(self):
        require(self.process is None or self.process.poll() is not None,
            'original supervisor remains live during observer close')
        require(self.process is None or self.settlement is not None,
            'original supervisor settlement remains unverified; retain identity proofs')
        require(all(fd < 0 or not identity.process_alive(fd)
            for fd in (self.master_pidfd, self.origin_pidfd)),
            'original daemon actors remain live after supervisor exit')
        native_pidfd = getattr(self, 'native_io_pidfd', -1)
        require(native_pidfd < 0 or not identity.process_alive(native_pidfd),
            'captured native I/O remains live; retain its observation and settle its owner')
        if self.context is not None:
            known_actors = [self.context.slim_pidfd,
                *(fd for fd, _ in self.context.workers.values())]
            require(all(fd < 0 or not identity.process_alive(fd) for fd in known_actors),
                'delegated source actors remain live after original supervisor exit')
        handoff = getattr(self, 'backend_handoff', None)
        if handoff is not None:
            handoff.close()
        receipt = getattr(self, 'backend_receipt', None)
        if receipt is not None:
            receipt.close()
            self.backend_receipt = None
        if self.context is not None:
            self.context.close()
            self.context = None
        if self.origin_channel is not None:
            self.origin_channel.close()
            self.origin_channel = None
        for name in ('master_pidfd', 'origin_pidfd', 'pidfd', 'output_fd',
                'native_io_pidfd', 'native_io_stdout_fd'):
            fd = getattr(self, name, -1)
            if fd >= 0:
                os.close(fd)
                setattr(self, name, -1)
        for value in self.files:
            value.close()


def capture_source_network_expectation(template_path, deadline_ns, *, repeated=False):
    """Pin the owned rt01 network template before backend startup or shell Popen.

    The returned value owns its O_NONBLOCK|O_NOFOLLOW descriptor. Pass it to
    OriginalShellLaunch, which takes ownership even when initialization fails.
    """
    now = time.monotonic_ns()
    require(type(deadline_ns) is int and deadline_ns > now and
        deadline_ns <= now + (SOURCE_RV9_AUTHORITY_NS if repeated else SOURCE_BASELINE_AUTHORITY_NS),
        'source network template capture has an invalid absolute deadline')
    raw_path = os.fspath(template_path)
    require(type(raw_path) is str and Path(raw_path).is_absolute(),
        'source network template path must be absolute')
    canonical_path = str(Path(raw_path).resolve(strict=True))
    require(raw_path == canonical_path,
        'source network template path must be canonical and nonsymlink')
    pinned = PinnedFile(canonical_path, deadline_ns=deadline_ns,
        maximum=SOURCE_INI_MAX_BYTES, nonblocking=True)
    try:
        value = os.fstat(pinned.fd)
        require(stat.S_ISREG(value.st_mode) and value.st_uid == os.getuid() and
            value.st_nlink == 1 and value.st_size <= SOURCE_INI_MAX_BYTES and
            stat.S_IMODE(value.st_mode) & 0o022 == 0 and
            str(pinned.path) == canonical_path,
            'source network template is not an owned bounded regular file')
        data = _read_pinned(pinned, deadline_ns, SOURCE_INI_MAX_BYTES)
        sections = OriginalShellLaunch._source_ini_values(data)
        port = sections['port0']
        return SourceNetworkExpectation(canonical_path, pinned.sha256.hex(),
            port['addr'], port['netmask'], port['broadcast'], port['gateway'],
            deadline_ns, pinned, repeated)
    except BaseException:
        pinned.close()
        raise



class PrivateC34OriginalShellLaunch(OriginalShellLaunch):
    """Same original-shell Origin/settlement semantics under fixed private pins."""
    def __init__(self, source_root, arguments, environment, nginx, nginx_hash,
            *, network_expectation, stdout, stderr, cwd=None, artifact_capture):
        import sys
        c34_module = sys.modules.get('_ker_nginx_source_c34_artifacts')
        if (c34_module is None or
                Path(c34_module.__file__).resolve(strict=True) !=
                    Path(__file__).with_name('nginx_source_c34_artifact_provider.py').resolve(strict=True) or
                type(artifact_capture) is not c34_module.PrivateC34ArtifactCapture):
            raise TypeError('private C34 launch requires its exact fixed artifact capture')
        deadline_text = environment.get('KER_NGINX_SOURCE_BOOTSTRAP_DEADLINE_NS', '')
        if not deadline_text.isascii() or not deadline_text.isdecimal():
            raise PermissionError('private C34 launch deadline is not canonical')
        artifact_capture.verify(int(deadline_text))
        super().__init__(source_root, arguments, environment, nginx, nginx_hash,
            network_expectation=network_expectation, stdout=stdout, stderr=stderr,
            cwd=cwd, _private_c34_capture=artifact_capture)


class OriginalSerialShellLaunch(OriginalShellLaunch):
    """Observe the pinned graceful-off shell and a master on the serial channel."""

    def __init__(self, source_root, nginx, manifest, template, output, cycle,
            *, trace, stderr=None, stdout=None):
        self.files = []
        self.process = None
        self.pidfd = self.master_pidfd = self.origin_pidfd = self.output_fd = -1
        self.context = self.origin_channel = self.settlement = None
        self.run_id = None
        self.started = self.unresolved = False
        self.creator_pid = os.getpid()
        self.creator_start = identity._start_ticks(self.creator_pid)
        self.pid_namespace = namespace_identity(self.creator_pid)
        self.deadline_ns = time.monotonic_ns() + 150_000_000_000
        self.output = str(Path(output).resolve())
        require(not Path(self.output).exists(), 'serial source output must be fresh')
        require(cycle.source_socket is not None and cycle.outer_pid == self.creator_pid and
            cycle.outer_start == self.creator_start,
            'serial source shell requires a named channel owned by this process')
        source = Path(source_root).resolve(strict=True)
        require(subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'],
            text=True).strip() == '646a641cfff77f4815e1e29829a09e1ed15a2999',
            'serial source revision differs from the pinned original')
        self.common = source / 'tests/integration/common'
        try:
            self.shell = self.pin(self.common.parent / 'test_graceful_reload.sh', SHELL_SHA256)
            self.supervisor_script = self.pin(self.common / 'reload_supervisor.py', SUPERVISOR_SHA256)
            self.checks_script = self.pin(self.common / 'reload_checks.py', CHECKS_SHA256)
            self.runtime_script = self.pin(self.common / 'reload_runtime.sh', RUNTIME_SHA256)
            self.launcher_script = self.pin(Path(__file__).with_name('ker-run.py'), _LAUNCHER_SHA256)
            self.bash = self.pin('/bin/bash')
            self.python = self.pin(shutil.which('python3', path=os.defpath))
            build = self.pin(manifest, maximum=16 * 1024 * 1024)
            manifest_data = json.loads(_read_pinned(build, self.deadline_ns, build.maximum))
            self.nginx = self.pin(nginx, manifest_data['nginx']['sha256'])
            self.binary_hash = self.nginx.sha256
            require(str(self.nginx.path) == manifest_data['nginx']['path'],
                'serial source Nginx differs from the build manifest')
            self.template = self.pin(template, maximum=SOURCE_INI_MAX_BYTES)
            config = self._source_ini_values(_read_pinned(self.template, self.deadline_ns,
                self.template.maximum))
            require(config['port0'] == dict(addr='198.18.0.2', netmask='255.255.255.0',
                broadcast='198.18.0.255', gateway='198.18.0.1', lcore_list='0') and
                config['ker_socket_broker'].get('version') == '1' and
                config['dpdk']['graceful_reload'] == '0' and
                config['dpdk']['primary_slim'] == '0' and
                config['dpdk']['lcore_mask'] == '1',
                'original serial source requires the bounded graceful-off network')
            self.arguments = ['--cases', 'precheck,gr0', '--workers', '1', '--graceful', '0',
                '--target-ip', '198.18.0.2', '--out', self.output,
                '--fstack-conf', str(self.template.path), '--nginx', str(self.nginx.path),
                '--build-manifest', str(build.path)]
            environment = dict(PATH=os.defpath, **cycle.nginx_environment(),
                KER_SOCKET_BROKER_PATH=config['ker_socket_broker']['path'],
                KER_FSTACK_NGINX_INI=str(Path(self.output) / 'fstack_gr0.ini'),
                KER_FSTACK_RUNTIME_TRACE=os.fspath(trace))
            self.cycle = cycle
            self.process = subprocess.Popen([str(self.bash.path), str(self.shell.path),
                *self.arguments], env=environment, stdout=stdout, stderr=stderr,
                close_fds=True)
            self.pidfd = os.pidfd_open(self.process.pid)
            self.start = identity._start_ticks(self.process.pid)
        except BaseException as error:
            if self.process is not None:
                raise OriginalLaunchUnsettled(self, error) from error
            self.close()
            raise

    def bind_initial_runtime(self, controller, context):
        from ker_serial_generation import SerialGenerationController

        require(type(controller) is SerialGenerationController and
            not hasattr(self, 'serial_runtime') and context is controller._old_context,
            'serial shell requires the controller’s initial native runtime')
        controller.verify_source_initial_runtime(context, self.cycle)
        self.serial_runtime = controller, context

    def live_initial_runtime(self):
        require(hasattr(self, 'serial_runtime'), 'serial shell has no captured native runtime')
        controller, context = self.serial_runtime
        controller.verify_source_initial_runtime(context, self.cycle)

    def bind_master(self, pid, deadline_ns):
        require(not self.started and not self.unresolved,
            'original serial master was already pinned')
        start = identity._start_ticks(pid)
        fd = os.pidfd_open(pid)
        try:
            while time.monotonic_ns() < deadline_ns:
                self.live_supervisor(deadline_ns)
                self.nginx.matches_process(pid, deadline_ns)
                require(namespace_identity(pid) == self.pid_namespace and
                    identity._pidfd_pid(fd) == pid and identity.process_alive(fd) and
                    identity._start_ticks(pid) == start,
                    'original serial master changed during observation')
                try:
                    snapshot, _ = _read_original_output_receipt(self, 'supervisor.json',
                        65536, deadline_ns)
                except BlockingIOError:
                    continue
                snapshot = json.loads(snapshot)
                actor = snapshot.get('supervisor', {})
                require(snapshot.get('run_id') == self.run_id and
                    (actor.get('pid'), actor.get('start_time'), actor.get('device'),
                        actor.get('inode')) == (self.process.pid, self.start,
                            *self.python.frozen[:2]),
                    'serial master membership belongs to a different supervisor')
                for member in snapshot.get('members', ()):
                    current = member.get('current') or {}
                    if (snapshot.get('stack') == 'gr0' and member.get('role') == 'target' and
                        (member.get('pid'), member.get('start_time'), current.get('device'),
                            current.get('inode')) == (pid, start, *self.nginx.frozen[:2])):
                        self.master_pid, self.master_start, self.master_pidfd = pid, start, fd
                        self.started = True
                        return
                time.sleep(.01)
            raise TimeoutError('original supervisor did not register the serial master')
        except BaseException:
            os.close(fd)
            self.unresolved = True
            raise

    def final_owner_receipt(self, owner, cycle):
        require(self.started and not self.unresolved and self.cycle is cycle and
            cycle.master_identity == (self.master_pid, os.getuid(), os.getgid(),
                self.master_start, self.binary_hash),
            'original serial master differs from the pinned cycle channel')
        settled = self.observe_settlement()
        require(settled['result'] == 0, 'original serial shell failed')
        deadline = time.monotonic_ns() + 1_000_000_000
        events, _ = _read_original_output_receipt(self, 'ownership-events.jsonl',
            8 * 1024 * 1024, deadline)
        require(hashlib.sha256(events).hexdigest() == settled['events_sha256'],
            'original serial events differ from final settlement')
        rows = [json.loads(row) for row in events.splitlines()]
        for pid, start in ((self.master_pid, self.master_start),
                (owner.pid, owner.start_ticks)):
            matched = [row for row in rows if row.get('run_id') == self.run_id and
                (row.get('pid'), row.get('start_time')) == (pid, start)]
            require(any(row.get('event') == 'signal_requested' and row.get('signal') == 'TERM'
                for row in matched) and not any(row.get('signal') == 'KILL' for row in matched) and
                sum(row.get('event') == 'exited' and row.get('stack') == 'gr0'
                    for row in matched) == 1,
                'original serial actor lacks natural supervisor-verified retirement')
        for artifact in self.files:
            artifact.live(deadline)
        return hashlib.sha256(b'ker-original-serial-shutdown-v1\0' +
            bytes.fromhex(settled['snapshot_sha256']) + events).digest()
