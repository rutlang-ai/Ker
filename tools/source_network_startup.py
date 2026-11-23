"""Strict source-profile startup records for the original-Linux runtime."""
import ipaddress
import fcntl
import hashlib
import errno
import os
import select
import stat
import subprocess
import threading
import time
from typing import NamedTuple

READY = b'KER_NATIVE_READY\n'
PROOF_PREFIX = b'KER_SOURCE_NETWORK_READBACK_V1 '
BOOTSTRAP_DEADLINE_ENV = 'KER_NGINX_SOURCE_BOOTSTRAP_DEADLINE_NS'
READBACK_ENV = 'KER_SOURCE_NETWORK_READBACK'
PROFILE_ENV = 'KER_NGINX_SOURCE_SHELL_ENABLE'
MAX_RECORD_BYTES = 4096
MAX_DEADLINE_AHEAD_NS = 300_000_000_000
_PROOF_KEYS = ('template_sha256', 'ifindex', 'address', 'netmask', 'broadcast',
               'gateway', 'route_oif', 'route_table', 'deadline_ns')
_LIFECYCLE_MARKERS = (b'KER_NATIVE_STOPPING\n', b'KER_NATIVE_DONE\n',
    b'KER_NATIVE_INCOMPLETE\n', b'KER_RX_DECISION_READY\n')
MAX_EXECUTABLE_BYTES = 512 * 1024 * 1024
_VALIDATED_STARTUP_TOKEN = object()
_RETAINED_RECEIPT_TOKEN = object()
_HANDOFF_TOKEN = object()


class SourceNetworkExpectation(NamedTuple):
    template_path: str
    template_sha256: str
    address: str
    netmask: str
    broadcast: str
    gateway: str
    deadline_ns: int
    template_file: object

    def readback_setting(self):
        return '|'.join(('v1', self.template_sha256, self.address, self.netmask,
            self.broadcast, self.gateway, str(self.deadline_ns)))


class BackendActorIdentity(NamedTuple):
    pid: int
    pidfd: int
    start_ticks: int
    executable_hash: bytes


class PinnedExecutable:
    """Hold and deadline-bound hash the prelaunch app ELF through startup."""
    def __init__(self, path, deadline_ns):
        if time.monotonic_ns() >= deadline_ns:
            raise TimeoutError('prelaunch executable pin deadline expired')
        self.path = os.path.realpath(path)
        self.fd = os.open(self.path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            if time.monotonic_ns() >= deadline_ns:
                raise TimeoutError('prelaunch executable open exceeded source deadline')
            before = os.fstat(self.fd)
            if (not stat.S_ISREG(before.st_mode) or not before.st_mode & 0o111 or
                    before.st_size < 0 or before.st_size > MAX_EXECUTABLE_BYTES):
                raise ValueError('prelaunch application is not a bounded executable regular file')
            self.metadata = self._metadata(before)
            if self._metadata(os.stat(self.path, follow_symlinks=False)) != self.metadata:
                raise RuntimeError('prelaunch executable path changed while pinning')
            if time.monotonic_ns() >= deadline_ns:
                raise TimeoutError('prelaunch executable metadata exceeded source deadline')
            self.sha256 = self._digest(self.fd, before.st_size, deadline_ns)
            self.verify(deadline_ns)
        except BaseException:
            os.close(self.fd)
            self.fd = -1
            raise

    @staticmethod
    def _metadata(value):
        return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
            value.st_ctime_ns, stat.S_IMODE(value.st_mode))

    @staticmethod
    def _digest(fd, size, deadline_ns):
        digest = hashlib.sha256()
        offset = 0
        while offset < size:
            if time.monotonic_ns() >= deadline_ns:
                raise TimeoutError('prelaunch executable hash exceeded source deadline')
            block = os.pread(fd, min(1024 * 1024, size - offset), offset)
            if not block:
                raise RuntimeError('prelaunch executable became truncated')
            digest.update(block)
            offset += len(block)
        if time.monotonic_ns() >= deadline_ns:
            raise TimeoutError('prelaunch executable hash finished after source deadline')
        return digest.digest()

    def verify(self, deadline_ns):
        if self.fd < 0 or time.monotonic_ns() >= deadline_ns:
            raise TimeoutError('pinned executable verification deadline expired')
        before = os.fstat(self.fd)
        if self._metadata(before) != self.metadata:
            raise RuntimeError('held prelaunch executable metadata changed')
        if self._metadata(os.stat(self.path, follow_symlinks=False)) != self.metadata:
            raise RuntimeError('prelaunch executable path inode or metadata changed')
        if time.monotonic_ns() >= deadline_ns:
            raise TimeoutError('pinned executable metadata exceeded source deadline')
        digest = self._digest(self.fd, before.st_size, deadline_ns)
        after = os.fstat(self.fd)
        path_after = os.stat(self.path, follow_symlinks=False)
        if (self._metadata(after) != self.metadata or
                self._metadata(path_after) != self.metadata or digest != self.sha256):
            raise RuntimeError('pinned prelaunch executable changed during verification')

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


class ValidatedStartup:
    """Immutable exact bytes and fields returned only by the strict parser."""
    __slots__ = ('_expected', '_prefix', '_tail', '_proof', '_validated_ns')

    def __init__(self, token, expected, prefix, tail, proof, validated_ns):
        if token is not _VALIDATED_STARTUP_TOKEN:
            raise TypeError('validated startup records are parser-owned')
        object.__setattr__(self, '_expected', _expected_key(expected))
        object.__setattr__(self, '_prefix', bytes(prefix))
        object.__setattr__(self, '_tail', bytes(tail))
        object.__setattr__(self, '_proof', tuple(proof.items()))
        object.__setattr__(self, '_validated_ns', validated_ns)

    def __setattr__(self, name, value):
        raise AttributeError('validated startup records are immutable')

    def __getitem__(self, name):
        if name == 'prefix':
            return self._prefix
        if name == 'tail':
            return self._tail
        if name == 'proof':
            return dict(self._proof)
        raise KeyError(name)


def _proc_start_ticks(pid):
    with open(f'/proc/{pid}/stat', 'rb', buffering=0) as stream:
        raw = stream.read(4096)
    close = raw.rfind(b')')
    if close < 0:
        raise RuntimeError('process stat has no command terminator')
    fields = raw[close + 2:].split()
    if len(fields) < 20:
        raise RuntimeError('process stat is truncated')
    return int(fields[19])


def _pidfd_pid(pidfd):
    with open(f'/proc/self/fdinfo/{pidfd}', 'rt', encoding='ascii') as stream:
        for line in stream:
            if line.startswith('Pid:'):
                value = line.split(':', 1)[1].strip()
                return int(value)
    raise RuntimeError('pidfd has no process identity')


def _expected_key(expected):
    keys = ('record', 'template_sha256', 'address', 'netmask', 'broadcast',
        'gateway', 'deadline_ns')
    if type(expected) is not dict or set(expected) != set(keys):
        raise ValueError('retained backend requires the exact source expectation')
    if (type(expected['record']) is not str or type(expected['deadline_ns']) is not int or
            any(type(expected[name]) is not str for name in keys[1:-1])):
        raise ValueError('retained backend expectation has invalid field types')
    return tuple(expected[name] for name in keys)

def _captured_expectation_key(expected):
    """Bridge the held template capture to the unchanged native dict contract."""
    if type(expected) is not SourceNetworkExpectation:
        raise ValueError('captured source expectation has the wrong exact type')
    return _expected_key({'record': expected.readback_setting(),
        'template_sha256': expected.template_sha256, 'address': expected.address,
        'netmask': expected.netmask, 'broadcast': expected.broadcast,
        'gateway': expected.gateway, 'deadline_ns': expected.deadline_ns})


class RetainedBackendReceipt:
    """Owned proof retained from one successful source startup validation."""
    __slots__ = ('creator_pid', 'creator_start_ticks', 'process', 'pid', 'start_ticks',
        'pidfd', 'startup_fd', 'executable', 'pipe_identity', 'expected', 'prefix',
        'proof', 'validated_ns', 'deadline_ns', 'runtime_service', 'actor_identity',
        'handoff', 'closed')

    def __setattr__(self, name, value):
        if not hasattr(self, name):
            object.__setattr__(self, name, value)
            return
        current = getattr(self, name)
        if (name == 'handoff' and current is None and
                type(value) is RetainedBackendHandoff):
            object.__setattr__(self, name, value)
            return
        if name == 'closed' and current is False and value is True:
            object.__setattr__(self, name, value)
            return
        raise AttributeError('retained backend evidence is immutable')

    def __init__(self, capability, process, pidfd, start_ticks, executable_pin,
            startup_fd, pipe_identity_value, expected, parsed, validated_ns,
            runtime_service):
        if capability is not _RETAINED_RECEIPT_TOKEN:
            raise TypeError('retained backend receipts are created at validated startup only')
        if (not isinstance(process, subprocess.Popen) or process.poll() is not None or
                type(start_ticks) is not int or start_ticks <= 0 or
                not isinstance(executable_pin, PinnedExecutable) or executable_pin.fd < 0 or
                type(pipe_identity_value) is not tuple or len(pipe_identity_value) != 3 or
                type(parsed) is not ValidatedStartup or type(validated_ns) is not int):
            raise ValueError('cannot retain an incomplete backend startup observation')
        expected_key = _expected_key(expected)
        if (parsed._expected != expected_key or validated_ns < parsed._validated_ns or
                validated_ns >= expected['deadline_ns']):
            raise ValueError('startup parser result is not the captured bounded expectation')
        self.creator_pid = os.getpid()
        self.creator_start_ticks = _proc_start_ticks(self.creator_pid)
        self.process = process
        self.pid = process.pid
        self.start_ticks = start_ticks
        duplicated = []
        try:
            self.pidfd = os.dup(pidfd)
            duplicated.append(self.pidfd)
            self.startup_fd = os.dup(startup_fd)
            duplicated.append(self.startup_fd)
            self.executable = object.__new__(PinnedExecutable)
            self.executable.path = executable_pin.path
            self.executable.fd = os.dup(executable_pin.fd)
            duplicated.append(self.executable.fd)
            self.executable.metadata = tuple(executable_pin.metadata)
            self.executable.sha256 = bytes(executable_pin.sha256)
            self.pipe_identity = tuple(pipe_identity_value)
            self.expected = expected_key
            self.prefix = bytes(parsed['prefix'])
            self.proof = tuple(parsed['proof'].items())
            self.validated_ns = validated_ns
            self.deadline_ns = expected['deadline_ns']
            self.runtime_service = runtime_service
            self.handoff = None
            self.closed = False
            for fd in duplicated:
                os.set_inheritable(fd, False)
            self.actor_identity = BackendActorIdentity(self.pid, self.pidfd,
                self.start_ticks, self.executable.sha256)
        except BaseException:
            for fd in duplicated:
                try:
                    os.close(fd)
                except OSError:
                    pass
            raise

    def validate_live(self, expected, runtime_actor, deadline_ns):
        if self.closed:
            raise RuntimeError('retained backend receipt is closed')
        if (os.getpid() != self.creator_pid or
                _proc_start_ticks(self.creator_pid) != self.creator_start_ticks):
            raise RuntimeError('retained backend receipt changed SDK creator')
        if _expected_key(expected) != self.expected:
            raise RuntimeError('retained backend receipt differs from launch expectation')
        try:
            actor_pid = runtime_actor.pid
            actor_pidfd = runtime_actor.pidfd
            actor_start = runtime_actor.start_ticks
            actor_hash = runtime_actor.executable_hash
        except AttributeError as error:
            raise RuntimeError('runtime actor lacks its captured pidfd identity') from error
        if (type(actor_pid) is not int or actor_pid != self.pid or
                type(actor_pidfd) is not int or actor_pidfd < 0 or
                type(actor_start) is not int or actor_start != self.start_ticks or
                type(actor_hash) is not bytes or actor_hash != self.executable.sha256 or
                _pidfd_pid(actor_pidfd) != self.pid):
            raise RuntimeError('runtime actor differs from the retained backend process identity')
        bound = min(self.deadline_ns, deadline_ns)
        if time.monotonic_ns() >= bound or deadline_ns > self.deadline_ns:
            raise TimeoutError('retained backend receipt is outside its immutable deadline')
        poller = select.poll()
        poller.register(self.pidfd, select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL)
        actor_poller = select.poll()
        actor_poller.register(actor_pidfd,
            select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL)
        if (self.process.pid != self.pid or self.process.poll() is not None or
                poller.poll(0) or actor_poller.poll(0) or _pidfd_pid(self.pidfd) != self.pid or
                _proc_start_ticks(self.pid) != self.start_ticks):
            raise RuntimeError('retained backend actor is no longer the captured live process')
        self.executable.verify(bound)
        if self.handoff is not None and self.handoff.template_file is not None:
            self.handoff.template_file.live(bound)
        if not process_executable_matches(self.pid, self.executable, bound):
            raise RuntimeError('retained backend executable identity changed')
        if pipe_identity(self.startup_fd) != self.pipe_identity:
            raise RuntimeError('retained backend startup FIFO identity changed')
        proof = dict(self.proof)
        encoded = READY + PROOF_PREFIX + ' '.join(
            f'{key}={value}' for key, value in proof.items()).encode() + b'\n'
        if encoded != self.prefix:
            raise RuntimeError('retained backend startup bytes/proof changed')
        if time.monotonic_ns() >= bound:
            raise TimeoutError('retained backend validation exceeded its immutable deadline')
        return True

    def close(self):
        if self.closed:
            return
        poller = select.poll()
        poller.register(self.pidfd, select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL)
        if self.process.poll() is None and not poller.poll(0):
            raise RuntimeError('retained backend actor is live; keep its proof descriptors')
        for fd in (self.pidfd, self.startup_fd, self.executable.fd):
            if fd >= 0:
                os.close(fd)
        self.executable.fd = -1
        object.__setattr__(self, 'closed', True)


def _capture_retained_backend_receipt(process, pidfd, start_ticks, executable_pin,
        startup_fd, pipe_identity_value, expected, parsed, validated_ns, runtime):
    """Private constructor used only at ker-run's post-validation boundary."""
    if type(parsed) is not ValidatedStartup:
        raise TypeError('backend receipt requires parser-produced startup evidence')
    return RetainedBackendReceipt(_RETAINED_RECEIPT_TOKEN, process, pidfd,
        start_ticks, executable_pin, startup_fd, pipe_identity_value, expected,
        parsed, validated_ns, runtime)

class RetainedBackendHandoff:
    """Single-owner same-process handoff; never a module-global receipt registry."""
    def __init__(self, token, expected, creator_pid=None, creator_start_ticks=None,
            template_file=None):
        if token is not _HANDOFF_TOKEN:
            raise TypeError('backend handoffs are created from a captured network expectation')
        self.expected = _expected_key(expected)
        self.creator_pid = os.getpid() if creator_pid is None else creator_pid
        self.creator_start_ticks = (_proc_start_ticks(self.creator_pid)
            if creator_start_ticks is None else creator_start_ticks)
        if (self.creator_pid != os.getpid() or
                self.creator_start_ticks != _proc_start_ticks(self.creator_pid)):
            raise ValueError('backend handoff must belong to its current SDK creator')
        self.template_file = template_file
        self._condition = threading.Condition()
        self._receipt = None
        self._failure = None
        self._taken = False
        self._closed = False

    @classmethod
    def for_network_expectation(cls, expectation, creator_pid=None,
            creator_start_ticks=None):
        if type(expectation) is not SourceNetworkExpectation:
            raise TypeError('backend handoff requires the captured network expectation type')
        record = expectation.readback_setting()
        fields = record.split('|')
        if len(fields) != 7:
            raise ValueError('network expectation has an invalid readback record')
        expected = {'record': record, 'template_sha256': fields[1], 'address': fields[2],
            'netmask': fields[3], 'broadcast': fields[4], 'gateway': fields[5],
            'deadline_ns': expectation.deadline_ns}
        return cls(_HANDOFF_TOKEN, expected, creator_pid, creator_start_ticks,
            getattr(expectation, 'template_file', None))

    def publish(self, receipt):
        if type(receipt) is not RetainedBackendReceipt:
            raise TypeError('backend handoff accepts only its retained receipt type')
        with self._condition:
            if (self._closed or self._receipt is not None or self._taken or
                    receipt.creator_pid != self.creator_pid or
                    receipt.creator_start_ticks != self.creator_start_ticks or
                    receipt.expected != self.expected):
                raise RuntimeError('backend receipt does not belong to this live handoff')
            receipt.handoff = self
            self._receipt = receipt
            self._condition.notify_all()

    def fail(self, error):
        with self._condition:
            if self._receipt is None and self._failure is None:
                self._failure = type(error).__name__
            self._condition.notify_all()

    def take(self, deadline_ns):
        with self._condition:
            if self._closed or self._taken:
                raise RuntimeError('backend handoff is closed or already consumed')
            while self._receipt is None and self._failure is None:
                remaining = deadline_ns - time.monotonic_ns()
                if remaining <= 0:
                    raise TimeoutError('retained backend receipt missed the immutable deadline')
                self._condition.wait(remaining / 1_000_000_000)
            if self._failure is not None:
                raise OSError(errno.ENOTSUP, 'source backend startup did not produce a retained receipt')
            receipt = self._receipt
            self._receipt = None
            self._taken = True
            return receipt

    def close(self):
        with self._condition:
            if self._closed:
                return
            receipt = self._receipt
            if receipt is not None:
                receipt.close()
            self._receipt = None
            self._closed = True
            self._condition.notify_all()


def _decimal(text, minimum=0, maximum=(1 << 64) - 1):
    if (type(text) is not str or not text or
            (text.startswith('0') and len(text) > 1) or
            not text.isascii() or not text.isdecimal()):
        raise ValueError('noncanonical decimal value')
    value = int(text, 10)
    if value < minimum or value > maximum:
        raise ValueError('decimal value outside allowed range')
    return value


def _ipv4(text):
    value = ipaddress.IPv4Address(text)
    if str(value) != text:
        raise ValueError('noncanonical IPv4 address')
    return value


def _supported_unicast_host(value, network):
    first_octet = int(value) >> 24
    return (1 <= first_octet <= 223 and first_octet != 127 and
        value in network and value != network.network_address and
        value != network.broadcast_address)


def prepare_expected(profile_flag, record, bootstrap_deadline, address, gateway,
                     *, forbidden_network_settings=(), now_ns=None):
    """Validate source-only env against already parsed ker-run launch settings."""
    if profile_flag is None:
        if record is not None:
            raise ValueError('network readback setting requires explicit source profile')
        return None
    if profile_flag != '1':
        raise ValueError('source profile flag must equal 1')
    if not record or not bootstrap_deadline:
        raise ValueError('source profile requires readback setting and immutable deadline')
    if forbidden_network_settings:
        raise ValueError('source profile rejects additional interface/address/route settings')
    if address is None or gateway is None:
        raise ValueError('source profile requires launch address and gateway')
    if not isinstance(address, ipaddress.IPv4Interface):
        address = ipaddress.IPv4Interface(address)
    if not isinstance(gateway, ipaddress.IPv4Address):
        gateway = ipaddress.IPv4Address(gateway)
    if type(record) is not str or len(record.encode('ascii', 'strict')) > 256:
        raise ValueError('readback setting is malformed or oversized')
    fields = record.split('|')
    if len(fields) != 7 or fields[0] != 'v1':
        raise ValueError('readback setting must have seven v1 fields')
    version, digest, addr_text, mask_text, broadcast_text, gateway_text, deadline_text = fields
    if len(digest) != 64 or any(ch not in '0123456789abcdef' for ch in digest):
        raise ValueError('readback setting template hash is malformed')
    addr, mask, broadcast, route_gateway = map(_ipv4,
        (addr_text, mask_text, broadcast_text, gateway_text))
    network = ipaddress.IPv4Network(address, strict=False)
    if (not 1 <= network.prefixlen <= 30 or
            address.ip != addr or network.netmask != mask or
            network.broadcast_address != broadcast or gateway != route_gateway or
            not _supported_unicast_host(addr, network) or
            not _supported_unicast_host(route_gateway, network) or
            addr == route_gateway):
        raise ValueError('readback network tuple differs from launch address/gateway')
    deadline = _decimal(deadline_text, minimum=1)
    if _decimal(bootstrap_deadline, minimum=1) != deadline:
        raise ValueError('readback deadline differs from immutable bootstrap deadline')
    now_ns = time.monotonic_ns() if now_ns is None else now_ns
    if type(now_ns) is not int or deadline <= now_ns or deadline - now_ns > MAX_DEADLINE_AHEAD_NS:
        raise ValueError('source startup deadline is expired or outside bounded window')
    return {'record': record, 'template_sha256': digest, 'address': str(addr),
        'netmask': str(mask), 'broadcast': str(broadcast), 'gateway': str(route_gateway),
        'deadline_ns': deadline}


def prepare_from_launch(args, environ, now_ns=None):
    """Bind the explicit source profile to ker-run's parsed launch tuple."""
    names = ('address6', 'vip_addresses', 'vip_addresses6', 'vlans',
        'vlan_gateways', 'vlan_gateways6', 'gateway6', 'interfaces', 'sysctls')
    forbidden = tuple(name for name in names if getattr(args, name, None))
    expected = prepare_expected(environ.get(PROFILE_ENV),
        environ.get(READBACK_ENV), environ.get(BOOTSTRAP_DEADLINE_ENV),
        getattr(args, 'address', None), getattr(args, 'gateway', None),
        forbidden_network_settings=forbidden, now_ns=now_ns)
    if expected is not None and not getattr(args, 'runtime_service', False):
        raise ValueError('source network startup requires pinned runtime-service identity')
    return expected


def pipe_identity(read_fd, write_fd=None):
    """Pin the startup FIFO created by primary_channels before child launch."""
    read_stat = os.fstat(read_fd)
    read_flags = fcntl.fcntl(read_fd, fcntl.F_GETFL)
    if (not stat.S_ISFIFO(read_stat.st_mode) or
            read_flags & os.O_ACCMODE != os.O_RDONLY or
            not read_flags & os.O_NONBLOCK):
        raise ValueError('source startup reader is not a nonblocking FIFO read end')
    identity = (read_stat.st_dev, read_stat.st_ino, stat.S_IFMT(read_stat.st_mode))
    if write_fd is not None:
        write_stat = os.fstat(write_fd)
        write_flags = fcntl.fcntl(write_fd, fcntl.F_GETFL)
        if (not stat.S_ISFIFO(write_stat.st_mode) or
                (write_stat.st_dev, write_stat.st_ino, stat.S_IFMT(write_stat.st_mode)) != identity or
                write_flags & os.O_ACCMODE != os.O_WRONLY):
            raise ValueError('startup endpoints are not the same FIFO pair')
    return identity


def _validate_tail(tail):
    if not tail:
        return
    for line in tail.splitlines(keepends=True):
        if line == READY or line.startswith(PROOF_PREFIX) or line.startswith(b'KER_SOURCE_NETWORK_'):
            raise ValueError('duplicate or unknown source proof in startup tail')
        if line in _LIFECYCLE_MARKERS or line.startswith(b'KER_NATIVE_STATS '):
            continue
        if not line.endswith(b'\n') and any(marker.startswith(line) for marker in _LIFECYCLE_MARKERS):
            continue
        raise ValueError('unknown startup record after source proof')


def parse_startup_prefix(data, expected, now_ns=None):
    """Validate READY and one proof; retain all later phase bytes verbatim."""
    if not isinstance(expected, dict) or not isinstance(data, bytes) or not data or len(data) > MAX_RECORD_BYTES:
        raise ValueError('source startup record is missing or oversized')
    if b'\0' in data or b'\r' in data:
        raise ValueError('source startup record contains forbidden bytes')
    first_end = data.find(b'\n')
    second_end = data.find(b'\n', first_end + 1) if first_end >= 0 else -1
    if first_end < 0 or second_end < 0 or data[:first_end + 1] != READY:
        raise ValueError('startup stream lacks exact READY/proof prefix')
    proof_line = data[first_end + 1:second_end + 1]
    try:
        proof = proof_line[:-1].decode('ascii')
    except UnicodeDecodeError as error:
        raise ValueError('source proof is not ASCII') from error
    prefix = PROOF_PREFIX.decode('ascii')
    if not proof.startswith(prefix):
        raise ValueError('second startup record is not the source network proof')
    tokens = proof[len(prefix):].split(' ')
    if len(tokens) != len(_PROOF_KEYS):
        raise ValueError('source proof has missing, extra, or duplicate fields')
    observed = {}
    for expected_key, token in zip(_PROOF_KEYS, tokens):
        key, separator, value = token.partition('=')
        if not separator or key != expected_key or not value or key in observed:
            raise ValueError('source proof field order or key set is invalid')
        observed[key] = value
    if observed['template_sha256'] != expected['template_sha256']:
        raise ValueError('source proof template hash mismatch')
    for key in ('address', 'netmask', 'broadcast', 'gateway'):
        if _ipv4(observed[key]) != _ipv4(expected[key]):
            raise ValueError(f'source proof {key} differs from captured expectation')
    if _decimal(observed['ifindex'], 1, (1 << 32) - 1) != _decimal(
            observed['route_oif'], 1, (1 << 32) - 1):
        raise ValueError('source proof route uses a different interface')
    if _decimal(observed['route_table'], 1, (1 << 32) - 1) != 254:
        raise ValueError('source proof is not for the main route table')
    deadline = _decimal(observed['deadline_ns'], 1)
    if deadline != expected['deadline_ns']:
        raise ValueError('source proof deadline mismatch')
    now_ns = time.monotonic_ns() if now_ns is None else now_ns
    if deadline <= now_ns or deadline - now_ns > MAX_DEADLINE_AHEAD_NS:
        raise ValueError('source proof arrived outside its immutable deadline')
    prefix_bytes = data[:second_end + 1]
    tail = data[second_end + 1:]
    _validate_tail(tail)
    return ValidatedStartup(_VALIDATED_STARTUP_TOKEN, expected, prefix_bytes,
        tail, observed, now_ns)


def startup_audit_record(parsed, expected_pipe_identity, app_pid, app_start_ticks,
                         executable_pin, validated_monotonic_ns, deadline_ns):
    """Build source-only audit data after all caller identity checks succeed."""
    if (type(parsed) is not ValidatedStartup or type(parsed['prefix']) is not bytes or
            type(parsed['proof']) is not dict or type(app_pid) is not int or
            app_pid <= 0 or type(app_start_ticks) is not int or app_start_ticks <= 0 or
            executable_pin is None or executable_pin.fd < 0 or
            type(deadline_ns) is not int or
            type(validated_monotonic_ns) is not int or
            validated_monotonic_ns < parsed._validated_ns or
            validated_monotonic_ns >= deadline_ns or
            time.monotonic_ns() >= deadline_ns):
        raise ValueError('source startup audit requested without successful bounded validation')
    if len(expected_pipe_identity) != 3 or len(executable_pin.metadata) != 6:
        raise ValueError('source startup audit identity metadata is incomplete')
    device, inode, size, mtime_ns, ctime_ns, mode = executable_pin.metadata
    pipe_device, pipe_inode, pipe_type = expected_pipe_identity
    return {
        'startup_prefix_hex': parsed['prefix'].hex(),
        'observed': dict(parsed['proof']),
        'startup_pipe': {'device': pipe_device, 'inode': pipe_inode,
            'type': pipe_type},
        'application': {'pid': app_pid, 'start_ticks': app_start_ticks,
            'executable': {'device': device, 'inode': inode, 'size': size,
                'mtime_ns': mtime_ns, 'ctime_ns': ctime_ns, 'mode': mode,
                'sha256': executable_pin.sha256.hex()}},
        'validated_monotonic_ns': validated_monotonic_ns,
    }


def read_startup_prefix(fd, expected_pipe_identity, deadline_ns, maximum=MAX_RECORD_BYTES):
    """Read through the proof newline under one absolute deadline, preserving tail."""
    if fd < 0 or maximum < len(READY) or maximum > MAX_RECORD_BYTES:
        raise ValueError('invalid startup pipe read request')
    before = pipe_identity(fd)
    if before != expected_pipe_identity:
        raise ValueError('source startup pipe identity changed before read')
    poller = select.poll()
    poller.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL)
    data = bytearray()
    while len(data) <= maximum:
        now = time.monotonic_ns()
        if now >= deadline_ns:
            raise TimeoutError('source startup proof deadline expired')
        timeout_ms = max(1, min((deadline_ns - now + 999_999) // 1_000_000, 2_147_483_647))
        events = poller.poll(timeout_ms)
        if not events:
            continue
        if events[0][1] & (select.POLLERR | select.POLLNVAL):
            raise OSError('source startup pipe poll error')
        try:
            block = os.read(fd, min(4096, maximum + 1 - len(data)))
        except BlockingIOError:
            continue
        if not block:
            raise EOFError('source startup writer closed before proof')
        data.extend(block)
        if data.count(b'\n') >= 2:
            after = pipe_identity(fd)
            if after != expected_pipe_identity:
                raise ValueError('source startup pipe identity changed during read')
            if time.monotonic_ns() >= deadline_ns:
                raise TimeoutError('source startup proof arrived after deadline')
            return bytes(data)
    raise ValueError('source startup stream exceeds bound')


def process_executable_matches(pid, pinned, deadline_ns):
    """Compare /proc/PID/exe with the held prelaunch ELF under one deadline."""
    if time.monotonic_ns() >= deadline_ns:
        raise TimeoutError('source application identity deadline expired')
    pinned.verify(deadline_ns)
    if time.monotonic_ns() >= deadline_ns:
        raise TimeoutError('source application identity deadline expired before proc open')
    fd = os.open(f'/proc/{pid}/exe', os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        if time.monotonic_ns() >= deadline_ns:
            raise TimeoutError('source application proc open exceeded deadline')
        before = os.fstat(fd)
        if PinnedExecutable._metadata(before) != pinned.metadata:
            return False
        digest = PinnedExecutable._digest(fd, before.st_size, deadline_ns)
        after = os.fstat(fd)
        path_after = os.stat(f'/proc/{pid}/exe')
        if (PinnedExecutable._metadata(after) != pinned.metadata or
                PinnedExecutable._metadata(path_after) != pinned.metadata or
                time.monotonic_ns() >= deadline_ns):
            return False
        pinned.verify(deadline_ns)
        return digest == pinned.sha256
    finally:
        os.close(fd)
