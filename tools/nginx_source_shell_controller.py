"""Typed same-process controller for the closed original source-shell path.

This module retains actual SDK launch objects.  It does not run from a helper
process and does not grant source authority while the Origin preparse gate is
closed.
"""
import array
import errno
import fcntl
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import select
import selectors
import secrets
import signal
import socket
import stat
import struct
import sys
import threading
import time
from types import MappingProxyType, SimpleNamespace
from typing import NamedTuple

_PROFILE_TOKEN = object()
_SCOPE_NAME = '_ker_nginx_source_scope'
_SCOPE_PATH = Path(__file__).with_name('nginx_source_scope.py').resolve(strict=True)
_C22_NAME = '_ker_nginx_source_c22_provider'
_C22_PATH = Path(__file__).with_name('nginx_source_c22_provider.py').resolve(strict=True)
_C34_PROFILE_NAME = '_ker_nginx_source_c34_profile'
_C34_PROFILE_PATH = Path(__file__).with_name('nginx_source_c34_profile.py').resolve(strict=True)
_ATTACH_NAME = '_ker_nginx_companion_attach'
_ATTACH_PATH = Path(__file__).with_name('nginx_companion_attach.py').resolve(strict=True)
_INITIAL_TRANSPORT_TOKEN = object()
_FIRST_CANDIDATE_GRANT_TOKEN = object()
_PRIVATE_INITIAL_EXIT_TOKEN = object()
SOURCE_STARTUP_BUFFER_MAX = 64 * 1024
SOURCE_STARTUP_TAIL_MAX = 4096


def create_source_c31_channels():
    """Create the two source-only C31 channels before the runtime app exists.

    This only prepares the authenticated transport.  It does not authorize a
    worker, send OWNER_AUTH, or change the source bootstrap control-only gate.
    The caller owns all four returned sockets and must close them transactionally
    if application launch does not complete.
    """
    if threading.current_thread() is not threading.main_thread():
        raise PermissionError('source C31 channels must be created by the SDK main thread')
    created = []
    try:
        for _ in range(2):
            pair = socket.socketpair(socket.AF_UNIX,
                socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
            created.extend(pair)
            for endpoint in pair:
                endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        expected_peer = (os.getpid(), os.getuid(), os.getgid())
        cookies = set()
        for endpoint in created:
            peer = struct.unpack('=3i', endpoint.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('=3i')))
            if peer != expected_peer:
                raise PermissionError('source C31 pair peer is not this SDK process')
            if (endpoint.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) != 1 or
                    endpoint.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) !=
                        socket.SOCK_SEQPACKET):
                raise PermissionError('source C31 pair lacks credentialed seqpacket transport')
            cookie = struct.unpack('=Q', endpoint.getsockopt(
                socket.SOL_SOCKET, getattr(socket, 'SO_COOKIE', 57), 8))[0]
            if not cookie or cookie in cookies:
                raise PermissionError('source C31 socket cookies are not distinct')
            cookies.add(cookie)
        return tuple(created)
    except BaseException:
        for endpoint in created:
            try:
                endpoint.close()
            except OSError:
                pass
        raise


class SourceStartupMarkerError(RuntimeError):
    """Failure evidence from the source-aware startup multiplexer."""
    def __init__(self, message, startup_bytes, *, eof=False, timed_out=False,
            actor_exit=None, cause=None, overflow=False, diagnostic_tail=b''):
        super().__init__(message)
        self.startup_bytes = bytes(startup_bytes)
        self.eof = eof
        self.timed_out = timed_out
        self.actor_exit = actor_exit
        self.cause = cause
        self.overflow = overflow
        self.diagnostic_tail = bytes(diagnostic_tail[-SOURCE_STARTUP_TAIL_MAX:])


class _InitialOwnerAuthView(NamedTuple):
    owner_pidfd: int
    owner_pid: int
    owner_tid: int
    owner_role: int
    owner_start: int
    owner_slot_device: int
    owner_slot_inode: int
    owner_cookie: int


class _FirstCandidateWorkerGrant(NamedTuple):
    """Controller-minted one-shot authority for only source key (1, 1)."""
    token: object
    controller: object
    context: object
    provider: object
    initial_transport: object
    channel: object
    channel_identity: tuple
    channel_cookie: int
    packet: bytes
    credentials: tuple
    relay: object
    relay_identity: tuple
    relay_cookie: int
    grant_deadline_ns: int
    worker_key: tuple
    cycle_proof: object
    master_identity: tuple
    initial_cycle_proof: object
    accepted_request: object = None


def _source_bootstrap_channel_identity(channel):
    """Pin the retained accepted C31 bootstrap socket, independently of READY cookies."""
    if type(channel) is not socket.socket or channel.fileno() < 0:
        raise OSError(errno.EBADF, 'retained initial bootstrap channel is closed')
    fd = channel.fileno()
    info = os.fstat(fd)
    status_flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    descriptor_flags = fcntl.fcntl(fd, fcntl.F_GETFD)
    cookie = struct.unpack('=Q', channel.getsockopt(socket.SOL_SOCKET,
        getattr(socket, 'SO_COOKIE', 57), 8))[0]
    sock_type = channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
    passcred = channel.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED)
    if (not stat.S_ISSOCK(info.st_mode) or channel.family != socket.AF_UNIX or
            sock_type != socket.SOCK_SEQPACKET or passcred != 1 or not cookie or
            not status_flags & os.O_NONBLOCK or
            not descriptor_flags & fcntl.FD_CLOEXEC):
        raise PermissionError('retained initial bootstrap channel lost its required socket flags')
    return (fd, info.st_dev, info.st_ino, info.st_mode, info.st_rdev,
        channel.family, sock_type, cookie, passcred, status_flags, descriptor_flags)


class _PrivateInitialWorkerExitObservation:
    """Controller-minted pending death observation; it proves no retirement."""
    __slots__ = ('token', 'controller', 'context', 'transport', 'provider',
        'pidfd', 'record', 'channel', 'channel_identity', 'cycle_proof', 'ready_identity', 'watch',
        'observed_ns')

    def __init__(self, token, controller, context, transport, provider,
            pidfd, record, channel, channel_identity, cycle_proof, ready_identity, watch, observed_ns):
        if token is not _PRIVATE_INITIAL_EXIT_TOKEN:
            raise TypeError('initial-worker exit observations are controller-owned')
        values = (token, controller, context, transport, provider, pidfd,
            tuple(record), channel, tuple(channel_identity), cycle_proof, tuple(ready_identity),
            MappingProxyType(dict(watch)), observed_ns)
        for name, value in zip(self.__slots__, values):
            object.__setattr__(self, name, value)

    def __setattr__(self, _name, _value):
        raise AttributeError('initial-worker exit observation is immutable')


class _AcceptedCandidateWorkerRequest(NamedTuple):
    """Private receipt for one packet actually received on the owned listener."""
    token: object
    controller: object
    listener: object
    listener_identity: tuple
    listener_cookie: int
    channel: object
    channel_identity: tuple
    channel_cookie: int
    packet: bytes
    credentials: tuple
    deadline_ns: int
    worker_key: tuple


_ACCEPTED_CANDIDATE_REQUEST_TOKEN = object()


def _scope_module():
    cached = sys.modules.get(_SCOPE_NAME)
    if cached is not None:
        if Path(cached.__file__).resolve(strict=True) != _SCOPE_PATH:
            raise ImportError('cached source scope adapter belongs to another path')
        return cached
    spec = importlib.util.spec_from_file_location(_SCOPE_NAME, _SCOPE_PATH)
    if spec is None or spec.loader is None:
        raise ImportError('cannot load the sealed source scope adapter')
    module = importlib.util.module_from_spec(spec)
    sys.modules[_SCOPE_NAME] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        if sys.modules.get(_SCOPE_NAME) is module:
            del sys.modules[_SCOPE_NAME]
        raise
    return module


def _c22_provider_module():
    cached = sys.modules.get(_C22_NAME)
    if cached is not None:
        if Path(cached.__file__).resolve(strict=True) != _C22_PATH:
            raise ImportError('cached C22 provider adapter belongs to another path')
        return cached
    spec = importlib.util.spec_from_file_location(_C22_NAME, _C22_PATH)
    if spec is None or spec.loader is None:
        raise ImportError('cannot load the pinned C22 provider adapter')
    module = importlib.util.module_from_spec(spec)
    sys.modules[_C22_NAME] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        if sys.modules.get(_C22_NAME) is module:
            del sys.modules[_C22_NAME]
        raise
    return module


def _c34_profile_module():
    cached = sys.modules.get(_C34_PROFILE_NAME)
    if cached is not None:
        if Path(cached.__file__).resolve(strict=True) != _C34_PROFILE_PATH:
            raise ImportError('cached private C34 profile belongs to another path')
        return cached
    spec = importlib.util.spec_from_file_location(_C34_PROFILE_NAME, _C34_PROFILE_PATH)
    if spec is None or spec.loader is None:
        raise ImportError('cannot load the fixed private C34 profile')
    module = importlib.util.module_from_spec(spec)
    sys.modules[_C34_PROFILE_NAME] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        if sys.modules.get(_C34_PROFILE_NAME) is module:
            del sys.modules[_C34_PROFILE_NAME]
        raise
    return module


def _attach_module():
    cached = sys.modules.get(_ATTACH_NAME)
    if cached is not None:
        if Path(cached.__file__).resolve(strict=True) != _ATTACH_PATH:
            raise ImportError('cached source attach adapter belongs to another path')
        return cached
    spec = importlib.util.spec_from_file_location(_ATTACH_NAME, _ATTACH_PATH)
    if spec is None or spec.loader is None:
        raise ImportError('cannot load the canonical source attachment adapter')
    module = importlib.util.module_from_spec(spec)
    sys.modules[_ATTACH_NAME] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        if sys.modules.get(_ATTACH_NAME) is module:
            del sys.modules[_ATTACH_NAME]
        raise
    return module


class _SourceInitialWorkerTransport:
    __slots__ = ('context', 'broker', 'relay', 'relay_auth', 'auth', 'app', 'app_pidfd',
        'supervisor_pidfd', 'nonce', 'epoch', 'authenticate', 'revoke',
        'attachment', 'watch', 'receiver', 'worker_pidfd', 'worker_view',
        'ready_identity', 'initial_bootstrap_channel_identity',
        'grant_attempted', 'auth_started', 'authenticated', 'settled',
        'cleanup_error', '_endpoint_cookies')

    def __init__(self, token, context, broker, relay, relay_auth, auth, app, app_pidfd,
            supervisor_pidfd, nonce, epoch, authenticate, revoke):
        if token is not _INITIAL_TRANSPORT_TOKEN:
            raise TypeError('source initial worker transport is controller-owned')
        self.context, self.broker = context, broker
        self.relay, self.relay_auth, self.auth = relay, relay_auth, auth
        cookie_option = getattr(socket, 'SO_COOKIE', 57)
        self._endpoint_cookies = tuple(struct.unpack('=Q', endpoint.getsockopt(
            socket.SOL_SOCKET, cookie_option, 8))[0]
            for endpoint in (relay, relay_auth, auth))
        self.app, self.app_pidfd = app, app_pidfd
        self.supervisor_pidfd = supervisor_pidfd
        self.nonce, self.epoch = bytes(nonce), epoch
        self.authenticate, self.revoke = authenticate, revoke
        self.attachment = self.watch = self.receiver = self.worker_view = None
        self.ready_identity = None
        self.initial_bootstrap_channel_identity = None
        self.worker_pidfd = -1
        self.grant_attempted = self.auth_started = self.authenticated = self.settled = False
        self.cleanup_error = None

    def request_revoke(self):
        if self.settled or not self.auth_started:
            return
        self.revoke()

    def close_relay_auth_after_send(self):
        endpoint = self.relay_auth
        if endpoint is not None:
            endpoint.close()
            self.relay_auth = None


class SourceShellProfile:
    """Captured exact precheck/rt01 launch parameters; no arbitrary profile dict."""
    __slots__ = ('origin_module', 'source_root', 'arguments', 'environment',
        'nginx', 'nginx_hash', 'network_expectation', 'scope_directory',
        'stdout', 'stderr', 'cwd', 'nonce', 'epoch', 'deadline_ns', 'output',
        'port_name', 'c22_build_capture')

    def __init__(self, token, origin_module, source_root, arguments, environment,
            nginx, nginx_hash, network_expectation, scope_directory, stdout,
            stderr, cwd, port_name, c22_build_capture):
        if token is not _PROFILE_TOKEN:
            raise TypeError('source-shell profiles are created only by capture()')
        self.origin_module = origin_module
        self.source_root = Path(source_root)
        self.arguments = tuple(arguments)
        self.environment = MappingProxyType(dict(environment))
        self.nginx = Path(nginx)
        self.nginx_hash = bytes(nginx_hash)
        self.network_expectation = network_expectation
        self.scope_directory = Path(scope_directory)
        self.stdout, self.stderr, self.cwd = stdout, stderr, cwd
        self.nonce = bytes.fromhex(environment['KER_NGINX_SOURCE_BOOTSTRAP_NONCE'])
        self.epoch = int(environment['KER_NGINX_SOURCE_BOOTSTRAP_EPOCH'])
        self.deadline_ns = int(environment['KER_NGINX_SOURCE_BOOTSTRAP_DEADLINE_NS'])
        self.output = self.arguments[self.arguments.index('--out') + 1]
        self.port_name = port_name
        if type(c22_build_capture) is not _c22_provider_module().C22HelperBuildCapture:
            raise TypeError('source profile requires the typed fixed-receipt C22 capture')
        self.c22_build_capture = c22_build_capture

    @classmethod
    def capture(cls, origin_module, startup_module, *, source_root, arguments,
            environment, nginx, nginx_hash, network_expectation, scope_directory,
            stdout, stderr, port_name, cwd=None):
        require = origin_module.require
        require(type(arguments) in (tuple, list) and all(type(arg) is str for arg in arguments),
            'source-shell arguments must be a captured string sequence')
        require(type(environment) is dict and all(type(key) is str and type(value) is str
            for key, value in environment.items()),
            'source-shell environment must be captured as exact strings')
        require(type(network_expectation) is startup_module.SourceNetworkExpectation and
            type(nginx_hash) is bytes and len(nginx_hash) == 32,
            'source-shell profile requires the exact network expectation and Nginx pin')
        require(Path(getattr(origin_module, '__file__', '')).resolve(strict=True) ==
            Path(__file__).with_name('nginx_source_origin.py').resolve(strict=True),
            'source-shell profile requires the canonical Origin module')
        require(environment.get('KER_NGINX_SOURCE_SHELL_ENABLE') == '1' and
            environment.get('KER_NGINX_SOURCE_FIRST_HUP_ENABLE') == '1',
            'source-shell profile flags are incomplete')
        nonce = environment.get('KER_NGINX_SOURCE_BOOTSTRAP_NONCE', '')
        require(re.fullmatch(r'[0-9a-f]{32}', nonce) is not None and nonce != '0' * 32,
            'source-shell nonce is not canonical')
        epoch_text = environment.get('KER_NGINX_SOURCE_BOOTSTRAP_EPOCH', '')
        deadline_text = environment.get(startup_module.BOOTSTRAP_DEADLINE_ENV, '')
        require(epoch_text.isascii() and epoch_text.isdecimal() and epoch_text[0] != '0' and
            deadline_text.isascii() and deadline_text.isdecimal() and deadline_text[0] != '0',
            'source-shell session/deadline is not canonical decimal')
        epoch, deadline = int(epoch_text), int(deadline_text)
        now = time.monotonic_ns()
        require(0 < epoch < 1 << 64 and now < deadline <= now + 300_000_000_000 and
            deadline == network_expectation.deadline_ns,
            'source-shell session or immutable deadline is outside its bound')
        require(environment.get('KER_NGINX_SOURCE_BOOTSTRAP_SUPERVISOR_PID') == str(os.getpid()) and
            environment.get('KER_NGINX_SOURCE_BOOTSTRAP_SUPERVISOR_START') ==
                str(origin_module.identity._start_ticks(os.getpid())),
            'source-shell supervisor identity differs from this SDK process')
        require(environment.get(startup_module.READBACK_ENV) in
            (None, network_expectation.readback_setting()),
            'source-shell readback differs from the pinned network template')
        require(isinstance(port_name, str) and 1 <= len(port_name) <= 63 and
            port_name.isascii() and all(ch.isalnum() or ch in '_.-' for ch in port_name),
            'source-shell requires one canonical native port name')
        args = list(arguments)

        def option(names):
            matches = []
            index = 0
            while index < len(args):
                if args[index] in names:
                    require(index + 1 < len(args), 'source-shell option lacks a value')
                    matches.append(args[index + 1]); index += 2
                else:
                    index += 1
            require(len(matches) == 1, 'source-shell option is missing or duplicated')
            return matches[0]

        require('--baseline' not in args and '--fault' not in args and
            option(('--cases', '-c')) == 'precheck,rt01' and
            option(('--workers',)) == '1' and option(('--graceful',)) == '1' and
            option(('--target-ip', '-t')) == network_expectation.address,
            'source-shell supports only the exact precheck,rt01 workers=1 graceful=1 profile')
        output = option(('--out', '-o'))
        template = option(('--fstack-conf',))
        require(Path(output).is_absolute() and str(Path(output).resolve(strict=False)) == output and
            not Path(output).exists() and template == network_expectation.template_path and
            args.count('--out') == 1 and args.count('--fstack-conf') == 1,
            'source-shell output must be fresh and template must be the captured file')
        scope = Path(scope_directory).resolve(strict=True)
        scope_info = os.stat(scope, follow_symlinks=False)
        require(scope.is_dir() and scope_info.st_uid == os.geteuid() and
            stat.S_IMODE(scope_info.st_mode) == 0o700,
            'source capsule directory must be an owned private directory')
        require(len(os.fsencode(scope / 'origin.sock')) < 108 and
            not (scope / 'origin.sock').exists() and not (scope / 'bootstrap.json').exists(),
            'source listener/capsule paths must be fresh and fit AF_UNIX')
        require(Path(source_root).is_dir() and Path(nginx).is_file(),
            'source root or pinned Nginx path is unavailable')
        copied_env = dict(environment)
        copied_env[startup_module.READBACK_ENV] = network_expectation.readback_setting()
        try:
            c22_capture = _c22_provider_module().C22HelperBuildCapture.capture(deadline)
        except FileNotFoundError as error:
            raise OSError(errno.ENOTSUP,
                'trusted fixed-receipt C22 helper build capture is unavailable') from error
        try:
            return cls(_PROFILE_TOKEN, origin_module, source_root, args, copied_env,
                nginx, nginx_hash, network_expectation, scope, stdout, stderr, cwd,
                port_name, c22_capture)
        except BaseException:
            c22_capture.close()
            raise

    def close(self):
        self.c22_build_capture.close()

    def __del__(self):
        try:
            self.close()
        except BaseException:
            pass


class SourceShellController:
    """Same-process owner of FD 200/201 and the exact original launch."""
    def __init__(self, profile):
        if type(profile) is not SourceShellProfile:
            private_type = _c34_profile_module().PrivateNewC34InteropProfile
            if type(profile) is not private_type:
                raise TypeError('source controller requires a captured source or private C34 profile')
        if threading.current_thread() is not threading.main_thread():
            raise PermissionError('source controller must be captured on the SDK main thread')
        self.profile = profile
        self.scope_api = _scope_module()
        self.capsules = None
        self.launch = None
        self.listener = None
        self.socket_path = None
        self.socket_identity = None
        self.io_actor = None
        self.io_record = None
        # Retain the exact Origin-created context.  This is the sole owner of
        # worker bootstrap endpoints and their PREEXIT receive side.
        self.bootstrap_context = None
        self.control_slim_channel = None
        # This stays empty until a typed, trusted C22 helper-build receipt and
        # the same-context initial-slot/relay/READY join are connected.
        self.initial_worker_binding = None
        self._first_candidate_worker_grant = None
        self._accepted_candidate_worker_request = None
        self._first_candidate_worker_grant_consumed = False
        self._first_candidate_worker_pending = False
        self._first_candidate_pending_watch = None
        self._first_candidate_pending_ready = None
        self._first_candidate_pending_error = None
        self._first_candidate_relay_anchor = None
        self._first_candidate_observed_pidfd = -1
        self._first_candidate_observed_ready = None
        self._first_candidate_source_prepared = None
        self._first_candidate_prepare_attempted = False
        self._first_candidate_activation_delivered = False
        self._first_candidate_revoke_attempted = False
        self._private_initial_exit_observation = None
        self._private_initial_exit_eof_hint_ns = None
        self._private_initial_retirement_proof = None
        self._private_initial_verify_started = False
        self._private_candidate_preexit_pending = None
        self._private_candidate_preexit_evidence = None
        self._private_stop_ack_receipt = None
        self._private_source_settlement_attempted = False
        self._private_source_settlement = None
        self.c22_provider = None
        self.broker_readiness = None
        self.started = False
        self.unresolved = False
        self.shutdown_requested = False
        self.stop_target_validated = False

    @property
    def nonce(self):
        return self.profile.nonce

    @property
    def epoch(self):
        return self.profile.epoch

    @property
    def deadline_ns(self):
        return self.profile.deadline_ns

    def validate_main(self, expected, control_nginx, args):
        network = self.profile.network_expectation
        address = getattr(args, 'address', None)
        gateway = getattr(args, 'gateway', None)
        startup = self.profile.origin_module._SOURCE_NETWORK_STARTUP
        private_type = _c34_profile_module().PrivateNewC34InteropProfile
        private_control_ok = False
        private_control_checks = ()
        if type(self.profile) is private_type:
            capture = self.profile.artifact_capture
            provider = _c34_profile_module()._provider()
            expected_preload = ':'.join(str(capture.artifact(name).path)
                for name in ('runtime', 'preload', 'shim'))
            env = control_nginx[3] if type(control_nginx) is tuple and len(control_nginx) == 8 else None
            binary, config, prefix = control_nginx[:3] if env is not None else (None, None, None)
            args_config = getattr(args, 'control_nginx_config', None)
            args_prefix = getattr(args, 'control_nginx_prefix', None)
            private_control_checks = (
                type(capture) is provider.PrivateC34ArtifactCapture,
                type(control_nginx) is tuple and len(control_nginx) == 8,
                type(env) is dict,
                control_nginx[0] == self.profile.nginx if type(control_nginx) is tuple and len(control_nginx) == 8 else False,
                isinstance(config, Path) and isinstance(prefix, Path),
                isinstance(args_config, Path) and isinstance(args_prefix, Path),
                config == args_config.resolve(strict=True) if isinstance(args_config, Path) else False,
                prefix == args_prefix.resolve(strict=True) if isinstance(args_prefix, Path) else False,
                config.is_file() if isinstance(config, Path) else False,
                prefix.is_dir() if isinstance(prefix, Path) else False,
                control_nginx[4:] == (True, True, True, True) if type(control_nginx) is tuple and len(control_nginx) == 8 else False,
                getattr(args, 'control_nginx_owner_module', None) is None,
                env.get('LD_PRELOAD') == expected_preload if type(env) is dict else False,
                env.get('KER_SOCKET_BROKER_PATH') == self.profile.environment.get('KER_SOCKET_BROKER_PATH') if type(env) is dict else False,
                env.get('KER_FSTACK_NGINX_INI') == self.profile.environment.get('KER_FSTACK_NGINX_INI') if type(env) is dict else False,
                set(env) <= {'LD_PRELOAD', 'KER_SOCKET_BROKER_PATH',
                    'KER_FSTACK_NGINX_INI', 'KER_FSTACK_RUNTIME_TRACE'} if type(env) is dict else False)
            private_control_ok = all(private_control_checks)
        if (type(expected) is not dict or
                startup._captured_expectation_key(network) != startup._expected_key(expected) or
                threading.current_thread() is not threading.main_thread() or
                (control_nginx is not None and not private_control_ok) or self.started or
                type(args.port) is not str or args.port != self.profile.port_name or
                args.queues != 1 or args.rx_lcores != '1' or not args.rx_decision or
                not args.runtime_service or not args.broker_readiness or
                address is None or str(address.ip) != network.address or
                str(address.network.netmask) != network.netmask or
                gateway is None or str(gateway) != network.gateway or
                bool(args.vlans or args.vlan_gateways or args.vlan_gateways6 or
                    args.interfaces or args.bonds or args.vdevs or
                    args.address6 is not None or args.gateway6 is not None or
                    args.vip_addresses or args.vip_addresses6 or
                    args.promiscuous is not None or args.all_multicast or
                    args.exception_iface is not None or args.sysctls or
                    args.tcp_ecn is not None) or
                expected['deadline_ns'] != self.deadline_ns):
            raise PermissionError(errno.ENOTSUP,
                'source controller does not match the closed source-shell runtime profile')
    def start(self):
        if self.started or threading.current_thread() is not threading.main_thread():
            raise RuntimeError('source controller start is one-shot on the SDK main thread')
        profile = self.profile
        private_type = _c34_profile_module().PrivateNewC34InteropProfile
        if type(profile) is not SourceShellProfile and type(profile) is not private_type:
            raise TypeError('source controller start requires an exact captured profile type')
        self.capsules = self.scope_api.SourceScopeCapsules(profile.origin_module)
        try:
            self.capsules.publish_bootstrap(profile.scope_directory / 'bootstrap.json')
            endpoint = profile.scope_directory / 'origin.sock'
            self.socket_path = endpoint
            channel = socket.socket(socket.AF_UNIX,
                socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
            self.listener = channel
            channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            self._listener_cookie = self._first_candidate_socket_cookie(channel)
            channel.bind(str(endpoint))
            info = os.stat(endpoint, follow_symlinks=False)
            self.socket_identity = (info.st_dev, info.st_ino)
            os.chmod(endpoint, 0o600, follow_symlinks=False)
            channel.listen(8)
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid():
                raise PermissionError('source origin endpoint is not an owned socket')
            environment = dict(profile.environment)
            environment['KER_NGINX_SOURCE_BOOTSTRAP_PATH'] = str(endpoint)
            if type(profile) is private_type:
                profile.artifact_capture.verify(profile.deadline_ns)
                self.launch = profile.origin_module.PrivateC34OriginalShellLaunch(
                    profile.source_root, list(profile.arguments), environment,
                    profile.nginx, profile.nginx_hash,
                    network_expectation=profile.network_expectation,
                    stdout=profile.stdout, stderr=profile.stderr, cwd=profile.cwd,
                    artifact_capture=profile.artifact_capture)
            elif type(profile) is SourceShellProfile:
                self.launch = profile.origin_module.OriginalShellLaunch(
                    profile.source_root, list(profile.arguments), environment,
                    profile.nginx, profile.nginx_hash,
                    network_expectation=profile.network_expectation,
                    stdout=profile.stdout, stderr=profile.stderr, cwd=profile.cwd)
            else:
                raise TypeError('source controller launch requires an exact captured profile type')
            self.launch.live_supervisor(self.deadline_ns)
            self.started = True
            return self.launch
        except BaseException as error:
            if (self.launch is None and
                    isinstance(error, getattr(profile.origin_module,
                        'OriginalLaunchUnsettled', ()))):
                self.launch = error.launch
            # Once Popen exists, retain every actor and capsule proof for the
            # caller's settlement path; never turn an uncertain launch into
            # a successful controller result.
            if self.launch is not None and self.launch.process is not None:
                self.unresolved = True
                raise
            self._close_unstarted()
            raise

    def observe_native_io_ready(self, process, pidfd, executable_hash):
        if not self.started or self.launch is None or self.io_actor is not None:
            raise RuntimeError('source I/O READY observation is not available or was already used')
        start_ticks = self.profile.origin_module.identity._start_ticks(process.pid)
        actor = SimpleNamespace(pid=process.pid, pidfd=pidfd, start_ticks=start_ticks,
            executable_hash=bytes(executable_hash))
        record = self.launch.observe_native_io_ready(process, actor,
            expected_port_name=self.profile.port_name)
        run_id = self.launch.run_id
        roots = []
        try:
            for path in ('/tmp', '/var/run/dpdk'):
                roots.append(self.scope_api.CapturedScopeRoot.capture(path, run_id))
            self.capsules.publish_run(self.launch, tuple(roots))
        except BaseException:
            for root in roots:
                try:
                    root.close()
                except OSError:
                    pass
            raise
        self.io_actor = actor
        self.io_record = record
        return record

    def _close_unstarted(self):
        if self.listener is not None:
            self.listener.close()
            self.listener = None
            if self.socket_path is not None and self.socket_identity is not None:
                try:
                    info = os.stat(self.socket_path, follow_symlinks=False)
                    if (info.st_dev, info.st_ino) == self.socket_identity:
                        os.unlink(self.socket_path)
                except FileNotFoundError:
                    pass
        if self.capsules is not None:
            self.capsules.close()
            self.capsules = None
        close_profile = getattr(self.profile, 'close', None)
        if callable(close_profile):
            close_profile()

    def accept_origin(self, runtime_actor):
        if (not self.started or self.launch is None or self.io_actor is None or
                self.listener is None):
            raise RuntimeError('source origin requires the retained original/I/O actors')
        receipt = self.launch.backend_handoff.take(self.deadline_ns)
        self.launch.attach_retained_backend_receipt(receipt)
        self.launch.backend_runtime_actor = runtime_actor
        remaining_ns = min(self.deadline_ns - time.monotonic_ns(), 5_000_000_000)
        if remaining_ns <= 0:
            raise TimeoutError('source origin observation deadline expired')
        self.listener.settimeout(remaining_ns / 1_000_000_000)
        try:
            channel, _ = self.listener.accept()
        finally:
            # The SDK main-loop selector needs a nonblocking listener.
            self.listener.setblocking(False)
        if channel.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) != 1:
            channel.close()
            raise PermissionError('accepted origin socket lost credential collection')
        try:
            context = self.launch.accept_origin(channel, runtime_actor, self.io_actor)
            bootstrap = self.profile.origin_module.bootstrap
            if type(context) is not bootstrap.SourceBootstrapSupervisor:
                raise TypeError('Origin returned a noncanonical source bootstrap context')
            if self.bootstrap_context is not None or self.launch.context is not context:
                raise RuntimeError('Origin context ownership is duplicated or changed')
            self.bootstrap_context = context
            return context
        except BaseException:
            channel.close()
            raise

    def start_c22_provider(self, broker_readiness):
        """Transfer this profile's exact held build capture to its one C22 provider.

        This starts the external helper only when the caller has already received
        the accepted Origin context and live C34 readiness object. It does not
        enable source worker grants or change the context's control-only phase.
        """
        if threading.current_thread() is not threading.main_thread():
            raise PermissionError('C22 provider must start on the SDK main thread')
        context = self.bootstrap_context
        private_type = _c34_profile_module().PrivateNewC34InteropProfile
        if (type(self.profile) is private_type or context is None or self.launch is None or
                self.launch.context is not context or
                getattr(context, 'control_only', False) is not True or self.c22_provider is not None):
            raise PermissionError(errno.ENOTSUP,
                'C22 provider requires one accepted control-only source context')
        provider_module = _c22_provider_module()
        capture = self.profile.c22_build_capture
        if type(capture) is not provider_module.C22HelperBuildCapture:
            raise TypeError('source profile C22 build capture changed type')
        try:
            provider = provider_module.SourceShellC22Provider(
                context, broker_readiness, capture)
        except provider_module.C22ProviderCleanupPending as pending:
            # Construction may fail after launch while the helper remains
            # unsettled. Retain its sockets, pidfd, and executable FD before
            # propagating the primary failure to the caller.
            self.c22_provider = pending.provider
            self.unresolved = True
            raise
        self.c22_provider = provider
        return provider

    def start_c34_interop_provider(self, broker_readiness):
        """Launch the fixed ABI1 helper only for the private NEWC34_INTEROP profile."""
        if threading.current_thread() is not threading.main_thread():
            raise PermissionError('private C34 provider must start on the SDK main thread')
        private_type = _c34_profile_module().PrivateNewC34InteropProfile
        context = self.bootstrap_context
        if (type(self.profile) is not private_type or context is None or
                type(self.launch) is not getattr(self.profile.origin_module, 'PrivateC34OriginalShellLaunch', None) or
                self.launch.context is not context or
                self.launch.c34_artifact_capture is not self.profile.artifact_capture or
                self.profile.helper_capture is not self.profile.artifact_capture.helper_capture or
                getattr(context, 'control_only', False) is not True or self.c22_provider is not None):
            raise PermissionError(errno.ENOTSUP,
                'private C34 provider requires one accepted control-only interop context')
        provider_module = _c22_provider_module()
        capture = self.profile.helper_capture
        provider_type = provider_module.SourceShellC34InteropProvider
        try:
            provider = provider_type(context, broker_readiness, capture)
        except provider_module.C22ProviderCleanupPending as pending:
            self.c22_provider = pending.provider
            self.unresolved = True
            raise
        self.c22_provider = provider
        return provider

    def bind_initial_worker_transport(self, broker_readiness, relay_endpoint,
            relay_auth_endpoint, auth_endpoint, app, app_pidfd, supervisor_pidfd, nonce, epoch,
            authenticate, revoke):
        """Retain the exact SDK C31 endpoints for one initial owner binding."""
        context = self.bootstrap_context
        if (threading.current_thread() is not threading.main_thread() or
                context is None or self.launch is None or self.launch.context is not context or
                getattr(context, 'control_only', False) is not True or
                getattr(self, '_initial_transport', None) is not None or
                type(getattr(broker_readiness, 'parent', None)) is not socket.socket or
                not callable(getattr(broker_readiness, 'poll_ready', None)) or
                type(app_pidfd) is not int or app_pidfd < 0 or
                type(supervisor_pidfd) is not int or supervisor_pidfd < 0 or
                type(nonce) is not bytes or nonce != self.nonce or
                type(epoch) is not int or epoch != self.epoch or
                not callable(authenticate) or not callable(revoke)):
            raise PermissionError(errno.ENOTSUP,
                'initial worker transport is not bound to the accepted source runtime')
        runtime = getattr(self.launch, 'backend_runtime_actor', None)
        identity = self.profile.origin_module.identity
        if (runtime is None or runtime.pid != app.pid or runtime.pidfd != app_pidfd or
                identity._pidfd_pid(app_pidfd) != app.pid or
                not identity.process_alive(app_pidfd) or
                identity._pidfd_pid(supervisor_pidfd) != os.getpid() or
                not identity.process_alive(supervisor_pidfd)):
            raise ProcessLookupError('initial worker C31 actor pidfds are stale')
        endpoints = (relay_endpoint, relay_auth_endpoint, auth_endpoint)
        cookies = set()
        for endpoint in endpoints:
            if (type(endpoint) is not socket.socket or
                    endpoint.family != socket.AF_UNIX or
                    endpoint.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_SEQPACKET or
                    endpoint.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) != 1 or
                    struct.unpack('=3i', endpoint.getsockopt(socket.SOL_SOCKET,
                        socket.SO_PEERCRED, 12)) != (os.getpid(), os.getuid(), os.getgid())):
                raise PermissionError('initial worker C31 endpoint is not creator-owned credentialed seqpacket')
            cookie = struct.unpack('=Q', endpoint.getsockopt(socket.SOL_SOCKET,
                getattr(socket, 'SO_COOKIE', 57), 8))[0]
            if not cookie or cookie in cookies:
                raise PermissionError('initial worker C31 endpoint cookies are not distinct')
            cookies.add(cookie)
        self.broker_readiness = broker_readiness
        self._initial_transport = _SourceInitialWorkerTransport(
            _INITIAL_TRANSPORT_TOKEN, context, broker_readiness,
            relay_endpoint, relay_auth_endpoint, auth_endpoint, app, app_pidfd, supervisor_pidfd,
            nonce, epoch, authenticate, revoke)
        self.initial_worker_binding = self._initial_transport
        return self._initial_transport

    def _initial_worker_ready_and_auth(self, transport, provider, watch, receiver):
        context = self.bootstrap_context
        if (type(transport) is not _SourceInitialWorkerTransport or
                transport is not getattr(self, '_initial_transport', None) or
                transport.context is not context or transport.broker is not self.broker_readiness or
                provider is not self.c22_provider or provider.context is not context or
                not transport.broker.ready or transport.broker.stopped or
                transport.grant_attempted or transport.settled):
            raise PermissionError('initial worker capability changed before owner READY')
        transport.grant_attempted = True
        transport.auth_started = True
        transport.watch = dict(watch)
        transport.receiver = receiver
        try:
            attach_module = _attach_module()
            attachment = attach_module.SourceAttachment(self.launch,
                revoke_native_auth=transport.request_revoke)
            transport.attachment = attachment
            attachment.attach(min(5.0,
                max(0.001, (self.deadline_ns - time.monotonic_ns()) / 1_000_000_000)))
            ready_identity, borrowed_pidfd = attachment.receive_owner_ready(
                watch, receiver,
                min(15.0, max(0.001,
                    (self.deadline_ns - time.monotonic_ns()) / 1_000_000_000)))
            record = context.workers.get((0, 0))
            proof = context.worker_proofs.get((0, 0))
            if (record is None or proof != context.initial_cycle_proof or
                    ready_identity[0] != watch['pid'] or ready_identity[4] != watch['tid'] or
                    ready_identity[6] != watch['start'] or ready_identity[7] != watch['slot_device'] or
                    ready_identity[8] != watch['slot_inode'] or ready_identity[9] != watch['cookie'] or
                    record[1][5] != ready_identity[0] or record[1][6] != ready_identity[4] or
                    record[1][11] != ready_identity[6] or
                    tuple(record[1][24:28]) != (ready_identity[7], ready_identity[8],
                        struct.unpack('=Q', transport.relay.getsockopt(socket.SOL_SOCKET,
                            getattr(socket, 'SO_COOKIE', 57), 8))[0], ready_identity[9]) or
                    (ready_identity[7], ready_identity[8]) != provider.slot_identities[0] or
                    time.monotonic_ns() >= self.deadline_ns):
                raise PermissionError('credentialed initial worker READY differs from grant/cycle/slot proof')
            worker_pidfd = os.dup(borrowed_pidfd)
            try:
                identity_module = self.profile.origin_module.identity
                if (identity_module._pidfd_pid(worker_pidfd) != ready_identity[0] or
                        not identity_module.process_alive(worker_pidfd) or
                        identity_module._start_ticks(ready_identity[0]) != ready_identity[6]):
                    raise ProcessLookupError('duplicated initial worker READY pidfd is stale')
            except BaseException:
                os.close(worker_pidfd)
                raise
            transport.worker_pidfd = worker_pidfd
            transport.ready_identity = tuple(ready_identity)
            retained_channel = context.worker_channels.get((0, 0))
            transport.initial_bootstrap_channel_identity = \
                _source_bootstrap_channel_identity(retained_channel)
            transport.worker_view = _InitialOwnerAuthView(worker_pidfd,
                ready_identity[0], ready_identity[4], ready_identity[3],
                ready_identity[6], ready_identity[7], ready_identity[8],
                ready_identity[9])
            transport.authenticate(transport.worker_view, self.deadline_ns)
            transport.authenticated = True
            transport.close_relay_auth_after_send()
            return transport.worker_view
        except BaseException as primary_error:
            self.unresolved = True
            attach_module = sys.modules.get(_ATTACH_NAME)
            if (attach_module is not None and
                    isinstance(primary_error, getattr(attach_module,
                        'AttachObserverUnsettled', ()))):
                transport.attachment = primary_error.attachment
            try:
                transport.request_revoke()
            except BaseException as revoke_error:
                transport.cleanup_error = revoke_error
            raise

    def source_worker_channels(self):
        """Return retained worker endpoints owned by the exact Origin context."""
        context = self.bootstrap_context
        if context is None:
            return ()
        if (type(context) is not self.profile.origin_module.bootstrap.SourceBootstrapSupervisor or
                getattr(self.launch, 'context', None) is not context):
            raise RuntimeError('source bootstrap context ownership changed')
        return tuple(context.worker_channels.values())

    @staticmethod
    def _peek_source_worker_channel(channel):
        try:
            packet, ancillary, flags, _ = channel.recvmsg(1, 0,
                getattr(socket, 'MSG_PEEK', 0) | getattr(socket, 'MSG_DONTWAIT', 0))
        except BlockingIOError:
            return 'empty', b''
        if ancillary or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
            return 'invalid', bytes(packet)
        return ('eof' if not packet else 'payload'), bytes(packet)

    def poll_source_preexit(self):
        """Pump one PREEXIT on the SDK main thread; never create another reader."""
        context = self.bootstrap_context
        if context is None:
            return None
        if (type(context) is not self.profile.origin_module.bootstrap.SourceBootstrapSupervisor or
                getattr(self.launch, 'context', None) is not context):
            raise RuntimeError('source bootstrap context ownership changed')
        if getattr(context, 'control_only', False):
            transport = getattr(self, '_initial_transport', None)
            if not context.workers and not context.worker_channels:
                if (getattr(context, '_activated_workers', set()) or
                        getattr(context, '_completed_master_barriers', set()) or
                        getattr(context, '_source_shell_committed_plans', {})):
                    raise PermissionError('control-only source context unexpectedly contains master authority')
                return None
            if (getattr(self, '_first_candidate_worker_pending', False) or
                    getattr(self, '_first_candidate_observed_ready', None) is not None):
                self._check_first_candidate_phase(transport)
                if (type(self.profile) is _c34_profile_module().PrivateNewC34InteropProfile and
                        type(getattr(self, 'c22_provider', None)) is
                            _c22_provider_module().SourceShellC34InteropProvider and
                        getattr(context, '_completed_master_barriers', set()) == {(1, 5), (1, 6)} and
                        (1, 1) in getattr(context, '_source_shell_committed_plans', {})):
                    self._advance_private_initial_listener_retirement(transport)
                initial_channel = context.worker_channels[(0, 0)]
                candidate_channel = context.worker_channels[(1, 1)]
                pending_exit = self._valid_private_initial_exit_observation(
                    transport, context)
                initial_readable = bool(select.select([initial_channel], [], [], 0)[0])
                if initial_readable:
                    state, packet = self._peek_source_worker_channel(initial_channel)
                    if state == 'payload' or state == 'invalid':
                        self.unresolved = True
                        self._revoke_first_candidate_once(transport)
                        raise OSError(errno.ENOTSUP,
                            'initial worker channel contains an unexpected PREEXIT/control record')
                    if state == 'eof' and not pending_exit:
                        private_committed = (
                            type(self.profile) is _c34_profile_module().PrivateNewC34InteropProfile and
                            getattr(context, '_completed_master_barriers', set()) == {(1, 5), (1, 6)} and
                            (1, 1) in getattr(context, '_source_shell_committed_plans', {}))
                        old_fd = context.workers[(0, 0)][0]
                        if not private_committed:
                            self.unresolved = True
                            self._revoke_first_candidate_once(transport)
                            raise OSError(errno.ENOTSUP,
                                'initial worker channel EOF is outside the private post-COMMIT phase')
                        if self.profile.origin_module.identity.process_alive(old_fd):
                            now = time.monotonic_ns()
                            if self._private_initial_exit_eof_hint_ns is None:
                                self._private_initial_exit_eof_hint_ns = now
                            elif now - self._private_initial_exit_eof_hint_ns > 100_000_000:
                                self.unresolved = True
                                self._revoke_first_candidate_once(transport)
                                raise TimeoutError('initial worker channel EOF was not followed by pidfd exit')
                            return None
                        self._check_first_candidate_phase(transport)
                        pending_exit = self._valid_private_initial_exit_observation(
                            transport, context)
                    if state == 'eof' and not pending_exit:
                        raise ProcessLookupError('initial worker exited without an exact post-COMMIT observation')
                private_preexit = (
                    type(self.profile) is _c34_profile_module().PrivateNewC34InteropProfile and
                    getattr(context, '_completed_master_barriers', set()) == {(1, 5), (1, 6)} and
                    (1, 1) in getattr(context, '_source_shell_committed_plans', {}) and
                    self._private_initial_retirement_proof is not None)
                pending_preexit = getattr(self, '_private_candidate_preexit_pending', None)
                candidate_readable = bool(select.select([candidate_channel], [], [], 0)[0])
                if private_preexit and (pending_preexit is not None or candidate_readable):
                    try:
                        if pending_preexit is None:
                            pending_preexit = context.poll_private_candidate_preexit(self)
                        if (pending_preexit is not None and
                                self._private_candidate_preexit_evidence is None):
                            context.authorize_private_candidate_preexit(self, pending_preexit)
                        if self._private_candidate_preexit_evidence is not None:
                            self._advance_private_candidate_stop(transport)
                    except BlockingIOError as exc:
                        if (exc.errno not in (errno.EAGAIN, errno.EWOULDBLOCK) or
                                pending_preexit is None or
                                time.monotonic_ns() >= pending_preexit.deadline_ns):
                            self.unresolved = True
                            self._revoke_first_candidate_once(transport)
                            raise
                        return None
                    except BaseException:
                        self.unresolved = True
                        self._revoke_first_candidate_once(transport)
                        raise
                elif candidate_readable:
                    self.unresolved = True
                    self._revoke_first_candidate_once(transport)
                    raise OSError(errno.ENOTSUP,
                        'candidate worker channel has unexpected PREEXIT/readability outside the exact private phase')
                return None
            if (type(transport) is not _SourceInitialWorkerTransport or
                    transport is not getattr(self, 'initial_worker_binding', None) or
                    not transport.authenticated or transport.settled or
                    set(context.workers) != {(0, 0)} or
                    set(context.worker_channels) != {(0, 0)} or
                    context.worker_proofs.get((0, 0)) != context.initial_cycle_proof or
                    getattr(context, '_activated_workers', set()) or
                    getattr(context, '_completed_master_barriers', set()) or
                    getattr(context, '_source_shell_committed_plans', {})):
                raise PermissionError('control-only source context unexpectedly contains worker/master authority')
            channel = context.worker_channels[(0, 0)]
            readable, _, _ = select.select([channel], [], [], 0)
            if readable:
                self.unresolved = True
                transport.revoke()
                raise OSError(errno.ENOTSUP,
                    'initial-only worker channel has a pending PREEXIT requiring the separate settlement provider')
            return None
        pending = context.poll_worker_preexit()
        if pending is None:
            return None
        self.unresolved = True
        # The original TERM observer is real and one-shot.  Native STOP/C28/C31
        # settlement has no connected producer in ker-run yet, so do not ACK.
        context.authorize_worker_preexit(pending.operation_id)
        raise OSError(errno.ENOTSUP,
            'source PREEXIT is authenticated; native STOP/C28/C31 settlement provider is not connected')

    def _advance_private_candidate_stop(self, transport):
        """Admit and poll one private broker STOP, retaining its raw ACK receipt."""
        if threading.current_thread() is not threading.main_thread():
            raise PermissionError('private broker STOP requires the SDK main thread')
        context = self.bootstrap_context
        provider = self.c22_provider
        broker = self.broker_readiness
        pending = self._private_candidate_preexit_pending
        evidence = self._private_candidate_preexit_evidence
        proof = self._private_initial_retirement_proof
        if (type(self.profile) is not _c34_profile_module().PrivateNewC34InteropProfile or
                type(transport) is not _SourceInitialWorkerTransport or
                transport is not self.initial_worker_binding or transport.context is not context or
                transport.broker is not broker or context is None or provider is None or broker is None or
                pending is None or evidence is None or proof is None or
                context._pending_preexits.get(pending.operation_id, (None,))[0] is not pending or
                context._authorized_preexits.get(pending.operation_id) is not evidence or
                getattr(context, '_source_initial_listener_retirements', {}).get(id(provider)) is not proof or
                getattr(provider, '_initial_retirement_proof', None) is not proof or
                getattr(self, '_private_stop_ack_receipt', None) is not None):
            if getattr(self, '_private_stop_ack_receipt', None) is not None:
                return self._validated_cached_private_stop_receipt(transport, broker)
            raise PermissionError('private STOP lacks the exact pending TERM and C34 proof join')
        retained_authorization = getattr(broker, '_private_stop_authorization', None)
        if getattr(broker, '_private_stop_ack_receipt', None) is not None:
            receipt = broker.private_stop_ack_receipt(retained_authorization)
            if (receipt.authorization.pending is not pending or
                    receipt.authorization.term_evidence is not evidence or
                    receipt.authorization.retirement_proof is not proof):
                raise PermissionError('retained private STOP ACK belongs to another PREEXIT phase')
            self._private_stop_ack_receipt = receipt
            return receipt
        if getattr(broker, '_stop', None) is None:
            if retained_authorization is not None:
                raise PermissionError('private STOP was already consumed without a retained ACK receipt')
            authorization = broker.authorize_private_stop(provider, pending, evidence, proof)
            broker.begin_stop(private_authorization=authorization)
        try:
            completed = broker.poll_stop()
            if not completed:
                return None
            authorization = getattr(broker, '_private_stop_authorization', None)
            receipt = broker.private_stop_ack_receipt(authorization)
            if (receipt.authorization.pending is not pending or
                    receipt.authorization.term_evidence is not evidence or
                    receipt.authorization.retirement_proof is not proof or
                    receipt.received_ns >= pending.deadline_ns):
                raise PermissionError('broker STOP did not retain the exact authenticated raw ACK')
            self._private_stop_ack_receipt = receipt
            return receipt
        except BaseException:
            self.unresolved = True
            raise

    def _validated_cached_private_stop_receipt(self, transport, broker):
        """Revalidate immutable historical phase joins before returning an ACK."""
        context = self.bootstrap_context
        provider = self.c22_provider
        pending = self._private_candidate_preexit_pending
        evidence = self._private_candidate_preexit_evidence
        proof = self._private_initial_retirement_proof
        authorization = getattr(broker, '_private_stop_authorization', None)
        receipt_cache = getattr(self, '_private_stop_ack_receipt', None)
        profile_module = _c34_profile_module()
        provider_module = _c22_provider_module()
        origin_module = getattr(self.profile, 'origin_module', None)
        origin = getattr(getattr(context, 'owner_live', None), '__self__', None)
        auth_ok = (
            authorization is not None and authorization.broker is broker and
            authorization.controller is self and authorization.provider is provider and
            authorization.context is context and authorization.pending is pending and
            authorization.term_evidence is evidence and authorization.retirement_proof is proof and
            authorization.deadline_ns == getattr(pending, 'deadline_ns', None) and
            getattr(broker, '_private_stop_authorization', None) is authorization and
            getattr(broker, '_private_stop_authorization_consumed', False) is True)
        if (threading.current_thread() is not threading.main_thread() or
                type(self) is not SourceShellController or
                type(self.profile) is not profile_module.PrivateNewC34InteropProfile or
                origin_module is None or
                type(origin) is not getattr(origin_module, 'PrivateC34OriginalShellLaunch', None) or
                type(transport) is not _SourceInitialWorkerTransport or
                transport is not self.initial_worker_binding or transport.context is not context or
                transport.broker is not broker or broker is not self.broker_readiness or
                transport.authenticated is not True or transport.settled is not False or
                transport.app != getattr(broker, 'app', None) or
                transport.app_pidfd != getattr(broker, 'app_pidfd', None) or
                transport.nonce != getattr(broker, 'nonce', None) or
                transport.epoch != getattr(broker, 'epoch', None) or
                context is None or provider is None or context.control_only is not True or
                type(provider) is not getattr(provider_module, 'SourceShellC34InteropProvider', None) or
                not auth_ok or pending is None or evidence is None or proof is None or
                getattr(context, '_pending_preexits', {}).get(pending.operation_id, (None,))[0] is not pending or
                getattr(context, '_authorized_preexits', {}).get(pending.operation_id) is not evidence or
                getattr(context, '_source_initial_listener_retirements', {}).get(id(provider)) is not proof or
                getattr(provider, '_initial_retirement_proof', None) is not proof or
                getattr(provider, 'context', None) is not context or
                getattr(provider, 'broker_readiness', None) is not broker or
                getattr(self, 'launch', None) is not origin or
                getattr(origin, 'context', None) is not context or
                getattr(self.profile, 'artifact_capture', None) is not
                    getattr(origin, 'c34_artifact_capture', None) or
                getattr(self.profile, 'helper_capture', None) is not
                    getattr(provider, '_private_c34_helper_capture', None)):
            raise PermissionError('cached private STOP ACK lost its exact historical phase binding')
        receipt = broker.private_stop_ack_receipt(authorization)
        if receipt is not receipt_cache:
            raise PermissionError('cached private STOP ACK differs from the broker receipt')
        return receipt

    def poll_private_stop_after_app_exit(self, broker_readiness=None):
        """Drain only an already-sent private STOP after the app has exited.

        This uses the same BrokerReadiness.poll_stop reader and the PREEXIT
        deadline.  It never starts a STOP or reads another channel.
        """
        broker = self.broker_readiness
        transport = self.initial_worker_binding
        request = getattr(broker, '_stop', None)
        authorization = getattr(broker, '_private_stop_authorization', None)
        if (threading.current_thread() is not threading.main_thread() or
                broker is None or broker is not broker_readiness or
                type(self.profile) is not _c34_profile_module().PrivateNewC34InteropProfile or
                type(transport) is not _SourceInitialWorkerTransport or
                transport is not self.initial_worker_binding or
                transport.broker is not broker or transport.context is not self.bootstrap_context or
                request is None or request.get('private') is not True or
                request.get('sent') is not True or request.get('authorization') is not authorization or
                authorization is None or authorization.pending is not self._private_candidate_preexit_pending or
                authorization.term_evidence is not self._private_candidate_preexit_evidence or
                authorization.retirement_proof is not self._private_initial_retirement_proof or
                getattr(self, '_private_stop_ack_receipt', None) is not None):
            raise PermissionError('post-exit STOP drain lacks the exact pending private authorization')
        app_pidfd = getattr(broker, 'app_pidfd', -1)
        if app_pidfd < 0:
            raise PermissionError('post-exit STOP drain lacks the bound app pidfd')
        app_poller = select.poll()
        app_poller.register(app_pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        if not app_poller.poll(0):
            raise PermissionError('post-exit STOP drain requires the observed bound app exit')
        if time.monotonic_ns() >= authorization.deadline_ns:
            self.unresolved = True
            raise TimeoutError('post-exit STOP drain exceeded the original PREEXIT deadline')
        return self._advance_private_candidate_stop(transport)

    def _advance_private_initial_listener_retirement(self, transport):
        """Advance only C28 old-listener retirement and its C34 VERIFY proof."""
        if threading.current_thread() is not threading.main_thread():
            raise PermissionError('private C28/C34 retirement pumping requires the SDK main thread')
        context = self.bootstrap_context
        provider = self.c22_provider
        broker = self.broker_readiness
        if (type(self.profile) is not _c34_profile_module().PrivateNewC34InteropProfile or
                type(transport) is not _SourceInitialWorkerTransport or
                transport is not self.initial_worker_binding or provider is None or
                broker is not transport.broker or provider is not self.c22_provider or
                context is not transport.context or context.control_only is not True or
                getattr(context, '_completed_master_barriers', set()) != {(1, 5), (1, 6)} or
                (1, 1) not in getattr(context, '_source_shell_committed_plans', {})):
            raise PermissionError('private initial listener retirement is outside the exact committed phase')
        if self._private_initial_retirement_proof is not None:
            return self._private_initial_retirement_proof
        if (not getattr(self, '_first_candidate_activation_delivered', False) or
                not getattr(provider, '_source_committed', False) or
                not broker.ready or broker.stopped):
            raise PermissionError('C28/C34 retirement requires the activated live candidate and broker')
        old_fd = context.workers[(0, 0)][0]
        if self.profile.origin_module.identity.process_alive(old_fd):
            return None
        observation = self._check_private_initial_worker_exit_binding(
            transport, provider, context)
        now = time.monotonic_ns()
        if getattr(provider, '_initial_retire_ack', None) is None:
            try:
                response = provider.retire_initial_listener(observation,
                    min(context.deadline_ns, now + 100_000_000))
            except BaseException:
                self.unresolved = True
                raise
            if response is None:
                return None
            try:
                provider.begin_c34_verify(1)
            except BaseException:
                self.unresolved = True
                raise
            self._private_initial_verify_started = True
        if not self._private_initial_verify_started:
            raise PermissionError('C34 VERIFY phase was not started after the correlated C28 ACK')
        try:
            # Exactly one nonblocking parent-channel poll is made per controller turn.
            packet = broker.poll_verify()
            if packet is None:
                return None
            result = getattr(broker, 'last_verify_result', None)
            proof = provider.finish_initial_listener_retirement(packet, result)
        except BaseException:
            self.unresolved = True
            raise
        self._private_initial_retirement_proof = proof
        return proof

    def pump_source_requests(self, broker_readiness=None):
        """One main-thread turn across the single listener and retained owner channels."""
        if self.bootstrap_context is None:
            return False
        if getattr(getattr(self, 'launch', None), 'process', None) is not None:
            self.check_live()
        if broker_readiness is not None:
            private_profile = _c34_profile_module().PrivateNewC34InteropProfile
            start_provider = (self.start_c34_interop_provider
                if type(self.profile) is private_profile else self.start_c22_provider)
            retained_broker = getattr(self, 'broker_readiness', None)
            if retained_broker not in (None, broker_readiness):
                raise RuntimeError('source controller broker readiness owner changed')
            self.broker_readiness = broker_readiness
            if not getattr(broker_readiness, 'ready', False):
                if broker_readiness.poll_ready():
                    start_provider(broker_readiness)
                else:
                    # Leave queued Origin records unread until the same C34
                    # readiness has authorized the C22 provider.  In
                    # particular, do not consume and reject an early initial
                    # worker request merely because the provider is not ready.
                    return False
            elif self.c22_provider is None:
                start_provider(broker_readiness)
            if getattr(getattr(self, 'launch', None), 'process', None) is not None:
                self.check_live()
        accepted = self.pump_bootstrap_listener()
        if getattr(getattr(self, 'launch', None), 'process', None) is not None:
            self.check_live()
        self.poll_source_preexit()
        return accepted

    def wait_startup_marker(self, startup_fd, startup_bytes, marker, timeout,
            description, app, app_pidfd, broker_readiness=None):
        """Multiplex startup, Origin, broker readiness, and the exact app pidfd."""
        context = self.bootstrap_context
        if (context is None or getattr(self.launch, 'context', None) is not context or
                type(context) is not self.profile.origin_module.bootstrap.SourceBootstrapSupervisor):
            raise OSError(errno.ENOTSUP, 'source startup marker wait lacks the authenticated Origin context')
        actor = getattr(self.launch, 'backend_runtime_actor', None)
        if (actor is None or actor.pid != app.pid or actor.pidfd != app_pidfd or
                app_pidfd < 0 or type(startup_bytes) is not bytes or
                type(marker) is not bytes or not marker or
                type(timeout) not in (int, float) or timeout <= 0):
            raise PermissionError('source startup marker wait is not bound to the retained runtime actor')
        deadline_ns = min(context.deadline_ns,
            time.monotonic_ns() + int(timeout * 1_000_000_000))
        if len(startup_bytes) > SOURCE_STARTUP_BUFFER_MAX:
            raise SourceStartupMarkerError(
                f'{description} startup buffer exceeded its finite diagnostic bound',
                startup_bytes[:SOURCE_STARTUP_BUFFER_MAX], overflow=True,
                diagnostic_tail=startup_bytes[-SOURCE_STARTUP_TAIL_MAX:])
        data = startup_bytes

        def check_deadline_and_actors():
            code = app.poll()
            if code is not None:
                raise SourceStartupMarkerError(
                    f'{description} exited before readiness marker; startup bytes={data!r}',
                    data, actor_exit=code)
            self.check_live()
            if broker_readiness is not None and broker_readiness.ready:
                broker_poller = select.poll()
                broker_poller.register(broker_readiness.parent.fileno(),
                    select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL)
                broker_status = broker_poller.poll(0)
                if broker_status:
                    broker_flags = broker_status[0][1]
                    if broker_flags & (select.POLLHUP | select.POLLERR | select.POLLNVAL):
                        raise ConnectionError('C34 readiness endpoint closed during source startup')
                    if broker_flags & select.POLLIN:
                        raise PermissionError('unexpected C34 record during initial source startup')
            if time.monotonic_ns() >= deadline_ns:
                raise SourceStartupMarkerError(
                    f'{description} startup timed out under its immutable deadline',
                    data, timed_out=True)

        try:
            if broker_readiness is None:
                self.pump_source_requests()
            else:
                self.pump_source_requests(broker_readiness)
            check_deadline_and_actors()
            with selectors.DefaultSelector() as selector:
                selector.register(startup_fd, selectors.EVENT_READ, 'startup')
                source_registered = False
                if broker_readiness is None or getattr(broker_readiness, 'ready', False):
                    selector.register(self.listener.fileno(), selectors.EVENT_READ, 'source')
                    source_registered = True
                selector.register(app_pidfd, selectors.EVENT_READ, 'app')
                if broker_readiness is not None:
                    if type(getattr(broker_readiness, 'parent', None)) is not socket.socket:
                        raise PermissionError('source broker readiness has no retained parent socket')
                    selector.register(broker_readiness.parent, selectors.EVENT_READ, 'broker')
                while marker not in data:
                    check_deadline_and_actors()
                    remaining_ns = deadline_ns - time.monotonic_ns()
                    try:
                        events = selector.select(remaining_ns / 1_000_000_000)
                    except InterruptedError:
                        continue
                    if not events:
                        raise SourceStartupMarkerError(
                            f'{description} startup timed out under its immutable deadline',
                            data, timed_out=True)
                    check_deadline_and_actors()
                    # Service the source channel before reading marker bytes
                    # when both are ready; the listener owns this single read.
                    if any(key.data == 'source' for key, _ in events):
                        if broker_readiness is None:
                            self.pump_source_requests()
                        else:
                            self.pump_source_requests(broker_readiness)
                        check_deadline_and_actors()
                    broker_events = [mask for key, mask in events if key.data == 'broker']
                    if broker_events:
                        if broker_readiness.ready:
                            poller = select.poll()
                            poller.register(broker_readiness.parent.fileno(),
                                select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL)
                            broker_status = poller.poll(0)
                            if broker_status:
                                broker_flags = broker_status[0][1]
                                if broker_flags & (select.POLLHUP | select.POLLERR | select.POLLNVAL):
                                    raise ConnectionError('C34 readiness endpoint closed during source startup')
                                if broker_flags & select.POLLIN:
                                    raise PermissionError('unexpected C34 record during initial source startup')
                        elif broker_readiness is None:
                            self.pump_source_requests()
                        else:
                            self.pump_source_requests(broker_readiness)
                        check_deadline_and_actors()
                        if (broker_readiness is not None and broker_readiness.ready and
                                not source_registered):
                            selector.register(self.listener.fileno(),
                                selectors.EVENT_READ, 'source')
                            source_registered = True
                    if any(key.data == 'app' for key, _ in events):
                        raise SourceStartupMarkerError(
                            'runtime pidfd became readable while app identity remained live', data)
                    if any(key.data == 'startup' for key, _ in events):
                        try:
                            room = SOURCE_STARTUP_BUFFER_MAX - len(data)
                            chunk = os.read(startup_fd, min(4096, room + 1))
                        except BlockingIOError:
                            chunk = None
                        except OSError as error:
                            raise SourceStartupMarkerError(
                                f'{description} startup pipe read failed: {error}', data,
                                cause=error) from error
                        if chunk == b'':
                            raise SourceStartupMarkerError(
                                f'{description} exited before readiness marker; startup bytes={data!r}',
                                data, eof=True)
                        if chunk:
                            room = SOURCE_STARTUP_BUFFER_MAX - len(data)
                            if len(chunk) > room:
                                data += chunk[:room]
                                raise SourceStartupMarkerError(
                                    f'{description} startup buffer exceeded its finite diagnostic bound',
                                    data, overflow=True, diagnostic_tail=chunk[room:])
                            data += chunk
                            check_deadline_and_actors()
                            if marker in data and time.monotonic_ns() >= deadline_ns:
                                raise SourceStartupMarkerError(
                                    f'{description} startup marker arrived after its immutable deadline',
                                    data, timed_out=True)
                check_deadline_and_actors()
                return data
        except SourceStartupMarkerError:
            raise
        except (OSError, PermissionError, RuntimeError, TimeoutError) as error:
            raise SourceStartupMarkerError(
                f'{description} source-aware startup failed: {error}', data,
                cause=error) from error

    def pump_bootstrap_listener(self):
        """Accept one bounded request; only the existing control-only slim grant is enabled."""
        context = self.bootstrap_context
        if context is None:
            return False
        if (type(context) is not self.profile.origin_module.bootstrap.SourceBootstrapSupervisor or
                getattr(self.launch, 'context', None) is not context or self.listener is None):
            raise RuntimeError('source bootstrap listener lost its exact context owner')
        try:
            channel, _ = self.listener.accept()
        except BlockingIOError:
            return False
        received_fds = []
        keep = False
        try:
            channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            deadline = min(context.deadline_ns, time.monotonic_ns() + 5_000_000_000)
            remaining = deadline - time.monotonic_ns()
            if remaining <= 0:
                raise TimeoutError('source bootstrap request deadline expired')
            channel.settimeout(remaining / 1_000_000_000)
            record = context.record_struct
            packet, ancillary, flags, _ = channel.recvmsg(record.size + 1,
                socket.CMSG_SPACE(12) + socket.CMSG_SPACE(64 * 4),
                getattr(socket, 'MSG_CMSG_CLOEXEC', 0) |
                getattr(socket, 'MSG_DONTWAIT', 0))
            credentials = []
            invalid = False
            for level, kind, value in ancillary:
                if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(value) == 12:
                    credentials.append(struct.unpack('=3i', value))
                elif level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    fds = array.array('i')
                    fds.frombytes(value[:len(value) - len(value) % fds.itemsize])
                    received_fds.extend(fds)
                    invalid = True
                else:
                    invalid = True
            for fd in received_fds:
                os.close(fd)
            received_fds.clear()
            allowed_flags = getattr(socket, 'MSG_CMSG_CLOEXEC', 0)
            if (invalid or flags & ~allowed_flags or
                    flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or
                    len(packet) != record.size):
                raise PermissionError('malformed source bootstrap request transport')
            fields = list(record.unpack(packet))
            bootstrap = self.profile.origin_module.bootstrap
            if (len(credentials) != 1 or fields[0:2] !=
                    [bootstrap.MAGIC, bootstrap.SHELL_VERSION] or fields[3] != record.size):
                raise OSError(errno.EPROTO, 'source bootstrap request has an unsupported envelope')
            if fields[4] == 2 and fields[2] in (5, 6):
                timing_start_ns = time.monotonic_ns()
                # Keep the accepted endpoint and all existing capability/worker
                # anchors if anything fails after this credentialed request was
                # consumed. Never ACK, recreate, or replay this operation.
                master_channels = getattr(self, '_private_source_master_channels', [])
                master_channels = master_channels + [channel]
                self._private_source_master_channels = master_channels
                keep = True
                try:
                    request_attempts = getattr(context,
                        '_private_source_master_request_attempts', set())
                    request_key = (1, fields[2])
                    if request_key in request_attempts:
                        raise PermissionError('private source master request was already consumed')
                    request_attempts.add(request_key)
                    context._private_source_master_request_attempts = request_attempts
                    channel.setblocking(False)
                    profile_type = _c34_profile_module().PrivateNewC34InteropProfile
                    prepared = getattr(self, '_first_candidate_source_prepared', None)
                    cap = getattr(self, '_first_candidate_worker_grant', None)
                    provider = self.c22_provider
                    if (type(self.profile) is not profile_type or
                            self._first_candidate_activation_delivered is not True or
                            prepared is None or cap is None or provider is None or
                            getattr(self, '_first_candidate_worker_pending', False) is not True):
                        raise OSError(errno.ENOTSUP,
                            'private source master PARK/COMMIT is not connected to the exact activated candidate')
                    def apply_source(operation, operation_deadline_ns):
                        if threading.current_thread() is not threading.main_thread():
                            raise PermissionError('private source cutover must run on the SDK main thread')
                        if operation == 5:
                            provider.park_source_group(operation_deadline_ns)
                            provider.bind_source_route_preparation(prepared)
                            return None
                        if operation == 6:
                            preparer = getattr(self, '_source_route_preparer', None)
                            route_module = sys.modules.get(getattr(preparer, '__module__', ''))
                            if route_module is None and getattr(
                                    sys.modules.get('__main__'),
                                    'rx_owner_source_route_prepare', None) is preparer:
                                route_module = sys.modules.get('__main__')
                            route_namespace = (vars(route_module) if route_module is not None
                                else getattr(preparer, '__globals__', {}))
                            send_command = route_namespace.get('send_source_route_command')
                            commit_kind = route_namespace.get(
                                '_RX_OWNER_SOURCE_ROUTE_COMMIT')
                            if not callable(send_command) or type(commit_kind) is not int:
                                raise OSError(errno.ENOTSUP,
                                    'private source route COMMIT dispatcher is unavailable')
                            status = send_command(cap.initial_transport.auth, prepared, commit_kind,
                                prepared.command_sequence + 1,
                                operation_deadline_ns=operation_deadline_ns)
                            if status != 0:
                                raise OSError(errno.EIO,
                                    'C31 source route COMMIT returned a nonzero status')
                            receipt = getattr(prepared, '_source_route_commit_receipt', None)
                            response = provider.commit_source_group_before(
                                operation_deadline_ns, receipt)
                            return {'native_current_cookie': response['listener_cookie']}
                        raise OSError(errno.ENOTSUP,
                            'private source master accepts only PARK and COMMIT')

                    context.private_source_master_barrier(channel, packet,
                        credentials[0], apply_source, self, prepared, cap, provider)
                    timings = getattr(self, '_private_source_master_timings', [])
                    self._private_source_master_timings = timings + [
                        (1, fields[2], timing_start_ns, time.monotonic_ns(), 'acknowledged')]
                    master_channels = getattr(self, '_private_source_master_channels', [])
                    self._private_source_master_channels = [item for item in master_channels
                        if item is not channel]
                    keep = False
                    return True
                except BaseException:
                    timings = getattr(self, '_private_source_master_timings', [])
                    self._private_source_master_timings = timings + [
                        (1, fields[2], timing_start_ns, time.monotonic_ns(), 'unresolved')]
                    self.unresolved = True
                    self._revoke_first_candidate_once(
                        getattr(self, '_initial_transport', None))
                    raise
            if fields[2:5] == [1, record.size, 1]:
                transport = getattr(self, '_initial_transport', None)
                provider = getattr(self, 'c22_provider', None)
                if (transport is None or
                        transport is not getattr(self, 'initial_worker_binding', None) or
                        provider is None or transport.context is not context or
                        transport.broker is not self.broker_readiness):
                    raise OSError(errno.ENOTSUP,
                        'initial worker grant lacks the trusted C22 build receipt and exact C31 source binding')
                request_key = (fields[9], fields[8])
                if request_key == (1, 1):
                    # Freeze provenance only after the owned listener performed
                    # the credentialed receive.  The same absolute request
                    # deadline covers C22 grant and the ordered READY watch.
                    self._check_initial_worker_binding(transport)
                    if (self._accepted_candidate_worker_request is not None or
                            getattr(self, '_first_candidate_worker_grant', None) is not None or
                            getattr(self, '_first_candidate_worker_pending', False)):
                        raise PermissionError('first candidate listener request was already consumed')
                    channel.setblocking(False)
                    listener_identity = self._first_candidate_endpoint_identity(self.listener)
                    listener_cookie = self._first_candidate_socket_cookie(self.listener)
                    channel_identity = self._first_candidate_endpoint_identity(channel)
                    channel_cookie = self._first_candidate_socket_cookie(channel)
                    if (not listener_cookie or not channel_cookie or
                            time.monotonic_ns() >= deadline):
                        raise TimeoutError('first candidate listener request expired before provenance capture')
                    self._accepted_candidate_worker_request = _AcceptedCandidateWorkerRequest(
                        _ACCEPTED_CANDIDATE_REQUEST_TOKEN, self, self.listener,
                        listener_identity, listener_cookie, channel, channel_identity,
                        channel_cookie, bytes(packet), tuple(credentials[0]),
                        deadline, (1, 1))
                    # A failure from here on is one-shot. Keep this exact
                    # accepted socket reachable until settlement unless the
                    # grant and READY observation both complete.
                    keep = True
                    # The first candidate gets a distinct SDK-created relay.
                    # Keep its peer anchored because the grant send may have an
                    # unknown result; never recreate it for a retry.
                    try:
                        relay, relay_anchor = socket.socketpair(socket.AF_UNIX,
                            socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
                        self._first_candidate_relay_anchor = relay_anchor
                        relay.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                        relay_anchor.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                        cap = self.mint_first_candidate_worker_grant(
                            transport, provider, channel, packet, credentials[0],
                            relay, deadline)
                        watch, receiver = provider.reply_first_candidate_worker(
                            self, cap, channel, packet, credentials[0], relay, deadline)
                        self._first_candidate_pending_watch = watch
                        self._first_candidate_pending_ready = receiver
                        if getattr(context, 'worker_ready_receivers', {}) != {}:
                            raise PermissionError('successful candidate grant retained an unexpected READY receiver map')
                        remaining_ns = deadline - time.monotonic_ns()
                        if remaining_ns <= 0:
                            raise TimeoutError('first candidate READY observation exceeded its accepted request deadline')
                        attachment = transport.attachment
                        if attachment is None:
                            raise PermissionError('first candidate READY lacks the retained initial observer')
                        ready, borrowed_pidfd = attachment.receive_first_candidate_ready(
                            watch, receiver, timeout=remaining_ns / 1_000_000_000)
                        self._join_first_candidate_ready(cap, watch, ready, borrowed_pidfd)
                        receiver.close()
                        self._first_candidate_pending_ready = None
                        provider._first_candidate_pending_ready = None
                        self._first_candidate_pending_error = None
                        provider._first_candidate_pending_error = None
                        self._first_candidate_observed_ready = tuple(ready)
                        if type(self.profile) is _c34_profile_module().PrivateNewC34InteropProfile:
                            self._prepare_and_activate_first_candidate(transport, cap, watch)
                        keep = False
                    except BaseException as error:
                        self.unresolved = True
                        self._first_candidate_worker_pending = True
                        self._first_candidate_pending_error = error
                        provider._first_candidate_pending_error = error
                        attachment = transport.attachment
                        if getattr(attachment, '_revoked', False):
                            self._first_candidate_revoke_attempted = True
                        else:
                            self._revoke_first_candidate_once(transport)
                        raise
                    return True
                if request_key != (0, 0):
                    raise OSError(errno.ENOTSUP,
                        'source worker request is outside the initial and first-candidate phases')
                # This accepted request socket has a per-request timeout for
                # recvmsg. Clear it before the one-shot grant: Python may poll
                # for writability under a positive timeout before sendmsg's
                # MSG_DONTWAIT reaches the kernel.
                channel.setblocking(False)
                watch, receiver = provider.reply_initial_worker(
                    channel, packet, credentials[0], transport.relay, deadline)
                self._initial_worker_ready_and_auth(transport, provider, watch, receiver)
                self.unresolved = not transport.authenticated
                return True
            if fields[2:5] != [1, record.size, 0]:
                raise OSError(errno.ENOTSUP,
                    'worker/master source requests require a separately authenticated later phase')
            context.reply_slim(channel, packet, credentials[0], control_only=True)
            self.control_slim_channel = channel
            keep = True
            return True
        finally:
            for fd in received_fds:
                os.close(fd)
            if not keep:
                channel.close()
            if 'relay' in locals():
                relay.close()

    def _join_first_candidate_ready(self, cap, watch, ready, borrowed_pidfd):
        """Retain only the exact role-1 READY produced by the ordered observer."""
        context = self.bootstrap_context
        provider = self.c22_provider
        if (type(cap) is not _FirstCandidateWorkerGrant or
                cap is not self._first_candidate_worker_grant or
                not self._first_candidate_worker_grant_consumed or
                not self._first_candidate_worker_pending or
                self._first_candidate_pending_error is not None or
                type(watch) is not dict or type(ready) is not tuple or len(ready) != 10 or
                context is None or provider is None or context.control_only is not True or
                self._first_candidate_pending_watch is not watch or
                self._first_candidate_pending_ready is None or
                set(context.workers) != {(0, 0), (1, 1)} or
                set(context.worker_channels) != {(0, 0), (1, 1)} or
                set(context.worker_process_slots) != {(0, 0), (1, 1)} or
                set(context.worker_proofs) != {(0, 0), (1, 1)} or
                getattr(context, 'worker_ready_receivers', {}) != {} or
                provider._used_slots != {0, 1} or
                getattr(context, '_activated_workers', set()) or
                getattr(context, '_completed_master_barriers', set()) or
                getattr(context, '_source_shell_committed_plans', {})):
            raise PermissionError('candidate READY lacks the exact pending control-only phase')
        record = context.workers[(1, 1)][1]
        proof = context.worker_proofs[(1, 1)]
        identity = self.profile.origin_module.identity
        candidate_pidfd = os.dup(borrowed_pidfd)
        try:
            if (proof is not cap.cycle_proof or watch.get('source_epoch') != 1 or
                    watch.get('generation') != 1 or watch.get('role') != 1 or
                    ready[0] != record[5] or ready[3] != 1 or ready[4] != record[6] or
                    ready[6] != record[11] or ready[7:9] != tuple(record[24:26]) or
                    ready[9] != record[27] or
                    (watch.get('pid'), watch.get('tid'), watch.get('start'),
                        watch.get('slot_device'), watch.get('slot_inode'), watch.get('cookie')) !=
                    (record[5], record[6], record[11], record[24], record[25], record[27]) or
                    context.worker_process_slots[(1, 1)] != watch.get('process_slot') or
                    (record[24], record[25]) != provider.slot_identities[1] or
                    record[26] != cap.relay_cookie or
                    record[14:17] != (context.epoch, context.deadline_ns, context.nonce) or
                    identity._pidfd_pid(candidate_pidfd) != ready[0] or
                    not identity.process_alive(candidate_pidfd) or
                    identity._start_ticks(ready[0]) != ready[6] or
                    identity._pidfd_pid(context.workers[(1, 1)][0]) != ready[0] or
                    not identity.process_alive(context.workers[(1, 1)][0]) or
                    self.profile.origin_module.parent_pid(ready[0]) != context.master.pid or
                    identity._start_ticks(context.master.pid) != context.master.start_ticks or
                    not identity.process_alive(context.master.pidfd) or
                    time.monotonic_ns() >= cap.grant_deadline_ns):
                raise PermissionError('candidate READY differs from its retained request, cycle, slot, or process proof')
        except BaseException:
            os.close(candidate_pidfd)
            raise
        self._first_candidate_observed_pidfd = candidate_pidfd

    def _prepare_and_activate_first_candidate(self, transport, cap, watch):
        """Run the private C31 PREPARED then original-record ACTIVATE phase once."""
        context = self.bootstrap_context
        profile_module = _c34_profile_module()
        preparer = getattr(self, '_source_route_preparer', None)
        if (type(self.profile) is not profile_module.PrivateNewC34InteropProfile or
                context is None or context.control_only is not True or
                type(cap) is not _FirstCandidateWorkerGrant or
                cap is not self._first_candidate_worker_grant or
                getattr(self, '_first_candidate_worker_grant_consumed', False) is not True or
                getattr(self, '_first_candidate_worker_pending', False) is not True or
                self._first_candidate_observed_ready is None or
                self._first_candidate_observed_pidfd < 0 or
                not callable(preparer) or
                getattr(self, '_first_candidate_prepare_attempted', False) or
                getattr(self, '_first_candidate_pending_error', None) is not None or
                getattr(self, 'unresolved', False) or
                getattr(self, '_first_candidate_source_prepared', None) is not None or
                getattr(self, '_first_candidate_activation_delivered', False)):
            raise PermissionError('private C31 PREPARE requires the exact one-shot observed role-1 grant')
        self._check_first_candidate_phase(transport)
        current_entry = context.workers.get((0, 0))
        candidate_entry = context.workers.get((1, 1))
        if (type(current_entry) is not tuple or len(current_entry) != 2 or
                type(candidate_entry) is not tuple or len(candidate_entry) != 2 or
                context.worker_proofs.get((0, 0)) is not context.initial_cycle_proof or
                context.worker_proofs.get((1, 1)) is not cap.cycle_proof or
                context.worker_channels.get((1, 1)) is None):
            raise PermissionError('private C31 PREPARE lost the retained context worker joins')
        current = transport.worker_view
        record = candidate_entry[1]
        candidate = _InitialOwnerAuthView(self._first_candidate_observed_pidfd,
            record[5], record[6], watch['role'], record[11], record[24],
            record[25], record[27])
        # Consume this capability immediately before the only operation that
        # can place PREPARE on C31. A send/ACK exception has an unknown result.
        self._first_candidate_prepare_attempted = True
        prepared = preparer(transport.auth, self._first_candidate_relay_anchor,
            transport.app, transport.app_pidfd, transport.supervisor_pidfd,
            current, candidate, context.master, transport.nonce, transport.epoch,
            context.deadline_ns, secrets.randbits(63) or 1,
            source_context=context, source_cycle_proof=cap.cycle_proof,
            source_epoch=1)
        # Retain immediately: any activation exception is an unknown one-shot
        # outcome and must never cause a second PREPARE or ACTIVATE attempt.
        self._first_candidate_source_prepared = prepared
        context.activate_prepared_first_candidate(prepared,
            context.worker_channels[(1, 1)], watch, self, cap)
        self._first_candidate_activation_delivered = True

    def _revoke_first_candidate_once(self, transport):
        if self._first_candidate_revoke_attempted:
            return
        self._first_candidate_revoke_attempted = True
        try:
            transport.request_revoke()
        except BaseException as error:
            transport.cleanup_error = error

    def wait_source_worker(self, timeout, app_pidfd):
        """Bound the main-thread wait by the source grant and app pidfd."""
        context = self.bootstrap_context
        if context is None:
            return False
        remaining = (context.deadline_ns - time.monotonic_ns()) / 1_000_000_000
        if remaining <= 0:
            raise TimeoutError('source worker pump exceeded its immutable grant deadline')
        wait_for = min(timeout, remaining)
        pending_preexit = getattr(self, '_private_candidate_preexit_pending', None)
        if (pending_preexit is not None and
                getattr(self, '_private_stop_ack_receipt', None) is None):
            preexit_remaining_ns = pending_preexit.deadline_ns - time.monotonic_ns()
            if preexit_remaining_ns <= 0:
                raise TimeoutError('private candidate STOP exceeded its PREEXIT deadline')
            wait_for = min(wait_for, preexit_remaining_ns / 1_000_000_000)
            if getattr(self, '_private_candidate_preexit_evidence', None) is None:
                # TERM may become observable without another FD becoming readable.
                wait_for = min(wait_for, 0.005)
        poller = select.poll()
        if self.listener is not None:
            poller.register(self.listener.fileno(), select.POLLIN | select.POLLERR | select.POLLHUP)
        transport = getattr(self, '_initial_transport', None)
        pending_exit = self._valid_private_initial_exit_observation(transport, context)
        eof_hint = self._private_initial_exit_eof_hint_ns is not None
        for key, channel in context.worker_channels.items():
            if key == (0, 0) and (pending_exit or eof_hint):
                if eof_hint and not pending_exit:
                    old_pidfd = context.workers[(0, 0)][0]
                    poller.register(old_pidfd, select.POLLIN | select.POLLHUP |
                        select.POLLERR | select.POLLNVAL)
                continue
            poller.register(channel.fileno(), select.POLLIN | select.POLLHUP |
                select.POLLERR | select.POLLNVAL)
        if app_pidfd is not None and app_pidfd >= 0:
            poller.register(app_pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        broker = getattr(self, 'broker_readiness', None)
        stop = getattr(broker, '_stop', None)
        private_stop_pending = stop is not None and stop.get('private') and stop.get('sent')
        if (broker is not None and
                (getattr(broker, '_verify', None) is not None or private_stop_pending) and
                type(getattr(broker, 'parent', None)) is socket.socket):
            poller.register(broker.parent.fileno(), select.POLLIN | select.POLLHUP |
                select.POLLERR | select.POLLNVAL)
        events = poller.poll(max(0, int(wait_for * 1000)))
        return any(fd != app_pidfd for fd, _ in events)

    def stop_original(self):
        """Ask only the captured supervisor to stop its own process tree."""
        launch = self.launch
        if launch is None or launch.process is None or launch.pidfd < 0:
            raise RuntimeError('original supervisor has no captured stop identity')
        process = launch.process
        if process.poll() is None:
            if time.monotonic_ns() >= self.deadline_ns:
                raise TimeoutError('original supervisor stop exceeded its immutable deadline')
            identity = self.profile.origin_module.identity
            if not self.stop_target_validated:
                launch.live_supervisor(self.deadline_ns)
            if (identity._pidfd_pid(launch.pidfd) != process.pid or
                    not identity.process_alive(launch.pidfd) or
                    identity._start_ticks(process.pid) != launch.start or
                    self.profile.origin_module.parent_pid(process.pid) != launch.creator_pid or
                    self.profile.origin_module.namespace_identity(process.pid) != launch.pid_namespace):
                raise ProcessLookupError('captured original supervisor identity changed before TERM')
            launch.python.matches_process(process.pid, self.deadline_ns)
            if not self.shutdown_requested:
                sender = getattr(signal, 'pidfd_send_signal', None)
                if sender is None:
                    raise OSError(errno.ENOTSUP, 'pidfd signal delivery is unavailable')
                sender(launch.pidfd, signal.SIGTERM, None, 0)
                self.shutdown_requested = True
        remaining_ns = self.deadline_ns - time.monotonic_ns()
        if process.poll() is None:
            if remaining_ns <= 0:
                raise TimeoutError('original supervisor stop exceeded its immutable deadline')
            process.wait(timeout=remaining_ns / 1_000_000_000)
        settlement = launch.observe_settlement()
        if (type(settlement) is not dict or settlement.get('settled') is not True or
                launch.settlement != settlement):
            raise RuntimeError('original supervisor shutdown lacks verified ECHILD settlement')
        return settlement

    def validate_stop_target(self):
        """Perform full OriginalShellLaunch liveness checks before native STOP."""
        launch = self.launch
        if launch is None or launch.process is None:
            raise RuntimeError('original supervisor is unavailable for stop validation')
        if launch.process.poll() is None:
            launch.live_supervisor(self.deadline_ns)
            self.stop_target_validated = True
        return True

    def check_live(self):
        """Revalidate all retained actors and pins under the original deadline."""
        launch = self.launch
        if launch is None or launch.process is None:
            raise RuntimeError('source launch is unavailable during liveness check')
        if time.monotonic_ns() >= self.deadline_ns:
            raise TimeoutError('source actor liveness check exceeded its immutable deadline')
        identity = self.profile.origin_module.identity
        context = getattr(launch, 'context', None)
        if context is None:
            launch.live_supervisor(self.deadline_ns)
        else:
            # The real bootstrap observer's live() calls the retained owner
            # callback, which revalidates the original supervisor/artifacts,
            # I/O pin and backend receipt under this same immutable deadline.
            context.live()
        if time.monotonic_ns() >= self.deadline_ns:
            raise TimeoutError('source pin validation exceeded its immutable deadline')

        def require_live(fd, pid, start, label):
            if (fd < 0 or identity._pidfd_pid(fd) != pid or
                    not identity.process_alive(fd) or
                    identity._start_ticks(pid) != start):
                raise ProcessLookupError(f'captured {label} actor is no longer live')

        if (launch.process.poll() is not None or
                identity._pidfd_pid(launch.pidfd) != launch.process.pid or
                not identity.process_alive(launch.pidfd) or
                identity._start_ticks(launch.process.pid) != launch.start or
                self.profile.origin_module.parent_pid(launch.process.pid) != launch.creator_pid or
                self.profile.origin_module.namespace_identity(launch.process.pid) != launch.pid_namespace):
            raise ProcessLookupError('captured original supervisor is no longer live')
        if launch.master_pidfd >= 0:
            context = getattr(launch, 'context', None)
            master = getattr(context, 'master', None)
            if master is None:
                raise RuntimeError('captured original master identity is unavailable')
            require_live(launch.master_pidfd, master.pid, master.start_ticks,
                'original master')
        if launch.origin_pidfd >= 0 and (identity._pidfd_pid(launch.origin_pidfd) <= 0 or
                not identity.process_alive(launch.origin_pidfd)):
            raise ProcessLookupError('captured origin actor is no longer live')
        if self.io_actor is not None:
            require_live(launch.native_io_pidfd, self.io_actor.pid,
                self.io_actor.start_ticks, 'native I/O')
        receipt = getattr(launch, 'backend_receipt', None)
        if receipt is not None:
            startup = self.profile.origin_module._SOURCE_NETWORK_STARTUP
            if (type(receipt) is not startup.RetainedBackendReceipt or
                    launch.backend_runtime_actor is None):
                raise RuntimeError('retained backend receipt lost its exact actor binding')
            receipt.validate_live(launch._backend_expected(),
                launch.backend_runtime_actor, self.deadline_ns)
        transport = getattr(self, '_initial_transport', None)
        if (context is not None and transport is not None and
                getattr(self, '_first_candidate_worker_pending', False) and
                set(getattr(context, '_completed_master_barriers', set())) ==
                    {(1, 5), (1, 6)} and
                (1, 1) in getattr(context, '_source_shell_committed_plans', {}) and
                (0, 0) in getattr(context, 'workers', {}) and
                not identity.process_alive(context.workers[(0, 0)][0])):
            # Establish the exact post-COMMIT old-exit phase before the generic
            # worker-live loop sees (0,0). This observation grants no retirement.
            self._check_first_candidate_phase(transport)
        if context is not None:
            if context.slim_pidfd >= 0:
                require_live(context.slim_pidfd, context.slim_pid,
                    context.slim_start_ticks, 'delegated supervisor')
            for key, entry in context.workers.items():
                if (type(key) is not tuple or len(key) != 2 or
                        any(type(value) is not int or value < 0 for value in key) or
                        type(entry) is not tuple or len(entry) != 2 or
                        type(entry[0]) is not int or entry[0] < 0 or
                        type(entry[1]) is not tuple or len(entry[1]) < 12):
                    raise RuntimeError('source worker delegation map is malformed')
                fd, record = entry
                pid, start = record[5], record[11]
                if (type(pid) is not int or pid <= 0 or type(start) is not int or start <= 0 or
                        key != (record[9], record[8])):
                    raise RuntimeError('source worker record does not match its epoch/generation key')
                pending_exit = (key == (0, 0) and
                    self._valid_private_initial_exit_observation(transport, context))
                if pending_exit:
                    if identity.process_alive(fd):
                        raise ProcessLookupError('observed initial worker exit reverted while its pidfd remained live')
                else:
                    require_live(fd, pid, start, 'delegated worker')
                    if not context._executable_live(pid):
                        raise ProcessLookupError('captured delegated worker executable changed')
                if time.monotonic_ns() >= self.deadline_ns:
                    raise TimeoutError('source worker liveness check exceeded its immutable deadline')
        transport = getattr(self, '_initial_transport', None)
        if transport is not None and not transport.settled:
            try:
                if (getattr(self, '_first_candidate_worker_pending', False) or
                        getattr(self, '_first_candidate_observed_ready', None) is not None):
                    self._check_first_candidate_phase(transport)
                else:
                    self._check_initial_worker_binding(transport)
            except BaseException as primary_error:
                self.unresolved = True
                if (getattr(self, '_first_candidate_worker_pending', False) or
                        getattr(self, '_accepted_candidate_worker_request', None) is not None):
                    self._revoke_first_candidate_once(transport)
                else:
                    try:
                        transport.request_revoke()
                    except BaseException as revoke_error:
                        transport.cleanup_error = revoke_error
                raise primary_error
        if time.monotonic_ns() >= self.deadline_ns:
            raise TimeoutError('source actor liveness check exceeded its immutable deadline')
        return True

    def _check_initial_worker_binding(self, transport):
        if (type(transport) is not _SourceInitialWorkerTransport or
                transport is not getattr(self, 'initial_worker_binding', None) or
                transport.context is not self.bootstrap_context or
                transport.broker is not self.broker_readiness):
            raise PermissionError('initial worker transport ownership changed')
        provider = self.c22_provider
        if provider is None:
            context = transport.context
            # Binding C31 endpoints precedes native C34 READY. Permit exactly
            # this inert, same-session pending phase while the main thread
            # continues polling readiness. No worker grant/proof may exist.
            if (type(getattr(transport.broker, 'ready', None)) is not bool or
                    getattr(transport.broker, 'stopped', True) is not False or
                    getattr(transport.broker, 'stop_attempted', False) is not False or
                    getattr(transport.broker, '_stop', None) is not None or
                    transport.grant_attempted or transport.auth_started or
                    transport.authenticated or transport.settled or
                    context.workers or context.worker_channels or
                    getattr(context, 'worker_proofs', {}) or
                    getattr(context, 'worker_process_slots', {}) or
                    getattr(context, '_initial_worker_grant_consumed', False) or
                    time.monotonic_ns() >= self.deadline_ns):
                raise PermissionError('pre-provider initial phase contains authority or stale C34 state')
            transport.broker._check_app_identity()
            return True
        if (provider.context is not transport.context or
                provider.broker_readiness is not transport.broker):
            raise PermissionError('initial C22 provider changed context or C34 session')
        provider._check_actor(self.deadline_ns)
        if not transport.grant_attempted:
            return True
        if not transport.authenticated:
            raise PermissionError('initial worker grant has not completed credentialed AUTH')
        self._check_authenticated_initial_worker_core(transport, provider)
        context = transport.context
        cycle_proof = context.worker_proofs.get((0, 0))
        if (set(context.workers) != {(0, 0)} or
                set(context.worker_channels) != {(0, 0)} or
                set(context.worker_process_slots) != {(0, 0)} or
                set(context.worker_proofs) != {(0, 0)} or
                getattr(context, 'worker_ready_receivers', {}) != {} or
                type(cycle_proof) is not type(context.initial_cycle_proof) or
                cycle_proof is not context.initial_cycle_proof or
                provider._used_slots != {0}):
            raise PermissionError('initial worker live proof or immutable owner view changed')
        return True

    def _check_authenticated_initial_worker_core(self, transport, provider):
        """Recheck the full immutable role-0 READY binding in either phase."""
        context = self.bootstrap_context
        if (transport is not self.initial_worker_binding or
                transport.context is not context or transport.broker is not self.broker_readiness or
                not transport.authenticated or transport.settled or
                type(transport.ready_identity) is not tuple or
                len(transport.ready_identity) != 10 or
                type(transport.worker_view) is not _InitialOwnerAuthView or
                transport.worker_pidfd < 0 or
                type(context.workers.get((0, 0))) is not tuple or
                len(context.workers[(0, 0)]) != 2 or
                (0, 0) not in context.worker_channels or
                (0, 0) not in context.worker_process_slots or
                (0, 0) not in context.worker_proofs):
            raise PermissionError('authenticated initial-worker core is incomplete')
        attachment = transport.attachment
        if attachment is None:
            raise PermissionError('initial worker has no retained owner attachment')
        attachment.check()
        ready = transport.ready_identity
        entry = context.workers[(0, 0)]
        record = entry[1]
        watch = transport.watch
        relay_cookie = self._first_candidate_socket_cookie(transport.relay)
        initial_attachment_ready = getattr(attachment, 'ready', None)
        if (type(watch) is not dict or
                type(initial_attachment_ready) is not tuple or
                len(initial_attachment_ready) != 2 or
                tuple(initial_attachment_ready[0]) != ready or
                (watch.get('pid'), watch.get('tid'), watch.get('role'),
                    watch.get('start'), watch.get('slot_device'),
                    watch.get('slot_inode'), watch.get('cookie'),
                    watch.get('source_epoch'), watch.get('generation')) !=
                (ready[0], ready[4], ready[3], ready[6], ready[7], ready[8],
                    ready[9], 0, 0)):
            raise PermissionError('initial owner attachment or watch changed after credentialed READY')
        expected = (transport.worker_pidfd, ready[0], ready[4], ready[3],
            ready[6], ready[7], ready[8], ready[9])
        if tuple(transport.worker_view) != expected:
            raise PermissionError('immutable OWNER_AUTH view no longer matches credentialed READY')
        identity = self.profile.origin_module.identity
        if (identity._pidfd_pid(transport.worker_pidfd) != ready[0] or
                not identity.process_alive(transport.worker_pidfd) or
                identity._start_ticks(ready[0]) != ready[6] or
                identity._pidfd_pid(initial_attachment_ready[1]) != ready[0] or
                not identity.process_alive(initial_attachment_ready[1]) or
                entry[0] < 0 or identity._pidfd_pid(entry[0]) != ready[0] or
                not identity.process_alive(entry[0]) or
                identity._start_ticks(ready[0]) != ready[6] or
                identity._start_ticks(ready[0]) != record[11] or
                record[5] != ready[0] or record[6] != ready[4] or
                record[8:10] != (0, 0) or record[14:17] !=
                    (context.epoch, context.deadline_ns, context.nonce) or
                record[20] != 2 or record[24:28] !=
                    (ready[7], ready[8], relay_cookie, ready[9]) or
                context.worker_process_slots[(0, 0)] != watch.get('process_slot') or
                (ready[7], ready[8]) != provider.slot_identities[0] or
                time.monotonic_ns() >= context.deadline_ns):
            raise ProcessLookupError('initial worker PID, slot, or immutable READY view changed')
        if provider._used_slots not in ({0}, {0, 1}):
            raise PermissionError('initial worker C22 slot provenance changed')
        transport.broker._check_app_identity()
        if transport.broker.ready is not True or transport.broker.stopped:
            raise ProcessLookupError('C34 native broker is not ready/live with initial owner AUTH')
        provider._check_actor(context.deadline_ns)
        return True

    def _valid_private_initial_exit_observation(self, transport, context):
        evidence = getattr(self, '_private_initial_exit_observation', None)
        if not (type(evidence) is _PrivateInitialWorkerExitObservation and
            evidence.token is _PRIVATE_INITIAL_EXIT_TOKEN and
            evidence.controller is self and evidence.context is context and
            evidence.transport is transport and evidence.provider is self.c22_provider and
            type(self.profile) is _c34_profile_module().PrivateNewC34InteropProfile and
            getattr(self.c22_provider, '_source_committed', False) is True and
            getattr(context, '_completed_master_barriers', set()) == {(1, 5), (1, 6)} and
            (1, 1) in getattr(context, '_source_shell_committed_plans', {}) and
            (0, 0) in getattr(context, 'workers', {}) and
            evidence.pidfd == context.workers[(0, 0)][0] and
            evidence.record == context.workers[(0, 0)][1] and
            evidence.channel is getattr(context, 'worker_channels', {}).get((0, 0)) and
            not self.profile.origin_module.identity.process_alive(evidence.pidfd) and
            evidence.ready_identity == getattr(transport, 'ready_identity', None) and
            evidence.watch == getattr(transport, 'watch', None) and
            evidence.cycle_proof is context.initial_cycle_proof):
            return False
        try:
            channel_identity = _source_bootstrap_channel_identity(evidence.channel)
            ready = evidence.ready_identity
            watch = evidence.watch
            provider = evidence.provider
            record = evidence.record
            broker = transport.broker
            broker._check_app_identity()
            return (channel_identity == evidence.channel_identity ==
                    getattr(transport, 'initial_bootstrap_channel_identity', None) and
                context.worker_process_slots.get((0, 0)) == watch.get('process_slot') and
                (ready[7], ready[8]) == provider.slot_identities[0] and
                (record[5], record[6], record[8], record[9], record[24], record[25], record[27]) ==
                    (ready[0], ready[4], 0, 0, ready[7], ready[8], ready[9]) and
                broker.ready is True and broker.stopped is False)
        except (OSError, PermissionError, AttributeError, IndexError, KeyError, TypeError):
            return False

    def _check_private_initial_worker_exit_binding(self, transport, provider, context):
        """Retain an exact old-worker exit observation after private COMMIT.

        This records only that the authenticated (0,0) process exited. C28
        listener retirement and C34 VERIFY remain separate, unimplemented gates.
        """
        private_profile = _c34_profile_module().PrivateNewC34InteropProfile
        attach_module = sys.modules.get(_ATTACH_NAME)
        if (type(self.profile) is not private_profile or attach_module is None or
                type(transport) is not _SourceInitialWorkerTransport or
                transport is not self.initial_worker_binding or
                transport.context is not context or transport.broker is not self.broker_readiness or
                not transport.authenticated or transport.settled or
                type(transport.attachment) is not getattr(attach_module, 'SourceAttachment', None) or
                context.control_only is not True or provider is not self.c22_provider or
                provider.context is not context or
                getattr(provider, '_source_committed', False) is not True or
                type(getattr(self, '_first_candidate_worker_grant', None)) is not
                    _FirstCandidateWorkerGrant or
                self._first_candidate_worker_grant.token is not _FIRST_CANDIDATE_GRANT_TOKEN or
                self._first_candidate_worker_grant.controller is not self or
                self._first_candidate_worker_grant.context is not context or
                self._first_candidate_worker_grant.provider is not provider or
                self._first_candidate_worker_grant.initial_transport is not transport or
                self._first_candidate_worker_grant.accepted_request is None or
                self._first_candidate_worker_grant.accepted_request is not
                    getattr(self, '_accepted_candidate_worker_request', None) or
                not self._first_candidate_worker_grant_consumed or
                not self._first_candidate_activation_delivered or
                getattr(context, '_completed_master_barriers', set()) != {(1, 5), (1, 6)} or
                (1, 1) not in getattr(context, '_source_shell_committed_plans', {}) or
                set(context.workers) != {(0, 0), (1, 1)} or
                set(context.worker_channels) != {(0, 0), (1, 1)} or
                context.worker_proofs.get((0, 0)) is not context.initial_cycle_proof or
                provider._used_slots != {0, 1}):
            raise PermissionError('initial worker exit is outside the exact private post-COMMIT phase')
        identity = self.profile.origin_module.identity
        attachment = transport.attachment
        old_fd, old_record = context.workers[(0, 0)]
        candidate_fd, candidate_record = context.workers[(1, 1)]
        ready = transport.ready_identity
        watch = transport.watch
        old_attachment = attachment.ready
        candidate_attachment = attachment.candidate_ready
        channel = context.worker_channels[(0, 0)]
        try:
            channel_identity = _source_bootstrap_channel_identity(channel)
            transport.broker._check_app_identity()
        except (OSError, PermissionError, AttributeError) as exc:
            raise PermissionError('retained initial bootstrap channel or broker identity changed') from exc
        if (type(ready) is not tuple or len(ready) != 10 or
                type(watch) is not dict or type(old_attachment) is not tuple or
                len(old_attachment) != 2 or tuple(old_attachment[0]) != ready or
                type(candidate_attachment) is not tuple or len(candidate_attachment) != 2 or
                type(old_record) is not tuple or len(old_record) < 28 or
                type(candidate_record) is not tuple or len(candidate_record) < 28 or
                transport.worker_view != _InitialOwnerAuthView(
                    transport.worker_pidfd, ready[0], ready[4], ready[3], ready[6],
                    ready[7], ready[8], ready[9]) or
                (watch.get('pid'), watch.get('tid'), watch.get('role'),
                    watch.get('start'), watch.get('slot_device'), watch.get('slot_inode'),
                    watch.get('cookie'), watch.get('source_epoch'), watch.get('generation')) !=
                    (ready[0], ready[4], ready[3], ready[6], ready[7], ready[8],
                        ready[9], 0, 0) or
                transport.initial_bootstrap_channel_identity != channel_identity or
                context.worker_process_slots.get((0, 0)) != watch.get('process_slot') or
                (ready[7], ready[8]) != provider.slot_identities[0] or
                transport.broker.ready is not True or transport.broker.stopped is not False or
                (old_record[5], old_record[6], old_record[8], old_record[9],
                    old_record[11], old_record[24], old_record[25], old_record[27]) !=
                    (ready[0], ready[4], 0, 0, ready[6], ready[7], ready[8], ready[9]) or
                candidate_attachment[0] != self._first_candidate_observed_ready or
                (candidate_record[5], candidate_record[6], candidate_record[8],
                    candidate_record[9], candidate_record[11]) !=
                    (candidate_attachment[0][0], candidate_attachment[0][4], 1, 1,
                        candidate_attachment[0][6])):
            raise PermissionError('retained initial/candidate READY associations changed after COMMIT')
        old_pidfds = (old_fd, transport.worker_pidfd, old_attachment[1])
        if (any(type(fd) is not int or fd < 0 for fd in old_pidfds) or
                any(identity.process_alive(fd) for fd in old_pidfds)):
            raise ProcessLookupError('initial worker pidfd exit is not yet observed on every retained view')
        candidate_pidfds = (candidate_fd, self._first_candidate_observed_pidfd,
            candidate_attachment[1])
        if (any(type(fd) is not int or fd < 0 for fd in candidate_pidfds) or
                any(not identity.process_alive(fd) for fd in candidate_pidfds) or
                identity._start_ticks(candidate_record[5]) != candidate_record[11]):
            raise ProcessLookupError('committed candidate pidfd is not live in every retained view')
        if (attachment.launch is not self.launch or attachment.context is not context or
                not attachment.attached or attachment.helper is None or
                attachment.helper.poll() is not None or
                attachment.master_pidfd != self.launch.master_pidfd or
                attachment.master_pidfd != context.master.pidfd or
                attachment.master_pid != context.master.pid or
                attachment.master_start != context.master.start_ticks or
                attachment.binary_hash != context.binary_hash or
                not attach_module._alive(attachment.helper_pidfd) or
                not attach_module._alive(attachment.master_pidfd)):
            raise ProcessLookupError('source attachment/helper/master is not live in the pending exit phase')
        poller = select.poll()
        if attachment.channel is None or attachment.channel.fileno() < 0:
            raise ConnectionError('source attachment control channel is unavailable')
        poller.register(attachment.channel.fileno(), select.POLLIN | select.POLLHUP |
            select.POLLERR | select.POLLNVAL)
        if poller.poll(0):
            raise ConnectionError('source attachment channel changed during initial worker exit')
        previous = getattr(self, '_private_initial_exit_observation', None)
        if previous is None:
            previous = _PrivateInitialWorkerExitObservation(_PRIVATE_INITIAL_EXIT_TOKEN,
                self, context, transport, provider, old_fd, old_record,
                channel, channel_identity,
                context.initial_cycle_proof, ready, watch, time.monotonic_ns())
            self._private_initial_exit_observation = previous
        if (not self._valid_private_initial_exit_observation(transport, context) or
                previous.ready_identity != ready or previous.watch != watch):
            raise PermissionError('pending initial worker exit observation was replaced')
        return previous

    def _check_first_candidate_phase(self, transport):
        """Check the narrow control-only (0,0)+(1,1) grant/READY phase."""
        context = self.bootstrap_context
        provider = self.c22_provider
        cap = self._first_candidate_worker_grant
        observed = getattr(self, '_first_candidate_observed_ready', None)
        pending_receipt_ok = (
            self._first_candidate_pending_error is None and
            self._first_candidate_pending_watch is not None and
            self._first_candidate_pending_ready is not None and
            provider is not None and
            context is not None and
            not getattr(context, 'worker_ready_receivers', {}) and
            provider._first_candidate_pending_watch is self._first_candidate_pending_watch and
            provider._first_candidate_pending_ready is self._first_candidate_pending_ready)
        observed_receipt_ok = (
            observed is not None and self._first_candidate_pending_ready is None and
            provider is not None and provider._first_candidate_pending_ready is None and
            provider._first_candidate_pending_watch is self._first_candidate_pending_watch and
            context is not None and
            not getattr(context, 'worker_ready_receivers', {}) and
            getattr(transport.attachment, 'candidate_ready', None) is not None and
            tuple(transport.attachment.candidate_ready[0]) == observed)
        activated = getattr(self, '_first_candidate_activation_delivered', False)
        prepared = getattr(self, '_first_candidate_source_prepared', None)
        registered_preparation = getattr(context, '_source_route_preparations', {}).get(
            id(prepared)) if context is not None and prepared is not None else None
        private_profile = type(self.profile) is _c34_profile_module().PrivateNewC34InteropProfile
        barriers = getattr(context, '_completed_master_barriers', set()) if context is not None else set()
        park = getattr(provider, '_source_park_evidence', None) if provider is not None else None
        park_join = getattr(context, '_source_route_park_joins', {}).get(
            id(prepared)) if context is not None and prepared is not None else None
        committed = bool(getattr(provider, '_source_committed', False)) if provider is not None else False
        private_master_phase_ok = (
            (barriers == set() and park is None and park_join is None and not committed) or
            (barriers == {(1, 5)} and park is not None and park_join is not None and
                park_join.prepared is prepared and park_join.park is park and
                park.context is context and park.provider is provider and not committed) or
            (barriers == {(1, 5), (1, 6)} and park is not None and park_join is not None and
                park_join.prepared is prepared and park_join.park is park and
                park.context is context and park.provider is provider and committed and
                (1, 1) in getattr(context, '_source_shell_committed_plans', {})))
        master_phase_ok = (private_master_phase_ok if private_profile else
            not barriers and not getattr(context, '_source_shell_committed_plans', {}))
        activation_state_ok = (
            not activated and not getattr(context, '_activated_workers', set()) and
                not getattr(context, '_activation_attempts', set())
            if not activated else
            type(prepared) is SimpleNamespace and
                registered_preparation is getattr(prepared, '_source_route_preparation', None) and
                registered_preparation is not None and registered_preparation.context is context and
                registered_preparation.park is None and
                registered_preparation.raw_prepared_ack ==
                    registered_preparation.expected_prepared_record and
                getattr(context, '_activated_workers', set()) == {(1, 1)} and
                getattr(context, '_activation_attempts', set()) == {(1, 1)} and
                id(prepared) in getattr(context, '_source_prepared_activation_attempts', set()))
        if (type(transport) is not _SourceInitialWorkerTransport or
                transport is not self.initial_worker_binding or
                transport.context is not context or transport.broker is not self.broker_readiness or
                not transport.authenticated or transport.settled or
                transport.attachment is None or context is None or
                context.control_only is not True or provider is None or
                provider.context is not context or provider._used_slots != {0, 1} or
                type(cap) is not _FirstCandidateWorkerGrant or
                cap is not self._first_candidate_worker_grant or
                not self._first_candidate_worker_grant_consumed or
                cap.accepted_request is not self._accepted_candidate_worker_request or
                self._first_candidate_worker_pending is not True or
                not (pending_receipt_ok or observed_receipt_ok) or
                not activation_state_ok or
                set(context.workers) != {(0, 0), (1, 1)} or
                set(context.worker_channels) != {(0, 0), (1, 1)} or
                set(context.worker_process_slots) != {(0, 0), (1, 1)} or
                set(context.worker_proofs) != {(0, 0), (1, 1)} or
                not master_phase_ok):
            raise PermissionError('control-only source candidate phase is not the exact one-shot grant')
        old_worker_pidfd = context.workers[(0, 0)][0]
        initial_exit = self._valid_private_initial_exit_observation(transport, context)
        if initial_exit or (private_profile and
                barriers == {(1, 5), (1, 6)} and committed and
                not self.profile.origin_module.identity.process_alive(old_worker_pidfd)):
            self._check_private_initial_worker_exit_binding(transport, provider, context)
        else:
            self._check_authenticated_initial_worker_core(transport, provider)
        phase_deadline = context.deadline_ns if activated else cap.grant_deadline_ns
        provider._check_actor(phase_deadline)
        context.live(phase_deadline)
        initial = context.workers[(0, 0)][1]
        candidate = context.workers[(1, 1)][1]
        candidate_channel = context.worker_channels[(1, 1)]
        candidate_proof = context.worker_proofs[(1, 1)]
        if (context.worker_proofs[(0, 0)] is not context.initial_cycle_proof or
                cap.initial_cycle_proof is not context.initial_cycle_proof or
                candidate_proof is not cap.cycle_proof or
                cap.master_identity != (context.master.pid, context.master.start_ticks,
                    context.master.pidfd) or
                self._first_candidate_endpoint_identity(candidate_channel) != cap.channel_identity or
                self._first_candidate_socket_cookie(candidate_channel) != cap.channel_cookie or
                initial[8:10] != (0, 0) or candidate[8:10] != (1, 1) or
                (candidate[9], candidate[8]) != (1, 1) or
                candidate[14:17] != (context.epoch, context.deadline_ns, context.nonce) or
                context.worker_process_slots[(1, 1)] is None or
                time.monotonic_ns() >= phase_deadline):
            raise PermissionError('source first-candidate key, proof, or deadline changed')
        if observed is not None:
            ready = observed
            pidfd = self._first_candidate_observed_pidfd
            if (pidfd < 0 or self._first_candidate_pending_watch.get('pid') != candidate[5] or
                    self._first_candidate_pending_watch.get('process_slot') !=
                        context.worker_process_slots[(1, 1)] or
                    ready[0] != candidate[5] or ready[3] != 1 or
                    ready[6] != candidate[11] or ready[7:9] != candidate[24:26] or
                    ready[9] != candidate[27] or
                    self.profile.origin_module.identity._pidfd_pid(pidfd) != ready[0] or
                    not self.profile.origin_module.identity.process_alive(pidfd)):
                raise PermissionError('observed candidate READY no longer matches its retained proof')
        return True

    @staticmethod
    def _first_candidate_endpoint_identity(endpoint):
        info = os.fstat(endpoint.fileno())
        return (info.st_dev, info.st_ino, info.st_mode,
            fcntl.fcntl(endpoint.fileno(), fcntl.F_GETFL),
            fcntl.fcntl(endpoint.fileno(), fcntl.F_GETFD))

    @staticmethod
    def _first_candidate_socket_cookie(endpoint):
        return struct.unpack('=Q', endpoint.getsockopt(socket.SOL_SOCKET,
            getattr(socket, 'SO_COOKIE', 57), 8))[0]

    def mint_first_candidate_worker_grant(self, transport, provider, channel,
            packet, credentials, relay, grant_deadline_ns):
        """Mint one capability only for the exact request captured by our listener."""
        if (threading.current_thread() is not threading.main_thread() or
                self._first_candidate_worker_grant is not None or
                self._first_candidate_worker_grant_consumed):
            raise PermissionError('first candidate worker grant is unavailable')
        context = self.bootstrap_context
        if (type(grant_deadline_ns) is not int or context is None or
                time.monotonic_ns() >= grant_deadline_ns or
                grant_deadline_ns > context.deadline_ns):
            raise TimeoutError('first candidate grant exceeds the immutable source deadline')
        accepted = self._accepted_candidate_worker_request
        if (type(accepted) is not _AcceptedCandidateWorkerRequest or
                accepted.token is not _ACCEPTED_CANDIDATE_REQUEST_TOKEN or
                accepted.controller is not self or accepted.listener is not self.listener or
                accepted.channel is not channel or accepted.packet != packet or
                accepted.credentials != tuple(credentials) or
                accepted.deadline_ns != grant_deadline_ns or accepted.worker_key != (1, 1) or
                self._first_candidate_endpoint_identity(self.listener) != accepted.listener_identity or
                self._first_candidate_socket_cookie(self.listener) != accepted.listener_cookie or
                self._first_candidate_endpoint_identity(channel) != accepted.channel_identity or
                self._first_candidate_socket_cookie(channel) != accepted.channel_cookie):
            raise PermissionError('first candidate grant lacks the exact owned-listener receive receipt')
        self._check_initial_worker_binding(transport)
        if (self.launch is None or self.launch.context is not context or
                self.c22_provider is not provider or provider.context is not context or
                provider.broker_readiness is not self.broker_readiness or
                context.control_only is not True or not transport.authenticated or
                transport.settled or provider._closed or provider._used_slots != {0} or
                type(context.workers) is not dict or set(context.workers) != {(0, 0)} or
                set(context.worker_channels) != {(0, 0)} or
                set(context.worker_process_slots) != {(0, 0)} or
                set(context.worker_proofs) != {(0, 0)} or
                getattr(context, '_activated_workers', set()) or
                getattr(context, '_completed_master_barriers', set()) or
                getattr(context, '_source_shell_committed_plans', {})):
            raise PermissionError('first candidate grant lacks the retained authenticated initial phase')
        provider._check_actor(grant_deadline_ns)
        if (type(packet) is not bytes or
                type(channel) is not socket.socket or
                type(relay) is not socket.socket or
                channel is relay or channel is transport.relay or
                relay is transport.relay):
            raise PermissionError('first candidate grant endpoint or request type is invalid')
        cookie_option = getattr(socket, 'SO_COOKIE', 57)
        initial_cookies = tuple(transport._endpoint_cookies)
        if (len(initial_cookies) != 3 or any(cookie <= 0 for cookie in initial_cookies) or
                len(set(initial_cookies)) != 3):
            raise PermissionError('initial C31 endpoint cookie snapshot is invalid')
        for endpoint in (channel, relay):
            if (endpoint.family != socket.AF_UNIX or
                    endpoint.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_SEQPACKET or
                    endpoint.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) != 1 or
                    not (fcntl.fcntl(endpoint.fileno(), fcntl.F_GETFD) & fcntl.FD_CLOEXEC) or
                    not (fcntl.fcntl(endpoint.fileno(), fcntl.F_GETFL) & os.O_NONBLOCK)):
                raise PermissionError('candidate C31 endpoints must be credentialed nonblocking CLOEXEC seqpackets')
        channel_cookie = self._first_candidate_socket_cookie(channel)
        relay_cookie = self._first_candidate_socket_cookie(relay)
        if (not channel_cookie or not relay_cookie or channel_cookie == relay_cookie or
                channel_cookie in initial_cookies or relay_cookie in initial_cookies):
            raise PermissionError('candidate control/relay endpoint aliases the initial C31 transport')
        fields = context._unpack_request(packet, 1, 1)
        master = context.master
        identity = self.profile.origin_module.identity
        peer = struct.unpack('=3i', channel.getsockopt(socket.SOL_SOCKET,
            socket.SO_PEERCRED, 12))
        if (credentials != peer or len(fields) < 29 or
                fields[5] <= 0 or fields[6] != fields[5] or
                peer != (fields[5], os.getuid(), os.getgid()) or
                fields[7] != master.pid or fields[8:10] != [1, 1] or
                fields[12] != master.start_ticks or
                fields[14:17] != [context.epoch, context.deadline_ns, context.nonce] or
                any(fields[17:29]) or grant_deadline_ns > fields[15]):
            raise PermissionError('candidate request does not name first source key (1, 1)')
        master_identity = (master.pid, master.start_ticks, master.pidfd)
        if (identity._pidfd_pid(master.pidfd) != master.pid or
                not identity.process_alive(master.pidfd) or
                identity._start_ticks(master.pid) != master.start_ticks or
                identity._pidfd_pid(transport.worker_pidfd) != transport.ready_identity[0] or
                not identity.process_alive(transport.worker_pidfd)):
            raise ProcessLookupError('original master or retained role-0 worker PIDFD changed')
        if (self.profile.origin_module.parent_pid(fields[5]) != master.pid or
                identity._start_ticks(fields[5]) != fields[11] or
                identity._sha256(f'/proc/{fields[5]}/exe') != context.binary_hash):
            raise ProcessLookupError('first candidate is not a live child of the original source master')
        cycle_proof = context._fresh_candidate_cycle_proof(fields)
        context._cycle_token_live(master.pid, cycle_proof.opaque_cycle_token)
        context._cycle_token_live(fields[5], cycle_proof.opaque_cycle_token)
        provider_module = _c22_provider_module()
        slot_info = provider_module._validate_broker_fifo(provider.slots[1],
            'first candidate source slot')
        if (provider.slot_identities is None or
                (slot_info.st_dev, slot_info.st_ino) != provider.slot_identities[1]):
            raise PermissionError('first candidate source slot changed its held FIFO identity')
        relay_peer = struct.unpack('=3i', relay.getsockopt(socket.SOL_SOCKET,
            socket.SO_PEERCRED, 12))
        if relay_peer != (os.getpid(), os.getuid(), os.getgid()):
            raise PermissionError('candidate relay was not created by this SDK actor')
        if self.launch.live_supervisor is not None:
            self.launch.live_supervisor(grant_deadline_ns)
        context.live()
        if (type(grant_deadline_ns) is not int or
                time.monotonic_ns() >= grant_deadline_ns or
                grant_deadline_ns > context.deadline_ns):
            raise TimeoutError('first candidate grant expired before capability retention')
        cap = _FirstCandidateWorkerGrant(_FIRST_CANDIDATE_GRANT_TOKEN,
            self, context, provider, transport, channel,
            self._first_candidate_endpoint_identity(channel), channel_cookie,
            bytes(packet), tuple(credentials), relay,
            self._first_candidate_endpoint_identity(relay), relay_cookie,
            grant_deadline_ns, (1, 1), cycle_proof, master_identity,
            context.worker_proofs[(0, 0)], accepted)
        self._first_candidate_worker_grant = cap
        return cap

    def _validate_first_candidate_worker_grant(self, cap, provider, channel,
            packet, credentials, relay, grant_deadline_ns):
        if (type(cap) is not _FirstCandidateWorkerGrant or
                cap.token is not _FIRST_CANDIDATE_GRANT_TOKEN or
                self._first_candidate_worker_grant_consumed or
                self._first_candidate_worker_grant is not cap or
                cap.controller is not self or cap.context is not self.bootstrap_context or
                cap.accepted_request is not self._accepted_candidate_worker_request or
                type(cap.accepted_request) is not _AcceptedCandidateWorkerRequest or
                cap.accepted_request.token is not _ACCEPTED_CANDIDATE_REQUEST_TOKEN or
                cap.accepted_request.controller is not self or
                cap.accepted_request.listener is not self.listener or
                cap.accepted_request.channel is not channel or
                cap.accepted_request.packet != packet or
                cap.accepted_request.credentials != tuple(credentials) or
                cap.accepted_request.deadline_ns != grant_deadline_ns or
                self._first_candidate_socket_cookie(self.listener) != cap.accepted_request.listener_cookie or
                self._first_candidate_endpoint_identity(self.listener) != cap.accepted_request.listener_identity or
                self._first_candidate_socket_cookie(channel) != cap.accepted_request.channel_cookie or
                self._first_candidate_endpoint_identity(channel) != cap.accepted_request.channel_identity or
                cap.provider is not provider or cap.initial_transport is not self.initial_worker_binding or
                cap.channel is not channel or cap.packet != packet or
                cap.credentials != tuple(credentials) or cap.relay is not relay or
                type(grant_deadline_ns) is not int or
                cap.grant_deadline_ns != grant_deadline_ns or cap.worker_key != (1, 1) or
                time.monotonic_ns() >= grant_deadline_ns or
                grant_deadline_ns > cap.context.deadline_ns or
                cap.context.control_only is not True or
                self._first_candidate_socket_cookie(channel) != cap.channel_cookie or
                self._first_candidate_socket_cookie(relay) != cap.relay_cookie or
                self._first_candidate_endpoint_identity(channel) != cap.channel_identity or
                self._first_candidate_endpoint_identity(relay) != cap.relay_identity):
            raise PermissionError('first candidate grant is copied, stale, or joined to another request')
        self._check_initial_worker_binding(cap.initial_transport)
        if (type(grant_deadline_ns) is not int or
                time.monotonic_ns() >= grant_deadline_ns or
                grant_deadline_ns > cap.context.deadline_ns):
            raise TimeoutError('first candidate grant expired during initial-binding recheck')
        return True

    def _consume_first_candidate_worker_grant(self, cap, context, provider,
            channel, packet, credentials, relay, grant_deadline_ns):
        if (type(cap) is not _FirstCandidateWorkerGrant or
                cap.token is not _FIRST_CANDIDATE_GRANT_TOKEN or
                self._first_candidate_worker_grant_consumed or
                self._first_candidate_worker_grant is not cap or
                cap.controller is not self or cap.context is not context or
                cap.accepted_request is not self._accepted_candidate_worker_request or
                type(cap.accepted_request) is not _AcceptedCandidateWorkerRequest or
                cap.accepted_request.token is not _ACCEPTED_CANDIDATE_REQUEST_TOKEN or
                cap.accepted_request.controller is not self or
                cap.accepted_request.listener is not self.listener or
                cap.accepted_request.channel is not channel or
                cap.accepted_request.packet != packet or
                cap.accepted_request.credentials != tuple(credentials) or
                cap.accepted_request.deadline_ns != grant_deadline_ns or
                self._first_candidate_socket_cookie(self.listener) != cap.accepted_request.listener_cookie or
                self._first_candidate_endpoint_identity(self.listener) != cap.accepted_request.listener_identity or
                self._first_candidate_socket_cookie(channel) != cap.accepted_request.channel_cookie or
                self._first_candidate_endpoint_identity(channel) != cap.accepted_request.channel_identity or
                context is not self.bootstrap_context or cap.provider is not provider or
                cap.channel is not channel or cap.packet != packet or
                cap.credentials != tuple(credentials) or cap.relay is not relay or
                type(grant_deadline_ns) is not int or
                cap.grant_deadline_ns != grant_deadline_ns or
                time.monotonic_ns() >= grant_deadline_ns or
                grant_deadline_ns > context.deadline_ns or
                self._first_candidate_socket_cookie(channel) != cap.channel_cookie or
                self._first_candidate_socket_cookie(relay) != cap.relay_cookie or
                self._first_candidate_endpoint_identity(channel) != cap.channel_identity or
                self._first_candidate_endpoint_identity(relay) != cap.relay_identity):
            raise PermissionError('first candidate grant cannot be consumed by this exact request')
        if (type(grant_deadline_ns) is not int or
                time.monotonic_ns() >= grant_deadline_ns or
                grant_deadline_ns > context.deadline_ns):
            raise TimeoutError('first candidate grant expired before capability consumption')
        self._first_candidate_worker_grant_consumed = True
        return cap

    def validate_settled_actors(self):
        """Check actor death without closing descriptors needed for receipts."""
        launch = self.launch
        if launch is None or launch.process is None or launch.process.poll() is None:
            raise RuntimeError('original supervisor remains live during settlement')
        known = [launch.pidfd, launch.master_pidfd, launch.origin_pidfd,
            launch.native_io_pidfd]
        context = getattr(launch, 'context', None)
        if context is not None:
            known.extend([context.slim_pidfd,
                *(fd for fd, _ in context.workers.values())])
        identity = self.profile.origin_module.identity
        if any(fd >= 0 and identity.process_alive(fd) for fd in known):
            raise RuntimeError('source actors remain live during settlement')
        receipt = getattr(launch, 'backend_receipt', None)
        if receipt is not None and identity.process_alive(receipt.pidfd):
            raise RuntimeError('retained backend actor remains live during settlement')
        return True

    def close_settled(self):
        if self.launch is None:
            self._close_unstarted()
            return
        settlement = self.launch.observe_settlement()
        if not settlement.get('settled'):
            raise RuntimeError('original shell launch has not settled')
        # Check liveness while all exact actor descriptors are still retained.
        # Capsule close rereads the original settlement files through output_fd.
        self.validate_settled_actors()
        c22_provider = getattr(self, 'c22_provider', None)
        if c22_provider is not None:
            if type(self.profile) is _c34_profile_module().PrivateNewC34InteropProfile:
                proof = getattr(self, '_private_source_settlement', None)
                context = self.bootstrap_context
                if proof is None or context._completed_retirements.get((1, 1)) is not proof:
                    raise PermissionError('private C22 CLOSE requires the recorded worker SETTLED')
                c22_provider.close_source_capabilities_after_settlement(proof, self.deadline_ns)
            else:
                c22_provider.close()
            self.c22_provider = None
        transport = getattr(self, '_initial_transport', None)
        if transport is not None:
            transport.settled = True
            if transport.attachment is not None:
                transport.attachment.close()
                transport.attachment = None
            if transport.receiver is not None:
                transport.receiver.close()
                transport.receiver = None
            if transport.worker_pidfd >= 0:
                os.close(transport.worker_pidfd)
                transport.worker_pidfd = -1
            transport.close_relay_auth_after_send()
            self._initial_transport = None
            self.initial_worker_binding = None
        close_profile = getattr(self.profile, 'close', None)
        if callable(close_profile):
            close_profile()
        self.capsules.close(self.launch)
        # The controller owns the accepted slim socket; the bootstrap context
        # only borrows that same endpoint for its correlated STOP path.
        control_channel = getattr(self, 'control_slim_channel', None)
        if control_channel is not None:
            context = getattr(self.launch, 'context', None)
            if context is not None and getattr(context, 'slim_channel', None) is control_channel:
                context.slim_channel = None
            self.control_slim_channel = None
            control_channel.close()
        # Only after capsules have independently re-read settlement may Origin
        # close the output descriptor and actor evidence it owns.
        self.launch.close()
        # A failed/unknown post-recv master request keeps its accepted endpoint
        # anchored until settlement has been validated through both Origin and
        # the capsule. Release these exact descriptors only at this boundary.
        for channel in getattr(self, '_private_source_master_channels', ()):
            try:
                if channel.fileno() >= 0:
                    channel.close()
            except OSError:
                pass
        self._private_source_master_channels = []
        self._private_runtime_artifacts = None
        # Candidate request/READY endpoints can outlive Context's own close:
        # the accepted socket is controller-owned, and a returned READY
        # receiver is mirrored by both Provider and Controller. Release these
        # exact anchors only after the independently re-read settlement above.
        accepted = getattr(self, '_accepted_candidate_worker_request', None)
        accepted_channel = getattr(accepted, 'channel', None)
        if accepted_channel is not None:
            try:
                if accepted_channel.fileno() >= 0:
                    accepted_channel.close()
            except OSError:
                pass
        ready = getattr(self, '_first_candidate_pending_ready', None)
        if ready is not None:
            try:
                if ready.fileno() >= 0:
                    ready.close()
            except OSError:
                pass
        provider = c22_provider
        if provider is not None:
            provider._first_candidate_pending_ready = None
            provider._first_candidate_pending_watch = None
            provider._first_candidate_pending_error = None
        self._first_candidate_pending_ready = None
        self._first_candidate_pending_watch = None
        self._first_candidate_pending_error = None
        self._first_candidate_worker_grant = None
        self._accepted_candidate_worker_request = None
        self._first_candidate_observed_ready = None
        self._first_candidate_worker_pending = False
        relay_anchor = getattr(self, '_first_candidate_relay_anchor', None)
        if relay_anchor is not None:
            relay_anchor.close()
            self._first_candidate_relay_anchor = None
        observed_pidfd = getattr(self, '_first_candidate_observed_pidfd', -1)
        if observed_pidfd >= 0:
            os.close(observed_pidfd)
            self._first_candidate_observed_pidfd = -1
        if self.listener is not None:
            endpoint = self.listener.getsockname()
            info = os.stat(endpoint, follow_symlinks=False)
            if (info.st_dev, info.st_ino) != self.socket_identity:
                raise PermissionError('source origin socket path was replaced')
            self.listener.close()
            os.unlink(endpoint)
            self.listener = None
        self.launch = None
        self.started = False
