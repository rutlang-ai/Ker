#!/usr/bin/env python3
"""Dedicated subreaper for one pinned control-only Nginx master subtree."""
import argparse
import array
import ctypes
import errno
import hashlib
import importlib.util
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import sys
import time

_WIRE_SPEC = importlib.util.spec_from_file_location(
    '_ker_nginx_companion_wire', Path(__file__).resolve().with_name(
        'nginx_companion_wire.py'))
if _WIRE_SPEC is None or _WIRE_SPEC.loader is None:
    raise ImportError('cannot load companion wire codec beside this helper')
wire = importlib.util.module_from_spec(_WIRE_SPEC)
_WIRE_SPEC.loader.exec_module(wire)

SO_PEERPIDFD = getattr(socket, 'SO_PEERPIDFD', 77)
UCRED = struct.Struct('=3i')
ENV_KEYS = frozenset(('LD_PRELOAD', 'KER_SOCKET_BROKER_PATH',
    'KER_FSTACK_NGINX_INI', 'KER_FSTACK_RUNTIME_TRACE',
    'KER_NGINX_OWNER_MODULE_PATH', 'KER_NGINX_OWNER_MODULE_SHA256',
    'KER_NGINX_CYCLE_FD', 'KER_NGINX_CYCLE_NONCE',
    'KER_NGINX_CYCLE_RUNTIME_NONCE', 'KER_NGINX_CYCLE_RUNTIME_EPOCH',
    'KER_NGINX_CYCLE_WORKER_PROFILE_SHA256',
    'KER_NGINX_CYCLE_OUTER_EXE_SHA256',
    'KER_NGINX_RX_OWNER_RELAY_FD',
    'KER_NGINX_RX_OWNER_RELAY_SUPERVISOR_PID',
    'KER_NGINX_RX_OWNER_RELAY_NONCE', 'KER_NGINX_RX_OWNER_RELAY_EPOCH',
    'KER_NGINX_SOURCE_FLOWMAP_TEST', 'KER_NGINX_SOURCE_ADMISSION_RELAY',
    'KER_NGINX_CANDIDATE_SLOT_FD',
    'KER_NGINX_SOURCE_ADMISSION_TEST_DELAY_US',
    'KER_C16_TEST_PUMP_FAIL_AFTER_STEP'))
START_PHASE = 1
RELOAD_PHASE = 2
STOP_PHASE = 3
MAX_CONFIG_BYTES = 4 * 1024 * 1024
MAX_CONFIG_TOKEN_BYTES = 4096
MAX_CONFIG_DIRECTIVES = 65536
SIGNAL_HANDLER_READY_TIMEOUT = 5.0
REQUIRED_MASTER_SIGNALS = ((1 << (signal.SIGHUP - 1)) |
    (1 << (signal.SIGQUIT - 1)))
OWNER_READY_MAGIC = 0x4B4E5244
OWNER_READY_VERSION = 2
OWNER_READY_RECORD = struct.Struct('=IHHIIQQQIIQQ')
SO_COOKIE = getattr(socket, 'SO_COOKIE', 57)


def start_ticks(pid):
    text = Path(f'/proc/{pid}/stat').read_text(encoding='ascii')
    close = text.rfind(')')
    fields = text[close + 2:].split()
    if close < 0 or len(fields) <= 19:
        raise RuntimeError('malformed process stat')
    value = int(fields[19], 10)
    if value <= 0:
        raise RuntimeError('invalid process start time')
    return value


def pidfd_pid(fd):
    for line in Path(f'/proc/self/fdinfo/{fd}').read_text().splitlines():
        if line.startswith('Pid:\t'):
            value = int(line.split('\t', 1)[1])
            if value > 0:
                return value
    raise OSError(9, 'invalid pidfd')


def process_parent(pid):
    text = Path(f'/proc/{pid}/stat').read_text(encoding='ascii')
    close = text.rfind(')')
    fields = text[close + 2:].split() if close >= 0 else []
    if len(fields) <= 1:
        raise RuntimeError('malformed worker process stat')
    return int(fields[1], 10)


def receive_owner_ready(endpoint, *, expected_cookie, binary_hash, master,
                         master_pidfd, master_start, supervisor_pidfd,
                         supervisor_pid, supervisor_start, expected_role=0,
                         expected_slot=None, timeout=15.0):
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('Nginx owner READY timed out')
        poller = select.poll()
        poller.register(endpoint.fileno(), select.POLLIN | select.POLLHUP |
            select.POLLERR | select.POLLNVAL)
        poller.register(master_pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        poller.register(supervisor_pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        events = poller.poll(max(1, int(remaining * 1000)))
        if not events:
            continue
        ready_events = dict(events)
        if master_pidfd in ready_events or supervisor_pidfd in ready_events:
            raise PermissionError('pinned Nginx master or companion supervisor exited before worker READY')
        event = ready_events.get(endpoint.fileno(), 0)
        if event & (select.POLLHUP | select.POLLERR | select.POLLNVAL):
            raise ConnectionError('Nginx owner READY channel closed')
        if not event & select.POLLIN:
            continue
        packet, ancillary, flags, _ = endpoint.recvmsg(OWNER_READY_RECORD.size + 1,
            socket.CMSG_SPACE(UCRED.size) + socket.CMSG_SPACE(16 * 4),
            getattr(socket, 'MSG_CMSG_CLOEXEC', 0))
        credentials = []
        received_fds = []
        invalid = bool(flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC))
        try:
            for level, kind, body in ancillary:
                if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(body) == UCRED.size:
                    credentials.append(UCRED.unpack(body))
                elif level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    values = array.array('i')
                    values.frombytes(body[:len(body) - len(body) % values.itemsize])
                    received_fds.extend(values)
                    invalid = True
                else:
                    invalid = True
            if invalid or len(packet) != OWNER_READY_RECORD.size or len(credentials) != 1:
                raise ValueError('malformed Nginx owner READY record or ancillary data')
            (magic, version, length, role, reserved, slot_device, slot_inode,
             worker_start, worker_pid, owner_tid, cookie_value, reserved3) = \
                OWNER_READY_RECORD.unpack(packet)
            credential_pid, credential_uid, credential_gid = credentials[0]
            if (magic != OWNER_READY_MAGIC or version != OWNER_READY_VERSION or
                    length != OWNER_READY_RECORD.size or role != expected_role or reserved or reserved3 or
                    not slot_device or not slot_inode or cookie_value != expected_cookie or
                    worker_pid != credential_pid or credential_uid != os.getuid() or
                    credential_gid != os.getgid() or owner_tid <= 0 or
                    worker_start <= 0 or worker_pid <= 0):
                raise PermissionError('Nginx worker READY identity/slot/profile mismatch')
            if expected_slot is not None and (slot_device, slot_inode) != expected_slot:
                raise PermissionError('Nginx worker READY did not bind the exact delegated candidate slot')
            if (master.poll() is not None or not process_alive(master_pidfd) or
                    start_ticks(master.pid) != master_start or
                    process_parent(worker_pid) != master.pid or
                    start_ticks(worker_pid) != worker_start or
                    sha256_file(f'/proc/{worker_pid}/exe') != binary_hash or
                    not Path(f'/proc/{worker_pid}/task/{owner_tid}').exists() or
                    not process_alive(supervisor_pidfd) or
                    start_ticks(supervisor_pid) != supervisor_start):
                raise PermissionError('Nginx READY worker is stale or not a child of the pinned master')
            worker_pidfd = os.pidfd_open(worker_pid, 0)
            try:
                if (pidfd_pid(worker_pidfd) != worker_pid or
                        not process_alive(worker_pidfd) or
                        start_ticks(worker_pid) != worker_start or
                        process_parent(worker_pid) != master.pid):
                    raise PermissionError('Nginx READY worker PIDFD identity changed')
                return ((worker_pid, credential_uid, credential_gid, role, owner_tid,
                    0, worker_start, slot_device, slot_inode, cookie_value), worker_pidfd)
            except BaseException:
                os.close(worker_pidfd)
                raise
        finally:
            _close_fds(received_fds)


def process_alive(pidfd):
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    return not poller.poll(0)


def caught_signals(pid):
    """Return /proc SigCgt, the kernel's installed-handler bitset."""
    try:
        for line in Path(f'/proc/{pid}/status').read_text(encoding='ascii').splitlines():
            if line.startswith('SigCgt:\t'):
                value = int(line.split('\t', 1)[1], 16)
                if value < 0:
                    break
                return value
    except (OSError, UnicodeError, ValueError):
        pass
    raise RuntimeError('cannot read a valid Nginx master SigCgt status')


def wait_for_master_signal_handlers(master, master_pidfd, master_start,
        binary_hash, supervisor_pid, supervisor_start, supervisor_pidfd,
        supervisor_hash, deadline):
    """Publish no STARTED receipt until the pinned master catches HUP/QUIT."""
    while True:
        if time.monotonic() >= deadline:
            raise TimeoutError('Nginx master signal-handler readiness timed out')
        if (master.poll() is not None or not process_alive(master_pidfd) or
                start_ticks(master.pid) != master_start or
                sha256_file(f'/proc/{master.pid}/exe') != binary_hash):
            raise ProcessLookupError(
                'Nginx master exited or changed before handler readiness '
                f'(returncode={master.poll()!r}, alive={process_alive(master_pidfd)}, '
                f'start={start_ticks(master.pid)!r}, expected_start={master_start})')
        if (not process_alive(supervisor_pidfd) or
                start_ticks(supervisor_pid) != supervisor_start or
                sha256_file(f'/proc/{supervisor_pid}/exe') != supervisor_hash):
            raise ProcessLookupError('companion supervisor exited before handler readiness')
        if caught_signals(master.pid) & REQUIRED_MASTER_SIGNALS == REQUIRED_MASTER_SIGNALS:
            # Recheck all pinned identities immediately before STARTED.
            if (master.poll() is None and process_alive(master_pidfd) and
                    start_ticks(master.pid) == master_start and
                    sha256_file(f'/proc/{master.pid}/exe') == binary_hash and
                    process_alive(supervisor_pidfd) and
                    start_ticks(supervisor_pid) == supervisor_start and
                    sha256_file(f'/proc/{supervisor_pid}/exe') == supervisor_hash):
                if time.monotonic() >= deadline:
                    raise TimeoutError('Nginx signal-handler readiness timed out')
                return
        time.sleep(0.01)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.digest()


def read_bounded_config(path):
    with open(path, 'rb') as stream:
        return stream.read(MAX_CONFIG_BYTES + 1)


def validate_control_nginx_config(config_bytes):
    """Tokenize the pinned profile with ngx_conf_read_token-style boundaries.

    This is deliberately a bounded profile validator, not a replacement for
    Nginx's parser. Nginx -t remains authoritative for syntax and directive
    semantics. Reject include at the directive-name token anywhere so startup
    and reload cannot escape the hashed top-level file.
    """
    if not isinstance(config_bytes, bytes) or len(config_bytes) > MAX_CONFIG_BYTES:
        raise ValueError('Nginx configuration exceeds the bounded profile size')
    directives = []
    fstack_conf_values = []
    arguments = []
    token = bytearray()
    token_started = False
    quote = 0
    after_quote = False
    variable_depth = 0
    block_depth = 0
    index = 0

    def append_byte(value):
        if len(token) >= MAX_CONFIG_TOKEN_BYTES:
            raise ValueError('Nginx configuration token exceeds the bounded profile size')
        token.append(value)

    def finish_token():
        nonlocal token_started
        if token_started:
            arguments.append(bytes(token))
            if len(arguments) > 8:
                raise ValueError('directive exceeds the bounded profile argument limit')
            token.clear()
            token_started = False

    def finish_directive():
        if not arguments:
            raise ValueError('empty Nginx directive')
        if arguments[0] == b'include':
            raise ValueError('Nginx include directives are unsupported in the pinned profile')
        if arguments[0] == b'fstack_conf':
            if block_depth != 0:
                raise ValueError('fstack_conf must be a top-level directive')
            if (len(arguments) != 2 or not arguments[1] or
                    b'\0' in arguments[1] or b'$' in arguments[1]):
                raise ValueError('fstack_conf must have one literal path argument')
            fstack_conf_values.append(arguments[1])
            if len(fstack_conf_values) != 1:
                raise ValueError('duplicate fstack_conf directives are unsupported')
        directives.append(tuple(arguments))
        if len(directives) > MAX_CONFIG_DIRECTIVES:
            raise ValueError('Nginx configuration has too many directives')
        arguments.clear()

    while index < len(config_bytes):
        ch = config_bytes[index]
        index += 1

        if quote:
            if ch == ord('\\'):
                if index >= len(config_bytes):
                    raise ValueError('unterminated Nginx configuration escape')
                escaped = config_bytes[index]
                index += 1
                decoded = {ord('"'): ord('"'), ord("'"): ord("'"),
                    ord('\\'): ord('\\'), ord('t'): 9, ord('r'): 13,
                    ord('n'): 10}.get(escaped)
                if decoded is None:
                    append_byte(ord('\\'))
                    append_byte(escaped)
                else:
                    append_byte(decoded)
                continue
            if ch == quote:
                quote = 0
                after_quote = True
                continue
            append_byte(ch)
            continue

        if after_quote:
            if ch in (32, 9, 10, 13):
                finish_token()
                after_quote = False
                continue
            if ch not in (ord(';'), ord('{'), ord('}')):
                raise ValueError('unsupported text adjacent to a quoted Nginx token')
            after_quote = False

        if ch in (32, 9, 10, 13):
            finish_token()
            continue

        if ch == ord('#') and not token_started:
            while index < len(config_bytes) and config_bytes[index] not in (10, 13):
                index += 1
            continue

        if ch in (ord('"'), ord("'")) and not token_started:
            token_started = True
            quote = ch
            continue

        if ch == ord('\\'):
            if index >= len(config_bytes):
                raise ValueError('unterminated Nginx configuration escape')
            escaped = config_bytes[index]
            index += 1
            decoded = {ord('"'): ord('"'), ord("'"): ord("'"),
                ord('\\'): ord('\\'), ord('t'): 9, ord('r'): 13,
                ord('n'): 10}.get(escaped)
            if decoded is None:
                append_byte(ord('\\'))
                append_byte(escaped)
            else:
                append_byte(decoded)
            token_started = True
            continue

        if ch == ord('$'):
            append_byte(ch)
            token_started = True
            continue
        if ch == ord('{') and token.endswith(b'$'):
            append_byte(ch)
            variable_depth += 1
            token_started = True
            continue
        if ch == ord('}') and variable_depth:
            append_byte(ch)
            variable_depth -= 1
            token_started = True
            continue

        if ch in (ord(';'), ord('{'), ord('}')) and not variable_depth:
            finish_token()
            if ch == ord('}'):
                if arguments or block_depth <= 0:
                    raise ValueError('unbalanced Nginx configuration block')
                block_depth -= 1
                continue
            finish_directive()
            if ch == ord('{'):
                block_depth += 1
            continue

        append_byte(ch)
        token_started = True

    if quote or after_quote or token_started or arguments or variable_depth or block_depth:
        raise ValueError('incomplete or unbalanced Nginx configuration')
    required = ((b'daemon', b'off'), (b'master_process', b'on'),
        (b'worker_processes', b'1'))
    if any(directives.count(item) != 1 for item in required):
        raise ValueError('C34 requires daemon-off, master-on, one-worker config')
    if len(fstack_conf_values) != 1:
        raise ValueError('C34 requires exactly one top-level fstack_conf directive')
    return tuple(directives)


def resolve_nginx_prefix_path(prefix, configured_path):
    """Resolve an Nginx config path using `-p` as its relative base."""
    path = Path(os.fsdecode(configured_path))
    if not path.is_absolute():
        path = Path(prefix) / path
    return path.resolve(strict=True)


def effective_fstack_ini(config_path, directives, environment_path):
    """Resolve the sole literal fstack_conf as pinned Nginx does for `-c`.

    Nginx sets conf_prefix to the active config file's directory and its
    fstack_conf setter uses ngx_conf_full_name(..., 1). Compare canonical
    identities as well as device/inode, then return the selected path that is
    actually hashed and validated.
    """
    selected = [directive[1] for directive in directives
        if directive and directive[0] == b'fstack_conf']
    if len(selected) != 1:
        raise ValueError('C34 requires exactly one effective fstack_conf path')
    raw = selected[0]
    if not raw or b'\0' in raw or b'$' in raw:
        raise ValueError('dynamic or invalid fstack_conf path is unsupported')
    raw_path = os.fsdecode(raw)
    if os.path.isabs(raw_path):
        configured = Path(raw_path)
    else:
        # ngx_get_full_name concatenates conf_prefix and the relative name.
        # Do not resolve relative to the launcher working directory.
        config_dir = os.fsencode(Path(config_path).resolve(strict=True).parent)
        configured = Path(os.fsdecode(config_dir + b'/' + raw))
    try:
        selected_path = configured.resolve(strict=True)
        environment = Path(environment_path).resolve(strict=True)
        selected_stat = selected_path.stat()
        environment_stat = environment.stat()
    except (OSError, RuntimeError) as error:
        raise ValueError('effective fstack_conf or environment INI cannot be resolved') from error
    if (not selected_path.is_file() or not environment.is_file() or
            (selected_stat.st_dev, selected_stat.st_ino) !=
                (environment_stat.st_dev, environment_stat.st_ino) or
            selected_path != environment):
        raise ValueError('KER_FSTACK_NGINX_INI does not name the effective fstack_conf file')
    return selected_path, (selected_stat.st_dev, selected_stat.st_ino)


def broker_ini_matches(path, expected_broker):
    """Accept the exact broker path and one unambiguous graceful_reload=0."""
    section = None
    dpdk_sections = 0
    broker_sections = 0
    dpdk_values = []
    broker_values = {}
    try:
        lines = path.read_text(encoding='utf-8').splitlines()
    except (OSError, UnicodeError):
        return False
    for raw in lines:
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
        if line.startswith('[') and line.endswith(']'):
            section = line[1:-1].strip().lower()
            if section == 'dpdk':
                dpdk_sections += 1
            elif section == 'ker_socket_broker':
                broker_sections += 1
            continue
        if section == 'dpdk' and '=' in line:
            key, value = (part.strip().lower() for part in line.split('=', 1))
            if key == 'graceful_reload':
                dpdk_values.append(value)
        elif section == 'ker_socket_broker' and '=' in line:
            key, value = (part.strip() for part in line.split('=', 1))
            if key in broker_values:
                return False
            broker_values[key] = value
    return (dpdk_sections == 1 and dpdk_values == ['0'] and
        broker_sections == 1 and broker_values.get('version') == '1' and
        broker_values.get('path') == expected_broker and
        set(broker_values) == {'version', 'path'})


def _close_fds(fds):
    for fd in fds:
        try:
            os.close(fd)
        except OSError:
            pass


def recv_record(channel, expected_credential, deadline, rights_count,
                watched_pidfds=()):
    poller = select.poll()
    channel_fd = channel.fileno()
    poller.register(channel_fd, select.POLLIN | select.POLLHUP | select.POLLERR)
    for pidfd in watched_pidfds:
        poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    while True:
        remaining = None if deadline is None else deadline - time.monotonic()
        if remaining is not None and remaining <= 0:
            raise TimeoutError('companion command deadline expired')
        timeout_ms = -1 if remaining is None else max(1, int(remaining * 1000))
        events = poller.poll(timeout_ms)
        if not events:
            continue
        if any(fd in watched_pidfds for fd, _ in events):
            raise ConnectionError('pinned process exited')
        channel_events = next((mask for fd, mask in events if fd == channel_fd), 0)
        if channel_events & select.POLLIN:
            pass
        elif channel_events & (select.POLLHUP | select.POLLERR | select.POLLNVAL):
            raise ConnectionError('companion supervisor channel closed')
        data, ancillary, flags, _ = channel.recvmsg(4096,
            socket.CMSG_SPACE(UCRED.size) + socket.CMSG_SPACE(4 * 4),
            getattr(socket, 'MSG_CMSG_CLOEXEC', 0))
        credentials = None
        fds = []
        ancillary_error = None
        rights_seen = False
        for level, kind, payload in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS:
                if credentials is not None or len(payload) != UCRED.size:
                    ancillary_error = 'duplicate/malformed companion credentials'
                elif ancillary_error is None:
                    credentials = UCRED.unpack(payload)
            elif level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                if rights_seen or rights_count == 0:
                    ancillary_error = 'unexpected companion descriptor ancillary data'
                rights_seen = True
                usable = len(payload) - len(payload) % 4
                if usable:
                    fds.extend(array.array('i', payload[:usable]))
            else:
                ancillary_error = 'unexpected companion ancillary data'
        try:
            for fd in fds:
                os.set_inheritable(fd, False)
            if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
                raise ValueError('truncated companion record')
            if ancillary_error is not None:
                raise ValueError(ancillary_error)
            if credentials != expected_credential:
                raise PermissionError('wrong companion message sender')
            if len(fds) != rights_count:
                raise ValueError('wrong companion descriptor count')
            if deadline is not None and time.monotonic() > deadline:
                raise TimeoutError('companion record arrived after deadline')
            return data, fds
        except BaseException:
            _close_fds(fds)
            raise


def send_record(channel, packet, fds=(), deadline=None):
    sent_rights = False
    poller = select.poll()
    poller.register(channel.fileno(), select.POLLOUT | select.POLLHUP | select.POLLERR)
    while True:
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError('companion response send deadline expired')
        try:
            if fds and not sent_rights:
                ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', fds))]
                sent = channel.sendmsg([packet], ancillary,
                    getattr(socket, 'MSG_NOSIGNAL', 0))
                if sent == len(packet):
                    sent_rights = True
            else:
                sent = channel.send(packet, getattr(socket, 'MSG_NOSIGNAL', 0))
            if sent != len(packet):
                raise OSError(5, 'short SOCK_SEQPACKET companion send')
            return
        except BlockingIOError:
            if deadline is None:
                timeout_ms = 1000
            else:
                timeout_ms = max(1, int((deadline - time.monotonic()) * 1000))
            events = poller.poll(timeout_ms)
            if events and events[0][1] & (select.POLLHUP | select.POLLERR):
                raise ConnectionError('companion supervisor channel closed')
        except InterruptedError:
            continue


def direct_children():
    path = Path(f'/proc/{os.getpid()}/task/{os.getpid()}/children')
    try:
        return [int(value) for value in path.read_text().split()]
    except FileNotFoundError:
        return []


def reap_nonblocking():
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if pid <= 0:
            return


def settle_descendants(master, master_pidfd, deadline):
    if master is not None:
        try:
            master.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            pass
    while time.monotonic() < deadline:
        reap_nonblocking()
        children = direct_children()
        if not children and (master is None or master.poll() is not None):
            return 0
        time.sleep(0.01)
    # Master has been asked to exit and exhausted its grace period. Only signal
    # processes that are currently direct children of this isolated subreaper,
    # using pidfds so numeric PID reuse cannot redirect cleanup.
    for pid in direct_children():
        fd = -1
        try:
            fd = os.pidfd_open(pid, 0)
            stat = Path(f'/proc/{pid}/stat').read_text(encoding='ascii')
            fields = stat[stat.rfind(')') + 2:].split()
            if int(fields[1]) != os.getpid():
                continue
            signal.pidfd_send_signal(fd, signal.SIGTERM)
        except (OSError, ValueError, IndexError):
            pass
        finally:
            if fd >= 0:
                os.close(fd)
    term_deadline = min(deadline + 1.0, time.monotonic() + 1.0)
    while time.monotonic() < term_deadline:
        reap_nonblocking()
        if not direct_children():
            return 0
        time.sleep(0.01)
    for pid in direct_children():
        fd = -1
        try:
            fd = os.pidfd_open(pid, 0)
            stat = Path(f'/proc/{pid}/stat').read_text(encoding='ascii')
            fields = stat[stat.rfind(')') + 2:].split()
            if int(fields[1]) != os.getpid():
                continue
            signal.pidfd_send_signal(fd, signal.SIGKILL)
        except (OSError, ValueError, IndexError):
            pass
        finally:
            if fd >= 0:
                os.close(fd)
    final_deadline = time.monotonic() + 2.0
    while time.monotonic() < final_deadline:
        reap_nonblocking()
        if not direct_children():
            return 0
        time.sleep(0.01)
    return len(direct_children())


def signal_master_and_settle(master, master_pidfd, deadline):
    """Request graceful exit, then always settle this subreaper's subtree."""
    try:
        signal.pidfd_send_signal(master_pidfd, signal.SIGQUIT)
    except OSError:
        # The master can exit between the liveness check and pidfd signal.
        # Settlement is still required to reap or contain adopted descendants.
        pass
    return settle_descendants(master, master_pidfd, deadline)


def retain_unresolved_subtree():
    """Keep subreaper ownership until every adopted child is actually gone."""
    while True:
        reap_nonblocking()
        if not direct_children():
            return
        time.sleep(0.05)


def run(args):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), 'PR_SET_CHILD_SUBREAPER failed')
    if sha256_file(__file__) != args.helper_sha256:
        raise PermissionError('Nginx helper executable profile changed')
    channel = socket.socket(fileno=args.control_fd)
    channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    parent_cred = struct.unpack('=3i', channel.getsockopt(socket.SOL_SOCKET,
        socket.SO_PEERCRED, UCRED.size))
    parent_pid = os.getppid()
    if parent_cred[0] != parent_pid:
        raise PermissionError('companion socket peer is not direct supervisor')
    hello = wire.pack_record(wire.HELLO, b'', args.nonce,
        args.epoch, 0)
    channel.setblocking(False)
    send_record(channel, hello, deadline=time.monotonic() + 5.0)
    deadline = time.monotonic() + 10.0
    packet, fds = recv_record(channel, parent_cred, deadline, 1)
    supervisor_pidfd = -1
    try:
        record_type, nonce, epoch, sequence = wire.unpack_header(packet)
        if record_type != wire.START or nonce != args.nonce or epoch != args.epoch or sequence != 1:
            raise ValueError('invalid START correlation')
        fields = wire.unpack_record(packet, wire.START, args.nonce, args.epoch,
            1, wire.START_BODY)
        (expected_parent_pid, expected_parent_uid, expected_parent_gid,
         reserved, expected_parent_start, expected_parent_hash,
         expected_binary_hash, expected_config_hash) = fields
        if reserved or (expected_parent_pid, expected_parent_uid,
                expected_parent_gid) != parent_cred:
            raise PermissionError('START parent identity mismatch')
        if pidfd_pid(fds[0]) != parent_pid or parent_pid != expected_parent_pid:
            raise PermissionError('START pidfd does not pin direct supervisor')
        if start_ticks(parent_pid) != expected_parent_start:
            raise PermissionError('START supervisor start time mismatch')
        if sha256_file(f'/proc/{parent_pid}/exe') != expected_parent_hash:
            raise PermissionError('START supervisor executable mismatch')
        supervisor_pidfd = fds.pop()
    finally:
        _close_fds(fds)

    binary = Path(args.binary).resolve(strict=True)
    config = Path(args.config).resolve(strict=True)
    prefix = Path(args.prefix).resolve(strict=True)
    actual_binary_hash = sha256_file(binary)
    config_bytes = read_bounded_config(config)
    actual_config_hash = hashlib.sha256(config_bytes).digest()
    ini_path = args.nginx_env.get('KER_FSTACK_NGINX_INI')
    if not ini_path:
        raise ValueError('C34 requires an F-Stack INI profile')
    if actual_binary_hash != expected_binary_hash or actual_config_hash != expected_config_hash:
        raise PermissionError('Nginx binary/configuration hash mismatch')
    if not config.is_file() or not binary.is_file() or not os.access(binary, os.X_OK):
        raise ValueError('invalid pinned Nginx profile files')
    directives = validate_control_nginx_config(config_bytes)
    if args.owner_ready_required:
        module_path_text = args.nginx_env.get('KER_NGINX_OWNER_MODULE_PATH')
        module_sha_text = args.nginx_env.get('KER_NGINX_OWNER_MODULE_SHA256')
        if not module_path_text or not module_sha_text:
            raise ValueError('owner READY requires a pinned C22 module identity')
        module_path = Path(module_path_text).resolve(strict=True)
        module_hash = bytes.fromhex(module_sha_text)
        if len(module_hash) != 32 or sha256_file(module_path) != module_hash:
            raise PermissionError('C22 owner-activation module hash mismatch')
        configured_modules = [resolve_nginx_prefix_path(prefix, item[1])
            for item in directives if len(item) == 2 and item[0] == b'load_module']
        if configured_modules.count(module_path) != 1:
            raise PermissionError('pinned C22 owner module is not loaded exactly once')
    effective_ini_path, effective_ini_identity = effective_fstack_ini(
        config, directives, ini_path)
    actual_ini_hash = sha256_file(effective_ini_path)
    profile = wire.profile_hash(actual_binary_hash, actual_config_hash,
        actual_ini_hash, str(prefix), args.nginx_env)
    if not broker_ini_matches(effective_ini_path,
            args.nginx_env['KER_SOCKET_BROKER_PATH']):
        raise ValueError('C34 requires graceful_reload=0 profile')
    nginx_env = {'PATH': '/usr/bin:/bin', **args.nginx_env}
    cycle_env_keys = {key for key in args.nginx_env if key.startswith('KER_NGINX_CYCLE_')}
    required_cycle_keys = {'KER_NGINX_CYCLE_FD', 'KER_NGINX_CYCLE_NONCE',
        'KER_NGINX_CYCLE_RUNTIME_NONCE', 'KER_NGINX_CYCLE_RUNTIME_EPOCH',
        'KER_NGINX_CYCLE_WORKER_PROFILE_SHA256', 'KER_NGINX_CYCLE_OUTER_EXE_SHA256'}
    if cycle_env_keys and cycle_env_keys != required_cycle_keys:
        raise ValueError('incomplete serial Nginx cycle-control environment')
    if (args.cycle_control_fd is None) != (not cycle_env_keys):
        raise ValueError('cycle-control endpoint and environment must be supplied together')
    if args.cycle_control_fd is not None:
        if (int(args.nginx_env['KER_NGINX_CYCLE_FD'], 10) != args.cycle_control_fd or
                args.cycle_control_fd < 3):
            raise ValueError('cycle-control descriptor does not match environment')
        cycle_socket_type = socket.socket(fileno=os.dup(args.cycle_control_fd))
        try:
            if (cycle_socket_type.family != socket.AF_UNIX or
                    cycle_socket_type.type & 0xF != socket.SOCK_SEQPACKET):
                raise ValueError('cycle-control endpoint must be Unix SOCK_SEQPACKET')
        finally:
            cycle_socket_type.close()
    test = subprocess.run([str(binary), '-t', '-p', str(prefix) + '/',
        '-c', str(config)], env=nginx_env, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
    if test.returncode:
        raise RuntimeError('pinned Nginx config test failed: ' +
            test.stderr.decode(errors='replace')[-2000:])

    owner_ready_receiver = owner_ready_sender = None
    owner_ready_cookie = 0
    owner_ready_pidfd = -1
    if args.owner_ready_required:
        owner_ready_receiver, owner_ready_sender = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        owner_ready_receiver.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        owner_ready_cookie = struct.unpack('=Q', owner_ready_sender.getsockopt(
            socket.SOL_SOCKET, SO_COOKIE, 8))[0]
        if not owner_ready_cookie:
            raise RuntimeError('Nginx owner READY endpoint has no socket cookie')
        nginx_env['KER_NGINX_OWNER_READY_FD'] = str(owner_ready_sender.fileno())

    def revalidate_reload_profile():
        if master is None or master.poll() is not None:
            raise PermissionError('pinned Nginx master exited before reload')
        if not process_alive(master_pidfd):
            raise PermissionError('pinned Nginx master identity is no longer live')
        if caught_signals(master.pid) & REQUIRED_MASTER_SIGNALS != REQUIRED_MASTER_SIGNALS:
            raise PermissionError('pinned Nginx master signal handlers are not installed')
        if (not process_alive(supervisor_pidfd) or
                start_ticks(expected_parent_pid) != expected_parent_start or
                sha256_file(f'/proc/{expected_parent_pid}/exe') != expected_parent_hash):
            raise PermissionError('companion supervisor identity is no longer live')
        current_binary_hash = sha256_file(binary)
        current_config_bytes = read_bounded_config(config)
        current_config_hash = hashlib.sha256(current_config_bytes).digest()
        try:
            current_directives = validate_control_nginx_config(current_config_bytes)
        except ValueError as exc:
            raise PermissionError('Nginx reload configuration left the pinned one-worker profile') from exc
        try:
            current_effective_ini, current_ini_identity = effective_fstack_ini(
                config, current_directives, ini_path)
        except ValueError as exc:
            raise PermissionError('Nginx reload changed the effective fstack_conf selection') from exc
        if (current_effective_ini != effective_ini_path or
                current_ini_identity != effective_ini_identity):
            raise PermissionError('Nginx reload changed the pinned effective fstack_conf file')
        current_ini_hash = sha256_file(current_effective_ini)
        current_profile = wire.profile_hash(current_binary_hash,
            current_config_hash, current_ini_hash, str(prefix), args.nginx_env)
        if (current_binary_hash != actual_binary_hash or
                current_config_hash != actual_config_hash or
                current_ini_hash != actual_ini_hash or current_profile != profile):
            raise PermissionError('pinned Nginx binary/configuration/INI profile changed before HUP')
        if sha256_file(f'/proc/{master.pid}/exe') != actual_binary_hash:
            raise PermissionError('running Nginx executable differs from pinned profile')
        if not broker_ini_matches(current_effective_ini,
                args.nginx_env['KER_SOCKET_BROKER_PATH']):
            raise PermissionError('Nginx reload INI left the pinned graceful_reload=0 profile')

    master = None
    master_pidfd = -1
    master_ticks = 0
    started_sent = False
    try:
        master_pass_fds = ([] if args.cycle_control_fd is None else
            [args.cycle_control_fd])
        if owner_ready_sender is not None:
            master_pass_fds.append(owner_ready_sender.fileno())
        if args.rx_owner_relay_fd is not None:
            master_pass_fds.append(args.rx_owner_relay_fd)
        if args.candidate_slot_fd is not None:
            master_pass_fds.append(args.candidate_slot_fd)
        master = subprocess.Popen([str(binary), '-p', str(prefix) + '/',
            '-c', str(config)], env=nginx_env, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            close_fds=True, pass_fds=tuple(master_pass_fds), start_new_session=False)
        if args.candidate_slot_fd is not None:
            os.close(args.candidate_slot_fd)
            args.candidate_slot_fd = None
        if owner_ready_sender is not None:
            owner_ready_sender.close()
            owner_ready_sender = None
        if args.rx_owner_relay_fd is not None:
            os.close(args.rx_owner_relay_fd)
            args.rx_owner_relay_fd = None
        if args.cycle_control_fd is not None:
            os.close(args.cycle_control_fd)
            args.cycle_control_fd = None
        master_pidfd = os.pidfd_open(master.pid, 0)
        master_ticks = start_ticks(master.pid)
        signal_ready_deadline = time.monotonic() + SIGNAL_HANDLER_READY_TIMEOUT
        if sha256_file(f'/proc/{master.pid}/exe') != actual_binary_hash:
            raise PermissionError('executed Nginx binary identity differs')
        wait_for_master_signal_handlers(master, master_pidfd, master_ticks,
            actual_binary_hash, expected_parent_pid, expected_parent_start,
            supervisor_pidfd, expected_parent_hash, signal_ready_deadline)
        if (time.monotonic() >= signal_ready_deadline or
                caught_signals(master.pid) & REQUIRED_MASTER_SIGNALS !=
                REQUIRED_MASTER_SIGNALS or not process_alive(master_pidfd) or
                start_ticks(master.pid) != master_ticks or
                sha256_file(f'/proc/{master.pid}/exe') != actual_binary_hash or
                not process_alive(supervisor_pidfd) or
                start_ticks(expected_parent_pid) != expected_parent_start or
                sha256_file(f'/proc/{expected_parent_pid}/exe') != expected_parent_hash or
                time.monotonic() >= signal_ready_deadline):
            raise PermissionError('pinned Nginx signal readiness changed before STARTED')
        started_body = wire.STARTED_BODY.pack(master.pid, os.getuid(), os.getgid(),
            0, master_ticks, actual_binary_hash, profile)
        send_record(channel, wire.pack_record(wire.STARTED, started_body,
            args.nonce, args.epoch, 1), (master_pidfd,), time.monotonic() + 5.0)
        started_sent = True
        if args.owner_ready_required:
            identity, owner_ready_pidfd = receive_owner_ready(
                owner_ready_receiver, expected_cookie=owner_ready_cookie,
                binary_hash=actual_binary_hash, master=master,
                master_pidfd=master_pidfd, master_start=master_ticks,
                supervisor_pidfd=supervisor_pidfd,
                supervisor_pid=expected_parent_pid,
                supervisor_start=expected_parent_start,
                expected_role=1 if args.candidate_slot_mode else 0,
                expected_slot=((args.candidate_slot_stat.st_dev,
                    args.candidate_slot_stat.st_ino)
                    if args.candidate_slot_stat is not None else None))
            owner_ready_receiver.close()
            owner_ready_receiver = None
            owner_ready_record = wire.pack_record(wire.OWNER_READY,
                wire.OWNER_READY_BODY.pack(*identity), args.nonce, args.epoch, 1)
            send_record(channel, owner_ready_record, (owner_ready_pidfd,),
                time.monotonic() + 5.0)
    except BaseException as error:
        print(f'ker-nginx-companion startup/owner setup failed: '
            f'{type(error).__name__}: {error}', file=sys.stderr)
        if master is not None:
            print(f'ker-nginx-companion Nginx master state before cleanup: '
                f'returncode={master.poll()!r} pid={master.pid} '
                f'pidfd_alive={process_alive(master_pidfd)}', file=sys.stderr)
            if master.poll() is None:
                try:
                    if master_pidfd >= 0:
                        signal.pidfd_send_signal(master_pidfd, signal.SIGQUIT)
                    else:
                        master.send_signal(signal.SIGQUIT)
                except OSError:
                    pass
            unresolved = settle_descendants(master, master_pidfd,
                time.monotonic() + 10.0)
        else:
            unresolved = 0
        error_sequence = 1 if (not started_sent or args.owner_ready_required) else 2
        error_body = wire.ERROR_BODY.pack(5, 1 if not started_sent else 2,
            0 if master is None else master.pid, unresolved,
            master_ticks, profile)
        try:
            send_record(channel, wire.pack_record(wire.ERROR, error_body,
                args.nonce, args.epoch, error_sequence),
                deadline=time.monotonic() + 1.0)
        except (OSError, ValueError):
            pass
        if master is not None and unresolved:
            retain_unresolved_subtree()
        if master_pidfd >= 0:
            os.close(master_pidfd)
        if owner_ready_pidfd >= 0:
            os.close(owner_ready_pidfd)
        if owner_ready_receiver is not None:
            owner_ready_receiver.close()
        if owner_ready_sender is not None:
            owner_ready_sender.close()
        os.close(supervisor_pidfd)
        return 1
    request_sequence = 2
    while True:
        if master.poll() is not None:
            # Reap only children adopted by this dedicated subreaper. Report
            # failure even when cleanup is complete; the caller can then stop
            # the broker without mistaking this for a healthy master lifetime.
            unresolved = settle_descendants(master, master_pidfd,
                time.monotonic() + 2.0)
            body = wire.ERROR_BODY.pack(10, 2, master.pid, unresolved,
                master_ticks, profile)
            try:
                send_record(channel, wire.pack_record(wire.ERROR, body, args.nonce,
                    args.epoch, request_sequence), deadline=time.monotonic() + 1.0)
            except (OSError, ValueError):
                pass
            if unresolved:
                retain_unresolved_subtree()
            return 1
        if owner_ready_pidfd >= 0 and not process_alive(owner_ready_pidfd):
            unresolved = signal_master_and_settle(master, master_pidfd,
                time.monotonic() + 10.0)
            body = wire.ERROR_BODY.pack(10, 2, master.pid, unresolved,
                master_ticks, profile)
            try:
                send_record(channel, wire.pack_record(wire.ERROR, body,
                    args.nonce, args.epoch, request_sequence),
                    deadline=time.monotonic() + 1.0)
            except (OSError, ValueError):
                pass
            if unresolved:
                retain_unresolved_subtree()
            return 1
        try:
            watched_pidfds = (supervisor_pidfd, master_pidfd)
            if owner_ready_pidfd >= 0:
                watched_pidfds += (owner_ready_pidfd,)
            data, fds = recv_record(channel, parent_cred, None, 0,
                watched_pidfds)
        except BaseException as error:
            # A dead supervisor or lost control channel cannot leave its
            # control-only Nginx subtree running without an owner. Malformed
            # credentials or ancillary data take the same fail-closed path.
            try:
                if master.poll() is None:
                    signal.pidfd_send_signal(master_pidfd, signal.SIGQUIT)
            except OSError:
                pass
            unresolved = settle_descendants(master, master_pidfd,
                time.monotonic() + 10.0)
            body = wire.ERROR_BODY.pack(71, 3, master.pid, unresolved,
                master_ticks, profile)
            try:
                send_record(channel, wire.pack_record(wire.ERROR, body,
                    args.nonce, args.epoch, request_sequence),
                    deadline=time.monotonic() + 1.0)
            except (OSError, ValueError):
                pass
            if unresolved:
                # Retain the subreaper and its ownership proof. A replacement
                # supervisor cannot safely adopt an unknown descendant set.
                retain_unresolved_subtree()
            return 1
        try:
            record_type, nonce, epoch, sequence = wire.unpack_header(data)
            if nonce != args.nonce or epoch != args.epoch or sequence != request_sequence:
                raise ValueError('invalid companion request correlation')
            if record_type == wire.RELOAD:
                if len(data) != wire.RELOAD_BYTES:
                    raise ValueError('invalid RELOAD size')
                if args.owner_ready_required:
                    body = wire.RELOAD_RESULT_BODY.pack(errno.ENOTSUP, 0,
                        master_ticks, profile)
                    send_record(channel, wire.pack_record(wire.RELOAD_RESULT,
                        body, args.nonce, args.epoch, request_sequence),
                        deadline=time.monotonic() + 5.0)
                    request_sequence += 1
                    continue
                revalidate_reload_profile()
                signal.pidfd_send_signal(master_pidfd, signal.SIGHUP)
                body = wire.RELOAD_RESULT_BODY.pack(0, 0, master_ticks, profile)
                send_record(channel, wire.pack_record(wire.RELOAD_RESULT, body,
                    args.nonce, args.epoch, sequence), deadline=time.monotonic() + 5.0)
                request_sequence += 1
                if request_sequence > wire.MAX_SEQUENCE:
                    raise OverflowError('companion request sequence exhausted')
                continue
            if record_type != wire.STOP or len(data) != wire.STOP_BYTES:
                raise ValueError('unexpected companion command')
            signal.pidfd_send_signal(master_pidfd, signal.SIGQUIT)
            unresolved = settle_descendants(master, master_pidfd,
                time.monotonic() + 10.0)
            if unresolved:
                body = wire.ERROR_BODY.pack(16, 3, master.pid, unresolved,
                    master_ticks, profile)
                try:
                    send_record(channel, wire.pack_record(wire.ERROR, body,
                        args.nonce, args.epoch, sequence), deadline=time.monotonic() + 1.0)
                except (OSError, ValueError):
                    pass
                retain_unresolved_subtree()
                return 1
            body = wire.SETTLED_BODY.pack(0, wire.CLEANUP_SETTLED,
                master.pid, 0, master_ticks, profile)
            send_record(channel, wire.pack_record(wire.SETTLED, body,
                args.nonce, args.epoch, sequence), deadline=time.monotonic() + 5.0)
            return 0
        except BaseException as error:
            try:
                if master.poll() is None:
                    signal.pidfd_send_signal(master_pidfd, signal.SIGQUIT)
            except OSError:
                pass
            unresolved = settle_descendants(master, master_pidfd,
                time.monotonic() + 10.0)
            body = wire.ERROR_BODY.pack(71, 3, master.pid, unresolved,
                master_ticks, profile)
            try:
                send_record(channel, wire.pack_record(wire.ERROR, body,
                    args.nonce, args.epoch, request_sequence),
                    deadline=time.monotonic() + 1.0)
            except (OSError, ValueError):
                pass
            if unresolved:
                retain_unresolved_subtree()
            return 1
        finally:
            _close_fds(fds)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--control-fd', type=int, required=True)
    parser.add_argument('--cycle-control-fd', type=int)
    parser.add_argument('--nonce', type=lambda value: bytes.fromhex(value), required=True)
    parser.add_argument('--epoch', type=int, required=True)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--config', required=True)
    parser.add_argument('--prefix', required=True)
    parser.add_argument('--helper-sha256', type=lambda value: bytes.fromhex(value), required=True)
    parser.add_argument('--owner-ready-required', action='store_true')
    parser.add_argument('--rx-owner-relay-fd', type=int)
    parser.add_argument('--candidate-slot-fd', type=int)
    parser.add_argument('--nginx-env', action='append', default=[])
    args = parser.parse_args(argv)
    if (len(args.nonce) != 16 or args.nonce == bytes(16) or args.epoch <= 0 or
            len(args.helper_sha256) != 32):
        parser.error('invalid companion nonce/epoch')
    values = {}
    for value in args.nginx_env:
        key, separator, item = value.partition('=')
        if not separator or key not in ENV_KEYS or key in values or not item:
            parser.error('invalid/duplicate Nginx environment entry')
        values[key] = item
    args.candidate_slot_mode = args.candidate_slot_fd is not None
    args.candidate_slot_stat = None
    if args.candidate_slot_mode:
        if (args.candidate_slot_fd < 3 or not args.owner_ready_required or
                values.get('KER_NGINX_CANDIDATE_SLOT_FD') != str(args.candidate_slot_fd) or
                values.get('KER_NGINX_SOURCE_ADMISSION_RELAY') != '1'):
            parser.error('candidate slot requires the explicit source-admission owner READY profile')
        try:
            args.candidate_slot_stat = os.fstat(args.candidate_slot_fd)
        except OSError as error:
            parser.error(f'candidate slot capability is not open: {error}')
        if ('KER_NGINX_SOURCE_ADMISSION_TEST_DELAY_US' in values and
                values['KER_NGINX_SOURCE_ADMISSION_TEST_DELAY_US'] != '350000'):
            parser.error('source-admission test delay is outside its bounded profile')
        if ('KER_C16_TEST_PUMP_FAIL_AFTER_STEP' in values and
                values['KER_C16_TEST_PUMP_FAIL_AFTER_STEP'] != '1'):
            parser.error('source-admission failure injection has an invalid profile value')
    elif ('KER_NGINX_CANDIDATE_SLOT_FD' in values or
            'KER_NGINX_SOURCE_ADMISSION_RELAY' in values or
            'KER_NGINX_SOURCE_ADMISSION_TEST_DELAY_US' in values or
            'KER_C16_TEST_PUMP_FAIL_AFTER_STEP' in values):
        parser.error('candidate slot profile fields require an inherited capability')
    if args.rx_owner_relay_fd is not None:
        if args.rx_owner_relay_fd < 3 or not args.owner_ready_required:
            parser.error('RX owner relay requires owner READY and a valid inherited descriptor')
        relay_channel = socket.socket(fileno=os.dup(args.rx_owner_relay_fd))
        try:
            if relay_channel.type & 0xF != socket.SOCK_SEQPACKET:
                parser.error('RX owner relay descriptor must be SOCK_SEQPACKET')
            peer_pid, peer_uid, peer_gid = struct.unpack('=3i',
                relay_channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                    struct.calcsize('=3i')))
            if (peer_pid != os.getppid() or peer_uid != os.getuid() or
                    peer_gid != os.getgid()):
                parser.error('RX owner relay peer is not the authenticated ker-run parent')
        finally:
            relay_channel.close()
        values['KER_NGINX_RX_OWNER_RELAY_FD'] = str(args.rx_owner_relay_fd)
    if 'LD_PRELOAD' not in values or 'KER_SOCKET_BROKER_PATH' not in values:
        parser.error('C34 companion requires FStack preload and socket broker path')
    args.nginx_env = values
    try:
        return run(args)
    except BaseException as error:
        print(f'ker-nginx-companion: {error}', file=sys.stderr)
        return 2
    finally:
        cycle_fd = getattr(args, 'cycle_control_fd', None)
        if cycle_fd is not None:
            try:
                os.close(cycle_fd)
            except OSError:
                pass


if __name__ == '__main__':
    sys.exit(main())
