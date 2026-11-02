#!/usr/bin/env python3
"""Dedicated subreaper for one pinned control-only Nginx master subtree."""
import argparse
import array
import ctypes
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
    'KER_FSTACK_NGINX_INI', 'KER_FSTACK_RUNTIME_TRACE'))
START_PHASE = 1
RELOAD_PHASE = 2
STOP_PHASE = 3


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


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.digest()


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
    actual_config_hash = sha256_file(config)
    ini_path = args.nginx_env.get('KER_FSTACK_NGINX_INI')
    if not ini_path:
        raise ValueError('C34 requires an F-Stack INI profile')
    actual_ini_hash = sha256_file(ini_path)
    if actual_binary_hash != expected_binary_hash or actual_config_hash != expected_config_hash:
        raise PermissionError('Nginx binary/configuration hash mismatch')
    profile = wire.profile_hash(actual_binary_hash, actual_config_hash,
        actual_ini_hash, str(prefix), args.nginx_env)
    if not config.is_file() or not binary.is_file() or not os.access(binary, os.X_OK):
        raise ValueError('invalid pinned Nginx profile files')
    config_lines = [line.split(b'#', 1)[0].strip()
        for line in config.read_bytes().splitlines()]
    if (any(line.startswith(b'include ') for line in config_lines) or
            sum(line == b'daemon off;' for line in config_lines) != 1 or
            sum(line == b'master_process on;' for line in config_lines) != 1 or
            sum(line == b'worker_processes 1;' for line in config_lines) != 1):
        raise ValueError('C34 requires daemon-off, master-on, one-worker config')
    if not broker_ini_matches(Path(ini_path),
            args.nginx_env['KER_SOCKET_BROKER_PATH']):
        raise ValueError('C34 requires graceful_reload=0 profile')
    nginx_env = {'PATH': '/usr/bin:/bin', **args.nginx_env}
    test = subprocess.run([str(binary), '-t', '-p', str(prefix) + '/',
        '-c', str(config)], env=nginx_env, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
    if test.returncode:
        raise RuntimeError('pinned Nginx config test failed')
    master = None
    master_pidfd = -1
    master_ticks = 0
    started_sent = False
    try:
        master = subprocess.Popen([str(binary), '-p', str(prefix) + '/',
            '-c', str(config)], env=nginx_env, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            close_fds=True, start_new_session=False)
        master_pidfd = os.pidfd_open(master.pid, 0)
        master_ticks = start_ticks(master.pid)
        if sha256_file(f'/proc/{master.pid}/exe') != actual_binary_hash:
            raise PermissionError('executed Nginx binary identity differs')
        started_body = wire.STARTED_BODY.pack(master.pid, os.getuid(), os.getgid(),
            0, master_ticks, actual_binary_hash, profile)
        send_record(channel, wire.pack_record(wire.STARTED, started_body,
            args.nonce, args.epoch, 1), (master_pidfd,), time.monotonic() + 5.0)
        started_sent = True
    except BaseException:
        if master is not None:
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
        error_body = wire.ERROR_BODY.pack(5, 1 if not started_sent else 2,
            0 if master is None else master.pid, unresolved,
            master_ticks, profile)
        try:
            send_record(channel, wire.pack_record(wire.ERROR, error_body,
                args.nonce, args.epoch, 1 if not started_sent else 2),
                deadline=time.monotonic() + 1.0)
        except (OSError, ValueError):
            pass
        if master is not None and unresolved:
            retain_unresolved_subtree()
        if master_pidfd >= 0:
            os.close(master_pidfd)
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
        try:
            data, fds = recv_record(channel, parent_cred, None, 0,
                (supervisor_pidfd, master_pidfd))
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
    parser.add_argument('--nonce', type=lambda value: bytes.fromhex(value), required=True)
    parser.add_argument('--epoch', type=int, required=True)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--config', required=True)
    parser.add_argument('--prefix', required=True)
    parser.add_argument('--helper-sha256', type=lambda value: bytes.fromhex(value), required=True)
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
    if 'LD_PRELOAD' not in values or 'KER_SOCKET_BROKER_PATH' not in values:
        parser.error('C34 companion requires FStack preload and socket broker path')
    args.nginx_env = values
    try:
        return run(args)
    except BaseException as error:
        print(f'ker-nginx-companion: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
