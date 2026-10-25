#!/usr/bin/env python3
"""Original Linux TCP/UDP peers over a real secondary directional ring PMD."""
import argparse
import ctypes
import errno
import faulthandler
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import shlex
import signal
import selectors
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from collections import deque

from hugepage_preflight import hugepage_capacity_error


def require(value, message):
    if not value: raise RuntimeError(message)


def _decode_captured_pipe_output(output):
    return (output or b'').decode(errors='replace')


def dpdk_mp_socket_paths(runtime_directory, file_prefix):
    """Return pinned primary/maximum-secondary paths from DPDK's EAL formula."""
    require(isinstance(file_prefix, str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', file_prefix) and
        file_prefix not in ('.', '..'),
        'DPDK file prefix must be a bounded ASCII-safe single path component')
    primary = Path(runtime_directory) / 'dpdk' / file_prefix / 'mp_socket'
    # Pinned eal_common_proc.c appends _<decimal pid>_<hex rte_rdtsc()>.
    # Bound pid_t by signed 32-bit and the uint64 TSC suffix by 16 hex digits.
    secondary = Path(str(primary) + '_2147483647_ffffffffffffffff')
    return primary, secondary


def prepare_handoff_hugepage_dir(runtime_directory, huge_parent, file_prefix):
    primary_socket, secondary_socket = validate_dpdk_mp_socket_paths(runtime_directory, file_prefix)
    directory_name = file_prefix + '-h'
    parent_fd, directory_fd, parent_identity, directory_identity = \
        create_handoff_hugepage_dir(huge_parent, directory_name)
    return primary_socket, secondary_socket, directory_name, parent_fd, directory_fd, \
        parent_identity, directory_identity


def validate_dpdk_mp_socket_paths(runtime_directory, file_prefix):
    primary, secondary = dpdk_mp_socket_paths(runtime_directory, file_prefix)
    limit = 108  # Linux sockaddr_un.sun_path includes its terminating NUL.
    lengths = (len(os.fsencode(primary)), len(os.fsencode(secondary)))
    require(max(lengths) < limit,
        f'pinned DPDK multiprocess socket path exceeds sun_path: primary={lengths[0]} '
        f'bytes secondary_worst_case={lengths[1]} bytes limit={limit - 1}')
    return primary, secondary


def eal_mp_channel_errors(*streams):
    patterns = (
        re.compile(r'socket path too long', re.IGNORECASE),
        re.compile(r'failed to init mp channel', re.IGNORECASE),
        re.compile(r'failed to send to .*due to bad file descriptor', re.IGNORECASE),
        re.compile(r'fail to send request .*:bus_vdev_mp', re.IGNORECASE),
        re.compile(r'vdev_scan\(\): failed to request vdev from primary', re.IGNORECASE),
    )
    return [line for stream in streams for line in stream.splitlines()
        if any(pattern.search(line) for pattern in patterns)]


def require_healthy_eal_mp_channel(profile, *streams):
    errors = eal_mp_channel_errors(*streams)
    require(not errors, f'{profile} EAL multiprocess channel failed: {errors!r}')


def require_live_eal_mp_channels(profile, primary_stderr, runner_stderr,
                                 primary_socket, owner_pid, peer_pid):
    require_healthy_eal_mp_channel(profile, primary_stderr, runner_stderr)
    primary_base = str(primary_socket)
    primary_lines = [line for line in primary_stderr.splitlines()
        if line.startswith('EAL: Multi-process socket ')]
    require(primary_lines == ['EAL: Multi-process socket ' + primary_base],
        f'{profile} primary did not bind the exact EAL multiprocess endpoint: {primary_lines!r}')
    prefix = re.compile(r'^EAL: Multi-process socket (.+)$')
    suffix = re.compile(r'^' + re.escape(primary_base) + r'_([0-9]+)_([0-9a-fA-F]{1,16})$')
    paths = []
    for line in runner_stderr.splitlines():
        match = prefix.fullmatch(line)
        if match:
            paths.append(match.group(1))
    identities = []
    path_by_pid = {}
    for path in paths:
        match = suffix.fullmatch(path)
        require(match is not None,
            f'{profile} secondary used an unexpected multiprocess socket path: {path!r}')
        pid = int(match.group(1))
        identities.append(pid)
        path_by_pid[pid] = path
    require(len(identities) == 2 and sorted(identities) == sorted((owner_pid, peer_pid)),
        f'{profile} did not initialize exactly the owner and peer EAL channels: {paths!r}; '
        f'expected pids={(owner_pid, peer_pid)!r}')
    print('KER_SESSION_HANDOFF_EAL_CHANNELS ' + json.dumps(dict(profile=profile,
        primary=primary_base, owner=dict(pid=owner_pid, socket=path_by_pid[owner_pid]),
        peer=dict(pid=peer_pid, socket=path_by_pid[peer_pid])), sort_keys=True), flush=True)
    return paths


def handoff_udp_payload(frame):
    """Return the exact handoff UDP payload from a complete expected Ethernet frame."""
    app_mac=bytes.fromhex('024b45520002')
    host_mac=bytes.fromhex('024b45520001')
    if len(frame)<14+20+8 or frame[:6]!=host_mac or frame[6:12]!=app_mac or frame[12:14]!=b'\x08\x00':
        return None
    ip=frame[14:]
    ihl=(ip[0]&15)*4
    if ip[0]>>4!=4 or ihl!=20 or len(ip)<ihl+8 or ip[9]!=17:
        return None
    total=struct.unpack('!H',ip[2:4])[0]
    if total<ihl+8 or len(ip)!=total or (struct.unpack('!H',ip[6:8])[0]&0x3fff):
        return None
    udp=ip[ihl:total]
    udp_len=struct.unpack('!H',udp[4:6])[0]
    if udp_len<8 or udp_len!=len(udp):
        return None
    if ip[12:16]!=socket.inet_aton('198.18.0.2') or ip[16:20]!=socket.inet_aton('198.18.0.1'):
        return None
    if struct.unpack('!HH',udp[:4])!=(45000,45001):
        return None
    return udp[8:]


def wait_for_handoff_wire_payload(sequence, wire_frames, wire_errors, wire_lock,
                                  runner, stats_path, runner_stderr_path, timeout=10):
    """Wait using only the actual packet capture and child diagnostics."""
    payload = f'KER-A09-HANDOFF-UDP seq={sequence}\n'.encode()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with wire_lock:
            matches = [frame for frame in wire_frames if handoff_udp_payload(frame) == payload]
            errors = list(wire_errors)
        if errors:
            raise RuntimeError('handoff wire peer failed: ' + repr(errors))
        if matches:
            return matches[0]
        if runner is not None and runner.poll() is not None:
            raise RuntimeError('runner exited before the expected wire payload: ' +
                json.dumps(dict(sequence=sequence, runner_pid=runner.pid,
                    runner_returncode=runner.returncode)))
        time.sleep(0.005)
    with wire_lock:
        captured = list(wire_frames)
        errors = list(wire_errors)
    rendered = []
    for frame in captured[:64]:
        summary = {'length': len(frame), 'hex': frame[:2048].hex()}
        if len(frame) >= 14:
            summary.update(ethertype=frame[12:14].hex(), dst_mac=frame[:6].hex(), src_mac=frame[6:12].hex())
        if len(frame) >= 42 and frame[12:14] == b'\x08\x06':
            summary.update(arp_opcode=frame[20:22].hex(),
                arp_sender_ip=socket.inet_ntoa(frame[28:32]), arp_target_ip=socket.inet_ntoa(frame[38:42]))
        try:
            parsed = handoff_udp_payload(frame)
            if parsed is not None: summary['udp_payload'] = parsed.hex()
        except (IndexError, struct.error):
            summary['udp_parse_error'] = True
        rendered.append(summary)
    try:
        latest_stats = stats_path.read_text(errors='replace') if stats_path.exists() else ''
    except OSError as error:
        latest_stats = 'read failed: ' + repr(error)
    runner_errors = runner_stderr_path.read_text(errors='replace') if runner_stderr_path.exists() else ''
    raise RuntimeError('original LKL UDP sequence did not reach the wire endpoint: ' + json.dumps(
        dict(sequence=sequence, expected_payload=payload.hex(), captured_frame_count=len(captured),
            captured_frames=rendered, captured_frames_truncated=len(captured) > len(rendered),
            wire_errors=errors, runner_pid=runner.pid if runner is not None else None,
            runner_returncode=runner.poll() if runner is not None else None,
            runner_stderr=runner_errors, stats=latest_stats), sort_keys=True))


def handoff_udp_test_frame(payload=b'KER-A09-HANDOFF-UDP seq=1\n'):
    app_mac=bytes.fromhex('024b45520002')
    host_mac=bytes.fromhex('024b45520001')
    source=socket.inet_aton('198.18.0.2')
    destination=socket.inet_aton('198.18.0.1')
    udp=struct.pack('!HHHH',45000,45001,8+len(payload),0)+payload
    ip=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(udp),0x1234,0x4000,64,17,0,source,destination)+udp
    return host_mac+app_mac+b'\x08\x00'+ip


def tap_interfaces_for_process(pid):
    """Read the kernel-reported interface for every original TUN file description."""
    names = []
    for path in Path(f'/proc/{pid}/fdinfo').iterdir():
        try:
            information = path.read_text()
        except FileNotFoundError:
            continue
        names.extend(line.split(':', 1)[1].strip() for line in information.splitlines()
            if line.startswith('iff:'))
    return names


def create_handoff_hugepage_dir(parent, name):
    parent = Path(parent).resolve(strict=True)
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    directory_fd = -1
    created = False
    try:
        parent_stat = os.fstat(parent_fd)
        parent_path_stat = os.stat(parent, follow_symlinks=False)
        require((parent_stat.st_dev, parent_stat.st_ino) ==
            (parent_path_stat.st_dev, parent_path_stat.st_ino) and
            stat.S_ISDIR(parent_stat.st_mode), 'hugepage parent path changed during open')
        parent_vfs = os.fstatvfs(parent_fd)
        os.mkdir(name, mode=0o700, dir_fd=parent_fd)
        created = True
        directory_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
            os.O_CLOEXEC, dir_fd=parent_fd)
        os.fchmod(directory_fd, 0o700)
        directory_stat = os.fstat(directory_fd)
        directory_vfs = os.fstatvfs(directory_fd)
        entry_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        require(stat.S_ISDIR(directory_stat.st_mode) and directory_stat.st_uid == os.geteuid() and
            stat.S_IMODE(directory_stat.st_mode) == 0o700 and
            directory_stat.st_dev == parent_stat.st_dev and
            (directory_stat.st_dev, directory_stat.st_ino) == (entry_stat.st_dev, entry_stat.st_ino) and
            int(directory_vfs.f_bsize or directory_vfs.f_frsize) ==
                int(parent_vfs.f_bsize or parent_vfs.f_frsize),
            'private handoff hugepage directory has unexpected owner, mode, device, or page class')
        require(not os.listdir(directory_fd), 'new private hugepage directory was not empty')
        page_class = int(directory_vfs.f_bsize or directory_vfs.f_frsize)
        return parent_fd, directory_fd, (parent_stat.st_dev, parent_stat.st_ino), \
            (directory_stat.st_dev, directory_stat.st_ino, directory_stat.st_uid,
                stat.S_IMODE(directory_stat.st_mode), page_class)
    except BaseException:
        if directory_fd >= 0:
            try:
                directory_stat = os.fstat(directory_fd)
                entry_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if created and (directory_stat.st_dev, directory_stat.st_ino) == \
                        (entry_stat.st_dev, entry_stat.st_ino) and not os.listdir(directory_fd):
                    os.close(directory_fd)
                    directory_fd = -1
                    os.rmdir(name, dir_fd=parent_fd)
            except OSError:
                pass
            try: os.close(directory_fd)
            except OSError: pass
        try: os.close(parent_fd)
        except OSError: pass
        raise


def _private_hugepage_entries(directory_fd, file_prefix, expected_dev, expected_uid):
    pattern = re.compile(re.escape(file_prefix) + r'map_[0-9]+(?:_[0-9]+)?')
    names = sorted(os.listdir(directory_fd))
    invalid = [name for name in names if not pattern.fullmatch(name)]
    require(not invalid, 'private hugepage directory contains unexpected entries: ' + repr(invalid))
    entries = {}
    for name in names:
        value = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        identity = (value.st_dev, value.st_ino, value.st_uid, stat.S_IFMT(value.st_mode),
            stat.S_IMODE(value.st_mode), value.st_nlink, value.st_size)
        require(stat.S_ISREG(value.st_mode) and value.st_uid == expected_uid and
            value.st_dev == expected_dev and value.st_nlink == 1,
            f'private hugepage entry has unsafe identity: {name!r} {identity!r}')
        entries[name] = identity
    return entries


def cleanup_private_hugepage_dir(parent, parent_fd, parent_identity, directory_name,
                                 directory_fd, directory_identity, file_prefix,
                                 pidfds, resident_pidfd, primary, runner,
                                 actor_proof_ready, before_second_pass=None):
    for pidfd in pidfds:
        require(select.select([pidfd], [], [], 5)[0],
            'refuse hugepage cleanup while an exact handoff child remains alive')
    if resident_pidfd >= 0:
        require(select.select([resident_pidfd], [], [], 5)[0],
            'refuse hugepage cleanup while the exact handoff resident remains alive')
    require((primary is None or primary.poll() is not None) and
        (runner is None or runner.poll() is not None),
        'refuse hugepage cleanup before resident and launcher reaping')
    def validate_directory_binding():
        parent_stat = os.fstat(parent_fd)
        parent_path_stat = os.stat(parent, follow_symlinks=False)
        require((parent_stat.st_dev, parent_stat.st_ino) == parent_identity and
            (parent_path_stat.st_dev, parent_path_stat.st_ino) == parent_identity and
            stat.S_ISDIR(parent_stat.st_mode),
            'private hugepage parent path was replaced; refusing cleanup')
        directory_stat = os.fstat(directory_fd)
        directory_vfs = os.fstatvfs(directory_fd)
        parent_vfs = os.fstatvfs(parent_fd)
        entry_stat = os.stat(directory_name, dir_fd=parent_fd, follow_symlinks=False)
        page_class = int(directory_vfs.f_bsize or directory_vfs.f_frsize)
        require((directory_stat.st_dev, directory_stat.st_ino, directory_stat.st_uid,
                stat.S_IMODE(directory_stat.st_mode), page_class) == directory_identity and
            (entry_stat.st_dev, entry_stat.st_ino) == directory_identity[:2] and
            stat.S_ISDIR(directory_stat.st_mode) and directory_stat.st_dev == parent_stat.st_dev and
            stat.S_IMODE(directory_stat.st_mode) == 0o700 and
            page_class == int(parent_vfs.f_bsize or parent_vfs.f_frsize),
            'private hugepage directory path, owner, mode, device, or page class changed; refusing cleanup')

    validate_directory_binding()
    entries = _private_hugepage_entries(directory_fd, file_prefix,
        directory_identity[0], os.geteuid())
    require(actor_proof_ready or not entries,
        'refuse private hugepage cleanup with backing files before all exact actor identities were captured')
    if before_second_pass is not None:
        before_second_pass()
    # Revalidate the entire directory and every entry immediately before the
    # first unlink. A single mismatch refuses the whole cleanup batch.
    validate_directory_binding()
    second = _private_hugepage_entries(directory_fd, file_prefix,
        directory_identity[0], os.geteuid())
    require(second == entries, 'private hugepage contents changed before cleanup commit; refusing all unlink')
    for name in sorted(second):
        os.unlink(name, dir_fd=directory_fd)
    require(not os.listdir(directory_fd), 'private hugepage directory is not empty after exact cleanup')
    current_entry = os.stat(directory_name, dir_fd=parent_fd, follow_symlinks=False)
    require((current_entry.st_dev, current_entry.st_ino) == directory_identity[:2],
        'private hugepage directory entry changed before rmdir')
    os.rmdir(directory_name, dir_fd=parent_fd)
    try:
        os.stat(directory_name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise RuntimeError('private hugepage directory remains after exact cleanup')
    return len(entries)


def report_hugepage_cleanup_refusal(mode, original_error, cleanup_error):
    def describe(error):
        if error is None:
            return None
        return dict(type=type(error).__name__, message=str(error))
    print('KER_SESSION_HANDOFF_HUGEPAGE_CLEANUP_REFUSED ' + json.dumps(dict(
        mode=mode, original=describe(original_error), cleanup=describe(cleanup_error)),
        sort_keys=True), flush=True)
    if original_error is None:
        raise cleanup_error.with_traceback(cleanup_error.__traceback__)


def read_bounded_line(process, timeout=25, max_bytes=1 << 20):
    require(process.stdout is not None, 'packet-session stdout is unavailable')
    deadline = time.monotonic() + timeout
    value = bytearray()
    fd = process.stdout.fileno()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError('packet-session output timed out before a complete line')
        readable, _, _ = select.select([fd], [], [], remaining)
        if not readable:
            raise RuntimeError('packet-session output timed out before a complete line')
        chunk = os.read(fd, 1)
        if not chunk:
            if value:
                raise RuntimeError('packet-session output ended before a complete line')
            return bytes(value)
        value.extend(chunk)
        if len(value) > max_bytes:
            raise RuntimeError('packet-session output line exceeded its byte limit')
        if chunk == b'\n':
            return bytes(value)


def read_bounded_stderr(stderr, timeout=0.1, max_bytes=8192):
    if stderr is None:
        return ''
    deadline = time.monotonic() + timeout
    value = bytearray()
    fd = stderr.fileno()
    while len(value) < max_bytes:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        readable, _, _ = select.select([fd], [], [], remaining)
        if not readable:
            break
        chunk = os.read(fd, min(4096, max_bytes - len(value)))
        if not chunk:
            break
        value.extend(chunk)
    return value.decode(errors='replace')


def line(process, timeout=25, stderr_path=None):
    value = read_bounded_line(process, timeout)
    if not value:
        if stderr_path is not None:
            diagnostic = Path(stderr_path).read_text(errors='replace') if Path(stderr_path).exists() else ''
        elif process.stderr is not None:
            diagnostic = read_bounded_stderr(process.stderr)
        else:
            diagnostic = ''
        raise RuntimeError('packet-session exited early: ' + diagnostic)
    return value.decode().strip()


def resolve_dpdk_plugin_dir(plugin_dir, environ=None):
    environment = os.environ if environ is None else environ
    configured = plugin_dir if plugin_dir is not None else environment.get('KER_DPDK_PLUGIN_DIR')
    if not configured:
        raise RuntimeError('configured DPDK PMD directory is required (--dpdk-plugin-dir or KER_DPDK_PLUGIN_DIR)')
    try:
        root = Path(configured).expanduser().resolve(strict=True)
    except OSError as error:
        raise RuntimeError('configured DPDK PMD directory is unavailable: ' + str(configured)) from error
    if not root.is_dir():
        raise RuntimeError('configured DPDK PMD path is not a directory: ' + str(root))
    return root


def resolve_dpdk_plugin_paths(plugin_dir, modules, environ=None):
    root = resolve_dpdk_plugin_dir(plugin_dir, environ)
    resolved = []
    for module in modules:
        requested = root / ('librte_' + module + '.so')
        try:
            library = requested.resolve(strict=True)
        except OSError as error:
            raise RuntimeError('configured DPDK PMD is missing: ' + str(requested)) from error
        if not library.is_file() or not os.access(library, os.R_OK):
            raise RuntimeError('configured DPDK PMD is not a readable regular file: ' + str(library))
        resolved.append(str(library))
    return resolved


def dpdk_plugin_eal_options(paths):
    return ' '.join('-d ' + shlex.quote(path) for path in paths)


def namespace_reexec_command(args, plugin_dir, script=None):
    script_path = Path(__file__).resolve() if script is None else Path(script).resolve()
    command = ['unshare', '-Urn', sys.executable, str(script_path), '--inside',
        '--huge-dir', str(args.huge_dir), '--dpdk-plugin-dir', str(plugin_dir)]
    if getattr(args, 'handoff_negative_profiles', False):
        command.append('--handoff-negative-profiles')
    command.extend(value for name in ('worker', 'tool', 'library', 'app')
        for value in ('--' + name, str(getattr(args, name).resolve())))
    return command


_active_handoff_evidence = None


def _capture_pidfd_readability(actor_fds, resident_pidfd):
    """Snapshot readiness while descriptors are live; returned booleans outlive close()."""
    required = {'app', 'producer', 'consumer'}
    if set(actor_fds) != required:
        raise ValueError(f'actor pidfd mapping must name exactly {sorted(required)}')
    return ({name: bool(select.select([fd], [], [], 0)[0]) for name, fd in actor_fds.items()},
        bool(resident_pidfd >= 0 and select.select([resident_pidfd], [], [], 0)[0]))


def _validate_actor_pidfd_mapping(actor_fds, actor_pids):
    """Check each named pidfd still names its independently recorded live actor."""
    required = {'app', 'producer', 'consumer'}
    if set(actor_fds) != required or set(actor_pids) != required:
        raise ValueError(f'actor pidfd mapping must name exactly {sorted(required)}')
    for name in sorted(required):
        if type(actor_pids[name]) is not int or actor_pids[name] <= 0:
            raise ValueError(f'{name} has no valid recorded PID')
        info = Path(f'/proc/self/fdinfo/{actor_fds[name]}').read_text()
        pid_line = next((line for line in info.splitlines() if line.startswith('Pid:')), None)
        if pid_line is None or int(pid_line.split(':', 1)[1]) != actor_pids[name]:
            raise ValueError(f'{name} pidfd does not name its recorded live actor')


@contextmanager
def _handoff_evidence_scope(api, evidence):
    global _active_handoff_evidence
    prior_evidence = _active_handoff_evidence
    original_request = api.Connection.request
    _active_handoff_evidence = evidence
    def evidence_request(connection, command, *call_args, **call_kwargs):
        response = original_request(connection, command, *call_args, **call_kwargs)
        if command in (api.STATUS, api.PMD_STATUS):
            evidence['snapshots'].append(dict(command=('STATUS' if command == api.STATUS else 'PMD_STATUS'),
                command_id=command, value=response))
        return response
    api.Connection.request = evidence_request
    try:
        yield
    finally:
        api.Connection.request = original_request
        _active_handoff_evidence = prior_evidence


@contextmanager
def _frame_full_traceback_scope(enabled, label):
    if enabled:
        print(label, file=sys.stderr, flush=True)
        faulthandler.dump_traceback_later(45, repeat=False, file=sys.stderr)
    try:
        yield
    finally:
        if enabled:
            faulthandler.cancel_dump_traceback_later()


def record(process, prefix, timeout=25):
    value = line(process, timeout)
    if not value.startswith(prefix + ' '):
        diagnostic = ''
        if process.poll() is None:
            try: process.wait(timeout=3)
            except subprocess.TimeoutExpired: pass
        if process.poll() is not None and process.stderr is not None:
            diagnostic = read_bounded_stderr(process.stderr)
        raise RuntimeError('unexpected output: ' + value + (('\nchild stderr:\n' + diagnostic) if diagnostic else ''))
    parsed = json.loads(value[len(prefix) + 1:])
    if _active_handoff_evidence is not None:
        _active_handoff_evidence['resident_markers'].append(dict(
            pid=process.pid, marker=prefix, value=parsed,
            raw=value))
    return parsed


def run_live_handoff_profile(args, api, plugin_paths, mode='positive'):
    evidence = dict(mode=mode, resident_markers=[], snapshots=[], actors={})
    with _frame_full_traceback_scope(mode == 'frame-full',
            'KER_SESSION_FRAME_FULL_PROFILE_BEGIN'):
        with _handoff_evidence_scope(api, evidence):
            return _run_live_handoff_profile_impl(args, api, plugin_paths, mode, evidence)


def _is_fatal_handoff_profile(mode):
    return mode not in ('positive', 'frame-positive')


def _run_live_handoff_profile_impl(args, api, plugin_paths, mode, evidence):
    with tempfile.TemporaryDirectory(prefix='a9-') as directory:
        root = Path(directory); control_path = root / 'control.sock'; stats_path = root / 'stats.json'
        plugin_options = dpdk_plugin_eal_options(plugin_paths)
        file_prefix = f'a9-{os.urandom(16).hex()}'
        huge_parent_path = args.huge_dir.resolve(strict=True)
        (primary_mp_socket, _, huge_dir_name, huge_parent_fd, huge_dir_fd,
            huge_parent_identity, huge_dir_identity) = prepare_handoff_hugepage_dir(
                root, huge_parent_path, file_prefix)
        private_huge_dir = huge_parent_path / huge_dir_name
        eal = (f'--lcores=0@{min(os.sched_getaffinity(0))} --no-pci --no-telemetry --iova-mode=va '
            f'-m 64 {plugin_options} --huge-dir={shlex.quote(str(private_huge_dir))} '
            f'--file-prefix={file_prefix}')
        common = ['--socket', str(control_path), '--worker', str(args.worker), '--eal', eal,
            '--paired-pmd', '--generation-rings']
        environment = os.environ | {'RUNTIME_DIRECTORY': str(root), 'PYTHONDONTWRITEBYTECODE': '1',
            'KER_SESSION_TEST_HANDOFF_PENDING_HB': '1'}
        if mode in ('frame-positive','frame-full','frame-death-prepared','frame-death-queued','frame-death-producer-active-consumer',
                'frame-death-consumer-prepared','frame-death-consumer-writing','frame-death-both-prepared','frame-lost-prepare-reply'):
            environment['KER_SESSION_TEST_FRAME_DRAIN'] = '1'
        if mode in ('frame-full','frame-death-queued'):
            environment['KER_SESSION_TEST_FRAME_FULL']='1'
            environment['KER_SESSION_TEST_FRAME_DRAIN_FULL']='1'
        if mode=='frame-death-prepared':
            environment['KER_SESSION_TEST_FRAME_DEATH_PREPARED']='1'
            environment['KER_SESSION_TEST_FRAME_DEATH_EMPTY']='1'
        if mode in ('frame-death-consumer-prepared','frame-death-both-prepared'):
            environment['KER_SESSION_TEST_FRAME_DEATH_CONSUMER_PREPARED']='1'
            environment['KER_SESSION_TEST_FRAME_DEATH_EMPTY']='1'
        if mode=='frame-death-both-prepared':
            environment['KER_SESSION_TEST_FRAME_BOTH_DEAD']='1'
        if mode=='frame-death-consumer-writing':
            environment['KER_SESSION_TEST_FRAME_DEATH_CONSUMER_WRITING']='1'
            environment['KER_SESSION_TEST_FRAME_DEATH_EMPTY']='1'
        if mode=='frame-death-queued':
            environment['KER_SESSION_TEST_FRAME_DEATH_QUEUED']='1'
            environment['KER_SESSION_TEST_FRAME_DEATH_SNAPSHOT']='1'
        if mode=='frame-death-producer-active-consumer':
            environment['KER_SESSION_TEST_FRAME_DEATH_PRODUCER_ACTIVE_CONSUMER']='1'
        if mode in ('prepare-enoent', 'prepare-ebusy', 'prepare-eperm'):
            environment['KER_SESSION_TEST_HANDOFF_PREPARE_REJECT'] = mode.removeprefix('prepare-').upper()
        elif mode.startswith('bad-prepare-error'):
            environment['KER_SESSION_TEST_HANDOFF_PREPARE_REJECT'] = 'ENOENT'
            field = mode.removeprefix('bad-prepare-error-') if mode != 'bad-prepare-error' else 'generation'
            environment['KER_SESSION_TEST_HANDOFF_BAD_ERROR_FIELD'] = field
        if mode == 'handoff-control-hup': environment['KER_SESSION_TEST_HANDOFF_CONTROL_HUP'] = '1'
        if mode is not None: environment['KER_SESSION_TEST_HANDOFF_MODE'] = mode
        primary = runner = None
        runner_stderr_handle = None
        wire = endpoint = None
        wire_stop = threading.Event()
        wire_frames = []
        wire_errors = []
        wire_lock = threading.Lock()
        wire_thread = None
        runner_stderr_path = root / 'runner.stderr.log'
        handoff_read = handoff_write = -1
        pidfds = []
        actor_pidfds = {}
        actor_pid_values = {}
        resident_pidfd = -1
        actor_proof_ready = False
        handoff_census_before = handoff_owner_before = None
        rejection_timeout_snapshot = None
        frame_full_stage = None
        try:
            primary = subprocess.Popen([sys.executable, str(args.tool), 'serve', *common],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, bufsize=0)
            resident_pidfd = os.pidfd_open(primary.pid)
            ready = record(primary, 'KER_SESSION_READY')
            require(ready['ring_pmd'] and ready['ports'] == 1 and ready['slot'] == 0,
                'handoff resident did not start the selected paired PMD/generation adapter')
            wire, endpoint = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
            wire.setblocking(False)
            host_mac=bytes.fromhex('024b45520001')
            def handoff_wire_peer():
                try:
                    while not wire_stop.is_set():
                        readable,_,_=select.select([wire],[],[],0.02)
                        if not readable:continue
                        frame=wire.recv(65536)
                        with wire_lock:wire_frames.append(frame)
                        if(len(frame)>=42 and frame[12:14]==b'\x08\x06' and frame[20:22]==b'\x00\x01' and
                            frame[28:32]==socket.inet_aton('198.18.0.2') and
                            frame[38:42]==socket.inet_aton('198.18.0.1')):
                            reply=(frame[6:12]+host_mac+b'\x08\x06'+
                                struct.pack('!HHBBH',1,0x0800,6,4,2)+host_mac+
                                socket.inet_aton('198.18.0.1')+frame[6:12]+frame[28:32])
                            if wire.send(reply)!=len(reply):raise RuntimeError('short ARP prewarm reply')
                except BaseException as error:
                    wire_errors.append(str(error));wire_stop.set()
            if mode in ('frame-positive','frame-full','frame-death-prepared','frame-death-producer-active-consumer','frame-death-consumer-prepared',
                    'frame-death-consumer-writing','frame-death-both-prepared','frame-lost-prepare-reply'):
                wire_thread=threading.Thread(target=handoff_wire_peer,daemon=True);wire_thread.start()
            def wait_wire_payload(sequence):
                return wait_for_handoff_wire_payload(sequence, wire_frames, wire_errors, wire_lock,
                    runner, stats_path, runner_stderr_path)
            handoff_read, handoff_write = os.pipe2(os.O_CLOEXEC)
            runner_environment = environment | {'KER_SESSION_TEST_HANDOFF_REPLAY_PREPARE': '1'}
            if mode in ('frame-positive','frame-full','frame-death-prepared','frame-death-queued','frame-death-producer-active-consumer',
                    'frame-death-consumer-prepared','frame-death-consumer-writing','frame-death-both-prepared','frame-lost-prepare-reply'):
                if mode!='frame-lost-prepare-reply':
                    runner_environment['KER_SESSION_TEST_FRAME_REPLAY']='1'
                    runner_environment['KER_SESSION_TEST_FRAME_NEGATIVES']='1'
            if mode in ('frame-full','frame-death-queued'):
                runner_environment['KER_SESSION_TEST_FRAME_DRAIN_FULL']='1'
            if mode=='frame-death-queued': runner_environment['KER_SESSION_TEST_FRAME_DEATH_QUEUED']='1'
            if mode=='frame-death-queued': runner_environment['KER_SESSION_TEST_FRAME_DEATH_SNAPSHOT']='1'
            if mode=='frame-death-prepared': runner_environment['KER_SESSION_TEST_FRAME_DEATH_PREPARED']='1'
            if mode in ('frame-death-consumer-prepared','frame-death-both-prepared'):
                runner_environment['KER_SESSION_TEST_FRAME_DEATH_CONSUMER_PREPARED']='1'
            if mode=='frame-death-both-prepared': runner_environment['KER_SESSION_TEST_FRAME_BOTH_DEAD']='1'
            if mode=='frame-lost-prepare-reply':
                runner_environment['KER_SESSION_TEST_FRAME_REPLY_LOST']='1'
                runner_environment['KER_SESSION_TEST_FRAME_REPLY_LOST_HOLD']='1'
                runner_environment['KER_SESSION_TEST_FRAME_DEATH_SNAPSHOT']='1'
            if mode=='frame-death-consumer-writing': runner_environment['KER_SESSION_TEST_FRAME_DEATH_CONSUMER_WRITING']='1'
            if mode=='frame-death-producer-active-consumer': runner_environment['KER_SESSION_TEST_FRAME_DEATH_PRODUCER_ACTIVE_CONSUMER']='1'
            if mode != 'positive':
                runner_environment['KER_SESSION_TEST_HANDOFF_MODE'] = mode
            runner_stderr_handle = runner_stderr_path.open('wb')
            runner = subprocess.Popen([sys.executable, str(args.tool), 'run', *common,
                '--wire-fd', str(endpoint.fileno()), '--library', str(args.library), '--stats', str(stats_path),
                '--address', '198.18.0.2/24', '--address6', '2001:db8:1::2/64',
                '--test-live-handoff-fd', str(handoff_read), '--', str(args.app),
                *(('--handoff-udp-trigger',) if mode in ('frame-positive','frame-full','frame-death-prepared','frame-death-producer-active-consumer',
                    'frame-death-consumer-prepared','frame-death-consumer-writing','frame-death-both-prepared','frame-lost-prepare-reply') else ('--signal-ready',))],
                pass_fds=(endpoint.fileno(), handoff_read), stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=runner_stderr_handle, env=runner_environment, bufsize=0)
            runner_stderr_handle.close(); runner_stderr_handle = None
            os.close(handoff_read); handoff_read = -1
            endpoint.close(); endpoint = None

            def startup_failure(reason):
                with wire_lock:
                    wire_failure_frames=[frame[:2048].hex() for frame in wire_frames[:64]]
                    wire_failure_errors=list(wire_errors)
                    wire_failure_count=len(wire_frames)
                if runner is not None and runner.poll() is None:
                    runner.terminate()
                    try: runner.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        runner.kill(); runner.wait()
                runner_output = b''
                if runner is not None and runner.stdout is not None:
                    try: runner_output, _ = runner.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        runner.kill(); runner_output, _ = runner.communicate()
                latest_raw = stats_path.read_text(errors='replace') if stats_path.exists() else ''
                try: latest = json.loads(latest_raw) if latest_raw else None
                except json.JSONDecodeError: latest = None
                if primary is not None and primary.poll() is None:
                    if primary.stdin is not None:
                        primary.stdin.close(); primary.stdin = None
                    try: resident_output, resident_errors = primary.communicate(timeout=10)
                    except subprocess.TimeoutExpired:
                        primary.terminate()
                        try: resident_output, resident_errors = primary.communicate(timeout=5)
                        except subprocess.TimeoutExpired:
                            primary.kill(); resident_output, resident_errors = primary.communicate()
                else:
                    resident_output, resident_errors = primary.communicate(timeout=5)
                runner_errors = runner_stderr_path.read_text(errors='replace') if runner_stderr_path.exists() else ''
                mp_errors = eal_mp_channel_errors(runner_errors, resident_errors.decode(errors='replace'))
                if mp_errors:
                    reason += '; EAL multiprocess diagnostics: ' + repr(mp_errors)
                diagnostic = dict(mode=mode, reason=reason, latest_stats=latest,
                    latest_stats_raw=latest_raw,
                    wire=dict(frame_count=wire_failure_count,frames_hex=wire_failure_frames,
                        frames_truncated=wire_failure_count>len(wire_failure_frames),errors=wire_failure_errors),
                    actors=dict(app=dict(pid=(latest or {}).get('app_pid'), returncode=(latest or {}).get('app_code')),
                        owner=dict(pid=((latest or {}).get('attached') or {}).get('pid'),
                            returncode=(latest or {}).get('worker_code')),
                        peer=dict(pid=((latest or {}).get('handoff_peer_attached') or {}).get('pid'),
                            returncode=(latest or {}).get('handoff_peer_code'))),
                    runner_returncode=runner.returncode if runner is not None else None,
                    runner_stdout=runner_output.decode(errors='replace'),
                    runner_stderr=runner_errors, eal_mp_channel_errors=mp_errors,
                    resident_pid=primary.pid, resident_returncode=primary.returncode,
                    resident_stdout=resident_output.decode(errors='replace'),
                    resident_stderr=resident_errors.decode(errors='replace'))
                rendered = json.dumps(diagnostic, sort_keys=True)
                print('KER_SESSION_HANDOFF_STARTUP_FAILURE ' + rendered, flush=True)
                return RuntimeError('handoff profile startup failed with diagnostics: ' + rendered)

            try:
                ready_line = line(runner, stderr_path=runner_stderr_path)
            except RuntimeError as error:
                raise startup_failure(str(error)) from error
            if ready_line != 'READY':
                raise startup_failure('handoff application did not reach its quiescent signal barrier: ' + ready_line)
            deadline = time.monotonic() + 15
            while True:
                before = json.loads(stats_path.read_text()) if stats_path.exists() else {}
                if before.get('stage') == 'application-started' and before.get('handoff_peer_attached'):
                    break
                if runner.poll() is not None:
                    raise startup_failure('handoff workers exited before the application barrier')
                if time.monotonic() >= deadline:
                    raise startup_failure('handoff workers did not attach before the application barrier')
                time.sleep(0.01)
            require(before['generation_rings'] is True and before['attached']['generation'] == 0 and
                before['grant']['generation'] == 0 and before['handoff_peer_attached']['generation'] == 1 and
                before['handoff_peer_attached']['slot'] == before['attached']['slot'] and
                before['handoff_peer_attached']['epoch'] == before['attached']['epoch'] and
                before['handoff_peer_early_denial']['queue_owner_key'] == 0 and
                before['handoff_peer_early_denial']['exception_endpoint_fd'] is False,
                'resident-admitted same-slot peer or pre-handoff denial differs')
            actor_pid_values = dict(app=before['app_pid'], producer=before['attached']['pid'],
                consumer=before['handoff_peer_attached']['pid'])
            app_pidfd = os.pidfd_open(actor_pid_values['app']); pidfds.append(app_pidfd)
            actor_pidfds['app'] = app_pidfd
            owner_pidfd = os.pidfd_open(actor_pid_values['producer']); pidfds.append(owner_pidfd)
            actor_pidfds['producer'] = owner_pidfd
            peer_pidfd = os.pidfd_open(actor_pid_values['consumer']); pidfds.append(peer_pidfd)
            actor_pidfds['consumer'] = peer_pidfd
            _validate_actor_pidfd_mapping(actor_pidfds, actor_pid_values)
            evidence['actors'] = dict(resident=dict(pid=primary.pid), app=dict(pid=before['app_pid']),
                producer=dict(pid=before['attached']['pid'], identity=before['attached']),
                consumer=dict(pid=before['handoff_peer_attached']['pid'], identity=before['handoff_peer_attached']))
            actor_proof_ready = True
            initial_pages = _private_hugepage_entries(huge_dir_fd, file_prefix,
                huge_dir_identity[0], os.geteuid())
            require(initial_pages, 'handoff resident created no private hugepage backing files')

            def fatal_profile_diagnostics(reason):
                try:
                    return _fatal_profile_diagnostics(reason)
                except Exception as error:
                    rendered = json.dumps(dict(mode=mode, reason=reason,
                        diagnostic_capture_error=f'{type(error).__name__}: {error}'), sort_keys=True)
                    print('KER_SESSION_HANDOFF_PROFILE_FAILURE ' + rendered, flush=True)
                    return RuntimeError('live handoff profile failed; diagnostic capture also failed: ' + rendered)

            def _fatal_profile_diagnostics(reason):
                if runner is not None and runner.poll() is None:
                    runner.terminate()
                    try: runner.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        runner.kill(); runner.wait()
                runner_output = b''
                if runner is not None and runner.stdout is not None:
                    try: runner_output, _ = runner.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        runner.kill(); runner_output, _ = runner.communicate()
                latest = None
                latest_raw = ''
                if stats_path.exists():
                    latest_raw = stats_path.read_text(errors='replace')
                    try: latest = json.loads(latest_raw)
                    except json.JSONDecodeError: pass
                stderr = runner_stderr_path.read_text(errors='replace') if runner_stderr_path.exists() else ''
                primary_output = primary_errors = b''
                if primary is not None and primary.poll() is None:
                    if primary.stdin is not None:
                        primary.stdin.close(); primary.stdin = None
                    try: primary_output, primary_errors = primary.communicate(timeout=10)
                    except subprocess.TimeoutExpired:
                        primary.terminate()
                        try: primary_output, primary_errors = primary.communicate(timeout=5)
                        except subprocess.TimeoutExpired:
                            primary.kill(); primary_output, primary_errors = primary.communicate()
                elif primary is not None and primary.stdout is not None:
                    try: primary_output, primary_errors = primary.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        primary.kill(); primary_output, primary_errors = primary.communicate()
                mp_errors = eal_mp_channel_errors(stderr, primary_errors.decode(errors='replace'))
                if mp_errors:
                    reason += '; EAL multiprocess diagnostics: ' + repr(mp_errors)
                actors = dict(resident=dict(pid=primary.pid, returncode=primary.poll()),
                    app=dict(pid=before['app_pid'], returncode=(latest or {}).get('app_code'),
                        pidfd_dead=bool(select.select([app_pidfd], [], [], 0)[0])),
                    owner=dict(pid=before['attached']['pid'], returncode=(latest or {}).get('worker_code'),
                        pidfd_dead=bool(select.select([owner_pidfd], [], [], 0)[0])),
                    peer=dict(pid=before['handoff_peer_attached']['pid'],
                        returncode=(latest or {}).get('handoff_peer_code'),
                        pidfd_dead=bool(select.select([peer_pidfd], [], [], 0)[0])))
                diagnostic = dict(mode=mode, reason=reason, latest_stats=latest, latest_stats_raw=latest_raw,
                    actors=actors,
                    runner_returncode=runner.returncode if runner is not None else None,
                    runner_stdout=runner_output.decode(errors='replace'), runner_stderr=stderr,
                    eal_mp_channel_errors=mp_errors,
                    resident_stdout=primary_output.decode(errors='replace'),
                    resident_stderr=primary_errors.decode(errors='replace'))
                rendered = json.dumps(diagnostic, sort_keys=True)
                print('KER_SESSION_HANDOFF_PROFILE_FAILURE ' + rendered, flush=True)
                return RuntimeError('live handoff profile failed with diagnostics: ' + rendered)

            require(not select.select([app_pidfd, owner_pidfd, peer_pidfd], [], [], 0)[0],
                'an app or worker exited before live handoff')
            connection = api.Connection(control_path)
            try:
                handoff_census_before = connection.request(api.STATUS)
                handoff_owner_before = connection.request(api.PMD_STATUS)
            finally: connection.close()
            if mode in ('frame-positive','frame-full','frame-death-prepared','frame-death-consumer-prepared',
                    'frame-death-consumer-writing','frame-death-both-prepared','frame-lost-prepare-reply'):
                require(os.write(handoff_write,b'U')==1,'could not request original LKL UDP prewarm')
                first_ack=record(runner,'KER_SESSION_TEST_UDP_TRIGGER_ACK')
                require(first_ack==dict(sequence=1,bytes=len(b'KER-A09-HANDOFF-UDP seq=1\n')),
                    'original app did not acknowledge the pre-handoff UDP prewarm')
                try: first_wire_frame=wait_wire_payload(1)
                except RuntimeError as error: raise startup_failure(str(error)) from error
            require(os.write(handoff_write, b'H') == 1, 'could not trigger the live handoff fixture')
            if mode not in ('frame-positive','frame-full','frame-death-prepared','frame-death-producer-active-consumer','frame-death-consumer-prepared',
                    'frame-death-consumer-writing','frame-death-both-prepared','frame-lost-prepare-reply'): os.close(handoff_write); handoff_write = -1
            if mode == 'handoff-control-hup':
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    try: current = json.loads(stats_path.read_text())
                    except (OSError, json.JSONDecodeError): current = {}
                    if current.get('stage') == 'handoff-control-hup': break
                    if runner.poll() is not None: break
                    time.sleep(0.005)
                runner_output, _ = runner.communicate(timeout=20)
                runner_text = runner_stderr_path.read_text(errors='replace') if runner_stderr_path.exists() else ''
                failure = json.loads(stats_path.read_text())
                require(runner.returncode != 0 and failure.get('stage') == 'failed' and
                    'KER_SESSION_TEST_HANDOFF_HEARTBEAT_PENDING' in runner_text and
                    'KER_SESSION_HANDOFF_BOUNDARY ' in runner_text and
                    'KER_SESSION_HANDOFF_WORKER_STOPPED ' in runner_text and
                    'KER_SESSION_HANDOFF_CONTROL_CLOSED ' in runner_text and
                    'KER_SESSION_HANDOFF_WORKER_RESUMED ' in runner_text and
                    'KER_SESSION_TEST_HANDOFF_CONTROL_HUP' in runner_text and
                    'KER_SESSION_TEST_HANDOFF_PREPARE_REJECTED' not in runner_text and
                    'KER_SESSION_TEST_HANDOFF_PREPARED' not in runner_text and
                    'KER_SESSION_PMD_PARKED ' not in runner_text,
                    f'control HUP did not fail closed before PREPARE: {failure!r}; {runner_text}')
                hup = failure.get('handoff_control_hup') or {}
                require(isinstance(hup.get('stopped_snapshot'), dict) and
                    hup.get('stopped_snapshot') == hup.get('closed_snapshot') and
                    hup['stopped_snapshot'].get('status', {}).get('process') ==
                        handoff_census_before.get('process') and
                    hup['stopped_snapshot'].get('pmd_status', {}).get('token') ==
                        handoff_owner_before.get('token'),
                    f'control EOF changed the stopped owner/census: {hup!r}')
                marker_order = [runner_text.index(marker) for marker in (
                    'KER_SESSION_HANDOFF_BOUNDARY ', 'KER_SESSION_HANDOFF_WORKER_STOPPED ',
                    'KER_SESSION_HANDOFF_CONTROL_CLOSED ', 'KER_SESSION_HANDOFF_WORKER_RESUMED ',
                    'KER_SESSION_TEST_HANDOFF_CONTROL_HUP ')]
                require(marker_order == sorted(marker_order),
                    f'control HUP did not close at the stopped boundary in order: {runner_text}')
                require(all(select.select([pidfd], [], [], 0)[0] for pidfd in pidfds),
                    'control HUP profile left an exact child alive')
                primary.stdin.close(); primary.stdin = None
                primary_output, primary_errors = primary.communicate(timeout=20)
                require_live_eal_mp_channels(mode, primary_errors.decode(errors='replace'), runner_text,
                    primary_mp_socket, before['attached']['pid'], before['handoff_peer_attached']['pid'])
                drained = [json.loads(line.removeprefix('KER_SESSION_DRAINED '))
                    for line in primary_output.decode().splitlines() if line.startswith('KER_SESSION_DRAINED ')]
                require(primary.returncode == 0 and drained and drained[-1].get('objects') == 511,
                    'control HUP changed resident ownership or prevented exact cleanup: ' + primary_errors.decode())
                print('PASS: control HUP with a pending ACK aborted before PREPARE and drained the unchanged owner')
                return
            if mode in ('prepare-enoent', 'prepare-ebusy', 'prepare-eperm'):
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    try: current = json.loads(stats_path.read_text())
                    except (OSError, json.JSONDecodeError): current = {}
                    if current.get('stage') == 'handoff-rejected': break
                    if runner.poll() is not None: raise RuntimeError('runner exited before rejection recovery')
                    time.sleep(0.005)
                else:
                    latest_raw = stats_path.read_text(errors='replace') if stats_path.exists() else ''
                    try: latest = json.loads(latest_raw) if latest_raw else None
                    except json.JSONDecodeError: latest = None
                    runner_stderr = runner_stderr_path.read_text(errors='replace') if runner_stderr_path.exists() else ''
                    rejection_timeout_snapshot = dict(mode=mode,
                        reason='worker did not publish handoff-rejected before the bounded deadline',
                        latest_stats=latest, latest_stats_raw=latest_raw,
                        runner_stderr=runner_stderr,
                        runner_returncode=runner.poll(), resident_returncode=primary.poll(),
                        actor_pids=dict(app=before['app_pid'], owner=before['attached']['pid'],
                            peer=before['handoff_peer_attached']['pid']),
                        census_before=handoff_census_before, owner_before=handoff_owner_before)
                    print('KER_SESSION_PREPARE_REJECTION_TIMEOUT_SNAPSHOT ' +
                        json.dumps(rejection_timeout_snapshot, sort_keys=True), flush=True)
                    raise RuntimeError('worker did not resume after its valid PREPARE rejection; '
                        'bounded diagnostic snapshot captured')
                runner_text = runner_stderr_path.read_text(errors='replace') if runner_stderr_path.exists() else ''
                require(all(marker in runner_text for marker in (
                    'KER_SESSION_TEST_HANDOFF_HEARTBEAT_PENDING',
                    'KER_SESSION_HANDOFF_BOUNDARY',
                    'KER_SESSION_TEST_HANDOFF_HEARTBEAT_DRAINED',
                    'KER_SESSION_TEST_HANDOFF_PREPARE_RESUMED',
                    'KER_SESSION_HANDOFF_BOUNDARY')),
                    'pending ACK, PREPARE, and queued H were not observed: ' + runner_text)
                marker_lines = runner_text.splitlines()
                pending_positions = [i for i, line in enumerate(marker_lines)
                    if line.startswith('KER_SESSION_TEST_HANDOFF_HEARTBEAT_PENDING ')]
                drained_positions = [i for i, line in enumerate(marker_lines)
                    if line.startswith('KER_SESSION_TEST_HANDOFF_HEARTBEAT_DRAINED ')]
                deferred_positions = [i for i, line in enumerate(marker_lines)
                    if line.startswith('KER_SESSION_TEST_HANDOFF_HEARTBEAT_DEFERRED ')]
                boundary_positions = [i for i, line in enumerate(marker_lines)
                    if line.startswith('KER_SESSION_HANDOFF_BOUNDARY ')]
                rejected_positions = [i for i, line in enumerate(marker_lines)
                    if line.startswith('KER_SESSION_TEST_HANDOFF_PREPARE_REJECTED ')]
                resumed_positions = [i for i, line in enumerate(marker_lines)
                    if line.startswith('KER_SESSION_TEST_HANDOFF_PREPARE_RESUMED ')]
                packet_ready_positions = [i for i, line in enumerate(marker_lines)
                    if line.startswith('KER_SESSION_PACKET_READY ')]
                rejected_records = [json.loads(marker_lines[i].split(' ', 1)[1]) for i in rejected_positions]
                require(len(pending_positions) == 1 and len(drained_positions) == 1 and
                    len(boundary_positions) == 2 and len(rejected_positions) == 2 and
                    len(resumed_positions) == 2 and
                    pending_positions[0] < boundary_positions[0] < drained_positions[0] <
                    rejected_positions[0] < resumed_positions[0] < boundary_positions[1] and
                    any(resumed_positions[0] < ready < boundary_positions[1] for ready in packet_ready_positions) and
                    boundary_positions[1] < rejected_positions[1] < resumed_positions[1] and
                    all(record.get('same_replay') is True for record in rejected_records) and
                    all(json.loads(marker_lines[i].split(' ', 1)[1]).get('status') ==
                        {'prepare-enoent': -errno.ENOENT, 'prepare-ebusy': -errno.EBUSY,
                         'prepare-eperm': -errno.EPERM}[mode] for i in resumed_positions) and
                    not any(line.startswith(('KER_SESSION_TEST_HANDOFF_PREPARED ',
                        'KER_SESSION_PMD_PARKED ', 'KER_SESSION_PACKET_DONE ')) for line in marker_lines),
                    'pending ACK, first PREPARE, and pipelined second H were not serviced in order: ' + runner_text)
                require(all(any(boundary < deferred < drained for boundary in boundary_positions
                                for drained in drained_positions) for deferred in deferred_positions),
                    'HEARTBEAT_DEFERRED diagnostic fell outside a handoff boundary/drain interval: ' + runner_text)
                connection = api.Connection(control_path)
                try:
                    rejected_census = connection.request(api.STATUS)
                    rejected_owner = connection.request(api.PMD_STATUS)
                    require(rejected_census == handoff_census_before and
                        rejected_owner == handoff_owner_before and
                        rejected_owner['token'] == before['grant']['queue_owner_key'] and
                        rejected_owner['generation'] == 0,
                        'valid PREPARE rejection changed owner, lease census, or pool state')
                finally: connection.close()
                runner.send_signal(signal.SIGTERM)
                runner_output, _ = runner.communicate(timeout=20)
                errors = runner_stderr_path.read_bytes() if runner_stderr_path.exists() else b''
                finished = json.loads(stats_path.read_text())
                require(runner.returncode == 143 and finished.get('stage') == 'interrupted' and
                    finished.get('worker_code') == 0 and finished.get('packet', {}).get('status') == 0 and
                    finished.get('handoff_peer_code') == 0 and finished.get('native', {}).get('buffers_live') == 0,
                    'worker failed cleanup after PREPARE rejection: ' + repr(finished) + errors.decode())
                require(all(select.select([pidfd], [], [], 0)[0] for pidfd in pidfds),
                    'PREPARE rejection profile left an exact actor alive')
                connection = api.Connection(control_path)
                try:
                    census = connection.request(api.STATUS); owner = connection.request(api.PMD_STATUS)
                    require(census['generation'] == 511 and census['token'] == 0 and owner['token'] == 0,
                        'PREPARE rejection cleanup did not restore pool/PMD ownership')
                finally: connection.close()
                primary.stdin.close(); primary.stdin = None
                primary_output, primary_errors = primary.communicate(timeout=20)
                require_live_eal_mp_channels(mode, primary_errors.decode(errors='replace'), runner_text,
                    primary_mp_socket, before['attached']['pid'], before['handoff_peer_attached']['pid'])
                require(primary.returncode == 0 and any(line.startswith('KER_SESSION_DRAINED ')
                    for line in primary_output.decode().splitlines()),
                    'PREPARE rejection did not cleanly drain the resident: ' + primary_errors.decode())
                print('KER_SESSION_PREPARE_REJECTION_RAW ' + json.dumps(dict(
                    mode=mode,
                    runner_stderr=errors.decode(errors='replace'),
                    primary_stdout=primary_output.decode(errors='replace'),
                    primary_stderr=primary_errors.decode(errors='replace'),
                    census_before=handoff_census_before,
                    owner_before=handoff_owner_before,
                    census_after_rejection=rejected_census,
                    owner_after_rejection=rejected_owner,
                    census_after_cleanup=census,
                    owner_after_cleanup=owner,
                    actor_pids=dict(owner=before['attached']['pid'], peer=before['handoff_peer_attached']['pid']),
                    runner_returncode=runner.returncode,
                    resident_returncode=primary.returncode), sort_keys=True), flush=True)
                print(f'PASS: {mode} drained a pending heartbeat, preserved queued H, returned exact rejection, and resumed the packet loop')
                return
            if _is_fatal_handoff_profile(mode):
                try:
                    runner_output, _ = runner.communicate(timeout=20)
                except subprocess.TimeoutExpired as error:
                    runner.kill(); runner_output, _ = runner.communicate()
                    raise RuntimeError('fatal handoff fixture did not terminate: ' +
                        (runner_stderr_path.read_text(errors='replace') if runner_stderr_path.exists() else '')) from error
                runner_text = runner_stderr_path.read_text(errors='replace') if runner_stderr_path.exists() else ''
                require_healthy_eal_mp_channel(mode, runner_text)
                failure = json.loads(stats_path.read_text())
                malformed_prepare = mode.startswith('bad-prepare-error') or mode == 'bad-prepare-success'
                require((runner.returncode != 0 if malformed_prepare else runner.returncode == 125) and
                    failure.get('stage') == 'failed' and
                    failure.get('worker_code') == 125 and failure.get('app_code') is not None,
                    f'{mode} did not fail closed through the launcher: {failure!r}; '
                    f'runner stdout={runner_output.decode(errors="replace")!r}; stderr={runner_text!r}')
                if malformed_prepare:
                    expected_kind = 'error' if mode.startswith('bad-prepare-error') else 'success'
                    require('KER_SESSION_TEST_HANDOFF_PREPARED' not in runner_text and
                        'KER_SESSION_PMD_PARKED ' not in runner_text and
                        'KER_SESSION_PACKET_DONE ' not in runner_text,
                        f'{mode} accepted a malformed PREPARE reply: {runner_text}')
                else:
                    require('KER_SESSION_TEST_HANDOFF_PREPARED' in runner_text and
                        'KER_SESSION_PMD_PARKED ' not in runner_text and
                        'KER_SESSION_PACKET_DONE ' not in runner_text,
                        f'{mode} emitted a post-failure success marker: {runner_text}')
                require('KER_SESSION_TEST_HANDOFF_HEARTBEAT_PENDING' in runner_text and
                    'KER_SESSION_TEST_HANDOFF_HEARTBEAT_DRAINED' in runner_text and
                    sum(line.startswith('KER_SESSION_PMD_GRANTED ') for line in runner_text.splitlines()) == 1 and
                    'KER_SESSION_HANDOFF_BOUNDARY ' in runner_text,
                    f'{mode} did not complete the pending-heartbeat boundary: {runner_text}')
                if mode == 'timeout':
                    require('KER_SESSION_TEST_HANDOFF_FDS_CLOSED' not in runner_text and
                        'KER_SESSION_TEST_HANDOFF_QUIESCED_SENT' not in runner_text,
                        'timeout profile reached QUIESCED despite resident timeout')
                elif mode in ('bad-capability', 'bad-tx-lease', 'bad-rx-lease'):
                    require('KER_SESSION_TEST_HANDOFF_FDS_CLOSED' in runner_text and
                        'KER_SESSION_TEST_HANDOFF_QUIESCED_SENT' in runner_text,
                        f'{mode} did not reach the intended closed-descriptor QUIESCED boundary')
                if mode == 'peer-death':
                    killed_peer = failure.get('handoff_negative_peer', {})
                    handoff_failure = failure.get('handoff_failure', {})
                    require(killed_peer.get('pid') == before['handoff_peer_attached']['pid'] and
                        killed_peer.get('returncode') == -signal.SIGKILL and killed_peer.get('pidfd_dead') is True,
                        f'peer-death profile did not kill the exact reserved peer: {failure!r}')
                    fatal_stage = handoff_failure.get('fatal_stage')
                    require(fatal_stage in ('resident-preempted-before-fd-close',
                            'resident-preempted-after-fd-close', 'quiesced-peer-revalidation') and
                        ((fatal_stage == 'resident-preempted-before-fd-close' and
                            handoff_failure.get('fds_closed') is None and handoff_failure.get('quiesced_sent') is None) or
                         (fatal_stage == 'resident-preempted-after-fd-close' and
                            handoff_failure.get('fds_closed') is not None and handoff_failure.get('quiesced_sent') is None) or
                         (fatal_stage == 'quiesced-peer-revalidation' and
                            handoff_failure.get('fds_closed') is not None and handoff_failure.get('quiesced_sent') is not None)),
                        f'peer-death failure stage markers disagree: {failure!r}')
                require(all(select.select([pidfd], [], [], 0)[0] for pidfd in pidfds),
                    f'{mode} fixture left an app, worker, or resident alive')
                primary.stdin.close(); primary.stdin = None
                primary_output, primary_errors = primary.communicate(timeout=20)
                require_live_eal_mp_channels(mode, primary_errors.decode(errors='replace'),
                    runner_text, primary_mp_socket, before['attached']['pid'],
                    before['handoff_peer_attached']['pid'])
                if malformed_prepare:
                    expected_field = (mode.removeprefix('bad-prepare-error-') if mode != 'bad-prepare-error'
                        else 'generation') if expected_kind == 'error' else 'token'
                    require(any(line.startswith('KER_SESSION_TEST_HANDOFF_REPLY_CORRUPTED ') and
                        f'"kind":"{expected_kind}"' in line and f'"field":"{expected_field}"' in line
                        for line in primary_output.decode().splitlines()),
                        f'{mode} resident did not inject the intended malformed reply')
                    if mode == 'bad-prepare-success':
                        require(primary.returncode == 125 and b'KER_SESSION_DRAINED ' not in primary_output and
                            select.select([resident_pidfd], [], [], 0)[0],
                            'malformed successful PREPARE did not leave the prepared session fail-closed')
                    else:
                        drained = [json.loads(line.removeprefix('KER_SESSION_DRAINED '))
                            for line in primary_output.decode().splitlines() if line.startswith('KER_SESSION_DRAINED ')]
                        require(primary.returncode == 0 and drained and drained[-1].get('objects') == 511,
                            'malformed failed PREPARE changed resident ownership or prevented cleanup')
                else:
                    require(primary.returncode == 125 and b'KER_SESSION_DRAINED ' not in primary_output and
                        select.select([resident_pidfd], [], [], 0)[0],
                        f'{mode} resident did not fail without a successful drain: {primary.returncode}; '
                        f'{primary_errors.decode(errors="replace")}')
                print('KER_SESSION_HANDOFF_FATAL_RESULT ' + json.dumps(dict(mode=mode, failure=failure,
                    runner_returncode=runner.returncode, runner_stdout=runner_output.decode(errors='replace'),
                    runner_stderr=runner_text, resident_returncode=primary.returncode,
                    resident_stdout=primary_output.decode(errors='replace'),
                    resident_stderr=primary_errors.decode(errors='replace')), sort_keys=True), flush=True)
                print(f'PASS: {mode} after PREPARE terminates exact actors with status125 and no PARKED/grant/DRAINED success')
                return
            deadline = time.monotonic() + 15
            while True:
                try:
                    after = json.loads(stats_path.read_text())
                except (OSError, json.JSONDecodeError):
                    if runner.poll() is not None:
                        raise fatal_profile_diagnostics('runner exited before publishing a complete handoff result')
                    after = {}
                if after.get('stage') == 'handoff-complete': break
                if runner.poll() is not None:
                    raise fatal_profile_diagnostics('runner exited before same-session handoff completed')
                if time.monotonic() >= deadline:
                    raise fatal_profile_diagnostics('same-session handoff exceeded its bounded completion deadline')
                time.sleep(0.01)
            handoff = after['handoff']; protocol = after['handoff_protocol']
            endpoint_name = ready['exception_endpoint_name']
            require(handoff['app_pid'] == before['app_pid'] and
                handoff['old_worker_pid'] == before['attached']['pid'] and
                handoff['peer_worker_pid'] == before['handoff_peer_attached']['pid'] and
                handoff['old_exception_fd_closed'] and handoff['old_owner_key'] != handoff['new_owner_key'] and
                endpoint_name in handoff['old_tun_interfaces_before'] and
                endpoint_name not in handoff['old_tun_interfaces_after'] and
                endpoint_name in handoff['successor_tun_interfaces'] and
                handoff['resident']['token'] == handoff['new_owner_key'] and
                handoff['successor']['generation'] == 1 and
                protocol['negative_prepare']['status'] == -1 and protocol['negative_prepare']['same_replay'] and
                protocol['replay_prepare']['same_response'] and
                not select.select([app_pidfd, owner_pidfd, peer_pidfd], [], [], 0)[0],
                'handoff changed process/endpoint identity or failed exact PREPARE/replay validation')
            if mode=='frame-death-prepared':
                require(os.write(handoff_write,b'U')==1,'could not queue original LKL PREPARED-death datagram')
                second_ack=record(runner,'KER_SESSION_TEST_UDP_TRIGGER_ACK')
                require(second_ack==dict(sequence=2,bytes=len(b'KER-A09-HANDOFF-UDP seq=2\n')),
                    'original app did not acknowledge the PREPARED-death datagram')
                deadline=time.monotonic()+10
                while time.monotonic()<deadline:
                    try: after=json.loads(stats_path.read_text())
                    except (OSError,json.JSONDecodeError): after={}
                    if after.get('handoff_frame_death'):break
                    require(runner.poll() is None,'runner exited before PREPARED-death recovery proof')
                    time.sleep(0.005)
                proof=after.get('handoff_frame_death') or {}
                require(proof.get('stage')=='prepared' and proof.get('pidfd_dead') is True and
                    proof.get('producer_status')==-signal.SIGKILL and
                    proof.get('prepared',{}).get('packet_still_queued') is True and
                    proof.get('census',{}).get('process')==1 and proof.get('census',{}).get('slot')==1 and
                    proof.get('owner_after_reap',{}).get('generation')==1 and
                    proof.get('reap',{}).get('tx')==proof.get('prepared',{}).get('tx_before') and
                    proof.get('reap',{}).get('packet_pool_in_use')==proof.get('prepared',{}).get('pool_before') and
                    proof.get('reap',{}).get('counters')==proof.get('prepared',{}).get('counters_before'),
                    'PREPARED producer death did not reclaim exactly one pending packet lease')
            elif mode=='frame-death-consumer-prepared':
                require(os.write(handoff_write,b'U')==1,'could not queue original LKL consumer-death datagram')
                second_ack=record(runner,'KER_SESSION_TEST_UDP_TRIGGER_ACK')
                require(second_ack==dict(sequence=2,bytes=len(b'KER-A09-HANDOFF-UDP seq=2\n')),
                    'original app did not acknowledge consumer-death datagram')
                deadline=time.monotonic()+12
                while time.monotonic()<deadline:
                    try: after=json.loads(stats_path.read_text())
                    except (OSError,json.JSONDecodeError): after={}
                    if after.get('handoff_frame_death'):break
                    require(runner.poll() is None,'runner exited before consumer-death recovery proof')
                    time.sleep(0.005)
                proof=after.get('handoff_frame_death') or {}
                prepared=proof.get('prepared',{}); preserved=proof.get('preserved',{}); cancelled=proof.get('cancelled',{})
                require(proof.get('stage')=='consumer-prepared' and
                    prepared.get('packet_still_queued') is True and
                    prepared.get('tx_prepared')==prepared.get('tx_before') and
                    prepared.get('pool_prepared')==prepared.get('pool_before')+1 and
                    prepared.get('counters_prepared')==prepared.get('counters_before') and
                    proof.get('consumer_pidfd_dead') is True and proof.get('consumer_status')==-signal.SIGKILL and
                    proof.get('producer_status')==1 and
                    proof.get('census',{}).get('process')==1 and proof.get('census',{}).get('slot')==1 and
                    proof.get('pmd_owner_after_reap',{}).get('token')==0 and
                    preserved.get('tx')==prepared.get('tx_before') and
                    preserved.get('packet_pool_in_use')==prepared.get('pool_before')+1 and
                    preserved.get('counters')==prepared.get('counters_before') and
                    cancelled.get('tx')==prepared.get('tx_before') and
                    cancelled.get('packet_pool_in_use')==prepared.get('pool_before') and
                    cancelled.get('counters')==prepared.get('counters_before') and
                    proof.get('final_census',{}).get('process')==0 and
                    proof.get('producer_pid')==before['attached']['pid'] and
                    proof.get('consumer_pid')==before['handoff_peer_attached']['pid'],
                    'consumer death did not preserve then exactly cancel its pending packet lease: '+repr(proof))
            elif mode=='frame-death-both-prepared':
                require(os.write(handoff_write,b'U')==1,'could not queue original LKL both-actor-death datagram')
                second_ack=record(runner,'KER_SESSION_TEST_UDP_TRIGGER_ACK')
                require(second_ack==dict(sequence=2,bytes=len(b'KER-A09-HANDOFF-UDP seq=2\n')),
                    'original app did not acknowledge both-actor-death datagram')
                deadline=time.monotonic()+10
                while time.monotonic()<deadline:
                    try:barrier=json.loads(stats_path.read_text()).get('handoff_frame_death_barrier',{})
                    except (OSError,json.JSONDecodeError):barrier={}
                    if barrier.get('stage')=='prepared-both-live':break
                    require(runner.poll() is None,'runner exited before the both-dead actor barrier')
                    time.sleep(0.005)
                require(barrier.get('producer_pid')==before['attached']['pid'] and
                    barrier.get('consumer_pid')==before['handoff_peer_attached']['pid'] and
                    barrier.get('producer_prepared') is True and barrier.get('producer_stopped') is True and
                    not select.select([owner_pidfd,peer_pidfd,resident_pidfd],[],[],0)[0],
                    'both-dead barrier did not hold both exact actors and resident live')
                resident_stop_sent=False
                try:
                    signal.pidfd_send_signal(resident_pidfd,signal.SIGSTOP)
                    resident_stop_sent=True
                    stop_deadline=time.monotonic()+5
                    while time.monotonic()<stop_deadline:
                        require(not select.select([resident_pidfd],[],[],0)[0],
                            'resident exited before the deterministic both-dead barrier')
                        state=next(line.split()[1] for line in
                            Path(f'/proc/{primary.pid}/status').read_text().splitlines()
                            if line.startswith('State:'))
                        if state in ('T','t'):break
                        time.sleep(0.005)
                    else:raise RuntimeError('exact resident pidfd did not reach stopped state')
                    signal.pidfd_send_signal(owner_pidfd,signal.SIGKILL)
                    signal.pidfd_send_signal(peer_pidfd,signal.SIGKILL)
                    dead_deadline=time.monotonic()+5
                    while time.monotonic()<dead_deadline:
                        if (select.select([owner_pidfd],[],[],0)[0] and
                                select.select([peer_pidfd],[],[],0)[0]):break
                        time.sleep(0.005)
                    else:raise RuntimeError('both exact actor pidfds did not become readable while resident was stopped')
                finally:
                    if resident_stop_sent and not select.select([resident_pidfd],[],[],0)[0]:
                        signal.pidfd_send_signal(resident_pidfd,signal.SIGCONT)
                deadline=time.monotonic()+15
                while time.monotonic()<deadline:
                    try:after=json.loads(stats_path.read_text())
                    except (OSError,json.JSONDecodeError):after={}
                    if after.get('handoff_frame_death',{}).get('stage')=='both-prepared-actors-dead':break
                    require(runner.poll() is None,'runner exited before both-dead recovery proof')
                    time.sleep(0.005)
                proof=after.get('handoff_frame_death') or {};prepared=proof.get('prepared',{})
                reaped=record(primary,'KER_SESSION_FRAME_BOTH_DEAD_REAPED')
                require(proof.get('stage')=='both-prepared-actors-dead' and
                    proof.get('producer_pid')==before['attached']['pid'] and
                    proof.get('consumer_pid')==before['handoff_peer_attached']['pid'] and
                    proof.get('producer_pidfd_dead') is True and proof.get('consumer_pidfd_dead') is True and
                    proof.get('producer_status')==-signal.SIGKILL and proof.get('consumer_status')==-signal.SIGKILL and
                    prepared.get('packet_still_queued') is True and
                    prepared.get('tx_prepared')==prepared.get('tx_before') and
                    prepared.get('pool_prepared')==prepared.get('pool_before')+1 and
                    prepared.get('counters_prepared')==prepared.get('counters_before') and
                    reaped.get('producer_pid')==proof.get('producer_pid') and
                    reaped.get('object_index')==prepared.get('object_index') and
                    reaped.get('lease_id')==prepared.get('lease_id') and
                    reaped.get('dead_mask')==3 and
                    reaped.get('tx_after')==0 and reaped.get('packet_pool_in_use')==0 and
                    reaped.get('counters')==prepared.get('counters_before') and
                    proof.get('final_census',{}).get('process')==0 and
                    proof.get('final_owner',{}).get('token')==0,
                    'both-dead prepared lease was not recovered exactly: '+repr(dict(proof=proof,reaped=reaped)))
            elif mode=='frame-lost-prepare-reply':
                require(os.write(handoff_write,b'U')==1,'could not request original LKL ambiguous-PREPARE datagram')
                second_ack=record(runner,'KER_SESSION_TEST_UDP_TRIGGER_ACK')
                require(second_ack==dict(sequence=2,bytes=len(b'KER-A09-HANDOFF-UDP seq=2\n')),
                    'original app did not acknowledge ambiguous-PREPARE datagram')
                deadline=time.monotonic()+15
                while time.monotonic()<deadline:
                    try:after=json.loads(stats_path.read_text())
                    except (OSError,json.JSONDecodeError):after={}
                    if after.get('handoff_frame_loss',{}).get('stage')=='prepare-reply-lost':break
                    require(runner.poll() is None,'runner exited before lost-reply ownership proof')
                    time.sleep(0.005)
                proof=after.get('handoff_frame_loss') or {}
                dropped=record(primary,'KER_SESSION_FRAME_REPLY_DROPPED')
                reaped=record(primary,'KER_SESSION_FRAME_REPLY_LOST_REAPED')
                snapshot=api.Connection(control_path)
                try:surviving_census=snapshot.request(api.STATUS);surviving_owner=snapshot.request(api.PMD_STATUS)
                finally:snapshot.close()
                with wire_lock:loss_wire=list(wire_frames);loss_wire_errors=list(wire_errors)
                seq1_count=sum(handoff_udp_payload(frame)==b'KER-A09-HANDOFF-UDP seq=1\n' for frame in loss_wire)
                seq2_count=sum(handoff_udp_payload(frame)==b'KER-A09-HANDOFF-UDP seq=2\n' for frame in loss_wire)
                require(proof.get('stage')=='prepare-reply-lost' and proof.get('eof',{}).get('command')==api.FRAME_PREPARE and
                    proof.get('eof',{}).get('no_retry') is True and proof.get('producer_pidfd_dead') is True and
                    proof.get('producer_status')==-signal.SIGKILL and dropped.get('pid')==before['attached']['pid'] and
                    dropped.get('sequence')==proof.get('eof',{}).get('sequence') and
                    dropped.get('command')==api.FRAME_PREPARE and dropped.get('request_handled_and_cached') is True and
                    dropped.get('object_index')==reaped.get('object_index') and dropped.get('lease_id')==reaped.get('lease_id') and
                    dropped.get('sequence')==reaped.get('sequence') and dropped.get('command')==reaped.get('command') and
                    reaped.get('dead_mask')==1 and
                    dropped.get('tx')==0 and dropped.get('packet_pool_in_use')==1 and
                    proof.get('retained',{}).get('tx')==dropped.get('tx') and
                    proof.get('retained',{}).get('packet_pool_in_use')==dropped.get('packet_pool_in_use') and
                    proof.get('retained',{}).get('counters')==dropped.get('counters') and
                    proof.get('retained_census',{}).get('process',0)>=1 and
                    proof.get('retained_census_after')==proof.get('retained_census') and
                    proof.get('retained_owner',{}).get('token')==after['handoff']['new_owner_key'] and
                    proof.get('retained_owner',{}).get('generation')==1 and
                    proof.get('retained_owner_after')==proof.get('retained_owner') and
                    reaped.get('producer_pid')==dropped.get('pid') and reaped.get('tx_after')==0 and
                    reaped.get('packet_pool_in_use')==0 and reaped.get('counters')==dropped.get('counters') and
                    surviving_census.get('process')==1 and surviving_owner.get('token')==after['handoff']['new_owner_key'] and
                    surviving_owner.get('generation')==1 and seq1_count==1 and seq2_count==0 and not loss_wire_errors and
                    'KER_SESSION_FRAME_COMMITTED' not in proof.get('producer_output',''),
                    'ambiguous PREPARE reply did not retain then exact-pidfd-reap the cached transaction: '+
                    repr(dict(proof=proof,dropped=dropped,reaped=reaped,census=surviving_census,owner=surviving_owner,
                        wire=(seq1_count,seq2_count,loss_wire_errors))))
            elif mode=='frame-death-consumer-writing':
                snapshot=api.Connection(control_path)
                try: writing_census_before=snapshot.request(api.STATUS);writing_owner_before=snapshot.request(api.PMD_STATUS)
                finally:snapshot.close()
                require(os.write(handoff_write,b'U')==1,'could not queue original LKL WRITING-death datagram')
                second_ack=record(runner,'KER_SESSION_TEST_UDP_TRIGGER_ACK')
                require(second_ack==dict(sequence=2,bytes=len(b'KER-A09-HANDOFF-UDP seq=2\n')),
                    'original app did not acknowledge WRITING-death datagram')
                deferred=record(primary,'KER_SESSION_TEST_REAP_DEFERRED')
                require(deferred.get('generation')==1 and deferred.get('pid')==before['handoff_peer_attached']['pid'] and
                    deferred.get('status')==-errno.EBUSY and deferred.get('attempt')==1 and
                    deferred.get('full_reap_attempts')==0 and deferred.get('preflight_only') is True and
                    deferred.get('tx_before')==deferred.get('tx_after') and
                    deferred.get('pool_before')==deferred.get('pool_after') and
                    deferred.get('counters_before')==deferred.get('counters_after'),
                    'dead consumer WRITING reap did not defer with unchanged ring/pool/counters: '+repr(deferred))
                snapshot=api.Connection(control_path)
                try: writing_census_after=snapshot.request(api.STATUS);writing_owner_after=snapshot.request(api.PMD_STATUS)
                finally:snapshot.close()
                require(writing_census_after==writing_census_before and writing_owner_after==writing_owner_before and
                    writing_owner_after.get('token')==after['handoff']['new_owner_key'],
                    'EBUSY defer changed exact registered actors or the dead consumer PMD owner snapshot')
                require(not select.select([primary.stdout],[],[],0)[0],
                    'resident retried the deferred dead-consumer reaper before the producer completion event')
                require(os.write(handoff_write,b'R')==1,'could not release WRITING actor after verifying EBUSY defer')
                retry=record(primary,'KER_SESSION_TEST_FRAME_REAP_RETRY')
                require(isinstance(retry.get('producer'),int) and retry.get('producer')>=0 and
                    retry.get('consumer')==deferred.get('client') and retry.get('sequence',0)>0 and
                    retry.get('command')==api.FRAME_COMMIT and retry.get('attempt')==2 and
                    retry.get('full_reap_attempts')==1 and
                    retry.get('status')==1 and retry.get('resolved') is True,
                    'exact queued COMMIT did not produce one bounded successful dead-consumer retry: '+repr(retry))
                deadline=time.monotonic()+12
                while time.monotonic()<deadline:
                    try:after=json.loads(stats_path.read_text())
                    except (OSError,json.JSONDecodeError):after={}
                    if after.get('handoff_frame_death',{}).get('stage')=='consumer-writing':break
                    require(runner.poll() is None,'runner exited before WRITING recovery proof')
                    time.sleep(0.005)
                proof=after.get('handoff_frame_death') or {}
                write_complete=proof.get('write_complete',{});cancelled=proof.get('cancelled',{})
                require(proof.get('stage')=='consumer-writing' and
                    proof.get('consumer_pidfd_dead') is True and proof.get('consumer_status')==-signal.SIGKILL and
                    proof.get('producer_status')==1 and write_complete.get('pool')==deferred.get('pool_before')+1 and
                    write_complete.get('counters')==deferred.get('counters_after') and
                    cancelled.get('status')==-errno.ESTALE and cancelled.get('tx')==deferred.get('tx_after') and
                    cancelled.get('pool')==deferred.get('pool_before') and
                    cancelled.get('counters')==deferred.get('counters_after') and
                    proof.get('final_census',{}).get('process')==0 and proof.get('final_pmd_owner',{}).get('token')==0,
                    'consumer WRITING death did not defer, complete, then stale-cancel exactly: '+repr(proof))
            elif mode=='frame-death-producer-active-consumer':
                require(os.write(handoff_write,b'U')==1,'could not request original LKL active-consumer datagram')
                second_ack=record(runner,'KER_SESSION_TEST_UDP_TRIGGER_ACK')
                require(second_ack==dict(sequence=2,bytes=len(b'KER-A09-HANDOFF-UDP seq=2\n')),
                    'original app did not acknowledge active-consumer datagram')
                deadline=time.monotonic()+15
                while time.monotonic()<deadline:
                    try:after=json.loads(stats_path.read_text())
                    except (OSError,json.JSONDecodeError):after={}
                    if after.get('handoff_frame_death_waiting',{}).get('stage')=='producer-dead-active-consumer':break
                    require(runner.poll() is None,'runner exited before active-consumer producer-death barrier')
                    time.sleep(0.005)
                else:raise RuntimeError('runner did not expose dead-producer/held-consumer barrier')
                committed=after['handoff_frame_death_waiting'].get('committed',{})
                deferred=record(primary,'KER_SESSION_TEST_REAP_DEFERRED')
                require(committed.get('generation')==0 and committed.get('queue')==0 and
                    isinstance(committed.get('object_index'),int) and deferred.get('generation')==0 and
                    deferred.get('pid')==before['attached']['pid'] and
                    deferred.get('status')==-errno.EBUSY and deferred.get('full_reap_attempts')==0 and
                    deferred.get('preflight_only') is True and deferred.get('tx_before')==0 and
                    deferred.get('tx_after')==0 and deferred.get('pool_before')==1 and
                    deferred.get('pool_after')==1 and
                    deferred.get('counters_before')==deferred.get('counters_after'),
                    'dead-producer readiness changed state or entered full reap while peer held the committed packet: '+repr(deferred))
                snapshot=api.Connection(control_path)
                try:held_census=snapshot.request(api.STATUS);held_owner=snapshot.request(api.PMD_STATUS)
                finally:snapshot.close()
                require(held_census.get('process')==handoff_census_before.get('process') and
                    held_census.get('slot')==handoff_census_before.get('slot') and
                    held_owner==handoff_owner_before,
                    'preflight EBUSY changed registered actors or exact surviving PMD owner')
                require(os.write(handoff_write,b'R')==1,'could not release the active peer dequeue after EBUSY validation')
                completed=record(primary,'KER_SESSION_TEST_REAP_COMPLETED')
                require(completed.get('status')==0 and completed.get('full_reap_attempts')==1 and
                    completed.get('tx_after')==0 and completed.get('pool_after')==0 and
                    completed.get('pidfd_dead') is True,
                    'readiness retry did not commit exactly one full reap after active dequeue release: '+repr(completed))
                deadline=time.monotonic()+15
                while time.monotonic()<deadline:
                    try:after=json.loads(stats_path.read_text())
                    except (OSError,json.JSONDecodeError):after={}
                    if after.get('handoff_frame_death',{}).get('stage')=='producer-active-consumer':break
                    require(runner.poll() is None,'runner exited before active-consumer recovery completed')
                    time.sleep(0.005)
                proof=after.get('handoff_frame_death') or {};drain=proof.get('drain',{})
                require(proof.get('stage')=='producer-active-consumer' and
                    proof.get('producer_pidfd_dead') is True and proof.get('producer_status')==-signal.SIGKILL and
                    proof.get('consumer_still_live') is True and proof.get('consumer_status') is None and
                    drain.get('object_index')==committed.get('object_index') and
                    drain.get('packet_pointer')==committed.get('packet_pointer') and
                    drain.get('frame_hex')==committed.get('frame_hex') and drain.get('tx_after')==0 and
                    proof.get('final_census',{}).get('process')==1 and
                    proof.get('final_owner')==handoff_owner_before,
                    'active live consumer did not retain and release the exact committed packet: '+repr(proof))
                with wire_lock:active_wire=list(wire_frames);active_wire_errors=list(wire_errors)
                require(sum(handoff_udp_payload(frame)==b'KER-A09-HANDOFF-UDP seq=1\n' for frame in active_wire)==1 and
                    sum(handoff_udp_payload(frame)==b'KER-A09-HANDOFF-UDP seq=2\n' for frame in active_wire)==0 and
                    not active_wire_errors,
                    'active-consumer recovery changed wire delivery of the original UDP datagrams')
                os.close(handoff_write);handoff_write=-1
            elif mode=='frame-death-queued':
                deadline=time.monotonic()+15
                while time.monotonic()<deadline:
                    try: after=json.loads(stats_path.read_text())
                    except (OSError,json.JSONDecodeError): after={}
                    if after.get('handoff_frame_death'):break
                    require(runner.poll() is None,'runner exited before queued-death peer drain proof')
                    time.sleep(0.005)
                proof=after.get('handoff_frame_death') or {}
                fill=proof.get('fill',{});drain=proof.get('drain',{})
                require(proof.get('stage')=='queued' and proof.get('pidfd_dead') is True and
                    proof.get('producer_status')==-signal.SIGKILL and
                    proof.get('census',{}).get('process')==1 and proof.get('census',{}).get('slot')==1 and
                    proof.get('owner_after_reap',{}).get('generation')==1 and
                    fill.get('count')==64 and fill.get('pool_after')==64 and
                    proof.get('retained',{}).get('tx')==64 and proof.get('retained',{}).get('packet_pool_in_use')==64 and
                    proof.get('retained',{}).get('counters')==fill.get('counters_after') and
                    drain.get('count')==64 and drain.get('tx_after')==0 and
                    drain.get('pool_before')==64 and drain.get('pool_after')==0 and
                    drain.get('objects')==fill.get('objects') and
                    drain.get('counters_before')==fill.get('counters_after') and
                    drain.get('counters_after')==drain.get('counters_before'),
                    'live consumer did not drain the exact retained TX journal after producer death')
                if handoff_write>=0: os.close(handoff_write);handoff_write=-1
            elif mode == 'frame-positive':
                require(os.write(handoff_write,b'U')==1,'could not request original LKL UDP post-PARKED frame')
                second_ack=record(runner,'KER_SESSION_TEST_UDP_TRIGGER_ACK')
                require(second_ack==dict(sequence=2,bytes=len(b'KER-A09-HANDOFF-UDP seq=2\n')),
                    'original app did not acknowledge the post-PARKED UDP datagram')
                capture_deadline=time.monotonic()+0.5
                while time.monotonic()<capture_deadline:
                    require(runner.poll() is None,'runner exited during bounded post-G wire observation')
                    time.sleep(0.005)
                with wire_lock:
                    wire_snapshot=list(wire_frames);wire_error_snapshot=list(wire_errors)
                first_payload=b'KER-A09-HANDOFF-UDP seq=1\n'
                second_payload=b'KER-A09-HANDOFF-UDP seq=2\n'
                seq1_count=sum(handoff_udp_payload(frame)==first_payload for frame in wire_snapshot)
                seq2_count=sum(handoff_udp_payload(frame)==second_payload for frame in wire_snapshot)
                frame_wire_observation=dict(first_wire_frame=bool(first_wire_frame),seq1_count=seq1_count,
                    seq2_count=seq2_count,errors=wire_error_snapshot)
            elif mode=='frame-full':
                frame_full_stage='request-seq2'
                print('KER_SESSION_FRAME_FULL_STAGE request-seq2', flush=True)
                require(os.write(handoff_write,b'U')==1,'could not request original LKL UDP full-ring datagram')
                frame_full_stage='wait-seq2-ack'
                print('KER_SESSION_FRAME_FULL_STAGE wait-seq2-ack', flush=True)
                second_ack=record(runner,'KER_SESSION_TEST_UDP_TRIGGER_ACK')
                require(second_ack==dict(sequence=2,bytes=len(b'KER-A09-HANDOFF-UDP seq=2\n')),
                    'original app did not acknowledge the full-ring UDP datagram')
                frame_full_stage='wait-full-ring-proof'
                print('KER_SESSION_FRAME_FULL_STAGE wait-full-ring-proof', flush=True)
                deadline=time.monotonic()+10
                while time.monotonic()<deadline:
                    try:after=json.loads(stats_path.read_text())
                    except (OSError,json.JSONDecodeError):after={}
                    if after.get('handoff_frame_full'):break
                    require(runner.poll() is None,'runner exited before full-ring cancel/drain proof')
                    time.sleep(0.005)
                fullproof=after.get('handoff_frame_full') or {}
                frame_full_stage='validate-full-ring-proof'
                print('KER_SESSION_FRAME_FULL_STAGE validate-full-ring-proof', flush=True)
                time.sleep(0.5)
                with wire_lock:
                    full_wire_snapshot=list(wire_frames);full_wire_errors=list(wire_errors)
                seq1_count=sum(handoff_udp_payload(frame)==b'KER-A09-HANDOFF-UDP seq=1\n' for frame in full_wire_snapshot)
                seq2_count=sum(handoff_udp_payload(frame)==b'KER-A09-HANDOFF-UDP seq=2\n' for frame in full_wire_snapshot)
                fill=fullproof.get('fill',{})
                cancel=fullproof.get('commit_cancel',{})
                drain=fullproof.get('drain',{})
                capacity=after.get('frame_full_capacity')
                require(fill.get('count')==capacity and fill.get('capacity')==capacity and
                    capacity==64 and
                    fill.get('pool_before')==0 and fill.get('pool_after')==capacity and
                    len(fill.get('counters_before',[]))==5 and
                    fill.get('counters_before')==fill.get('counters_after') and
                    len(fill.get('objects',[]))==capacity and
                    [item.get('ordinal') for item in fill.get('objects',[])]==list(range(capacity)) and
                    len({item.get('index') for item in fill.get('objects',[])})==capacity and
                    len({item.get('pointer') for item in fill.get('objects',[])})==capacity and
                    cancel.get('status')==-errno.ENOBUFS and cancel.get('pool_restored') is True and
                    cancel.get('tx_after')==capacity and cancel.get('tx_capacity')==capacity and
                    cancel.get('pool_before')==capacity and cancel.get('pool_after')==capacity and
                    cancel.get('counters_before')==fill.get('counters_after') and
                    len(cancel.get('counters_after',[]))==5 and
                    cancel.get('counters_after',[])[:4]==cancel.get('counters_before',[])[:4] and
                    cancel.get('counters_after',[])[4]==cancel.get('counters_before',[-1]*5)[4]+1 and
                    drain.get('tx_after')==0 and drain.get('count')==capacity and
                    drain.get('pool_before')==capacity and drain.get('pool_after')==0 and
                    drain.get('counters_before')==cancel.get('counters_after') and
                    drain.get('counters_after')==drain.get('counters_before') and
                    drain.get('objects')==fill.get('objects') and
                    seq1_count==1 and seq2_count==0 and not full_wire_errors,
                    'full generation TX ring did not reject/cancel then drain exactly')
                frame_full_stage='full-ring-proof-passed'
                print('KER_SESSION_FRAME_FULL_STAGE full-ring-proof-passed', flush=True)
                os.close(handoff_write);handoff_write=-1
            runner.send_signal(signal.SIGTERM)
            output, _ = runner.communicate(timeout=20)
            errors = runner_stderr_path.read_bytes() if runner_stderr_path.exists() else b''
            finished = json.loads(stats_path.read_text())
            if mode=='frame-positive':
                proof=finished.get('handoff_frame') or {}
                commits=proof.get('committed_records',[]);releases=proof.get('drained_records',[])
                second_payload=b'KER-A09-HANDOFF-UDP seq=2\n'
                u2_commits=[item for item in commits if second_payload.hex() in item.get('frame_hex','')]
                u2_releases=[item for item in releases if item.get('sequence')==2]
                same_u2=(len(u2_commits)==len(u2_releases)==1 and all(
                    u2_commits[0].get(left)==u2_releases[0].get(right) for left,right in (
                        ('packet_pointer','packet_pointer'),('object_index','object_index'),
                        ('pool_tag','pool_tag'),('tx_lease_id','lease_id'),('length','length'),('frame_hex','frame_hex'))))
                committed_count=proof.get('bijection',{}).get('committed')
                drained_count=proof.get('bijection',{}).get('drained')
                frame_positive_checks=dict(
                    same_u2=same_u2,
                    commit_bijection=(committed_count==len(commits)),
                    release_bijection=(drained_count==len(releases)),
                    bijection_counts_match=(committed_count==drained_count),
                    tx_empty=(proof.get('final_batch',{}).get('tx_after')==0),
                    quiescent=(proof.get('quiescent')=={'tx_count':0,'packet_pool_in_use':0}),
                    first_wire_frame=bool(frame_wire_observation.get('first_wire_frame')),
                    seq1_once=(frame_wire_observation.get('seq1_count')==1),
                    seq2_absent=(frame_wire_observation.get('seq2_count')==0),
                    wire_peer_clean=(not frame_wire_observation.get('errors')))
                frame_positive_failure_context=dict(
                    checks=frame_positive_checks,
                    stats_stage=finished.get('stage'),
                    proof=proof,
                    u2_commits=u2_commits,
                    u2_releases=u2_releases,
                    wire_observation=frame_wire_observation,
                    first_wire_frame=(first_wire_frame.hex() if first_wire_frame is not None else None))
                require(all(frame_positive_checks.values()),
                    'post-PARKED original LKL frame was not drained as the exact same generation-ring object')
            expected_worker_code=(1 if mode=='frame-death-consumer-prepared' else
                -signal.SIGKILL if mode in ('frame-death-prepared','frame-death-queued','frame-death-producer-active-consumer') else 0)
            if mode in ('frame-death-both-prepared','frame-lost-prepare-reply'):expected_worker_code=-signal.SIGKILL
            expected_peer_code=-signal.SIGKILL if mode in ('frame-death-consumer-prepared','frame-death-both-prepared') else 0
            expected_worker_cleanup=(finished.get('worker_code')==expected_worker_code and finished.get('packet') is None
                if mode in ('frame-death-prepared','frame-death-queued','frame-death-producer-active-consumer','frame-death-consumer-prepared','frame-death-both-prepared','frame-lost-prepare-reply') else
                finished.get('worker_code')==0 and finished.get('packet',{}).get('status')==0)
            require(runner.returncode == 143 and finished.get('stage') == 'interrupted' and
                finished.get('native_cleanup') == 'graceful' and finished.get('app_code') == 143 and
                expected_worker_cleanup and
                finished.get('handoff_peer_code') == expected_peer_code and
                (finished.get('handoff_peer_packet') is None if expected_peer_code else
                    finished.get('handoff_peer_packet', {}).get('status') == 0) and
                finished.get('native', {}).get('buffers_live') == 0,
                'live handoff application/worker teardown failed: ' + repr(finished) + errors.decode())
            require(all(select.select([pidfd], [], [], 0)[0] for pidfd in pidfds),
                'handoff app or either worker survived orderly launcher cleanup')
            connection = api.Connection(control_path)
            try:
                census = connection.request(api.STATUS); owner = connection.request(api.PMD_STATUS)
                require(census['generation'] == 511 and census['token'] == 0 and census['process'] == 0 and
                    owner['token'] == 0, 'handoff normal cleanup did not restore the pool/owner baseline')
            finally: connection.close()
            primary.stdin.close(); primary.stdin = None
            primary_output, primary_errors = primary.communicate(timeout=20)
            runner_text = runner_stderr_path.read_text(errors='replace') if runner_stderr_path.exists() else ''
            require('KER_SESSION_TEST_HANDOFF_HEARTBEAT_PENDING' in runner_text and
                'KER_SESSION_TEST_HANDOFF_HEARTBEAT_DRAINED' in runner_text,
                'positive handoff did not drain its real pending heartbeat before PREPARE')
            if mode=='frame-positive':
                require('KER_SESSION_FRAME_NEGATIVE_PREPARES_PASS' in runner_text and
                    'KER_SESSION_FRAME_CANCEL_REPLAY_PASS' in runner_text,
                    'frame negative PREPARE or exact CANCEL replay proof is missing')
            require_live_eal_mp_channels(mode, primary_errors.decode(errors='replace'), runner_text,
                primary_mp_socket, before['attached']['pid'], before['handoff_peer_attached']['pid'])
            require(primary.returncode == 0, 'handoff resident did not exit cleanly: ' + primary_errors.decode())
            drained = [json.loads(line.removeprefix('KER_SESSION_DRAINED '))
                for line in primary_output.decode().splitlines() if line.startswith('KER_SESSION_DRAINED ')]
            require(drained and drained[-1]['objects'] == 511 and drained[-1]['outstanding'] == 0,
                'handoff resident did not report exact final pool cleanup')
        finally:
            original_error = sys.exc_info()[1]
            cleanup_error = None
            finalization_errors = []
            cleaned_hugepage_files = None
            try:
                for name, value in (('handoff_read', handoff_read),
                                    ('handoff_write', handoff_write)):
                    if value >= 0:
                        try: os.close(value)
                        except BaseException as error: finalization_errors.append(error)
                        if name == 'handoff_read': handoff_read = -1
                        else: handoff_write = -1
                cleanup_outputs = {}
                for label, process in (('launcher', runner), ('resident', primary)):
                    if process is None:
                        continue
                    try:
                        if process.poll() is None:
                            process.terminate()
                            try: process.wait(timeout=10)
                            except subprocess.TimeoutExpired:
                                process.kill(); process.wait(timeout=10)
                        if process.poll() is not None:
                            cleanup_outputs[label] = process.communicate(timeout=5)
                        else:
                            raise RuntimeError(f'{label} did not exit during fixture cleanup')
                    except BaseException as error:
                        finalization_errors.append(RuntimeError(f'{label} cleanup failed: {error}'))
                if rejection_timeout_snapshot is not None:
                    runner_out, runner_err = cleanup_outputs.get('launcher', (b'', b''))
                    resident_out, resident_err = cleanup_outputs.get('resident', (b'', b''))
                    runner_stderr = runner_stderr_path.read_text(errors='replace') if runner_stderr_path.exists() else ''
                    final_snapshot = dict(rejection_timeout_snapshot,
                        runner_returncode=runner.poll(), resident_returncode=primary.poll(),
                        runner_stdout=_decode_captured_pipe_output(runner_out),
                        runner_stderr=runner_stderr,
                        resident_stdout=_decode_captured_pipe_output(resident_out),
                        resident_stderr=_decode_captured_pipe_output(resident_err))
                    print('KER_SESSION_PREPARE_REJECTION_TIMEOUT_FINAL ' +
                        json.dumps(final_snapshot, sort_keys=True), flush=True)
                if mode in ('frame-positive', 'frame-full') and original_error is not None:
                    failure_stats = None
                    try: failure_stats = json.loads(stats_path.read_text())
                    except (OSError, json.JSONDecodeError): pass
                    runner_out, runner_err = cleanup_outputs.get('launcher', (b'', b''))
                    resident_out, resident_err = cleanup_outputs.get('resident', (b'', b''))
                    failure_context = locals().get('frame_positive_failure_context')
                    raw_runner_stderr = (runner_stderr_path.read_text(errors='replace')
                        if runner_stderr_path.exists() else '')
                    if mode == 'frame-full':
                        with wire_lock:
                            failure_wire_frames = list(wire_frames)
                            failure_wire_errors = list(wire_errors)
                        failure_record = dict(
                            mode=mode, stage=frame_full_stage, reason=str(original_error),
                            stats=failure_stats,
                            wire_seq1_frames=[frame.hex() for frame in failure_wire_frames
                                if handoff_udp_payload(frame)==b'KER-A09-HANDOFF-UDP seq=1\n'],
                            wire_seq2_frames=[frame.hex() for frame in failure_wire_frames
                                if handoff_udp_payload(frame)==b'KER-A09-HANDOFF-UDP seq=2\n'],
                            wire_frame_count=len(failure_wire_frames), wire_errors=failure_wire_errors,
                            runner_returncode=(runner.returncode if runner is not None else None),
                            resident_returncode=(primary.returncode if primary is not None else None),
                            runner_stdout=_decode_captured_pipe_output(runner_out),
                            runner_stderr=raw_runner_stderr,
                            runner_stderr_pipe=_decode_captured_pipe_output(runner_err),
                            resident_stdout=_decode_captured_pipe_output(resident_out),
                            resident_stderr=_decode_captured_pipe_output(resident_err))
                        print('KER_SESSION_FRAME_FULL_FAILURE ' +
                            json.dumps(failure_record, sort_keys=True), flush=True)
                    else:
                        failure_record=dict(
                            reason=str(original_error),
                            checks=(failure_context or {}).get('checks'),
                            stage=(failure_context or {}).get('stats_stage'),
                            handoff_frame=(failure_stats or {}).get('handoff_frame'),
                            u2_commits=(failure_context or {}).get('u2_commits'),
                            u2_releases=(failure_context or {}).get('u2_releases'),
                            wire_observation=(failure_context or {}).get('wire_observation'),
                            first_wire_frame=(failure_context or {}).get('first_wire_frame'),
                            runner_returncode=(runner.returncode if runner is not None else None),
                            resident_returncode=(primary.returncode if primary is not None else None),
                            runner_stdout=_decode_captured_pipe_output(runner_out),
                            runner_stderr=raw_runner_stderr,
                            runner_stderr_pipe=_decode_captured_pipe_output(runner_err),
                            resident_stdout=_decode_captured_pipe_output(resident_out),
                            resident_stderr=_decode_captured_pipe_output(resident_err))
                        print('KER_SESSION_FRAME_POSITIVE_FAILURE ' +
                            json.dumps(failure_record, sort_keys=True), flush=True)
                if finalization_errors:
                    raise RuntimeError('handoff actor/pipe cleanup failed before hugepage cleanup: ' +
                        repr([str(error) for error in finalization_errors]))
                cleaned_hugepage_files = cleanup_private_hugepage_dir(huge_parent_path, huge_parent_fd,
                    huge_parent_identity, huge_dir_name, huge_dir_fd, huge_dir_identity,
                    file_prefix, pidfds, resident_pidfd, primary, runner, actor_proof_ready)
            except BaseException as error:
                cleanup_error = error
            finally:
                # Snapshot readiness after actor/hugepage cleanup but before
                # closing the pidfds. The booleans remain valid evidence later.
                try:
                    evidence['actor_pidfd_readable_after_cleanup'], evidence['resident_pidfd_readable_after_cleanup'] = \
                        _capture_pidfd_readability(actor_pidfds, resident_pidfd)
                except (OSError, ValueError) as error:
                    finalization_errors.append(RuntimeError(f'could not snapshot live pidfds: {error}'))
                # Always release process and directory descriptors, even when
                # private-directory validation or reporting refuses deletion.
                closers = []
                if endpoint is not None: closers.append(endpoint.close)
                wire_stop.set()
                if wire_thread is not None:
                    wire_thread.join(timeout=2)
                    if wire_thread.is_alive():
                        finalization_errors.append(RuntimeError('handoff wire peer did not stop'))
                if wire is not None: closers.append(wire.close)
                for process in (runner, primary):
                    if process is not None:
                        for stream in (process.stdin, process.stdout, process.stderr):
                            if stream is not None: closers.append(stream.close)
                closers.extend(lambda fd=fd: os.close(fd) for fd in pidfds)
                if resident_pidfd >= 0: closers.append(lambda: os.close(resident_pidfd))
                if runner_stderr_handle is not None: closers.append(runner_stderr_handle.close)
                closers.extend((lambda: os.close(huge_dir_fd), lambda: os.close(huge_parent_fd)))
                for close in closers:
                    try: close()
                    except BaseException as error: finalization_errors.append(error)
            if finalization_errors:
                close_error = RuntimeError('handoff descriptor finalization failed: ' +
                    repr([str(error) for error in finalization_errors]))
                if cleanup_error is None:
                    cleanup_error = close_error
                else:
                    cleanup_error = RuntimeError(str(cleanup_error) + '; ' + str(close_error))
            if cleanup_error is not None:
                report_hugepage_cleanup_refusal(mode, original_error, cleanup_error)
            if cleaned_hugepage_files is not None:
                print(f'KER_SESSION_HANDOFF_HUGEPAGES_RECLAIMED profile={mode} mode=private '
                    f'files={cleaned_hugepage_files}', flush=True)
            if original_error is None and cleanup_error is None:
                evidence['runner_returncode'] = runner.returncode if runner is not None else None
                evidence['resident_returncode'] = primary.returncode if primary is not None else None
                evidence['runner_stderr'] = (runner_stderr_path.read_text(errors='replace')
                    if runner_stderr_path.exists() else '')
                evidence['resident_stdout'] = (locals().get('primary_output', b'').decode(errors='replace'))
                evidence['resident_stderr'] = (locals().get('primary_errors', b'').decode(errors='replace'))
                evidence['stats'] = (json.loads(stats_path.read_text()) if stats_path.exists() else None)
                evidence['app_returncode'] = (evidence.get('stats') or {}).get('app_code')
                evidence['producer_returncode'] = (evidence.get('stats') or {}).get('worker_code')
                evidence['consumer_returncode'] = (evidence.get('stats') or {}).get('handoff_peer_code')
                frame_locals = locals()
                evidence['wire_observations'] = {name: [frame.hex() for frame in frame_locals[name]]
                    for name in ('wire_snapshot', 'full_wire_snapshot', 'active_wire', 'loss_wire')
                    if name in frame_locals}
                evidence['wire_errors'] = {name: frame_locals[name] for name in
                    ('wire_error_snapshot', 'full_wire_errors', 'active_wire_errors', 'loss_wire_errors')
                    if name in frame_locals}
                if 'first_wire_frame' in frame_locals:
                    evidence['wire_observations']['first_wire_frame'] = frame_locals['first_wire_frame'].hex()
                serial_records = list(evidence['resident_markers'])
                for stream_name, stream_text in (('runner_stderr', evidence['runner_stderr']),
                        ('resident_stdout', evidence['resident_stdout']),
                        ('resident_stderr', evidence['resident_stderr'])):
                    for raw_line in stream_text.splitlines():
                        prefix, separator, payload = raw_line.partition(' ')
                        if separator and prefix.startswith('KER_SESSION_') and payload.startswith('{'):
                            try: parsed = json.loads(payload)
                            except json.JSONDecodeError: continue
                            serial_records.append(dict(source=stream_name, marker=prefix,
                                value=parsed, raw=raw_line))
                evidence['serial_records'] = serial_records
                evidence['capture_sha256'] = hashlib.sha256(
                    json.dumps(evidence, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
                print('KER_SESSION_FRAME_PROFILE_EVIDENCE ' + json.dumps(evidence, sort_keys=True), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('worker', 'tool', 'library', 'app'): parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--inside', action='store_true')
    parser.add_argument('--handoff-negative-profiles', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--dpdk-plugin-dir', type=Path)
    parser.add_argument('--huge-dir', type=Path, default=Path('/dev/hugepages'))
    args = parser.parse_args()
    plugin_dir = resolve_dpdk_plugin_dir(args.dpdk_plugin_dir)
    plugin_paths = resolve_dpdk_plugin_paths(plugin_dir, ('mempool_ring',))
    reason = hugepage_capacity_error(args.huge_dir, 64 * 1024 * 1024)
    if reason:
        print('SKIP: ' + reason + '; no host settings changed'); return 77
    if not args.inside:
        return subprocess.run(namespace_reexec_command(args, plugin_dir)).returncode
    require(Path('/dev/net/tun').exists(), 'original host TAP driver is required')
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    tap = os.open('/dev/net/tun', os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC)
    interface = 'kersession0'
    try: socket.if_nametoindex(interface)
    except OSError: pass
    else: raise RuntimeError('refuse an existing TAP interface')
    fcntl.ioctl(tap, 0x400454ca, struct.pack('16sH22x', interface.encode(), 0x1002))
    for command in (
        ['link', 'set', interface, 'address', '02:4b:45:52:00:01', 'mtu', '1500'],
        ['addr', 'add', '198.18.0.1/24', 'dev', interface],
        ['-6', 'addr', 'add', '2001:db8:1::1/64', 'dev', interface, 'nodad'],
        ['link', 'set', interface, 'up']): subprocess.run(['ip', *command], check=True)
    spec = importlib.util.spec_from_file_location('ker_session_api', args.tool)
    api = importlib.util.module_from_spec(spec); spec.loader.exec_module(api)
    wire, endpoint = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    wire.setblocking(False)
    stop = threading.Event(); errors = []; frames = []; counts = [0, 0]

    def bridge():
        to_tap, to_worker = deque(), deque()
        try:
            while not stop.is_set():
                readers = ([wire] if len(to_tap) < 64 else []) + ([tap] if len(to_worker) < 64 else [])
                writers = ([tap] if to_tap else []) + ([wire] if to_worker else [])
                readable, writable, _ = select.select(readers, writers, [], 0.02)
                if wire in readable:
                    data = wire.recv(65536)
                    require(14 <= len(data) <= 1518, 'malformed native wire frame')
                    to_tap.append(data); frames.append(('native', data))
                if tap in readable:
                    data = os.read(tap, 65536)
                    require(14 <= len(data) <= 1518, 'malformed host TAP frame')
                    to_worker.append(data); frames.append(('host', data))
                if tap in writable:
                    try: amount = os.write(tap, to_tap[0])
                    except BlockingIOError: pass
                    else:
                        require(amount == len(to_tap[0]), 'short TAP frame'); to_tap.popleft(); counts[0] += 1
                if wire in writable:
                    try: amount = wire.send(to_worker[0])
                    except BlockingIOError: pass
                    else:
                        require(amount == len(to_worker[0]), 'short Ethernet channel frame'); to_worker.popleft(); counts[1] += 1
        except ConnectionRefusedError:
            stop.set()  # The worker closes its transferred endpoint after kernel teardown.
        except BaseException as error: errors.append(str(error)); stop.set()

    thread = threading.Thread(target=bridge); thread.start()
    primary = app = standby = None
    exception_capture = None
    with tempfile.TemporaryDirectory(prefix='ker-session-packets-') as directory:
        root = Path(directory); path = root / 'control.sock'; stats_path = root / 'stats.json'
        plugin_options = dpdk_plugin_eal_options(plugin_paths)
        eal = (f'--lcores=0@{min(os.sched_getaffinity(0))} --no-pci --no-telemetry --iova-mode=va '
            f'-m 64 {plugin_options} --huge-dir={shlex.quote(str(args.huge_dir))} '
            f'--file-prefix=packets-{os.getpid()}-{os.urandom(4).hex()}')
        common = ['--socket', str(path), '--worker', str(args.worker), '--eal', eal, '--paired-pmd']
        environment = os.environ | {'RUNTIME_DIRECTORY': str(root), 'PYTHONDONTWRITEBYTECODE': '1'}
        try:
            primary = subprocess.Popen([sys.executable, str(args.tool), 'serve', *common],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, bufsize=0)
            created = record(primary, 'KER_SESSION_READY')
            require(created['rings'] == 128 and created['ports'] == 1 and created['epoch'] == 0 and created['slot'] == 0,
                'resident did not precreate the complete shared geometry and actual network port')
            app = subprocess.Popen([sys.executable, str(args.tool), 'run', *common, '--wire-fd', str(endpoint.fileno()),
                '--library', str(args.library), '--stats', str(stats_path), '--address', '198.18.0.2/24', '--address6', '2001:db8:1::2/64',
                '--', str(args.app), '--fixed-mtu'], pass_fds=(endpoint.fileno(),),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, bufsize=0)
            require(line(app) == 'READY', 'original Linux application did not start')
            initial = json.loads(stats_path.read_text())
            attached, grant, geometry = (initial[key] for key in ('attached', 'grant', 'geometry'))
            require(attached['pid'] == grant['pid'] and attached['validated_rings'] == 128 and geometry['rx_ring'] != geometry['tx_ring'],
                'worker is not the granted actual secondary with directional PMD queues')
            exception_name = created['exception_endpoint_name']
            exception_ifindex = created['exception_endpoint_ifindex']
            require(exception_name.startswith('kex') and exception_ifindex > 0 and
                geometry['exception_endpoint_ifindex'] == exception_ifindex,
                'resident and granted worker disagree on the persistent exception endpoint identity')
            subprocess.run(['ip', 'address', 'add', '198.18.0.77/32', 'dev', exception_name], check=True)
            exception_mac = bytes.fromhex(json.loads(subprocess.check_output(
                ['ip', '-json', 'link', 'show', 'dev', exception_name], text=True))[0]['address'].replace(':', ''))
            exception_capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            exception_capture.bind((exception_name, 0)); exception_capture.setblocking(False)
            require(attached['generation'] == 0 and grant['generation'] == 0 and
                grant['queue_owner_key'] == grant['exception_endpoint_owner_key'] != 0 and
                grant['exception_endpoint_fd'] is True and geometry['exception_endpoint_owner_key'] == grant['queue_owner_key'],
                'PMD queue and session exception endpoint do not share one grant identity')
            connection = api.Connection(path)
            try:
                census = connection.request(api.STATUS)
                require(census['generation'] == 508 and census['token'] == 3 and census['process'] == 1,
                    'packet TX/RX objects not journaled before native application startup')
            finally: connection.close()
            # Trace real process creation without replacing any successful
            # launch: a competing run must never invoke the application guard.
            trace = root / 'trace'; trace.mkdir()
            marker = root / 'forbidden-app-spawn'
            (trace / 'sitecustomize.py').write_text(
                'import os, subprocess\nfrom pathlib import Path\n_original = subprocess.Popen\n'
                'def record(*values, **options):\n'
                ' command = values[0] if values else options.get("args")\n'
                ' if isinstance(command, (list, tuple)) and command and Path(command[0]).name == "ker-app":\n'
                '  Path(os.environ["KER_TEST_APP_SPAWN_MARKER"]).write_text("spawned")\n'
                ' return _original(*values, **options)\nsubprocess.Popen = record\n')
            spare, rejected_endpoint = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
            rejected = subprocess.Popen([sys.executable, str(args.tool), 'run', *common,
                '--wire-fd', str(rejected_endpoint.fileno()), '--library', str(args.library),
                '--address6', '2001:db8:1::2/64', '--', str(args.app)],
                pass_fds=(rejected_endpoint.fileno(),), stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=environment | {'PYTHONPATH': str(trace), 'KER_TEST_APP_SPAWN_MARKER': str(marker)}, bufsize=0)
            rejected_endpoint.close()
            try:
                denied_output, denied_errors = rejected.communicate(timeout=20)
                require(rejected.returncode == 125 and b'PMD consumer grant rejected -16' in denied_errors and
                    b'KER_SESSION_ATTACHED' in denied_errors and not marker.exists(),
                    'busy secondary launched application or bypassed actual admission: ' + denied_errors.decode())
            finally:
                spare.close()
                if rejected.poll() is None: rejected.kill(); rejected.wait()
            standby_stats = root / 'standby.json'
            standby_marker = root / 'standby-app-spawn'
            standby = subprocess.Popen([sys.executable, str(args.tool), 'run', *common, '--standby', '--generation', '1',
                '--wire-fd', str(endpoint.fileno()), '--library', str(args.library),
                '--stats', str(standby_stats), '--address6', '2001:db8:1::2/64',
                '--', str(args.app), '--fixed-mtu'], pass_fds=(endpoint.fileno(),),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=environment | {'PYTHONPATH': str(trace), 'KER_TEST_APP_SPAWN_MARKER': str(standby_marker),
                    'KER_SESSION_TEST_PENDING_HB_BEFORE_PMD': '1'}, bufsize=0)
            endpoint.close()
            deadline = time.monotonic() + 20
            while True:
                waiting = json.loads(standby_stats.read_text()) if standby_stats.exists() else {}
                if waiting.get('stage') == 'standby' and waiting.get('standby_samples', 0) >= 5: break
                require(standby.poll() is None and time.monotonic() < deadline, 'real paired standby did not stay attached')
                time.sleep(0.02)
            pending = waiting['attached']
            require(waiting['standby']['queue_owner_key'] == 0 and
                waiting['standby']['exception_endpoint_owner_key'] == 0 and
                waiting['standby']['exception_endpoint_fd'] is False,
                'denied standby received or claimed the persistent exception endpoint')
            # Inject one uniquely addressed real ARP exception through the session
            # endpoint while a second generation is attached but ungranted.
            exception_sender = bytes.fromhex('024b455200aa')
            arp = (b'\xff' * 6 + exception_sender + b'\x08\x06' +
                struct.pack('!HHBBH', 1, 0x0800, 6, 4, 1) + exception_sender +
                socket.inet_aton('198.18.0.170') + b'\x00' * 6 + socket.inet_aton('198.18.0.77'))
            require(wire.send(arp) == len(arp), 'could not inject the selected ARP exception frame')
            arp_deadline = time.monotonic() + 5
            exception_frames = []
            arp_reply = []
            while time.monotonic() < arp_deadline:
                arp_reply = [frame for direction, frame in frames if direction == 'native' and
                    len(frame) >= 42 and frame[0:6] == exception_sender and frame[12:14] == b'\x08\x06' and
                    frame[20:22] == b'\x00\x02' and frame[22:28] == exception_mac and
                    frame[28:32] == socket.inet_aton('198.18.0.77') and frame[32:38] == exception_sender and
                    frame[38:42] == socket.inet_aton('198.18.0.170')]
                readable, _, _ = select.select([exception_capture], [], [], 0)
                if readable:
                    observed = exception_capture.recv(65536)
                    if observed == arp: exception_frames.append(observed)
                if arp_reply and exception_frames: break
                require(not errors and app.poll() is None and standby.poll() is None,
                    'exception path exited while waiting for the original Linux ARP reply')
                time.sleep(0.01)
            quiet_until = time.monotonic() + 0.15
            while time.monotonic() < quiet_until:
                readable, _, _ = select.select([exception_capture], [], [], 0.01)
                if readable and exception_capture.recv(65536) == arp: exception_frames.append(arp)
            require(len(exception_frames) == 1, 'the fixed exception endpoint did not receive the selected ARP frame exactly once')
            require(len(arp_reply) == 1, 'original Linux did not return exactly one ARP reply through the granted endpoint')
            # A large host UDP datagram forces real IPv4 fragments across the
            # native packet channel. The exception TAP is not a fragment sink;
            # the production counter advances only after packet_fd accepts it.
            fragment_probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                fragment_probe.setsockopt(socket.IPPROTO_IP, getattr(socket, 'IP_MTU_DISCOVER', 10),
                    getattr(socket, 'IP_PMTUDISC_DONT', 0))
                fragment_probe.sendto(bytes((i * 13) & 255 for i in range(4096)), ('198.18.0.2', 44999))
            finally:
                fragment_probe.close()
            def selected_fragment(frame):
                return (len(frame) >= 34 and frame[12:14] == b'\x08\x00' and
                    socket.inet_ntoa(frame[26:30]) == '198.18.0.1' and
                    socket.inet_ntoa(frame[30:34]) == '198.18.0.2' and
                    (struct.unpack('!H', frame[20:22])[0] & 0x3fff) != 0)
            fragment_quiet_until = time.monotonic() + 0.3
            exception_fragments = []
            while time.monotonic() < fragment_quiet_until:
                readable, _, _ = select.select([exception_capture], [], [], 0.01)
                if readable:
                    captured = exception_capture.recv(65536)
                    if selected_fragment(captured): exception_fragments.append(captured)
            require(not exception_fragments, 'IPv4 fragment was copied to the exception TAP instead of native RX')
            require(not waiting['app_started'] and not standby_marker.exists() and
                attached['generation'] == 0 and pending['generation'] == 1 and
                pending['pid'] != attached['pid'] and pending['master'] != attached['master'] and
                pending['epoch'] != attached['epoch'] and pending['slot'] != attached['slot'] and
                pending['rings'] != attached['rings'], 'standby launched an app or reused the owner namespace')
            connection = api.Connection(path)
            try:
                owner = connection.request(api.PMD_STATUS)
                census = connection.request(api.STATUS)
                require(owner['epoch'] == attached['epoch'] and owner['slot'] == attached['slot'] and
                    owner['generation'] == 0 and owner['process'] == attached['process'] == 0 and
                    owner['token'] == grant['queue_owner_key'] and
                    census['generation'] == 507 and census['token'] == 4 and census['process'] == 2,
                    'standby acquired data leases or displaced a live owner')
            finally: connection.close()
            require(not select.select([standby.stdout], [], [], 0)[0], 'standby application produced output before admission')

            # Interrupt another real queued master. It must reap the actual
            # secondary without ever creating an application or data lease.
            spare, canceled_endpoint = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
            canceled_stats = root / 'canceled.json'
            canceled_marker = root / 'canceled-app-spawn'
            canceled = subprocess.Popen([sys.executable, str(args.tool), 'run', *common, '--standby',
                '--wire-fd', str(canceled_endpoint.fileno()), '--library', str(args.library),
                '--stats', str(canceled_stats), '--', str(args.app)], pass_fds=(canceled_endpoint.fileno(),),
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=environment | {'PYTHONPATH': str(trace), 'KER_TEST_APP_SPAWN_MARKER': str(canceled_marker)}, bufsize=0)
            canceled_endpoint.close()
            canceled_pidfd = -1
            try:
                deadline = time.monotonic() + 20
                while True:
                    queued = json.loads(canceled_stats.read_text()) if canceled_stats.exists() else {}
                    if queued.get('stage') == 'standby' and queued.get('standby_samples', 0) >= 3: break
                    require(canceled.poll() is None and time.monotonic() < deadline, 'cancel fixture never queued')
                    time.sleep(0.02)
                canceled_pidfd = os.pidfd_open(queued['attached']['pid'])
                canceled.send_signal(signal.SIGINT)
                canceled_output, canceled_errors = canceled.communicate(timeout=10)
                require(canceled.returncode == 130 and not canceled_output and not canceled_marker.exists() and
                    select.select([canceled_pidfd], [], [], 0)[0],
                    'queued cancellation launched an app or left its real worker alive: ' + canceled_errors.decode())
                deadline = time.monotonic() + 5
                while True:
                    connection = api.Connection(path)
                    try: census = connection.request(api.STATUS)
                    finally: connection.close()
                    if census['generation'] == 507 and census['token'] == 4 and census['process'] == 2: break
                    require(time.monotonic() < deadline, 'queued cancellation leaked its control lease')
                    time.sleep(0.02)
            finally:
                spare.close()
                if canceled_pidfd >= 0: os.close(canceled_pidfd)
                if canceled.poll() is None: canceled.kill(); canceled.wait()
            # SIGTERM while queued owns only its control lease: no packet
            # completion is expected until the PMD grant and packet loop exist.
            queued_trace = root / 'queued-signal-trace'; queued_trace.mkdir()
            (queued_trace / 'sitecustomize.py').write_text(
                'import os, subprocess\nfrom pathlib import Path\n_original = subprocess.Popen\n'
                'def record(*values, **options):\n'
                ' command = values[0] if values else options.get("args")\n'
                ' if isinstance(command, (list, tuple)) and command and Path(command[0]).name == "ker-app":\n'
                '  Path(os.environ["KER_TEST_APP_SPAWN_MARKER"]).write_text("spawned")\n'
                ' return _original(*values, **options)\nsubprocess.Popen = record\n')
            spare, queued_endpoint = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
            queued_stats = root / 'queued-sigterm.json'
            queued_marker = root / 'queued-sigterm-app-spawn'
            queued_term = subprocess.Popen([sys.executable, str(args.tool), 'run', *common, '--standby',
                '--wire-fd', str(queued_endpoint.fileno()), '--library', str(args.library),
                '--stats', str(queued_stats), '--', str(args.app)], pass_fds=(queued_endpoint.fileno(),),
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=environment | {'PYTHONPATH': str(queued_trace),
                    'KER_TEST_APP_SPAWN_MARKER': str(queued_marker)}, bufsize=0)
            queued_endpoint.close()
            queued_pidfd = -1
            try:
                deadline = time.monotonic() + 20
                while True:
                    queued = json.loads(queued_stats.read_text()) if queued_stats.exists() else {}
                    if queued.get('stage') == 'standby' and queued.get('standby_samples', 0) >= 3: break
                    require(queued_term.poll() is None and time.monotonic() < deadline,
                        'SIGTERM fixture never reached control-only standby')
                    time.sleep(0.02)
                queued_pidfd = os.pidfd_open(queued['attached']['pid'])
                queued_term.send_signal(signal.SIGTERM)
                queued_output, queued_errors = queued_term.communicate(timeout=10)
                queued = json.loads(queued_stats.read_text())
                require(queued_term.returncode == 143 and not queued_output and not queued_marker.exists() and
                    queued['stage'] == 'interrupted' and queued['signal'] == signal.SIGTERM and
                    not queued['app_started'] and queued['packet'] is None and queued['worker_code'] == 0 and
                    queued['app_code'] is None and select.select([queued_pidfd], [], [], 0)[0] and
                    b'KER_SESSION_PACKET_DONE' not in queued_errors,
                    'queued SIGTERM launched an app or reported packet activity: ' + repr(queued) + queued_errors.decode())
                connection = api.Connection(path)
                try:
                    owner = connection.request(api.PMD_STATUS)
                    census = connection.request(api.STATUS)
                    require(owner['epoch'] == attached['epoch'] and owner['slot'] == attached['slot'] and
                        census['generation'] == 507 and census['token'] == 4 and census['process'] == 2,
                        'queued SIGTERM changed original PMD ownership or leaked its control lease')
                finally: connection.close()
                print('PASS: queued SIGTERM returns143 with no app/packet activity and restores only the control lease')
            finally:
                spare.close()
                if queued_pidfd >= 0: os.close(queued_pidfd)
                if queued_term.poll() is None: queued_term.kill(); queued_term.wait()
            print('CHECK: live paired standby and canceled standby have no native application', flush=True)

            def exchange_native(process, *, finish=True):
                process.stdin.write(b'G'); process.stdin.flush()
                payload = bytes((i * 17 + (i >> 8)) & 255 for i in range(4097))
                for family, address in ((socket.AF_INET, '198.18.0.2'), (socket.AF_INET6, '2001:db8:1::2')):
                    with socket.socket(family, socket.SOCK_STREAM) as client:
                        client.settimeout(10); client.connect((address, 45000)); client.sendall(payload)
                        data = bytearray()
                        while True:
                            chunk = client.recv(8192)
                            if not chunk: break
                            data.extend(chunk)
                        require(bytes(data) == b'NATIVE:' + payload, 'native TCP bytes/EOF differ')
                    with socket.socket(family, socket.SOCK_DGRAM) as client:
                        client.settimeout(10); client.sendto(payload[:512], (address, 45000))
                        data, peer = client.recvfrom(8192)
                        require(data == b'NATIVE:' + payload[:512] and peer[0] == address, 'native UDP reply/peer differ')
                require(line(process) == 'NATIVE_DONE', 'native MTU rollback/service completion failed')
                if finish:
                    process.stdin.write(b'Q'); process.stdin.flush()

            def graceful_signal_release(process, stats_file, control_path):
                before = json.loads(stats_file.read_text())
                require(before.get('app_started') and before.get('stage') == 'application-started' and
                    before['grant']['queue_owner_key'] == before['grant']['exception_endpoint_owner_key'] != 0,
                    'replacement owner did not reach a fully granted application before cleanup')
                app_fd = os.pidfd_open(before['app_pid'])
                worker_fd = os.pidfd_open(before['attached']['pid'])
                try:
                    process.send_signal(signal.SIGTERM)
                    output, errors = process.communicate(timeout=20)
                    after = json.loads(stats_file.read_text())
                    require(process.returncode == 143 and after.get('stage') == 'interrupted' and
                        after.get('native_cleanup') == 'graceful' and after.get('app_code') == 143 and
                        after.get('worker_code') == 0 and after.get('packet', {}).get('status') == 0 and
                        after.get('native', {}).get('buffers_live') == 0 and
                        select.select([app_fd], [], [], 0)[0] and select.select([worker_fd], [], [], 0)[0],
                        'signal cleanup did not reap the replacement owner cleanly: ' + repr(after) + errors.decode())
                    connection = api.Connection(control_path)
                    try:
                        census = connection.request(api.STATUS)
                        require(census['generation'] == 511 and census['token'] == 0 and census['process'] == 0,
                            'replacement owner cleanup left a shared object leased')
                    finally: connection.close()
                    return output
                finally:
                    os.close(app_fd); os.close(worker_fd)

            exchange_native(app)
            output, stderr = app.communicate(timeout=20)
            require(app.returncode == 0, 'packet-session application failed: ' + output.decode() + stderr.decode())
            require(b'PASS: original native IPv4/IPv6 TCP/UDP services' in output, 'native application proof absent')
            finished = json.loads(stats_path.read_text())
            require(finished['stage'] == 'finished' and finished['app_started'], 'supervisor completion snapshot absent')
            stats, native = finished['packet'], finished['native']
            require(stats['tx'] > 0 and stats['rx'] > 0 and stats['to_wire'] > 0 and stats['from_wire'] > 0 and stats['status'] == 0 and
                stats['exception_from_wire'] >= 1 and stats['exception_to_wire'] >= 1 and stats['exception_to_native'] >= 1 and
                stats['exception_endpoint_owner_key'] == grant['queue_owner_key'] and stats['fragment_to_native'] >= 1,
                'actual single-owner ARP exception, fragment-to-native route, or endpoint identity accounting differs')
            require(native['passive_opens'] >= 2 and native['udp_in_datagrams'] >= 1 and native['udp_out_datagrams'] >= 1 and
                native['udp6_in_datagrams'] >= 1 and native['udp6_out_datagrams'] >= 1 and native['buffers_live'] == 0,
                'traffic bypassed original Linux or retained native buffers')
            require(line(standby) == 'READY', 'retained standby did not start a real original Linux application')
            admitted = json.loads(standby_stats.read_text())
            require(admitted['attached'] == pending and admitted['grant']['pid'] == pending['pid'] and
                admitted['grant']['epoch'] == pending['epoch'] and admitted['grant']['generation'] == 1 and
                admitted['grant']['exception_endpoint_ifindex'] == exception_ifindex and
                admitted['grant']['exception_endpoint_fd'] is True and standby_marker.exists(),
                'takeover restarted the standby PID/EAL/epoch or skipped the real application launch')
            connection = api.Connection(path)
            try:
                owner = connection.request(api.PMD_STATUS)
                census = connection.request(api.STATUS)
                require(owner['epoch'] == pending['epoch'] and owner['slot'] == pending['slot'] and
                    owner['generation'] == 1 and owner['process'] == 0 and
                    owner['token'] == admitted['grant']['queue_owner_key'] == admitted['grant']['exception_endpoint_owner_key'] and
                    owner['token'] != 0 and census['generation'] == 508 and census['token'] == 3 and census['process'] == 1,
                    'takeover did not transfer exactly the two journaled device objects')
            finally: connection.close()
            exchange_native(standby)
            print('CHECK: same-PID retained standby completed real TCP/UDP traffic', flush=True)
            standby_output, standby_errors = standby.communicate(timeout=20)
            require(standby.returncode == 0 and b'PASS: original native IPv4/IPv6 TCP/UDP services' in standby_output,
                'native traffic after same-PID takeover failed: ' + standby_errors.decode())
            require(b'KER_SESSION_TEST_PENDING_HB_QUEUED' in standby_errors and
                b'KER_SESSION_TEST_PENDING_HB_DRAINED' in standby_errors,
                'paired standby PMD acquisition did not exercise the queued-heartbeat boundary')
            taken = json.loads(standby_stats.read_text())
            require(taken['stage'] == 'finished' and taken['packet']['tx'] > 0 and taken['packet']['rx'] > 0 and
                taken['native']['passive_opens'] >= 2 and taken['native']['udp_in_datagrams'] >= 1 and
                taken['native']['udp6_in_datagrams'] >= 1 and taken['native']['buffers_live'] == 0,
                'takeover traffic bypassed original PMD/Linux or left native buffers')
            stop.set(); thread.join(timeout=3)
            require(not thread.is_alive(), 'external Ethernet bridge did not stop')
            connection = api.Connection(path)
            try:
                census = connection.request(api.STATUS)
                require(census['generation'] == 511 and census['token'] == 0 and census['process'] == 0,
                    'original control/TX/RX objects not returned after both exact secondary deaths')
            finally: connection.close()
            protocols = set()
            for direction, frame in frames:
                if frame[12:14] == b'\x08\x00' and len(frame) >= 34: protocols.add((direction, 4, frame[23]))
                if frame[12:14] == b'\x86\xdd' and len(frame) >= 54: protocols.add((direction, 6, frame[20]))
            require(all((direction, version, protocol) in protocols for direction in ('native', 'host')
                for version in (4, 6) for protocol in (6, 17)), 'independent Ethernet capture missed TCP/UDP directions')
            require(not errors and all(counts), 'external wire bridge failed: ' + repr(errors))
            # Kill the real granted worker at the published worker-ready
            # boundary. Both instrumentation wrappers forward real operations;
            # neither creates a successful fake child or fake EAL reply.
            with (trace / 'sitecustomize.py').open('a') as out:
                out.write('import json, select, signal\n_replace = os.replace\n'
                    'def replace(source, target):\n'
                    ' result = _replace(source, target)\n'
                    ' if os.fspath(target) == os.environ.get("KER_TEST_KILL_AT_WORKER_READY"):\n'
                    '  data = json.loads(Path(target).read_text())\n'
                    '  if data.get("stage") == "worker-ready":\n'
                    '   fd = os.pidfd_open(data["attached"]["pid"])\n'
                    '   try:\n'
                    '    signal.pidfd_send_signal(fd, signal.SIGKILL)\n'
                    '    if not select.select([fd], [], [], 5)[0]:raise RuntimeError("test worker death timeout")\n'
                    '   finally:os.close(fd)\n'
                    ' return result\nos.replace = replace\n')
            spare, prestart_endpoint = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
            prestart_stats = root / 'prestart.json'
            prestart = subprocess.Popen([sys.executable, str(args.tool), 'run', *common,
                '--wire-fd', str(prestart_endpoint.fileno()), '--library', str(args.library),
                '--stats', str(prestart_stats), '--', str(args.app)], pass_fds=(prestart_endpoint.fileno(),),
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=environment | {'PYTHONPATH': str(trace), 'KER_TEST_APP_SPAWN_MARKER': str(marker),
                    'KER_TEST_KILL_AT_WORKER_READY': str(prestart_stats)}, bufsize=0)
            prestart_endpoint.close()
            try:
                prestart_output, prestart_errors = prestart.communicate(timeout=20)
                snapshot = json.loads(prestart_stats.read_text())
                require(prestart.returncode == 125 and b'exited before application launch' in prestart_errors and
                    not marker.exists() and snapshot['stage'] == 'failed' and not snapshot['app_started'],
                    'known dead ready worker still launched an app: ' + prestart_errors.decode())
            finally:
                spare.close()
                if prestart.poll() is None: prestart.kill(); prestart.wait()
            # Deliver SIGTERM to the real launcher just after it starts its
            # actual worker. It must wait for EAL startup, quiesce that worker,
            # and return the signal status without ever spawning ker-app.
            with (trace / 'sitecustomize.py').open('a') as out:
                out.write('import signal\n_start_worker = subprocess.Popen\n'
                    'def signal_after_worker(*values, **options):\n'
                    ' command = values[0] if values else options.get("args")\n'
                    ' result = _start_worker(*values, **options)\n'
                    ' if isinstance(command, (list, tuple)) and command and Path(command[0]).name == "ker-io-session":\n'
                    '  os.kill(os.getpid(), signal.SIGTERM)\n'
                    ' return result\nsubprocess.Popen = signal_after_worker\n')
            signal_stats = root / 'signal-before-app.json'
            spare, signal_endpoint = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
            signalled = subprocess.Popen([sys.executable, str(args.tool), 'run', *common,
                '--wire-fd', str(signal_endpoint.fileno()), '--library', str(args.library),
                '--stats', str(signal_stats), '--', str(args.app)], pass_fds=(signal_endpoint.fileno(),),
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=environment | {'PYTHONPATH': str(trace)}, bufsize=0)
            signal_endpoint.close()
            try:
                _, signal_errors = signalled.communicate(timeout=20)
                snapshot = json.loads(signal_stats.read_text())
                require(signalled.returncode == 143 and not snapshot['app_started'] and
                    snapshot['stage'] == 'interrupted' and b'KER_SESSION_PACKET_DONE' in signal_errors and
                    not marker.exists(), 'pre-app SIGTERM did not clean the actual worker: ' + signal_errors.decode())
                print('PASS: pre-app SIGTERM drains the actual worker, returns143, and never launches ker-app')
            finally:
                spare.close()
                if signalled.poll() is None: signalled.kill(); signalled.wait()
            # Fail an actual granted worker while the real native application
            # is waiting at its setup barrier. The supervisor must report125,
            # stop the app and recover all three original journaled objects.
            sink, failed_endpoint = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
            failed = subprocess.Popen([sys.executable, str(args.tool), 'run', *common,
                '--wire-fd', str(failed_endpoint.fileno()), '--library', str(args.library),
                '--address6', '2001:db8:1::2/64', '--stats', str(root / 'failed.json'), '--', str(args.app)],
                pass_fds=(failed_endpoint.fileno(),), stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, bufsize=0)
            failed_endpoint.close()
            worker_pidfd = -1
            try:
                require(line(failed) == 'READY', 'failure fixture did not reach original Linux')
                failed_worker = json.loads((root / 'failed.json').read_text())['attached']
                worker_pidfd = os.pidfd_open(failed_worker['pid'])
                signal.pidfd_send_signal(worker_pidfd, signal.SIGKILL)
                failed.wait(timeout=15)  # Keep stdin open so EOF cannot mask backend loss.
                failed_output, failed_errors = failed.communicate(timeout=2)
                require(failed.returncode == 125 and b'exited while application was running' in failed_errors and
                    b'PASS:' not in failed_output and select.select([worker_pidfd], [], [], 0)[0],
                    'worker loss was reported as successful application teardown: ' + failed_errors.decode())
                deadline = time.monotonic() + 5
                while True:
                    connection = api.Connection(path)
                    try: census = connection.request(api.STATUS)
                    finally: connection.close()
                    if census['generation'] == 511 and census['token'] == 0 and census['process'] == 0: break
                    require(time.monotonic() < deadline, 'worker death leaked original packet/control objects')
                    time.sleep(0.02)
            finally:
                sink.close()
                if worker_pidfd >= 0: os.close(worker_pidfd)
                if failed.poll() is None: failed.kill(); failed.wait()
            # SIGTERM the real launcher while its original Linux application
            # is held at READY with stdin still open. The launcher must reap
            # both native children and preserve the conventional signal status.
            sink, interrupted_endpoint = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
            interrupted_stats = root / 'interrupted.json'
            interrupted = subprocess.Popen([sys.executable, str(args.tool), 'run', *common,
                '--wire-fd', str(interrupted_endpoint.fileno()), '--library', str(args.library),
                '--stats', str(interrupted_stats), '--address6', '2001:db8:1::2/64', '--', str(args.app), '--signal-ready'],
                pass_fds=(interrupted_endpoint.fileno(),), stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, bufsize=0)
            interrupted_endpoint.close()
            app_pidfd = worker_pidfd = -1
            try:
                require(line(interrupted) == 'READY', 'SIGTERM fixture did not reach original Linux')
                snapshot = json.loads(interrupted_stats.read_text())
                app_pidfd = os.pidfd_open(snapshot['app_pid'])
                worker_pidfd = os.pidfd_open(snapshot['attached']['pid'])
                interrupted.send_signal(signal.SIGTERM)
                interrupted_output, interrupted_errors = interrupted.communicate(timeout=15)
                snapshot = json.loads(interrupted_stats.read_text())
                require(interrupted.returncode == 143 and snapshot['stage'] == 'interrupted' and
                    snapshot['native_cleanup'] == 'graceful' and snapshot['native']['buffers_live'] == 0 and
                    snapshot['worker_code'] == 0 and snapshot['packet']['status'] == 0 and
                    select.select([app_pidfd], [], [], 0)[0] and select.select([worker_pidfd], [], [], 0)[0],
                    'SIGTERM did not report exact child cleanup: ' + repr(snapshot) + interrupted_errors.decode())
                connection = api.Connection(path)
                try:
                    census = connection.request(api.STATUS)
                    require(census['generation'] == 511 and census['token'] == 0 and census['process'] == 0,
                        'SIGTERM left original session pool objects leased')
                finally: connection.close()
            finally:
                sink.close()
                for pidfd in (app_pidfd, worker_pidfd):
                    if pidfd >= 0: os.close(pidfd)
                if interrupted.poll() is None: interrupted.kill(); interrupted.wait()
            primary.stdin.close(); primary.stdin = None
            try:
                primary_output, primary_errors = primary.communicate(timeout=20)
            except subprocess.TimeoutExpired:
                primary.kill()
                primary_output, primary_errors = primary.communicate(timeout=5)
                raise RuntimeError('resident packet cleanup timed out: stdout=' + primary_output.decode(errors='replace') +
                    ' stderr=' + primary_errors.decode(errors='replace'))
            require(primary.returncode == 0, 'resident packet-device cleanup failed: ' + primary_errors.decode(errors='replace'))
            require(b'KER_SESSION_DRAINED' in primary_output, 'resident pool cleanup proof absent')
            # Stop the resident while a second real native application remains
            # at READY. Its registration socket must quiesce the worker inside
            # the resident's five second cleanup window.
            stop_path = root / 'resident-stop.sock'
            stop_common = ['--socket', str(stop_path), '--worker', str(args.worker), '--eal', eal,
                '--paired-pmd']
            stopping_primary = subprocess.Popen([sys.executable, str(args.tool), 'serve', *stop_common],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, bufsize=0)
            record(stopping_primary, 'KER_SESSION_READY')
            sink, resident_endpoint = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
            resident_stats = root / 'resident-stop.json'
            resident_app = subprocess.Popen([sys.executable, str(args.tool), 'run', *stop_common,
                '--wire-fd', str(resident_endpoint.fileno()), '--library', str(args.library),
                '--stats', str(resident_stats), '--address6', '2001:db8:1::2/64', '--', str(args.app)],
                pass_fds=(resident_endpoint.fileno(),), stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, bufsize=0)
            resident_endpoint.close()
            app_pidfd = worker_pidfd = -1
            try:
                require(line(resident_app) == 'READY', 'resident-shutdown fixture did not reach original Linux')
                snapshot = json.loads(resident_stats.read_text())
                app_pidfd = os.pidfd_open(snapshot['app_pid'])
                worker_pidfd = os.pidfd_open(snapshot['attached']['pid'])
                stopping_primary.send_signal(signal.SIGTERM)
                resident_output, resident_errors = stopping_primary.communicate(timeout=8)
                launcher_output, launcher_errors = resident_app.communicate(timeout=12)
                require(stopping_primary.returncode == 0 and b'KER_SESSION_DRAINED' in resident_output,
                    'resident did not complete normal DRAINED cleanup: ' + resident_errors.decode())
                require(resident_app.returncode == 125 and b'worker exited while application was running' in launcher_errors and
                    select.select([app_pidfd], [], [], 0)[0] and select.select([worker_pidfd], [], [], 0)[0],
                    'resident shutdown did not reap launcher children or report backend loss: ' + launcher_errors.decode())
            finally:
                sink.close()
                for pidfd in (app_pidfd, worker_pidfd):
                    if pidfd >= 0: os.close(pidfd)
                for process in (resident_app, stopping_primary):
                    if process.poll() is None: process.kill(); process.wait()
            # Deterministically stop after phase 2 is published but before the
            # destructive TAP write. The resident must fail closed, not regrant.
            boundary_path = root / 'exception-write-boundary.sock'
            boundary_eal = eal.replace('packets-', 'exception-write-boundary-')
            boundary_common = ['--socket', str(boundary_path), '--worker', str(args.worker),
                '--eal', boundary_eal, '--paired-pmd']
            boundary_marker = root / 'hold-exception-write'
            boundary_environment = environment | {'KER_SESSION_TEST_HOLD_EXCEPTION_WRITE': str(boundary_marker)}
            boundary_primary = subprocess.Popen([sys.executable, str(args.tool), 'serve', *boundary_common],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=boundary_environment, bufsize=0)
            boundary_ready = record(boundary_primary, 'KER_SESSION_READY')
            boundary_wire, boundary_endpoint = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
            boundary_stats = root / 'exception-write-owner.json'
            boundary_owner = subprocess.Popen([sys.executable, str(args.tool), 'run', *boundary_common,
                '--wire-fd', str(boundary_endpoint.fileno()), '--library', str(args.library),
                '--address6', '2001:db8:1::2/64', '--stats', str(boundary_stats), '--', str(args.app)],
                pass_fds=(boundary_endpoint.fileno(),), stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=boundary_environment, bufsize=0)
            boundary_endpoint.close()
            try:
                require(line(boundary_owner) == 'READY', 'write-boundary owner did not reach original Linux')
                boundary_state = json.loads(boundary_stats.read_text())
                boundary_grant = boundary_state['grant']
                require(boundary_state['attached']['pid'] == boundary_grant['pid'] and
                    boundary_grant['queue_owner_key'] == boundary_grant['exception_endpoint_owner_key'] != 0 and
                    boundary_grant['exception_endpoint_ifindex'] == boundary_ready['exception_endpoint_ifindex'] and
                    boundary_grant['exception_endpoint_fd'] is True,
                    'write-boundary owner did not hold the paired PMD/TAP grant before standby startup')
            except BaseException:
                boundary_wire.close()
                for process in (boundary_owner, boundary_primary):
                    if process.poll() is None: process.kill(); process.wait()
                raise
            boundary_standby_stats = root / 'exception-write-standby.json'
            boundary_standby_wire = boundary_standby_endpoint = boundary_standby = None
            try:
                boundary_standby_wire, boundary_standby_endpoint = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
                boundary_standby = subprocess.Popen([sys.executable, str(args.tool), 'run', *boundary_common,
                    '--standby', '--wire-fd', str(boundary_standby_endpoint.fileno()), '--library', str(args.library),
                    '--address6', '2001:db8:1::2/64', '--stats', str(boundary_standby_stats), '--', str(args.app)],
                    pass_fds=(boundary_standby_endpoint.fileno(),), stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, bufsize=0)
                boundary_standby_endpoint.close(); boundary_standby_endpoint = None
            except BaseException:
                if boundary_standby_endpoint is not None: boundary_standby_endpoint.close()
                if boundary_standby_wire is not None: boundary_standby_wire.close()
                boundary_wire.close()
                for process in (boundary_standby, boundary_owner, boundary_primary):
                    if process is not None and process.poll() is None: process.kill(); process.wait()
                raise
            boundary_pidfd = -1
            try:
                deadline = time.monotonic() + 15
                while True:
                    state = json.loads(boundary_standby_stats.read_text()) if boundary_standby_stats.exists() else {}
                    if state.get('stage') == 'standby' and state.get('standby_samples', 0) >= 2: break
                    require(boundary_standby.poll() is None and time.monotonic() < deadline,
                        'write-boundary standby did not remain attached')
                    time.sleep(0.02)
                boundary_pending = state['attached']
                require(boundary_pending['generation'] == 0 and
                    state['standby']['queue_owner_key'] == 0 and
                    state['standby']['exception_endpoint_owner_key'] == 0 and
                    state['standby']['exception_endpoint_fd'] is False,
                    'phase-2 standby unexpectedly held an endpoint grant before owner death')
                boundary_marker.touch()
                frame = (b'\xff' * 6 + bytes.fromhex('024b455200aa') + b'\x08\x06' +
                    struct.pack('!HHBBH', 1, 0x0800, 6, 4, 1) + bytes.fromhex('024b455200aa') +
                    socket.inet_aton('198.18.0.170') + b'\x00' * 6 + socket.inet_aton('198.18.0.77'))
                require(boundary_wire.send(frame) == len(frame), 'write-boundary frame injection failed')
                owner_state = json.loads(boundary_stats.read_text())
                worker_pid = owner_state['attached']['pid']; boundary_pidfd = os.pidfd_open(worker_pid)
                deadline = time.monotonic() + 10
                stopped = False
                while time.monotonic() < deadline:
                    try: status_text = Path(f'/proc/{worker_pid}/status').read_text()
                    except FileNotFoundError: break
                    stopped = any(line.startswith('State:') and line.split()[1] == 'T' for line in status_text.splitlines())
                    if stopped: break
                    time.sleep(0.01)
                require(stopped, 'worker did not stop after publishing phase 2 before TAP write')
                signal.pidfd_send_signal(boundary_pidfd, signal.SIGKILL)
                require(select.select([boundary_pidfd], [], [], 5)[0], 'phase-2 owner death was not observed')
                os.close(boundary_pidfd); boundary_pidfd = -1
                boundary_owner.communicate(timeout=15)
                primary_output, primary_errors = boundary_primary.communicate(timeout=10)
                standby_output, standby_errors = boundary_standby.communicate(timeout=10)
                standby_state = json.loads(boundary_standby_stats.read_text())
                require(boundary_primary.returncode == 125 and b'KER_SESSION_DRAINED' not in primary_output and
                    boundary_standby.returncode == 125 and standby_state.get('stage') == 'failed' and
                    not standby_state.get('app_started', False) and 'grant' not in standby_state and
                    standby_state.get('attached') == boundary_pending and not standby_output,
                    'ambiguous TAP write was reassigned instead of failing the session closed: ' +
                    primary_errors.decode(errors='replace') + standby_errors.decode(errors='replace'))
            finally:
                if boundary_pidfd >= 0: os.close(boundary_pidfd)
                boundary_wire.close(); boundary_standby_wire.close()
                for process in (boundary_owner, boundary_primary, boundary_standby):
                    if process.poll() is None: process.kill(); process.wait()
            # Stop the actual granted worker after a TAP output has entered the
            # exact RX lease/PMD TX path but before external-wire send. Reaping
            # must account this known one-frame discard exactly once.
            discard_path = root / 'exception-discard.sock'
            discard_eal = eal.replace('packets-', 'exception-discard-')
            discard_common = ['--socket', str(discard_path), '--worker', str(args.worker),
                '--eal', discard_eal, '--paired-pmd']
            discard_marker = root / 'hold-exception-output'
            discard_environment = environment | {'KER_SESSION_TEST_HOLD_EXCEPTION_OUTPUT': str(discard_marker)}
            discard_primary = subprocess.Popen([sys.executable, str(args.tool), 'serve', *discard_common],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=discard_environment, bufsize=0)
            discard_ready = record(discard_primary, 'KER_SESSION_READY')
            discard_wire, discard_endpoint = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
            discard_stats = root / 'exception-discard-owner.json'
            discard_owner = subprocess.Popen([sys.executable, str(args.tool), 'run', *discard_common,
                '--wire-fd', str(discard_endpoint.fileno()), '--library', str(args.library),
                '--address6', '2001:db8:1::2/64', '--stats', str(discard_stats), '--', str(args.app)],
                pass_fds=(discard_endpoint.fileno(),), stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=discard_environment, bufsize=0)
            discard_endpoint.close()
            try:
                require(line(discard_owner) == 'READY', 'exception-discard owner did not reach original Linux')
                discard_state = json.loads(discard_stats.read_text())
                discard_grant = discard_state['grant']
                require(discard_state['attached']['pid'] == discard_grant['pid'] and
                    discard_grant['queue_owner_key'] == discard_grant['exception_endpoint_owner_key'] != 0 and
                    discard_grant['exception_endpoint_ifindex'] == discard_ready['exception_endpoint_ifindex'] and
                    discard_grant['exception_endpoint_fd'] is True,
                    'exception-discard owner did not hold the paired PMD/TAP grant before standby startup')
            except BaseException:
                discard_wire.close()
                for process in (discard_owner, discard_primary):
                    if process.poll() is None: process.kill(); process.wait()
                raise
            discard_standby_stats = root / 'exception-discard-standby.json'
            standby_wire = standby_endpoint = discard_standby = None
            try:
                standby_wire, standby_endpoint = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
                discard_standby = subprocess.Popen([sys.executable, str(args.tool), 'run', *discard_common,
                    '--standby', '--wire-fd', str(standby_endpoint.fileno()), '--library', str(args.library),
                    '--address6', '2001:db8:1::2/64', '--stats', str(discard_standby_stats), '--', str(args.app), '--signal-ready'],
                    pass_fds=(standby_endpoint.fileno(),), stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, bufsize=0)
                standby_endpoint.close(); standby_endpoint = None
            except BaseException:
                if standby_endpoint is not None: standby_endpoint.close()
                if standby_wire is not None: standby_wire.close()
                discard_wire.close()
                for process in (discard_standby, discard_owner, discard_primary):
                    if process is not None and process.poll() is None: process.kill(); process.wait()
                raise
            discard_pidfd = -1
            try:
                deadline = time.monotonic() + 15
                while True:
                    state = json.loads(discard_standby_stats.read_text()) if discard_standby_stats.exists() else {}
                    if state.get('stage') == 'standby' and state.get('standby_samples', 0) >= 2: break
                    require(discard_standby.poll() is None and time.monotonic() < deadline,
                        'exception-discard standby did not remain attached')
                    time.sleep(0.02)
                subprocess.run(['ip', 'address', 'add', '198.18.0.99/32',
                    'dev', discard_ready['exception_endpoint_name']], check=True)
                raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
                raw.bind((discard_ready['exception_endpoint_name'], 0))
                frame = (b'\xff' * 6 + bytes.fromhex('024b45520099') + b'\x08\x06' +
                    struct.pack('!HHBBH', 1, 0x0800, 6, 4, 1) + bytes.fromhex('024b45520099') +
                    socket.inet_aton('198.18.0.170') + b'\x00' * 6 + socket.inet_aton('198.18.0.99'))
                discard_marker.touch()
                require(raw.send(frame) == len(frame), 'could not inject test Ethernet frame into the resident TAP')
                raw.close()
                owner_state = json.loads(discard_stats.read_text())
                worker_pid = owner_state['attached']['pid']; discard_pidfd = os.pidfd_open(worker_pid)
                deadline = time.monotonic() + 10
                stopped = False
                while time.monotonic() < deadline:
                    try: status_text = Path(f'/proc/{worker_pid}/status').read_text()
                    except FileNotFoundError: break
                    stopped = any(line.startswith('State:') and 'T' in line for line in status_text.splitlines())
                    if stopped: break
                    time.sleep(0.01)
                require(stopped, 'worker did not stop at the published phase-5 output boundary')
                signal.pidfd_send_signal(discard_pidfd, signal.SIGKILL)
                require(select.select([discard_pidfd], [], [], 5)[0], 'phase-5 worker death was not observed')
                os.close(discard_pidfd); discard_pidfd = -1
                discard_owner.communicate(timeout=15)
                require(discard_owner.returncode == 125, 'killed packet owner did not report backend failure')
                require(line(discard_standby) == 'READY', 'standby did not inherit the exact persistent endpoint after phase-5 reclaim')
                admitted = json.loads(discard_standby_stats.read_text())
                require(admitted['grant']['queue_owner_key'] == admitted['grant']['exception_endpoint_owner_key'] != 0 and
                    admitted['grant']['exception_endpoint_ifindex'] == discard_ready['exception_endpoint_ifindex'] and
                    admitted['grant']['exception_endpoint_fd'] is True,
                    'phase-5 regrant did not retain the same endpoint identity/fd authorization')
                discard_standby_output = graceful_signal_release(discard_standby, discard_standby_stats, discard_path)
                discard_primary.stdin.close(); discard_primary.stdin = None
                discard_primary_output, discard_primary_errors = discard_primary.communicate(timeout=20)
                require(discard_primary.returncode == 0, 'exception-discard resident cleanup failed: ' + discard_primary_errors.decode())
                reclaim_records = [json.loads(line.removeprefix('KER_SESSION_EXCEPTION_RECLAIM '))
                    for line in discard_primary_output.decode().splitlines()
                    if line.startswith('KER_SESSION_EXCEPTION_RECLAIM ')]
                drained_records = [json.loads(line.removeprefix('KER_SESSION_DRAINED '))
                    for line in discard_primary_output.decode().splitlines() if line.startswith('KER_SESSION_DRAINED ')]
                require(reclaim_records == [{'phase': 5, 'discarded': 1, 'total': 1}] and
                    drained_records and drained_records[-1]['exception_lease_discarded'] == 1,
                    'resident did not account the single known phase-5 output discard exactly once')
            finally:
                if discard_pidfd >= 0: os.close(discard_pidfd)
                discard_wire.close(); standby_wire.close()
                for process in (discard_owner, discard_primary, discard_standby):
                    if process.poll() is None: process.kill(); process.wait()
            # Phase 7 means the selected exception frame has been copied to
            # the persistent TAP, but the same journaled mbuf is still pending
            # native RX. Kill the exact owner at that boundary and prove one
            # discard is accounted before the same endpoint is regranted.
            native_path = root / 'exception-native.sock'
            native_eal = eal.replace('packets-', 'exception-native-')
            native_common = ['--socket', str(native_path), '--worker', str(args.worker),
                '--eal', native_eal, '--paired-pmd']
            native_marker = root / 'hold-exception-native'
            native_environment = environment | {'KER_SESSION_TEST_HOLD_EXCEPTION_NATIVE': str(native_marker)}
            native_primary = subprocess.Popen([sys.executable, str(args.tool), 'serve', *native_common],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=native_environment, bufsize=0)
            native_ready = record(native_primary, 'KER_SESSION_READY')
            native_wire, native_endpoint = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
            native_owner_stats = root / 'exception-native-owner.json'
            native_owner = subprocess.Popen([sys.executable, str(args.tool), 'run', *native_common,
                '--wire-fd', str(native_endpoint.fileno()), '--library', str(args.library),
                '--address6', '2001:db8:1::2/64', '--stats', str(native_owner_stats), '--', str(args.app)],
                pass_fds=(native_endpoint.fileno(),), stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=native_environment, bufsize=0)
            native_endpoint.close()
            native_standby_wire = native_standby_endpoint = native_standby = None
            native_pidfd = -1
            try:
                require(line(native_owner) == 'READY', 'phase-7 owner did not reach original Linux')
                native_owner_state = json.loads(native_owner_stats.read_text())
                native_grant = native_owner_state['grant']
                require(native_owner_state['attached']['pid'] == native_grant['pid'] and
                    native_grant['queue_owner_key'] == native_grant['exception_endpoint_owner_key'] != 0 and
                    native_grant['exception_endpoint_ifindex'] == native_ready['exception_endpoint_ifindex'] and
                    native_grant['exception_endpoint_fd'] is True,
                    'phase-7 owner did not hold the endpoint grant')
                subprocess.run(['ip', 'address', 'add', '198.18.0.100/32',
                    'dev', native_ready['exception_endpoint_name']], check=True)
                native_standby_stats = root / 'exception-native-standby.json'
                native_standby_wire, native_standby_endpoint = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
                native_standby = subprocess.Popen([sys.executable, str(args.tool), 'run', *native_common,
                    '--standby', '--generation', '1', '--wire-fd', str(native_standby_endpoint.fileno()),
                    '--library', str(args.library), '--address6', '2001:db8:1::2/64',
                    '--stats', str(native_standby_stats), '--', str(args.app), '--signal-ready'],
                    pass_fds=(native_standby_endpoint.fileno(),), stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, bufsize=0)
                native_standby_endpoint.close(); native_standby_endpoint = None
                deadline = time.monotonic() + 15
                while True:
                    state = json.loads(native_standby_stats.read_text()) if native_standby_stats.exists() else {}
                    if state.get('stage') == 'standby' and state.get('standby_samples', 0) >= 2: break
                    require(native_standby.poll() is None and time.monotonic() < deadline,
                        'phase-7 standby did not remain attached')
                    time.sleep(0.02)
                require(state['attached']['generation'] == 1 and
                    state['standby']['exception_endpoint_fd'] is False and
                    state['standby']['exception_endpoint_owner_key'] == 0,
                    'phase-7 standby received the endpoint before admission')
                native_marker.touch()
                native_frame = (b'\xff' * 6 + bytes.fromhex('024b455200bb') + b'\x08\x06' +
                    struct.pack('!HHBBH', 1, 0x0800, 6, 4, 1) + bytes.fromhex('024b455200bb') +
                    socket.inet_aton('198.18.0.171') + b'\x00' * 6 + socket.inet_aton('198.18.0.100'))
                require(native_wire.send(native_frame) == len(native_frame), 'phase-7 ARP injection failed')
                native_pid = native_owner_state['attached']['pid']; native_pidfd = os.pidfd_open(native_pid)
                deadline = time.monotonic() + 10
                stopped = False
                while time.monotonic() < deadline:
                    try: status_text = Path(f'/proc/{native_pid}/status').read_text()
                    except FileNotFoundError: break
                    stopped = any(line.startswith('State:') and line.split()[1] == 'T' for line in status_text.splitlines())
                    if stopped: break
                    time.sleep(0.01)
                require(stopped, 'worker did not stop after TAP copy at phase 7 before native RX enqueue')
                signal.pidfd_send_signal(native_pidfd, signal.SIGKILL)
                require(select.select([native_pidfd], [], [], 5)[0], 'phase-7 owner death was not observed')
                os.close(native_pidfd); native_pidfd = -1
                native_owner.communicate(timeout=15)
                require(native_owner.returncode == 125, 'phase-7 owner loss did not fail its launcher')
                require(line(native_standby) == 'READY', 'phase-7 exact-death recovery did not regrant the endpoint')
                native_admitted = json.loads(native_standby_stats.read_text())
                require(native_admitted['grant']['generation'] == 1 and
                    native_admitted['grant']['exception_endpoint_ifindex'] == native_ready['exception_endpoint_ifindex'] and
                    native_admitted['grant']['exception_endpoint_fd'] is True and
                    native_admitted['grant']['queue_owner_key'] == native_admitted['grant']['exception_endpoint_owner_key'] != 0,
                    'phase-7 regrant changed endpoint identity or owner authorization')
                native_standby_output = graceful_signal_release(native_standby, native_standby_stats, native_path)
                native_primary.stdin.close(); native_primary.stdin = None
                native_primary_output, native_primary_errors = native_primary.communicate(timeout=20)
                require(native_primary.returncode == 0, 'phase-7 resident cleanup failed: ' + native_primary_errors.decode())
                reclaim_records = [json.loads(line.removeprefix('KER_SESSION_EXCEPTION_RECLAIM '))
                    for line in native_primary_output.decode().splitlines()
                    if line.startswith('KER_SESSION_EXCEPTION_RECLAIM ')]
                drained_records = [json.loads(line.removeprefix('KER_SESSION_DRAINED '))
                    for line in native_primary_output.decode().splitlines() if line.startswith('KER_SESSION_DRAINED ')]
                require(reclaim_records == [{'phase': 7, 'discarded': 1, 'total': 1}] and
                    drained_records and drained_records[-1]['exception_lease_discarded'] == 1,
                    'resident did not account exactly one known phase-7 native-handoff discard')
            finally:
                if native_pidfd >= 0: os.close(native_pidfd)
                native_wire.close()
                if native_standby_endpoint is not None: native_standby_endpoint.close()
                if native_standby_wire is not None: native_standby_wire.close()
                for process in (native_owner, native_primary, native_standby):
                    if process is not None and process.poll() is None: process.kill(); process.wait()
            print('PASS: exact phase-7 TAP-copy/native-handoff lease is reclaimed once before endpoint regrant')
            print('PASS: exact phase-5 TAP output lease is reclaimed and counted once before endpoint regrant')
            print('PASS: original guest Linux peers exchange exact IPv4/IPv6 TCP4097/UDP512 with original imported Linux')
            print('PASS: actual granted EAL secondary consumes independent original PMD RX/TX queues; resident stays off packet path')
            print('PASS: fixed1500 MTU rejects live mutation coherently; original Linux/PMD counters and bidirectional Ethernet capture')
            print('PASS: original control/TX/RX journal restores all511 objects after process death and native kernel teardown')
            print('PASS: real competing secondary never launches an application; actual worker loss returns125 and restores all original objects')
            print('PASS: app-owned SIGTERM reaches native DONE; launcher reports143, reaps exact children, worker packet status0 and native buffers0')
            print('PASS: resident SIGTERM closes registration, worker exits before five second deadline, resident drains, launcher reports125')
            print('PASS: retained paired standby keeps the same actual PID/EAL/epoch and carries real native TCP/UDP after admission')
            print('PASS: source A4 primary precreates all128 coordinate rings and one original network port before actual secondary lookup')
        finally:
            if app is not None and app.poll() is None:
                app.terminate()
                try: app.wait(timeout=10)
                except subprocess.TimeoutExpired: app.kill(); app.wait()
            if standby is not None and standby.poll() is None:
                standby.terminate()
                try: standby.wait(timeout=10)
                except subprocess.TimeoutExpired: standby.kill(); standby.wait()
            if primary is not None and primary.poll() is None:
                primary.terminate()
                try: primary.wait(timeout=10)
                except subprocess.TimeoutExpired: primary.kill(); primary.wait()
            stop.set(); thread.join(timeout=3); wire.close(); endpoint.close(); os.close(tap)
            if exception_capture is not None: exception_capture.close()
    run_live_handoff_profile(args, api, plugin_paths)
    print('PASS: a generation-admitted same-process peer takes the PMD/exception grant while the original Linux app and parked worker remain alive, then both workers drain cleanly')
    run_live_handoff_profile(args, api, plugin_paths, mode='frame-positive')
    print('PASS: original LKL post-PARKED UDP frame is journaled before prepare and drained by the admitted peer as the exact mbuf pointer/bytes once')
    run_live_handoff_profile(args, api, plugin_paths, mode='frame-full')
    print('PASS: a full actual generation TX ring rejects/cancels the frame and returns the ring/pool to measured ownership')
    run_live_handoff_profile(args, api, plugin_paths, mode='frame-death-prepared')
    print('PASS: exact producer pidfd death after PREPARE reclaims the pending lease once')
    run_live_handoff_profile(args, api, plugin_paths, mode='frame-death-consumer-prepared')
    print('PASS: exact consumer pidfd death preserves a prepared lease until producer cancellation')
    run_live_handoff_profile(args, api, plugin_paths, mode='frame-death-both-prepared')
    print('PASS: exact producer and consumer pidfd deaths recover one prepared lease without retargeting')
    run_live_handoff_profile(args, api, plugin_paths, mode='frame-lost-prepare-reply')
    print('PASS: lost PREPARE reply is not retried; pending allocation survives control EOF until exact producer pidfd reap')
    run_live_handoff_profile(args, api, plugin_paths, mode='frame-death-consumer-writing')
    print('PASS: consumer death during packet WRITING defers reap without mutation, then cancels after write completion')
    run_live_handoff_profile(args, api, plugin_paths, mode='frame-death-queued')
    print('PASS: live opposite-generation consumer drains exact queued objects after producer death')
    run_live_handoff_profile(args, api, plugin_paths, mode='frame-death-producer-active-consumer')
    print('PASS: dead-producer readiness defers without mutation during a live peer dequeue and retries after release')
    if args.handoff_negative_profiles:
        for mode in ('bad-capability', 'bad-tx-lease', 'bad-rx-lease', 'peer-death', 'timeout',
                'handoff-control-hup',
                'prepare-enoent', 'prepare-ebusy', 'prepare-eperm', 'bad-prepare-error',
                'bad-prepare-error-token', 'bad-prepare-error-capability', 'bad-prepare-error-tx-lease',
                'bad-prepare-error-rx-lease', 'bad-prepare-error-sequence', 'bad-prepare-success'):
            run_live_handoff_profile(args, api, plugin_paths, mode)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
