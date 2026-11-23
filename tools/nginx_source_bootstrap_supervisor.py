"""Private source-bootstrap identity validation; not generation I/O authority.

The caller must obtain master identity from the pinned companion's process
publication and runtime/I/O identities from their authenticated launcher. This
module does not discover or grant actors from a caller-provided PID alone.
"""
import array
import hashlib
import importlib.util
import os
import fcntl
import stat
from pathlib import Path
import socket
import struct
import subprocess
import time
from types import SimpleNamespace

_SPEC = importlib.util.spec_from_file_location('_source_companion_identity',
    Path(__file__).with_name('nginx_companion_supervisor.py'))
identity = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(identity)
RECORD = struct.Struct('=IHH8I5Q16s4I8Q')
MAGIC = 0x4b534247


def require(condition, message):
    if not condition:
        raise PermissionError(message)


def memory(pid, address, length):
    with open(f'/proc/{pid}/mem', 'rb', buffering=0) as stream:
        result = os.pread(stream.fileno(), length, address)
    require(len(result) == length, 'incomplete pinned process memory observation')
    return result


def shared_mapping(pid, address):
    for line in Path(f'/proc/{pid}/maps').read_text().splitlines():
        fields = line.split(maxsplit=5)
        first, last = (int(value, 16) for value in fields[0].split('-'))
        if first <= address < last:
            require(fields[1] == 'rw-s' and fields[2] == '00000000' and
                int(fields[4]) > 0, 'source block is not inherited shared anonymous memory')
            return first, last, fields[3], fields[4]
    raise PermissionError('source block is outside pinned process mappings')


class SourceBootstrapSupervisor:
    """One exact master plus separately pinned live native runtime/I/O actors.

    Delegates finite slim control and exact initial/first-successor worker
    slots. Native route/selector work remains the caller's responsibility;
    authenticated master barriers certify only its checked, bounded outcome.
    """
    @classmethod
    def from_companion(cls, companion, runtime, io, nonce, epoch, deadline_ns):
        """Bind only after the companion client authenticated STARTED.

        Borrow the companion-owned pidfd; never discover a master by PID file
        or replace the companion's ownership/settlement responsibility.
        """
        require(companion.master_pidfd >= 0 and companion.master_pid > 0 and
            companion.helper is not None and companion.helper.poll() is None and
            not companion.unresolved and not companion.settled,
            'source bootstrap requires a live authenticated companion master')
        master = SimpleNamespace(pid=companion.master_pid,
            pidfd=companion.master_pidfd, start_ticks=companion.master_start,
            executable_hash=companion.binary_hash)
        fault_profile = companion.nginx_env.get('KER_NGINX_SOURCE_ABORT_RETRY_ENABLE')
        require(fault_profile is None or (fault_profile == '1' and
            companion.nginx_env.get('FF_FAULT') == 'flip_fail_once' and
            companion.nginx_env.get('KER_NGINX_SOURCE_FIRST_HUP_ENABLE') == '1'),
            'source abort test is not the exact companion launch profile')
        successor_profile = companion.nginx_env.get('KER_NGINX_SOURCE_SUCCESSOR_ENABLE')
        require(successor_profile is None or (successor_profile == '1' and
            fault_profile is None and 'FF_FAULT' not in companion.nginx_env and
            companion.nginx_env.get('KER_NGINX_SOURCE_FIRST_HUP_ENABLE') == '1'),
            'source successor is not the exact companion launch profile')
        return cls(master, runtime, io, companion.binary, companion.binary_hash,
            nonce, epoch, deadline_ns, allow_abort_retry=fault_profile == '1',
            allow_successor=successor_profile == '1')

    def __init__(self, master, runtime, io, binary, binary_hash, nonce, epoch, deadline_ns,
            *, allow_abort_retry=False, allow_successor=False):
        self.master, self.runtime, self.io = master, runtime, io
        self.binary = Path(binary).resolve(strict=True)
        self.binary_hash = bytes(binary_hash)
        self.nonce, self.epoch, self.deadline_ns = bytes(nonce), epoch, deadline_ns
        self.supervisor_start = identity._start_ticks(os.getpid())
        self.slim_pid = None
        self.slim_pidfd = -1
        self.slim_start_ticks = 0
        self.slim_reply = None
        self.slim_channel = None
        self.slim_stop_sent = False
        self.workers = {}
        require(type(allow_abort_retry) is bool and type(allow_successor) is bool and
            not (allow_abort_retry and allow_successor), 'invalid source profile selectors')
        self.allow_abort_retry = allow_abort_retry
        self.allow_successor = allow_successor
        self._executable_files = {}
        require(len(self.nonce) == 16 and any(self.nonce) and epoch > 0 and
            time.monotonic_ns() < deadline_ns <= time.monotonic_ns() + 300_000_000_000,
            'invalid finite source-bootstrap launch context')
        require(len({master.pid, runtime.pid, io.pid, os.getpid()}) == 4,
            'source actors must be separate processes')
        require(identity._sha256(self.binary) == self.binary_hash,
            'pinned Nginx executable changed')
        try:
            for actor in (self.master, self.runtime, self.io):
                self._pin_executable(actor.pid, actor.pidfd, actor.start_ticks,
                    actor.executable_hash)
            executable_fd = self._executable_files[self.master.pid][0]
            header = os.pread(executable_fd, 64, 0)
            require(header[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<H', header, 16)[0] == 2,
                'source observer supports the pinned little-endian ELF64 ET_EXEC build only')
            # Parse exports from the same open inode whose content was hashed,
            # even if the original launch pathname is subsequently replaced.
            exports = subprocess.run(['nm', '-D', '--defined-only',
                f'/proc/self/fd/{executable_fd}'], pass_fds=(executable_fd,),
                check=True, capture_output=True, text=True).stdout.splitlines()
            wanted = {'ngx_ff_reload_shm', 'ngx_ff_graceful_reload', 'ngx_ff_process',
                'ngx_process', 'ngx_worker', 'ngx_process_slot'}
            self.symbols = {fields[2]: int(fields[0], 16) for line in exports
                if len(fields := line.split()) == 3 and fields[2] in wanted}
            require(self.symbols.keys() == wanted, 'source ABI exports are incomplete')
            self.live()
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _file_identity(value):
        return (value.st_dev, value.st_ino, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)

    def _pin_executable(self, pid, pidfd, start, expected_hash):
        require(pid not in self._executable_files and
            identity._pidfd_pid(pidfd) == pid and identity.process_alive(pidfd) and
            identity._start_ticks(pid) == start, 'executable actor changed before pinning')
        fd = os.open(f'/proc/{pid}/exe', os.O_RDONLY | os.O_CLOEXEC)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode), 'actor executable is not a regular file')
            digest = hashlib.sha256()
            while block := os.read(fd, 65536):
                digest.update(block)
            frozen = self._file_identity(before)
            require(digest.digest() == expected_hash and
                self._file_identity(os.fstat(fd)) == frozen and
                self._file_identity(os.stat(f'/proc/{pid}/exe')) == frozen and
                identity._pidfd_pid(pidfd) == pid and identity.process_alive(pidfd) and
                identity._start_ticks(pid) == start,
                'executable content or actor changed while pinning')
            self._executable_files[pid] = (fd, frozen)
            fd = -1
        finally:
            if fd >= 0:
                os.close(fd)

    def _executable_live(self, pid):
        fd, frozen = self._executable_files[pid]
        # Keep the hashed inode open for the grant lifetime. Every observation
        # detects exec/replacement or changed metadata on that same inode;
        # active executable writes are additionally denied by Linux ETXTBSY.
        return (self._file_identity(os.fstat(fd)) == frozen and
            self._file_identity(os.stat(f'/proc/{pid}/exe')) == frozen)

    def live(self):
        require(time.monotonic_ns() < self.deadline_ns, 'source bootstrap authority expired')
        require(identity._start_ticks(os.getpid()) == self.supervisor_start,
            'source supervisor identity changed')
        for actor in (self.master, self.runtime, self.io):
            require(identity._pidfd_pid(actor.pidfd) == actor.pid and
                identity.process_alive(actor.pidfd) and
                identity._start_ticks(actor.pid) == actor.start_ticks and
                self._executable_live(actor.pid),
                'pinned source/native actor is no longer live')
        require(self.master.executable_hash == self.binary_hash, 'master executable is not pinned Nginx')
        if self.slim_pidfd >= 0:
            require(identity._pidfd_pid(self.slim_pidfd) == self.slim_pid and
                identity.process_alive(self.slim_pidfd) and
                identity._start_ticks(self.slim_pid) == self.slim_start_ticks and
                self._executable_live(self.slim_pid),
                'exact delegated slim actor exited or changed identity')

    def _scalar(self, pid, name, code):
        size = struct.calcsize(code)
        return struct.unpack(code, memory(pid, self.symbols[name], size))[0]

    def validate_slim(self, channel, packet, credentials):
        self.live()
        require(len(packet) == RECORD.size, 'source bootstrap request has invalid size')
        r = list(RECORD.unpack(packet))
        require(r[:5] == [MAGIC, 3, 1, RECORD.size, 0] and r[8:11] == [0, 0, 0] and
            r[14] == self.epoch and r[15] == self.deadline_ns and r[16] == self.nonce and
            not any(r[17:]), 'source bootstrap request is outside the initial slim profile')
        peer = struct.unpack('=3i', channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        require(credentials == peer == (r[5], os.getuid(), os.getgid()) and
            r[5] == r[6] and r[7] == self.master.pid and r[12] == self.master.start_ticks and
            self.slim_pid is None, 'source bootstrap sender/master/role identity mismatch')
        require(r[5] not in (self.master.pid, self.runtime.pid, self.io.pid, os.getpid()),
            'source slim primary is not a separate actor')
        pidfd = os.pidfd_open(r[5])
        try:
            require(identity._pidfd_pid(pidfd) == r[5] and identity.process_alive(pidfd) and
                identity._start_ticks(r[5]) == r[11] and
                identity._sha256(f'/proc/{r[5]}/exe') == self.binary_hash,
                'source slim executable or process identity mismatch')
            address = self._scalar(self.master.pid, 'ngx_ff_reload_shm', '=Q')
            require(address and address == r[13] and
                self._scalar(r[5], 'ngx_ff_reload_shm', '=Q') == address,
                'source actor did not inherit the exact master reload block')
            mapping = shared_mapping(self.master.pid, address)
            require(shared_mapping(r[5], address) == mapping,
                'source reload block is not the same inherited mapping')
            prefix = memory(self.master.pid, address, 32)
            values = struct.unpack('=8I', prefix)
            require(values[0] == 0x46524c4d and values[1] == 1 and
                32 <= values[2] <= 16384 and address + values[2] <= mapping[1] and
                values[3:] == (0, 0, 0, 0, 0) and memory(r[5], address, 32) == prefix,
                'source reload block is outside the original initial steady state')
            require(self._scalar(self.master.pid, 'ngx_ff_graceful_reload', '=i') == 1 and
                self._scalar(r[5], 'ngx_ff_graceful_reload', '=i') == 1 and
                self._scalar(self.master.pid, 'ngx_process', '=Q') == 1 and
                self._scalar(r[5], 'ngx_process', '=Q') == 1 and
                self._scalar(r[5], 'ngx_ff_process', '=q') == 3,
                'caller is not the original source slim-primary branch')
            # At this exact preflight wait, original source close-all-FDs has
            # finished and the new transport has opened only a pidfd/socket.
            descriptors = {int(path.name): os.readlink(path) for path in
                Path(f'/proc/{r[5]}/fd').iterdir()}
            extra = [value for fd, value in descriptors.items() if fd >= 3]
            require(len(extra) == 2 and extra.count('anon_inode:[pidfd]') == 1 and
                sum(value.startswith('socket:[') for value in extra) == 1,
                'slim primary retained inherited descriptor authority')
            self.live()
            require(memory(self.master.pid, address, 32) == prefix and identity.process_alive(pidfd),
                'source state/actor changed during observation')
            pinned = pidfd
            pidfd = -1
            return r, pinned
        finally:
            if pidfd >= 0:
                os.close(pidfd)

    def reply_slim(self, channel, packet, credentials, *, control_only=False):
        r, self.slim_pidfd = self.validate_slim(channel, packet, credentials)
        self.slim_start_ticks = r[11]
        r[2] = 2
        r[17], r[21] = os.getpid(), self.supervisor_start
        r[18], r[22] = self.runtime.pid, self.runtime.start_ticks
        r[19], r[23] = self.io.pid, self.io.start_ticks
        r[20] = 1 if control_only else 0
        data = RECORD.pack(*r)
        # An attempted grant consumes this launch role, including short sends.
        self.slim_pid = r[5]
        self._pin_executable(self.slim_pid, self.slim_pidfd, self.slim_start_ticks,
            self.binary_hash)
        self.live()
        rights = array.array('i', (self.runtime.pidfd, self.io.pidfd))
        require(channel.sendmsg([data], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)],
            getattr(socket, 'MSG_NOSIGNAL', 0)) == len(data), 'short source bootstrap grant')
        self.slim_reply, self.slim_channel = tuple(r), channel
        return {'master_pid': self.master.pid, 'slim_pid': self.slim_pid,
            'source_block_address': r[13], 'runtime_pid': self.runtime.pid,
            'io_pid': self.io.pid, 'scope': ('finite slim control only; no generation I/O'
                if control_only else 'transport proof; generation I/O not yet authorized')}

    def stop_slim(self, channel):
        self.live()
        require(channel is self.slim_channel and self.slim_reply is not None and
            self.slim_reply[20] == 1 and not self.slim_stop_sent,
            'no unused control-only slim grant on this exact channel')
        record = list(self.slim_reply)
        record[2] = 3
        self.slim_stop_sent = True
        data = RECORD.pack(*record)
        require(channel.send(data, getattr(socket, 'MSG_NOSIGNAL', 0)) == len(data),
            'short correlated source slim STOP')

    def prepare_aborted_retry(self, acquire_native_slot):
        """Adopt one acknowledged native retry plan after the original abort.

        Native RETRY must already have been acknowledged inside the first
        abort barrier while the original candidate was alive. The callback
        transfers that plan's fresh candidate FIFO only after source T0/death.
        It must not create a replacement plan or owner. No READY or selector
        is changed here.
        """
        self.live()
        require(self.allow_abort_retry and not hasattr(self, '_retry_slot') and
            getattr(self, '_completed_master_barriers', set()) == {(1, 5), (1, 9)} and
            getattr(self, '_native_retry_cookie', 0) > 0,
            'retry requires the acknowledged first pre-flip abort')
        old_pidfd, old = self.workers[(0, 0)]
        dead_pidfd, dead = self.workers[(1, 1)]
        require(identity.process_alive(old_pidfd) and
            identity._start_ticks(old[5]) == old[11] and
            not identity.process_alive(dead_pidfd),
            'retry requires the same live old owner and exact dead aborted successor')
        address = self.slim_reply[13]
        def original_idle():
            return (struct.unpack('=8I', memory(self.master.pid, address, 32))[3:7] ==
                (1, 0, 1, 0) and struct.unpack('=3I', memory(self.master.pid,
                    address + 48 + 128 * 8, 12)) == (0, 0, 0))
        require(original_idle(), 'source did not return to original idle after abort')
        # Consume before calling native code. Failure never enables another try.
        self._retry_slot = None
        fd = acquire_native_slot()
        try:
            value = os.fstat(fd)
            require(stat.S_ISFIFO(value.st_mode) and
                fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_WRONLY and
                (value.st_dev, value.st_ino) not in (old[24:26], dead[24:26]),
                'native retry did not transfer a fresh candidate FIFO')
            self.live()
            require(original_idle() and identity.process_alive(old_pidfd) and
                not identity.process_alive(dead_pidfd), 'source/native retry identity changed')
            self._retry_slot = (value.st_dev, value.st_ino)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def prepare_successful_successor(self, acquire_native_slot):
        """Consume one native successor adoption after original gen-1 commit.

        The callback returns the fresh candidate FIFO and the preserved live
        listener cookie from the acknowledged native SUCCESSOR transaction.
        The committed actor and its original generation are never relabeled.
        """
        self.live()
        require(self.allow_successor and not hasattr(self, '_successor_slot') and
            getattr(self, '_completed_master_barriers', set()) == {(1, 5), (1, 6)} and
            getattr(self, '_native_committed_cookie', 0) > 0,
            'successor requires the acknowledged original first commit')
        retired_fd, retired = self.workers[(0, 0)]
        current_fd, current = self.workers[(1, 1)]
        address = self.slim_reply[13]
        def original_idle():
            return (struct.unpack('=8I', memory(self.master.pid, address, 32))[3:7] ==
                (1, 1, 1, 0) and struct.unpack('=3I', memory(self.master.pid,
                    address + 48 + 128 * 8, 12)) == (1, 0, 0))
        require(original_idle() and not identity.process_alive(retired_fd) and
            identity.process_alive(current_fd) and
            identity._start_ticks(current[5]) == current[11],
            'successor requires original idle, retired predecessor and same live gen-1 actor')
        self._successor_slot = None
        fd, cookie = acquire_native_slot()
        try:
            value = os.fstat(fd)
            require(type(cookie) is int and cookie == self._native_committed_cookie and
                stat.S_ISFIFO(value.st_mode) and
                fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_WRONLY and
                (value.st_dev, value.st_ino) not in (retired[24:26], current[24:26]),
                'native successor did not preserve the live listener and transfer a fresh FIFO')
            self.live()
            require(original_idle() and not identity.process_alive(retired_fd) and
                identity.process_alive(current_fd) and
                identity._start_ticks(current[5]) == current[11],
                'original successor lineage changed during native adoption')
            self._successor_slot = (value.st_dev, value.st_ino)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _source_round(self, source_epoch):
        if source_epoch == 1:
            return 0, 1
        if source_epoch == 2 and self.allow_abort_retry and getattr(self, '_retry_slot', None):
            return 0, 1
        if source_epoch == 2 and self.allow_successor and getattr(self, '_successor_slot', None):
            return 1, 0
        raise PermissionError('source round has no bounded acknowledged native lineage')

    def reply_worker(self, channel, packet, credentials, slot_fd, relay):
        """Delegate an exact FIFO slot plus fresh relay/READY to a source child.

        The caller retains slot/relay ownership. The returned receiver must be
        transferred to the contained companion; its queued READY credentials
        originate in the worker, never a copied supervisor message.
        """
        self.live()
        require(self.slim_pidfd >= 0 and self.slim_reply[20] == 1,
            'worker grant requires the exact live control-only slim primary')
        require(len(packet) == RECORD.size, 'worker bootstrap record size mismatch')
        r = list(RECORD.unpack(packet))
        require(r[:5] == [MAGIC, 3, 1, RECORD.size, 1] and not r[10] and
            r[14:17] == [self.epoch, self.deadline_ns, self.nonce] and not any(r[17:]),
            'worker bootstrap context mismatch')
        peer = struct.unpack('=3i', channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        require(peer == credentials == (r[5], os.getuid(), os.getgid()) and r[5] == r[6] and
            r[7] == self.master.pid and r[12] == self.master.start_ticks,
            'worker sender/master identity mismatch')
        pidfd = os.pidfd_open(r[5])
        ready_receiver = ready_sender = None
        try:
            require(identity._pidfd_pid(pidfd) == r[5] and identity.process_alive(pidfd) and
                identity._start_ticks(r[5]) == r[11] and
                identity._sha256(f'/proc/{r[5]}/exe') == self.binary_hash,
                'worker executable or pidfd mismatch')
            fields = Path(f'/proc/{r[5]}/stat').read_text().rpartition(')')[2].split()
            require(int(fields[1]) == self.master.pid and
                self._scalar(r[5], 'ngx_process', '=Q') == 3 and
                self._scalar(r[5], 'ngx_worker', '=Q') == 0 and
                self._scalar(r[5], 'ngx_ff_process', '=q') == 2 and
                self._scalar(r[5], 'ngx_ff_graceful_reload', '=i') == 1,
                'caller is not source worker zero/secondary of exact master')
            address = self._scalar(self.master.pid, 'ngx_ff_reload_shm', '=Q')
            require(address == r[13] == self._scalar(r[5], 'ngx_ff_reload_shm', '=Q') and
                shared_mapping(self.master.pid, address) == shared_mapping(r[5], address),
                'worker does not share original master reload block')
            prefix = memory(self.master.pid, address, 32)
            values = struct.unpack('=8I', prefix)
            require(values[:2] == (0x46524c4d, 1) and 32 <= values[2] <= 16384 and
                r[9] == values[3] and values[4] in (0, 1) and values[5] in (0, 1) and
                values[6] in (0, 1) and r[8] == (values[5] if values[6] else values[4]),
                'worker generation does not match original source selection')
            # Native plan roles remain distinct from the source generation.
            # Epoch two has one explicit lineage: aborted retry or committed
            # successor, each requiring its own acknowledged native adoption.
            role = 0 if values[3:] == (0, 0, 0, 0, 0) else 1
            old_generation, target_generation = self._source_round(values[3]) if role else (0, 0)
            require((role == 0 and r[8:10] == [0, 0]) or
                (role == 1 and values[4:7] == (old_generation, target_generation, 1) and
                    r[8] == target_generation),
                'worker is outside the bounded original source rounds')
            key = (r[9], r[8])
            require(key not in self.workers, 'source worker generation already delegated')
            process_slot = self._scalar(r[5], 'ngx_process_slot', '=q')
            require(0 <= process_slot < 128, 'source worker process slot is outside original READY array')
            slot = os.fstat(slot_fd)
            require(stat.S_ISFIFO(slot.st_mode) and
                fcntl.fcntl(slot_fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_WRONLY,
                'worker slot is not a write-only SDK FIFO capability')
            if r[9] == 2:
                if self.allow_successor:
                    current_pidfd, current = self.workers[(1, 1)]
                    dead_pidfd, dead = self.workers[(0, 0)]
                    require((slot.st_dev, slot.st_ino) == self._successor_slot and
                        r[5] not in (dead[5], current[5]) and
                        not identity.process_alive(dead_pidfd) and
                        identity.process_alive(current_pidfd) and
                        identity._start_ticks(current[5]) == current[11],
                        'successor candidate changed the committed source lineage')
                else:
                    dead_pidfd, dead = self.workers[(1, 1)]
                    require((slot.st_dev, slot.st_ino) == self._retry_slot and
                        r[5] != dead[5] and not identity.process_alive(dead_pidfd),
                        'retry candidate does not match fresh native slot/dead predecessor')
            require(relay.family == socket.AF_UNIX and relay.type & 15 == socket.SOCK_SEQPACKET,
                'worker relay is not Unix seqpacket')
            require(struct.unpack('=3i', relay.getsockopt(socket.SOL_SOCKET,
                socket.SO_PEERCRED, 12)) == (os.getpid(), os.getuid(), os.getgid()),
                'worker relay was not created by exact supervisor')
            ready_receiver, ready_sender = socket.socketpair(socket.AF_UNIX,
                socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
            ready_receiver.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            cookie_option = getattr(socket, 'SO_COOKIE', 57)
            relay_cookie = struct.unpack('=Q', relay.getsockopt(socket.SOL_SOCKET, cookie_option, 8))[0]
            ready_cookie = struct.unpack('=Q', ready_sender.getsockopt(socket.SOL_SOCKET, cookie_option, 8))[0]
            require(relay_cookie and ready_cookie and relay_cookie != ready_cookie,
                'source relay/READY channels are not distinct')
            r[2] = 2
            r[17], r[21] = os.getpid(), self.supervisor_start
            r[18], r[22] = self.runtime.pid, self.runtime.start_ticks
            r[19], r[23] = self.io.pid, self.io.start_ticks
            r[20] = 2 if role == 0 else 4
            r[24:28] = [slot.st_dev, slot.st_ino, relay_cookie, ready_cookie]
            self.live()
            require(memory(self.master.pid, address, 32) == prefix and identity.process_alive(pidfd),
                'source worker state changed before grant')
            # Consume before sending; a short/error send cannot renew authority.
            self.workers[key] = (pidfd, tuple(r))
            pidfd = -1
            rights = array.array('i', (self.runtime.pidfd, self.io.pidfd, slot_fd,
                relay.fileno(), ready_sender.fileno()))
            data = RECORD.pack(*r)
            require(channel.sendmsg([data], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)],
                getattr(socket, 'MSG_NOSIGNAL', 0)) == len(data), 'short source worker grant')
            watch = dict(pid=r[5], tid=r[6], role=role, start=r[11],
                slot_device=r[24], slot_inode=r[25], cookie=r[27],
                pidfd=self.workers[key][0], source_epoch=r[9], generation=r[8],
                process_slot=process_slot)
            result = ready_receiver
            ready_receiver = None
            return watch, result
        finally:
            if pidfd >= 0: os.close(pidfd)
            if ready_receiver is not None: ready_receiver.close()
            if ready_sender is not None: ready_sender.close()

    def slim_exited(self):
        require(self.slim_pidfd >= 0, 'no exact slim actor was delegated')
        return not identity.process_alive(self.slim_pidfd)

    def activate_worker(self, channel, watch):
        """Permit original READY only after caller verifies C31 PREPARED.

        This consumes the already granted first-HUP identity; it grants no
        new slot, deadline, generation, or process authority.
        """
        self.live()
        key = (watch['source_epoch'], watch['generation'])
        old_generation, target_generation = self._source_round(key[0])
        require(key[1] == target_generation and key in self.workers,
            'source activation is not an exact delegated bounded candidate')
        pidfd, granted = self.workers[key]
        record = list(granted)
        activated = getattr(self, '_activated_workers', set())
        require(key not in activated and record[20] == 4 and
            identity.process_alive(pidfd) and identity._pidfd_pid(pidfd) == watch['pid'] and
            identity._start_ticks(watch['pid']) == record[11] and
            struct.unpack('=3i', channel.getsockopt(socket.SOL_SOCKET,
                socket.SO_PEERCRED, 12)) == (watch['pid'], os.getuid(), os.getgid()),
            'source activation candidate/channel changed identity')
        values = struct.unpack('=8I', memory(self.master.pid, record[13], 32))
        require(values[3:7] == (key[0], old_generation, target_generation, 1),
            'original source round changed before candidate activation')
        activated.add(key)
        self._activated_workers = activated
        record[2] = 4
        payload = RECORD.pack(*record)
        require(channel.send(payload, getattr(socket, 'MSG_NOSIGNAL', 0)) == len(payload),
            'short source activation send')

    def master_barrier(self, channel, packet, credentials, apply):
        """Bind an original master park/commit/pre-flip-abort to native work.

        ``apply`` must validate its original-SYN queue/route/containment proofs
        before returning. An exception sends no success receipt; post-swap
        uncertainty must be quarantined by the caller.
        """
        self.live()
        require(len(packet) == RECORD.size, 'invalid source master barrier size')
        record = list(RECORD.unpack(packet))
        operation = record[2]
        source_epoch = record[9]
        old_generation, target_generation = self._source_round(source_epoch)
        require(operation in (5, 6, 9) and (operation != 9 or self.allow_abort_retry) and
            record[:2] == [0x4b534247, 3] and
            record[3:11] == [RECORD.size, 2, self.master.pid, self.master.pid,
                self.master.pid, target_generation, source_epoch, 0] and
            record[11:13] == [self.master.start_ticks, self.master.start_ticks] and
            record[14:17] == [self.epoch, self.deadline_ns, self.nonce] and
            not any(record[17:28]) and
            time.monotonic_ns() < record[28] <= self.deadline_ns and
            record[28] - time.monotonic_ns() <= 100_000_000 and
            credentials == (self.master.pid, os.getuid(), os.getgid()) and
            struct.unpack('=3i', channel.getsockopt(socket.SOL_SOCKET,
                socket.SO_PEERCRED, 12)) == credentials,
            'source master barrier correlation/credentials mismatch')
        address = self._scalar(self.master.pid, 'ngx_ff_reload_shm', '=Q')
        require(address == record[13] == self.slim_reply[13] and
            (source_epoch, target_generation) in getattr(self, '_activated_workers', set()),
            'source master barrier lacks activated exact candidate')
        values = struct.unpack('=8I', memory(self.master.pid, address, 32))
        owner, stopped, fsm = struct.unpack('=3I',
            memory(self.master.pid, address + 48 + 128 * 8, 12))
        expected_markers = {5: (old_generation, 0), 6: (target_generation, 0),
            9: (old_generation, 1)}
        require(values[3:7] == (source_epoch, old_generation, target_generation, 1) and fsm == 2 and
            (owner, stopped) == expected_markers[operation],
            'source master barrier does not match original T2 park/release state')
        if operation == 9:
            candidate_pidfd, candidate = self.workers[(source_epoch, 1)]
            require(identity.process_alive(candidate_pidfd) and
                identity._pidfd_pid(candidate_pidfd) == candidate[5] and
                identity._start_ticks(candidate[5]) == candidate[11],
                'pre-flip abort successor already exited; quarantine required')
        barriers = getattr(self, '_master_barriers', set())
        key = (source_epoch, operation)
        require(key not in barriers and (operation == 5 or
            ((source_epoch, 5) in barriers and (source_epoch, 6) not in barriers and
                (source_epoch, 9) not in barriers)),
            'source master barrier is repeated or out of order')
        if operation == 5:
            if not hasattr(self, '_master_control_deadlines'):
                self._master_control_deadlines = {}
            self._master_control_deadlines[source_epoch] = record[28]
        else:
            require(record[28] == self._master_control_deadlines[source_epoch],
                'source COMMIT attempted to renew the PARK deadline')
        barriers.add(key)
        self._master_barriers = barriers
        control_deadline = record[28]
        require(time.monotonic_ns() < control_deadline,
            'source operation expired before native barrier work')
        outcome = apply(operation, control_deadline)
        if operation == 9 and outcome is not None:
            require(type(outcome) is dict and set(outcome) == {'native_retry_cookie'} and
                type(outcome['native_retry_cookie']) is int and outcome['native_retry_cookie'] > 0,
                'native retry adoption receipt is malformed')
        if operation == 6 and self.allow_successor:
            require(type(outcome) is dict and set(outcome) == {'native_current_cookie'} and
                type(outcome['native_current_cookie']) is int and outcome['native_current_cookie'] > 0,
                'native successful commit lacks its preserved current-listener receipt')
        require(time.monotonic_ns() < control_deadline,
            'native barrier exceeded original operation deadline; quarantine required')
        self.live()
        require(struct.unpack('=8I', memory(self.master.pid, address, 32))[3:7] ==
            (source_epoch, old_generation, target_generation, 1),
            'source round changed during native barrier')
        if operation == 9:
            require(identity.process_alive(candidate_pidfd) and
                identity._start_ticks(candidate[5]) == candidate[11] and
                struct.unpack('=3I', memory(self.master.pid,
                    address + 48 + 128 * 8, 12)) == (0, 1, 2),
                'pre-flip abort lost its live successor/parked source state')
        record[2] = operation + 2
        record[17], record[21] = os.getpid(), self.supervisor_start
        record[18], record[22] = self.runtime.pid, self.runtime.start_ticks
        record[19], record[23] = self.io.pid, self.io.start_ticks
        rights = array.array('i', (self.runtime.pidfd, self.io.pidfd))
        payload = RECORD.pack(*record)
        require(time.monotonic_ns() < control_deadline,
            'source operation expired before native receipt; quarantine required')
        require(channel.sendmsg([payload], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)],
            getattr(socket, 'MSG_NOSIGNAL', 0)) == len(payload),
            'short source master native barrier receipt')
        if not hasattr(self, '_completed_master_barriers'):
            self._completed_master_barriers = set()
        self._completed_master_barriers.add(key)
        if operation == 9 and outcome is not None:
            # The native callback certifies an acknowledged adoption while
            # the exact source candidate is still alive. After this receipt
            # the unchanged source failure path may terminate that candidate.
            self._native_retry_cookie = outcome['native_retry_cookie']
        if operation == 6 and self.allow_successor:
            self._native_committed_cookie = outcome['native_current_cookie']

    def close(self):
        """Release observation handles; companion still owns subtree settlement."""
        if self.slim_pidfd >= 0:
            os.close(self.slim_pidfd)
            self.slim_pidfd = -1
        for pidfd, _ in self.workers.values():
            os.close(pidfd)
        self.workers.clear()
        for fd, _ in self._executable_files.values():
            os.close(fd)
        self._executable_files.clear()
