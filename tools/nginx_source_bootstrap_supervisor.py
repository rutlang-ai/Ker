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
        return cls(master, runtime, io, companion.binary, companion.binary_hash,
            nonce, epoch, deadline_ns)

    def __init__(self, master, runtime, io, binary, binary_hash, nonce, epoch, deadline_ns):
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
            # This batch admits only initial generation zero and its first
            # source-controlled successor. Respawn/repeated rounds stay closed.
            role = 0 if values[3:] == (0, 0, 0, 0, 0) else 1
            require((role == 0 and r[8:10] == [0, 0]) or
                (role == 1 and values[3] == 1 and values[4:7] == (0, 1, 1) and r[8] == 1),
                'worker is outside the bounded original initial/first-HUP round')
            key = (r[9], r[8])
            require(key not in self.workers, 'source worker generation already delegated')
            process_slot = self._scalar(r[5], 'ngx_process_slot', '=q')
            require(0 <= process_slot < 128, 'source worker process slot is outside original READY array')
            slot = os.fstat(slot_fd)
            require(stat.S_ISFIFO(slot.st_mode) and
                fcntl.fcntl(slot_fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_WRONLY,
                'worker slot is not a write-only SDK FIFO capability')
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
        require(key == (1, 1) and key in self.workers,
            'source activation is not an exact delegated first-HUP candidate')
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
        require(values[3:7] == (1, 0, 1, 1),
            'original source round changed before candidate activation')
        activated.add(key)
        self._activated_workers = activated
        record[2] = 4
        payload = RECORD.pack(*record)
        require(channel.send(payload, getattr(socket, 'MSG_NOSIGNAL', 0)) == len(payload),
            'short source activation send')

    def master_barrier(self, channel, packet, credentials, apply):
        """Bind an original master park/commit call to native adapter work.

        ``apply`` must validate its original-SYN queue/route/containment proofs
        before returning. An exception sends no success receipt; post-swap
        uncertainty must be quarantined by the caller.
        """
        self.live()
        require(len(packet) == RECORD.size, 'invalid source master barrier size')
        record = list(RECORD.unpack(packet))
        operation = record[2]
        require(operation in (5, 6) and record[:2] == [0x4b534247, 3] and
            record[3:11] == [RECORD.size, 2, self.master.pid, self.master.pid,
                self.master.pid, 1, 1, 0] and
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
            (1, 1) in getattr(self, '_activated_workers', set()),
            'source master barrier lacks activated exact candidate')
        values = struct.unpack('=8I', memory(self.master.pid, address, 32))
        owner, stopped, fsm = struct.unpack('=3I',
            memory(self.master.pid, address + 48 + 128 * 8, 12))
        require(values[3:7] == (1, 0, 1, 1) and fsm == 2 and stopped == 0 and
            owner == (0 if operation == 5 else 1),
            'source master barrier does not match original T2 park/release state')
        barriers = getattr(self, '_master_barriers', set())
        require(operation not in barriers and (operation == 5 or 5 in barriers),
            'source master barrier is repeated or out of order')
        if operation == 5:
            self._master_control_deadline = record[28]
        else:
            require(record[28] == self._master_control_deadline,
                'source COMMIT attempted to renew the PARK deadline')
        barriers.add(operation)
        self._master_barriers = barriers
        control_deadline = record[28]
        require(time.monotonic_ns() < control_deadline,
            'source operation expired before native barrier work')
        apply(operation, control_deadline)
        require(time.monotonic_ns() < control_deadline,
            'native barrier exceeded original operation deadline; quarantine required')
        self.live()
        require(struct.unpack('=8I', memory(self.master.pid, address, 32))[3:7] ==
            (1, 0, 1, 1), 'source round changed during native barrier')
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
