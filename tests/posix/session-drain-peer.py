#!/usr/bin/env python3
"""Source-shaped worker-drain peer lifecycle over the resident EAL session."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
from hugepage_preflight import hugepage_capacity_error
from dpdk_runtime import private_runtime_environment
import queue
import signal
import select
import shlex
import subprocess
import socket
import struct
import sys
import tempfile
import threading
import time


class Lines:
    def __init__(self, stream):
        self.lines = queue.Queue()
        self.history = []
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self._read, args=(stream,), daemon=True)
        self.thread.start()

    def _read(self, stream):
        for line in stream:
            line = line.rstrip('\n')
            with self.lock:
                self.history.append(line)
            self.lines.put(line)
        self.lines.put(None)

    def snapshot(self):
        with self.lock:
            return '\n'.join(self.history)

    def take(self, prefix, timeout=10):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                line = self.lines.get(timeout=max(0.01, deadline - time.monotonic()))
            except queue.Empty:
                break
            if line is None:
                raise RuntimeError('process stdout closed before ' + prefix)
            if line.startswith(prefix + ' '):
                return json.loads(line[len(prefix) + 1:])
        raise RuntimeError('timed out waiting for ' + prefix)


CHILDREN = []


class Child:
    def __init__(self, argv, *, label, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=None):
        self.label = label
        self.process = subprocess.Popen(argv, stdin=stdin, stdout=stdout, stderr=stderr,
                                        text=True, bufsize=1, env=env)
        self.lines = Lines(self.process.stdout) if self.process.stdout else None
        self.errors = Lines(self.process.stderr) if self.process.stderr else None
        CHILDREN.append(self)

    def wait_line(self, prefix, timeout=10):
        return self.lines.take(prefix, timeout)

    def send(self, data):
        self.process.stdin.write(data)
        self.process.stdin.flush()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


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


def open_worker_pidfd(identity):
    if not hasattr(os, 'pidfd_open'):
        raise RuntimeError('Linux pidfd_open is required for exact worker-death proof')
    return os.pidfd_open(identity['pid'], 0)


def wait_dead(fd, pid):
    poller = select.poll()
    poller.register(fd, select.POLLIN)
    if not poller.poll(5000):
        raise RuntimeError('worker process remained alive: ' + str(pid))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--worker', type=Path, required=True)
    parser.add_argument('--tool', type=Path, required=True)
    parser.add_argument('--dpdk-plugin-dir', type=Path)
    parser.add_argument('--huge-dir', type=Path, default=Path('/dev/hugepages'))
    args = parser.parse_args()
    plugin_dir = resolve_dpdk_plugin_dir(args.dpdk_plugin_dir)
    plugin_paths = resolve_dpdk_plugin_paths(plugin_dir, ('mempool_ring', 'net_ring'))
    worker = args.worker.resolve(strict=True)
    tool = args.tool.resolve(strict=True)
    try:
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            peer_pidfd = struct.unpack('i', left.getsockopt(socket.SOL_SOCKET, 77, struct.calcsize('i')))[0]
            os.close(peer_pidfd)
        finally:
            left.close(); right.close()
    except OSError as error:
        print('SKIP: exact peer pidfds unavailable: ' + str(error), flush=True)
        return 77
    spec = importlib.util.spec_from_file_location('ker_session_api', tool)
    api = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = api
    spec.loader.exec_module(api)
    root = Path(tempfile.gettempdir()) / ('ker-drain-peer-' + str(os.getpid()))
    root.mkdir(mode=0o700, parents=True)
    path = root / 'resident.sock'
    huge_dir = args.huge_dir.resolve()
    capacity_error = hugepage_capacity_error(huge_dir, 64 * 1024 * 1024)
    if capacity_error:
        print('SKIP: ' + capacity_error, flush=True)
        return 77
    plugin_args = dpdk_plugin_eal_options(plugin_paths)
    eal = (f'--no-pci --no-telemetry --iova-mode=va -m 64 --huge-dir={shlex.quote(str(huge_dir))} '
           f'{plugin_args} --file-prefix=drain-{os.getpid()}-{os.urandom(4).hex()}')
    runtime = root / 'runtime'
    env = private_runtime_environment(runtime)
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    resident = old = current = ordinary = replacement = queued_hup = None
    resident_stopped = False
    worker_fds = {}

    def epoch_live(epoch):
        connection = api.Connection(path)
        try:
            return bool(connection.request(api.EPOCH_LIVE, epoch=epoch)['token'])
        finally:
            connection.close()

    def status():
        connection = api.Connection(path)
        try:
            return connection.request(api.STATUS)
        finally:
            connection.close()

    def start_parent(extra_env=None):
        child_env = env if extra_env is None else env | extra_env
        return Child([sys.executable, str(tool), 'lease', '--socket', str(path),
                      '--worker', str(worker), '--eal', eal], label='lease', env=child_env)

    def wait_released(epoch):
        deadline = time.monotonic() + 6
        while time.monotonic() < deadline:
            if not epoch_live(epoch):
                return
            time.sleep(0.05)
        raise RuntimeError('epoch was not reclaimed after its exact worker death')

    try:
        resident = Child([sys.executable, str(tool), 'serve', '--socket', str(path),
                          '--worker', str(worker), '--eal', eal], label='resident', env=env)
        ready = resident.wait_line('KER_SESSION_READY', 20)
        require(ready['stage'] == 'shared-control' and ready['slots'] == 4,
                'resident did not publish expected session geometry')

        old = start_parent({'KER_SESSION_TEST_DQ_PENDING_HB': '1'})
        old_identity = old.wait_line('KER_SESSION_ATTACHED', 20)
        worker_fds['old'] = open_worker_pidfd(old_identity)
        old.errors.take('KER_SESSION_TEST_DQ_INITIAL_HEARTBEAT_ACKED', 10)
        os.kill(resident.process.pid, signal.SIGSTOP)
        resident_stopped = True
        old.send('h')
        old.errors.take('KER_SESSION_TEST_DQ_HEARTBEAT_REQUESTED', 10)
        old.errors.take('KER_SESSION_TEST_DQ_HEARTBEAT_PENDING', 10)
        # The two-byte write keeps Q queued behind the already-consumed D.
        # The stopped resident cannot acknowledge the pending heartbeat until
        # the worker proves it deferred Q while finishing D's response.
        old.send('DQ')
        old.errors.take('KER_SESSION_TEST_DQ_D_CONSUMED', 10)
        old.errors.take('KER_SESSION_TEST_DQ_HEARTBEAT_DEFERRED', 10)
        os.kill(resident.process.pid, signal.SIGCONT)
        resident_stopped = False
        drain = old.wait_line('KER_SESSION_DRAIN_MODE', 10)
        require(drain['epoch'] == old_identity['epoch'] and drain['slot'] == old_identity['slot'] and
                drain['generation'] == 0 and drain['process'] == 0,
                'drain authorization was not bound to the attached worker coordinate')
        peer = old.wait_line('KER_SESSION_PEER', 10)
        require(peer['epoch'] == old_identity['epoch'] and
                old.lines.snapshot().index('KER_SESSION_DRAIN_MODE ') < old.lines.snapshot().index('KER_SESSION_PEER '),
                'queued Q was not answered after the consumed D response')
        print('PASS: pending heartbeat ACK was drained after D while queued Q remained ordered', flush=True)
        os.kill(old.process.pid, signal.SIGKILL)
        old.process.wait(timeout=5)
        print('PASS: authenticated drain-mode worker survives its master control EOF', flush=True)

        # A control hangup while the consumed D is waiting for its pending
        # heartbeat must not authorize drain mode. This uses the same real
        # heartbeat/registration protocol as the positive DQ ordering case.
        queued_hup = start_parent({'KER_SESSION_TEST_DQ_PENDING_HB': '1'})
        hup_identity = queued_hup.wait_line('KER_SESSION_ATTACHED', 20)
        worker_fds['queued_hup'] = open_worker_pidfd(hup_identity)
        queued_hup.errors.take('KER_SESSION_TEST_DQ_INITIAL_HEARTBEAT_ACKED', 10)
        os.kill(resident.process.pid, signal.SIGSTOP)
        resident_stopped = True
        queued_hup.send('h')
        queued_hup.errors.take('KER_SESSION_TEST_DQ_HEARTBEAT_REQUESTED', 10)
        queued_hup.errors.take('KER_SESSION_TEST_DQ_HEARTBEAT_PENDING', 10)
        queued_hup.send('D')
        queued_hup.errors.take('KER_SESSION_TEST_DQ_D_CONSUMED', 10)
        queued_hup.process.stdin.close()
        queued_hup.errors.take('KER_SESSION_TEST_DQ_CONTROL_HUP', 10)
        os.kill(resident.process.pid, signal.SIGCONT)
        resident_stopped = False
        queued_hup.process.wait(timeout=10)
        queued_hup.wait_line('KER_SESSION_CHILD_REAP', 5)
        wait_dead(worker_fds['queued_hup'], hup_identity['pid'])
        hup_output = queued_hup.lines.snapshot()
        require('KER_SESSION_DRAIN_MODE ' not in hup_output and queued_hup.process.returncode != 0,
                'control HUP authorized DRAIN_MODE or was not rejected during pending ACK')
        wait_released(hup_identity['epoch'])
        print('PASS: control HUP during a pending heartbeat rejected consumed D without drain authorization', flush=True)
        queued_hup = None

        current = start_parent()
        current_identity = current.wait_line('KER_SESSION_ATTACHED', 20)
        worker_fds['current'] = open_worker_pidfd(current_identity)
        require(current_identity['epoch'] != old_identity['epoch'] and
                current_identity['slot'] != old_identity['slot'] and
                current_identity['generation'] == old_identity['generation'] == 0 and
                current_identity['process'] == old_identity['process'] == 0,
                'workers did not occupy distinct same-generation authenticated coordinates')
        time.sleep(0.4)
        current.send('Q')
        peer = current.wait_line('KER_SESSION_PEER', 10)
        require(peer == dict(epoch=old_identity['epoch'], generation=1, draining=True,
                             mirror_epoch=old_identity['epoch'], mirror_generation=1,
                             mirror_draining=True), 'fresh orphan worker was not selected and mirrored: ' + repr(peer))
        print('PASS: fresh worker stamp survives master death and selects the foreign epoch', flush=True)

        current.send('R')
        current.wait_line('KER_SESSION_RELOAD_ACTIVE', 5)
        current.send('Q')
        fallback = current.wait_line('KER_SESSION_PEER', 10)
        require(fallback == dict(epoch=current_identity['epoch'], generation=1, draining=False,
                                 mirror_epoch=current_identity['epoch'], mirror_generation=1,
                                 mirror_draining=False), 'reload-active did not select caller fallback: ' + repr(fallback))
        current.send('R')
        current.wait_line('KER_SESSION_RELOAD_ACTIVE', 5)
        print('PASS: reload-active suppresses foreign drain selection and mirrors caller fallback', flush=True)

        # A newer eligible worker replaces the selected peer while draining
        # remains true. The same caller mirror must publish the complete new
        # epoch/generation tuple, not combine it with a prior snapshot.
        replacement = start_parent()
        replacement_identity = replacement.wait_line('KER_SESSION_ATTACHED', 20)
        worker_fds['replacement'] = open_worker_pidfd(replacement_identity)
        require(replacement_identity['epoch'] not in (old_identity['epoch'], current_identity['epoch']) and
                replacement_identity['slot'] not in (old_identity['slot'], current_identity['slot']),
                'replacement worker did not receive a distinct resident coordinate')
        replacement.send('D')
        replacement.wait_line('KER_SESSION_DRAIN_MODE', 10)
        os.kill(replacement.process.pid, signal.SIGKILL)
        replacement.process.wait(timeout=5)
        time.sleep(0.35)
        current.send('Q')
        newer = current.wait_line('KER_SESSION_PEER', 10)
        require(newer == dict(epoch=replacement_identity['epoch'], generation=1, draining=True,
                              mirror_epoch=replacement_identity['epoch'], mirror_generation=1,
                              mirror_draining=True), 'true-to-true peer replacement published a mixed/stale mirror: ' + repr(newer))
        print('PASS: true-to-true peer replacement publishes one coherent epoch/generation snapshot', flush=True)

        os.kill(old_identity['pid'], signal.SIGKILL)
        wait_dead(worker_fds['old'], old_identity['pid'])
        current.send('Q')
        retained = current.wait_line('KER_SESSION_PEER', 10)
        require(retained == newer, 'reaping the older worker corrupted the newer draining snapshot: ' + repr(retained))
        os.kill(replacement_identity['pid'], signal.SIGKILL)
        wait_dead(worker_fds['replacement'], replacement_identity['pid'])
        current.send('Q')
        grace = current.wait_line('KER_SESSION_PEER', 10)
        require(grace == newer, 'last fresh replacement stamp was discarded on pidfd death: ' + repr(grace))
        print('PASS: dead drain worker remains a peer through its last-stamp freshness window', flush=True)
        time.sleep(2.1)
        current.send('Q')
        stale = current.wait_line('KER_SESSION_PEER', 10)
        require(stale == dict(epoch=current_identity['epoch'], generation=1, draining=False,
                              mirror_epoch=current_identity['epoch'], mirror_generation=1,
                              mirror_draining=False), 'stale/dead worker did not preserve fallback mirror: ' + repr(stale))
        wait_released(old_identity['epoch'])
        wait_released(replacement_identity['epoch'])
        print('PASS: after freshness expires the peer falls back and both stale slots are reclaimed', flush=True)

        current.process.stdin.close()
        current.process.wait(timeout=10)
        require(current.process.returncode == 0, 'ordinary current worker did not cleanly stop')
        current = None

        ordinary = start_parent()
        normal_identity = ordinary.wait_line('KER_SESSION_ATTACHED', 20)
        worker_fds['ordinary'] = open_worker_pidfd(normal_identity)
        os.kill(ordinary.process.pid, signal.SIGKILL)
        ordinary.process.wait(timeout=5)
        wait_dead(worker_fds['ordinary'], normal_identity['pid'])
        wait_released(normal_identity['epoch'])
        print('PASS: an ordinary worker still exits when its master control pipe closes', flush=True)

        census = status()
        require(census['slot'] == 0 and census['process'] == 0 and census['token'] == 0,
                'worker/epoch/mempool resources remained after the scenario: ' + repr(census))
        resident.process.stdin.close()
        resident.process.wait(timeout=10)
        require(resident.process.returncode == 0, 'resident did not shut down cleanly')
        drained = resident.wait_line('KER_SESSION_DRAINED', 5)
        require(drained['outstanding'] == 0 and drained['objects'] == 511,
                'resident did not restore the exact control-pool baseline: ' + repr(drained))
        resident = None
        print('PASS: resident released all slots and control-pool objects', flush=True)
        return 0
    finally:
        if resident_stopped and resident is not None and resident.process.poll() is None:
            try: os.kill(resident.process.pid, signal.SIGCONT)
            except ProcessLookupError: pass
        # Drain-authorized workers can outlive a failed lease/master. Kill only
        # the exact processes pinned by pidfds, while the resident can still
        # observe/reclaim them; never signal a recycled numeric PID.
        for name, fd in worker_fds.items():
            try:
                poller = select.poll(); poller.register(fd, select.POLLIN)
                if not poller.poll(0):
                    if not hasattr(signal, 'pidfd_send_signal'):
                        raise RuntimeError('pidfd_send_signal is required for failure cleanup')
                    signal.pidfd_send_signal(fd, signal.SIGKILL)
                    wait_dead(fd, name)
            except ProcessLookupError:
                pass
        for fd in worker_fds.values():
            try: os.close(fd)
            except OSError: pass
        for child in (old, current, ordinary, replacement, queued_hup):
            if child is not None and child.process.poll() is None:
                child.process.kill()
                try: child.process.wait(timeout=3)
                except subprocess.TimeoutExpired: pass
        if resident is not None and resident.process.poll() is None:
            resident.process.kill()
            try: resident.process.wait(timeout=3)
            except subprocess.TimeoutExpired: pass


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print('session-drain-peer: ' + str(error), file=sys.stderr)
        for child in CHILDREN:
            for reader in (child.lines, child.errors):
                if reader is not None:
                    reader.thread.join(timeout=0.2)
            print('--- ' + child.label + ' stdout ---', file=sys.stderr)
            if child.lines is not None:
                print(child.lines.snapshot(), file=sys.stderr)
            print('--- ' + child.label + ' stderr ---', file=sys.stderr)
            if child.errors is not None:
                print(child.errors.snapshot(), file=sys.stderr)
        raise SystemExit(1)
