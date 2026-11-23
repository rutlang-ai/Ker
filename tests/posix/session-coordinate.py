#!/usr/bin/env python3
"""Exercise the authenticated, unseeded live-coordinate query with original EAL."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import selectors
import shlex
import subprocess
import sys
import tempfile
import time

from hugepage_preflight import hugepage_capacity_error


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


def read_record(process, prefix, timeout=45):
    deadline = time.monotonic() + timeout
    line = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while time.monotonic() < deadline:
            if process.poll() is not None:
                break
            events = selector.select(max(0, deadline - time.monotonic()))
            if not events:
                break
            chunk = os.read(process.stdout.fileno(), 1)
            if not chunk:
                break
            if chunk != b'\n':
                line.extend(chunk)
                continue
            text = line.decode(errors='replace')
            line.clear()
            if text.startswith(prefix + ' '):
                return json.loads(text[len(prefix) + 1:]), text
    detail = ''
    if process.poll() is not None:
        try:
            _out, err = process.communicate(timeout=2)
            detail = f' status={process.returncode} stderr={err.decode(errors="replace")}'
        except subprocess.TimeoutExpired:
            detail = ' exited with unread output'
    raise RuntimeError(f'timed out waiting for {prefix}{detail}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', type=Path, required=True)
    parser.add_argument('--tool', type=Path, required=True)
    parser.add_argument('--dpdk-plugin-dir', type=Path)
    parser.add_argument('--huge-dir', type=Path, default=Path('/dev/hugepages'))
    args = parser.parse_args()
    plugin_dir = resolve_dpdk_plugin_dir(args.dpdk_plugin_dir)
    plugin_paths = resolve_dpdk_plugin_paths(plugin_dir, ('mempool_ring',))
    reason = hugepage_capacity_error(args.huge_dir, 64 * 1024 * 1024)
    if reason:
        print('SKIP: ' + reason + '; no host settings changed')
        return 77

    spec = importlib.util.spec_from_file_location('ker_session_tool', args.tool)
    api = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(api)
    with tempfile.TemporaryDirectory(prefix='ker-session-coordinate-') as temporary:
        root = Path(temporary)
        socket_path = root / 'control.sock'
        run_id = f'{os.getpid()}-{os.urandom(6).hex()}'
        cpu = min(os.sched_getaffinity(0))
        plugin_options = dpdk_plugin_eal_options(plugin_paths)
        eal = (f'--lcores=0@{cpu} --no-pci --no-telemetry --iova-mode=va -m 64 {plugin_options} '
               f'--huge-dir={shlex.quote(str(args.huge_dir))} --file-prefix=coordinate-{run_id}')
        common = ['--socket', str(socket_path), '--worker', str(args.worker), '--eal', eal]
        environment = dict(os.environ, RUNTIME_DIRECTORY=str(root))
        primary = subprocess.Popen([sys.executable, str(args.tool), 'serve', *common],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, bufsize=0)
        probe = None
        worker_pidfd = supervisor_pidfd = -1
        try:
            ready, _ = read_record(primary, 'KER_SESSION_READY')
            require(ready.get('stage') == 'shared-control' and ready.get('rings') == 128 and
                    ready.get('slots') == 4, 'resident did not publish the expected fixed ring geometry')
            unbound = api.Connection(socket_path)
            try:
                request = api.packet(api.COORDINATE_QUERY, 1)
                unbound.socket.sendall(api.encode(request))
                data = unbound.socket.recv(api.WIRE.size + 1)
                require(len(data) == api.WIRE.size, 'unbound coordinate query returned a malformed response')
                denied = dict(zip(api.FIELDS, api.WIRE.unpack(data)))
                require(denied['status'] == -1 and
                        all(denied[field] == 0 for field in ('session', 'epoch', 'token', 'slot', 'generation', 'process')),
                        'unbound client learned a hidden live coordinate')
            finally:
                unbound.close()

            probe = subprocess.Popen([sys.executable, str(args.tool), 'coordinate-probe', *common],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, bufsize=0)
            supervisor_pidfd = os.pidfd_open(probe.pid, 0)
            attached, _ = read_record(probe, 'KER_SESSION_ATTACHED')
            require(attached.get('stage') == 'shared-control' and attached.get('master') == probe.pid and
                    attached.get('generation') == 0 and attached.get('process') == 0 and
                    attached.get('slot', 0) != 0 and attached.get('epoch', 0) != 0,
                    'worker did not attach to a live nonzero generation-0 coordinate')
            worker_pidfd = os.pidfd_open(attached['pid'], 0)
            coordinate, _ = read_record(probe, 'KER_SESSION_COORDINATE')
            require(coordinate.get('query_sent') is True and coordinate.get('query_completed') is True,
                    'unseeded typed coordinate query was not sent and completed')
            require((coordinate.get('session'), coordinate.get('epoch'), coordinate.get('slot'),
                     coordinate.get('generation'), coordinate.get('process')) ==
                    (ready['session'], attached['epoch'], attached['slot'], 0, 0),
                    'query result does not match the live attached worker')
            require(coordinate.get('target_found') is True and
                    isinstance(coordinate.get('target_ring'), str) and
                    coordinate.get('target_ring') != coordinate.get('slot_zero_ring'),
                    'production ring-name helper did not resolve a distinct proc-1 ring from the returned coordinate')

            probe.stdin.close()
            probe.stdin = None
            probe_output, probe_error = probe.communicate(timeout=45)
            require(probe.returncode == 0, 'coordinate probe supervisor failed: ' +
                    probe_error.decode(errors='replace'))
            reap = [json.loads(line[len(b'KER_SESSION_CHILD_REAP '):])
                    for line in probe_output.splitlines()
                    if line.startswith(b'KER_SESSION_CHILD_REAP ')]
            require(len(reap) == 1 and reap[0].get('pid') == attached['pid'] and
                    reap[0].get('status') == 0 and reap[0].get('escalated') is False,
                    'exact coordinate worker was not cleanly reaped')
            with selectors.DefaultSelector() as selector:
                selector.register(worker_pidfd, selectors.EVENT_READ, 'worker')
                selector.register(supervisor_pidfd, selectors.EVENT_READ, 'supervisor')
                ready_pids = {key.data for key, _ in selector.select(10)}
                require(ready_pids == {'worker', 'supervisor'},
                        'exact EAL worker and lease-supervisor pidfds did not both become readable')

            deadline = time.monotonic() + 10
            status = None
            while time.monotonic() < deadline:
                connection = api.Connection(socket_path)
                try:
                    status = connection.request(api.STATUS)
                finally:
                    connection.close()
                if (status['slot'] == 0 and status['process'] == 0 and
                        status['generation'] == 511 and status['token'] == 0):
                    break
                time.sleep(0.02)
            require(status is not None and status['slot'] == 0 and status['process'] == 0 and
                    status['generation'] == 511 and status['token'] == 0,
                    'resident did not reap exact worker/master leases to the 511-object baseline: ' + repr(status))

            primary.stdin.close()
            primary.stdin = None
            primary_output, primary_error = primary.communicate(timeout=30)
            drained_records = [json.loads(line.removeprefix('KER_SESSION_DRAINED '))
                for line in primary_output.decode(errors='replace').splitlines()
                if line.startswith('KER_SESSION_DRAINED ')]
            cleanup_ok = (len(drained_records) == 1 and
                drained_records[0].get('outstanding') == 0 and drained_records[0].get('objects') == 511 and
                drained_records[0].get('exception_lease_discarded', 0) == 0)
            require(primary.returncode == 0 and cleanup_ok,
                    'resident did not complete exact pool cleanup: records=' + repr(drained_records) +
                    ' stderr=' + primary_error.decode(errors='replace'))
            print('PASS: unseeded authenticated live-coordinate query, production proc-1 ring lookup, '
                  'exact worker pidfd reap, and 511-object cleanup')
            return 0
        finally:
            for exact_pidfd in (worker_pidfd, supervisor_pidfd):
                if exact_pidfd >= 0:
                    os.close(exact_pidfd)
            if probe is not None and probe.poll() is None:
                if probe.stdin and not probe.stdin.closed:
                    probe.stdin.close(); probe.stdin = None
                try:
                    probe.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    probe.kill(); probe.communicate(timeout=2)
            if primary.poll() is None:
                if primary.stdin and not primary.stdin.closed:
                    primary.stdin.close(); primary.stdin = None
                try:
                    primary.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    primary.kill(); primary.communicate(timeout=2)


if __name__ == '__main__':
    raise SystemExit(main())
