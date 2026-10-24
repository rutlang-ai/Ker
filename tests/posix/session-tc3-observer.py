#!/usr/bin/env python3
"""Source-shaped same-generation, two-master TC-3 observer barrier."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import selectors
import shlex
import socket
import subprocess
import sys
import tempfile
import time

from hugepage_preflight import hugepage_capacity_error


def require(value, message):
    if not value:
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


def line(process, prefix, timeout=30):
    while True:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            require(selector.select(timeout), 'timed out waiting for ' + prefix)
        raw = process.stdout.readline()
        if not raw:
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait()
            errors = process.stderr.read().decode(errors='replace') if process.stderr is not None else ''
            raise RuntimeError(prefix + ' stream closed; exit=' + str(process.returncode) + '; stderr=' + errors)
        value = raw.decode().strip()
        if prefix.startswith('WORKER ') and value.startswith('WORKER EAL:'):
            print('INFO: ' + value, flush=True)
            continue
        if not value.startswith(prefix + ' '):
            if process.stdin is not None and not process.stdin.closed:
                process.stdin.close()
                process.stdin = None
            try:
                rest, errors = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill(); rest, errors = process.communicate()
            raise RuntimeError(prefix + ' expected, got ' + value + '; remaining output=' +
                               rest.decode(errors='replace') + '; stderr=' +
                               (errors.decode(errors='replace') if errors else ''))
        return json.loads(value[len(prefix) + 1:])


def worker_line(process, prefix, timeout=30):
    value = line(process, 'WORKER ' + prefix, timeout)
    return value


def stop(process):
    if process is not None and process.poll() is None:
        process.kill(); process.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', type=Path, required=True)
    parser.add_argument('--tool', type=Path, required=True)
    parser.add_argument('--dpdk-plugin-dir', type=Path)
    parser.add_argument('--huge-dir', type=Path, default=Path('/dev/hugepages'))
    args = parser.parse_args()
    plugin_dir = resolve_dpdk_plugin_dir(args.dpdk_plugin_dir)
    plugin_paths = resolve_dpdk_plugin_paths(plugin_dir, ('mempool_ring', 'net_ring'))
    reason = hugepage_capacity_error(args.huge_dir, 64 * 1024 * 1024)
    if reason:
        print('SKIP: ' + reason + '; no host settings changed')
        return 77
    spec = importlib.util.spec_from_file_location('ker_session_tool', args.tool)
    api = importlib.util.module_from_spec(spec); spec.loader.exec_module(api)
    processes = []
    helpers = []
    run_id = f'{os.getpid()}-{os.urandom(5).hex()}'
    cpu = min(os.sched_getaffinity(0))
    plugin_options = dpdk_plugin_eal_options(plugin_paths)
    eal = (f'--lcores=0@{cpu} --no-pci --no-telemetry --iova-mode=va -m 64 '
           f'--huge-dir={shlex.quote(str(args.huge_dir))} --file-prefix=tc3-observer-{run_id} '
           f'{plugin_options}')
    with tempfile.TemporaryDirectory(prefix='ker-tc3-observer-') as name:
        runtime = Path(name)
        path = runtime / 'control.sock'
        env = dict(os.environ, RUNTIME_DIRECTORY=str(runtime), KER_SESSION_TEST_PROBE_GATE='1', PYTHONDONTWRITEBYTECODE='1')
        primary = subprocess.Popen([str(args.worker), '--role', 'primary', '--socket', str(path),
            '--control-fd', '0', '--paired-pmd', '--', *api.role_arguments(eal, 'primary', paired_pmd=True)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, bufsize=0)
        processes.append(primary)
        try:
            ready = line(primary, 'KER_SESSION_READY')
            require(ready['ring_pmd'] is True and ready['exception_endpoint_ifindex'] > 0 and
                    ready['exception_endpoint_name'], 'resident did not create the session exception endpoint')

            def launch(label, standby):
                command = [sys.executable, str(Path(__file__).resolve()), '--master-worker',
                    '--worker', str(args.worker), '--tool', str(args.tool), '--socket', str(path), '--eal', eal]
                if standby: command.append('--standby')
                helper = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, env=env, bufsize=0)
                processes.append(helper); helpers.append(helper)
                ticket = line(helper, 'MASTER')
                attached = worker_line(helper, 'KER_SESSION_ATTACHED')
                status = worker_line(helper, 'KER_SESSION_PMD_STANDBY' if standby else 'KER_SESSION_PMD_GRANTED')
                observer = worker_line(helper, 'KER_SESSION_TC3_OBSERVER_READY')
                require(attached['generation'] == 0 and attached['process'] == 0 and
                        attached['master'] == helper.pid and attached['epoch'] == ticket['epoch'] and
                        attached['slot'] == ticket['slot'],
                        label + ' attachment identity did not match its independent master')
                require(status['generation'] == 0 and status['process'] == 0 and
                        bool(status['queue_owner_key']) is (not standby), label + ' admission did not match expected ownership')
                require(observer['generation'] == 0 and observer['process'] == 0 and
                        observer['epoch'] == ticket['epoch'] and observer['slot'] == ticket['slot'] and
                        observer['exception_ifindex'] == ready['exception_endpoint_ifindex'],
                        label + ' observer lost its actual session endpoint/coordinate identity')
                return dict(label=label, ticket=ticket, attached=attached, status=status,
                            observer=observer, process=helper)

            owner = launch('owner', False)
            standby = launch('standby', True)
            require(owner['process'].pid != standby['process'].pid and
                    owner['ticket']['epoch'] != standby['ticket']['epoch'] and
                    owner['ticket']['slot'] != standby['ticket']['slot'] and
                    owner['attached']['rings'][0] != standby['attached']['rings'][0],
                    'independent masters did not receive distinct epochs, slots, and message rings')
            require(owner['observer']['owns_device'] and owner['observer']['exception_endpoint_fd'] and
                    owner['observer']['queue_owner_key'] == owner['observer']['exception_endpoint_owner_key'] and
                    not standby['observer']['owns_device'] and not standby['observer']['exception_endpoint_fd'] and
                    standby['observer']['queue_owner_key'] == owner['observer']['queue_owner_key'] and
                    standby['observer']['exception_endpoint_owner_key'] == owner['observer']['queue_owner_key'],
                    'same-generation endpoint authorization did not follow the single PMD grant')

            for helper in helpers:
                helper.stdin.write(b'S'); helper.stdin.flush()
            before = [worker_line(owner['process'], 'KER_SESSION_TC3_SAMPLE'),
                      worker_line(standby['process'], 'KER_SESSION_TC3_SAMPLE')]
            require(all(item['sample'] == 0 for item in before), 'initial ownership samples were not labeled before barrier')
            # Release the second sample only after both workers completed the first.
            for helper in helpers:
                helper.stdin.write(b'S'); helper.stdin.flush()
            after = [worker_line(owner['process'], 'KER_SESSION_TC3_SAMPLE'),
                     worker_line(standby['process'], 'KER_SESSION_TC3_SAMPLE')]
            require(all(item['sample'] == 1 for item in after), 'post-barrier samples were not independently observed')
            samples = before + after
            snapshots = {(s['owner_epoch'], s['owner_generation'], s['owner_slot'], s['owner_process'],
                          s['queue_owner_key'], s['exception_endpoint_owner_key'], s['exception_ifindex']) for s in samples}
            require(len(snapshots) == 1, 'the two workers observed an unstable owner/endpoint snapshot')
            owner_epoch, owner_gen, owner_slot, owner_process, owner_key, endpoint_key, ifindex = next(iter(snapshots))
            require(owner_epoch != 0 and owner_gen == 0 and owner_process == 0 and owner_key == endpoint_key and
                    ifindex == ready['exception_endpoint_ifindex'] and owner_slot == owner['ticket']['slot'] and
                    all(s['generation'] == 0 and s['process'] == 0 for s in samples) and
                    sum(s['nohw'] for s in before) == 1 and sum(s['nohw'] for s in after) == 1 and
                    [s['nohw'] for s in before] == [s['nohw'] for s in after],
                    'source-shaped nohw/owner generation-0 contract failed')

            # Publish one real typed, resident-leased mbuf from each secondary.
            # Resident gate verifies both distinct rings before either is drained.
            for helper in helpers:
                helper.stdin.write(b'P'); helper.stdin.flush()
            primary.stdin.write(b'D'); primary.stdin.flush()
            pending = line(primary, 'KER_SESSION_TC3_TOKENS_PENDING')
            require(pending['generation'] == 0 and pending['process'] == 0 and pending['count'] == 2 and
                    pending['rings_distinct'] is True and pending['exception_ifindex'] == ifindex and
                    set(pending['slots']) == {owner['ticket']['slot'], standby['ticket']['slot']} and
                    set(pending['epochs']) == {owner['ticket']['epoch'], standby['ticket']['epoch']} and
                    pending['owner_epoch'] == owner_epoch,
                    'resident did not verify exactly one proper token in each distinct live master ring')
            done = [worker_line(owner['process'], 'KER_SESSION_TC3_PROBE_DONE'),
                    worker_line(standby['process'], 'KER_SESSION_TC3_PROBE_DONE')]
            require(all(item['count'] == 1 and item['generation'] == 0 and item['process'] == 0 and
                        item['primary_pid'] == primary.pid for item in done) and
                    {item['epoch'] for item in done} == {owner['ticket']['epoch'], standby['ticket']['epoch']} and
                    {item['slot'] for item in done} == {owner['ticket']['slot'], standby['ticket']['slot']},
                    'each independent master did not receive exactly one own typed primary response')
            print('CHECK: two independent live generation-0/process-0 masters sampled one stable non-primary owner before and after a shared barrier', flush=True)
            print('CHECK: distinct real message rings held one resident-leased typed token each before either token was drained', flush=True)
            print('PASS: pinned TC-3 same-generation single-consumer/shared-token observer contract', flush=True)
            for helper in helpers:
                helper.stdin.write(b'Q'); helper.stdin.flush()
            for case, response in zip((owner, standby), done):
                helper = case['process']
                require(helper.wait(timeout=20) == 0, 'master/observer chain did not cleanly retire')
                helper.stdin.close()
                helper_output = helper.stdout.read().decode(errors='replace')
                release_records = [line.removeprefix('MASTER_RELEASED ') for line in helper_output.splitlines()
                                   if line.startswith('MASTER_RELEASED ')]
                require(len(release_records) == 1, 'master helper omitted its child-death/release record: ' + helper_output)
                release = json.loads(release_records[0])
                require(release == dict(worker_pid=response['pid'], worker_status=0,
                                        worker_pidfd_dead=True, master_released=True),
                        'exact worker process death or master slot release was not proven: ' + repr(release))
            primary.stdin.close()
            require(primary.wait(timeout=20) == 0, 'resident did not cleanly stop after both masters retired')
            primary_output = primary.stdout.read().decode(errors='replace')
            drained_records = [line.removeprefix('KER_SESSION_DRAINED ') for line in primary_output.splitlines()
                               if line.startswith('KER_SESSION_DRAINED ')]
            require(len(drained_records) == 1, 'resident omitted final mempool drain proof: ' + primary_output)
            drained = json.loads(drained_records[0])
            require(drained == dict(outstanding=0, objects=511, exception_lease_discarded=0),
                    'resident did not restore all original pool objects: ' + repr(drained))
            stderr = primary.stderr.read().decode(errors='replace')
            if stderr:
                print('INFO: resident EAL diagnostics: ' + stderr.strip(), flush=True)
            require(not any(marker in stderr.upper() for marker in ('ERROR', 'FAILED', 'FATAL')),
                    'resident emitted an EAL/runtime failure: ' + stderr)
            print('CHECK: both exact worker PIDs died, both master slots released, and resident reported outstanding=0/objects=511', flush=True)
            print('PASS: TC-3 observer cleanup returned every resident object and stopped cleanly', flush=True)
            return 0
        finally:
            for helper in helpers:
                if helper.poll() is None:
                    try: helper.kill()
                    except OSError: pass
            for process in reversed(processes):
                stop(process)
    return 0


def master_worker(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('--master-worker', action='store_true')
    parser.add_argument('--worker', type=Path, required=True)
    parser.add_argument('--tool', type=Path, required=True)
    parser.add_argument('--socket', type=Path, required=True)
    parser.add_argument('--eal', required=True)
    parser.add_argument('--standby', action='store_true')
    args = parser.parse_args(argv)
    spec = importlib.util.spec_from_file_location('ker_session_tool', args.tool)
    api = importlib.util.module_from_spec(spec); spec.loader.exec_module(api)
    connection = api.Connection(args.socket)
    ticket = connection.request(api.MASTER)
    print('MASTER ' + json.dumps(ticket), flush=True)
    ticket_r, ticket_w = os.pipe2(os.O_CLOEXEC)
    control_r, control_w = os.pipe2(os.O_CLOEXEC)
    packet_host, packet_child = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    wire_host, wire_child = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    mtu_host, mtu_child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    command = [str(args.worker), '--role', 'secondary', '--socket', str(args.socket),
        '--control-fd', str(control_r), '--ticket-fd', str(ticket_r), '--generation', '0',
        '--process', '0', '--paired-pmd', '--tc3-observer']
    if args.standby: command.append('--standby')
    command.extend(['--packet-fd', str(packet_child.fileno()), '--wire-fd', str(wire_child.fileno()),
        '--mtu-fd', str(mtu_child.fileno()), '--', *api.role_arguments(args.eal, 'secondary', paired_pmd=True)])
    child = subprocess.Popen(command,
        pass_fds=(ticket_r, control_r, packet_child.fileno(), wire_child.fileno(), mtu_child.fileno()),
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
    try:
        child_pidfd = os.pidfd_open(child.pid)
    except OSError as error:
        child.kill(); child.wait()
        raise RuntimeError('exact observer worker pidfd unavailable') from error
    os.close(ticket_r); os.close(control_r)
    packet_child.close(); wire_child.close(); mtu_child.close()
    packet_host.close(); wire_host.close(); mtu_host.close()
    if os.write(ticket_w, api.encode(ticket)) != api.WIRE.size:
        child.kill(); child.wait(); raise RuntimeError('short master ticket write')
    os.close(ticket_w)
    selector = selectors.DefaultSelector()
    selector.register(child.stdout.fileno(), selectors.EVENT_READ, 'worker')
    selector.register(sys.stdin.fileno(), selectors.EVENT_READ, 'control')
    pending = bytearray(); input_open = True
    try:
        while child.poll() is None or pending:
            for key, _ in selector.select(0.1):
                if key.data == 'worker':
                    data = os.read(child.stdout.fileno(), 4096)
                    if not data:
                        try: selector.unregister(child.stdout.fileno())
                        except KeyError: pass
                        if pending:
                            print('WORKER ' + pending.decode(errors='replace'), flush=True)
                            pending.clear()
                        continue
                    pending.extend(data)
                    while b'\n' in pending:
                        raw, _, rest = pending.partition(b'\n'); pending[:] = rest
                        print('WORKER ' + raw.decode(errors='replace'), flush=True)
                elif input_open:
                    data = os.read(sys.stdin.fileno(), 4096)
                    if not data:
                        input_open = False; selector.unregister(sys.stdin.fileno())
                        if child.poll() is None:
                            try: os.write(control_w, b'Q')
                            except OSError: pass
                    else:
                        view = memoryview(data)
                        while view:
                            try: count = os.write(control_w, view)
                            except BrokenPipeError: break
                            view = view[count:]
            if child.poll() is not None:
                try: data = os.read(child.stdout.fileno(), 4096)
                except OSError: data = b''
                if data:
                    pending.extend(data)
                    while b'\n' in pending:
                        raw, _, rest = pending.partition(b'\n'); pending[:] = rest
                        print('WORKER ' + raw.decode(errors='replace'), flush=True)
                elif not pending:
                    break
        result = child.wait(timeout=5)
        if pending: print('WORKER ' + pending.decode(errors='replace'), flush=True)
        with selectors.PollSelector() as death:
            death.register(child_pidfd, selectors.EVENT_READ)
            pidfd_dead = bool(death.select(0))
        if not pidfd_dead:
            raise RuntimeError('exact observer worker pidfd did not become readable after wait')
        import errno
        deadline = time.monotonic() + 5
        while True:
            try:
                connection.request(api.RELEASE, session=ticket['session'], epoch=ticket['epoch'],
                    token=ticket['token'], slot=ticket['slot'])
                break
            except OSError as error:
                if error.errno != errno.EBUSY or time.monotonic() >= deadline: raise
                time.sleep(0.05)
        print('MASTER_RELEASED ' + json.dumps(dict(worker_pid=child.pid, worker_status=result,
            worker_pidfd_dead=pidfd_dead, master_released=True)), flush=True)
        return result
    finally:
        selector.close()
        try: os.close(control_w)
        except OSError: pass
        if child.poll() is None:
            child.kill(); child.wait()
        os.close(child_pidfd)
        connection.close()


if __name__ == '__main__':
    if '--master-worker' in sys.argv:
        raise SystemExit(master_worker(sys.argv[1:]))
    raise SystemExit(main())
