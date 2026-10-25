"""Launch an original Linux instance on a granted secondary packet session."""
import errno
import ipaddress
import json
import os
from pathlib import Path
import select
import selectors
import signal
import socket
import subprocess
import sys
import tempfile
import time


def signal_pidfd(pidfd, signum):
    """Signal one exact process identity through its already-open pidfd."""
    sender = getattr(signal, 'pidfd_send_signal', None)
    if sender is None:
        raise RuntimeError('pidfd_send_signal is required for exact handoff fixture control')
    sender(pidfd, signum)


def wait_pidfd_process_stopped(pidfd, pid, timeout=5):
    """Wait for an exact pidfd target to report a stopped /proc state."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if select.select([pidfd], [], [], 0)[0]:
            raise RuntimeError('exact handoff worker exited before reaching stopped state')
        if pidfd_process_stopped(pidfd, pid):
            return
        time.sleep(0.005)
    raise RuntimeError('exact handoff worker did not reach stopped state before deadline')


def pidfd_process_stopped(pidfd, pid):
    """Check the stopped state of a live exact pidfd target."""
    if select.select([pidfd], [], [], 0)[0]:
        return False
    try:
        lines = Path(f'/proc/{pid}/status').read_text().splitlines()
    except FileNotFoundError:
        return False
    state = next((line.split()[1] for line in lines if line.startswith('State:')), None)
    observed_pid = next((int(line.split()[1]) for line in lines if line.startswith('Pid:')), None)
    return observed_pid == pid and state in ('T', 't')


def resume_pidfd_if_live(pidfd):
    """Resume an exact worker if it is still alive; tolerate concurrent exit."""
    if select.select([pidfd], [], [], 0)[0]:
        return False
    try:
        signal_pidfd(pidfd, signal.SIGCONT)
    except ProcessLookupError:
        if select.select([pidfd], [], [], 0)[0]:
            return False
        raise
    return True


def tap_interfaces_for_process(pid, *, fdinfo_dir=None):
    """Return TUN interface names attached to a process from its fdinfo."""
    directory = Path(f'/proc/{pid}/fdinfo') if fdinfo_dir is None else Path(fdinfo_dir)
    names = []
    for path in directory.iterdir():
        try:
            information = path.read_text()
        except FileNotFoundError:
            continue
        names.extend(line.split(':', 1)[1].strip() for line in information.splitlines()
            if line.startswith('iff:'))
    return names



def validate_interrupted_cleanup(worker_code, packet_stats, *, packet_expected=True, app_launched=False,
                                 app_code=None, startup=b'', native_stats=None, worker_expected_code=None):
    """Validate signal cleanup without overriding the application's signal semantics."""
    if worker_expected_code is not None and worker_code == worker_expected_code and packet_stats is None:
        pass
    elif worker_code != 0:
        raise RuntimeError('secondary packet cleanup failed during signal cancellation')
    elif packet_expected:
        if not isinstance(packet_stats, dict) or packet_stats.get('status') != 0:
            raise RuntimeError('secondary packet worker did not report clean signal teardown')
    elif packet_stats is not None:
        raise RuntimeError('control-only standby unexpectedly reported packet activity')
    if not app_launched:
        return None
    if app_code not in (-signal.SIGTERM, 128 + signal.SIGTERM):
        raise RuntimeError('original Linux application did not exit from SIGTERM: ' + repr(app_code))
    ready = b'KER_NATIVE_READY\n' in startup
    stopping = b'KER_NATIVE_STOPPING\n' in startup
    done = b'KER_NATIVE_DONE\n' in startup
    incomplete = b'KER_NATIVE_INCOMPLETE\n' in startup
    if not ready:
        raise RuntimeError('SIGTERM arrived before native application readiness')
    if stopping:
        if (not done or incomplete or not isinstance(native_stats, dict) or
                native_stats.get('buffers_live') != 0):
            raise RuntimeError('started native teardown did not finish cleanly')
        return 'graceful'
    if done or incomplete or native_stats is not None:
        raise RuntimeError('native teardown markers are inconsistent after signal termination')
    return 'signal-terminated'


def validate_frame_committed_record(record, payload):
    """Validate the actual FRAME_COMMITTED schema; sequence is not in this reply."""
    if (not isinstance(record, dict) or record.get('queue') != 0 or record.get('generation') != 0 or
            not isinstance(record.get('object_index'), int) or record.get('object_index') < 0 or
            not isinstance(record.get('pool_tag'), int) or record.get('pool_tag') <= 0 or
            not isinstance(record.get('packet_pointer'), str) or not record['packet_pointer'] or
            not isinstance(record.get('length'), int) or record.get('length') < 14 or
            not isinstance(record.get('frame_hex'), str) or payload.hex() not in record['frame_hex']):
        raise RuntimeError('parked original LKL endpoint did not commit the exact second UDP frame')
    return record


FRAME_U2_TRIGGER_MODES = frozenset({
    'frame-positive', 'frame-full', 'frame-death-prepared',
    'frame-death-producer-active-consumer', 'frame-death-consumer-prepared',
    'frame-death-consumer-writing', 'frame-death-both-prepared', 'frame-lost-prepare-reply',
})


def handoff_trigger_complete(mode, handoff_seen, udp_sequence):
    """Whether this profile consumed its complete H/U trigger sequence."""
    return bool(handoff_seen and (mode not in FRAME_U2_TRIGGER_MODES or udp_sequence >= 2))


def close_completed_handoff_trigger(mode, handoff_seen, udp_sequence, fd, close_fd):
    if fd is not None and handoff_trigger_complete(mode, handoff_seen, udp_sequence):
        close_fd(fd)
        return None
    return fd


def handoff_trigger_action(data):
    if data == b'U':
        return 'udp'
    if data == b'H':
        return 'handoff'
    return 'invalid'


def validate_parked_owner_cleared(record, worker_pid):
    """Validate the immediate owner-clear record after the PARKED transition."""
    if (not isinstance(record, dict) or set(record) != {'pid', 'owner_key'} or
            type(record.get('pid')) is not int or record['pid'] != worker_pid or
            type(record.get('owner_key')) is not int or record['owner_key'] != 0):
        raise RuntimeError('parked owner did not report the exact cleared-owner state: ' + repr(record))


def validate_frame_negative_markers(prepare, cancel):
    prepare_fields = {'variants', 'datagram_queued', 'ring_unchanged', 'pool_unchanged'}
    if (not isinstance(prepare, dict) or set(prepare) != prepare_fields or
            type(prepare.get('variants')) is not int or prepare['variants'] != 12 or
            any(prepare.get(field) is not True for field in
                ('datagram_queued', 'ring_unchanged', 'pool_unchanged'))):
        raise RuntimeError('frame-negative PREPARES summary did not match the exact expected result: ' + repr(prepare))
    cancel_fields = {'prepared_replay', 'bad_commit_denied', 'bad_cancel_denied',
        'cancel_replay', 'datagram_queued', 'pool_restored'}
    if (not isinstance(cancel, dict) or set(cancel) != cancel_fields or
            any(cancel.get(field) is not True for field in cancel_fields)):
        raise RuntimeError('frame CANCEL replay summary did not match the exact expected result: ' + repr(cancel))


def read_frame_negative_prefix(worker, ready, include_negatives):
    negative_prepares = cancel_replay = None
    if include_negatives:
        negative_prepares = ready('KER_SESSION_FRAME_NEGATIVE_PREPARES_PASS', process=worker)
        cancel_replay = ready('KER_SESSION_FRAME_CANCEL_REPLAY_PASS', process=worker)
        validate_frame_negative_markers(negative_prepares, cancel_replay)
    return negative_prepares, cancel_replay


def read_frame_commit_sequence(worker, ready, include_negatives):
    """Consume only enabled frame summaries, then the exact commit record."""
    negative_prepares, cancel_replay = read_frame_negative_prefix(worker, ready, include_negatives)
    committed = ready('KER_SESSION_FRAME_COMMITTED', process=worker)
    return negative_prepares, cancel_replay, committed


def validate_handoff_peer_cleanup(metrics, peer_present, peer_code, peer_packet_stats):
    """Require packet completion only after validated handoff ownership."""
    if not peer_present:
        return
    if peer_code != 0:
        raise RuntimeError('handoff peer did not exit cleanly')
    committed = (metrics.get('handoff') or {}).get('stage') == 'committed'
    if committed:
        if not isinstance(peer_packet_stats, dict) or peer_packet_stats.get('status') != 0:
            raise RuntimeError('committed handoff peer did not report successful packet cleanup')
    elif peer_packet_stats is not None:
        raise RuntimeError('control-only handoff peer unexpectedly reported packet completion')


def run_session(args, api):
    address = ipaddress.ip_interface(args.address or '198.18.0.2/24')
    address6 = ipaddress.ip_interface(args.address6) if args.address6 else None
    for item, version in ((address, 4), (address6, 6)):
        if item is not None and (item.version != version or item.ip.is_unspecified or
                                 item.ip.is_multicast or item.ip.is_loopback):
            raise ValueError('packet sessions require unicast interface addresses')
    if address.ip == ipaddress.IPv4Address('255.255.255.255') or (address.network.prefixlen < 31 and
            address.ip in (address.network.network_address, address.network.broadcast_address)) or (
            address6 is not None and address6.ip.ipv4_mapped is not None):
        raise ValueError('packet sessions require usable unicast endpoints')
    worker_path = args.worker.resolve(strict=True)
    guard = worker_path.parent / 'ker-app'
    if not guard.is_file():
        raise ValueError('ker-app is required beside ker-io-session')
    library = args.library.resolve(strict=True)
    handoff_fd = getattr(args, 'test_live_handoff_fd', None)
    handoff_mode = os.environ.get('KER_SESSION_TEST_HANDOFF_MODE')
    handoff_modes = {'positive', 'frame-positive', 'frame-full', 'frame-death-prepared', 'frame-death-queued', 'frame-death-producer-active-consumer', 'frame-death-consumer-prepared', 'frame-death-consumer-writing', 'frame-death-both-prepared', 'frame-lost-prepare-reply', 'bad-capability', 'bad-tx-lease', 'bad-rx-lease', 'peer-death', 'timeout',
        'handoff-control-hup',
        'prepare-enoent', 'prepare-ebusy', 'prepare-eperm', 'bad-prepare-error',
        'bad-prepare-error-token', 'bad-prepare-error-capability', 'bad-prepare-error-tx-lease',
        'bad-prepare-error-rx-lease', 'bad-prepare-error-sequence', 'bad-prepare-success'}
    if handoff_fd is not None and handoff_mode is not None and handoff_mode not in handoff_modes:
        raise ValueError('unknown test handoff mode')
    if handoff_fd is not None and not getattr(args, 'generation_rings', False):
        raise ValueError('test live handoff requires the generation-ring adapter')
    # Validation does not mutate file-description flags. The caller transfers
    # this endpoint; the launcher closes its own copy after the child starts.
    with socket.socket(fileno=os.dup(args.wire_fd)) as endpoint:
        if endpoint.family != socket.AF_UNIX or endpoint.type != socket.SOCK_DGRAM:
            raise ValueError('--wire-fd must be a connected local Ethernet datagram endpoint')
        endpoint.getpeername()
    connection = api.Connection(args.socket)
    worker = peer_worker = app = None
    worker_pidfd = -1
    app_pidfd = -1
    peer_worker_pidfd = -1
    handoff_udp_ready = False
    frame_death_complete = False
    frame_death_worker_expected_code = None
    peer_control_w = peer_wire_fd = -1
    peer_packet_worker = peer_packet_app = peer_mtu_worker = peer_mtu_app = None
    owned = {args.wire_fd}
    if handoff_fd is not None:
        owned.add(handoff_fd)
    metrics = {'stage': 'starting', 'app_started': False}
    metrics['generation_rings'] = bool(getattr(args, 'generation_rings', False))
    completed = False
    received_signal = None
    previous_sigterm = signal.getsignal(signal.SIGTERM)
    previous_sigint = signal.getsignal(signal.SIGINT)

    def record_signal(signum, _frame):
        # Keep the handler async and non-reentrant; child cleanup stays in the
        # ordinary control flow and finally block.
        nonlocal received_signal
        if received_signal is None:
            received_signal = signum

    def publish():
        if args.stats is None: return
        target = args.stats.absolute()
        with tempfile.NamedTemporaryFile('w', dir=target.parent, prefix='.' + target.name + '.', delete=False) as out:
            temporary = Path(out.name)
            json.dump(metrics, out); out.write('\n')
        try: os.replace(temporary, target)
        finally: temporary.unlink(missing_ok=True)

    packet_worker, packet_app = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    mtu_worker, mtu_app = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)

    def pipe(flags):
        pair = os.pipe2(flags); owned.update(pair); return pair

    def close(fd):
        if fd in owned:
            owned.remove(fd); os.close(fd)

    def release(ticket):
        deadline = time.monotonic() + 5
        while True:
            try:
                connection.request(api.RELEASE, session=ticket['session'], epoch=ticket['epoch'],
                    token=ticket['token'], slot=ticket['slot'])
                return
            except OSError as error:
                if error.errno != errno.EBUSY or time.monotonic() >= deadline:
                    raise
                time.sleep(0.02)

    def ready(*prefixes, process=None):
        process = worker if process is None else process
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            if not selector.select(20):
                raise RuntimeError('secondary packet startup timed out')
        line = process.stdout.readline()
        prefix = next((value for value in prefixes if line.startswith(value.encode() + b' ')), None)
        if prefix is None:
            raise RuntimeError('secondary packet startup failed: ' + line.decode(errors='replace'))
        value = json.loads(line[len(prefix) + 1:])
        if prefix != 'KER_SESSION_PMD_STANDBY' or 'standby' not in metrics:
            print(line.decode().rstrip(), file=sys.stderr, flush=True)
        return (prefix, value) if len(prefixes) > 1 else value

    def wait_marker(process, prefix, timeout=10):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                if not selector.select(max(0, deadline-time.monotonic())):
                    break
            line = process.stdout.readline()
            if not line:
                raise RuntimeError('worker exited before ' + prefix)
            if line.startswith(prefix.encode() + b' '):
                print(line.decode().rstrip(), file=sys.stderr, flush=True)
                return json.loads(line[len(prefix)+1:])
            print(line.decode().rstrip(), file=sys.stderr, flush=True)
        raise RuntimeError('timed out waiting for ' + prefix)

    def start_handoff_peer(ticket):
        nonlocal peer_worker, peer_control_w, peer_packet_worker, peer_packet_app, peer_worker_pidfd
        nonlocal peer_mtu_worker, peer_mtu_app
        if handoff_fd is None:
            return
        if args.generation != 0 or args.standby or peer_wire_fd < 0:
            raise RuntimeError('live handoff fixture requires a generation-zero owner')
        peer_packet_worker, peer_packet_app = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        peer_mtu_worker, peer_mtu_app = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        ticket_r, ticket_w = pipe(os.O_CLOEXEC)
        control_r, peer_control_w = pipe(os.O_CLOEXEC)
        os.set_blocking(peer_control_w, False)
        peer_environment = os.environ.copy()
        peer_environment.pop('KER_SESSION_TEST_HANDOFF_PENDING_HB', None)
        peer_arguments = [str(worker_path), '--role', 'secondary', '--paired-pmd', '--standby',
            '--socket', str(args.socket), '--control-fd', str(control_r), '--ticket-fd', str(ticket_r),
            '--generation', '1', '--process', str(args.process), '--packet-fd', str(peer_packet_worker.fileno()),
            '--generation-rings']
        if os.environ.get('KER_SESSION_TEST_FRAME_DRAIN') == '1':
            peer_arguments.append('--test-generation-frame-drain')
        if os.environ.get('KER_SESSION_TEST_FRAME_DRAIN_FULL') == '1':
            peer_environment['KER_SESSION_TEST_FRAME_DRAIN_FULL']='1'
        if os.environ.get('KER_SESSION_TEST_FRAME_DEATH_EMPTY') == '1':
            peer_environment['KER_SESSION_TEST_FRAME_DEATH_EMPTY']='1'
        if os.environ.get('KER_SESSION_TEST_FRAME_DEATH_SNAPSHOT') == '1':
            peer_environment['KER_SESSION_TEST_FRAME_DEATH_SNAPSHOT']='1'
        if os.environ.get('KER_SESSION_TEST_FRAME_DEATH_PRODUCER_ACTIVE_CONSUMER') == '1':
            peer_environment['KER_SESSION_TEST_FRAME_DEATH_PRODUCER_ACTIVE_CONSUMER']='1'
            peer_environment['KER_SESSION_TEST_FRAME_STOP_ACTIVE_DEQUEUE']='1'
        peer_arguments.extend(['--wire-fd', str(peer_wire_fd), '--mtu-fd', str(peer_mtu_worker.fileno()), '--',
            *api.role_arguments(args.eal, 'secondary', paired_pmd=True)])
        peer_worker = subprocess.Popen(peer_arguments,
            pass_fds=(control_r, ticket_r, peer_packet_worker.fileno(), peer_wire_fd, peer_mtu_worker.fileno()),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, env=peer_environment, bufsize=0)
        peer_worker_pidfd=os.pidfd_open(peer_worker.pid)
        close(control_r); close(ticket_r)
        peer_packet_worker.close(); peer_packet_worker = None
        peer_mtu_worker.close(); peer_mtu_worker = None
        data = api.encode(ticket)
        if os.write(ticket_w, data) != len(data):
            raise RuntimeError('short handoff peer ticket write')
        close(ticket_w)
        attached = ready('KER_SESSION_ATTACHED', process=peer_worker)
        outcome, standby = ready('KER_SESSION_PMD_GRANTED', 'KER_SESSION_PMD_STANDBY', process=peer_worker)
        if (outcome != 'KER_SESSION_PMD_STANDBY' or attached['slot'] != ticket['slot'] or
                attached['epoch'] != ticket['epoch'] or attached['generation'] != 1 or
                attached['process'] != args.process or standby['queue_owner_key'] != 0 or
                standby['exception_endpoint_owner_key'] != 0 or standby['exception_endpoint_fd']):
            raise RuntimeError('same-master opposite-generation peer did not remain control-only')
        metrics['exception_endpoint_name'] = f"kex{ticket['session'] & 0xffffffff:08x}"
        if os.write(peer_control_w, b'P') != 1:
            raise RuntimeError('short early standby admission request')
        denied_outcome, denied = ready('KER_SESSION_PMD_GRANTED', 'KER_SESSION_PMD_STANDBY', process=peer_worker)
        if (denied_outcome != 'KER_SESSION_PMD_STANDBY' or denied['queue_owner_key'] != 0 or
                denied['exception_endpoint_owner_key'] != 0 or denied['exception_endpoint_fd']):
            raise RuntimeError('successor acquired packet or exception authority before old-owner quiescence')
        connection = api.Connection(args.socket)
        try:
            owner = connection.request(api.PMD_STATUS)
        finally:
            connection.close()
        if owner['token'] != metrics['grant']['queue_owner_key'] or owner['generation'] != 0 or owner['epoch'] != ticket['epoch']:
            raise RuntimeError('early standby request displaced the live generation-zero owner')
        metrics['handoff_peer_early_denial'] = denied
        metrics['handoff_peer_attached'] = attached
        metrics['handoff_peer_standby'] = standby
        publish()

    def perform_test_handoff():
        nonlocal control_w, handoff_udp_ready, frame_death_complete, frame_death_worker_expected_code
        if peer_worker is None or app is None or app.poll() is not None or worker.poll() is not None:
            raise RuntimeError('live handoff fixture lost its original app/owner before transition')
        old_tun_interfaces_before = tap_interfaces_for_process(worker.pid)
        if metrics.get('exception_endpoint_name') not in old_tun_interfaces_before:
            raise RuntimeError('original owner did not hold the resident-selected TAP endpoint before handoff')
        if handoff_mode == 'handoff-control-hup':
            try:
                if os.write(control_w, b'H') != 1:
                    raise RuntimeError('could not request owner quiescence')
                boundary = wait_marker(worker, 'KER_SESSION_HANDOFF_BOUNDARY')
                wait_pidfd_process_stopped(worker_pidfd, worker.pid)
                print('KER_SESSION_HANDOFF_WORKER_STOPPED {"exact_pidfd":true}', file=sys.stderr, flush=True)
                snapshot_connection = api.Connection(args.socket)
                try:
                    stopped_snapshot = dict(status=snapshot_connection.request(api.STATUS),
                        pmd_status=snapshot_connection.request(api.PMD_STATUS))
                finally:
                    snapshot_connection.close()
                close(control_w)
                control_w = -1
                snapshot_connection = api.Connection(args.socket)
                try:
                    closed_snapshot = dict(status=snapshot_connection.request(api.STATUS),
                        pmd_status=snapshot_connection.request(api.PMD_STATUS))
                finally:
                    snapshot_connection.close()
                if stopped_snapshot != closed_snapshot:
                    raise RuntimeError('control EOF changed owner/census while the worker was stopped')
                print('KER_SESSION_HANDOFF_CONTROL_CLOSED {"owner_unchanged":true}',
                    file=sys.stderr, flush=True)
                metrics['handoff_control_hup'] = dict(boundary=boundary,
                    stopped_snapshot=stopped_snapshot, closed_snapshot=closed_snapshot)
                publish()
            finally:
                if control_w >= 0:
                    close(control_w)
                    control_w = -1
                if worker_pidfd >= 0 and pidfd_process_stopped(worker_pidfd, worker.pid) and \
                        resume_pidfd_if_live(worker_pidfd):
                    print('KER_SESSION_HANDOFF_WORKER_RESUMED {"exact_pidfd":true}',
                        file=sys.stderr, flush=True)
            wait_marker(worker, 'KER_SESSION_TEST_HANDOFF_CONTROL_HUP')
            metrics.update(stage='handoff-control-hup', handoff_protocol=dict(
                boundary=boundary, prepare_authorized=False,
                stopped_snapshot=metrics['handoff_control_hup']['stopped_snapshot'],
                closed_snapshot=metrics['handoff_control_hup']['closed_snapshot']))
            publish()
            raise RuntimeError('control EOF correctly prevented PREPARE after the handoff boundary')
        commands = b'HH' if handoff_mode in ('prepare-enoent', 'prepare-ebusy', 'prepare-eperm') else b'H'
        if os.write(control_w, commands) != len(commands):
            raise RuntimeError('could not request owner quiescence')
        boundary = wait_marker(worker, 'KER_SESSION_HANDOFF_BOUNDARY')
        negative_prepare = wait_marker(worker, 'KER_SESSION_TEST_HANDOFF_PREPARE_REJECTED')
        prepare_rejected_mode = handoff_mode in ('prepare-enoent', 'prepare-ebusy', 'prepare-eperm') or \
            (handoff_mode is not None and (handoff_mode.startswith('bad-prepare-error') or
                handoff_mode == 'bad-prepare-success'))
        if prepare_rejected_mode:
            # The explicit invalid-lease replay hook above has already proved
            # idempotency and reports same_replay on this marker. The
            # production PREPARE error path returns before its success-only
            # PREPARE_REPLAY marker, so waiting for that marker would stall.
            if negative_prepare.get('same_replay') is not True:
                raise RuntimeError('invalid-lease PREPARE rejection replay was not verified')
            replay_prepare = None
        else:
            replay_prepare = wait_marker(worker, 'KER_SESSION_TEST_HANDOFF_PREPARE_REPLAY')
        prepared = None
        if handoff_mode in ('prepare-enoent', 'prepare-ebusy', 'prepare-eperm'):
            expected_status = {'prepare-enoent': -errno.ENOENT, 'prepare-ebusy': -errno.EBUSY,
                'prepare-eperm': -errno.EPERM}[handoff_mode]
            resumed = wait_marker(worker, 'KER_SESSION_TEST_HANDOFF_PREPARE_RESUMED')
            if resumed.get('status') != expected_status:
                raise RuntimeError('resident returned the wrong exact PREPARE rejection')
            next_boundary = wait_marker(worker, 'KER_SESSION_HANDOFF_BOUNDARY')
            next_rejected = wait_marker(worker, 'KER_SESSION_TEST_HANDOFF_PREPARE_REJECTED')
            if next_rejected.get('same_replay') is not True:
                raise RuntimeError('second invalid-lease PREPARE replay was not verified')
            next_resumed = wait_marker(worker, 'KER_SESSION_TEST_HANDOFF_PREPARE_RESUMED')
            if next_resumed.get('status') != expected_status:
                raise RuntimeError('worker did not service the pipelined second handoff request')
            metrics.update(stage='handoff-rejected', handoff_protocol=dict(
                prepare_status=expected_status, pending_heartbeat=True, queued_h_serviced=True,
                boundaries=[boundary,next_boundary], negative_prepare=[negative_prepare,next_rejected],
                replay_verified=[negative_prepare.get('same_replay'), next_rejected.get('same_replay')]))
            publish()
            return
        malformed_prepare = handoff_mode is not None and (
            handoff_mode.startswith('bad-prepare-error') or handoff_mode == 'bad-prepare-success')
        if not malformed_prepare and handoff_mode is not None:
            prepared = wait_marker(worker, 'KER_SESSION_TEST_HANDOFF_PREPARED')
        if malformed_prepare:
            try: worker.wait(timeout=10)
            except subprocess.TimeoutExpired as error:
                raise RuntimeError('malformed PREPARE reply did not fail closed') from error
            if worker.returncode != 125:
                raise RuntimeError('malformed PREPARE reply did not terminate the old worker with status 125')
            metrics.update(stage='handoff-malformed-reply', handoff_failure=dict(
                mode=handoff_mode, worker_code=worker.returncode, boundary=boundary))
            publish()
            raise RuntimeError('worker rejected a malformed PREPARE reply as required')
        if handoff_mode == 'peer-death':
            peer_pidfd = os.pidfd_open(peer_worker.pid)
            try:
                peer_worker.kill()
                peer_output, peer_errors = peer_worker.communicate(timeout=10)
                if peer_worker.returncode != -signal.SIGKILL:
                    raise RuntimeError('reserved peer did not die from the exact fixture SIGKILL: ' +
                        (peer_errors or b'').decode(errors='replace'))
                if not select.select([peer_pidfd], [], [], 0)[0]:
                    raise RuntimeError('reserved peer pidfd did not become readable after SIGKILL')
                metrics['handoff_negative_peer'] = dict(pid=peer_worker.pid, returncode=peer_worker.returncode,
                    pidfd_dead=True, output=peer_output.decode(errors='replace'))
                publish()
            finally:
                os.close(peer_pidfd)
            try:
                if os.write(control_w, b'D') != 1:
                    raise RuntimeError('short peer-death owner release command')
            except BrokenPipeError:
                metrics['handoff_negative_peer']['resident_preempted_release'] = True
                publish()
            try:
                fds_closed = wait_marker(worker, 'KER_SESSION_TEST_HANDOFF_FDS_CLOSED', timeout=2)
            except RuntimeError:
                # The resident may reap the exact dead reserved peer and fail
                # closed before the old worker consumes D or closes its FDs.
                fds_closed = None
            quiesced_sent = None
            if fds_closed is not None:
                try:
                    quiesced_sent = wait_marker(worker, 'KER_SESSION_TEST_HANDOFF_QUIESCED_SENT', timeout=2)
                except RuntimeError:
                    pass
            try:
                worker.wait(timeout=8)
            except subprocess.TimeoutExpired as error:
                raise RuntimeError('resident did not fail closed after reserved-peer death') from error
            if worker.returncode != 125:
                raise RuntimeError('reserved-peer death did not terminate the old owner with status 125')
            metrics.update(stage='handoff-fatal-peer-death', handoff_failure=dict(mode=handoff_mode,
                worker_code=worker.returncode, prepared=prepared, fds_closed=fds_closed,
                quiesced_sent=quiesced_sent,
                fatal_stage=('resident-preempted-before-fd-close' if fds_closed is None else
                    ('resident-preempted-after-fd-close' if quiesced_sent is None else 'quiesced-peer-revalidation')),
                peer=metrics.get('handoff_negative_peer')))
            publish()
            raise RuntimeError('resident failed closed after reserved-peer death')
        if handoff_mode == 'timeout':
            try:
                worker.wait(timeout=8)
            except subprocess.TimeoutExpired as error:
                raise RuntimeError('resident timeout did not terminate the prepared owner') from error
            metrics.update(stage='handoff-fatal-timeout', handoff_failure=dict(
                mode=handoff_mode, worker_code=worker.returncode, prepared=prepared))
            publish()
            raise RuntimeError('resident timeout terminated the owner before QUIESCED')
        fds_closed = quiesced_sent = None
        if handoff_mode is not None:
            fds_closed = wait_marker(worker, 'KER_SESSION_TEST_HANDOFF_FDS_CLOSED')
            quiesced_sent = wait_marker(worker, 'KER_SESSION_TEST_HANDOFF_QUIESCED_SENT')
        if handoff_mode in ('bad-capability', 'bad-tx-lease', 'bad-rx-lease'):
            try:
                worker.wait(timeout=8)
            except subprocess.TimeoutExpired as error:
                raise RuntimeError('resident did not fail closed after invalid QUIESCED') from error
            if worker.returncode != 125:
                raise RuntimeError('invalid QUIESCED did not terminate the old owner with status 125')
            metrics.update(stage='handoff-fatal-quiesced', handoff_failure=dict(mode=handoff_mode,
                worker_code=worker.returncode, prepared=prepared, fds_closed=fds_closed,
                quiesced_sent=quiesced_sent, peer=metrics.get('handoff_negative_peer')))
            publish()
            raise RuntimeError('resident failed closed after the expected invalid QUIESCED')
        if handoff_mode not in (None, 'positive', 'frame-positive', 'frame-full',
                'frame-death-prepared','frame-death-queued','frame-death-producer-active-consumer','frame-death-consumer-prepared',
                'frame-death-consumer-writing','frame-death-both-prepared','frame-lost-prepare-reply'):
            raise RuntimeError('test handoff mode is not a fatal profile')
        parked = wait_marker(worker, 'KER_SESSION_PMD_PARKED')
        if (boundary.get('idle') is not True or boundary.get('owner_key') != metrics['grant']['queue_owner_key'] or
                parked.get('pid') != worker.pid or parked.get('old_owner_key') != metrics['grant']['queue_owner_key'] or
                parked.get('successor_slot') != metrics['handoff_peer_attached']['slot'] or
                parked.get('successor_generation') != 1 or app.poll() is not None or worker.poll() is not None):
            raise RuntimeError('same-process handoff did not park the granted generation-zero worker')
        owner_cleared = ready('KER_SESSION_PMD_PARKED', process=worker)
        validate_parked_owner_cleared(owner_cleared, worker.pid)
        old_exception_fd = metrics['geometry'].get('exception_endpoint_fd_number')
        old_tun_interfaces = tap_interfaces_for_process(worker.pid)
        if (not isinstance(old_exception_fd, int) or Path(f'/proc/{worker.pid}/fd/{old_exception_fd}').exists() or
                metrics['geometry'].get('exception_endpoint_ifindex') <= 0 or
                metrics['exception_endpoint_name'] in old_tun_interfaces):
            raise RuntimeError('parked owner still holds the session exception endpoint or another alias to its TAP')
        if os.write(peer_control_w, b'P') != 1:
            raise RuntimeError('could not admit the exact reserved successor')
        successor = ready('KER_SESSION_PMD_GRANTED', process=peer_worker)
        geometry = ready('KER_SESSION_PACKET_READY', process=peer_worker)
        successor_tun_interfaces = tap_interfaces_for_process(peer_worker.pid)
        connection = api.Connection(args.socket)
        try:
            observed = connection.request(api.PMD_STATUS)
        finally:
            connection.close()
        expected_key = 1 + (successor['slot'] * 2 + successor['generation']) * 4 + successor['process']
        if (successor['generation'] != 1 or
                successor['slot'] != metrics['attached']['slot'] or successor['epoch'] != metrics['attached']['epoch'] or
                successor['pid'] != metrics['handoff_peer_attached']['pid'] or successor['pid'] == worker.pid or
                successor['queue_owner_key'] != expected_key or successor['exception_endpoint_owner_key'] != expected_key or
                not successor['exception_endpoint_fd'] or geometry['exception_endpoint_owner_key'] != expected_key or
                metrics['exception_endpoint_name'] not in successor_tun_interfaces or
                observed['token'] != expected_key or observed['generation'] != 1 or
                observed['slot'] != metrics['attached']['slot'] or observed['epoch'] != metrics['attached']['epoch'] or
                app.poll() is not None or worker.poll() is not None or peer_worker.poll() is not None):
            raise RuntimeError('resident did not grant the same-session successor while old app/worker remained live')
        metrics['handoff'] = dict(stage='committed', app_pid=app.pid, old_worker_pid=worker.pid,
            peer_worker_pid=peer_worker.pid, old_owner_key=metrics['grant']['queue_owner_key'],
            new_owner_key=expected_key, old_exception_fd=old_exception_fd,
            old_exception_fd_closed=True, old_tun_interfaces_before=old_tun_interfaces_before,
            old_tun_interfaces_after=old_tun_interfaces, successor_tun_interfaces=successor_tun_interfaces,
            boundary=boundary, parked=parked, owner_cleared=owner_cleared,
            successor=successor, geometry=geometry, resident=observed)
        metrics['handoff_protocol'] = dict(negative_prepare=negative_prepare, replay_prepare=replay_prepare)
        metrics['stage'] = 'handoff-complete'
        handoff_udp_ready = True
        publish()
        if handoff_mode in ('frame-full','frame-death-queued'):
            if os.write(control_w,b'F')!=1: raise RuntimeError('could not request actual generation TX ring fill')
            filled=wait_marker(worker,'KER_SESSION_FRAME_FULL_FILLED')
            if (not isinstance(filled.get('count'),int) or filled['count']<=0 or
                filled.get('capacity')!=filled.get('count') or
                filled.get('pool_before')!=0 or filled.get('pool_after')!=filled['count'] or
                len(filled.get('counters_before',[]))!=5 or
                filled.get('counters_before')!=filled.get('counters_after') or
                filled.get('count')!=64 or len(filled.get('objects',[]))!=filled.get('count') or
                [item.get('ordinal') for item in filled.get('objects',[])]!=list(range(64)) or
                len({item.get('index') for item in filled.get('objects',[])})!=64 or
                len({item.get('pointer') for item in filled.get('objects',[])})!=64):
                raise RuntimeError('actual generation TX ring fill did not report a positive capacity')
            metrics['frame_full_capacity']=filled['count']
            metrics['frame_full_fill']=filled;publish()
            if handoff_mode=='frame-death-queued':
                wait_pidfd_process_stopped(worker_pidfd,worker.pid)
                if select.select([worker_pidfd],[],[],0)[0]:
                    raise RuntimeError('queued producer pidfd became readable before SIGKILL')
                signal.pidfd_send_signal(worker_pidfd,signal.SIGKILL)
                dead_output,_=worker.communicate(timeout=10)
                if worker.returncode!=-signal.SIGKILL or not select.select([worker_pidfd],[],[],0)[0]:
                    raise RuntimeError('queued producer did not die on its captured pidfd')
                deadline=time.monotonic()+10
                while time.monotonic()<deadline:
                    snapshot_connection=api.Connection(args.socket)
                    try: census=snapshot_connection.request(api.STATUS)
                    finally: snapshot_connection.close()
                    if census['process']==1 and census['slot']==1:break
                    time.sleep(0.01)
                else:raise RuntimeError('resident did not reap the exact queued producer')
                snapshot_connection=api.Connection(args.socket)
                try: reap_owner=snapshot_connection.request(api.PMD_STATUS)
                finally: snapshot_connection.close()
                if (reap_owner['token']!=expected_key or reap_owner['generation']!=1 or
                    reap_owner['slot']!=metrics['handoff_peer_attached']['slot']):
                    raise RuntimeError('producer reaping changed the exact live consumer owner')
                if peer_control_w<0 or os.write(peer_control_w,b'S')!=1:
                    raise RuntimeError('could not request queued-object snapshot before drain')
                retained=ready('KER_SESSION_FRAME_DEATH_SNAPSHOT',process=peer_worker)
                if (retained.get('tx')!=filled['count'] or retained.get('packet_pool_in_use')!=filled['count'] or
                    retained.get('counters')!=filled.get('counters_after')):
                    raise RuntimeError('reaping changed queued TX objects/counters before live consumer drain')
                if peer_control_w<0 or os.write(peer_control_w,b'G')!=1:
                    raise RuntimeError('could not request live-consumer drain after producer death')
                drained_full=ready('KER_SESSION_FRAME_FULL_DRAINED',process=peer_worker)
                if (drained_full.get('count')!=filled['count'] or drained_full.get('tx_after')!=0 or
                    drained_full.get('pool_before')!=filled['count'] or drained_full.get('pool_after')!=0 or
                    drained_full.get('objects')!=filled.get('objects') or
                    drained_full.get('counters_before')!=filled.get('counters_after') or
                    drained_full.get('counters_after')!=drained_full.get('counters_before')):
                    raise RuntimeError('live consumer did not drain exact retained objects after producer death')
                metrics['handoff_frame_death']=dict(stage='queued',producer_pid=worker.pid,
                    producer_status=worker.returncode,pidfd_dead=True,census=census,
                    stopped=True,owner_after_reap=reap_owner,retained=retained,
                    output=dead_output.decode(errors='replace'),fill=filled,drain=drained_full)
                frame_death_complete=True
                frame_death_worker_expected_code=-signal.SIGKILL
                metrics['stage']='handoff-complete';publish()
                return

    def finish_signal_before_app(packet_expected):
        nonlocal completed
        close(control_w)
        if peer_control_w >= 0: close(peer_control_w)
        try: output, _ = worker.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            worker.kill(); worker.communicate()
            raise RuntimeError('secondary packet worker did not exit after launcher signal')
        decoded = output.decode()
        print(decoded.rstrip(), file=sys.stderr, flush=True)
        packet_lines = [line.removeprefix('KER_SESSION_PACKET_DONE ')
            for line in decoded.splitlines() if line.startswith('KER_SESSION_PACKET_DONE ')]
        if len(packet_lines) > 1:
            raise RuntimeError('secondary packet worker reported duplicate completion')
        packet_stats = json.loads(packet_lines[0]) if packet_lines else None
        peer_packet_stats = None
        if peer_worker is not None:
            try: peer_output, peer_errors = peer_worker.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                peer_worker.kill(); peer_output, peer_errors = peer_worker.communicate()
                raise RuntimeError('handoff standby did not exit after launcher signal: ' + (peer_errors or b'').decode(errors='replace'))
            print(peer_output.decode().rstrip(), file=sys.stderr, flush=True)
            peer_lines = [line.removeprefix('KER_SESSION_PACKET_DONE ')
                for line in peer_output.decode().splitlines() if line.startswith('KER_SESSION_PACKET_DONE ')]
            if len(peer_lines) > 1: raise RuntimeError('handoff peer reported duplicate completion')
            peer_packet_stats = json.loads(peer_lines[0]) if peer_lines else None
            if peer_worker.returncode != 0 or peer_packet_stats is not None:
                raise RuntimeError('control-only handoff peer did not remain data-plane inactive')
        metrics.update(packet=packet_stats, worker_code=worker.returncode, app_code=None, signal=received_signal,
            handoff_peer_packet=peer_packet_stats,
            handoff_peer_code=peer_worker.returncode if peer_worker is not None else None)
        release(ticket)
        validate_interrupted_cleanup(worker.returncode, packet_stats, packet_expected=packet_expected)
        metrics.update(native_cleanup=None, stage='interrupted'); publish(); completed = True
        return 128 + received_signal

    signal.signal(signal.SIGTERM, record_signal)
    signal.signal(signal.SIGINT, record_signal)
    try:
        ticket = connection.request(api.MASTER)
        ticket_r, ticket_w = pipe(os.O_CLOEXEC)
        control_r, control_w = pipe(os.O_CLOEXEC)
        startup_r, startup_w = pipe(os.O_CLOEXEC | os.O_NONBLOCK)
        if handoff_fd is not None:
            if args.generation != 0 or args.standby:
                raise RuntimeError('test live handoff requires a generation-zero packet owner')
            peer_wire_fd = os.dup(args.wire_fd)
            owned.add(peer_wire_fd)
        worker = subprocess.Popen([str(worker_path), '--role', 'secondary', '--paired-pmd',
            *(['--standby'] if args.standby else []),
            '--socket', str(args.socket), '--control-fd', str(control_r), '--ticket-fd', str(ticket_r),
            '--generation', str(args.generation), '--process', str(args.process),
            *(['--generation-rings'] if getattr(args, 'generation_rings', False) else []),
            *(['--test-generation-frame-source'] if os.environ.get('KER_SESSION_TEST_FRAME_FULL')=='1' or
                os.environ.get('KER_SESSION_TEST_FRAME_DEATH_PREPARED')=='1' or
                os.environ.get('KER_SESSION_TEST_FRAME_DEATH_QUEUED')=='1' or
                os.environ.get('KER_SESSION_TEST_FRAME_DEATH_CONSUMER_PREPARED')=='1' or
                os.environ.get('KER_SESSION_TEST_FRAME_DEATH_CONSUMER_WRITING')=='1' else []),
            '--packet-fd', str(packet_worker.fileno()), '--wire-fd', str(args.wire_fd),
            '--mtu-fd', str(mtu_worker.fileno()), '--',
            *api.role_arguments(args.eal, 'secondary', paired_pmd=True)],
            pass_fds=(control_r, ticket_r, packet_worker.fileno(), mtu_worker.fileno(), args.wire_fd),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, bufsize=0)
        if handoff_fd is not None:
            # Capture the exact worker identity while it is known live; HUP
            # cleanup must never signal a recycled numeric PID.
            worker_pidfd = os.pidfd_open(worker.pid)
        close(control_r); close(ticket_r); close(args.wire_fd)
        packet_worker.close(); mtu_worker.close()
        data = api.encode(ticket)
        if os.write(ticket_w, data) != len(data):
            raise RuntimeError('short secondary ticket write')
        close(ticket_w)
        metrics['attached'] = ready('KER_SESSION_ATTACHED')
        outcome, grant = ready('KER_SESSION_PMD_GRANTED', 'KER_SESSION_PMD_STANDBY')
        while outcome == 'KER_SESSION_PMD_STANDBY':
            if not args.standby:
                raise RuntimeError('unexpected standby admission')
            metrics.update(stage='standby', standby=grant,
                standby_samples=metrics.get('standby_samples', 0) + 1)
            publish()
            if received_signal is not None:
                return finish_signal_before_app(packet_expected=False)
            time.sleep(0.1)
            if received_signal is not None:
                return finish_signal_before_app(packet_expected=False)
            if worker.poll() is not None:
                raise RuntimeError('secondary packet standby exited before admission')
            if received_signal is not None:
                return finish_signal_before_app(packet_expected=False)
            if os.write(control_w, b'P') != 1:
                raise RuntimeError('short standby admission request')
            outcome, grant = ready('KER_SESSION_PMD_GRANTED', 'KER_SESSION_PMD_STANDBY')
        metrics['grant'] = grant
        if grant['pid'] != metrics['attached']['pid'] or grant['epoch'] != metrics['attached']['epoch']:
            raise RuntimeError('secondary packet identity changed during admission')
        info = metrics['geometry'] = ready('KER_SESSION_PACKET_READY')
        if info['mtu'] != 1500 or info['tx_features'] != 0 or info['rx_ring'] == info['tx_ring']:
            raise RuntimeError('unsupported secondary packet geometry')
        start_handoff_peer(ticket)
        metrics['stage'] = 'worker-ready'; publish()
        if received_signal is not None:
            return finish_signal_before_app(packet_expected=True)
        environment = {k: v for k, v in os.environ.items() if not k.startswith(
            ('LKL_', 'KER_PACKET_', 'KER_NATIVE_', 'KER_RUN_', 'KER_STARTUP_', 'KER_PRELOAD_', 'KER_SESSION_TEST_'))}
        environment.update(KER_PRELOAD_LIBRARY=(environment.pop('LD_PRELOAD') + ':' if environment.get('LD_PRELOAD') else '') + str(library),
            KER_PACKET_FD=str(packet_app.fileno()), KER_PACKET_CONTROL_FD=str(mtu_app.fileno()),
            KER_STARTUP_FD=str(startup_w), KER_PACKET_MTU='1500', KER_PACKET_MAX_MTU='1500',
            KER_NATIVE_TX_FEATURES='0', KER_SHUTDOWN_TIMEOUT_MS='5000',
            LKL_HIJACK_NET_IP=str(address.ip), LKL_HIJACK_NET_NETMASK_LEN=str(address.network.prefixlen),
            LKL_HIJACK_NET_MAC='02:4b:45:52:00:02', LKL_HIJACK_NET_IFTYPE='ker-channel', LKL_HIJACK_OFFLOAD='0')
        if address6:
            environment['KER_NATIVE_ADDRESS6'] = str(address6)
        if worker.poll() is not None:
            raise RuntimeError('secondary packet worker exited before application launch')
        app = subprocess.Popen([str(guard), *args.command], env=environment,
            pass_fds=(packet_app.fileno(), mtu_app.fileno(), startup_w))
        app_pidfd = os.pidfd_open(app.pid)
        metrics.update(stage='application-started', app_started=True, app_pid=app.pid); publish()
        packet_app.close(); mtu_app.close(); close(startup_w)
        startup = b''
        handoff_udp_sequence = 0
        handoff_seen = False
        deadline = time.monotonic() + 20
        stopping_at = None

        def drain_startup():
            nonlocal startup
            while True:
                try: data = os.read(startup_r, 4096)
                except BlockingIOError: break
                if not data: break
                startup += data
                if len(startup) > 65536:
                    raise RuntimeError('native startup/control output exceeded its bound')

        def trigger_handoff_udp():
            nonlocal handoff_udp_sequence, frame_death_complete, frame_death_worker_expected_code, peer_control_w
            if handoff_mode not in ('frame-positive','frame-full','frame-death-prepared',
                    'frame-death-producer-active-consumer','frame-death-consumer-prepared','frame-death-consumer-writing',
                    'frame-death-both-prepared','frame-lost-prepare-reply') or app is None or app_pidfd < 0 or app.poll() is not None:
                raise RuntimeError('UDP handoff trigger is available only for the live positive app')
            sequence = handoff_udp_sequence + 1
            if (sequence == 1 and handoff_udp_ready) or (sequence == 2 and not handoff_udp_ready):
                raise RuntimeError('UDP trigger is out of the prewarm/PARKED order')
            payload = f'KER-A09-HANDOFF-UDP seq={sequence}\n'.encode()
            acknowledgement = f'KER_HANDOFF_UDP_SENT seq={sequence} bytes={len(payload)}\n'.encode()
            if acknowledgement in startup:
                raise RuntimeError('application UDP trigger acknowledgement was already observed')
            if not select.select([app_pidfd], [], [], 0)[0]:
                signal.pidfd_send_signal(app_pidfd, signal.SIGUSR1)
            else:
                raise RuntimeError('exact original app pidfd is already readable')
            ack_deadline = time.monotonic() + 10
            while acknowledgement not in startup:
                drain_startup()
                if app.poll() is not None:
                    raise RuntimeError('original LKL UDP app exited before acknowledging its trigger')
                if time.monotonic() >= ack_deadline:
                    raise RuntimeError('original LKL UDP app trigger acknowledgement timed out')
                time.sleep(0.005)
            if startup.count(acknowledgement) != 1:
                raise RuntimeError('original LKL UDP app emitted a duplicate trigger acknowledgement')
            handoff_udp_sequence = sequence
            print('KER_SESSION_TEST_UDP_TRIGGER_ACK ' + json.dumps(dict(sequence=sequence,
                bytes=len(payload))), flush=True)
            if sequence != 2:
                return
            include_negatives = os.environ.get('KER_SESSION_TEST_FRAME_NEGATIVES') is not None
            negative_prepares, cancel_replay = read_frame_negative_prefix(
                worker, ready, include_negatives)
            if handoff_mode=='frame-lost-prepare-reply':
                eof=ready('KER_SESSION_TEST_FRAME_REPLY_EOF')
                if eof.get('command')!=getattr(api,'FRAME_PREPARE',19) or type(eof.get('sequence')) is not int or \
                    eof.get('sequence')<1 or eof.get('no_retry') is not True:
                    raise RuntimeError('lost PREPARE response did not fail closed on the exact request without retry')
                wait_pidfd_process_stopped(worker_pidfd,worker.pid)
                if select.select([worker_pidfd],[],[],0)[0]:
                    raise RuntimeError('producer exited before ambiguous PREPARE ownership snapshot')
                snapshot=api.Connection(args.socket)
                try:retained_census_before=snapshot.request(api.STATUS);retained_owner_before=snapshot.request(api.PMD_STATUS)
                finally:snapshot.close()
                if (retained_census_before.get('process',0)<1 or
                    retained_owner_before.get('token')!=metrics['handoff']['new_owner_key'] or
                    retained_owner_before.get('generation')!=1):
                    raise RuntimeError('lost PREPARE reply changed actor census or authenticated peer PMD owner before reap')
                if peer_control_w<0 or os.write(peer_control_w,b'S')!=1:
                    raise RuntimeError('could not snapshot the prepared lease while producer remained alive')
                retained=ready('KER_SESSION_FRAME_DEATH_SNAPSHOT',process=peer_worker)
                if retained.get('tx')!=0 or retained.get('packet_pool_in_use')!=1:
                    raise RuntimeError('lost PREPARE reply did not retain its exact pending allocation while producer lived')
                snapshot=api.Connection(args.socket)
                try:retained_census_after=snapshot.request(api.STATUS);retained_owner_after=snapshot.request(api.PMD_STATUS)
                finally:snapshot.close()
                if retained_census_after!=retained_census_before or retained_owner_after!=retained_owner_before:
                    raise RuntimeError('lost PREPARE reply changed actor registration or peer PMD owner before exact producer death')
                signal.pidfd_send_signal(worker_pidfd,signal.SIGKILL)
                producer_output,producer_errors=worker.communicate(timeout=10)
                if worker.returncode!=-signal.SIGKILL or not select.select([worker_pidfd],[],[],0)[0]:
                    raise RuntimeError('ambiguous PREPARE producer did not die on its captured pidfd')
                deadline=time.monotonic()+10
                while time.monotonic()<deadline:
                    snap=api.Connection(args.socket)
                    try:census=snap.request(api.STATUS);owner=snap.request(api.PMD_STATUS)
                    finally:snap.close()
                    if census.get('process')==1 and owner.get('token')==metrics['handoff']['new_owner_key']:
                        break
                    time.sleep(0.01)
                else:raise RuntimeError('exact lost-reply producer reap changed the surviving peer owner')
                metrics['handoff_frame_loss']=dict(stage='prepare-reply-lost',eof=eof,retained=retained,
                    retained_census=retained_census_before,retained_census_after=retained_census_after,
                    retained_owner=retained_owner_before,retained_owner_after=retained_owner_after,
                    producer_pid=worker.pid,producer_status=worker.returncode,producer_pidfd_dead=True,
                    producer_output=producer_output.decode(errors='replace'),
                    producer_stderr=producer_errors.decode(errors='replace'),final_census=census,final_owner=owner)
                frame_death_complete=True
                frame_death_worker_expected_code=-signal.SIGKILL
                metrics['stage']='handoff-complete';publish();return
            if handoff_mode=='frame-death-consumer-writing':
                writing=ready('KER_SESSION_FRAME_WRITING_HELD')
                wait_pidfd_process_stopped(worker_pidfd,worker.pid)
                if select.select([worker_pidfd],[],[],0)[0]:
                    raise RuntimeError('WRITING producer pidfd became readable before consumer death')
                if peer_worker_pidfd<0 or select.select([peer_worker_pidfd],[],[],0)[0]:
                    raise RuntimeError('opposite-generation consumer pidfd was not live before SIGKILL')
                signal.pidfd_send_signal(peer_worker_pidfd,signal.SIGKILL)
                peer_output,peer_errors=peer_worker.communicate(timeout=10)
                if peer_worker.returncode!=-signal.SIGKILL or not select.select([peer_worker_pidfd],[],[],0)[0]:
                    raise RuntimeError('WRITING consumer did not die on its captured pidfd')
                if peer_control_w>=0:close(peer_control_w);peer_control_w=-1
                metrics['handoff_frame_death']={
                    'stage':'consumer-writing-waiting','producer_pid':worker.pid,
                    'consumer_pid':peer_worker.pid,'consumer_status':peer_worker.returncode,
                    'consumer_pidfd_dead':True,'writing':writing,
                    'consumer_output':peer_output.decode(errors='replace'),
                    'consumer_stderr':peer_errors.decode(errors='replace')}
                publish()
                continue_deadline=time.monotonic()+10
                while time.monotonic()<continue_deadline:
                    readable,_,_=select.select([handoff_fd],[],[],0.05)
                    if not readable:
                        if app.poll() is not None:raise RuntimeError('application exited while WRITING recovery was paused')
                        continue
                    command=os.read(handoff_fd,1)
                    if command!=b'R':raise RuntimeError('invalid WRITING recovery continuation command')
                    break
                else:raise RuntimeError('launcher did not receive bounded WRITING recovery continuation')
                signal.pidfd_send_signal(worker_pidfd,signal.SIGCONT)
                write_complete=ready('KER_SESSION_FRAME_CONSUMER_DEATH_WRITE_COMPLETE')
                cancelled=ready('KER_SESSION_FRAME_CONSUMER_DEATH_CANCELLED')
                producer_output,_=worker.communicate(timeout=10)
                if worker.returncode!=1:raise RuntimeError('WRITING producer did not fail stale COMMIT closed')
                deadline=time.monotonic()+10
                while time.monotonic()<deadline:
                    snap=api.Connection(args.socket)
                    try:final_census=snap.request(api.STATUS);final_owner=snap.request(api.PMD_STATUS)
                    finally:snap.close()
                    if final_census['process']==0 and final_owner['token']==0:break
                    time.sleep(0.01)
                else:raise RuntimeError('WRITING actor recovery did not retire both dead registrations')
                metrics['handoff_frame_death'].update(stage='consumer-writing',
                    producer_status=worker.returncode,write_complete=write_complete,cancelled=cancelled,
                    producer_output=producer_output.decode(errors='replace'),final_census=final_census,
                    final_pmd_owner=final_owner)
                frame_death_complete=True
                frame_death_worker_expected_code=1
                metrics['stage']='handoff-complete';publish()
                return
            if handoff_mode in ('frame-death-prepared','frame-death-consumer-prepared','frame-death-both-prepared'):
                prepared=ready('KER_SESSION_FRAME_PREPARED_FOR_DEATH')
                wait_pidfd_process_stopped(worker_pidfd,worker.pid)
                if select.select([worker_pidfd],[],[],0)[0]:
                    raise RuntimeError('PREPARED producer pidfd became readable before SIGKILL')
                if handoff_mode in ('frame-death-consumer-prepared','frame-death-both-prepared'):
                    if peer_worker_pidfd<0 or select.select([peer_worker_pidfd],[],[],0)[0]:
                        raise RuntimeError('opposite-generation consumer pidfd was not live before SIGKILL')
                    if handoff_mode=='frame-death-both-prepared':
                        metrics['handoff_frame_death_barrier']=dict(stage='prepared-both-live',
                            producer_pid=worker.pid,consumer_pid=peer_worker.pid,
                            producer_prepared=True,producer_stopped=True)
                        publish()
                        deadline=time.monotonic()+15
                        while time.monotonic()<deadline:
                            producer_dead=bool(select.select([worker_pidfd],[],[],0)[0])
                            consumer_dead=bool(select.select([peer_worker_pidfd],[],[],0)[0])
                            if producer_dead and consumer_dead:break
                            select.select([worker_pidfd,peer_worker_pidfd],[],[],0.05)
                        else:raise RuntimeError('fixture did not kill both prepared actors through their captured pidfds')
                    else:
                        signal.pidfd_send_signal(peer_worker_pidfd,signal.SIGKILL)
                    peer_output,peer_errors=peer_worker.communicate(timeout=10)
                    if peer_worker.returncode!=-signal.SIGKILL or not select.select([peer_worker_pidfd],[],[],0)[0]:
                        raise RuntimeError('consumer did not die on its captured pidfd')
                    if peer_control_w>=0:close(peer_control_w);peer_control_w=-1
                    if handoff_mode=='frame-death-both-prepared':
                        producer_output,producer_errors=worker.communicate(timeout=10)
                        if worker.returncode!=-signal.SIGKILL or not select.select([worker_pidfd],[],[],0)[0]:
                            raise RuntimeError('prepared producer did not die on its captured pidfd')
                        deadline=time.monotonic()+10
                        while time.monotonic()<deadline:
                            snapshot_connection=api.Connection(args.socket)
                            try:final_census=snapshot_connection.request(api.STATUS);final_owner=snapshot_connection.request(api.PMD_STATUS)
                            finally:snapshot_connection.close()
                            if final_census['process']==0 and final_owner['token']==0:break
                            time.sleep(0.01)
                        else:raise RuntimeError('resident did not reap both dead prepared-frame actors')
                        metrics['handoff_frame_death']=dict(stage='both-prepared-actors-dead',
                            producer_pid=worker.pid,consumer_pid=peer_worker.pid,
                            producer_status=worker.returncode,consumer_status=peer_worker.returncode,
                            producer_pidfd_dead=True,consumer_pidfd_dead=True,prepared=prepared,
                            final_census=final_census,final_owner=final_owner,
                            producer_output=producer_output.decode(errors='replace'),
                            producer_stderr=producer_errors.decode(errors='replace'),
                            consumer_output=peer_output.decode(errors='replace'))
                        frame_death_complete=True
                        frame_death_worker_expected_code=-signal.SIGKILL
                        metrics['stage']='handoff-complete';publish();return
                    deadline=time.monotonic()+10
                    while time.monotonic()<deadline:
                        snapshot_connection=api.Connection(args.socket)
                        try: census=snapshot_connection.request(api.STATUS)
                        finally:snapshot_connection.close()
                        if census['process']==1 and census['slot']==1:break
                        time.sleep(0.01)
                    else:raise RuntimeError('resident did not reap exact dead consumer')
                    snapshot_connection=api.Connection(args.socket)
                    try: owner_after_reap=snapshot_connection.request(api.PMD_STATUS)
                    finally:snapshot_connection.close()
                    if owner_after_reap['token']!=0:
                        raise RuntimeError('dead consumer PMD lease was not reclaimed')
                    signal.pidfd_send_signal(worker_pidfd,signal.SIGCONT)
                    preserved=wait_marker(worker,'KER_SESSION_FRAME_CONSUMER_DEATH_PENDING_PRESERVED')
                    cancelled=wait_marker(worker,'KER_SESSION_FRAME_CONSUMER_DEATH_CANCELLED')
                    worker_output,_=worker.communicate(timeout=10)
                    if worker.returncode!=1:
                        raise RuntimeError('producer did not return after the exact stale-consumer cancellation')
                    deadline=time.monotonic()+10
                    while time.monotonic()<deadline:
                        snapshot_connection=api.Connection(args.socket)
                        try: final_census=snapshot_connection.request(api.STATUS)
                        finally:snapshot_connection.close()
                        if final_census['process']==0:break
                        time.sleep(0.01)
                    else:raise RuntimeError('resident did not reap the producer after stale-consumer cancellation')
                    metrics['handoff_frame_death']=dict(stage='consumer-prepared',producer_pid=worker.pid,
                        producer_status=worker.returncode,consumer_pid=peer_worker.pid,
                        consumer_status=peer_worker.returncode,consumer_pidfd_dead=True,
                        census=census,final_census=final_census,pmd_owner_after_reap=owner_after_reap,
                        prepared=prepared,preserved=preserved,cancelled=cancelled,
                        consumer_output=peer_output.decode(errors='replace'),consumer_stderr=peer_errors.decode(errors='replace'),
                        producer_output=worker_output.decode(errors='replace'))
                    frame_death_complete=True
                    frame_death_worker_expected_code=1
                    metrics['stage']='handoff-complete';publish()
                    return
                signal.pidfd_send_signal(worker_pidfd,signal.SIGKILL)
                dead_output,_=worker.communicate(timeout=10)
                if worker.returncode!=-signal.SIGKILL or not select.select([worker_pidfd],[],[],0)[0]:
                    raise RuntimeError('PREPARED producer did not die on its captured pidfd')
                deadline=time.monotonic()+10
                while time.monotonic()<deadline:
                    snapshot_connection=api.Connection(args.socket)
                    try: census=snapshot_connection.request(api.STATUS)
                    finally: snapshot_connection.close()
                    if census['process']==1 and census['slot']==1:break
                    time.sleep(0.01)
                else:raise RuntimeError('resident did not reap the exact PREPARED producer')
                snapshot_connection=api.Connection(args.socket)
                try: reap_owner=snapshot_connection.request(api.PMD_STATUS)
                finally: snapshot_connection.close()
                if (reap_owner['token']!=expected_key or reap_owner['generation']!=1 or
                    reap_owner['slot']!=metrics['handoff_peer_attached']['slot']):
                    raise RuntimeError('PREPARED producer reap changed the exact live consumer owner')
                if peer_control_w<0 or os.write(peer_control_w,b'G')!=1:
                    raise RuntimeError('could not request PREPARED lease recovery snapshot')
                reaped=ready('KER_SESSION_FRAME_DEATH_REAPED',process=peer_worker)
                if reaped.get('tx')!=prepared.get('tx_before') or \
                    reaped.get('packet_pool_in_use')!=prepared.get('pool_before') or \
                    reaped.get('counters')!=prepared.get('counters_before'):
                    raise RuntimeError('PREPARED producer death did not restore packet-pool baseline')
                metrics['handoff_frame_death']=dict(stage='prepared',producer_pid=worker.pid,
                    producer_status=worker.returncode,pidfd_dead=True,prepared=prepared,
                    stopped=True,owner_after_reap=reap_owner,census=census,
                    output=dead_output.decode(errors='replace'),reap=reaped)
                frame_death_complete=True
                frame_death_worker_expected_code=-signal.SIGKILL
                metrics['stage']='handoff-complete';publish()
                return
            if handoff_mode=='frame-full':
                full=ready('KER_SESSION_FRAME_FULL_COMMIT_CANCELLED')
                if (full.get('status')!=-errno.ENOBUFS or full.get('pool_restored') is not True or
                    full.get('tx_after')!=metrics.get('frame_full_capacity') or
                    full.get('tx_capacity')!=metrics.get('frame_full_capacity') or
                    full.get('pool_before')!=metrics.get('frame_full_capacity') or
                    full.get('pool_after')!=metrics.get('frame_full_capacity') or
                    full.get('counters_before')!=metrics.get('frame_full_fill',{}).get('counters_after') or
                    len(full.get('counters_after',[]))!=5 or
                    full.get('counters_after')[:4]!=full.get('counters_before',[])[:4] or
                    full.get('counters_after',[])[4]!=full.get('counters_before',[-1]*5)[4]+1):
                    raise RuntimeError('full TX ring did not cancel the prepared original frame exactly')
                if peer_control_w<0 or os.write(peer_control_w,b'G')!=1:
                    raise RuntimeError('could not request full-ring peer drain')
                drained_full=ready('KER_SESSION_FRAME_FULL_DRAINED',process=peer_worker)
                if (drained_full.get('tx_after')!=0 or drained_full.get('count')!=metrics.get('frame_full_capacity') or
                    drained_full.get('pool_before')!=metrics.get('frame_full_capacity') or
                    drained_full.get('pool_after')!=0 or
                    drained_full.get('counters_before')!=full.get('counters_after') or
                    drained_full.get('counters_after')!=drained_full.get('counters_before') or
                    drained_full.get('objects')!=metrics.get('frame_full_fill',{}).get('objects')):
                    raise RuntimeError('peer did not drain the exact filled generation TX ring')
                metrics['handoff_frame_full']=dict(fill=metrics['frame_full_fill'],
                    commit_cancel=full,drain=drained_full)
                publish();return
            _, _, committed = read_frame_commit_sequence(worker, ready, False)
            if include_negatives and (negative_prepares['variants'] != 12 or
                    not cancel_replay['cancel_replay']):
                raise RuntimeError('frame test-only negative controls did not complete before COMMIT')
            validate_frame_committed_record(committed,payload)
            if handoff_mode=='frame-death-producer-active-consumer':
                if peer_control_w<0 or os.write(peer_control_w,b'G')!=1:
                    raise RuntimeError('could not start live consumer dequeue before producer death')
                ready('KER_GENERATION_ACTIVE_DEQUEUE_HELD',process=peer_worker)
                wait_pidfd_process_stopped(peer_worker_pidfd,peer_worker.pid)
                if select.select([peer_worker_pidfd],[],[],0)[0]:
                    raise RuntimeError('active live consumer pidfd became readable before producer death')
                signal.pidfd_send_signal(worker_pidfd,signal.SIGKILL)
                dead_output,_=worker.communicate(timeout=10)
                if worker.returncode!=-signal.SIGKILL or not select.select([worker_pidfd],[],[],0)[0]:
                    raise RuntimeError('active-dequeue producer did not die on its captured pidfd')
                metrics['handoff_frame_death_waiting']=dict(stage='producer-dead-active-consumer',
                    producer_pid=worker.pid,consumer_pid=peer_worker.pid,producer_status=worker.returncode,
                    producer_pidfd_dead=True,consumer_pidfd_dead=False,committed=committed,
                    producer_output=dead_output.decode(errors='replace'))
                publish()
                deadline=time.monotonic()+10
                while time.monotonic()<deadline:
                    readable,_,_=select.select([handoff_fd],[],[],0.05)
                    if readable:
                        if os.read(handoff_fd,1)!=b'R':
                            raise RuntimeError('invalid active-consumer recovery continuation')
                        break
                    if app.poll() is not None:raise RuntimeError('application exited during active-consumer recovery')
                else:raise RuntimeError('fixture did not release the active consumer after checking EBUSY')
                signal.pidfd_send_signal(peer_worker_pidfd,signal.SIGCONT)
                drained=ready('KER_SESSION_FRAME_DRAINED',process=peer_worker)
                for field in ('object_index','pool_tag','packet_pointer','length','frame_hex'):
                    if drained.get(field)!=committed.get(field):
                        raise RuntimeError('active consumer changed committed packet '+field)
                if (drained.get('sequence')!=2 or drained.get('tx_before')!=1 or drained.get('tx_after')!=0 or
                    drained.get('pool_in_use_after')+1!=drained.get('pool_in_use_before')):
                    raise RuntimeError('active consumer did not release the exact in-flight packet')
                deadline=time.monotonic()+10
                while time.monotonic()<deadline:
                    census_connection=api.Connection(args.socket)
                    try:census=census_connection.request(api.STATUS);owner=census_connection.request(api.PMD_STATUS)
                    finally:census_connection.close()
                    if census.get('process')==1 and census.get('slot')==1:break
                    time.sleep(0.02)
                else:raise RuntimeError('readiness timer did not reap producer after active packet release')
                if owner.get('token')!=expected_key or owner.get('generation')!=1 or peer_worker.poll() is not None:
                    raise RuntimeError('active-consumer recovery changed surviving peer PMD owner')
                metrics['handoff_frame_death']=dict(stage='producer-active-consumer',
                    producer_pid=worker.pid,consumer_pid=peer_worker.pid,
                    producer_status=worker.returncode,consumer_status=None,consumer_still_live=peer_worker.poll() is None,
                    producer_pidfd_dead=True,committed=committed,drain=drained,final_census=census,
                    final_owner=owner,producer_output=dead_output.decode(errors='replace'))
                frame_death_complete=True
                frame_death_worker_expected_code=-signal.SIGKILL
                metrics['stage']='handoff-complete';publish();return
            if peer_control_w < 0 or os.write(peer_control_w, b'G') != 1:
                raise RuntimeError('could not request exact admitted-peer TX journal drain')
            drained = ready('KER_SESSION_FRAME_DRAINED', process=peer_worker)
            for field in ('object_index', 'pool_tag', 'packet_pointer', 'length', 'frame_hex'):
                if drained.get(field) != committed.get(field):
                    raise RuntimeError('peer TX drain changed committed packet ' + field)
            if drained.get('sequence') != 2:
                raise RuntimeError('peer TX drain returned the wrong original app datagram')
            if (drained.get('tx_before') != 1 or drained.get('tx_after') != 0 or
                not isinstance(drained.get('pool_in_use_before'), int) or
                drained.get('pool_in_use_after') + 1 != drained.get('pool_in_use_before')):
                raise RuntimeError('peer TX drain did not report the exact one-object ring/pool release')
            metrics['handoff_frame'] = dict(committed=committed, drained=drained,
                same_pointer=True, same_bytes=True, peer_release_once=True,
                ring_empty_after=drained['tx_after']==0,
                packet_pool_released_once=(drained['pool_in_use_before']-drained['pool_in_use_after']==1))
            publish()

        while app.poll() is None:
            if received_signal is not None:
                if handoff_fd is not None:
                    close(handoff_fd); handoff_fd=None
                app.terminate()
                try: app.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    app.kill(); app.wait()
                break
            if handoff_fd is not None:
                trigger = select.poll(); trigger.register(handoff_fd, select.POLLIN | select.POLLHUP | select.POLLERR)
                if trigger.poll(0):
                    data = os.read(handoff_fd, 1)
                    action = handoff_trigger_action(data)
                    if action == 'udp':
                        trigger_handoff_udp()
                        handoff_fd = close_completed_handoff_trigger(
                            handoff_mode, handoff_seen, handoff_udp_sequence, handoff_fd, close)
                    elif action == 'handoff':
                        if handoff_mode not in FRAME_U2_TRIGGER_MODES:
                            close(handoff_fd); handoff_fd = None
                        perform_test_handoff()
                        handoff_seen = True
                    else:
                        close(handoff_fd); handoff_fd = None
                        raise RuntimeError('invalid live-handoff fixture trigger')
            drain_startup()
            if b'KER_NATIVE_READY\n' not in startup and time.monotonic() >= deadline:
                raise RuntimeError('native Linux startup timed out')
            if b'KER_NATIVE_STOPPING\n' in startup:
                if stopping_at is None: stopping_at = time.monotonic()
                if time.monotonic() - stopping_at > 5:
                    raise RuntimeError('native Linux teardown timed out')
            elif worker.poll() is not None and app.poll() is None and not frame_death_complete:
                # Consume a destructor notification before classifying loss.
                drain_startup()
                if b'KER_NATIVE_STOPPING\n' not in startup:
                    raise RuntimeError('secondary packet worker exited while application was running')
            time.sleep(0.01)
        code = app.wait()
        drain_startup()
        if handoff_fd is not None and not handoff_trigger_complete(
                handoff_mode, handoff_seen, handoff_udp_sequence):
            raise RuntimeError('test application exited before the handoff trigger')
        if handoff_fd is not None:
            close(handoff_fd); handoff_fd = None
        close(control_w)
        if peer_control_w >= 0: close(peer_control_w)
        try: output, _ = worker.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            worker.kill(); worker.communicate()
            raise RuntimeError('secondary packet worker did not exit')
        print(output.decode().rstrip(), file=sys.stderr, flush=True)
        packet_stats = None
        for line in output.decode().splitlines():
            if line.startswith('KER_SESSION_PACKET_DONE '):
                packet_stats = json.loads(line.removeprefix('KER_SESSION_PACKET_DONE '))
        peer_packet_stats = None
        peer_code = None
        if peer_worker is not None:
            try: peer_output, peer_errors = peer_worker.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                peer_worker.kill(); peer_output, peer_errors = peer_worker.communicate()
                raise RuntimeError('handoff peer did not exit after packet-control EOF: ' + (peer_errors or b'').decode(errors='replace'))
            print(peer_output.decode().rstrip(), file=sys.stderr, flush=True)
            peer_code = peer_worker.returncode
            peer_lines = [line.removeprefix('KER_SESSION_PACKET_DONE ')
                for line in peer_output.decode().splitlines() if line.startswith('KER_SESSION_PACKET_DONE ')]
            if len(peer_lines) > 1:
                raise RuntimeError('handoff peer reported duplicate packet completion')
            peer_packet_stats = json.loads(peer_lines[0]) if peer_lines else None
        native_stats = None
        for line in startup.decode().splitlines():
            if line.startswith('KER_NATIVE_STATS '):
                native_stats = json.loads(line.removeprefix('KER_NATIVE_STATS '))
                print('KER_SESSION_NATIVE_STATS ' + json.dumps(native_stats), file=sys.stderr, flush=True)
        metrics.update(packet=packet_stats, native=native_stats, worker_code=worker.returncode, app_code=code,
            handoff_peer_packet=peer_packet_stats, handoff_peer_code=peer_code)
        release(ticket)
        if handoff_mode in ('frame-death-consumer-prepared','frame-death-both-prepared'):
            if peer_code != -signal.SIGKILL or peer_packet_stats is not None:
                raise RuntimeError('intentional consumer death lost its exact pidfd outcome')
        else:
            validate_handoff_peer_cleanup(metrics, peer_worker is not None, peer_code, peer_packet_stats)
        if frame_death_complete:
            if worker.returncode!=frame_death_worker_expected_code or packet_stats is not None:
                raise RuntimeError('intentional actor-death profile lost its exact pidfd outcome')
        elif worker.returncode or packet_stats is None or packet_stats['status']:
            raise RuntimeError('secondary packet cleanup failed')
        if received_signal is not None:
            native_cleanup = validate_interrupted_cleanup(worker.returncode, packet_stats,
                packet_expected=not frame_death_complete, app_launched=True,
                app_code=code, startup=startup, native_stats=native_stats,
                worker_expected_code=frame_death_worker_expected_code if frame_death_complete else None)
            metrics.update(native_cleanup=native_cleanup, stage='interrupted'); publish(); completed = True
            return 128 + received_signal
        if code:
            metrics['stage'] = 'application-failed'; publish(); completed = True
            return code if code > 0 else 128 - code
        if (b'KER_NATIVE_READY\n' not in startup or b'KER_NATIVE_DONE\n' not in startup or
                b'KER_NATIVE_INCOMPLETE\n' in startup or native_stats is None or native_stats['buffers_live']):
            raise RuntimeError('native kernel did not finish cleanly')
        metrics['stage'] = 'finished'; publish(); completed = True
        return 0
    finally:
        try:
            if worker_pidfd >= 0:
                if worker is not None and pidfd_process_stopped(worker_pidfd, worker.pid):
                    resume_pidfd_if_live(worker_pidfd)
            if app is not None and app.poll() is None:
                if app_pidfd >= 0: signal.pidfd_send_signal(app_pidfd, signal.SIGTERM)
                else: app.terminate()
                try: app.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    if app_pidfd >= 0: signal.pidfd_send_signal(app_pidfd, signal.SIGKILL)
                    else: app.kill()
                    app.wait()
            for fd in tuple(owned): close(fd)
            if worker is not None and worker.poll() is None:
                try: worker.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    if worker_pidfd >= 0: signal.pidfd_send_signal(worker_pidfd, signal.SIGKILL)
                    else: worker.kill()
                    worker.wait()
            if peer_worker is not None and peer_worker.poll() is None:
                try: peer_worker.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    if peer_worker_pidfd >= 0: signal.pidfd_send_signal(peer_worker_pidfd, signal.SIGKILL)
                    else: peer_worker.kill()
                    peer_worker.wait()
            for endpoint in (packet_worker, packet_app, mtu_worker, mtu_app): endpoint.close()
            for endpoint in (peer_packet_worker, peer_packet_app, peer_mtu_worker, peer_mtu_app):
                if endpoint is not None: endpoint.close()
            for pidfd_name in ('worker_pidfd','peer_worker_pidfd','app_pidfd'):
                exact_pidfd=locals()[pidfd_name]
                if exact_pidfd>=0: os.close(exact_pidfd)
            connection.close()
            if not completed:
                metrics.update(stage='failed', worker_code=worker.poll() if worker is not None else None,
                    app_code=app.poll() if app is not None else None,
                    handoff_peer_code=peer_worker.poll() if peer_worker is not None else None)
                publish()
        finally:
            signal.signal(signal.SIGTERM, previous_sigterm)
            signal.signal(signal.SIGINT, previous_sigint)
