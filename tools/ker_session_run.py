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
import struct


def signal_pidfd(pidfd, signum):
    """Signal one exact process identity through its already-open pidfd."""
    sender = getattr(signal, 'pidfd_send_signal', None)
    if sender is None:
        raise RuntimeError('pidfd_send_signal is required for exact handoff fixture control')
    sender(pidfd, signum)


def handoff_ipv4_udp_payload(frame):
    """Return a complete IPv4/UDP payload only for the fixture's exact tuple."""
    if not isinstance(frame, bytes) or len(frame) < 14 + 20 + 8 or frame[12:14] != b'\x08\x00':
        return None
    ip = frame[14:]
    version_ihl = ip[0]
    ihl = (version_ihl & 15) * 4
    if version_ihl >> 4 != 4 or ihl != 20 or len(ip) < ihl:
        return None
    total = struct.unpack('!H', ip[2:4])[0]
    if total != len(ip) or total < ihl + 8 or ip[9] != 17 or struct.unpack('!H', ip[6:8])[0] & 0x3fff:
        return None
    if ip[12:16] != bytes((198, 18, 0, 2)) or ip[16:20] != bytes((198, 18, 0, 1)):
        return None
    header = ip[:ihl]
    words = struct.unpack('!10H', header)
    total_sum = sum(words)
    while total_sum >> 16:
        total_sum = (total_sum & 0xffff) + (total_sum >> 16)
    if total_sum != 0xffff:
        return None
    udp = ip[ihl:total]
    source_port, destination_port, udp_length, udp_checksum = struct.unpack('!HHHH', udp[:8])
    if source_port != 45000 or destination_port != 45001 or udp_length != len(udp):
        return None
    if udp_checksum:
        pseudo = ip[12:20] + b'\x00\x11' + struct.pack('!H', udp_length)
        data = pseudo + udp
        if len(data) & 1:
            data += b'\x00'
        checksum = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
        while checksum >> 16:
            checksum = (checksum & 0xffff) + (checksum >> 16)
        if checksum != 0xffff:
            return None
    return udp[8:]


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
                                 app_code=None, startup=b'', native_stats=None):
    """Validate signal cleanup without overriding the application's signal semantics."""
    if worker_code != 0:
        raise RuntimeError('secondary packet cleanup failed during signal cancellation')
    if packet_expected:
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


FRAME_U2_TRIGGER_MODES = frozenset({'frame-positive'})


def handoff_trigger_complete(mode, handoff_seen, udp_sequence):
    """Require the handoff command and all mode-specific UDP triggers."""
    return bool(handoff_seen and (mode not in FRAME_U2_TRIGGER_MODES or udp_sequence == 2))


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


def require_complete_handoff_trigger(mode, handoff_seen, udp_sequence):
    if not handoff_trigger_complete(mode, handoff_seen, udp_sequence):
        raise RuntimeError('test application exited before the handoff trigger sequence completed')


def reject_handoff_trigger_eof(mode, handoff_seen, udp_sequence):
    if not handoff_trigger_complete(mode, handoff_seen, udp_sequence):
        raise RuntimeError('handoff trigger pipe reached EOF before the trigger sequence completed')
    raise RuntimeError('handoff trigger pipe reached unexpected EOF')


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
    handoff_modes = {'positive', 'frame-positive', 'bad-capability', 'bad-tx-lease', 'bad-rx-lease', 'peer-death', 'timeout',
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
    handoff_udp_ready = False
    peer_control_w = peer_wire_fd = -1
    peer_packet_worker = peer_packet_app = peer_mtu_worker = peer_mtu_app = None
    owned = {args.wire_fd}
    if handoff_fd is not None:
        owned.add(handoff_fd)
    metrics = {'stage': 'starting', 'app_started': False}
    metrics['generation_rings'] = bool(getattr(args, 'generation_rings', False))
    frame_committed_records = []
    frame_drained_records = []
    worker_deferred_output = []
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

    def capture_frame_owner_line(raw):
        if handoff_mode != 'frame-positive' or not raw.startswith(b'KER_SESSION_FRAME_COMMITTED '):
            return False
        record=json.loads(raw.split(b' ',1)[1])
        fields={'port','queue','generation','length','object_index','pool_tag','tx_lease_id',
            'packet_pointer','frame_hex'}
        if (set(record)!=fields or type(record.get('port')) is not int or record['port']!=0 or
            type(record.get('queue')) is not int or record['queue']!=0 or
            type(record.get('generation')) is not int or record['generation']!=0 or
            type(record.get('length')) is not int or not 14<=record['length']<=1518 or
            type(record.get('object_index')) is not int or record['object_index']<0 or
            type(record.get('pool_tag')) is not int or record['pool_tag']<=0 or
            type(record.get('tx_lease_id')) is not int or record['tx_lease_id']<=0 or
            not isinstance(record.get('packet_pointer'),str) or
            not record['packet_pointer'].startswith('0x') or
            not record['packet_pointer'][2:] or record['packet_pointer'][2][0] not in '123456789abcdef' or
            any(c not in '0123456789abcdef' for c in record['packet_pointer'][2:])):
            raise RuntimeError('producer commit lacks exact frame object identity')
        try: frame=bytes.fromhex(record['frame_hex'])
        except (TypeError,ValueError) as error: raise RuntimeError('producer commit frame is malformed') from error
        if len(frame)!=record['length'] or frame.hex()!=record['frame_hex']:
            raise RuntimeError('producer commit frame length/encoding mismatch')
        frame_committed_records.append(record)
        print(raw.decode(errors='replace').rstrip(),file=sys.stderr,flush=True)
        return True

    def ready(*prefixes, process=None):
        process = worker if process is None else process
        deadline=time.monotonic()+20
        while time.monotonic()<deadline:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout,selectors.EVENT_READ)
                if not selector.select(max(0,deadline-time.monotonic())):break
            line=process.stdout.readline()
            if not line:raise RuntimeError('secondary packet worker exited before '+','.join(prefixes))
            if process is worker and capture_frame_owner_line(line):continue
            prefix=next((value for value in prefixes if line.startswith(value.encode()+b' ')),None)
            if prefix is None:raise RuntimeError('secondary packet startup failed: '+line.decode(errors='replace'))
            value=json.loads(line[len(prefix)+1:])
            if prefix!='KER_SESSION_PMD_STANDBY' or 'standby' not in metrics:
                print(line.decode().rstrip(),file=sys.stderr,flush=True)
            return (prefix,value) if len(prefixes)>1 else value
        raise RuntimeError('secondary packet startup timed out waiting for '+','.join(prefixes))

    def wait_for_u2_commit(payload,timeout=10):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            for record in frame_committed_records:
                try:frame=bytes.fromhex(record['frame_hex'])
                except (KeyError,TypeError,ValueError):continue
                if handoff_ipv4_udp_payload(frame)==payload:
                    return record
            with selectors.DefaultSelector() as selector:
                selector.register(worker.stdout,selectors.EVENT_READ)
                if not selector.select(max(0,deadline-time.monotonic())):break
            raw=worker.stdout.readline()
            if not raw:raise RuntimeError('producer exited before committing original U2')
            if not capture_frame_owner_line(raw):
                print(raw.decode(errors='replace').rstrip(),file=sys.stderr,flush=True)
        raise RuntimeError('timed out waiting for original U2 frame commit')

    def request_frame_batch():
        if peer_control_w<0 or peer_worker is None or peer_worker.poll() is not None:
            raise RuntimeError('frame consumer is unavailable')
        if os.write(peer_control_w,b'G')!=1:raise RuntimeError('short frame drain request')
        records=[];deadline=time.monotonic()+10
        while time.monotonic()<deadline:
            with selectors.DefaultSelector() as selector:
                selector.register(peer_worker.stdout,selectors.EVENT_READ)
                if not selector.select(max(0,deadline-time.monotonic())):break
            raw=peer_worker.stdout.readline()
            if not raw:raise RuntimeError('frame peer exited before batch completion')
            if raw.startswith(b'KER_SESSION_FRAME_DRAINED '):
                record=json.loads(raw.split(b' ',1)[1])
                fields={'sequence','consumer_generation','object_index','lease_id','pool_tag',
                    'packet_pointer','length','frame_hex'}
                if (set(record)!=fields or type(record.get('sequence')) is not int or record['sequence'] != 0 or
                    type(record.get('consumer_generation')) is not int or record['consumer_generation']!=1 or
                    type(record.get('object_index')) is not int or record['object_index']<0 or
                    type(record.get('lease_id')) is not int or record['lease_id']<=0 or
                    type(record.get('pool_tag')) is not int or record['pool_tag']<=0 or
                    type(record.get('length')) is not int or not 14<=record['length']<=1518 or
                    not isinstance(record.get('packet_pointer'),str) or not record['packet_pointer'].startswith('0x') or
                    len(record['packet_pointer'])<3 or record['packet_pointer'][2] not in '123456789abcdef' or
                    any(c not in '0123456789abcdef' for c in record['packet_pointer'][2:])):
                    raise RuntimeError('peer release record has invalid object identity')
                try:frame=bytes.fromhex(record['frame_hex'])
                except (TypeError,ValueError) as error:raise RuntimeError('peer release bytes are malformed') from error
                if len(frame)!=record['length'] or frame.hex()!=record['frame_hex']:
                    raise RuntimeError('peer release frame length/encoding mismatch')
                print(raw.decode(errors='replace').rstrip(),file=sys.stderr,flush=True)
                records.append(record);continue
            if raw.startswith(b'KER_SESSION_FRAME_BATCH '):
                batch=json.loads(raw.split(b' ',1)[1])
                fields={'drained','tx_before','tx_after','pool_in_use_before','pool_in_use_after'}
                if (set(batch)!=fields or any(type(batch.get(k)) is not int or batch[k]<0 for k in fields) or
                    batch['drained']!=len(records) or batch['tx_before']>64 or batch['tx_after']>64):
                    raise RuntimeError('peer batch counters do not match release records')
                print(raw.decode(errors='replace').rstrip(),file=sys.stderr,flush=True)
                frame_drained_records.extend(records)
                return records,batch
            raise RuntimeError('unexpected peer frame output: '+raw.decode(errors='replace').rstrip())
        raise RuntimeError('timed out waiting for peer frame batch')

    def finish_frame_owner_output():
        if worker is None or worker.stdout is None:return
        deadline=time.monotonic()+10
        eof=False
        while not eof:
            with selectors.DefaultSelector() as selector:
                selector.register(worker.stdout,selectors.EVENT_READ)
                if not selector.select(max(0,deadline-time.monotonic())):
                    if worker.poll() is None:raise RuntimeError('parked frame producer did not stop after control close')
                    break
            raw=worker.stdout.readline()
            if not raw:eof=True;continue
            if not capture_frame_owner_line(raw):worker_deferred_output.append(raw)
        if worker.poll() is None:raise RuntimeError('parked frame producer remained live after app teardown')

    def validate_frame_commit_drain_bijection():
        def key(record, lease_field):
            return (record.get('pool_tag'),record.get('object_index'),record.get(lease_field))
        commits=list(frame_committed_records);drains=list(frame_drained_records)
        commit_keys=[key(item,'tx_lease_id') for item in commits]
        drain_keys=[key(item,'lease_id') for item in drains]
        if (len(commits)!=len(drains) or len(set(commit_keys))!=len(commit_keys) or
            len(set(drain_keys))!=len(drain_keys) or set(commit_keys)!=set(drain_keys)):
            raise RuntimeError('frame producer commits and peer releases are not a one-to-one lease bijection')
        drain_by_key={key(item,'lease_id'):item for item in drains}
        for committed in commits:
            drained=drain_by_key[key(committed,'tx_lease_id')]
            for left,right in (('packet_pointer','packet_pointer'),('length','length'),('frame_hex','frame_hex'),
                ('pool_tag','pool_tag'),('object_index','object_index'),('tx_lease_id','lease_id')):
                if committed.get(left)!=drained.get(right):
                    raise RuntimeError('peer release changed committed frame '+left)
        payload=b'KER-A09-HANDOFF-UDP seq=2\n'
        def carries_u2(item):
            try:return handoff_ipv4_udp_payload(bytes.fromhex(item['frame_hex']))==payload
            except (KeyError,TypeError,ValueError):return False
        u2_commits=[item for item in commits if carries_u2(item)]
        u2_drains=[item for item in drains if carries_u2(item)]
        if len(u2_commits)!=1 or len(u2_drains)!=1 or key(u2_commits[0],'tx_lease_id')!=key(u2_drains[0],'lease_id'):
            raise RuntimeError('the original U2 datagram was not committed and drained exactly once')
        return commits,drains

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
        nonlocal peer_worker, peer_control_w, peer_packet_worker, peer_packet_app
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
        peer_arguments.extend(['--wire-fd', str(peer_wire_fd), '--mtu-fd', str(peer_mtu_worker.fileno()), '--',
            *api.role_arguments(args.eal, 'secondary', paired_pmd=True)])
        peer_worker = subprocess.Popen(peer_arguments,
            pass_fds=(control_r, ticket_r, peer_packet_worker.fileno(), peer_wire_fd, peer_mtu_worker.fileno()),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, env=peer_environment, bufsize=0)
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
        nonlocal control_w, handoff_udp_ready
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
        if handoff_mode not in (None, 'positive', 'frame-positive'):
            raise RuntimeError('test handoff mode is not a fatal profile')
        parked = wait_marker(worker, 'KER_SESSION_PMD_PARKED')
        if (boundary.get('idle') is not True or boundary.get('owner_key') != metrics['grant']['queue_owner_key'] or
                parked.get('pid') != worker.pid or parked.get('old_owner_key') != metrics['grant']['queue_owner_key'] or
                parked.get('successor_slot') != metrics['handoff_peer_attached']['slot'] or
                parked.get('successor_generation') != 1 or app.poll() is not None or worker.poll() is not None):
            raise RuntimeError('same-process handoff did not park the granted generation-zero worker')
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
            boundary=boundary, parked=parked,
            successor=successor, geometry=geometry, resident=observed)
        metrics['handoff_protocol'] = dict(negative_prepare=negative_prepare, replay_prepare=replay_prepare)
        metrics['stage'] = 'handoff-complete'
        handoff_udp_ready = True
        publish()

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
            nonlocal handoff_udp_sequence
            if handoff_mode != 'frame-positive' or app is None or app_pidfd < 0 or app.poll() is not None:
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
            committed = wait_for_u2_commit(payload)
            try:committed_frame=bytes.fromhex(committed.get('frame_hex',''))
            except (TypeError,ValueError):committed_frame=b''
            if (committed.get('queue') != 0 or committed.get('generation') != 0 or
                committed.get('packet_pointer') is None or committed.get('object_index') is None or
                committed.get('pool_tag') is None or handoff_ipv4_udp_payload(committed_frame)!=payload):
                raise RuntimeError('parked original LKL endpoint did not commit the exact second UDP frame')
            batch_records,batch=request_frame_batch()
            if batch['tx_after']:
                more_records,final_batch=request_frame_batch()
                batch_records.extend(more_records);batch=final_batch
            matches=[item for item in batch_records if handoff_ipv4_udp_payload(bytes.fromhex(item['frame_hex']))==payload]
            if len(matches)!=1 or any(matches[0].get(left)!=committed.get(right) for left,right in
                    (('object_index','object_index'),('pool_tag','pool_tag'),('lease_id','tx_lease_id'),
                     ('packet_pointer','packet_pointer'),('length','length'),('frame_hex','frame_hex'))):
                raise RuntimeError('peer TX drain changed or duplicated the exact original U2 object')
            metrics['handoff_frame'] = dict(committed_records=list(frame_committed_records),
                drained_records=list(frame_drained_records),initial_batch=batch)
            publish()

        while app.poll() is None:
            if received_signal is not None:
                app.terminate()
                try: app.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    app.kill(); app.wait()
                break
            if handoff_fd is not None:
                trigger = select.poll(); trigger.register(handoff_fd, select.POLLIN | select.POLLHUP | select.POLLERR)
                if trigger.poll(0):
                    data = os.read(handoff_fd, 1)
                    if not data:
                        close(handoff_fd); handoff_fd = None
                        reject_handoff_trigger_eof(handoff_mode, handoff_seen, handoff_udp_sequence)
                    action = handoff_trigger_action(data)
                    if action == 'udp':
                        trigger_handoff_udp()
                        handoff_fd = close_completed_handoff_trigger(
                            handoff_mode, handoff_seen, handoff_udp_sequence, handoff_fd, close)
                    elif action == 'handoff':
                        if handoff_mode != 'frame-positive':
                            close(handoff_fd); handoff_fd = None
                        perform_test_handoff()
                        handoff_seen = True
                    else:
                        close(handoff_fd); handoff_fd = None
                        raise RuntimeError('invalid live-handoff fixture trigger or incomplete trigger EOF')
            drain_startup()
            if b'KER_NATIVE_READY\n' not in startup and time.monotonic() >= deadline:
                raise RuntimeError('native Linux startup timed out')
            if b'KER_NATIVE_STOPPING\n' in startup:
                if stopping_at is None: stopping_at = time.monotonic()
                if time.monotonic() - stopping_at > 5:
                    raise RuntimeError('native Linux teardown timed out')
            elif worker.poll() is not None and app.poll() is None:
                # Consume a destructor notification before classifying loss.
                drain_startup()
                if b'KER_NATIVE_STOPPING\n' not in startup:
                    raise RuntimeError('secondary packet worker exited while application was running')
            time.sleep(0.01)
        code = app.wait()
        drain_startup()
        if handoff_fd is not None:
            require_complete_handoff_trigger(handoff_mode, handoff_seen, handoff_udp_sequence)
            close(handoff_fd); handoff_fd = None
        close(control_w)
        if handoff_mode == 'frame-positive':
            finish_frame_owner_output()
            final_batch=None
            for _ in range(4):
                _,final_batch=request_frame_batch()
                if final_batch['tx_after']==0:break
            else:raise RuntimeError('peer frame TX ring did not reach empty after producer exit')
            if peer_control_w<0 or os.write(peer_control_w,b'Q')!=1:
                raise RuntimeError('could not request final peer frame quiescence')
            quiescent=ready('KER_SESSION_FRAME_QUIESCENT',process=peer_worker)
            if quiescent!={'tx_count':0,'packet_pool_in_use':0}:
                raise RuntimeError('peer frame ring or packet pool remained nonempty')
            commits,drains=validate_frame_commit_drain_bijection()
            frame_proof=metrics.get('handoff_frame') or {}
            frame_proof.update(committed_records=commits,drained_records=drains,
                final_batch=final_batch,quiescent=quiescent,
                commit_bijection={'committed':len(commits),'drained':len(drains)})
            metrics['handoff_frame']=frame_proof;publish()
        if peer_control_w >= 0: close(peer_control_w)
        try: output, _ = worker.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            worker.kill(); worker.communicate()
            raise RuntimeError('secondary packet worker did not exit')
        output=b''.join(worker_deferred_output)+output
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
        validate_handoff_peer_cleanup(metrics, peer_worker is not None, peer_code, peer_packet_stats)
        if worker.returncode or packet_stats is None or packet_stats['status']:
            raise RuntimeError('secondary packet cleanup failed')
        if received_signal is not None:
            native_cleanup = validate_interrupted_cleanup(worker.returncode, packet_stats, app_launched=True,
                app_code=code, startup=startup, native_stats=native_stats)
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
            if app_pidfd >= 0:
                os.close(app_pidfd)
                app_pidfd = -1
            if worker_pidfd >= 0:
                if worker is not None and pidfd_process_stopped(worker_pidfd, worker.pid):
                    resume_pidfd_if_live(worker_pidfd)
                os.close(worker_pidfd)
                worker_pidfd = -1
            if app is not None and app.poll() is None:
                app.terminate()
                try: app.wait(timeout=5)
                except subprocess.TimeoutExpired: app.kill(); app.wait()
            for fd in tuple(owned): close(fd)
            if worker is not None and worker.poll() is None:
                try: worker.wait(timeout=5)
                except subprocess.TimeoutExpired: worker.kill(); worker.wait()
            if peer_worker is not None and peer_worker.poll() is None:
                try: peer_worker.wait(timeout=5)
                except subprocess.TimeoutExpired: peer_worker.kill(); peer_worker.wait()
            for endpoint in (packet_worker, packet_app, mtu_worker, mtu_app): endpoint.close()
            for endpoint in (peer_packet_worker, peer_packet_app, peer_mtu_worker, peer_mtu_app):
                if endpoint is not None: endpoint.close()
            connection.close()
            if not completed:
                metrics.update(stage='failed', worker_code=worker.poll() if worker is not None else None,
                    app_code=app.poll() if app is not None else None,
                    handoff_peer_code=peer_worker.poll() if peer_worker is not None else None)
                publish()
        finally:
            signal.signal(signal.SIGTERM, previous_sigterm)
            signal.signal(signal.SIGINT, previous_sigint)
