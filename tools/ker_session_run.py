"""Launch an original Linux instance on a granted secondary packet session."""
import errno
import ipaddress
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import subprocess
import sys
import tempfile
import time



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
    # Validation does not mutate file-description flags. The caller transfers
    # this endpoint; the launcher closes its own copy after the child starts.
    with socket.socket(fileno=os.dup(args.wire_fd)) as endpoint:
        if endpoint.family != socket.AF_UNIX or endpoint.type != socket.SOCK_DGRAM:
            raise ValueError('--wire-fd must be a connected local Ethernet datagram endpoint')
        endpoint.getpeername()
    connection = api.Connection(args.socket)
    worker = app = None
    owned = {args.wire_fd}
    metrics = {'stage': 'starting', 'app_started': False}
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

    def ready(*prefixes):
        with selectors.DefaultSelector() as selector:
            selector.register(worker.stdout, selectors.EVENT_READ)
            if not selector.select(20):
                raise RuntimeError('secondary packet startup timed out')
        line = worker.stdout.readline()
        prefix = next((value for value in prefixes if line.startswith(value.encode() + b' ')), None)
        if prefix is None:
            raise RuntimeError('secondary packet startup failed: ' + line.decode(errors='replace'))
        value = json.loads(line[len(prefix) + 1:])
        if prefix != 'KER_SESSION_PMD_STANDBY' or 'standby' not in metrics:
            print(line.decode().rstrip(), file=sys.stderr, flush=True)
        return (prefix, value) if len(prefixes) > 1 else value

    def finish_signal_before_app(packet_expected):
        nonlocal completed
        close(control_w)
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
        metrics.update(packet=packet_stats, worker_code=worker.returncode, app_code=None, signal=received_signal)
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
        worker = subprocess.Popen([str(worker_path), '--role', 'secondary', '--paired-pmd',
            *(['--standby'] if args.standby else []),
            '--socket', str(args.socket), '--control-fd', str(control_r), '--ticket-fd', str(ticket_r),
            '--generation', str(args.generation), '--process', str(args.process),
            '--packet-fd', str(packet_worker.fileno()), '--wire-fd', str(args.wire_fd),
            '--mtu-fd', str(mtu_worker.fileno()), '--',
            *api.role_arguments(args.eal, 'secondary', paired_pmd=True)],
            pass_fds=(control_r, ticket_r, packet_worker.fileno(), mtu_worker.fileno(), args.wire_fd),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, bufsize=0)
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
        metrics['stage'] = 'worker-ready'; publish()
        if received_signal is not None:
            return finish_signal_before_app(packet_expected=True)
        environment = {k: v for k, v in os.environ.items() if not k.startswith(
            ('LKL_', 'KER_PACKET_', 'KER_NATIVE_', 'KER_RUN_', 'KER_STARTUP_', 'KER_PRELOAD_'))}
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
        metrics.update(stage='application-started', app_started=True, app_pid=app.pid); publish()
        packet_app.close(); mtu_app.close(); close(startup_w)
        startup = b''
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

        while app.poll() is None:
            if received_signal is not None:
                app.terminate()
                try: app.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    app.kill(); app.wait()
                break
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
        close(control_w)
        try: output, _ = worker.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            worker.kill(); worker.communicate()
            raise RuntimeError('secondary packet worker did not exit')
        print(output.decode().rstrip(), file=sys.stderr, flush=True)
        packet_stats = None
        for line in output.decode().splitlines():
            if line.startswith('KER_SESSION_PACKET_DONE '):
                packet_stats = json.loads(line.removeprefix('KER_SESSION_PACKET_DONE '))
        native_stats = None
        for line in startup.decode().splitlines():
            if line.startswith('KER_NATIVE_STATS '):
                native_stats = json.loads(line.removeprefix('KER_NATIVE_STATS '))
                print('KER_SESSION_NATIVE_STATS ' + json.dumps(native_stats), file=sys.stderr, flush=True)
        metrics.update(packet=packet_stats, native=native_stats, worker_code=worker.returncode, app_code=code)
        release(ticket)
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
            if app is not None and app.poll() is None:
                app.terminate()
                try: app.wait(timeout=5)
                except subprocess.TimeoutExpired: app.kill(); app.wait()
            for fd in tuple(owned): close(fd)
            if worker is not None and worker.poll() is None:
                try: worker.wait(timeout=5)
                except subprocess.TimeoutExpired: worker.kill(); worker.wait()
            for endpoint in (packet_worker, packet_app, mtu_worker, mtu_app): endpoint.close()
            connection.close()
            if not completed:
                metrics.update(stage='failed', worker_code=worker.poll() if worker is not None else None,
                    app_code=app.poll() if app is not None else None)
                publish()
        finally:
            signal.signal(signal.SIGTERM, previous_sigterm)
            signal.signal(signal.SIGINT, previous_sigint)
