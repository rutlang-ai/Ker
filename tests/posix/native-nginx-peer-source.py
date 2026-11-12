#!/usr/bin/env python3
"""Two contained original Nginx owners, original classifiers and native TCP.

The private source windows are prepared through upstream reload APIs. This is
not qualification of the complete original same-master reload shell/FSM.
"""
import argparse
import array
from concurrent.futures import ThreadPoolExecutor
import ctypes
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import select
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def require(value, reason):
    if not value:
        raise RuntimeError(reason)


def pair(nonblocking=False):
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    for endpoint in (a, b):
        endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        endpoint.setblocking(not nonblocking)
    return a, b


class Control:
    """Private inherited process channel, pinned run and exact SCM credentials."""
    def __init__(self, fd, peer, token):
        self.channel = socket.socket(fileno=fd)
        self.peer = peer
        self.pidfd = os.pidfd_open(peer)
        self.start = Path(f'/proc/{peer}/stat').read_text().rpartition(')')[2].split()[19]
        self.token = token

    def send(self, stage, **fields):
        self.channel.send(json.dumps(dict(stage=stage, token=self.token, **fields)).encode())

    def receive(self, stage, timeout=40):
        require(select.select([self.channel], [], [], timeout)[0], f'{stage} timed out')
        body, anc, flags, _ = self.channel.recvmsg(65536, socket.CMSG_SPACE(12))
        require(body, f'{stage}: supervisor channel closed; inspect evidence logs')
        require(not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC), 'control truncated')
        require(anc == [(socket.SOL_SOCKET, socket.SCM_CREDENTIALS,
            struct.pack('=3i', self.peer, os.getuid(), os.getgid()))], 'control credentials changed')
        require(not select.select([self.pidfd], [], [], 0)[0], 'control peer died')
        require(Path(f'/proc/{self.peer}/stat').read_text().rpartition(')')[2].split()[19] == self.start,
            'control process identity changed')
        result = json.loads(body)
        require(result.get('token') == self.token and result.get('stage') == stage, f'{stage}: {result}')
        return result


def supervisor(args):
    kr = load('peer_ker_run', ROOT / 'tools/ker-run.py')
    root, build = args.root, args.build
    if args.async_accept_expiry:
        require(len(str(root)) < 64,
            'C28 admission test TMPDIR must stay below the native 64-byte path bound')
        os.environ['RUNTIME_DIRECTORY'] = str(root)
    ctrl = Control(args.control_fd, os.getppid(), args.token)
    nonce, epoch = secrets.token_bytes(16), secrets.randbits(63) or 1
    supfd = os.pidfd_open(os.getpid())
    sup = kr.rx_decision_identity(os.getpid(), supfd)
    decision_app, decision_io = pair(True)
    primary_app, primary_owner = pair(True)
    old_app, old_owner = pair(True)
    auth_sup, auth_app = pair(True)
    item = dict(name='primary', port='net_tap0', tx_offloads='off', queues=1,
        mtu=1500, max_mtu=9000, mbuf_mode='large', rx_lcores=None, rss=False,
        address=ipaddress.IPv4Interface('198.18.0.2/24'), address6=None,
        vip_addresses=[], vip_addresses6=[], eal=(
            f'--lcores=0@{min(os.sched_getaffinity(0))} --no-huge --no-pci --no-shconf '
            f'--no-telemetry --iova-mode=va -m 64 -d {args.dpdk_plugin_dir}/librte_net_tap.so '
            '--vdev=net_tap0,iface=kerpeer,remote=kerlink'))
    worker = kr.AdditionalWorker(item)
    app = service = ready = None
    owners = []
    try:
        worker.start(build / 'ker-io-worker', SimpleNamespace(idle_sleep_us=1000,
            tx_delay_us=0, numa=True, all_multicast=False, promiscuous=None,
            log_dir=None, log_level=None, pcap_dir=None), decision_io.fileno())
        workerfd = os.pidfd_open(worker.process.pid)
        executable = build / 'ker-socket-broker-rx-owner-relay-fixture'
        apphash = kr.runtime_service.sha256_file(executable)
        service = kr.runtime_service.RuntimeServiceSupervisor(root / 'service.sock',
            worker.process, workerfd, kr.process_start_ticks(worker.process.pid),
            kr.runtime_service.process_executable_hash(worker.process.pid), worker.info,
            apphash, hashlib.sha256(b'ker-runtime-service/slim-primary/v1\0' + apphash).digest(),
            worker.stop_write)
        service.start()
        ready = kr.broker_readiness.BrokerReadiness(build / 'ker-io-worker', worker.info,
            service.worker_profile_hash)
        run_sup, run_app = pair()
        startup_read, startup_write = os.pipe2(os.O_CLOEXEC)
        os.set_blocking(startup_read, False)
        env = {key: value for key, value in os.environ.items() if not key.startswith(
            ('LKL_', 'KER_PACKET_', 'KER_RUNTIME_SERVICE_', 'KER_BROKER_', 'KER_RUN_CONTROL_', 'KER_RX_'))}
        env.update(KER_PRELOAD_LIBRARY=str(build / 'libker-posix.so'),
            KER_NATIVE_TX_FEATURES=str(worker.info['tx_offload_features']),
            KER_RUN_FD=str(run_app.fileno()), KER_STARTUP_FD=str(startup_write),
            KER_SHUTDOWN_TIMEOUT_MS='30000', KER_PACKET_CONTROL_FD=str(worker.app_mtu.fileno()),
            KER_PACKET_MAX_MTU='9000', KER_PACKET_FD=str(worker.app_packet.fileno()),
            KER_PACKET_MTU='1500', LKL_HIJACK_NET_IFTYPE='ker-channel',
            LKL_HIJACK_NET_IP='198.18.0.2', LKL_HIJACK_NET_NETMASK_LEN='24',
            LKL_HIJACK_NET_MAC=worker.info['mac'], LKL_HIJACK_OFFLOAD='0',
            KER_RX_DECISION_FD=str(decision_app.fileno()), KER_RX_OWNER_RELAY_FD=str(primary_app.fileno()),
            KER_RX_OWNER_AUTH_FD=str(auth_app.fileno()),
            KER_RX_OWNER_RELAY_SUPERVISOR_PID=str(os.getpid()),
            KER_RX_OWNER_RELAY_SUPERVISOR_START_TICKS=str(sup.start_ticks),
            KER_RX_OWNER_RELAY_NONCE=nonce.hex(), KER_RX_OWNER_RELAY_EPOCH=str(epoch),
            KER_RX_OWNER_PEER_AUTH_ENABLE='1', KER_RX_OWNER_RELAY_SOURCE_ADMISSION_TEST='1',
            KER_RX_OWNER_RELAY_PROBE_TOKEN=secrets.token_hex(12),
            KER_RX_OWNER_RELAY_SOURCE_PEER_TEST='1', KER_RX_OWNER_RELAY_SOURCE_PEER_PORT='41081',
            RUNTIME_DIRECTORY=str(root), TMPDIR=str(root))
        if args.async_accept_expiry:
            env.update(KER_C28_TEST_CONTROLLER_TRACE='1',
                KER_C28_TEST_ACCEPT_POLL_GATE=str(root / 'accept-poll-release'),
                KER_C28_TEST_ACCEPT_POLL_MARKER=str(root / 'accept-poll-pending'))
        env.update(service.env)
        env.update(ready.environment())
        app = subprocess.Popen([str(build / 'ker-app'), str(executable), str(root / 'broker.sock')],
            env=env, pass_fds=(worker.app_packet.fileno(), worker.app_mtu.fileno(), run_app.fileno(),
                startup_write, decision_app.fileno(), primary_app.fileno(), auth_app.fileno(), ready.child_fd()),
            stdout=(root / 'broker.stdout').open('wb'), stderr=(root / 'broker.stderr').open('wb'))
        appfd = os.pidfd_open(app.pid)
        ready.child_started(app, apphash)
        service.bind_actor(app, appfd)
        kr.rx_decision_bootstrap(decision_app, kr.rx_decision_wire.TARGET_CONSUMER,
            kr.rx_decision_identity(app.pid, appfd), sup, supfd, nonce, epoch)
        kr.rx_decision_bootstrap(decision_io, kr.rx_decision_wire.TARGET_WORKER,
            kr.rx_decision_identity(worker.process.pid, workerfd), sup, supfd, nonce, epoch)
        decision_app.close(); decision_io.close(); run_app.close(); auth_app.close()
        os.close(startup_write)
        status = kr.wait_startup_marker(startup_read, b'', b'KER_NATIVE_READY\n', 20, 'native ready')
        status = kr.wait_startup_marker(startup_read, status, b'KER_RX_DECISION_READY\n', 20, 'C31 ready')
        deadline = time.monotonic() + 20
        while not ready.poll_ready():
            require(time.monotonic() < deadline and app.poll() is None, 'broker READY failed')
            time.sleep(.01)
        ctrl.send('BROKER_READY')
        module = build / 'ker-fstack-nginx-owner-activation-alias-test.so'
        for label, transfer, relay, candidate in (
                ('old', args.initial_fd, old_owner, False), ('new', args.candidate_fd, primary_owner, True)):
            prefix = root / label
            (prefix / 'logs').mkdir(parents=True)
            (prefix / 'html').mkdir()
            (prefix / 'html/index.html').write_text(label + '-nginx\n')
            ini = prefix / 'fstack.ini'
            ini.write_text(f'[ker_socket_broker]\nversion=1\npath={root / "broker.sock"}\n\n[dpdk]\ngraceful_reload=0\n')
            ownerenv = dict(LD_PRELOAD=':'.join(str(build / name) for name in (
                    'libker-fstack-nginx-worker-shim.so', 'libfstack.so', 'libker-socket-preload.so')),
                KER_SOCKET_BROKER_PATH=str(root / 'broker.sock'), KER_FSTACK_NGINX_INI=str(ini),
                KER_FSTACK_RUNTIME_TRACE=str(prefix / 'runtime.trace'),
                KER_NGINX_OWNER_MODULE_PATH=str(module),
                KER_NGINX_OWNER_MODULE_SHA256=hashlib.sha256(module.read_bytes()).hexdigest(),
                KER_NGINX_RX_OWNER_RELAY_FD=str(relay.fileno()),
                KER_NGINX_RX_OWNER_RELAY_SUPERVISOR_PID=str(os.getpid()),
                KER_NGINX_RX_OWNER_RELAY_NONCE=nonce.hex(), KER_NGINX_RX_OWNER_RELAY_EPOCH=str(epoch),
                KER_NGINX_SOURCE_PEER_PAIR='1')
            ownerenv.update({'KER_NGINX_SOURCE_ADMISSION_RELAY': '1', 'KER_NGINX_CANDIDATE_SLOT_FD': str(transfer)}
                if candidate else {'KER_NGINX_SOURCE_PEER_OLD': '1', 'KER_NGINX_INITIAL_SLOT_FD': str(transfer)})
            config = prefix / 'nginx.conf'
            exports = '\n'.join(f'env {key};' for key in ownerenv)
            config.write_text(f'''load_module {module};
daemon off; master_process on; worker_processes 1; user root;
fstack_conf "fstack.ini"; timer_resolution 1ms;
pid {prefix}/logs/nginx.pid; error_log {prefix}/logs/error.log notice;
{exports}
events {{ worker_connections 256; use epoll; }}
http {{ access_log off; sendfile off; keepalive_timeout 300; keepalive_requests 100000;
server {{ listen 198.18.0.2:4108 reuseport backlog=16; root {prefix}/html; index index.html; }} }}
''')
            companion = kr.nginx_companion.NginxCompanion(args.nginx, config, prefix,
                ownerenv, owner_ready_required=True, rx_owner_relay_fd=relay.fileno(),
                **({'candidate_slot_transfer_fd': transfer} if candidate else {'initial_slot_transfer_fd': transfer}))
            owners.append(companion)
            companion.start()
            relay.close()
        old, new = owners
        kr.rx_owner_expected_auth(auth_sup, app, appfd, supfd, new, nonce, epoch, sup.start_ticks)
        kr.rx_owner_relay_auth(primary_app, app, appfd, supfd, new, nonce, epoch)
        kr.rx_owner_peer_auth(auth_sup, old_app, app, appfd, supfd, new, old,
            nonce, epoch, time.monotonic_ns() + 120_000_000_000)
        primary_app.close()
        ctrl.send('PAIR_READY', owners=[dict(pid=o.owner_pid, tid=o.owner_tid, role=o.owner_role,
            cookie=o.owner_cookie) for o in owners])
        for label, owner in zip(('OLD', 'NEW'), owners):
            ctrl.receive('STOP_' + label)
            owner.check()
            owner.stop()
            require(owner.settled and not owner.unresolved, 'owner did not settle')
            ctrl.send(label + '_STOPPED')
        ctrl.receive('STOP_RUNTIME')
        ready.stop()
        require(select.select([run_sup], [], [], 35)[0] and run_sup.recv(64) == b'KER_RUN_STOP\n',
            'native shutdown did not reach run STOP')
        require(service.prepare_worker_shutdown(1.0), 'runtime-service lease not released')
        require(not worker.finish(), 'DPDK worker ownership did not settle')
        status = kr.drain_startup_status(startup_read, status)
        require(kr.normal_native_shutdown_markers(status), f'incomplete native shutdown: {status!r}')
        run_sup.send(b'OK\n')
        require(app.wait(timeout=10) == 0, 'C31 broker exit failed')
        native = kr.native_statistics(status)
        if args.async_accept_expiry:
            require(native and native.get('passive_opens') == 2 and
                native.get('buffers_live') == 0 and
                native.get('buffer_allocations') == native.get('buffer_releases') +
                    native.get('buffer_shutdown_releases') and
                worker.stats.get('outstanding') == 0 and
                worker.stats.get('control_eof') is True and
                worker.stats.get('worker_exit_code') == 0 and
                worker.stats.get('shutdown_timed_out') is False and
                worker.stats.get('rx_decision_settled') and
                worker.stats.get('rx_decision_drops') == 0,
                f'uncertain async ACCEPT or control resources did not settle: native={native} io={worker.stats}')
        else:
            require(native and native.get('passive_opens', 0) >= 3, f'no original TCP evidence: {native}')
        ctrl.send('DONE', native=native, io=worker.stats, startup=status.decode())
    finally:
        # Failed runs retain their logs and never produce a successful receipt.
        for owner in reversed(owners):
            if owner.started and not owner.stop_attempted:
                try: owner.stop()
                except Exception as error: print(f'owner cleanup unresolved: {error}', file=sys.stderr)
            owner.close()
        if app is not None and app.poll() is None:
            app.terminate()
            try: app.wait(timeout=5)
            except subprocess.TimeoutExpired: app.kill(); app.wait()
        if worker.process is not None: worker.finish()
        if ready is not None: ready.close()
        if service is not None: service.close()


def inside(args):
    if args.async_accept_expiry:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p,
            ctypes.c_char_p, ctypes.c_ulong, ctypes.c_void_p]
        require(libc.mount(None, b'/', None, 16384 | (1 << 18), None) == 0,
            'private mount propagation failed')
        require(libc.mount(b'tmpfs', b'/run', b'tmpfs', 2 | 4,
            b'mode=0755,size=8m') == 0, 'private /run tmpfs mount failed')
    base = load('peer_tap_helpers', ROOT / 'tests/posix/native-nginx-companion-tap.py')
    probe = load('peer_original_http_probe', ROOT / 'tests/upstream/fstack/tests/integration/common/reload_probes/http_probe.py')
    base.set_up_network()
    root = args.root
    parent, child = pair()
    transfers = [pair(), pair()]
    token = secrets.token_hex(16)
    command = [sys.executable, __file__, '--supervisor', '--build', str(args.build),
        '--nginx', str(args.nginx), '--dpdk-plugin-dir', str(args.dpdk_plugin_dir),
        '--root', str(root), '--source-nginx-module-source', str(args.source_nginx_module_source), '--token', token, '--control-fd', str(child.fileno()),
        '--initial-fd', str(transfers[0][1].fileno()), '--candidate-fd', str(transfers[1][1].fileno())]
    if args.async_accept_expiry:
        command.append('--async-accept-expiry')
    process = subprocess.Popen(command, pass_fds=(child.fileno(), *(p[1].fileno() for p in transfers)),
        stdout=(root / 'supervisor.stdout').open('wb'), stderr=(root / 'supervisor.stderr').open('wb'))
    child.close()
    for p in transfers: p[1].close()
    ctrl = Control(parent.detach(), process.pid, token)
    controller = held = None
    try:
        ctrl.receive('BROKER_READY')
        caprecv, capsend = pair()
        controller = subprocess.Popen([str(args.build / 'ker-nginx-owner-group-controller'),
            str(root / 'broker.sock'), str(capsend.fileno())], pass_fds=(capsend.fileno(),),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0, stderr=(root / 'controller.stderr').open('wb'))
        capsend.close()
        require(select.select([caprecv], [], [], 10)[0], 'slot creation timed out')
        body, ancillary, flags, _ = caprecv.recvmsg(8, socket.CMSG_SPACE(12) + socket.CMSG_SPACE(8))
        caps, creds = [], []
        for level, kind, value in ancillary:
            require(level == socket.SOL_SOCKET, 'invalid slot ancillary')
            if kind == socket.SCM_RIGHTS:
                values = array.array('i'); values.frombytes(value); caps.extend(values)
            elif kind == socket.SCM_CREDENTIALS: creds.append(struct.unpack('=3i', value))
            else: raise RuntimeError('unexpected slot ancillary')
        try:
            require(body == b'N' and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) and len(caps) == 2 and
                creds == [(controller.pid, os.getuid(), os.getgid())], 'invalid group slot authority')
            for index, tag in enumerate((b'KER_INITIAL_SLOT_V1', b'KER_CANDIDATE_SLOT_V1')):
                transfers[index][0].sendmsg([tag], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [caps[index]]))])
        finally:
            for fd in caps: os.close(fd)
            caprecv.close()
        owners = ctrl.receive('PAIR_READY')['owners']

        def command(value):
            controller.stdin.write((value + '\n').encode()); controller.stdin.flush()
            return base.wait_line(controller, 'OWNER_GROUP_OK ' + value, 15)

        def connect(port=0):
            connection = socket.socket()
            connection.settimeout(10)
            connection.bind(('198.18.0.1', port))
            connection.connect(('198.18.0.2', 4108))
            return connection

        def http(connection, label, close=False):
            body = (label + '-nginx\n').encode()
            result = probe.response(connection, expect_eof=close, expect_md5=hashlib.md5(body).hexdigest())
            require(result[0] == len(body) and result[3] and result[4], f'{label} original HTTP oracle failed: {result}')

        command('CONTROL'); command('CENSUS0'); command('CENSUS1')
        held = connect(41081)
        http(held, 'old')
        before = time.monotonic_ns()
        command('BEGIN')
        if args.async_accept_expiry:
            bounded_deadline = time.monotonic_ns() + 500_000_000
            with ThreadPoolExecutor(max_workers=1) as pool:
                queued = pool.submit(connect, 41082)
                command('QUEUED')
                command('HELD')
                require(not queued.done(), 'original SYN completed before selector change')
                marker = root / 'accept-poll-pending'
                release = root / 'accept-poll-release'

                def release_after_deadline():
                    marker_deadline = time.monotonic() + 10
                    while time.monotonic() < marker_deadline and not marker.exists():
                        time.sleep(.001)
                    require(marker.exists(), 'C28 never entered async ACCEPT poll')
                    while time.monotonic_ns() <= bounded_deadline + 20_000_000:
                        time.sleep(.001)
                    release.touch()

                releaser = threading.Thread(target=release_after_deadline, daemon=True)
                releaser.start()
                command('COMMIT_BEFORE_QUARANTINE ' + str(bounded_deadline))
                releaser.join(timeout=12)
                require(not releaser.is_alive() and release.exists(),
                    'async ACK poll gate did not release after the absolute deadline')
                try:
                    uncertain = queued.result(timeout=3)
                    connect_outcome = 'kernel_completed_before_quarantine'
                    uncertain.close()
                except OSError as error:
                    connect_outcome = 'not_completed:' + type(error).__name__
            http(held, 'old')
            after = time.monotonic_ns()
            require(after > bounded_deadline,
                'async quarantine test did not cross the absolute deadline')
            held.shutdown(socket.SHUT_WR)
            require(held.recv(1) == b'', 'old TCP did not close normally')
            held.close(); held = None
            command('RELEASE')
            ctrl.send('STOP_OLD'); ctrl.receive('OLD_STOPPED')
            ctrl.send('STOP_NEW'); ctrl.receive('NEW_STOPPED')
            controller.stdin.write(b'STOP\n'); controller.stdin.flush()
            require(controller.wait(timeout=10) == 0, 'group controller failed after quarantine')
            ctrl.send('STOP_RUNTIME')
            done = ctrl.receive('DONE')
            require(process.wait(timeout=10) == 0, 'supervisor failed after quarantine')
            broker = (root / 'broker.stdout').read_text() + (root / 'broker.stderr').read_text()
            controller_log = (root / 'controller.stderr').read_text()
            held_match = re.search(r'C28_HELD packet_id=(\d+) lease=(\d+) deadline_ns=(\d+)', broker)
            quarantine_match = re.search(
                r'C28_ASYNC_ACCEPT_QUARANTINED phase=(\d+) result=(-\d+) received=(\d+) accepted=(\d+) monotonic_ns=(\d+)',
                controller_log)
            selector_match = re.search(r'C28_SELECTOR_CHANGED monotonic_ns=(\d+)', broker)
            accept_match = re.search(
                r'C28_ACCEPT_BEGIN packet_id=(\d+) sent=1 monotonic_ns=(\d+)', broker)
            require(held_match, 'did not capture original held C28 packet ID')
            require(quarantine_match and tuple(map(int, quarantine_match.groups()[:4])) ==
                (6, -110, 1, 0), f'async C28 did not remain quarantined: {controller_log}')
            require(selector_match and accept_match and
                accept_match.group(1) == held_match.group(1) and
                int(selector_match.group(1)) < int(accept_match.group(2)) < bounded_deadline <
                    int(quarantine_match.group(5)) and
                int(held_match.group(3)) > bounded_deadline,
                'selector change, same held-SYN ACCEPT, absolute expiry, and quarantine did not order correctly')
            require(marker.read_text() == 'C28_ASYNC_ACCEPT_PENDING\n',
                'C28 test gate did not observe pending asynchronous ACK poll')
            native = done.get('native')
            io = done.get('io')
            require(native and native.get('passive_opens') == 2 and
                native.get('buffers_live') == 0 and
                native.get('buffer_allocations') == native.get('buffer_releases') +
                    native.get('buffer_shutdown_releases') and
                io and io.get('outstanding') == 0 and io.get('control_eof') is True and
                io.get('worker_exit_code') == 0 and io.get('shutdown_timed_out') is False and
                io.get('rx_decision_settled') and io.get('rx_decision_drops') == 0,
                f'quarantined SYN or control resources did not settle: native={native} io={io}')
            evidence = dict(status='PASS_ASYNC_OUTCOME_QUARANTINED', owners=owners,
                held_packet_id=int(held_match.group(1)), held_lease=int(held_match.group(2)),
                held_deadline_ns=int(held_match.group(3)), control_deadline_ns=bounded_deadline,
                accept_poll_marker=marker.read_text().strip(),
                quarantine_phase=int(quarantine_match.group(1)),
                quarantine_result=int(quarantine_match.group(2)),
                received_packets=int(quarantine_match.group(3)),
                accepted_packets=int(quarantine_match.group(4)),
                quarantine_monotonic_ns=int(quarantine_match.group(5)),
                selector_changed_monotonic_ns=int(selector_match.group(1)),
                accept_begin_monotonic_ns=int(accept_match.group(2)),
                queued_connect_outcome=connect_outcome,
                queued_connect_semantics='Unknown after timeout: kernel connect can complete before quarantine; no rejection or rollback is claimed.',
                old_body_before_ns=before, old_body_after_ns=after,
                native=native, io=io)
            (root / 'receipt.json').write_text(json.dumps(evidence, indent=2) + '\n')
            print(json.dumps(evidence, sort_keys=True))
            return
        with ThreadPoolExecutor(max_workers=1) as pool:
            queued = pool.submit(connect, 41082)
            command('QUEUED')
            require(not queued.done(), 'queued SYN completed before COMMIT')
            command('COMMIT')
            committed = time.monotonic_ns()
            with queued.result(timeout=10) as connection: http(connection, 'new', True)
        http(held, 'old')
        after = time.monotonic_ns()
        with connect(41083) as connection: http(connection, 'new', True)
        held.shutdown(socket.SHUT_WR)
        require(held.recv(1) == b'', 'old TCP did not close normally')
        held.close(); held = None
        command('DRAINED0'); command('DRAINED1')
        ctrl.send('STOP_OLD'); ctrl.receive('OLD_STOPPED')
        command('RETIRE0'); command('CLOSED0')
        ctrl.send('STOP_NEW'); ctrl.receive('NEW_STOPPED')
        command('CLOSED1'); command('RELEASE')
        controller.stdin.write(b'STOP\n'); controller.stdin.flush()
        require(controller.wait(timeout=10) == 0, 'group controller failed')
        ctrl.send('STOP_RUNTIME')
        done = ctrl.receive('DONE')
        require(process.wait(timeout=10) == 0, 'supervisor failed')
        # Receipt correlates actual callback decisions for the same packet.
        text = (root / 'supervisor.stderr').read_text() + ''.join(
            (root / label / 'logs/error.log').read_text() for label in ('old', 'new'))
        broker = (root / 'broker.stdout').read_text() + (root / 'broker.stderr').read_text()
        decisions = re.findall(r'SOURCE_PEER_CLASSIFIER packet=(\d+) pid=(\d+) tid=(\d+) result=(-?\d+) unchanged=(\d+)', text)
        old, new = owners
        old_local = {p for p, pid, tid, result, unchanged in decisions if
            (int(pid), int(tid), int(result), unchanged) == (old['pid'], old['tid'], 0, '1')}
        new_peer = {p for p, pid, tid, result, unchanged in decisions if
            (int(pid), int(tid), int(result), unchanged) == (new['pid'], new['tid'], -3, '1')}
        forwarded = set(re.findall(r'RX_OWNER_PEER_HANDOFF packet=(\d+) .*action=1 ', broker))
        matched = old_local & new_peer & forwarded
        require(matched, 'no packet traversed both unchanged original classifiers PEER->LOCAL')
        frames = re.findall(r'RX_OWNER_RELAY_PEER_FRAME packet_id=(\d+) source_port=(\d+) dispatcher_result=(-?\d+) frame_hash=(\d+) bytes=(\d+) monotonic_ns=(\d+) frame_hex=([0-9a-f]+)', broker)
        data_handoffs = []
        for packet, port, result, digest, length, stamp, encoded in frames:
            frame = bytes.fromhex(encoded)
            require(len(frame) == int(length) and frame[12:14] == b'\x08\x00' and
                frame[23] == 6 and frame[26:34] == socket.inet_aton('198.18.0.1') +
                    socket.inet_aton('198.18.0.2'), 'invalid captured old native TCP frame')
            tcp = 14 + (frame[14] & 15) * 4
            require(struct.unpack_from('!HH', frame, tcp) == (41081, 4108), 'old tuple changed')
            value = 2166136261
            for byte in frame: value = ((value ^ byte) * 16777619) & 0xffffffff
            require(value == int(digest) and port == '41081' and result == '-3' and packet in matched,
                'old frame was not forwarded unchanged through both original callbacks')
            payload = frame[tcp + (frame[tcp + 12] >> 4) * 4:]
            if payload.startswith(b'GET / HTTP/1.1'):
                data_handoffs.append(dict(packet_id=int(packet), monotonic_ns=int(stamp), frame_hash=value))
        require(any(item['monotonic_ns'] < before for item in data_handoffs) and
            any(committed < item['monotonic_ns'] < after for item in data_handoffs),
            'missing old TCP request payload handoff before and after COMMIT')
        require('SOURCE_PREVIOUS_OWNER_ARMED' in text, 'old original classifier was not armed')
        evidence = dict(status='PASS', owners=owners, handoff_packet_ids=sorted(map(int, matched)),
            old_request_handoffs=data_handoffs, source_nginx_module_sha256=hashlib.sha256(args.source_nginx_module_source.read_bytes()).hexdigest(),
            old_body_before_ns=before, selector_commit_ns=committed, same_old_stream_body_after_ns=after,
            **{k:v for k,v in done.items() if k not in ('stage','token')})
        (root / 'receipt.json').write_text(json.dumps(evidence, indent=2) + '\n')
        print(json.dumps(evidence, sort_keys=True))
    finally:
        if held is not None: held.close()
        for childproc in (controller, process):
            if childproc is not None and childproc.poll() is None:
                childproc.terminate()
                try: childproc.wait(timeout=10)
                except subprocess.TimeoutExpired: childproc.kill(); childproc.wait()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--nginx', type=Path, required=True)
    parser.add_argument('--dpdk-plugin-dir', type=Path, required=True)
    parser.add_argument('--root', type=Path)
    parser.add_argument('--source-nginx-module-source', type=Path, required=True)
    parser.add_argument('--inside', action='store_true')
    parser.add_argument('--supervisor', action='store_true')
    parser.add_argument('--async-accept-expiry', action='store_true',
        help='expire a native asynchronous ACCEPT outcome under the fixed 500 ms deadline')
    for name in ('control-fd', 'initial-fd', 'candidate-fd'):
        parser.add_argument('--' + name, type=int)
    parser.add_argument('--token')
    args = parser.parse_args()
    require(hashlib.sha256(args.source_nginx_module_source.read_bytes()).hexdigest() ==
        'd33fd03ea7a9626130a6029a03505dce54f9ee74d863f3d648f31903a0307f14', 'upstream Nginx source checksum changed')
    if args.supervisor: supervisor(args)
    elif args.inside: inside(args)
    else:
        root = args.root or Path(tempfile.mkdtemp(prefix='ker-peer-source-', dir='/dev/shm'))
        root.mkdir(exist_ok=True)
        if args.async_accept_expiry:
            root = root / f'r{time.time_ns()}-{os.getpid()}'
            root.mkdir()
        print(f'evidence: {root}', flush=True)
        namespace = ['--user', '--map-auto', '--map-root-user', '--mount', '--net', '--fork'] \
            if args.async_accept_expiry else ['-Urn']
        command = ['unshare', *namespace, sys.executable, __file__, '--inside', '--build', str(args.build.resolve()),
            '--nginx', str(args.nginx.resolve()), '--dpdk-plugin-dir', str(args.dpdk_plugin_dir.resolve()),
            '--root', str(root.resolve()), '--source-nginx-module-source', str(args.source_nginx_module_source.resolve())]
        if args.async_accept_expiry:
            command.append('--async-accept-expiry')
        subprocess.run(command, check=True, timeout=180)


if __name__ == '__main__':
    main()
