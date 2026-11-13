#!/usr/bin/env python3
"""Exercise original flip-fail abort followed by same-master epoch-2 retry."""
import argparse
import array
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
import time
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
MODULE_SHA256 = 'd33fd03ea7a9626130a6029a03505dce54f9ee74d863f3d648f31903a0307f14'
LC_SHA256 = 'b6539d6c81cd9fceff3c657493b52d962cd4260e09e2d8dec38ecfe88ecca8ac'
LC_DURATION_SECONDS = 30
LC_PROCESS_SETTLE_SECONDS = 5
TIMING_EVENTS = []
READY_WORDS = {}


def timing(stage, operation=None, deadline_ns=None, **fields):
    TIMING_EVENTS.append(dict(stage=stage, operation=operation,
        monotonic_ns=time.monotonic_ns(), deadline_ns=deadline_ns, **fields))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def require(value, message):
    if not value:
        raise RuntimeError(message)


def wait_new_handoffs(path, offset, deadline_ns):
    """Read only appended broker lines until a new authenticated handoff appears."""
    found = []
    pending = b''
    with path.open('rb', buffering=0) as stream:
        stream.seek(offset)
        while time.monotonic_ns() < deadline_ns:
            chunk = stream.read(65536)
            if chunk:
                pending += chunk
                lines = pending.split(b'\n')
                pending = lines.pop()
                observed_ns = time.monotonic_ns()
                for line in lines:
                    match = re.search(rb'RX_OWNER_PEER_HANDOFF packet=(\d+) .*action=1 ', line)
                    if match:
                        found.append(dict(packet_id=int(match.group(1)),
                            observed_ns=observed_ns, line=line.decode('ascii', 'replace')))
                if found:
                    return found
            else:
                time.sleep(min(.001, max(0, (deadline_ns-time.monotonic_ns())/1e9)))
    return found


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True,
        help='native build containing ker-app, ker-io-worker, and libker-posix')
    parser.add_argument('--adapter-build', type=Path, required=True,
        help='build containing the current C31 fixture, source module, and controller')
    parser.add_argument('--fault-runtime', type=Path, required=True,
        help='dedicated fault-test runtime build containing libfstack.so')
    parser.add_argument('--nginx', type=Path, required=True)
    parser.add_argument('--dpdk-plugin-dir', type=Path, required=True)
    parser.add_argument('--source-nginx-module-source', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True,
        help='host directory retaining all run logs, diagnostics, and receipts')
    parser.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--run-dir', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    require('KER_TEST_SOURCE_ROUTE_DELAY_SWAP' not in os.environ,
        'positive abort/retry profile refuses the unit-test source-route delay flag')
    for field in ('build', 'adapter_build', 'fault_runtime', 'nginx',
            'dpdk_plugin_dir', 'source_nginx_module_source'):
        setattr(args, field, getattr(args, field).resolve(strict=True))
    args.root = args.root.resolve()
    require((args.build / 'ker-app').is_file() and
        (args.build / 'ker-io-worker').is_file() and
        (args.build / 'libker-posix.so').is_file(), 'native build is incomplete')
    require((args.adapter_build / 'ker-socket-broker-rx-owner-relay-fixture').is_file() and
        (args.adapter_build / 'ker-nginx-owner-group-controller').is_file() and
        (args.adapter_build / 'ker-fstack-nginx-owner-activation.so').is_file() and
        (args.adapter_build / 'libker-fstack-nginx-worker-shim.so').is_file() and
        (args.adapter_build / 'libker-socket-preload.so').is_file(),
        'adapter build lacks source-master test artifacts')
    args.fixture = args.adapter_build / 'ker-socket-broker-rx-owner-relay-fixture'
    args.fixture_sha256 = hashlib.sha256(args.fixture.read_bytes()).hexdigest()
    require((args.fault_runtime / 'libfstack.so').is_file(),
        'fault runtime build lacks its dedicated libfstack.so')
    require((args.dpdk_plugin_dir / 'librte_net_tap.so').is_file(),
        'DPDK plugin directory lacks librte_net_tap.so')
    require(hashlib.sha256(args.source_nginx_module_source.read_bytes()).hexdigest() ==
        MODULE_SHA256, 'pinned upstream Nginx event-module source changed')
    lc_probe = ROOT / 'tests/upstream/fstack/tests/integration/common/reload_probes/m4_lc.py'
    require(hashlib.sha256(lc_probe.read_bytes()).hexdigest() == LC_SHA256,
        'pinned original m4_lc.py probe changed')
    require(not args.root.is_relative_to(Path('/dev/shm')),
        '--root must be outside /dev/shm because the test mounts private tmpfs there')
    return args


args = arguments()
if not args.inside:
    args.root.mkdir(parents=True, exist_ok=True)
    run_dir = args.root / f'run-{time.time_ns()}-{os.getpid()}'
    run_dir.mkdir()
    (run_dir / 'launch-evidence.json').write_text(json.dumps({
        'fixture': str(args.fixture),
        'fixture_sha256': args.fixture_sha256,
        'inherited_KER_TEST_SOURCE_ROUTE_DELAY_SWAP': False,
        'KER_C28_TEST_CONTROLLER_TRACE': True,
    }, indent=2) + '\n')
    command = ['unshare', '--user', '--map-auto', '--map-root-user', '--mount',
        '--pid', '--net', '--fork', '--kill-child', '--mount-proc', sys.executable,
        str(Path(__file__).resolve()), '--inside', '--build', str(args.build),
        '--adapter-build', str(args.adapter_build), '--fault-runtime', str(args.fault_runtime),
        '--nginx', str(args.nginx), '--dpdk-plugin-dir', str(args.dpdk_plugin_dir),
        '--source-nginx-module-source', str(args.source_nginx_module_source),
        '--root', str(args.root), '--run-dir', str(run_dir)]
    try:
        with (run_dir / 'process.log').open('wb') as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                timeout=330, check=False)
    except subprocess.TimeoutExpired as error:
        (run_dir / 'launcher-timeout.json').write_text(json.dumps(
            {'timeout_seconds': 330, 'command': command}, indent=2) + '\n')
        raise SystemExit(f'abort/retry integration timed out; evidence retained at {run_dir}') from error
    (run_dir / 'launcher.json').write_text(json.dumps(
        {'returncode': result.returncode, 'command': command}, indent=2) + '\n')
    if result.returncode:
        print(f'FAIL: abort/retry test exited {result.returncode}; evidence: {run_dir}',
            file=sys.stderr)
        print((run_dir / 'process.log').read_text(errors='replace')[-8000:], file=sys.stderr)
        raise SystemExit(result.returncode)
    print(f'PASS: source abort/retry evidence: {run_dir}')
    raise SystemExit(0)

require(args.run_dir is not None, 'internal invocation lacks evidence directory')
libc = ctypes.CDLL(None, use_errno=True)
libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p,
    ctypes.c_char_p, ctypes.c_ulong, ctypes.c_void_p]
require(libc.mount(None, b'/', None, 16384 | (1 << 18), None) == 0,
    'cannot make mount propagation private')
for target, options in ((b'/run', b'mode=0755,size=8m'),
        (b'/dev/shm', b'mode=1777,size=64m')):
    require(libc.mount(b'tmpfs', target, b'tmpfs', 2 | 4, options) == 0,
        f'cannot mount private tmpfs at {target.decode()}')

tree = ROOT
base = load('source_worker_tap', tree / 'tests/posix/native-nginx-companion-tap.py')
base.set_up_network()
peer = load('source_peer_setup', tree / 'tests/posix/native-nginx-peer-source.py')
pair = peer.pair
kr = load('source_worker_kr', tree / 'tools/ker-run.py')
boot = load('source_worker_boot', tree / 'tools/nginx_source_bootstrap_supervisor.py')
lc_checks = load('source_retry_lc_checks',
    tree / 'tests/upstream/fstack/tests/integration/common/reload_checks.py')
namespace_root = Path(tempfile.mkdtemp(prefix='ker-source-abort-retry-', dir='/dev/shm'))
root = namespace_root
build = args.build
adapter_build = args.adapter_build
fault_build = args.fault_runtime
nginx_binary = args.nginx
dpdk_plugin_dir = args.dpdk_plugin_dir
source_module = args.source_nginx_module_source
evidence_dir = args.run_dir
state = evidence_dir
manager = authority = controller = lc_probe = None
lc_output = None
caps = []
channels = []
source_watch = {}
def lc_progress():
    if lc_output is None:
        return []
    text = (evidence_dir / 'm4-lc.log').read_text(errors='replace')
    return [(float(elapsed), int(requests), int(failures)) for elapsed, requests, failures in
        re.findall(r'^LC_PROGRESS elapsed=([0-9.]+) n=([0-9]+) fail=([0-9]+)$',
            text, re.M)]


def wait_lc_progress(predicate, timeout, description):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        require(lc_probe is not None and lc_probe.poll() is None,
            'original m4_lc.py exited before ' + description)
        samples = lc_progress()
        if samples and predicate(samples[-1]):
            return samples[-1]
        time.sleep(.05)
    raise RuntimeError('original m4_lc.py did not prove ' + description)


def execute():
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
    global manager,authority,controller,lc_probe,lc_output
    try:
        worker.start(build / 'ker-io-worker', SimpleNamespace(idle_sleep_us=1000,
            tx_delay_us=0, numa=True, all_multicast=False, promiscuous=None,
            log_dir=None, log_level=None, pcap_dir=None), decision_io.fileno())
        workerfd = os.pidfd_open(worker.process.pid)
        executable = adapter_build / 'ker-socket-broker-rx-owner-relay-fixture'
        apphash = kr.runtime_service.sha256_file(executable)
        require(apphash.hex() == args.fixture_sha256,
            'relay fixture hash changed after launch evidence was recorded')
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
            KER_RX_OWNER_PEER_AUTH_ENABLE='1', KER_RX_OWNER_SOURCE_ROUTE_ENABLE='1',
            KER_C28_TEST_CONTROLLER_TRACE='1',
            KER_RX_OWNER_RELAY_PROBE_TOKEN=secrets.token_hex(12),
            RUNTIME_DIRECTORY=str(root), TMPDIR=str(root))
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
        caprecv,capsend=pair()
        controller=subprocess.Popen([str(adapter_build/'ker-nginx-owner-group-controller'),str(root/'broker.sock'),str(capsend.fileno())],pass_fds=(capsend.fileno(),),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=(root/'controller.stderr').open('wb'),bufsize=0)
        capsend.close()
        require(select.select([caprecv],[],[],10)[0],'controller slot transfer timed out')
        body,anc,flags,_=caprecv.recvmsg(8,socket.CMSG_SPACE(12)+socket.CMSG_SPACE(8))
        creds=[]
        for level,kind,value in anc:
            if kind==socket.SCM_RIGHTS:
                fds=array.array('i');fds.frombytes(value);caps.extend(fds)
            elif kind==socket.SCM_CREDENTIALS:creds.append(struct.unpack('=3i',value))
            else:raise RuntimeError('unexpected slot ancillary')
        require(body==b'N' and not flags and len(caps)==2 and creds==[(controller.pid,os.getuid(),os.getgid())],'invalid original SDK slot transfer')
        # Retain the exact native controller transfer channel for RETRY_SLOT.
        def command(value):
            sent_ns=time.monotonic_ns()
            print('OWNER_GROUP_COMMAND_SEND',value,sent_ns,flush=True)
            controller.stdin.write((value+'\n').encode());controller.stdin.flush()
            result=base.wait_line(controller,'OWNER_GROUP_OK '+value,15)
            print('OWNER_GROUP_COMMAND_ACK',value,time.monotonic_ns(),result,flush=True)
            return result
        def held_cutover():
            line=command('HELD')
            match=re.fullmatch(r'OWNER_GROUP_OK HELD lease=([1-9][0-9]*) phase=([0-9]+) received=([1-9][0-9]*) accepted=0',line)
            require(match is not None,'native cutover is not the same prepared held-SYN state: '+line)
            return dict(lease=int(match[1]),phase=int(match[2]),received=int(match[3]),accepted=0)
        def original_ready_word(watch):
            address=source_address+48+watch['process_slot']*8
            return struct.unpack('=Q',boot.memory(manager.master_pid,address,8))[0]
        def expected_original_ready(watch):
            return (int(watch['source_epoch'])<<32)|int(watch['pid'])
        endpoint=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);endpoint.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1);endpoint.bind(str(root/'source.sock'));endpoint.listen();endpoint.settimeout(8)
        deadline=time.monotonic_ns()+140_000_000_000
        prefix=root/'nginx';(prefix/'logs').mkdir(parents=True);(prefix/'html').mkdir();(prefix/'html/index.html').write_text('original-source-worker\n'); large=bytes(range(256))*1024; (prefix/'html/large.bin').write_bytes(large)
        ini=prefix/'fstack.ini';ini.write_text(f'[ker_socket_broker]\nversion=1\npath={root}/broker.sock\n[dpdk]\ngraceful_reload=1\nlcore_mask=0x3\n')
        module=adapter_build/'ker-fstack-nginx-owner-activation.so'
        ownerenv=dict(KER_NGINX_SOURCE_FIRST_HUP_ENABLE='1',KER_NGINX_SOURCE_ABORT_RETRY_ENABLE='1',FF_FAULT='flip_fail_once',LD_PRELOAD=':'.join(map(str,[adapter_build/'libker-fstack-nginx-worker-shim.so',fault_build/'libfstack.so',adapter_build/'libker-socket-preload.so'])),KER_SOCKET_BROKER_PATH=str(root/'broker.sock'),KER_FSTACK_NGINX_INI=str(ini),KER_FSTACK_RUNTIME_TRACE=str(prefix/'runtime.trace'),KER_NGINX_OWNER_MODULE_PATH=str(module),KER_NGINX_OWNER_MODULE_SHA256=hashlib.sha256(module.read_bytes()).hexdigest(),KER_NGINX_SOURCE_BOOTSTRAP_PATH=str(root/'source.sock'),KER_NGINX_SOURCE_BOOTSTRAP_NONCE=nonce.hex(),KER_NGINX_SOURCE_BOOTSTRAP_EPOCH=str(epoch),KER_NGINX_SOURCE_BOOTSTRAP_DEADLINE_NS=str(deadline),KER_NGINX_SOURCE_BOOTSTRAP_SUPERVISOR_PID=str(os.getpid()),KER_NGINX_SOURCE_BOOTSTRAP_SUPERVISOR_START=str(sup.start_ticks))
        config=prefix/'nginx.conf';exports='\n'.join(f'env {key};' for key in ownerenv)
        config.write_text(f'load_module {module};\ndaemon off; master_process on; worker_processes 1; user root;\nfstack_conf {ini}; timer_resolution 1ms;\npid {prefix}/logs/nginx.pid; error_log {prefix}/logs/error.log notice;\n{exports}\nevents {{ worker_connections 256; use epoll; }}\nhttp {{ access_log off; sendfile off; keepalive_timeout 300; server {{ listen 198.18.0.2:4108 reuseport backlog=16; root {prefix}/html; index index.html; }} }}\n')
        manager=kr.nginx_companion.NginxCompanion(nginx_binary,config,prefix,ownerenv,owner_ready_required=True,source_bootstrap_required=True)
        def started(companion):
            global authority
            actor=lambda process,pidfd:SimpleNamespace(pid=process.pid,pidfd=pidfd,start_ticks=kr.process_start_ticks(process.pid),executable_hash=kr.runtime_service.process_executable_hash(process.pid))
            authority=boot.SourceBootstrapSupervisor.from_companion(companion,actor(app,appfd),actor(worker.process,workerfd),nonce,epoch,deadline)
            for role in [0,1]:
                channel,_=endpoint.accept();channels.append(channel)
                packet,anc,flags,_=channel.recvmsg(boot.RECORD.size+1,socket.CMSG_SPACE(12))
                require(not flags and len(anc)==1 and anc[0][:2]==(socket.SOL_SOCKET,socket.SCM_CREDENTIALS),'invalid source credentials')
                creds=struct.unpack('=3i',anc[0][2]);r=boot.RECORD.unpack(packet);require(r[4]==role,'unexpected source startup order')
                if role==0:authority.reply_slim(channel,packet,creds,control_only=True)
                else:
                    watch,receiver=authority.reply_worker(channel,packet,creds,caps[0],primary_owner)
                    source_watch.update(watch)
                    os.close(caps[0]);caps[0]=-1
                    try:companion.watch_source_worker(watch,receiver)
                    finally:receiver.close()
        manager.start(timeout=20,on_master_started=started)
        require(manager.started and manager.owner_role==0,'source worker READY failed')
        trace=(prefix/'runtime.trace').read_text();require('ff_source_original_ready' not in trace,'original READY published before C31 AUTH')
        source_address=authority.slim_reply[13]
        ready_address=source_address+48+source_watch['process_slot']*8
        require(struct.unpack('=Q',boot.memory(manager.master_pid,ready_address,8))[0]==0,'original READY word changed before C31 AUTH')
        kr.rx_owner_expected_auth(auth_sup,app,appfd,supfd,manager,nonce,epoch,sup.start_ticks)
        kr.rx_owner_relay_auth(primary_app,app,appfd,supfd,manager,nonce,epoch)
        primary_app.close();primary_owner.close()
        until=time.monotonic()+5
        while time.monotonic()<until:
            trace=(prefix/'runtime.trace').read_text()
            if 'ff_source_original_ready' in trace:break
            time.sleep(.01)
        require('ff_source_original_ready' in trace,'authenticated original source READY never published')
        require(struct.unpack('=Q',boot.memory(manager.master_pid,ready_address,8))[0]==manager.owner_pid,'original source READY word not exact epoch0/workerPID')
        command('CONTROL');command('CENSUS0')
        lc_script = tree / 'tests/upstream/fstack/tests/integration/common/reload_probes/m4_lc.py'
        lc_output = (evidence_dir / 'm4-lc.log').open('wb')
        lc_started_ns = time.monotonic_ns()
        lc_probe = subprocess.Popen([sys.executable, str(lc_script),
            '--server', '198.18.0.2', '--port', '4108', '--conns', '12',
            '--interval', '0.1', '--duration', str(LC_DURATION_SECONDS),
            '--fresh', '0.5', '--timeout', '2'],
            stdout=lc_output, stderr=subprocess.STDOUT)
        lc_anchor = wait_lc_progress(lambda sample:
            sample[0] >= 3.0 and sample[1] >= 12 and sample[2] == 0,
            15, 'a healthy 3-second original LC anchor')
        pre_hup_lc = lc_progress()
        require(pre_hup_lc and all(failures == 0 for _, _, failures in pre_hup_lc) and
            'PROBE_ERROR' not in (evidence_dir / 'm4-lc.log').read_text(errors='replace'),
            'strict pre-abort LC progress had failures')
        # Keep a real request active: original drain_start correctly closes idle keepalives.
        conn=socket.socket();conn.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,8192);conn.settimeout(8);conn.connect(('198.18.0.2',4108))
        conn.sendall(b'GET /large.bin HTTP/1.1\r\nHost: source\r\nConnection: close\r\n\r\n')
        response=b''
        while b'\r\n\r\n' not in response:response+=conn.recv(4096)
        header,body=response.split(b'\r\n\r\n',1)
        require(b'200 OK' in header,'initial long response failed')
        old=SimpleNamespace(**{name:getattr(manager,name) for name in ('owner_pid','owner_tid','owner_start','owner_role','owner_slot_device','owner_slot_inode','owner_cookie','owner_pidfd')})
        first_hup_started_ns = time.monotonic_ns()
        timing('first_hup_signal_begin')
        manager.signal_source_hup()
        timing('first_hup_signal_return')
        channel,_=endpoint.accept();channels.append(channel)
        packet,anc,flags,_=channel.recvmsg(boot.RECORD.size+1,socket.CMSG_SPACE(12))
        require(not flags and len(anc)==1 and anc[0][:2]==(socket.SOL_SOCKET,socket.SCM_CREDENTIALS),'invalid candidate credentials')
        watch,receiver=authority.reply_worker(channel,packet,struct.unpack('=3i',anc[0][2]),caps[1],old_owner)
        os.close(caps[1]);caps[1]=-1
        try: candidate=manager.watch_source_candidate(watch,receiver,timeout=15)
        finally:receiver.close()
        print('ACTUAL_SOURCE_CANDIDATE_READY',watch,flush=True)
        command('CENSUS1')
        prepared=kr.rx_owner_source_route_prepare(auth_sup,old_app,app,appfd,supfd,old,candidate,authority.master,nonce,epoch,deadline,secrets.randbits(63) or 1)
        old_owner.close() # retain only supervisor's app-end copy until original candidate termination
        queued=None; gaps=[]; barriers=[]
        first_expected_ready=expected_original_ready(watch)
        first_ready_before=original_ready_word(watch)
        require(first_ready_before==0,
            f'epoch1 original candidate READY published before native queue proof: {first_ready_before:#x}')
        timing('first_cutover_stage_begin')
        command('BEGIN')
        queued=socket.socket();queued.setblocking(False)
        queued.connect_ex(('198.18.0.2',4108))
        command('QUEUED');first_cutover_held=held_cutover()
        first_ready_after=original_ready_word(watch)
        require(first_ready_after==0,
            f'epoch1 original candidate READY changed before ACTIVATE: {first_ready_after:#x}')
        READY_WORDS['epoch1']=dict(before_queue=first_ready_before,after_held=first_ready_after,
            expected_after_activate=first_expected_ready)
        timing('first_cutover_stage_held')
        authority.activate_worker(channel,watch)
        timing('first_candidate_activated')
        def apply(operation, control_deadline):
            nonlocal queued,body
            entered_ns=time.monotonic_ns()
            timing('callback_enter', operation, control_deadline)
            def live():require(time.monotonic_ns()<control_deadline,'source native operation deadline expired')
            live()
            if operation==5:
                timing('held_command_send', operation, control_deadline)
                held=held_cutover();live()
                require(held['lease']==first_cutover_held['lease'],
                    'first PARK changed the pre-activated held-SYN lease')
                ready_word=original_ready_word(watch)
                READY_WORDS['epoch1']['at_park']=ready_word
                require(ready_word==first_expected_ready,
                    f'epoch1 original READY did not match ACTIVATE candidate at PARK: {ready_word:#x}')
                timing('held_command_ack', operation, control_deadline)
            else:
                require(operation==9,'only original pre-flip abort is expected')
                timing('held_command_send', operation, control_deadline)
                print('FIRST_ABORT_PHASE_EVENT', 'held_command_begin', time.monotonic_ns(), flush=True)
                held=held_cutover();live()
                require(held['lease']==first_cutover_held['lease'],
                    'first abort changed the pre-activated held-SYN lease')
                timing('held_command_ack', operation, control_deadline)
                print('FIRST_ABORT_PHASE_EVENT', 'held_command_complete', time.monotonic_ns(), flush=True)
                print('FIRST_ABORT_PHASE_EVENT', 'abort_command_begin', time.monotonic_ns(), flush=True)
                timing('abort_command_send', operation, control_deadline)
                command('ABORT');live()
                timing('abort_command_ack', operation, control_deadline)
                print('FIRST_ABORT_PHASE_EVENT', 'abort_command_complete', time.monotonic_ns(), flush=True)
                # Native adoption requires the original candidate's live
                # admission task; the original source has not killed it yet.
                print('FIRST_ABORT_PHASE_EVENT', 'native_retry_write', time.monotonic_ns(), flush=True)
                controller.stdin.write(f'SOURCE_RETRY_BEFORE {control_deadline}\n'.encode());controller.stdin.flush()
                timing('native_retry_command_sent', operation, control_deadline)
                retry_lines=[]
                while True:
                    live()
                    require(select.select([controller.stdout],[],[],
                        max(0,(control_deadline-time.monotonic_ns())/1e9))[0], 'native bounded RETRY exceeded PARK budget')
                    print('FIRST_ABORT_PHASE_EVENT', 'native_retry_readable', time.monotonic_ns(), flush=True)
                    line=controller.stdout.readline().decode().strip();retry_lines.append(line)
                    timing('native_retry_line', operation, control_deadline, line=line)
                    print('FIRST_ABORT_PHASE_EVENT', 'native_retry_line', time.monotonic_ns(), repr(line), flush=True)
                    require(line and controller.poll() is None,'native bounded RETRY failed '+repr(retry_lines))
                    if line==f'OWNER_GROUP_OK SOURCE_RETRY_BEFORE {control_deadline}':break
                cookies=[int(m[1]) for line in retry_lines if (m:=re.fullmatch(r'SUCCESSOR_COOKIE preserved=([1-9][0-9]*)',line))]
                require(len(cookies)==1,'native RETRY lacks exact preserved listener cookie')
                completed=[m for line in retry_lines if (m:=re.fullmatch(r'SOURCE_RETRY_BEFORE_COMPLETE ns=([0-9]+) deadline=([0-9]+)',line))]
                require(len(completed)==1 and int(completed[0][1])<control_deadline and
                    int(completed[0][2])==control_deadline,
                    'native bounded RETRY did not complete before the original PARK deadline')
                print('NATIVE_RETRY_ADOPTED_BEFORE_SOURCE_ABORT',retry_lines,control_deadline,time.monotonic_ns(),flush=True)
                live()
                status=kr.send_source_route_command(auth_sup,prepared,kr._RX_OWNER_SOURCE_ROUTE_ABORT,prepared.command_sequence+1,operation_deadline_ns=control_deadline)
                require(status==0,'C31 pending ABORT rejected '+str(status));live()
                require(kr.nginx_companion.process_alive(candidate.owner_pidfd),'source candidate died before original failure return')
            barriers.append(dict(operation=operation,deadline=control_deadline,
                entered=entered_ns,completed=time.monotonic_ns()))
            timing('callback_complete', operation, control_deadline)
            if operation==9:return dict(native_retry_cookie=cookies[0])
        for operation in [5,9]:
            master_channel,_=endpoint.accept();channels.append(master_channel)
            packet,anc,flags,_=master_channel.recvmsg(boot.RECORD.size+1,socket.CMSG_SPACE(12))
            require(not flags and len(anc)==1 and anc[0][:2]==(socket.SOL_SOCKET,socket.SCM_CREDENTIALS),'invalid master barrier credentials')
            require(boot.RECORD.unpack(packet)[2]==operation,'source master barrier order mismatch')
            timing('barrier_record_received', operation)
            authority.master_barrier(master_channel,packet,struct.unpack('=3i',anc[0][2]),apply)
            timing('barrier_ack_sent', operation)
        require([item['operation'] for item in barriers] == [5, 9] and
            barriers[0]['deadline'] == barriers[1]['deadline'],
            'first PARK and native-abort phases did not share the original bounded deadline')
        for barrier in barriers:
            require(0 < barrier['deadline'] - barrier['entered'] <= 100_000_000 and
                barrier['entered'] <= barrier['completed'] < barrier['deadline'],
                f'first source abort phase missed its exact bounded deadline: {barrier}')
        until=time.monotonic()+5
        while time.monotonic()<until:
            values=struct.unpack('=8I',boot.memory(manager.master_pid,source_address,32))
            owner,stopped,fsm=struct.unpack('=3I',boot.memory(manager.master_pid,source_address+48+128*8,12))
            if values[3:7]==(1,0,1,0) and (owner,stopped,fsm)==(0,0,0) and not kr.nginx_companion.process_alive(candidate.owner_pidfd):break
            time.sleep(.01)
        require(values[3:7]==(1,0,1,0) and (owner,stopped,fsm)==(0,0,0),'original abort did not restore T0/old generation')
        require(not kr.nginx_companion.process_alive(candidate.owner_pidfd),'aborted source candidate did not exit')
        abort_confirmed_ns = time.monotonic_ns()
        abort_lc_samples = lc_progress()
        require(abort_lc_samples, 'original LC probe lost its progress record at abort')
        abort_lc_sample = abort_lc_samples[-1]
        old_app.close()
        require(manager.owner_pid==old.owner_pid and kr.nginx_companion.process_alive(old.owner_pidfd),'initial source owner changed after abort')
        original_log=(prefix/'logs/error.log').read_text()
        first_error = original_log.find('T2_HANDOVER -> T_ERROR')
        first_reset = original_log.find('T_ERROR -> T0_IDLE')
        abort_message = original_log.find('graceful reload aborted: rx ownership flip failed')
        require(first_hup_started_ns - lc_started_ns >= 3_000_000_000 and
            0 <= first_error < first_reset < abort_message and
            original_log.count('graceful reload aborted: rx ownership flip failed') == 1 and
            'graceful reload complete' not in original_log,
            'original flip_fail_once/T_ERROR/T0 ordering or strict pre-abort anchor failed')
        queued.setblocking(True);queued.settimeout(8)
        queued.sendall(b'GET / HTTP/1.1\r\nHost: source\r\nConnection: close\r\n\r\n');fresh=b''
        while chunk:=queued.recv(4096):fresh+=chunk
        queued.close();require(b'original-source-worker\n' in fresh,'held SYN did not return to original old Linux TCP')
        while chunk:=conn.recv(65536):body+=chunk
        conn.close();require(body==large,'same old original TCP body changed across source flip failure')
        # rt24 keeps its anchor connections open across the failed HUP, so
        # check the rejected listener only here; require all streams drained
        # after the unchanged 30-second LC run closes them below.
        command('CLOSED_REJECTED')
        print('ACTUAL_SOURCE_ORIGINAL_FLIP_ABORT_T0',values,barriers,flush=True)
        manager.retire_aborted_source_candidate()
        def acquire_retry_slot():
            command('RETRY_SLOT')
            require(select.select([caprecv],[],[],10)[0], 'retry FIFO transfer timeout')
            data,anc,flags,_=caprecv.recvmsg(8,socket.CMSG_SPACE(12)+socket.CMSG_SPACE(4))
            rights=[];credentials=[]
            for level,kind,value in anc:
                require(level==socket.SOL_SOCKET,'wrong retry transfer cmsg level')
                if kind==socket.SCM_RIGHTS:
                    fds=array.array('i');fds.frombytes(value);rights.extend(fds)
                elif kind==socket.SCM_CREDENTIALS:credentials.append(struct.unpack('=3i',value))
                else:raise RuntimeError('unexpected retry FIFO ancillary')
            require(data==b'N' and not flags and len(rights)==1 and
                credentials==[(controller.pid,os.getuid(),os.getgid())], 'retry FIFO sender mismatch')
            print('NATIVE_RETRY_SLOT_AFTER_SOURCE_ABORT',authority._native_retry_cookie,os.fstat(rights[0]),flush=True)
            return rights[0]
        caps[1]=authority.prepare_aborted_retry(acquire_retry_slot)
        if caps[0]>=0:os.close(caps[0]);caps[0]=-1
        # A second real old-owner stream spans the retry HUP.
        abort_elapsed = (abort_confirmed_ns - lc_started_ns) / 1e9
        post_abort_lc = wait_lc_progress(lambda sample:
            sample[0] >= abort_elapsed + 5.0 and
            sample[1] > abort_lc_sample[1] and
            sample[2] == abort_lc_sample[2],
            12, 'five seconds of healthy old-generation LC progress after abort')
        post_abort_samples = [sample for sample in lc_progress()
            if abort_lc_sample[0] <= sample[0] <= post_abort_lc[0]]
        require(post_abort_samples and all(sample[2] == abort_lc_sample[2]
            for sample in post_abort_samples),
            'LC traffic failed while waiting after abort and before the retry HUP')
        require('PROBE_ERROR kind=fresh' not in
            (evidence_dir / 'm4-lc.log').read_text(errors='replace'),
            'fresh LC connections failed before retry HUP')
        large=bytes(range(256))*1024;(prefix/'html/large.bin').write_bytes(large)
        conn=socket.socket();conn.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,8192);conn.settimeout(8)
        conn.connect(('198.18.0.2',4108));conn.sendall(b'GET /large.bin HTTP/1.1\r\nHost: source\r\nConnection: close\r\n\r\n')
        response=b''
        while b'\r\n\r\n' not in response:response+=conn.recv(4096)
        header,body=response.split(b'\r\n\r\n',1);require(b'200 OK' in header,'old retry response failed')
        retry_hup_started_ns = time.monotonic_ns()
        require(retry_hup_started_ns - abort_confirmed_ns >= 5_000_000_000,
            'second HUP began before five seconds of post-abort old-owner progress')
        timing('retry_hup_signal_begin')
        manager.signal_source_hup()
        timing('retry_hup_signal_return')
        retry_channel,_=endpoint.accept();channels.append(retry_channel)
        packet,anc,flags,_=retry_channel.recvmsg(boot.RECORD.size+1,socket.CMSG_SPACE(12))
        require(not flags and len(anc)==1 and anc[0][:2]==(socket.SOL_SOCKET,socket.SCM_CREDENTIALS),'invalid retry credentials')
        retry_app,retry_owner=pair(True)
        watch,receiver=authority.reply_worker(retry_channel,packet,struct.unpack('=3i',anc[0][2]),caps[1],retry_owner)
        os.close(caps[1]);caps[1]=-1
        require(watch['source_epoch']==2,'retry is not original source epoch2')
        try:candidate=manager.watch_source_candidate(watch,receiver,timeout=15)
        finally:receiver.close()
        print('ACTUAL_SOURCE_RETRY_READY',watch,flush=True)
        command('CENSUS1')
        prior=prepared
        prepared=kr.rx_owner_source_route_prepare(auth_sup,retry_app,app,appfd,supfd,old,candidate,
            authority.master,nonce,epoch,deadline,prior.operation_id+1,
            command_sequence=prior.command_sequence+1,source_epoch=2,previous_aborted=prior)
        retry_owner.close();retry_app.close()
        retry_expected_ready=expected_original_ready(watch)
        retry_ready_before=original_ready_word(watch)
        require(retry_ready_before!=retry_expected_ready,
            f'epoch2 original candidate READY published before native queue proof: {retry_ready_before:#x}')
        timing('retry_cutover_stage_begin')
        command('BEGIN')
        queued=socket.socket();queued.setblocking(False)
        queued.connect_ex(('198.18.0.2',4108))
        command('QUEUED');retry_cutover_held=held_cutover()
        retry_ready_after=original_ready_word(watch)
        require(retry_ready_after!=retry_expected_ready,
            f'epoch2 original candidate READY changed before ACTIVATE: {retry_ready_after:#x}')
        READY_WORDS['epoch2']=dict(before_queue=retry_ready_before,after_held=retry_ready_after,
            expected_after_activate=retry_expected_ready)
        timing('retry_cutover_stage_held')
        authority.activate_worker(retry_channel,watch)
        timing('retry_candidate_activated')
        def apply_retry(operation,control_deadline):
            nonlocal queued,body
            entered_ns=time.monotonic_ns()
            def live():require(time.monotonic_ns()<control_deadline,'retry immutable native budget expired')
            live()
            if operation==5:
                held=held_cutover();live()
                require(held['lease']==retry_cutover_held['lease'],
                    'retry PARK changed the pre-activated held-SYN lease')
                ready_word=original_ready_word(watch)
                READY_WORDS['epoch2']['at_park']=ready_word
                require(ready_word==retry_expected_ready,
                    f'epoch2 original READY did not match ACTIVATE candidate at PARK: {ready_word:#x}')
            else:
                require(operation==6,'unexpected retry terminal operation')
                held=held_cutover();live()
                require(held['lease']==retry_cutover_held['lease'],
                    'retry COMMIT changed the pre-activated held-SYN lease')
                broker_log=root/'broker.stdout'
                handoff_offset=broker_log.stat().st_size
                attempt_ns=time.monotonic_ns()
                print('RETRY_COMMIT_AFTER_FRAME_BEGIN',attempt_ns,control_deadline,flush=True)
                try:
                    result=kr.send_source_route_command(auth_sup,prepared,
                        kr._RX_OWNER_SOURCE_ROUTE_COMMIT_AFTER_FRAME,
                        prepared.command_sequence+1,operation_deadline_ns=control_deadline)
                except Exception as error:
                    print('RETRY_COMMIT_AFTER_FRAME_ERROR',type(error).__name__,str(error),
                        time.monotonic_ns(),getattr(prepared,'last_command_observation',None),flush=True)
                    raise
                print('RETRY_COMMIT_AFTER_FRAME_RESULT',result,time.monotonic_ns(),
                    getattr(prepared,'last_command_observation',None),flush=True)
                require(result==0,'deferred retry route cut failed '+str(result));live()
                handoffs=wait_new_handoffs(broker_log,handoff_offset,control_deadline)
                live()
                require(handoffs,'no newly appended RX_OWNER_PEER_HANDOFF before native COMMIT')
                gap=dict(source_epoch=2,packet_ids=[item['packet_id'] for item in handoffs],
                    handoff_observed_ns=handoffs[0]['observed_ns'],
                    handoff_line=handoffs[0]['line'],candidate_pid=candidate.owner_pid,
                    old_pid=old.owner_pid)
                gaps.append(gap)
                print('RETRY_GAP_HANDOFF_OBSERVED',gap,flush=True)
                held=held_cutover();live()
                require(held['lease']==retry_cutover_held['lease'] and
                    not select.select([],[queued],[],0)[1],'retry SYN escaped or lease changed')
                command('COMMIT_BEFORE '+str(control_deadline));live()
                manager.promote_source_candidate(timeout=max(.001,(control_deadline-time.monotonic_ns())/1e9));live()
                conn.settimeout(8)
            barriers.append(dict(source_epoch=2,operation=operation,deadline=control_deadline,
                entered=entered_ns,completed=time.monotonic_ns()))
        for operation in [5,6]:
            master_channel,_=endpoint.accept();channels.append(master_channel)
            packet,anc,flags,_=master_channel.recvmsg(boot.RECORD.size+1,socket.CMSG_SPACE(12))
            require(not flags and len(anc)==1 and anc[0][:2]==(socket.SOL_SOCKET,socket.SCM_CREDENTIALS),'invalid retry master credentials')
            require(boot.RECORD.unpack(packet)[2]==operation,'retry master barrier order mismatch')
            authority.master_barrier(master_channel,packet,struct.unpack('=3i',anc[0][2]),apply_retry)
        retry_barriers = [item for item in barriers if item.get('source_epoch') == 2]
        require([item['operation'] for item in retry_barriers] == [5, 6] and
            retry_barriers[0]['deadline'] == retry_barriers[1]['deadline'],
            'retry PARK and COMMIT did not share one immutable deadline')
        for barrier in retry_barriers:
            require(0 < barrier['deadline'] - barrier['entered'] <= 100_000_000 and
                barrier['entered'] <= barrier['completed'] < barrier['deadline'],
                f'retry source phase missed its exact bounded deadline: {barrier}')
        queued.setblocking(True);queued.settimeout(8);queued.sendall(b'GET / HTTP/1.1\r\nHost: source\r\nConnection: close\r\n\r\n');fresh=b''
        while chunk:=queued.recv(4096):fresh+=chunk
        queued.close();require(b'original-source-worker\n' in fresh,'retry fresh TCP failed')
        while chunk:=conn.recv(65536):body+=chunk
        conn.close();require(body==large,'retry old original TCP body corrupted')
        # Old-generation connections must be drained now, but DRAINED1 also
        # covers the new owner's live rt24 keepalives and is checked only
        # after the unchanged 30-second probe closes them below.
        command('DRAINED0')
        until=time.monotonic()+15
        while time.monotonic()<until:
            values=struct.unpack('=8I',boot.memory(manager.master_pid,source_address,32))
            owner,stopped,fsm=struct.unpack('=3I',boot.memory(manager.master_pid,source_address+48+128*8,12))
            if values[3:7]==(2,1,1,0) and (owner,stopped,fsm)==(1,0,0):break
            time.sleep(.01)
        require(values[3:7]==(2,1,1,0) and (owner,stopped,fsm)==(1,0,0),'original retry FSM did not settle')
        before_shutdown_log=(prefix/'logs/error.log').read_text()
        started_workers=set(map(int,re.findall(r'start worker process (\d+)',before_shutdown_log)))
        exited_workers=set(map(int,re.findall(r'worker process (\d+) exited with code 0',
            before_shutdown_log)))
        active_workers=sorted(started_workers-exited_workers)
        require(len(started_workers)==3 and active_workers==[manager.owner_pid],
            f'one configured original source worker was not restored: starts={sorted(started_workers)}, '
            f'exits={sorted(exited_workers)}, active={active_workers}')
        command('OLD_CAPS');command('DROP_PARENT')
        command('RETIRE0')
        until=time.monotonic()+5
        while time.monotonic()<until and 'ff_source_plane_retired' not in (prefix/'runtime.trace').read_text():time.sleep(.01)
        require('ff_source_plane_retired' in (prefix/'runtime.trace').read_text(),'retry admission not retired')
        print('ACTUAL_SOURCE_RETRY_COMMITTED',values,barriers,gaps,flush=True)
        lc_deadline_ns = lc_started_ns + int(
            (LC_DURATION_SECONDS + LC_PROCESS_SETTLE_SECONDS) * 1_000_000_000)
        lc_wait_seconds = max(0.0,
            (lc_deadline_ns - time.monotonic_ns()) / 1_000_000_000)
        require(lc_probe is not None and lc_probe.wait(timeout=lc_wait_seconds) in (0, 1),
            f'original m4_lc.py did not finish by its original {LC_DURATION_SECONDS}-second deadline '
            f'plus {LC_PROCESS_SETTLE_SECONDS}-second settle')
        if lc_output is not None:
            lc_output.close();lc_output=None
        command('DRAINED0');command('DRAINED1')
        lc_log=(evidence_dir/'m4-lc.log').read_text(errors='replace')
        lc_fields=lc_checks.summary('lc',lc_log,'perf')
        require(lc_fields['conns']=='12' and int(lc_fields['reqs'])>0 and
            int(lc_fields['fresh_n'])>0 and lc_fields['fresh_fail']=='0' and
            int(lc_fields['fail'])<=12 and int(lc_fields['reconnects'])<=12,
            f'original rt24 LC oracle failed: {lc_fields}')
        retry_completion = re.findall(
            r'graceful reload complete: generation 1 now active \(took (\d+) ms: handover (\d+) ms, drain (\d+) ms',
            before_shutdown_log)
        require(before_shutdown_log.count('graceful reload complete') == 1 and
            len(retry_completion) == 1 and int(retry_completion[0][2]) <= 15000 and
            before_shutdown_log.count('T5_GOLD_QUIT -> T0_IDLE') == 1,
            'original retry completion, T5->T0, or 15-second drain oracle failed')
        require('graceful reload aborted: rx ownership flip failed' in before_shutdown_log and
            before_shutdown_log.find('graceful reload aborted: rx ownership flip failed') <
            before_shutdown_log.find('graceful reload complete'),
            'original fault abort did not precede the sole successful completion')
        retry_cookie = getattr(authority,'_native_retry_cookie',0)
        require(retry_cookie > 0, 'native listener retry was not acknowledged before original abort')
        authority.stop_slim(channels[0])
        until=time.monotonic()+3
        while not authority.slim_exited() and time.monotonic()<until:time.sleep(.01)
        require(authority.slim_exited(),'source slim failed STOP')
        manager.stop();require(manager.settled and not manager.unresolved,'companion source subtree unresolved')
        for index,fd in enumerate(caps):
            if fd>=0:os.close(fd);caps[index]=-1
        command('RELEASE');command('CLOSED0');command('CLOSED1')
        controller.stdin.write(b'STOP\n');controller.stdin.flush();require(controller.wait(timeout=5)==0,'controller did not stop')
        for fd in caps:
            if fd>=0:os.close(fd)
        caps.clear()
        ready.stop()
        require(select.select([run_sup],[],[],35)[0] and run_sup.recv(64)==b'KER_RUN_STOP\n','native shutdown missing')
        require(service.prepare_worker_shutdown(1.0),'runtime lease remains')
        require(not worker.finish(),'IO owner unresolved')
        status=kr.drain_startup_status(startup_read,status);require(kr.normal_native_shutdown_markers(status),'native shutdown markers missing')
        run_sup.send(b'OK\n');require(app.wait(timeout=10)==0,'native broker failed')
        trace=(prefix/'runtime.trace').read_text()
        original_log=(prefix/'logs/error.log').read_text()
        classifications=re.findall(
            r'SOURCE_OWNER_RELAY packet=(\d+) pid=(\d+) tid=(\d+) status=(\d+) result=(-?\d+)',trace)
        for gap in gaps:
            packet_ids=set(map(str,gap['packet_ids']))
            peer_ids={n for n,pid,tid,status,result in classifications
                if int(pid)==gap['candidate_pid'] and status=='0' and result=='-3'}
            local_ids={n for n,pid,tid,status,result in classifications
                if int(pid)==gap['old_pid'] and status=='0' and result=='0'}
            require(packet_ids <= peer_ids & local_ids,
                f"captured handoff IDs lack actual candidate PEER/old LOCAL callbacks: {sorted(packet_ids)}")
            gap['callback_correlation_verified_after_commit']=True
        native=kr.native_statistics(status)
        io=worker.stats
        require(native and native.get('passive_opens',0)>=1 and native.get('buffers_live')==0 and
            native.get('buffer_allocations')==native.get('buffer_releases')+
                native.get('buffer_shutdown_releases'),
            f'original Linux TCP accounting did not balance: {native}')
        require(io and io.get('rx_decision_settled') and io.get('outstanding')==0 and
            io.get('rx_decision_drops')==0 and io.get('worker_exit_code')==0 and
            not io.get('shutdown_timed_out'), f'native IO did not settle: {io}')
        final_lc_samples=lc_progress()
        receipt=dict(status='PASS_ORIGINAL_RT24_ABORT_RETRY',
            fixture=str(executable),fixture_sha256=args.fixture_sha256,
            inherited_KER_TEST_SOURCE_ROUTE_DELAY_SWAP=False,
            KER_C28_TEST_CONTROLLER_TRACE=True,
            scope=('Actual original m4_lc.py and rt24 traffic/FSM oracle on a one-master '
                'flip_fail_once abort followed by epoch-2 retry. This test does not run '
                'the full original test_graceful_reload.sh shell entrypoint or full matrix.'),
            configured_source_workers=1,initial_anchor=lc_anchor,
            first_hup_started_ns=first_hup_started_ns,abort_confirmed_ns=abort_confirmed_ns,
            retry_hup_started_ns=retry_hup_started_ns,
            old_progress_after_abort=post_abort_lc,
            native_retry_cookie=retry_cookie,lc_summary=lc_fields,
            lc_progress=final_lc_samples,lc_exit_code=lc_probe.returncode,
            worker_starts=sorted(started_workers),worker_exits=sorted(exited_workers),
            active_worker_count=len(active_workers),active_worker_pid=active_workers[0],
            completions=len(retry_completion),drain_ms=int(retry_completion[0][2]),
            t5_to_t0_count=before_shutdown_log.count('T5_GOLD_QUIT -> T0_IDLE'),
            master=manager.master_pid,worker=manager.owner_pid,tid=manager.owner_tid,
            slot=[manager.owner_slot_device,manager.owner_slot_inode],
            ready_cookie=manager.owner_cookie,native=native,io=io,trace=trace,
            barriers=barriers,gap=gaps,body_bytes=len(body),
            body_sha256=hashlib.sha256(body).hexdigest(),source_state=list(values),
            original_log=original_log,timing_events=TIMING_EVENTS,ready_words=READY_WORDS)
        (evidence_dir/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
        print('PASS_ORIGINAL_RT24_ABORT_RETRY '+json.dumps(receipt,sort_keys=True))
    finally:
        diagnostic={str(f):f.read_text(errors='replace') for f in root.rglob('*') if f.is_file() and f.suffix in ['.log','.trace','.stderr','.stdout']}
        if (evidence_dir/'m4-lc.log').exists():
            diagnostic[str(evidence_dir/'m4-lc.log')]=(evidence_dir/'m4-lc.log').read_text(errors='replace')
        diagnostic['source_master_timing_events']=json.dumps(TIMING_EVENTS,indent=2)
        diagnostic['source_master_ready_words']=json.dumps(READY_WORDS,indent=2)
        (evidence_dir/'diagnostic.json').write_text(json.dumps(diagnostic,indent=2))
        if manager is not None and manager.channel is not None:manager.channel.close()
        if authority is not None:authority.close()
        for channel in channels:channel.close()
        for fd in caps:
            if fd>=0:os.close(fd)
        if controller is not None and controller.poll() is None:controller.terminate()
        if app is not None and app.poll() is None:app.terminate()
        if lc_probe is not None and lc_probe.poll() is None:lc_probe.terminate();lc_probe.wait(timeout=3)
        if lc_output is not None:lc_output.close()
execute()
