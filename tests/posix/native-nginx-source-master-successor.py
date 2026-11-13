#!/usr/bin/env python3
"""Exercise two successful original source HUPs and a gen-1 old TCP stream.

Uses the unchanged original rv9 fresh-only probe for its rounds=2 duration.
This is a bounded parity slice, not full rv9/resource-trend or shell coverage.
"""
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
ROUND_COUNT = 2
ROUND_INTERVAL_SECONDS = 15
LC_DURATION_SECONDS = ROUND_COUNT * ROUND_INTERVAL_SECONDS + 90
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
    parser.add_argument('--runtime', type=Path, required=True,
        help='ordinary runtime build containing libfstack.so')
    parser.add_argument('--nginx', type=Path, required=True)
    parser.add_argument('--dpdk-plugin-dir', type=Path, required=True)
    parser.add_argument('--source-nginx-module-source', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True,
        help='host directory retaining all run logs, diagnostics, and receipts')
    parser.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--run-dir', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    require('KER_TEST_SOURCE_ROUTE_DELAY_SWAP' not in os.environ,
        'positive successor profile refuses the unit-test source-route delay flag')
    for field in ('build', 'adapter_build', 'runtime', 'nginx',
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
    require((args.runtime / 'libfstack.so').is_file(),
        'ordinary runtime build lacks its ordinary libfstack.so')
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
        '--adapter-build', str(args.adapter_build), '--runtime', str(args.runtime),
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
        raise SystemExit(f'source-successor integration timed out; evidence retained at {run_dir}') from error
    (run_dir / 'launcher.json').write_text(json.dumps(
        {'returncode': result.returncode, 'command': command}, indent=2) + '\n')
    if result.returncode:
        print(f'FAIL: source-successor test exited {result.returncode}; evidence: {run_dir}',
            file=sys.stderr)
        print((run_dir / 'process.log').read_text(errors='replace')[-8000:], file=sys.stderr)
        raise SystemExit(result.returncode)
    print(f'PASS: source successor evidence: {run_dir}')
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
namespace_root = Path(tempfile.mkdtemp(prefix='ker-source-successor-', dir='/dev/shm'))
root = namespace_root
build = args.build
adapter_build = args.adapter_build
runtime_build = args.runtime
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
        deadline=time.monotonic_ns()+180_000_000_000
        prefix=root/'nginx';(prefix/'logs').mkdir(parents=True);(prefix/'html').mkdir();(prefix/'html/index.html').write_text('original-source-worker\n'); large=bytes(range(256))*4096; (prefix/'html/large.bin').write_bytes(large)
        ini=prefix/'fstack.ini';ini.write_text(f'[ker_socket_broker]\nversion=1\npath={root}/broker.sock\n[dpdk]\ngraceful_reload=1\nlcore_mask=0x3\n')
        module=adapter_build/'ker-fstack-nginx-owner-activation.so'
        ownerenv=dict(KER_NGINX_SOURCE_FIRST_HUP_ENABLE='1',KER_NGINX_SOURCE_SUCCESSOR_ENABLE='1',LD_PRELOAD=':'.join(map(str,[adapter_build/'libker-fstack-nginx-worker-shim.so',runtime_build/'libfstack.so',adapter_build/'libker-socket-preload.so'])),KER_SOCKET_BROKER_PATH=str(root/'broker.sock'),KER_FSTACK_NGINX_INI=str(ini),KER_FSTACK_RUNTIME_TRACE=str(prefix/'runtime.trace'),KER_NGINX_OWNER_MODULE_PATH=str(module),KER_NGINX_OWNER_MODULE_SHA256=hashlib.sha256(module.read_bytes()).hexdigest(),KER_NGINX_SOURCE_BOOTSTRAP_PATH=str(root/'source.sock'),KER_NGINX_SOURCE_BOOTSTRAP_NONCE=nonce.hex(),KER_NGINX_SOURCE_BOOTSTRAP_EPOCH=str(epoch),KER_NGINX_SOURCE_BOOTSTRAP_DEADLINE_NS=str(deadline),KER_NGINX_SOURCE_BOOTSTRAP_SUPERVISOR_PID=str(os.getpid()),KER_NGINX_SOURCE_BOOTSTRAP_SUPERVISOR_START=str(sup.start_ticks))
        config=prefix/'nginx.conf';exports='\n'.join(f'env {key};' for key in ownerenv)
        config.write_text(f'load_module {module};\ndaemon off; master_process on; worker_processes 1; worker_shutdown_timeout 15s; user root;\nfstack_conf {ini}; timer_resolution 1ms;\npid {prefix}/logs/nginx.pid; error_log {prefix}/logs/error.log notice;\n{exports}\nevents {{ worker_connections 256; use epoll; }}\nhttp {{ access_log off; sendfile off; keepalive_timeout 300; server {{ listen 198.18.0.2:4108 reuseport backlog=16; root {prefix}/html; index index.html; }} }}\n')
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
        lc_script=tree/'tests/upstream/fstack/tests/integration/common/reload_probes/m4_lc.py'
        lc_output=(evidence_dir/'m4-lc.log').open('wb')
        lc_started_ns=time.monotonic_ns()
        lc_probe=subprocess.Popen([sys.executable,str(lc_script),'--server','198.18.0.2',
            '--port','4108','--conns','0','--interval','0.5','--duration',str(LC_DURATION_SECONDS),
            '--fresh','0.2','--timeout','2'],stdout=lc_output,stderr=subprocess.STDOUT)
        wait_lc_progress(lambda value:value[0]>=3 and value[2]==0,15,'active original fresh-only probe')
        barriers=[];gaps=[];rounds=[];prepared=None;previous_hup_ns=None
        actor_fields=('owner_pid','owner_tid','owner_start','owner_role','owner_slot_device',
            'owner_slot_inode','owner_cookie','owner_pidfd')
        for source_epoch in (1,2):
            target_generation=1 if source_epoch==1 else 0
            old_generation=1-target_generation
            previous_prepared=prepared
            if source_epoch==2:
                def acquire_successor():
                    controller.stdin.write(b'NEXT\n');controller.stdin.flush()
                    cookie=None;seen=[]
                    until=time.monotonic()+12
                    while time.monotonic()<until:
                        require(select.select([controller.stdout],[],[],max(.001,until-time.monotonic()))[0],
                            'native successor adoption did not reply')
                        line=controller.stdout.readline().decode().strip();seen.append(line)
                        if line.startswith('SUCCESSOR_COOKIE preserved='):cookie=int(line.split('=')[1])
                        if line=='OWNER_GROUP_OK NEXT':break
                        require(controller.poll() is None,'native successor controller exited')
                    require(cookie and seen[-1]=='OWNER_GROUP_OK NEXT','native successor adoption unconfirmed')
                    require(select.select([caprecv],[],[],3)[0],'native successor FIFO missing')
                    marker,ancillary,flags,_=caprecv.recvmsg(8,
                        socket.CMSG_SPACE(12)+socket.CMSG_SPACE(4),
                        getattr(socket,'MSG_CMSG_CLOEXEC',0))
                    descriptors=[];credentials=[];invalid=False
                    try:
                        for level,kind,value in ancillary:
                            if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
                                values=array.array('i')
                                size=len(value)-len(value)%values.itemsize
                                values.frombytes(value[:size]);descriptors.extend(values)
                                invalid=invalid or size!=len(value)
                            elif level==socket.SOL_SOCKET and kind==socket.SCM_CREDENTIALS and len(value)==12:
                                credentials.append(struct.unpack('=3i',value))
                            else:invalid=True
                        print('NATIVE_SUCCESSOR_TRANSFER',dict(marker=marker.hex(),flags=flags,
                            credentials=credentials,descriptor_count=len(descriptors)),flush=True)
                        require(not invalid and not (flags & ~getattr(socket,'MSG_CMSG_CLOEXEC',0)) and
                            marker==b'N' and len(descriptors)==1 and
                            credentials==[(controller.pid,os.getuid(),os.getgid())] and
                            not os.get_inheritable(descriptors[0]),
                            'invalid authenticated native successor FIFO transfer')
                        print('NATIVE_SOURCE_SUCCESSOR_ADOPTED',seen,flush=True)
                        transferred=descriptors.pop();caps.append(transferred)
                        return transferred,cookie
                    finally:
                        for descriptor in descriptors:os.close(descriptor)
                candidate_slot=authority.prepare_successful_successor(acquire_successor)
                candidate_slot_index=len(caps)-1
                source_app,source_owner=pair(True);channels.extend([source_app,source_owner])
            else:
                candidate_slot=caps[1];candidate_slot_index=1
                source_app,source_owner=old_app,old_owner
            conn=socket.socket();conn.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,8192)
            conn.settimeout(8);conn.connect(('198.18.0.2',4108))
            conn.sendall(b'GET /large.bin HTTP/1.1\r\nHost: source\r\nConnection: close\r\n\r\n')
            response=b''
            while b'\r\n\r\n' not in response:
                chunk=conn.recv(4096)
                require(chunk,'original current-generation stream ended before its HTTP header')
                response+=chunk
            header,body=response.split(b'\r\n\r\n',1)
            require(b'200 OK' in header and len(body)<len(large),'original current-generation stream is not active')
            old=SimpleNamespace(**{name:getattr(manager,name) for name in actor_fields})
            if previous_hup_ns is not None:
                next_hup_ns=previous_hup_ns+ROUND_INTERVAL_SECONDS*1_000_000_000
                while time.monotonic_ns()<next_hup_ns:
                    require(lc_probe.poll() is None,'original probe ended before next original HUP')
                    time.sleep(min(.05,(next_hup_ns-time.monotonic_ns())/1e9))
            hup_ns=time.monotonic_ns();previous_hup_ns=hup_ns
            manager.signal_source_hup()
            channel,_=endpoint.accept();channels.append(channel)
            packet,anc,flags,_=channel.recvmsg(boot.RECORD.size+1,socket.CMSG_SPACE(12))
            require(not flags and len(anc)==1 and anc[0][:2]==(socket.SOL_SOCKET,socket.SCM_CREDENTIALS),
                'invalid source successor credentials')
            watch,receiver=authority.reply_worker(channel,packet,struct.unpack('=3i',anc[0][2]),
                candidate_slot,source_owner)
            os.close(candidate_slot);caps[candidate_slot_index]=-1
            require((watch['source_epoch'],watch['generation'])==(source_epoch,target_generation),
                'original source did not alternate its generation')
            try:candidate=manager.watch_source_candidate(watch,receiver,timeout=15)
            finally:receiver.close()
            command('CENSUS1')
            native_cookie=int(command('COOKIE1').split('cookie=')[1])
            operation_id=(secrets.randbits(62) or 1) if previous_prepared is None else previous_prepared.operation_id+1
            sequence=1 if previous_prepared is None else previous_prepared.command_sequence+1
            prepared=kr.rx_owner_source_route_prepare(auth_sup,source_app,app,appfd,supfd,old,candidate,
                authority.master,nonce,epoch,deadline,operation_id,command_sequence=sequence,
                source_epoch=source_epoch,previous_committed=previous_prepared)
            source_app.close();source_owner.close()
            before_word=original_ready_word(watch)
            require(before_word!=expected_original_ready(watch),'original READY appeared before native staging')
            command('BEGIN')
            queued=socket.socket();queued.setblocking(False)
            require(queued.connect_ex(('198.18.0.2',4108)) in (0,115),'queued source SYN failed')
            command('QUEUED')
            held=held_cutover()
            require(not select.select([],[queued],[],0)[1] and original_ready_word(watch)==before_word,
                'native SYN or original READY escaped staging')
            authority.activate_worker(channel,watch)
            round_barriers=[];gap=None
            def apply(operation,control_deadline):
                nonlocal gap,body
                entered=time.monotonic_ns()
                def live():require(time.monotonic_ns()<control_deadline,'original source barrier expired')
                live();same=held_cutover();live()
                require(same['lease']==held['lease'],'native held-SYN lease changed')
                if operation==5:
                    require(original_ready_word(watch)==expected_original_ready(watch),
                        'original READY does not name exact activated source candidate')
                    require(not select.select([],[queued],[],0)[1],'native SYN escaped before PARK')
                    outcome=None
                else:
                    require(operation==6,'unexpected source successor terminal operation')
                    log=root/'broker.stdout';offset=log.stat().st_size
                    result=kr.send_source_route_command(auth_sup,prepared,
                        kr._RX_OWNER_SOURCE_ROUTE_COMMIT_AFTER_FRAME,prepared.command_sequence+1,
                        operation_deadline_ns=control_deadline)
                    live();require(result==0,'C31 source successor cut failed')
                    # The original rv9 probe uses no parked keepalives. Read
                    # already-buffered bytes once on this separate old TCP
                    # stream so the real client emits its window-update ACK
                    # through the new classifier before native selector flip.
                    conn.setblocking(False)
                    try:
                        chunk=conn.recv(65536)
                    except BlockingIOError as error:
                        timing('old_stream_window_progress_unavailable',operation,control_deadline,
                            source_epoch=source_epoch)
                        raise RuntimeError('old TCP has no buffered window progress; native COMMIT remains unconfirmed') from error
                    finally:
                        conn.settimeout(8)
                    require(chunk,'old original TCP stream ended before the handoff gap')
                    body+=chunk
                    timing('old_stream_window_progress',operation,control_deadline,
                        source_epoch=source_epoch,bytes=len(chunk))
                    live()
                    handoffs=wait_new_handoffs(log,offset,control_deadline);live()
                    require(handoffs,'no actual candidate PEER handoff before native selector commit')
                    gap=dict(source_epoch=source_epoch,source_generation=target_generation,
                        packet_ids=[item['packet_id'] for item in handoffs],
                        observed_ns=handoffs[0]['observed_ns'],line=handoffs[0]['line'],
                        candidate_pid=candidate.owner_pid,old_pid=old.owner_pid)
                    require(held_cutover()['lease']==held['lease'] and
                        not select.select([],[queued],[],0)[1],'held SYN lease changed before commit')
                    command('COMMIT_BEFORE '+str(control_deadline));live()
                    manager.promote_source_candidate(timeout=max(.001,(control_deadline-time.monotonic_ns())/1e9))
                    live();outcome={'native_current_cookie':native_cookie}
                round_barriers.append(dict(source_epoch=source_epoch,operation=operation,
                    deadline=control_deadline,entered=entered,completed=time.monotonic_ns()))
                return outcome
            for operation in (5,6):
                master_channel,_=endpoint.accept();channels.append(master_channel)
                packet,anc,flags,_=master_channel.recvmsg(boot.RECORD.size+1,socket.CMSG_SPACE(12))
                require(not flags and len(anc)==1 and anc[0][:2]==(socket.SOL_SOCKET,socket.SCM_CREDENTIALS),
                    'invalid source master credentials')
                require(boot.RECORD.unpack(packet)[2]==operation,'source master barrier order changed')
                authority.master_barrier(master_channel,packet,struct.unpack('=3i',anc[0][2]),apply)
            require(round_barriers[0]['deadline']==round_barriers[1]['deadline'],
                'source PARK and COMMIT renewed their deadline')
            for barrier in round_barriers:
                require(0<barrier['deadline']-barrier['entered']<=100_000_000 and
                    barrier['entered']<=barrier['completed']<barrier['deadline'],
                    'original source operation exceeded its unchanged budget')
            barriers.extend(round_barriers);gaps.append(gap)
            queued.setblocking(True);queued.settimeout(8)
            queued.sendall(b'GET / HTTP/1.1\r\nHost: source\r\nConnection: close\r\n\r\n');fresh=b''
            while chunk:=queued.recv(4096):fresh+=chunk
            queued.close();require(b'original-source-worker\n' in fresh,'new generation original TCP failed')
            while chunk:=conn.recv(65536):body+=chunk
            conn.close();require(body==large,'same original old-generation TCP body changed')
            command('DRAINED0')
            until=time.monotonic()+18
            while time.monotonic()<until:
                values=struct.unpack('=8I',boot.memory(manager.master_pid,source_address,32))
                markers=struct.unpack('=3I',boot.memory(manager.master_pid,source_address+48+128*8,12))
                if values[3:7]==(source_epoch,target_generation,target_generation,0) and markers==(target_generation,0,0):break
                time.sleep(.01)
            require(values[3:7]==(source_epoch,target_generation,target_generation,0) and
                markers==(target_generation,0,0),'original source successful round did not settle')
            command('RETIRE0')
            until=time.monotonic()+5
            marker=f'ff_source_plane_retired pid={manager.owner_pid}'
            while time.monotonic()<until and marker not in (prefix/'runtime.trace').read_text():time.sleep(.01)
            require(marker in (prefix/'runtime.trace').read_text(),'real source candidate admission did not retire')
            log=(prefix/'logs/error.log').read_text()
            completed=re.findall(r'graceful reload complete: generation ([01]) now active .*?drain ([0-9]+) ms',log)
            require(len(completed)==source_epoch and int(completed[-1][0])==target_generation,
                'original completion count or generation changed')
            rounds.append(dict(source_epoch=source_epoch,generation=target_generation,old_pid=old.owner_pid,
                candidate_pid=manager.owner_pid,body_sha256=hashlib.sha256(body).hexdigest(),
                native_listener_cookie=native_cookie,drain_ms=int(completed[-1][1]),hup_ns=hup_ns))
            print('ACTUAL_ORIGINAL_SUCCESSOR_ROUND',rounds[-1],flush=True)
        until=lc_started_ns+(LC_DURATION_SECONDS+LC_PROCESS_SETTLE_SECONDS)*1_000_000_000
        require(lc_probe.wait(timeout=max(0,(until-time.monotonic_ns())/1e9))==0,
            'unchanged original rv9 fresh probe failed')
        lc_output.close();lc_output=None
        lc_fields=lc_checks.summary('lc',(evidence_dir/'m4-lc.log').read_text())
        require(lc_fields['conns']=='0' and lc_fields['fresh_fail']=='0' and int(lc_fields['fresh_n'])>0,
            'original rv9 fresh-only oracle failed')
        command('DRAINED0');command('DRAINED1');command('OLD_CAPS');command('DROP_PARENT')
        original_log=(prefix/'logs/error.log').read_text()
        starts=set(map(int,re.findall(r'start worker process (\d+)',original_log)))
        exits=set(map(int,re.findall(r'worker process (\d+) exited with code 0',original_log)))
        require(len(starts)==3 and starts-exits=={manager.owner_pid} and
            original_log.count('T5_GOLD_QUIT -> T0_IDLE')==2 and
            'graceful reload aborted' not in original_log,'original source workers/FSM did not settle twice')
        authority.stop_slim(channels[0])
        until=time.monotonic()+3
        while not authority.slim_exited() and time.monotonic()<until:time.sleep(.01)
        require(authority.slim_exited(),'source slim STOP failed')
        manager.stop();require(manager.settled and not manager.unresolved,'source companion subtree unresolved')
        original_log=(prefix/'logs/error.log').read_text()
        final_starts=set(map(int,re.findall(r'start worker process (\d+)',original_log)))
        final_exits=set(map(int,re.findall(r'worker process (\d+) exited with code 0',original_log)))
        require(final_starts==starts and final_exits==starts and
            not re.search(r'worker process \d+ exited on signal',original_log),
            'original source worker shutdown was not normal')
        for index,fd in enumerate(caps):
            if fd>=0:os.close(fd);caps[index]=-1
        command('RELEASE');command('CLOSED0');command('CLOSED1')
        controller.stdin.write(b'STOP\n');controller.stdin.flush();require(controller.wait(timeout=5)==0,'native controller failed')
        ready.stop()
        require(select.select([run_sup],[],[],35)[0] and run_sup.recv(64)==b'KER_RUN_STOP\n','native shutdown missing')
        require(service.prepare_worker_shutdown(1.0) and not worker.finish(),'native ownership did not settle')
        status=kr.drain_startup_status(startup_read,status)
        require(kr.normal_native_shutdown_markers(status),'normal native shutdown markers missing')
        run_sup.send(b'OK\n');require(app.wait(timeout=10)==0,'native runtime failed')
        trace=(prefix/'runtime.trace').read_text()
        classifications=re.findall(r'SOURCE_OWNER_RELAY packet=(\d+) pid=(\d+) tid=(\d+) status=(\d+) result=(-?\d+)',trace)
        for gap in gaps:
            ids=set(map(str,gap['packet_ids']))
            peers={n for n,pid,tid,status,result in classifications if int(pid)==gap['candidate_pid'] and status=='0' and result=='-3'}
            locals_={n for n,pid,tid,status,result in classifications if int(pid)==gap['old_pid'] and status=='0' and result=='0'}
            require(ids<=peers&locals_,'successor gap lacks exact original candidate PEER/old LOCAL callbacks')
        native=kr.native_statistics(status);io=worker.stats
        require(native and native['buffers_live']==0 and
            native['buffer_allocations']==native['buffer_releases']+native['buffer_shutdown_releases'],
            'native buffers not balanced')
        require(io and io['rx_decision_settled'] and io['outstanding']==0 and io['rx_decision_drops']==0 and
            io['worker_exit_code']==0 and not io['shutdown_timed_out'],'native packet ownership not settled')
        receipt=dict(status='PASS_ACTUAL_SOURCE_TWO_SUCCESSFUL_HUPS',
            scope='Two-round rv9 parity slice using unchanged original fresh probe; not full100-round rv9/resource trend or original shell.',
            fixture_sha256=args.fixture_sha256,rounds=rounds,barriers=barriers,gaps=gaps,
            original_probe_duration=LC_DURATION_SECONDS,lc_summary=lc_fields,source_state=list(values),
            native=native,io=io,original_log=original_log,trace=trace,worker_starts=sorted(starts),
            worker_exits_before_stop=sorted(exits),worker_exits=sorted(final_exits),
            active_worker_pid_before_stop=manager.owner_pid)
        (evidence_dir/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
        print('PASS_ACTUAL_SOURCE_TWO_SUCCESSFUL_HUPS',json.dumps(receipt,sort_keys=True),flush=True)
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
