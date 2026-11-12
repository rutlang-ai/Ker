#!/usr/bin/env python3
"""Qualify one bounded first HUP on a real original Nginx master.

This exercises actual source bootstrap, original Linux TCP, and the first
same-master reload. It does not qualify repeated reloads or full-shell policy.
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
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
SOURCE_NGINX_SHA256 = 'd33fd03ea7a9626130a6029a03505dce54f9ee74d863f3d648f31903a0307f14'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def require(value, message):
    if not value:
        raise RuntimeError(message)


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--nginx', type=Path, required=True)
    parser.add_argument('--dpdk-plugin-dir', type=Path, required=True)
    parser.add_argument('--source-nginx-module-source', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True,
        help='host directory where this run retains logs, receipt, and artifacts')
    parser.add_argument('--mode', choices=('first-hup', 'shared-budget-expiry'),
        default='first-hup', help='run the positive first HUP or expired-COMMIT containment case')
    parser.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--run-dir', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    args.build = args.build.resolve(strict=True)
    args.nginx = args.nginx.resolve(strict=True)
    args.dpdk_plugin_dir = args.dpdk_plugin_dir.resolve(strict=True)
    args.source_nginx_module_source = args.source_nginx_module_source.resolve(strict=True)
    args.root = args.root.resolve()
    require((args.build / 'ker-io-worker').is_file() and
        (args.build / 'ker-socket-broker-rx-owner-relay-fixture').is_file() and
        (args.build / 'ker-nginx-owner-group-controller').is_file(),
        'build directory lacks source-master test binaries')
    require((args.dpdk_plugin_dir / 'librte_net_tap.so').is_file(),
        'DPDK plugin directory lacks librte_net_tap.so')
    require(hashlib.sha256(args.source_nginx_module_source.read_bytes()).hexdigest() ==
        SOURCE_NGINX_SHA256, 'pinned upstream Nginx event module source changed')
    require(not args.root.is_relative_to(Path('/dev/shm')),
        '--root must be outside /dev/shm because the test uses a private /dev/shm mount')
    return args


args = arguments()
if not args.inside:
    args.root.mkdir(parents=True, exist_ok=True)
    run_dir = args.root / f'run-{time.time_ns()}-{os.getpid()}'
    run_dir.mkdir()
    command = ['unshare', '--user', '--map-auto', '--map-root-user', '--mount',
        '--pid', '--net', '--fork', '--kill-child', '--mount-proc', sys.executable,
        str(Path(__file__).resolve()), '--inside', '--build', str(args.build),
        '--nginx', str(args.nginx), '--dpdk-plugin-dir', str(args.dpdk_plugin_dir),
        '--source-nginx-module-source', str(args.source_nginx_module_source),
        '--root', str(args.root), '--mode', args.mode, '--run-dir', str(run_dir)]
    try:
        with (run_dir / 'process.log').open('wb') as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                timeout=300, check=False)
    except subprocess.TimeoutExpired as error:
        (run_dir / 'launcher-timeout.json').write_text(json.dumps(
            {'timeout_seconds': 300, 'command': command}, indent=2) + '\n')
        raise SystemExit('source-master HUP integration test timed out; evidence retained at ' + str(run_dir)) from error
    (run_dir / 'launcher.json').write_text(json.dumps(
        {'returncode': result.returncode, 'command': command}, indent=2) + '\n')
    if result.returncode:
        print(f'FAIL: {args.mode} test exited {result.returncode}; evidence: {run_dir}', file=sys.stderr)
        if (run_dir / 'process.log').exists():
            print((run_dir / 'process.log').read_text(errors='replace')[-8000:], file=sys.stderr)
        raise SystemExit(result.returncode)
    print(f'PASS: {args.mode} evidence: {run_dir}')
    raise SystemExit(0)

require(args.run_dir is not None, 'internal test invocation lacks evidence directory')
libc = ctypes.CDLL(None, use_errno=True)
libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p,
    ctypes.c_char_p, ctypes.c_ulong, ctypes.c_void_p]
require(libc.mount(None, b'/', None, 16384 | (1 << 18), None) == 0,
    'cannot make mount propagation private')
for target, options in ((b'/run', b'mode=0755,size=8m'),
        (b'/dev/shm', b'mode=1777,size=64m')):
    require(libc.mount(b'tmpfs', target, b'tmpfs', 2 | 4, options) == 0,
        f'cannot mount private tmpfs at {target.decode()}')

base = load('source_worker_tap', ROOT / 'tests/posix/native-nginx-companion-tap.py')
base.set_up_network()
peer = load('source_peer_setup', ROOT / 'tests/posix/native-nginx-peer-source.py')
pair = peer.pair
kr = load('source_worker_kr', ROOT / 'tools/ker-run.py')
boot = load('source_worker_boot', ROOT / 'tools/nginx_source_bootstrap_supervisor.py')
root = Path(tempfile.mkdtemp(prefix='ker-source-master-', dir='/dev/shm'))
build = args.build
dpdk_plugin_dir = args.dpdk_plugin_dir
nginx_binary = args.nginx
source_module = args.source_nginx_module_source
evidence_dir = args.run_dir
manager=authority=controller=None;caps=[];channels=[];source_watch={}
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
    global manager,authority,controller
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
            KER_RX_OWNER_PEER_AUTH_ENABLE='1', KER_RX_OWNER_SOURCE_ROUTE_ENABLE='1',
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
        controller=subprocess.Popen([str(build/'ker-nginx-owner-group-controller'),str(root/'broker.sock'),str(capsend.fileno())],pass_fds=(capsend.fileno(),),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=(root/'controller.stderr').open('wb'),bufsize=0)
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
        caprecv.close()
        def command(value):
            controller.stdin.write((value+'\n').encode());controller.stdin.flush()
            return base.wait_line(controller,'OWNER_GROUP_OK '+value,15)
        endpoint=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);endpoint.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1);endpoint.bind(str(root/'source.sock'));endpoint.listen();endpoint.settimeout(8)
        deadline=time.monotonic_ns()+140_000_000_000
        prefix=root/'nginx';(prefix/'logs').mkdir(parents=True);(prefix/'html').mkdir();(prefix/'html/index.html').write_text('original-source-worker\n'); large=bytes(range(256))*32768; (prefix/'html/large.bin').write_bytes(large)
        ini=prefix/'fstack.ini';ini.write_text(f'[ker_socket_broker]\nversion=1\npath={root}/broker.sock\n[dpdk]\ngraceful_reload=1\nlcore_mask=0x3\n')
        module=build/'ker-fstack-nginx-owner-activation.so'
        ownerenv=dict(KER_NGINX_SOURCE_FIRST_HUP_ENABLE='1',LD_PRELOAD=':'.join(str(build/name) for name in ['libker-fstack-nginx-worker-shim.so','libfstack.so','libker-socket-preload.so']),KER_SOCKET_BROKER_PATH=str(root/'broker.sock'),KER_FSTACK_NGINX_INI=str(ini),KER_FSTACK_RUNTIME_TRACE=str(prefix/'runtime.trace'),KER_NGINX_OWNER_MODULE_PATH=str(module),KER_NGINX_OWNER_MODULE_SHA256=hashlib.sha256(module.read_bytes()).hexdigest(),KER_NGINX_SOURCE_BOOTSTRAP_PATH=str(root/'source.sock'),KER_NGINX_SOURCE_BOOTSTRAP_NONCE=nonce.hex(),KER_NGINX_SOURCE_BOOTSTRAP_EPOCH=str(epoch),KER_NGINX_SOURCE_BOOTSTRAP_DEADLINE_NS=str(deadline),KER_NGINX_SOURCE_BOOTSTRAP_SUPERVISOR_PID=str(os.getpid()),KER_NGINX_SOURCE_BOOTSTRAP_SUPERVISOR_START=str(sup.start_ticks))
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
        # Keep a real request active: original drain_start correctly closes idle keepalives.
        conn=socket.socket();conn.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,8192);conn.settimeout(8);conn.connect(('198.18.0.2',4108))
        conn.sendall(b'GET /large.bin HTTP/1.1\r\nHost: source\r\nConnection: close\r\n\r\n')
        response=b''
        while b'\r\n\r\n' not in response:response+=conn.recv(4096)
        header,body=response.split(b'\r\n\r\n',1)
        require(b'200 OK' in header,'initial long response failed')
        old=SimpleNamespace(**{name:getattr(manager,name) for name in ('owner_pid','owner_tid','owner_start','owner_role','owner_slot_device','owner_slot_inode','owner_cookie','owner_pidfd')})
        old_pid = old.owner_pid
        manager.signal_source_hup()
        channel,_=endpoint.accept();channels.append(channel)
        packet,anc,flags,_=channel.recvmsg(boot.RECORD.size+1,socket.CMSG_SPACE(12))
        require(not flags and len(anc)==1 and anc[0][:2]==(socket.SOL_SOCKET,socket.SCM_CREDENTIALS),'invalid candidate credentials')
        watch,receiver=authority.reply_worker(channel,packet,struct.unpack('=3i',anc[0][2]),caps[1],old_owner)
        os.close(caps[1]);caps[1]=-1
        try: candidate=manager.watch_source_candidate(watch,receiver,timeout=15)
        finally:receiver.close()
        candidate_pid = watch['pid']
        print('ACTUAL_SOURCE_CANDIDATE_READY',watch,flush=True)
        command('CENSUS1')
        prepared=kr.rx_owner_source_route_prepare(auth_sup,old_app,app,appfd,supfd,old,candidate,authority.master,nonce,epoch,deadline,secrets.randbits(63) or 1)
        old_app.close();old_owner.close()
        authority.activate_worker(channel,watch)
        queued=None; gaps=[]; barriers=[]; route_commit_ns=None; native_commit_ns=None
        correlated_gap_ids=[]; correlated_gap_observed_ns=None; expiry_held_status=None
        def apply(operation, control_deadline):
            nonlocal queued,body,route_commit_ns,native_commit_ns,correlated_gap_ids,correlated_gap_observed_ns,expiry_held_status
            entered_ns=time.monotonic_ns()
            def live():require(time.monotonic_ns()<control_deadline,'source native operation deadline expired')
            live()
            if operation==5:
                command('BEGIN');live()
                queued=socket.socket();queued.setblocking(False);queued.connect_ex(('198.18.0.2',4108))
                command('QUEUED')
                if args.mode == 'shared-budget-expiry':
                    controller.stdin.write(b'HELD\n');controller.stdin.flush()
                    expiry_held_status=base.wait_line(controller,'CUTOVER_HELD',15)
                    base.wait_line(controller,'OWNER_GROUP_OK HELD',15)
                else:
                    command('HELD')
                live()
            else:
                # Snapshot PEER traffic before the C31 route swap. A buffered
                # response read is not sufficient evidence of post-swap routing.
                broker_path=root/'broker.stdout'
                before_handoff_ids=set(re.findall(
                    r'RX_OWNER_PEER_HANDOFF packet=(\d+) .*action=1 ',
                    broker_path.read_text(errors='replace')))
                while True:
                    status=kr.send_source_route_command(auth_sup,prepared,kr._RX_OWNER_SOURCE_ROUTE_COMMIT,prepared.command_sequence+1,operation_deadline_ns=control_deadline)
                    if status==0:
                        route_commit_ns=time.monotonic_ns()
                        break
                    require(status==-16,'source route COMMIT rejected '+str(status));live()
                source_trace=prefix/'runtime.trace'
                while time.monotonic_ns()<control_deadline:
                    live()
                    readable,_,_=select.select([conn],[],[],
                        max(0,(control_deadline-time.monotonic_ns())/1e9))
                    if readable:
                        chunk=conn.recv(65536)
                        require(chunk,'old active TCP closed during PEER handoff')
                        body+=chunk
                        gaps.append(dict(bytes=len(chunk),at=time.monotonic_ns(),
                            after_route_commit=True))
                    broker_log=broker_path.read_text(errors='replace')
                    trace_log=source_trace.read_text(errors='replace')
                    handoffs=set(re.findall(
                        r'RX_OWNER_PEER_HANDOFF packet=(\d+) .*action=1 ',broker_log))
                    classifications=re.findall(
                        r'SOURCE_OWNER_RELAY packet=(\d+) pid=(\d+) tid=(\d+) status=(\d+) result=(-?\d+)',
                        trace_log)
                    candidate_peer={packet for packet,pid,tid,relay_status,result in classifications
                        if int(pid)==candidate_pid and relay_status=='0' and result=='-3'}
                    old_local={packet for packet,pid,tid,relay_status,result in classifications
                        if int(pid)==old_pid and relay_status=='0' and result=='0'}
                    correlated_gap_ids=sorted((handoffs-before_handoff_ids) & candidate_peer & old_local,
                        key=int)
                    if correlated_gap_ids:
                        break
                    if not readable:
                        break
                    time.sleep(.001)
                require(correlated_gap_ids,
                    'no new post-swap PEER packet was classified by candidate and LOCAL by old owner before native COMMIT')
                correlated_gap_observed_ns=time.monotonic_ns()
                gaps.append(dict(packet_ids=list(map(int,correlated_gap_ids)),
                    observed_ns=correlated_gap_observed_ns,before_native_commit=True))
                # The native original SYN queue must still hold the fresh SYN.
                command('HELD');live()
                require(not select.select([],[queued],[],0)[1],'fresh SYN escaped before native commit')
                conn.settimeout(max(.001,(control_deadline-time.monotonic_ns())/1e9))
                chunk=conn.recv(65536);require(chunk,'old active response stopped during PEER handoff');body+=chunk
                conn.settimeout(8)
                gaps.append(dict(bytes=len(chunk),at=time.monotonic_ns()))
                live();command('COMMIT_BEFORE '+str(control_deadline));live()
                native_commit_ns=time.monotonic_ns()
                manager.promote_source_candidate(timeout=max(.001,(control_deadline-time.monotonic_ns())/1e9));live()
            barriers.append(dict(operation=operation,deadline=control_deadline,
                entered=entered_ns,completed=time.monotonic_ns()))
        for operation in [5,6]:
            master_channel,_=endpoint.accept();channels.append(master_channel)
            packet,anc,flags,_=master_channel.recvmsg(boot.RECORD.size+1,socket.CMSG_SPACE(12))
            require(not flags and len(anc)==1 and anc[0][:2]==(socket.SOL_SOCKET,socket.SCM_CREDENTIALS),'invalid master barrier credentials')
            require(boot.RECORD.unpack(packet)[2]==operation,'source master barrier order mismatch')
            if args.mode == 'shared-budget-expiry' and operation == 6:
                expiry=boot.RECORD.unpack(packet)[28]
                require(bool(barriers) and expiry==barriers[0]['deadline'],
                    'expired COMMIT changed the immutable PARK deadline')
                source=struct.unpack('=8I',boot.memory(manager.master_pid,source_address,32))
                state_before=struct.unpack('=3I',boot.memory(
                    manager.master_pid,source_address+48+128*8,12))
                require(source[3:7]==(1,0,1,1) and state_before==(1,0,2) and
                    manager.owner_pid==old_pid and expiry_held_status is not None and
                    re.search(r'CUTOVER_HELD phase=1 received=1 accepted=0',expiry_held_status),
                    'negative control did not start from original released T2')
                conn.close()
                queued.close()
                time.sleep(max(0,(expiry-time.monotonic_ns())/1e9)+.03)
                rejected=None
                try:
                    authority.master_barrier(master_channel,packet,
                        struct.unpack('=3i',anc[0][2]),apply)
                except (RuntimeError,ProcessLookupError,PermissionError,FileNotFoundError) as error:
                    rejected=str(error)
                observed_ns=time.monotonic_ns()
                require(observed_ns>=expiry and rejected and
                    prepared.command_sequence==1 and len(barriers)==1 and
                    route_commit_ns is None and native_commit_ns is None,
                    'expired COMMIT applied C31 route or native selector operation')
                require(select.select([manager.master_pidfd],[],[],3)[0],
                    'original master did not fail closed after expired COMMIT')
                for bound_channel in channels:
                    bound_channel.close()
                containment_error=None
                try:
                    manager.stop(timeout=15)
                except (RuntimeError,TimeoutError) as error:
                    containment_error=str(error)
                controller.stdin.write(b'QUARANTINED\n');controller.stdin.flush()
                command_result=base.wait_line(controller,'SOURCE_EXPIRED_QUARANTINED',15)
                base.wait_line(controller,'OWNER_GROUP_OK QUARANTINED',15)
                require(re.search(r'SOURCE_EXPIRED_QUARANTINED phase=6 result=-\d+ received=\d+ accepted=0',
                    command_result), 'native selector did not report read-only quarantined state')
                helper_status=manager.helper.wait(timeout=5)
                require(helper_status==1 and containment_error,
                    'expired source handover did not report expected helper error exit')
                error_match=re.search(r'Nginx containment unresolved: (\(.*\))',
                    containment_error)
                require(error_match is not None,'missing structured source containment error health')
                import ast
                error_fields=ast.literal_eval(error_match.group(1))
                require(len(error_fields)==6 and error_fields[2]==manager.master_pid and
                    error_fields[3]==0 and error_fields[4]==manager.master_start,
                    f'source containment error reported unresolved children or wrong master: {error_fields!r}')
                source_pidfds=[('old-worker',old_pid,old.owner_pidfd),
                    ('candidate-worker',candidate_pid,candidate.owner_pidfd),
                    ('slim-primary',authority.slim_pid,authority.slim_pidfd),
                    ('master',manager.master_pid,manager.master_pidfd)]
                for label,actor_pid,pidfd in source_pidfds:
                    require(select.select([pidfd],[],[],3)[0],
                        f'{label} pidfd remained live after explicit grant withdrawal')
                dead_actor_pidfds=[{'actor':label,'pid':actor_pid,'dead':True}
                    for label,actor_pid,_ in source_pidfds]
                for index,fd in enumerate(caps):
                    if fd>=0:os.close(fd);caps[index]=-1
                release_result=command('RELEASE')
                closed0_result=command('CLOSED0')
                closed1_result=command('CLOSED1')
                controller.stdin.write(b'STOP\n');controller.stdin.flush()
                require(controller.wait(timeout=5)==0,'controller did not stop')
                controller_exit=controller.returncode
                ready.stop()
                require(select.select([run_sup],[],[],35)[0] and
                    run_sup.recv(64)==b'KER_RUN_STOP\n','negative native shutdown missing')
                require(service.prepare_worker_shutdown(1.0),'negative runtime lease remains')
                require(not worker.finish(),'negative IO owner unresolved')
                status=kr.drain_startup_status(startup_read,status)
                require(kr.normal_native_shutdown_markers(status),
                    'negative native shutdown markers missing')
                run_sup.send(b'OK\n')
                require(app.wait(timeout=10)==0,'negative native broker failed')
                require(app.returncode==0,'negative runtime broker did not exit successfully')
                native=kr.native_statistics(status)
                io=worker.stats
                require(native and native.get('passive_opens')==1 and
                    native.get('buffers_live')==0 and
                    native.get('buffer_allocations')==native.get('buffer_releases')+
                    native.get('buffer_shutdown_releases'),
                    f'negative native Linux TCP accounting did not balance: {native}')
                require(io and io.get('rx_decision_settled') and
                    io.get('outstanding')==0 and io.get('rx_decision_drops')==0 and
                    io.get('worker_exit_code')==0 and not io.get('shutdown_timed_out'),
                    f'negative native IO did not settle cleanly: {io}')
                trace=(prefix/'runtime.trace').read_text()
                original_log=(prefix/'logs/error.log').read_text()
                receipt=dict(status='PASS_SOURCE_SHARED_BUDGET_EXPIRY_CONTAINED',
                    scope='Expired first same-master HUP COMMIT only; no successful reload is claimed.',
                    master=manager.master_pid,old_worker_pid=old_pid,candidate_worker_pid=candidate_pid,
                    park_deadline_ns=barriers[0]['deadline'],commit_deadline_ns=expiry,
                    rejection_observed_ns=observed_ns,rejected=rejected,
                    route_sequence=prepared.command_sequence,route_commit_applied=False,
                    native_commit_applied=False,original_released_state=list(state_before),
                    held_fresh_syn=expiry_held_status,
                    source_state=list(source),source_helper_exit=helper_status,
                    source_containment_error=containment_error,
                    source_unresolved_children=error_fields[3],source_pidfds_dead=True,
                    dead_source_actor_pidfds=dead_actor_pidfds,
                    native_quarantined=command_result,native=native,io=io,
                    controller_cleanup=[release_result,closed0_result,closed1_result],
                    controller_exit_code=controller_exit,runtime_broker_exit_code=app.returncode,
                    runtime_service_shutdown=True,trace=trace,original_log=original_log)
                (evidence_dir/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
                print('PASS_SOURCE_SHARED_BUDGET_EXPIRY_CONTAINED '+
                    json.dumps(receipt,sort_keys=True))
                return
            authority.master_barrier(master_channel,packet,struct.unpack('=3i',anc[0][2]),apply)
        require([item['operation'] for item in barriers] == [5,6] and
            barriers[0]['deadline'] == barriers[1]['deadline'],
            'PARK and COMMIT did not share one immutable 100 ms deadline')
        for barrier in barriers:
            require(0 < barrier['deadline'] - barrier['entered'] <= 100_000_000 and
                barrier['entered'] <= barrier['completed'] < barrier['deadline'],
                f'original master barrier missed its exact bounded deadline: {barrier}')
        require(route_commit_ns is not None and native_commit_ns is not None and
            route_commit_ns < native_commit_ns < barriers[1]['deadline'],
            'C31 route/native selector did not commit under the shared deadline')
        queued.setblocking(True);queued.settimeout(8)
        queued.sendall(b'GET / HTTP/1.1\r\nHost: source\r\nConnection: close\r\n\r\n');fresh=b''
        while chunk:=queued.recv(4096):fresh+=chunk
        queued.close();require(b'original-source-worker\n' in fresh,'fresh generation body failed')
        while chunk:=conn.recv(65536):body+=chunk
        conn.close();require(body==large,'same old original TCP body changed across real HUP')
        command('DRAINED0');command('DRAINED1')
        until=time.monotonic()+12
        while time.monotonic()<until:
            values=struct.unpack('=8I',boot.memory(manager.master_pid,source_address,32))
            owner,stopped,fsm=struct.unpack('=3I',boot.memory(manager.master_pid,source_address+48+128*8,12))
            if values[4:7]==(1,1,0) and owner==1 and not stopped and fsm==0:break
            time.sleep(.01)
        require(values[4:7]==(1,1,0) and owner==1 and not stopped and fsm==0,'original source FSM did not settle '+str((values,owner,stopped,fsm)))
        command('RETIRE0')
        until=time.monotonic()+5
        while time.monotonic()<until and 'ff_source_plane_retired' not in (prefix/'runtime.trace').read_text():time.sleep(.01)
        require('ff_source_plane_retired' in (prefix/'runtime.trace').read_text(),'native admission did not drain before original map retirement')
        steady=socket.create_connection(('198.18.0.2',4108),timeout=8);steady.sendall(b'GET / HTTP/1.1\r\nHost: source\r\nConnection: close\r\n\r\n');steady_response=b''
        while chunk:=steady.recv(4096):steady_response+=chunk
        steady.close();require(b'original-source-worker\n' in steady_response,'post-retirement original TCP failed');command('DRAINED1')
        print('ACTUAL_SOURCE_HUP_SETTLED',values,barriers,gaps,flush=True)
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
        for transition in ['T0_IDLE -> T1_GNEW_SPAWN','T1_GNEW_SPAWN -> T2_HANDOVER','T2_HANDOVER -> T3_DRAIN','T3_DRAIN -> T4_DRAIN_DONE','T4_DRAIN_DONE -> T5_GOLD_QUIT','T5_GOLD_QUIT -> T0_IDLE']:require(transition in original_log,'missing actual original transition '+transition)
        require('exited on signal' not in original_log and
            re.search(rf'worker process {old_pid} exited with code 0', original_log) and
            re.search(rf'worker process {candidate_pid} exited with code 0', original_log),
            'original old/new source worker did not exit normally')
        native=kr.native_statistics(status)
        io=worker.stats
        require(native and native.get('passive_opens',0)>=3 and
            native.get('buffers_live') == 0 and
            native.get('buffer_allocations') == native.get('buffer_releases') + native.get('buffer_shutdown_releases'),
            f'original Linux socket/buffer accounting did not balance: {native}')
        require(io and io.get('outstanding') == 0 and io.get('control_eof') is True and
            io.get('shutdown_timed_out') is False and io.get('worker_exit_code') == 0 and
            io.get('rx_decision_settled') is True and io.get('rx_decision_drops') == 0 and
            io.get('rx_decision_local_cancelled') == 0 and io.get('dropped') == 0,
            f'native I/O/RX authority did not settle cleanly: {io}')
        classifications = re.findall(
            r'SOURCE_OWNER_RELAY packet=(\d+) pid=(\d+) tid=(\d+) status=(\d+) result=(-?\d+)', trace)
        old_local = {packet for packet,pid,tid,relay_status,result in classifications
            if (int(pid),relay_status,result) == (old_pid,'0','0')}
        candidate_peer = {packet for packet,pid,tid,relay_status,result in classifications
            if (int(pid),relay_status,result) == (candidate_pid,'0','-3')}
        broker_log=(root/'broker.stdout').read_text()+(root/'broker.stderr').read_text()
        forwarded=set(re.findall(r'RX_OWNER_PEER_HANDOFF packet=(\d+) .*action=1 ',broker_log))
        matched=old_local & candidate_peer & forwarded
        require(matched, 'no packet ID correlated original PEER classifier -> old LOCAL classifier -> native handoff')
        require(set(map(str,correlated_gap_ids)) <= matched and
            correlated_gap_observed_ns < native_commit_ns < barriers[1]['deadline'],
            'new correlated PEER->old-LOCAL packet was not observed after route swap and before native commit')
        body_hash=hashlib.sha256(body).hexdigest()
        require(body_hash==hashlib.sha256(large).hexdigest(), 'old original TCP body hash changed across HUP')
        receipt=dict(status='PASS_ACTUAL_SOURCE_FIRST_HUP',scope='Bounded first same-master HUP only; does not qualify repeated reload/full shell policy.',
            master=manager.master_pid,old_worker_pid=old_pid,worker=manager.owner_pid,tid=manager.owner_tid,
            slot=[manager.owner_slot_device,manager.owner_slot_inode],ready_cookie=manager.owner_cookie,
            native=native,io=io,trace=trace,barriers=barriers,gap=gaps,
            shared_barrier_deadline_ns=barriers[0]['deadline'],route_commit_ns=route_commit_ns,
            native_selector_commit_ns=native_commit_ns,body_bytes=len(body),body_sha256=body_hash,
            expected_body_sha256=hashlib.sha256(large).hexdigest(),source_state=list(values),
            original_log=original_log,post_retirement_tcp=True,
            classifier_packet_ids=sorted(map(int,matched)),gap_classifier_packet_ids=correlated_gap_ids,
            classifier_rows=[{'packet_id':int(packet),'pid':int(pid),'tid':int(tid),
                'status':int(relay_status),'result':int(result)}
                for packet,pid,tid,relay_status,result in classifications if packet in matched],
            old_local_packet_ids=sorted(map(int,old_local)),candidate_peer_packet_ids=sorted(map(int,candidate_peer)),
            native_handoff_packet_ids=sorted(map(int,forwarded)))
        (evidence_dir/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
        print('PASS_ACTUAL_SOURCE_FIRST_HUP '+json.dumps(receipt,sort_keys=True))
    finally:
        diagnostic={str(f.relative_to(root)):f.read_text(errors='replace')
            for f in root.rglob('*') if f.is_file() and f.suffix in ['.log','.trace','.stderr','.stdout']}
        (evidence_dir/'diagnostic.json').write_text(json.dumps(diagnostic,indent=2)+'\n')
        artifacts=evidence_dir/'artifacts'
        artifacts.mkdir(exist_ok=True)
        for source in root.rglob('*'):
            relative=source.relative_to(root)
            destination=artifacts/relative
            if source.is_dir():
                destination.mkdir(parents=True,exist_ok=True)
            elif source.is_file() and not source.is_symlink():
                destination.parent.mkdir(parents=True,exist_ok=True)
                shutil.copy2(source,destination)
        if manager is not None and manager.channel is not None:manager.channel.close()
        if authority is not None:authority.close()
        for channel in channels:channel.close()
        for fd in caps:
            if fd>=0:os.close(fd)
        if controller is not None and controller.poll() is None:controller.terminate()
        if app is not None and app.poll() is None:app.terminate()
execute()
