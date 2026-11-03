#!/usr/bin/env python3
"""Physical pinned-Nginx A→B serial cycle with native retirement evidence."""
import argparse
from pathlib import Path
import importlib.util, json, os, signal, subprocess, sys, tempfile, time, select

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--launcher', type=Path, required=True)
parser.add_argument('--library', type=Path, required=True)
parser.add_argument('--worker', type=Path, required=True)
parser.add_argument('--fstack-runtime', type=Path, required=True)
parser.add_argument('--preload-library', type=Path, required=True)
parser.add_argument('--worker-shim', type=Path, required=True)
parser.add_argument('--owner-module', type=Path, required=True)
parser.add_argument('--dpdk-plugin-dir', type=Path, required=True)
parser.add_argument('--nginx', type=Path, required=True)
parser.add_argument('--broker', type=Path, required=True)
parser.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
args = parser.parse_args()
if not args.inside:
 command = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()),
     '--launcher', str(args.launcher.resolve()), '--library', str(args.library.resolve()),
     '--worker', str(args.worker.resolve()), '--fstack-runtime', str(args.fstack_runtime.resolve()),
     '--preload-library', str(args.preload_library.resolve()), '--worker-shim', str(args.worker_shim.resolve()),
     '--owner-module', str(args.owner_module.resolve()), '--dpdk-plugin-dir', str(args.dpdk_plugin_dir.resolve()),
     '--nginx', str(args.nginx.resolve()), '--broker', str(args.broker.resolve()), '--inside']
 raise SystemExit(subprocess.run(command, env=os.environ | {'PYTHONDONTWRITEBYTECODE':'1'}).returncode)
S=Path(__file__).resolve().parents[2]
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
ctlmod=load('root_c39_serial',S/'tools/ker_serial_generation.py');cm=load('root_c39_companion',S/'tools/nginx_companion_supervisor.py');cy=load('root_c39_cycle',S/'tools/nginx_cycle_control.py');tap=load('root_c39_tap',S/'tests/posix/native-nginx-companion-tap.py');readytap=load('root_c39_readytap',S/'tests/posix/native-socket-broker-readiness.py')
tap.set_up_network();readytap.enable_subreaper()
r=Path(tempfile.mkdtemp(prefix='c39-root-nginx-',dir='/dev/shm'));print('ARTIFACT_ROOT',r,flush=True)
pre=r/'nginx';(pre/'logs').mkdir(parents=True);(pre/'html').mkdir();(pre/'html/index.html').write_bytes(tap.BODY)
rpc=r/'broker.sock';ini=pre/'fstack.ini';ini.write_text(f'[ker_socket_broker]\nversion=1\npath={rpc}\n\n[dpdk]\ngraceful_reload=0\n');conf=pre/'nginx.conf'
conf.write_text(f'''load_module {args.owner_module.resolve()};
daemon off;
master_process on;
worker_processes 1;
user root;
fstack_conf "fstack.ini";
timer_resolution 1ms;
pid {pre}/logs/nginx.pid;
error_log {pre}/logs/error.log notice;
env LD_PRELOAD;
env KER_SOCKET_BROKER_PATH;
env KER_FSTACK_RUNTIME_TRACE;
events {{ worker_connections 256; use epoll; }}
http {{ access_log off; sendfile off; tcp_nopush off; keepalive_timeout 0;
server {{ listen 198.18.0.2:80 reuseport; server_name ker.test; root {pre}/html; index index.html; }} }}
''')
launch=ctlmod.InnerLaunch(args.launcher.resolve(),args.library.resolve(),args.worker.resolve(),args.broker.resolve(),args.dpdk_plugin_dir.resolve(),r,rpc_path=rpc)
ctl=ctlmod.SerialGenerationController(launch,port=80);contexts=[];comp=None;cycle=None;fds=[];watches=[];out={'root':str(r),'events':[],'status':'FAIL'};helperfd=-1
def mark(name,**kw):out['events'].append({'event':name,'monotonic_ns':time.monotonic_ns(),**kw});print(name,kw,flush=True)
def process_fds(pid):
 result={}
 try: entries=list(Path(f'/proc/{pid}/fd').iterdir())
 except FileNotFoundError:return result
 for entry in entries:
  try:result[int(entry.name)]=os.readlink(entry)
  except OSError:pass
 return result
def pidfd_targets(pid):
 result=[]
 for fd,target in process_fds(pid).items():
  if target!='anon_inode:[pidfd]':continue
  try:
   rows=Path(f'/proc/{pid}/fdinfo/{fd}').read_text().splitlines()
   row=next((line for line in rows if line.startswith('Pid:\t')),None)
   if row:result.append(int(row.split('\t',1)[1]))
  except (OSError,ValueError):pass
 return result
def assert_child_fd_isolation(master,worker,cycle_inode,outer_pid):
 master_fds=process_fds(master);worker_fds=process_fds(worker);target=f'socket:[{cycle_inode}]'
 if target not in master_fds.values() or target in worker_fds.values():raise RuntimeError(f'cycle endpoint master/worker FD boundary failed: master={master_fds!r} worker={worker_fds!r}')
 if outer_pid not in pidfd_targets(master) or outer_pid in pidfd_targets(worker):raise RuntimeError(f'outer pidfd master/worker FD boundary failed: master={pidfd_targets(master)!r} worker={pidfd_targets(worker)!r}')

def killfd(fd):
 if fd>=0:
  try:signal.pidfd_send_signal(fd,signal.SIGKILL)
  except ProcessLookupError:pass
try:
 a=ctl.start_inner('old');contexts.append(a);ar=ctl.receive_ready(a);mark('A_READY',pid=a.process.pid,nonce=ar[2].hex(),epoch=ar[3],profile=ar[4].hex())
 try:ctl.start_inner('new')
 except ctlmod.ProtocolError:mark('PREMATURE_B_REJECTED')
 else:raise RuntimeError('B launch was accepted before old retirement and settlement')
 cycle=cy.NginxCycleControl(ar[2:5]);cycle_target=os.readlink(f'/proc/self/fd/{cycle.master.fileno()}');cycle_inode=int(cycle_target[8:-1]);outer_pid=os.getpid();env={'LD_PRELOAD':f'{args.worker_shim.resolve()}:{args.fstack_runtime.resolve()}:{args.preload_library.resolve()}','KER_SOCKET_BROKER_PATH':str(rpc),'KER_FSTACK_NGINX_INI':str(ini),'KER_FSTACK_RUNTIME_TRACE':str(r/'runtime.trace'),**cycle.nginx_environment()}
 comp=cm.NginxCompanion(str(args.nginx.resolve()),conf,pre,env,cycle_control_fd=cycle.master.fileno());comp.start();helperfd=os.pidfd_open(comp.helper.pid);cycle.close_master_copy();mark('NGINX_STARTED',master=comp.master_pid)
 af=cycle.accept_initial_watch(comp);fds.append(af);aw=ctl.verify_external_watch(a,af,comp,cycle);watches.append(aw);tap.wait_http()
 if tap.child_pids(comp.master_pid)!=[aw.actor_identity.pid]:raise RuntimeError('A owner is not exact child of pinned Nginx master')
 assert_child_fd_isolation(comp.master_pid,aw.actor_identity.pid,cycle_inode,outer_pid)
 mark('HTTP_A',worker=aw.actor_identity.pid,master=comp.master_pid,fd_isolation='PASS')
 try:cycle.accept_initial_watch(comp,timeout=.05)
 except cy.CycleControlError:mark('DUPLICATE_INITIAL_WATCH_REJECTED')
 else:raise RuntimeError('duplicate initial watch accepted')
 comp.reload();cycle.receive_drained();deadline=cycle.transition_deadline;mark('CYCLE_DRAINED',cycle=cycle.cycle,sequence=cycle.last_request[0])
 retired=ctl.verify_external_watch(a,af,comp,cycle,require_retired=True,live_watch=aw,deadline=deadline);os.close(af);fds.remove(af);mark('A_RETIRED',worker=aw.actor_identity.pid)
 settled=ctl.stop_inner(a,retired,deadline=deadline);mark('A_SETTLED',outstanding=settled.stats.get('outstanding'),control_eof=settled.stats.get('control_eof'));b=ctl.start_next(a,retired,settled);contexts.append(b);br=ctl.receive_ready(b,deadline=deadline);mark('B_READY',pid=b.process.pid,nonce=br[2].hex(),epoch=br[3],profile=br[4].hex())
 cycle.send_ready(br[2:5]);bf=cycle.accept_successor_watch(br[2:5]);fds.append(bf);bw=ctl.verify_external_watch(b,bf,comp,cycle);watches.append(bw);tap.wait_http()
 if bw.actor_identity.pid==aw.actor_identity.pid or tap.child_pids(comp.master_pid)!=[bw.actor_identity.pid]:raise RuntimeError('B owner is not a distinct exact child of the same master')
 assert_child_fd_isolation(comp.master_pid,bw.actor_identity.pid,cycle_inode,outer_pid)
 if br[2]==ar[2] or br[3]==ar[3]:raise RuntimeError('B reused A runtime nonce/epoch')
 mark('HTTP_B',worker=bw.actor_identity.pid,master=comp.master_pid,fd_isolation='PASS')
 comp.stop();mark('COMPANION_SETTLED',master=comp.master_pid,helper_exit=comp.helper.returncode);shutdown=ctl.record_companion_shutdown(b,bw,comp,cycle);last=ctl.verify_external_shutdown_watch(b,bf,shutdown);os.close(bf);fds.remove(bf);settled_b=ctl.stop_inner(b,last);ctl.close_watch(bw);ctl.close_context(b,'settled');comp.close();cycle.close();out['status']='PASS';mark('B_SETTLED',outstanding=settled_b.stats.get('outstanding'),control_eof=settled_b.stats.get('control_eof'))
 names=[x['event'] for x in out['events']]
 expected=['A_READY','NGINX_STARTED','HTTP_A','CYCLE_DRAINED','A_RETIRED','A_SETTLED','B_READY','HTTP_B','COMPANION_SETTLED','B_SETTLED','ALL_SETTLED']
 positions=[names.index(name) for name in expected[:-1]]
 if positions!=sorted(positions):raise RuntimeError(f'physical lifecycle event order invalid: {names!r}')
 mark('ALL_SETTLED',event_order='PASS',worker_pids=[aw.actor_identity.pid,bw.actor_identity.pid],same_master=comp.master_pid)
except BaseException as e:
 out.update(status='FAIL',error=repr(e));mark('FAIL',error=repr(e))
 # Explicit failed-test cleanup through exact owned process handles only.
 if comp is not None:
  if comp.master_pidfd>=0:killfd(comp.master_pidfd)
  if comp.helper is not None:
   try:
    for child in tap.child_pids(comp.helper.pid):
     try:fd=os.pidfd_open(child);killfd(fd);os.close(fd)
     except ProcessLookupError:pass
   except FileNotFoundError:pass
 for watch in watches:killfd(watch.actor_pidfd)
 for c in contexts:
  if not c.closed:
   for fd in (c.app_pidfd,c.worker_pidfd,c.pidfd):killfd(fd)
   try:c.process.wait(timeout=5)
   except subprocess.TimeoutExpired:pass
 if comp is not None and comp.helper is not None:
  killfd(helperfd)
  try:comp.helper.wait(timeout=5)
  except subprocess.TimeoutExpired:pass
 out['cleanup']='EXPLICIT_TEST_FAILURE_NOT_SETTLEMENT'
 raise
finally:
 for fd in fds:
  try:os.close(fd)
  except OSError:pass
 if helperfd>=0:os.close(helperfd)
 out['inner_events']=[{'label':c.label,'events':c.events}for c in contexts];(r/'result.json').write_text(json.dumps(out,indent=2));print(f'C39_EVIDENCE {r / 'result.json'}',flush=True)
