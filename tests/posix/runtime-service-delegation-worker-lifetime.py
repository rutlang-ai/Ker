#!/usr/bin/env python3
"""Verify C33 actor delegation keeps an actual DPDK worker pool pinned."""
import ctypes
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import threading
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / 'tools'
sys.path.insert(0, str(TOOLS))
import runtime_service


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def _stop_process(process):
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)


def _cleanup_worker(process, channel, log):
    channel.close()
    _stop_process(process)
    log.close()


def _close_writer_ref(writer_ref):
    descriptor = writer_ref['fd']
    writer_ref['fd'] = -1
    if descriptor >= 0:
        try:
            os.close(descriptor)
        except OSError:
            pass


def _cleanup_actor(actor):
    _stop_process(actor)


def _cleanup_service(service):
    if service is not None:
        service.close()


def _cleanup_fd(descriptor):
    try:
        os.close(descriptor)
    except OSError:
        pass


def start_release_waiter(service, timeout, cleanup):
    condition = service._condition
    original_wait = condition.wait
    entered_wait = threading.Event()
    result = []

    def observed_wait(wait_timeout=None):
        entered_wait.set()
        return original_wait(wait_timeout)

    condition.wait = observed_wait
    waiter = threading.Thread(target=lambda: result.append(
        service.wait_for_release(timeout)), daemon=True)
    waiter.start()
    cleanup.callback(_restore_waiter, condition, original_wait, waiter, service)
    require(entered_wait.wait(1.0),
        'wait_for_release did not reach Condition.wait with a pinned role')
    return waiter, result, condition, original_wait


def _restore_waiter(condition, original_wait, waiter, service):
    service.close()
    waiter.join(timeout=2)
    condition.wait = original_wait


def _cleanup_marked_child(marker_path):
    try:
        child = int(Path(marker_path).read_text())
    except (FileNotFoundError, ValueError, OSError):
        return
    try:
        pidfd = os.pidfd_open(child, 0)
    except ProcessLookupError:
        pidfd = -1
    if pidfd >= 0:
        try:
            signal.pidfd_send_signal(pidfd, signal.SIGTERM)
        except ProcessLookupError:
            pass
        readable, _, _ = select.select([pidfd], [], [], 1.0)
        if not readable:
            try:
                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
            except ProcessLookupError:
                pass
            select.select([pidfd], [], [], 1.0)
        os.close(pidfd)
    try:
        os.waitpid(child, os.WNOHANG)
    except ChildProcessError:
        pass


def wait_for_child_exit(pid, timeout):
    pidfd = os.pidfd_open(pid, 0)
    try:
        readable, _, _ = select.select([pidfd], [], [], timeout)
        require(readable, 'child pidfd did not become readable before deadline')
    finally:
        os.close(pidfd)
    reaped_pid, status = os.waitpid(pid, os.WNOHANG)
    require(reaped_pid == pid, 'exited child was not waitable by this supervisor')
    return status


def read_ready(process, timeout=20):
    readable, _, _ = select.select([process.stdout], [], [], timeout)
    require(readable, 'actual worker READY timeout')
    line = process.stdout.readline()
    require(line.startswith('KER_IO_READY '),
        'actual worker did not emit READY: ' + line)
    ready = json.loads(line.split(' ', 1)[1])
    require(ready.get('process_type') == 'primary', 'worker is not primary')
    require(type(ready.get('mbuf_pool_count')) is int and
        ready['mbuf_pool_count'] > 0, 'worker has no live mbuf pool')
    return ready


def start_worker(worker, directory, dpdk_plugin_dir, cleanup):
    app_channel, io_channel = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    control_read, control_write = os.pipe()
    cpu = min(os.sched_getaffinity(0))
    eal = [f'--lcores=0@{cpu}', '--no-huge', '--no-pci', '--no-shconf',
        '--no-telemetry', '--iova-mode=va', '-m', '64', '-d',
        str(dpdk_plugin_dir / 'librte_net_tap.so'),
        '--vdev=net_tap0,iface=kerpeer,remote=kerlink']
    log = (directory / 'worker.stderr').open('w+')
    writer_ref = {'fd': control_write}
    process = subprocess.Popen([str(worker), '--packet-fd', str(io_channel.fileno()),
        '--control-fd', str(control_read), '--port', 'net_tap0', '--tx-delay-us', '0',
        '--', *eal], pass_fds=(io_channel.fileno(), control_read),
        stdout=subprocess.PIPE, stderr=log, text=True)
    cleanup.callback(_cleanup_worker, process, app_channel, log)
    cleanup.callback(_close_writer_ref, writer_ref)
    io_channel.close()
    os.close(control_read)
    ready = read_ready(process)
    return process, app_channel, writer_ref, ready, log


def _run_case(worker, actor_binary, directory, dpdk_plugin_dir, cleanup):
    process, channel, writer_ref, ready, log = start_worker(worker, directory,
        dpdk_plugin_dir, cleanup)
    worker_pidfd = os.pidfd_open(process.pid, 0)
    cleanup.callback(_cleanup_fd, worker_pidfd)
    actor_executable = actor_binary.resolve(strict=True)
    actor_hash = runtime_service.sha256_file(actor_executable)
    role_profile = hashlib.sha256(b'ff-slim-delegation-test-v1').digest()
    service_dir = directory / 'service'
    service_dir.mkdir(mode=0o700)
    service = runtime_service.RuntimeServiceSupervisor(
        service_dir / 'service.sock', process, worker_pidfd,
        runtime_service.process_start_ticks(process.pid),
        runtime_service.process_executable_hash(process.pid), ready,
        actor_hash, role_profile, writer_ref['fd'], ttl_seconds=30,
        max_clients=4, delegation_enabled=True)
    cleanup.callback(_cleanup_service, service)
    service.start()
    # Keep only the supervisor-owned duplicate. Its close after final RELEASE
    # is the actual worker stop signal.
    _close_writer_ref(writer_ref)

    claimed = directory / 'final-claimed'
    release = directory / 'final-release'
    released = directory / 'final-released'
    stage_pid_marker = directory / 'stage1-pid'
    primary_pid_marker = directory / 'primary-pid'
    env = os.environ.copy()
    env.update(service.env)
    env['KER_TEST_FINAL_CLAIMED'] = str(claimed)
    env['KER_TEST_FINAL_RELEASE'] = str(release)
    env['KER_TEST_FINAL_RELEASED'] = str(released)
    env['KER_TEST_STAGE1_PID'] = str(stage_pid_marker)
    env['KER_TEST_PRIMARY_PID'] = str(primary_pid_marker)
    actor_error = (directory / 'actor.stderr').open('w+')
    actor = subprocess.Popen([str(actor_executable)], env=env,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=actor_error)
    cleanup.callback(actor_error.close)
    cleanup.callback(_cleanup_actor, actor)
    cleanup.callback(_cleanup_marked_child, stage_pid_marker)
    cleanup.callback(_cleanup_marked_child, primary_pid_marker)
    cleanup.callback(_cleanup_marked_child, claimed)
    actor_pidfd = os.pidfd_open(actor.pid, 0)
    cleanup.callback(_cleanup_fd, actor_pidfd)
    service.bind_actor(actor, actor_pidfd)

    # The direct actor waits for stage1 to exit after it binds the primary.
    # Its exit, plus the final marker, proves the final claim was made by the
    # reparented target process after both upstream-style actor exits.
    actor.wait(timeout=10)
    require(actor.returncode == 0, 'direct actor failed: ' + actor_error.read())
    deadline = time.monotonic() + 8
    while not claimed.exists() and time.monotonic() < deadline:
        time.sleep(0.005)
    require(claimed.exists(), 'reparented primary did not claim: ' + actor_error.read())
    final_pid = int(claimed.read_text())
    require(final_pid != actor.pid, 'final role reused direct actor PID')
    require(service.active_count == 1,
        'direct/stage leases were not replaced by one final lease')
    require(process.poll() is None, 'actual worker exited while final role held lease')
    require(not select.select([channel], [], [], 0)[0],
        'actual worker control channel reached EOF before final RELEASE')
    release_waiter, waiter_result, condition, original_wait = start_release_waiter(
        service, 8.0, cleanup)
    require(release_waiter.is_alive() and not waiter_result and
        service.active_count == 1 and process.poll() is None,
        'supervisor release gate did not remain blocked by the final live role')
    print('delegated-pool-pinned: READY mbuf_pool_count=%d final_pid=%d active=%d' %
        (ready['mbuf_pool_count'], final_pid, service.active_count), flush=True)

    release.touch()
    deadline = time.monotonic() + 8
    while (service.active_count or not released.exists()) and time.monotonic() < deadline:
        time.sleep(0.005)
    require(released.exists() and service.active_count == 0,
        'final C client did not RELEASE its exact role')
    release_waiter.join(timeout=2)
    condition.wait = original_wait
    require(not release_waiter.is_alive() and waiter_result == [True],
        'supervisor release gate did not open after final RELEASE')
    final_status = wait_for_child_exit(final_pid, 2.0)
    require(os.WIFEXITED(final_status) and
        os.WEXITSTATUS(final_status) == 0,
        'reparented primary did not exit cleanly after RELEASE')
    require(service.wait_for_release(2.0), 'server did not observe final RELEASE')
    require(service.prepare_worker_shutdown(2.0),
        'worker shutdown did not begin after final role RELEASE')
    output, _ = process.communicate(timeout=10)
    require(process.returncode == 0, 'worker cleanup failed: ' + log.read())
    done = [line for line in output.splitlines() if line.startswith('KER_IO_DONE ')]
    require(len(done) == 1, 'expected one KER_IO_DONE record: ' + output)
    stats = json.loads(done[0].split(' ', 1)[1])
    require(stats.get('outstanding') == 0 and stats.get('control_eof') is True,
        'worker did not settle cleanly: ' + repr(stats))
    print('delegated-pool-released: ' + json.dumps(stats, sort_keys=True), flush=True)

def run_case(worker, actor_binary, directory, dpdk_plugin_dir):
    with ExitStack() as cleanup:
        return _run_case(worker, actor_binary, directory, dpdk_plugin_dir, cleanup)


def _run_expired_grant_case(worker, actor_binary, directory, dpdk_plugin_dir, cleanup):
    process, channel, writer_ref, ready, log = start_worker(worker, directory,
        dpdk_plugin_dir, cleanup)
    worker_pidfd = os.pidfd_open(process.pid, 0)
    cleanup.callback(_cleanup_fd, worker_pidfd)
    actor_executable = actor_binary.resolve(strict=True)
    actor_hash = runtime_service.sha256_file(actor_executable)
    role_profile = hashlib.sha256(b'ff-slim-delegation-test-v1').digest()
    service_dir = directory / 'service-expiry'
    service_dir.mkdir(mode=0o700)
    service = runtime_service.RuntimeServiceSupervisor(
        service_dir / 'service.sock', process, worker_pidfd,
        runtime_service.process_start_ticks(process.pid),
        runtime_service.process_executable_hash(process.pid), ready,
        actor_hash, role_profile, writer_ref['fd'], ttl_seconds=30,
        max_clients=4, delegation_enabled=True)
    cleanup.callback(_cleanup_service, service)
    service.start()
    _close_writer_ref(writer_ref)

    failed = directory / 'final-claim-failed'
    stage_pid_marker = directory / 'expiry-stage1-pid'
    primary_pid_marker = directory / 'expiry-primary-pid'
    env = os.environ.copy()
    env.update(service.env)
    env['KER_TEST_EXPECT_FINAL_CLAIM_FAILURE'] = '1'
    env['KER_TEST_DELAY_FINAL_CLAIM_MS'] = '5500'
    env['KER_TEST_FINAL_CLAIM_FAILED'] = str(failed)
    env['KER_TEST_STAGE1_PID'] = str(stage_pid_marker)
    env['KER_TEST_PRIMARY_PID'] = str(primary_pid_marker)
    actor_error = (directory / 'expiry-actor.stderr').open('w+')
    actor = subprocess.Popen([str(actor_executable)], env=env,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=actor_error)
    cleanup.callback(actor_error.close)
    cleanup.callback(_cleanup_actor, actor)
    cleanup.callback(_cleanup_marked_child, stage_pid_marker)
    cleanup.callback(_cleanup_marked_child, primary_pid_marker)
    cleanup.callback(_cleanup_marked_child, failed)
    actor_pidfd = os.pidfd_open(actor.pid, 0)
    cleanup.callback(_cleanup_fd, actor_pidfd)
    service.bind_actor(actor, actor_pidfd)
    actor.wait(timeout=10)
    require(actor.returncode == 0, 'expiry-chain actor failed: ' + actor_error.read())
    release_waiter, waiter_result, condition, original_wait = start_release_waiter(
        service, 8.0, cleanup)
    require(release_waiter.is_alive() and not waiter_result and
        service._delegated_grants,
        'supervisor release gate did not remain blocked by the pending grant')
    deadline = time.monotonic() + 10
    while not failed.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    require(failed.exists(), 'expired primary grant did not fail its CLAIM')
    final_pid = int(failed.read_text())
    final_status = wait_for_child_exit(final_pid, 2.0)
    require(os.WIFEXITED(final_status) and
        os.WEXITSTATUS(final_status) == 0,
        'expired final actor did not exit cleanly')
    release_waiter.join(timeout=2)
    condition.wait = original_wait
    require(not release_waiter.is_alive() and waiter_result == [True] and
        service.active_count == 0 and
        not service._delegated_grants and service._delegation_intent is None,
        'expired grant or its role intent remained pinned')
    require(process.poll() is None and not select.select([channel], [], [], 0)[0],
        'worker stopped before supervisor settled expiry')
    require(service.prepare_worker_shutdown(2.0),
        'worker shutdown did not settle after unclaimed grant expiry')
    output, _ = process.communicate(timeout=10)
    require(process.returncode == 0, 'worker failed after grant expiry: ' + log.read())
    done = [line for line in output.splitlines() if line.startswith('KER_IO_DONE ')]
    require(len(done) == 1, 'expected one expiry KER_IO_DONE record: ' + output)
    stats = json.loads(done[0].split(' ', 1)[1])
    require(stats.get('outstanding') == 0 and stats.get('control_eof') is True,
        'worker did not settle after grant expiry: ' + repr(stats))
    print('delegated-grant-expired: final claim rejected after 5s grant TTL; ' +
        'worker settled ' + json.dumps(stats, sort_keys=True), flush=True)
def run_expired_grant_case(worker, actor_binary, directory, dpdk_plugin_dir):
    with ExitStack() as cleanup:
        return _run_expired_grant_case(worker, actor_binary, directory,
            dpdk_plugin_dir, cleanup)


def _run_dead_primary_case(worker, actor_binary, directory, dpdk_plugin_dir, cleanup):
    process, channel, writer_ref, ready, log = start_worker(worker, directory,
        dpdk_plugin_dir, cleanup)
    worker_pidfd = os.pidfd_open(process.pid, 0)
    cleanup.callback(_cleanup_fd, worker_pidfd)
    actor_executable = actor_binary.resolve(strict=True)
    actor_hash = runtime_service.sha256_file(actor_executable)
    role_profile = hashlib.sha256(b'ff-slim-delegation-test-v1').digest()
    service_dir = directory / 'service-dead-primary'
    service_dir.mkdir(mode=0o700)
    service = runtime_service.RuntimeServiceSupervisor(
        service_dir / 'service.sock', process, worker_pidfd,
        runtime_service.process_start_ticks(process.pid),
        runtime_service.process_executable_hash(process.pid), ready,
        actor_hash, role_profile, writer_ref['fd'], ttl_seconds=30,
        max_clients=4, delegation_enabled=True)
    cleanup.callback(_cleanup_service, service)
    service.start()
    _close_writer_ref(writer_ref)

    claimed = directory / 'dead-final-claimed'
    release = directory / 'dead-final-release'
    stage_pid_marker = directory / 'death-stage1-pid'
    primary_pid_marker = directory / 'death-primary-pid'
    env = os.environ.copy()
    env.update(service.env)
    env['KER_TEST_FINAL_CLAIMED'] = str(claimed)
    env['KER_TEST_FINAL_RELEASE'] = str(release)
    env['KER_TEST_STAGE1_PID'] = str(stage_pid_marker)
    env['KER_TEST_PRIMARY_PID'] = str(primary_pid_marker)
    actor_error = (directory / 'death-actor.stderr').open('w+')
    actor = subprocess.Popen([str(actor_executable)], env=env,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=actor_error)
    cleanup.callback(actor_error.close)
    cleanup.callback(_cleanup_actor, actor)
    cleanup.callback(_cleanup_marked_child, stage_pid_marker)
    cleanup.callback(_cleanup_marked_child, primary_pid_marker)
    cleanup.callback(_cleanup_marked_child, claimed)
    actor_pidfd = os.pidfd_open(actor.pid, 0)
    cleanup.callback(_cleanup_fd, actor_pidfd)
    service.bind_actor(actor, actor_pidfd)
    actor.wait(timeout=10)
    require(actor.returncode == 0, 'death-chain actor failed: ' + actor_error.read())
    deadline = time.monotonic() + 8
    while not claimed.exists() and time.monotonic() < deadline:
        time.sleep(0.005)
    require(claimed.exists(), 'final role did not claim before death test')
    final_pid = int(claimed.read_text())
    final_pidfd = os.pidfd_open(final_pid, 0)
    release_waiter, waiter_result, condition, original_wait = start_release_waiter(
        service, 8.0, cleanup)
    require(release_waiter.is_alive() and not waiter_result and
        service.active_count == 1,
        'supervisor release gate did not remain blocked by the final live role')
    os.kill(final_pid, signal.SIGKILL)
    readable, _, _ = select.select([final_pidfd], [], [], 2.0)
    os.close(final_pidfd)
    require(readable, 'killed final role did not exit before deadline')
    final_status = wait_for_child_exit(final_pid, 0)
    require(os.WIFSIGNALED(final_status) and
        os.WTERMSIG(final_status) == signal.SIGKILL,
        'final role did not die under pidfd test')
    release_waiter.join(timeout=2)
    condition.wait = original_wait
    require(not release_waiter.is_alive() and waiter_result == [True] and
        service.active_count == 0 and
        not service._delegated_actors,
        'dead primary role remained active in supervisor')
    require(process.poll() is None and not select.select([channel], [], [], 0)[0],
        'worker stopped before dead-role cleanup')
    require(service.prepare_worker_shutdown(2.0),
        'worker shutdown did not settle after final role death')
    output, _ = process.communicate(timeout=10)
    require(process.returncode == 0, 'worker failed after final role death: ' + log.read())
    done = [line for line in output.splitlines() if line.startswith('KER_IO_DONE ')]
    require(len(done) == 1, 'expected one dead-role KER_IO_DONE record: ' + output)
    stats = json.loads(done[0].split(' ', 1)[1])
    require(stats.get('outstanding') == 0 and stats.get('control_eof') is True,
        'worker did not settle after final role death: ' + repr(stats))
    print('delegated-primary-death: pidfd removed final role; worker settled ' +
        json.dumps(stats, sort_keys=True), flush=True)
def run_dead_primary_case(worker, actor_binary, directory, dpdk_plugin_dir):
    with ExitStack() as cleanup:
        return _run_dead_primary_case(worker, actor_binary, directory,
            dpdk_plugin_dir, cleanup)


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', type=Path, required=True)
    parser.add_argument('--actor', type=Path, required=True)
    parser.add_argument('--dpdk-plugin-dir', type=Path, required=True)
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    worker = args.worker.resolve(strict=True)
    actor = args.actor.resolve(strict=True)
    plugins = args.dpdk_plugin_dir.resolve(strict=True)
    if not args.inside:
        return subprocess.run(['unshare', '-Urn', sys.executable, '-B',
            str(Path(__file__).resolve()), '--inside', '--worker', str(worker),
            '--actor', str(actor), '--dpdk-plugin-dir', str(plugins)]).returncode

    # The final role is intentionally reparented after stage1 exits. Make this
    # fixture its kernel parent so it can reap the exact target after RELEASE.
    if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), 'PR_SET_CHILD_SUBREAPER')
    for scope in ('all', 'default'):
        Path('/proc/sys/net/ipv6/conf/' + scope + '/disable_ipv6').write_text('1\n')
    for command in (['ip', 'link', 'add', 'kerhost', 'type', 'veth', 'peer', 'name', 'kerlink'],
                    ['ip', 'link', 'set', 'kerhost', 'up'],
                    ['ip', 'link', 'set', 'kerlink', 'up']):
        subprocess.run(command, check=True)
    with tempfile.TemporaryDirectory(prefix='ker-runtime-service-delegation-worker-') as temporary:
        directory = Path(temporary)
        run_case(worker, actor, directory, plugins)
        run_expired_grant_case(worker, actor, directory, plugins)
        run_dead_primary_case(worker, actor, directory, plugins)
    print('PASS: C33 fresh-exec delegation pins actual DPDK worker pool through final RELEASE',
        flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
