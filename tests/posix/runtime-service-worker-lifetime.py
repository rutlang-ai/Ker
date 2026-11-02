#!/usr/bin/env python3
"""Exercise runtime-service pins against a real DPDK TAP worker and pool."""
import json
import hashlib
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / 'tools'
sys.path.insert(0, str(TOOLS))
import runtime_service


COUNTERS = ('tx', 'rx', 'tx_bytes', 'rx_bytes', 'tx_dropped', 'rx_dropped',
            'dropped', 'tx_retries', 'rx_retries', 'outstanding')


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def read_ready(process, timeout=20):
    readable, _, _ = select.select([process.stdout], [], [], timeout)
    require(readable, 'actual worker READY timeout')
    line = process.stdout.readline()
    require(line.startswith('KER_IO_READY '), 'actual worker did not emit READY: ' + line)
    ready = json.loads(line.split(' ', 1)[1])
    require(ready.get('process_type') == 'primary', 'worker is not the primary process')
    require(type(ready.get('mbuf_pool_count')) is int and ready['mbuf_pool_count'] > 0,
            'worker READY did not report a live mbuf pool')
    require(type(ready.get('queues')) is int and ready['queues'] > 0,
            'worker READY did not report a live queue')
    return ready


def start_worker(worker, directory):
    app_channel, io_channel = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    control_read, control_write = os.pipe()
    cpu = min(os.sched_getaffinity(0))
    eal = [f'--lcores=0@{cpu}', '--no-huge', '--no-pci', '--no-shconf',
           '--no-telemetry', '--iova-mode=va', '-m', '64',
           '--vdev=net_tap0,iface=kerpeer,remote=kerlink']
    log = (directory / 'worker.stderr').open('w+')
    process = subprocess.Popen([str(worker), '--packet-fd', str(io_channel.fileno()),
        '--control-fd', str(control_read), '--port', 'net_tap0', '--tx-delay-us', '0',
        '--', *eal], pass_fds=(io_channel.fileno(), control_read),
        stdout=subprocess.PIPE, stderr=log, text=True)
    io_channel.close()
    os.close(control_read)
    ready = read_ready(process)
    return process, app_channel, control_write, ready, log


def run_case(worker, actor_executable, directory, kill_worker=False):
    process, channel, control_write, ready, log = start_worker(worker, directory)
    worker_pidfd = os.pidfd_open(process.pid, 0)
    app_executable = actor_executable.resolve(strict=True)
    app_hash = runtime_service.sha256_file(app_executable)
    app_profile = hashlib.sha256(
        b'ker-runtime-service/slim-primary/v1\0' + app_hash).digest()
    service_dir = directory / ('service-kill' if kill_worker else 'service-pin')
    service_dir.mkdir(mode=0o700)
    supervisor = runtime_service.RuntimeServiceSupervisor(service_dir / 'service.sock',
        process, worker_pidfd, runtime_service.process_start_ticks(process.pid),
        runtime_service.process_executable_hash(process.pid), ready, app_hash,
        app_profile, control_write)
    supervisor.start()

    release_read, release_write = os.pipe()
    actor_env = os.environ.copy()
    actor_env.update(supervisor.env)
    actor_env['KER_TEST_RELEASE_FD'] = str(release_read)
    actor = subprocess.Popen([str(app_executable)] +
        (['--expect-worker-death'] if kill_worker else []), env=actor_env,
        pass_fds=(release_read,), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True)
    actor_pidfd = os.pidfd_open(actor.pid, 0)
    supervisor.bind_actor(actor, actor_pidfd)
    os.close(release_read)
    actor_line = actor.stdout.readline().strip()
    require(actor_line == 'CLAIMED', 'real-worker actor failed to claim: ' + actor_line)

    if kill_worker:
        os.kill(process.pid, 9)
        process.wait(timeout=5)
        os.write(release_write, b'R')
        actor_output, actor_error = actor.communicate(timeout=5)
        require(actor.returncode == 0 and 'DEAD_REJECTED check_errno=' in actor_output and
                'claim_errno=' in actor_output,
                'worker-death CHECK was not rejected cleanly: ' + actor_output + actor_error)
        require(supervisor.revoked, 'worker death did not revoke the active runtime lease')
        print('worker-death: READY mbuf_pool_count=%d, CHECK failed, lease revoked' %
              ready['mbuf_pool_count'], flush=True)
    else:
        # The original control writer closes while the live role owns its
        # duplicate. The actual worker and its READY-reported pool must remain.
        os.close(control_write)
        control_write = -1
        time.sleep(0.25)
        require(process.poll() is None, 'worker stopped when the original control writer closed')
        require(not supervisor.revoked and supervisor.active_count == 1,
                'worker resource lease was revoked by an unrelated pipe close')
        os.write(release_write, b'C')
        require(actor.stdout.readline().strip() == 'CHECKED',
                'C client could not CHECK its lease after original-writer close')
        require(process.poll() is None, 'worker stopped during lease CHECK')
        os.write(release_write, b'R')
        require(actor.stdout.readline().strip() == 'RELEASED', 'actor did not release its lease')
        actor.communicate(timeout=5)
        require(actor.returncode == 0, 'actor failed during CHECK/RELEASE')
        require(supervisor.prepare_worker_shutdown(2.0), 'explicit shutdown did not observe RELEASE')
        output, _ = process.communicate(timeout=10)
        require(process.returncode == 0, 'worker cleanup failed: ' + log.read())
        done = [line for line in output.splitlines() if line.startswith('KER_IO_DONE ')]
        require(len(done) == 1, 'expected one worker DONE snapshot: ' + output)
        stats = json.loads(done[0].split(' ', 1)[1])
        require(set(COUNTERS) <= stats.keys(), 'worker DONE snapshot is incomplete')
        require(stats['outstanding'] == 0 and stats['control_eof'] is True,
                'worker did not release its pool cleanly after lease release')
        require(stats['stop_requests'] == 0,
                'closing the original control writer fabricated a worker stop request')
        print('lease-pin: READY mbuf_pool_count=%d, worker survived original-writer close, RELEASE then EOF cleanup=%s' %
              (ready['mbuf_pool_count'], json.dumps(stats, sort_keys=True)), flush=True)

    supervisor.close()
    os.close(worker_pidfd)
    os.close(actor_pidfd)
    os.close(release_write)
    channel.close()
    log.close()


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', type=Path, required=True)
    parser.add_argument('--actor', type=Path, required=True)
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    worker = args.worker.resolve(strict=True)
    actor = args.actor.resolve(strict=True)
    if not args.inside:
        return subprocess.run(['unshare', '-Urn', sys.executable,
            str(Path(__file__).resolve()), '--inside', '--worker', str(worker),
            '--actor', str(actor)]).returncode
    for scope in ('all', 'default'):
        Path('/proc/sys/net/ipv6/conf/' + scope + '/disable_ipv6').write_text('1\n')
    for command in (['ip', 'link', 'add', 'kerhost', 'type', 'veth', 'peer', 'name', 'kerlink'],
                    ['ip', 'link', 'set', 'kerhost', 'up'], ['ip', 'link', 'set', 'kerlink', 'up']):
        subprocess.run(command, check=True)
    with tempfile.TemporaryDirectory(prefix='ker-runtime-service-worker-') as temporary:
        directory = Path(temporary)
        run_case(worker, actor, directory)
        run_case(worker, actor, directory, kill_worker=True)
    print('PASS: real DPDK primary/pool lease pin and worker-death revocation', flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
