"""Exercise the private ker-run runtime-service actor grant on real processes."""
import hashlib
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile
import time
import unittest


TOOLS = Path(__file__).resolve().parents[2] / 'tools'
sys.path.insert(0, str(TOOLS))
import runtime_service
import runtime_service_wire as wire


ACTOR = r'''import json, os, socket, sys, time
import runtime_service_wire as w
env = os.environ
path = env['KER_RUNTIME_SERVICE_PATH']
nonce = bytes.fromhex(env['KER_RUNTIME_SERVICE_NONCE'])
epoch = int(env['KER_RUNTIME_SERVICE_EPOCH'])
ticket = bytes.fromhex(env['KER_RUNTIME_SERVICE_TICKET'])
role = bytes.fromhex(env['KER_RUNTIME_SERVICE_PROFILE'])

def connect():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    s.connect(path)
    s.settimeout(2)
    return s

def rpc(s, operation, sequence, lease=b'\0' * w.LEASE_BYTES, body=b''):
    request = w.pack_header(operation, sequence, epoch, nonce, lease,
        packet_length=w.HEADER.size + len(body)) + body
    s.sendall(request)
    packet = s.recv(w.HEADER.size + w.CLAIM_RESULT.size)
    op, status, seq, got_epoch, got_nonce, got_lease = w.unpack_header(packet)
    assert (op, seq, got_epoch, got_nonce) == (operation, sequence, epoch, nonce)
    return status, got_lease, packet[w.HEADER.size:]

# A same-uid, same-executable sibling has the ticket but is not the Popen
# actor. It must not receive a role lease.
pid = os.fork()
if pid == 0:
    try:
        sibling = connect()
        status, _, _ = rpc(sibling, w.CLAIM, 1,
            body=w.CLAIM_BODY.pack(ticket, role))
        os._exit(0 if status == 13 else 21)
    except BaseException as error:
        os.write(2, repr(error).encode())
        os._exit(22)
_, status = os.waitpid(pid, 0)
assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, os.WEXITSTATUS(status) if os.WIFEXITED(status) else status

# Claim and then prove that a fork cannot reuse an already connected socket:
# SO_PEERCRED remains the parent PID, but per-message SCM_CREDENTIALS changes.
channel = connect()
status, lease, body = rpc(channel, w.CLAIM, 1,
    body=w.CLAIM_BODY.pack(ticket, role))
assert status == 0 and len(body) == w.CLAIM_RESULT.size
assert body == w.CLAIM_RESULT.pack(bytes.fromhex(env['KER_RUNTIME_SERVICE_WORKER_PROFILE']))
pid = os.fork()
if pid == 0:
    try:
        rpc(channel, w.CHECK, 2, lease)
        os._exit(23)
    except BaseException:
        os._exit(0)
_, status = os.waitpid(pid, 0)
assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, os.WEXITSTATUS(status) if os.WIFEXITED(status) else status
channel.close()

open(env['KER_TEST_LEASE_DROPPED'], 'w').close()
while not os.path.exists(env['KER_TEST_LEASE_CONTINUE']):
    time.sleep(0.005)

# Same process reconnects with the opaque lease and can check/release exactly
# once; a socket disconnect alone did not release the worker resource pin.
channel = connect()
assert rpc(channel, w.CHECK, 1, lease)[0] == 0
assert rpc(channel, w.RELEASE, 2, lease)[0] == 0
channel.close()
print(json.dumps({'sibling_claim': 13, 'inherited_socket_rejected': True,
    'claim': 0, 'reconnect_check': 0, 'release': 0}))
'''

EMPTY_RIGHTS_ACTOR = r'''import array, os, socket
import runtime_service_wire as w
env = os.environ
channel = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
channel.connect(env['KER_RUNTIME_SERVICE_PATH'])
nonce = bytes.fromhex(env['KER_RUNTIME_SERVICE_NONCE'])
epoch = int(env['KER_RUNTIME_SERVICE_EPOCH'])
request = w.pack_header(w.CLAIM, 1, epoch, nonce,
    packet_length=w.HEADER.size + w.CLAIM_BODY.size) + w.CLAIM_BODY.pack(
        bytes.fromhex(env['KER_RUNTIME_SERVICE_TICKET']),
        bytes.fromhex(env['KER_RUNTIME_SERVICE_PROFILE']))
channel.sendall(request)
response = channel.recv(w.HEADER.size + w.CLAIM_RESULT.size)
_, status, _, _, _, lease = w.unpack_header(response)
assert status == 0
fd = os.open('/dev/null', os.O_RDONLY)
channel.sendmsg([b''], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
    array.array('i', [fd]))])
os.close(fd)
channel.close()
'''


class RuntimeServiceActorGrantTest(unittest.TestCase):
    def test_direct_child_only_and_reconnect_release(self):
        with tempfile.TemporaryDirectory(prefix='ker-runtime-service-test-') as directory:
            worker = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
            worker_pidfd = os.pidfd_open(worker.pid, 0)
            control_read, control_write = os.pipe2(os.O_CLOEXEC)
            service = None
            actor = None
            actor_pidfd = -1
            try:
                ready = {'process_type': 'primary', 'mbuf_pool_count': 4,
                    'queues': 1, 'memory_bytes': 65536, 'port': 'test-port'}
                service = runtime_service.RuntimeServiceSupervisor(
                    Path(directory) / 'service.sock', worker, worker_pidfd,
                    runtime_service.process_start_ticks(worker.pid),
                    runtime_service.sha256_file(f'/proc/{worker.pid}/exe'), ready,
                    runtime_service.sha256_file(sys.executable),
                    hashlib.sha256(b'ff-slim-primary-profile-v1').digest(),
                    control_write, ttl_seconds=30, max_clients=1)
                # The supervisor retains its own control writer; closing the
                # caller-side writer must not stop the real worker resource.
                os.close(control_write)
                control_write = -1
                service.start()
                env = os.environ.copy()
                env.update(service.env)
                env['PYTHONPATH'] = str(TOOLS)
                dropped_marker = Path(directory) / 'lease-dropped'
                continue_marker = Path(directory) / 'continue-reconnect'
                env['KER_TEST_LEASE_DROPPED'] = str(dropped_marker)
                env['KER_TEST_LEASE_CONTINUE'] = str(continue_marker)
                actor = subprocess.Popen([sys.executable, '-c', ACTOR], env=env,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                actor_pidfd = os.pidfd_open(actor.pid, 0)
                service.bind_actor(actor, actor_pidfd)
                deadline = time.monotonic() + 5
                while not dropped_marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.005)
                self.assertTrue(dropped_marker.exists(), 'actor did not close its first service connection')
                self.assertEqual(service.active_count, 1,
                    'socket EOF incorrectly released the worker resource lease')
                self.assertFalse(select.select([control_read], [], [], 0)[0],
                    'worker control channel closed while the actor lease was live')
                continue_marker.touch()
                stdout, stderr = actor.communicate(timeout=10)
                self.assertEqual(actor.returncode, 0, stderr)
                result = json.loads(stdout)
                self.assertEqual(result['sibling_claim'], 13)
                self.assertTrue(result['inherited_socket_rejected'])
                self.assertEqual((result['claim'], result['reconnect_check'],
                    result['release']), (0, 0, 0))
                self.assertEqual(service.active_count, 0)
                self.assertTrue(service.wait_for_release(0.1))

                def wait_client_count(count):
                    deadline = time.monotonic() + 2
                    while len(service._connection_threads) != count and time.monotonic() < deadline:
                        time.sleep(0.005)
                    self.assertEqual(len(service._connection_threads), count)

                held = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                held.settimeout(2)
                held.connect(service.path)
                wait_client_count(1)
                excess = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                excess.settimeout(2)
                excess.connect(service.path)
                self.assertEqual(excess.recv(1), b'',
                    'service did not reject a connection over its thread limit')
                excess.close()
                held.close()
                wait_client_count(0)
                recovered = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                recovered.settimeout(2)
                recovered.connect(service.path)
                wait_client_count(1)
                recovered.close()
                wait_client_count(0)
                self.assertTrue(service.prepare_worker_shutdown(0.1))
                self.assertEqual(os.read(control_read, 1), b'',
                    'worker control channel remained pinned after explicit shutdown')
            finally:
                if actor is not None and actor.poll() is None:
                    actor.kill()
                    actor.wait()
                if service is not None:
                    service.close()
                if worker.poll() is None:
                    worker.terminate()
                    try:
                        worker.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        worker.kill()
                        worker.wait()
                for descriptor in (actor_pidfd, worker_pidfd, control_read, control_write):
                    if descriptor >= 0:
                        os.close(descriptor)

    def test_zero_length_rights_message_closes_fd_and_revokes_actor(self):
        with tempfile.TemporaryDirectory(prefix='ker-runtime-service-rights-') as directory:
            worker = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
            worker_pidfd = os.pidfd_open(worker.pid, 0)
            control_read, control_write = os.pipe2(os.O_CLOEXEC)
            service = None
            actor = None
            actor_pidfd = -1
            try:
                ready = {'process_type': 'primary', 'mbuf_pool_count': 4, 'queues': 1}
                service = runtime_service.RuntimeServiceSupervisor(
                    Path(directory) / 'service.sock', worker, worker_pidfd,
                    runtime_service.process_start_ticks(worker.pid),
                    runtime_service.process_executable_hash(worker.pid), ready,
                    runtime_service.sha256_file(sys.executable),
                    hashlib.sha256(b'ff-slim-primary-profile-v1').digest(),
                    control_write, max_clients=1)
                service.start()
                def null_descriptors():
                    count = 0
                    for name in os.listdir('/proc/self/fd'):
                        try:
                            count += os.readlink('/proc/self/fd/' + name) == '/dev/null'
                        except FileNotFoundError:
                            pass
                    return count
                baseline_null_fds = null_descriptors()
                env = os.environ.copy()
                env.update(service.env)
                env['PYTHONPATH'] = str(TOOLS)
                actor = subprocess.Popen([sys.executable, '-c', EMPTY_RIGHTS_ACTOR],
                    env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                actor_pidfd = os.pidfd_open(actor.pid, 0)
                service.bind_actor(actor, actor_pidfd)
                _, stderr = actor.communicate(timeout=5)
                self.assertEqual(actor.returncode, 0, stderr)
                deadline = time.monotonic() + 2
                while not service.revoked and time.monotonic() < deadline:
                    time.sleep(0.005)
                self.assertTrue(service.revoked, 'malformed actor packet did not revoke the grant')
                self.assertEqual(service.active_count, 0)
                os.close(actor_pidfd)
                actor_pidfd = -1
                deadline = time.monotonic() + 2
                while service._connection_threads and time.monotonic() < deadline:
                    time.sleep(0.005)
                self.assertFalse(service._connection_threads)
                self.assertEqual(null_descriptors(), baseline_null_fds,
                    'zero-length SCM_RIGHTS packet leaked its received descriptor')
            finally:
                if actor is not None and actor.poll() is None:
                    actor.kill()
                    actor.wait()
                if service is not None:
                    service.close()
                if worker.poll() is None:
                    worker.terminate()
                    try:
                        worker.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        worker.kill()
                        worker.wait()
                for descriptor in (actor_pidfd, worker_pidfd, control_read, control_write):
                    if descriptor >= 0:
                        os.close(descriptor)


if __name__ == '__main__':
    unittest.main()
