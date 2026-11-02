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
import threading
import time
import unittest


TOOLS = Path(__file__).resolve().parents[2] / 'tools'
sys.path.insert(0, str(TOOLS))
import runtime_service
import runtime_service_wire as wire


ACTOR = r'''import array, json, os, socket, sys, time
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
        fd = os.open('/dev/null', os.O_RDONLY)
        packet = w.pack_header(w.CHECK, 2, epoch, nonce, lease,
            packet_length=w.HEADER.size)
        channel.sendmsg([packet], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
            array.array('i', [fd]))])
        os.close(fd)
        os._exit(0)
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

DELEGATION_CHAIN_ACTOR = r"""import array, os, secrets, socket, sys, time
import runtime_service_wire as w
env = os.environ
path = env['KER_RUNTIME_SERVICE_PATH']
nonce = bytes.fromhex(env['KER_RUNTIME_SERVICE_NONCE'])
epoch = int(env['KER_RUNTIME_SERVICE_EPOCH'])
profile = bytes.fromhex(env['KER_RUNTIME_SERVICE_PROFILE'])
ticket = bytes.fromhex(env['KER_RUNTIME_SERVICE_TICKET'])
role = w.ROLE_SLIM_STAGE1
final_claimed = env['KER_TEST_FINAL_CLAIMED']
final_release = env['KER_TEST_FINAL_RELEASE']

def connect():
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    sock.connect(path)
    sock.settimeout(3)
    return sock

def rpc(sock, operation, sequence, lease=b'\0' * w.LEASE_BYTES, body=b'', fd=None):
    packet = w.pack_header(operation, sequence, epoch, nonce, lease,
        packet_length=w.HEADER.size + len(body)) + body
    if fd is None:
        sent = sock.send(packet)
    else:
        sent = sock.sendmsg([packet], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
            array.array('i', [fd]))])
    assert sent == len(packet)
    response = sock.recv(w.HEADER.size + 64)
    op, status, seq, got_epoch, got_nonce, got_lease = w.unpack_header(response)
    assert (op, seq, got_epoch, got_nonce) == (operation, sequence, epoch, nonce)
    return status, got_lease, response[w.HEADER.size:]

def create_child(sock, sequence, lease, child_role):
    status, _, body = rpc(sock, w.DELEGATE_INTENT, sequence, lease, body=
        w.pack_delegate_intent(secrets.token_bytes(16), child_role))
    assert status == 0
    intent = w.unpack_intent_result(body)
    child_env = dict(env)
    child_env['KER_TEST_EXPECTED_PARENT_PID'] = str(os.getpid())
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(write_fd)
        os.dup2(read_fd, 0)
        if read_fd != 0:
            os.close(read_fd)
        os.execve(sys.executable, [sys.executable, '-c', CHILD, CHILD], child_env)
    os.close(read_fd)
    child_pidfd = os.pidfd_open(pid, 0)
    status, _, _ = rpc(sock, w.DELEGATE_BIND, sequence + 1,
        b'\xa5' * w.LEASE_BYTES,
        body=w.pack_delegate_bind(intent), fd=child_pidfd)
    assert status == 116, 'BIND accepted a different parent lease from the intent'
    status, _, body = rpc(sock, w.DELEGATE_BIND, sequence + 2, lease,
        body=w.pack_delegate_bind(intent), fd=child_pidfd)
    os.close(child_pidfd)
    assert status == 0
    grant_ticket, returned_role = w.unpack_bind_result(body)
    assert returned_role == child_role
    assert os.write(write_fd, grant_ticket + returned_role.to_bytes(4, 'little')) == 36
    os.close(write_fd)
    return pid, sequence + 3

CHILD = r'''import array, os, socket, sys, time
import runtime_service_wire as w
env = os.environ
grant = sys.stdin.buffer.read(w.DELEGATE_BIND_RESULT.size)
assert len(grant) == w.DELEGATE_BIND_RESULT.size
ticket, role = w.unpack_bind_result(grant)
nonce = bytes.fromhex(env['KER_RUNTIME_SERVICE_NONCE'])
epoch = int(env['KER_RUNTIME_SERVICE_EPOCH'])
profile = bytes.fromhex(env['KER_RUNTIME_SERVICE_PROFILE'])

def connect():
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    sock.connect(env['KER_RUNTIME_SERVICE_PATH'])
    sock.settimeout(3)
    return sock

def rpc(sock, operation, sequence, lease=b'\0' * w.LEASE_BYTES, body=b'', fd=None):
    packet = w.pack_header(operation, sequence, epoch, nonce, lease,
        packet_length=w.HEADER.size + len(body)) + body
    if fd is None:
        sent = sock.send(packet)
    else:
        sent = sock.sendmsg([packet], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
            array.array('i', [fd]))])
    assert sent == len(packet)
    response = sock.recv(w.HEADER.size + 64)
    op, status, seq, got_epoch, got_nonce, got_lease = w.unpack_header(response)
    assert (op, seq, got_epoch, got_nonce) == (operation, sequence, epoch, nonce)
    return status, got_lease, response[w.HEADER.size:]

def create_child(sock, sequence, lease, child_role):
    status, _, body = rpc(sock, w.DELEGATE_INTENT, sequence, lease, body=
        w.pack_delegate_intent(os.urandom(16), child_role))
    assert status == 0
    intent = w.unpack_intent_result(body)
    child_env = dict(env)
    child_env['KER_TEST_EXPECTED_PARENT_PID'] = str(os.getpid())
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(write_fd)
        os.dup2(read_fd, 0)
        if read_fd != 0:
            os.close(read_fd)
        os.execve(sys.executable,
            [sys.executable, '-c', sys.argv[1], sys.argv[1]], child_env)
    os.close(read_fd)
    child_pidfd = os.pidfd_open(pid, 0)
    status, _, _ = rpc(sock, w.DELEGATE_BIND, sequence + 1,
        b'\xa5' * w.LEASE_BYTES,
        body=w.pack_delegate_bind(intent), fd=child_pidfd)
    assert status == 116, 'BIND accepted a different parent lease from the intent'
    status, _, body = rpc(sock, w.DELEGATE_BIND, sequence + 2, lease,
        body=w.pack_delegate_bind(intent), fd=child_pidfd)
    os.close(child_pidfd)
    assert status == 0
    grant_ticket, returned_role = w.unpack_bind_result(body)
    assert returned_role == child_role
    assert os.write(write_fd, grant_ticket + returned_role.to_bytes(4, 'little')) == 36
    os.close(write_fd)
    return pid, sequence + 3

sock = connect()
if role == w.ROLE_SLIM_STAGE1:
    status, lease, body = rpc(sock, w.CLAIM, 1,
        body=w.CLAIM_BODY.pack(ticket, profile))
    assert status == 0 and len(body) == w.CLAIM_RESULT.size
    # The stage1 parent remains alive until BIND completes, then exits. The
    # final child waits for this PID to change before attempting CLAIM.
    child_pid, next_sequence = create_child(sock, 2, lease, w.ROLE_SLIM_PRIMARY)
    status, _, _ = rpc(sock, w.DELEGATE_INTENT, next_sequence, lease, body=
        w.pack_delegate_intent(os.urandom(16), w.ROLE_SLIM_PRIMARY))
    assert status == 13, 'stage1 replacement grant was unexpectedly accepted'
    status, _, _ = rpc(sock, w.RELEASE, next_sequence + 1, lease)
    assert status == 0
    status, _, _ = rpc(sock, w.RELEASE, next_sequence + 2, lease)
    assert status == 0, 'stage1 lost its exact RELEASE tombstone'
    os.close(sock.fileno())
    os._exit(0)
assert role == w.ROLE_SLIM_PRIMARY
old_parent = int(env['KER_TEST_EXPECTED_PARENT_PID'])
deadline = time.monotonic() + 5
while os.getppid() == old_parent and time.monotonic() < deadline:
    time.sleep(0.002)
assert os.getppid() != old_parent, 'stage1 parent did not exit before final CLAIM'
defer_claim = env.get('KER_TEST_DEFER_FINAL_CLAIM')
if defer_claim:
    deadline = time.monotonic() + 5
    while not os.path.exists(env['KER_TEST_ALLOW_FINAL_CLAIM']) and time.monotonic() < deadline:
        time.sleep(0.002)
    assert os.path.exists(env['KER_TEST_ALLOW_FINAL_CLAIM'])
status, lease, body = rpc(sock, w.CLAIM, 1,
    body=w.CLAIM_BODY.pack(ticket, profile))
if status != 0:
    status_marker = env.get('KER_TEST_FINAL_CLAIM_STATUS')
    if status_marker:
        open(status_marker, 'w').write(str(status))
        os._exit(0)
assert status == 0 and len(body) == w.CLAIM_RESULT.size
status, _, _ = rpc(sock, w.CHECK, 2, lease)
assert status == 0
open(env['KER_TEST_FINAL_CLAIMED'], 'w').close()
if env.get('KER_TEST_FINAL_EXIT_AFTER_CLAIM'):
    os._exit(0)
deadline = time.monotonic() + 10
while not os.path.exists(env['KER_TEST_FINAL_RELEASE']) and time.monotonic() < deadline:
    time.sleep(0.005)
assert os.path.exists(env['KER_TEST_FINAL_RELEASE'])
status, _, _ = rpc(sock, w.RELEASE, 3, lease)
assert status == 0
status, _, _ = rpc(sock, w.RELEASE, 4, lease)
assert status == 0, 'primary lost its exact RELEASE tombstone'
sock.close()
'''

master = connect()
status, master_lease, _ = rpc(master, w.CLAIM, 1,
    body=w.CLAIM_BODY.pack(ticket, profile))
assert status == 0
stage1_pid, next_sequence = create_child(master, 2, master_lease,
    w.ROLE_SLIM_STAGE1)
status, _, _ = rpc(master, w.DELEGATE_INTENT, next_sequence, master_lease, body=
    w.pack_delegate_intent(secrets.token_bytes(16), w.ROLE_SLIM_STAGE1))
assert status == 13, 'master replacement stage1 grant was unexpectedly accepted'
if env.get('KER_TEST_MASTER_HOLD'):
    status, _, _ = rpc(master, w.RELEASE, next_sequence + 1, master_lease)
    assert status == 0
    open(env['KER_TEST_MASTER_RELEASED'], 'w').close()
    deadline = time.monotonic() + 10
    while not os.path.exists(final_release) and time.monotonic() < deadline:
        time.sleep(0.005)
    assert os.path.exists(final_release)
    status, _, _ = rpc(master, w.RELEASE, next_sequence + 2, master_lease)
    assert status == 0, 'master RELEASE tombstone was lost after child role releases'
master.close()
os._exit(0)
"""


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
                deadline = time.monotonic() + 2
                while service._connection_threads and time.monotonic() < deadline:
                    time.sleep(0.005)
                self.assertFalse(service._connection_threads)
                self.assertEqual(null_descriptors(), baseline_null_fds,
                    'forked peer SCM_RIGHTS descriptor leaked before credential rejection')
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
                if actor is not None and actor.stderr is not None:
                    actor.stderr.close()
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


class RuntimeServiceDelegationWireTest(unittest.TestCase):
    def test_fixed_delegation_records_round_trip(self):
        nonce = bytes(range(wire.NONCE_BYTES))
        intent_id = bytes(range(16, 32))
        ticket = bytes(range(wire.TICKET_BYTES))
        for role in (wire.ROLE_SLIM_STAGE1, wire.ROLE_SLIM_PRIMARY):
            with self.subTest(role=role):
                intent = wire.pack_delegate_intent(nonce, role)
                self.assertEqual(len(intent), 24)
                self.assertEqual(wire.unpack_delegate_intent(intent), (nonce, role))
                self.assertEqual(wire.unpack_intent_result(
                    wire.pack_intent_result(intent_id)), intent_id)
                bind = wire.pack_delegate_bind(intent_id)
                self.assertEqual(len(bind), 16)
                self.assertEqual(wire.unpack_delegate_bind(bind), intent_id)
                grant = wire.pack_bind_result(ticket, role)
                self.assertEqual(len(grant), 36)
                self.assertEqual(wire.unpack_bind_result(grant), (ticket, role))

    def test_delegation_codec_rejects_bad_lengths_roles_and_reserved_bits(self):
        with self.assertRaises(ValueError):
            wire.pack_delegate_intent(b'short', wire.ROLE_SLIM_STAGE1)
        with self.assertRaises(ValueError):
            wire.pack_delegate_intent(bytes(16), 99)
        good = wire.pack_delegate_intent(bytes(16), wire.ROLE_SLIM_STAGE1)
        with self.assertRaises(ValueError):
            wire.unpack_delegate_intent(good[:-1])
        with self.assertRaises(ValueError):
            wire.unpack_delegate_intent(good[:20] + b'\x01\x00\x00\x00')
        with self.assertRaises(ValueError):
            wire.unpack_delegate_intent(good[:16] + b'\x63\x00\x00\x00' + bytes(4))
        with self.assertRaises(ValueError):
            wire.unpack_intent_result(bytes(15))
        with self.assertRaises(ValueError):
            wire.unpack_delegate_bind(bytes(17))
        with self.assertRaises(ValueError):
            wire.unpack_bind_result(bytes(36 - 4) + b'\x63\x00\x00\x00')


class RuntimeServiceDelegationChainTest(unittest.TestCase):
    def test_two_stage_pidfd_grants_survive_parent_exit_and_pin_worker(self):
        with tempfile.TemporaryDirectory(prefix='ker-runtime-service-delegation-') as directory:
            worker = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
            worker_pidfd = os.pidfd_open(worker.pid, 0)
            control_read, control_write = os.pipe2(os.O_CLOEXEC)
            actor = None
            actor_pidfd = -1
            service = None
            try:
                ready = {'process_type': 'primary', 'mbuf_pool_count': 4,
                    'queues': 1, 'memory_bytes': 65536, 'port': 'test-port'}
                actor_path = Path(os.environ.get('KER_TEST_C33_ACTOR', sys.executable)).resolve()
                app_hash = runtime_service.sha256_file(actor_path)
                service = runtime_service.RuntimeServiceSupervisor(
                    Path(directory) / 'service.sock', worker, worker_pidfd,
                    runtime_service.process_start_ticks(worker.pid),
                    runtime_service.process_executable_hash(worker.pid), ready,
                    app_hash, hashlib.sha256(b'ff-slim-delegation-test-v1').digest(),
                    control_write, ttl_seconds=30, max_clients=4,
                    delegation_enabled=True)
                os.close(control_write)
                control_write = -1
                service.start()
                claimed = Path(directory) / 'final-claimed'
                release = Path(directory) / 'final-release'
                env = os.environ.copy()
                env.update(service.env)
                env['PYTHONPATH'] = str(TOOLS)
                env['KER_TEST_FINAL_CLAIMED'] = str(claimed)
                env['KER_TEST_FINAL_RELEASE'] = str(release)
                error_log = Path(directory) / 'delegation-stderr'
                error_stream = error_log.open('w')
                actor_command = ([str(actor_path)] if 'KER_TEST_C33_ACTOR' in os.environ else
                    [sys.executable, '-c', DELEGATION_CHAIN_ACTOR])
                actor = subprocess.Popen(actor_command,
                    env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=error_stream)
                error_stream.close()
                actor_pidfd = os.pidfd_open(actor.pid, 0)
                service.bind_actor(actor, actor_pidfd)
                actor.wait(timeout=10)
                self.assertEqual(actor.returncode, 0, error_log.read_text())

                deadline = time.monotonic() + 8
                while not claimed.exists() and time.monotonic() < deadline:
                    time.sleep(0.005)
                self.assertTrue(claimed.exists(),
                    'reparented final child did not claim its bound grant: ' +
                    error_log.read_text())
                self.assertFalse(select.select([control_read], [], [], 0)[0],
                    'master exit released the worker before final-role RELEASE')
                self.assertEqual(service.active_count, 1)
                release.touch()
                deadline = time.monotonic() + 8
                while service.active_count and time.monotonic() < deadline:
                    time.sleep(0.005)
                self.assertEqual(service.active_count, 0)
                self.assertTrue(service.wait_for_release(1.0))
                self.assertTrue(service.prepare_worker_shutdown(0.1))
                self.assertEqual(os.read(control_read, 1), b'')
            finally:
                if actor is not None and actor.poll() is None:
                    actor.kill()
                    actor.wait()
                if actor is not None and actor.stderr is not None:
                    actor.stderr.close()
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

    def test_unclaimed_bound_grant_expires_and_child_ticket_stays_stale(self):
        class ControlledClock:
            value = 100.0

            def __call__(self):
                return self.value

        clock = ControlledClock()
        with tempfile.TemporaryDirectory(prefix='ker-runtime-service-expiry-') as directory:
            worker = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
            worker_pidfd = os.pidfd_open(worker.pid, 0)
            control_read, control_write = os.pipe2(os.O_CLOEXEC)
            actor = None
            actor_pidfd = -1
            service = None
            try:
                ready = {'process_type': 'primary', 'mbuf_pool_count': 4,
                    'queues': 1, 'memory_bytes': 65536, 'port': 'test-port'}
                app_hash = runtime_service.sha256_file(sys.executable)
                service = runtime_service.RuntimeServiceSupervisor(
                    Path(directory) / 'service.sock', worker, worker_pidfd,
                    runtime_service.process_start_ticks(worker.pid),
                    runtime_service.process_executable_hash(worker.pid), ready,
                    app_hash, hashlib.sha256(b'ff-slim-delegation-expiry-v1').digest(),
                    control_write, ttl_seconds=30, max_clients=4, clock=clock,
                    delegation_enabled=True)
                os.close(control_write)
                control_write = -1
                service.start()
                claimed = Path(directory) / 'final-claimed'
                release = Path(directory) / 'final-release'
                allow_claim = Path(directory) / 'allow-final-claim'
                claim_status = Path(directory) / 'final-claim-status'
                env = os.environ.copy()
                env.update(service.env)
                env['PYTHONPATH'] = str(TOOLS)
                env['KER_TEST_FINAL_CLAIMED'] = str(claimed)
                env['KER_TEST_FINAL_RELEASE'] = str(release)
                env['KER_TEST_DEFER_FINAL_CLAIM'] = '1'
                env['KER_TEST_ALLOW_FINAL_CLAIM'] = str(allow_claim)
                env['KER_TEST_FINAL_CLAIM_STATUS'] = str(claim_status)
                error_log = Path(directory) / 'delegation-stderr'
                error_stream = error_log.open('w')
                actor = subprocess.Popen([sys.executable, '-c', DELEGATION_CHAIN_ACTOR],
                    env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=error_stream)
                error_stream.close()
                actor_pidfd = os.pidfd_open(actor.pid, 0)
                service.bind_actor(actor, actor_pidfd)
                actor.wait(timeout=10)
                self.assertEqual(actor.returncode, 0)
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    with service._condition:
                        service._reap_locked()
                        pending_roles = {grant['role'] for grant in
                            service._delegated_grants.values()}
                        stage_actors = len(service._delegated_actors)
                    if (wire.ROLE_SLIM_PRIMARY in pending_roles and
                            stage_actors == 0):
                        break
                    time.sleep(0.005)
                self.assertEqual((pending_roles, stage_actors),
                    ({wire.ROLE_SLIM_PRIMARY}, 0),
                    'expected only the final unclaimed child grant to pin the worker')
                self.assertFalse(select.select([control_read], [], [], 0)[0],
                    'master and stage1 exit released worker while final grant remained live')
                clock.value += 6.0
                with service._condition:
                    service._reap_locked()
                self.assertEqual(len(service._delegated_grants), 0,
                    'expired bound grant retained its pidfd/resource pin')
                allow_claim.touch()
                deadline = time.monotonic() + 5
                while not claim_status.exists() and time.monotonic() < deadline:
                    time.sleep(0.005)
                self.assertTrue(claim_status.exists(), 'expired child did not receive a terminal claim result: ' +
                    error_log.read_text())
                self.assertEqual(claim_status.read_text(), '116',
                    'expired child ticket was accepted or returned an unrelated status')
                self.assertTrue(service.wait_for_release(1.0))
                self.assertFalse(select.select([control_read], [], [], 0)[0],
                    'server dropped worker control before explicit shutdown')
                self.assertTrue(service.prepare_worker_shutdown(0.1))
                self.assertEqual(os.read(control_read, 1), b'')
            finally:
                if actor is not None and actor.poll() is None:
                    actor.kill()
                    actor.wait()
                if actor is not None and actor.stderr is not None:
                    actor.stderr.close()
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

    def test_final_actor_death_releases_role_then_explicit_shutdown_closes_worker(self):
        with tempfile.TemporaryDirectory(prefix='ker-runtime-service-death-') as directory:
            worker = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
            worker_pidfd = os.pidfd_open(worker.pid, 0)
            control_read, control_write = os.pipe2(os.O_CLOEXEC)
            actor = None
            actor_pidfd = -1
            service = None
            try:
                ready = {'process_type': 'primary', 'mbuf_pool_count': 4,
                    'queues': 1, 'memory_bytes': 65536, 'port': 'test-port'}
                app_hash = runtime_service.sha256_file(sys.executable)
                service = runtime_service.RuntimeServiceSupervisor(
                    Path(directory) / 'service.sock', worker, worker_pidfd,
                    runtime_service.process_start_ticks(worker.pid),
                    runtime_service.process_executable_hash(worker.pid), ready,
                    app_hash, hashlib.sha256(b'ff-slim-delegation-death-v1').digest(),
                    control_write, ttl_seconds=30, max_clients=4,
                    delegation_enabled=True)
                os.close(control_write)
                control_write = -1
                service.start()
                claimed = Path(directory) / 'final-claimed'
                release = Path(directory) / 'final-release'
                env = os.environ.copy()
                env.update(service.env)
                env['PYTHONPATH'] = str(TOOLS)
                env['KER_TEST_FINAL_CLAIMED'] = str(claimed)
                env['KER_TEST_FINAL_RELEASE'] = str(release)
                env['KER_TEST_FINAL_EXIT_AFTER_CLAIM'] = '1'
                actor = subprocess.Popen([sys.executable, '-c', DELEGATION_CHAIN_ACTOR],
                    env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE, text=True)
                actor_pidfd = os.pidfd_open(actor.pid, 0)
                service.bind_actor(actor, actor_pidfd)
                actor.wait(timeout=10)
                self.assertEqual(actor.returncode, 0,
                    actor.stderr.read() if actor.stderr is not None else '')
                deadline = time.monotonic() + 8
                while (not claimed.exists() or service.active_count) and time.monotonic() < deadline:
                    time.sleep(0.005)
                self.assertTrue(claimed.exists(), 'final actor never claimed before its exit')
                self.assertEqual(service.active_count, 0,
                    'confirmed final pidfd death retained a role lease')
                self.assertFalse(select.select([control_read], [], [], 0)[0],
                    'role death unexpectedly bypassed explicit worker shutdown')
                self.assertTrue(service.wait_for_release(1.0))
                self.assertTrue(service.prepare_worker_shutdown(0.1))
                self.assertEqual(os.read(control_read, 1), b'')
            finally:
                if actor is not None and actor.poll() is None:
                    actor.kill()
                    actor.wait()
                if actor is not None and actor.stderr is not None:
                    actor.stderr.close()
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

    def test_release_tombstones_remain_per_role_after_later_releases(self):
        with tempfile.TemporaryDirectory(prefix='ker-runtime-service-tombstones-') as directory:
            worker = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
            worker_pidfd = os.pidfd_open(worker.pid, 0)
            control_read, control_write = os.pipe2(os.O_CLOEXEC)
            actor = None
            actor_pidfd = -1
            service = None
            try:
                ready = {'process_type': 'primary', 'mbuf_pool_count': 4,
                    'queues': 1, 'memory_bytes': 65536, 'port': 'test-port'}
                app_hash = runtime_service.sha256_file(sys.executable)
                service = runtime_service.RuntimeServiceSupervisor(
                    Path(directory) / 'service.sock', worker, worker_pidfd,
                    runtime_service.process_start_ticks(worker.pid),
                    runtime_service.process_executable_hash(worker.pid), ready,
                    app_hash, hashlib.sha256(b'ff-slim-delegation-tombstones-v1').digest(),
                    control_write, ttl_seconds=30, max_clients=4,
                    delegation_enabled=True)
                os.close(control_write)
                control_write = -1
                service.start()
                claimed = Path(directory) / 'final-claimed'
                release = Path(directory) / 'final-release'
                master_released = Path(directory) / 'master-released'
                env = os.environ.copy()
                env.update(service.env)
                env['PYTHONPATH'] = str(TOOLS)
                env['KER_TEST_FINAL_CLAIMED'] = str(claimed)
                env['KER_TEST_FINAL_RELEASE'] = str(release)
                env['KER_TEST_MASTER_HOLD'] = '1'
                env['KER_TEST_MASTER_RELEASED'] = str(master_released)
                actor = subprocess.Popen([sys.executable, '-c', DELEGATION_CHAIN_ACTOR],
                    env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE, text=True)
                actor_pidfd = os.pidfd_open(actor.pid, 0)
                service.bind_actor(actor, actor_pidfd)
                deadline = time.monotonic() + 8
                while (not master_released.exists() or not claimed.exists()) and time.monotonic() < deadline:
                    time.sleep(0.005)
                self.assertTrue(master_released.exists(), 'master did not release its role')
                self.assertTrue(claimed.exists(), 'final role did not claim after stage1 exit')
                self.assertEqual(service.active_count, 1,
                    'master/stage1 release did not leave exactly the primary role active')
                release.touch()
                actor.wait(timeout=10)
                self.assertEqual(actor.returncode, 0,
                    actor.stderr.read() if actor.stderr is not None else '')
                deadline = time.monotonic() + 5
                while service.active_count and time.monotonic() < deadline:
                    time.sleep(0.005)
                self.assertEqual(service.active_count, 0)
                self.assertTrue(service.wait_for_release(1.0))
                self.assertTrue(service.prepare_worker_shutdown(0.1))
                self.assertEqual(os.read(control_read, 1), b'')
            finally:
                if actor is not None and actor.poll() is None:
                    actor.kill()
                    actor.wait()
                if actor is not None and actor.stderr is not None:
                    actor.stderr.close()
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


class RuntimeServiceAncillaryRightsTest(unittest.TestCase):
    def test_received_rights_are_closed_when_process_identity_recheck_fails(self):
        sender = r'''import array, os, socket, time
s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
s.connect(os.environ['KER_RUNTIME_SERVICE_PATH'])
fd = os.open('/dev/null', os.O_RDONLY)
s.sendmsg([b'bad'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [fd]))])
os.close(fd)
time.sleep(0.05)
s.close()
'''
        with tempfile.TemporaryDirectory(prefix='ker-runtime-service-identity-fd-') as directory:
            worker = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
            worker_pidfd = os.pidfd_open(worker.pid, 0)
            control_read, control_write = os.pipe2(os.O_CLOEXEC)
            service = None
            actor = None
            original = runtime_service.process_start_ticks
            try:
                ready = {'process_type': 'primary', 'mbuf_pool_count': 4,
                    'queues': 1, 'memory_bytes': 65536, 'port': 'test-port'}
                service = runtime_service.RuntimeServiceSupervisor(
                    Path(directory) / 'service.sock', worker, worker_pidfd,
                    original(worker.pid), runtime_service.process_executable_hash(worker.pid),
                    ready, runtime_service.sha256_file(sys.executable),
                    hashlib.sha256(b'ff-slim-identity-fd-test-v1').digest(), control_write)
                service.start()
                def null_descriptors():
                    count = 0
                    for name in os.listdir('/proc/self/fd'):
                        try:
                            count += os.readlink('/proc/self/fd/' + name) == '/dev/null'
                        except FileNotFoundError:
                            pass
                    return count
                baseline = null_descriptors()
                calls = {}
                def fail_identity_recheck(pid):
                    if threading.current_thread().name == 'ker-runtime-service-client':
                        calls[pid] = calls.get(pid, 0) + 1
                        if calls[pid] == 2:
                            raise OSError(5, 'injected peer identity read failure')
                    return original(pid)
                runtime_service.process_start_ticks = fail_identity_recheck
                env = os.environ.copy()
                env.update(service.env)
                actor = subprocess.Popen([sys.executable, '-c', sender], env=env,
                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
                _, stderr = actor.communicate(timeout=5)
                self.assertEqual(actor.returncode, 0, stderr)
                deadline = time.monotonic() + 2
                while service._connection_threads and time.monotonic() < deadline:
                    time.sleep(0.005)
                self.assertEqual(calls.get(actor.pid), 2,
                    'injected failure did not occur on the post-recv identity recheck')
                self.assertEqual(null_descriptors(), baseline,
                    'SCM_RIGHTS descriptor leaked when peer identity recheck failed')
            finally:
                runtime_service.process_start_ticks = original
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
                for descriptor in (worker_pidfd, control_read, control_write):
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
