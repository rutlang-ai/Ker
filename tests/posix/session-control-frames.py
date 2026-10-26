#!/usr/bin/env python3
"""Real resident control-frame checks; no secondary EAL or network traffic."""
import argparse
from contextlib import ExitStack, closing, contextmanager
import errno
import importlib.util
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

from dpdk_runtime import private_runtime_environment


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def channel(path):
    result = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    result.settimeout(3)
    try:
        result.connect(str(path))
    except BaseException:
        result.close()
        raise
    return result


def exchange(api, connection, request, status=0):
    connection.sendall(api.encode(request))
    raw = connection.recv(129)
    require(len(raw) == 128, 'resident reply has wrong record length')
    reply = dict(zip(api.FIELDS, api.WIRE.unpack(raw)))
    # Independent signed-byte interpretation checks negative C errno replies.
    require(int.from_bytes(raw[88:96], sys.byteorder, signed=True) == status,
            'resident status differs from expected errno: ' + repr(reply))
    require(reply['status'] == status and reply['command'] == request['command'] and
            reply['sequence'] == request['sequence'], 'reply lost request identity')
    return raw, reply


def status_snapshot(api, path, session, slots=0, users=0):
    with closing(api.Connection(path)) as connection:
        reply = connection.request(api.STATUS)
    require(reply['session'] == session and reply['generation'] == 511 - users and
            reply['token'] == users and reply['slot'] == slots and reply['process'] == users,
            'control request leaked objects, slots or users: ' + repr(reply))
    return reply


def roundtrip(api, path, session):
    with closing(api.Connection(path)) as connection:
        reply = connection.request(api.STATUS)
        require(reply['sequence'] == 1 and reply['session'] == session and
                reply['generation'] == 511 and reply['token'] == 0,
                'Python/C STATUS roundtrip failed')
        live = connection.request(api.EPOCH_LIVE, epoch=0)
        require(live['sequence'] == 2 and live['token'] == 1 and live['session'] == session,
                'resident epoch query failed')
        epoch = 0xfedcba9876543210
        absent = connection.request(api.EPOCH_LIVE, epoch=epoch)
        require(absent['sequence'] == 3 and absent['epoch'] == epoch and
                absent['token'] == 0 and absent['session'] == session,
                '64-bit epoch did not survive C/Python roundtrip')
    # A sequence with its high bit set must remain an unsigned 64-bit value.
    with channel(path) as connection:
        raw, reply = exchange(api, connection, api.packet(api.STATUS, 0x8000000000000042))
        require(int.from_bytes(raw[24:32], sys.byteorder) == 0x8000000000000042 and
                reply['session'] == session, '64-bit sequence was truncated')
    status_snapshot(api, path, session)


def malformed(api, path, session):
    valid = api.encode(api.packet(api.STATUS, 1))
    for length in (0, 1, 127, 129, 256):
        payload = valid[:length] if length < 128 else valid + bytes(length - 128)
        with channel(path) as connection:
            require(connection.send(payload) == length, 'short local record send')
            try:
                reply = connection.recv(129)
            except ConnectionResetError:
                reply = b''
            require(reply == b'', 'resident accepted a malformed record length')
        status_snapshot(api, path, session)
    cases = [({'magic': api.MAGIC ^ 1}, -errno.EPROTO),
             ({'version': api.VERSION + 1}, -errno.EPROTO),
             ({'status': -1}, -errno.EPROTO), ({'status': 1}, -errno.EPROTO),
             ({'status': 2}, -errno.EPROTO), ({'sequence': 0}, -errno.EPROTO)]
    for field in ('session', 'epoch', 'generation', 'process', 'token', 'slot',
                  'capability', 'tx_lease_id', 'rx_lease_id', 'packet_pool_tag',
                  'packet_object_index', 'packet_port', 'packet_queue'):
        cases.append(({field: 1}, -errno.EINVAL))
    for changes, expected in cases:
        request = api.packet(api.STATUS, 1)
        request.update(changes)
        with channel(path) as connection:
            exchange(api, connection, request, expected)
            # The same transport must make progress after a rejected frame.
            exchange(api, connection, api.packet(api.STATUS, 2))
        status_snapshot(api, path, session)
    with channel(path) as connection:
        _, ticket = exchange(api, connection, api.packet(api.MASTER, 1))
        identity = {key: ticket[key] for key in ('session', 'epoch', 'token', 'slot')}
        for sequence, command in ((2, 0), (3, 0xffffffffffffffff)):
            exchange(api, connection, api.packet(command, sequence, **identity), -errno.EOPNOTSUPP)
        exchange(api, connection, api.packet(api.RELEASE, 4, **identity))
    status_snapshot(api, path, session)


def replay(api, path, session):
    with channel(path) as connection:
        request = api.packet(api.MASTER, 1)
        original, ticket = exchange(api, connection, request)
        repeated, _ = exchange(api, connection, request)
        require(repeated == original, 'identical MASTER retry was not byte-identical')
        with closing(api.Connection(path)) as observer:
            state = observer.request(api.STATUS)
        require(state['slot'] == 1 and state['process'] == 0 and state['token'] == 0,
                'MASTER retry allocated another slot or mbuf')
        identity = {key: ticket[key] for key in ('session', 'epoch', 'token', 'slot')}
        exchange(api, connection, api.packet(api.RELEASE, 1, **identity), -errno.EPROTO)
        exchange(api, connection, api.packet(api.STATUS, 0), -errno.EPROTO)
        with closing(api.Connection(path)) as observer:
            require(observer.request(api.EPOCH_LIVE, epoch=ticket['epoch'])['token'] == 1,
                    'conflicting replay released the master epoch')
        release = api.packet(api.RELEASE, 2, **identity)
        original, _ = exchange(api, connection, release)
        repeated, _ = exchange(api, connection, release)
        require(repeated == original, 'identical RELEASE retry was not byte-identical')
        exchange(api, connection, api.packet(api.RELEASE, 3, **identity), -errno.ESTALE)
        with closing(api.Connection(path)) as observer:
            require(observer.request(api.EPOCH_LIVE, epoch=ticket['epoch'])['token'] == 0,
                    'released epoch is still reported live')
    status_snapshot(api, path, session)


def identity(ticket):
    return {key: ticket[key] for key in ('session', 'epoch', 'token', 'slot')}


def epoch_live(api, path, epoch, expected):
    with closing(api.Connection(path)) as observer:
        reply = observer.request(api.EPOCH_LIVE, epoch=epoch)
    require(reply['epoch'] == epoch and reply['token'] == expected,
            'unexpected epoch liveness: ' + repr(reply))


def isolation(api, path, session):
    with channel(path) as first, channel(path) as second, channel(path) as stranger:
        # Sequence caches belong to connections, even with identical peer PIDs.
        _, a = exchange(api, first, api.packet(api.MASTER, 1))
        original, b = exchange(api, second, api.packet(api.MASTER, 1))
        require(a['slot'] != b['slot'] and a['epoch'] != b['epoch'] and
                a['token'] != 0 and b['token'] != 0, 'masters share slot identity')
        status_snapshot(api, path, session, slots=2)
        exchange(api, first, api.packet(api.RELEASE, 2, **identity(b)), -errno.EPERM)
        exchange(api, stranger, api.packet(api.RELEASE, 1, **identity(a)), -errno.EPERM)
        bad = identity(a)
        bad['token'] ^= 1
        exchange(api, first, api.packet(api.RELEASE, 3, **bad), -errno.ESTALE)
        for ticket in (a, b):
            epoch_live(api, path, ticket['epoch'], 1)
        repeated, _ = exchange(api, second, api.packet(api.MASTER, 1))
        require(repeated == original, 'another connection changed the replay cache')
        status_snapshot(api, path, session, slots=2)
        exchange(api, first, api.packet(api.RELEASE, 4, **identity(a)))
        epoch_live(api, path, b['epoch'], 1)
        exchange(api, second, api.packet(api.RELEASE, 2, **identity(b)))
    status_snapshot(api, path, session)


def capacity(api, path, session):
    with ExitStack() as stack:
        connections = [stack.enter_context(channel(path)) for _ in range(4)]
        tickets = [exchange(api, connection, api.packet(api.MASTER, 1))[1]
                   for connection in connections[:3]]
        require({ticket['slot'] for ticket in tickets} == {1, 2, 3},
                'unexpected resident slot capacity')
        status_snapshot(api, path, session, slots=3)
        request = api.packet(api.MASTER, 1)
        rejected, _ = exchange(api, connections[3], request, -errno.ENOSPC)
        repeated, _ = exchange(api, connections[3], request, -errno.ENOSPC)
        require(repeated == rejected, 'capacity error retry changed its cached reply')
        for ticket in tickets:
            epoch_live(api, path, ticket['epoch'], 1)
        status_snapshot(api, path, session, slots=3)
        exchange(api, connections[1], api.packet(api.RELEASE, 2, **identity(tickets[1])))
        # The failed request remains cached after capacity returns.
        repeated, _ = exchange(api, connections[3], request, -errno.ENOSPC)
        require(repeated == rejected, 'resource change invalidated the sequence cache')
        _, replacement = exchange(api, connections[3], api.packet(api.MASTER, 2))
        require(replacement['slot'] == tickets[1]['slot'] and
                replacement['epoch'] > tickets[1]['epoch'], 'freed slot was not reusable')
        status_snapshot(api, path, session, slots=3)
        for index in (0, 2):
            exchange(api, connections[index], api.packet(api.RELEASE, 2, **identity(tickets[index])))
        exchange(api, connections[3], api.packet(api.RELEASE, 3, **identity(replacement)))
    status_snapshot(api, path, session)


def recycle(api, path, session):
    with channel(path) as old, channel(path) as current:
        _, previous = exchange(api, old, api.packet(api.MASTER, 1))
        exchange(api, old, api.packet(api.RELEASE, 2, **identity(previous)))
        epoch_live(api, path, previous['epoch'], 0)
        _, replacement = exchange(api, current, api.packet(api.MASTER, 1))
        require(replacement['slot'] == previous['slot'] and
                replacement['epoch'] > previous['epoch'], 'recycled slot retained its epoch')
        exchange(api, old, api.packet(api.RELEASE, 3, **identity(previous)), -errno.ESTALE)
        mixed = identity(replacement)
        mixed['epoch'] = previous['epoch']
        exchange(api, current, api.packet(api.RELEASE, 2, **mixed), -errno.ESTALE)
        # Even a current ticket cannot transfer ownership to the released client.
        exchange(api, old, api.packet(api.RELEASE, 4, **identity(replacement)), -errno.EPERM)
        status_snapshot(api, path, session, slots=1)
        epoch_live(api, path, previous['epoch'], 0)
        epoch_live(api, path, replacement['epoch'], 1)
        exchange(api, current, api.packet(api.RELEASE, 3, **identity(replacement)))
        epoch_live(api, path, replacement['epoch'], 0)
    status_snapshot(api, path, session)


# This child owns a real master or pre-EAL reservation connection.
# It never starts a secondary EAL.
MASTER_CHILD = r"""
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location('api', sys.argv[1])
api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(api)
connection = api.Connection(sys.argv[2])
if len(sys.argv) == 4:
    ticket = json.loads(sys.argv[3])
    reply = connection.request(api.RESERVE, **ticket)
else:
    reply = connection.request(api.MASTER)
print(json.dumps(reply), flush=True)
command = sys.stdin.buffer.read(1)
if command == b'C':
    connection.close()
    print('CLOSED', flush=True)
    command = sys.stdin.buffer.read(1)
if command != b'X':
    raise RuntimeError('unexpected master-child command')
# Deliberately leave any open socket to process teardown, without RELEASE.
"""


def child_line(process):
    data = bytearray()
    deadline = time.monotonic() + 3
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while time.monotonic() < deadline:
            if not selector.select(max(0, deadline - time.monotonic())):
                break
            byte = os.read(process.stdout.fileno(), 1)
            if not byte:
                break
            data.extend(byte)
            if byte == b'\n':
                return data.decode().rstrip('\n')
    raise RuntimeError('master child did not acknowledge: ' + repr(data))


@contextmanager
def master_child(api, path, reservation=None):
    extra = [] if reservation is None else [json.dumps(reservation)]
    process = subprocess.Popen([sys.executable, '-c', MASTER_CHILD, api.__file__, str(path), *extra],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, bufsize=0)
    pidfd = None
    try:
        pidfd = os.pidfd_open(process.pid)
        ticket = json.loads(child_line(process))
        yield process, pidfd, ticket
    finally:
        if process.poll() is None:
            process.kill()  # Also terminates a stopped child, on failure.
        process.wait(timeout=5)
        process.stdin.close()
        process.stdout.close()
        errors = process.stderr.read()
        process.stderr.close()
        if pidfd is not None:
            os.close(pidfd)
        if errors:
            print(errors.decode(errors='replace'), file=sys.stderr)


def require_pidfd(pidfd, dead):
    with selectors.DefaultSelector() as selector:
        selector.register(pidfd, selectors.EVENT_READ)
        require(bool(selector.select(0)) == dead, 'unexpected exact child pidfd liveness')


def wait_slots(api, path, session, expected):
    deadline = time.monotonic() + 3
    with closing(api.Connection(path)) as observer:
        while True:
            state = observer.request(api.STATUS)
            require(state['session'] == session and state['generation'] == 511 and
                    state['token'] == state['process'] == 0,
                    'master lifetime changed pool/user accounting: ' + repr(state))
            if state['slot'] == expected:
                return
            require(time.monotonic() < deadline, 'dead master slot was not reclaimed: ' + repr(state))
            time.sleep(0.01)


def master_lifetime(api, path, session, mode):
    with ExitStack() as stack:
        parents = [stack.enter_context(channel(path)) for _ in range(2 if mode == 'frozen' else 1)]
        tickets = [exchange(api, connection, api.packet(api.MASTER, 1))[1]
                   for connection in parents]
        child, pidfd, ticket = stack.enter_context(master_child(api, path))
        require(ticket['session'] == session and
                ticket['slot'] not in {entry['slot'] for entry in tickets},
                'child did not acquire an independent slot')
        count = len(parents) + 1
        status_snapshot(api, path, session, slots=count)
        require_pidfd(pidfd, False)
        if mode != 'death':
            require(child.stdin.write(b'C') == 1, 'failed to command child EOF')
            require(child_line(child) == 'CLOSED', 'child did not close its socket')
        if mode == 'frozen':
            signal.pidfd_send_signal(pidfd, signal.SIGSTOP)
            deadline = time.monotonic() + 3
            while Path(f'/proc/{child.pid}/stat').read_text().rsplit(')', 1)[1].split()[0] not in ('T', 't'):
                require(time.monotonic() < deadline, 'master child did not stop')
                time.sleep(0.01)
        # Positive liveness is established from the exact pidfd, not the socket.
        for _ in range(8):
            require_pidfd(pidfd, False)
            status_snapshot(api, path, session, slots=count)
            epoch_live(api, path, ticket['epoch'], 1)
        with channel(path) as foreign:
            exchange(api, foreign, api.packet(api.RELEASE, 1, **identity(ticket)), -errno.EPERM)
            if mode == 'frozen':
                exchange(api, foreign, api.packet(api.MASTER, 2), -errno.ENOSPC)
        if mode == 'eof':
            require(child.stdin.write(b'X') == 1, 'failed to request normal child exit')
            require(child.wait(timeout=5) == 0, 'master child exit failed')
        else:
            signal.pidfd_send_signal(pidfd, signal.SIGKILL)
            require(child.wait(timeout=5) == -signal.SIGKILL, 'master child did not die by SIGKILL')
        require_pidfd(pidfd, True)
        wait_slots(api, path, session, len(parents))
        epoch_live(api, path, 0, 1)
        epoch_live(api, path, ticket['epoch'], 0)
        for entry in tickets:
            epoch_live(api, path, entry['epoch'], 1)
        with channel(path) as successor:
            exchange(api, successor, api.packet(api.RELEASE, 1, **identity(ticket)), -errno.ESTALE)
            _, new = exchange(api, successor, api.packet(api.MASTER, 2))
            require(new['slot'] == ticket['slot'] and new['epoch'] > ticket['epoch'],
                    'exact process death did not make its slot reusable')
            exchange(api, successor, api.packet(api.RELEASE, 3, **identity(ticket)), -errno.ESTALE)
            epoch_live(api, path, ticket['epoch'], 0)
            epoch_live(api, path, new['epoch'], 1)
            exchange(api, successor, api.packet(api.RELEASE, 4, **identity(new)))
        for connection, entry in zip(parents, tickets):
            exchange(api, connection, api.packet(api.RELEASE, 2, **identity(entry)))
    status_snapshot(api, path, session)


def reservation_proof(api, path, session, mode):
    with ExitStack() as stack:
        master = stack.enter_context(channel(path))
        _, ticket = exchange(api, master, api.packet(api.MASTER, 1))
        coordinate = identity(ticket)
        children = []
        coordinates = ((0, 0), (1, 3)) if mode == 'coordinates' else ((0, 0),)
        for generation, process in coordinates:
            request = dict(coordinate, generation=generation, process=process)
            child, pidfd, reply = stack.enter_context(master_child(api, path, request))
            require(all(reply[key] == value for key, value in request.items()),
                    'reservation reply lost coordinate identity')
            children.append((child, pidfd))
        status_snapshot(api, path, session, slots=1, users=len(children))
        sequence = 2
        for child, pidfd in children:
            require_pidfd(pidfd, False)
            exchange(api, master, api.packet(api.RELEASE, sequence, **coordinate), -errno.EBUSY)
            sequence += 1
        if mode != 'death':
            for child, pidfd in children:
                require(child.stdin.write(b'C') == 1, 'failed to command borrower EOF')
                require(child_line(child) == 'CLOSED', 'borrower did not close its socket')
                require_pidfd(pidfd, False)
            for _ in range(8):
                status_snapshot(api, path, session, slots=1, users=len(children))
                epoch_live(api, path, ticket['epoch'], 1)
                exchange(api, master, api.packet(api.RELEASE, sequence, **coordinate), -errno.EBUSY)
                sequence += 1
        for index, (child, pidfd) in enumerate(children):
            if mode == 'eof':
                require(child.stdin.write(b'X') == 1, 'failed to request borrower exit')
                require(child.wait(timeout=5) == 0, 'borrower did not exit normally')
            else:
                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                require(child.wait(timeout=5) == -signal.SIGKILL, 'borrower did not die by SIGKILL')
            require_pidfd(pidfd, True)
            remaining = len(children) - index - 1
            deadline = time.monotonic() + 3
            with closing(api.Connection(path)) as observer:
                while True:
                    state = observer.request(api.STATUS)
                    require(state['slot'] == 1 and state['session'] == session and
                            state['generation'] + state['token'] == 511 and
                            state['process'] == state['token'],
                            'invalid reservation accounting during reap: ' + repr(state))
                    if state['process'] == remaining:
                        break
                    require(time.monotonic() < deadline, 'reservation did not reap after exact death')
                    time.sleep(0.01)
            status_snapshot(api, path, session, slots=1, users=remaining)
            epoch_live(api, path, ticket['epoch'], 1)
            epoch_live(api, path, 0, 1)
            if remaining:
                require_pidfd(children[index + 1][1], False)
                exchange(api, master, api.packet(api.RELEASE, sequence, **coordinate), -errno.EBUSY)
                sequence += 1
        exchange(api, master, api.packet(api.RELEASE, sequence, **coordinate))
        epoch_live(api, path, ticket['epoch'], 0)
    status_snapshot(api, path, session)


def ready(process):
    captured = bytearray()
    deadline = time.monotonic() + 10
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while time.monotonic() < deadline:
            if not selector.select(max(0, deadline - time.monotonic())):
                break
            data = os.read(process.stdout.fileno(), 4096)
            if not data:
                break
            captured.extend(data)
            for line in captured.splitlines(keepends=True):
                if line.startswith(b'KER_SESSION_READY ') and line.endswith(b'\n'):
                    return json.loads(line[len(b'KER_SESSION_READY '):]), bytes(captured)
    raise RuntimeError('actual resident did not publish READY: ' + captured.decode(errors='replace'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', type=Path, required=True)
    parser.add_argument('--tool', type=Path, required=True)
    parser.add_argument('--profile', choices=('roundtrip', 'malformed', 'replay', 'isolation', 'capacity', 'recycle',
                                               'master-eof', 'master-death', 'master-frozen',
                                               'reservation-eof', 'reservation-death',
                                               'reservation-coordinates'), required=True)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('control_frame_api', args.tool)
    api = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(api)
    with tempfile.TemporaryDirectory(prefix='ker-control-frame-') as temporary:
        root = Path(temporary)
        path = root / 'control.sock'
        cpu = min(os.sched_getaffinity(0))
        env = {key: value for key, value in os.environ.items() if not key.startswith('KER_SESSION_TEST_')}
        env = private_runtime_environment(root, env)
        command = [str(args.worker.resolve()), '--role', 'primary', '--socket', str(path),
                   '--control-fd', '0', '--', f'--lcores=0@{cpu}', '--no-pci', '--no-huge',
                   '--no-shconf', '--no-telemetry', '--iova-mode=va', '-m', '64',
                   f'--file-prefix=ker-control-{os.getpid()}']
        with (root / 'stderr.log').open('w+b') as errors:
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=errors, env=env)
            try:
                record, output = ready(process)
                require(record['stage'] == 'shared-control' and record['session'] != 0 and
                        record['ports'] == 0 and record['ring_pmd'] is False,
                        'unexpected resident configuration')
                profiles = {'roundtrip': roundtrip, 'malformed': malformed, 'replay': replay,
                            'isolation': isolation, 'capacity': capacity, 'recycle': recycle}
                if args.profile.startswith('reservation-'):
                    reservation_proof(api, path, record['session'], args.profile.removeprefix('reservation-'))
                elif args.profile.startswith('master-'):
                    master_lifetime(api, path, record['session'], args.profile.removeprefix('master-'))
                else:
                    profiles[args.profile](api, path, record['session'])
                process.stdin.close()
                process.wait(timeout=10)
                output += process.stdout.read()
                require(process.returncode == 0, 'resident cleanup failed')
                drained = [json.loads(line[len(b'KER_SESSION_DRAINED '):])
                           for line in output.splitlines() if line.startswith(b'KER_SESSION_DRAINED ')]
                require(len(drained) == 1 and drained[0]['outstanding'] == 0 and
                        drained[0]['objects'] == 511 and not path.exists(),
                        'missing exact reclamation/socket cleanup evidence')
            except BaseException:
                errors.seek(0)
                print(errors.read().decode(errors='replace'), file=sys.stderr)
                raise
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
                process.stdout.close()
                if not process.stdin.closed:
                    process.stdin.close()
    print('PASS: actual resident control profile=' + args.profile + ' and exact cleanup')
    return 0


if __name__ == '__main__':
    sys.exit(main())
