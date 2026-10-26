#!/usr/bin/env python3
"""Real resident control-frame checks; no secondary EAL or network traffic."""
import argparse
from contextlib import closing
import errno
import importlib.util
import json
import os
from pathlib import Path
import selectors
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


def status_snapshot(api, path, session):
    with closing(api.Connection(path)) as connection:
        reply = connection.request(api.STATUS)
    require(reply['session'] == session and reply['generation'] == 511 and
            reply['token'] == 0 and reply['slot'] == reply['process'] == 0,
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
    parser.add_argument('--profile', choices=('roundtrip', 'malformed', 'replay'), required=True)
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
                profiles = {'roundtrip': roundtrip, 'malformed': malformed, 'replay': replay}
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
