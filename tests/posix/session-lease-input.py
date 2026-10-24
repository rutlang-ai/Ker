#!/usr/bin/env python3
"""Exercise production lease relay EOF, large input and early child exit."""
import argparse
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace


def require(value, message):
    if not value:
        raise RuntimeError(message)


def child_reap(output):
    records = [line.removeprefix('KER_SESSION_CHILD_REAP ')
        for line in output.splitlines() if line.startswith('KER_SESSION_CHILD_REAP ')]
    require(len(records) == 1, 'expected exactly one child reap record: ' + output)
    return json.loads(records[0])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tool', type=Path, required=True)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('ker_session_tool', args.tool)
    api = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(api)

    cleanup_spec = importlib.util.spec_from_file_location('ker_session_run',
        args.tool.resolve().parent / 'ker_session_run.py')
    cleanup = importlib.util.module_from_spec(cleanup_spec)
    cleanup_spec.loader.exec_module(cleanup)

    def rejected_cleanup(label, *values, **options):
        try:
            cleanup.validate_interrupted_cleanup(*values, **options)
        except RuntimeError:
            return
        raise RuntimeError('SIGTERM cleanup accepted failed ' + label)

    cleanup.validate_interrupted_cleanup(0, {'status': 0})
    cleanup.validate_interrupted_cleanup(0, None, packet_expected=False)
    rejected_cleanup('acquired pre-app missing packet', 0, None)
    rejected_cleanup('queued nonzero worker', 1, None, packet_expected=False)
    rejected_cleanup('queued unexpected packet', 0, {'status': 0}, packet_expected=False)
    require(cleanup.validate_interrupted_cleanup(0, {'status': 0}, app_launched=True,
        app_code=-15, startup=b'KER_NATIVE_READY\n', native_stats=None) == 'signal-terminated',
        'exact SIGTERM death without destructor markers was not classified truthfully')
    require(cleanup.validate_interrupted_cleanup(0, {'status': 0}, app_launched=True,
        app_code=-15, startup=b'KER_NATIVE_READY\nKER_NATIVE_STOPPING\nKER_NATIVE_DONE\n',
        native_stats={'buffers_live': 0}) == 'graceful', 'complete native teardown was not classified graceful')
    rejected_cleanup('worker', 1, {'status': 0})
    rejected_cleanup('packet status', 0, {'status': 1})
    rejected_cleanup('missing packet completion', 0, None)
    rejected_cleanup('app status', 0, {'status': 0}, app_launched=True, app_code=0,
        startup=b'KER_NATIVE_READY\n', native_stats=None)
    rejected_cleanup('inconsistent no-stop stats', 0, {'status': 0}, app_launched=True,
        app_code=-15, startup=b'KER_NATIVE_READY\n', native_stats={'buffers_live': 0})
    rejected_cleanup('missing native completion', 0, {'status': 0}, app_launched=True,
        app_code=-15, startup=b'KER_NATIVE_READY\nKER_NATIVE_STOPPING\n', native_stats={'buffers_live': 0})
    rejected_cleanup('incomplete native teardown', 0, {'status': 0}, app_launched=True,
        app_code=-15, startup=b'KER_NATIVE_READY\nKER_NATIVE_STOPPING\nKER_NATIVE_DONE\nKER_NATIVE_INCOMPLETE\n',
        native_stats={'buffers_live': 0})
    rejected_cleanup('live native buffers', 0, {'status': 0}, app_launched=True,
        app_code=-15, startup=b'KER_NATIVE_READY\nKER_NATIVE_STOPPING\nKER_NATIVE_DONE\n', native_stats={'buffers_live': 1})
    print('PASS: SIGTERM returns success only after worker, packet and native cleanup validation')

    ticket = api.packet(api.MASTER, session=17, epoch=23, token=31, slot=1)
    ticket_data = api.encode(ticket)
    ticket_size = len(ticket_data)
    state = SimpleNamespace(connection=None)

    class FakeConnection:
        def __init__(self, _socket):
            self.released = 0
            self.closed = False
            state.connection = self

        def request(self, command, **values):
            if command == api.MASTER:
                return ticket
            require(command == api.RELEASE, 'unexpected lease command')
            require(values == {key: ticket[key] for key in ('session', 'epoch', 'token', 'slot')},
                    'release did not use the exact acquired ticket')
            self.released += 1
            return api.packet(command, **values)

        def close(self):
            self.closed = True

    api.Connection = FakeConnection
    worker_source = f'''#!/usr/bin/python3
import os
import sys
control = int(sys.argv[sys.argv.index('--control-fd') + 1])
ticket_fd = int(sys.argv[sys.argv.index('--ticket-fd') + 1])
ticket = bytearray()
while len(ticket) < {ticket_size}:
    chunk = os.read(ticket_fd, {ticket_size} - len(ticket))
    if not chunk:
        raise SystemExit(2)
    ticket.extend(chunk)
os.close(ticket_fd)
received = bytearray()
while True:
    chunk = os.read(control, 4096)
    if not chunk:
        break
    received.extend(chunk)
with open(os.environ['KER_SESSION_RELAY_CAPTURE'], 'wb') as output:
    output.write(received)
with open(os.environ['KER_SESSION_RELAY_TICKET'], 'wb') as output:
    output.write(ticket)
'''
    fast_worker_source = f'''#!/usr/bin/python3
import os
import sys
import time
control = int(sys.argv[sys.argv.index('--control-fd') + 1])
ticket_fd = int(sys.argv[sys.argv.index('--ticket-fd') + 1])
ticket = bytearray()
while len(ticket) < {ticket_size}:
    chunk = os.read(ticket_fd, {ticket_size} - len(ticket))
    if not chunk:
        raise SystemExit(2)
    ticket.extend(chunk)
os.close(ticket_fd)
os.close(control)
with open(os.environ['KER_SESSION_RELAY_TICKET'], 'wb') as output:
    output.write(ticket)
with open(os.environ['KER_SESSION_RELAY_CLOSED'], 'w') as output:
    output.write(str(os.getpid()))
deadline = time.monotonic() + 10
while not os.path.exists(os.environ['KER_SESSION_RELAY_GO']):
    if time.monotonic() >= deadline:
        raise SystemExit(3)
    time.sleep(0.001)
'''
    early_exit_worker_source = f'''#!/usr/bin/python3
import os
import sys
control = int(sys.argv[sys.argv.index('--control-fd') + 1])
ticket_fd = int(sys.argv[sys.argv.index('--ticket-fd') + 1])
ticket = bytearray()
while len(ticket) < {ticket_size}:
    chunk = os.read(ticket_fd, {ticket_size} - len(ticket))
    if not chunk:
        raise SystemExit(2)
    ticket.extend(chunk)
os.close(ticket_fd)
with open(os.environ['KER_SESSION_RELAY_TICKET'], 'wb') as output:
    output.write(ticket)
with open(os.environ['KER_SESSION_RELAY_EARLY_PID'], 'w') as output:
    output.write(str(os.getpid()))
'''

    with tempfile.TemporaryDirectory(prefix='ker-lease-input-') as directory:
        root = Path(directory)
        worker = root / 'relay-worker.py'
        worker.write_text(worker_source)
        worker.chmod(0o700)
        empty = root / 'stdin-empty'
        empty.write_bytes(b'')
        binary = bytes(index % 251 for index in range(1024 * 1024))
        data_file = root / 'stdin-binary'
        data_file.write_bytes(binary)

        cases = (
            ('/dev/null', lambda: open(os.devnull, 'rb'), b''),
            ('empty regular file', lambda: empty.open('rb'), b''),
            ('1 MiB binary regular file', lambda: data_file.open('rb'), binary),
        )
        original_stdin = api.sys.stdin
        original_stdout = api.sys.stdout
        try:
            for index, (label, open_input, expected) in enumerate(cases):
                capture = root / f'capture-{index}'
                ticket_capture = root / f'ticket-{index}'
                os.environ['KER_SESSION_RELAY_CAPTURE'] = str(capture)
                os.environ['KER_SESSION_RELAY_TICKET'] = str(ticket_capture)
                api.sys.stdin = open_input()
                stdout = io.StringIO()
                api.sys.stdout = stdout
                try:
                    result = api.lease(SimpleNamespace(socket=root / 'unused.sock', worker=worker,
                        generation=0, process=0, eal='', probe_count=0, action='lease'))
                finally:
                    api.sys.stdout = original_stdout
                    api.sys.stdin.close()
                    api.sys.stdin = original_stdin
                require(result == 0, label + ' did not complete normally')
                require(state.connection.released == 1 and state.connection.closed,
                        label + ' did not release the exact lease and close the connection')
                require(capture.read_bytes() == expected,
                        label + ' bytes were not forwarded exactly: ' + repr(capture.read_bytes()))
                require(ticket_capture.read_bytes() == ticket_data,
                        label + ' worker did not receive the exact registration ticket')
                reaped = child_reap(stdout.getvalue())
                require(reaped['status'] == 0 and not reaped['escalated'] and
                        not reaped['input_abandoned'],
                        label + ' child did not exit cleanly: ' + repr(reaped))
                print('PASS: ' + label + ' exact relay, child status and lease release')

            # Force the actual adapter to write only after its child closes
            # the control reader. The 1 MiB regular file exceeds pipe capacity.
            fast_worker = root / 'fast-worker.py'
            fast_worker.write_text(fast_worker_source)
            fast_worker.chmod(0o700)
            closed = root / 'control-closed'
            go = root / 'allow-exit'
            ticket_capture = root / 'fast-ticket'
            os.environ['KER_SESSION_RELAY_CLOSED'] = str(closed)
            os.environ['KER_SESSION_RELAY_GO'] = str(go)
            os.environ['KER_SESSION_RELAY_TICKET'] = str(ticket_capture)
            api.sys.stdin = data_file.open('rb')
            stdout = io.StringIO()
            api.sys.stdout = stdout
            real_write = api.os.write
            write_count = 0

            def coordinated_write(fd, data):
                nonlocal write_count
                try:
                    count = real_write(fd, data)
                except BrokenPipeError:
                    go.touch()
                    raise
                write_count += 1
                if write_count == 1:
                    require(data == ticket_data, 'first relay write was not the lease ticket')
                    deadline = time.monotonic() + 10
                    while not closed.exists():
                        require(time.monotonic() < deadline, 'fast worker did not close its control reader')
                        time.sleep(0.001)
                return count

            api.os.write = coordinated_write
            try:
                result = api.lease(SimpleNamespace(socket=root / 'unused.sock', worker=fast_worker,
                    generation=0, process=0, eal='', probe_count=0, action='lease'))
            finally:
                api.os.write = real_write
                api.sys.stdout = original_stdout
                api.sys.stdin.close()
                api.sys.stdin = original_stdin
            require(write_count >= 1 and go.exists(), 'fixture did not force control-pipe EPIPE')
            require(result == 0, 'closed control reader changed successful child status')
            require(state.connection.released == 1 and state.connection.closed,
                    'closed control reader did not release the exact lease')
            require(ticket_capture.read_bytes() == ticket_data,
                    'fast-exit worker did not receive the exact registration ticket')
            reaped = child_reap(stdout.getvalue())
            child_pid = int(closed.read_text())
            require(reaped == {'pid': child_pid, 'status': 0, 'escalated': False,
                               'input_abandoned': True},
                    'reap marker did not identify the successful closed-reader child: ' + repr(reaped))
            print('PASS: deterministic EPIPE stops forwarding, reaps exact child, and releases lease')

            # Let a separate child consume the ticket and exit before lease()
            # reaches its first worker.poll(). The production adapter must
            # collect that exact success without attempting a control write.
            early_worker = root / 'early-exit-worker.py'
            early_worker.write_text(early_exit_worker_source)
            early_worker.chmod(0o700)
            early_pid_file = root / 'early-pid'
            ticket_capture = root / 'early-ticket'
            os.environ['KER_SESSION_RELAY_EARLY_PID'] = str(early_pid_file)
            os.environ['KER_SESSION_RELAY_TICKET'] = str(ticket_capture)
            api.sys.stdin = data_file.open('rb')
            stdout = io.StringIO()
            api.sys.stdout = stdout
            real_write = api.os.write
            real_popen = api.subprocess.Popen
            write_count = 0
            child_process = None

            def capture_popen(*args, **kwargs):
                nonlocal child_process
                child_process = real_popen(*args, **kwargs)
                return child_process

            def wait_after_ticket_write(fd, data):
                nonlocal write_count
                count = real_write(fd, data)
                write_count += 1
                if write_count == 1:
                    require(data == ticket_data, 'first early-exit write was not the lease ticket')
                    require(child_process.wait(timeout=10) == 0,
                            'early-exit child did not finish successfully before relay polling')
                return count

            api.os.write = wait_after_ticket_write
            api.subprocess.Popen = capture_popen
            try:
                result = api.lease(SimpleNamespace(socket=root / 'unused.sock', worker=early_worker,
                    generation=0, process=0, eal='', probe_count=0, action='lease'))
            finally:
                api.os.write = real_write
                api.subprocess.Popen = real_popen
                api.sys.stdout = original_stdout
                api.sys.stdin.close()
                api.sys.stdin = original_stdin
            require(write_count == 1, 'relay wrote control data after child exited before polling')
            require(result == 0 and state.connection.released == 1 and state.connection.closed,
                    'early child exit did not preserve status0 and release the exact lease')
            require(ticket_capture.read_bytes() == ticket_data,
                    'early-exit child did not receive the exact ticket')
            reaped = child_reap(stdout.getvalue())
            require(reaped == {'pid': int(early_pid_file.read_text()), 'status': 0,
                               'escalated': False, 'input_abandoned': False},
                    'reap marker did not identify the pre-poll successful child: ' + repr(reaped))
            print('PASS: child exits before first poll, no control write, exact reap and lease release')
        finally:
            api.sys.stdin = original_stdin
            api.sys.stdout = original_stdout
            os.environ.pop('KER_SESSION_RELAY_CAPTURE', None)
            os.environ.pop('KER_SESSION_RELAY_TICKET', None)
            os.environ.pop('KER_SESSION_RELAY_CLOSED', None)
            os.environ.pop('KER_SESSION_RELAY_GO', None)
            os.environ.pop('KER_SESSION_RELAY_EARLY_PID', None)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
