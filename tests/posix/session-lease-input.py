#!/usr/bin/env python3
"""Exercise the production lease relay with stdin descriptors epoll rejects."""
import argparse
import importlib.util
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace


def require(value, message):
    if not value:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tool', type=Path, required=True)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('ker_session_tool', args.tool)
    api = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(api)

    ticket = api.packet(api.MASTER, session=17, epoch=23, token=31, slot=1)
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
    worker_source = '''#!/usr/bin/python3
import os
import sys
control = int(sys.argv[sys.argv.index('--control-fd') + 1])
ticket_fd = int(sys.argv[sys.argv.index('--ticket-fd') + 1])
ticket = bytearray()
while len(ticket) < 88:
    chunk = os.read(ticket_fd, 88 - len(ticket))
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

    with tempfile.TemporaryDirectory(prefix='ker-lease-input-') as directory:
        root = Path(directory)
        worker = root / 'relay-worker.py'
        worker.write_text(worker_source)
        worker.chmod(0o700)
        empty = root / 'stdin-empty'
        empty.write_bytes(b'')
        binary = b'\x00\xff\ncontrol\x80\x00'
        data_file = root / 'stdin-binary'
        data_file.write_bytes(binary)

        cases = (
            ('/dev/null', lambda: open(os.devnull, 'rb'), b''),
            ('empty regular file', lambda: empty.open('rb'), b''),
            ('binary regular file', lambda: data_file.open('rb'), binary),
        )
        original_stdin = api.sys.stdin
        try:
            for index, (label, open_input, expected) in enumerate(cases):
                capture = root / f'capture-{index}'
                ticket_capture = root / f'ticket-{index}'
                os.environ['KER_SESSION_RELAY_CAPTURE'] = str(capture)
                os.environ['KER_SESSION_RELAY_TICKET'] = str(ticket_capture)
                api.sys.stdin = open_input()
                try:
                    result = api.lease(SimpleNamespace(socket=root / 'unused.sock', worker=worker,
                        generation=0, process=0, eal=''))
                finally:
                    api.sys.stdin.close()
                    api.sys.stdin = original_stdin
                require(result == 0, label + ' did not complete normally')
                require(state.connection.released == 1 and state.connection.closed,
                        label + ' did not release the exact lease and close the connection')
                require(capture.read_bytes() == expected,
                        label + ' bytes were not forwarded exactly: ' + repr(capture.read_bytes()))
                require(ticket_capture.read_bytes() == api.encode(ticket),
                        label + ' worker did not receive the exact registration ticket')
                print('PASS: ' + label + ' EOF/relay, exact bytes, child shutdown and lease release')
        finally:
            api.sys.stdin = original_stdin
            os.environ.pop('KER_SESSION_RELAY_CAPTURE', None)
            os.environ.pop('KER_SESSION_RELAY_TICKET', None)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
