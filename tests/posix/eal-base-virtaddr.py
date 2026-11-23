#!/usr/bin/env python3
"""Actual EAL virtual-address hints with native host TCP/UDP traffic."""
import argparse
import json
import os
from pathlib import Path
import selectors
import socket
import subprocess
import sys
import tempfile

PAYLOAD = b'native-mac-only\0'


def require(value, message):
    if not value:
        raise RuntimeError(message)


def ip(*args):
    subprocess.run(['ip', *args], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('launcher', 'library', 'worker', 'app'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    if not args.inside:
        command = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()), '--inside']
        for name in ('launcher', 'library', 'worker', 'app'):
            command += ['--' + name, str(getattr(args, name).resolve())]
        return subprocess.run(command).returncode
    ip('link', 'set', 'lo', 'up')
    ip('link', 'add', 'kerhost', 'type', 'veth', 'peer', 'name', 'kerlink')
    ip('addr', 'add', '198.18.0.1/24', 'dev', 'kerhost')
    for name in ('kerhost', 'kerlink'):
        ip('link', 'set', name, 'up')
    cpu = min(os.sched_getaffinity(0))
    eal = f'--lcores=0@{cpu} --no-pci --no-telemetry -m 64 --no-huge --no-shconf --iova-mode=va --vdev=net_tap0,iface=kerpeer,remote=kerlink'
    profiles = (('raw-eight', '', [], ' --base-virtaddr=0x200000000', '', 0x200000000),
                ('ini-sixteen', '[dpdk]\nbase_virtaddr=0x400000000\n', [], '', '', 0x400000000),
                ('cli-twentyfour', '[dpdk]\nbase_virtaddr=0x400000000\n', ['--base-virtaddr', '0x600000000'], '', '', 0x600000000),
                ('unaligned', '', ['--base-virtaddr', '0x800000001'], '', '', 0x801000000),
                ('terminator', '', ['--base-virtaddr', '0xa00000000'], '', ' -- --base-virtaddr=0xc00000000', 0xa00000000))
    with tempfile.TemporaryDirectory(prefix='ker-eal-va-') as directory:
        root = Path(directory)
        for index, (name, ini, options, extra_eal, remainder, expected) in enumerate(profiles):
            config, stats = root / (name + '.ini'), root / (name + '.json')
            config.write_text(ini)
            port = 30300 + index
            command = [sys.executable, str(args.launcher), '--library', str(args.library),
                '--io-worker', str(args.worker), '--address', '198.18.0.2/24', '--port', 'net_tap0',
                '--eal', eal + extra_eal + ' --file-prefix=ker-va-' + str(index) + remainder, '--config', str(config), *options, '--stats', str(stats),
                '--', str(args.app), str(port)]
            with (root / (name + '.log')).open('w+') as log:
                app = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=log, text=True,
                    env=dict(os.environ, RUNTIME_DIRECTORY=str(root)))
                try:
                    with selectors.DefaultSelector() as selector:
                        selector.register(app.stdout, selectors.EVENT_READ)
                        require(selector.select(20), 'EAL memory worker startup timeout')
                    require(app.stdout.readline().startswith('READY '), 'EAL memory application not ready')
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                        udp.settimeout(8); udp.connect(('198.18.0.2', port)); udp.send(PAYLOAD)
                        require(udp.recv(256) == PAYLOAD, 'EAL memory worker did not receive/echo UDP')
                    with socket.socket(socket.AF_INET) as tcp:
                        tcp.settimeout(8); tcp.connect(('198.18.0.2', port)); tcp.sendall(PAYLOAD)
                        packet = b''
                        while len(packet) < len(PAYLOAD):
                            part = tcp.recv(len(PAYLOAD) - len(packet))
                            require(part, 'unexpected TCP EOF'); packet += part
                        require(packet == PAYLOAD, 'EAL memory worker TCP payload changed')
                    output = app.communicate(timeout=20)[0]
                    require(app.returncode == 0 and 'PASS:' in output, 'EAL memory native traffic failed')
                    record = json.loads(stats.read_text())
                    actual_base = int(record['io']['memory_base'], 16)
                    require(expected <= actual_base < expected + (1 << 30),
                            f'actual EAL virtual-address hint not used in the test mapping region: {record["io"]}')
                    require(record['io']['hugepages'] is False, 'EAL regular-page policy not applied')
                    require(record['stop_requests'] or record['control_eof'], 'control shutdown not observed')
                    require(record['outstanding'] == 0 and record['native']['passive_opens'] == 1 and
                            record['native']['udp_in_datagrams'] == 1 and record['native']['udp_out_datagrams'] == 1,
                            'missing native traffic or packet cleanup')
                    print(f'PASS: {name}, requested region={expected:#x}, actual first mapped segment={actual_base:#x}, native TCP/UDP and clean shutdown', flush=True)
                except Exception:
                    log.flush(); log.seek(0); print(log.read(), file=sys.stderr)
                    raise
                finally:
                    if app.poll() is None:
                        app.terminate()
                        try:
                            app.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            app.kill(); app.wait()
    return 0


if __name__ == '__main__':
    sys.exit(main())
