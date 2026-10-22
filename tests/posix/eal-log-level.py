#!/usr/bin/env python3
"""EAL startup log filtering and post-init overrides with native host TCP/UDP traffic."""
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
    profiles = (('raw-warning', '', [], ' --log-level=4', 4, 4, False),
                ('ini-info', '[dpdk]\nlog_level=7\n', [], '', 7, 7, True),
                ('cli-warning', '[dpdk]\nlog_level=7\n', ['--eal-log-level', '4'], '', 4, 4, False),
                ('post-init-info', '[dpdk]\nlog_level=4\n', ['--log-level', '7'], '', 4, 7, False),
                ('cli-info', '[dpdk]\nlog_level=4\n', ['--eal-log-level', '7'], '', 7, 7, True),
                ('typed-global-component-warning', '', ['--eal-log-level', '7'],
                    ' --log-level=lib.eal:warning', 7, 7, False),
                ('typed-global-component-info', '', ['--eal-log-level', '7'],
                    ' --log-level lib.eal:info', 7, 7, True))
    with tempfile.TemporaryDirectory(prefix='ker-eal-log-') as directory:
        root = Path(directory)
        for index, (name, ini, options, extra_eal, expected, final_level, iova_info) in enumerate(profiles):
            config, stats = root / (name + '.ini'), root / (name + '.json')
            config.write_text(ini)
            port = 30300 + index
            command = [sys.executable, str(args.launcher), '--library', str(args.library),
                '--io-worker', str(args.worker), '--address', '198.18.0.2/24', '--port', 'net_tap0',
                '--eal', eal + extra_eal + ' --file-prefix=ker-log-' + str(index), '--config', str(config), *options, '--stats', str(stats),
                '--', str(args.app), str(port)]
            with (root / (name + '.log')).open('w+') as log:
                app = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=log, text=True,
                    env=dict(os.environ, RUNTIME_DIRECTORY=str(root)))
                try:
                    with selectors.DefaultSelector() as selector:
                        selector.register(app.stdout, selectors.EVENT_READ)
                        require(selector.select(20), 'EAL log worker startup timeout')
                    require(app.stdout.readline().startswith('READY '), 'EAL log application not ready')
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                        udp.settimeout(8); udp.connect(('198.18.0.2', port)); udp.send(PAYLOAD)
                        require(udp.recv(256) == PAYLOAD, 'EAL log worker did not receive/echo UDP')
                    with socket.socket(socket.AF_INET) as tcp:
                        tcp.settimeout(8); tcp.connect(('198.18.0.2', port)); tcp.sendall(PAYLOAD)
                        packet = b''
                        while len(packet) < len(PAYLOAD):
                            part = tcp.recv(len(PAYLOAD) - len(packet))
                            require(part, 'unexpected TCP EOF'); packet += part
                        require(packet == PAYLOAD, 'EAL log worker TCP payload changed')
                    output = app.communicate(timeout=20)[0]
                    require(app.returncode == 0 and 'PASS:' in output, 'EAL log native traffic failed')
                    record = json.loads(stats.read_text())
                    require(record['io']['eal_log_level'] == expected and record['io']['log_level'] == final_level,
                            f'actual EAL/post-init log level mismatch: {record["io"]}')
                    log.flush(); log.seek(0)
                    startup_log = log.read()
                    require(('Selected IOVA mode' in startup_log) == iova_info,
                            'EAL startup INFO filtering mismatch: ' + startup_log)
                    require(record['stop_requests'] or record['control_eof'], 'control shutdown not observed')
                    require(record['outstanding'] == 0 and record['native']['passive_opens'] == 1 and
                            record['native']['udp_in_datagrams'] == 1 and record['native']['udp_out_datagrams'] == 1,
                            'missing native traffic or packet cleanup')
                    print(f'PASS: {name}, EAL startup level={expected}, final level={final_level}, early INFO filtering, native TCP/UDP and clean shutdown', flush=True)
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
