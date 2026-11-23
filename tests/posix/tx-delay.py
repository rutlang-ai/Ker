#!/usr/bin/env python3
"""Real TX batch deadlines with native host TCP/UDP traffic and clean shutdown."""
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
    eal = f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry --iova-mode=va -m 64 --vdev=net_tap0,iface=kerpeer,remote=kerlink'
    profiles = (('default', None, [], 0), ('ini-100us', 100, [], 100),
                ('cli-zero', 100, ['--tx-delay-us', '0'], 0),
                ('ini-10us', 10, [], 10), ('cli-100us', 0, ['--tx-delay-us', '100'], 100))
    with tempfile.TemporaryDirectory(prefix='ker-tx-delay-') as directory:
        root = Path(directory)
        for index, (name, ini, options, expected) in enumerate(profiles):
            config, stats = root / (name + '.ini'), root / (name + '.json')
            config.write_text('' if ini is None else '[dpdk]\npkt_tx_delay=' + str(ini) + '\n')
            port = 30200 + index
            command = [sys.executable, str(args.launcher), '--library', str(args.library),
                '--io-worker', str(args.worker), '--address', '198.18.0.2/24', '--port', 'net_tap0',
                '--eal', eal, '--idle-sleep-us', '100000', '--config', str(config), *options, '--stats', str(stats),
                '--', str(args.app), str(port)]
            with (root / (name + '.log')).open('w+') as log:
                app = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=log, text=True)
                try:
                    with selectors.DefaultSelector() as selector:
                        selector.register(app.stdout, selectors.EVENT_READ)
                        require(selector.select(20), 'TX batch worker startup timeout')
                    require(app.stdout.readline().startswith('READY '), 'TX batch application not ready')
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                        udp.settimeout(8); udp.connect(('198.18.0.2', port)); udp.send(PAYLOAD)
                        require(udp.recv(256) == PAYLOAD, 'TX batch worker did not receive/echo UDP')
                    with socket.socket(socket.AF_INET) as tcp:
                        tcp.settimeout(8); tcp.connect(('198.18.0.2', port)); tcp.sendall(PAYLOAD)
                        packet = b''
                        while len(packet) < len(PAYLOAD):
                            part = tcp.recv(len(PAYLOAD) - len(packet))
                            require(part, 'unexpected TCP EOF'); packet += part
                        require(packet == PAYLOAD, 'TX batch worker TCP payload changed')
                    output = app.communicate(timeout=20)[0]
                    require(app.returncode == 0 and 'PASS:' in output, 'TX batch native traffic failed')
                    record = json.loads(stats.read_text())
                    require(record['io']['tx_delay_us'] == expected, 'effective TX batch policy mismatch')
                    require(record['tx_flushes'] > 0, 'no real PMD TX batch flush')
                    require(bool(record['tx_timer_flushes']) == bool(expected),
                            'configured timer did not flush a real non-full TX batch')
                    require(record['stop_requests'] or record['control_eof'], 'control shutdown not observed')
                    require(record['outstanding'] == 0 and record['native']['passive_opens'] == 1 and
                            record['native']['udp_in_datagrams'] == 1 and record['native']['udp_out_datagrams'] == 1,
                            'missing native traffic or packet cleanup')
                    print(f'PASS: {name}, {expected}us, actual TX batch flushes, host TCP/UDP and control shutdown', flush=True)
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
