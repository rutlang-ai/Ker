#!/usr/bin/env python3
"""Original Linux Fast Open with independent peers and actual SYN payload evidence."""
import argparse
import json
import os
from pathlib import Path
import selectors
import socket
import struct
import subprocess
import sys
import tempfile

PAYLOAD = b'original-linux-fastopen\0'

def require(value, message):
    if not value:
        raise RuntimeError(message)

def syn_payloads(capture, port):
    capture.setblocking(False)
    found = []
    while True:
        try:
            frame = capture.recv(65536)
        except BlockingIOError:
            break
        if len(frame) < 54 or frame[12:14] != b'\x08\x00':
            continue
        ip = frame[14:]
        if ip[0] >> 4 != 4 or ip[9] != 6:
            continue
        ihl = (ip[0] & 15) * 4
        tcp = ip[ihl:struct.unpack('!H', ip[2:4])[0]]
        if len(tcp) >= 20 and struct.unpack('!H', tcp[2:4])[0] == port and tcp[13] & 0x12 == 0x02:
            found.append(tcp[(tcp[12] >> 4) * 4:])
    return found

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('launcher', 'library', 'worker', 'app'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    if not args.inside:
        return subprocess.run(['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()),
            '--inside', *sys.argv[1:]]).returncode
    def ip(*values):
        subprocess.run(['ip', *values], check=True)
    ip('link', 'set', 'lo', 'up')
    ip('link', 'add', 'kerhost', 'type', 'veth', 'peer', 'name', 'kerlink')
    ip('addr', 'add', '198.18.0.1/24', 'dev', 'kerhost')
    for name in ('kerhost', 'kerlink'):
        ip('link', 'set', name, 'up')
    # This private network namespace only: enable client/server and no-cookie SYN data.
    Path('/proc/sys/net/ipv4/tcp_fastopen').write_text('519\n')
    cpu = min(os.sched_getaffinity(0))
    eal = f'--lcores=0@{cpu} --no-pci --no-huge --no-shconf --no-telemetry -m 64 --iova-mode=va --vdev=net_tap0,iface=kerpeer,remote=kerlink'
    with tempfile.TemporaryDirectory(prefix='ker-tfo-') as directory:
        root = Path(directory)
        environment = dict(os.environ, RUNTIME_DIRECTORY=str(root))
        for index, role in enumerate(('host-reference', 'client', 'server')):
            address = '127.0.0.1' if role == 'host-reference' else ('198.18.0.2' if role == 'server' else '198.18.0.1')
            port = 31600 + index
            stats = root / (role + '.json')
            native = [sys.executable, str(args.launcher), '--library', str(args.library),
                '--io-worker', str(args.worker), '--address', '198.18.0.2/24', '--port', 'net_tap0',
                '--eal', eal, '--sysctl', 'net.ipv4.tcp_fastopen=519', '--stats', str(stats), '--']
            listen = [str(args.app), 'server', address, str(port)]
            connect = [str(args.app), 'client', address, str(port)]
            if role == 'server':
                listen = native + listen
            elif role == 'client':
                connect = native + connect
            with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as capture:
                capture.bind(('lo' if role == 'host-reference' else 'kerhost', 0))
                with (root / (role + '.log')).open('w+') as log:
                    process = subprocess.Popen(listen, stdout=subprocess.PIPE, stderr=log, text=True, env=environment)
                    try:
                        with selectors.DefaultSelector() as selector:
                            selector.register(process.stdout, selectors.EVENT_READ)
                            require(selector.select(20), 'Fast Open server startup timeout')
                        require(process.stdout.readline() == f'READY {port}\n', 'Fast Open server not ready')
                        result = subprocess.run(connect, capture_output=True, text=True, timeout=25, env=environment)
                        require(result.returncode == 0 and 'PASS:' in result.stdout, result.stderr)
                        output = process.communicate(timeout=20)[0]
                        require(process.returncode == 0 and 'PASS:' in output, output)
                        payloads = syn_payloads(capture, port)
                        require(PAYLOAD in payloads and b'' in payloads,
                                'missing exact data-bearing SYN or ordinary SYN: ' + repr(payloads))
                        if role != 'host-reference':
                            record = json.loads(stats.read_text())
                            counter = 'passive_opens' if role == 'server' else 'active_opens'
                            require(record['native'][counter] >= 2 and record['tx'] and record['rx'] and
                                    record['outstanding'] == 0, 'missing original Linux traffic/cleanup evidence')
                        print('PASS: ' + role + ', exact SYN data, ordinary SYN control, exact streams and EOF', flush=True)
                    except Exception:
                        log.flush(); log.seek(0); print(log.read(), file=sys.stderr)
                        raise
                    finally:
                        if process.poll() is None:
                            process.terminate()
                            try:
                                process.wait(timeout=5)
                            except subprocess.TimeoutExpired:
                                process.kill(); process.wait()
    return 0

if __name__ == '__main__':
    sys.exit(main())
