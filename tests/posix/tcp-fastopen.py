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

def syn_records(capture, port):
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
        if len(tcp) < 20 or not tcp[13] & 2:
            continue
        source, destination = struct.unpack('!HH', tcp[:4])
        if port not in (source, destination):
            continue
        header = (tcp[12] >> 4) * 4
        require(20 <= header <= len(tcp), 'invalid captured TCP header length')
        cookie = None
        offset = 20
        while offset < header:
            kind = tcp[offset]
            if kind == 0:
                break
            if kind == 1:
                offset += 1
                continue
            require(offset + 2 <= header, 'truncated TCP option')
            length = tcp[offset + 1]
            require(length >= 2 and offset + length <= header, 'invalid TCP option length')
            if kind == 34:
                require(cookie is None, 'multiple Fast Open options')
                cookie = tcp[offset + 2:offset + length]
            offset += length
        found.append(dict(source=source, destination=destination, ack=bool(tcp[13] & 16),
                          payload=tcp[header:], cookie=cookie))
    return found


def verify_syns(records, port, cookies):
    syns = [v for v in records if v['destination'] == port and not v['ack']]
    require(any(v['payload'] == b'' and v['cookie'] is None for v in syns),
            'ordinary connect control SYN missing')
    if not cookies:
        require(any(v['payload'] == PAYLOAD for v in syns), 'exact data-bearing SYN missing')
        return
    requests = [v for v in syns if v['payload'] == b'' and v['cookie'] == b'']
    require(requests, 'initial empty SYN with Fast Open cookie request missing')
    replies = [v for v in records if v['source'] == port and v['ack'] and v['cookie']]
    issued = [reply for reply in replies if any(reply['destination'] == request['source'] for request in requests)]
    require(issued, 'no nonempty cookie returned for the initial cookie request')
    require(all(4 <= len(v['cookie']) <= 16 for v in issued), 'invalid issued Fast Open cookie length')
    reused = [v for v in syns if v['payload'] == PAYLOAD and v['cookie'] and any(
        v['cookie'] == reply['cookie'] and v['source'] != reply['destination'] for reply in issued)]
    require(reused, 'a fresh connection did not reuse the issued cookie with exact SYN payload')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('launcher', 'library', 'worker', 'app'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--cookie-exchange', action='store_true', help='require real cookie request, response and reuse on a fresh connection')
    parser.add_argument('--nonblocking', action='store_true', help='validate nonblocking Fast Open initiation and no-cookie resend')
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    args.cookie_exchange = args.cookie_exchange or args.nonblocking
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
    # Private network namespace only: cookie mode enables client/server without no-cookie flags.
    policy = '3' if args.cookie_exchange else '519'
    Path('/proc/sys/net/ipv4/tcp_fastopen').write_text(policy + '\n')
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
                '--eal', eal, '--sysctl', 'net.ipv4.tcp_fastopen=' + policy, '--stats', str(stats), '--']
            listen = [str(args.app), 'server', address, str(port)]
            connect = [str(args.app), 'client', address, str(port)]
            if args.cookie_exchange:
                mode = 'nonblocking' if args.nonblocking else 'cookies'
                listen += [mode]; connect += [mode]
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
                        if args.nonblocking:
                            require('no-cookie EINPROGRESS' in result.stdout and 'cached-cookie send accepted' in result.stdout,
                                    'missing nonblocking return/readiness evidence')
                        output = process.communicate(timeout=20)[0]
                        require(process.returncode == 0 and 'PASS:' in output, output)
                        verify_syns(syn_records(capture, port), port, args.cookie_exchange)
                        if role != 'host-reference':
                            record = json.loads(stats.read_text())
                            counter = 'passive_opens' if role == 'server' else 'active_opens'
                            require(record['native'][counter] >= (3 if args.cookie_exchange else 2) and record['tx'] and record['rx'] and
                                    record['outstanding'] == 0, 'missing original Linux traffic/cleanup evidence')
                        print('PASS: ' + role + (', cookie request/response/reuse on fresh connection' if args.cookie_exchange else ', exact SYN data') + ', ordinary SYN control, exact streams and EOF', flush=True)
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
