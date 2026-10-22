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

def tcp_records(capture, port):
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
        if len(tcp) < 20:
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
        found.append(dict(source=source, destination=destination, ack=bool(tcp[13] & 16), syn=bool(tcp[13] & 2),
                          sequence=struct.unpack('!I', tcp[4:8])[0], acknowledgement=struct.unpack('!I', tcp[8:12])[0],
                          payload=tcp[header:], cookie=cookie))
    return found


def verify_syns(records, port, cookies):
    syns = [v for v in records if v['destination'] == port and v['syn'] and not v['ack']]
    require(any(v['payload'] == b'' and v['cookie'] is None for v in syns),
            'ordinary connect control SYN missing')
    if not cookies:
        require(any(v['payload'] == PAYLOAD for v in syns), 'exact data-bearing SYN missing')
        return
    requests = [v for v in syns if v['payload'] == b'' and v['cookie'] == b'']
    require(requests, 'initial empty SYN with Fast Open cookie request missing')
    replies = [v for v in records if v['source'] == port and v['syn'] and v['ack'] and v['cookie']]
    issued = [reply for reply in replies if any(reply['destination'] == request['source'] for request in requests)]
    require(issued, 'no nonempty cookie returned for the initial cookie request')
    require(all(4 <= len(v['cookie']) <= 16 for v in issued), 'invalid issued Fast Open cookie length')
    reused = [v for v in syns if v['payload'] == PAYLOAD and v['cookie'] and any(
        v['cookie'] == reply['cookie'] and v['source'] != reply['destination'] for reply in issued)]
    require(reused, 'a fresh connection did not reuse the issued cookie with exact SYN payload')


def verify_rotation(records, port):
    syns = [v for v in records if v['destination'] == port and v['syn'] and not v['ack']]
    replies = [v for v in records if v['source'] == port and v['syn'] and v['ack']]
    initial = [v for v in syns if v['cookie'] == b'' and not v['payload']]
    issued = [v for v in replies if v['cookie'] and any(v['destination'] == r['source'] for r in initial)]
    require(issued, 'initial key cookie response missing')
    stale = [v for v in syns if v['payload'] == PAYLOAD and any(
        v['cookie'] == r['cookie'] and v['source'] != r['destination'] for r in issued)]
    require(stale, 'stale cookie was not presented with SYN data')
    replacements = [r for r in replies if r['cookie'] and 4 <= len(r['cookie']) <= 16 and any(
        r['destination'] == v['source'] and r['cookie'] != v['cookie'] and
        r['acknowledgement'] == (v['sequence'] + 1) % (1 << 32) for v in stale)]
    require(replacements, 'stale SYN data was not rejected with a replacement cookie and SYN-only acknowledgement')
    require(any(not r['syn'] and r['destination'] == port and r['payload'] == PAYLOAD and any(
        r['source'] == v['source'] and r['sequence'] == (v['sequence'] + 1) % (1 << 32)
        for v in stale) for r in records), 'rejected SYN payload was not resent on the established stream')
    refreshed = [v for v in syns if v['payload'] == PAYLOAD and any(
        v['cookie'] == r['cookie'] and v['source'] != r['destination'] for r in replacements)]
    require(refreshed, 'fresh connection did not reuse the replacement cookie')
    require(any(r['destination'] == v['source'] and
        r['acknowledgement'] == (v['sequence'] + 1 + len(PAYLOAD)) % (1 << 32)
        for r in replies for v in refreshed), 'replacement cookie SYN data was not acknowledged')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('launcher', 'library', 'worker', 'app'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--cookie-exchange', action='store_true', help='require real cookie request, response and reuse on a fresh connection')
    parser.add_argument('--nonblocking', action='store_true', help='validate nonblocking Fast Open initiation and no-cookie resend')
    parser.add_argument('--key-rotation', action='store_true', help='rotate the listener key and require stale-cookie fallback and recovery')
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    args.cookie_exchange = args.cookie_exchange or args.nonblocking or args.key_rotation
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
                mode = 'rotation' if args.key_rotation else ('nonblocking' if args.nonblocking else 'cookies')
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
                        records = tcp_records(capture, port)
                        verify_syns(records, port, args.cookie_exchange)
                        if args.key_rotation:
                            verify_rotation(records, port)
                            print('PASS: stale cookie rejected, payload resent, replacement cookie accepted', flush=True)
                        if role != 'host-reference':
                            record = json.loads(stats.read_text())
                            counter = 'passive_opens' if role == 'server' else 'active_opens'
                            require(record['native'][counter] >= (4 if args.key_rotation else (3 if args.cookie_exchange else 2)) and record['tx'] and record['rx'] and
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
