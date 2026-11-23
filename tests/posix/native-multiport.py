#!/usr/bin/env python3
"""Independent host peers for one Linux kernel with two DPDK-backed interfaces."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import selectors
import signal
import time
import socket
import struct
import subprocess
import sys
import tempfile
import threading


def require(value, message):
    if not value: raise RuntimeError(message)


def run(*arguments):
    subprocess.run(['ip', *arguments], check=True)


def owned_run(arguments, timeout, **options):
    if options.pop('capture_output', False):
        options.update(stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    process = subprocess.Popen(arguments, start_new_session=True, **options)
    try:
        output, errors = process.communicate(timeout=timeout)
    except BaseException:
        os.killpg(process.pid, signal.SIGKILL); process.wait(); raise
    return subprocess.CompletedProcess(arguments, process.returncode, output, errors)


def cross_wire(root):
    # IPv4/IPv6 requests leave aux with a primary source; replies enter primary.
    expected = {'primary': {(4, '198.19.0.1', '198.18.0.2'), (6, '2001:db8:2::1', '2001:db8:1::2')},
                'aux': {(4, '198.18.0.2', '198.19.0.1'), (6, '2001:db8:1::2', '2001:db8:2::1')}}
    for name, direction in (('primary', 'rx'), ('aux', 'tx')):
        found = set(); directory = root if name == 'primary' else root / name
        for path in directory.glob('ker-' + direction + '-*.pcap'):
            data = path.read_bytes(); offset = 24
            endian = '<' if data[:4] == b'\xd4\xc3\xb2\xa1' else '>'
            while offset < len(data):
                _, _, length, original = struct.unpack_from(endian + 'IIII', data, offset); offset += 16
                frame = data[offset:offset + length]; offset += length
                require(len(frame) == length == original, 'truncated per-interface packet')
                packet = frame[14:]
                if frame[12:14] == b'\x08\x00' and packet[9] == 17:
                    found.add((4, str(ipaddress.ip_address(packet[12:16])), str(ipaddress.ip_address(packet[16:20]))))
                elif frame[12:14] == b'\x86\xdd' and packet[6] == 17:
                    found.add((6, str(ipaddress.ip_address(packet[8:24])), str(ipaddress.ip_address(packet[24:40]))))
        require(expected[name] <= found, name + ': shared-kernel asymmetric UDP evidence missing: ' + str(found))


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
    run('link', 'set', 'lo', 'up')
    Path('/proc/sys/net/ipv4/conf/all/rp_filter').write_text('0\n')
    for side in range(2):
        host, link = 'host' + str(side), 'link' + str(side)
        run('link', 'add', host, 'type', 'veth', 'peer', 'name', link)
        run('addr', 'add', f'198.{18 + side}.0.1/24', 'dev', host)
        run('-6', 'addr', 'add', f'2001:db8:{side + 1}::1/64', 'dev', host, 'nodad')
        run('link', 'set', host, 'up'); run('link', 'set', link, 'up')
        Path('/proc/sys/net/ipv4/conf/' + host + '/rp_filter').write_text('0\n')
    cpu = min(os.sched_getaffinity(0))
    common = f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry --iova-mode=va -m 64 '
    with tempfile.TemporaryDirectory(prefix='ker-multiport-') as directory:
        root = Path(directory); config = root / 'ports.ini'; stats = root / 'stats.json'; capture = root / 'pcap'; capture.mkdir()
        text = ('[network]\naddress=198.18.0.2/24\naddress6=2001:db8:1::2/64\n'
                'vip_addresses=198.18.0.3/24,198.18.0.4/24,198.18.0.5/24\n'
                'vip_addresses6=2001:db8:1::3/128,2001:db8:1::4/128\n'
                '[dpdk]\nport=net_tap0\neal=' + common + '--vdev=net_tap0,iface=kerprimary,remote=link0\n'
                '[interface.aux]\nport=net_tap1\neal=' + common + '--vdev=net_tap1,iface=keraux,remote=link1\n'
                'address=198.19.0.2/24\naddress6=2001:db8:2::2/64\nmax_mtu=2000\n'
                'vip_addresses=198.19.0.3/24,198.19.0.4/24,198.19.0.5/24\n'
                'vip_addresses6=2001:db8:2::3/128,2001:db8:2::4/128\n')
        config.write_text(text)
        sockets, expected, received, errors = [], set(), set(), []
        for side in range(2):
            for family, ip, count in ((socket.AF_INET, f'198.{18 + side}.0.1', 4),
                                      (socket.AF_INET6, f'2001:db8:{side + 1}::1', 3)):
                listener = socket.socket(family); listener.bind((ip, 29600)); listener.listen(16); sockets.append(listener)
                for vip in range(2, 2 + count):
                    expected.add(f'198.{18 + side}.0.{vip}' if family == socket.AF_INET else f'2001:db8:{side + 1}::{vip}')
        for family, ip in ((socket.AF_INET, '198.19.0.1'), (socket.AF_INET6, '2001:db8:2::1')):
            peer = socket.socket(family, socket.SOCK_DGRAM); peer.bind((ip, 29600)); sockets.append(peer)
        stopped = threading.Event()
        def serve():
            try:
                with selectors.DefaultSelector() as selector:
                    for peer in sockets: selector.register(peer, selectors.EVENT_READ)
                    while not stopped.is_set():
                        for event, _ in selector.select(0.1):
                            peer = event.fileobj
                            if peer.type & socket.SOCK_DGRAM:
                                payload, address = peer.recvfrom(100); require(len(payload) == 16, 'short UDP')
                                require(address[0] in ('198.18.0.2', '2001:db8:1::2'), 'wrong cross-interface source')
                                peer.sendto(payload, address); continue
                            connection, address = peer.accept()
                            with connection:
                                connection.settimeout(5); data = b''
                                while len(data) < 16:
                                    part = connection.recv(16 - len(data)); require(part, 'short TCP'); data += part
                                require(address[0] in expected and address[0] not in received, 'wrong/duplicate VIP source')
                                received.add(address[0]); connection.sendall(data)
                                require(connection.recv(1) == b'', 'missing native EOF')
            except Exception as error: errors.append(str(error))
        thread = threading.Thread(target=serve); thread.start()
        with (root / 'native.log').open('w+') as log:
            try:
                result = owned_run([sys.executable, str(args.launcher), '--config', str(config),
                    '--library', str(args.library), '--io-worker', str(args.worker), '--stats', str(stats),
                    '--pcap-dir', str(capture), '--', str(args.app)], stdout=log, stderr=log, timeout=40)
                require(result.returncode == 0, 'multi-interface application failed')
                require(not errors and received == expected, 'host peer/source mismatch: ' + str(errors) + str(received))
                record = json.loads(stats.read_text()); auxiliary = record['interfaces'][0]
                require(record['native']['active_opens'] >= 14, 'TCP bypassed the single original Linux instance')
                for item in (record, auxiliary):
                    require(item['tx'] > 0 and item['rx'] > 0 and item['outstanding'] == 0, 'port did not carry packets or leaked buffers')
                require(record['mtu_changes'] == 0 and auxiliary['mtu_changes'] == 2 and auxiliary['mtu_final'] == 1500,
                        'MTU controls did not select the correct worker')
                for pid in (record['worker_pid'], auxiliary['pid']):
                    try: os.kill(pid, 0)
                    except ProcessLookupError: pass
                    else: raise RuntimeError('owned worker process was not reaped')
                cross_wire(capture)
                print('PASS: two real ports in one Linux, all VIPs, cross-interface UDP, independent MTU and zero buffers', flush=True)
            except Exception:
                log.flush(); log.seek(0); print(log.read(), file=sys.stderr); raise
            finally:
                stopped.set(); thread.join(timeout=10)
                for peer in sockets: peer.close()
        # Start primary successfully, then fail the second EAL/device lookup.
        # The user application must not run, and both workers must be reaped.
        config.write_text(text.replace('port=net_tap1', 'port=missing-port'))
        marker = root / 'application-entered'
        failure_stats = root / 'failure.json'
        result = owned_run([sys.executable, str(args.launcher), '--config', str(config),
            '--library', str(args.library), '--io-worker', str(args.worker), '--stats', str(failure_stats),
            '--', sys.executable, '-c', 'from pathlib import Path; Path(' + repr(str(marker)) + ').touch()'],
            capture_output=True, text=True, timeout=25)
        require(result.returncode == 125 and not marker.exists(), 'auxiliary startup failure ran the application: ' + result.stderr)
        record = json.loads(failure_stats.read_text())
        require(record['outstanding'] == record['interfaces'][0]['outstanding'] == 0,
                'startup failure leaked worker buffers')
        for pid in (record['worker_pid'], record['interfaces'][0]['pid']):
            try: os.kill(pid, 0)
            except ProcessLookupError: pass
            else: raise RuntimeError('failed-startup worker was not reaped')
        print('PASS: additional startup failure stops before the application and reaps both workers', flush=True)
        # Both workers can start, yet the original Linux DAD on the second
        # interface must reject an address already owned by the host peer.
        config.write_text(text.replace('address6=2001:db8:2::2/64', 'address6=2001:db8:2::1/64'))
        marker = root / 'dad-application-entered'; dad_stats = root / 'dad-failure.json'
        result = owned_run([sys.executable, str(args.launcher), '--config', str(config),
            '--library', str(args.library), '--io-worker', str(args.worker), '--stats', str(dad_stats),
            '--', sys.executable, '-c', 'from pathlib import Path; Path(' + repr(str(marker)) + ').touch()'],
            capture_output=True, text=True, timeout=25)
        require(result.returncode == 125 and not marker.exists() and 'additional interface configuration' in result.stderr,
                'additional original Linux DAD failure was not propagated: ' + result.stderr)
        record = json.loads(dad_stats.read_text())
        require(record['outstanding'] == record['interfaces'][0]['outstanding'] == 0,
                'native initialization failure leaked either worker pool')
        for pid in (record['worker_pid'], record['interfaces'][0]['pid']):
            try: os.kill(pid, 0)
            except ProcessLookupError: pass
            else: raise RuntimeError('native initialization failure did not reap a worker')
        print('PASS: additional original Linux DAD failure cleans up both running workers', flush=True)
        # Explicitly stop only this launcher's auxiliary child while its native
        # application is alive. A zero worker exit still invalidates the backend.
        config.write_text(text)
        marker = root / 'running-application'; death_stats = root / 'worker-death.json'
        with (root / 'worker-death.log').open('w+') as log:
            process = subprocess.Popen([sys.executable, str(args.launcher), '--config', str(config),
                '--library', str(args.library), '--io-worker', str(args.worker), '--stats', str(death_stats),
                '--', sys.executable, '-c', 'from pathlib import Path; import time; Path(' + repr(str(marker)) + ').touch(); time.sleep(30)'],
                stdout=log, stderr=log, start_new_session=True)
            try:
                deadline = time.monotonic() + 12
                while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.05)
                require(marker.exists(), 'native app did not reach the running stage')
                children = Path(f'/proc/{process.pid}/task/{process.pid}/children').read_text().split()
                auxiliary_pids = []
                for child in children:
                    argv = Path('/proc/' + child + '/cmdline').read_bytes().split(b'\0')
                    if b'--port' in argv and argv[argv.index(b'--port') + 1] == b'net_tap1':
                        auxiliary_pids.append(int(child))
                require(len(auxiliary_pids) == 1, 'cannot identify the owned auxiliary worker')
                os.kill(auxiliary_pids[0], signal.SIGTERM)
                require(process.wait(timeout=20) == 125, 'auxiliary worker exit was not propagated')
                record = json.loads(death_stats.read_text())
                require(record['outstanding'] == record['interfaces'][0]['outstanding'] == 0,
                        'runtime worker loss leaked surviving worker buffers')
                for pid in (record['worker_pid'], record['interfaces'][0]['pid']):
                    try: os.kill(pid, 0)
                    except ProcessLookupError: pass
                    else: raise RuntimeError('runtime worker loss did not reap both workers')
                print('PASS: auxiliary runtime exit invalidates the backend and reaps both workers', flush=True)
            except BaseException:
                log.flush(); log.seek(0); print(log.read(), file=sys.stderr)
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL); process.wait()
                raise
    return 0


if __name__ == '__main__': sys.exit(main())
