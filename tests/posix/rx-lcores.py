#!/usr/bin/env python3
"""Actual EAL queue owners over original virtio/vhost/TAP and Linux sockets."""
import argparse
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import struct
import subprocess
import sys
import tempfile


def require(value, message):
    if not value:
        raise RuntimeError(message)


def line(process):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        require(selector.select(20), 'process readiness timed out')
    return process.stdout.readline().strip()


def stop(process):
    if process is None:
        return
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL); process.wait()
    # Every launched group belongs to this test, including native/worker
    # children left behind by a failed launcher.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def owned_run(command, **options):
    timeout = options.pop('timeout')
    options.pop('capture_output')
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=True, **options)
    try:
        output, errors = process.communicate(timeout=timeout)
        return subprocess.CompletedProcess(command, process.returncode, output, errors)
    finally:
        stop(process)


def frames(directory, direction):
    result = []
    for path in directory.glob('ker-' + direction + '*.pcap'):
        data = path.read_bytes(); require(data[:4] == b'\xd4\xc3\xb2\xa1', 'unexpected PCAP format')
        offset = 24
        while offset < len(data):
            require(offset + 16 <= len(data), 'partial PCAP record')
            _, _, size, original = struct.unpack_from('<IIII', data, offset); offset += 16
            require(size == original and offset + size <= len(data), 'truncated RX handoff capture')
            result.append(data[offset:offset + size]); offset += size
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('launcher', 'library', 'worker', 'app', 'bridge', 'pmd-root'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    cpus = sorted(os.sched_getaffinity(0))[:2]
    modules = []
    for name in ('tap', 'virtio', 'vhost'):
        found = list(args.pmd_root.glob('dpdk/pmds-*/librte_net_' + name + '.so'))
        if not found:
            print('SKIP: original ' + name + ' PMD required'); return 77
        modules.append(str(found[0]))
    if len(cpus) < 2 or not Path('/dev/net/tun').exists():
        print('SKIP: two allowed CPUs and host TAP required'); return 77
    environment = dict(os.environ, LD_PRELOAD=':'.join(modules))
    if not args.inside:
        command = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()), '--inside']
        for name in ('launcher', 'library', 'worker', 'app', 'bridge', 'pmd-root'):
            command += ['--' + name, str(getattr(args, name.replace('-', '_')).resolve())]
        return subprocess.run(command, env=environment).returncode
    for command in (
            ['ip', 'link', 'set', 'lo', 'up'],
            ['ip', 'link', 'add', 'kerhost', 'type', 'veth', 'peer', 'name', 'kerlink'],
            ['ip', 'addr', 'add', '198.18.0.1/24', 'dev', 'kerhost'],
            ['ip', '-6', 'addr', 'add', '2001:db8:1::1/64', 'dev', 'kerhost', 'nodad'],
            ['ip', 'link', 'set', 'kerhost', 'up'], ['ip', 'link', 'set', 'kerlink', 'up']):
        subprocess.run(command, check=True)
    # Preserve IPv6 on the configured peer; prevent automatic IPv6 traffic on
    # later raw-only TAPs from polluting exact exception ownership counts.
    Path('/proc/sys/net/ipv6/conf/default/disable_ipv6').write_text('1')
    with tempfile.TemporaryDirectory(prefix='ker-rx-cores-') as directory:
        root = Path(directory); path = root / 'vhost.sock'
        backend = [str(args.bridge), f'--lcores=0@{cpus[0]}', '--no-huge', '--no-pci', '--no-shconf',
            '--no-telemetry', '--iova-mode=va', '-m', '64', f'--vdev=net_vhost0,iface={path},queues=2',
            '--vdev=net_tap0,iface=kerbackend,remote=kerlink', '--', '--alternate-queues']
        with (root / 'bridge.log').open('w+') as backend_log:
            bridge = subprocess.Popen(backend, stdout=subprocess.PIPE, stderr=backend_log, env=environment, text=True, start_new_session=True)
            process = None
            try:
                require(line(bridge) == 'READY' and path.is_socket(), 'vhost/TAP backend unavailable')
                def config_text(main_core, cores, exception=True):
                    return ('[network]\naddress=198.18.0.2/24\naddress6=2001:db8:1::2/64\nmax_mtu=1500\n'
                        '[dpdk]\nnb_vdev=1\nport=net_virtio_user0\nqueues=2\n' + f'rx_lcores={cores}\n'
                        + ('exception_iface=coreexcept\nexception_type=34997\n' if exception else '')
                        + f'eal=--lcores=0@{cpus[0]},1@{cpus[1]} --main-lcore={main_core} --no-huge --no-pci '
                        '--no-shconf --no-telemetry --iova-mode=va -m 96\n'
                        + f'[vdev0]\npath={path}\nqueues=2\nqueue_size=512\nmac=02:11:22:33:44:55\ncq=1\n')
                def command(config, stats, app):
                    return [sys.executable, str(args.launcher), '--config', str(config), '--library', str(args.library),
                        '--io-worker', str(args.worker), '--stats', str(stats), '--', *app]
                # Main membership must use the actual original EAL main ID,
                # not assume zero or confuse an enabled core with a port owner.
                for main_core, cores in ((0, '1'), (1, '0'), (0, '2')):
                    config, stats, marker = root / 'bad.ini', root / 'bad.json', root / 'app-entered'
                    config.write_text(config_text(main_core, cores))
                    result = owned_run(command(config, stats, ['/usr/bin/touch', str(marker)]),
                        capture_output=True, text=True, env=environment, timeout=20)
                    diagnostic = ('exception owner main lcore is missing' if cores != '2' else 'select unique enabled EAL lcores')
                    require(result.returncode == 125 and diagnostic in result.stderr and not marker.exists(),
                            'invalid port lcore mapping reached application: ' + result.stdout + result.stderr)
                    record = json.loads(stats.read_text())
                    require(record['outstanding'] == 0 and record['io'] is None, 'failed mapping leaked packets/reached readiness')
                    require(subprocess.run(['ip', 'link', 'show', 'coreexcept'], capture_output=True).returncode != 0,
                            'invalid port owner created the exception TAP')
                print('PASS: test_ff_check_config_kni_primary_lcore_missing_fails', flush=True)
                for name, main_core, cores, exception in (('main0', 0, '0,1', True),
                        ('main1', 1, '0,1', True), ('remote-only', 0, '1', False)):
                    config, stats = root / (name + '.ini'), root / (name + '.json')
                    capture = root / (name + '-pcap'); capture.mkdir()
                    config.write_text(config_text(main_core, cores, exception) + f'\n[capture]\ndirectory={capture}\n')
                    for family in ([], ['-6']):
                        subprocess.run(['ip', *family, 'neigh', 'flush', 'dev', 'kerhost'], check=True)
                    with (root / (name + '.log')).open('w+') as log:
                        process = subprocess.Popen(command(config, stats, [str(args.app), '--fixed-mtu']), env=environment,
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, text=True, start_new_session=True)
                        try:
                            require(line(process) == 'READY', 'native application failed before main')
                            if exception:
                                with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x88b5)) as wire, \
                                        socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x88b5)) as tap:
                                    wire.bind(('kerhost', 0)); tap.bind(('coreexcept', 0)); wire.settimeout(5); tap.settimeout(5)
                                    frame = bytes.fromhex('ffffffffffff02123456789a88b5') + bytes(range(50))
                                    reply = frame[:14] + bytes(reversed(range(50)))
                                    require(wire.send(frame) == len(frame) and tap.recv(2048) == frame,
                                            'remote/main RX handoff changed exception frame')
                                    require(tap.send(reply) == len(reply) and wire.recv(2048) == reply,
                                            'exception frame did not return through the original PMD')
                            process.stdin.write('G'); process.stdin.flush()
                            for family, address in ((socket.AF_INET, '198.18.0.2'), (socket.AF_INET6, '2001:db8:1::2')):
                                payload = bytes((i * 17 + (i >> 8)) & 255 for i in range(4097))
                                with socket.socket(family, socket.SOCK_STREAM) as tcp:
                                    tcp.settimeout(10); tcp.connect((address, 45000)); tcp.sendall(payload)
                                    response = b''
                                    while len(response) < len(payload) + 7:
                                        part = tcp.recv(8192); require(part, 'premature native TCP EOF'); response += part
                                    require(response == b'NATIVE:' + payload, 'native TCP bytes differ')
                                with socket.socket(family, socket.SOCK_DGRAM) as udp:
                                    udp.settimeout(10); udp.sendto(payload[:512], (address, 45000))
                                    require(udp.recv(2048) == b'NATIVE:' + payload[:512], 'native UDP bytes differ')
                            require(line(process) == 'NATIVE_DONE', 'native socket teardown failed')
                            output, _ = process.communicate('Q', timeout=20)
                            require(process.returncode == 0 and 'PASS:' in output, 'native/worker shutdown failed: ' + output)
                            record = json.loads(stats.read_text()); pollers = record['rx_pollers']
                            owners = [int(core) for core in cores.split(',')]
                            require(record['outstanding'] == 0 and len(pollers) == 2, 'RX handoff leaked buffers')
                            for q, poller in enumerate(pollers):
                                expected = owners[q % len(owners)]
                                require(poller['queue'] == q and poller['owner'] == poller['lcore'] == expected
                                        and poller['cpu'] == cpus[expected] and poller['packets'] > 0 and poller['polls'] > 0,
                                        'PMD queue did not run on the selected actual EAL lcore: ' + str(pollers))
                            require(record['io']['main_lcore'] == main_core and record['io']['rss'] is None,
                                    'actual EAL main differs or injection was mislabeled as RSS')
                            require([p['packets'] for p in pollers] == record['rx_by_queue'] and
                                    sum(record['rx_by_queue']) == record['rx'] + record['rx_dropped'] + record['exception_selected']
                                    + record['rx_shutdown_discarded'] - record['rx_startup_discarded'], 'RX queue ownership accounting differs')
                            require(record['native']['passive_opens'] == 2 and record['native']['active_opens'] == 0
                                    and record['native']['udp_in_datagrams'] == record['native']['udp6_in_datagrams'] == 1,
                                    'original native IPv4/IPv6 TCP/UDP was not exercised')
                            rx_frames = frames(capture, 'rx')
                            require(len(rx_frames) == sum(record['rx_by_queue']) and record['mtu_final'] == 1500
                                    and record['mtu_changes'] == 0, 'RX PCAP gap/duplicate or unsafe remote MTU change')
                            if exception:
                                require(rx_frames.count(frame) == 1 and frames(capture, 'tx').count(reply) == 1,
                                        'exception RX/TX capture missing or duplicated on handoff')
                                require(record['exception_to_host'] == record['exception_from_host'] == 1,
                                        'exception queue did not preserve its main owner: ' + str(record))
                            print('PASS: ' + name + ' actual RX owners=' + str(pollers) + '; original Linux IPv4/IPv6 TCP/UDP, zero mbufs', flush=True)
                        except BaseException:
                            log.flush(); log.seek(0); print(log.read(), file=sys.stderr); raise
                        finally:
                            stop(process)
                print('PASS: test_ff_check_config_kni_primary_lcore_present_ok', flush=True)
                bridge.terminate(); output, _ = bridge.communicate(timeout=10)
                require(bridge.returncode == 0, 'original vhost/TAP backend failed')
                records = [json.loads(item[7:]) for item in output.splitlines() if item.startswith('BRIDGE ')]
                require(len(records) == 1 and records[0]['outstanding'] == 0 and records[0]['to_host'] > 0
                        and records[0]['to_native'] > 0 and not path.exists(), 'backend ownership/socket cleanup failed')
            except BaseException:
                backend_log.flush(); backend_log.seek(0); print(backend_log.read(), file=sys.stderr); raise
            finally:
                stop(process); stop(bridge)
    return 0


if __name__ == '__main__':
    sys.exit(main())
