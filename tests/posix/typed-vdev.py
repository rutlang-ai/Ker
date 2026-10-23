#!/usr/bin/env python3
"""Real virtio-user -> independent vhost/TAP -> host-kernel ICMP acceptance."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import socket

spec = importlib.util.spec_from_file_location('icmp_mtu', Path(__file__).with_name('icmp-mtu.py'))
mtu = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mtu)
require, ready, stop = mtu.require, mtu.ready, mtu.stop


def main():
    if sys.argv[1:] == ['--socket-server']:
        def receive_exact(stream, length):
            data = bytearray()
            while len(data) < length:
                chunk = stream.recv(length - len(data))
                require(chunk, 'native TCP stream closed early')
                data.extend(chunk)
            return bytes(data)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            tcp.bind(('198.18.0.2', 27991)); tcp.listen(1)
            udp.bind(('198.18.0.2', 27992))
            print('READY sockets', flush=True)
            connection, _ = tcp.accept()
            with connection:
                data = receive_exact(connection, len(b'original-linux-tcp'))
                require(data == b'original-linux-tcp', 'native TCP payload mismatch')
                connection.sendall(data)
            data, peer = udp.recvfrom(256)
            require(data == b'original-linux-udp', 'native UDP payload mismatch')
            udp.sendto(data, peer)
        print('PASS: original Linux TCP and UDP over virtio-user', flush=True)
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('launcher', 'library', 'worker', 'app', 'bridge', 'pmd-root'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--startup-delay-library', type=Path, required=True)
    parser.add_argument('--queue-one', action='store_true')
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    modules = []
    for name in ('tap', 'virtio', 'vhost'):
        found = list(args.pmd_root.glob('dpdk/pmds-*/librte_net_' + name + '.so'))
        if not found:
            print('SKIP: build/install the pinned DPDK net_' + name + ' PMD', flush=True)
            return 77
        modules.append(str(found[0]))
    environment = dict(os.environ)
    environment['LD_PRELOAD'] = ':'.join(modules)
    library_path = str(args.pmd_root.resolve())
    if environment.get('LD_LIBRARY_PATH'):
        library_path += ':' + environment['LD_LIBRARY_PATH']
    environment['LD_LIBRARY_PATH'] = library_path
    if not args.inside:
        command = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()), '--inside']
        for name in ('launcher', 'library', 'worker', 'app', 'bridge', 'pmd-root', 'startup-delay-library'):
            command += ['--' + name, str(getattr(args, name.replace('-', '_')).resolve())]
        if args.queue_one:
            command.append('--queue-one')
        return subprocess.run(command, env=environment).returncode
    for command in (
        ['ip', 'link', 'set', 'lo', 'up'],
        ['ip', 'link', 'add', 'kerhost', 'type', 'veth', 'peer', 'name', 'kerlink'],
        ['ip', 'addr', 'add', '198.18.0.1/24', 'dev', 'kerhost'],
        ['ip', '-6', 'addr', 'add', '2001:db8:1::1/64', 'dev', 'kerhost', 'nodad'],
        ['ip', 'link', 'set', 'kerhost', 'up'], ['ip', 'link', 'set', 'kerlink', 'up']):
        subprocess.run(command, check=True)
    cpus = sorted(os.sched_getaffinity(0))
    cpu = cpus[0]
    bridge_cpu = cpus[1] if len(cpus) > 1 else cpu
    with tempfile.TemporaryDirectory(prefix='ker-vdev-') as directory:
        root = Path(directory)
        backend_path = root / 'vhost.sock'
        flood_trigger = root / 'startup-flood-trigger'
        flood_ack = root / 'startup-flood-ack'
        flood_completed = root / 'startup-flood-completed'
        bridge_environment = dict(environment)
        bridge_environment['KER_TEST_VHOST_FLOOD_TRIGGER'] = str(flood_trigger)
        bridge_environment['KER_TEST_VHOST_FLOOD_ACK'] = str(flood_ack)
        backend = [str(args.bridge), f'--lcores=0@{bridge_cpu}', '--no-huge', '--no-pci', '--no-shconf',
            '--no-telemetry', '--iova-mode=va', '-m', '64',
            f'--vdev=net_vhost0,iface={backend_path},queues=2',
            '--vdev=net_tap0,iface=kerbackend,remote=kerlink']
        if args.queue_one:
            backend += ['--', '--queue-one']
        with (root / 'bridge.log').open('w+') as backend_log:
            bridge = subprocess.Popen(backend, stdout=subprocess.PIPE, stderr=backend_log, env=bridge_environment, text=True)
            try:
                ready(bridge)
                require(backend_path.is_socket(), 'real vhost socket not created')
                # The pinned PMD rejects the original fixture's iface+socket
                # combination. Preserve that error; do not silently drop iface.
                rejected = root / 'unsupported-iface.ini'
                rejected.write_text('[network]\naddress=198.18.0.2/24\n[dpdk]\nnb_vdev=1\n'
                    'port=net_virtio_user0\n'
                    f'eal=--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry --iova-mode=va -m 64\n'
                    f'[vdev0]\niface=eth0\npath={backend_path}\nqueues=2\nqueue_size=512\nmac=00:11:22:33:44:55\ncq=1\n')
                rejected_stats = root / 'unsupported-iface.json'
                result = subprocess.run([sys.executable, str(args.launcher), '--config', str(rejected),
                    '--library', str(args.library), '--io-worker', str(args.worker), '--stats', str(rejected_stats),
                    '--', '/bin/true'], capture_output=True, text=True, env=environment, timeout=20)
                require(result.returncode == 125 and 'arg iface applies only to vhost-kernel backend' in result.stderr,
                        'unsupported iface/socket tuple was silently accepted: ' + result.stderr)
                require(json.loads(rejected_stats.read_text())['outstanding'] == 0, 'rejected vdev leaked buffers')
                print('PASS: unsupported source iface/socket tuple fails explicitly and cleans up', flush=True)
                if args.queue_one:
                    for label, options, diagnostic in (
                            ('capacity', ['--queues', '3'], 'requested queue pairs exceed ethdev capacity'),
                            ('rss', ['--queues', '2', '--rss'], 'RSS requires IPv4/IPv6 TCP/UDP')):
                        marker = root / (label + '-application-started')
                        failure_stats = root / (label + '.json')
                        eal = (f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry '
                               f'--iova-mode=va -m 64 --vdev=net_virtio_user0,path={backend_path},queues=2,cq=1')
                        result = subprocess.run([sys.executable, str(args.launcher),
                            '--address', '198.18.0.2/24', '--port', 'net_virtio_user0', '--eal', eal,
                            '--library', str(args.library), '--io-worker', str(args.worker),
                            '--stats', str(failure_stats), *options, '--', '/usr/bin/touch', str(marker)],
                            env=environment, capture_output=True, text=True, timeout=20)
                        require(result.returncode == 125 and diagnostic in result.stderr and not marker.exists(),
                                'unsupported device request reached application: ' + result.stderr)
                        require(json.loads(failure_stats.read_text())['outstanding'] == 0,
                                'unsupported device request leaked buffers')
                    print('PASS: capacity/RSS requests rejected before application with zero owned buffers', flush=True)
                for queue_size, repeated in ((512, False), (4096, True), (32768, False)):
                    name = 'repeat' if repeated else 'queue-' + str(queue_size)
                    config, stats, capture = root / (name + '.ini'), root / (name + '.json'), root / (name + '-pcap')
                    capture.mkdir()
                    # Supported vhost-user subset; iface is kernel-backend-only in pinned DPDK.
                    text = '[dpdk]\nnb_vdev=1\nport=net_virtio_user0\n'
                    if args.queue_one:
                        text += 'queues=2\n'
                    memory_mb = 1024 if queue_size == 32768 else 64
                    text += f'eal=--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry --iova-mode=va -m {memory_mb}\n'
                    text += '[network]\naddress=198.18.0.2/24\naddress6=2001:db8:1::2/64\nmax_mtu=1500\n'
                    if repeated:
                        text += '[vdev0]\npath=/missing-backend\nqueues=bad\nqueue_size=3\nmac=invalid\ncq=9\n'
                    text += f'[vdev0]\npath={backend_path}\nqueues=2\nqueue_size={queue_size}\nmac=00:11:22:33:44:55\ncq=1\n'
                    config.write_text(text)
                    subprocess.run(['ip', 'neigh', 'flush', 'dev', 'kerhost'], check=True)
                    subprocess.run(['ip', '-6', 'neigh', 'flush', 'dev', 'kerhost'], check=True)
                    with (root / (name + '.log')).open('w+') as log:
                        process = subprocess.Popen([sys.executable, str(args.launcher), '--config', str(config),
                            '--library', str(args.library), '--io-worker', str(args.worker), '--stats', str(stats),
                            '--pcap-dir', str(capture), '--', str(args.app), 'native', '1500',
                            '198.18.0.1', '2001:db8:1::1'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=log, env=environment, text=True)
                        try:
                            ready(process)
                            peer = subprocess.run([str(args.app), 'peer', '1500', '198.18.0.2', '2001:db8:1::2'],
                                capture_output=True, text=True, timeout=20)
                            require(peer.returncode == 0 and peer.stdout.count('PASS:') == 2, peer.stdout + peer.stderr)
                            output, _ = process.communicate('G', timeout=20)
                            require(process.returncode == 0 and output.count('PASS:') == 2, 'native ICMP failed: ' + output)
                            record = json.loads(stats.read_text())
                            info = record['io']
                            print('DPDK virtio-user runtime evidence (' + name + '): ' +
                                json.dumps(record, sort_keys=True), flush=True)
                            require(info['driver'] == 'net_virtio_user' and info['port_count'] == 1,
                                    'typed vdev did not select the original virtio-user PMD: ' + str(info))
                            require(info['mac'] == '00:11:22:33:44:55' and info['max_rx_queues'] == 2
                                    and info['max_tx_queues'] == 2 and info['rx_descriptors'] == queue_size,
                                    'typed MAC/queue capacity did not reach actual PMD: ' + str(info))
                            require(info['mbuf_pool_count'] >= info['rx_descriptors'] + info['tx_descriptors'] + 320,
                                    'mbuf pool does not cover RX/TX descriptors and worker headroom: ' + str(info))
                            if args.queue_one:
                                require(info['queues'] == 2 and info['data_tx_queue'] == 0,
                                        'active queue count or application TX queue differs: ' + str(info))
                                counts = record['rx_by_queue']
                                require(len(counts) == 2 and sum(counts) == record['rx'] + record['rx_dropped'] and
                                        counts[0] == 0 and counts[1] > 0 and info['rss'] is None,
                                        'frames were not received on queue 1 with RSS disabled: ' + str(record))
                            require(record['tx'] > 0 and record['rx'] > 0 and record['outstanding'] == 0,
                                    'missing actual traffic or leaked virtio buffers')
                            require(info['queues'] == (2 if args.queue_one else 1) and info['data_tx_queue'] == 0,
                                    'active pairs or application TX queue differ from request')
                            counts = record['rx_by_queue']
                            require(len(counts) == info['queues'] and sum(counts) == record['rx'] + record['rx_dropped'] + record.get('rx_shutdown_discarded', 0) - record.get('rx_startup_discarded', 0),
                                    'queue accounting differs from received frames')
                            if args.queue_one:
                                require(counts[0] == 0 and counts[1] > 0,
                                        'independently injected queue-1 frames were not received: ' + str(counts))
                                require(info['rss'] is None, 'queue injection was mislabeled as RSS')
                                print('PASS: actual PMD rx_by_queue=' + str(counts) + '; RSS disabled', flush=True)
                            mtu.wire(capture, 1500)
                            print('PASS: ' + name + ' typed virtio-user queue_size=' + str(queue_size) +
                                ', real vhost/TAP IPv4/IPv6 and zero leaks', flush=True)
                            if queue_size in (4096, 32768):
                                tcp_udp_stats = root / (name + '-tcp-udp.json')
                                tcp_udp_config = config
                                with (root / (name + '-tcp-udp.log')).open('w+') as socket_log:
                                    startup_flood = queue_size == 4096
                                    startup_queue_ready = flood_completed
                                    if startup_flood:
                                        # The pinned virtio-user PMD only posts the full configured ring
                                        # before startup RX when vectorized RX is enabled. Exercise its
                                        # original raw EAL vdev interface without expanding Ker's typed
                                        # configuration schema.
                                        tcp_udp_config = root / 'queue-4096-vectorized.ini'
                                        tcp_udp_config.write_text(
                                            '[dpdk]\nnb_vdev=0\nport=net_virtio_user0\n'
                                            f'eal=--lcores=0@{cpu} --no-huge --no-pci --no-shconf '
                                            f'--no-telemetry --iova-mode=va -m 64 '
                                            f'--vdev=net_virtio_user0,path={backend_path},queues=2,'
                                            'queue_size=4096,mac=00:11:22:33:44:55,'
                                            'vectorized=1,mrg_rxbuf=0,in_order=0\n'
                                            '[network]\naddress=198.18.0.2/24\n'
                                            'address6=2001:db8:1::2/64\nmax_mtu=1500\n')
                                    command = [sys.executable, str(args.launcher), '--config', str(tcp_udp_config),
                                        '--library', str(args.library), '--io-worker', str(args.worker),
                                        '--stats', str(tcp_udp_stats)]
                                    if startup_flood:
                                        command.append('--no-promiscuous')
                                    command += ['--', sys.executable, str(Path(__file__).resolve()), '--socket-server']
                                    worker_environment = environment
                                    if startup_flood:
                                        worker_environment = dict(environment)
                                        worker_environment['LD_PRELOAD'] += ':' + str(args.startup_delay_library.resolve())
                                        worker_environment['KER_TEST_VHOST_FLOOD_TRIGGER'] = str(flood_trigger)
                                        worker_environment['KER_TEST_VHOST_FLOOD_ACK'] = str(flood_ack)
                                        worker_environment['KER_TEST_VHOST_FLOOD_COMPLETED'] = str(startup_queue_ready)
                                    native = subprocess.Popen(command, stdout=subprocess.PIPE,
                                        stderr=socket_log, env=worker_environment, text=True)
                                    try:
                                        ready(native)
                                        with socket.create_connection(('198.18.0.2', 27991), timeout=10) as peer:
                                            peer.sendall(b'original-linux-tcp')
                                            response = bytearray()
                                            while len(response) < len(b'original-linux-tcp'):
                                                chunk = peer.recv(len(b'original-linux-tcp') - len(response))
                                                require(chunk, 'native TCP echo closed early')
                                                response.extend(chunk)
                                            require(bytes(response) == b'original-linux-tcp', 'native TCP echo mismatch')
                                        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
                                            peer.settimeout(10)
                                            peer.sendto(b'original-linux-udp', ('198.18.0.2', 27992))
                                            require(peer.recvfrom(256)[0] == b'original-linux-udp', 'native UDP echo mismatch')
                                        output, _ = native.communicate(timeout=20)
                                        require(native.returncode == 0 and 'PASS:' in output,
                                            'native TCP/UDP process failed: ' + output)
                                        record = json.loads(tcp_udp_stats.read_text())
                                        require(record['tx'] and record['rx'] and record['outstanding'] == 0 and
                                            record['native']['passive_opens'] > 0 and
                                            record['native']['udp_in_datagrams'] > 0 and
                                            record['native']['udp_out_datagrams'] > 0,
                                            'native TCP/UDP counters or zero-buffer cleanup missing: ' + str(record))
                                        if startup_flood:
                                            print('DPDK startup-drain runtime evidence: ' +
                                                json.dumps(record, sort_keys=True), flush=True)
                                            require(record['rx_startup_discarded'] > 256 and
                                                record['io']['driver'] == 'net_virtio_user' and
                                                record['io']['rx_descriptors'] == 4096 and
                                                record['io']['promiscuous'] is False and startup_queue_ready.exists(),
                                                'startup backlog was not drained beyond 256 with promiscuous mode restored: ' + str(record))
                                            print('PASS: queued vhost frames=' + str(record['rx_startup_discarded']) +
                                                ' drained by original vectorized virtio-user queue_size=4096; '
                                                'promiscuous=false; native TCP/UDP and zero buffers',
                                                flush=True)
                                        print('PASS: queue_size=' + str(queue_size) +
                                            ' real imported Linux TCP/UDP and zero buffers', flush=True)
                                    except Exception:
                                        socket_log.flush(); socket_log.seek(0); print(socket_log.read(), file=sys.stderr)
                                        raise
                                    finally:
                                        stop(native)
                        except Exception:
                            log.flush(); log.seek(0); print(log.read(), file=sys.stderr)
                            raise
                        finally:
                            stop(process)
                bridge.terminate()
                output, _ = bridge.communicate(timeout=10)
                require(bridge.returncode == 0, 'vhost/TAP backend failed')
                lines = [line.removeprefix('BRIDGE ') for line in output.splitlines() if line.startswith('BRIDGE ')]
                require(len(lines) == 1, 'missing backend ownership evidence: ' + output)
                record = json.loads(lines[0])
                require(record['to_host'] > 0 and record['to_native'] > 0 and record['outstanding'] == 0,
                        'vhost/TAP did not bridge both ways or leaked mbufs')
                require(record['startup_flood'] == 1800,
                        'vhost did not queue the requested startup-ring flood: ' + str(record))
                print('PASS: vhost queued all ' + str(record['startup_flood']) +
                    ' startup frames through the original virtio PMD', flush=True)
                require(not backend_path.exists(), 'vhost socket leaked after backend close')
            except Exception:
                backend_log.flush(); backend_log.seek(0); print(backend_log.read(), file=sys.stderr)
                raise
            finally:
                stop(bridge)
    return 0


if __name__ == '__main__':
    sys.exit(main())
