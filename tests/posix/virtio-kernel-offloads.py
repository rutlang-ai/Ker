#!/usr/bin/env python3
"""Original virtio-user/vhost-net IPv4/IPv6 TSO with independent wire checks."""
import argparse
import concurrent.futures
import importlib.util
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import subprocess
import sys
import tempfile
import threading

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('offloads', Path(__file__).with_name('tx-offloads.py'))
offloads = importlib.util.module_from_spec(spec)
spec.loader.exec_module(offloads)
require = offloads.require


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('launcher', 'library', 'worker', 'app', 'pmd-root', 'failure-library'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    modules = list(args.pmd_root.glob('dpdk/pmds-*/librte_net_virtio.so'))
    if not modules:
        print('SKIP: install the pinned original virtio PMD')
        return 77
    try:
        descriptor = os.open('/dev/vhost-net', os.O_RDWR)
        os.close(descriptor)
    except OSError as error:
        print('SKIP: /dev/vhost-net unavailable: ' + str(error))
        return 77
    environment = dict(os.environ, LD_PRELOAD=str(modules[0]))
    if not args.inside:
        command = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()), '--inside']
        for name in ('launcher', 'library', 'worker', 'app', 'pmd-root', 'failure-library'):
            command += ['--' + name, str(getattr(args, name.replace('-', '_')).resolve())]
        return subprocess.run(command, env=environment).returncode
    for command in (
            ['ip', 'link', 'set', 'lo', 'up'],
            ['ip', 'link', 'add', 'offhost', 'type', 'veth', 'peer', 'name', 'offlink'],
            ['ip', 'addr', 'add', '198.18.0.1/24', 'dev', 'offhost'],
            ['ip', '-6', 'addr', 'add', '2001:db8:1::1/64', 'dev', 'offhost', 'nodad'],
            ['ip', 'link', 'set', 'offhost', 'up'], ['ip', 'link', 'set', 'offlink', 'up'],
            ['tc', 'qdisc', 'add', 'dev', 'offlink', 'clsact']):
        subprocess.run(command, check=True)
    for name in ('offhost', 'offlink'):
        subprocess.run(['ethtool', '-K', name, 'gro', 'off', 'gso', 'off', 'tso', 'off', 'tx', 'off'], check=True, capture_output=True)
    cpu = min(os.sched_getaffinity(0))
    with tempfile.TemporaryDirectory(prefix='ker-virtio-tso-') as directory:
        root = Path(directory)
        for mode, storage, queues, persistent, rename_tap in (('off', 'large', 1, None, False), ('checksum', 'large', 1, None, False),
                ('tso', 'large', 1, None, False), ('tso', 'scatter', 2, False, False), ('tso', 'large', 1, True, False),
                ('tso', 'large', 1, False, True)):
            label = mode + '-' + storage + ('-persistent-' + str(persistent) if persistent is not None else '') + ('-rename' if rename_tap else '')
            stats, config = root / (label + '.json'), root / (label + '.ini')
            config.write_text('[network]\naddress=198.18.0.2/24\naddress6=2001:db8:1::2/64\n'
                f'[dpdk]\nnb_vdev=1\nport=net_virtio_user0\nqueues={queues}\nmbuf_mode={storage}\ntx_offloads={mode}\n'
                f'eal=--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry --iova-mode=va -m 96\n'
                f'[vdev0]\npath=/dev/vhost-net\niface=offpeer\nqueues={queues}\nqueue_size=512\nmac=02:11:22:33:44:55\ncq=1\n')
            if mode == 'off':
                for name, injected in (('unnamed', False), ('readback', True)):
                    negative = root / (name + '.ini')
                    negative.write_text(config.read_text() if injected else config.read_text().replace('iface=offpeer\n', ''))
                    failure_stats, marker = root / (name + '.json'), root / (name + '-app-entered')
                    failure_env = dict(environment)
                    if injected:
                        subprocess.run(['ip', 'tuntap', 'add', 'dev', 'offpeer', 'mode', 'tap', 'multi_queue', 'vnet_hdr'], check=True)
                        failure_env['LD_PRELOAD'] = str(args.failure_library) + ':' + environment['LD_PRELOAD']
                        failure_env['KER_TEST_RECEIVE_MODE_FAILURE'] = '1'
                    result = subprocess.run([sys.executable, str(args.launcher), '--config', str(negative),
                        '--library', str(args.library), '--io-worker', str(args.worker), '--stats', str(failure_stats),
                        '--', '/usr/bin/touch', str(marker)], env=failure_env, text=True, capture_output=True, timeout=20)
                    failed = json.loads(failure_stats.read_text())
                    require(result.returncode == 125 and not marker.exists() and failed['outstanding'] == 0 and
                            'cannot enable --all-multicast' in result.stderr, 'unsupported/failed receive mode reached app: ' + result.stderr)
                    if injected:
                        require('INJECT: kernel TAP flag readback EIO after successful set' in result.stderr and
                                failed['host_receive_mode_restored'], 'readback failure did not exercise real rollback: ' +
                                result.stderr + ' stats=' + json.dumps(failed))
                        flags = json.loads(subprocess.check_output(['ip', '-j', 'link', 'show', 'offpeer'], text=True))[0]['flags']
                        require('ALLMULTI' not in flags and 'UP' not in flags, 'failed startup changed persistent TAP flags')
                        subprocess.run(['ip', 'tuntap', 'del', 'dev', 'offpeer', 'mode', 'tap', 'multi_queue', 'vnet_hdr'], check=True)
                    else:
                        links = json.loads(subprocess.check_output(['ip', '-j', 'link'], text=True))
                        require(not any(link.get('link_type') == 'ether' and link['ifname'].startswith('tap') for link in links),
                                'rejected unnamed kernel TAP leaked')
                    print('PASS: kernel receive-mode ' + name + ' rejects before app; flags restored, zero mbufs', flush=True)
            if persistent is not None:
                subprocess.run(['ip', 'tuntap', 'add', 'dev', 'offpeer', 'mode', 'tap', 'multi_queue', 'vnet_hdr'], check=True)
                subprocess.run(['ip', 'link', 'set', 'offpeer', 'allmulticast', 'on' if persistent else 'off'], check=True)
            for family in ([], ['-6']):
                subprocess.run(['ip', *family, 'neigh', 'flush', 'dev', 'offhost'], check=True)
            sockets = []
            wire = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            wire.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            wire.bind(('offhost', 0))
            stop = threading.Event()
            process = None
            with (root / (label + '.log')).open('w+') as log:
                try:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                        try:
                            recording = executor.submit(offloads.capture, wire, stop, 42000)
                            peers = []
                            for family in (0, 1):
                                for tcp in (False, True):
                                    sock = socket.socket(socket.AF_INET6 if family else socket.AF_INET,
                                                         socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM)
                                    sockets.append(sock)
                                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                                    sock.bind(('2001:db8:1::1' if family else '198.18.0.1', 42000))
                                    if tcp:
                                        sock.listen()
                                    peers.append(executor.submit(offloads.peer, sock, tcp, family))
                            process = subprocess.Popen([sys.executable, str(args.launcher), '--config', str(config),
                                '--library', str(args.library), '--io-worker', str(args.worker), '--stats', str(stats),
                                '--', str(args.app), '42000', 'wait'], env=environment, text=True,
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, start_new_session=True)
                            with selectors.DefaultSelector() as selector:
                                selector.register(process.stdout, selectors.EVENT_READ)
                                require(selector.select(20), 'virtio/vhost-net startup timeout')
                            require(process.stdout.readline().strip() == 'READY', 'application failed before link setup')
                            tap_name = 'offpeer'
                            if rename_tap:
                                original_index = json.loads(subprocess.check_output(['ip', '-j', 'link', 'show', tap_name], text=True))[0]['ifindex']
                                subprocess.run(['ip', 'link', 'set', tap_name, 'name', 'offpeer-moved'], check=True)
                                tap_name = 'offpeer-moved'
                                moved = json.loads(subprocess.check_output(['ip', '-j', 'link', 'show', tap_name], text=True))[0]
                                require(moved['ifindex'] == original_index, 'TAP rename changed interface index')
                            # The original kernel backend assigns the guest MAC to TAP.
                            # Forward Ethernet through original TC, like net_tap's
                            # remote path; a bridge's local FDB would consume that MAC.
                            for command in (['tc', 'filter', 'del', 'dev', 'offlink', 'ingress'],
                                            ['ip', 'link', 'set', tap_name, 'up'],
                                            ['tc', 'qdisc', 'add', 'dev', tap_name, 'clsact'],
                                            ['tc', 'filter', 'add', 'dev', tap_name, 'ingress', 'matchall',
                                             'action', 'mirred', 'egress', 'redirect', 'dev', 'offlink'],
                                            ['tc', 'filter', 'add', 'dev', 'offlink', 'ingress', 'pref', '1', 'matchall',
                                             'action', 'mirred', 'egress', 'redirect', 'dev', tap_name]):
                                subprocess.run(command, check=True)
                            link = json.loads(subprocess.check_output(['ip', '-j', 'link', 'show', tap_name], text=True))[0]
                            require('ALLMULTI' in link['flags'], 'host TAP all-multicast flag was not actually set')
                            output, _ = process.communicate('G', timeout=25)
                            require(process.returncode == 0 and output.count('PASS:') == 2,
                                    'native virtio offload execution failed: ' + output)
                            for peer in peers:
                                peer.result(timeout=2)
                            stop.set()
                            counts = recording.result(timeout=2)
                            record = json.loads(stats.read_text())
                            info = record['io']
                            require(info['driver'] == 'net_virtio_user' and info['mac'] == '02:11:22:33:44:55',
                                    'typed kernel backend did not reach original PMD')
                            require(info['queues'] == queues and info['max_rx_queues'] == queues and info['rx_descriptors'] == 512,
                                    'wrong actual active/capacity/descriptor geometry')
                            require(info['tx_offload_mode'] == {'off': 0, 'checksum': 1, 'tso': 2}[mode], 'wrong offload mode')
                            require(record['mtu_changes'] == 2 and record['mtu_final'] == 1500, 'offload queue restart not executed')
                            require(info['all_multicast_method'] == 'host_tap' and record['host_receive_mode_restored'],
                                    'missing real host receive-mode adaptation/restoration')
                            require(record['outstanding'] == record['dropped'] == 0, 'virtio ownership/drop failure')
                            require(info['tx_offload_features'] == (0 if mode == 'off' else 1 if mode == 'checksum' else 0x1801),
                                    'actual original Linux feature negotiation differs')
                            if mode == 'tso':
                                require(record['tx_tso4'] > 0 and record['tx_tso6'] > 0,
                                        'missing actual original Linux IPv4/IPv6 TSO requests')
                            else:
                                require(record['tx_tso4'] == record['tx_tso6'] == 0, 'unexpected TSO requests')
                            if mode == 'off':
                                require(record['tx_tcp_checksum'] == record['tx_udp_checksum'] == 0, 'default off changed')
                            else:
                                require(record['tx_tcp_checksum'] > 0 and record['tx_udp_checksum'] == 8,
                                        'no actual original Linux checksum requests')
                            require(info['rss'] is None and sum(record['rx_by_queue']) == record['rx'] + record['rx_dropped'],
                                    'queue accounting differs or non-RSS landing mislabeled')
                            require(counts['tcp4'] > 100 and counts['tcp6'] > 100 and counts['udp4'] == counts['udp6'] == 4,
                                    'missing independent wire evidence')
                            print('PASS: kernel virtio ' + label + ' queues=' + str(queues) + '; wire=' + str(counts) +
                                  '; requests=' + str({k: record[k] for k in ('tx_tcp_checksum', 'tx_udp_checksum', 'tx_tso4', 'tx_tso6')}), flush=True)
                        finally:
                            stop.set()
                except Exception:
                    log.flush(); log.seek(0); print(log.read(), file=sys.stderr)
                    if stats.exists(): print(stats.read_text(), file=sys.stderr)
                    raise
                finally:
                    stop.set()
                    wire.close()
                    for sock in sockets:
                        sock.close()
                    if process and process.poll() is None:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.communicate()
            if persistent is None:
                require(subprocess.run(['ip', 'link', 'show', 'offpeer'], capture_output=True).returncode != 0,
                        'ephemeral vhost-kernel TAP survived worker teardown')
            else:
                tap_name = 'offpeer-moved' if rename_tap else 'offpeer'
                flags = json.loads(subprocess.check_output(['ip', '-j', 'link', 'show', tap_name], text=True))[0]['flags']
                require(('ALLMULTI' in flags) == persistent and 'UP' in flags,
                        'worker did not preserve original multicast state and unrelated interface flags')
                subprocess.run(['ip', 'tuntap', 'del', 'dev', tap_name, 'mode', 'tap', 'multi_queue', 'vnet_hdr'], check=True)
                print('PASS: persistent kernel TAP restores ALLMULTI=' + str(persistent) + ' and preserves UP' +
                      (' after rename' if rename_tap else ''), flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
