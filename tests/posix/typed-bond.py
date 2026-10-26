#!/usr/bin/env python3
"""Original DPDK 802.3ad bond against an independent host Linux LACP bond."""
import argparse
import configparser
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

spec = importlib.util.spec_from_file_location('icmp_mtu', Path(__file__).with_name('icmp-mtu.py'))
mtu = importlib.util.module_from_spec(spec); spec.loader.exec_module(mtu)
require, ready, stop = mtu.require, mtu.ready, mtu.stop


def command(*args):
    return subprocess.run(['ip', *args], check=True, capture_output=True, text=True)


def lacp_ready(member_count=2):
    deadline = time.monotonic() + 30
    observed = []
    while time.monotonic() < deadline:
        observed = []
        for index in range(member_count):
            name = 'host' + str(index)
            record = json.loads(command('-d', '-j', 'link', 'show', name).stdout)[0]
            info = record['linkinfo']['info_slave_data']
            observed.append(info)
        if all(info.get('ad_actor_oper_port_state', 0) & 0x30 == 0x30 and
               info.get('ad_partner_oper_port_state', 0) & 0x30 == 0x30 for info in observed):
            require(len({info.get('ad_aggregator_id') for info in observed}) == 1,
                'members use different LACP aggregators')
            return
        time.sleep(0.1)
    raise RuntimeError('LACP did not reach collecting/distributing on both partners: ' + str(observed))


def timing_values(source=False):
    if not source:
        return dict(lsc_poll_period_ms=100, up_delay=100, down_delay=200)
    fixture = Path(__file__).resolve().parents[1] / 'upstream/fstack/tests/unit/fixtures/valid_dpdk_extra_keys.ini'
    values = configparser.ConfigParser(interpolation=None)
    with fixture.open() as stream:
        values.read_file(stream)
    return {key: values.getint('bond0', key) for key in ('lsc_poll_period_ms', 'up_delay', 'down_delay')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('launcher', 'library', 'worker', 'app', 'pmd-root'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--bridge', type=Path)
    parser.add_argument('--large-virtio-member', action='store_true')
    parser.add_argument('--inside', action='store_true')
    parser.add_argument('--source-timings', action='store_true',
                        help='use the pinned dpdk_extra_keys bond timing fields')
    parser.add_argument('--queues', type=int, choices=(1, 3), default=1)
    args = parser.parse_args()
    timings = timing_values(args.source_timings)
    modules = []
    for name in ('tap', 'bond'):
        found = list(args.pmd_root.glob('dpdk/pmds-*/librte_net_' + name + '.so'))
        if not found:
            print('SKIP: missing original DPDK ' + name + ' PMD', flush=True); return 77
        modules.append(str(found[0]))
    environment = dict(os.environ)
    environment.pop('LD_PRELOAD', None)  # The bond worker links original PMDs statically.
    if not args.inside:
        argv = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()), '--inside', '--queues', str(args.queues)]
        for name in ('launcher', 'library', 'worker', 'app', 'pmd-root'):
            argv += ['--' + name, str(getattr(args, name.replace('-', '_')).resolve())]
        if args.source_timings:
            argv += ['--source-timings']
        if args.bridge:
            argv += ['--bridge', str(args.bridge.resolve())]
        if args.large_virtio_member:
            argv += ['--large-virtio-member']
        return subprocess.run(argv, env=environment).returncode
    command('link', 'set', 'lo', 'up')
    host_mode = 'active-backup' if args.large_virtio_member else '802.3ad'
    command('link', 'add', 'hostbond', 'type', 'bond', 'mode', host_mode, 'miimon', '100',
        *([] if args.large_virtio_member else ['lacp_rate', 'fast']))
    member_count = 3 if args.large_virtio_member else 2
    for index in range(member_count):
        command('link', 'add', 'host' + str(index), 'type', 'veth', 'peer', 'name', 'link' + str(index))
        command('link', 'set', 'host' + str(index), 'master', 'hostbond')
        command('link', 'set', 'host' + str(index), 'up')
        command('link', 'set', 'link' + str(index), 'up')
    command('addr', 'add', '198.18.0.1/24', 'dev', 'hostbond')
    command('-6', 'addr', 'add', '2001:db8:1::1/64', 'dev', 'hostbond', 'nodad')
    command('link', 'set', 'hostbond', 'up')
    cpu = min(os.sched_getaffinity(0))
    with tempfile.TemporaryDirectory(prefix='ker-bond-') as directory:
        root = Path(directory); stats = root / 'stats.json'; capture = root / 'pcap'; capture.mkdir()
        backend = None
        backend_log = None
        flood_trigger = root / 'startup-flood-trigger'
        flood_ack = root / 'startup-flood-ack'
        flood_completed = root / 'startup-flood-completed'
        if args.large_virtio_member:
            require(args.bridge is not None, '--bridge is required for a large virtio bond member')
            backend_path = root / 'vhost.sock'
            backend_environment = dict(environment)
            backend_environment['LD_PRELOAD'] = ':'.join(modules[:1] + [str(path) for path in
                args.pmd_root.glob('dpdk/pmds-*/librte_net_vhost.so')])
            backend_environment['LD_LIBRARY_PATH'] = str(args.pmd_root.resolve()) + ':' + backend_environment.get('LD_LIBRARY_PATH', '')
            backend_environment['KER_TEST_VHOST_FLOOD_TRIGGER'] = str(flood_trigger)
            backend_environment['KER_TEST_VHOST_FLOOD_ACK'] = str(flood_ack)
            backend_log = (root / 'bridge.log').open('w+')
            backend = subprocess.Popen([str(args.bridge), f'--lcores=0@{cpu}', '--no-huge',
                '--no-pci', '--no-shconf', '--no-telemetry', '--iova-mode=va', '-m', '64',
                f'--vdev=net_vhost0,iface={backend_path},queues=2',
                '--vdev=net_tap0,iface=kerbackend,remote=link2'], stdout=subprocess.PIPE,
                stderr=backend_log, env=backend_environment, text=True)
            try:
                ready(backend)
            except Exception:
                backend_log.flush(); backend_log.seek(0); print(backend_log.read(), file=sys.stderr)
                stop(backend)
                raise
            require(backend_path.is_socket(), 'large-member vhost socket was not created')
            command('link', 'set', 'dev', 'hostbond', 'type', 'bond', 'active_slave', 'host2')
            host_info = json.loads(command('-d', '-j', 'link', 'show', 'hostbond').stdout)[0]
            require(host_info.get('linkinfo', {}).get('info_data', {}).get('active_slave') == 'host2',
                'host active-backup bond did not select the virtio member path: ' + str(host_info))
        config = root / 'bond.ini'
        eal_vdevs = ('--vdev=net_tap0,iface=bondtap0,remote=link0 '
            '--vdev=net_tap1,iface=bondtap1,remote=link1')
        if args.large_virtio_member:
            eal_vdevs += (f' --vdev=net_virtio_user0,path={backend_path},queues=2,'
                'queue_size=4096,mac=02:00:00:00:00:03,cq=1,'
                'vectorized=1,mrg_rxbuf=0,in_order=0')
        config_text = ('[network]\naddress=198.18.0.2/24\naddress6=2001:db8:1::2/64\n'
            f'[dpdk]\nnb_bond=1\nport=net_bonding0\nqueues={args.queues}\n'
            f'eal=--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry --iova-mode=va -m {256 if args.large_virtio_member else 64} '
            f'{eal_vdevs}\n')
        if not args.large_virtio_member:
            config_text += '[bond0]\nmode=invalid\nslave=missing\nprimary=missing\nmac=invalid\nxmit_policy=invalid\n'
        config_text += (f'[bond0]\nmode={1 if args.large_virtio_member else 4}\n'
            f'slave={",".join(str(index) for index in range(member_count))}\n'
            f'primary={2 if args.large_virtio_member else 0}\nsocket_id=0\nmac=AA:BB:CC:DD:EE:FF\n'
            + ('' if args.large_virtio_member else 'xmit_policy=l34\n')
            + ''.join(f'{key}={value}\n' for key, value in timings.items()))
        config.write_text(config_text)
        with (root / 'native.log').open('w+') as log:
            worker_command = [sys.executable, str(args.launcher), '--config', str(config),
                '--library', str(args.library), '--io-worker', str(args.worker), '--stats', str(stats),
                '--pcap-dir', str(capture)]
            worker_environment = environment
            if args.large_virtio_member:
                worker_command += ['--no-promiscuous', '--', str(args.app), 'native', '1500',
                    '198.18.0.1', '2001:db8:1::1']
                worker_environment = dict(environment)
                worker_environment['KER_TEST_VHOST_FLOOD_TRIGGER'] = str(flood_trigger)
                worker_environment['KER_TEST_VHOST_FLOOD_ACK'] = str(flood_ack)
                worker_environment['KER_TEST_VHOST_FLOOD_COMPLETED'] = str(flood_completed)
            else:
                worker_command += ['--', str(args.app), 'native', '1500', '198.18.0.1', '2001:db8:1::1']
            process = subprocess.Popen(worker_command,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, env=worker_environment, text=True)
            try:
                ready(process)
                if not args.large_virtio_member:
                    lacp_ready(member_count)
                peer = subprocess.run([str(args.app), 'peer', '1500', '198.18.0.2', '2001:db8:1::2'], capture_output=True, text=True, timeout=20)
                require(peer.returncode == 0 and peer.stdout.count('PASS:') == 2, peer.stdout + peer.stderr)
                # Remove one real physical path while the same native kernel
                # and bond worker stay live; the remaining aggregate must work.
                if not args.large_virtio_member:
                    command('link', 'set', 'host0', 'down')
                    deadline = time.monotonic() + 10
                    while time.monotonic() < deadline:
                        record = json.loads(command('-d', '-j', 'link', 'show', 'host1').stdout)[0]
                        info = record['linkinfo']['info_slave_data']
                        if info.get('ad_actor_oper_port_state', 0) & 0x30 == 0x30:
                            break
                        time.sleep(0.1)
                    time.sleep(4)  # Original LACP short timeout expires the disconnected partner.
                    peer = subprocess.run([str(args.app), 'peer', '1500', '198.18.0.2', '2001:db8:1::2'],
                        capture_output=True, text=True, timeout=20)
                    require(peer.returncode == 0 and peer.stdout.count('PASS:') == 2, 'member-loss recovery failed: ' + peer.stderr)
                output, _ = process.communicate('G', timeout=20)
                require(process.returncode == 0 and output.count('PASS:') == 2, 'native bond traffic failed: ' + output)
                record = json.loads(stats.read_text()); bond = record['bond']
                require(record['io']['driver'] == 'net_bonding' and record['io']['port_count'] == member_count + 1
                        and record['io']['mac'] == 'aa:bb:cc:dd:ee:ff' and record['io']['socket_id'] == 0, 'wrong actual bond/MAC')
                expected = dict(mode=1 if args.large_virtio_member else 4,
                    primary=2 if args.large_virtio_member else 0,
                    poll_ms=timings['lsc_poll_period_ms'], up_ms=timings['up_delay'],
                    down_ms=timings['down_delay'], members=member_count)
                if not args.large_virtio_member:
                    expected['xmit_policy'] = 2
                require(all(record['io']['bond'][key] == value for key, value in expected.items()),
                        'initial original DPDK bond settings differ: ' + str(record['io']['bond']))
                require(all(bond[key] == value for key, value in expected.items() if key != 'primary')
                        and bond['primary'] == (2 if args.large_virtio_member else bond['primary']) and
                        (args.large_virtio_member or bond['primary'] in (0, 1)) and
                        1 <= bond['active'] <= member_count and
                        (args.large_virtio_member or 1 <= bond['lacp_distributing'] <= member_count),
                        'LACP did not retire the disconnected path: ' + str(bond))
                require(record['outstanding'] == 0 and record['tx'] > 0 and record['rx'] > 0, 'missing bond traffic or leaked member buffers')
                require(record['io']['queues'] == args.queues and
                        record['io']['pool_rx_descriptors'] >= 3 * args.queues * 256 and
                        record['io']['pool_tx_descriptors'] >= 3 * args.queues * 256,
                        'selected bond or member descriptors missing from pool budget')
                if args.large_virtio_member:
                    require(record['io']['pool_rx_descriptors'] > 4095 and
                        record['io']['pool_tx_descriptors'] > 4095 and
                        record['io']['mbuf_pool_count'] == record['io']['pool_rx_descriptors'] +
                        record['io']['pool_tx_descriptors'] + 320,
                        'large virtio member was not included in aggregate pool budget: ' + str(record['io']))
                    member_rx_budget = record['io']['pool_rx_descriptors'] - 256
                    require(record['rx_startup_discarded'] >= 1800 and
                        256 < record['rx_startup_discarded'] <= member_rx_budget and
                        flood_completed.is_file(),
                        'bond did not drain the deterministic 1800-frame virtio-member backlog: ' + str(record))
                print('DPDK bond runtime evidence: ' + json.dumps(record, sort_keys=True), flush=True)
                # The capture includes both the initial peer exchange and the
                # second exchange after one LACP member is removed.
                mtu.wire(capture, 1500, request_counts=None if args.large_virtio_member else {'rx': 6, 'tx': 3})
                print('PASS: actual original bond mode=' + str(bond['mode']) +
                    (' with LACP partners' if bond['mode'] == 4 else ' with a large virtio member') +
                    ', bond fields, IPv4/IPv6 frames and zero buffers', flush=True)
            except Exception:
                log.flush(); log.seek(0); print(log.read(), file=sys.stderr); raise
            finally:
                stop(process)
                if backend is not None:
                    if process.returncode not in (0, None) and backend_log is not None:
                        backend_log.flush(); backend_log.seek(0)
                        print(backend_log.read(), file=sys.stderr)
                    stop(backend)
                if backend_log is not None:
                    backend_log.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
