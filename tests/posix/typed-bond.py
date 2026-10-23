#!/usr/bin/env python3
"""Original DPDK 802.3ad bond against an independent host Linux LACP bond."""
import argparse
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


def lacp_ready():
    deadline = time.monotonic() + 30
    observed = []
    while time.monotonic() < deadline:
        observed = []
        for name in ('host0', 'host1'):
            record = json.loads(command('-d', '-j', 'link', 'show', name).stdout)[0]
            info = record['linkinfo']['info_slave_data']
            observed.append(info)
        if all(info.get('ad_actor_oper_port_state', 0) & 0x30 == 0x30 and
               info.get('ad_partner_oper_port_state', 0) & 0x30 == 0x30 for info in observed):
            require(observed[0]['ad_aggregator_id'] == observed[1]['ad_aggregator_id'], 'members use different LACP aggregators')
            return
        time.sleep(0.1)
    raise RuntimeError('LACP did not reach collecting/distributing on both partners: ' + str(observed))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('launcher', 'library', 'worker', 'app', 'pmd-root'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    modules = []
    for name in ('tap', 'bond'):
        found = list(args.pmd_root.glob('dpdk/pmds-*/librte_net_' + name + '.so'))
        if not found:
            print('SKIP: missing original DPDK ' + name + ' PMD', flush=True); return 77
        modules.append(str(found[0]))
    environment = dict(os.environ)
    environment.pop('LD_PRELOAD', None)  # The bond worker links original PMDs statically.
    if not args.inside:
        argv = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()), '--inside']
        for name in ('launcher', 'library', 'worker', 'app', 'pmd-root'):
            argv += ['--' + name, str(getattr(args, name.replace('-', '_')).resolve())]
        return subprocess.run(argv, env=environment).returncode
    command('link', 'set', 'lo', 'up')
    command('link', 'add', 'hostbond', 'type', 'bond', 'mode', '802.3ad', 'miimon', '100', 'lacp_rate', 'fast')
    for index in range(2):
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
        config = root / 'bond.ini'
        config.write_text('[network]\naddress=198.18.0.2/24\naddress6=2001:db8:1::2/64\n'
            '[dpdk]\nnb_bond=1\nport=net_bonding0\n'
            f'eal=--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry --iova-mode=va -m 64 '
            '--vdev=net_tap0,iface=bondtap0,remote=link0 --vdev=net_tap1,iface=bondtap1,remote=link1\n'
            '[bond0]\nmode=invalid\nslave=missing\nprimary=missing\nmac=invalid\nxmit_policy=invalid\n'
            '[bond0]\nmode=4\nslave=0,1\nprimary=0\nsocket_id=0\nmac=AA:BB:CC:DD:EE:FF\n'
            'xmit_policy=l34\nlsc_poll_period_ms=100\nup_delay=100\ndown_delay=200\n')
        with (root / 'native.log').open('w+') as log:
            process = subprocess.Popen([sys.executable, str(args.launcher), '--config', str(config),
                '--library', str(args.library), '--io-worker', str(args.worker), '--stats', str(stats),
                '--pcap-dir', str(capture), '--', str(args.app), 'native', '1500', '198.18.0.1', '2001:db8:1::1'],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, env=environment, text=True)
            try:
                ready(process)
                lacp_ready()
                peer = subprocess.run([str(args.app), 'peer', '1500', '198.18.0.2', '2001:db8:1::2'], capture_output=True, text=True, timeout=20)
                require(peer.returncode == 0 and peer.stdout.count('PASS:') == 2, peer.stdout + peer.stderr)
                # Remove one real physical path while the same native kernel
                # and bond worker stay live; the remaining aggregate must work.
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
                require(record['io']['driver'] == 'net_bonding' and record['io']['port_count'] == 3
                        and record['io']['mac'] == 'aa:bb:cc:dd:ee:ff' and record['io']['socket_id'] == 0, 'wrong actual bond/MAC')
                expected = dict(mode=4, primary=0, xmit_policy=2, poll_ms=100, up_ms=100, down_ms=200, members=2)
                require(all(record['io']['bond'][key] == value for key, value in expected.items()),
                        'initial original DPDK bond settings differ: ' + str(record['io']['bond']))
                require(all(bond[key] == value for key, value in expected.items() if key != 'primary')
                        and bond['primary'] in (0, 1) and 1 <= bond['active'] <= 2 and bond['lacp_distributing'] == 1,
                        'LACP did not retire the disconnected path: ' + str(bond))
                require(record['outstanding'] == 0 and record['tx'] > 0 and record['rx'] > 0, 'missing bond traffic or leaked member buffers')
                mtu.wire(capture, 1500)
                print('PASS: actual mode4 LACP partners, all bond fields, IPv4/IPv6 frames and zero buffers', flush=True)
            except Exception:
                log.flush(); log.seek(0); print(log.read(), file=sys.stderr); raise
            finally:
                stop(process)
    return 0


if __name__ == '__main__':
    sys.exit(main())
