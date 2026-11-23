#!/usr/bin/env python3
"""Run the dual-family UDP public-API matrix in isolated host/native kernels."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--app', type=Path, required=True)
    p.add_argument('--host-only', action='store_true')
    p.add_argument('--signal-boundary', action='store_true')
    p.add_argument('--inside', action='store_true')
    for name in ('launcher', 'library', 'worker'):
        p.add_argument('--' + name, type=Path)
    args = p.parse_args()
    if not args.inside:
        command = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()), '--inside', '--app', str(args.app.resolve())]
        if args.signal_boundary:
            command += ['--signal-boundary']
        if args.host_only:
            command += ['--host-only']
        else:
            for name in ('launcher', 'library', 'worker'):
                command += ['--' + name, str(getattr(args, name).resolve())]
        return subprocess.run(command).returncode
    for scope in ('all', 'default', 'lo'):
        Path('/proc/sys/net/ipv6/conf/' + scope + '/disable_ipv6').write_text('0\n')
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    if args.host_only:
        return subprocess.run([str(args.app), *(['host'] if args.signal_boundary else [])], check=False, timeout=25).returncode
    for command in (
        ['ip', 'link', 'add', 'kerhost', 'type', 'veth', 'peer', 'name', 'kerlink'],
        ['ip', 'link', 'set', 'kerhost', 'up'], ['ip', 'link', 'set', 'kerlink', 'up']):
        subprocess.run(command, check=True)
    cpu = min(os.sched_getaffinity(0))
    eal = (f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry '
           '--iova-mode=va -m 64 --vdev=net_tap0,iface=kerpeer,remote=kerlink')
    with tempfile.TemporaryDirectory(prefix='ker-udp-contracts-') as directory:
        stats = Path(directory) / 'stats.json'
        result = subprocess.run([sys.executable, str(args.launcher), '--library', str(args.library),
            '--io-worker', str(args.worker), '--address', '198.18.0.2/24', '--port', 'net_tap0',
            '--eal', eal, '--stats', str(stats), '--', str(args.app), *(['native'] if args.signal_boundary else [])], timeout=30)
        if result.returncode:
            return result.returncode
        record = json.loads(stats.read_text())
        if args.signal_boundary:
            if record['outstanding'] != 0 or 'native' not in record:
                raise RuntimeError('signal boundary cleanup failed')
            return 0
        if record['outstanding'] != 0 or record['native']['udp_in_datagrams'] < 20 or record['native']['udp_out_datagrams'] < 140 or record['native']['udp6_in_datagrams'] < 20 or record['native']['udp6_out_datagrams'] < 140:
            raise RuntimeError('native UDP/cleanup counters do not corroborate the matrix')
    return 0


if __name__ == '__main__':
    sys.exit(main())
