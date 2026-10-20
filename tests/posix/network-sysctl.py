#!/usr/bin/env python3
"""Apply Linux network sysctls before application startup, using real DPDK and sockets."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('launcher', 'library', 'worker', 'app', 'probe'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    if not args.inside:
        command = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()), '--inside']
        for name in ('launcher', 'library', 'worker', 'app', 'probe'):
            command += ['--' + name, str(getattr(args, name).resolve())]
        return subprocess.run(command).returncode
    for scope in ('all', 'default'):
        Path('/proc/sys/net/ipv6/conf/' + scope + '/disable_ipv6').write_text('1\n')
    for command in (['ip', 'link', 'add', 'kerhost', 'type', 'veth', 'peer', 'name', 'kerlink'],
                    ['ip', 'link', 'set', 'kerhost', 'up'], ['ip', 'link', 'set', 'kerlink', 'up']):
        subprocess.run(command, check=True)
    cpu = min(os.sched_getaffinity(0))
    eal = (f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry '
           '--iova-mode=va -m 64 --vdev=net_tap0,iface=kerpeer,remote=kerlink')
    launcher = [sys.executable, str(args.launcher), '--library', str(args.library),
                '--io-worker', str(args.worker), '--address', '198.18.0.2/24',
                '--port', 'net_tap0', '--eal', eal]
    environment = os.environ.copy()
    environment['LD_PRELOAD'] = str(args.probe) + ' ' + environment.get('LD_PRELOAD', '')
    with tempfile.TemporaryDirectory(prefix='ker-network-sysctl-') as directory:
        root = Path(directory)
        config = root / 'sysctl.ini'
        config.write_text('[sysctl]\nnet.ipv4.ip_default_ttl=65\n'
            'net.ipv4.tcp_keepalive_time=42\nnet.ipv4.tcp_keepalive_intvl=7\n'
            'net.ipv4.tcp_keepalive_probes=4\nnet.ipv4.tcp_syn_retries=3\n')
        launcher += ['--config', str(config)]
        empty = root / 'empty.ini'
        empty.write_text('')
        host_paths = [Path('/proc/sys/net/ipv4') / name for name in
            ('ip_default_ttl', 'tcp_keepalive_time', 'tcp_keepalive_intvl',
             'tcp_keepalive_probes', 'tcp_syn_retries')]
        host_before = [path.read_text() for path in host_paths]
        # The launcher must discard this inherited internal override.
        environment['KER_NATIVE_SYSCTLS'] = 'net.ipv4.ip_default_ttl=99'
        cases = [
            ('omitted', ['--config', str(empty)], 0,
             'PASS: five native network sysctls effective', 64),
            ('ini', [], 0, 'PASS: five native network sysctls effective', 65),
            ('override', ['--sysctl', 'net.ipv4.ip_default_ttl=66'], 0,
             'PASS: five native network sysctls effective', 66),
            ('unknown', ['--sysctl', 'net.ipv4.ker_no_such_sysctl=1'], 125,
             '/proc/sys/net/ipv4/ker_no_such_sysctl', 65),
            ('invalid-value', ['--sysctl', 'net.ipv4.ip_default_ttl=0'], 125,
             '/proc/sys/net/ipv4/ip_default_ttl', 65),
        ]
        for name, options, expected, diagnostic, ttl in cases:
            marker, stats, cleanup = [root / (name + suffix) for suffix in ('.app', '.json', '.cleanup')]
            env = environment.copy()
            env['KER_TEST_STARTUP_CLEANUP'] = str(cleanup)
            env.pop('KER_TEST_STARTUP_FAILURE', None)
            result = subprocess.run([*launcher, *options, '--stats', str(stats), '--',
                                     str(args.app), str(ttl), str(marker), str(int(name == 'omitted'))], env=env,
                                    capture_output=True, text=True, timeout=40)
            require(result.returncode == expected, f'{name}: status={result.returncode} {result.stderr}')
            require(diagnostic in result.stdout + result.stderr, f'{name}: missing diagnostic {result.stderr}')
            require(marker.exists() == (expected == 0), f'{name}: application execution out of order')
            require(cleanup.is_file() and cleanup.read_text().strip() == '0',
                    f'{name}: actual EAL cleanup missing or failed')
            require(stats.is_file(), f'{name}: worker cleanup snapshot lost')
            record = json.loads(stats.read_text())
            require(record['outstanding'] == 0, f'{name}: worker leaked mbufs: {record}')
            if expected != 0:
                require('application did not initialize the native Linux backend' in result.stderr,
                        f'{name}: failed native startup unexpectedly sent READY')
            require(record['io']['port_count'] == 1, f'{name}: EAL did not initialize')
            require(('native' in record) == (expected == 0),
                    f'{name}: failed native initialization was acknowledged as ready')
            require([path.read_text() for path in host_paths] == host_before,
                    f'{name}: host sysctls changed')
            print('PASS: ' + name + ' startup order, application marker and worker/EAL cleanup', flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
