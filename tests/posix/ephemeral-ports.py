#!/usr/bin/env python3
"""Qualify private original-Linux port policy and independent DPDK traffic."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile


def require(value, message):
    if not value:
        raise RuntimeError(message)


def source_port(address, low, high, reserved):
    require(address[0] == '198.18.0.2', f'wrong native source: {address}')
    require(low <= address[1] <= high and address[1] != reserved,
            f'port range/reservation bypassed: {address}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('launcher', 'library', 'worker', 'app'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--per-socket', action='store_true')
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    for name in ('launcher', 'library', 'worker', 'app'):
        require(getattr(args, name).is_file(), 'missing test artifact: ' + str(getattr(args, name)))
    if not args.inside:
        command = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()), '--inside']
        for name in ('launcher', 'library', 'worker', 'app'):
            command += ['--' + name, str(getattr(args, name).resolve())]
        if args.per_socket:
            command.append('--per-socket')
        return subprocess.run(command).returncode
    # Host IPv6 is unnecessary: native IPv6 allocation uses its own loopback.
    for scope in ('all', 'default'):
        Path('/proc/sys/net/ipv6/conf/' + scope + '/disable_ipv6').write_text('1\n')
    for command in (['ip', 'link', 'add', 'kerhost', 'type', 'veth', 'peer', 'name', 'kerlink'],
                    ['ip', 'addr', 'add', '198.18.0.1/24', 'dev', 'kerhost'],
                    ['ip', 'link', 'set', 'kerhost', 'up'], ['ip', 'link', 'set', 'kerlink', 'up']):
        subprocess.run(command, check=True)
    host_files = [Path('/proc/sys/net/ipv4') / name for name in
                  ('ip_local_port_range', 'ip_local_reserved_ports', 'ip_unprivileged_port_start')]
    original = [p.read_text() for p in host_files]
    cpu = min(os.sched_getaffinity(0))
    eal = (f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry '
           '--iova-mode=va -m 64 --vdev=net_tap0,iface=kerpeer,remote=kerlink')
    command = [sys.executable, str(args.launcher), '--library', str(args.library),
        '--io-worker', str(args.worker), '--address', '198.18.0.2/24', '--port', 'net_tap0', '--eal', eal]
    cases = [('default', '', [], 32768, 60999, 0),
        ('ini', '[network]\nephemeral_ports=40000-40007\n', [], 40000, 40007, 0),
        ('override', '[network]\nephemeral_ports=40000-40007\n',
         ['--ephemeral-ports', '41000-41007'], 41000, 41007, 0),
        ('reserved', '[network]\nephemeral_ports=40000-40007\n',
         ['--sysctl', 'net.ipv4.ip_local_reserved_ports=40000'], 40000, 40007, 40000),
        ('minimum', '', ['--ephemeral-ports', '1024-1024'], 1024, 1024, 0),
        ('maximum', '', ['--ephemeral-ports', '65535-65535'], 65535, 65535, 0),
        ('generic-raised-boundary',
         '[sysctl]\nnet.ipv4.ip_unprivileged_port_start=1024\n'
         'net.ipv4.ip_local_port_range=40000 40007\n',
         ['--sysctl', 'net.ipv4.ip_local_port_range=50000 50007',
          '--sysctl', 'net.ipv4.ip_unprivileged_port_start=50000'], 50000, 50007, 0)]
    if args.per_socket:
        cases = [('socket-ini', '[network]\nephemeral_ports=40000-40015\n', [], 40000, 40015, 0),
            ('socket-override', '[network]\nephemeral_ports=40000-40015\n',
             ['--ephemeral-ports', '41000-41015'], 41000, 41015, 0)]
    with tempfile.TemporaryDirectory(prefix='ker-ephemeral-') as directory:
        root = Path(directory)
        for index, (name, text, options, low, high, reserved) in enumerate(cases):
            config, stats = root / (name + '.ini'), root / (name + '.json')
            config.write_text(text)
            port = 28350 + index * 2
            with socket.socket() as listener, socket.socket(type=socket.SOCK_DGRAM) as udp, (root / (name + '.log')).open('w+') as log:
                listener.bind(('198.18.0.1', port)); listener.listen(1); listener.settimeout(20)
                udp.bind(('198.18.0.1', port + 1)); udp.settimeout(10)
                # An inherited internal environment value must never override the CLI/INI.
                environment = dict(os.environ, KER_NATIVE_SYSCTLS='net.ipv4.ip_local_port_range=43000 43007')
                process = subprocess.Popen([*command, '--config', str(config), *options,
                    '--stats', str(stats), '--', str(args.app), str(low), str(high), str(reserved), str(port),
                    *(["socket-ranges"] if args.per_socket else [])],
                    env=environment, stdout=log, stderr=log, text=True)
                try:
                    peer, address = listener.accept()
                    source_port(address, low + 8 if args.per_socket else low, low + 11 if args.per_socket else high, reserved)
                    with peer:
                        peer.settimeout(8)
                        payload = b''
                        while len(payload) < 16:
                            part = peer.recv(16 - len(payload)); require(part, 'short TCP payload')
                            payload += part
                        require(payload == b'ephemeral-ports\0', 'TCP payload differs')
                        peer.sendall(payload)
                    payload, address = udp.recvfrom(1024)
                    source_port(address, low + 8 if args.per_socket else low, low + 11 if args.per_socket else high, reserved)
                    require(payload == b'ephemeral-ports\0', 'UDP payload differs')
                    require(udp.sendto(payload, address) == len(payload), 'UDP echo short')
                    require(process.wait(timeout=20) == 0, name + ': application failed')
                    log.flush(); log.seek(0); output = log.read()
                    require(output.count('PASS:') == 6, name + ': missing allocation/traffic checks: ' + output)
                    record = json.loads(stats.read_text())
                    require(record['tx'] > 0 and record['rx'] > 0 and record['outstanding'] == 0,
                            name + ': missing actual DPDK traffic or leaked buffers')
                    require(record['native']['active_opens'] >= 1, 'TCP bypassed original Linux')
                    require(record['native']['udp_in_datagrams'] >= 1 and
                            record['native']['udp_out_datagrams'] >= 1, 'UDP bypassed original Linux')
                    require([p.read_text() for p in host_files] == original, 'host port policy changed')
                    print('PASS: ' + name + ' original Linux IPv4/IPv6 allocation and independent TCP/UDP traffic', flush=True)
                except Exception:
                    log.flush(); log.seek(0); print(log.read(), file=sys.stderr)
                    raise
                finally:
                    if process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            process.kill(); process.wait()
    return 0


if __name__ == '__main__':
    sys.exit(main())
