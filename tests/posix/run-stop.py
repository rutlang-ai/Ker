#!/usr/bin/env python3
"""Real native callback run/stop with independent host peers and reaped EAL workers."""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading


def require(value, message):
    if not value:
        raise RuntimeError(message)


def peer(sock, tcp, expected):
    sock.settimeout(20)
    if tcp:
        connection, _ = sock.accept()
        with connection:
            connection.settimeout(20)
            data = connection.recv(128)
            require(data == expected, 'TCP callback payload differs: ' + repr(data))
            connection.sendall(data)
            require(connection.recv(1) == b'', 'native run did not close its open TCP socket')
        return 'eof'
    data, address = sock.recvfrom(128)
    require(data == expected, 'UDP callback payload differs: ' + repr(data))
    sock.sendto(data, address)
    return 'udp'


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
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    targets = ['198.18.0.1', '198.19.0.1', '2001:db8:1::1', '2001:db8:2::1']
    for index in range(2):
        for command in (
                ['ip', 'link', 'add', f'runhost{index}', 'type', 'veth', 'peer', 'name', f'runlink{index}'],
                ['ip', 'addr', 'add', f'198.{18 + index}.0.1/24', 'dev', f'runhost{index}'],
                ['ip', '-6', 'addr', 'add', f'2001:db8:{index + 1}::1/64', 'dev', f'runhost{index}', 'nodad'],
                ['ip', 'link', 'set', f'runhost{index}', 'up'], ['ip', 'link', 'set', f'runlink{index}', 'up']):
            subprocess.run(command, check=True)
    cpu = min(os.sched_getaffinity(0))
    with tempfile.TemporaryDirectory(prefix='ker-run-stop-') as directory:
        root = Path(directory)
        wrapper = root / 'ker-io-worker'
        (root / 'ker-app').symlink_to(args.worker.parent / 'ker-app')
        for phase, mode in enumerate(('oneshot', 'repeat', 'external', 'null', 'worker-failure')):
            port = 41000 + phase
            pids, stats, config = root / (mode + '.pids'), root / (mode + '.json'), root / (mode + '.ini')
            wrapper.write_text('#!' + sys.executable + '\nimport os, subprocess, sys\n'
                f'with open({str(pids)!r}, "a") as output: output.write(str(os.getpid()) + "\\n")\n'
                + (f'result = subprocess.run([{str(args.worker)!r}, *sys.argv[1:]], close_fds=False)\n'
                   'raise SystemExit(result.returncode or 9)\n' if mode == 'worker-failure' else
                   f'os.execv({str(args.worker)!r}, [{str(args.worker)!r}, *sys.argv[1:]])\n'))
            wrapper.chmod(0o755)
            eal = f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry --iova-mode=va -m 64'
            config.write_text('[network]\naddress=198.18.0.2/24\naddress6=2001:db8:1::2/64\nmax_mtu=1500\n'
                '[dpdk]\nqueues=2\nport=net_tap0\n'
                f'eal={eal} --vdev=net_tap0,iface=runpeer0,remote=runlink0\n'
                '[interface.aux]\naddress=198.19.0.2/24\naddress6=2001:db8:2::2/64\nport=net_tap0\n'
                f'eal={eal} --vdev=net_tap0,iface=runpeer1,remote=runlink1\n')
            sockets, futures = [], []
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
                    for index, target in enumerate(targets):
                        family = socket.AF_INET if index < 2 else socket.AF_INET6
                        for tcp in (False, True):
                            sock = socket.socket(family, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM)
                            sockets.append(sock)
                            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                            sock.bind((target, port))
                            if tcp:
                                sock.listen()
                            payload = f'run-stop-family{index}-protocol{int(tcp)}'.encode()
                            futures.append(executor.submit(peer, sock, tcp, payload))
                    result = subprocess.run([sys.executable, str(args.launcher), '--config', str(config),
                        '--library', str(args.library), '--io-worker', str(wrapper), '--stats', str(stats),
                        '--', str(args.app), mode, str(port), str(pids)], capture_output=True, text=True, timeout=35)
                    require(result.returncode == (125 if mode == 'worker-failure' else 0),
                            mode + ': launcher failed: ' + result.stdout + result.stderr)
                    require('PASS: ' + mode in result.stdout, 'missing native post-return evidence: ' + result.stdout)
                    outcomes = [future.result(timeout=3) for future in futures]
                    require(outcomes.count('eof') == 4 and outcomes.count('udp') == 4, 'missing independent peer evidence')
                    record = json.loads(stats.read_text())
                    require(record['run_shutdown'] and record['run_shutdown_workers'] == 2 and
                            record['run_shutdown_ack'] == (mode != 'worker-failure'), 'wrong supervisor ack: ' + str(record))
                    require(record['outstanding'] == 0 and len(record['interfaces']) == 1 and
                            record['interfaces'][0]['outstanding'] == 0, 'run returned with owned buffers')
                    require(record['io']['queues'] == 2 and record['interfaces'][0]['io']['queues'] == 2,
                            'two real queue pairs per interface were not configured')
                    require(all(record['native'][key] >= 2 for key in
                            ('udp_in_datagrams', 'udp_out_datagrams', 'udp6_in_datagrams', 'udp6_out_datagrams')),
                            'UDP bypassed the original Linux counters')
                    require(record['native']['active_opens'] >= 4 and record['tx'] and record['rx'] and
                            record['interfaces'][0]['tx'] and record['interfaces'][0]['rx'], 'missing actual original Linux/DPDK traffic')
                    for pid in map(int, pids.read_text().splitlines()):
                        require(not Path('/proc', str(pid)).exists(), 'worker survived acknowledged teardown')
                    print(result.stdout.strip(), flush=True)
                    print('PASS: host observed four TCP EOFs; all native/DPDK resources released; ' + mode, flush=True)
            finally:
                for sock in sockets:
                    sock.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
