#!/usr/bin/env python3
"""Qualify deferred native TCP binding with a single available source port."""
import argparse
from contextlib import ExitStack
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


def exercise(command, source, directory, name):
    with ExitStack() as stack:
        listeners = []
        for port in range(28600, 28603):
            listener = stack.enter_context(socket.socket())
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(('198.18.0.1', port)); listener.listen(1); listener.settimeout(20)
            listeners.append(listener)
        log = stack.enter_context((directory / (name + '.log')).open('w+'))
        process = subprocess.Popen(command + [source, '198.18.0.1', '28600'],
                                   stdout=log, stderr=log, text=True)
        try:
            peers = []
            for listener in listeners:
                peer, address = listener.accept()
                stack.enter_context(peer); peer.settimeout(8)
                require(address == (source, 40000), 'wrong source tuple: ' + str(address))
                peers.append(peer)
            require(len(peers) == 3, 'missing simultaneous connections')
            for index, peer in enumerate(peers):
                expected = bytes(index * 31 + offset for offset in range(16))
                payload = b''
                while len(payload) < 16:
                    part = peer.recv(16 - len(payload)); require(part, 'short payload')
                    payload += part
                require(payload == expected, 'payload mismatch')
                peer.sendall(payload)
                require(peer.recv(1) == b'', 'missing application FIN')
                peer.shutdown(socket.SHUT_WR)
            require(process.wait(timeout=10) == 0, name + ' application failed')
            log.flush(); log.seek(0); require('PASS:' in log.read(), 'missing application evidence')
            print('PASS: ' + name + ' three simultaneous source-port40000 tuples and exact traffic', flush=True)
        except Exception:
            log.flush(); log.seek(0); print(log.read(), file=sys.stderr)
            raise
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('launcher', 'library', 'worker', 'app'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    for name in ('launcher', 'library', 'worker', 'app'):
        require(getattr(args, name).is_file(), 'missing artifact: ' + str(getattr(args, name)))
    if not args.inside:
        command = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()), '--inside']
        for name in ('launcher', 'library', 'worker', 'app'):
            command += ['--' + name, str(getattr(args, name).resolve())]
        return subprocess.run(command).returncode
    for scope in ('all', 'default'):
        Path('/proc/sys/net/ipv6/conf/' + scope + '/disable_ipv6').write_text('1\n')
    for command in (['ip', 'link', 'set', 'lo', 'up'],
                    ['ip', 'link', 'add', 'kerhost', 'type', 'veth', 'peer', 'name', 'kerlink'],
                    ['ip', 'addr', 'add', '198.18.0.1/24', 'dev', 'kerhost'],
                    ['ip', 'link', 'set', 'kerhost', 'up'], ['ip', 'link', 'set', 'kerlink', 'up']):
        subprocess.run(command, check=True)
    range_file = Path('/proc/sys/net/ipv4/ip_local_port_range')
    reserved_file = Path('/proc/sys/net/ipv4/ip_local_reserved_ports')
    originals = range_file.read_text(), reserved_file.read_text()
    with tempfile.TemporaryDirectory(prefix='ker-no-port-') as directory:
        work = Path(directory)
        try:
            range_file.write_text('40000 40000\n'); reserved_file.write_text('\n')
            exercise([str(args.app)], '198.18.0.1', work, 'host-reference')
        finally:
            range_file.write_text(originals[0]); reserved_file.write_text(originals[1])
        cpu = min(os.sched_getaffinity(0))
        eal = (f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry '
               '--iova-mode=va -m 64 --vdev=net_tap0,iface=kerpeer,remote=kerlink')
        stats = work / 'native.json'
        native = [sys.executable, str(args.launcher), '--library', str(args.library),
                  '--io-worker', str(args.worker), '--address', '198.18.0.2/24',
                  '--port', 'net_tap0', '--eal', eal, '--ephemeral-ports', '40000-40000',
                  '--stats', str(stats), '--', str(args.app)]
        exercise(native, '198.18.0.2', work, 'native')
        record = json.loads(stats.read_text())
        require(record['native']['active_opens'] >= 3, 'missing original Linux opens')
        require(record['tx'] and record['rx'] and record['outstanding'] == 0, 'missing traffic or leaked buffers')
        require((range_file.read_text(), reserved_file.read_text()) == originals, 'host policy changed')
        print('PASS: native single-port deferred bind and unchanged host policy, zero outstanding', flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
