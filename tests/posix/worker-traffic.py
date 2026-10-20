#!/usr/bin/env python3
"""Measure actual net_tap worker packet/byte counters and stop lifecycle."""
import argparse
import json
import os
from pathlib import Path
import selectors
import socket
import subprocess
import sys
import tempfile
import time

HEADER = bytes(12)  # Fixed virtio-net v1 header from packet-channel.h.
COUNTERS = ('tx', 'rx', 'tx_bytes', 'rx_bytes', 'tx_dropped', 'rx_dropped',
            'dropped', 'tx_retries', 'rx_retries', 'outstanding')


def require(value, message):
    if not value:
        raise RuntimeError(message)


def frame(destination, source, ethertype, length, seed):
    return (destination + source + ethertype.to_bytes(2, 'big') +
            bytes((seed + i) % 256 for i in range(length - 14)))


def run_worker(worker, work, traffic):
    app, channel = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    app.settimeout(5)
    control_read, control_write = os.pipe()
    cpu = min(os.sched_getaffinity(0))
    eal = [f'--lcores=0@{cpu}', '--no-huge', '--no-pci', '--no-shconf',
           '--no-telemetry', '--iova-mode=va', '-m', '64',
           '--vdev=net_tap0,iface=kerpeer,remote=kerlink']
    process = None
    with (work / ('traffic.log' if traffic else 'idle.log')).open('w+') as log:
        try:
            process = subprocess.Popen([str(worker), '--packet-fd', str(channel.fileno()),
                '--control-fd', str(control_read), '--port', 'net_tap0', '--', *eal],
                pass_fds=(channel.fileno(), control_read), stdout=subprocess.PIPE,
                stderr=log, text=True)
            channel.close(); os.close(control_read); control_read = -1
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                require(selector.select(20), 'worker READY timeout')
            line = process.stdout.readline()
            require(line.startswith('KER_IO_READY '), 'worker startup: ' + line)
            ready = json.loads(line.split(' ', 1)[1])
            if traffic:
                host_info = json.loads(subprocess.check_output(['ip', '-j', 'link', 'show', 'dev', 'kerhost']))
                host_mac = bytes.fromhex(host_info[0]['address'].replace(':', ''))
                worker_mac = bytes.fromhex(ready['mac'].replace(':', ''))
                with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as peer:
                    peer.bind(('kerhost', 0)); peer.settimeout(5)
                    # Host -> PMD -> native packet channel, exact full Ethernet bytes.
                    for index, length in enumerate((60, 127, 1514)):
                        packet = frame(worker_mac, host_mac, 0x88b5, length, index)
                        require(peer.send(packet) == length, 'short host send')
                        received = app.recv(16384)
                        require(received[:12] == HEADER and len(received) == 12 + length,
                                'invalid RX channel framing')
                        require(received[12:] == packet, 'RX bytes changed')
                    # Native packet channel -> PMD -> independent host interface.
                    for index, length in enumerate((60, 127, 1514)):
                        packet = frame(host_mac, worker_mac, 0x88b6, length, index + 10)
                        require(app.send(HEADER + packet) == 12 + length, 'short channel send')
                        deadline = time.monotonic() + 5
                        while True:
                            received = peer.recv(16384)
                            if received == packet:
                                break
                            require(time.monotonic() < deadline, 'TX bytes not observed at host')
                # Rejected native frame lengths must affect only TX drops.
                app.send(b'x')
                app.send(HEADER + bytes(1515))
            else:
                # No native producer, no host addresses, IPv6 disabled in this namespace.
                time.sleep(0.02)
            # Repeated stop requests use the real control channel. Closing it
            # also exercises EOF during the drain, without sending any signals.
            os.write(control_write, b'xx')
            os.close(control_write); control_write = -1
            output, _ = process.communicate(timeout=10)
            log.flush(); log.seek(0); errors = log.read()
            require(process.returncode == 0, f'worker status={process.returncode}: {errors}')
            lines = [line for line in output.splitlines() if line.startswith('KER_IO_DONE ')]
            require(len(lines) == 1, 'expected one DONE snapshot: ' + output)
            stats = json.loads(lines[0].split(' ', 1)[1])
            require(set(COUNTERS) <= stats.keys(), 'missing traffic counter')
            require(stats['stop_requests'] == 2, 'worker did not consume both stop requests')
            require(stats['control_eof'] is True, 'worker did not observe control EOF')
            expected = dict.fromkeys(COUNTERS, 0)
            if traffic:
                expected.update(tx=3, rx=3, tx_bytes=1701, rx_bytes=1701, tx_dropped=2, dropped=2)
            for name, value in expected.items():
                # Retries are scheduling-dependent; they must not inflate packet/byte totals.
                if traffic and name in ('tx_retries', 'rx_retries'):
                    require(isinstance(stats[name], int) and stats[name] >= 0, 'invalid retry counter')
                else:
                    require(stats[name] == value, f'{name}: {stats[name]} != {value}; {stats}')
            print(('traffic' if traffic else 'idle') + ': ' + json.dumps(stats), flush=True)
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()
            channel.close(); app.close()
            if control_read >= 0:
                os.close(control_read)
            if control_write >= 0:
                os.close(control_write)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', type=Path, required=True)
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    if not args.inside:
        return subprocess.run(['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()),
            '--inside', '--worker', str(args.worker.resolve())]).returncode
    # Private test namespace only: eliminate unsolicited IPv6 link traffic.
    for scope in ('all', 'default'):
        Path('/proc/sys/net/ipv6/conf/' + scope + '/disable_ipv6').write_text('1\n')
    for command in (['ip', 'link', 'add', 'kerhost', 'type', 'veth', 'peer', 'name', 'kerlink'],
                    ['ip', 'link', 'set', 'kerhost', 'up'], ['ip', 'link', 'set', 'kerlink', 'up']):
        subprocess.run(command, check=True)
    with tempfile.TemporaryDirectory(prefix='ker-worker-traffic-') as directory:
        work = Path(directory)
        run_worker(args.worker, work, False)
        run_worker(args.worker, work, True)
    print('PASS: actual DPDK idle/traffic snapshots, frame bytes, directional drops and repeated stop', flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
