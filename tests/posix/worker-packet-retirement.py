#!/usr/bin/env python3
"""Packet-channel retirement must not retire the independent control owner."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import time


def run(args):
    helper = Path(__file__).with_name('native-nginx-companion-tap.py')
    spec = importlib.util.spec_from_file_location('worker_retirement_tap', helper)
    tap = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tap)
    tap.set_up_network()
    app, packet = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    control_read, control_write = os.pipe()
    cpu = min(os.sched_getaffinity(0))
    command = [str(args.worker), '--packet-fd', str(packet.fileno()),
        '--control-fd', str(control_read), '--port', 'net_tap0', '--no-numa',
        '--no-promiscuous', '--', f'--lcores=0@{cpu}', '--no-huge', '--no-pci',
        '--no-shconf', '--no-telemetry', '--iova-mode=va', '-m', '64', '-d',
        str(args.dpdk_plugin_dir / 'librte_net_tap.so'),
        '--vdev=net_tap0,iface=kerpeer,remote=kerlink']
    process = subprocess.Popen(command, pass_fds=(packet.fileno(), control_read),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    packet.close()
    os.close(control_read)
    try:
        readable, _, _ = select.select([process.stdout], [], [], 20)
        if not readable:
            raise RuntimeError('worker did not become ready')
        line = process.stdout.readline()
        if not line.startswith(b'KER_IO_READY '):
            raise RuntimeError(f'worker startup failed: {line!r}')
        ready = json.loads(line.split(b' ', 1)[1])
        frame = bytes.fromhex(ready['mac'].replace(':', '')) + bytes.fromhex(
            '02000000000188b5') + bytes(46)
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as wire:
            wire.bind(('kerhost', 0))
            wire.send(frame)
            app.settimeout(5)
            received = app.recv(65535)
            if not received.endswith(frame):
                raise RuntimeError('real TAP RX did not reach the packet channel')
            app.close()
            # Continue real RX after retirement, beyond the worker drain bound.
            deadline = time.monotonic() + .75
            while time.monotonic() < deadline:
                wire.send(frame)
                if process.poll() is not None:
                    raise RuntimeError('packet retirement prematurely retired the control owner')
                time.sleep(.005)
        if args.control_eof:
            os.close(control_write)
            control_write = None
        else:
            os.write(control_write, b'S')
        stdout, stderr = process.communicate(timeout=10)
        if process.returncode:
            raise RuntimeError(f'worker stop failed: {stderr.decode(errors="replace")}')
        stats = [json.loads(line.split(b' ', 1)[1]) for line in stdout.splitlines()
            if line.startswith(b'KER_IO_DONE ')]
        if (len(stats) != 1 or stats[0]['stop_requests'] != (0 if args.control_eof else 1) or
                stats[0]['control_eof'] != args.control_eof or
                stats[0]['outstanding'] != 0 or stats[0]['rx_shutdown_discarded'] < 1):
            raise RuntimeError(f'missing explicit control retirement evidence: {stdout!r}')
        print('WORKER_PACKET_RETIREMENT_OK ' + json.dumps(stats[0], sort_keys=True))
    finally:
        app.close()
        if control_write is not None:
            os.close(control_write)
        if process.poll() is None:
            process.kill()
            process.communicate()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', type=Path, required=True)
    parser.add_argument('--dpdk-plugin-dir', type=Path, required=True)
    parser.add_argument('--inside', action='store_true')
    parser.add_argument('--control-eof', action='store_true')
    args = parser.parse_args()
    if args.inside:
        run(args)
    else:
        raise SystemExit(subprocess.run(['unshare', '-Urn', sys.executable,
            str(Path(__file__).resolve()), '--inside', '--worker', str(args.worker.resolve()),
            '--dpdk-plugin-dir', str(args.dpdk_plugin_dir.resolve()),
            *(['--control-eof'] if args.control_eof else [])]).returncode)
