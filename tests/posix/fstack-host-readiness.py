#!/usr/bin/env python3
"""Retained readiness helper on original Linux, plus an actual TCP/UDP caller."""
import argparse
import json
import os
from pathlib import Path
import selectors
import socket
import subprocess
import sys
import tempfile

from dpdk_runtime import private_runtime_environment

PAYLOAD = b'caller-readiness\0'


def require(value, message):
    if not value:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('launcher', 'library', 'worker', 'app', 'pmd-root'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--profile', choices=('source', 'consumer', 'fault', 'mmap-fatal', 'mmap-return'), required=True)
    parser.add_argument('--inside', action='store_true')
    parser.add_argument('--install-example-from', type=Path)
    parser.add_argument('--install-bindir', default='bin')
    args = parser.parse_args()
    if not args.inside:
        command = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()),
                   '--inside', '--profile', args.profile]
        for name in ('launcher', 'library', 'worker', 'app', 'pmd-root'):
            command += ['--' + name, str(getattr(args, name.replace('-', '_')).resolve())]
        if args.install_example_from:
            command += ['--install-example-from', str(args.install_example_from.resolve()),
                        '--install-bindir', args.install_bindir]
        return subprocess.run(command).returncode
    wire = args.profile == 'consumer'
    driver = 'net_tap' if wire else 'net_null'
    modules = list(args.pmd_root.glob('dpdk/pmds-*/librte_' + driver + '.so'))
    require(len(modules) == 1, 'one original ' + driver + ' PMD is required; no skip')
    if wire:
        def ip(*command):
            subprocess.run(['ip', *command], check=True)
        ip('link', 'set', 'lo', 'up')
        ip('link', 'add', 'kerhost', 'type', 'veth', 'peer', 'name', 'kerlink')
        ip('addr', 'add', '198.18.0.1/24', 'dev', 'kerhost')
        for name in ('kerhost', 'kerlink'):
            ip('link', 'set', name, 'up')
    cpu = min(os.sched_getaffinity(0))
    device = 'net_tap0,iface=kerpeer,remote=kerlink' if wire else 'net_null0,no-rx=1'
    eal = f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry --iova-mode=va -m 64 --vdev={device}'
    with tempfile.TemporaryDirectory(prefix='ker-host-readiness-') as directory:
        root = Path(directory)
        application = args.app
        if args.install_example_from:
            require(wire, 'installed profile requires the real TCP/UDP caller')
            require(not Path(args.install_bindir).is_absolute() and '..' not in Path(args.install_bindir).parts,
                    'installed profile requires a relative bindir')
            prefix = root / 'installed'
            subprocess.run(['cmake', '--install', str(args.install_example_from), '--prefix', str(prefix),
                            '--component', 'host-readiness-example'], check=True)
            application = prefix / args.install_bindir / args.app.name
            require(application.is_file(), 'caller example not installed')
            require(list(prefix.rglob('LICENSE')), 'upstream license not installed')
        environment = private_runtime_environment(root / 'dpdk')
        environment['LD_PRELOAD'] = str(modules[0])
        environment['LD_LIBRARY_PATH'] = str(args.pmd_root) + ':' + environment.get('LD_LIBRARY_PATH', '')
        stats = root / 'stats.json'
        command = [sys.executable, str(args.launcher), '--library', str(args.library),
                   '--io-worker', str(args.worker), '--address', '198.18.0.2/24',
                   '--port', 'net_tap0' if wire else 'net_null0', '--eal', eal,
                   '--stats', str(stats), '--', str(application)]
        if wire:
            command += ['29912']
        with (root / 'stderr').open('w+') as log:
            app = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=log,
                                   env=environment, text=True)
            try:
                if wire:
                    with selectors.DefaultSelector() as selector:
                        selector.register(app.stdout, selectors.EVENT_READ)
                        require(selector.select(20), 'caller readiness startup timeout')
                    require(app.stdout.readline().startswith('READY '), 'caller not ready')
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                        udp.settimeout(8)
                        udp.sendto(PAYLOAD, ('198.18.0.2', 29912))
                        require(udp.recv(256) == PAYLOAD, 'UDP caller payload mismatch')
                    with socket.create_connection(('198.18.0.2', 29912), timeout=8) as tcp:
                        tcp.sendall(PAYLOAD)
                        response = b''
                        while len(response) < len(PAYLOAD):
                            part = tcp.recv(len(PAYLOAD) - len(response))
                            require(part, 'unexpected caller TCP EOF')
                            response += part
                        require(response == PAYLOAD, 'TCP caller payload mismatch')
                output = app.communicate(timeout=30)[0]
                log.flush(); log.seek(0); errors = log.read()
                if args.profile.startswith('mmap-'):
                    record = json.loads(stats.read_text())
                    expected_code = 1 if args.profile == 'mmap-fatal' else 3
                    require(app.returncode == expected_code
                            and 'NATIVE_MMAP_ERROR_RETURNED' in output
                            and 'HOST_MMAP_FATAL_ARMED' in output,
                            'missing real caller mmap exit evidence: ' + output + errors + str(record))
                    if args.profile == 'mmap-fatal':
                        require('fst mmap failed:' in errors and 'HOST_MMAP_FATAL_RETURNED' not in output,
                                'original fatal mmap branch did not terminate the caller: ' + output + errors)
                    else:
                        require('HOST_MMAP_FATAL_RETURNED' in output and 'fst mmap failed:' not in errors,
                                'negative control did not distinguish a mere mmap error return')
                    require(record['outstanding'] == 0 and record['io']['driver'] == driver,
                            'caller exit leaked original PMD buffers')
                    print('PASS: real caller mmap ' + args.profile + '; exact app exit and zero PMD buffers')
                    return 0
                if args.profile == 'fault':
                    require(app.returncode != 0 and 'HOST_READINESS_MOD_FAULT' in errors
                            and '(triples[0]) == (app_fd2)' in errors,
                            'source assertion did not detect the real MOD failure: ' + output + errors)
                    require(json.loads(stats.read_text())['outstanding'] == 0,
                            'injected MOD failure leaked original PMD mbufs')
                    print('PASS: original remapped-tag assertion rejects injected MOD failure')
                    return 0
                require(app.returncode == 0, 'native readiness application failed: ' + output + errors)
                marker = ('PASS: native TCP/UDP consumed remapped readiness tags' if wire else
                          'HOST_SOURCE_CASE test_ff_host_kqueue_ctl_add_idempotent')
                require(output.count(marker) == 1, 'missing/duplicate acceptance marker: ' + output)
                record = json.loads(stats.read_text())
                require(record['run_shutdown'] and record['run_shutdown_ack'] and
                        record['outstanding'] == 0 and record['io']['driver'] == driver,
                        'native/PMD shutdown or ownership evidence missing: ' + str(record))
                native = record['native']
                require(native['passive_opens'] == (1 if wire else 5), 'original Linux TCP accept count mismatch')
                if wire:
                    require(output.count('HOST_MAPPING_BUFFER_RECLAIMED') == 1,
                            'real caller mapped network buffer was not reclaimed')
                    require(native['udp_in_datagrams'] == native['udp_out_datagrams'] == 1,
                            'original Linux UDP exchange not observed')
                print('PASS: native host readiness ' + args.profile + '; original Linux and zero outstanding mbufs')
            except Exception:
                log.flush(); log.seek(0); print(log.read(), file=sys.stderr)
                raise
            finally:
                if app.poll() is None:
                    app.terminate()
                    try:
                        app.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        app.kill(); app.wait()
    return 0


if __name__ == '__main__':
    sys.exit(main())
