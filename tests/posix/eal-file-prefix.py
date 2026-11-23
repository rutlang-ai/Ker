#!/usr/bin/env python3
"""EAL runtime file-prefix namespaces and live primary exclusion with native host TCP/UDP traffic."""
import argparse
import json
import os
from pathlib import Path
import selectors
import socket
import subprocess
import sys
import tempfile

PAYLOAD = b'native-mac-only\0'


def require(value, message):
    if not value:
        raise RuntimeError(message)


def ip(*args):
    subprocess.run(['ip', *args], check=True)


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
    ip('link', 'set', 'lo', 'up')
    ip('link', 'add', 'kerhost', 'type', 'veth', 'peer', 'name', 'kerlink')
    ip('addr', 'add', '198.18.0.1/24', 'dev', 'kerhost')
    for name in ('kerhost', 'kerlink'):
        ip('link', 'set', name, 'up')
    cpu = min(os.sched_getaffinity(0))
    eal = f'--lcores=0@{cpu} --no-pci --no-telemetry --proc-type=primary -m 64 --no-huge --iova-mode=va --vdev=net_tap0,iface=kerpeer,remote=kerlink'
    profiles = (('raw', '', [], ' --file-prefix=ker-raw', 'ker-raw'),
                ('auto', '', [], ' --file-prefix=ker-auto', 'ker-auto'),
                ('cli-primary-override', '[dpdk]\neal=--proc-type=secondary\n', [],
                    ' --file-prefix=ker-cli-primary', 'ker-cli-primary'),
                ('ini', '[dpdk]\nfile_prefix=mytest\n', [], '', 'mytest'),
                ('cli', '[dpdk]\nfile_prefix=unused-ini\n', ['--file-prefix', 'cli.override-1'], '', 'cli.override-1'),
                ('cli-before-terminator', '', ['--file-prefix', 'typed-before-terminator'],
                    ' -- --file-prefix=ignored-suffix -- --file-prefix=ignored-later',
                    'typed-before-terminator'))
    with tempfile.TemporaryDirectory(prefix='ker-eal-prefix-') as directory:
        root = Path(directory)
        # The source case named test_ipfw_pr_cfg_handler_isolated actually
        # supplies an invalid process type, not an IPFW firewall rule. Exercise
        # original EAL parsing through the real INI -> launcher -> worker path.
        worker_pid = root / 'invalid-worker.pid'
        wrapper = root / 'record-worker'
        wrapper.write_text('#!' + sys.executable + '\nimport os, sys\n'
            + 'from pathlib import Path\nPath(' + repr(str(worker_pid)) + ').write_text(str(os.getpid()))\n'
            + 'worker = ' + repr(str(args.worker.resolve())) + '\nos.execv(worker, [worker, *sys.argv[1:]])\n')
        wrapper.chmod(0o700)
        for process_arg in ('--proc-type=bogus_proc_type', '--proc-type bogus_proc_type'):
            config, stats = root / 'invalid.ini', root / 'invalid.json'
            marker = root / 'invalid-app-entered'
            config.write_text('[network]\naddress=198.18.0.2/24\n[dpdk]\nport=net_tap0\n'
                'exception_iface=invalidexcept\nexception_type=34997\nfile_prefix=ker-raw\n'
                + 'eal=' + eal.replace('--proc-type=primary', process_arg) + '\n')
            result = subprocess.run([sys.executable, str(args.launcher), '--config', str(config),
                '--library', str(args.library), '--io-worker', str(wrapper), '--stats', str(stats),
                '--', '/usr/bin/touch', str(marker)],
                env=dict(os.environ, RUNTIME_DIRECTORY=str(root)), capture_output=True, text=True, timeout=20)
            require(result.returncode == 125 and 'invalid process type: bogus_proc_type' in result.stderr
                    and 'ker EAL:' in result.stderr and 'DPDK worker failed before packet I/O became ready' in result.stderr,
                    'invalid process type did not fail in original EAL: ' + result.stdout + result.stderr)
            require(not marker.exists() and not stats.exists() and 'KER_IO_READY' not in result.stdout,
                    'invalid EAL process reached application entry or worker readiness')
            require(worker_pid.is_file(), 'real EAL worker was not executed')
            require(not Path('/proc/' + worker_pid.read_text()).exists(), 'failed EAL worker was not reaped')
            require(not (root / 'dpdk' / 'ker-raw').exists(), 'invalid process created an EAL runtime namespace')
            for iface in ('kerpeer', 'invalidexcept'):
                require(subprocess.run(['ip', 'link', 'show', iface], capture_output=True).returncode != 0,
                        'invalid EAL process created an interface: ' + iface)
            worker_pid.unlink()
        print('PASS: test_ipfw_pr_cfg_handler_isolated; original EAL rejected both invalid process-type forms before app/device setup', flush=True)
        for index, (name, ini, options, extra_eal, expected) in enumerate(profiles):
            config, stats = root / (name + '.ini'), root / (name + '.json')
            config.write_text(ini)
            port = 30300 + index
            profile_eal = eal.replace('--proc-type=primary', '--proc-type=auto') if name == 'auto' else eal
            command = [sys.executable, str(args.launcher), '--library', str(args.library),
                '--io-worker', str(args.worker), '--address', '198.18.0.2/24', '--port', 'net_tap0',
                '--eal', profile_eal + extra_eal, '--config', str(config), *options, '--stats', str(stats),
                '--', str(args.app), str(port)]
            with (root / (name + '.log')).open('w+') as log:
                app = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=log, text=True,
                    env=dict(os.environ, RUNTIME_DIRECTORY=str(root)))
                try:
                    with selectors.DefaultSelector() as selector:
                        selector.register(app.stdout, selectors.EVENT_READ)
                        require(selector.select(20), 'EAL namespace worker startup timeout')
                    require(app.stdout.readline().startswith('READY '), 'EAL namespace application not ready')
                    require((root / 'dpdk' / expected / 'config').is_file(),
                            'EAL did not create the selected shared configuration namespace')
                    if name == 'cli':
                        require(not (root / 'dpdk' / 'unused-ini').exists(), 'overridden INI namespace was used')
                    if name == 'raw':
                        # The first native app is still waiting for traffic. A duplicate
                        # primary must fail on the real EAL lock before creating a PMD.
                        duplicate_stats = root / 'duplicate.json'
                        duplicate = subprocess.run([sys.executable, str(args.launcher), '--library', str(args.library),
                            '--io-worker', str(args.worker), '--address', '198.19.0.2/24', '--port', 'net_tap1',
                            '--eal', f'--lcores=0@{cpu} --no-pci --no-huge --no-telemetry --proc-type=primary -m 64',
                            '--file-prefix', expected, '--stats', str(duplicate_stats), '--', '/bin/true'],
                            env=dict(os.environ, RUNTIME_DIRECTORY=str(root)), capture_output=True, text=True, timeout=15)
                        require(duplicate.returncode == 125 and 'Cannot create lock' in duplicate.stderr,
                                'same-prefix primary was not rejected by EAL lock: ' + duplicate.stderr)
                        require(not duplicate_stats.exists() and 'READY ' not in duplicate.stdout,
                                'duplicate primary reached readiness')
                        # Reject an explicit secondary before executing even a
                        # PID-recording exec wrapper, while a real same-prefix
                        # primary remains live and later completes TCP/UDP.
                        for mode in ('--proc-type=secondary', '--proc-type secondary'):
                            for auxiliary in (False, True):
                                secondary_config = root / 'secondary.ini'
                                secondary_stats = root / 'secondary.json'
                                marker = root / 'secondary-entered'
                                secondary_eal = f'--lcores=0@{cpu} --no-pci --no-huge --no-telemetry ' + mode
                                secondary_config.write_text('[interface.other]\naddress=198.20.0.2/24\n'
                                    'port=net_tap2\neal=' + secondary_eal + '\n' if auxiliary else '')
                                require(app.poll() is None, 'primary exited before secondary preflight')
                                rejected = subprocess.run([sys.executable, str(args.launcher),
                                    '--library', str(args.library), '--io-worker', str(wrapper),
                                    '--address', '198.19.0.2/24', '--port', 'net_tap1',
                                    '--eal', (secondary_eal if not auxiliary else
                                        f'--lcores=0@{cpu} --no-pci --no-huge --proc-type=primary'),
                                    '--file-prefix', expected, '--config', str(secondary_config),
                                    '--stats', str(secondary_stats), '--', '/bin/touch', str(marker)],
                                    env=dict(os.environ, RUNTIME_DIRECTORY=str(root)),
                                    capture_output=True, text=True, timeout=15)
                                require(rejected.returncode == 2 and
                                    'secondary EAL processes are unsupported' in rejected.stderr,
                                    'secondary was not rejected before EAL: ' + rejected.stdout + rejected.stderr)
                                require(not worker_pid.exists() and not marker.exists() and not secondary_stats.exists(),
                                    'secondary preflight executed worker/app or published stats')
                                require(app.poll() is None, 'secondary request terminated live primary')
                        print('PASS: explicit secondary main/aux modes rejected before worker exec; primary remains live', flush=True)
                        # A different prefix permits a second real EAL/native instance
                        # while the first stays live; use its own TAP and native subnet.
                        isolated_stats = root / 'isolated.json'
                        isolated = subprocess.run([sys.executable, str(args.launcher), '--library', str(args.library),
                            '--io-worker', str(args.worker), '--address', '198.19.0.2/24', '--port', 'net_tap1',
                            '--eal', f'--lcores=0@{cpu} --no-pci --no-huge --no-telemetry --proc-type=primary -m 64 --vdev=net_tap1,iface=kerisolated',
                            '--file-prefix', 'ker-independent', '--stats', str(isolated_stats), '--', '/bin/true'],
                            env=dict(os.environ, RUNTIME_DIRECTORY=str(root)), capture_output=True, text=True, timeout=15)
                        require(isolated.returncode == 0, 'distinct-prefix native instance failed: ' + isolated.stderr)
                        isolated_record = json.loads(isolated_stats.read_text())
                        require(isolated_record['outstanding'] == 0, 'distinct-prefix instance leaked packets')
                        require((root / 'dpdk' / 'ker-independent' / 'config').is_file(),
                                'distinct EAL namespace missing')
                        print('PASS: live same-prefix primary exclusion and distinct-prefix concurrent native lifecycle', flush=True)
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                        udp.settimeout(8); udp.connect(('198.18.0.2', port)); udp.send(PAYLOAD)
                        require(udp.recv(256) == PAYLOAD, 'EAL namespace worker did not receive/echo UDP')
                    with socket.socket(socket.AF_INET) as tcp:
                        tcp.settimeout(8); tcp.connect(('198.18.0.2', port)); tcp.sendall(PAYLOAD)
                        packet = b''
                        while len(packet) < len(PAYLOAD):
                            part = tcp.recv(len(PAYLOAD) - len(packet))
                            require(part, 'unexpected TCP EOF'); packet += part
                        require(packet == PAYLOAD, 'EAL namespace worker TCP payload changed')
                    output = app.communicate(timeout=20)[0]
                    require(app.returncode == 0 and 'PASS:' in output, 'EAL namespace native traffic failed')
                    record = json.loads(stats.read_text())
                    require(record['stop_requests'] or record['control_eof'], 'control shutdown not observed')
                    require(record['io']['process_type'] == 'primary', 'accepted EAL mode was not actually primary')
                    require(record['outstanding'] == 0 and record['native']['passive_opens'] == 1 and
                            record['native']['udp_in_datagrams'] == 1 and record['native']['udp_out_datagrams'] == 1,
                            'missing native traffic or packet cleanup')
                    print(f'PASS: {name}, actual runtime namespace={expected}, native TCP/UDP and clean shutdown', flush=True)
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
