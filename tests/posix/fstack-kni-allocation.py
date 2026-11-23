#!/usr/bin/env python3
"""Named original KNI allocation failures and real kernel-vhost/TAP consumer."""
import argparse
import json
import os
from pathlib import Path
import queue
import resource
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from dpdk_runtime import private_runtime_environment


def require(value, message):
    if not value:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('app', 'pmd-root'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--profile', choices=('stats', 'slot', 'fatal-stats', 'fatal-slot', 'bypass', 'consumer', 'owner-bypass'), required=True)
    parser.add_argument('--inside', action='store_true')
    parser.add_argument('--install-example-from', type=Path)
    parser.add_argument('--install-bindir', default='bin')
    parser.add_argument('--install-libdir', default='lib')
    args = parser.parse_args()
    if not args.inside:
        command = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()), '--inside',
                   '--profile', args.profile, '--app', str(args.app.resolve()), '--pmd-root', str(args.pmd_root.resolve())]
        if args.install_example_from:
            command += ['--install-example-from', str(args.install_example_from.resolve()), '--install-bindir', args.install_bindir,
                        '--install-libdir', args.install_libdir]
        return subprocess.run(command).returncode
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    Path('/proc/sys/net/ipv6/conf/default/disable_ipv6').write_text('1')
    Path('/proc/sys/net/ipv6/conf/all/disable_ipv6').write_text('1')
    is_consumer = args.profile in ('consumer', 'owner-bypass')
    drivers = ('tap', 'virtio') if is_consumer else ('null',)
    modules = []
    for driver in drivers:
        found = list(args.pmd_root.glob('dpdk/pmds-*/librte_net_' + driver + '.so'))
        require(len(found) == 1, 'exact original ' + driver + ' PMD required; no skip')
        modules += found
    with tempfile.TemporaryDirectory(prefix='ker-kni-') as directory:
        root = Path(directory); app = args.app
        env = private_runtime_environment(root / 'dpdk')
        if args.install_example_from:
            require(args.profile == 'consumer' and not Path(args.install_bindir).is_absolute()
                    and '..' not in Path(args.install_bindir).parts
                    and not Path(args.install_libdir).is_absolute()
                    and '..' not in Path(args.install_libdir).parts, 'invalid install profile')
            prefix = root / 'installed'
            subprocess.run(['cmake', '--install', str(args.install_example_from), '--prefix', str(prefix),
                            '--component', 'kni-host-example'], check=True)
            app = prefix / args.install_bindir / args.app.name
            licenses = list(prefix.rglob('LICENSE'))
            require(app.is_file() and len(licenses) == 1 and licenses[0].read_bytes() ==
                    (Path(__file__).resolve().parents[2] / 'third_party/fstack-kni-bridge/LICENSE').read_bytes(),
                    'actual caller/license not independently installed')
        if args.install_example_from:
            env['LD_LIBRARY_PATH'] = str(prefix / args.install_libdir) + ':' + env.get('LD_LIBRARY_PATH', '')
        env['LD_PRELOAD'] = ':'.join(map(str, modules))
        env['LD_LIBRARY_PATH'] = str(args.pmd_root) + ':' + env.get('LD_LIBRARY_PATH', '')
        if not is_consumer:
            result = subprocess.run([str(app), args.profile], env=env, cwd=root, capture_output=True, text=True, timeout=30)
            if args.profile == 'fatal-stats':
                require(result.returncode == 1 and 'REAL_KNI_EXIT stats_null=1 failed=1 hotplug=0' in result.stderr
                        and 'rte_zmalloc(1 (struct netio_kni_stat *)) failed' in result.stderr,
                        'original stats fatal path did not exit exactly1: ' + result.stdout + result.stderr)
            elif args.profile == 'fatal-slot':
                require(result.returncode == -signal.SIGABRT and 'REAL_KNI_PANIC slot_null=1 failed=1 hotplug=0' in result.stderr
                        and 'rte_zmalloc kni_interface_stats failed' in result.stderr,
                        'original slot fatal path did not SIGABRT: ' + result.stdout + result.stderr)
            elif args.profile == 'bypass':
                require(result.returncode == 1 and 'KNI_FAULT_BYPASS' in result.stderr
                        and 'check failed: expected_kni_fatal' in result.stderr and 'KNI_SOURCE_OOM' not in result.stdout,
                        'allocation-success mutation passed the source fatal expectation: ' + result.stdout + result.stderr)
            else:
                marker = 'KNI_SOURCE_OOM ' + args.profile + ' cycles=5 failed_once=true hotplug=0'
                require(result.returncode == 0 and result.stdout.count(marker) == 1,
                        'complete original OOM source assertions failed: ' + result.stdout + result.stderr)
            print('PASS: original KNI allocation ' + args.profile)
            return 0
        for device in ('/dev/net/tun', '/dev/vhost-net'):
            require(Path(device).is_char_device() and os.access(device, os.R_OK | os.W_OK), 'required device unavailable: ' + device)
        command = [str(app), '--lcores=0@' + str(min(os.sched_getaffinity(0))), '--no-huge', '--no-pci', '--no-shconf',
                   '--no-telemetry', '--iova-mode=va', '-m', '64', '--file-prefix=kni-' + str(os.getpid()),
                   '--vdev=net_tap0,iface=wire0']
        with (root / 'stderr').open('w+') as errors:
            child = subprocess.Popen(command, env=env, cwd=root, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=errors, text=True)
            lines, records = [], queue.Queue()
            def read_stdout():
                for line in child.stdout:
                    lines.append(line); records.put(line)
                records.put(None)
            reader = threading.Thread(target=read_stdout, daemon=True); reader.start()
            try:
                deadline = time.monotonic() + 20
                while True:
                    line = records.get(timeout=max(0.1, deadline - time.monotonic()))
                    require(line is not None, 'caller exited before ready')
                    if line.startswith('READY_KNI_HOST_BRIDGE '): break
                    require(time.monotonic() < deadline, 'caller readiness timed out')
                require(records.get(timeout=5) == 'OWNER_PENDING active=0 selected=1 attached=1\n',
                        'caller did not publish the pending KNI owner identity')
                for iface in ('wire0', 'veth0'):
                    subprocess.run(['ip', 'link', 'set', iface, 'up'], check=True)
                info = json.loads(subprocess.check_output(['ip', '-j', 'link', 'show', 'wire0'], text=True))[0]
                mac = bytes.fromhex(info['address'].replace(':', ''))
                def frame(tag):
                    return mac + bytes.fromhex('02000000009988b5') + bytes((i * 7 + tag) % 256 for i in range(114))
                def receive(sock, expected):
                    stop = time.monotonic() + 8
                    while time.monotonic() < stop:
                        sock.settimeout(max(0.1, stop - time.monotonic()))
                        data, address = sock.recvfrom(2048)
                        if address[2] == socket.PACKET_OUTGOING: continue
                        require(data == expected, 'original PMD/host frame bytes differ')
                        return
                    raise RuntimeError('actual host frame not received')
                with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x88b5)) as wire, \
                        socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x88b5)) as host:
                    wire.bind(('wire0', 0)); host.bind(('veth0', 0))
                    one, two = frame(0x31), frame(0x73)
                    require(wire.send(one) == len(one), 'wire injection failed')
                    if args.profile == 'owner-bypass':
                        receive(host, one)
                        require(child.poll() is None, 'mutated caller exited before control observation')
                        child.terminate(); child.wait(timeout=5); reader.join(timeout=3)
                        require('OWNER_ACTIVATED' not in ''.join(lines),
                                'owner-bypass control unexpectedly activated before transmitting')
                        print('PASS: bypass control demonstrates queued traffic escapes before KNI owner activation')
                        return 0
                    require(records.get(timeout=5) == 'OWNER_QUEUED pending=1 tx=0\n',
                            'pending frame was not observed in the original KNI ring before activation')
                    host.settimeout(0.3)
                    try:
                        host.recvfrom(2048)
                        require(False, 'future KNI owner transmitted before activation')
                    except TimeoutError:
                        pass
                    child.stdin.write('a'); child.stdin.flush()
                    require(records.get(timeout=5) == 'OWNER_ACTIVATED active=1 selected=1 attached=1\n',
                            'original reload owner activation was not observed')
                    receive(host, one)
                    require(host.send(two) == len(two), 'host injection failed'); receive(wire, two)
                child.stdin.write('x'); child.stdin.flush(); child.wait(timeout=15); reader.join(timeout=3)
                errors.flush(); errors.seek(0); diagnostic = errors.read()
                require(child.returncode == 0 and ''.join(lines).count('KNI_HOST_BRIDGE rx=1 tx=2 dropped=0 pool=2047 ports=0') == 1,
                        'original KNI caller/counters/cleanup failed: ' + ''.join(lines) + diagnostic)
                require(subprocess.run(['ip', 'link', 'show', 'veth0'], capture_output=True).returncode != 0 and
                        subprocess.run(['ip', 'link', 'show', 'wire0'], capture_output=True).returncode != 0,
                        'test-owned TAP interface survived cleanup')
                print('PASS: original KNI future-owner gate, reload activation, TAP/kernel-vhost virtio-user exact frames, live stats and pool2047')
            except Exception:
                errors.flush(); errors.seek(0); print(''.join(lines) + errors.read(), file=sys.stderr)
                raise
            finally:
                if child.poll() is None:
                    child.terminate()
                    try: child.wait(timeout=5)
                    except subprocess.TimeoutExpired: child.kill(); child.wait()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
