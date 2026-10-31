#!/usr/bin/env python3
"""Real native worker idle policy, host TCP/UDP wakeup and clean shutdown."""
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

PAYLOAD = b'native-mac-only\0'
MAX_IDLE_SLEEP_US = 100_000
IDLE_TIMEOUT_OBSERVATION_SECONDS = 5
IDLE_PROFILES = (('default', None, [], 1000), ('ini-20us', 20, [], 20),
    ('cli-busy', 100000, ['--idle-sleep-us', '0'], 0),
    ('ini-max', 100000, [], 100000),
    ('cli-max', 0, ['--idle-sleep-us', '100000'], 100000))


def require(value, message):
    if not value:
        raise RuntimeError(message)


def ip(*args):
    subprocess.run(['ip', *args], check=True)


def observe_idle_timeout(arm_fd, notify_fd, timeout=IDLE_TIMEOUT_OBSERVATION_SECONDS):
    with selectors.DefaultSelector() as selector:
        selector.register(notify_fd, selectors.EVENT_READ)
        if selector.select(0):
            raise RuntimeError('idle timeout notification arrived before application readiness')
        if os.write(arm_fd, b'A') != 1:
            raise RuntimeError('cannot arm idle timeout observation')
        if not selector.select(timeout):
            raise RuntimeError('worker did not complete an idle timeout after application readiness')
    if os.read(notify_fd, 1) != b'T':
        raise RuntimeError('invalid idle timeout notification')


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
    eal = f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry --iova-mode=va -m 64 --vdev=net_tap0,iface=kerpeer,remote=kerlink'
    profiles = IDLE_PROFILES
    with tempfile.TemporaryDirectory(prefix='ker-idle-wait-') as directory:
        root = Path(directory)
        environment = private_runtime_environment(root / 'dpdk')
        for index, (name, ini, options, expected) in enumerate(profiles):
            config, stats = root / (name + '.ini'), root / (name + '.json')
            config.write_text('' if ini is None else '[dpdk]\nidle_sleep=' + str(ini) + '\n')
            port = 29900 + index
            arm_read, arm_write = os.pipe()
            notify_read, notify_write = os.pipe()
            command = [sys.executable, str(args.launcher), '--library', str(args.library),
                '--io-worker', str(args.worker), '--address', '198.18.0.2/24', '--port', 'net_tap0',
                '--eal', eal, '--config', str(config), *options, '--stats', str(stats),
                '--test-idle-timeout-arm-fd', str(arm_read),
                '--test-idle-timeout-notify-fd', str(notify_write),
                '--', str(args.app), str(port)]
            with (root / (name + '.log')).open('w+') as log:
                app = None
                try:
                    app = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=log, text=True,
                        env=environment, pass_fds=(arm_read, notify_write))
                    os.close(arm_read); arm_read = -1
                    os.close(notify_write); notify_write = -1
                    with selectors.DefaultSelector() as selector:
                        selector.register(app.stdout, selectors.EVENT_READ)
                        require(selector.select(20), 'idle worker startup timeout')
                    require(app.stdout.readline().startswith('READY '), 'idle application not ready')
                    observe_idle_timeout(arm_write, notify_read)
                    os.close(arm_write); arm_write = -1
                    os.close(notify_read); notify_read = -1
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                        udp.settimeout(8); udp.connect(('198.18.0.2', port)); udp.send(PAYLOAD)
                        require(udp.recv(256) == PAYLOAD, 'idle worker did not receive/echo UDP')
                    with socket.socket(socket.AF_INET) as tcp:
                        tcp.settimeout(8); tcp.connect(('198.18.0.2', port)); tcp.sendall(PAYLOAD)
                        packet = b''
                        while len(packet) < len(PAYLOAD):
                            part = tcp.recv(len(PAYLOAD) - len(packet))
                            require(part, 'unexpected TCP EOF'); packet += part
                        require(packet == PAYLOAD, 'idle worker TCP payload changed')
                    output = app.communicate(timeout=20)[0]
                    require(app.returncode == 0 and 'PASS:' in output, 'idle native traffic failed')
                    record = json.loads(stats.read_text())
                    require(record['io']['idle_sleep_us'] == expected, 'effective idle policy mismatch')
                    require(record['idle_waits'] >= record['idle_timeouts'] > 0,
                            'no actual idle timeout occurred during application idle interval')
                    require(record['stop_requests'] or record['control_eof'], 'control shutdown not observed')
                    require(record['outstanding'] == 0 and record['native']['passive_opens'] == 1 and
                            record['native']['udp_in_datagrams'] == 1 and record['native']['udp_out_datagrams'] == 1,
                            'missing native traffic or packet cleanup')
                    print(f'PASS: {name}, {expected}us, actual idle timeouts, host TCP/UDP and control shutdown', flush=True)
                except Exception:
                    log.flush(); log.seek(0); print(log.read(), file=sys.stderr)
                    raise
                finally:
                    for fd in (arm_read, arm_write, notify_read, notify_write):
                        if fd >= 0:
                            os.close(fd)
                    if app is not None and app.poll() is None:
                        app.terminate()
                        try:
                            app.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            app.kill(); app.wait()
    return 0


if __name__ == '__main__':
    sys.exit(main())
