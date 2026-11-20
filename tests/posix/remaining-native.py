"""Run source-shaped native cases in an isolated real TAP data plane."""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
for field in ('launcher', 'library', 'worker', 'app'):
    parser.add_argument('--' + field, type=Path, required=True)
parser.add_argument('--profile', choices=('address', 'mmap', 'one', 'repeat', 'wait'), required=True)
parser.add_argument('--inside', action='store_true')
args = parser.parse_args()
if not args.inside:
    sys.exit(subprocess.run(['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()),
                             *sys.argv[1:], '--inside']).returncode)

for command in (['link', 'add', 'casepeer', 'type', 'veth', 'peer', 'name', 'caselink'],
                ['link', 'set', 'casepeer', 'up'], ['link', 'set', 'caselink', 'up'],
                ['addr', 'add', '198.18.0.1/24', 'dev', 'casepeer']):
    subprocess.run(['ip', *command], check=True)
cpu = min(os.sched_getaffinity(0))
with tempfile.TemporaryDirectory(prefix='ker-final-source-') as temporary:
    root = Path(temporary)
    config, stats = root / 'native.ini', root / 'stats.json'
    config.write_text('[network]\naddress=198.18.0.2/24\n[dpdk]\nport=net_tap0\n'
                      f'eal=--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry '
                      '--iova-mode=va -m 96 --vdev=net_tap0,iface=casewire,remote=caselink\n')
    command = [sys.executable, str(args.launcher), '--config', str(config),
               '--library', str(args.library), '--io-worker', str(args.worker),
               '--stats', str(stats), '--', str(args.app)]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer, concurrent.futures.ThreadPoolExecutor(1) as pool:
        if args.profile in ('one', 'repeat'):
            peer.bind(('198.18.0.1', 46543))
            peer.settimeout(5)

            def echo():
                data, sender = peer.recvfrom(256)
                assert data == b'run-stop-original-linux\0' and sender[0] == '198.18.0.2'
                assert peer.sendto(data, sender) == len(data)

            proof = pool.submit(echo)
        else:
            proof = None
        if args.profile in ('one', 'repeat', 'wait'):
            command.append(args.profile)
        result = subprocess.run(command, text=True, capture_output=True, timeout=22)
        print(result.stdout, end='')
        if result.returncode != (1 if args.profile == 'mmap' else 0):
            raise RuntimeError(result.stdout + result.stderr)
        if proof is not None:
            proof.result()
    record = json.loads(stats.read_text())
    assert record['outstanding'] == 0 and record['native']['buffers_live'] == 0, record
    if args.profile == 'mmap':
        assert 'HOST_MMAP_FATAL_ARMED' in result.stdout and 'mmap' in result.stderr, result.stderr
    elif args.profile == 'address':
        assert [line for line in result.stdout.splitlines() if line.startswith('ADDRESS_NATIVE_EXCHANGE ')] == [
            'ADDRESS_NATIVE_EXCHANGE ' + value for value in ('2 0', '10 0', '2 1', '10 1', '2 0', '10 0')]
        assert record['native']['active_opens'] == record['native']['passive_opens'] == 6
    else:
        assert record['run_shutdown_ack'], record
        if args.profile != 'wait':
            assert record['tx'] > 0 and record['rx'] > 0, record
