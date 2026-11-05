"""Run unchanged fork-based MPTCP helpers against one resident imported Linux."""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

HEADER = struct.Struct('=IIIIIIq')
MAGIC, STOP = 0x4b4d5331, 12


def require(value, message):
    if not value:
        raise RuntimeError(message)


def stop(path):
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as channel:
        channel.settimeout(2)
        channel.connect(str(path))
        channel.sendall(HEADER.pack(MAGIC, STOP, 0, 0, 0, 0, 0))
        reply = HEADER.unpack(channel.recv(32))
        require(reply[:3] == (MAGIC, STOP, 0), 'invalid fixture stop response')
        if reply[-1] < 0:
            raise OSError(-reply[-1], 'fixture stop rejected')


def run_helper(command, environment, timeout=25):
    child = subprocess.Popen(command, env=environment, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        out, err = child.communicate(timeout=timeout)
    except BaseException as error:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        out, err = child.communicate()
        raise RuntimeError(str(error) + '\n' + out + err) from error
    return dict(command=[str(x) for x in command], returncode=child.returncode, stdout=out, stderr=err)


def validate_case(result):
    require(result['returncode'] == 0, 'original helper failed: ' + result['stdout'] + result['stderr'])
    require(not re.search(r'skip|not ok|xfail|unsupported', result['stdout'] + result['stderr'], re.I),
            'upstream feature check skipped or failed')


def validate_native(counts, program, profiles):
    require(counts['sockets'] == 2 * profiles and counts['accepts'] == profiles and counts['live'] == 0,
            'missing native sockets or unsettled lifecycle')
    require(counts['sent'] == counts['received'] and counts['sent'] >= 256,
            'native socket byte accounting mismatch')
    require(counts['mptcp'] == (2 if program == 'sockopt' else 4), 'missing MPTCP socket operations')
    require(counts['negotiated'] == 2, 'missing native MPTCP negotiation')
    require(counts['fallback'] == (0 if program == 'sockopt' else 1), 'incorrect native fallback control')
    if program == 'sockopt':
        require(counts['infos'] >= 20 and counts['full_info'] == 2, 'MPTCP info tests did not execute')
    else:
        require(counts['inq'] > 20 and counts['sent'] > 3 * 1024 * 1024, 'INQ data/control tests did not execute')


def main():
    parser = argparse.ArgumentParser()
    for name in ('server', 'binary', 'control', 'launcher', 'library', 'worker', 'pmd_dir', 'manifest', 'evidence'):
        parser.add_argument('--' + name.replace('_', '-'), type=Path, required=True)
    parser.add_argument('--program', choices=('sockopt', 'inq'), required=True)
    parser.add_argument('--family', choices=('4', '6'), required=True)
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    if not args.inside:
        return subprocess.run(['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()),
                               *sys.argv[1:], '--inside']).returncode
    manifest = json.loads(args.manifest.read_text())
    source = Path(manifest['source']) / 'tools/testing/selftests/net/mptcp'
    originals = {}
    for name in (f'mptcp_{args.program}.c', 'mptcp_sockopt.sh', 'Makefile'):
        original = subprocess.check_output(['git', '-C', manifest['source'], 'show',
            manifest['linux']['revision'] + ':tools/testing/selftests/net/mptcp/' + name])
        require((source / name).read_bytes() == original, 'modified original Linux source: ' + name)
        originals[name] = original
    report = dict(status='FAIL', revision=manifest['linux']['revision'], fingerprint=manifest['fingerprint'],
                  program=args.program, family=args.family,
                  source_hashes={k: hashlib.sha256(v).hexdigest() for k, v in originals.items()},
                  binary_sha256=hashlib.sha256(args.binary.read_bytes()).hexdigest(),
                  library_sha256=hashlib.sha256(args.library.read_bytes()).hexdigest(),
                  server_sha256=hashlib.sha256(args.server.read_bytes()).hexdigest())
    environment = {k: v for k, v in os.environ.items() if k != 'LD_PRELOAD' and not k.startswith('KER_')}
    family_args = ['-6'] if args.family == '6' else []
    profiles = [[]] if args.program == 'sockopt' else [[], ['-t', 'tcp'], ['-r', 'tcp'], ['-t', 'tcp', '-r', 'tcp']]
    try:
        for command in (['ip', 'link', 'set', 'lo', 'up'],
            ['ip', 'link', 'add', 'kerhost', 'type', 'veth', 'peer', 'name', 'kerlink'],
            ['ip', 'tuntap', 'add', 'dev', 'kerpeer', 'mode', 'tap', 'multi_queue'],
            *[['ip', 'link', 'set', n, 'up'] for n in ('kerhost', 'kerlink', 'kerpeer')]):
            subprocess.run(command, check=True)
        cpu = min(os.sched_getaffinity(0))
        eal = (f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry --iova-mode=va -m 64 '
               f'-d {shlex.quote(str(args.pmd_dir / "librte_net_tap.so"))} --vdev=net_tap0,iface=kerpeer,remote=kerlink')
        with tempfile.TemporaryDirectory(prefix='ker-mptcp-socket-', dir='/dev/shm') as temporary:
            root = Path(temporary)
            channel, counts_file, stats = root / 'socket', root / 'counts.json', root / 'stats.json'
            environment['KER_MPTCP_SOCKET_CHANNEL'] = str(channel)
            # Reject absence explicitly, before starting the imported kernel.
            rejected = run_helper([args.control], environment)
            require(rejected['returncode'] == 0 and rejected['stdout'].strip() == 'MISSING_BACKEND_REJECTED',
                    'missing native fixture fell back to host TCP/MPTCP')
            report['missing_backend_control'] = rejected
            out = (root / 'server.stdout').open('w+')
            err = (root / 'server.stderr').open('w+')
            process = subprocess.Popen([sys.executable, str(args.launcher), '--library', str(args.library),
                '--io-worker', str(args.worker), '--address', '198.18.0.2/24', '--port', 'net_tap0', '--eal', eal,
                '--stats', str(stats), '--', str(args.server), str(channel), str(counts_file)],
                env=environment, stdout=out, stderr=err, start_new_session=True)
            try:
                deadline = time.monotonic() + 20
                while not channel.exists():
                    require(process.poll() is None and time.monotonic() < deadline, 'resident kernel startup failed')
                    time.sleep(0.01)
                # Invalid messages must be rejected without killing the kernel owner.
                with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as bad:
                    bad.settimeout(2); bad.connect(str(channel))
                    bad.sendall(HEADER.pack(MAGIC + 1, STOP, 0, 0, 0, 0, 0))
                    require(bad.recv(1) == b'', 'malformed fixture message accepted')
                report['malformed_frame_control'] = 'rejected'
                report['cases'] = []
                for profile in profiles:
                    result = run_helper([args.binary, *family_args, *profile], environment)
                    report['cases'].append(result)
                    validate_case(result)
                deadline = time.monotonic() + 5
                while True:
                    try:
                        stop(channel)
                        break
                    except OSError as error:
                        require(error.errno == errno.EBUSY and time.monotonic() < deadline,
                                'native socket lifecycle failed to settle: ' + str(error))
                        time.sleep(0.01)
                require(process.wait(timeout=20) == 0, 'native kernel/worker shutdown failed')
                report['native_fixture'] = json.loads(counts_file.read_text())
                validate_native(report['native_fixture'], args.program, len(profiles))
                report['stats'] = json.loads(stats.read_text())
                require(report['stats'].get('outstanding') == 0, 'packet ownership did not settle')
                for name, data in originals.items():
                    require((source / name).read_bytes() == data, 'upstream file changed during execution')
                report['status'] = 'PASS_IMPORTED_LINUX'
                print('LINUX_ORIGINAL_MPTCP_SOCKET_PASS', args.program, args.family, len(profiles))
                return 0
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL); process.wait()
                for stream, name in ((out, 'server_stdout'), (err, 'server_stderr')):
                    stream.flush(); stream.seek(0); report[name] = stream.read(); stream.close()
    except BaseException as error:
        report['error'] = str(error)
        raise
    finally:
        args.evidence.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        print('Linux MPTCP socket selftest failed: ' + str(error), file=sys.stderr)
        sys.exit(1)
