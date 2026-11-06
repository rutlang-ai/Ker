"""Run original binding selftests against the shared native socket fixture."""
import argparse
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import time


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fixture = load('native_socket_fixture', 'linux-mptcp-socket-selftest.py')
cleanup = load('native_socket_cleanup', 'linux-mptcp-diag-selftest.py')
tap = load('original_kselftest_tap', 'linux-unix-selftest.py')
require = fixture.require

# Complete default programs; helper and individual assertion counts stay separate.
CONTRACTS = {
    'reuseaddr_conflict': (None, 5, 0),
    'sk_bind_sendto_listen': (None, 2, 0),
    # The fixture counts socket() and accept() separately: three socket()
    # calls plus one accept() in each of the two original variants.
    'bind_timewait': (2, 6, 2),
    'bind_wildcard': (132, 1056, 0),
}


def main():
    parser = argparse.ArgumentParser()
    for name in ('server', 'binary', 'control', 'launcher', 'library', 'worker', 'pmd_dir', 'manifest', 'evidence'):
        parser.add_argument('--' + name.replace('_', '-'), type=Path, required=True)
    parser.add_argument('--program', choices=CONTRACTS, required=True)
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    if not args.inside:
        return subprocess.run(['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()),
                               *sys.argv[1:], '--inside']).returncode
    manifest = json.loads(args.manifest.read_text())
    source = Path(manifest['source'])
    paths = ['tools/testing/selftests/net/' + args.program + '.c',
             'tools/testing/selftests/net/Makefile', 'tools/testing/selftests/kselftest.h',
             'tools/testing/selftests/kselftest_harness.h']
    originals = {}
    for path in paths:
        original = subprocess.check_output(['git', '-C', str(source), 'show', manifest['linux']['revision'] + ':' + path])
        require((source / path).read_bytes() == original, 'modified upstream source: ' + path)
        originals[path] = original
    report = dict(status='FAIL', program=args.program, revision=manifest['linux']['revision'],
                  fingerprint=manifest['fingerprint'], source_hashes={p: hashlib.sha256(b).hexdigest() for p, b in originals.items()},
                  binary_sha256=hashlib.sha256(args.binary.read_bytes()).hexdigest(),
                  library_sha256=hashlib.sha256(args.library.read_bytes()).hexdigest(),
                  server_sha256=hashlib.sha256(args.server.read_bytes()).hexdigest())
    environment = {k: v for k, v in os.environ.items() if k != 'LD_PRELOAD' and not k.startswith('KER_')}
    try:
        for command in (['ip', 'link', 'set', 'lo', 'up'],
                        ['ip', 'link', 'add', 'kerhost', 'type', 'veth', 'peer', 'name', 'kerlink'],
                        ['ip', 'tuntap', 'add', 'dev', 'kerpeer', 'mode', 'tap', 'multi_queue'],
                        *[['ip', 'link', 'set', name, 'up'] for name in ('kerhost', 'kerlink', 'kerpeer')]):
            subprocess.run(command, check=True)
        cpu = min(os.sched_getaffinity(0))
        eal = (f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry --iova-mode=va -m 64 '
               f'-d {shlex.quote(str(args.pmd_dir / "librte_net_tap.so"))} --vdev=net_tap0,iface=kerpeer,remote=kerlink')
        with tempfile.TemporaryDirectory(prefix='ker-linux-net-', dir='/dev/shm') as temporary:
            root = Path(temporary)
            channel, counts, stats = root / 'socket', root / 'counts.json', root / 'stats.json'
            environment['KER_MPTCP_SOCKET_CHANNEL'] = str(channel)
            report['missing_backend_control'] = fixture.run_helper([args.control], environment)
            require(report['missing_backend_control']['returncode'] == 0 and
                    report['missing_backend_control']['stdout'].strip() == 'MISSING_BACKEND_REJECTED',
                    'unavailable native backend was not rejected')
            with (root / 'server.stdout').open('w+') as out, (root / 'server.stderr').open('w+') as err:
                process = subprocess.Popen([sys.executable, str(args.launcher), '--library', str(args.library),
                    '--io-worker', str(args.worker), '--address', '198.18.0.2/24', '--port', 'net_tap0', '--eal', eal,
                    '--stats', str(stats), '--', str(args.server), str(channel), str(counts)],
                    env=environment, stdout=out, stderr=err, start_new_session=True)
                try:
                    deadline = time.monotonic() + 20
                    while not channel.exists():
                        require(process.poll() is None and time.monotonic() < deadline, 'resident kernel startup failed')
                        time.sleep(0.01)
                    child = subprocess.Popen([str(args.binary)], env=environment, stdout=subprocess.PIPE,
                                             stderr=subprocess.PIPE, text=True, start_new_session=True)
                    try:
                        stdout, stderr = child.communicate(timeout=300)
                    except BaseException:
                        cleanup.kill_tree(child.pid)
                        cleanup.bounded_communicate(child, timeout=5)
                        raise
                    result = dict(returncode=child.returncode, stdout=stdout, stderr=stderr)
                    report['original'] = result
                    require(child.returncode == 0, 'original selftest failed: ' + stdout + stderr)
                    expected_tap, sockets, accepts = CONTRACTS[args.program]
                    if expected_tap is not None:
                        result['cases'] = tap.tap_result(result)
                        require(len(result['cases']) == expected_tap, 'incomplete original fixture/variant matrix')
                    deadline = time.monotonic() + 5
                    while True:
                        try:
                            fixture.stop(channel)
                            break
                        except OSError as error:
                            require(error.errno == errno.EBUSY and time.monotonic() < deadline, 'native sockets did not settle')
                            time.sleep(0.01)
                    require(process.wait(timeout=20) == 0, 'native kernel/worker shutdown failed')
                    native = json.loads(counts.read_text())
                    report['native_fixture'] = native
                    require(native['sockets'] == sockets and native['accepts'] == accepts and native['live'] == 0,
                            'original native socket matrix or cleanup differs')
                    require(native['mptcp'] == 0, 'unexpected protocol substitution')
                    report['stats'] = json.loads(stats.read_text())
                    require(report['stats'].get('outstanding') == 0, 'packet ownership did not settle')
                    require(report['stats'].get('worker_exit_code') == 0 and
                            report['stats'].get('control_eof') is True and
                            report['stats'].get('shutdown_timed_out') is False,
                            'native worker did not stop normally')
                    if accepts:
                        mib = report['stats'].get('native', {})
                        require(mib.get('active_opens') == accepts and mib.get('passive_opens') == accepts,
                                'original TIME_WAIT connections did not reach native TCP')
                    for path, original in originals.items():
                        require((source / path).read_bytes() == original, 'upstream source changed during test')
                    report['status'] = 'PASS_IMPORTED_LINUX'
                    print('LINUX_ORIGINAL_NETWORK_PASS', args.program, expected_tap or 'program-exit', sockets)
                    return 0
                finally:
                    if process.poll() is None:
                        cleanup.kill_tree(process.pid)
                        process.wait(timeout=10)
                    for stream, name in ((out, 'server_stdout'), (err, 'server_stderr')):
                        stream.flush(); stream.seek(0); report[name] = stream.read()
    except BaseException as error:
        report['error'] = str(error)
        raise
    finally:
        args.evidence.parent.mkdir(parents=True, exist_ok=True)
        args.evidence.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        sys.exit('Linux network selftest failed: ' + str(error))
