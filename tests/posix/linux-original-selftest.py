"""Run unchanged pinned Linux selftests directly on the imported kernel."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import tempfile


def require(value, message):
    if not value:
        raise RuntimeError(message)


def run_program(command, env, timeout):
    # The launcher owns a worker child: timeouts must reap the whole job.
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, env=env, start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate()
        raise
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def main():
    parser = argparse.ArgumentParser()
    for name in ('launcher', 'library', 'worker', 'binary', 'source', 'pmd_dir', 'manifest', 'evidence'):
        parser.add_argument('--' + name.replace('_', '-'), type=Path, required=True)
    parser.add_argument('--case-arg', action='append', default=[])
    parser.add_argument('--inside', action='store_true')
    parser.add_argument('--host-control', action='store_true')
    args = parser.parse_args()
    if not args.inside:
        return subprocess.run(['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()),
            *sys.argv[1:], '--inside']).returncode
    manifest = json.loads(args.manifest.read_text())
    revision = manifest['linux']['revision']
    relative = 'tools/testing/selftests/net/' + args.source.name
    original = subprocess.run(['git', '-C', manifest['source'], 'show', revision + ':' + relative],
        check=True, capture_output=True).stdout
    source = args.source.read_bytes()
    require(source == original, 'Linux selftest differs from its pinned upstream blob')
    report = dict(status='FAIL', source=relative, revision=revision,
        source_sha256=hashlib.sha256(source).hexdigest(), binary_sha256=hashlib.sha256(args.binary.read_bytes()).hexdigest(),
        kernel_release=manifest['release'], kernel_fingerprint=manifest['fingerprint'],
        arguments=args.case_arg, host_control=args.host_control)
    for command in (['ip', 'link', 'set', 'lo', 'up'],
        ['ip', 'link', 'add', 'kerhost', 'type', 'veth', 'peer', 'name', 'kerlink'],
        ['ip', 'tuntap', 'add', 'dev', 'kerpeer', 'mode', 'tap', 'multi_queue'],
        ['ip', 'addr', 'add', '198.18.0.1/24', 'dev', 'kerhost'],
        *[['ip', 'link', 'set', name, 'up'] for name in ('kerhost', 'kerlink', 'kerpeer')]):
        subprocess.run(command, check=True)
    cpu = min(os.sched_getaffinity(0))
    eal = (f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry --iova-mode=va -m 64 '
        f'-d {shlex.quote(str(args.pmd_dir / "librte_net_tap.so"))} --vdev=net_tap0,iface=kerpeer,remote=kerlink')
    with tempfile.TemporaryDirectory(prefix='linux-selftest-', dir='/dev/shm') as tmp:
        stats = Path(tmp) / 'stats.json'
        env = dict(os.environ)
        env.pop('LD_PRELOAD', None)
        env.pop('KER_SOCKET_BROKER_PATH', None)
        try:
            if args.host_control:
                host = run_program([str(args.binary), *args.case_arg], env=env, timeout=30)
                report.update(host_returncode=host.returncode, host_stdout=host.stdout, host_stderr=host.stderr)
                require(host.returncode == 0, 'host control did not pass independently')
            binary = '/bin/true' if args.host_control else str(args.binary)
            result = run_program([sys.executable, str(args.launcher), '--library', str(args.library),
                '--io-worker', str(args.worker), '--address', '198.18.0.2/24', '--port', 'net_tap0',
                '--eal', eal, '--stats', str(stats), '--', binary, *([] if args.host_control else args.case_arg)],
                env=env, timeout=60)
            report.update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
            require(result.returncode == 0, 'original Linux selftest or native launcher failed: ' + result.stderr)
            counters = json.loads(stats.read_text()); report['stats'] = counters
            imported_activity = (counters.get('native', {}).get('active_opens', 0) >= 1 and
                counters.get('native', {}).get('passive_opens', 0) >= 1)
            if args.host_control:
                require(not imported_activity and counters.get('native', {}).get('active_opens') == 0 and
                    counters.get('native', {}).get('passive_opens') == 0,
                    'host-only execution unexpectedly produced imported-kernel TCP activity')
                require(counters.get('outstanding') == 0, 'idle native control leaked resources')
                require(args.source.read_bytes() == original, 'selftest changed during host control')
                report['status'] = 'HOST_ONLY_REJECTED'
                print('HOST_ONLY_PASS_REJECTED_AS_IMPORTED_KERNEL_COVERAGE')
                return 0
            require(imported_activity,
                'missing imported-kernel TCP activity; host execution is not a kernel pass')
            require(counters.get('outstanding') == 0, 'native resources did not settle')
            require(args.source.read_bytes() == original, 'Linux selftest changed during execution')
            report['status'] = 'PASS'
            print('LINUX_ORIGINAL_SELFTEST_PASS ' + relative)
            return 0
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
        print('Linux original selftest failed: ' + str(error), file=sys.stderr)
        sys.exit(1)
