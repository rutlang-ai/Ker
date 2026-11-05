"""Run pinned, unchanged TCP-AO programs with their real imported Linux fixtures."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile

from importlib.util import module_from_spec, spec_from_file_location
_spec = spec_from_file_location('original_linux_runner', Path(__file__).with_name('linux-original-selftest.py'))
_runner = module_from_spec(_spec)
_spec.loader.exec_module(_runner)
require = _runner.require


# These three XFAILs are marked FIXME by the pinned key-management.c itself.
# Retain and report them separately; any other expected failure is rejected.
UPSTREAM_XFAILS = {
    'listen() after current/rnext keys set: the socket has current/rnext keys: 100:200',
    'listen socket, delete current key from before listen(): failed to delete the key 100:100 -16',
    'listen socket, delete rnext key from before listen(): failed to delete the key 200:200 -16',
}


def tap_result(output, program):
    totals = re.findall(r'^# Totals: pass:(\d+) fail:(\d+) xfail:(\d+) xpass:(\d+) skip:(\d+) error:(\d+)$', output, re.M)
    require(len(totals) == 1, 'missing or ambiguous kselftest totals')
    passed, failed, xfailed, xpassed, skipped, errors = map(int, totals[0])
    require(passed > 0 and not any((failed, xpassed, skipped, errors)),
            'failure, skip, xpass or error is not a pass')
    require(re.findall(r'^1\.\.(\d+)$', output, re.M) == [str(passed + xfailed)], 'TAP plan/count mismatch')
    cases = re.findall(r'^ok (\d+) (.*)$', output, re.M)
    require([int(i) for i, _ in cases] == list(range(1, passed + xfailed + 1)), 'missing or duplicated TAP cases')
    require(not re.search(r'^not ok ', output, re.M), 'failing TAP result')
    expected = [name.removeprefix('# XFAIL ') for _, name in cases if name.startswith('# XFAIL ')]
    require(len(expected) == xfailed and len(set(expected)) == len(expected), 'XFAIL count mismatch')
    require(not expected or (program == 'key-management' and set(expected) <= UPSTREAM_XFAILS),
            'unreviewed upstream XFAIL')
    return dict(passed=[name for _, name in cases if not name.startswith('# XFAIL ')],
                upstream_xfails=expected)


def source_bytes(path, symlink):
    require(path.is_symlink() == symlink, 'source file type differs from upstream: ' + str(path))
    return os.readlink(path).encode() if symlink else path.read_bytes()


def main():
    parser = argparse.ArgumentParser()
    for name in ('binary', 'source', 'launcher', 'library', 'worker', 'pmd_dir', 'manifest', 'evidence'):
        parser.add_argument('--' + name.replace('_', '-'), type=Path, required=True)
    parser.add_argument('--family', choices=(4, 6), type=int, required=True)
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    if not args.inside:
        return subprocess.run(['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()),
                               *sys.argv[1:], '--inside']).returncode
    manifest = json.loads(args.manifest.read_text())
    revision, upstream = manifest['linux']['revision'], Path(manifest['source'])
    relative = 'tools/testing/selftests/net/tcp_ao/' + args.source.name
    paths = [relative, 'tools/testing/selftests/kselftest.h']
    if args.source.name == 'icmps-accept.c':
        paths.append('tools/testing/selftests/net/tcp_ao/icmps-discard.c')
    paths += subprocess.run(['git', '-C', str(upstream), 'ls-tree', '-r', '--name-only', revision,
                             'tools/testing/selftests/net/tcp_ao/lib'], check=True, capture_output=True,
                            text=True).stdout.splitlines()
    hashes, symlinks = {}, {}
    for path in paths:
        original = subprocess.run(['git', '-C', str(upstream), 'show', revision + ':' + path],
                                   check=True, capture_output=True).stdout
        tree = subprocess.run(['git', '-C', str(upstream), 'ls-tree', revision, '--', path],
                              check=True, capture_output=True, text=True).stdout
        symlinks[path] = tree.startswith('120000 ')
        require(source_bytes(upstream / path, symlinks[path]) == original, 'modified upstream source: ' + path)
        hashes[path] = hashlib.sha256(original).hexdigest()
    report = dict(status='FAIL', source=relative, revision=revision, family=args.family,
                  source_hashes=hashes, source_symlinks=symlinks, kernel_fingerprint=manifest['fingerprint'],
                  binary_sha256=hashlib.sha256(args.binary.read_bytes()).hexdigest(),
                  adapter_sha256=hashlib.sha256(args.library.read_bytes()).hexdigest())
    try:
        for command in (['ip', 'link', 'set', 'lo', 'up'],
            ['ip', 'link', 'add', 'kerhost', 'type', 'veth', 'peer', 'name', 'kerlink'],
            ['ip', 'tuntap', 'add', 'dev', 'kerpeer', 'mode', 'tap', 'multi_queue'],
            *[['ip', 'link', 'set', n, 'up'] for n in ('kerhost', 'kerlink', 'kerpeer')]):
            subprocess.run(command, check=True)
        cpu = min(os.sched_getaffinity(0))
        eal = (f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry --iova-mode=va -m 64 '
               f'-d {shlex.quote(str(args.pmd_dir / "librte_net_tap.so"))} --vdev=net_tap0,iface=kerpeer,remote=kerlink')
        environment = {k: v for k, v in os.environ.items() if k != 'LD_PRELOAD' and not k.startswith('KER_')}
        with tempfile.TemporaryDirectory(prefix='linux-tcp-ao-', dir='/dev/shm') as temporary:
            stats = Path(temporary) / 'stats.json'
            result = _runner.run_program([sys.executable, str(args.launcher), '--library', str(args.library),
                '--io-worker', str(args.worker), '--address', '198.18.0.2/24', '--port', 'net_tap0',
                '--eal', eal, '--stats', str(stats), '--', str(args.binary)], environment, 850)
            report.update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
            require(result.returncode == 0, 'original TCP-AO program/launcher failed: ' + result.stderr)
            report.update(tap_result(result.stdout, args.source.stem))
            operations = re.findall(r'^KER_LINUX_SELFTEST_OPS (.+)$', result.stderr, re.M)
            require(len(operations) == 1, 'missing native fixture evidence')
            report['native_fixture_operations'] = ops = json.loads(operations[0])
            require(ops['unshare'] >= 2 and ops['setns'] >= 2 and ops['open'] and ops['netlink'] and ops['mount'],
                    'namespace/proc/netlink setup did not run on imported Linux')
            options = re.findall(r'^KER_TCP_AO_OPTIONS (\d+)$', result.stderr, re.M)
            require(len(options) == 1 and int(options[0]) > 0, 'missing original Linux TCP-AO socket operations')
            report['ao_options'] = int(options[0])
            report['stats'] = counters = json.loads(stats.read_text())
            require(counters.get('outstanding') == 0, 'unsettled native packet resources')
            for path, digest in hashes.items():
                require(hashlib.sha256(source_bytes(upstream / path, symlinks[path])).hexdigest() == digest,
                        'original Linux source changed during execution')
            report['status'] = 'PASS_WITH_UPSTREAM_XFAIL' if report['upstream_xfails'] else 'PASS_IMPORTED_LINUX'
            print('LINUX_ORIGINAL_TCP_AO_PASS', args.source.stem, args.family, len(report['passed']), 'upstream_xfails', len(report['upstream_xfails']))
            return 0
    except BaseException as error:
        report['error'] = str(error)
        raise
    finally:
        args.evidence.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        print('Linux TCP-AO selftest failed: ' + str(error), file=sys.stderr)
        sys.exit(1)
