"""Unchanged Linux AF_UNIX tests against the host and Ker's host IPC adapter."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile


def require(value, message):
    if not value:
        raise RuntimeError(message)


def run(command, environment, directory, timeout=60):
    process = subprocess.Popen(command, env=environment, cwd=directory,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate()
        raise
    return dict(returncode=process.returncode, stdout=stdout, stderr=stderr)


def tap_result(result):
    require(result['returncode'] == 0, 'original selftest failed: ' + result['stderr'])
    totals = re.findall(r'^# Totals: pass:(\d+) fail:(\d+) xfail:(\d+) xpass:(\d+) skip:(\d+) error:(\d+)$',
                        result['stdout'], re.MULTILINE)
    require(len(totals) == 1, 'missing or ambiguous kselftest totals')
    passed, *other = map(int, totals[0])
    require(passed > 0 and not any(other), 'failed, skipped, or expected-failure selftests are not passes')
    plan = re.findall(r'^1\.\.(\d+)$', result['stdout'], re.MULTILINE)
    require(plan == [str(passed)], 'kselftest plan and passing count differ')
    cases = re.findall(r'^ok \d+ (.+)$', result['stdout'], re.MULTILINE)
    require(len(cases) == passed and len(set(cases)) == passed, 'missing or duplicated passing cases')
    return cases


def main():
    parser = argparse.ArgumentParser()
    for name in ('binary', 'source', 'library', 'observer', 'manifest', 'evidence'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    if not args.inside:
        return subprocess.run(['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()),
                               *sys.argv[1:], '--inside']).returncode
    manifest = json.loads(args.manifest.read_text())
    revision = manifest['linux']['revision']
    upstream = Path(manifest['source'])
    relative = 'tools/testing/selftests/net/af_unix/' + args.source.name
    paths = [relative, 'tools/testing/selftests/kselftest_harness.h',
             'tools/testing/selftests/kselftest.h']
    originals = {}
    for path in paths:
        original = subprocess.check_output(['git', '-C', str(upstream), 'show', revision + ':' + path])
        require((upstream / path).read_bytes() == original, 'modified upstream source/header: ' + path)
        originals[path] = original
    require(args.source.read_bytes() == originals[relative], 'selftest is not the pinned source')
    report = dict(status='FAIL', scope='host-backed AF_UNIX compatibility through Ker socket preload',
                  imported_kernel_af_unix=False, revision=revision, source=relative,
                  source_hashes={p: hashlib.sha256(b).hexdigest() for p, b in originals.items()},
                  binary_sha256=hashlib.sha256(args.binary.read_bytes()).hexdigest(),
                  adapter_sha256=hashlib.sha256(args.library.read_bytes()).hexdigest(),
                  observer_sha256=hashlib.sha256(args.observer.read_bytes()).hexdigest())
    try:
        subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
        environment = {k: v for k, v in os.environ.items()
                       if k != 'LD_PRELOAD' and not k.startswith('KER_')}
        with tempfile.TemporaryDirectory(prefix='ker-linux-unix-') as temporary:
            root = Path(temporary)
            for mode in ('host', 'adapter'):
                work = root / mode
                work.mkdir()
                env = dict(environment)
                audit = root / 'adapter.log'
                if mode == 'adapter':
                    env.update(LD_PRELOAD=str(args.observer) + ':' + str(args.library),
                               KER_UNIX_TEST_AUDIT=str(audit), KER_UNIX_TEST_LIBRARY=str(args.library))
                    if args.source.stem == 'msg_oob':
                        # This original AF_UNIX test intentionally uses host TCP as its oracle.
                        env['KER_UNIX_TEST_HOST_TCP_REFERENCE'] = '1'
                result = run([str(args.binary)], env, work)
                report[mode] = result
                result['cases'] = tap_result(result)
            require(report['adapter']['cases'] == report['host']['cases'], 'host/adapter test inventories differ')
            marks = audit.read_text().splitlines()
            report['adapter_observations'] = {mark: marks.count(mark) for mark in sorted(set(marks))}
            require(marks.count('KER_UNIX_ADAPTER_LOADED') >= 1, 'Ker adapter was not loaded')
            require(any(mark in marks for mark in ('KER_UNIX_SOCKET', 'KER_UNIX_SOCKETPAIR')),
                    'no AF_UNIX operations reached the observed adapter execution')
            require(('HOST_TCP_REFERENCE_SOCKET' in marks) == (args.source.stem == 'msg_oob'),
                    'unexpected TCP oracle routing')
            if args.source.stem == 'unix_connect':
                rejected = root / 'rejected'
                rejected.mkdir()
                env.update(KER_UNIX_TEST_REJECT='1')
                control = run([str(args.binary)], env, rejected)
                report['rejection_control'] = control
                require(control['returncode'] != 0 and re.search(r'^not ok ', control['stdout'], re.MULTILINE),
                        'AF_UNIX failure injection did not fail the original assertions')
            for path, original in originals.items():
                require((upstream / path).read_bytes() == original, 'upstream file changed during test: ' + path)
            report['status'] = 'PASS_HOST_COMPATIBILITY'
            print('LINUX_AF_UNIX_HOST_COMPATIBILITY_PASS ' + args.source.stem +
                  ' cases=' + str(len(report['adapter']['cases'])))
    except BaseException as error:
        report['error'] = str(error)
        raise
    finally:
        args.evidence.parent.mkdir(parents=True, exist_ok=True)
        args.evidence.write_text(json.dumps(report, indent=2) + '\n')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        print('Linux AF_UNIX selftest failed: ' + str(error), file=sys.stderr)
        sys.exit(1)
