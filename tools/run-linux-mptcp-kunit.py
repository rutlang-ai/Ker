#!/usr/bin/env python3
"""Build a separate native test kernel and run its unchanged MPTCP KUnit suites."""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
EXPECTED = {
    'mptcp-crypto': ['mptcp_crypto_test_basic'],
    'mptcp-token': ['mptcp_token_test_req_basic', 'mptcp_token_test_msk_basic',
                    'mptcp_token_test_accept', 'mptcp_token_test_destroyed'],
}


class EvidenceError(RuntimeError):
    pass


def require(value, message):
    if not value:
        raise EvidenceError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


@contextmanager
def run_lock(build):
    build.mkdir(parents=True, exist_ok=True)
    with (build / '.mptcp-kunit-run.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def stage_inputs(root, destination):
    """Reuse the unchanged builder with an isolated, fingerprinted input root.

    Only the composed defconfig differs; no production files or kernel sources
    are changed. The ordinary builder retains its own artifact/provenance lock.
    """
    marker = destination / '.ker-mptcp-kunit-inputs'
    if destination.exists():
        require(marker.is_file() and marker.read_text() == 'mptcp-kunit\n', 'refusing to replace foreign input directory')
        shutil.rmtree(destination)
    for directory in ('config', 'tools', 'src/posix'):
        (destination / directory).mkdir(parents=True, exist_ok=True)
    marker.write_text('mptcp-kunit\n')
    for name in ('config/native-linux.json', 'tools/build-native-linux.py'):
        shutil.copyfile(root / name, destination / name)
    seed = (root / 'config/native-linux.defconfig').read_bytes()
    extra = (root / 'config/native-linux-mptcp-kunit.config').read_bytes()
    (destination / 'config/native-linux.defconfig').write_bytes(seed + b'\n' + extra)
    shutil.copytree(root / 'src/posix/lkl-overlay', destination / 'src/posix/lkl-overlay')
    return destination / 'tools/build-native-linux.py'


def validate_tree(test, success):
    require(test.status == success and not test.counts.errors, 'KUnit did not complete successfully')
    require(test.expected_count == 2 and len(test.subtests) == 2, 'incomplete MPTCP suite plan')
    suites = {}
    for suite in test.subtests:
        require(suite.status == success and not suite.counts.errors, 'failed, skipped or malformed MPTCP suite')
        require(suite.name in EXPECTED and suite.name not in suites, 'unexpected or duplicate MPTCP suite')
        names = [case.name for case in suite.subtests]
        require(names == EXPECTED[suite.name] and suite.expected_count == len(names), 'incomplete MPTCP case plan')
        require(all(case.status == success and not case.subtests and not case.counts.errors
                    for case in suite.subtests), 'failed, skipped, nested or malformed MPTCP case')
        suites[suite.name] = names
    require(set(suites) == set(EXPECTED), 'missing MPTCP suite')
    require(test.counts.passed == 5 and test.counts.failed == test.counts.crashed == test.counts.skipped == 0,
            'unexpected MPTCP KUnit totals')
    return suites


def check_config(config):
    lines = set(config.splitlines())
    for option in ('KUNIT', 'MPTCP_KUNIT_TEST', 'MPTCP', 'MPTCP_IPV6'):
        require('CONFIG_' + option + '=y' in lines, 'required test kernel config missing: ' + option)
    for option in ('KUNIT_ALL_TESTS', 'KUNIT_TEST', 'KUNIT_EXAMPLE_TEST', 'KUNIT_DEFAULT_ENABLED'):
        require('CONFIG_' + option + '=y' not in lines and 'CONFIG_' + option + '=m' not in lines,
                'unexpected KUnit profile selection: ' + option)


def check_execution(result):
    require(result.returncode == 0, 'native KUnit harness failed: ' + result.stderr)
    require(result.stdout.count('KER_MPTCP_KUNIT_BOOTED') == 1 and
            result.stdout.count('KER_MPTCP_KUNIT_HALTED') == 1, 'kernel boot/halt lifecycle incomplete')


def parse_log(parser, output):
    """Retain upstream parser diagnostics without presenting the expected
    disabled-control rejection as an unexpected CI failure."""
    capture = io.StringIO()
    previous = parser.stdout
    parser.stdout = type(previous)(capture)
    try:
        tree = parser.parse_run_tests(output.splitlines())
    finally:
        parser.stdout = previous
    return tree, capture.getvalue()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--cache', type=Path, default=Path.home() / '.cache/ker/native-linux.git')
    parser.add_argument('--jobs', type=int, default=min(os.cpu_count() or 1, 16))
    parser.add_argument('--production-manifest', type=Path,
                        help='also verify the production artifact keeps KUnit disabled')
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error('--jobs must be positive')
    build = args.build.resolve()
    with run_lock(build):
        return run(args, build)


def run(args, build):
    report = dict(status='FAIL', profile='mptcp-kunit', suites=EXPECTED)
    evidence = build / 'linux-original-mptcp-kunit.json'
    production_seed_hash = sha(ROOT / 'config/native-linux.defconfig')
    try:
        if args.production_manifest:
            production = json.loads(args.production_manifest.read_text())
            production_config = Path(production['kernel']) / '.config'
            require(sha(production_config) == production['config_sha256'], 'production config artifact digest mismatch')
            selected = set(production_config.read_text().splitlines())
            require('CONFIG_KUNIT=y' not in selected and 'CONFIG_KUNIT=m' not in selected,
                    'KUnit leaked into production kernel')
            expected = subprocess.check_output([sys.executable, str(ROOT / 'tools/build-native-linux.py'),
                                                '--print-fingerprint'], text=True).strip()
            require(production['fingerprint'] == expected, 'production artifact fingerprint mismatch')
            report['production_fingerprint'] = production['fingerprint']
        builder = stage_inputs(ROOT, build / 'inputs')
        subprocess.run([sys.executable, str(builder), '--build', str(build), '--cache', str(args.cache),
                        '--jobs', str(args.jobs)], check=True)
        proof = json.loads((build / 'native-linux.json').read_text())
        fingerprint = subprocess.check_output([sys.executable, str(builder), '--print-fingerprint'], text=True).strip()
        require(proof['fingerprint'] == fingerprint, 'test profile artifact fingerprint mismatch')
        if args.production_manifest:
            require(fingerprint != production['fingerprint'] and proof['kernel'] != production['kernel'],
                    'test and production profiles must have distinct artifacts')
        kernel, source = Path(proof['kernel']), Path(proof['source'])
        tools = kernel / 'tools/lkl'
        require(sha(kernel / '.config') == proof['config_sha256'] and
                sha(tools / 'liblkl.a') == proof['library_sha256'], 'test profile artifact digest mismatch')
        check_config((kernel / '.config').read_text())
        report.update(artifact_provenance=proof, revision=proof['linux']['revision'], fingerprint=fingerprint, config_sha256=proof['config_sha256'],
                      library_sha256=proof['library_sha256'], production_defconfig_sha256=production_seed_hash)
        originals = {}
        for name in ('net/mptcp/crypto_test.c', 'net/mptcp/token_test.c', 'net/mptcp/Makefile', 'net/mptcp/Kconfig',
                     'tools/testing/kunit/kunit_parser.py', 'tools/testing/kunit/kunit_printer.py'):
            original = subprocess.check_output(['git', '-C', str(source), 'show', proof['linux']['revision'] + ':' + name])
            require((source / name).read_bytes() == original, 'modified original Linux file: ' + name)
            originals[name] = hashlib.sha256(original).hexdigest()
        report['source_hashes'] = originals
        binary = build / 'ker-linux-mptcp-kunit'
        harness = ROOT / 'tests/posix/linux-mptcp-kunit.c'
        adapters = [ROOT / 'src/posix' / (name + '.c')
                    for name in ('host-memory', 'host-thread', 'host-clock', 'host-timer', 'host-usercopy')]
        adapter_headers = [path.with_suffix('.h') for path in adapters if path.with_suffix('.h').is_file()]
        report['host_adapter_hashes'] = {str(path.relative_to(ROOT)): sha(path) for path in adapters + adapter_headers}
        compiler = shlex.split(os.environ.get('CC', 'cc'))
        require(compiler, 'empty host compiler command')
        subprocess.run([*compiler, '-Wall', '-Wextra', '-Werror',
                        '-isystem', str(source / 'tools/lkl/include'), '-isystem', str(tools / 'include'),
                        '-I', str(ROOT / 'src/posix'), str(harness), *map(str, adapters),
                        str(tools / 'liblkl.a'), '-lpthread', '-ldl', '-lrt', '-o', str(binary)], check=True)
        report.update(binary_sha256=sha(binary), harness_sha256=sha(harness))
        environment = {k: v for k, v in os.environ.items() if k != 'LD_PRELOAD' and not k.startswith('KER_')}
        environment['PYTHONDONTWRITEBYTECODE'] = '1'
        # Use the unchanged pinned upstream KTAP parser, including its plan and
        # error handling. Ker additionally requires exactly the selected suites
        # and SUCCESS at every level; upstream considers SKIPPED an ok_status.
        sys.path.insert(0, str(source / 'tools/testing/kunit'))
        import kunit_parser
        report['executions'] = []
        for disabled in (False, True):
            command = [str(binary)] + (['--disabled'] if disabled else [])
            result = subprocess.run(command, capture_output=True, text=True, env=environment, timeout=90)
            log = build / ('mptcp-kunit-disabled.log' if disabled else 'mptcp-kunit.log')
            log.write_text(result.stdout + result.stderr)
            check_execution(result)
            tree, diagnostics = parse_log(kunit_parser, result.stdout)
            execution = dict(disabled=disabled, returncode=result.returncode, log=log.name,
                             log_sha256=sha(log), parser_output=diagnostics)
            report['executions'].append(execution)
            if disabled:
                require('kunit: disabled' in result.stdout and not tree.subtests, 'disabled control still ran tests')
                try:
                    validate_tree(tree, kunit_parser.TestStatus.SUCCESS)
                except EvidenceError:
                    execution['status'] = 'DISABLED_KERNEL_REJECTED'
                else:
                    raise EvidenceError('disabled KUnit execution counted as coverage')
            else:
                execution['cases'] = validate_tree(tree, kunit_parser.TestStatus.SUCCESS)
                execution['status'] = 'PASS_IMPORTED_LINUX_KUNIT'
        require(sha(ROOT / 'config/native-linux.defconfig') == production_seed_hash, 'production config changed')
        report['status'] = 'PASS_IMPORTED_LINUX_KUNIT'
        print('LINUX_ORIGINAL_MPTCP_KUNIT_PASS 2 suites 5 cases')
        return 0
    except BaseException as error:
        report['error'] = str(error)
        raise
    finally:
        evidence.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        sys.exit('native MPTCP KUnit failed: ' + str(error))
