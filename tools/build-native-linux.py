#!/usr/bin/env python3
"""Build pinned Linux TCP/socket code with the LKL architecture in a generated tree."""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
from time import monotonic, sleep

ROOT = Path(__file__).resolve().parent.parent

# Keep network fetches bounded by a generous parent-side timeout. The hard
# total includes all attempts, backoff and local checks, but never changes the
# pinned URL or requested revision.
FETCH_ATTEMPTS = 3
FETCH_ATTEMPT_TIMEOUT_SECONDS = 180
FETCH_CLEANUP_TIMEOUT_SECONDS = 1
FETCH_LOCAL_TIMEOUT_SECONDS = 5
FETCH_BACKOFF_SECONDS = (5, 10)
FETCH_TOTAL_BUDGET_SECONDS = (FETCH_ATTEMPTS * FETCH_ATTEMPT_TIMEOUT_SECONDS +
    FETCH_ATTEMPTS * 2 * FETCH_CLEANUP_TIMEOUT_SECONDS +
    sum(FETCH_BACKOFF_SECONDS) + 4 * FETCH_LOCAL_TIMEOUT_SECONDS)

_FETCH_PERMANENT_ERRORS = (
    'authentication failed', 'could not read username', 'could not read password',
    'permission denied (publickey)', 'certificate', 'ssl certificate',
    'tls alert', 'tls handshake', 'gnutls_handshake', 'couldn\'t find remote ref',
    'could not find remote ref', 'not our ref', 'not a valid object name',
    'bad object', 'repository not found', 'requested url returned error: 401',
    'requested url returned error: 403', 'requested url returned error: 404',
)
_FETCH_TRANSIENT_ERRORS = (
    'couldn\'t connect to server', 'failed to connect to', 'connection reset',
    'connection timed out', 'operation timed out', 'recv failure',
    'unexpected disconnect', 'early eof', 'remote end hung up',
    'requested url returned error: 502', 'requested url returned error: 503',
    'requested url returned error: 504',
)


def tracked_config_fragment(root, config_fragment):
    if config_fragment is None:
        return None
    root = Path(root).resolve()
    path = Path(config_fragment)
    if not path.is_absolute():
        path = root / path
    try:
        return path.resolve(strict=True).relative_to(root).as_posix()
    except ValueError as error:
        raise ValueError('kernel config fragment must be tracked under the source root') from error


def paired_kconfig_prelude(root, config_fragment):
    if not config_fragment:
        return None
    fragment = tracked_config_fragment(root, config_fragment)
    path = (Path(root) / fragment).with_suffix('.Kconfig')
    return path if path.is_file() else None


def external_kconfig_root(original, prelude):
    """Insert an earlier default after mainmenu in a generated build input.

    The source Kconfig is never edited. A hidden symbol cannot be selected by
    a .config seed; Kconfig's documented first-visible-default rule permits
    this adapter to select its value without patching the architecture tree.
    """
    lines = original.splitlines(keepends=True)
    entries = [i for i, line in enumerate(lines) if line.startswith(b'mainmenu ')]
    if len(entries) != 1:
        raise RuntimeError('expected exactly one root Kconfig mainmenu')
    position = entries[0] + 1
    return b''.join(lines[:position]) + b'\n' + prelude + b'\n' + b''.join(lines[position:])


def source_fingerprint(root=ROOT, config_fragment=None):
    root = Path(root)
    manifest_path = root / 'config/native-linux.json'
    defconfig_path = root / 'config/native-linux.defconfig'
    overlay = root / 'src/posix/lkl-overlay'
    digest = hashlib.sha256(manifest_path.read_bytes() + defconfig_path.read_bytes())
    if config_fragment:
        fragment = tracked_config_fragment(root, config_fragment)
        fragment_path = root / fragment
        digest.update(fragment.encode())
        digest.update(fragment_path.read_bytes())
        prelude = paired_kconfig_prelude(root, fragment)
        if prelude:
            digest.update(str(prelude.relative_to(root)).encode())
            digest.update(prelude.read_bytes())
    # The builder controls how these inputs become an artifact. Include the
    # exact script being executed so changes to that process invalidate proofs.
    digest.update(Path(__file__).resolve().read_bytes())
    for path in sorted(overlay.rglob('*')):
        if path.is_file():
            digest.update(str(path.relative_to(overlay)).encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()


def run(args, **kwargs):
    print('+', ' '.join(map(str, args)), flush=True)
    return subprocess.run(list(map(str, args)), check=True, **kwargs)


def git(repo, *args, **kwargs):
    return run(['git', '-C', repo, *args], **kwargs)


def output(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args], text=True).strip()


def wire_ker_builtin_adapters(source):
    """Add Ker's built-in LKL adapter objects to generated Kbuild input.

    The overlay copier intentionally refuses to replace upstream files. This
    narrowly appends Ker adapter objects to the architecture's existing obj-y list;
    include/net and all protocol implementation files remain byte-identical.
    """
    makefile = Path(source) / 'arch/lkl/kernel/Makefile'
    text = makefile.read_text()
    objects = ('ker_tcp_payload.o', 'ker_tcp_request_revoke.o',
        'ker_ff_admission_queue.o')
    for object_name in objects:
        if text.count(object_name):
            raise RuntimeError('generated LKL Makefile already wires ' + object_name)
    lines = text.splitlines(keepends=True)
    matches = [i for i, line in enumerate(lines) if line.startswith('obj-y = ')]
    if len(matches) != 1:
        raise RuntimeError('expected exactly one arch/lkl/kernel obj-y assignment')
    if lines and not lines[-1].endswith(('\n', '\r')):
        lines[-1] += '\n'
    lines.extend('obj-y += ' + object_name + '\n' for object_name in objects)
    makefile.write_text(''.join(lines))
    git(source, 'add', '--', 'arch/lkl/kernel/Makefile')


@contextmanager
def repository_lock(repo):
    # A shallow fetch computes its update before Git takes shallow.lock.
    # Serialize the complete presence-check/fetch across builder processes,
    # including callers reaching one bare cache through different symlinks.
    cache = Path(repo).resolve()
    cache.parent.mkdir(parents=True, exist_ok=True)
    with (cache.parent / (cache.name + '.fetch.lock')).open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def fetch(repo, url, revision):
    with repository_lock(repo):
        # Disable detached maintenance before inspecting or fetching this cache.
        git(repo, 'config', 'gc.auto', '0', timeout=FETCH_LOCAL_TIMEOUT_SECONDS)
        git(repo, 'config', 'maintenance.auto', 'false', timeout=FETCH_LOCAL_TIMEOUT_SECONDS)
        present = subprocess.run(['git', '-C', str(repo), 'cat-file', '-e', revision + '^{commit}'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=FETCH_LOCAL_TIMEOUT_SECONDS)
        if present.returncode:
            command = ['git', '-C', str(repo), 'fetch', '--depth=1', '--no-tags', url, revision]
            print(f'native fetch budget attempts={FETCH_ATTEMPTS} '
                f'attempt_timeout_s={FETCH_ATTEMPT_TIMEOUT_SECONDS} '
                f'backoff_s={FETCH_BACKOFF_SECONDS} total_subprocess_budget_s='
                f'{FETCH_TOTAL_BUDGET_SECONDS}', flush=True)
            last_error = None
            for attempt in range(1, FETCH_ATTEMPTS + 1):
                started = monotonic()
                print(f'native fetch attempt={attempt}/{FETCH_ATTEMPTS} '
                    f'revision={revision} timeout_s={FETCH_ATTEMPT_TIMEOUT_SECONDS}',
                    flush=True)
                try:
                    result = _run_fetch_attempt(command, FETCH_ATTEMPT_TIMEOUT_SECONDS)
                    elapsed = monotonic() - started
                    diagnostic = ((result.stdout or '') + '\n' + (result.stderr or '')).strip()
                    if result.returncode == 0:
                        print(f'native fetch attempt={attempt}/{FETCH_ATTEMPTS} '
                            f'result=success elapsed_s={elapsed:.3f}', flush=True)
                        last_error = None
                        break
                    classification = _classify_fetch_error(diagnostic)
                    excerpt = ' '.join(diagnostic.split())[:1000]
                    print(f'native fetch attempt={attempt}/{FETCH_ATTEMPTS} '
                        f'result=failed class={classification} rc={result.returncode} '
                        f'elapsed_s={elapsed:.3f} diagnostic={excerpt}', flush=True)
                    last_error = subprocess.CalledProcessError(result.returncode,
                        command, output=result.stdout, stderr=result.stderr)
                    if classification != 'transient' or attempt == FETCH_ATTEMPTS:
                        raise last_error
                except subprocess.TimeoutExpired as error:
                    elapsed = monotonic() - started
                    output = error.output or ''
                    stderr = error.stderr or ''
                    if isinstance(output, bytes): output = output.decode(errors='replace')
                    if isinstance(stderr, bytes): stderr = stderr.decode(errors='replace')
                    diagnostic = (str(output) + '\n' + str(stderr)).strip()
                    excerpt = ' '.join(diagnostic.split())[:1000]
                    classification = _classify_fetch_error(diagnostic)
                    print(f'native fetch attempt={attempt}/{FETCH_ATTEMPTS} '
                        f'result=timeout class={classification} elapsed_s={elapsed:.3f} '
                        f'diagnostic={excerpt}', flush=True)
                    last_error = error
                    if classification == 'permanent':
                        raise
                    if attempt == FETCH_ATTEMPTS:
                        raise
                if last_error is not None:
                    delay = FETCH_BACKOFF_SECONDS[attempt - 1]
                    print(f'native fetch retry revision={revision} '
                        f'backoff_s={delay:.3f}', flush=True)
                    sleep(delay)
            if last_error is None:
                verified = subprocess.run(['git', '-C', str(repo), 'cat-file', '-e',
                    revision + '^{commit}'], stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, timeout=FETCH_LOCAL_TIMEOUT_SECONDS)
                if verified.returncode:
                    raise RuntimeError('git fetch reported success but requested commit is absent: ' +
                        revision)


def _run_fetch_attempt(command, timeout):
    """Run one fetch in an owned process group and reap it on deadline.

    Git may leave a transport helper holding the pipes when only the git
    parent is killed. The fresh session lets timeout cleanup target this
    command tree without signalling unrelated processes.
    """
    process = subprocess.Popen(command, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        stdout, stderr = _stop_fetch_process_group(process, error.output, error.stderr)
        raise subprocess.TimeoutExpired(command, timeout, output=stdout,
            stderr=stderr or error.stderr) from error
    except BaseException:
        # Signals/cancellation must not leave a network operation running
        # after its owner unwinds.
        _stop_fetch_process_group(process)
        raise
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def _stop_fetch_process_group(process, output=None, stderr=None):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    # The helper is expected to share the group's pipes. Keep cleanup bounded
    # even if a detached descendant unexpectedly retained a pipe: close local
    # readers and wait for the owned git parent directly.
    try:
        return process.communicate(timeout=FETCH_CLEANUP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as error:
        output = error.output or output
        stderr = error.stderr or stderr
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
        if process.poll() is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
        try:
            process.wait(timeout=FETCH_CLEANUP_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired as wait_error:
            raise RuntimeError('could not reap bounded native fetch process') from wait_error
        return output, stderr


def _classify_fetch_error(diagnostic):
    lowered = diagnostic.lower()
    if any(marker in lowered for marker in _FETCH_PERMANENT_ERRORS):
        return 'permanent'
    if any(marker in lowered for marker in _FETCH_TRANSIENT_ERRORS):
        return 'transient'
    return 'unclassified'


@contextmanager
def artifact_lock(build):
    """Serialize source preparation, compilation and proof publication per output."""
    build = Path(build).resolve()
    build.mkdir(parents=True, exist_ok=True)
    # Keep this inode stable across invocations; never unlink an advisory lock.
    with (build / '.ker-native-build.lock').open('a+') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(stream, fcntl.LOCK_UN)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path,
        default=Path(os.environ.get('XDG_CACHE_HOME', Path.home() / '.cache')) / 'ker/native-linux.git')
    parser.add_argument('--build', type=Path, default=ROOT / 'build-native-linux')
    parser.add_argument('--jobs', type=int, default=min(os.cpu_count() or 1, 16))
    parser.add_argument('--config-fragment', type=Path,
        help='additional tracked kernel options for an isolated test profile')
    parser.add_argument('--print-fingerprint', action='store_true',
        help='print the input fingerprint without reading or changing build artifacts')
    parser.add_argument('--fingerprint-root', type=Path, default=ROOT,
        help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.print_fingerprint:
        print(source_fingerprint(args.fingerprint_root, args.config_fragment))
        return
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        parser.error('the native POSIX backend currently supports x86_64 Linux')
    if args.jobs < 1:
        parser.error('--jobs must be positive')
    with artifact_lock(args.build):
        build_artifacts(args)


def build_artifacts(args):
    if args.config_fragment:
        args.config_fragment = Path(tracked_config_fragment(ROOT, args.config_fragment))
    manifest_path = ROOT / 'config/native-linux.json'
    manifest = json.loads(manifest_path.read_text())
    overlay = ROOT / 'src/posix/lkl-overlay'
    fingerprint = source_fingerprint(ROOT, args.config_fragment)
    cache = args.cache.resolve()
    build = args.build.resolve()
    build.mkdir(parents=True, exist_ok=True)
    with repository_lock(cache):
        if not cache.exists():
            run(['git', 'init', '--bare', cache])
    linux = manifest['linux']
    lkl = manifest['lkl']
    fetch(cache, linux['repository'], linux['revision'])
    fetch(cache, lkl['repository'], lkl['base_revision'])
    fetch(cache, lkl['repository'], lkl['revision'])
    # Refuse any LKL fork change to protocol sources before constructing the tree.
    git(cache, 'diff', '--exit-code', lkl['base_revision'], lkl['revision'], '--',
        *manifest['protocol_paths'])
    source = build / ('source-' + fingerprint[:16])
    prepared = build / ('prepared-' + fingerprint[:16] + '.json')
    if not source.exists():
        git(cache, 'worktree', 'add', '--detach', source, linux['revision'])
        patch = subprocess.check_output(['git', '-C', str(cache), 'diff', '--binary',
            lkl['base_revision'], lkl['revision']])
        git(source, 'apply', '--3way', '--whitespace=nowarn', input=patch)
        for path in sorted(overlay.rglob('*')):
            if path.is_file():
                target = source / path.relative_to(overlay)
                if target.exists():
                    raise RuntimeError('Ker overlay would replace an upstream file: ' + str(target))
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, target)
                git(source, 'add', '--', target.relative_to(source))
        wire_ker_builtin_adapters(source)
        tree = output(source, 'write-tree')
        prepared.write_text(json.dumps({'fingerprint': fingerprint, 'tree': tree}, indent=2) + '\n')
    expected = json.loads(prepared.read_text())
    if expected['fingerprint'] != fingerprint or output(source, 'write-tree') != expected['tree']:
        raise RuntimeError('generated source index differs from the recorded pinned preparation')
    git(source, 'diff', '--exit-code')
    git(source, 'diff', '--cached', '--exit-code', linux['revision'], '--', *manifest['protocol_paths'])
    kernel = build / ('kernel-' + fingerprint[:16])
    kernel.mkdir(exist_ok=True)
    env = dict(os.environ, OUTPUT=str(kernel))
    prelude = paired_kconfig_prelude(ROOT, args.config_fragment)
    if prelude:
        config_root = kernel / 'Kconfig.ker-profile'
        config_root.write_bytes(external_kconfig_root((source / 'Kconfig').read_bytes(), prelude.read_bytes()))
        env['KBUILD_KCONFIG'] = str(config_root)
    run(['make', '-C', source / 'tools/lkl', 'conf'], env=env)
    if not (kernel / '.config').exists():
        seed = (ROOT / 'config/native-linux.defconfig').read_bytes()
        if args.config_fragment:
            fragment_path = args.config_fragment
            if not fragment_path.is_absolute():
                fragment_path = ROOT / fragment_path
            seed += b'\n' + fragment_path.read_bytes()
        host = (kernel / 'tools/lkl/kernel.config').read_bytes()
        (kernel / '.config').write_bytes(seed + b'\n' + host)
    run(['make', '-C', source, 'ARCH=lkl', 'O=' + str(kernel), 'olddefconfig'], env=env)
    tools = kernel / 'tools/lkl'
    run(['make', '-C', source / 'tools/lkl', '-j', args.jobs,
        tools / 'liblkl.a', tools / 'lib/hijack/liblkl-hijack.so'], env=env)
    git(source, 'diff', '--exit-code')
    if output(source, 'write-tree') != expected['tree']:
        raise RuntimeError('generated source index changed during the build')
    git(source, 'diff', '--cached', '--exit-code', linux['revision'], '--', *manifest['protocol_paths'])
    release = subprocess.check_output(['make', '-s', '-C', str(source), 'ARCH=lkl',
        'O=' + str(kernel), 'kernelrelease'], text=True).strip()
    proof = {'schema': 1, 'linux': linux, 'lkl': lkl, 'fingerprint': fingerprint,
        'source': str(source), 'kernel': str(kernel), 'release': release,
        'source_tree': expected['tree'],
        'net_tree': output(cache, 'rev-parse', linux['revision'] + ':net'),
        'include_net_tree': output(cache, 'rev-parse', linux['revision'] + ':include/net'),
        'config_sha256': hashlib.sha256((kernel / '.config').read_bytes()).hexdigest(),
        'library_sha256': hashlib.sha256((tools / 'liblkl.a').read_bytes()).hexdigest()}
    if args.config_fragment:
        proof['config_fragment'] = args.config_fragment.as_posix()
    if prelude:
        proof['kconfig_prelude'] = str(prelude.relative_to(ROOT))
        proof['kconfig_prelude_sha256'] = hashlib.sha256(prelude.read_bytes()).hexdigest()
        proof['kconfig_root_sha256'] = hashlib.sha256(config_root.read_bytes()).hexdigest()
    (build / 'native-linux.json').write_text(json.dumps(proof, indent=2) + '\n')
    print('Native Linux artifacts and protocol provenance:', build / 'native-linux.json')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        sys.exit('native Linux build failed: ' + str(error))
