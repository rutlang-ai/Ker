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
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent


def source_fingerprint(root=ROOT):
    root = Path(root)
    manifest_path = root / 'config/native-linux.json'
    defconfig_path = root / 'config/native-linux.defconfig'
    overlay = root / 'src/posix/lkl-overlay'
    digest = hashlib.sha256(manifest_path.read_bytes() + defconfig_path.read_bytes())
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


def wire_ker_tcp_payload(source):
    """Add Ker's one built-in LKL adapter object to generated Kbuild input.

    The overlay copier intentionally refuses to replace upstream files. This
    narrowly appends one object to the architecture's existing obj-y list;
    include/net and all protocol implementation files remain byte-identical.
    """
    makefile = Path(source) / 'arch/lkl/kernel/Makefile'
    text = makefile.read_text()
    if text.count('ker_tcp_payload.o'):
        raise RuntimeError('generated LKL Makefile already wires ker_tcp_payload.o')
    lines = text.splitlines(keepends=True)
    matches = [i for i, line in enumerate(lines) if line.startswith('obj-y = ')]
    if len(matches) != 1:
        raise RuntimeError('expected exactly one arch/lkl/kernel obj-y assignment')
    if lines and not lines[-1].endswith(('\n', '\r')):
        lines[-1] += '\n'
    lines.append('obj-y += ker_tcp_payload.o\n')
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
        git(repo, 'config', 'gc.auto', '0')
        git(repo, 'config', 'maintenance.auto', 'false')
        present = subprocess.run(['git', '-C', str(repo), 'cat-file', '-e', revision + '^{commit}'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if present.returncode:
            git(repo, 'fetch', '--depth=1', '--no-tags', url, revision)


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
    parser.add_argument('--print-fingerprint', action='store_true',
        help='print the input fingerprint without reading or changing build artifacts')
    parser.add_argument('--fingerprint-root', type=Path, default=ROOT,
        help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.print_fingerprint:
        print(source_fingerprint(args.fingerprint_root))
        return
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        parser.error('the native POSIX backend currently supports x86_64 Linux')
    if args.jobs < 1:
        parser.error('--jobs must be positive')
    with artifact_lock(args.build):
        build_artifacts(args)


def build_artifacts(args):
    manifest_path = ROOT / 'config/native-linux.json'
    manifest = json.loads(manifest_path.read_text())
    overlay = ROOT / 'src/posix/lkl-overlay'
    fingerprint = source_fingerprint(ROOT)
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
        wire_ker_tcp_payload(source)
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
    run(['make', '-C', source / 'tools/lkl', 'conf'], env=env)
    if not (kernel / '.config').exists():
        seed = (ROOT / 'config/native-linux.defconfig').read_bytes()
        host = (kernel / 'tools/lkl/kernel.config').read_bytes()
        (kernel / '.config').write_bytes(seed + b'\n' + host)
    run(['make', '-C', source, 'ARCH=lkl', 'O=' + str(kernel), 'olddefconfig'])
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
    (build / 'native-linux.json').write_text(json.dumps(proof, indent=2) + '\n')
    print('Native Linux artifacts and protocol provenance:', build / 'native-linux.json')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        sys.exit('native Linux build failed: ' + str(error))
