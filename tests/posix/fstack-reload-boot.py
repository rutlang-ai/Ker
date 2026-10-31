#!/usr/bin/env python3
"""Original boot assertions, real four-ring consumer and startup failure controls."""
import argparse
import os
from pathlib import Path
import re
import subprocess
import tempfile
from dpdk_runtime import private_runtime_environment


def require(value, message):
    if not value:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app', type=Path, required=True)
    parser.add_argument('--pmd-root', type=Path, required=True)
    parser.add_argument('--profile', choices=('source', 'no-hook', 'dirty-start', 'consumer'), required=True)
    parser.add_argument('--install-example-from', type=Path)
    parser.add_argument('--install-bindir', default='bin')
    parser.add_argument('--install-libdir', default='lib')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='ker-reload-boot-') as temporary:
        root = Path(temporary); app = args.app.resolve()
        if args.install_example_from:
            require(args.profile == 'consumer' and not Path(args.install_bindir).is_absolute()
                    and '..' not in Path(args.install_bindir).parts
                    and not Path(args.install_libdir).is_absolute()
                    and '..' not in Path(args.install_libdir).parts, 'invalid independent installation')
            prefix = root / 'installed'
            subprocess.run(['cmake', '--install', str(args.install_example_from), '--prefix', str(prefix),
                            '--component', 'reload-frame-example'], check=True)
            app = prefix / args.install_bindir / app.name
            require(app.is_file(), 'reload-frame caller not installed')
            licenses = list(prefix.rglob('LICENSE'))
            require(len(licenses) == 1 and licenses[0].read_bytes() ==
                    (Path(__file__).resolve().parents[2] / 'third_party/fstack-reload/LICENSE').read_bytes(),
                    'original reload license not installed intact')
        env = private_runtime_environment(root / 'dpdk')
        env['LD_LIBRARY_PATH'] = str(args.pmd_root) + ':' + env.get('LD_LIBRARY_PATH', '')
        if args.install_example_from:
            env['LD_LIBRARY_PATH'] = str(prefix / args.install_libdir) + ':' + env['LD_LIBRARY_PATH']
        if args.profile == 'consumer':
            cpu = min(os.sched_getaffinity(0))
            for length in (64, 4096, 9014):
                frame = bytes.fromhex('02000000000202000000000188b5') + bytes(
                    (i * 13 + 5) % 256 for i in range(length - 14))
                source, target = root / 'input.bin', root / 'output.bin'; source.write_bytes(frame)
                result = subprocess.run([str(app), f'--lcores=0@{cpu}', '--no-huge', '--no-pci', '--no-shconf',
                    '--no-telemetry', '--iova-mode=va', '-m', '64', f'--file-prefix=reload-boot-{os.getpid()}-{length}',
                    '--', str(source), str(target)], env=env, cwd=root, capture_output=True, text=True, timeout=30)
                require(result.returncode == 0, 'actual reload-frame consumer failed: ' + result.stdout + result.stderr)
                require(target.read_bytes() == frame, 'four-ring cycle changed independently supplied bytes')
                require(result.stdout.count('RELOAD_BOOT_READY attached=1 owner=0 ports=1 rings=4 hooks=1 tx=0') == 1,
                        'missing actual boot baseline: ' + result.stdout)
                require(re.findall(r'RELOAD_FRAME_CYCLE bytes=(\d+) segments=(\d+) rings=4 handovers=2 tx=2 rx=3 pool=511',
                                   result.stdout) == [(str(length), str((length + 383) // 384))],
                        'missing actual four-ring/counter/ownership evidence: ' + result.stdout)
            print('PASS: original PMD and all four drain rings consumed exact64/4096/9014-byte frames after clean boot')
        else:
            result = subprocess.run([str(app)], env=env, cwd=root, capture_output=True, text=True, timeout=30)
            if args.profile == 'source':
                marker = 'RELOAD_BOOT_SOURCE test_it_a09_boot_state cycles=5 boot_tx=0 hooks=1 transfer_tx=2 transfer_rx=3 pool=511'
                require(result.returncode == 0 and result.stdout.count(marker) == 1,
                        'complete source boot assertions failed: ' + result.stdout + result.stderr)
                print('PASS: complete original boot function and five actual lifecycle/traffic cycles')
            else:
                marker, assertion = (('RELOAD_BOOT_HOOK_ALLOCATION_FAILED', 'source_start()')
                    if args.profile == 'no-hook' else ('RELOAD_BOOT_PREMATURE_TX', 'example_reload_cycle_tx_calls(cycle)'))
                require(result.returncode == 1 and marker in result.stderr and assertion in result.stderr
                        and 'check failed:' in result.stderr and 'RELOAD_BOOT_SOURCE' not in result.stdout,
                        'boot mutation did not fail its original assertion: ' + result.stdout + result.stderr)
                print('PASS: rejected boot mutation ' + args.profile)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
