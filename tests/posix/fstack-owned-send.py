#!/usr/bin/env python3
"""Real owned-input conversion failures and original PMD caller qualification."""
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
    parser.add_argument('--profile', choices=('null', 'copy', 'no-free', 'copy-success', 'consumer'), required=True)
    parser.add_argument('--install-example-from', type=Path)
    parser.add_argument('--install-bindir', default='bin')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='ker-owned-frame-') as temporary:
        root = Path(temporary)
        app = args.app.resolve()
        if args.install_example_from:
            require(args.profile == 'consumer' and not Path(args.install_bindir).is_absolute()
                    and '..' not in Path(args.install_bindir).parts, 'invalid independent installation profile')
            prefix = root / 'installed'
            subprocess.run(['cmake', '--install', str(args.install_example_from), '--prefix', str(prefix),
                            '--component', 'owned-frame-example'], check=True)
            app = prefix / args.install_bindir / app.name
            require(app.is_file(), 'owned caller executable not installed')
            licenses = list(prefix.rglob('LICENSE'))
            require(len(licenses) == 1 and licenses[0].read_bytes() ==
                    (Path(__file__).resolve().parents[2] / 'third_party/fstack-owned-send/LICENSE').read_bytes(),
                    'original owned-send license not installed intact')
        env = private_runtime_environment(root / 'dpdk')
        env['LD_LIBRARY_PATH'] = str(args.pmd_root) + ':' + env.get('LD_LIBRARY_PATH', '')
        if args.profile == 'consumer':
            cpu = min(os.sched_getaffinity(0))
            for length in (64, 4096, 9014):
                # Experimental Ethernet payload, with no synthetic TCP/IP behavior.
                frame = bytes.fromhex('02000000000202000000000188b5') + bytes(
                    (i * 7 + 13) % 256 for i in range(length - 14))
                source, target = root / 'input.bin', root / 'output.bin'
                source.write_bytes(frame)
                command = [str(app), f'--lcores=0@{cpu}', '--no-huge', '--no-pci', '--no-shconf',
                           '--no-telemetry', '--iova-mode=va', '-m', '64',
                           f'--file-prefix=owned-{os.getpid()}-{length}', '--', str(source), str(target)]
                result = subprocess.run(command, env=env, cwd=root, capture_output=True, text=True, timeout=30)
                require(result.returncode == 0, 'actual PMD caller failed: ' + result.stdout + result.stderr)
                require(target.read_bytes() == frame, 'original PMD output differs from the independent input')
                require(re.findall(r'OWNED_FRAME_FORWARDED bytes=(\d+) segments=(\d+) tx=1 rx=1 pool=511',
                                   result.stdout) == [(str(length), str((length + 383) // 384))],
                        'missing exact caller/PMD/chain/pool evidence: ' + result.stdout)
            print('PASS: actual owned-frame caller; exact 64/4096/9014-byte original PMD exchanges and pool511')
        else:
            mode = 'copy' if args.profile in ('copy', 'copy-success') else 'null'
            result = subprocess.run([str(app), mode], env=env, cwd=root, capture_output=True, text=True, timeout=30)
            if args.profile in ('no-free', 'copy-success'):
                marker = 'OWNED_INPUT_FREE_SUPPRESSED' if args.profile == 'no-free' else 'OWNED_COPY_FALSE_SUCCESS'
                assertion = ('rte_mempool_avail_count(fixture.pool) == 511' if args.profile == 'no-free' else
                             '(rv) == (-1)')
                require(result.returncode == 1 and marker in result.stderr and assertion in result.stderr
                        and 'OWNED_SOURCE_CASE' not in result.stdout,
                        'negative control did not fail its source/ownership assertion: ' + result.stdout + result.stderr)
                print('PASS: rejected owned-send mutation ' + args.profile)
            else:
                source_case = ('test_ff_dpdk_if_send_copydata_fail' if mode == 'copy' else
                               'test_ff_dpdk_if_send_null_ctx_with_mbuf')
                marker = 'OWNED_SOURCE_CASE ' + source_case + ' exact_cleanup=true failure_tx=0 failure_rx=0 recovery_tx=1 recovery_rx=1 unique_pool=511'
                require(result.returncode == 0 and result.stdout.count(marker) == 1,
                        'complete source contract/cleanup failed: ' + result.stdout + result.stderr)
                print('PASS: ' + source_case + '; actual owned-input cleanup and zero PMD output')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
