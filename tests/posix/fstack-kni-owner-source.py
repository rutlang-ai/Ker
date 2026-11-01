#!/usr/bin/env python3
"""Run retained KNI owner assertions with only the original net_ring PMD."""
import argparse
from pathlib import Path
import subprocess
import tempfile
from dpdk_runtime import private_runtime_environment


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app', type=Path, required=True)
    parser.add_argument('--pmd-root', type=Path, required=True)
    parser.add_argument('--profile', choices=('owner', 'short-tx'), default='owner')
    args = parser.parse_args()
    modules = list(args.pmd_root.glob('dpdk/pmds-*/librte_net_ring.so'))
    if len(modules) != 1:
        raise RuntimeError('exactly one original net_ring PMD is required')
    with tempfile.TemporaryDirectory(prefix='ker-kni-owner-source-') as temporary:
        root = Path(temporary)
        env = private_runtime_environment(root / 'dpdk')
        env['LD_PRELOAD'] = str(modules[0])
        env['LD_LIBRARY_PATH'] = str(args.pmd_root) + ':' + env.get('LD_LIBRARY_PATH', '')
        command = [str(args.app.resolve())]
        if args.profile == 'short-tx':
            command.append('short-tx')
        result = subprocess.run(command, cwd=root, env=env,
                                capture_output=True, text=True, timeout=30)
        marker = ('PASS: original KNI short-TX contract and real net_ring sink recovery'
                  if args.profile == 'short-tx' else
                  'PASS: original KNI future owner activation and nonowner contracts')
        if result.returncode or result.stdout.count(marker) != 1:
            raise RuntimeError('retained KNI ' + args.profile + ' assertions failed, exit=' +
                               str(result.returncode) + ':\n' + result.stdout + result.stderr)
    print('PASS: original KNI ' + args.profile + ' assertions on net_ring')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
