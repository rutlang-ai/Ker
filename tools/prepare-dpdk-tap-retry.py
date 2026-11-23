#!/usr/bin/env python3
"""Prepare an isolated, pinned DPDK tree with the TAP ownership fix.

Never modifies the checked-out dependency. The output must be a new directory;
use KER_DPDK_SOURCE_DIR with tools/build-dpdk.sh to build it separately.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

PIN = 'd129414711aa7c4954f997acf4c54338574a7d92'


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=root / 'third_party/dpdk')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    patch = root / 'compat/dpdk/tap-tx-retry.patch'
    # Archive the immutable commit, ignoring any local build products/edits.
    commit = subprocess.check_output(['git', '-C', str(args.source), 'rev-parse', PIN + '^{commit}'], text=True).strip()
    if commit != PIN:
        raise RuntimeError('unexpected DPDK commit')
    output = args.output.resolve()
    if output.is_relative_to(root) or output.is_relative_to(args.source.resolve()):
        raise RuntimeError("output must be outside Ker and dependency source trees")
    if output.exists():
        raise RuntimeError('output must not already exist: ' + str(output))
    output.mkdir(parents=True)
    with tempfile.TemporaryFile() as archive:
        subprocess.run(['git', '-C', str(args.source), 'archive', PIN], stdout=archive, check=True)
        archive.seek(0)
        subprocess.run(['tar', '-x', '-C', str(output)], stdin=archive, check=True)
    subprocess.run(['git', 'apply', '--check', str(patch)], cwd=output, check=True)
    subprocess.run(['git', 'apply', str(patch)], cwd=output, check=True)
    manifest = {'upstream_commit': PIN, 'patch_sha256': hashlib.sha256(patch.read_bytes()).hexdigest(),
                'tap_source_sha256': hashlib.sha256((output / 'drivers/net/tap/rte_eth_tap.c').read_bytes()).hexdigest(),
                'compatibility_abi': 'ker_dpdk_tap_tx_retry_abi=1'}
    (output / 'ker-tap-retry-provenance.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(output)


if __name__ == '__main__':
    main()
