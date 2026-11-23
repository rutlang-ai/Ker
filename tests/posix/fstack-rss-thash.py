#!/usr/bin/env python3
"""Validate deterministic full-loop quality and mandatory EAL/solver failures."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app', type=Path, required=True)
    parser.add_argument('--negative-app', type=Path, required=True)
    parser.add_argument('--evidence', type=Path)
    args = parser.parse_args()
    evidence = {'families': {}, 'negative_controls': {}, 'host_hugepages_modified': False}
    with tempfile.TemporaryDirectory(prefix='ker-thash-') as directory:
        def run(app, mode):
            with tempfile.TemporaryDirectory(dir=directory) as runtime:
                env = dict(os.environ, RUNTIME_DIRECTORY=runtime, XDG_RUNTIME_DIR=runtime)
                result = subprocess.run([str(app), mode], env=env, text=True,
                                        capture_output=True, timeout=30)
                return {'returncode': result.returncode, 'stdout': result.stdout,
                        'stderr': result.stderr}
        for family in ('ipv4', 'ipv6'):
            runs = [run(args.app, family) for _ in range(2)]
            for result in runs:
                require(result['returncode'] == 0 and
                        f'PASS: original {family} thash assertions' in result['stdout'],
                        f'{family} original assertions failed: {result}')
                require('skipping' not in result['stdout'].lower(), 'source case skipped')
            require(runs[0]['stdout'] == runs[1]['stdout'],
                    f'{family} fixed seeds did not reproduce the measured rates')
            rows = re.findall(r'reta=(128|512): adjust_tuple_ok=(\d+)/200 .*?'
                              r'FULL-LOOP final landing=(\d+)/200', runs[0]['stdout'])
            require(len(rows) == 2 and {r[0] for r in rows} == {'128', '512'} and
                    all(int(r[1]) > 0 and r[2] == '200' for r in rows),
                    f'{family} failed required two-RETA full-loop quality: {rows}')
            evidence['families'][family] = {'runs': runs, 'reta_rows': rows,
                                           'contexts_freed_and_eal_cleaned': True}
            negative = run(args.negative_app, family)
            require(negative['returncode'] != 0 and
                    'check failed: adj128 > 0' in negative['stderr'] and
                    'PASS: original' not in negative['stdout'],
                    f'{family} rejected solver results did not fail the source gate: {negative}')
            evidence['negative_controls'][family] = negative
        invalid = run(args.app, 'invalid-eal')
        require(invalid['returncode'] != 0 and
                ('check failed: rte_eal_init(2, bad) >= 0' in invalid['stderr'] or
                 'unknown argument --ker-invalid-eal-option' in invalid['stderr'])
                and 'PASS: original' not in invalid['stdout'],
                f'actual EAL argument failure was accepted or skipped: {invalid}')
        evidence['negative_controls']['invalid_eal'] = invalid
    if args.evidence:
        with args.evidence.open('x') as output:
            json.dump(evidence, output, indent=2)
            output.write('\n')
    print('PASS: IPv4/IPv6 fixed-seed 200/200 full loops; solver rejection and EAL failure remain fatal')


if __name__ == '__main__':
    main()
