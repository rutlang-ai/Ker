#!/usr/bin/env python3
"""Audit the pinned upstream tests without executing upstream code.

Catalog integrity is separate from compatibility completion. --require-complete
fails while any case is blocked; a successful default audit is NOT a test pass
for those cases or for the retained upstream harnesses.
"""
import argparse
import ast
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sys

STATES = {'scenario-adapted', 'blocked', 'architecture-specific', 'harness-only', 'partial'}
SHELL_ENTRIES = {
    'tests/integration/test_graceful_reload.sh': 'shell-e2e',
    'tests/integration/test_mtu.sh': 'manual-checklist',
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def source_cases(snapshot, files):
    result = {}
    for name in sorted(files):
        path = snapshot / name
        if path.suffix == '.c' and path.name.startswith('test'):
            text = path.read_text()
            # Remove comments before scanning registrations; never execute tests
            # or import the Python test module to discover its cases.
            text = re.sub(r'/\*.*?\*/|//[^\n]*', '', text, flags=re.S)
            macros = re.findall(r'\b(cmocka_unit_test\w*)\s*\(', text)
            require(set(macros) <= {'cmocka_unit_test', 'cmocka_unit_test_setup_teardown'},
                    f'Unrecognized registration macro in {name}: {set(macros)}')
            cases = re.findall(r'cmocka_unit_test(?:_setup_teardown)?\(\s*([A-Za-z_]\w*)', text)
            require(len(cases) == len(macros), f'Unparsed registration in {name}')
            require(len(cases) == len(set(cases)), f'Duplicate registration in {name}')
            for case in cases:
                result[name + '::' + case] = 'cmocka'
        elif path.suffix == '.py' and path.name.startswith('test'):
            for cls in ast.parse(path.read_text()).body:
                if isinstance(cls, ast.ClassDef):
                    for method in cls.body:
                        if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)) and method.name.startswith('test_'):
                            case = name + '::' + cls.name + '.' + method.name
                            require(case not in result, f'Duplicate Python case: {case}')
                            result[case] = 'python-unittest'
        elif name in SHELL_ENTRIES:
            result[name + '::entrypoint'] = SHELL_ENTRIES[name]
    return result


def validate(root):
    manifest = json.loads((root / 'tests/fstack-migration.json').read_text())
    require(manifest['schema'] == 1, 'Unsupported migration schema')
    require(manifest['revision'] == '646a641cfff77f4815e1e29829a09e1ed15a2999',
            'Upstream pin changed; explicitly review/rebuild the whole catalog')
    require(manifest['source_root'] == 'tests/upstream/fstack', 'Unexpected snapshot root')
    snapshot = root / manifest['source_root']
    files = manifest['files']
    actual = set()
    for path in snapshot.rglob('*'):
        require(not path.is_symlink(), f'Symlink in upstream snapshot: {path}')
        if path.is_file():
            actual.add(path.relative_to(snapshot).as_posix())
    require(actual == set(files), f'Snapshot file mismatch: missing={set(files)-actual}, extra={actual-set(files)}')
    for name, proof in files.items():
        path = Path(name)
        require(not path.is_absolute() and '..' not in path.parts, f'Unsafe snapshot path: {name}')
        require(name == 'LICENSE' or name.startswith('tests/'), f'Out-of-scope snapshot file: {name}')
        data = (snapshot / name).read_bytes()
        blob = b'blob ' + str(len(data)).encode() + b'\0' + data
        require(hashlib.sha1(blob).hexdigest() == proof['git_blob'], f'Git blob mismatch: {name}')
        require(hashlib.sha256(data).hexdigest() == proof['sha256'], f'SHA256 mismatch: {name}')
        require(bool((snapshot / name).stat().st_mode & 0o111) == proof['executable'],
                f'Executable mode mismatch: {name}')
    discovered = source_cases(snapshot, files)
    records = manifest['cases']
    ids = [item['id'] for item in records]
    require(len(ids) == len(set(ids)), 'Duplicate catalog case ID')
    require(set(ids) == set(discovered),
            f'Case mismatch: missing={set(discovered)-set(ids)}, extra={set(ids)-set(discovered)}')
    cmake = [root / 'CMakeLists.txt', root / 'tests/CMakeLists.txt', *(root / 'cmake').glob('*.cmake')]
    ctests = set()
    for path in cmake:
        text = path.read_text()
        ctests.update(re.findall(r'add_test\(\s*NAME\s+([\w-]+)\s', text))
        # Table-driven fstack-adapted scenarios are actual CTests too.
        if 'add_test(NAME fstack-${fstack_case} ' in text:
            for values in re.findall(r'foreach\(fstack_case\s+([^)]*)\)', text):
                ctests.update('fstack-' + value for value in values.split())
    provenance = json.loads((root / 'tests/fstack-provenance.json').read_text())
    require(provenance['revision'] == manifest['revision'], 'Provenance and snapshot pins differ')
    for item in records:
        require(item['kind'] == discovered[item['id']], f'Wrong case kind: {item["id"]}')
        require(item['status'] in STATES, f'Unknown status: {item["id"]}')
        require(item['reason'].strip(), f'Missing disposition: {item["id"]}')
        links = item['ker_tests']
        if item['status'] in ('scenario-adapted', 'partial'):
            require(links, f'Adapted case has no runnable Ker test: {item["id"]}')
        else:
            require(not links, f'Unadapted case has ambiguous pass mappings: {item["id"]}')
        if item['status'] == 'partial':
            require(item.get('remaining', '').strip(), f'Missing partial-coverage boundary: {item["id"]}')
        for link in links:
            require(link['ctest'] in ctests, f'Missing CTest {link["ctest"]} for {item["id"]}')
            require(link['provenance_case'] in provenance['cases'], f'Missing provenance: {item["id"]}')
            proof = provenance['cases'][link['provenance_case']]
            source_file, source_case = item['id'].split('::', 1)
            require(proof.get('source_file') == source_file,
                    f'Provenance source file mismatch: {item["id"]} -> {link["provenance_case"]}')
            cases = proof.get('source_case', [])
            if isinstance(cases, str):
                cases = [cases]
            require(source_case in cases,
                    f'Provenance source case mismatch: {item["id"]} -> {link["provenance_case"]}')
    return manifest, Counter(item['status'] for item in records)


def report(manifest, counts):
    print(f'Catalog integrity verified: {len(manifest["files"])} pinned files, {len(manifest["cases"])} entrypoints/cases')
    for state in sorted(STATES):
        print(f'  {state}: {counts[state]}')
    print('This is an inventory audit, not compatibility passes for every catalog entry. Upstream code was not executed.')
    print('Blocked cases remain incomplete; architecture-specific and harness-only entries are not Ker passes.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--require-complete', action='store_true')
    args = parser.parse_args()
    try:
        manifest, counts = validate(args.root)
        report(manifest, counts)
        if args.require_complete and (counts['blocked'] or counts['partial']):
            print(f'Migration incomplete: {counts["blocked"]} blocked + {counts["partial"]} partial cases', file=sys.stderr)
            return 2
        return 0
    except (ValueError, KeyError, OSError, SyntaxError) as error:
        print(f'F-Stack catalog invalid: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
