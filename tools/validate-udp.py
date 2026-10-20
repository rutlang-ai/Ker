#!/usr/bin/env python3
"""Run every declared UDP CTest and report functional passes separately from gaps."""
import argparse
from collections import Counter
import json
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET


KINDS = {'functional', 'unsupported-boundary', 'manual'}


def selected_tests(matrix, registered):
    features = matrix['features']
    ids = [feature['id'] for feature in features]
    if len(ids) != len(set(ids)):
        raise ValueError('duplicate UDP feature ID')
    required = set()
    for feature in features:
        kind, tests = feature['kind'], feature['ctests']
        if kind not in KINDS or not isinstance(tests, list) or len(tests) != len(set(tests)):
            raise ValueError('invalid UDP feature classification/tests')
        if kind == 'manual':
            if tests or not feature['note'].strip():
                raise ValueError('manual boundary must explain its gap without runnable pass mappings')
        elif not tests:
            raise ValueError('automated feature requires a runnable test')
        required.update(tests)
    labeled = set()
    for test in registered['tests']:
        labels = next((value['value'] for value in test.get('properties', []) if value['name'] == 'LABELS'), [])
        if 'native-udp' in labels:
            labeled.add(test['name'])
    if required != labeled:
        raise ValueError(f'UDP matrix/registered test mismatch: absent={sorted(required-labeled)}, omitted={sorted(labeled-required)}')
    return sorted(required)


def junit_results(path, expected):
    results = {}
    for test in ET.parse(path).getroot().iter('testcase'):
        name = test.attrib['name']
        if name in results or name not in expected:
            raise ValueError('duplicate or unexpected JUnit testcase: ' + name)
        results[name] = 'passed' if (test.find('failure') is None and test.find('error') is None
                                   and test.find('skipped') is None
                                   and test.attrib.get('status', 'run') not in ('notrun', 'disabled')) else 'failed'
    for name in expected:
        results.setdefault(name, 'missing')
    return results


def report(matrix, results, returncode):
    features = []
    for original in matrix['features']:
        feature = dict(original)
        if feature['kind'] == 'manual':
            feature['status'] = 'not-validated'
        elif any(results.get(name) != 'passed' for name in feature['ctests']):
            feature['status'] = 'failed'
        else:
            feature['status'] = 'passed' if feature['kind'] == 'functional' else 'unsupported-confirmed'
        features.append(feature)
    automated = returncode == 0 and all(value == 'passed' for value in results.values())
    complete = automated and all(feature['status'] == 'passed' for feature in features)
    return dict(schema=1,scope=matrix['scope'],ctest_returncode=returncode,tests=results,features=features,
                automated_checks_passed=automated,all_features_supported_and_validated=complete,
                feature_totals=dict(Counter(feature['status'] for feature in features)))


def test_artifacts(build, registered, names):
    """Hash every existing local file named by selected CTest commands."""
    build = build.resolve()
    source = Path(__file__).resolve().parents[1]
    expected = set(names)
    artifacts = {}
    uses_launcher = False
    for test in registered['tests']:
        if test['name'] not in expected:
            continue
        command = test.get('command')
        if not isinstance(command, list) or not command:
            raise ValueError('registered test has no command: ' + test['name'])
        for argument in command:
            candidate = Path(argument)
            if not candidate.is_absolute():
                continue
            in_build = candidate == build or build in candidate.parents
            in_source = candidate == source or source in candidate.parents
            if not candidate.exists():
                if in_build or in_source:
                    raise ValueError(f'missing local test artifact for {test["name"]}: {candidate}')
                continue
            if not candidate.is_file():
                continue
            path = candidate.resolve()
            if path == source / 'tools/ker-run.py':
                uses_launcher = True
            try:
                key = 'build/' + path.relative_to(build).as_posix()
            except ValueError:
                try:
                    key = 'source/' + path.relative_to(source).as_posix()
                except ValueError:
                    if argument != command[0] and not os.access(path, os.X_OK):
                        continue
                    key = 'external/' + str(path).lstrip('/')
            artifacts[key] = hashlib.sha256(path.read_bytes()).hexdigest()
    if uses_launcher:
        app_guard = build / 'ker-app'
        if not app_guard.is_file():
            raise ValueError(f'missing local test artifact used by ker-run.py: {app_guard}')
        artifacts['build/ker-app'] = hashlib.sha256(app_guard.read_bytes()).hexdigest()
    return dict(sorted(artifacts.items()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, required=True)
    parser.add_argument('--matrix', type=Path, default=Path(__file__).resolve().parents[1] / 'tests/udp-validation.json')
    parser.add_argument('--report', type=Path)
    parser.add_argument('--require-complete', action='store_true')
    parser.add_argument('--from-junit', type=Path,
        help='deprecated; imported JUnit is not accepted as tested-binary evidence')
    parser.add_argument('--ctest-returncode', type=int,
        help='deprecated; imported JUnit is not accepted as tested-binary evidence')
    args = parser.parse_args()
    if args.from_junit is not None or args.ctest_returncode is not None:
        parser.error('imported JUnit cannot establish tested-binary provenance; run the selected CTests with this tool')
    build = args.build_dir.resolve()
    output = (args.report or build / 'udp-validation-report.json').resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    matrix = json.loads(args.matrix.read_text())
    registered = json.loads(subprocess.check_output(['ctest', '--test-dir', str(build), '--show-only=json-v1'], text=True))
    names = selected_tests(matrix, registered)
    junit = Path(str(output) + '.junit.xml')
    command = ['ctest', '--test-dir', str(build), '--output-on-failure', '--no-tests=error',
               '--output-junit', str(junit), '-R', '^(' + '|'.join(re.escape(name) for name in names) + ')$']
    log_path = Path(str(output) + '.ctest.log')
    with log_path.open('w') as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
    returncode = result.returncode
    results = junit_results(junit, names)
    summary = report(matrix, results, returncode)
    summary.update(build_dir=str(build),junit=str(junit),log=str(log_path) if log_path else None,
        execution_mode='executed-ctest',
        matrix_sha256=hashlib.sha256(args.matrix.read_bytes()).hexdigest(),
        test_artifacts_sha256=test_artifacts(build, registered, names))
    output.write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({'ctests': dict(Counter(results.values())), 'features': summary['feature_totals'],
                      'automated_checks_passed': summary['automated_checks_passed'],
                      'all_features_supported_and_validated': summary['all_features_supported_and_validated'],
                      'report': str(output)}, indent=2))
    if not summary['automated_checks_passed']:
        return 1
    return 2 if args.require_complete and not summary['all_features_supported_and_validated'] else 0


if __name__ == '__main__':
    sys.exit(main())
