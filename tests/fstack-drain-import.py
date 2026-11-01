#!/usr/bin/env python3
"""Audit exact pinned drain-ring sources and the selected upstream test case."""
import hashlib
import json
from pathlib import Path
import re

root = Path(__file__).resolve().parents[1]

upstream = root / 'third_party/fstack-reload/UPSTREAM.json'
upstream_manifest = json.loads(upstream.read_text())
for filename in ('ff_drain_ring.c', 'ff_drain_ring.h'):
    path = root / 'third_party/fstack-reload' / filename
    record = upstream_manifest['files'][filename]
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == record['sha256'], filename
    assert record['source_file'] == 'lib/' + filename

test_manifest = json.loads((root / 'tests/fstack-drain-source.json').read_text())
test_path = root / test_manifest['source_file']
test_source = test_path.read_text()
assert hashlib.sha256(test_source.encode()).hexdigest() == test_manifest['source_sha256']

declaration_start = test_source.index('static struct ff_config p1_saved_cfg;')
declaration_end = test_source.index('static uint16_t p1_port_id;', declaration_start)
declarations = test_source[declaration_start:declaration_end + len('static uint16_t p1_port_id;')]
parts = [declarations]
for name in test_manifest['helpers']:
    candidates = list(re.finditer(r'(?m)^static (?:int|void)\s+', test_source))
    starts = [match.start() for match in candidates if test_source.startswith(name + '(', match.end())]
    assert len(starts) == 1, name
    start = starts[0]
    brace = test_source.index('{', start)
    depth = 0
    for index in range(brace, len(test_source)):
        if test_source[index] == '{':
            depth += 1
        elif test_source[index] == '}':
            depth -= 1
            if depth == 0:
                parts.append(test_source[start:index + 1])
                break
    else:
        raise AssertionError(f'unclosed source function: {name}')
assert (root / 'tests/fstack-drain-source.inc').read_text() == '\n\n'.join(parts) + '\n'

helper_manifest = json.loads((root / 'tests/fstack-drain-create-ring.json').read_text())
helper_path = root / helper_manifest['source_file']
helper_source = helper_path.read_text()
assert hashlib.sha256(helper_source.encode()).hexdigest() == helper_manifest['source_sha256']
match = re.search(r'(?m)^struct rte_ring \*\ncreate_ring\(', helper_source)
assert match
brace = helper_source.index('{', match.start())
depth = 0
for index in range(brace, len(helper_source)):
    if helper_source[index] == '{':
        depth += 1
    elif helper_source[index] == '}':
        depth -= 1
        if depth == 0:
            expected = helper_source[match.start():index + 1] + '\n'
            break
else:
    raise AssertionError('unclosed original create_ring helper')
assert (root / 'tests/fstack-drain-create-ring.inc').read_text() == expected
print('PASS: pinned drain-ring implementation, create_ring helper, and exact foreign-epoch source fixture audited')
