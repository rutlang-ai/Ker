#!/usr/bin/env python3
"""Verify the unchanged metadata implementation and complete source cases."""
import hashlib
import json
from pathlib import Path
root = Path(__file__).resolve().parents[1]
folder = root / 'third_party/fstack-flow-map'
manifest = json.loads((folder / 'UPSTREAM.json').read_text())
for name, spec in manifest['files'].items():
    data = (folder / name).read_bytes()
    if hashlib.sha256(data).hexdigest() != spec['sha256']:
        raise SystemExit(f'FAIL: upstream file changed: {name}')
source = (root / 'tests/upstream/fstack/tests/unit/test_ff_dpdk_if.c').read_bytes()
parts = []
for name in ['test_ut_nr_23_flow_map', 'test_a1_flow_map_single_phase',
             'test_a1_flow_map_admission_rule', 'test_a1_flow_map_revoke',
             'test_p3_flow_map_bounded_growth']:
    a = source.index(b'static void\n' + name.encode() + b'(')
    b = source.index(b'\n}\n', a) + 3
    parts.append(source[a:b])
if (root / 'tests/fstack-flow-map-source.inc').read_bytes() != b'\n'.join(parts):
    raise SystemExit('FAIL: incomplete or modified source cases')
print('PASS: original flow-map implementation and all five complete source cases')
