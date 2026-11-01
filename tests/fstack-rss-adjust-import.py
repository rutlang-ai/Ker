#!/usr/bin/env python3
"""Audit literal RSS adjustment helper and source-test imports."""
import hashlib
import json
import re
from pathlib import Path
import runpy

root = Path(__file__).resolve().parents[1]
implementation = root / 'third_party/fstack-pools/ff_dpdk_if.c'
manifest = json.loads((root / 'third_party/fstack-rss-adjust/UPSTREAM.json').read_text())
source = implementation.read_text()
assert hashlib.sha256(source.encode()).hexdigest() == manifest['source_sha256']
parts = []
for name in manifest['functions']:
    match = re.search(r'(?:static (?:inline )?)?(?:uint32_t|int)\n' + name + r'\(', source)
    assert match, name
    end = source.index('\n}', match.start()) + 2
    parts.append(source[match.start():end])
assert (root / 'third_party/fstack-rss-adjust/rss-adjust-functions.inc').read_text() == '\n\n'.join(parts) + '\n'
state_names = ('FF_RSS_THASH_V4_TUPLE_LEN', 'FF_RSS_THASH_V4_SPORT_OFF',
               'FF_RSS_THASH_SPORT_HELPER_LEN', 'FF_RSS_THASH_ADJUST_ATTEMPTS',
               'FF_RSS_THASH_V6_TUPLE_LEN', 'FF_RSS_THASH_V6_SPORT_OFF')
state_expected = [next(line for line in source.splitlines() if line.startswith('#define ' + name + ' '))
                  for name in state_names]
for name in ('rss_thash_ctx', 'rss_thash_sport_h', 'rss_thash_ready',
             'rss_thash6_ctx', 'rss_thash6_sport_h', 'rss_thash6_ready'):
    match = re.search(r'^static (?:struct rte_thash_ctx \*|struct rte_thash_subtuple_helper \*|int )' +
                      name + r'\[RTE_MAX_ETHPORTS\];$', source, re.M)
    assert match, name
    state_expected.append(match.group())
state_expected.append('static int ff_rss_key_built;')
assert (root / 'third_party/fstack-rss-adjust/rss-adjust-state.inc').read_text() == '\n'.join(state_expected) + '\n'
test_manifest = json.loads((root / 'tests/fstack-rss-adjust-source.json').read_text())
test_source = (root / 'tests/upstream/fstack/tests/unit/test_ff_dpdk_if.c').read_text()
assert hashlib.sha256(test_source.encode()).hexdigest() == test_manifest['source_sha256']
source_parts = []
for name in test_manifest['cases']:
    start = test_source.index('static void\n' + name + '(')
    end = test_source.index('\n}', start) + 2
    source_parts.append(test_source[start:end])
assert (root / 'tests/fstack-rss-adjust-source.inc').read_text() == '\n\n'.join(source_parts) + '\n'
runpy.run_path(str(root / 'tests/fstack-rss-table-import.py'), run_name='__main__')
print(f"PASS: original RSS adjustment functions, state, {len(test_manifest['cases'])} source cases, and shared helpers audited")
