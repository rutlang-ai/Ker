"""Verify complete unmodified RSS table/hash excerpts and source assertions."""
import hashlib
import json
import re
from pathlib import Path

root = Path(__file__).resolve().parents[1]
directory = root / 'third_party/fstack-rss-table'
manifest = json.loads((directory / 'UPSTREAM.json').read_text())
source = (directory / manifest['retained_source']).read_text()
assert hashlib.sha256(source.encode()).hexdigest() == manifest['source_sha256']
parts = []
for name in manifest['functions']:
    match = re.search(r'(?:static (?:inline )?)?(?:uint32_t|int)\n' + name + r'\(', source)
    assert match, name
    end = source.index('\n}', match.start()) + 2
    parts.append(source[match.start():end])
assert (directory / 'rss-functions.inc').read_text() == '\n\n'.join(parts) + '\n'
for name in ('rss-tables.inc', 'rss-key.inc'):
    assert (directory / name).read_text().rstrip() in source, name
test_source = (root / 'tests/upstream/fstack/tests/unit/test_ff_dpdk_if.c').read_text()
start = test_source.index('static void\ntest_ff_rss_tbl_set_portrange_no_cfg(')
end = test_source.index('\n}', start) + 2
assert (root / 'tests/fstack-rss-table-source.inc').read_text().rstrip() == test_source[start:end]
print('RSS table/hash implementation and complete source assertion verified')
for name in (root / 'tests/fstack-rss-cases.txt').read_text().splitlines():
    start = test_source.index('static void\n' + name + '(')
    end = test_source.index('\n}', start) + 2
    assert (root / 'tests/fstack-rss-source' / (name + '.inc')).read_text().rstrip() == test_source[start:end]
expected = []
for name in ('test_rsskey_40', 'test_saddr6', 'test_daddr6'):
    start = test_source.index('static const uint8_t ' + name + '[')
    end = test_source.index('\n};', start) + 3
    expected.append(test_source[start:end])
for name in ('test_toeplitz', 'test_expected_rss_check', 'test_expected_rss_check6',
             'test_rss_build_table', 'test_rss_softc', 'test_rss6_build_table'):
    match = re.search(r'static (?:uint32_t|int|void \*)\n' + name + r'\(', test_source)
    assert match, name
    end = test_source.index('\n}', match.start()) + 2
    expected.append(test_source[match.start():end])
for name in ('TEST_RSS_PORT', 'TEST_RSS_NBQ', 'TEST_RSS_QID', 'TEST_RSS_RETA', 'TEST_RSS_FIRST', 'TEST_RSS_LAST'):
    expected.insert(0, next(line for line in test_source.splitlines() if line.startswith('#define ' + name + ' ')))
expected.insert(6, 'static struct ff_rss_check_cfg g_rss_cfg;\nstatic struct ff_dpdk_if_context g_test_ctx;')
assert (root / 'tests/fstack-rss-source-helpers.inc').read_text() == '\n\n'.join(expected) + '\n'
print('complete original RSS helper declarations/functions verified')
