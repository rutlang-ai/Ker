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
assert (root / 'tests/fstack-rss-table-source.inc').read_text().rstrip() in test_source
print('RSS table/hash implementation and complete source assertion verified')
