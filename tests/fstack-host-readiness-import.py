"""Require byte-identical retained implementation and complete source assertion."""
import hashlib
import json
from pathlib import Path
import re

root = Path(__file__).resolve().parents[1]
directory = root / 'third_party/fstack-host-readiness'
manifest = json.loads((directory / 'UPSTREAM.json').read_text())
source = (directory / 'ff_host_interface.c').read_text()
assert hashlib.sha256(source.encode()).hexdigest() == manifest['source_sha256']
assert (directory / 'LICENSE').read_text() == source[:source.index('*/') + 2] + '\n'
assert manifest['revision'] == json.loads((root / 'tests/fstack-migration.json').read_text())['revision']
parts = []
for name in manifest['functions']:
    match = re.search(r'(?:int|void)\n' + name + r'\(', source)
    assert match, name
    end = source.index('\n}', match.start()) + 2
    parts.append(source[match.start():end])
assert (directory / 'host-functions.inc').read_text() == '\n\n'.join(parts) + '\n'
test = (root / 'tests/upstream/fstack/tests/unit/test_ff_host_interface.c').read_text()
start = test.index('static void\ntest_ff_host_kqueue_ctl_add_idempotent(')
end = test.index('\n}', start) + 2
assert (root / 'tests/fstack-host-readiness-source.inc').read_text() == test[start:end] + '\n'
print('Complete readiness source case and unchanged host helper excerpts verified')
