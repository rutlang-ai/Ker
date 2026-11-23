"""Check full upstream mapping helpers, flag definitions and source assertion."""
import hashlib
import json
from pathlib import Path
import re

root = Path(__file__).resolve().parents[1]
directory = root / 'third_party/fstack-host-readiness'
manifest = json.loads((directory / 'UPSTREAM.json').read_text())
source = (directory / 'ff_host_interface.c').read_text()
header = (directory / 'ff_host_interface.h').read_text()
assert hashlib.sha256(source.encode()).hexdigest() == manifest['source_sha256']
assert hashlib.sha256(header.encode()).hexdigest() == manifest['header_sha256']
assert manifest['revision'] == json.loads((root / 'tests/fstack-migration.json').read_text())['revision']
parts = []
for name in manifest['memory_functions']:
    match = re.search(r'(?:void \*|int)\n' + name + r'\(', source)
    assert match, name
    end = source.index('\n}', match.start()) + 2
    parts.append(source[match.start():end])
assert (directory / 'memory-functions.inc').read_text() == '\n\n'.join(parts) + '\n'
flags = '\n'.join(line for line in header.splitlines()
                  if line.startswith(('#define ff_PROT_', '#define ff_MAP_'))) + '\n'
assert (directory / 'memory-flags.inc').read_text() == flags
test = (root / 'tests/upstream/fstack/tests/unit/test_ff_host_interface.c').read_text()
start = test.index('static void\ntest_ff_mmap_failure_exits(')
end = test.index('\n}', start) + 2
assert (root / 'tests/fstack-host-mmap-source.inc').read_text() == test[start:end] + '\n'
print('Original fatal mmap source case, mapping bodies and flags verified')
