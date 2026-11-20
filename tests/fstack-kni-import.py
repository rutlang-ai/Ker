"""Verify the literal KNI implementation excerpts and retained source assertions."""
from pathlib import Path
import json
import re
import hashlib
root = Path(__file__).resolve().parents[1]
p = root / 'third_party/fstack-kni-bridge'
m = json.loads((p / 'UPSTREAM.json').read_text())
source, header = (p / 'ff_dpdk_kni.c').read_bytes(), (p / 'ff_dpdk_kni.h').read_bytes()
assert hashlib.sha256(source).hexdigest() == m['source_sha256']
assert hashlib.sha256(header).hexdigest() == m['header_sha256']
assert m['revision'] == json.loads((root / 'tests/fstack-migration.json').read_text())['revision']
parts = []
for name in m['functions']:
    match = re.search(rb'(?m)^(?:static )?(?:int|void|enum FilterReturn)\n' + name.encode() + rb'\(', source)
    assert match, name
    end = source.index(b'\n}', match.start()) + 2
    parts.append(source[match.start():end])
assert (p / 'functions.inc').read_bytes() == b'\n\n'.join(parts) + b'\n'
start = source.index(b'struct kni_interface_stats {'); end = source.index(b'\n};', start) + 3
assert (p / 'stats.inc').read_bytes() == source[start:end] + b'\n'
assert (p / 'LICENSE').read_bytes() == source[:source.index(b'*/') + 2] + b'\n'
source = (root / 'tests/upstream/fstack/tests/unit/test_ff_dpdk_kni.c').read_bytes()
start = source.index(b'static int p1_cold;')
end = source.index(b'static void\ntest_p1_kni_stats_oom(', start)
owner_cases = source[start:end].rstrip(b'\n') + b'\n'
assert (root / 'tests/fstack-kni-owner-source.inc').read_bytes() == owner_cases
for name in (b'test_p1_future_kni_owner', b'test_p1_kni_nonowner',
             b'test_p1_future_kni_short_tx', b'test_p1_future_kni_full_ring'):
    assert name in owner_cases

for label in ('stats', 'slot'):
    start = source.index(b'static void\ntest_p1_kni_' + label.encode() + b'_oom(')
    end = source.index(b'\n}', start) + 2
    assert (root / ('tests/fstack-kni-' + label + '-oom-source.inc')).read_bytes() == source[start:end] + b'\n'
print('Pinned KNI implementation, four ownership cases and both allocation cases verified')
