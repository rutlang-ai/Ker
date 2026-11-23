"""Verify the literal complete source test and unchanged interval implementation."""
import hashlib
import json
from pathlib import Path
root = Path(__file__).resolve().parents[1]
directory = root / 'third_party/fstack-caller-clock'
manifest = json.loads((directory / 'UPSTREAM.json').read_text())
source = (directory / manifest['retained_source']).read_bytes()
assert hashlib.sha256(source).hexdigest() == manifest['source_sha256']
assert manifest['revision'] == json.loads((root / 'tests/fstack-migration.json').read_text())['revision']
start = source.index(b'uint64_t\nff_hardclock_interval_tsc(')
end = source.index(b'\n}', start) + 2
assert (directory / 'interval.inc').read_bytes() == source[start:end] + b'\n'
assert (directory / 'LICENSE').read_bytes() == source[:source.index(b'*/') + 2] + b'\n'
source = (root / 'tests/upstream/fstack/tests/unit/test_ff_dpdk_if.c').read_bytes()
start = source.index(b'static void\ntest_ut_nr_17_hardclock_interval(')
end = source.index(b'\n}', start) + 2
assert (root / 'tests/fstack-caller-clock-source.inc').read_bytes() == source[start:end] + b'\n'
print('Unchanged original interval body and complete source assertions verified')
