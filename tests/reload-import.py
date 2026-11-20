"""Verify the pinned reload implementation and retained source cases."""
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
directory = root / 'third_party/fstack-reload'
manifest = json.loads((directory / 'UPSTREAM.json').read_text())
assert manifest['revision'] == '646a641cfff77f4815e1e29829a09e1ed15a2999'
assert set(manifest['files']) == {
    'ff_reload.c', 'ff_config.h', 'ff_log.h', 'ff_reload_gendir.c',
    'ff_drain_ring.c', 'ff_drain_ring.h',
}
for name, record in manifest['files'].items():
    assert record['source_file'] == 'lib/' + name
    data = (directory / name).read_bytes()
    assert hashlib.sha256(data).hexdigest() == record['sha256'], name
    blob = b'blob ' + str(len(data)).encode() + b'\0' + data
    assert hashlib.sha1(blob).hexdigest() == record['git_blob'], name

source = (root / 'tests/upstream/fstack/tests/unit/test_ff_config.c').read_bytes()
cases_dir = root / 'tests/fstack-reload-source'
cases = sorted(cases_dir.glob('test_*.inc'))
assert cases
for case in cases:
    start = source.index(b'static void\n' + case.stem.encode() + b'(')
    end = source.index(b'\n}', start) + 2
    assert case.read_bytes() == source[start:end] + b'\n', case.name

proof_cases = cases_dir / 'user-proof-cases.inc'
start = source.index(b'static uint32_t\np2_dead_pid(')
last = source.index(b'static void\ntest_rx15_ring_user_census_and_purge_lock(', start)
end = source.index(b'\n}', last) + 2
assert proof_cases.read_bytes() == source[start:end] + b'\n', proof_cases.name
