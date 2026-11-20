"""Verify the 15 retained directory and drain assertions and the ring helper."""
import hashlib
import json
import re
from pathlib import Path

root = Path(__file__).resolve().parents[1]
inventory = json.loads((root / 'tests/fstack-migration.json').read_text())

source_path = 'tests/unit/test_ff_dpdk_if.c'
source = (root / inventory['source_root'] / source_path).read_bytes()
assert hashlib.sha256(source).hexdigest() == inventory['files'][source_path]['sha256']
sections = []
for first, last in (
    (b'static struct ff_config p1_saved_cfg;', b'/* RX-15:'),
    (b'/* Set up "old master gone', b'int\nmain(void)'),
    (b'static void\ntest_f_m4_1_drain_ring_full_visible(', b'/* UT-NR-23:'),
    (b'static void\ntest_ut_nr_19_drain_ring_sp_sc(', b'/* F-M4-1:'),
):
    start = source.index(first)
    sections.append(source[start:source.index(last, start)].rstrip(b'\n'))
assert (root / 'tests/fstack-drain-source.inc').read_bytes() == b'\n\n'.join(sections) + b'\n'

orphan = json.loads((root / 'tests/fstack-drain-orphans-source.json').read_text())
assert hashlib.sha256(source).hexdigest() == orphan['source_sha256']
parts = []
for name in orphan['helpers']:
    match = re.search(rb'(?m)^static (?:uint32_t|void)\n' + name.encode() + rb'\(', source)
    assert match, name
    end = source.index(b'\n}\n', match.start()) + 3
    parts.append(source[match.start():end])
assert (root / 'tests/fstack-drain-orphans-source.inc').read_bytes() == b'\n'.join(parts)

helper = json.loads((root / 'tests/fstack-drain-create-ring.json').read_text())
source = (root / helper['source_file']).read_bytes()
assert hashlib.sha256(source).hexdigest() == helper['source_sha256']
start = source.index(b'struct rte_ring *\ncreate_ring(')
end = source.index(b'\n}\n', start) + 3
assert (root / 'tests/fstack-drain-create-ring.inc').read_bytes() == source[start:end]
print('PASS: original ring helper and 15 retained generation directory and drain cases')
