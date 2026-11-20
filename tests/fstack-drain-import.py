"""Verify the 14 retained directory and drain assertions and the ring helper."""
import hashlib
import json
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
):
    start = source.index(first)
    sections.append(source[start:source.index(last, start)].rstrip(b'\n'))
assert (root / 'tests/fstack-drain-source.inc').read_bytes() == b'\n\n'.join(sections) + b'\n'

helper = json.loads((root / 'tests/fstack-drain-create-ring.json').read_text())
source = (root / helper['source_file']).read_bytes()
assert hashlib.sha256(source).hexdigest() == helper['source_sha256']
start = source.index(b'struct rte_ring *\ncreate_ring(')
end = source.index(b'\n}\n', start) + 3
assert (root / 'tests/fstack-drain-create-ring.inc').read_bytes() == source[start:end]
print('PASS: original ring helper and 14 retained generation directory and drain cases')
