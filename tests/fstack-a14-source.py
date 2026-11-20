"""Extract pinned multiprocess scenarios, leaving FreeBSD stubs outside Ker."""
import hashlib
import json
from pathlib import Path
import sys

root = Path(__file__).resolve().parents[1]
inventory = json.loads((root / 'tests/fstack-migration.json').read_text())
name = 'tests/integration/test_ff_gendir_mp_integration.c'
source = (root / inventory['source_root'] / name).read_bytes()
if hashlib.sha256(source).hexdigest() != inventory['files'][name]['sha256']:
    raise ValueError('Pinned A14 source hash differs from the inventory')
first = source.index(b'#define ROLE_PRIMARY')
before = source.index(b'/* bridge stubs:', first)
before = source.rindex(b'/* --------', first, before)
after = source.index(b'extern uint16_t nb_dev_ports;', before)
assert source[before:after].count(b'ff_veth_attach') == 1
Path(sys.argv[1]).write_bytes(source[first:before] + b'\n' + source[after:])
