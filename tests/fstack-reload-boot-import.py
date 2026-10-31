"""Retain every original boot-state assertion without compiling its stub suite."""
import json
from pathlib import Path
root = Path(__file__).resolve().parents[1]
assert json.loads((root / 'tests/fstack-migration.json').read_text())['revision'] == '646a641cfff77f4815e1e29829a09e1ed15a2999'
source = (root / 'tests/upstream/fstack/tests/integration/test_ff_reload_integration.c').read_bytes()
start = source.index(b'static void\ntest_it_a09_boot_state(')
end = source.index(b'\n}', start) + 2
assert (root / 'tests/fstack-reload-boot-source.inc').read_bytes() == source[start:end] + b'\n'
print('Complete unchanged test_it_a09_boot_state assertion function verified')
