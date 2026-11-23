"""Verify pinned KNI owner helpers, source cases and implementation excerpts."""
from pathlib import Path
import importlib.util
import json
import re
import hashlib

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    'kni_allocation_import', root / 'tests/fstack-kni-allocation-import.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

source = (root / 'tests/upstream/fstack/tests/unit/test_ff_dpdk_kni.c').read_bytes()
start = source.index(b'static int p1_cold;')
end = source.index(b'static void\ntest_p1_kni_stats_oom(', start)
helpers = source[start:end].rstrip(b'\n') + b'\n'
actual = (root / 'tests/fstack-kni-owner-source.inc').read_bytes()
assert actual == helpers, 'KNI owner fixture helpers/source assertions drifted from pinned source'
for case in (b'test_p1_future_kni_owner', b'test_p1_kni_nonowner'):
    assert case in actual
metadata = json.loads((root / 'third_party/fstack-kni-bridge/UPSTREAM.json').read_text())
implementation = (root / 'third_party/fstack-kni-bridge/ff_dpdk_kni.c').read_bytes()
assert hashlib.sha256(implementation).hexdigest() == metadata['source_sha256']
for name in metadata['functions']:
    match = re.search(rb'(?m)^(?:static )?(?:int|void|enum FilterReturn)\n' +
                      name.encode() + rb'\(', implementation)
    assert match, name
    finish = implementation.index(b'\n}', match.start()) + 2
    # The shared importer performs exact byte extraction for every selected function.
    excerpt = implementation[match.start():finish]
    assert excerpt in (root / 'third_party/fstack-kni-bridge/functions.inc').read_bytes()
print('Pinned KNI owner/nonowner helpers, source cases and implementation verified')
