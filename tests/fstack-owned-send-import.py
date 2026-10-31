"""Require the complete literal sender and both complete source assertions."""
import hashlib
import json
from pathlib import Path
root = Path(__file__).resolve().parents[1]
directory = root / 'third_party/fstack-owned-send'
manifest = json.loads((directory / 'UPSTREAM.json').read_text())
source = (directory / manifest['retained_source']).read_bytes()
assert hashlib.sha256(source).hexdigest() == manifest['source_sha256']
assert manifest['revision'] == json.loads((root / 'tests/fstack-migration.json').read_text())['revision']
start = source.index(b'int\nff_dpdk_if_send('); end = source.index(b'\n}', start) + 2
assert (directory / 'send.inc').read_bytes() == source[start:end] + b'\n'
assert (directory / 'LICENSE').read_bytes() == source[:source.index(b'*/') + 2] + b'\n'
header = (directory / 'ff_dpdk_if.h').read_bytes()
assert hashlib.sha256(header).hexdigest() == manifest['header_sha256']
start = header.index(b'struct ff_tx_offload {'); end = header.index(b'\n};', start) + 3
assert (directory / 'offload.inc').read_bytes() == header[start:end] + b'\n'
for file, name, label in [('unit/test_ff_dpdk_if.c', 'test_ff_dpdk_if_send_null_ctx_with_mbuf', 'null'),
                          ('integration/test_ff_dpdk_if_integration.c', 'test_ff_dpdk_if_send_copydata_fail', 'copy')]:
    source = (root / 'tests/upstream/fstack/tests' / file).read_bytes()
    start = source.index(b'static void\n' + name.encode() + b'('); end = source.index(b'\n}', start) + 2
    assert (root / ('tests/fstack-owned-send-' + label + '-source.inc')).read_bytes() == source[start:end] + b'\n'
print('Unchanged complete owned sender, offload declaration and source assertions verified')
