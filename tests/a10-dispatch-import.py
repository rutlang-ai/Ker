#!/usr/bin/env python3
"""Verify the unchanged synthetic A10 classifier and packet/key fixtures."""
from pathlib import Path
root = Path(__file__).resolve().parents[1]
source = (root / 'tests/upstream/fstack/tests/integration/test_ff_reload_integration.c').read_bytes()
def function(start):
    a = source.index(start)
    return source[a:source.index(b'\n}\n', a) + 3]
expected = {
    'examples/a10-classifier-source.inc': function(b'static int\nit_flow_dispatcher('),
    'tests/fstack-a10-packets-source.inc': b'\n'.join(function(start) for start in [
        b'static void\nfill_tcp_ack(', b'static struct rte_mbuf *\ninj_mbuf(',
        b'static void\nflow_key_v4(']),
}
for name, data in expected.items():
    if (root / name).read_bytes() != data:
        raise SystemExit('FAIL: changed A10 source excerpt: ' + name)
print('PASS: original A10 classifier, TCP-shaped ACK fixture and tuple builder unchanged')
