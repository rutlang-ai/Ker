#!/usr/bin/env python3
"""Guard the unchanged full sources, callback ABI, runtime and source tests."""
import hashlib
import json
from pathlib import Path
root = Path(__file__).resolve().parents[1]
p = root / 'third_party/fstack-dispatcher'
m = json.loads((p / 'UPSTREAM.json').read_text())
assert m['revision'] == '646a641cfff77f4815e1e29829a09e1ed15a2999'
assert set(m['files']) == {'../fstack-address-policy/ff_api.h', '../fstack-pools/ff_dpdk_if.c'}
for name, record in m['files'].items():
    data = (p / name).read_bytes()
    assert hashlib.sha256(data).hexdigest() == record['sha256']
    assert hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == record['git_blob']
h = (p / '../fstack-address-policy/ff_api.h').read_bytes()
c = (p / '../fstack-pools/ff_dpdk_if.c').read_bytes()
license = c[:c.index(b'*/')+2]+b'\n'
parts = [license]
a = h.index(b'typedef int (*dispatch_func_t)'); b = h.index(b';', a)+1
parts.append(h[a:b]+b'\n')
a = h.index(b'struct ff_dispatcher_context {'); b = h.index(b'\n};', a)+3
parts.append(h[a:b]+b'\n')
a = h.index(b'typedef int (*dispatch_func_context_t)'); b = h.index(b';', a)+1
parts.append(h[a:b]+b'\n')
assert (root / 'include/ker/detail/fstack-dispatch-api.inc').read_bytes() == b'\n'.join(parts)
parts = [license]
for key in [b'static dispatch_func_t ', b'static dispatch_func_context_t ']:
    parts.append(next(line for line in c.splitlines(keepends=True) if line.startswith(key)))
for name in ['ff_regist_packet_dispatcher', 'ff_regist_packet_dispatcher_context',
             'ff_unregist_packet_dispatcher', 'ff_unregist_packet_dispatcher_context']:
    a = c.index(b'void\n'+name.encode()+b'('); b = c.index(b'\n}\n', a)+3
    parts.append(c[a:b])
assert (p / 'registration-runtime.inc').read_bytes() == b'\n'.join(parts)
a = c.index(b'            if (packet_dispatcher) {', c.index(b'void *data = rte_pktmbuf_mtod(rtem, void*)'))
b = c.index(b'\n\n            if (ret == FF_DISPATCH_RESPONSE)', a)
assert (p / 'call-runtime.inc').read_bytes() == c[a:b]+b'\n'
s = (root / 'tests/upstream/fstack/tests/unit/test_ff_dpdk_if.c').read_bytes()
parts = []
for name in ['fake_dispatcher', 'fake_dispatcher_ctx', 'test_ff_regist_packet_dispatcher_smoke',
             'test_ff_regist_packet_dispatcher_context_smoke', 'test_ut_nr_24_unregist_dispatcher']:
    a = s.index(b'static '+(b'int' if name.startswith('fake_') else b'void')+b'\n'+name.encode()+b'(')
    b = s.index(b'\n}\n', a)+3; parts.append(s[a:b])
assert (root / 'tests/fstack-dispatch-source.inc').read_bytes() == b'\n'.join(parts)
print('PASS: exact original dispatcher ABI, full sources, registration, call block and complete three source tests')
