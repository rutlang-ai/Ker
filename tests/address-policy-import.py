#!/usr/bin/env python3
"""Guard complete pinned sources, compiled callbacks and original assertions."""
import hashlib
import json
from pathlib import Path
root = Path(__file__).resolve().parents[1]
base = root / 'third_party/fstack-address-policy'
m = json.loads((base / 'UPSTREAM.json').read_text())
assert m['revision'] == '646a641cfff77f4815e1e29829a09e1ed15a2999'
assert set(m['files']) == {'ff_api.h', 'ff_event.h', 'ff_errno.h', '../fstack-pools/ff_dpdk_if.c'}
for name, record in m['files'].items():
    data = (base / name).read_bytes()
    assert hashlib.sha256(data).hexdigest() == record['sha256']
    assert hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == record['git_blob']
h = (base / 'ff_api.h').read_bytes()
c = (base / '../fstack-pools/ff_dpdk_if.c').read_bytes()
parts = [c[:c.index(b'*/')+2] + b'\n']
parts.extend(line for line in h.splitlines(keepends=True) if line.startswith((b'#define AF_INET6_LINUX ', b'#define AF_INET6_FREEBSD ')))
a = h.index(b'typedef int (*pcblddr_func_t)'); b = h.index(b';', a)+1
parts.append(h[a:b]+b'\n')
parts.append(next(line for line in c.splitlines(keepends=True) if line.startswith(b'static pcblddr_func_t ')))
a = c.index(b'int\nff_in_pcbladdr('); b = c.index(b'\nint\nff_rss_tbl_init', a)
parts.append(c[a:b])
assert (base / 'address-runtime.inc').read_bytes() == b'\n'.join(parts)
s = (root / 'tests/upstream/fstack/tests/unit/test_ff_dpdk_if.c').read_bytes()
parts = []
for name in ['fake_pcblddr', 'test_ff_regist_pcblddr_fun_smoke', 'test_ff_in_pcbladdr_no_callback']:
    a = s.index(b'static '+(b'int' if name == 'fake_pcblddr' else b'void')+b'\n'+name.encode()+b'(')
    b = s.index(b'\n}\n', a)+3; parts.append(s[a:b])
a = s.index(b'static struct {\n    int   invoked;')
b = s.index(b'\n}\n', s.index(b'capturing_pcblddr(', a))+3; parts.append(s[a:b])
for name in ['test_ff_in_pcbladdr_af_inet_dispatches', 'test_ff_in_pcbladdr_af_inet6_freebsd_to_linux_remap']:
    a = s.index(b'static void\n'+name.encode()+b'(')
    b = s.index(b'\n}\n', a)+3; parts.append(s[a:b])
for key in ['AF_INET6_FREEBSD_VAL', 'AF_INET6_LINUX_VAL']:
    parts.insert(-1, next(line for line in s.splitlines(keepends=True) if line.startswith(b'#define '+key.encode()+b' ')))
assert (root / 'tests/fstack-address-source.inc').read_bytes() == b'\n'.join(parts)
print('PASS: complete unchanged address-callback sources, literal runtime and four source tests')
