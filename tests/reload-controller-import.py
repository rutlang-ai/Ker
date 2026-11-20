#!/usr/bin/env python3
"""Keep original caller policy/licensing bytes and core/application separation."""
import hashlib
import json
from pathlib import Path
root=Path(__file__).resolve().parents[1]
p=root/'third_party/fstack-nginx'
m=json.loads((p/'UPSTREAM.json').read_text())
assert m['revision']=='646a641cfff77f4815e1e29829a09e1ed15a2999'
assert set(m['files'])=={'ngx_ff_reload_fsm.h','LICENSE.fstack','LICENSE.nginx'}
for name,record in m['files'].items():
    data=(p/name).read_bytes()
    assert hashlib.sha256(data).hexdigest()==record['sha256'],name
    assert hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==record['git_blob'],name
for path in (root/'src').rglob('*'):
    if path.suffix in {'.c','.h'}: assert 'ngx_ff_reload_fsm' not in path.read_text(),str(path)
source = (root / 'tests/upstream/fstack/tests/unit/test_ff_config.c').read_bytes()
start = source.index(b'/* UT-NR-10: legal chain')
end = source.index(b'/* UT-NR-12: generation mapping', start)
assert (root / 'tests/fstack-reload-fsm-source.inc').read_bytes() == source[start:end].rstrip(b'\n') + b'\n'
print('PASS: unchanged caller policy, licensing and four original source cases')
