#!/usr/bin/env python3
"""Verify the callback reader still uses byte-identical pinned inih sources."""
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
source = root / 'third_party/inih'
manifest = json.loads((source / 'UPSTREAM.json').read_text())
assert manifest['revision'] == '646a641cfff77f4815e1e29829a09e1ed15a2999'
assert set(manifest['files']) == {'ff_ini_parser.c', 'ff_ini_parser.h'}
for name, record in manifest['files'].items():
    data = (source / name).read_bytes()
    assert hashlib.sha256(data).hexdigest() == record['sha256'], name
    blob = b'blob ' + str(len(data)).encode() + b'\0' + data
    assert hashlib.sha1(blob).hexdigest() == record['git_blob'], name
print('PASS: original F-Stack/inih source/header bytes and pinned revision')
