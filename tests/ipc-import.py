#!/usr/bin/env python3
"""Check the borrowed-EAL adapter's unchanged pinned F-Stack dependencies."""
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
source = root / 'third_party/fstack-ipc'
manifest = json.loads((source / 'UPSTREAM.json').read_text())
assert manifest['revision'] == '646a641cfff77f4815e1e29829a09e1ed15a2999'
assert {name: record['source_file'] for name, record in manifest['files'].items()} == {
    'ff_ipc.c': 'tools/compat/ff_ipc.c',
    'ff_ipc.h': 'tools/compat/ff_ipc.h',
    'ff_msg.h': 'lib/ff_msg.h',
    'ff_reload.h': 'lib/ff_reload.h',
}
for name, record in manifest['files'].items():
    data = (source / name).read_bytes()
    assert hashlib.sha256(data).hexdigest() == record['sha256'], name
    blob = b'blob ' + str(len(data)).encode() + b'\0' + data
    assert hashlib.sha1(blob).hexdigest() == record['git_blob'], name
print('PASS: original F-Stack IPC source/header bytes and pinned revision')
