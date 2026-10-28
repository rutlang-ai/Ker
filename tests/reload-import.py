#!/usr/bin/env python3
"""Verify unchanged source runtime/configuration layout and shared IPC headers."""
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
for directory, names in [
    ('fstack-reload', {'ff_reload.c', 'ff_config.h'}),
    ('fstack-ipc', {'ff_ipc.c', 'ff_ipc.h', 'ff_msg.h', 'ff_reload.h'}),
]:
    source = root / 'third_party' / directory
    manifest = json.loads((source / 'UPSTREAM.json').read_text())
    assert manifest['revision'] == '646a641cfff77f4815e1e29829a09e1ed15a2999'
    assert set(manifest['files']) == names
    for name, record in manifest['files'].items():
        data = (source / name).read_bytes()
        assert hashlib.sha256(data).hexdigest() == record['sha256'], name
        blob = b'blob ' + str(len(data)).encode() + b'\0' + data
        assert hashlib.sha1(blob).hexdigest() == record['git_blob'], name
print('PASS: unchanged pinned reload runtime, configuration layout and IPC dependencies')
