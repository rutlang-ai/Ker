"""Verify the byte-identical source used by the reload message adapter."""
import hashlib
import json
from pathlib import Path

directory = Path(__file__).resolve().parents[1] / 'third_party/fstack-reload'
manifest = json.loads((directory / 'UPSTREAM.json').read_text())
assert manifest['revision'] == '646a641cfff77f4815e1e29829a09e1ed15a2999'
assert set(manifest['files']) == {'ff_reload.c', 'ff_config.h'}
for name, record in manifest['files'].items():
    data = (directory / name).read_bytes()
    assert hashlib.sha256(data).hexdigest() == record['sha256'], name
    blob = b'blob ' + str(len(data)).encode() + b'\0' + data
    assert hashlib.sha1(blob).hexdigest() == record['git_blob'], name
