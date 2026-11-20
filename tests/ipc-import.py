"""Check the unchanged F-Stack IPC source and message layouts."""
import hashlib
import json
from pathlib import Path

directory = Path(__file__).resolve().parents[1] / 'third_party/fstack-ipc'
manifest = json.loads((directory / 'UPSTREAM.json').read_text())
assert manifest['revision'] == '646a641cfff77f4815e1e29829a09e1ed15a2999'
assert set(manifest['files']) == {'ff_ipc.c', 'ff_ipc.h', 'ff_msg.h', 'ff_reload.h'}
for name, record in manifest['files'].items():
    data = (directory / name).read_bytes()
    assert hashlib.sha256(data).hexdigest() == record['sha256'], name
    blob = b'blob ' + str(len(data)).encode() + b'\0' + data
    assert hashlib.sha1(blob).hexdigest() == record['git_blob'], name
print('PASS: pinned IPC adapter inputs and message layouts')
