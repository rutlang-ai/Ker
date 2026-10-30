"""Check the unchanged parser and the complete retained source contract."""
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
manifest = json.loads((root / 'third_party/fstack-config/UPSTREAM.json').read_text())
for name, entry in manifest['files'].items():
    actual = hashlib.sha256((root / 'third_party/fstack-config' / name).read_bytes()).hexdigest()
    assert actual == entry['sha256'], name
source = (root / 'tests/upstream/fstack/tests/unit/test_ff_config.c').read_text()
excerpt = (root / 'tests/fstack-config-unload-source.inc').read_text().rstrip()
assert excerpt in source
assert excerpt.startswith('static void\ntest_ff_unload_config_zeroes_state(')
cases = (root / 'tests/fstack-config-cases.txt').read_text().splitlines()
for name in cases:
    start = source.index('static void\n' + name + '(')
    end = source.index('\n}', start) + 2
    retained = (root / 'tests/fstack-config-source' / (name + '.inc')).read_text().rstrip()
    assert retained == source[start:end], name
print('unchanged parser and complete unload source contract verified')
