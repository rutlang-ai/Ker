#!/usr/bin/env bash
set -euo pipefail
if (( $# != 1 )); then
    echo 'usage: build_packetdrill.sh OUTPUT_DIRECTORY' >&2
    exit 2
fi
output_dir=$1
# The 2024 tool's TCP_INFO layout fits the pinned Linux 6.12 UAPI. Newer
# packetdrill revisions assert a larger structure, even on a stock 6.12 host.
revision=8051382e6ac928c4c13a88b34832649d9b07abc2
sha256=7325318f2a07282ee457b23b1f84adc14928a6d719a8262607bb8dde4ce6133d
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/ker-packetdrill.XXXXXX")
trap 'rm -rf -- "$work_dir"' EXIT
curl --fail --location --retry 3 \
    "https://codeload.github.com/google/packetdrill/tar.gz/${revision}" \
    --output "$work_dir/source.tar.gz"
printf '%s  %s\n' "$sha256" "$work_dir/source.tar.gz" | sha256sum --check --status
mkdir -p "$work_dir/source" "$output_dir"
tar -xf "$work_dir/source.tar.gz" --strip-components=1 -C "$work_dir/source"
tool_dir="$work_dir/source/gtests/net/packetdrill"
python3 - "$tool_dir" "$work_dir/originals.json" <<'PY'
import hashlib, json, sys
from pathlib import Path
root = Path(sys.argv[1])
files = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
         for p in root.rglob('*') if p.is_file()}
Path(sys.argv[2]).write_text(json.dumps(files, indent=2) + '\n')
PY
# GNU11 accepts this unchanged tool's bool enum; dynamic linkage permits the
# private syscall adapter. Packet parsing, assertions and timing stay upstream.
make -C "$tool_dir" -j 2 CC='cc -std=gnu11' 'packetdrill-ext-libs=-lpthread -lrt -ldl'
install -m 0755 "$tool_dir/packetdrill" "$output_dir/packetdrill"
python3 - "$tool_dir" "$output_dir" "$revision" "$sha256" "$work_dir/originals.json" <<'PY'
import hashlib, json, sys
from pathlib import Path
root, output = map(Path, sys.argv[1:3])
sources = json.loads(Path(sys.argv[5]).read_text())
for name, expected in sources.items():
    if hashlib.sha256((root / name).read_bytes()).hexdigest() != expected:
        raise SystemExit('modified packetdrill source: ' + name)
proof = dict(repository='https://github.com/google/packetdrill', revision=sys.argv[3],
             archive_sha256=sys.argv[4], source_hashes=sources,
             cc='cc -std=gnu11', libraries='-lpthread -lrt -ldl',
             binary_sha256=hashlib.sha256((output / 'packetdrill').read_bytes()).hexdigest())
(output / 'provenance.json').write_text(json.dumps(proof, indent=2) + '\n')
PY
