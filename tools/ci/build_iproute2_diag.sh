#!/usr/bin/env bash
set -euo pipefail
if (( $# != 1 )); then
    echo 'usage: build_iproute2_diag.sh OUTPUT_DIRECTORY' >&2
    exit 2
fi
output_dir=$1
version=6.12.0
sha256=bbd141ef7b5d0127cc2152843ba61f274dc32814fa3e0f13e7d07a080bef53d9
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/ker-iproute2-diag.XXXXXX")
trap 'rm -rf -- "$work_dir"' EXIT
curl --fail --location --retry 3 \
    "https://www.kernel.org/pub/linux/utils/net/iproute2/iproute2-${version}.tar.xz" \
    --output "$work_dir/source.tar.xz"
printf '%s  %s\n' "$sha256" "$work_dir/source.tar.xz" | sha256sum --check --status
mkdir -p "$work_dir/source" "$output_dir"
tar -xf "$work_dir/source.tar.xz" --strip-components=1 -C "$work_dir/source"
(
    cd "$work_dir/source"
    sha256sum misc/ss.c misc/nstat.c lib/libnetlink.c tc/tc.c tc/q_netem.c > "$work_dir/originals.sha256"
)
make -C "$work_dir/source" -j 2 SUBDIRS='lib misc tc'
(
    cd "$work_dir/source"
    sha256sum --check "$work_dir/originals.sha256"
)
install -m 0755 "$work_dir/source/misc/ss" "$output_dir/ss"
install -m 0755 "$work_dir/source/misc/nstat" "$output_dir/nstat"
install -m 0755 "$work_dir/source/tc/tc" "$output_dir/tc"
python3 - "$output_dir" "$version" "$sha256" "$work_dir/originals.sha256" <<'PY'
import hashlib
import json
from pathlib import Path
import sys
root = Path(sys.argv[1])
proof = dict(version=sys.argv[2], archive_sha256=sys.argv[3],
    source_hashes={line.split()[1]: line.split()[0] for line in Path(sys.argv[4]).read_text().splitlines()},
    binaries={name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in ('ss', 'nstat', 'tc')})
(root / 'provenance.json').write_text(json.dumps(proof, indent=2) + '\n')
PY
"$output_dir/ss" -V
