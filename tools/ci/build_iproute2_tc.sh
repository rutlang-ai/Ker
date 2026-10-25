#!/usr/bin/env bash
set -euo pipefail

if (( $# != 1 )); then
    echo "usage: $0 OUTPUT_DIRECTORY" >&2
    exit 2
fi

output_dir=$1
version=6.10.0
sha256=91a62f82737b44905a00fa803369c447d549e914e9a2a4018fdd75b1d54e8dce
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/ker-iproute2-${version}.XXXXXX")
trap 'rm -rf -- "$work_dir"' EXIT

archive="$work_dir/iproute2-${version}.tar.xz"
source_dir="$work_dir/source"
mkdir -p "$source_dir" "$output_dir"
curl --fail --location --retry 3 \
    "https://www.kernel.org/pub/linux/utils/net/iproute2/iproute2-${version}.tar.xz" \
    --output "$archive"
printf '%s  %s\n' "$sha256" "$archive" | sha256sum --check --status
tar -xf "$archive" --strip-components=1 -C "$source_dir"

# Build from the top-level Makefile so its include paths and config are passed
# correctly into lib and tc; direct `make -C lib` loses that context.
make -C "$source_dir" -j 2 SUBDIRS='lib tc'
install -m 0755 "$source_dir/tc/tc" "$output_dir/tc"
"$output_dir/tc" -V

if [[ ! -d /sys/module/sch_netem ]]; then
    if (( EUID == 0 )); then
        modprobe sch_netem
    else
        sudo -n modprobe sch_netem
    fi
fi
unshare --user --map-root-user --net sh -ceu '
    tc_bin=$1
    ip link set lo up
    "$tc_bin" qdisc add dev lo root netem delay 2ms 1ms loss 2% reorder 20% 50% seed 42
    "$tc_bin" qdisc show dev lo | grep -Fq "qdisc netem"
    "$tc_bin" qdisc del dev lo root
' sh "$output_dir/tc"
