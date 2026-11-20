#!/usr/bin/env bash
# Validate the original IPv4 rt01 configuration on a matched Ker/Nginx build.
set -euo pipefail

if [[ $# != 4 ]]; then
    echo "Usage: $0 <nginx> <broker-socket> <fstack-template> <new-output-directory>" >&2
    exit 2
fi

nginx=$(realpath -e -- "$1")
broker=$(realpath -e -- "$2")
template=$(realpath -e -- "$3")
output=$(realpath -m -- "$4")
[[ -x "$nginx" && -S "$broker" && -f "$template" ]]
umask 077
mkdir -- "$output"
mkdir -- "$output/logs"

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$here/upstream/fstack/tests/integration/test_graceful_reload.sh"
TARGET_IP=127.0.0.1
WORKERS=1
OUT="$output"
LOG="$OUT/generation.log"
RUN_ID="rt01-config-test-$$"
FSTACK_TPL="$template"
ini=$(gen_fstack_ini rt01 1 0)
conf=$(gen_nginx_conf rt01 0)

# This probe stops at configuration validation. There is no Origin server.
unset FF_FAULT KER_NGINX_SOURCE_SUCCESSOR_ENABLE KER_NGINX_SOURCE_ABORT_RETRY_ENABLE
unset KER_NGINX_SOURCE_SHELL_ENABLE KER_NGINX_SOURCE_FIRST_HUP_ENABLE
unset KER_NGINX_SOURCE_BOOTSTRAP_PATH KER_SOCKET_BROKER_PATH
export KER_FSTACK_NGINX_INI="$ini"

expect_listener_rejection() {
    local configuration="$1" log="$2" rc=0
    timeout 10 "$nginx" -t -p "$OUT/" -c "$configuration" </dev/null >"$log" 2>&1 || rc=$?
    if [[ "$rc" != 1 ]] || ! grep -Fq 'C22 profile validation: listener structure/options' "$log"; then
        echo "Expected an explicit listener rejection for $configuration (exit $rc)" >&2
        cat -- "$log" >&2
        return 1
    fi
}

expect_listener_rejection "$conf" "$OUT/legacy-mode.log"

read -r start_ticks deadline nonce < <(python3 -B - "$$" <<'PY'
from pathlib import Path
import secrets
import sys
import time

stat = Path(f"/proc/{sys.argv[1]}/stat").read_text().rsplit(")", 1)[1].split()
print(stat[19], time.monotonic_ns() + 30_000_000_000, secrets.token_hex(16))
PY
)
export KER_NGINX_SOURCE_SHELL_ENABLE=1 KER_NGINX_SOURCE_FIRST_HUP_ENABLE=1
export KER_NGINX_SOURCE_BOOTSTRAP_PATH="$OUT/origin.sock"
export KER_SOCKET_BROKER_PATH="$broker"
export KER_NGINX_SOURCE_BOOTSTRAP_SUPERVISOR_PID=$$
export KER_NGINX_SOURCE_BOOTSTRAP_SUPERVISOR_START="$start_ticks"
export KER_NGINX_SOURCE_BOOTSTRAP_NONCE="$nonce"
export KER_NGINX_SOURCE_BOOTSTRAP_EPOCH=1
export KER_NGINX_SOURCE_BOOTSTRAP_DEADLINE_NS="$deadline"
timeout 10 "$nginx" -t -p "$OUT/" -c "$conf" </dev/null >"$OUT/source-shell-mode.log" 2>&1

sed 's/listen       80;/listen       81;/' "$conf" > "$OUT/ngx_wrong_port.conf"
expect_listener_rejection "$OUT/ngx_wrong_port.conf" "$OUT/wrong-port.log"
printf 'Original rt01 Nginx listener profile accepted with both rejection controls\n'
