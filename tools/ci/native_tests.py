#!/usr/bin/env python3
"""Select, run, and report the hosted native-backend test matrix."""
from __future__ import annotations

import json
import hashlib
import ast
import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET


LINUX_PROTOCOL_SELFTESTS = (
    "linux-original-sk-connect-zero-addr", "linux-original-tcp-inq-ipv4",
    "linux-original-tcp-inq-ipv6", "linux-original-reject-host-only",
    "linux-original-net-reuseaddr_conflict", "linux-original-net-sk_bind_sendto_listen",
    "linux-original-net-bind_timewait", "linux-original-net-bind_wildcard",
    "linux-original-net-reuseport_dualstack", "linux-original-net-sk_so_peek_off",
    "linux-original-net-run_netsocktests",
)

LINUX_NET_PROFILE_TESTS = {"linux-original-net-tun", "linux-original-net-reuseport_addr_any"}
LINUX_MACVTAP_PROFILE_TEST = "linux-original-net-tap"
LINUX_NETLINK_DUMPS_PROFILE_TEST = "linux-original-net-netlink-dumps"
LINUX_NEXTHOP_PROFILE_TEST = "linux-original-forwarding-router-nh"
LINUX_NEXTHOP_REALTIME_TEST = "nexthop-realtime-wrapper-contract"
LINUX_BRIDGE_PROFILE_TEST = "linux-original-forwarding-router-bridge"
LINUX_BRIDGE_REALTIME_TEST = "bridge-realtime-wrapper-contract"
LINUX_BRIDGE_PACKET_REALTIME_TEST = "bridge-packet-realtime-wrapper-contract"
LINUX_BRIDGE_PROFILE_TESTS = {LINUX_BRIDGE_PROFILE_TEST: "router_bridge.sh",
                              "linux-original-forwarding-router-bridge-vlan": "router_bridge_vlan.sh",
                              "linux-original-forwarding-router-bridge-1d": "router_bridge_1d.sh",
                              "linux-original-forwarding-router-bridge-vlan-upper": "router_bridge_vlan_upper.sh",
                              "linux-original-forwarding-router-bridge-pvid-vlan-upper": "router_bridge_pvid_vlan_upper.sh",
                              "linux-original-forwarding-router-bridge-vlan-upper-pvid": "router_bridge_vlan_upper_pvid.sh",
                              "linux-original-forwarding-bridge-mdb-host": "bridge_mdb_host.sh",
                              "linux-original-forwarding-bridge-sticky-fdb": "bridge_sticky_fdb.sh",
                              "linux-original-forwarding-bridge-fdb-learning-limit": "bridge_fdb_learning_limit.sh",
                              "linux-original-forwarding-bridge-mdb-port-down": "bridge_mdb_port_down.sh",
                              "linux-original-forwarding-bridge-port-isolation": "bridge_port_isolation.sh",
                              "linux-original-forwarding-bridge-vlan-unaware": "bridge_vlan_unaware.sh",
                              "linux-original-forwarding-bridge-vlan-aware": "bridge_vlan_aware.sh",
                              "linux-original-forwarding-bridge-locked-port": "bridge_locked_port.sh"}
LINUX_XT_STRING_PROFILE_TEST = "linux-original-netfilter-xt-string"
LINUX_RPATH_PROFILE_TEST = "linux-original-netfilter-rpath"
LINUX_RPATH_REALTIME_TEST = "rpath-realtime-wrapper-contract"
LINUX_IPIP_PROFILE_TEST = "linux-original-netfilter-conntrack-ipip-mtu"
LINUX_NAT_PROFILE_TEST = "linux-original-netfilter-conntrack-icmp-related"
LINUX_CONNTRACK_PROFILE_TEST = "linux-original-netfilter-conntrack-dump-flush"
LINUX_NETNS_NAME_PROFILE_TEST = "linux-original-net-netns-name"
LINUX_FORWARDING_PROFILE_TEST = "linux-original-forwarding-router-vid1"
LINUX_FORWARDING_PROFILE_TESTS = {LINUX_FORWARDING_PROFILE_TEST: "router_vid_1.sh",
                                  "linux-original-forwarding-mtu": "min_max_mtu.sh",
                                  "linux-original-forwarding-router-broadcast": "router_broadcast.sh"}
LINUX_BROADCAST_REALTIME_TEST = "broadcast-realtime-wrapper-contract"

LINUX_AF_UNIX_SELFTESTS = (
    "linux-original-af-unix-diag_uid", "linux-original-af-unix-msg_oob",
    "linux-original-af-unix-scm_pidfd", "linux-original-af-unix-scm_rights",
    "linux-original-af-unix-unix_connect",
)

LINUX_MPTCP_SELFTESTS = (
    "linux-mptcp-fixture-shutdown",
    "linux-original-mptcp-ipv4-client", "linux-original-mptcp-ipv4-server",
    "linux-original-mptcp-ipv6-client", "linux-original-mptcp-ipv6-server",
    "linux-original-mptcp-pm-netlink",
    "linux-original-mptcp-sockopt-ipv4", "linux-original-mptcp-sockopt-ipv6",
    "linux-original-mptcp-inq-ipv4", "linux-original-mptcp-inq-ipv6",
    "linux-original-mptcp-diag",
    "native-c24-ingress-freeze-tap", "native-c28-broker-owned-cutover-tap",
    "native-c28-broker-owned-cutover-abort-tap", "native-c28-cutover-start-cancel-destroy-retry",
    "linux-original-mptcp-simult-flows", "linux-original-mptcp-userspace-pm",
)
LINUX_MPTCP_SOCKOPT_PROFILE_TEST = "linux-original-mptcp-sockopt-shell"
LINUX_MPTCP_JOIN_PROFILE_TEST = "linux-original-mptcp-join"
LINUX_MPTCP_JOIN_EXPECTED_CASES = 126
LINUX_MPTCP_CONNECT_PROFILE_TESTS = {"linux-original-mptcp-connect-" + suite
                                     for suite in ("connect", "mmap", "sendfile", "checksum")}

LINUX_TCP_AO_SELFTESTS = tuple(
    f"linux-original-tcp-ao-{program}-ipv{family}"
    for program in ("bench-lookups", "connect", "connect-deny", "icmps-accept", "icmps-discard",
                    "key-management", "restore", "rst", "self-connect", "seq-ext",
                    "setsockopt-closed", "unsigned-md5")
    for family in (4, 6)
)

HOSTED_SAFE = (
    "native-fstack-fortify-bounds",
    "native-linux-fetch-lock",
    "native-packet-header",
    "native-fstack-session-peer-drain-retry",
    "native-fstack-session-lease-input",
    "native-fstack-session-dpdk-plugin-discovery",
    "native-fstack-session-envelope",
    "native-fstack-session-peer-mirror",
    "native-fstack-hugepage-preflight",
    "native-fstack-packet-device",
    "native-fstack-worker-clock",
    "native-fstack-worker-log",
    "native-fstack-thread-runtime",
    "native-fstack-thread-runtime-debug",
    "native-fstack-thread-runtime-release",
    "native-fstack-host-usercopy",
    "native-fstack-host-semaphore-debug",
    "native-fstack-host-semaphore-release",
    "native-fstack-host-failure-debug",
    "native-fstack-host-failure-release",
    "native-fstack-fd-map",
    "native-fstack-errno",
    "native-fstack-entropy",
    "native-fstack-realtime",
    "native-fstack-current-time-optional",
    "native-fstack-current-time-errors",
    "native-fstack-current-time-parallel",
    "native-fstack-current-time-sockets",
    "native-fstack-current-time-parallel-sockets",
    "native-fstack-host-runtime",
    "native-fstack-exception-config",
    "native-fstack-buffer-resize",
    "native-fstack-buffer-write-overflow",
    "native-fstack-buffer-write-null",
    "native-fstack-buffer-write-copy",
    "native-fstack-buffer-write-parallel",
    "native-fstack-buffer-write-handoff",
    "native-fstack-buffer-writer-empty",
    "native-fstack-buffer-writer-append",
    "native-fstack-buffer-writer-zero",
    "native-fstack-buffer-writer-constructor",
    "native-fstack-buffer-writer-retry",
    "native-fstack-buffer-writer-stale",
    "native-fstack-buffer-segments-ranges",
    "native-fstack-buffer-segments-layout",
    "native-fstack-buffer-segments-failures",
    "native-fstack-buffer-segments-constructor-matrix",
    "native-fstack-buffer-segments-destroy-matrix",
    "native-fstack-buffer-segments-parallel",
    "native-fstack-buffer-segments-handoff",
    "native-fstack-host-pages-debug",
    "native-fstack-host-pages-release",
    "native-fstack-host-timer-debug",
    "native-fstack-host-timer-release",
    "native-fstack-launcher-config",
    "native-fstack-config-lifecycle",
    "native-fstack-interface-section-validation",
    "native-fstack-bond-worker-limits",
    "native-ker-run-boundaries",
    "native-ker-run-exit-status",
    "native-linux-fingerprint-stale-inputs",
    "native-linux-artifact-lock",
    "native-bond-numa-preflight",
    "udp-validation-report-guards",
    "host-udp-signal-reference",
    "host-udp-contract-matrix",
    "host-fstack-socket-contracts-reference",
    "host-fstack-readiness-reference",
    "native-fstack-typed-vdev-config",
    "native-fstack-rx-queues-config",
    "native-fstack-typed-bond-config",
    "native-fstack-multiport-config",
    "fstack-sendmmsg-short-boundary",
)

SESSION_DIRECT = "native-fstack-session-native-packets"
SESSION_CTEST = (
    "native-fstack-session-control-roundtrip",
    "native-fstack-session-control-malformed",
    "native-fstack-session-control-replay",
    "native-fstack-session-control-isolation",
    "native-fstack-session-control-capacity",
    "native-fstack-session-control-recycle",
    "native-fstack-session-control-master-eof",
    "native-fstack-session-control-master-death",
    "native-fstack-session-control-master-frozen",
    "native-fstack-session-control-reservation-eof",
    "native-fstack-session-control-reservation-death",
    "native-fstack-session-control-reservation-coordinates",
    "native-fstack-session-control-reservation-replay",
    "native-fstack-session-control-reservation-collision",
    "native-fstack-session-control-reservation-bounds",
    "native-fstack-session-orphan-reservation-eof",
    "native-fstack-session-orphan-reservation-frozen",
    "native-fstack-session-orphan-reservation-staged",
    "native-fstack-session-namespace-names",
    "native-fstack-session-namespace-isolation",
    "native-fstack-session-namespace-recreate",
    "native-packet-header",
    "native-fstack-session-peer-drain-retry",
    "native-fstack-session-lease-input",
    "native-fstack-session-dpdk-plugin-discovery",
    "native-fstack-session-envelope",
    "native-fstack-session-tc3-observer",
    "native-fstack-session-peer-mirror",
    "native-fstack-session-drain-peer",
    "native-fstack-session-standby",
    "native-fstack-session-ring-pmd",
    "native-fstack-session-registration",
    "native-fstack-session-coordinate",
    "native-fstack-hugepage-preflight",
    "native-fstack-session-generation-rings",
    "native-fstack-session-generation-rings-registration",
    "native-fstack-session-generation-tx-full",
    "native-fstack-session-generation-detach",
    "native-fstack-session-generation-empty-config",
    "native-fstack-session-generation-invalid-selected-entry",
    "native-fstack-session-orphan-identity",
    "native-fstack-session-orphan-inflight-both",
    "native-fstack-session-orphan-inflight-rx",
    "native-fstack-session-orphan-inflight-tx",
    "native-fstack-session-orphan-live",
    "native-fstack-session-orphan-reap",
)

MANDATORY_SESSION_PROFILES = frozenset({
    "positive", "frame-positive", "nonframe-active-reap",
    "bad-capability", "bad-tx-lease", "bad-rx-lease", "peer-death", "timeout",
    "handoff-control-hup", "prepare-enoent", "prepare-ebusy", "prepare-eperm",
    "bad-prepare-error", "bad-prepare-error-token", "bad-prepare-error-capability",
    "bad-prepare-error-tx-lease", "bad-prepare-error-rx-lease",
    "bad-prepare-error-sequence", "bad-prepare-success",
})
MANDATORY_NEGATIVE_PROFILES = frozenset(MANDATORY_SESSION_PROFILES - {
    "positive", "frame-positive", "nonframe-active-reap",
})
FRAME_RECOVERY_PROFILES = frozenset({
    "frame-full",
    "frame-death-prepared", "frame-death-consumer-prepared",
    "frame-death-both-prepared", "frame-lost-prepare-reply",
    "frame-death-consumer-writing", "frame-death-queued",
    "frame-death-producer-active-consumer",
})

# These component tests use real EAL with --no-huge and no TAP device. RX queue
# ownership additionally requires at least two CPUs in the runner's cpuset.
NOHUGE_EAL = (
    "worker-mbuf",
    "native-fstack-pcap",
    "native-fstack-rx-lcores-ownership",
)

# These socket tests use real EAL with --no-huge and net_tap. They need no
# hugetlb allocation, but do need /dev/net/tun and unprivileged network namespaces.
NOHUGE_TAP = (
    "native-fstack-fortified-io",
    "native-raw-icmp-contracts",
    "native-fstack-packet-sockets",
    "native-fstack-eal-base-virtaddr",
    "native-fstack-eal-file-prefix",
    "native-fstack-eal-log-level",
    "native-fstack-eal-memory",
    "native-fstack-memory-channels",
    "native-fstack-exception-filter",
    "native-fstack-application-environment",
    "native-fstack-startup-lifecycle",
    "native-fstack-startup-failures",
    "native-fstack-bind-address-no-port",
    "native-fstack-ephemeral-ports",
    "native-fstack-network-sysctl",
    "native-posix-tcp-interop",
    "native-udp-signal-boundary",
    "native-udp-wire-errors",
)

# These software datapath tests have explicit, provisionable CI dependencies:
# the pinned TAP retry adapter, DPDK virtio/vhost PMDs, /dev/vhost-net, and two
# allowed CPUs. They must not silently pass via CTest's skip return code.
REQUIRED_SOFTWARE_DATAPATH = (
    "native-fstack-tap-offload-retry",
    "native-fstack-virtio-kernel-offloads",
    "native-fstack-native-buffers",
    "native-fstack-typed-vdev",
    "native-fstack-rx-lcores",
    "native-fstack-rx-queues",
)

# Add a name only after reviewing why that particular test cannot run on the
# hosted runner. An empty set makes any new/unreviewed skip fail the full job.
REVIEWED_OPTIONAL_SKIPS: frozenset[str] = frozenset()


def summary(message: str) -> None:
    print(message)
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as stream:
            stream.write(f"\n{message}\n")


def require(value: bool, message: str) -> None:
    if not value:
        raise RuntimeError(message)


def ctest_inventory(build: Path) -> list[dict]:
    result = subprocess.run(
        ["ctest", "--test-dir", str(build), "--show-only=json-v1"],
        check=True, capture_output=True, text=True,
    )
    return json.loads(result.stdout)["tests"]


def ctest_names(build: Path) -> set[str]:
    return {item["name"] for item in ctest_inventory(build)}


def test_properties(item: dict) -> dict:
    raw = item.get("properties", [])
    if isinstance(raw, dict):
        return raw
    return {prop.get("name"): prop.get("value") for prop in raw if isinstance(prop, dict)}


def property_labels(item: dict) -> set[str]:
    value = test_properties(item).get("LABELS", [])
    if isinstance(value, str):
        return set(value.split(";"))
    return set(value)


def run_group(build: Path, group: str, tests: tuple[str, ...]) -> None:
    registered = ctest_names(build)
    missing = sorted(set(tests) - registered)
    if missing:
        raise RuntimeError(f"{group}: expected CTests are absent: {missing}")
    regex = "^(" + "|".join(re.escape(name) for name in tests) + ")$"
    with tempfile.TemporaryDirectory(prefix="ker-ctest-") as temporary:
        junit = Path(temporary) / "results.xml"
        result = subprocess.run(
            ["ctest", "--test-dir", str(build), "--no-tests=error",
             "--output-on-failure", "--output-junit", str(junit), "-R", regex],
            check=False,
        )
        if not junit.is_file():
            raise RuntimeError(f"{group}: CTest did not produce its result report")
        root = ET.parse(junit).getroot()
        cases = root.findall(".//testcase")
        by_name: dict[str, list[ET.Element]] = {}
        for case in cases:
            by_name.setdefault(case.attrib.get("name", ""), []).append(case)
        bad = []
        for name in tests:
            found = by_name.get(name, [])
            if len(found) != 1:
                bad.append(f"{name}: expected once, saw {len(found)}")
                continue
            case = found[0]
            if case.find("skipped") is not None:
                bad.append(f"{name}: skipped")
            if case.find("failure") is not None or case.find("error") is not None:
                bad.append(f"{name}: failed")
        if result.returncode or bad:
            raise RuntimeError(f"{group}: required tests did not all pass: {bad}")
        summary(f"{group}: PASS ({len(tests)}/{len(tests)} required tests; no skips).")


def junit_cases(path: Path) -> list[ET.Element]:
    root = ET.parse(path).getroot()
    return root.findall(".//testcase")


def report_junit(path: Path, expected: set[str] | None = None,
                 required: set[str] | None = None,
                 ctest_returncode: int = 0) -> None:
    cases = junit_cases(path)
    by_name: dict[str, list[ET.Element]] = {}
    for case in cases:
        by_name.setdefault(case.attrib.get("name", ""), []).append(case)
    skipped = sorted(case.attrib.get("name", "?") for case in cases if case.find("skipped") is not None)
    failed = sorted(case.attrib.get("name", "?") for case in cases
                    if case.find("failure") is not None or case.find("error") is not None)
    passed = len(cases) - len(skipped) - len(failed)
    summary(f"CTest report: {len(cases)} total; {passed} passed; {len(skipped)} skipped; {len(failed)} failed.")
    if skipped:
        summary("CTest skipped tests (not passes): " + ", ".join(skipped))
    if failed:
        summary("CTest failed tests: " + ", ".join(failed))
    malformed = []
    if expected is not None:
        for name in sorted(expected):
            if len(by_name.get(name, [])) != 1:
                malformed.append(f"{name}: expected once in JUnit, saw {len(by_name.get(name, []))}")
        extras = sorted(set(by_name) - expected)
        if extras:
            malformed.append("unexpected JUnit tests: " + ", ".join(extras))
    required = required or set()
    required_skips = sorted(set(skipped) & required)
    if required_skips:
        malformed.append("required tests skipped: " + ", ".join(required_skips))
    unreviewed_skips = sorted(set(skipped) - required - REVIEWED_OPTIONAL_SKIPS)
    if unreviewed_skips:
        malformed.append("unreviewed CTest skips: " + ", ".join(unreviewed_skips))
    if not cases or failed or malformed or ctest_returncode:
        raise RuntimeError("full CTest graph failed: " + repr(dict(
            ctest_returncode=ctest_returncode, failed=failed, problems=malformed)))


def run_full_ctest(build: Path, junit: Path) -> None:
    inventory = ctest_inventory(build)
    by_name = {item["name"]: item for item in inventory}
    names = set(by_name)
    validate_default_profile_inventory(names)
    missing = sorted((set(HOSTED_SAFE) | set(NOHUGE_EAL) | set(NOHUGE_TAP) |
                      set(REQUIRED_SOFTWARE_DATAPATH) | set(LINUX_PROTOCOL_SELFTESTS) |
                      set(LINUX_AF_UNIX_SELFTESTS) | set(LINUX_MPTCP_SELFTESTS) | set(LINUX_TCP_AO_SELFTESTS) |
                      set(SESSION_CTEST) | {SESSION_DIRECT}) - names)
    if missing:
        raise RuntimeError("native CTest inventory is missing required tests: " + repr(missing))
    session_labeled = {
        item["name"] for item in inventory
        if "session" in property_labels(item)
    }
    if session_labeled != set(SESSION_CTEST) | {SESSION_DIRECT}:
        raise RuntimeError("session CTest label inventory changed: " + repr({
            "missing": sorted((set(SESSION_CTEST) | {SESSION_DIRECT}) - session_labeled),
            "unexpected": sorted(session_labeled - (set(SESSION_CTEST) | {SESSION_DIRECT})),
        }))
    expected = names - {SESSION_DIRECT}
    required = (set(HOSTED_SAFE) | set(NOHUGE_EAL) | set(NOHUGE_TAP) |
                set(REQUIRED_SOFTWARE_DATAPATH) | set(LINUX_PROTOCOL_SELFTESTS) |
                set(LINUX_AF_UNIX_SELFTESTS) | set(LINUX_MPTCP_SELFTESTS) | set(LINUX_TCP_AO_SELFTESTS) | set(SESSION_CTEST))
    result = subprocess.run(
        ["ctest", "--test-dir", str(build), "--no-tests=error", "--output-on-failure",
         "--output-junit", str(junit), "--parallel", "1", "-E", "^" + re.escape(SESSION_DIRECT) + "$"],
        check=False,
    )
    if not junit.is_file():
        raise RuntimeError("full CTest graph did not produce JUnit output")
    report_junit(junit, expected=expected, required=required, ctest_returncode=result.returncode)
    summary(f"Full native CTest graph: {len(expected)} registered tests; {len(required)} mandatory hosted/session/software-datapath tests; unreviewed skips fail.")


def run_net_profile(build: Path, junit: Path) -> None:
    inventory = ctest_inventory(build)
    require(all(sum(item['name'] == name for item in inventory) == 1 for name in LINUX_NET_PROFILE_TESTS),
            'net profile must register both complete original entries exactly once')
    cache = (build / 'CMakeCache.txt').read_text()
    native_build = next((line.split('=', 1)[1] for line in cache.splitlines()
                         if line.startswith('KER_NATIVE_LINUX_BUILD:PATH=')), None)
    require(native_build, 'net selftest profile has no native kernel path')
    manifest = json.loads((Path(native_build) / 'native-linux.json').read_text())
    require(manifest.get('config_fragment') == 'config/native-linux-net-selftests.config',
            'net selftests require their dedicated TUN/DCCP kernel profile')
    config = set((Path(manifest['kernel']) / '.config').read_text().splitlines())
    require({'CONFIG_TUN=y', 'CONFIG_IP_DCCP=y'}.issubset(config),
            'net profile lacks real native TUN/DCCP support')
    expression = '^(' + '|'.join(sorted(LINUX_NET_PROFILE_TESTS)) + ')$'
    result = subprocess.run(['ctest', '--test-dir', str(build), '--no-tests=error', '--output-on-failure',
                             '--output-junit', str(junit), '--parallel', '1', '-R', expression], check=False)
    require(junit.is_file(), 'net profile CTest did not produce JUnit')
    report_junit(junit, expected=LINUX_NET_PROFILE_TESTS, required=LINUX_NET_PROFILE_TESTS,
                 ctest_returncode=result.returncode)
    for name in sorted(LINUX_NET_PROFILE_TESTS):
        evidence = json.loads((build / (name + '.json')).read_text())
        require(evidence.get('status') == 'PASS_IMPORTED_LINUX' and
                evidence.get('fingerprint') == manifest.get('fingerprint'), 'net profile native evidence mismatch')
    summary('Original net: complete tun and reuseport_addr_any.sh entries, PASS ' + manifest['fingerprint'])


def run_macvtap_profile(build: Path, junit: Path) -> None:
    name = LINUX_MACVTAP_PROFILE_TEST
    inventory = ctest_inventory(build)
    require(sum(item['name'] == name for item in inventory) == 1,
            'macvtap profile must register the complete original tap entry exactly once')
    cache = (build / 'CMakeCache.txt').read_text()
    native_build = next((line.split('=', 1)[1] for line in cache.splitlines()
                         if line.startswith('KER_NATIVE_LINUX_BUILD:PATH=')), None)
    require(native_build, 'macvtap profile has no native kernel path')
    manifest = json.loads((Path(native_build) / 'native-linux.json').read_text())
    require(manifest.get('config_fragment') == 'config/native-linux-macvtap.config',
            'macvtap test requires its dedicated native kernel profile')
    config = set((Path(manifest['kernel']) / '.config').read_text().splitlines())
    require({'CONFIG_DUMMY=y', 'CONFIG_MACVLAN=y', 'CONFIG_MACVTAP=y', 'CONFIG_TAP=y',
             'CONFIG_SYSFS=y'}.issubset(config), 'macvtap profile lacks its native driver/sysfs facilities')
    result = subprocess.run(['ctest', '--test-dir', str(build), '--no-tests=error', '--output-on-failure',
                             '--output-junit', str(junit), '--parallel', '1', '-R', '^' + name + '$'], check=False)
    require(junit.is_file(), 'macvtap CTest did not produce JUnit')
    report_junit(junit, expected={name}, required={name}, ctest_returncode=result.returncode)
    evidence = json.loads((build / (name + '.json')).read_text())
    require(evidence.get('status') == 'PASS_IMPORTED_LINUX' and
            evidence.get('fingerprint') == manifest.get('fingerprint') and
            evidence.get('original', {}).get('cases') == ['tap.test_packet_valid_udp_gso',
                'tap.test_packet_valid_udp_csum', 'tap.test_packet_crash_tap_invalid_eth_proto'],
            'incomplete native macvtap evidence')
    summary('Original macvtap: all three original packet/error cases, PASS ' + manifest['fingerprint'])


def run_netlink_dumps_profile(build: Path, junit: Path) -> None:
    name = LINUX_NETLINK_DUMPS_PROFILE_TEST
    inventory = ctest_inventory(build)
    require(sum(item['name'] == name for item in inventory) == 1,
            'Netlink dumps profile must register the complete original entry exactly once')
    cache = (build / 'CMakeCache.txt').read_text()
    native_build = next((line.split('=', 1)[1] for line in cache.splitlines()
                         if line.startswith('KER_NATIVE_LINUX_BUILD:PATH=')), None)
    require(native_build, 'Netlink dumps profile has no native kernel path')
    manifest = json.loads((Path(native_build) / 'native-linux.json').read_text())
    require(manifest.get('config_fragment') == 'config/native-linux-netlink-dumps.config',
            'Netlink dumps require the dedicated native mqueue profile')
    config = (Path(manifest['kernel']) / '.config').read_text().splitlines()
    require('CONFIG_POSIX_MQUEUE=y' in config, 'Netlink dump reference test requires real native mqueue')
    result = subprocess.run(['ctest', '--test-dir', str(build), '--no-tests=error', '--output-on-failure',
                             '--output-junit', str(junit), '--parallel', '1', '-R', '^' + name + '$'], check=False)
    require(junit.is_file(), 'Netlink dumps CTest did not produce JUnit')
    report_junit(junit, expected={name}, required={name}, ctest_returncode=result.returncode)
    evidence = json.loads((build / (name + '.json')).read_text())
    native = evidence.get('native_fixture', {})
    require(evidence.get('status') == 'PASS_IMPORTED_LINUX' and
            evidence.get('fingerprint') == manifest.get('fingerprint') and
            evidence.get('original', {}).get('cases') == ['global.test_sanity',
                'global.close_in_progress', 'global.close_with_ref'] and
            tuple(native.get(k) for k in ('generic_netlinks', 'mq_opens', 'mq_notifications',
                'mq_closes', 'notified_netlink_closes', 'live')) == (3, 1, 1, 1, 1, 0),
            'incomplete native Netlink dump/message-queue reference evidence')
    summary('Original Netlink dumps: three complete lifecycle cases, PASS ' + manifest['fingerprint'])


def run_nexthop_profile(build: Path, junit: Path) -> None:
    name = LINUX_NEXTHOP_PROFILE_TEST
    control = LINUX_NEXTHOP_REALTIME_TEST
    inventory = [item['name'] for item in ctest_inventory(build)]
    require(inventory.count(name) == 1 and inventory.count(control) == 1,
            'nexthop profile must register the complete original entry and realtime ABI control exactly once')
    cache = (build / 'CMakeCache.txt').read_text()
    native_build = next((line.split('=', 1)[1] for line in cache.splitlines()
                         if line.startswith('KER_NATIVE_LINUX_BUILD:PATH=')), None)
    require(native_build, 'nexthop profile has no native kernel path')
    manifest = json.loads((Path(native_build) / 'native-linux.json').read_text())
    config = set((Path(manifest['kernel']) / '.config').read_text().splitlines())
    require(manifest.get('config_fragment') == 'config/native-linux-nexthop-selftests.config' and
            {'CONFIG_VETH=y', 'CONFIG_NET_VRF=y', 'CONFIG_IP_ROUTE_MULTIPATH=y',
             'CONFIG_IP_MULTIPLE_TABLES=y', 'CONFIG_IPV6_MULTIPLE_TABLES=y', 'CONFIG_NET_CLS_ACT=y',
             'CONFIG_NET_SCH_INGRESS=y'}.issubset(config),
            'nexthop requires its real native nexthop/clsact/VRF profile')
    result = subprocess.run(['ctest', '--test-dir', str(build), '--no-tests=error', '--output-on-failure',
                            '--output-junit', str(junit), '--parallel', '1', '-R', '^(' + name + '|' + control + ')$'], check=False)
    require(junit.is_file(), 'nexthop CTest did not produce JUnit')
    report_junit(junit, expected={name, control}, required={name, control}, ctest_returncode=result.returncode)
    evidence = json.loads((build / (name + '.json')).read_text())
    require(evidence.get('status') == 'PASS_IMPORTED_LINUX' and
            evidence.get('fingerprint') == manifest.get('fingerprint'), 'wrong native nexthop evidence')
    script = Path(__file__).resolve().parents[2] / 'tests/posix/linux-nexthop-selftest.py'
    spec = importlib.util.spec_from_file_location('nexthop_contract', script)
    contract = importlib.util.module_from_spec(spec); spec.loader.exec_module(contract)
    contract.validate_evidence(evidence)
    summary('Original nexthop objects: complete shared IPv4/IPv6 routing and clsact lifecycle, PASS ' + manifest['fingerprint'])


def run_bridge_profile(build: Path, junit: Path) -> None:
    names = set(LINUX_BRIDGE_PROFILE_TESTS)
    controls = {LINUX_BRIDGE_REALTIME_TEST, LINUX_BRIDGE_PACKET_REALTIME_TEST}
    inventory = [item['name'] for item in ctest_inventory(build)]
    require(all(inventory.count(name) == 1 for name in names | controls),
            'bridge profile must register all fourteen complete original entries and both clock controls exactly once')
    cache = (build / 'CMakeCache.txt').read_text()
    native_build = next((line.split('=', 1)[1] for line in cache.splitlines()
                         if line.startswith('KER_NATIVE_LINUX_BUILD:PATH=')), None)
    require(native_build, 'bridge profile has no native kernel path')
    manifest = json.loads((Path(native_build) / 'native-linux.json').read_text())
    config = set((Path(manifest['kernel']) / '.config').read_text().splitlines())
    require(manifest.get('config_fragment') == 'config/native-linux-bridge-selftests.config' and
            {'CONFIG_VETH=y', 'CONFIG_NET_VRF=y', 'CONFIG_VLAN_8021Q=y', 'CONFIG_IP_ROUTE_MULTIPATH=y',
             'CONFIG_IP_MULTIPLE_TABLES=y', 'CONFIG_IPV6_MULTIPLE_TABLES=y', 'CONFIG_BRIDGE=y',
             'CONFIG_BRIDGE_VLAN_FILTERING=y', 'CONFIG_BRIDGE_IGMP_SNOOPING=y',
             'CONFIG_NET_CLS_ACT=y', 'CONFIG_NET_SCH_INGRESS=y', 'CONFIG_NET_CLS_FLOWER=y',
             'CONFIG_NET_ACT_GACT=y', 'CONFIG_NET_ACT_MIRRED=y'}.issubset(config),
            'bridge requires its real native bridge/VLAN/VRF profile')
    required = names | controls
    selection = '^(' + '|'.join(re.escape(item) for item in sorted(required)) + ')$'
    result = subprocess.run(['ctest', '--test-dir', str(build), '--no-tests=error', '--output-on-failure',
                            '--output-junit', str(junit), '--parallel', '1', '-R', selection], check=False)
    require(junit.is_file(), 'bridge CTest did not produce JUnit')
    report_junit(junit, expected=required, required=required, ctest_returncode=result.returncode)
    contract_script = Path(__file__).resolve().parents[2] / 'tests/posix/linux-bridge-selftest.py'
    spec = importlib.util.spec_from_file_location('bridge_contract', contract_script)
    contract = importlib.util.module_from_spec(spec); spec.loader.exec_module(contract)
    for name, program in LINUX_BRIDGE_PROFILE_TESTS.items():
        evidence = json.loads((build / (name + '.json')).read_text())
        require(evidence.get('status') == 'PASS_IMPORTED_LINUX' and
                evidence.get('fingerprint') == manifest.get('fingerprint') and
                evidence.get('program') == program, 'wrong native bridge/VLAN evidence')
        contract.validate_evidence(evidence)
    summary('Original routed bridge/PVID, VLAN switching, 802.1D and VLAN uppers: fourteen complete shells including MDB, learning limits, isolation, VLAN switching and locked-port/MAB redirect, PASS ' + manifest['fingerprint'])


def run_xt_string_profile(build: Path, junit: Path) -> None:
    name = LINUX_XT_STRING_PROFILE_TEST
    require(sum(item['name'] == name for item in ctest_inventory(build)) == 1,
            'xt_string profile must register the complete original entry exactly once')
    cache = (build / 'CMakeCache.txt').read_text()
    native_build = next((line.split('=', 1)[1] for line in cache.splitlines()
                         if line.startswith('KER_NATIVE_LINUX_BUILD:PATH=')), None)
    require(native_build, 'xt_string profile has no native kernel path')
    manifest = json.loads((Path(native_build) / 'native-linux.json').read_text())
    config = set((Path(manifest['kernel']) / '.config').read_text().splitlines())
    require(manifest.get('config_fragment') == 'config/native-linux-xt-string-selftests.config' and
            {'CONFIG_DUMMY=y', 'CONFIG_NETFILTER_XTABLES=y', 'CONFIG_IP_NF_IPTABLES=y',
             'CONFIG_IP_NF_FILTER=y', 'CONFIG_NETFILTER_XT_MATCH_STRING=y', 'CONFIG_TEXTSEARCH=y',
             'CONFIG_TEXTSEARCH_BM=y', 'CONFIG_TEXTSEARCH_KMP=y'}.issubset(config),
            'xt_string requires its real native string/BM/KMP profile')
    result = subprocess.run(['ctest', '--test-dir', str(build), '--no-tests=error', '--output-on-failure',
                            '--output-junit', str(junit), '--parallel', '1', '-R', '^' + name + '$'], check=False)
    require(junit.is_file(), 'xt_string CTest did not produce JUnit')
    report_junit(junit, expected={name}, required={name}, ctest_returncode=result.returncode)
    evidence = json.loads((build / (name + '.json')).read_text())
    require(evidence.get('status') == 'PASS_IMPORTED_LINUX' and
            evidence.get('fingerprint') == manifest.get('fingerprint'), 'wrong native xt_string evidence')
    script = Path(__file__).resolve().parents[2] / 'tests/posix/linux-xt-string-selftest.py'
    spec = importlib.util.spec_from_file_location('xt_string_contract', script)
    contract = importlib.util.module_from_spec(spec); spec.loader.exec_module(contract)
    contract.validate_evidence(evidence)
    summary('Original xt_string: ten UDP probes, eight complete BM/KMP counter windows, PASS ' + manifest['fingerprint'])


def run_rpath_profile(build: Path, junit: Path) -> None:
    name = LINUX_RPATH_PROFILE_TEST
    inventory = ctest_inventory(build)
    require(sum(item['name'] == name for item in inventory) == 1 and
            sum(item['name'] == LINUX_RPATH_REALTIME_TEST for item in inventory) == 1,
            'rpath profile must register the original entry and realtime ABI control exactly once')
    cache = (build / 'CMakeCache.txt').read_text()
    native_build = next((line.split('=', 1)[1] for line in cache.splitlines()
                         if line.startswith('KER_NATIVE_LINUX_BUILD:PATH=')), None)
    require(native_build, 'rpath profile has no native kernel path')
    manifest = json.loads((Path(native_build) / 'native-linux.json').read_text())
    config = set((Path(manifest['kernel']) / '.config').read_text().splitlines())
    require(manifest.get('config_fragment') == 'config/native-linux-rpath-selftests.config' and
            {
                'CONFIG_DUMMY=y', 'CONFIG_IP_ROUTE_MULTIPATH=y', 'CONFIG_NETFILTER_XTABLES=y',
                'CONFIG_IP_NF_IPTABLES=y', 'CONFIG_IP_NF_RAW=y', 'CONFIG_IP_NF_MATCH_RPFILTER=y',
                'CONFIG_IP6_NF_IPTABLES=y', 'CONFIG_IP6_NF_RAW=y', 'CONFIG_IP6_NF_MATCH_RPFILTER=y',
                'CONFIG_NF_TABLES=y', 'CONFIG_NF_TABLES_INET=y', 'CONFIG_NFT_FIB_IPV4=y',
                'CONFIG_NFT_FIB_IPV6=y', 'CONFIG_NFT_FIB_INET=y',
            }.issubset(config),
            'rpath shell requires its real native rpfilter/fib profile')
    required = {name, LINUX_RPATH_REALTIME_TEST}
    result = subprocess.run(['ctest', '--test-dir', str(build), '--no-tests=error', '--output-on-failure',
                            '--output-junit', str(junit), '--parallel', '1', '-R',
                            '^(' + '|'.join(sorted(required)) + ')$'], check=False)
    require(junit.is_file(), 'rpath CTest did not produce JUnit')
    report_junit(junit, expected=required, required=required, ctest_returncode=result.returncode)
    evidence = json.loads((build / (name + '.json')).read_text())
    require(evidence.get('status') == 'PASS_IMPORTED_LINUX' and
            evidence.get('fingerprint') == manifest.get('fingerprint'), 'wrong native rpath evidence')
    script = Path(__file__).resolve().parents[2] / 'tests/posix/linux-rpath-selftest.py'
    spec = importlib.util.spec_from_file_location('rpath_contract', script)
    contract = importlib.util.module_from_spec(spec); spec.loader.exec_module(contract)
    contract.validate_evidence(evidence)
    summary('Original reverse-path filtering: IPv4/IPv6, legacy/nft, plain/VRF, PASS ' + manifest['fingerprint'])


def run_ipip_profile(build: Path, junit: Path) -> None:
    name = LINUX_IPIP_PROFILE_TEST
    control = 'linux-mixed-poll-timeout-control'
    require(sum(item['name'] == name for item in ctest_inventory(build)) == 1 and
            sum(item['name'] == control for item in ctest_inventory(build)) == 1,
            'IPIP profile must register the complete original entry exactly once')
    cache = (build / 'CMakeCache.txt').read_text()
    native_build = next((line.split('=', 1)[1] for line in cache.splitlines()
                         if line.startswith('KER_NATIVE_LINUX_BUILD:PATH=')), None)
    require(native_build, 'IPIP profile has no native kernel path')
    manifest = json.loads((Path(native_build) / 'native-linux.json').read_text())
    config = set((Path(manifest['kernel']) / '.config').read_text().splitlines())
    require(manifest.get('config_fragment') == 'config/native-linux-ipip-selftests.config' and
            {'CONFIG_NET_IPIP=y', 'CONFIG_NF_CONNTRACK=y', 'CONFIG_NETFILTER_XTABLES=y',
             'CONFIG_IP_NF_IPTABLES=y', 'CONFIG_IP_NF_FILTER=y', 'CONFIG_NETFILTER_XT_MATCH_CONNTRACK=y'}.issubset(config),
            'IPIP shell requires its real native tunnel/conntrack profile')
    result = subprocess.run(['ctest', '--test-dir', str(build), '--no-tests=error', '--output-on-failure',
                            '--output-junit', str(junit), '--parallel', '1', '-R', '^(' + name + '|' + control + ')$'], check=False)
    require(junit.is_file(), 'IPIP CTest did not produce JUnit')
    report_junit(junit, expected={name, control}, required={name, control}, ctest_returncode=result.returncode)
    evidence = json.loads((build / (name + '.json')).read_text())
    require(evidence.get('status') == 'PASS_IMPORTED_LINUX' and
            evidence.get('fingerprint') == manifest.get('fingerprint'), 'wrong native IPIP evidence')
    script = Path(__file__).resolve().parents[2] / 'tests/posix/linux-ipip-selftest.py'
    spec = importlib.util.spec_from_file_location('ipip_contract', script)
    contract = importlib.util.module_from_spec(spec); spec.loader.exec_module(contract)
    contract.validate_evidence(evidence)
    summary('Original IPIP PMTU: five namespaces, both conntrack modes, mixed readiness control, PASS ' + manifest['fingerprint'])


def run_nat_profile(build: Path, junit: Path) -> None:
    name = LINUX_NAT_PROFILE_TEST
    require(sum(item['name'] == name for item in ctest_inventory(build)) == 1,
            'NAT profile must register the complete original entry exactly once')
    cache = (build / 'CMakeCache.txt').read_text()
    native_build = next((line.split('=', 1)[1] for line in cache.splitlines()
                         if line.startswith('KER_NATIVE_LINUX_BUILD:PATH=')), None)
    require(native_build, 'NAT profile has no native kernel path')
    manifest = json.loads((Path(native_build) / 'native-linux.json').read_text())
    config = set((Path(manifest['kernel']) / '.config').read_text().splitlines())
    require(manifest.get('config_fragment') == 'config/native-linux-nat-selftests.config' and
            {'CONFIG_NF_CONNTRACK=y', 'CONFIG_NF_NAT=y', 'CONFIG_NF_TABLES=y', 'CONFIG_NF_TABLES_INET=y',
             'CONFIG_NFT_CT=y', 'CONFIG_NFT_NAT=y', 'CONFIG_NFT_MASQ=y'}.issubset(config),
            'NAT shell requires its real native nftables/masquerade profile')
    result = subprocess.run(['ctest', '--test-dir', str(build), '--no-tests=error', '--output-on-failure',
                            '--output-junit', str(junit), '--parallel', '1', '-R', '^' + name + '$'], check=False)
    require(junit.is_file(), 'NAT CTest did not produce JUnit')
    report_junit(junit, expected={name}, required={name}, ctest_returncode=result.returncode)
    evidence = json.loads((build / (name + '.json')).read_text())
    require(evidence.get('status') == 'PASS_IMPORTED_LINUX' and
            evidence.get('fingerprint') == manifest.get('fingerprint'), 'wrong native NAT evidence')
    script = Path(__file__).resolve().parents[2] / 'tests/posix/linux-nat-selftest.py'
    spec = importlib.util.spec_from_file_location('nat_contract', script)
    contract = importlib.util.module_from_spec(spec); spec.loader.exec_module(contract)
    contract.validate_evidence(evidence)
    summary('Original ICMP RELATED/NAT: four namespaces, fifteen native counter observations, PASS ' + manifest['fingerprint'])


def run_conntrack_profile(build: Path, junit: Path) -> None:
    name = LINUX_CONNTRACK_PROFILE_TEST
    require(sum(item['name'] == name for item in ctest_inventory(build)) == 1,
            'conntrack profile must register the complete original entry exactly once')
    cache = (build / 'CMakeCache.txt').read_text()
    native_build = next((line.split('=', 1)[1] for line in cache.splitlines()
                         if line.startswith('KER_NATIVE_LINUX_BUILD:PATH=')), None)
    require(native_build, 'conntrack profile has no native kernel path')
    manifest = json.loads((Path(native_build) / 'native-linux.json').read_text())
    config = set((Path(manifest['kernel']) / '.config').read_text().splitlines())
    require(manifest.get('config_fragment') == 'config/native-linux-conntrack.config' and
            {'CONFIG_NF_CONNTRACK=y', 'CONFIG_NF_CONNTRACK_ZONES=y', 'CONFIG_NF_CT_NETLINK=y'}.issubset(config),
            'conntrack dump/flush requires real native ctnetlink and zone filtering')
    result = subprocess.run(['ctest', '--test-dir', str(build), '--no-tests=error', '--output-on-failure',
                            '--output-junit', str(junit), '--parallel', '1', '-R', '^' + name + '$'], check=False)
    require(junit.is_file(), 'conntrack CTest did not produce JUnit')
    report_junit(junit, expected={name}, required={name}, ctest_returncode=result.returncode)
    evidence = json.loads((build / (name + '.json')).read_text())
    require(evidence.get('status') == 'PASS_IMPORTED_LINUX' and
            evidence.get('fingerprint') == manifest.get('fingerprint') and
            evidence.get('program') == 'conntrack_dump_flush', 'wrong native conntrack evidence')
    script = Path(__file__).resolve().parents[2] / 'tests/posix/linux-network-selftest.py'
    spec = importlib.util.spec_from_file_location('conntrack_contract', script)
    contract = importlib.util.module_from_spec(spec); spec.loader.exec_module(contract)
    contract.validate_original('conntrack_dump_flush', evidence.get('original', {}))
    contract.validate_missing_backend('conntrack_dump_flush', evidence.get('original_missing_backend_control', {}))
    contract.validate_conntrack(evidence.get('native_fixture', {}))
    stats = evidence.get('stats', {})
    require(stats.get('outstanding') == 0 and stats.get('worker_exit_code') == 0 and
            stats.get('control_eof') is True and stats.get('shutdown_timed_out') is False,
            'native conntrack resources did not stop normally')
    summary('Original conntrack: complete three-case IPv4/IPv6 zone dump/flush, PASS ' + manifest['fingerprint'])


def run_netns_name_profile(build: Path, junit: Path) -> None:
    name = LINUX_NETNS_NAME_PROFILE_TEST
    inventory = ctest_inventory(build)
    require(sum(item['name'] == name for item in inventory) == 1,
            'namespace-name profile must register the complete original shell exactly once')
    cache = (build / 'CMakeCache.txt').read_text()
    native_build = next((line.split('=', 1)[1] for line in cache.splitlines()
                         if line.startswith('KER_NATIVE_LINUX_BUILD:PATH=')), None)
    require(native_build, 'namespace-name profile has no native kernel path')
    manifest = json.loads((Path(native_build) / 'native-linux.json').read_text())
    require(manifest.get('config_fragment') == 'config/native-linux-netns-name.config' and
            'CONFIG_DUMMY=y' in (Path(manifest['kernel']) / '.config').read_text().splitlines(),
            'namespace-name shell requires its real native dummy profile')
    result = subprocess.run(['ctest', '--test-dir', str(build), '--no-tests=error', '--output-on-failure',
                            '--output-junit', str(junit), '--parallel', '1', '-R', '^' + name + '$'], check=False)
    require(junit.is_file(), 'namespace-name CTest did not produce JUnit')
    report_junit(junit, expected={name}, required={name}, ctest_returncode=result.returncode)
    evidence = json.loads((build / (name + '.json')).read_text())
    native = evidence.get('native_fixture', {})
    original = evidence.get('original', {})
    moves = [r for r in evidence.get('commands', []) if r.get('operation') == 'move']
    require(evidence.get('status') == 'PASS_IMPORTED_LINUX' and
            evidence.get('fingerprint') == manifest.get('fingerprint') and
            original.get('returncode') == 0 and not original.get('stderr') and
            original.get('stdout', '').split() == ['netns-name.sh', '[', 'OK', ']'] and
            len(evidence.get('commands', [])) == 30 and
            [r.get('returncode') for r in moves] == [0, 1, 0, 1, 0] and
            [r.get('errno') for r in moves if r.get('returncode')] == [17, 17] and
            native.get('namespaces_created') == native.get('namespaces_deleted') == 2 and
            native.get('netlinks', 0) >= 30 and native.get('live') == 0,
            'incomplete native namespace-name lifecycle evidence')
    summary('Original namespace names: complete move/conflict/rename/alternative-name shell, PASS ' + manifest['fingerprint'])


def run_forwarding_profile(build: Path, junit: Path) -> None:
    names = set(LINUX_FORWARDING_PROFILE_TESTS) | {LINUX_BROADCAST_REALTIME_TEST}
    inventory = ctest_inventory(build)
    require(all(sum(item['name'] == name for item in inventory) == 1 for name in names),
            'forwarding profile must register all three complete original shells and the realtime control exactly once')
    cache = (build / 'CMakeCache.txt').read_text()
    native_build = next((line.split('=', 1)[1] for line in cache.splitlines()
                         if line.startswith('KER_NATIVE_LINUX_BUILD:PATH=')), None)
    require(native_build, 'forwarding profile has no native kernel path')
    manifest = json.loads((Path(native_build) / 'native-linux.json').read_text())
    require(manifest.get('config_fragment') == 'config/native-linux-forwarding.config' and
            'CONFIG_IP_ROUTE_MULTIPATH=y' in (Path(manifest['kernel']) / '.config').read_text().splitlines(),
            'forwarding shell requires its native multipath routing profile')
    result = subprocess.run(['ctest', '--test-dir', str(build), '--no-tests=error', '--output-on-failure',
                            '--output-junit', str(junit), '--parallel', '1', '-R', '^(' + '|'.join(sorted(names)) + ')$'], check=False)
    require(junit.is_file(), 'forwarding CTest did not produce JUnit')
    report_junit(junit, expected=names, required=names, ctest_returncode=result.returncode)
    # Use the same complete traffic/cleanup contracts for local execution and
    # uploaded CI evidence, rather than treating exit codes as coverage.
    script = Path(__file__).resolve().parents[2] / 'tests/posix/linux-forwarding-selftest.py'
    spec = importlib.util.spec_from_file_location('forwarding_contract', script)
    contract = importlib.util.module_from_spec(spec); spec.loader.exec_module(contract)
    for name, program in LINUX_FORWARDING_PROFILE_TESTS.items():
        evidence = json.loads((build / (name + '.json')).read_text())
        require(evidence.get('status') == 'PASS_IMPORTED_LINUX' and evidence.get('program') == program and
                evidence.get('fingerprint') == manifest.get('fingerprint'), 'wrong native forwarding evidence')
        contract.validate_evidence(evidence)
    summary('Original forwarding: complete VLAN 1, min/max MTU and broadcast shells plus realtime ABI control, PASS ' + manifest['fingerprint'])


def run_packetdrill_profile(build: Path, junit: Path) -> None:
    name = "linux-original-packetdrill"
    inventory = ctest_inventory(build)
    require(sum(item["name"] == name for item in inventory) == 1,
            "packetdrill profile must register its complete original matrix exactly once")
    cache = (build / "CMakeCache.txt").read_text()
    native_build = next((line.split("=", 1)[1] for line in cache.splitlines()
                         if line.startswith("KER_NATIVE_LINUX_BUILD:PATH=")), None)
    require(native_build, "packetdrill profile has no native kernel path")
    manifest = json.loads((Path(native_build) / "native-linux.json").read_text())
    require(manifest.get("config_fragment") == "config/native-linux-packetdrill.config",
            "packetdrill did not use its dedicated TUN/FQ kernel profile")
    config = set((Path(manifest["kernel"]) / ".config").read_text().splitlines())
    require({"CONFIG_TUN=y", "CONFIG_NET_SCH_FQ=y", "CONFIG_HIGH_RES_TIMERS=y", "CONFIG_HZ=1000"}.issubset(config),
            "packetdrill profile lacks its recorded native device/timer facilities")
    result = subprocess.run(["ctest", "--test-dir", str(build), "--no-tests=error", "--output-on-failure",
                            "--output-junit", str(junit), "--parallel", "1", "-R", "^" + name + "$"], check=False)
    require(junit.is_file(), "packetdrill profile CTest did not produce JUnit")
    report_junit(junit, expected={name}, required={name}, ctest_returncode=result.returncode)
    evidence = json.loads((build / (name + ".json")).read_text())
    require(evidence.get("status") == "PASS_IMPORTED_LINUX" and
            evidence.get("fingerprint") == manifest.get("fingerprint"), "packetdrill native evidence mismatch")
    scripts, entries = evidence.get("original_scripts", []), evidence.get("entries", [])
    require(len(scripts) == 24 and len({x["script"] for x in scripts}) == 24 and
            len(entries) == 48 and all(x.get("returncode") == 0 and not x.get("stderr") for x in [*scripts, *entries]),
            "packetdrill did not finish all 24 original entries and 48 family configurations without helper errors")
    for script in scripts:
        family_entries = [item for item in entries if item.get("arguments", [None])[-1] == script["script"]]
        require(len(family_entries) == 2 and {item["arguments"][0] for item in family_entries} ==
                {"--ip_version=ipv4", "--ip_version=ipv6"}, "packetdrill family configuration is missing or duplicated")
    summary("Original packetdrill: 24 scripts / 48 family configurations, PASS " + manifest["fingerprint"])


def run_sockopt_profile(build: Path, junit: Path) -> None:
    inventory = ctest_inventory(build)
    names = {item["name"] for item in inventory}
    validate_sockopt_profile_inventory(inventory)

    cache = (build / "CMakeCache.txt").read_text()
    native_build = next((line.split("=", 1)[1] for line in cache.splitlines()
                         if line.startswith("KER_NATIVE_LINUX_BUILD:PATH=")), None)
    require(native_build, "sockopt profile build has no native kernel artifact path")
    manifest_path = Path(native_build) / "native-linux.json"
    manifest = json.loads(manifest_path.read_text())
    require(manifest.get("config_fragment") == "config/native-linux-mptcp-sockopt.config",
            "sockopt test did not use the dedicated netfilter kernel profile")
    config = (Path(manifest["kernel"]) / ".config").read_text().splitlines()
    required_options = {"CONFIG_NETFILTER_XTABLES=y", "CONFIG_NETFILTER_XT_MATCH_MARK=y",
                        "CONFIG_IP_NF_IPTABLES=y", "CONFIG_IP_NF_FILTER=y",
                        "CONFIG_IP6_NF_IPTABLES=y", "CONFIG_IP6_NF_FILTER=y"}
    require(required_options.issubset(set(config)), "sockopt profile kernel is missing required netfilter options")

    result = subprocess.run(
        ["ctest", "--test-dir", str(build), "--no-tests=error", "--output-on-failure",
         "--output-junit", str(junit), "--parallel", "1", "-R",
         "^" + re.escape(LINUX_MPTCP_SOCKOPT_PROFILE_TEST) + "$"], check=False)
    if not junit.is_file():
        raise RuntimeError("sockopt profile CTest did not produce JUnit output")
    report_junit(junit, expected={LINUX_MPTCP_SOCKOPT_PROFILE_TEST},
                 required={LINUX_MPTCP_SOCKOPT_PROFILE_TEST}, ctest_returncode=result.returncode)
    evidence_path = build / "linux-original-mptcp-sockopt-shell.json"
    evidence = json.loads(evidence_path.read_text())
    require(evidence.get("status") == "PASS_IMPORTED_LINUX" and evidence.get("returncode") == 0 and
            len(evidence.get("cases", [])) == 11,
            "sockopt profile did not complete every original shell assertion")
    require(evidence.get("fingerprint") == manifest.get("fingerprint"),
            "sockopt evidence fingerprint differs from its kernel manifest")
    summary("Original MPTCP sockopt shell profile: PASS " + manifest["fingerprint"])


def run_connect_profile(build: Path, junit: Path) -> None:
    inventory = ctest_inventory(build)
    validate_sockopt_profile_inventory(inventory)
    for name in LINUX_MPTCP_CONNECT_PROFILE_TESTS:
        require(sum(item["name"] == name for item in inventory) == 1,
                "connect profile must contain each original shell entry exactly once: " + name)
    cache = (build / "CMakeCache.txt").read_text()
    native_build = next((line.split("=", 1)[1] for line in cache.splitlines()
                         if line.startswith("KER_NATIVE_LINUX_BUILD:PATH=")), None)
    require(native_build, "connect profile build has no native kernel artifact path")
    manifest = json.loads((Path(native_build) / "native-linux.json").read_text())
    require(manifest.get("config_fragment") == "config/native-linux-mptcp-connect.config",
            "connect shells did not use their dedicated netfilter kernel profile")
    config = set((Path(manifest["kernel"]) / ".config").read_text().splitlines())
    require({"CONFIG_NF_TABLES=y", "CONFIG_NF_TABLES_INET=y", "CONFIG_NFT_SOCKET=y",
             "CONFIG_NFT_TPROXY=y"}.issubset(config), "connect kernel lacks real nftables transparent proxy support")
    pattern = "^(" + "|".join(re.escape(name) for name in sorted(LINUX_MPTCP_CONNECT_PROFILE_TESTS)) + ")$"
    result = subprocess.run(["ctest", "--test-dir", str(build), "--no-tests=error", "--output-on-failure",
                             "--output-junit", str(junit), "--parallel", "1", "-R", pattern], check=False)
    require(junit.is_file(), "connect profile CTest did not produce JUnit output")
    report_junit(junit, expected=LINUX_MPTCP_CONNECT_PROFILE_TESTS,
                 required=LINUX_MPTCP_CONNECT_PROFILE_TESTS, ctest_returncode=result.returncode)
    for name in sorted(LINUX_MPTCP_CONNECT_PROFILE_TESTS):
        evidence = json.loads((build / (name + ".json")).read_text())
        require(evidence.get("status") == "PASS_IMPORTED_LINUX" and evidence.get("returncode") == 0 and
                len(evidence.get("cases", [])) == 68, "incomplete original connect shell: " + name)
        require(evidence.get("fingerprint") == manifest.get("fingerprint"), "connect evidence kernel fingerprint differs")
    summary("Original MPTCP connect/mmap/sendfile/checksum shells: PASS " + manifest["fingerprint"])


def run_join_profile(build: Path, junit: Path) -> None:
    inventory = ctest_inventory(build)
    validate_sockopt_profile_inventory(inventory)
    require(sum(item["name"] == LINUX_MPTCP_JOIN_PROFILE_TEST for item in inventory) == 1,
            "join profile must contain the original full shell exactly once")
    cache = (build / "CMakeCache.txt").read_text()
    native_build = next((line.split("=", 1)[1] for line in cache.splitlines()
                         if line.startswith("KER_NATIVE_LINUX_BUILD:PATH=")), None)
    require(native_build, "join profile build has no native kernel artifact path")
    manifest = json.loads((Path(native_build) / "native-linux.json").read_text())
    require(manifest.get("config_fragment") == "config/native-linux-mptcp-join.config",
            "join shell did not use its dedicated fault-injection kernel profile")
    config = set((Path(manifest["kernel"]) / ".config").read_text().splitlines())
    required = {"CONFIG_" + name + "=y" for name in ("IP_NF_MANGLE", "IP6_NF_MANGLE", "NETFILTER_XT_MARK",
                "NETFILTER_XT_MATCH_BPF", "NETFILTER_XT_MATCH_LENGTH", "NETFILTER_XT_MATCH_STATISTIC",
                "IP_NF_TARGET_REJECT", "IP6_NF_TARGET_REJECT", "NET_SCH_INGRESS", "NET_CLS_FW",
                "NET_CLS_ACT", "NET_ACT_PEDIT", "NET_ACT_CSUM")}
    require(required.issubset(config), "join kernel lacks native fault-injection modules")
    result = subprocess.run(["ctest", "--test-dir", str(build), "--no-tests=error", "--output-on-failure",
                             "--output-junit", str(junit), "--parallel", "1", "-R",
                             "^" + re.escape(LINUX_MPTCP_JOIN_PROFILE_TEST) + "$"], check=False)
    require(junit.is_file(), "join profile CTest did not produce JUnit output")
    report_junit(junit, expected={LINUX_MPTCP_JOIN_PROFILE_TEST}, required={LINUX_MPTCP_JOIN_PROFILE_TEST},
                 ctest_returncode=result.returncode)
    evidence = json.loads((build / (LINUX_MPTCP_JOIN_PROFILE_TEST + ".json")).read_text())
    require(evidence.get("status") == "PASS_IMPORTED_LINUX" and evidence.get("returncode") == 0 and
            len(evidence.get("cases", [])) == LINUX_MPTCP_JOIN_EXPECTED_CASES,
            "incomplete original join shell matrix")
    require(evidence.get("fingerprint") == manifest.get("fingerprint"), "join evidence kernel fingerprint differs")
    summary("Original complete MPTCP join shell: PASS " + manifest["fingerprint"])


def validate_default_profile_inventory(names: set[str]) -> None:
    require(LINUX_NEXTHOP_PROFILE_TEST not in names, "nexthop requires its native nexthop/clsact/VRF profile")
    require(not names.intersection(LINUX_BRIDGE_PROFILE_TESTS), "bridge requires its native bridge/VLAN/VRF profile")
    require(LINUX_XT_STRING_PROFILE_TEST not in names, "xt_string requires its native string/BM/KMP profile")
    require(LINUX_RPATH_PROFILE_TEST not in names, 'rpath shell requires its native rpfilter/fib profile')
    require(LINUX_IPIP_PROFILE_TEST not in names, 'IPIP shell requires its native tunnel profile')
    require(LINUX_NAT_PROFILE_TEST not in names, 'NAT shell requires its native nftables profile')
    require(LINUX_CONNTRACK_PROFILE_TEST not in names, 'conntrack requires its native zone profile')
    require(not set(LINUX_FORWARDING_PROFILE_TESTS) & names, 'forwarding shell requires native multipath profile')
    require(LINUX_NETNS_NAME_PROFILE_TEST not in names, 'namespace-name shell requires native dummy profile')
    require(LINUX_NETLINK_DUMPS_PROFILE_TEST not in names, 'Netlink dumps require native POSIX mqueue profile')
    require(LINUX_MACVTAP_PROFILE_TEST not in names, 'macvtap requires its fingerprinted driver profile')
    require(not names.intersection(LINUX_NET_PROFILE_TESTS), 'TUN/DCCP tests require their fingerprinted net profile')
    require(LINUX_MPTCP_SOCKOPT_PROFILE_TEST not in names,
            "sockopt shell test must run in its fingerprinted netfilter profile")
    require(LINUX_MPTCP_JOIN_PROFILE_TEST not in names, "join shell requires its fingerprinted fault-injection profile")
    require(not names.intersection(LINUX_MPTCP_CONNECT_PROFILE_TESTS),
            "connect shells must run in their fingerprinted netfilter profile")
    required = {"native-c24-ingress-freeze-tap", "native-c28-broker-owned-cutover-tap",
                "native-c28-broker-owned-cutover-abort-tap",
                "native-c28-cutover-start-cancel-destroy-retry"}
    require(required.issubset(names),
            "missing required tests from default ingress-freeze profile")


def validate_sockopt_profile_inventory(inventory: list[dict]) -> None:
    names = {item["name"] for item in inventory}
    require(sum(item["name"] == LINUX_MPTCP_SOCKOPT_PROFILE_TEST for item in inventory) == 1,
            "sockopt profile CTest inventory must contain the original shell test exactly once")
    excluded = {"native-c24-ingress-freeze-tap", "native-c28-broker-owned-cutover-tap",
                "native-c28-broker-owned-cutover-abort-tap",
                "native-c28-cutover-start-cancel-destroy-retry"}
    require(not names.intersection(excluded), "sockopt profile unexpectedly includes admission hook-inventory tests")


def _literal_profile_tuple(node: ast.AST) -> set[str] | None:
    if not isinstance(node, (ast.Tuple, ast.List)):
        return None
    if not all(isinstance(item, ast.Constant) and isinstance(item.value, str) for item in node.elts):
        return None
    return {item.value for item in node.elts}


def expected_session_profiles(source_path: Path) -> tuple[set[str], bool]:
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(source_path))
    main = next((node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                 and node.name == "main"), None)
    if main is None:
        raise RuntimeError("native session fixture has no main() profile entry point")
    explicit: set[str] = set()
    negative: set[str] = set()
    for node in ast.walk(main):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name) or node.func.id != "run_live_handoff_profile":
            continue
        mode = next((kw.value for kw in node.keywords if kw.arg == "mode"), None)
        if mode is None:
            if len(node.args) < 4:
                explicit.add("positive")
            elif isinstance(node.args[3], ast.Constant) and isinstance(node.args[3].value, str):
                explicit.add(node.args[3].value)
        elif isinstance(mode, ast.Constant) and isinstance(mode.value, str):
            explicit.add(mode.value)
    for node in ast.walk(main):
        if not isinstance(node, ast.For) or not isinstance(node.target, ast.Name) or node.target.id != "mode":
            continue
        modes = _literal_profile_tuple(node.iter)
        if modes is not None and any(
                isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and
                call.func.id == "run_live_handoff_profile" and
                ((len(call.args) >= 4 and isinstance(call.args[3], ast.Name) and call.args[3].id == "mode") or
                 any(kw.arg == "mode" and isinstance(kw.value, ast.Name) and kw.value.id == "mode"
                     for kw in call.keywords))
                for child in node.body for call in ast.walk(child)):
            negative |= modes
    if negative != MANDATORY_SESSION_PROFILES - {"positive", "frame-positive", "nonframe-active-reap"}:
        raise RuntimeError("fixture negative-profile loop differs from the required 16-profile set: " + repr({
            "missing": sorted((MANDATORY_SESSION_PROFILES - {"positive", "frame-positive", "nonframe-active-reap"}) - negative),
            "unexpected": sorted(negative - MANDATORY_SESSION_PROFILES),
        }))
    if not {"positive", "frame-positive", "nonframe-active-reap"} <= explicit:
        raise RuntimeError("fixture is missing a required positive/frame/non-FRAME profile call")
    recovery = explicit & FRAME_RECOVERY_PROFILES
    if recovery and recovery != FRAME_RECOVERY_PROFILES:
        raise RuntimeError("fixture has a partial frame-recovery profile set: " + repr({
            "missing": sorted(FRAME_RECOVERY_PROFILES - recovery),
        }))
    expected = explicit | negative
    if expected != MANDATORY_SESSION_PROFILES and expected != (MANDATORY_SESSION_PROFILES | FRAME_RECOVERY_PROFILES):
        raise RuntimeError("fixture profile inventory is not a recognized complete set: " + repr(sorted(expected)))
    structured = "KER_SESSION_FRAME_PROFILE_EVIDENCE" in source
    if recovery and not structured:
        raise RuntimeError("frame-recovery profiles require structured per-profile evidence records")
    return expected, structured


def _legacy_profile_success_marker(mode: str) -> str:
    if mode == "positive":
        return ("PASS: a generation-admitted same-process peer takes the PMD/exception grant while the original "
                "Linux app and parked worker remain alive, then both workers drain cleanly")
    if mode == "frame-positive":
        return ("PASS: original LKL post-PARKED UDP frame is journaled before prepare and drained by the admitted "
                "peer as the exact mbuf pointer/bytes once")
    if mode == "nonframe-active-reap":
        return ("PASS: bounded non-FRAME full reap waited for the real RX dequeue, retired the dead borrower, "
                "and restored all rings")
    if mode == "handoff-control-hup":
        return "PASS: control HUP with a pending ACK aborted before PREPARE and drained the unchanged owner"
    if mode in {"prepare-enoent", "prepare-ebusy", "prepare-eperm"}:
        return (f"PASS: {mode} drained a pending heartbeat, preserved queued H, returned exact rejection, "
                "and resumed the packet loop")
    if mode in MANDATORY_NEGATIVE_PROFILES:
        return (f"PASS: {mode} after PREPARE terminates exact actors with status125 and no "
                "PARKED/grant/DRAINED success")
    raise ValueError("unsupported legacy native session profile: " + mode)


def verify_session_profiles(log_path: Path, source_path: Path) -> None:
    expected_profiles, structured = expected_session_profiles(source_path)
    observed: list[str] = []
    eal_profiles: list[str] = []
    cleanup_profiles: list[str] = []
    for line in log_path.read_text(errors="replace").splitlines():
        eal_prefix = "KER_SESSION_HANDOFF_EAL_CHANNELS "
        if line.startswith(eal_prefix):
            channel = json.loads(line[len(eal_prefix):])
            profile = channel.get("profile") if isinstance(channel, dict) else None
            owner = channel.get("owner", {}) if isinstance(channel, dict) else {}
            peer = channel.get("peer", {}) if isinstance(channel, dict) else {}
            if (not isinstance(profile, str) or not isinstance(channel, dict) or
                    not isinstance(owner, dict) or not isinstance(peer, dict) or
                    not isinstance(channel.get("primary"), str) or
                    type(owner.get("pid")) is not int or type(peer.get("pid")) is not int or
                    owner["pid"] == peer["pid"] or not isinstance(owner.get("socket"), str) or
                    not isinstance(peer.get("socket"), str)):
                raise RuntimeError("session EAL-channel record is malformed: " + repr(channel))
            eal_profiles.append(profile)
        cleanup_match = re.fullmatch(
            r"KER_SESSION_HANDOFF_HUGEPAGES_RECLAIMED profile=([^ ]+) mode=private(?: .*)?", line)
        if cleanup_match:
            cleanup_profiles.append(cleanup_match.group(1))
        prefix = "KER_SESSION_FRAME_PROFILE_EVIDENCE "
        if not line.startswith(prefix):
            continue
        record = json.loads(line[len(prefix):])
        if not isinstance(record, dict):
            raise RuntimeError("session profile evidence is not a JSON object")
        mode = record.get("mode")
        if not isinstance(mode, str):
            raise RuntimeError("session profile evidence lacks a mode string")
        digest = record.get("capture_sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise RuntimeError(f"{mode}: profile evidence has a malformed capture digest")
        unhashed = dict(record)
        del unhashed["capture_sha256"]
        calculated = hashlib.sha256(json.dumps(
            unhashed, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if digest != calculated:
            raise RuntimeError(f"{mode}: profile evidence capture digest does not match its content")
        observed.append(mode)
    if len(eal_profiles) != len(set(eal_profiles)) or set(eal_profiles) != expected_profiles:
        raise RuntimeError("native session EAL-channel profile set mismatch: " + repr({
            "expected": sorted(expected_profiles), "observed": eal_profiles,
            "missing": sorted(expected_profiles - set(eal_profiles)),
            "unexpected": sorted(set(eal_profiles) - expected_profiles),
        }))
    if len(cleanup_profiles) != len(set(cleanup_profiles)) or set(cleanup_profiles) != expected_profiles:
        raise RuntimeError("native session hugepage-cleanup profile set mismatch: " + repr({
            "expected": sorted(expected_profiles), "observed": cleanup_profiles,
            "missing": sorted(expected_profiles - set(cleanup_profiles)),
            "unexpected": sorted(set(cleanup_profiles) - expected_profiles),
        }))
    if "KER_SESSION_HANDOFF_HUGEPAGE_CLEANUP_REFUSED " in log_path.read_text(errors="replace"):
        raise RuntimeError("native session runtime reported private hugepage cleanup refusal")
    if structured and (len(observed) != len(set(observed)) or set(observed) != expected_profiles):
        raise RuntimeError("native session profile set mismatch: " + repr({
            "expected": sorted(expected_profiles), "observed": observed,
            "missing": sorted(expected_profiles - set(observed)),
            "unexpected": sorted(set(observed) - expected_profiles),
        }))
    text = log_path.read_text(errors="replace")
    if not structured:
        if observed:
            raise RuntimeError("legacy profile output unexpectedly contains structured evidence records")
        profile_lines = set(text.splitlines())
        for mode in expected_profiles:
            marker = _legacy_profile_success_marker(mode)
            if marker not in profile_lines:
                raise RuntimeError(f"legacy native session runtime lacks profile success marker for {mode}")
    for marker in (
        _legacy_profile_success_marker("positive"),
        _legacy_profile_success_marker("frame-positive"),
    ):
        if marker not in set(text.splitlines()):
            raise RuntimeError("native session runtime lacks terminal success marker: " + marker)
    count = len(observed) if structured else len(expected_profiles)
    summary(f"Native session runtime: {count}/{len(expected_profiles)} source-derived profiles; "
            f"{len(eal_profiles)}/{len(expected_profiles)} exact EAL channel records.")


def nohuge_prerequisite() -> tuple[bool, str]:
    tun = Path("/dev/net/tun")
    if not tun.is_char_device():
        return False, "/dev/net/tun is not a character device"
    unshare = shutil.which("unshare")
    if not unshare:
        return False, "unshare is unavailable"
    probe = r'''
import fcntl, os, socket, struct
name = b"ker-ci-tun-probe"
fd = os.open("/dev/net/tun", os.O_RDWR | os.O_CLOEXEC)
try:
    fcntl.ioctl(fd, 0x400454ca, struct.pack("16sH22x", name, 0x1002))
finally:
    os.close(fd)
if any(ifname == name.decode() for _, ifname in socket.if_nameindex()):
    raise SystemExit("TAP interface remained after its fd closed")
'''
    result = subprocess.run([unshare, "-Urn", sys.executable, "-c", probe],
                            capture_output=True, text=True)
    if result.returncode:
        detail = result.stderr.strip() or f"exit {result.returncode}"
        return False, "user namespace/TAP create-and-close probe failed: " + detail
    return True, ""


def tap_preflight() -> None:
    available, reason = nohuge_prerequisite()
    if not available:
        raise RuntimeError("required unshare/TUN TAP preflight failed: " + reason)
    summary("Required unshare -Urn TUN/TAP create-close preflight: PASS.")


def native_datapath_preflight(prefix: Path) -> None:
    """Fail before CTest unless provisioned virtio/vhost/TAP paths are usable."""
    require_two_cpus()
    tap_preflight()
    resolved_prefix = _resolved_dpdk_prefix(prefix)
    plugin_directories = {
        name: dpdk_plugin_directory(resolved_prefix, (name,))
        for name in ("librte_net_tap.so", "librte_net_virtio.so", "librte_net_vhost.so")
    }
    device = Path("/dev/vhost-net")
    if not device.is_char_device():
        raise RuntimeError("required /dev/vhost-net character device is unavailable; load vhost_net")
    try:
        descriptor = os.open(device, os.O_RDWR | os.O_CLOEXEC)
    except OSError as error:
        raise RuntimeError(f"required /dev/vhost-net cannot be opened by the test user: {error}") from error
    else:
        os.close(descriptor)
    summary("Required software datapath preflight: two CPUs, TAP, /dev/vhost-net, and pinned TAP/virtio/vhost PMDs PASS.")
    for name, directory in sorted(plugin_directories.items()):
        summary(f"Pinned {name}: {directory}")


def verify_tap_retry_source(source: Path, patch: Path) -> dict[str, str]:
    """Verify the isolated DPDK TAP adapter against its pinned provenance."""
    source = source.resolve(strict=True)
    patch = patch.resolve(strict=True)
    manifest_path = source / "ker-tap-retry-provenance.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        patch_bytes = patch.read_bytes()
        tap_bytes = (source / "drivers/net/tap/rte_eth_tap.c").read_bytes()
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"TAP retry provenance is incomplete: {error}") from error
    expected = {
        "upstream_commit": "d129414711aa7c4954f997acf4c54338574a7d92",
        "patch_sha256": hashlib.sha256(patch_bytes).hexdigest(),
        "tap_source_sha256": hashlib.sha256(tap_bytes).hexdigest(),
        "compatibility_abi": "ker_dpdk_tap_tx_retry_abi=1",
    }
    if manifest != expected:
        raise RuntimeError(f"TAP retry provenance mismatch: expected {expected!r}, got {manifest!r}")
    summary("Isolated pinned DPDK TAP retry provenance: PASS " + json.dumps(manifest, sort_keys=True))
    return manifest


def _resolved_dpdk_prefix(prefix: Path) -> Path:
    try:
        resolved = prefix.resolve(strict=True)
    except OSError as error:
        raise RuntimeError(f"pinned DPDK install directory is missing: {prefix}") from error
    if not resolved.is_dir():
        raise RuntimeError(f"pinned DPDK install path is not a directory: {prefix}")
    return resolved


def _validated_dpdk_file(prefix: Path, candidate: Path) -> Path:
    try:
        target = candidate.resolve(strict=True)
    except OSError as error:
        raise RuntimeError(f"pinned DPDK file is missing or dangling: {candidate}") from error
    if not target.is_file():
        raise RuntimeError(f"pinned DPDK target is not a regular file: {candidate} -> {target}")
    try:
        target.relative_to(prefix)
    except ValueError as error:
        raise RuntimeError(f"pinned DPDK file escapes install prefix: {candidate} -> {target}") from error
    return target


def dpdk_runtime_directories(prefix: Path) -> list[Path]:
    resolved_prefix = _resolved_dpdk_prefix(prefix)
    directories = {
        _validated_dpdk_file(resolved_prefix, path).parent
        for path in resolved_prefix.rglob("librte_*.so*")
    }
    if not directories:
        raise RuntimeError(f"pinned DPDK install has no shared-library files: {resolved_prefix}")
    return sorted(directories)


def dpdk_plugin_directory(prefix: Path, required_plugins: tuple[str, ...]) -> Path:
    if not required_plugins or any("/" in name or not name.endswith(".so") for name in required_plugins):
        raise RuntimeError("DPDK plugin names must be unversioned .so basenames")
    resolved_prefix = _resolved_dpdk_prefix(prefix)
    for plugin in resolved_prefix.rglob(required_plugins[0]):
        _validated_dpdk_file(resolved_prefix, plugin)
        plugin_directory = plugin.parent.resolve(strict=True)
        try:
            plugin_directory.relative_to(resolved_prefix)
        except ValueError as error:
            raise RuntimeError(f"pinned DPDK plugin directory escapes install prefix: {plugin_directory}") from error
        missing = False
        for name in required_plugins[1:]:
            sibling = plugin_directory / name
            if not sibling.exists() and not sibling.is_symlink():
                missing = True
                break
            _validated_dpdk_file(resolved_prefix, sibling)
        if not missing:
            return plugin_directory
    raise RuntimeError(f"pinned DPDK install is missing required plugins: {required_plugins!r}")


def require_two_cpus() -> None:
    try:
        count = len(os.sched_getaffinity(0))
    except AttributeError:
        count = os.cpu_count() or 1
    if count < 2:
        raise RuntimeError("native-fstack-rx-lcores-ownership requires two allowed CPUs")


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[1] not in {"hosted-safe", "nohuge-eal", "nohuge-tap", "report-junit", "full-ctest", "sockopt-profile", "connect-profile", "join-profile", "packetdrill-profile", "net-profile", "macvtap-profile", "netlink-dumps-profile", "netns-name-profile", "forwarding-profile", "conntrack-profile", "nat-profile", "ipip-profile", "rpath-profile", "xt-string-profile", "bridge-profile", "nexthop-profile", "tap-preflight", "native-datapath-preflight", "verify-tap-retry-source", "verify-session-profiles", "dpdk-library-path", "dpdk-plugin-dir"}:
        print(f"usage: {argv[0]} full-ctest CTEST_BUILD_DIR JUNIT_FILE | sockopt-profile|connect-profile|join-profile|packetdrill-profile|net-profile|macvtap-profile|netlink-dumps-profile|netns-name-profile|forwarding-profile|conntrack-profile|nat-profile|ipip-profile|rpath-profile|xt-string-profile|bridge-profile|nexthop-profile CTEST_BUILD_DIR JUNIT_FILE | hosted-safe|nohuge-eal|nohuge-tap CTEST_BUILD_DIR | tap-preflight | native-datapath-preflight PREFIX | verify-tap-retry-source SOURCE PATCH | verify-session-profiles LOG FIXTURE | report-junit JUNIT_FILE | dpdk-library-path PREFIX | dpdk-plugin-dir PREFIX PLUGIN...", file=sys.stderr)
        return 2
    if argv[1] == "tap-preflight":
        if len(argv) != 2:
            raise RuntimeError("tap-preflight takes no additional arguments")
        tap_preflight()
        return 0
    if argv[1] == "native-datapath-preflight":
        if len(argv) != 3:
            raise RuntimeError("native-datapath-preflight requires the pinned DPDK install prefix")
        native_datapath_preflight(Path(argv[2]))
        return 0
    if argv[1] == "verify-tap-retry-source":
        if len(argv) != 4:
            raise RuntimeError("verify-tap-retry-source requires isolated source and checked-in patch paths")
        verify_tap_retry_source(Path(argv[2]), Path(argv[3]))
        return 0
    if argv[1] == "dpdk-library-path":
        if len(argv) != 3:
            raise RuntimeError("dpdk-library-path requires the install prefix")
        print(os.pathsep.join(str(path) for path in dpdk_runtime_directories(Path(argv[2]))))
        return 0
    if argv[1] == "dpdk-plugin-dir":
        if len(argv) < 4:
            raise RuntimeError("dpdk-plugin-dir requires an install prefix and plugin names")
        print(dpdk_plugin_directory(Path(argv[2]), tuple(argv[3:])))
        return 0
    if len(argv) < 3:
        raise RuntimeError(f"{argv[1]} requires an argument")
    group, build = argv[1], Path(argv[2])
    if group == "verify-session-profiles":
        if len(argv) != 4:
            raise RuntimeError("verify-session-profiles requires log path and fixture source path")
        verify_session_profiles(build, Path(argv[3]))
        return 0
    if group == "full-ctest":
        if len(argv) != 4:
            raise RuntimeError("full-ctest requires build directory and JUnit output path")
        run_full_ctest(build, Path(argv[3]))
        return 0
    if group == "net-profile":
        if len(argv) != 4:
            raise RuntimeError("net-profile requires build directory and JUnit output path")
        run_net_profile(build, Path(argv[3]))
        return 0
    if group == "nexthop-profile":
        if len(argv) != 4:
            raise RuntimeError("nexthop-profile requires build directory and JUnit output path")
        run_nexthop_profile(build, Path(argv[3]))
        return 0
    if group == "bridge-profile":
        if len(argv) != 4:
            raise RuntimeError("bridge-profile requires build directory and JUnit output path")
        run_bridge_profile(build, Path(argv[3]))
        return 0
    if group == "xt-string-profile":
        if len(argv) != 4:
            raise RuntimeError("xt-string-profile requires build directory and JUnit output path")
        run_xt_string_profile(build, Path(argv[3]))
        return 0
    if group == "rpath-profile":
        if len(argv) != 4:
            raise RuntimeError("rpath-profile requires build directory and JUnit output path")
        run_rpath_profile(build, Path(argv[3]))
        return 0
    if group == "ipip-profile":
        if len(argv) != 4:
            raise RuntimeError("ipip-profile requires build directory and JUnit output path")
        run_ipip_profile(build, Path(argv[3]))
        return 0
    if group == "nat-profile":
        if len(argv) != 4:
            raise RuntimeError("nat-profile requires build directory and JUnit output path")
        run_nat_profile(build, Path(argv[3]))
        return 0
    if group == "conntrack-profile":
        if len(argv) != 4:
            raise RuntimeError("conntrack-profile requires build directory and JUnit output path")
        run_conntrack_profile(build, Path(argv[3]))
        return 0
    if group == "forwarding-profile":
        if len(argv) != 4:
            raise RuntimeError("forwarding-profile requires build directory and JUnit output path")
        run_forwarding_profile(build, Path(argv[3]))
        return 0
    if group == "netns-name-profile":
        if len(argv) != 4:
            raise RuntimeError("netns-name-profile requires build directory and JUnit output path")
        run_netns_name_profile(build, Path(argv[3]))
        return 0
    if group == "netlink-dumps-profile":
        if len(argv) != 4:
            raise RuntimeError("netlink-dumps-profile requires build directory and JUnit output path")
        run_netlink_dumps_profile(build, Path(argv[3]))
        return 0
    if group == "macvtap-profile":
        if len(argv) != 4:
            raise RuntimeError("macvtap-profile requires build directory and JUnit output path")
        run_macvtap_profile(build, Path(argv[3]))
        return 0
    if group == "packetdrill-profile":
        if len(argv) != 4:
            raise RuntimeError("packetdrill-profile requires build directory and JUnit output path")
        run_packetdrill_profile(build, Path(argv[3]))
        return 0
    if group == "join-profile":
        if len(argv) != 4:
            raise RuntimeError("join-profile requires build directory and JUnit output path")
        run_join_profile(build, Path(argv[3]))
        return 0
    if group == "connect-profile":
        if len(argv) != 4:
            raise RuntimeError("connect-profile requires build directory and JUnit output path")
        run_connect_profile(Path(argv[2]), Path(argv[3]))
        return 0
    if group == "sockopt-profile":
        if len(argv) != 4:
            raise RuntimeError("sockopt-profile requires build directory and JUnit output path")
        run_sockopt_profile(build, Path(argv[3]))
        return 0
    if group == "report-junit":
        report_junit(build)
        return 0
    if group == "hosted-safe":
        run_group(build, "Hosted native component/adapter tests", HOSTED_SAFE)
        return 0
    if group == "nohuge-eal":
        require_two_cpus()
        run_group(build, "No-huge EAL component tests", NOHUGE_EAL)
        return 0
    available, reason = nohuge_prerequisite()
    if not available:
        raise RuntimeError("required unshare/TUN TAP tests cannot run: " + reason)
    run_group(build, "No-huge EAL/TAP socket tests", NOHUGE_TAP)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv))
    except (OSError, RuntimeError, subprocess.CalledProcessError, ET.ParseError, KeyError, ValueError) as error:
        print("native test selection failed: " + str(error), file=sys.stderr)
        raise SystemExit(1)
