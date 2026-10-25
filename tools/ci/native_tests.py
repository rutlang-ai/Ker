#!/usr/bin/env python3
"""Select, run, and report the hosted native-backend test matrix."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET


HOSTED_SAFE = (
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
    "native-fstack-host-semaphore-debug",
    "native-fstack-host-semaphore-release",
    "native-fstack-host-failure-debug",
    "native-fstack-host-failure-release",
    "native-fstack-fd-map",
    "native-fstack-errno",
    "native-fstack-entropy",
    "native-fstack-realtime",
    "native-fstack-host-runtime",
    "native-fstack-exception-config",
    "native-fstack-buffer-resize",
    "native-fstack-host-pages-debug",
    "native-fstack-host-pages-release",
    "native-fstack-host-timer-debug",
    "native-fstack-host-timer-release",
    "native-fstack-launcher-config",
    "native-fstack-config-lifecycle",
    "native-ker-run-exit-status",
    "native-linux-fingerprint-stale-inputs",
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
)

SESSION_PROFILES = frozenset({
    "positive", "frame-positive", "nonframe-active-reap", "frame-full",
    "frame-death-prepared", "frame-death-consumer-prepared",
    "frame-death-both-prepared", "frame-lost-prepare-reply",
    "frame-death-consumer-writing", "frame-death-queued",
    "frame-death-producer-active-consumer", "bad-capability", "bad-tx-lease",
    "bad-rx-lease", "peer-death", "timeout", "handoff-control-hup",
    "prepare-enoent", "prepare-ebusy", "prepare-eperm", "bad-prepare-error",
    "bad-prepare-error-token", "bad-prepare-error-capability",
    "bad-prepare-error-tx-lease", "bad-prepare-error-rx-lease",
    "bad-prepare-error-sequence", "bad-prepare-success",
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


def summary(message: str) -> None:
    print(message)
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as stream:
            stream.write(f"\n{message}\n")


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
    if not cases or failed or malformed or ctest_returncode:
        raise RuntimeError("full CTest graph failed: " + repr(dict(
            ctest_returncode=ctest_returncode, failed=failed, problems=malformed)))


def run_full_ctest(build: Path, junit: Path) -> None:
    inventory = ctest_inventory(build)
    by_name = {item["name"]: item for item in inventory}
    names = set(by_name)
    missing = sorted((set(HOSTED_SAFE) | set(NOHUGE_EAL) | set(NOHUGE_TAP) |
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
    required = set(HOSTED_SAFE) | set(NOHUGE_EAL) | set(NOHUGE_TAP) | set(SESSION_CTEST)
    result = subprocess.run(
        ["ctest", "--test-dir", str(build), "--no-tests=error", "--output-on-failure",
         "--output-junit", str(junit), "--parallel", "2", "-E", "^" + re.escape(SESSION_DIRECT) + "$"],
        check=False,
    )
    if not junit.is_file():
        raise RuntimeError("full CTest graph did not produce JUnit output")
    report_junit(junit, expected=expected, required=required, ctest_returncode=result.returncode)
    summary(f"Full native CTest graph: {len(expected)} registered tests; {len(required)} mandatory hosted/session tests; session suite has no skips.")


def verify_session_profiles(log_path: Path) -> None:
    observed: list[str] = []
    for line in log_path.read_text(errors="replace").splitlines():
        prefix = "KER_SESSION_FRAME_PROFILE_EVIDENCE "
        if not line.startswith(prefix):
            continue
        record = json.loads(line[len(prefix):])
        mode = record.get("mode")
        if not isinstance(mode, str):
            raise RuntimeError("session profile evidence lacks a mode string")
        if not isinstance(record.get("capture_sha256"), str) or not record["capture_sha256"]:
            raise RuntimeError(f"{mode}: profile evidence lacks its capture digest")
        observed.append(mode)
    if len(observed) != len(set(observed)) or set(observed) != SESSION_PROFILES:
        raise RuntimeError("native session profile set mismatch: " + repr({
            "expected": sorted(SESSION_PROFILES), "observed": observed,
            "missing": sorted(SESSION_PROFILES - set(observed)),
            "unexpected": sorted(set(observed) - SESSION_PROFILES),
        }))
    text = log_path.read_text(errors="replace")
    for marker in (
        "PASS: a generation-admitted same-process peer takes the PMD/exception grant",
        "PASS: original LKL post-PARKED UDP frame is journaled before prepare",
    ):
        if marker not in text:
            raise RuntimeError("native session runtime lacks terminal success marker: " + marker)
    summary(f"Native session runtime: {len(observed)}/{len(SESSION_PROFILES)} exact profile evidence records.")


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


def require_two_cpus() -> None:
    try:
        count = len(os.sched_getaffinity(0))
    except AttributeError:
        count = os.cpu_count() or 1
    if count < 2:
        raise RuntimeError("native-fstack-rx-lcores-ownership requires two allowed CPUs")


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[1] not in {"hosted-safe", "nohuge-eal", "nohuge-tap", "report-junit", "full-ctest", "tap-preflight", "verify-session-profiles"}:
        print(f"usage: {argv[0]} full-ctest CTEST_BUILD_DIR JUNIT_FILE | hosted-safe|nohuge-eal|nohuge-tap CTEST_BUILD_DIR | tap-preflight | verify-session-profiles LOG | report-junit JUNIT_FILE", file=sys.stderr)
        return 2
    if argv[1] == "tap-preflight":
        if len(argv) != 2:
            raise RuntimeError("tap-preflight takes no additional arguments")
        tap_preflight()
        return 0
    if len(argv) < 3:
        raise RuntimeError(f"{argv[1]} requires an argument")
    group, build = argv[1], Path(argv[2])
    if group == "verify-session-profiles":
        verify_session_profiles(build)
        return 0
    if group == "full-ctest":
        if len(argv) != 4:
            raise RuntimeError("full-ctest requires build directory and JUnit output path")
        run_full_ctest(build, Path(argv[3]))
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
    except (OSError, RuntimeError, subprocess.CalledProcessError, ET.ParseError, KeyError) as error:
        print("native test selection failed: " + str(error), file=sys.stderr)
        raise SystemExit(1)
