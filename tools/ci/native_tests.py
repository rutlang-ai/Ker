#!/usr/bin/env python3
"""Select, run, and report the hosted native-backend test matrix."""
from __future__ import annotations

import json
import hashlib
import ast
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
         "--output-junit", str(junit), "--parallel", "1", "-E", "^" + re.escape(SESSION_DIRECT) + "$"],
        check=False,
    )
    if not junit.is_file():
        raise RuntimeError("full CTest graph did not produce JUnit output")
    report_junit(junit, expected=expected, required=required, ctest_returncode=result.returncode)
    summary(f"Full native CTest graph: {len(expected)} registered tests; {len(required)} mandatory hosted/session tests; session suite has no skips.")


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
        return "PASS: a generation-admitted same-process peer takes the PMD/exception grant"
    if mode == "frame-positive":
        return "PASS: original LKL post-PARKED UDP frame is journaled before prepare"
    if mode == "nonframe-active-reap":
        return "PASS: bounded non-FRAME full reap waited for the real RX dequeue"
    return f"PASS: {mode}"


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
        for mode in expected_profiles:
            marker = _legacy_profile_success_marker(mode)
            if marker not in text:
                raise RuntimeError(f"legacy native session runtime lacks profile success marker for {mode}")
    for marker in (
        _legacy_profile_success_marker("positive"),
        _legacy_profile_success_marker("frame-positive"),
    ):
        if marker not in text:
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


def require_two_cpus() -> None:
    try:
        count = len(os.sched_getaffinity(0))
    except AttributeError:
        count = os.cpu_count() or 1
    if count < 2:
        raise RuntimeError("native-fstack-rx-lcores-ownership requires two allowed CPUs")


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[1] not in {"hosted-safe", "nohuge-eal", "nohuge-tap", "report-junit", "full-ctest", "tap-preflight", "verify-session-profiles"}:
        print(f"usage: {argv[0]} full-ctest CTEST_BUILD_DIR JUNIT_FILE | hosted-safe|nohuge-eal|nohuge-tap CTEST_BUILD_DIR | tap-preflight | verify-session-profiles LOG FIXTURE | report-junit JUNIT_FILE", file=sys.stderr)
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
        if len(argv) != 4:
            raise RuntimeError("verify-session-profiles requires log path and fixture source path")
        verify_session_profiles(build, Path(argv[3]))
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
    except (OSError, RuntimeError, subprocess.CalledProcessError, ET.ParseError, KeyError, ValueError) as error:
        print("native test selection failed: " + str(error), file=sys.stderr)
        raise SystemExit(1)
