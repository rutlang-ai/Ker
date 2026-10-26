"""Unit checks for the native CTest selector and its no-skip contract."""
from __future__ import annotations

import ast
import importlib.util
from pathlib import Path
import hashlib
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
from types import SimpleNamespace

import native_tests


class NativeTestSelectorTests(unittest.TestCase):
    def test_udp_completion_ack_waits_for_success_and_is_not_sent_on_client_failure(self):
        source = Path(__file__).resolve().parents[2] / "tests/posix/tcp-interop.py"
        spec = importlib.util.spec_from_file_location("ker_test_tcp_interop", source)
        self.assertIsNotNone(spec)
        interop = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(interop)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            child = root / "peer.py"
            child.write_text(
                "import os, sys\n"
                "from pathlib import Path\n"
                "print('READY 26444', flush=True)\n"
                "if os.read(0, 1) == b'\\xa5': Path(sys.argv[1]).write_text('ack')\n",
                encoding="utf-8",
            )
            log_path = root / "server.log"
            success_marker = root / "success.marker"
            with log_path.open("w", encoding="utf-8") as log:
                with interop.server([sys.executable, str(child), str(success_marker)], 26444,
                                    log, os.environ, completion_ack=True):
                    pass
            self.assertEqual(success_marker.read_text(encoding="utf-8"), "ack")

            failure_marker = root / "failure.marker"
            with log_path.open("w", encoding="utf-8") as log:
                with self.assertRaisesRegex(RuntimeError, "client checks failed"):
                    with interop.server([sys.executable, str(child), str(failure_marker)], 26444,
                                        log, os.environ, completion_ack=True):
                        raise RuntimeError("client checks failed")
            self.assertFalse(failure_marker.exists())

    def fixture_source(self, recovery: bool) -> str:
        recovery_calls = "".join(
            f"    run_live_handoff_profile(args, api, plugin_paths, mode={mode!r})\n"
            for mode in sorted(native_tests.FRAME_RECOVERY_PROFILES)) if recovery else ""
        evidence = "    marker = 'KER_SESSION_FRAME_PROFILE_EVIDENCE'\n" if recovery else ""
        negative = tuple(sorted(native_tests.MANDATORY_NEGATIVE_PROFILES))
        return (
            "def run_live_handoff_profile(args, api, plugins, mode='positive'): pass\n"
            "def main(args, api, plugins):\n"
            "    run_live_handoff_profile(args, api, plugins)\n"
            "    run_live_handoff_profile(args, api, plugins, mode='frame-positive')\n"
            "    run_live_handoff_profile(args, api, plugins, mode='nonframe-active-reap')\n"
            + recovery_calls +
            "    if args.handoff_negative_profiles:\n"
            f"        for mode in {negative!r}:\n"
            "            run_live_handoff_profile(args, api, plugins, mode=mode)\n"
            + evidence
        )

    def session_log(self, profiles, structured: bool) -> list[str]:
        lines = []
        for mode in sorted(profiles):
            channels = dict(profile=mode, primary="/run/dpdk/base", owner=dict(pid=100, socket="owner.sock"),
                            peer=dict(pid=101, socket="peer.sock"))
            lines.append("KER_SESSION_HANDOFF_EAL_CHANNELS " + json.dumps(channels, sort_keys=True))
            lines.append(f"KER_SESSION_HANDOFF_HUGEPAGES_RECLAIMED profile={mode} mode=private pages=0")
            if structured:
                evidence = dict(mode=mode, resident_markers=[], snapshots=[], actors={})
                evidence["capture_sha256"] = hashlib.sha256(json.dumps(
                    evidence, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                lines.append("KER_SESSION_FRAME_PROFILE_EVIDENCE " + json.dumps(evidence, sort_keys=True))
            else:
                lines.append(native_tests._legacy_profile_success_marker(mode))
        lines += [native_tests._legacy_profile_success_marker("positive"),
                  native_tests._legacy_profile_success_marker("frame-positive")]
        return lines

    def junit_run(self, skipped: bool = False, failure: bool = False, error: bool = False,
                  returncode: int = 0, names: tuple[str, ...] = ("required-a",)):
        def run(command, **_kwargs):
            report = Path(command[command.index("--output-junit") + 1])
            skip = "<skipped/>" if skipped else ""
            failed = "<failure message='bad'/>" if failure else ""
            errored = "<error message='bad'/>" if error else ""
            report.write_text(
                '<testsuites><testsuite>' + ''.join(
                    f'<testcase name="{name}" classname="native">{skip}{failed}{errored}</testcase>'
                    for name in names) + '</testsuite></testsuites>',
                encoding="utf-8",
            )
            return SimpleNamespace(returncode=returncode)
        return run

    def test_required_suite_passes_only_with_exact_junit_record(self):
        with mock.patch.object(native_tests, "ctest_names", return_value={"required-a"}), \
             mock.patch.object(native_tests.subprocess, "run", side_effect=self.junit_run()):
            native_tests.run_group(Path("build"), "selector test", ("required-a",))

    def test_missing_required_ctest_fails_before_run(self):
        with mock.patch.object(native_tests, "ctest_names", return_value=set()), \
             mock.patch.object(native_tests.subprocess, "run") as run:
            with self.assertRaisesRegex(RuntimeError, "expected CTests are absent"):
                native_tests.run_group(Path("build"), "selector test", ("required-a",))
            run.assert_not_called()

    def test_ctest_skip_is_not_accepted_as_a_pass(self):
        with mock.patch.object(native_tests, "ctest_names", return_value={"required-a"}), \
             mock.patch.object(native_tests.subprocess, "run", side_effect=self.junit_run(skipped=True)):
            with self.assertRaisesRegex(RuntimeError, "skipped"):
                native_tests.run_group(Path("build"), "selector test", ("required-a",))

    def test_full_junit_report_allows_only_explicitly_reviewed_optional_skip(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "ctest.xml"
            report.write_text(
                '<testsuites><testsuite><testcase name="required-a"/>'
                '<testcase name="hardware-test"><skipped/></testcase></testsuite></testsuites>', encoding="utf-8")
            with mock.patch.object(native_tests, "REVIEWED_OPTIONAL_SKIPS", frozenset({"hardware-test"})), \
                 mock.patch.object(native_tests, "summary") as summary:
                native_tests.report_junit(report, expected={"required-a", "hardware-test"},
                                          required={"required-a"})
            self.assertTrue(any("hardware-test" in call.args[0] for call in summary.call_args_list))
            with mock.patch.object(native_tests, "REVIEWED_OPTIONAL_SKIPS", frozenset()), \
                 self.assertRaisesRegex(RuntimeError, "unreviewed CTest skips"):
                native_tests.report_junit(report, expected={"required-a", "hardware-test"},
                                          required={"required-a"})

    def test_junit_rejects_duplicate_and_missing_records(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "ctest.xml"
            report.write_text('<testsuites><testsuite><testcase name="required-a"/>'
                              '<testcase name="required-a"/></testsuite></testsuites>', encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "expected once"):
                native_tests.report_junit(report, expected={"required-a", "required-b"}, required={"required-a"})

    def test_full_graph_requires_every_session_test_and_reports_full_inventory(self):
        all_names = (set(native_tests.HOSTED_SAFE) | set(native_tests.NOHUGE_EAL) |
                     set(native_tests.NOHUGE_TAP) | set(native_tests.REQUIRED_SOFTWARE_DATAPATH) |
                     set(native_tests.SESSION_CTEST) |
                     {native_tests.SESSION_DIRECT, "optional-hardware"})
        inventory = [{"name": name, "properties": [
            {"name": "LABELS", "value": ["session", "fstack"]}
            if name in set(native_tests.SESSION_CTEST) | {native_tests.SESSION_DIRECT}
            else {"name": "LABELS", "value": ["fstack"]}
        ]} for name in sorted(all_names)]
        with tempfile.TemporaryDirectory() as temporary:
            junit = Path(temporary) / "full.xml"

            def run(command, **_kwargs):
                self.assertIn("-E", command)
                self.assertEqual(command[command.index("--parallel") + 1], "1")
                self.assertEqual(command[command.index("-E") + 1],
                                 "^" + native_tests.re.escape(native_tests.SESSION_DIRECT) + "$")
                expected = sorted(all_names - {native_tests.SESSION_DIRECT})
                cases = "".join(f'<testcase name="{name}"/>' for name in expected
                                 if name != "optional-hardware")
                cases += '<testcase name="optional-hardware"><skipped/></testcase>'
                junit.write_text("<testsuites><testsuite>" + cases + "</testsuite></testsuites>",
                                 encoding="utf-8")
                return SimpleNamespace(returncode=0)

            with mock.patch.object(native_tests, "REVIEWED_OPTIONAL_SKIPS", frozenset({"optional-hardware"})), \
                 mock.patch.object(native_tests, "ctest_inventory", return_value=inventory), \
                 mock.patch.object(native_tests.subprocess, "run", side_effect=run), \
                 mock.patch.object(native_tests, "summary"):
                native_tests.run_full_ctest(Path("build"), junit)

    def test_control_and_orphan_session_regressions_are_mandatory_inventory(self):
        cmake = Path(__file__).resolve().parents[2] / "cmake/NativeLinux.cmake"
        registrations = set(re.findall(
            r"add_test\(NAME (native-fstack-session-(?:control|orphan)-[A-Za-z0-9-]+)",
            cmake.read_text(encoding="utf-8"),
        ))
        self.assertTrue(registrations)
        self.assertTrue(registrations <= set(native_tests.SESSION_CTEST))

        all_names = (set(native_tests.HOSTED_SAFE) | set(native_tests.NOHUGE_EAL) |
                     set(native_tests.NOHUGE_TAP) | set(native_tests.REQUIRED_SOFTWARE_DATAPATH) |
                     set(native_tests.SESSION_CTEST) | {native_tests.SESSION_DIRECT})
        session_names = set(native_tests.SESSION_CTEST) | {native_tests.SESSION_DIRECT}
        inventory = [{"name": name, "properties": [
            {"name": "LABELS", "value": ["session", "fstack"]}
            if name in session_names else {"name": "LABELS", "value": ["fstack"]}
        ]} for name in sorted(all_names)]
        for skipped in sorted(registrations):
            with self.subTest(skipped=skipped), tempfile.TemporaryDirectory() as temporary:
                junit = Path(temporary) / "full.xml"

                def run(_command, **_kwargs):
                    cases = "".join(
                        f'<testcase name="{name}">' + ("<skipped/>" if name == skipped else "") +
                        "</testcase>" for name in sorted(all_names - {native_tests.SESSION_DIRECT})
                    )
                    junit.write_text(f"<testsuites><testsuite>{cases}</testsuite></testsuites>",
                                     encoding="utf-8")
                    return SimpleNamespace(returncode=0)

                with mock.patch.object(native_tests, "ctest_inventory", return_value=inventory), \
                     mock.patch.object(native_tests.subprocess, "run", side_effect=run), \
                     self.assertRaisesRegex(RuntimeError, "required tests skipped"):
                    native_tests.run_full_ctest(Path(temporary), junit)

        # A registration omitted from the selector is rejected before execution.
        missing_inventory = [item for item in inventory
                             if item["name"] != sorted(registrations)[0]]
        with mock.patch.object(native_tests, "ctest_inventory", return_value=missing_inventory), \
             self.assertRaisesRegex(RuntimeError, "missing required tests"):
            native_tests.run_full_ctest(Path("build"), Path("unused.xml"))

        # Unknown session-labeled registrations remain fail-closed.
        unknown_inventory = inventory + [{"name": "native-fstack-session-unreviewed", "properties": [
            {"name": "LABELS", "value": ["session", "fstack"]}
        ]}]
        with mock.patch.object(native_tests, "ctest_inventory", return_value=unknown_inventory), \
             self.assertRaisesRegex(RuntimeError, "session CTest label inventory changed"):
            native_tests.run_full_ctest(Path("build"), Path("unused.xml"))

    def test_full_graph_rejects_each_software_datapath_skip(self):
        all_names = (set(native_tests.HOSTED_SAFE) | set(native_tests.NOHUGE_EAL) |
                     set(native_tests.NOHUGE_TAP) | set(native_tests.REQUIRED_SOFTWARE_DATAPATH) |
                     set(native_tests.SESSION_CTEST) | {native_tests.SESSION_DIRECT})
        inventory = [{"name": name, "properties": [
            {"name": "LABELS", "value": ["session", "fstack"]}
            if name in set(native_tests.SESSION_CTEST) | {native_tests.SESSION_DIRECT}
            else {"name": "LABELS", "value": ["fstack"]}
        ]} for name in sorted(all_names)]
        for skipped in native_tests.REQUIRED_SOFTWARE_DATAPATH:
            with self.subTest(skipped=skipped), tempfile.TemporaryDirectory() as temporary:
                junit = Path(temporary) / "full.xml"

                def run(_command, **_kwargs):
                    expected = sorted(all_names - {native_tests.SESSION_DIRECT})
                    cases = "".join(
                        f'<testcase name="{name}">' + ("<skipped/>" if name == skipped else "") +
                        "</testcase>" for name in expected)
                    junit.write_text("<testsuites><testsuite>" + cases + "</testsuite></testsuites>",
                                     encoding="utf-8")
                    return SimpleNamespace(returncode=0)

                with mock.patch.object(native_tests, "ctest_inventory", return_value=inventory), \
                     mock.patch.object(native_tests.subprocess, "run", side_effect=run), \
                     mock.patch.object(native_tests, "summary"), \
                     self.assertRaisesRegex(RuntimeError, "required tests skipped"):
                    native_tests.run_full_ctest(Path("build"), junit)

    def test_dpdk_runtime_discovery_follows_meson_unversioned_plugin_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix = Path(temporary) / "dpdk"
            plugin_dir = prefix / "lib64" / "dpdk" / "pmds-27.0"
            library_dir = prefix / "lib64"
            plugin_dir.mkdir(parents=True)
            library_dir.mkdir(parents=True, exist_ok=True)
            for name in ("librte_mempool_ring", "librte_net_ring"):
                (plugin_dir / f"{name}.so.27.0").write_bytes(b"versioned DPDK plugin")
                (plugin_dir / f"{name}.so").symlink_to(f"{name}.so.27.0")
            (library_dir / "librte_eal.so.27").write_bytes(b"versioned DPDK library")
            (library_dir / "librte_eal.so").symlink_to("librte_eal.so.27")

            self.assertEqual(native_tests.dpdk_plugin_directory(
                prefix, ("librte_mempool_ring.so", "librte_net_ring.so")), plugin_dir)
            self.assertCountEqual(native_tests.dpdk_runtime_directories(prefix), [plugin_dir, library_dir])
            with self.assertRaisesRegex(RuntimeError, "missing required plugins"):
                native_tests.dpdk_plugin_directory(prefix, ("librte_missing.so",))

    def test_dpdk_discovery_rejects_missing_dangling_and_out_of_prefix_targets(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outside = root / "outside.so"
            outside.write_bytes(b"outside install")

            missing = root / "missing"
            missing.mkdir()
            with self.assertRaisesRegex(RuntimeError, "no shared-library files"):
                native_tests.dpdk_runtime_directories(missing)
            with self.assertRaisesRegex(RuntimeError, "missing required plugins"):
                native_tests.dpdk_plugin_directory(missing, ("librte_mempool_ring.so",))

            dangling_runtime = root / "dangling-runtime"
            dangling_runtime.mkdir()
            (dangling_runtime / "librte_eal.so").symlink_to("missing-version.so")
            with self.assertRaisesRegex(RuntimeError, "missing or dangling"):
                native_tests.dpdk_runtime_directories(dangling_runtime)

            dangling_plugin = root / "dangling-plugin" / "pmds"
            dangling_plugin.mkdir(parents=True)
            (dangling_plugin / "librte_mempool_ring.so").symlink_to("missing-version.so")
            with self.assertRaisesRegex(RuntimeError, "missing or dangling"):
                native_tests.dpdk_plugin_directory(
                    dangling_plugin.parents[0], ("librte_mempool_ring.so",))

            escaping_runtime = root / "escaping-runtime"
            escaping_runtime.mkdir()
            (escaping_runtime / "librte_eal.so").symlink_to(outside)
            with self.assertRaisesRegex(RuntimeError, "escapes install prefix"):
                native_tests.dpdk_runtime_directories(escaping_runtime)

            escaping_plugin = root / "escaping-plugin" / "pmds"
            escaping_plugin.mkdir(parents=True)
            (escaping_plugin / "librte_mempool_ring.so").symlink_to(outside)
            with self.assertRaisesRegex(RuntimeError, "escapes install prefix"):
                native_tests.dpdk_plugin_directory(
                    escaping_plugin.parents[0], ("librte_mempool_ring.so",))

    def test_junit_rejects_nonzero_ctest_even_when_xml_is_green(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "ctest.xml"
            report.write_text('<testsuites><testsuite><testcase name="required-a"/></testsuite></testsuites>',
                              encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "ctest_returncode"):
                native_tests.report_junit(report, expected={"required-a"}, required={"required-a"},
                                          ctest_returncode=1)

    def test_junit_rejects_failures_and_errors(self):
        for tag in ("failure", "error"):
            with self.subTest(tag=tag), tempfile.TemporaryDirectory() as temporary:
                report = Path(temporary) / "ctest.xml"
                report.write_text(f'<testsuites><testsuite><testcase name="required-a"><{tag}/>'
                                  f'</testcase></testsuite></testsuites>', encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, "full CTest graph failed"):
                    native_tests.report_junit(report, expected={"required-a"}, required={"required-a"})

    def test_required_skip_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "ctest.xml"
            report.write_text('<testsuites><testsuite><testcase name="required-a"><skipped/></testcase>'
                              '</testsuite></testsuites>', encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "required tests skipped"):
                native_tests.report_junit(report, expected={"required-a"}, required={"required-a"})

    def test_session_profile_verifier_supports_exact_legacy19_and_structured27_sets(self):
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "session.log"
            for recovery in (False, True):
                source = Path(temporary) / f"fixture-{recovery}.py"
                source.write_text(self.fixture_source(recovery), encoding="utf-8")
                expected, structured = native_tests.expected_session_profiles(source)
                self.assertEqual(len(expected), 27 if recovery else 19)
                self.assertEqual(structured, recovery)
                lines = self.session_log(expected, structured)
                log.write_text("\n".join(lines), encoding="utf-8")
                native_tests.verify_session_profiles(log, source)

                if not structured:
                    hup_marker = native_tests._legacy_profile_success_marker("handoff-control-hup")
                    altered = [line for line in lines if line != hup_marker]
                    altered.append(hup_marker + " (embedded text is not an exact success line)")
                    log.write_text("\n".join(altered), encoding="utf-8")
                    with self.assertRaisesRegex(RuntimeError,
                                                "legacy native session runtime lacks profile success marker for handoff-control-hup"):
                        native_tests.verify_session_profiles(log, source)

                missing_eal = [line for line in lines if not line.startswith("KER_SESSION_HANDOFF_EAL_CHANNELS ")]
                log.write_text("\n".join(missing_eal), encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, "EAL-channel profile set mismatch"):
                    native_tests.verify_session_profiles(log, source)

                lines = self.session_log(expected, structured)
                extra = dict(profile="unexpected", primary="/run/dpdk/base",
                             owner=dict(pid=100, socket="owner.sock"),
                             peer=dict(pid=101, socket="peer.sock"))
                lines.append("KER_SESSION_HANDOFF_EAL_CHANNELS " + json.dumps(extra, sort_keys=True))
                log.write_text("\n".join(lines), encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, "EAL-channel profile set mismatch"):
                    native_tests.verify_session_profiles(log, source)

                lines = self.session_log(expected, structured)
                missing_cleanup = [line for line in lines if "HUGEPAGES_RECLAIMED" not in line]
                log.write_text("\n".join(missing_cleanup), encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, "hugepage-cleanup profile set mismatch"):
                    native_tests.verify_session_profiles(log, source)

                lines = self.session_log(expected, structured)
                lines.append("KER_SESSION_HANDOFF_HUGEPAGES_RECLAIMED profile=unexpected mode=private files=0")
                log.write_text("\n".join(lines), encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, "hugepage-cleanup profile set mismatch"):
                    native_tests.verify_session_profiles(log, source)

                lines = self.session_log(expected, structured)
                lines.append("KER_SESSION_HANDOFF_HUGEPAGE_CLEANUP_REFUSED {}")
                log.write_text("\n".join(lines), encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, "cleanup refusal"):
                    native_tests.verify_session_profiles(log, source)

                lines = self.session_log(expected, structured)
                if structured:
                    evidence_index = next(i for i, line in enumerate(lines)
                                          if line.startswith("KER_SESSION_FRAME_PROFILE_EVIDENCE "))
                    record = json.loads(lines[evidence_index].split(" ", 1)[1])
                    record["capture_sha256"] = "0" * 64
                    lines[evidence_index] = "KER_SESSION_FRAME_PROFILE_EVIDENCE " + json.dumps(record, sort_keys=True)
                    log.write_text("\n".join(lines), encoding="utf-8")
                    with self.assertRaisesRegex(RuntimeError, "digest does not match"):
                        native_tests.verify_session_profiles(log, source)

                    record["capture_sha256"] = "not-a-digest"
                    lines[evidence_index] = "KER_SESSION_FRAME_PROFILE_EVIDENCE " + json.dumps(record, sort_keys=True)
                    log.write_text("\n".join(lines), encoding="utf-8")
                    with self.assertRaisesRegex(RuntimeError, "malformed capture digest"):
                        native_tests.verify_session_profiles(log, source)

    def test_checked_in_session_fixture_inventory_matches_classifier_negative_profiles(self):
        source = Path(__file__).resolve().parents[2] / "tests/posix/session-native-packets.py"
        expected, structured = native_tests.expected_session_profiles(source)
        self.assertEqual(expected, native_tests.MANDATORY_SESSION_PROFILES | native_tests.FRAME_RECOVERY_PROFILES)
        self.assertTrue(structured)
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main")
        negative_loop = next(node for node in ast.walk(main) if isinstance(node, ast.For) and
                             isinstance(node.target, ast.Name) and node.target.id == "mode" and
                             native_tests._literal_profile_tuple(node.iter) is not None and
                             "bad-capability" in native_tests._literal_profile_tuple(node.iter))
        self.assertEqual(native_tests._literal_profile_tuple(negative_loop.iter),
                         native_tests.MANDATORY_NEGATIVE_PROFILES)

    def test_legacy_fixed_profile_markers_match_checked_in_fixture_literals(self):
        source = Path(__file__).resolve().parents[2] / "tests/posix/session-native-packets.py"
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        printed_literals = {
            node.args[0].value for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "print" and
            node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)
        }
        for mode in ("positive", "frame-positive", "nonframe-active-reap", "handoff-control-hup"):
            marker = native_tests._legacy_profile_success_marker(mode)
            with self.subTest(mode=mode):
                self.assertIn(marker, printed_literals)

    def test_session_profile_inventory_fails_closed_for_missing_renamed_or_unsupported_values(self):
        valid = self.fixture_source(False)
        literal = repr(tuple(sorted(native_tests.MANDATORY_NEGATIVE_PROFILES)))
        mutations = (
            (valid.replace(literal, literal.replace("'bad-capability'", "'renamed-capability'", 1)),
             "negative-profile loop differs"),
            (valid.replace("for mode in " + literal,
                           "for mode in " + literal.replace("'bad-capability', ", "", 1)),
             "negative-profile loop differs"),
            (valid.replace("for mode in " + literal, "for mode in get_negative_profiles()"),
             "negative-profile loop differs"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "fixture.py"
            for mutated, message in mutations:
                with self.subTest(source=mutated):
                    source.write_text(mutated, encoding="utf-8")
                    with self.assertRaisesRegex(RuntimeError, message):
                        native_tests.expected_session_profiles(source)

    def test_nohuge_eal_does_not_require_tun_but_required_tap_preflight_fails_closed(self):
        with mock.patch.object(native_tests, "nohuge_prerequisite", return_value=(False, "no TUN")):
            with self.assertRaisesRegex(RuntimeError, "required unshare/TUN TAP preflight"):
                native_tests.tap_preflight()

    def test_native_datapath_preflight_requires_pinned_pm_ds_device_and_two_cpus(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix = Path(temporary)
            directories = []

            def plugin(_prefix, names):
                self.assertEqual(len(names), 1)
                directories.append(names[0])
                return prefix / "lib64" / "dpdk" / "pmds-27.0"

            with mock.patch.object(native_tests, "require_two_cpus") as cpus, \
                 mock.patch.object(native_tests, "tap_preflight") as tap, \
                 mock.patch.object(native_tests, "dpdk_plugin_directory", side_effect=plugin), \
                 mock.patch.object(Path, "is_char_device", return_value=True), \
                 mock.patch.object(native_tests.os, "open", return_value=77) as open_device, \
                 mock.patch.object(native_tests.os, "close") as close_device, \
                 mock.patch.object(native_tests, "summary"):
                native_tests.native_datapath_preflight(prefix)
            cpus.assert_called_once_with()
            tap.assert_called_once_with()
            self.assertCountEqual(directories, ("librte_net_tap.so", "librte_net_virtio.so",
                                                "librte_net_vhost.so"))
            open_device.assert_called_once_with(Path("/dev/vhost-net"), native_tests.os.O_RDWR |
                                                native_tests.os.O_CLOEXEC)
            close_device.assert_called_once_with(77)

            with mock.patch.object(native_tests, "require_two_cpus"), \
                 mock.patch.object(native_tests, "tap_preflight"), \
                 mock.patch.object(native_tests, "dpdk_plugin_directory", side_effect=plugin), \
                 mock.patch.object(Path, "is_char_device", return_value=False), \
                 mock.patch.object(native_tests.os, "open") as open_device:
                with self.assertRaisesRegex(RuntimeError, "vhost-net character device"):
                    native_tests.native_datapath_preflight(prefix)
                open_device.assert_not_called()

    def test_tap_retry_manifest_binds_exact_pinned_patch_and_prepared_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "dpdk"
            tap = source / "drivers/net/tap/rte_eth_tap.c"
            tap.parent.mkdir(parents=True)
            tap.write_text("patched TAP source\n", encoding="utf-8")
            patch = root / "tap.patch"
            patch.write_text("pinned patch\n", encoding="utf-8")
            manifest = {
                "upstream_commit": "d129414711aa7c4954f997acf4c54338574a7d92",
                "patch_sha256": hashlib.sha256(patch.read_bytes()).hexdigest(),
                "tap_source_sha256": hashlib.sha256(tap.read_bytes()).hexdigest(),
                "compatibility_abi": "ker_dpdk_tap_tx_retry_abi=1",
            }
            (source / "ker-tap-retry-provenance.json").write_text(
                json.dumps(manifest), encoding="utf-8")
            with mock.patch.object(native_tests, "summary"):
                self.assertEqual(native_tests.verify_tap_retry_source(source, patch), manifest)

            bad_manifest = dict(manifest, upstream_commit="un-pinned")
            (source / "ker-tap-retry-provenance.json").write_text(
                json.dumps(bad_manifest), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "provenance mismatch"):
                native_tests.verify_tap_retry_source(source, patch)

            (source / "ker-tap-retry-provenance.json").write_text(
                json.dumps(manifest), encoding="utf-8")
            patch.write_text("different patch\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "provenance mismatch"):
                native_tests.verify_tap_retry_source(source, patch)

            patch.write_text("pinned patch\n", encoding="utf-8")
            tap.write_text("changed source\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "provenance mismatch"):
                native_tests.verify_tap_retry_source(source, patch)

    def test_workflow_session_timeout_kills_pipeline_descendants(self):
        workflow = (Path(__file__).resolve().parents[2] / ".github/workflows/ci.yml").read_text(
            encoding="utf-8")
        timeout_line = re.search(r"(?m)^\s*(timeout\b[^\n]*\b900s)\s*\\\s*$", workflow)
        self.assertIsNotNone(timeout_line, "session workflow timeout command was not found")
        command = timeout_line.group(1)
        self.assertNotIn("--foreground", command,
                         "foreground mode leaves pipeline descendants holding the log pipe")
        command = command.replace("--kill-after=20s", "--kill-after=1s").replace("900s", "1s")
        timeout_argv = shlex.split(command)

        with tempfile.TemporaryDirectory() as temporary:
            pid_file = Path(temporary) / "grandchild.pid"
            child = (
                "trap '' TERM; "
                "( trap '' TERM; printf '%s\\n' \"$BASHPID\" > \"$1\"; "
                "while :; do sleep 1; done ) & wait"
            )
            def start_timeout(variant: list[str]) -> tuple[subprocess.Popen, float]:
                pipeline = (shlex.join(variant) + " bash -c " + shlex.quote(child) +
                            " _ " + shlex.quote(str(pid_file)) + " 2>&1 | cat")
                started = time.monotonic()
                process = subprocess.Popen(
                    ["bash", "-o", "pipefail", "-c", pipeline],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                    start_new_session=True,
                )
                return process, started

            def terminate_test_tree(process: subprocess.Popen) -> None:
                if pid_file.is_file():
                    grandchild = int(pid_file.read_text(encoding="utf-8").strip())
                    try:
                        os.killpg(os.getpgid(grandchild), signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    process.communicate(timeout=2)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.communicate(timeout=2)

            process = None
            try:
                process, started = start_timeout(timeout_argv)
                output, _ = process.communicate(timeout=5)
                elapsed = time.monotonic() - started
                self.assertNotEqual(process.returncode, 0, output)
                self.assertLess(elapsed, 4.5, output)
                self.assertTrue(pid_file.is_file(), output)
                grandchild = int(pid_file.read_text(encoding="utf-8").strip())
                for _ in range(20):
                    try:
                        os.kill(grandchild, 0)
                    except ProcessLookupError:
                        break
                    stat = Path(f"/proc/{grandchild}/stat")
                    if not stat.exists() or stat.read_text(encoding="utf-8").split()[2] == "Z":
                        break
                    time.sleep(0.05)
                else:
                    self.fail(f"timeout left TERM-ignoring grandchild {grandchild} alive")
            finally:
                if process is not None:
                    terminate_test_tree(process)

            # Reintroducing the old GNU timeout mode causes the pipeline shell
            # to hang on the descendant's inherited stdout. Bound that mutant
            # here and kill its entire test tree so the test itself leaves no
            # orphan behind.
            pid_file.unlink(missing_ok=True)
            foreground_argv = list(timeout_argv)
            foreground_argv.insert(1, "--foreground")
            process = subprocess.Popen(
                ["bash", "-o", "pipefail", "-c", shlex.join(foreground_argv) +
                 " bash -c " + shlex.quote(child) + " _ " + shlex.quote(str(pid_file)) + " 2>&1 | cat"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                start_new_session=True,
            )
            try:
                with self.assertRaises(subprocess.TimeoutExpired):
                    process.communicate(timeout=2.5)
                self.assertTrue(pid_file.is_file(), "foreground mutant did not start descendant")
            finally:
                terminate_test_tree(process)

if __name__ == "__main__":
    unittest.main()
