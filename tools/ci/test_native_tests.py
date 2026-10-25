"""Unit checks for the native CTest selector and its no-skip contract."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

import native_tests


class NativeTestSelectorTests(unittest.TestCase):
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

    def test_full_junit_report_allows_and_reports_nonrequired_hardware_skip(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "ctest.xml"
            report.write_text(
                '<testsuites><testsuite><testcase name="required-a"/>'
                '<testcase name="hardware-test"><skipped/></testcase></testsuite></testsuites>', encoding="utf-8")
            with mock.patch.object(native_tests, "summary") as summary:
                native_tests.report_junit(report, expected={"required-a", "hardware-test"},
                                          required={"required-a"})
            self.assertTrue(any("hardware-test" in call.args[0] for call in summary.call_args_list))

    def test_junit_rejects_duplicate_and_missing_records(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "ctest.xml"
            report.write_text('<testsuites><testsuite><testcase name="required-a"/>'
                              '<testcase name="required-a"/></testsuite></testsuites>', encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "expected once"):
                native_tests.report_junit(report, expected={"required-a", "required-b"}, required={"required-a"})

    def test_full_graph_requires_every_session_test_and_reports_full_inventory(self):
        all_names = (set(native_tests.HOSTED_SAFE) | set(native_tests.NOHUGE_EAL) |
                     set(native_tests.NOHUGE_TAP) | set(native_tests.SESSION_CTEST) |
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
                self.assertEqual(command[command.index("-E") + 1],
                                 "^" + native_tests.re.escape(native_tests.SESSION_DIRECT) + "$")
                expected = sorted(all_names - {native_tests.SESSION_DIRECT})
                cases = "".join(f'<testcase name="{name}"/>' for name in expected
                                 if name != "optional-hardware")
                cases += '<testcase name="optional-hardware"><skipped/></testcase>'
                junit.write_text("<testsuites><testsuite>" + cases + "</testsuite></testsuites>",
                                 encoding="utf-8")
                return SimpleNamespace(returncode=0)

            with mock.patch.object(native_tests, "ctest_inventory", return_value=inventory), \
                 mock.patch.object(native_tests.subprocess, "run", side_effect=run), \
                 mock.patch.object(native_tests, "summary"):
                native_tests.run_full_ctest(Path("build"), junit)

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

    def test_session_profile_verifier_requires_exact_profiles_digest_and_success_markers(self):
        record = {"mode": "positive", "capture_sha256": "abc"}
        lines = ["KER_SESSION_FRAME_PROFILE_EVIDENCE " + __import__("json").dumps(
            dict(record, mode=mode)) for mode in sorted(native_tests.SESSION_PROFILES)]
        lines += ["PASS: a generation-admitted same-process peer takes the PMD/exception grant",
                  "PASS: original LKL post-PARKED UDP frame is journaled before prepare"]
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "session.log"
            log.write_text("\n".join(lines), encoding="utf-8")
            native_tests.verify_session_profiles(log)
            log.write_text("\n".join(lines[:-1]), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "terminal success marker"):
                native_tests.verify_session_profiles(log)
            log.write_text("\n".join(lines + [lines[0]]), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "profile set mismatch"):
                native_tests.verify_session_profiles(log)

    def test_nohuge_eal_does_not_require_tun_but_required_tap_preflight_fails_closed(self):
        with mock.patch.object(native_tests, "nohuge_prerequisite", return_value=(False, "no TUN")):
            with self.assertRaisesRegex(RuntimeError, "required unshare/TUN TAP preflight"):
                native_tests.tap_preflight()


if __name__ == "__main__":
    unittest.main()
