import json
from contextlib import redirect_stdout
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "ci"))

import capture_mptcp_io_provenance
import mptcp_io_trace_status
import native_tests


def event(role, op, phase, *, result=-1, requested=3, flags=0x2,
          port=10042, fd=5, pid=101, timestamp=1.0):
    return (f"{timestamp:.9f} role={role} op={op} phase={phase} pid={pid} tid={pid} "
            f"peer={pid} port={port} fd={fd} flags=0x{flags:x} requested={requested} "
            f"result={result} errno=0")


def complete_trace():
    rows = []
    for role, pid in (("helper", 101), ("native", 202)):
        rows.extend((event(role, "recvmsg", "begin", pid=pid, result=-1, timestamp=1),
                     event(role, "recvmsg", "end", pid=pid, result=3, timestamp=2),
                     event(role, "read", "begin", pid=pid, flags=0, result=-1,
                           requested=3, timestamp=3),
                     event(role, "read", "end", pid=pid, flags=0, result=3,
                           requested=3, timestamp=4)))
    return "\n".join(rows) + "\n"


class MptcpIoTraceStatusTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.trace = self.root / "trace.jsonl"
        self.report = self.root / "report.json"
        self.status = self.root / "diagnostic-status.json"
        self.provenance = self.root / "provenance-status.json"
        self.report.write_text(json.dumps({"status": "FAIL_IMPORTED_LINUX",
                                           "returncode": 1, "cases": ["case 45"]}))
        self.provenance.write_text(json.dumps({"status": "complete"}))

    def tearDown(self):
        self.temp.cleanup()

    def validate(self, extra_text_paths=None):
        return mptcp_io_trace_status.validate(
            self.trace, [self.report], self.status, extra_text_paths,
            self.provenance)

    def test_failed_original_with_both_trace_scopes_is_valid_diagnostic(self):
        self.trace.write_text(complete_trace())
        result = self.validate()
        self.assertEqual(result["status"], "valid")
        self.assertEqual(result["counts"]["helper_positive_peek_read_pairs"], 1)
        self.assertEqual(result["counts"]["native_positive_peek_read_pairs"], 1)
        self.assertEqual(json.loads(self.status.read_text())["status"], "valid")
        self.assertEqual(result["reports"][0]["status"], "FAIL_IMPORTED_LINUX")

    def test_missing_trace_is_classified_and_status_is_written(self):
        result = self.validate()
        self.assertEqual(result["status"], "invalid")
        self.assertIn("trace_missing", result["classification"])
        self.assertTrue(self.status.is_file())

    def test_cli_writes_invalid_status_before_returning_failure(self):
        with redirect_stdout(io.StringIO()):
            result = mptcp_io_trace_status.main([
                "--trace", str(self.root / "missing.jsonl"),
                "--report", str(self.report), "--status", str(self.status),
                "--provenance-status", str(self.provenance),
            ])
        self.assertEqual(result, 1)
        self.assertEqual(json.loads(self.status.read_text())["status"], "invalid")

    def test_empty_trace_is_classified(self):
        self.trace.write_text("")
        result = self.validate()
        self.assertIn("trace_empty", result["classification"])

    def test_missing_native_peek_scope_is_classified(self):
        self.trace.write_text("\n".join(event("helper", "recvmsg", phase,
                                                result=4 if phase == "end" else -1,
                                                pid=101, timestamp=i)
                                           for i, phase in enumerate(("begin", "end"), 1)) + "\n")
        result = self.validate()
        self.assertIn("native_peek_read_scope_missing", result["classification"])

    def test_missing_helper_peek_scope_is_classified(self):
        rows = [event("native", "recvmsg", "begin", pid=202),
                event("native", "recvmsg", "end", pid=202, result=3, timestamp=2)]
        self.trace.write_text("\n".join(rows) + "\n")
        result = self.validate()
        self.assertIn("helper_peek_read_scope_missing", result["classification"])

    def test_error_markers_in_trace_and_report_are_classified(self):
        self.trace.write_text(complete_trace() + "KER_MPTCP_IO_TRACE_ERROR write\n")
        report = json.loads(self.report.read_text())
        report["server_stderr"] = "KER_MPTCP_IO_TRACE_ERROR open"
        self.report.write_text(json.dumps(report))
        result = self.validate()
        self.assertTrue(any(reason.startswith("trace_error_marker:")
                            for reason in result["classification"]))
        self.assertIn("trace_error_in_report:report.json", result["classification"])

    def test_external_stderr_error_marker_is_classified(self):
        self.trace.write_text(complete_trace())
        stderr = self.root / "native.stderr"
        stderr.write_text("KER_MPTCP_IO_TRACE_ERROR write\n")
        result = self.validate([stderr])
        self.assertIn("trace_error_in_text:native.stderr", result["classification"])

    def test_blocked_peek_without_following_read_is_reported_not_rejected(self):
        rows = [event(role, "recvmsg", phase, pid=pid, result=-1 if phase == "begin" else 3,
                      timestamp=1 if phase == "begin" else 2)
                for role, pid in (("helper", 101), ("native", 202))
                for phase in ("begin", "end")]
        self.trace.write_text("\n".join(rows) + "\n")
        result = self.validate()
        self.assertEqual(result["status"], "valid")
        self.assertEqual(result["counts"]["helper_incomplete_peek_read_calls"], 1)
        self.assertEqual(result["counts"]["native_incomplete_peek_read_calls"], 1)

    def test_incomplete_provenance_is_classified(self):
        self.trace.write_text(complete_trace())
        self.provenance.write_text(json.dumps({"status": "incomplete"}))
        result = self.validate()
        self.assertIn("provenance_incomplete", result["classification"])


class MptcpIoProvenanceCaptureTests(unittest.TestCase):
    def test_complete_capture_requires_all_elfs_and_nonempty_commands(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            build, output = root / "build", root / "out"
            build.mkdir()
            for name in capture_mptcp_io_provenance.REQUIRED_BINARIES:
                (build / name).write_bytes(b"test ELF placeholder")

            def run(argv, **kwargs):
                output_text = "ninja commands\n" if argv[0] == "ninja" else "symbols\n"
                return capture_mptcp_io_provenance.subprocess.CompletedProcess(
                    argv, 0, output_text, "")

            with mock.patch.object(capture_mptcp_io_provenance.subprocess, "run", side_effect=run):
                result = capture_mptcp_io_provenance.capture(build, output)
            self.assertEqual(result["status"], "complete")
            self.assertEqual(len(result["binaries"]), 4)
            self.assertTrue(result["build_commands"]["nonempty"])
            self.assertTrue((output / "provenance-status.json").is_file())

    def test_missing_elf_makes_status_incomplete_after_status_write(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            build, output = root / "build", root / "out"
            build.mkdir()
            for name in capture_mptcp_io_provenance.REQUIRED_BINARIES[:-1]:
                (build / name).write_bytes(b"test ELF placeholder")

            def run(argv, **kwargs):
                return capture_mptcp_io_provenance.subprocess.CompletedProcess(
                    argv, 0, "ninja commands\n" if argv[0] == "ninja" else "symbols\n", "")

            with mock.patch.object(capture_mptcp_io_provenance.subprocess, "run", side_effect=run):
                result = capture_mptcp_io_provenance.capture(build, output)
            self.assertEqual(result["status"], "incomplete")
            self.assertFalse(result["binaries"][-1]["source_exists"])
            self.assertEqual(json.loads((output / "provenance-status.json").read_text())["status"],
                             "incomplete")

    def test_failed_symbol_capture_makes_status_incomplete(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            build, output = root / "build", root / "out"
            build.mkdir()
            for name in capture_mptcp_io_provenance.REQUIRED_BINARIES:
                (build / name).write_bytes(b"test ELF placeholder")

            def run(argv, **kwargs):
                if argv[0] == "nm":
                    return capture_mptcp_io_provenance.subprocess.CompletedProcess(
                        argv, 9, "", "nm failed")
                return capture_mptcp_io_provenance.subprocess.CompletedProcess(
                    argv, 0, "ninja commands\n", "")

            with mock.patch.object(capture_mptcp_io_provenance.subprocess, "run", side_effect=run):
                result = capture_mptcp_io_provenance.capture(build, output)
            self.assertEqual(result["status"], "incomplete")
            self.assertEqual(result["binaries"][0]["nm_exit_code"], 9)
            self.assertTrue((output / "provenance-status.json").is_file())


class MptcpIoWorkflowScopeTests(unittest.TestCase):
    def test_trace_activation_is_limited_to_the_four_shell_connect_step(self):
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
        start = workflow.index("      - name: Run the four complete original MPTCP connect shells")
        end = workflow.index("      - name: Capture MPTCP connect diagnostic provenance", start)
        step = workflow[start:end]
        self.assertEqual(step.count("KER_MPTCP_IO_TRACE:"), 1)
        self.assertIn("native_tests.py connect-profile", step)
        self.assertEqual(native_tests.LINUX_MPTCP_CONNECT_PROFILE_TESTS, {
            "linux-original-mptcp-connect-connect",
            "linux-original-mptcp-connect-mmap",
            "linux-original-mptcp-connect-sendfile",
            "linux-original-mptcp-connect-checksum",
        })

    def test_diagnostic_validation_and_upload_run_after_failure(self):
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
        validation = workflow.split("      - name: Validate MPTCP connect diagnostic artifacts", 1)[1]
        validation = validation.split("      - name:", 1)[0]
        self.assertIn("if: always()", validation)
        self.assertIn("mptcp_io_trace_status.py", validation)
        upload = workflow.split("      - name: Upload native test reports", 1)[1]
        self.assertIn("if: always()", upload)
        self.assertIn("native-mptcp-connect-io-trace.jsonl", upload)
        self.assertIn("native-mptcp-connect-diagnostic/", upload)

if __name__ == "__main__":
    unittest.main()
