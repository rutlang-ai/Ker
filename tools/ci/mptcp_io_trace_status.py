#!/usr/bin/env python3
"""Validate diagnostic MPTCP peek/read trace coverage for CI artifacts."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


TRACE_ERROR = "KER_MPTCP_IO_TRACE_ERROR"


def _read_report(path: Path) -> tuple[dict | None, list[str]]:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        return None, [f"report_unreadable:{path.name}:{type(exc).__name__}"]
    if not isinstance(value, dict):
        return None, [f"report_not_object:{path.name}"]
    reasons = []
    if TRACE_ERROR in json.dumps(value, sort_keys=True):
        reasons.append(f"trace_error_in_report:{path.name}")
    return value, reasons


def _parse_trace(path: Path) -> tuple[list[dict], list[str]]:
    if not path.exists():
        return [], ["trace_missing"]
    try:
        content = path.read_text()
    except OSError as exc:
        return [], [f"trace_unreadable:{type(exc).__name__}"]
    if not content.strip():
        return [], ["trace_empty"]
    rows = []
    reasons = []
    for line_number, line in enumerate(content.splitlines(), 1):
        if TRACE_ERROR in line:
            reasons.append(f"trace_error_marker:line_{line_number}")
            continue
        try:
            fields = dict(item.split("=", 1) for item in line.split()[1:])
            row = {
                **fields,
                "time": float(line.split()[0]),
                "pid": int(fields["pid"]),
                "fd": int(fields["fd"]),
                "flags": int(fields["flags"], 16),
                "requested": int(fields["requested"]),
                "result": int(fields["result"]),
            }
        except (IndexError, KeyError, TypeError, ValueError):
            reasons.append(f"trace_malformed_record:line_{line_number}")
            continue
        rows.append(row)
    if not rows:
        reasons.append("trace_has_no_records")
    return rows, reasons


def _peek_read_metrics(rows: list[dict], role: str) -> dict[str, int]:
    """Return peek scope and optional read-pair metrics for one side."""
    streams: dict[tuple[int, int, str], list[tuple[int, dict]]] = {}
    for index, row in enumerate(rows):
        if row.get("role") != role or row.get("op") not in {"recvmsg", "read"}:
            continue
        key = (row["pid"], row["fd"], row.get("port", ""))
        streams.setdefault(key, []).append((index, row))

    pairs = negative = incomplete = mismatches = scope = 0
    for events in streams.values():
        events.sort(key=lambda item: item[0])
        for position, (_, peek) in enumerate(events):
            if (peek.get("op") != "recvmsg" or peek.get("phase") not in {"begin", "end"} or
                    not peek["flags"] & 2):
                continue
            scope += 1
            if peek.get("phase") != "end":
                continue
            if peek["result"] < 0:
                negative += 1
                continue
            following = events[position + 1:]
            read_begin = next(((idx, row) for idx, row in following
                               if row.get("op") in {"read", "recvmsg"} and
                               row.get("phase") == "begin"), None)
            if read_begin is None or read_begin[1].get("op") != "read":
                incomplete += 1
                continue
            read_end = next((row for idx, row in following
                             if idx > read_begin[0] and row.get("op") == "read" and
                             row.get("phase") == "end"), None)
            if read_end is None:
                incomplete += 1
                continue
            if (read_begin[1]["requested"] != peek["result"] or
                    read_end["result"] != peek["result"]):
                mismatches += 1
                continue
            pairs += 1
    return {"peek_scope_events": scope, "positive_peek_read_pairs": pairs,
            "negative_peeks": negative, "incomplete_peek_read_calls": incomplete,
            "read_result_mismatches": mismatches}


def validate(trace_path: Path, report_paths: list[Path], status_path: Path,
             extra_text_paths: list[Path] | None = None,
             provenance_status_path: Path | None = None) -> dict:
    rows, reasons = _parse_trace(trace_path)
    reports = []
    for path in report_paths:
        value, report_reasons = _read_report(path)
        reasons.extend(report_reasons)
        if value is not None:
            reports.append({"path": str(path), "status": value.get("status"),
                            "returncode": value.get("returncode"),
                            "case_count": len(value.get("cases", []))})
    for path in extra_text_paths or []:
        try:
            if TRACE_ERROR in path.read_text(errors="replace"):
                reasons.append(f"trace_error_in_text:{path.name}")
        except OSError:
            reasons.append(f"text_artifact_unreadable:{path.name}")

    helper = _peek_read_metrics(rows, "helper")
    native = _peek_read_metrics(rows, "native")
    counts = {
        "trace_records": len(rows),
        "helper_peek_scope_events": helper["peek_scope_events"],
        "helper_positive_peek_read_pairs": helper["positive_peek_read_pairs"],
        "helper_negative_peeks": helper["negative_peeks"],
        "helper_incomplete_peek_read_calls": helper["incomplete_peek_read_calls"],
        "helper_read_result_mismatches": helper["read_result_mismatches"],
        "native_peek_scope_events": native["peek_scope_events"],
        "native_positive_peek_read_pairs": native["positive_peek_read_pairs"],
        "native_negative_peeks": native["negative_peeks"],
        "native_incomplete_peek_read_calls": native["incomplete_peek_read_calls"],
        "native_read_result_mismatches": native["read_result_mismatches"],
        "helper_event_count": sum(row.get("role") == "helper" for row in rows),
        "native_event_count": sum(row.get("role") == "native" for row in rows),
    }
    if helper["peek_scope_events"] == 0:
        reasons.append("helper_peek_read_scope_missing")
    if native["peek_scope_events"] == 0:
        reasons.append("native_peek_read_scope_missing")
    if not report_paths:
        reasons.append("original_reports_missing")
    provenance = None
    if provenance_status_path is not None:
        try:
            provenance = json.loads(provenance_status_path.read_text())
            if provenance.get("status") != "complete":
                reasons.append("provenance_incomplete")
        except (OSError, json.JSONDecodeError, AttributeError):
            reasons.append("provenance_status_missing_or_invalid")
    status = {
        "status": "valid" if not reasons else "invalid",
        "classification": sorted(set(reasons)) if reasons else ["trace_and_original_reports_valid"],
        "trace_path": str(trace_path),
        "reports": reports,
        "counts": counts,
        "provenance": provenance,
    }
    status_path.parent.mkdir(parents=True, exist_ok=True)
    status_path.write_text(json.dumps(status, indent=2, sort_keys=True) + "\n")
    return status


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace", type=Path, required=True)
    parser.add_argument("--report", type=Path, action="append", default=[])
    parser.add_argument("--scan-text", type=Path, action="append", default=[])
    parser.add_argument("--provenance-status", type=Path)
    parser.add_argument("--status", type=Path, required=True)
    args = parser.parse_args(argv)
    result = validate(args.trace, args.report, args.status, args.scan_text,
                      args.provenance_status)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "valid" else 1


if __name__ == "__main__":
    sys.exit(main())
