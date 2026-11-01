#!/usr/bin/env python3
"""Audit the complete pinned RSS microbenchmark and its original table builder."""
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
manifest = json.loads((root / "tests/fstack-rss-microbench-source.json").read_text())
source = (root / manifest["source_file"]).read_text()
assert hashlib.sha256(source.encode()).hexdigest() == manifest["source_sha256"]
start = source.index("#include <time.h>\n\n#ifndef FF_RSS_RECHECK_MICROBENCH_N")
end = source.index("\n/* ===== R-F:", start)
assert (root / manifest["microbench"]).read_text() == source[start:end]
helper_start = source.index("static int\ntest_rss_build_table(")
helper_end = source.index("\n}", helper_start) + 2
helpers = (root / manifest["helper"]).read_text()
assert source[helper_start:helper_end] + "\n" in helpers
assert "#define FF_RSS_RECHECK_MICROBENCH_N 10000" in source[start:end]
print("PASS: complete original RSS microbenchmark, rd_now_ns, N=10000, and table builder audited")
