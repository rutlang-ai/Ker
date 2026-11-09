#!/usr/bin/env python3
"""Capture and validate the exact MPTCP diagnostic helper/runtime artifacts."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys


REQUIRED_BINARIES = (
    "ker-linux-mptcp-diag-connect",
    "ker-linux-mptcp-socket-server",
    "libker-linux-mptcp-diag-preload.so",
    "libker-posix.so.0.1.0",
)
BUILD_TARGETS = (
    "ker-linux-mptcp-diag-connect",
    "ker-linux-mptcp-socket-server",
    "ker-linux-mptcp-diag-preload",
    "ker-posix",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def capture(build_dir: Path, output_dir: Path) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    binaries = []
    for name in REQUIRED_BINARIES:
        source = build_dir / name
        destination = output_dir / name
        item = {"name": name, "source_exists": source.is_file(),
                "copy_exit_code": None, "nm_exit_code": None, "nm_symbols_nonempty": False,
                "sha256": None}
        if source.is_file():
            try:
                shutil.copy2(source, destination)
                item["copy_exit_code"] = 0
                item["sha256"] = _sha256(destination)
            except OSError as exc:
                item["copy_exit_code"] = 1
                item["copy_error"] = f"{type(exc).__name__}: {exc}"
            if item["copy_exit_code"] == 0:
                try:
                    result = subprocess.run(["nm", "-D", str(destination)],
                                            capture_output=True, text=True, check=False)
                    item["nm_exit_code"] = result.returncode
                    symbols_path = output_dir / f"{name}.dynamic-symbols.txt"
                    symbols_path.write_text(result.stdout)
                    item["nm_symbols_path"] = str(symbols_path)
                    item["nm_symbols_nonempty"] = symbols_path.stat().st_size > 0
                    if item["nm_symbols_nonempty"]:
                        item["nm_symbols_sha256"] = _sha256(symbols_path)
                    if result.stderr:
                        (output_dir / f"{name}.dynamic-symbols.stderr").write_text(result.stderr)
                except OSError as exc:
                    item["nm_exit_code"] = 127
                    item["nm_error"] = f"{type(exc).__name__}: {exc}"
        else:
            item["copy_exit_code"] = 1
            item["nm_exit_code"] = 127
        binaries.append(item)

    commands_path = output_dir / "build-commands.txt"
    try:
        result = subprocess.run(["ninja", "-C", str(build_dir), "-t", "commands",
                                 *BUILD_TARGETS], capture_output=True, text=True, check=False)
        commands_path.write_text(result.stdout)
        command_exit_code = result.returncode
        command_stderr = result.stderr
    except OSError as exc:
        commands_path.write_text("")
        command_exit_code = 127
        command_stderr = f"{type(exc).__name__}: {exc}"
    if command_stderr:
        (output_dir / "build-commands.stderr").write_text(command_stderr)

    complete = (all(item["source_exists"] and item["copy_exit_code"] == 0 and
                    item["nm_exit_code"] == 0 and item["nm_symbols_nonempty"] and item["sha256"]
                    for item in binaries) and
                command_exit_code == 0 and commands_path.stat().st_size > 0)
    status = {
        "status": "complete" if complete else "incomplete",
        "capture_exit_code": 0 if complete else 1,
        "binaries": binaries,
        "build_commands": {"path": str(commands_path),
                           "exit_code": command_exit_code,
                           "nonempty": commands_path.stat().st_size > 0,
                           "sha256": _sha256(commands_path)},
    }
    status_path = output_dir / "provenance-status.json"
    status_path.write_text(json.dumps(status, indent=2, sort_keys=True) + "\n")
    return status


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    status = capture(args.build_dir, args.output_dir)
    print(json.dumps(status, sort_keys=True))
    return 0 if status["status"] == "complete" else 1


if __name__ == "__main__":
    sys.exit(main())
