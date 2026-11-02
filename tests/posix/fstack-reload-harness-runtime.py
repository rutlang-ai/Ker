#!/usr/bin/env python3
"""Run the unchanged pinned F-Stack reload harness tests in a bwrap sandbox."""

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


PINNED = {
    "tests/upstream/fstack/tests/unit/test_reload_harness.py":
        "8b847ac33ca8c5d6ddfc81c3e35f2cca1a275408a5753eae064b005b1fe9d791",
    "tests/upstream/fstack/tests/unit/Makefile":
        "9e03b444894cc79f1bec2d8f3e4b2de6ad9d4c01a0b79c807dac2fefa43ba17f",
    "tests/upstream/fstack/tests/integration/common/reload_checks.py":
        "686a57c12981af7be78a24f2f8e94e0070e456ee5042fe0f528b200bfc37bb7d",
    "tests/upstream/fstack/tests/integration/common/reload_remote.py":
        "b679a74477f835f25ab7e0ba144bceeb7569611433ecefc15e344d7046c58d07",
    "tests/upstream/fstack/tests/integration/common/reload_supervisor.py":
        "901e5ab1acff7110621a205786bf349cb8085a9f8e6c8549d9901e2449fd5d74",
    "tests/upstream/fstack/tests/integration/common/reload_runtime.sh":
        "af7961ecd6bf9bf3d9e9a924c5cec94ca4ce1ae0d07ee2f40e4712d11d2e7841",
    "tests/upstream/fstack/tests/integration/test_graceful_reload.sh":
        "7efd3e0d10e584daa57377915da0ba2a9d1f67bebbcd2f512298230d71f35203",
    "tests/upstream/fstack/tests/unit/reload_process_fixture.c":
        "7179e41f9bc6f7641f4728b4f4383af9b9eb840b122e15dd064d62274d7c1add",
    "tests/upstream/fstack/tests/integration/common/reload_probes/http_probe.py":
        "7c19eae3b1dd6eeaa914d12e4d42fbb45d03370aad40232c42c42cfe8c756b31",
    "tests/upstream/fstack/tests/integration/common/reload_probes/m4_cps.py":
        "64c3f277457cb0bfff0c2fa458ffd52ec0f40e38c1e021749ba34c25288b105e",
    "tests/upstream/fstack/tests/integration/common/reload_probes/m4_lc.py":
        "b6539d6c81cd9fceff3c657493b52d962cd4260e09e2d8dec38ecfe88ecca8ac",
    "tests/upstream/fstack/tests/integration/common/reload_probes/m4_outage.py":
        "4d57b775a52ceab27b6a64aae6334ad168f6944cf74250054ab8ea6cc2231569",
    "tests/upstream/fstack/tests/integration/common/reload_probes/m4_stream.py":
        "838aaa38d72220d4b8d0f8a2c93bbcc1d45886d96db896e13c1d64a0e4b01958",
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_sources(repo):
    for relative, expected in PINNED.items():
        path = repo / relative
        actual = digest(path)
        if actual != expected:
            raise RuntimeError(f"pinned source hash mismatch: {relative}: {actual}")


def write_tools(workspace, source_dir):
    tools = (("kill_process.py", "kill_process.py"),
             ("kill_process.sh", "kill_process.sh"),
             ("rm_tmp_file.py", "rm_tmp_file.py"),
             ("rm_tmp_file.sh", "rm_tmp_file.sh"),
             ("chmod_modify.py", "chmod_modify.py"),
             ("chmod_modify.sh", "chmod_modify.sh"))
    for source, target in tools:
        output = workspace / target
        output.write_bytes((source_dir / source).read_bytes())
        output.chmod(0o700)


def sandbox_command(repo, workspace, focused, unit_copy=None):
    if not shutil.which("bwrap"):
        raise RuntimeError("bwrap is required; no unsandboxed fallback is allowed")
    command = [
        "bwrap", "--die-with-parent", "--ro-bind", "/", "/",
        "--tmpfs", "/mnt", "--dir", "/mnt/repo", "--ro-bind", str(repo), "/mnt/repo",
    ]
    if not focused:
        if unit_copy is None:
            raise RuntimeError("private unit-tree overlay is required")
        # The upstream Makefile builds its C helper beside the test source. Keep
        # that one directory as a private writable copy; checked-in source and
        # the rest of the repository remain read-only.
        command += ["--ro-bind", str(unit_copy), "/mnt/repo/tests/upstream/fstack/tests/unit"]
    command += [
        "--tmpfs", "/data", "--dir", "/data/workspace",
        "--bind", str(workspace), "/data/workspace",
        "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
        "--tmpfs", "/run", "--tmpfs", "/home", "--tmpfs", "/root",
        "--unshare-user", "--uid", "0", "--gid", "0",
        "--unshare-pid", "--unshare-net", "--unshare-ipc", "--unshare-uts",
        "--clearenv", "--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin",
        "--setenv", "HOME", "/tmp", "--setenv", "TMPDIR", "/tmp",
        "--setenv", "PYTHONDONTWRITEBYTECODE", "1",
        "--setenv", "PYTHONNOUSERSITE", "1", "--chdir", "/mnt/repo",
    ]
    if focused:
        command += [sys.executable, "-B", "-S",
                    "/mnt/repo/tests/posix/reload-harness-runtime/test_helpers.py"]
    else:
        command += [sys.executable, "-B",
                    "/mnt/repo/tests/upstream/fstack/tests/unit/test_reload_harness.py", "-v"]
    return command


def execute_sandbox(command, timeout, env=None):
    """Return (status, combined output, timed_out) for one sandbox invocation."""
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, timeout=timeout,
            env=env if env is not None else {"PATH": "/usr/local/bin:/usr/bin:/bin"})
    except subprocess.TimeoutExpired as error:
        output = error.stdout or ""
        if isinstance(output, bytes):
            output = output.decode(errors="replace")
        return 124, output, True
    return result.returncode, result.stdout or "", False


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--focused-only", action="store_true")
    parser.add_argument("--timeout", type=float, default=300.0)
    parser.add_argument("--log", type=Path)
    args = parser.parse_args(argv)
    if not (0 < args.timeout <= 900):
        parser.error("timeout must be between 0 and 900 seconds")
    repo = args.repo.resolve(strict=True)
    try:
        verify_sources(repo)
    except (OSError, RuntimeError) as error:
        print(f"SOURCE_VERIFICATION_FAILED: {error}", file=sys.stderr)
        return 2

    work = Path(tempfile.mkdtemp(prefix="ker-c10-reload-runtime-"))
    try:
        write_tools(work, Path(__file__).resolve().with_name("reload-harness-runtime"))
        unit_copy = None
        if not args.focused_only:
            source_unit = repo / "tests/upstream/fstack/tests/unit"
            unit_copy = work / "upstream-unit"
            unit_copy.mkdir()
            copied = ("Makefile", "test_reload_harness.py", "reload_process_fixture.c")
            for name in copied:
                shutil.copy2(source_unit / name, unit_copy / name)
                relative = "tests/upstream/fstack/tests/unit/" + name
                if digest(unit_copy / name) != PINNED[relative]:
                    raise RuntimeError(f"private source copy failed verification: {name}")
            compiler = shutil.which("cc")
            if not compiler:
                raise RuntimeError("a C compiler is required for the unchanged upstream fixture")
            version = subprocess.run([compiler, "--version"], capture_output=True,
                text=True, check=True).stdout.splitlines()[0]
            build = [compiler, "-std=c11", "-O0", "-g", "-Wall", "-Wextra", "-Werror",
                     "-o", str(unit_copy / "reload_process_fixture"),
                     str(unit_copy / "reload_process_fixture.c")]
            subprocess.run(build, check=True, capture_output=True, text=True)
            print(f"FIXTURE_BUILD source_sha256={digest(unit_copy / 'reload_process_fixture.c')} "
                  f"compiler={compiler!r} version={version!r} command={build!r} "
                  f"binary_sha256={digest(unit_copy / 'reload_process_fixture')}")
        runs = [True] if args.focused_only else [True, False]
        for focused in runs:
            command = sandbox_command(repo, work, focused, unit_copy)
            status, output, timed_out = execute_sandbox(command, args.timeout)
            print(output, end="")
            if args.log:
                with args.log.open("a") as log:
                    log.write(("FOCUSED HELPERS\n" if focused else "PINNED 53-TEST SUITE\n") + output)
            if timed_out:
                print(f"SANDBOX_TIMEOUT: {args.timeout}s", file=sys.stderr)
                return status
            if status:
                print(f"SANDBOX_FAILED: exit={status}", file=sys.stderr)
                return status
            if focused:
                if "Ran 5 tests" not in output or "OK" not in output or "skipped=" in output:
                    print("FOCUSED_TEST_COUNT_OR_VERDICT_MISMATCH", file=sys.stderr)
                    return 1
            else:
                if "Ran 53 tests" not in output or "OK" not in output or "skipped=" in output:
                    print("PINNED_TEST_COUNT_OR_VERDICT_MISMATCH", file=sys.stderr)
                    return 1
                for name in ("Makefile", "test_reload_harness.py", "reload_process_fixture.c"):
                    relative = "tests/upstream/fstack/tests/unit/" + name
                    if digest(unit_copy / name) != PINNED[relative]:
                        print(f"UPSTREAM_TEST_SOURCE_CHANGED_DURING_RUN: {name}", file=sys.stderr)
                        return 1
                print("BOUNDARY: all 53 upstream harness tooling tests passed; no native TCP compatibility claim")
        return 0
    finally:
        shutil.rmtree(work)


if __name__ == "__main__":
    sys.exit(main())
