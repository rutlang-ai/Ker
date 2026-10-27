#!/usr/bin/env python3
"""Fetch Ker's pinned Linux submodule, retrying only transient HTTP 429 errors."""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path
from typing import Callable


ROOT = Path(__file__).resolve().parents[2]
LINUX_PATH = "third_party/linux"
MAX_ATTEMPTS = 4
INITIAL_BACKOFF_SECONDS = 15


def _run(command: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, check=False)


def _expected_gitlink(root: Path, run: Callable = _run) -> str:
    result = run(["git", "ls-tree", "HEAD", LINUX_PATH], cwd=root)
    if result.returncode != 0:
        raise subprocess.CalledProcessError(result.returncode, result.args, output=result.stdout)
    fields = result.stdout.strip().split()
    if len(fields) < 3 or fields[0] != "160000" or fields[-1] != LINUX_PATH:
        raise RuntimeError(f"{LINUX_PATH} is not a pinned gitlink in HEAD")
    return fields[2]


def _is_http_429(output: str) -> bool:
    lowered = output.lower()
    return "http 429" in lowered or "returned error: 429" in lowered


def checkout_pinned_linux(
    root: Path = ROOT,
    *,
    max_attempts: int = MAX_ATTEMPTS,
    initial_backoff_seconds: float = INITIAL_BACKOFF_SECONDS,
    run: Callable = _run,
    sleep: Callable[[float], None] = time.sleep,
    output: Callable[[str], None] = print,
) -> str:
    """Initialize the exact recorded gitlink, backing off only on HTTP 429."""
    if max_attempts < 1:
        raise ValueError("max_attempts must be positive")
    expected = _expected_gitlink(root, run)
    command = ["git", "submodule", "update", "--init", "--depth", "1", LINUX_PATH]
    delay = initial_backoff_seconds

    for attempt in range(1, max_attempts + 1):
        result = run(command, cwd=root)
        if result.stdout:
            output(result.stdout.rstrip())
        if result.returncode == 0:
            actual = run(["git", "-C", LINUX_PATH, "rev-parse", "HEAD"], cwd=root)
            if actual.returncode != 0:
                raise subprocess.CalledProcessError(actual.returncode, actual.args, output=actual.stdout)
            actual_sha = actual.stdout.strip()
            if actual_sha != expected:
                raise RuntimeError(
                    f"{LINUX_PATH} checkout {actual_sha} does not match pinned gitlink {expected}"
                )
            output(f"{LINUX_PATH} gitlink: {actual_sha}")
            return actual_sha

        if not _is_http_429(result.stdout or "") or attempt == max_attempts:
            raise subprocess.CalledProcessError(result.returncode, command, output=result.stdout)
        output(
            f"Pinned Linux checkout hit HTTP 429 (attempt {attempt}/{max_attempts}); "
            f"retrying in {delay:g}s."
        )
        sleep(delay)
        delay *= 2

    raise RuntimeError("unreachable pinned Linux checkout retry state")


if __name__ == "__main__":
    try:
        checkout_pinned_linux()
    except (OSError, RuntimeError, subprocess.CalledProcessError, ValueError) as error:
        print(f"pinned Linux checkout failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
