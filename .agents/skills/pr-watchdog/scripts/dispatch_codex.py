#!/usr/bin/env python3
"""Queue one poller event into a persistent Codex coordinator session."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

from poll_prs import validate_state_path


INLINE_EVENT_LIMIT = 64 * 1024


def persist_event(payload: bytes) -> Path:
    """Atomically persist an oversized event for asynchronous coordinator reads."""
    digest = hashlib.sha256(payload).hexdigest()
    event_dir = Path.home() / ".local/state/pr-watchdog/events"
    path = validate_state_path(event_dir / f"event-{digest}.json")
    event_dir = path.parent
    event_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory_mode = event_dir.lstat().st_mode
    if not stat.S_ISDIR(directory_mode) or directory_mode & 0o077:
        raise RuntimeError(f"event directory must be a private directory: {event_dir}")
    if path.exists():
        if path.stat().st_mode & 0o077:
            raise RuntimeError(f"event file must have private permissions: {path}")
        if path.read_bytes() != payload:
            raise RuntimeError(f"event reference content mismatch: {path}")
        return path

    descriptor, temporary_name = tempfile.mkstemp(prefix=".event-", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    return path


def event_message(event: dict) -> str:
    serialized = json.dumps(event, ensure_ascii=False, sort_keys=True)
    if len(serialized.encode("utf-8")) <= INLINE_EVENT_LIMIT:
        return (
            "PR watchdog event received. Reconcile all watched PRs, then schedule the required "
            "Sol/Luna work and continue the review/CI/rebase loop. Do not merge.\n"
            f"Event:\n{serialized}"
        )
    reference = persist_event(serialized.encode("utf-8"))
    return (
        "PR watchdog event received. Reconcile all watched PRs, then schedule the required "
        "Sol/Luna work and continue the review/CI/rebase loop. Do not merge.\n"
        f"The complete event is stored at {json.dumps(str(reference))}. Read and parse that JSON file before "
        "reconciling; the file is retained for asynchronous processing."
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--thread", required=True, help="persistent Codex session UUID or exact name")
    args = parser.parse_args()
    payload = sys.stdin.read().strip()
    if not payload:
        parser.error("expected one JSON event on stdin")
    try:
        event = json.loads(payload)
    except json.JSONDecodeError as error:
        parser.error(f"invalid JSON event: {error}")
    message = event_message(event)
    result = subprocess.run(
        ["codex", "queue", "--thread", args.thread, "--message", message],
        check=False,
    )
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
