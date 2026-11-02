#!/usr/bin/env python3
"""Identity-checked pidfd signal helper for the isolated upstream fixture."""

import argparse
import json
import math
import os
from pathlib import Path
import select
import signal
import stat
import sys
import time


EXIT_INVALID = 2
EXIT_TIMEOUT = 3
EXIT_MISMATCH = 4
MAX_WAIT = 300.0

SIGNALS = {
    name: getattr(signal, "SIG" + name)
    for name in ("HUP", "INT", "QUIT", "KILL", "USR1", "USR2", "TERM",
                 "CONT", "STOP", "WINCH", "ALRM", "PIPE")
    if hasattr(signal, "SIG" + name)
}


def parse_args(argv):
    if argv == ["--capabilities"]:
        return None
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--signal", required=True)
    parser.add_argument("--pid", required=True, type=int)
    parser.add_argument("--start-time", required=True, type=int)
    parser.add_argument("--exe", required=True)
    parser.add_argument("--device", required=True, type=int)
    parser.add_argument("--inode", required=True, type=int)
    parser.add_argument("--wait", type=float, default=0.0)
    args = parser.parse_args(argv)
    if (args.signal not in SIGNALS or args.pid <= 0 or args.start_time <= 0 or
            args.device < 0 or args.inode <= 0 or not args.exe.startswith("/") or
            args.exe.endswith(" (deleted)") or not math.isfinite(args.wait) or
            args.wait < 0 or args.wait > MAX_WAIT):
        parser.error("invalid signal or process identity/deadline")
    return args


def read_identity(pid):
    proc = Path("/proc") / str(pid)
    stat = (proc / "stat").read_text()
    fields = stat.rsplit(")", 1)[1].split()
    if fields[0] == "Z":
        raise ProcessLookupError(pid)
    exe = os.readlink(proc / "exe")
    if exe.endswith(" (deleted)"):
        raise ValueError("live process executable was deleted")
    st = (proc / "exe").stat()
    return {"pid": pid, "start_time": int(fields[19]), "exe": exe,
            "device": st.st_dev, "inode": st.st_ino}


def audit(record):
    target = os.environ.get("KILL_IDENTITY_AUDIT")
    if not target:
        return
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(target, flags, 0o600)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid():
            raise OSError("audit target is not an owned regular file")
        os.write(fd, (json.dumps(record, sort_keys=True) + "\n").encode())
    finally:
        os.close(fd)


def run(args):
    try:
        pidfd = os.pidfd_open(args.pid, 0)
    except OSError as error:
        print(f"pidfd_open failed: {error}", file=sys.stderr)
        return EXIT_INVALID
    try:
        expected = {"pid": args.pid, "start_time": args.start_time,
                    "exe": args.exe, "device": args.device, "inode": args.inode}
        try:
            current = read_identity(args.pid)
        except (FileNotFoundError, ProcessLookupError, ValueError, OSError) as error:
            print(f"could not validate target identity: {error}", file=sys.stderr)
            return EXIT_MISMATCH
        if current != expected:
            print("target identity mismatch", file=sys.stderr)
            return EXIT_MISMATCH

        sig = SIGNALS[args.signal]
        try:
            signal.pidfd_send_signal(pidfd, sig, None, 0)
        except OSError as error:
            print(f"pidfd signal failed: {error}", file=sys.stderr)
            audit({"pid": args.pid, "signal": args.signal, "result": "signal_error",
                   "errno": error.errno, "time_ns": time.time_ns()})
            return EXIT_INVALID

        record = {**expected, "signal": args.signal, "result": "sent",
                  "time_ns": time.time_ns()}
        if args.wait:
            poller = select.poll()
            poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
            if not poller.poll(math.ceil(args.wait * 1000)):
                record["result"] = "wait_timeout"
                audit(record)
                return EXIT_TIMEOUT
            record["result"] = "terminated"
        audit(record)
        return 0
    finally:
        os.close(pidfd)


def main(argv=None):
    try:
        args = parse_args(sys.argv[1:] if argv is None else argv)
    except SystemExit as error:
        return int(error.code)
    if args is None:
        print("pidfd-identity-v1")
        return 0
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        print("pidfd operations unavailable", file=sys.stderr)
        return EXIT_INVALID
    try:
        return run(args)
    except (OSError, ValueError) as error:
        print(f"pidfd helper failed: {error}", file=sys.stderr)
        return EXIT_INVALID


if __name__ == "__main__":
    sys.exit(main())
