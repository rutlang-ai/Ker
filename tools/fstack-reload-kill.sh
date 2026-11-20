#!/usr/bin/env bash
# Adapter for the F-Stack reload supervisor's identity-checked signal helper.
exec python3 -I -B - "$@" <<'PY'
import argparse
import math
import os
import select
import signal
import sys

SIGNALS = ("HUP", "USR1", "USR2", "WINCH", "QUIT", "TERM", "INT",
           "KILL", "STOP", "CONT")


def identity(proc):
    stat_fd = os.open("stat", os.O_RDONLY | os.O_CLOEXEC, dir_fd=proc)
    with os.fdopen(stat_fd, "rb") as stat_file:
        fields = stat_file.read().rsplit(b")", 1)[1].split()
    if fields[0] == b"Z":
        raise ProcessLookupError("target exited")
    executable = os.readlink("exe", dir_fd=proc)
    if executable.endswith(" (deleted)"):
        raise ValueError("target executable was deleted")
    image = os.stat("exe", dir_fd=proc)
    return int(fields[19]), executable, image.st_dev, image.st_ino


def send(args):
    # Open the pidfd before inspecting procfs. If the PID is recycled during
    # verification, the pidfd still refers only to the original process.
    pidfd = os.pidfd_open(args.pid)
    try:
        proc = os.open(f"/proc/{args.pid}", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            expected = args.start_time, args.exe, args.device, args.inode
            if identity(proc) != expected or identity(proc) != expected:
                raise ValueError("target identity mismatch")
            signal.pidfd_send_signal(pidfd, signal.Signals["SIG" + args.signal])
        finally:
            os.close(proc)
        if args.wait == 0:
            return 0
        poller = select.poll()
        poller.register(pidfd, select.POLLIN)
        return 0 if poller.poll(math.ceil(args.wait * 1000)) else 3
    finally:
        os.close(pidfd)


def main():
    if sys.argv[1:] == ["--capabilities"]:
        fd = os.pidfd_open(os.getpid())
        try:
            signal.pidfd_send_signal(fd, 0)
        finally:
            os.close(fd)
        print("pidfd-identity-v1")
        return 0

    parser = argparse.ArgumentParser(prog="kill_process.sh", allow_abbrev=False)
    parser.add_argument("--signal", required=True, choices=SIGNALS)
    parser.add_argument("--pid", required=True, type=int)
    parser.add_argument("--start-time", required=True, type=int)
    parser.add_argument("--exe", required=True)
    parser.add_argument("--device", required=True, type=int)
    parser.add_argument("--inode", required=True, type=int)
    parser.add_argument("--wait", default=0, type=float)
    args = parser.parse_args()
    if (args.pid <= 1 or args.pid == os.getpid() or args.start_time < 0
            or not os.path.isabs(args.exe) or args.device < 0 or args.inode <= 0
            or not 0 <= args.wait <= 14400):
        parser.error("invalid signal target, identity or wait")
    return send(args)


try:
    sys.exit(main())
except (AttributeError, IndexError, OSError, OverflowError, ValueError) as error:
    print(f"kill_process.sh: {error}", file=sys.stderr)
    sys.exit(4)
PY
