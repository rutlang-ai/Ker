#!/usr/bin/env python3
import argparse
import os
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--test", required=True)
    args = parser.parse_args()
    try:
        with open("/proc/meminfo", encoding="ascii") as info:
            free_pages = next(int(line.split()[1]) for line in info if line.startswith("HugePages_Free:"))
    except (OSError, StopIteration, ValueError):
        free_pages = 0
    if free_pages < 64:
        print("SKIP: NR19 requires 64 free 2 MiB hugepages for real EAL secondaries")
        return 77
    prefix = f"ker-nr19-{os.getpid()}-{time.monotonic_ns() & 0xfffffff:x}"
    command = [args.test, "--no-pci", f"--file-prefix={prefix}",
               "--proc-type=primary", "--", "primary"]
    completed = subprocess.run(command, check=False)
    return completed.returncode


if __name__ == "__main__":
    sys.exit(main())
