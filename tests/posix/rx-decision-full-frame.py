#!/usr/bin/env python3
"""Verify complete chained-mbuf RX-decision snapshots with an independent hash."""
import argparse
import hashlib
import os
import struct
import subprocess


FRAME_BYTES = 9000 + 14 + 4
RECORD = struct.Struct("<IIHHI")


def expected_frame(packet_index):
    return bytes(((offset * 73 + (offset >> 4) * 19 + packet_index * 29 + 11) & 0xff)
        for offset in range(FRAME_BYTES))


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker", required=True)
    args = parser.parse_args()
    cpu = min(os.sched_getaffinity(0))
    command = [args.worker, "--rx-decision-full-frame-test",
        f"--lcores=0@{cpu}", "--no-huge", "--no-pci", "--no-shconf",
        "--no-telemetry", "--iova-mode=va", "-m", "64"]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=30, check=False)
    require(result.returncode == 0,
        f"real chained mbuf lease control failed rc={result.returncode}: "
        f"stdout={result.stdout[-512:]!r} stderr={result.stderr[-2048:]!r}")
    cursor = 0
    for packet_index, expected_action in enumerate((1, 2)):
        require(cursor + RECORD.size <= len(result.stdout), "short frame report record")
        frame_bytes, first_segment_bytes, segment_count, action, reserved = RECORD.unpack_from(
            result.stdout, cursor)
        cursor += RECORD.size
        require(frame_bytes == FRAME_BYTES and 0 < first_segment_bytes < frame_bytes and
            segment_count >= 2 and action == expected_action and reserved == 0,
            f"packet {packet_index}: invalid retained mbuf metadata")
        end = cursor + frame_bytes
        require(end <= len(result.stdout), "truncated full-frame report")
        captured = result.stdout[cursor:end]
        cursor = end
        expected = expected_frame(packet_index)
        require(captured == expected, f"packet {packet_index}: full frame differs")
        require(hashlib.sha256(captured).digest() == hashlib.sha256(expected).digest(),
            f"packet {packet_index}: full-frame SHA256 mismatch")
    require(cursor == len(result.stdout), "unexpected bytes after frame reports")
    print("RX_DECISION_FULL_FRAME_PASS packets=2 bytes=9018 segments=multi actions=LOCAL,DROP")
    for packet_index in range(2):
        print(f"packet={packet_index + 1} sha256={hashlib.sha256(expected_frame(packet_index)).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
