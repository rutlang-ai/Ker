#!/usr/bin/env python3
"""Prove prepared shutdown survives EBUSY and retains a real TCP drain timeout."""
import argparse
import json
import os
from pathlib import Path
import select
import shlex
import socket
import subprocess
import sys
import tempfile
import time


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def wait_line(process, prefix, timeout=30):
    deadline = time.monotonic() + timeout
    pending = getattr(process, "_retry_pending", bytearray())
    while time.monotonic() < deadline:
        newline = pending.find(b"\n")
        if newline >= 0:
            line = bytes(pending[:newline + 1]).decode("utf-8", "replace").rstrip("\n")
            del pending[:newline + 1]
            if line.startswith(prefix):
                process._retry_pending = pending
                return line
            continue
        ready, _, _ = select.select([process.stdout], [], [], max(0, deadline - time.monotonic()))
        if not ready:
            break
        chunk = os.read(process.stdout.fileno(), 4096)
        if not chunk:
            break
        pending.extend(chunk)
    process._retry_pending = pending
    output, errors = process.communicate(timeout=2) if process.poll() is not None else (b"", b"")
    raise RuntimeError(f"timed out waiting for {prefix!r}; rc={process.poll()}; "
        f"pending={bytes(pending)!r}; stdout={output!r}; stderr={errors!r}")


def inside(args):
    for command in (
        ["ip", "link", "set", "lo", "up"],
        ["ip", "link", "add", "kerhost", "type", "veth", "peer", "name", "kerlink"],
        ["ip", "addr", "add", "198.18.0.1/24", "dev", "kerhost"],
        ["ip", "link", "set", "kerhost", "up"],
        ["ip", "link", "set", "kerlink", "up"],
    ):
        subprocess.run(command, check=True)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("198.18.0.1", 9090))
    listener.listen(1)
    listener.settimeout(30)
    peer = None
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix="ker-rx-shutdown-retry-",
                dir=os.environ.get("TMPDIR", "/dev/shm")) as temp:
            root = Path(temp)
            stats_path = root / "stats.json"
            eal = (f"--lcores=0@{min(os.sched_getaffinity(0))} --no-huge --no-pci "
                f"--no-shconf --no-telemetry --iova-mode=va -m 64 "
                f"-d {shlex.quote(str(args.dpdk_plugin_dir / 'librte_net_tap.so'))} "
                "--vdev=net_tap0,iface=kerpeer,remote=kerlink")
            command = [sys.executable, str(args.launcher), "--library", str(args.library),
                "--io-worker", str(args.worker), "--address", "198.18.0.2/24",
                "--port", "net_tap0", "--eal", eal, "--stats", str(stats_path),
                "--rx-decision", "--", str(args.app)]
            if args.mode != "retry":
                command.append(args.mode)
            env = os.environ | {"PYTHONDONTWRITEBYTECODE": "1",
                "RUNTIME_DIRECTORY": str(root), "TMPDIR": str(root),
                "KER_SHUTDOWN_TIMEOUT_MS": "1"}
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False,
                env=env, bufsize=0, start_new_session=True)
            ready = wait_line(process, "C31_RETRY_APP_READY", 30)
            require(ready == "C31_RETRY_APP_READY", f"unexpected app ready line: {ready!r}")
            peer, _ = listener.accept()
            peer.settimeout(10 if args.mode != "retry" else 1)
            proof = wait_line(process,
                "C31_BLOCKING_CLOSE_WAIT" if args.mode != "retry" else "C31_RETRY_PROOF",
                10 if args.mode != "retry" else 45)
            if args.mode == "retry":
                require("pending=1" in proof and "error=110" in proof,
                    f"retry did not preserve the actual pending send queue timeout: {proof!r}")
            else:
                require("pending=1" in proof and "error=16" in proof,
                    f"cleanup helper did not hit its bounded wait with a blocked {args.mode}: {proof!r}")
            require("wrong_context_rejected=1" in proof,
                f"cleanup-only retry accepted a different context: {proof!r}")
            fields = dict(item.split("=", 1) for item in proof.split()[1:] if "=" in item)
            require(fields.get("loop_calls") == fields.get("first_calls"),
                f"same-context cleanup retry re-entered the business callback: {proof!r}")
            require(int(fields.get("notsent", "0")) > 0 and int(fields.get("bytes", "0")) > 0,
                f"fixture did not prove original Linux had unsent TCP bytes: {proof!r}")
            if args.mode != "retry":
                received = 0
                while True:
                    chunk = peer.recv(65536)
                    if not chunk:
                        break
                    received += len(chunk)
                expected = int(fields["bytes"]) + (1024 * 1024 if args.mode == "stdio" else 0)
                require(received == expected,
                    f"host did not receive exact stream bytes through cleanup: {received} != {expected}")
                done = wait_line(process, "C31_BLOCKING_CLOSE_DONE", 15)
                done_fields = dict(item.split("=", 1) for item in done.split() if "=" in item)
                require(done_fields.get("error") == "0" and
                    int(done_fields.get("decisions", "0")) >
                    int(done_fields.get("decisions_at_stop", "0")),
                    f"owner thread did not pump RX decisions while cleanup blocked: {done!r}")
            output, errors = process.communicate(timeout=30)
            require((process.returncode != 0 if args.mode == "retry" else process.returncode == 0),
                f"unexpected ker-run status for {args.mode}: {process.returncode}")
            require(stats_path.is_file(), "ker-run did not write worker settlement stats")
            stats = json.loads(stats_path.read_text())
            require(stats.get("rx_decision_enabled") is True and
                stats.get("rx_decision_settled") is True and
                stats.get("outstanding") == 0 and
                stats.get("run_shutdown") is True and
                stats.get("rx_decision_leases", 0) > 0 and
                stats.get("rx_decision_local") == stats.get("rx_decision_forwarded"),
                f"worker did not settle after cleanup retry: {stats!r}; "
                f"stdout={output!r}; stderr={errors!r}")
            if args.mode == "retry":
                require(b"KER_NATIVE_INCOMPLETE" in errors or
                    b"invalid native run shutdown marker sequence" in errors,
                    f"expected bounded native drain failure was not recorded: {errors!r}")
            print(f"C31_{args.mode.upper()}_TAP_OK proof={proof} stats={stats!r}")
    finally:
        if peer:
            peer.close()
        listener.close()
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        subprocess.run(["ip", "link", "delete", "kerpeer"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--launcher", type=Path, required=True)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--worker", type=Path, required=True)
    parser.add_argument("--app", type=Path, required=True)
    parser.add_argument("--dpdk-plugin-dir", type=Path, required=True)
    parser.add_argument("--mode", choices=("retry", "linger", "stdio"), default="retry")
    parser.add_argument("--inside", action="store_true")
    args = parser.parse_args()
    if args.inside:
        return inside(args)
    command = ["unshare", "-Urn", sys.executable, str(Path(__file__).resolve()), "--inside"]
    for name in ("launcher", "library", "worker", "app", "dpdk_plugin_dir"):
        command += ["--" + name.replace("_", "-"), str(getattr(args, name).resolve())]
    command += ["--mode", args.mode]
    return subprocess.run(command).returncode


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"RX decision shutdown retry TAP failed: {error}", file=sys.stderr)
        raise SystemExit(1)
