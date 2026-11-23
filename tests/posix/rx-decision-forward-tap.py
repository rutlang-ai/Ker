#!/usr/bin/env python3
"""Exercise the private RX decision lease over the real TAP/original-Linux path."""
import argparse
import errno
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
import traceback


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def wait_line(process, prefix, timeout=10):
    deadline = time.monotonic() + timeout
    pending = getattr(process, "_rx_pending", bytearray())
    while time.monotonic() < deadline:
        newline = pending.find(b"\n")
        if newline >= 0:
            line = bytes(pending[:newline + 1]).decode("utf-8", "replace").rstrip("\n")
            del pending[:newline + 1]
            process._rx_pending = pending
            if line.startswith(prefix):
                return line
            continue
        ready, _, _ = select.select([process.stdout], [], [], max(0, deadline - time.monotonic()))
        if not ready:
            break
        chunk = os.read(process.stdout.fileno(), 4096)
        if not chunk:
            if process.poll() is None:
                process.terminate()
                try:
                    output, errors = process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill(); output, errors = process.communicate()
            else:
                output, errors = process.communicate()
            raise RuntimeError(f"{prefix!r} stdout closed before marker; rc={process.returncode}; "
                f"pending={bytes(pending)!r}; stdout={output!r}; stderr={errors!r}")
        pending.extend(chunk)
    process._rx_pending = pending
    output, errors = process.communicate(timeout=2) if process.poll() is not None else (b"", b"")
    raise RuntimeError(f"timed out waiting for {prefix!r}; rc={process.poll()}; "
        f"pending={bytes(pending)!r}; stdout={output!r}; stderr={errors!r}")


def read_exact(connection, size):
    result = bytearray()
    while len(result) < size:
        data = connection.recv(size - len(result))
        if not data:
            break
        result.extend(data)
    return bytes(result)


def wait_fifo_byte(fd, path, expected, timeout=10):
    deadline = time.monotonic() + timeout
    data = bytearray()
    while time.monotonic() < deadline and len(data) < 1:
        ready, _, _ = select.select([fd], [], [], max(0, deadline - time.monotonic()))
        if ready:
            chunk = os.read(fd, 1 - len(data))
            if chunk:
                data.extend(chunk)
    require(bytes(data) == expected, f"{path.name} marker mismatch/timeout: {bytes(data)!r}")


def release_fifo(path):
    fd = os.open(path, os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        require(os.write(fd, b"\xa5") == 1, "shutdown release marker short write")
    finally:
        os.close(fd)


def ipv4_tcp(frame):
    if len(frame) < 14 or frame[12:14] != b"\x08\x00":
        return None
    ip = frame[14:]
    if len(ip) < 20 or ip[0] >> 4 != 4:
        return None
    ihl = (ip[0] & 0x0f) * 4
    if ihl < 20 or len(ip) < ihl + 20 or ip[9] != 6:
        return None
    tcp = ip[ihl:]
    offset = (tcp[12] >> 4) * 4
    if offset < 20 or len(tcp) < offset:
        return None
    return {
        "src": socket.inet_ntoa(ip[12:16]),
        "dst": socket.inet_ntoa(ip[16:20]),
        "sport": int.from_bytes(tcp[0:2], "big"),
        "dport": int.from_bytes(tcp[2:4], "big"),
        "flags": tcp[13],
    }


def collect_tcp(capture, source_port, duration):
    syns, responses = [], []
    deadline = time.monotonic() + duration
    capture.setblocking(False)
    while time.monotonic() < deadline:
        ready, _, _ = select.select([capture], [], [], min(.01, deadline - time.monotonic()))
        if not ready:
            continue
        try:
            frame = capture.recv(65535)
        except BlockingIOError:
            continue
        packet = ipv4_tcp(frame)
        if packet and packet["src"] == "198.18.0.2" and packet["dst"] == "198.18.0.1" and \
                packet["sport"] == 8080 and packet["dport"] == source_port:
            responses.append(packet)
        elif packet and packet["src"] == "198.18.0.1" and packet["dst"] == "198.18.0.2" and \
                packet["sport"] == source_port and packet["dport"] == 8080 and \
                packet["flags"] & 0x12 == 0x02:
            syns.append(packet)
    return syns, responses


def run_case(args, root, mode, decision):
    case_root = root / mode
    case_root.mkdir()
    stats_path = case_root / "stats.json"
    barrier_ready_path = case_root / "shutdown-ready"
    barrier_release_path = case_root / "shutdown-release"
    data_marker = case_root / "data-queued"
    if mode != "drop":
        os.mkfifo(barrier_ready_path, 0o600)
        os.mkfifo(barrier_release_path, 0o600)
        # Keep a reader present before the app emits PREPARED; otherwise a
        # FIFO can discard the byte when its last writer closes before we open.
        barrier_ready_fd = os.open(barrier_ready_path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    else:
        barrier_ready_fd = -1
    eal = (f"--lcores=0@{min(os.sched_getaffinity(0))} --no-huge --no-pci "
        f"--no-shconf --no-telemetry --iova-mode=va -m 64 "
        f"-d {shlex.quote(str(args.dpdk_plugin_dir / 'librte_net_tap.so'))} "
        "--vdev=net_tap0,iface=kerpeer,remote=kerlink")
    worker = args.test_worker if mode in ("eagain", "queued-drop") else args.worker
    command = [sys.executable, str(args.launcher), "--library", str(args.library),
        "--io-worker", str(worker), "--address", "198.18.0.2/24",
        "--port", "net_tap0", "--eal", eal, "--stats", str(stats_path)]
    if decision:
        command.append("--rx-decision")
    command += ["--", str(args.app), mode]
    env = os.environ | {"PYTHONDONTWRITEBYTECODE": "1", "RUNTIME_DIRECTORY": str(case_root),
        "TMPDIR": str(case_root)}
    if mode != "drop":
        env["KER_RX_DECISION_TEST_READY_PATH"] = str(barrier_ready_path)
        env["KER_RX_DECISION_TEST_RELEASE_PATH"] = str(barrier_release_path)
    if mode == "eagain":
        env["KER_RX_DECISION_TEST_EAGAIN_ONCE"] = "1"
    if mode == "queued-drop":
        env["KER_RX_DECISION_TEST_DATA_MARKER_PATH"] = str(data_marker)
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=False, env=env, bufsize=0, start_new_session=True)
    peers = []
    capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    capture.bind(("kerhost", 0))
    try:
        ready = wait_line(process, f"RX_DECISION_APP_READY mode={mode}", 30)
        require(f"mode={mode} " in ready, f"unexpected app readiness: {ready!r}")
        if mode in ("local", "eagain", "immediate", "queued-drop", "legacy"):
            mac = ready.rsplit("mac=", 1)[-1]
            require(len(mac) == 17 and mac.count(":") == 5, f"invalid worker MAC in ready marker: {ready!r}")
            subprocess.run(["ip", "neigh", "replace", "198.18.0.2", "lladdr", mac,
                "dev", "kerhost", "nud", "permanent"], check=True)
        if mode in ("local", "eagain", "immediate", "legacy"):
            peer = socket.create_connection(("198.18.0.2", 8080), timeout=5)
            peers.append(peer)
            peer.settimeout(5)
            payload = ("C31-" + mode + "-original-linux-tcp").encode()
            peer.sendall(payload)
            peer.shutdown(socket.SHUT_WR)
            received = read_exact(peer, len(payload))
            require(received == payload, f"{mode} echo mismatch: {received!r}")
            require(peer.recv(1) == b"", f"{mode} TCP peer did not close after echo")
            wait_fifo_byte(barrier_ready_fd, barrier_ready_path, b"\x5a")
            release_fifo(barrier_release_path)
        elif mode == "queued-drop":
            wait_line(process, "RX_DECISION_APP_STOPPING mode=queued-drop", 10)
            wait_fifo_byte(barrier_ready_fd, barrier_ready_path, b"\x5a")
            peer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            peers.append(peer)
            peer.bind(("198.18.0.1", 0))
            source_port = peer.getsockname()[1]
            peer.setblocking(False)
            connect_result = peer.connect_ex(("198.18.0.2", 8080))
            require(connect_result in (0, errno.EINPROGRESS, errno.EALREADY, errno.EWOULDBLOCK),
                f"queued-DATA nonblocking connect failed: errno={connect_result}")
            marker_deadline = time.monotonic() + 3
            while time.monotonic() < marker_deadline and not data_marker.exists():
                time.sleep(.001)
            require(data_marker.is_file(), "worker did not queue a real DATA lease while shutdown was paused")
            packet_id = int(data_marker.read_text().strip())
            require(packet_id > 0, f"invalid queued DATA packet ID: {packet_id}")
            release_fifo(barrier_release_path)
            _, responses = collect_tcp(capture, source_port, .5)
            require(not responses, f"queued DATA cleanup DROP allowed a TCP response: {responses!r}")
        else:
            peer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            peers.append(peer)
            peer.settimeout(.25)
            peer.bind(("198.18.0.1", 0))
            source_port = peer.getsockname()[1]
            try:
                peer.connect(("198.18.0.2", 8080))
            except (TimeoutError, OSError):
                pass
            syns, responses = collect_tcp(capture, source_port, .8)
            require(syns, "DROP test produced no real host TCP SYN (neighbor resolution may have hidden the flow)")
            require(not responses, f"DROP decision injected a TCP response: {responses!r}")
        done = wait_line(process, f"RX_DECISION_APP_DONE mode={mode}", 20)
        if "completed=1" not in done or "error=0" not in done:
            try:
                output, errors = process.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                process.terminate()
                output, errors = process.communicate(timeout=5)
            raise RuntimeError(f"application did not complete cleanly: {done!r}; "
                f"rc={process.poll()}; stdout={output!r}; stderr={errors!r}; "
                f"stats={stats_path.read_text() if stats_path.exists() else 'missing'}")
        if mode == "immediate":
            fields = dict(item.split("=", 1) for item in done.split() if "=" in item)
            require(int(fields.get("callbacks", "0")) > int(fields.get("callbacks_at_stop", "0")),
                f"native shutdown made no RX decision progress after immediate stop: {done!r}")
        output, errors = process.communicate(timeout=20)
        require(process.returncode == 0,
            f"ker-run {mode} failed: rc={process.returncode}; stdout={output!r}; stderr={errors!r}")
        require(stats_path.is_file(), f"ker-run omitted {mode} worker stats")
        stats = json.loads(stats_path.read_text())
        if decision:
            require(stats.get("rx_decision_enabled") is True and
                stats.get("rx_decision_settled") is True and stats.get("outstanding") == 0,
                f"{mode} worker did not settle cleanly: {stats!r}")
            require(stats.get("rx_decision_leases", 0) > 0,
                f"{mode} exercised no decision leases: {stats!r}")
            if mode in ("local", "immediate"):
                require(stats.get("rx_decision_local", 0) ==
                    stats.get("rx_decision_forwarded", 0) and
                    stats.get("rx_decision_local_cancelled", 0) == 0 and
                    stats.get("rx_decision_drops", 0) == 0,
                    f"LOCAL leases were lost, canceled, or duplicated: {stats!r}")
            elif mode == "eagain":
                require(stats.get("rx_decision_test_eagain_injected") == 1 and
                    stats.get("rx_decision_test_eagain_same_id") == 1,
                    f"EAGAIN retry did not retain the exact authorized lease: {stats!r}")
                require(stats.get("rx_decision_local") == stats.get("rx_decision_forwarded") and
                    stats.get("rx_decision_drops", 0) == 0 and
                    stats.get("rx_decision_local_cancelled", 0) == 0,
                    f"EAGAIN retry lost or duplicated the original packet: {stats!r}")
            elif mode == "queued-drop":
                require(stats.get("rx_decision_test_data_marked") is True and
                    stats.get("rx_decision_drops", 0) > 0 and
                    stats.get("rx_decision_local", 0) == 0 and
                    stats.get("rx_decision_forwarded", 0) == 0 and
                    stats.get("rx_decision_local_cancelled", 0) == 0,
                    f"shutdown did not settle queued DATA by DROP: {stats!r}")
            else:
                require(stats.get("rx_decision_drops", 0) > 0 and
                    stats.get("rx_decision_forwarded", 0) == 0,
                    f"DROP did not suppress local injection: {stats!r}")
        else:
            require(stats.get("rx_decision_enabled") is False,
                f"default path unexpectedly enabled decision leases: {stats!r}")
        return stats
    except Exception as error:
        if process.poll() is None:
            process.terminate()
            try:
                output, errors = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                output, errors = process.communicate()
        else:
            output, errors = process.communicate()
        stats_text = stats_path.read_text() if stats_path.exists() else "missing"
        raise RuntimeError(f"{mode}: {error}; rc={process.returncode}; app_stdout={output!r}; "
            f"app_stderr={errors!r}; worker_stats={stats_text}") from error
    finally:
        for peer in peers:
            peer.close()
        capture.close()
        if barrier_ready_fd >= 0:
            os.close(barrier_ready_fd)
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait()
        subprocess.run(["ip", "link", "delete", "kerpeer"], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, check=False)


def inside(args):
    for command in (
        ["ip", "link", "set", "lo", "up"],
        ["ip", "link", "add", "kerhost", "type", "veth", "peer", "name", "kerlink"],
        ["ip", "addr", "add", "198.18.0.1/24", "dev", "kerhost"],
        ["ip", "link", "set", "kerhost", "up"],
        ["ip", "link", "set", "kerlink", "up"],
    ):
        subprocess.run(command, check=True)
    with tempfile.TemporaryDirectory(prefix="ker-rx-decision-", dir=os.environ.get("TMPDIR", "/dev/shm")) as temp:
        root = Path(temp)
        local = run_case(args, root, "local", True)
        eagain = run_case(args, root, "eagain", True)
        run_case(args, root, "immediate", True)
        run_case(args, root, "queued-drop", True)
        dropped = run_case(args, root, "drop", True)
        subprocess.run(["ip", "neigh", "replace", "198.18.0.2", "lladdr",
            dropped["io"]["mac"], "dev", "kerhost", "nud", "permanent"], check=True)
        run_case(args, root, "legacy", False)
    print("RX_DECISION_TAP_OK local=echo eagain=same-lease immediate=drain-ack queued=drop drop=no-response legacy=echo")
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--launcher", type=Path, required=True)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--worker", type=Path, required=True)
    parser.add_argument("--test-worker", type=Path, required=True)
    parser.add_argument("--app", type=Path, required=True)
    parser.add_argument("--dpdk-plugin-dir", type=Path, required=True)
    parser.add_argument("--inside", action="store_true")
    args = parser.parse_args()
    if args.inside:
        return inside(args)
    command = ["unshare", "-Urn", sys.executable, str(Path(__file__).resolve()), "--inside"]
    for name in ("launcher", "library", "worker", "test_worker", "app", "dpdk_plugin_dir"):
        command += ["--" + name.replace("_", "-"), str(getattr(args, name).resolve())]
    return subprocess.run(command).returncode


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"RX decision TAP fixture failed: {error}\n{traceback.format_exc()}", file=sys.stderr)
        raise SystemExit(1)
