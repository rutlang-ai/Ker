#!/usr/bin/env python3
"""Fail-closed RX lease tests against the real DPDK TAP worker."""
import argparse
import array
import errno
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import traceback

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import rx_decision_wire as wire


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def process_start_ticks(pid):
    text = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    close = text.rfind(")")
    fields = text[close + 2:].split()
    require(close >= 0 and len(fields) > 19, f"cannot parse process start time for {pid}")
    return int(fields[19], 10)


def credentials(ancillary):
    for level, kind, data in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS:
            return struct.unpack("3i", data[:struct.calcsize("3i")])
    return None


def recv_message(endpoint, timeout):
    readable, _, _ = select.select([endpoint], [], [], timeout)
    if not readable:
        raise TimeoutError("timed out waiting for RX decision datagram")
    data, ancillary, flags, _ = endpoint.recvmsg(
        wire.MAX_MESSAGE, socket.CMSG_SPACE(struct.calcsize("3i")))
    require(not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC), "truncated RX decision datagram")
    return data, credentials(ancillary)


def make_header(kind, nonce, epoch, packet_id=0, control_id=0, deadline=0, body=b""):
    return wire.pack_header(kind, nonce, epoch, packet_id=packet_id,
        control_id=control_id, deadline_ns=deadline, body_bytes=len(body)) + body


def recv_worker_line(process, prefix, timeout=15):
    pending = getattr(process, "_rx_pending", bytearray())
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        newline = pending.find(b"\n")
        if newline >= 0:
            line = bytes(pending[:newline + 1]).decode("utf-8", "replace").rstrip("\n")
            del pending[:newline + 1]
            process._rx_pending = pending
            if line.startswith(prefix):
                return line
            continue
        ready, _, _ = select.select([process.stdout], [], [], deadline - time.monotonic())
        if not ready:
            break
        chunk = os.read(process.stdout.fileno(), 4096)
        if not chunk:
            break
        pending.extend(chunk)
    process._rx_pending = pending
    raise RuntimeError(f"worker did not emit {prefix}: rc={process.poll()}, pending={bytes(pending)!r}")


def parse_ipv4_tcp(frame):
    if len(frame) < 54 or frame[12:14] != b"\x08\x00":
        return None
    ip = frame[14:]
    if ip[0] >> 4 != 4 or ip[9] != 6:
        return None
    ihl = (ip[0] & 15) * 4
    if ihl < 20 or len(ip) < ihl + 20:
        return None
    tcp = ip[ihl:]
    return (socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20]),
        int.from_bytes(tcp[:2], "big"), int.from_bytes(tcp[2:4], "big"), tcp[13])


def wait_for_syn(capture, source_port, timeout=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ready, _, _ = select.select([capture], [], [], min(.05, deadline - time.monotonic()))
        if not ready:
            continue
        frame = capture.recv(65535)
        packet = parse_ipv4_tcp(frame)
        if packet and packet[0] == "198.18.0.1" and packet[1] == "198.18.0.2" and \
                packet[2] == source_port and packet[4] & 0x02 and not packet[4] & 0x10:
            return
    raise RuntimeError(f"host did not emit the real TCP SYN for source port {source_port}")


def open_syn(capture):
    peer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    peer.setblocking(False)
    peer.bind(("198.18.0.1", 0))
    source_port = peer.getsockname()[1]
    result = peer.connect_ex(("198.18.0.2", 8080))
    require(result in (0, errno.EINPROGRESS, errno.EALREADY, errno.EWOULDBLOCK),
        f"host TCP connect failed before SYN: errno={result}")
    wait_for_syn(capture, source_port)
    return peer, source_port


def consumer_process(fd, report, mode, worker_pid, worker_uid, worker_gid,
        worker_start, nonce, epoch):
    endpoint = socket.socket(fileno=fd)
    try:
        command = report.recv()
        if command != "bootstrap-sent":
            return
        if mode == "replay":
            report.send(("waiting-hello",))
            if report.recv() != "hello-now":
                return
        hello = make_header(wire.HELLO, nonce, epoch, control_id=wire.HELLO_CONTROL_ID)
        endpoint.sendall(hello)
        ready, sender = recv_message(endpoint, 3)
        fields = wire.unpack_header(ready)
        require(sender == (worker_pid, worker_uid, worker_gid),
            f"READY sender credentials mismatch: {sender!r}")
        require(fields[2] == wire.READY and fields[8] == wire.HELLO_CONTROL_ID,
            f"invalid worker READY: {fields!r}")
        report.send(("ready",))
        saved_replay_result = None
        while True:
            message, sender = recv_message(endpoint, 5)
            fields = wire.unpack_header(message)
            require(sender == (worker_pid, worker_uid, worker_gid),
                f"DATA sender credentials mismatch: {sender!r}")
            require(fields[2] == wire.DATA and fields[5] == nonce and
                    fields[6] == epoch and fields[7] > 0,
                f"invalid DATA lease header: {fields!r}")
            packet_id = fields[7]
            require(len(message) >= wire.HEADER_BYTES + wire.DATA_BYTES,
                "truncated worker DATA lease")
            data = wire.DATA_BODY.unpack_from(message, wire.HEADER_BYTES)
            frame = message[wire.HEADER_BYTES + wire.DATA_BYTES:]
            require(data[0] >= len(frame) >= 54 and data[1] == len(frame) and
                    data[9] >= data[2] + data[1] and data[6] == 0 and data[7] == 0 and
                    not (data[8] & ~wire.RX_KNOWN_CKSUM_MASK),
                f"invalid real-frame snapshot metadata: {data!r}, bytes={len(frame)}")
            packet = parse_ipv4_tcp(frame)
            require(packet and packet[0] == "198.18.0.1" and packet[1] == "198.18.0.2" and
                    packet[4] & 0x02 and not packet[4] & 0x10,
                f"DATA lease was not the injected TCP SYN: {packet!r}")
            report.send(("data", packet_id))
            if mode == "timeout" or mode == "dead-peer":
                report.recv()  # Parent releases us after recording timeout/death intent.
                continue
            if mode == "wrong-sender":
                report.recv()  # Parent, authenticated only as supervisor, sends the bad RESULT.
                continue
            if mode == "replay":
                if saved_replay_result is None:
                    report.recv()  # Authorize original mbuf N as DROP.
                    result_body = wire.RESULT_BODY.pack(wire.DROP, 0, 0, 0)
                    saved_replay_result = make_header(wire.RESULT, nonce, epoch,
                        packet_id=packet_id, body=result_body)
                    endpoint.sendall(saved_replay_result)
                    report.send(("dropped-first", packet_id))
                else:
                    report.recv()  # Replay RESULT(N) as the response to DATA(N+1).
                    endpoint.sendall(saved_replay_result)
                    report.send(("replayed", packet_id))
                continue
            raise RuntimeError(f"unknown case {mode}")
    except (EOFError, BrokenPipeError, OSError):
        return
    except Exception as error:
        try:
            report.send(("error", str(error)))
        except (BrokenPipeError, EOFError):
            pass
    finally:
        endpoint.close()


def start_worker(args):
    packet_app, packet_io = socket.socketpair(socket.AF_UNIX,
        socket.SOCK_DGRAM | socket.SOCK_NONBLOCK)
    mtu_app, mtu_io = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    control_read, control_write = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
    supervisor_endpoint, worker_endpoint = socket.socketpair(socket.AF_UNIX,
        socket.SOCK_SEQPACKET)
    supervisor_endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    worker_endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    process = None
    try:
        cpu = min(os.sched_getaffinity(0))
        eal = [f"--lcores=0@{cpu}", "--no-huge", "--no-pci", "--no-shconf",
            "--no-telemetry", "--iova-mode=va", "-m", "64", "-d",
            str(args.dpdk_plugin_dir / "librte_net_tap.so"),
            "--vdev=net_tap0,iface=kerpeer,remote=kerlink"]
        command = [str(args.worker), "--packet-fd", str(packet_io.fileno()),
            "--tx-offloads", "0", "--queues", "1", "--mtu-fd", str(mtu_io.fileno()),
            "--max-mtu", "9000", "--control-fd", str(control_read),
            "--idle-sleep-us", "1000", "--tx-delay-us", "0", "--port", "net_tap0",
            "--mtu", "1500", "--mbuf-mode", "large", "--no-numa",
            "--no-promiscuous", "--rx-decision-fd", str(worker_endpoint.fileno()), "--", *eal]
        process = subprocess.Popen(command,
            pass_fds=(packet_io.fileno(), mtu_io.fileno(), control_read, worker_endpoint.fileno()),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0, start_new_session=True)
        packet_io.close(); mtu_io.close(); worker_endpoint.close(); os.close(control_read)
        ready_line = recv_worker_line(process, "KER_IO_READY ", 20)
        ready = json.loads(ready_line[len("KER_IO_READY "):])
        require(ready.get("mac"), f"worker READY lacks interface MAC: {ready!r}")
        subprocess.run(["ip", "neigh", "replace", "198.18.0.2", "lladdr", ready["mac"],
            "dev", "kerhost", "nud", "permanent"], check=True)
        return (process, packet_app, mtu_app, control_write, supervisor_endpoint)
    except Exception:
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.communicate()
        for endpoint in (packet_app, packet_io, mtu_app, mtu_io,
                supervisor_endpoint, worker_endpoint):
            try: endpoint.close()
            except OSError: pass
        for fd in (control_read, control_write):
            try: os.close(fd)
            except OSError: pass
        raise


def wait_report(channel, expected, timeout=3):
    if not channel.poll(timeout):
        raise TimeoutError(f"consumer did not report {expected}")
    value = channel.recv()
    require(value[0] == expected, f"consumer report mismatch: wanted {expected}, got {value!r}")
    return value


def run_case(args, case_root, mode):
    for command in (["ip", "link", "set", "lo", "up"],
            ["ip", "link", "add", "kerhost", "type", "veth", "peer", "name", "kerlink"],
            ["ip", "addr", "add", "198.18.0.1/24", "dev", "kerhost"],
            ["ip", "link", "set", "kerhost", "up"],
            ["ip", "link", "set", "kerlink", "up"]):
        subprocess.run(command, check=True)
    process = packet_app = mtu_app = control_write = endpoint = consumer = report = None
    peers = []
    capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    capture.bind(("kerhost", 0)); capture.setblocking(False)
    try:
        process, packet_app, mtu_app, control_write, endpoint = start_worker(args)
        endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        import multiprocessing
        context = multiprocessing.get_context("fork")
        parent, child = context.Pipe()
        report = parent
        nonce = os.urandom(wire.NONCE_BYTES)
        epoch = int.from_bytes(os.urandom(8), "little") or 1
        consumer = context.Process(target=consumer_process,
            args=(endpoint.fileno(), child, mode, process.pid, os.getuid(), os.getgid(),
                process_start_ticks(process.pid), nonce, epoch))
        consumer.start(); child.close()
        target_pidfd = os.pidfd_open(consumer.pid)
        supervisor_pidfd = os.pidfd_open(os.getpid())
        try:
            start = process_start_ticks(consumer.pid)
            body = wire.BOOTSTRAP_BODY.pack(wire.TARGET_CONSUMER, consumer.pid,
                os.getuid(), os.getgid(), start, os.getpid(), os.getuid(), os.getgid(),
                0, process_start_ticks(os.getpid()))
            bootstrap = wire.pack_header(wire.BOOTSTRAP, nonce, epoch,
                control_id=wire.BOOTSTRAP_CONTROL_ID, body_bytes=len(body)) + body
            rights = array.array("i", (target_pidfd, supervisor_pidfd))
            sent = endpoint.sendmsg([bootstrap], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)])
            require(sent == len(bootstrap), "short authenticated bootstrap")
        finally:
            os.close(target_pidfd); os.close(supervisor_pidfd)
        parent.send("bootstrap-sent")
        if mode == "replay":
            wait_report(parent, "waiting-hello", 3)
            # The worker deliberately holds RX until HELLO. Queue two independent
            # host-generated SYNs first so both original mbufs are in the next burst.
            first, first_port = open_syn(capture); peers.append(first)
            second, _ = open_syn(capture); peers.append(second)
            parent.send("hello-now")
        wait_report(parent, "ready", 5)

        # Every fault is triggered only after a real TCP SYN enters the DPDK TAP.
        if mode != "replay":
            first, first_port = open_syn(capture); peers.append(first)
        if mode == "dead-peer":
            packet_id = wait_report(parent, "data", 3)[1]
            require(packet_id > 0, "dead-peer case received invalid packet id")
            os.kill(consumer.pid, signal.SIGKILL)
        elif mode == "timeout":
            packet_id = wait_report(parent, "data", 3)[1]
            require(packet_id > 0, "timeout case received invalid packet id")
            parent.send("hold")
        elif mode == "wrong-sender":
            packet_id = wait_report(parent, "data", 3)[1]
            require(packet_id > 0, "wrong-sender case received invalid packet id")
            result_body = wire.RESULT_BODY.pack(wire.DROP, 0, 0, 0)
            bad_result = make_header(wire.RESULT, nonce, epoch, packet_id=packet_id,
                body=result_body)
            require(endpoint.send(bad_result) == len(bad_result), "short rogue RESULT send")
            parent.send("hold")
        elif mode == "replay":
            first_id = wait_report(parent, "data", 3)[1]
            require(first_id > 0, "replay case received invalid first packet id")
            parent.send("send-first-drop")
            dropped_id = wait_report(parent, "dropped-first", 3)[1]
            require(dropped_id == first_id,
                f"first valid DROP did not match its DATA packet: {first_id}, {dropped_id}")
            second_id = wait_report(parent, "data", 3)[1]
            require(second_id > first_id,
                f"worker did not issue a distinct second lease: {first_id}, {second_id}")
            parent.send("send-replay")
            replayed_for_id = wait_report(parent, "replayed", 3)[1]
            require(replayed_for_id == second_id,
                f"replayed RESULT was not attempted as DATA N+1: {replayed_for_id}, {second_id}")
        else:
            raise RuntimeError(f"unknown producer fault {mode}")

        try:
            process.wait(timeout=4)
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"worker failed to terminate after {mode}")
        require(process.returncode != 0, f"worker accepted {mode} and exited successfully")
        output_tail = process.stdout.read()
        error_output = process.stderr.read()
        stdout = bytes(getattr(process, "_rx_pending", b"")) + output_tail
        stderr = error_output.decode("utf-8", "replace")
        stdout_text = stdout.decode("utf-8", "replace")
        done_lines = [line[len("KER_IO_DONE "):] for line in stdout_text.splitlines()
            if line.startswith("KER_IO_DONE ")]
        require(done_lines, f"worker omitted cleanup stats: {stdout_text!r}; stderr={stderr!r}")
        stats = json.loads(done_lines[-1])
        require(stats.get("rx_decision_enabled") is True and stats.get("outstanding") == 0,
            f"worker did not release all pool buffers: {stats!r}")
        require(sum(stats.get("rx_by_queue", [])) >= 1,
            f"fault case never reached the real DPDK RX queue: {stats!r}")
        require(stats.get("rx_decision_forwarded", 0) == 0 and
                stats.get("rx_decision_local", 0) == 0,
            f"failed lease reached packet_fd: {stats!r}")
        readable, _, _ = select.select([packet_app], [], [], .02)
        require(not readable, f"worker delivered packet_fd datagram after {mode}")
        decision_errors = [line for line in stderr.splitlines() if line.startswith("ker: RX decision")]
        require(decision_errors,
            f"worker did not report the fail-closed decision path: {stderr!r}")
        expected_error = "Protocol error" if mode in ("replay", "wrong-sender") else "Connection timed out"
        require(expected_error in decision_errors[-1],
            f"unexpected fail-closed cause for {mode}: {decision_errors[-1]!r}")
        if mode == "replay":
            require(stats.get("rx_decision_drops", 0) == 1 and
                    sum(stats.get("rx_by_queue", [])) >= 2,
                f"replay did not settle N and receive N+1 before rejection: {stats!r}")
        require(consumer is not None, "missing authenticated consumer process")
        return {"mode": mode, "worker_rc": process.returncode,
            "rx_packets": sum(stats.get("rx_by_queue", [])),
            "leases": stats.get("rx_decision_leases"),
            "drops": stats.get("rx_decision_drops"),
            "forwarded": stats.get("rx_decision_forwarded"),
            "outstanding": stats.get("outstanding"),
            "error": decision_errors[-1]}
    finally:
        if consumer is not None:
            if consumer.is_alive(): consumer.kill()
            consumer.join(timeout=2)
        if report is not None: report.close()
        if endpoint is not None: endpoint.close()
        if packet_app is not None: packet_app.close()
        if mtu_app is not None: mtu_app.close()
        if control_write is not None: os.close(control_write)
        for peer in peers: peer.close()
        capture.close()
        if process is not None and process.poll() is None:
            process.kill(); process.wait()
        subprocess.run(["ip", "link", "delete", "kerhost"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


def inside(args):
    root = Path(tempfile.mkdtemp(prefix="ker-rx-producer-faults-", dir=os.environ.get("TMPDIR", "/dev/shm")))
    results = []
    try:
        for mode in ("timeout", "replay", "wrong-sender", "dead-peer"):
            case_root = root / mode
            case_root.mkdir()
            results.append(run_case(args, case_root, mode))
    finally:
        import shutil
        shutil.rmtree(root, ignore_errors=True)
    print("RX_DECISION_PRODUCER_FAULTS_OK " + json.dumps(results, sort_keys=True))
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker", type=Path, required=True)
    parser.add_argument("--dpdk-plugin-dir", type=Path, required=True)
    parser.add_argument("--inside", action="store_true")
    args = parser.parse_args()
    if args.inside:
        return inside(args)
    command = ["unshare", "-Urn", sys.executable, str(Path(__file__).resolve()), "--inside",
        "--worker", str(args.worker.resolve()), "--dpdk-plugin-dir",
        str(args.dpdk_plugin_dir.resolve())]
    return subprocess.run(command).returncode


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"RX decision producer fault fixture failed: {error}\n{traceback.format_exc()}",
            file=sys.stderr)
        raise SystemExit(1)
