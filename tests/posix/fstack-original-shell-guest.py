#!/usr/bin/env python3
"""Run an original F-Stack source-shell test in private Linux namespaces."""

import argparse
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import shutil
import secrets
import subprocess
import sys
import tempfile
import threading
import traceback
import time

SSH_ROOT = Path("/run/fstack-ssh")
WORKSPACE = Path("/data/workspace")
SERVER_IP = "169.254.28.1"
CLIENT_IP = "169.254.28.2"
SSH_PORT = 2222
PRODUCTION_CASES = ("precheck", "gr0", "baseline", "rt01", "rt02", "rv9",
                    "rt12", "rt23", "rt25", "rt30", "rt31")
FAULT_CASES = ("rt20", "rt20b", "rt21", "rt22", "rt24", "rt26")


def run(*command, **kwargs):
    return subprocess.run(command, check=True, **kwargs)


def namespace(kind):
    return os.readlink(f"/proc/self/ns/{kind}")


def ephemeral_filesystems(readonly_inputs=(), writable_inputs=()):
    # Keep descriptors to accepted inputs that live under a path covered by a
    # tmpfs mount. Their original pathnames are hidden by that mount, but the
    # descriptors still refer to the original trees and can be rebound there.
    overlays = (Path("/tmp"), Path("/usr/local"))
    preserved = []
    for writable, paths in ((False, readonly_inputs), (True, writable_inputs)):
        for path in paths:
            path = Path(path).resolve(strict=True)
            if not any(path != root and path.is_relative_to(root) for root in overlays):
                continue
            if any(path == prior and writable == prior_writable
                   for prior, prior_writable, _ in preserved):
                continue
            flags = os.O_PATH
            fd = os.open(path, flags)
            preserved.append((path, writable, fd))

    for path in ("/data", "/run", "/tmp", "/dev/hugepages", "/dev/shm", "/usr/local"):
        run("mount", "-t", "tmpfs", "tmpfs", path)

    # Restore only the supplied trees, leaving the rest of /tmp and /usr/local
    # ephemeral. Output directories are rebound writable; all other accepted
    # paths remain read-only inside the guest.
    anchors = Path("/run/fstack-inputs")
    anchors.mkdir()
    for index, (path, writable, fd) in enumerate(
            sorted(preserved, key=lambda item: len(item[0].parts))):
        is_directory = os.path.isdir(f"/proc/self/fd/{fd}")
        anchor = anchors / str(index)
        if is_directory:
            anchor.mkdir()
        else:
            anchor.touch()
        # Use a distinct in-namespace anchor: util-linux canonicalizes mount
        # sources, and mounting an fd straight back over its own old pathname
        # can resolve to the newly mounted tmpfs instead of the open tree.
        run("mount", "--bind", f"/proc/self/fd/{fd}", anchor, pass_fds=(fd,))
        if not writable:
            run("mount", "-o", "remount,bind,ro", anchor)
        if is_directory:
            if not path.is_dir():
                path.mkdir(parents=True)
        else:
            if not path.parent.is_dir():
                path.parent.mkdir(parents=True)
            if not path.is_file():
                path.touch()
        run("mount", "--bind", anchor, path)
        if not writable:
            run("mount", "-o", "remount,bind,ro", path)
        else:
            run("mount", "-o", "remount,bind,rw", path)
    for _, _, fd in preserved:
        os.close(fd)

    WORKSPACE.mkdir()
    for path, mode in (("/run/sshd", 0o755), ("/run/dpdk", 0o700), ("/tmp", 0o700)):
        target = Path(path)
        target.mkdir(exist_ok=True)
        target.chmod(mode)
    for path in ("/usr/share/empty.sshd", "/var/empty/sshd"):
        if Path(path).is_dir():
            run("mount", "-t", "tmpfs", "-o", "mode=0755", "tmpfs", path)


def configure_ssh():
    SSH_ROOT.mkdir(mode=0o700)
    key = SSH_ROOT / "client-key"
    host = SSH_ROOT / "host-key"
    for path in (key, host):
        run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", path)
    authorized = SSH_ROOT / "authorized_keys"
    shutil.copyfile(key.with_suffix(".pub"), authorized)
    authorized.chmod(0o600)
    (SSH_ROOT / "known_hosts").write_text(f"[{CLIENT_IP}]:{SSH_PORT} " +
                                         host.with_suffix(".pub").read_text())
    files = {
        "passwd": f"root:x:0:0:root:{SSH_ROOT}:/bin/bash\n"
                  "sshd:x:65534:65534:sshd:/run/sshd:/sbin/nologin\n",
        "group": "root:x:0:\nsshd:x:65534:\n",
        "shadow": "root::19000:0:99999:7:::\nsshd:!:19000:0:99999:7:::\n",
        "ssh_config": f"""Host f-stack-client
    HostName {CLIENT_IP}
    User root
    Port {SSH_PORT}
    IdentityFile {key}
    IdentitiesOnly yes
    UserKnownHostsFile {SSH_ROOT / 'known_hosts'}
    GlobalKnownHostsFile /dev/null
    StrictHostKeyChecking yes
    BatchMode yes
""",
    }
    for name, content in files.items():
        local = SSH_ROOT / name
        local.write_text(content)
        if name == "shadow":
            local.chmod(0o600)
        target = "/etc/ssh/ssh_config" if name == "ssh_config" else f"/etc/{name}"
        run("mount", "--bind", local, target)
    config = SSH_ROOT / "sshd_config"
    config.write_text(f"""ListenAddress {CLIENT_IP}:{SSH_PORT}
HostKey {host}
PidFile {SSH_ROOT / 'sshd.pid'}
AuthorizedKeysFile {authorized}
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
Subsystem sftp internal-sftp
UsePAM no
""")
    return config


def start_client(config, log_path):
    # The SSH control veth is separate from the traffic interfaces the case sets up.
    client = subprocess.Popen(["unshare", "--net", "sleep", "infinity"])
    child_ns = Path(f"/proc/{client.pid}/ns/net")
    deadline = time.monotonic() + 5
    while os.readlink(child_ns) == namespace("net"):
        if client.poll() is not None or time.monotonic() >= deadline:
            raise RuntimeError("client network namespace did not start")
        time.sleep(0.02)
    enter = ["nsenter", "-t", str(client.pid), "-n"]
    run("ip", "link", "set", "lo", "up")
    run("ip", "link", "add", "kerctl", "type", "veth", "peer", "name", "kerclient")
    run("ip", "addr", "add", f"{SERVER_IP}/30", "dev", "kerctl")
    run("ip", "link", "set", "kerctl", "up")
    run("ip", "link", "set", "kerclient", "netns", str(client.pid))
    run(*enter, "ip", "link", "set", "lo", "up")
    run(*enter, "ip", "addr", "add", f"{CLIENT_IP}/30", "dev", "kerclient")
    run(*enter, "ip", "link", "set", "kerclient", "up")
    sshd = shutil.which("sshd")
    if sshd is None:
        raise RuntimeError("OpenSSH sshd is required in the test guest")
    server = subprocess.Popen([*enter, sshd, "-D", "-E", log_path, "-f", config])
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and server.poll() is None:
        result = subprocess.run(["ssh", "-n", "-o", "ConnectTimeout=1", "f-stack-client",
                                 "readlink", "/proc/self/ns/net"],
                                capture_output=True, text=True, check=False)
        if result.returncode == 0:
            if result.stdout.strip() != os.readlink(child_ns):
                raise RuntimeError("SSH client is outside the expected client network namespace")
            return client.pid
        time.sleep(0.05)
    raise RuntimeError(f"SSH client did not start; see {log_path}")


def prepare_source(repo, fixture, case):
    manifest = Path((fixture / "manifest-path").read_text().strip()).resolve(strict=True)
    if not manifest.is_relative_to(fixture):
        raise RuntimeError("source-shell fixture manifest is outside its build tree")
    build = json.loads(manifest.read_text())
    source = manifest.parent / "fstack"
    nginx = source / "app/nginx-1.28.0/objs/nginx"
    if build["nginx"]["path"] != str(nginx) or build["fault_injection"] is not (case in FAULT_CASES):
        raise RuntimeError("the original case requires its matching source-shell build variant")

    (WORKSPACE / "f-stack").symlink_to(source, target_is_directory=True)
    for name in ("ker-source-shell-wrapper.py", "nginx-source-shell-helper.py"):
        shutil.copyfile(repo / "tools" / name, WORKSPACE / name)
    for name in ("kill_process.sh", "rm_tmp_file.sh", "chmod_modify.sh"):
        wrapper = WORKSPACE / name
        wrapper.write_text("#!/bin/sh\n"
                           f'exec /usr/bin/python3 -I {WORKSPACE}/ker-source-shell-wrapper.py {name} "$@"\n')
        wrapper.chmod(0o755)

    system_conf = Path("/usr/local/nginx_fstack/conf")
    system_conf.mkdir(parents=True)
    shutil.copyfile(source / "app/nginx-1.28.0/conf/mime.types", system_conf / "mime.types")
    sys.path.insert(0, str(repo / "tools"))
    return source, nginx, manifest


def run_precheck(source, nginx, manifest, run_dir):
    import nginx_source_origin
    from nginx_source_scope import SourceScopeCapsules

    capsules = SourceScopeCapsules(nginx_source_origin)
    captured = run_dir / "original-output"
    try:
        capsules.publish_bootstrap(run_dir / "bootstrap.json")
        run("/bin/bash", source / "tests/integration/test_graceful_reload.sh",
            "--cases", "precheck", "--target-ip", "198.18.0.2", "--workers", "1",
            "--nginx", nginx, "--fstack-conf", source / "config.ini",
            "--build-manifest", manifest, "--out", captured,
            env={"PATH": os.defpath, "LC_ALL": "C"})
    finally:
        capsules.close()

    verify_original_verdicts(captured, ["precheck"])


def verify_original_verdicts(output, cases):
    verdicts = [json.loads(line) for line in (output / "results.jsonl").read_text().splitlines()]
    if [(row["case"], row["verdict"], row["exit_code"]) for row in verdicts] != [
            (case, "PASS", 0) for case in cases]:
        raise RuntimeError(f"original F-Stack did not report PASS for {cases}")
    events = [json.loads(line) for line in (output / "ownership-events.jsonl").read_text().splitlines()]
    if not events or (events[-1]["event"], events[-1]["result"], events[-1]["echild"]) != (
            "run_finished", 0, True):
        raise RuntimeError("original F-Stack supervisor did not settle")
    return events[-1]


def prepare_data_link(client):
    enter = ["nsenter", "-t", str(client), "-n"]
    run("ip", "link", "add", "kerlink", "type", "veth", "peer", "name", "kertraffic")
    run("ip", "link", "set", "kerlink", "up")
    run("ip", "link", "set", "kertraffic", "netns", str(client))
    run(*enter, "ip", "addr", "add", "198.18.0.1/24", "dev", "kertraffic")
    run(*enter, "ip", "link", "set", "kertraffic", "up")


def prepare_serial_tap(client):
    prepare_data_link(client)
    run("ip", "tuntap", "add", "dev", "kerpeer", "mode", "tap", "multi_queue")
    run("ip", "link", "set", "kerpeer", "up")


def run_gr0(repo, source, nginx, manifest, run_dir, args):
    from ker_serial_generation import InnerLaunch, SerialGenerationController
    from nginx_cycle_control import NginxCycleControl
    import nginx_source_origin as origin
    from nginx_source_scope import CapturedScopeRoot, SourceScopeCapsules

    output = run_dir / "original-output"
    broker = run_dir / "broker.sock"
    template = run_dir / "template.ini"
    template.write_text(f"""[ker_socket_broker]
version=1
path={broker}
[dpdk]
fstack_log_level=0
graceful_reload=0
primary_slim=0
lcore_mask=1
file_prefix=gr0-template
fstack_log_file_prefix={output}/fstack-
[port0]
lcore_list=0
addr=198.18.0.2
netmask=255.255.255.0
broadcast=198.18.0.255
gateway=198.18.0.1
""")
    launch = InnerLaunch(repo / "tools/ker-run.py", args.library, args.worker,
                         args.broker, args.pmd_dir, run_dir, rpc_path=broker)
    controller = SerialGenerationController(launch, port=80, max_generations=2)
    old = controller.start_inner("old")
    ready = controller.receive_ready(old)[2:5]
    cycle = NginxCycleControl(ready, source_socket=run_dir / "kngc.sock")
    capsules = SourceScopeCapsules(origin)
    capsules.publish_bootstrap(run_dir / "bootstrap.json")
    original = origin.OriginalSerialShellLaunch(source, nginx, manifest, template,
                                               output, cycle, trace=run_dir / "runtime.trace")
    original.bind_initial_runtime(controller, old)
    original.wait_supervisor()
    capsules.publish_run(original, (CapturedScopeRoot.capture("/tmp", original.run_id),))
    cycle.bind_source_master(original)
    watch_fd = cycle.accept_initial_watch(original)
    try:
        live = controller.verify_external_watch(old, watch_fd, original, cycle)
        cycle.receive_drained(timeout=65)
        deadline = cycle.transition_deadline
        retired = controller.verify_external_watch(old, watch_fd, original, cycle,
            require_retired=True, live_watch=live, deadline=deadline)
    finally:
        os.close(watch_fd)
    stopped = controller.stop_inner(old, retired, deadline=deadline)
    new = controller.start_next(old, retired, stopped)
    ready = controller.receive_ready(new, deadline=deadline)[2:5]
    cycle.send_ready(ready)
    watch_fd = cycle.accept_successor_watch(ready)
    try:
        live = controller.verify_external_watch(new, watch_fd, original, cycle)
        if original.process.wait(timeout=90) != 0:
            raise RuntimeError("original gr0 probe failed")
        shutdown = controller.record_original_shutdown(new, live, original, cycle)
        retired_new = controller.verify_external_shutdown_watch(new, watch_fd, shutdown)
    finally:
        os.close(watch_fd)
    stopped_new = controller.stop_inner(new, retired_new)
    final = verify_original_verdicts(output, ["precheck", "gr0"])
    (run_dir / "serial-result.json").write_text(json.dumps({
        "final": final, "old": old.events, "new": new.events,
        "native_shutdown_a": stopped.stats, "native_shutdown_b": stopped_new.stats,
    }, indent=2) + "\n")
    controller.close_watch(live)
    controller.close_context(new, "settled")
    capsules.close(original)
    cycle.close()
    original.close()


def rt12_virtio(testpmd, stop, evidence):
    def interfaces():
        listing = run("ip", "-j", "link", "show", capture_output=True, text=True)
        return {entry["ifname"]: entry for entry in json.loads(listing.stdout)}

    def wait_interfaces(*names):
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline and not stop.is_set():
            current = interfaces()
            if all(name in current for name in names):
                return current
            time.sleep(0.05)
        raise RuntimeError(f"rt12 interfaces did not appear: {names}")

    pmds = [item.parent for item in testpmd.parent.parent.glob(
        "lib*/dpdk/pmds-*/librte_net_virtio.so")]
    if len(pmds) != 1 or not (pmds[0] / "librte_net_af_packet.so").is_file():
        raise RuntimeError("rt12 testpmd requires its installed virtio and af_packet PMDs")
    pmd_dir = pmds[0]
    libraries = pmd_dir.parent.parent
    devices = wait_interfaces("kerprobe", "kerkni")
    run("ip", "link", "set", "kerprobe", "up")
    for source, target in (("kerlink", "kerprobe"), ("kerprobe", "kerlink")):
        run("tc", "qdisc", "add", "dev", source, "clsact")
        run("tc", "filter", "add", "dev", source, "ingress", "pref", "1",
            "matchall", "action", "mirred", "egress", "redirect", "dev", target)
    mac = devices["kerkni"]["address"]
    main_cpu, io_cpu = sorted(os.sched_getaffinity(0))[-2:]
    with (evidence / "virtio-testpmd.log").open("wb") as log:
        command = [testpmd, "-l", f"{main_cpu},{io_cpu}", "--main-lcore", str(main_cpu),
            "--no-huge", "--no-pci", "--no-telemetry", "--iova-mode=va", "-m", "96",
            "--file-prefix=rt12-virtio", "--vdev=net_af_packet0,iface=kerkni",
            f"--vdev=net_virtio_user0,path=/dev/vhost-net,iface=veth0,mac={mac}", "--",
            "-i", "--auto-start", "--no-numa", "--forward-mode=io", "--nb-cores=1",
            "--total-num-mbufs=8192"]
        env = {**os.environ, "LD_LIBRARY_PATH": str(libraries)}
        with subprocess.Popen(command, env=env, stdin=subprocess.PIPE, stdout=log,
                              stderr=subprocess.STDOUT) as sidecar:
            try:
                wait_interfaces("veth0")
                run("ip", "link", "set", "veth0", "up")
                run("ip", "addr", "add", "198.18.0.3/24", "dev", "veth0")
                with (evidence / "virtio-link-before").open("wb") as receipt:
                    run("ip", "-d", "-o", "link", "show", "veth0", stdout=receipt)
                while not stop.wait(0.1):
                    if sidecar.poll() is not None:
                        raise RuntimeError("rt12 testpmd exited while the original probe was active")
            finally:
                if sidecar.poll() is None:
                    try:
                        sidecar.communicate(b"show port stats all\nstop\nquit\n", timeout=10)
                    except subprocess.TimeoutExpired:
                        sidecar.kill()
                        sidecar.communicate()
                        raise
            if sidecar.returncode != 0 or "veth0" in interfaces():
                raise RuntimeError("rt12 testpmd did not remove its virtio-user interface")


@contextmanager
def capture_runtime_log(path):
    sys.stdout.flush()
    sys.stderr.flush()
    out_fd = os.dup(1)
    err_fd = os.dup(2)
    try:
        with path.open("wb") as log:
            os.dup2(log.fileno(), 1, inheritable=True)
            os.dup2(log.fileno(), 2, inheritable=True)
            try:
                yield
            finally:
                sys.stdout.flush()
                sys.stderr.flush()
    finally:
        os.dup2(out_fd, 1, inheritable=True)
        os.dup2(err_fd, 2, inheritable=True)
        os.close(out_fd)
        os.close(err_fd)


def run_c34(repo, nginx, manifest, prefix, run_dir, args):
    import nginx_source_origin as origin

    launcher = repo / "tools/ker-run.py"
    spec = importlib.util.spec_from_file_location("ker_run", launcher)
    ker_run = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = ker_run
    spec.loader.exec_module(ker_run)
    artifacts = ker_run._load_source_shell_controller()._c34_profile_module()._provider()
    fault = origin.SOURCE_HUP_FAULTS.get(args.case)
    seconds = 1750 if args.case == "rv9" else 410 if args.case == "baseline" else 280
    deadline = time.monotonic_ns() + seconds * 1_000_000_000
    with open(run_dir / "caller.conf", "w") as dummy:
        dummy.write("events {}\n")
    capture = artifacts.PrivateC34ArtifactCapture.capture_test_fixture(manifest, args.library,
        args.worker, args.broker, args.owner_helper, deadline, fault=fault)
    try:
        cpu, rx_cpu = sorted(os.sched_getaffinity(0))[:2]
        pmd = args.pmd_dir / "librte_net_tap.so"
        eal = (f"--lcores=0@{cpu},1@{rx_cpu} --no-huge --no-pci --no-telemetry "
               f"--iova-mode=va -m 96 -d {pmd} ")
        exception = []
        if args.case == "rt12":
            eal += "--main-lcore=1 --vdev=net_tap0,iface=kerprobe"
            exception = ["--exception-iface", "kerkni", "--exception-mode", "ports",
                         "--exception-policy", "reject", "--exception-tcp-ports", "80,443",
                         "--exception-udp-ports", "53"]
        else:
            eal += "--vdev=net_tap0,iface=kerpeer,remote=kerlink"
        broker = run_dir / "broker.sock"
        out = run_dir / "original-output"
        ini = out / f"fstack_{origin.SOURCE_CASE_TAGS[args.case]}.ini"
        trace = run_dir / "runtime.trace"
        preload = ":".join(str(capture.artifact(role).path)
                           for role in ("runtime", "preload", "shim"))
        os.environ.update(KER_NGINX_SOURCE_BOOTSTRAP_DEADLINE_NS=str(deadline),
                          KER_RX_OWNER_SOURCE_ROUTE_ENABLE="1",
                          KER_RX_OWNER_PEER_AUTH_ENABLE="1",
                          KER_RX_OWNER_RELAY_PROBE_TOKEN=secrets.token_hex(12))
        sys.argv = list(map(str, [launcher, "--address", "198.18.0.2/24", "--gateway",
            "198.18.0.1", f"--eal={eal}", "--port", "net_tap0",
            "--max-mtu", "1500", "--no-rss", "--runtime-service", "--rx-decision",
            "--broker-readiness", "--queues", "1", "--rx-lcores", "1", *exception,
            "--stats", run_dir / "native.stats.json",
            "--control-nginx-binary", nginx, "--control-nginx-config", run_dir / "caller.conf",
            "--control-nginx-prefix", prefix, "--control-nginx-owner-ready",
            "--control-nginx-source-bootstrap-required", "--control-nginx-source-shell-profile",
            "--control-nginx-source-private-c34-profile", "--control-nginx-rx-relay",
            "--control-nginx-env", f"LD_PRELOAD={preload}",
            "--control-nginx-env", f"KER_SOCKET_BROKER_PATH={broker}",
            "--control-nginx-env", f"KER_FSTACK_NGINX_INI={ini}",
            "--control-nginx-env", f"KER_FSTACK_RUNTIME_TRACE={trace}",
            "--", args.broker, broker]))
        if args.case == "rt12":
            stop = threading.Event()
            with ThreadPoolExecutor(max_workers=1) as pool:
                sidecar = pool.submit(rt12_virtio, args.virtio_testpmd, stop, run_dir)
                try:
                    status = ker_run.main(c34_test_capture=capture)
                finally:
                    stop.set()
                    sidecar.result()
        else:
            status = ker_run.main(c34_test_capture=capture)
        if status != 0:
            raise RuntimeError(f"C34 native runtime exited {status}")
    except Exception:
        traceback.print_exc()
        raise
    finally:
        capture.close()
    verify_original_verdicts(out, ["precheck", args.case])
    stats = json.loads((run_dir / "native.stats.json").read_text())
    if (stats.get("run_shutdown_ack") is not True or stats.get("outstanding") != 0 or
            stats.get("worker_exit_code") != 0 or stats.get("rx_decision_settled") is not True):
        raise RuntimeError(f"Missing native STOP or RX settlement for {args.case}")


def prepare_nginx_prefix(source, stage):
    prefix = stage / "nginx-prefix"
    run("mount", "-t", "tmpfs", "tmpfs", prefix)
    for name in ("html", "logs"):
        (prefix / name).mkdir()
    shutil.copyfile(source / "app/nginx-1.28.0/html/index.html", prefix / "html/index.html")
    return prefix


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--case", choices=PRODUCTION_CASES + FAULT_CASES, required=True)
    for name in ("library", "worker", "broker", "pmd-dir", "owner-helper", "virtio-testpmd"):
        parser.add_argument(f"--{name}", type=Path)
    parser.add_argument("--parent-namespaces", nargs=3)
    args = parser.parse_args()
    repo = args.repo.resolve(strict=True)
    fixture = args.fixture.resolve(strict=True)
    out = args.output.resolve()
    inputs = {}
    if args.case != "precheck":
        names = ("library", "worker", "broker", "pmd_dir")
        if args.case != "gr0":
            names += ("owner_helper",)
        if args.case == "rt12":
            names += ("virtio_testpmd",)
        for name in names:
            path = getattr(args, name)
            if path is None:
                parser.error(f"{args.case} requires --{name.replace('_', '-')}")
            inputs[name] = path.resolve(strict=True)
            setattr(args, name, inputs[name])
    kinds = ("pid", "mnt", "net")
    current = [namespace(kind) for kind in kinds]
    if args.parent_namespaces is None:
        out.mkdir(parents=True, exist_ok=True)
        run_dir = Path(tempfile.mkdtemp(prefix=f"{args.case}-", dir=out))
        print(f"F-Stack source-shell {args.case} artifacts {run_dir}", flush=True)
        run("unshare", "--map-auto", "--map-root-user", "--mount", "--propagation",
            "private", "--net", "--ipc", "--pid", "--fork", "--mount-proc", "--kill-child",
            sys.executable, "-B", Path(__file__).resolve(), "--repo", repo, "--fixture", fixture,
            "--output", run_dir, "--case", args.case, "--parent-namespaces", *current,
            *[arg for name, path in inputs.items() for arg in (f"--{name.replace('_', '-')}", path)])
        return
    if os.getpid() != 1 or os.geteuid() != 0 or any(
            parent == child for parent, child in zip(args.parent_namespaces, current)):
        raise RuntimeError("guest setup requires private PID, mount and network namespaces")
    readonly_inputs = [repo, fixture]
    readonly_inputs.extend(inputs.values())
    # C34 captures runtime libraries beside the worker, and the build manifest
    # points at the pinned DPDK Meson tree through this source-tree symlink.
    if args.worker is not None:
        if args.worker.parent not in (Path("/tmp"), Path("/usr/local")):
            readonly_inputs.append(args.worker.parent)
    if args.pmd_dir is not None:
        libraries = args.pmd_dir.parent.parent
        if libraries not in (Path("/tmp"), Path("/usr/local")):
            readonly_inputs.append(libraries)
    manifest = Path((fixture / "manifest-path").read_text().strip()).resolve(strict=True)
    readonly_inputs.append((manifest.parent / "fstack/dpdk/build").resolve(strict=True))
    if args.case == "rt12":
        # The sidecar testpmd has its own install prefix and PMD tree; it may
        # differ from Ker's --pmd-dir and may itself live under /usr/local.
        sidecar_prefix = args.virtio_testpmd.parent.parent
        sidecar_pmds = list(sidecar_prefix.glob("lib*/dpdk/pmds-*/librte_net_virtio.so"))
        if sidecar_prefix in (Path("/tmp"), Path("/usr/local")):
            readonly_inputs.append(args.virtio_testpmd.parent)
        else:
            readonly_inputs.append(sidecar_prefix)
        for pmd in sidecar_pmds:
            readonly_inputs.append(pmd.parent.parent)
    ephemeral_filesystems(readonly_inputs, (out,))
    os.environ["TMPDIR"] = "/tmp"
    client = start_client(configure_ssh(), out / "sshd.log")
    source, nginx, manifest = prepare_source(repo, fixture, args.case)
    if args.case == "precheck":
        run("ip", "tuntap", "add", "dev", "kerprobe", "mode", "tap", "multi_queue")
        run("ip", "link", "del", "kerprobe")
        run_precheck(source, nginx, manifest, out)
    else:
        prefix = prepare_nginx_prefix(source, manifest.parent)
        if args.case == "rt12":
            prepare_data_link(client)
        else:
            prepare_serial_tap(client)
        runtime = Path(tempfile.mkdtemp(prefix=f"ker-{args.case}-", dir="/dev/shm"))
        try:
            if args.case == "gr0":
                run_gr0(repo, source, nginx, manifest, runtime, args)
            else:
                log = runtime / "kernel-and-nginx.log"
                try:
                    with capture_runtime_log(log):
                        run_c34(repo, nginx, manifest, prefix, runtime, args)
                except Exception:
                    with log.open(errors="replace") as stream:
                        sys.stderr.writelines(deque(stream, maxlen=30))
                    raise
        finally:
            shutil.copytree(runtime, out / "runtime", ignore_dangling_symlinks=True,
                            ignore=lambda directory, entries: [name for name in entries
                                if (Path(directory) / name).is_socket()])


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"F-Stack source-shell guest failed: {error}") from error
