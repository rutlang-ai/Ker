#!/usr/bin/env python3
"""Run an original F-Stack source-shell test in private Linux namespaces."""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

SSH_ROOT = Path("/run/fstack-ssh")
WORKSPACE = Path("/data/workspace")
SERVER_IP = "169.254.28.1"
CLIENT_IP = "169.254.28.2"
SSH_PORT = 2222


def run(*command, **kwargs):
    return subprocess.run(command, check=True, **kwargs)


def namespace(kind):
    return os.readlink(f"/proc/self/ns/{kind}")


def ephemeral_filesystems():
    for path in ("/data", "/run", "/tmp", "/dev/hugepages", "/dev/shm", "/usr/local"):
        run("mount", "-t", "tmpfs", "tmpfs", path)
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


def prepare_source(repo, fixture):
    manifest = Path((fixture / "manifest-path").read_text().strip()).resolve(strict=True)
    if not manifest.is_relative_to(fixture):
        raise RuntimeError("source-shell fixture manifest is outside its build tree")
    build = json.loads(manifest.read_text())
    source = manifest.parent / "fstack"
    nginx = source / "app/nginx-1.28.0/objs/nginx"
    if build["nginx"]["path"] != str(nginx) or build["fault_injection"] is not False:
        raise RuntimeError("the original case requires the production source-shell fixture")

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


def prepare_serial_tap(client):
    enter = ["nsenter", "-t", str(client), "-n"]
    run("ip", "link", "add", "kerlink", "type", "veth", "peer", "name", "kertraffic")
    run("ip", "link", "set", "kerlink", "up")
    run("ip", "link", "set", "kertraffic", "netns", str(client))
    run(*enter, "ip", "addr", "add", "198.18.0.1/24", "dev", "kertraffic")
    run(*enter, "ip", "link", "set", "kertraffic", "up")
    run("ip", "tuntap", "add", "dev", "kerpeer", "mode", "tap", "multi_queue")
    run("ip", "link", "set", "kerpeer", "up")


def run_gr0(repo, source, nginx, manifest, run_dir, args):
    from ker_serial_generation import InnerLaunch, SerialGenerationController
    from nginx_cycle_control import NginxCycleControl
    import nginx_source_origin as origin
    from nginx_source_scope import CapturedScopeRoot, SourceScopeCapsules

    prefix = manifest.parent / "nginx-prefix"
    for name in ("html", "logs"):
        (prefix / name).mkdir(exist_ok=True)
    shutil.copyfile(source / "app/nginx-1.28.0/html/index.html", prefix / "html/index.html")

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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--case", choices=("precheck", "gr0"), required=True)
    for name in ("library", "worker", "broker", "pmd-dir"):
        parser.add_argument(f"--{name}", type=Path)
    parser.add_argument("--parent-namespaces", nargs=3)
    args = parser.parse_args()
    repo = args.repo.resolve(strict=True)
    fixture = args.fixture.resolve(strict=True)
    out = args.output.resolve()
    inputs = {}
    if args.case == "gr0":
        for name in ("library", "worker", "broker", "pmd_dir"):
            path = getattr(args, name)
            if path is None:
                parser.error(f"gr0 requires --{name.replace('_', '-')}")
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
    ephemeral_filesystems()
    os.environ["TMPDIR"] = "/tmp"
    client = start_client(configure_ssh(), out / "sshd.log")
    source, nginx, manifest = prepare_source(repo, fixture)
    if args.case == "precheck":
        run("ip", "tuntap", "add", "dev", "kerprobe", "mode", "tap", "multi_queue")
        run("ip", "link", "del", "kerprobe")
        run_precheck(source, nginx, manifest, out)
    else:
        prepare_serial_tap(client)
        runtime = Path(tempfile.mkdtemp(prefix="ker-gr0-", dir="/dev/shm"))
        try:
            run_gr0(repo, source, nginx, manifest, runtime, args)
        finally:
            shutil.copytree(runtime, out / "runtime", ignore_dangling_symlinks=True,
                            ignore=lambda directory, entries: [name for name in entries
                                if (Path(directory) / name).is_socket()])


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"F-Stack source-shell guest failed: {error}") from error
