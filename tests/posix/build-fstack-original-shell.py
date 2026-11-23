#!/usr/bin/env python3
"""Build the unchanged pinned F-Stack Nginx caller for the source shell tests."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile

SOURCE_REVISION = "646a641cfff77f4815e1e29829a09e1ed15a2999"
DPDK_REVISION = "d129414711aa7c4954f997acf4c54338574a7d92"
NGINX_SOURCE = Path("app/nginx-1.28.0")
FAULT_SYMBOLS = (
    "ff_reload_fault_is",
    "ff_reload_fault_is_once",
)
FF_HEADERS = (
    "fstack-address-policy/ff_api.h",
    "fstack-address-policy/ff_errno.h",
    "fstack-address-policy/ff_event.h",
    "fstack-flow-map/ff_flow_map.h",
    "fstack-ipc/ff_msg.h",
    "fstack-ipc/ff_reload.h",
    "fstack-reload/ff_config.h",
    "fstack-reload/ff_log.h",
)


def output(command, **kwargs):
    return subprocess.check_output(command, text=True, **kwargs).strip()


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def require_unchanged_source(source):
    if (output(["git", "-C", source, "rev-parse", "HEAD"]) != SOURCE_REVISION
            or output(["git", "-C", source, "status", "--porcelain", "--untracked-files=no"])):
        raise ValueError(f"{source} must be an unchanged checkout of F-Stack {SOURCE_REVISION}")


def require_pinned_dpdk(build):
    info = json.loads((build / "meson-info/meson-info.json").read_text())
    source = Path(info["directories"]["source"])
    if (output(["git", "-C", source, "rev-parse", "HEAD"]) != DPDK_REVISION
            or output(["git", "-C", source, "status", "--porcelain", "--untracked-files=no"])):
        raise ValueError(f"{build} must be built from unchanged DPDK {DPDK_REVISION}")


def recorded_command(command, log, *, cwd, env):
    print(f"$ {shlex.join(map(str, command))}", file=log, flush=True)
    subprocess.run(command, cwd=cwd, env=env, stdout=log,
                   stderr=subprocess.STDOUT, check=True)


def symbol_table(elf):
    symbols = {}
    for line in output(["nm", "--defined-only", elf]).splitlines():
        fields = line.split()
        if len(fields) == 3:
            symbols[fields[2]] = fields[0]
    return symbols


def fork_return_pc(binary, symbol):
    disassembly = output(["objdump", "-d", f"--disassemble={symbol}", binary])
    matches = re.findall(r"\bcallq?\s+[^\n]*<fork@plt>[^\n]*\n\s*([\da-f]+):",
                         disassembly)
    if len(matches) != 1:
        raise ValueError(f"{symbol} must have one direct fork call in {binary}")
    return "0x" + matches[0]


def build_caller(args, source, stage, log):
    nginx = source / NGINX_SOURCE
    binary = nginx / "objs/nginx"
    ff_lib = stage / "ff/lib"
    prefix = stage / "nginx-prefix"
    ff_lib.mkdir(parents=True)
    prefix.mkdir()
    scratch = stage / "tmp"
    scratch.mkdir()
    for name in FF_HEADERS:
        header = args.repo / "third_party" / name
        (ff_lib / header.name).symlink_to(header)
    (ff_lib / "libfstack.so").symlink_to(args.runtime)
    shim = ff_lib / "libker-fstack-nginx-worker-shim.so"
    env = {
        **os.environ,
        "CC": str(args.cc),
        "LC_ALL": "C",
        "TMPDIR": str(scratch),
        "FF_PATH": str(ff_lib.parent),
        "KER_NGINX_ADDON_FSTACK_ROOT": str(source),
        "KER_NGINX_ADDON_BUILD_DIR": str(args.runtime.parent),
        "KER_NGINX_ADDON_SHIM": str(shim),
    }
    if args.dpdk_pkgconfig:
        env["PKG_CONFIG_PATH"] = os.pathsep.join(filter(None, (
            str(args.dpdk_pkgconfig), env.get("PKG_CONFIG_PATH"))))
    configure = [
        "/bin/sh", "./configure", "--with-ff_module", "--with-debug",
        "--without-http_rewrite_module", "--without-http_gzip_module",
        f"--prefix={prefix}", f"--with-ld-opt=-L{ff_lib} -Wl,-rpath,{ff_lib}",
    ]
    make = [args.make, f"-j{args.jobs}"]
    includes = (
        nginx / "src/core", nginx / "src/event", nginx / "src/event/modules",
        nginx / "src/os/unix", nginx / "objs", args.repo / "include",
        args.repo / "third_party/fstack-address-policy",
        args.repo / "third_party/fstack-flow-map",
    )

    def compile_shim(build_id, daemon_pc, respawn_pc, worker):
        command = [
            args.cc, "-std=c11", "-fPIC", "-shared", "-Wall", "-Wextra", "-Werror",
            "-Wl,--no-undefined", "-Wl,-soname,libker-fstack-nginx-worker-shim.so",
            f'-DKER_FSTACK_NGINX_EXPECTED_BUILD_ID="{build_id}"',
            f"-DKER_FSTACK_NGINX_DAEMON_FORK_RETURN_PC={daemon_pc}",
            f"-DKER_FSTACK_NGINX_RESPAWN_FORK_RETURN_PC={respawn_pc}",
            f"-DKER_FSTACK_NGINX_WORKER_PROCESS_ADDRESS={worker}",
            *[f"-I{include}" for include in includes], "-o", shim,
            args.repo / "src/posix/fstack-nginx-multiworker-shim.c", "-ldl",
        ]
        recorded_command(command, log, cwd=nginx, env=env)

    recorded_command(configure, log, cwd=nginx, env=env)
    compile_shim("BOOTSTRAP_NEVER_EXECUTED", "0", "0", "0")
    recorded_command([*configure, f"--add-module={args.repo / 'tools/nginx-source-addon'}"],
                     log, cwd=nginx, env=env)
    recorded_command(make, log, cwd=nginx, env=env)
    first = stage / "nginx-first.elf"
    shutil.copyfile(binary, first)
    build_ids = re.findall(r"Build ID: ([0-9a-f]+)", output(["readelf", "-n", first]))
    if len(build_ids) != 1:
        raise ValueError(f"{first} must have one ELF build ID")
    worker = symbol_table(first).get("ngx_worker_process_cycle")
    if worker is None or not re.fullmatch(r"[0-9a-fA-F]+", worker):
        raise ValueError(f"{first} must define ngx_worker_process_cycle")
    compile_shim(build_ids[0], fork_return_pc(first, "ngx_daemon"),
                 fork_return_pc(first, "ngx_spawn_process"), "0x" + worker)
    binary.unlink()
    recorded_command(make, log, cwd=nginx, env=env)
    if digest(binary) != digest(first):
        raise ValueError("relink with the ABI-matched shim changed the Nginx ELF")
    return binary


def capture_manifest(args, source, binary, build_log, stage):
    symbols = symbol_table(args.runtime)
    present = [symbol for symbol in FAULT_SYMBOLS if symbol in symbols]
    if present != (list(FAULT_SYMBOLS) if args.fault else []):
        raise ValueError(f"{args.runtime} has unexpected fault hooks: {present}")
    if args.fault:
        commands = output([args.ninja, "-C", args.runtime.parent, "-t", "commands",
                           "ker-fstack-nginx-fault-test-runtime"]).splitlines()
        fault_commands = [cmd for cmd in commands if "-DFF_RELOAD_FAULT_INJECTION=1" in shlex.split(cmd)]
        if not fault_commands:
            raise ValueError("fault runtime compilation evidence is missing")
    else:
        fault_commands = []

    with build_log.open() as stream:
        collapsed = stream.read().replace("\\\n", " ")
    link = next((line.strip() for line in reversed(collapsed.splitlines())
                 if re.match(r"^\s*\S+\s+-o\s+objs/nginx\s", line)), None)
    if link is None:
        raise ValueError("successful Nginx link command is missing from its build log")
    link_receipt = stage / "link-receipt.txt"
    link_receipt.write_text(link + "\n" + f"{build_log} sha256={digest(build_log)}\n")

    checker = source / "tests/integration/common/reload_checks.py"
    spec = importlib.util.spec_from_file_location("reload_checks", checker)
    checks = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checks)
    files = [checks.source_record(path) for path in sorted(checks.production_sources(source))]
    nginx_sha = digest(binary)
    runtime_sha = digest(args.runtime)
    manifest = stage / "build.json"
    manifest.write_text(json.dumps({
        "version": 1,
        "source_head": SOURCE_REVISION,
        "fault_injection": args.fault,
        "fault_symbols": present,
        "zc_recv": False,
        "zc_send": False,
        "build_commands": [link, *fault_commands],
        "source_files": files,
        "nginx": {"path": str(binary), "sha256": nginx_sha},
        "libfstack": {"path": str(args.runtime), "sha256": runtime_sha},
        "build_log": {"path": str(link_receipt), "sha256": digest(link_receipt)},
        "link_record": {
            "command": link, "source_files": files, "exit_code": 0,
            "nginx_sha256": nginx_sha, "libfstack_sha256": runtime_sha,
        },
    }, indent=2) + "\n")
    checks.verify_build(manifest, binary, SOURCE_REVISION, fault="ready_never" if args.fault else "")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("repo", "source", "runtime", "output"):
        parser.add_argument(f"--{flag}", type=Path, required=True)
    parser.add_argument("--dpdk-build", type=Path, required=True)
    parser.add_argument("--dpdk-pkgconfig", type=Path)
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--make", default="make")
    parser.add_argument("--ninja", default="ninja")
    parser.add_argument("--jobs", type=int, default=min(8, len(os.sched_getaffinity(0))))
    parser.add_argument("--fault", action="store_true")
    args = parser.parse_args()
    for name in ("repo", "source", "runtime", "dpdk_build"):
        setattr(args, name, getattr(args, name).resolve(strict=True))
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    require_unchanged_source(args.source)
    require_pinned_dpdk(args.dpdk_build)
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "manifest-path").unlink(missing_ok=True)
    stage = Path(tempfile.mkdtemp(prefix="build-", dir=args.output))
    source = stage / "fstack"
    build_log = stage / "build.log"
    print(f"F-Stack source-shell build log {build_log}", flush=True)
    with build_log.open("w") as log:
        # Use a fresh tree so configure and make cannot consume stale caller objects.
        recorded_command(["git", "clone", "--quiet", "--no-checkout", "--local",
                          args.source, source], log, cwd=stage, env=os.environ)
        recorded_command(["git", "-C", source, "checkout", "--quiet", "--detach",
                          SOURCE_REVISION], log, cwd=stage, env=os.environ)
        require_unchanged_source(source)
        (source / "dpdk/build").symlink_to(args.dpdk_build, target_is_directory=True)
        binary = build_caller(args, source, stage, log)
    require_unchanged_source(source)
    manifest = capture_manifest(args, source, binary, build_log, stage)
    # Publish only after the unchanged upstream checker accepts the new artifacts.
    receipt = stage / "manifest-path"
    receipt.write_text(f"{manifest}\n")
    receipt.replace(args.output / "manifest-path")
    print(manifest)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"F-Stack source-shell build failed: {error}") from error
