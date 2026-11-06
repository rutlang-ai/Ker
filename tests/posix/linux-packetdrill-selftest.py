"""Run all unchanged pinned Linux packetdrill entries on imported Linux."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import re
import shlex
import subprocess
import sys
import tempfile
import time


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


fixture = load('packetdrill_fixture', 'linux-mptcp-socket-selftest.py')
cleanup = load('packetdrill_cleanup', 'linux-mptcp-diag-selftest.py')
wire = load('packetdrill_wire', 'linux-mptcp-diag-shim.py')
tap = load('packetdrill_tap', 'linux-unix-selftest.py')
require = fixture.require
TOOL_REVISION = '8051382e6ac928c4c13a88b34832649d9b07abc2'


def main():
    parser = argparse.ArgumentParser()
    for name in ('server', 'preload', 'diag_preload', 'tool', 'iproute', 'launcher', 'library',
                 'worker', 'pmd_dir', 'manifest', 'evidence'):
        parser.add_argument('--' + name.replace('_', '-'), type=Path, required=True)
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    if not args.inside:
        return subprocess.run(['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()),
                               *sys.argv[1:], '--inside']).returncode
    manifest = json.loads(args.manifest.read_text())
    require(manifest.get('config_fragment') == 'config/native-linux-packetdrill.config',
            'packetdrill requires its fingerprinted TUN/FQ kernel')
    provenance = json.loads(args.tool.with_name('provenance.json').read_text())
    require(provenance['revision'] == TOOL_REVISION and
            provenance['binary_sha256'] == hashlib.sha256(args.tool.read_bytes()).hexdigest(),
            'packetdrill tool provenance mismatch')
    source = Path(manifest['source']); suite = source / 'tools/testing/selftests/net/packetdrill'
    scripts = sorted(suite.glob('*.pkt'))
    require(len(scripts) == 24, 'incomplete pinned packetdrill default entries')
    originals = {}
    for path in [*sorted(p for p in suite.iterdir() if p.is_file()),
                 source / 'tools/testing/selftests/kselftest/ktap_helpers.sh']:
        relative = str(path.relative_to(source))
        original = subprocess.check_output(['git', '-C', str(source), 'show',
                                            manifest['linux']['revision'] + ':' + relative])
        require(path.read_bytes() == original, 'modified upstream source: ' + relative)
        originals[relative] = original
    report = dict(status='FAIL', revision=manifest['linux']['revision'], fingerprint=manifest['fingerprint'],
                  tool_provenance=provenance, source_hashes={p: hashlib.sha256(b).hexdigest() for p, b in originals.items()},
                  binary_hashes={name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in
                                 [('server', args.server), ('preload', args.preload), ('library', args.library)]},
                  original_scripts=[], entries=[])
    environment = {k: v for k, v in os.environ.items() if k != 'LD_PRELOAD' and
                   not k.startswith('KER_') and k != 'KSFT_MACHINE_SLOW'}
    try:
        for command in (['ip', 'link', 'set', 'lo', 'up'],
                        ['ip', 'link', 'add', 'kerhost', 'type', 'veth', 'peer', 'name', 'kerlink'],
                        ['ip', 'tuntap', 'add', 'dev', 'kerpeer', 'mode', 'tap', 'multi_queue'],
                        *[['ip', 'link', 'set', name, 'up'] for name in ('kerhost', 'kerlink', 'kerpeer')]):
            subprocess.run(command, check=True)
        cpu = min(os.sched_getaffinity(0))
        eal = (f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry --iova-mode=va -m 64 '
               f'-d {shlex.quote(str(args.pmd_dir / "librte_net_tap.so"))} --vdev=net_tap0,iface=kerpeer,remote=kerlink')
        # Executables stay on the ordinary executable temporary filesystem;
        # short IPC/data paths use shm without requiring it to be executable.
        with tempfile.TemporaryDirectory(prefix='ker-packetdrill-') as executable, \
             tempfile.TemporaryDirectory(prefix='ker-pkt-', dir='/dev/shm') as ipc:
            root, ipc = Path(executable), Path(ipc)
            work = root / 'net/packetdrill'; work.mkdir(parents=True)
            for relative, original in originals.items():
                local = root / relative.removeprefix('tools/testing/selftests/')
                local.parent.mkdir(parents=True, exist_ok=True); local.write_bytes(original)
                local.chmod((source / relative).stat().st_mode & 0o777)
            bins = root / 'bin'; bins.mkdir()
            helper = Path(__file__).with_name('linux-packetdrill-command.py')
            for name in ('packetdrill', 'ip', 'tc', 'sysctl', 'cat', 'grep'):
                path = bins / name
                path.write_text('#!/bin/sh\nexec env -u LD_PRELOAD ' + shlex.quote(sys.executable) + ' ' +
                                shlex.quote(str(helper)) + ' ' + name + ' "$@"\n'); path.chmod(0o700)
            echo = Path(__file__).with_name('linux-packetdrill-echo.py')
            bash_env = root / 'bash-env'
            bash_env.write_text('echo() { env -u LD_PRELOAD ' + shlex.quote(sys.executable) + ' ' +
                                shlex.quote(str(echo)) + ' "$@"; }\n')
            config = dict(tool=str(args.tool), preload=str(args.preload), diag_preload=str(args.diag_preload),
                          iproute=str(args.iproute), bash_env=str(bash_env), entries=str(ipc / 'entries.jsonl'),
                          sysctls=str(ipc / 'sysctls.jsonl'))
            config_file = ipc / 'config.json'; config_file.write_text(json.dumps(config))
            channel, counts, stats = ipc / 'socket', ipc / 'counts.json', ipc / 'stats.json'
            environment.update(KER_MPTCP_SOCKET_CHANNEL=str(channel), KER_PACKETDRILL_CONFIG=str(config_file),
                               KER_PACKETDRILL_SYSCTL_LOG=config['sysctls'], PATH=str(bins) + os.pathsep + environment['PATH'])
            os.environ['KER_MPTCP_SOCKET_CHANNEL'] = str(channel)
            with (ipc / 'stdout').open('w+') as out, (ipc / 'stderr').open('w+') as err:
                process = subprocess.Popen([sys.executable, str(args.launcher), '--library', str(args.library),
                    '--io-worker', str(args.worker), '--address', '198.18.0.2/24', '--port', 'net_tap0', '--eal', eal,
                    '--stats', str(stats), '--', str(args.server), str(channel), str(counts)],
                    env=environment, stdout=out, stderr=err, start_new_session=True)
                try:
                    deadline = time.monotonic() + 20
                    while not channel.exists():
                        require(process.poll() is None and time.monotonic() < deadline, 'native startup failed')
                        time.sleep(0.01)
                    # The stock tool locks its address space. Keep its original
                    # mlockall and timing, but bound pthread stacks within the
                    # host's ordinary 8 MiB locked-memory allowance.
                    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
                    resource.setrlimit(resource.RLIMIT_STACK, (1024 * 1024, resource.getrlimit(resource.RLIMIT_STACK)[1]))
                    report['stack_bytes'] = 1024 * 1024
                    report['locked_memory_limit'] = resource.getrlimit(resource.RLIMIT_MEMLOCK)
                    # A malformed native proc write must fail through the same
                    # shell adapter, leaving the real kernel value unchanged.
                    wire.rpc(wire.NEWNS, 'negative'); wire.rpc(wire.UP, 'negative')
                    control_env = dict(environment, KER_MPTCP_SOCKET_NAMESPACE='negative', LD_PRELOAD=str(args.preload), BASH_ENV=str(bash_env))
                    alias = subprocess.run(['/bin/bash', '-c',
                        'exec 3>/proc/sys/net/ipv4/tcp_ecn; exec 4>&3; exec 3>&-; echo 1 >&4; exec 4>&-'],
                        env=control_env, capture_output=True, text=True, timeout=10)
                    report['proc_alias_control'] = dict(returncode=alias.returncode, stderr=alias.stderr)
                    require(alias.returncode == 0 and not alias.stderr and
                            wire.rpc(wire.FILE, 'negative', '/proc/sys/net/ipv4/tcp_ecn').strip() == b'1',
                            'closing the original proc descriptor invalidated its live Bash duplicate')
                    before = wire.rpc(wire.FILE, 'negative', '/proc/sys/net/ipv4/tcp_ecn')
                    control = subprocess.run(['/bin/bash', '-c', 'echo invalid > /proc/sys/net/ipv4/tcp_ecn'],
                                             env=control_env, capture_output=True, text=True, timeout=10)
                    report['invalid_sysctl_control'] = dict(returncode=control.returncode, stderr=control.stderr)
                    require(control.returncode != 0 and 'Invalid argument' in control.stderr and
                            wire.rpc(wire.FILE, 'negative', '/proc/sys/net/ipv4/tcp_ecn') == before,
                            'invalid native sysctl write was not rejected without mutation')
                    wire.rpc(wire.DELNS, 'negative')
                    for script in scripts:
                        child = subprocess.Popen(['bash', './ksft_runner.sh', script.name], cwd=work,
                            env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
                        try:
                            stdout, stderr = child.communicate(timeout=110)
                        except BaseException:
                            cleanup.kill_tree(child.pid); cleanup.bounded_communicate(child, timeout=5); raise
                        result = dict(script=script.name, returncode=child.returncode, stdout=stdout, stderr=stderr)
                        report['original_scripts'].append(result)
                        require(child.returncode == 0 and not stderr, 'original packetdrill failed: ' + script.name + '\n' + stderr)
                        require(len(tap.tap_result(result)) == 2, 'incomplete original IPv4/IPv6 TAP plan')
                    report['entries'] = [json.loads(line) for line in Path(config['entries']).read_text().splitlines()]
                    require(len(report['entries']) == 48 and all(x['returncode'] == 0 and not x['stderr'] for x in report['entries']),
                            'incomplete packetdrill entry matrix or hidden helper failure')
                    for script in scripts:
                        entries = [x for x in report['entries'] if x['arguments'][-1] == script.name]
                        require(len(entries) == 2 and {x['arguments'][0] for x in entries} ==
                                {'--ip_version=ipv4', '--ip_version=ipv6'}, 'missing original family configuration')
                    for entry in report['entries']:
                        lines = [line.split()[1:] for line in entry['snmp'].splitlines() if line.startswith('Tcp:')]
                        require(len(lines) == 2 and len(lines[0]) == len(lines[1]), 'missing real native TCP counters')
                        entry['native_tcp'] = dict(zip(lines[0], map(int, lines[1])))
                        require(entry['native_tcp'].get('InSegs', 0) > 0 and entry['native_tcp'].get('OutSegs', 0) > 0,
                                'packetdrill entry did not exercise native TCP packet processing')
                    report['sysctls'] = [json.loads(line) for line in Path(config['sysctls']).read_text().splitlines()]
                    require(any(x['operation'] == 'original_echo' and x['namespace'] != 'negative' for x in report['sysctls']),
                            'original sysctl set/restore did not reach native proc')
                    default_keys = set(re.findall(r'(net[./][a-z0-9_./]+)=', (suite / 'defaults.sh').read_text()))
                    require(default_keys, 'original defaults lost its sysctl contract')
                    for entry in report['entries']:
                        if './defaults.sh' not in (suite / entry['arguments'][-1]).read_text(): continue
                        keys = {row['setting'].partition('=')[0].replace('/', '.') for row in report['sysctls']
                                if row['namespace'] == entry['namespace'] and row['operation'] == 'sysctl'}
                        require(default_keys.issubset(keys), 'original default sysctl operation was omitted or failed')
                    fixture.stop(channel); require(process.wait(timeout=20) == 0, 'native shutdown failed')
                    report['native_fixture'] = native = json.loads(counts.read_text())
                    require(native['live'] == 0 and native['mptcp'] == 0 and native['raw_sockets'] > 0 and
                            native['namespaces_created'] == native['namespaces_deleted'] == 49,
                            'native packet/namespace lifecycle differs')
                    require(native.get('tun_opens') == 48 and native.get('tun_offloads', 0) >= 48 and
                            native.get('packet_timestamps', 0) > 0 and
                            all(native.get(key, 0) > 0 for key in ('epoll_creates', 'epoll_controls', 'epoll_waits')),
                            'original TUN/offload/timestamp/epoll operations did not enter Linux')
                    report['stats'] = observed = json.loads(stats.read_text())
                    require(observed.get('outstanding') == 0 and observed.get('worker_exit_code') == 0 and
                            observed.get('control_eof') is True and observed.get('shutdown_timed_out') is False,
                            'kernel/worker packet ownership did not settle')
                    buffers = observed.get('native', {})
                    require(buffers.get('buffer_allocations', 0) > 0 and buffers.get('buffers_live') == 0 and
                            buffers['buffer_allocations'] == buffers.get('buffer_releases') == buffers.get('buffer_shutdown_releases'),
                            'native zerocopy buffer lifetime did not settle')
                    for relative, original in originals.items():
                        require((source / relative).read_bytes() == original and
                                (root / relative.removeprefix('tools/testing/selftests/')).read_bytes() == original,
                                'original script changed during execution')
                    report['status'] = 'PASS_IMPORTED_LINUX'
                    print('LINUX_ORIGINAL_PACKETDRILL_PASS 24 scripts 48 family configurations')
                    return 0
                finally:
                    if process.poll() is None:
                        cleanup.kill_tree(process.pid); process.wait(timeout=10)
                    for path, key in ((Path(config['entries']), 'entries'), (Path(config['sysctls']), 'sysctls')):
                        if path.exists() and not report.get(key):
                            report[key] = [json.loads(line) for line in path.read_text().splitlines()]
                    for stream, key in ((out, 'server_stdout'), (err, 'server_stderr')):
                        stream.flush(); stream.seek(0); report[key] = stream.read()
    except BaseException as error:
        report['error'] = str(error)
        raise
    finally:
        args.evidence.parent.mkdir(parents=True, exist_ok=True)
        args.evidence.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        sys.exit('Linux packetdrill selftests failed: ' + str(error))
