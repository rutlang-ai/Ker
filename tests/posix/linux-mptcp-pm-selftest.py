"""Run unchanged pm_netlink.sh and pm_nl_ctl against one imported Linux instance."""
import argparse
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

spec = importlib.util.spec_from_file_location('pm_scaffold', Path(__file__).with_name('linux-mptcp-pm-ip.py'))
scaffold = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scaffold)


def require(value, message):
    if not value:
        raise RuntimeError(message)


def tap_result(output):
    plan = re.findall(r'^1\.\.(\d+)$', output, re.M)
    cases = re.findall(r'^ok (\d+) - (.+?) # time=\d+ms$', output, re.M)
    require(plan == ['23'], 'missing or incomplete upstream TAP plan')
    require([int(i) for i, _ in cases] == list(range(1, int(plan[0]) + 1)), 'incomplete or failing upstream TAP')
    require(not re.search(r'^(not ok |.*# (?:SKIP|IGNORE|TODO))', output, re.M), 'failed or skipped upstream test')
    return [name for _, name in cases]


def command(args, work, environment):
    return subprocess.run(args, cwd=work, env=environment, capture_output=True, text=True, timeout=10)


def run_script(args, work, environment, timeout):
    process = subprocess.Popen(args, cwd=work, env=environment, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate()
        raise
    return subprocess.CompletedProcess(args, process.returncode, stdout, stderr)


def main():
    parser = argparse.ArgumentParser()
    for name in ('server', 'binary', 'launcher', 'library', 'worker', 'pmd_dir', 'manifest', 'evidence'):
        parser.add_argument('--' + name.replace('_', '-'), type=Path, required=True)
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    if not args.inside:
        return subprocess.run(['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()),
                               *sys.argv[1:], '--inside']).returncode
    manifest = json.loads(args.manifest.read_text())
    source = Path(manifest['source']) / 'tools/testing/selftests/net'
    files = ('mptcp/pm_netlink.sh', 'mptcp/mptcp_lib.sh', 'mptcp/pm_nl_ctl.c', 'mptcp/Makefile',
             'lib.sh', 'net_helper.sh')
    originals = {}
    for name in files:
        original = subprocess.check_output(['git', '-C', manifest['source'], 'show',
            manifest['linux']['revision'] + ':tools/testing/selftests/net/' + name])
        require((source / name).read_bytes() == original, 'modified original Linux file: ' + name)
        originals[name] = original
    report = dict(status='FAIL', revision=manifest['linux']['revision'], fingerprint=manifest['fingerprint'],
                  source_hashes={k: hashlib.sha256(v).hexdigest() for k, v in originals.items()},
                  binary_sha256=hashlib.sha256(args.binary.read_bytes()).hexdigest(),
                  library_sha256=hashlib.sha256(args.library.read_bytes()).hexdigest(),
                  server_sha256=hashlib.sha256(args.server.read_bytes()).hexdigest())
    try:
        for cmd in (['ip', 'link', 'set', 'lo', 'up'],
            ['ip', 'link', 'add', 'kerhost', 'type', 'veth', 'peer', 'name', 'kerlink'],
            ['ip', 'tuntap', 'add', 'dev', 'kerpeer', 'mode', 'tap', 'multi_queue'],
            *[['ip', 'link', 'set', n, 'up'] for n in ('kerhost', 'kerlink', 'kerpeer')]):
            subprocess.run(cmd, check=True)
        cpu = min(os.sched_getaffinity(0))
        eal = (f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry --iova-mode=va -m 64 '
               f'-d {shlex.quote(str(args.pmd_dir / "librte_net_tap.so"))} --vdev=net_tap0,iface=kerpeer,remote=kerlink')
        environment = {k: v for k, v in os.environ.items() if k != 'LD_PRELOAD' and not k.startswith(('KER_', 'SELFTESTS_MPTCP_', 'MPTCP_LIB_'))}
        environment.update(SELFTESTS_MPTCP_LIB_EXPECT_ALL_FEATURES='1', SELFTESTS_MPTCP_LIB_OVERRIDE_FLAKY='1', NO_COLOR='1')
        with tempfile.TemporaryDirectory(prefix='ker-mptcp-pm-', dir='/dev/shm') as temporary:
            root = Path(temporary)
            work = root / 'net/mptcp'; work.mkdir(parents=True)
            for name, data in originals.items():
                path = root / 'net' / name; path.write_bytes(data)
            (work / 'pm_nl_ctl').symlink_to(args.binary)
            bin_dir = root / 'bin'; bin_dir.mkdir()
            shim = bin_dir / 'ip'
            shim.write_text('#!' + sys.executable + '\n' + Path(__file__).with_name('linux-mptcp-pm-ip.py').read_text())
            shim.chmod(0o700)
            environment.update(KER_MPTCP_PM_REAL_IP=shutil.which('ip'), KER_MPTCP_PM_SOCKET=str(root / 'pm.sock'),
                               PATH=str(bin_dir) + os.pathsep + environment['PATH'])
            os.environ['KER_MPTCP_PM_SOCKET'] = environment['KER_MPTCP_PM_SOCKET']
            stats = root / 'stats.json'
            server_stdout = (root / 'server.stdout').open('w+')
            server_stderr = (root / 'server.stderr').open('w+')
            process = subprocess.Popen([sys.executable, str(args.launcher), '--library', str(args.library),
                '--io-worker', str(args.worker), '--address', '198.18.0.2/24', '--port', 'net_tap0', '--eal', eal,
                '--stats', str(stats), '--', str(args.server), environment['KER_MPTCP_PM_SOCKET']],
                env=environment, stdout=server_stdout, stderr=server_stderr, start_new_session=True)
            try:
                deadline = time.monotonic() + 20
                while True:
                    try:
                        probe = scaffold.rpc(scaffold.PROBE)
                        break
                    except (FileNotFoundError, ConnectionRefusedError):
                        require(process.poll() is None and time.monotonic() < deadline, 'native PM fixture startup failed')
                        time.sleep(0.01)
                require(probe.strip() == b'1', 'imported kernel has no enabled MPTCP')
                report['native_mptcp_probe'] = probe.decode()
                try:
                    scaffold.rpc(0xffff)
                except OSError as error:
                    require(error.errno == errno.EOPNOTSUPP, 'wrong unsupported-fixture error')
                else:
                    raise RuntimeError('unsupported fixture operation reported success')
                report['unsupported_operation_control'] = 'EOPNOTSUPP'
                with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as bad:
                    bad.settimeout(2)
                    bad.connect(environment['KER_MPTCP_PM_SOCKET'])
                    bad.sendall(scaffold.HEADER.pack(scaffold.MAGIC + 1, scaffold.STOP, 0, 0, 0, 0, 0))
                    require(bad.recv(1) == b'', 'malformed transport frame was accepted')
                require(scaffold.rpc(scaffold.PROBE).strip() == b'1', 'malformed frame stopped native fixture')
                report['malformed_frame_control'] = 'rejected_without_state_change'

                rejected = command([str(args.binary), 'limits'], work,
                    dict(environment, KER_MPTCP_PM_NAMESPACE='', KER_MPTCP_PM_SOCKET=str(root / 'absent.sock')))
                require(rejected.returncode != 0, 'missing native fixture silently fell back to host Netlink')
                report['missing_backend_control'] = dict(returncode=rejected.returncode, stderr=rejected.stderr)
                result = run_script(['bash', './pm_netlink.sh'], work, environment, timeout=150)
                report.update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
                require(result.returncode == 0, 'original PM script failed: ' + result.stdout + result.stderr)
                report['cases'] = tap_result(result.stdout)
                # Separate real namespaces must not share the original kernel PM endpoint table.
                for ns in ('pm-control-a', 'pm-control-b'):
                    scaffold.text(scaffold.NEWNS, ns)
                first = command([str(args.binary), 'add', '10.77.0.1'], work,
                                dict(environment, KER_MPTCP_PM_NAMESPACE='pm-control-a'))
                require(first.returncode == 0, 'namespace control add failed: ' + first.stderr)
                dumps = {}
                for ns in ('pm-control-a', 'pm-control-b'):
                    output = command([str(args.binary), 'dump'], work, dict(environment, KER_MPTCP_PM_NAMESPACE=ns))
                    require(output.returncode == 0, 'namespace control dump failed')
                    dumps[ns] = output.stdout
                require('10.77.0.1' in dumps['pm-control-a'] and not dumps['pm-control-b'], 'native PM namespace isolation lost')
                report['namespace_isolation_control'] = dumps
                for ns in ('pm-control-a', 'pm-control-b'):
                    scaffold.text(scaffold.DELNS, ns)
                deadline = time.monotonic() + 5
                while True:
                    counts = json.loads(scaffold.rpc(scaffold.STATUS))
                    if not counts['live_netlink']:
                        break
                    require(time.monotonic() < deadline, 'native Netlink clients leaked')
                    time.sleep(0.005)
                counts = json.loads(scaffold.rpc(scaffold.STOP)); report['native_fixture'] = counts
                require(counts['created'] == counts['deleted'] == 3 and counts['live_namespaces'] == counts['live_netlink'] == 0,
                        'native namespace/Netlink lifecycle did not settle')
                require(counts['sends'] >= 500 and counts['receives'] == counts['sends'] and counts['sysctls'] == 3 and counts['link_ups'] == 1,
                        'missing native PM control activity')
                require(process.wait(timeout=20) == 0, 'native PM kernel/worker shutdown failed')
                report['stats'] = json.loads(stats.read_text())
                require(report['stats'].get('outstanding') == 0, 'native packet resources did not settle')
                for name, data in originals.items():
                    require((source / name).read_bytes() == data and (root / 'net' / name).read_bytes() == data,
                            'original script/helper source changed during execution')
                report['status'] = 'PASS_IMPORTED_LINUX'
                print('LINUX_ORIGINAL_MPTCP_PM_PASS', len(report['cases']))
                return 0
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL); process.wait()
                for stream, name in ((server_stdout, 'server_stdout'), (server_stderr, 'server_stderr')):
                    stream.flush(); stream.seek(0); report[name] = stream.read(); stream.close()
    except BaseException as error:
        report['error'] = str(error)
        raise
    finally:
        args.evidence.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        print('Linux PM selftest failed: ' + str(error), file=sys.stderr)
        sys.exit(1)
