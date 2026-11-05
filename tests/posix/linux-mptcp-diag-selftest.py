"""Run the complete unchanged upstream MPTCP diag.sh on imported Linux."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

spec = importlib.util.spec_from_file_location('diag_transport', Path(__file__).with_name('linux-mptcp-diag-shim.py'))
transport = importlib.util.module_from_spec(spec); spec.loader.exec_module(transport)
spec = importlib.util.spec_from_file_location('socket_runner', Path(__file__).with_name('linux-mptcp-socket-selftest.py'))
socket_runner = importlib.util.module_from_spec(spec); spec.loader.exec_module(socket_runner)


def require(value, message):
    if not value:
        raise RuntimeError(message)


def tap_result(output):
    plan = re.findall(r'^1\.\.(\d+)$', output, re.M)
    cases = re.findall(r'^ok (\d+) - (.+?) # time=\d+ms$', output, re.M)
    require(plan == ['29'] and [int(number) for number, _ in cases] == list(range(1, 30)), 'incomplete upstream diag TAP')
    require(not re.search(r'^(not ok |.*# (?:SKIP|IGNORE|TODO))', output, re.M), 'failed or skipped upstream diagnostic')
    return [name for _, name in cases]


def validate_counts(counts):
    require(counts['mptcp'] == 403 and counts['accepts'] == 202 and counts['live'] == 0 and counts['max_live'] >= 200,
            'full native concurrency/connection matrix did not execute')
    require(counts['negotiated'] == 402 and counts['fallback'] == 1 and counts['netlinks'] >= 27 and
            counts['diag_sends'] >= counts['netlinks'] and counts['diag_receives'] >= counts['diag_sends'],
            'native negotiation/fallback/diagnostic activity missing')
    require(counts['namespaces_created'] == counts['namespaces_deleted'] == 2, 'native namespace cleanup incomplete')


def kill_tree(pid):
    """GNU timeout creates child process groups. Stop each owned parent before
    walking its children, then signal stable pidfds, including those groups."""
    handles = []
    deadline = time.monotonic() + 3

    def freeze(target):
        try:
            handle = os.pidfd_open(target)
        except ProcessLookupError:
            return
        handles.append(handle)
        try:
            signal.pidfd_send_signal(handle, signal.SIGSTOP)
            while True:
                state = Path(f'/proc/{target}/stat').read_text().rsplit(') ', 1)[1].split()[0]
                if state in ('T', 't', 'Z'):
                    break
                require(time.monotonic() < deadline, 'owned test process did not stop for cleanup')
                time.sleep(0.001)
            children = Path(f'/proc/{target}/task/{target}/children').read_text().split()
        except (ProcessLookupError, FileNotFoundError):
            return
        for child in children:
            freeze(int(child))

    try:
        freeze(pid)
    finally:
        for handle in reversed(handles):
            try:
                signal.pidfd_send_signal(handle, signal.SIGKILL)
            except ProcessLookupError:
                pass
            finally:
                os.close(handle)


def main():
    parser = argparse.ArgumentParser()
    for name in ('server', 'binary', 'preload', 'tools', 'launcher', 'library', 'worker', 'pmd_dir', 'manifest', 'evidence'):
        parser.add_argument('--' + name.replace('_', '-'), type=Path, required=True)
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    if not args.inside:
        return subprocess.run(['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()), *sys.argv[1:], '--inside']).returncode
    manifest = json.loads(args.manifest.read_text())
    source = Path(manifest['source']) / 'tools/testing/selftests/net'
    originals = {}
    for name in ('mptcp/diag.sh', 'mptcp/mptcp_lib.sh', 'mptcp/mptcp_connect.c', 'mptcp/Makefile', 'lib.sh', 'net_helper.sh'):
        original = subprocess.check_output(['git', '-C', manifest['source'], 'show', manifest['linux']['revision'] + ':tools/testing/selftests/net/' + name])
        require((source / name).read_bytes() == original, 'modified upstream source: ' + name)
        originals[name] = original
    report = dict(status='FAIL', revision=manifest['linux']['revision'], fingerprint=manifest['fingerprint'],
        source_hashes={name: hashlib.sha256(data).hexdigest() for name, data in originals.items()},
        binary_sha256=hashlib.sha256(args.binary.read_bytes()).hexdigest(),
        preload_sha256=hashlib.sha256(args.preload.read_bytes()).hexdigest(),
        library_sha256=hashlib.sha256(args.library.read_bytes()).hexdigest())
    bins = None
    try:
        tools = json.loads((args.tools / 'provenance.json').read_text())
        require(tools['version'] == '6.12.0' and tools['archive_sha256'] ==
                'bbd141ef7b5d0127cc2152843ba61f274dc32814fa3e0f13e7d07a080bef53d9', 'wrong iproute2 pin')
        for name in ('ss', 'nstat'):
            require(hashlib.sha256((args.tools / name).read_bytes()).hexdigest() == tools['binaries'][name], 'modified iproute2 binary')
        report['iproute2'] = tools
        for command in (['ip', 'link', 'set', 'lo', 'up'],
            ['ip', 'link', 'add', 'kerhost', 'type', 'veth', 'peer', 'name', 'kerlink'],
            ['ip', 'tuntap', 'add', 'dev', 'kerpeer', 'mode', 'tap', 'multi_queue'],
            *[['ip', 'link', 'set', name, 'up'] for name in ('kerhost', 'kerlink', 'kerpeer')]):
            subprocess.run(command, check=True)
        cpu = min(os.sched_getaffinity(0))
        eal = (f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry --iova-mode=va -m 64 '
               f'-d {shlex.quote(str(args.pmd_dir / "librte_net_tap.so"))} --vdev=net_tap0,iface=kerpeer,remote=kerlink')
        environment = {k: v for k, v in os.environ.items() if k != 'LD_PRELOAD' and
            not k.startswith(('KER_', 'PROC_', 'NSTAT_', 'SELFTESTS_MPTCP_', 'MPTCP_LIB_')) and k != 'TCPDIAG_FILE'}
        environment.update(SELFTESTS_MPTCP_LIB_EXPECT_ALL_FEATURES='1', SELFTESTS_MPTCP_LIB_OVERRIDE_FLAKY='1', NO_COLOR='1')
        bins = Path(tempfile.mkdtemp(prefix='ker-mptcp-diag-bin-', dir=args.binary.resolve().parent))
        shim = Path(__file__).with_name('linux-mptcp-diag-shim.py').read_text()
        for name in ('ip', 'ss'):
            (bins / name).write_text('#!' + sys.executable + '\n' + shim)
            (bins / name).chmod(0o700)
        with tempfile.TemporaryDirectory(prefix='ker-mptcp-diag-', dir='/dev/shm') as temporary:
            root = Path(temporary); work = root / 'net/mptcp'; work.mkdir(parents=True)
            for name, data in originals.items(): (root / 'net' / name).write_bytes(data)
            (work / 'mptcp_connect').symlink_to(args.binary)
            channel, stats, counts_file = root / 'socket', root / 'stats.json', root / 'counts.json'
            environment.update(KER_MPTCP_SOCKET_CHANNEL=str(channel), KER_MPTCP_DIAG_PRELOAD=str(args.preload),
                KER_MPTCP_DIAG_SS=str(args.tools / 'ss'), KER_MPTCP_DIAG_NSTAT=str(args.tools / 'nstat'),
                KER_MPTCP_DIAG_REAL_IP=shutil.which('ip'), PATH=str(bins) + os.pathsep + environment['PATH'])
            os.environ['KER_MPTCP_SOCKET_CHANNEL'] = str(channel)
            out = (root / 'server.stdout').open('w+'); err = (root / 'server.stderr').open('w+')
            process = subprocess.Popen([sys.executable, str(args.launcher), '--library', str(args.library),
                '--io-worker', str(args.worker), '--address', '198.18.0.2/24', '--port', 'net_tap0', '--eal', eal,
                '--stats', str(stats), '--', str(args.server), str(channel), str(counts_file)],
                env=environment, stdout=out, stderr=err, start_new_session=True)
            try:
                deadline = time.monotonic() + 20
                while not channel.exists():
                    require(process.poll() is None and time.monotonic() < deadline, 'resident kernel startup failed')
                    time.sleep(0.01)
                require(transport.rpc(transport.FILE, '', '/proc/sys/net/mptcp/enabled').strip() == b'1', 'native MPTCP disabled')
                # A real second namespace both tests isolation and leaves a
                # genuine nonmatching entry for upstream cleanup_ns's grep -v.
                # No namespace listing or diagnostic result is synthesized.
                control = 'diag-isolation-control'
                transport.rpc(transport.NEWNS, control)
                observation, errors = [], []
                finished = threading.Event()

                def observe_isolation():
                    try:
                        while not finished.wait(0.05):
                            status = json.loads(transport.rpc(transport.STATUS))
                            if status['live'] < 200:
                                continue
                            protocols = transport.rpc(transport.FILE, control, '/proc/net/protocols').decode()
                            inuse = [int(line.split()[2]) for line in protocols.splitlines() if line.split()[:1] == ['MPTCP']]
                            require(inuse == [0], 'proc counters leaked across native namespaces')
                            other = subprocess.run([str(args.tools / 'ss'), '-inHM'], capture_output=True, text=True,
                                env=dict(environment, LD_PRELOAD=str(args.preload), KER_MPTCP_SOCKET_NAMESPACE=control), timeout=5)
                            require(other.returncode == 0 and not other.stdout.strip(), 'socket diagnostics leaked across native namespaces')
                            observation.append(dict(active_native_sockets=status['live'], mptcp_inuse=inuse[0],
                                ss_returncode=other.returncode, ss_stdout=other.stdout, ss_stderr=other.stderr))
                            return
                    except BaseException as error:
                        errors.append(str(error))

                result = subprocess.Popen(['bash', './diag.sh'], cwd=work, env=environment, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True, start_new_session=True)
                observer = threading.Thread(target=observe_isolation)
                observer.start()
                try:
                    stdout, stderr = result.communicate(timeout=220)
                except BaseException:
                    kill_tree(result.pid); stdout, stderr = result.communicate()
                    report.update(stdout=stdout, stderr=stderr); raise
                finally:
                    finished.set(); observer.join(timeout=7)
                report.update(returncode=result.returncode, stdout=stdout, stderr=stderr)
                report['namespace_isolation_control'] = observation
                require(not observer.is_alive() and not errors and observation, 'namespace isolation control failed: ' + repr(errors))
                require(result.returncode == 0, 'original diag script failed: ' + stdout + stderr)
                report['cases'] = tap_result(stdout)
                require(transport.rpc(transport.LISTNS).decode().splitlines() == [control], 'original test namespace was not deleted')
                transport.rpc(transport.DELNS, control)
                require(transport.rpc(transport.LISTNS) == b'', 'control namespace was not deleted')
                deadline = time.monotonic() + 5
                while json.loads(transport.rpc(transport.STATUS))['live']:
                    require(time.monotonic() < deadline, 'native diagnostic sockets leaked')
                    time.sleep(0.01)
                socket_runner.stop(channel)
                require(process.wait(timeout=20) == 0, 'native kernel/worker shutdown failed')
                counts = json.loads(counts_file.read_text()); report['native_fixture'] = counts
                validate_counts(counts)
                report['stats'] = json.loads(stats.read_text())
                require(report['stats'].get('outstanding') == 0, 'packet ownership did not settle')
                for name, data in originals.items():
                    require((source / name).read_bytes() == data and (root / 'net' / name).read_bytes() == data, 'upstream source changed')
                report['status'] = 'PASS_IMPORTED_LINUX'
                print('LINUX_ORIGINAL_MPTCP_DIAG_PASS', len(report['cases']))
                return 0
            finally:
                if process.poll() is None:
                    kill_tree(process.pid); process.wait()
                for stream, name in ((out, 'server_stdout'), (err, 'server_stderr')):
                    stream.flush(); stream.seek(0); report[name] = stream.read(); stream.close()
    except BaseException as error:
        report['error'] = str(error)
        raise
    finally:
        if bins is not None: shutil.rmtree(bins)
        args.evidence.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        sys.exit('Linux MPTCP diagnostic selftest failed: ' + str(error))
