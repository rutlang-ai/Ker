"""Run unchanged upstream MPTCP diagnostic/socket-option shells on imported Linux."""
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


def tap_result(output, expected=29):
    plan = re.findall(r'^1\.\.(\d+)$', output, re.M)
    cases = re.findall(r'^ok (\d+) - (.+?) # time=\d+ms$', output, re.M)
    require(plan == [str(expected)] and [int(number) for number, _ in cases] == list(range(1, expected + 1)), 'incomplete upstream MPTCP shell TAP')
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

    def process_stat(target):
        try:
            fields = Path(f'/proc/{target}/stat').read_text().rsplit(') ', 1)[1].split()
        except FileNotFoundError:
            return None
        # Fields after comm start at state (field 3): PPID is 1 and starttime
        # is 19. starttime prevents a reused PID from being mistaken for a child.
        return fields[0], int(fields[1]), fields[19]

    def direct_children(target):
        children_path = Path(f'/proc/{target}/task/{target}/children')
        try:
            pids = children_path.read_text().split()
        except FileNotFoundError:
            # Some proc mounts omit task/*/children. The frozen parent cannot
            # create more children, so recover its direct children by PPID.
            pids = []
            for entry in Path('/proc').iterdir():
                require(time.monotonic() < deadline, 'process discovery exceeded cleanup deadline')
                if not entry.name.isdecimal():
                    continue
                try:
                    fields = (entry / 'stat').read_text().rsplit(') ', 1)[1].split()
                except (FileNotFoundError, PermissionError):
                    continue
                if int(fields[1]) == target:
                    pids.append((entry.name, fields[19]))
        else:
            pids = [(child, None) for child in pids]

        result = []
        for child, starttime in pids:
            info = process_stat(int(child))
            if info is None or info[1] != target:
                continue
            if starttime is not None and info[2] != starttime:
                continue
            result.append((int(child), info[2]))
        return result

    def freeze(target, expected_starttime=None, expected_parent=None):
        try:
            handle = os.pidfd_open(target)
        except ProcessLookupError:
            return
        registered = False
        try:
            identity = process_stat(target)
            if identity is None or (expected_starttime is not None and identity[2] != expected_starttime) or \
                    (expected_parent is not None and identity[1] != expected_parent):
                return
            handles.append(handle)
            registered = True
            signal.pidfd_send_signal(handle, signal.SIGSTOP)
            while True:
                identity = process_stat(target)
                if identity is None:
                    return
                state = identity[0]
                if state in ('T', 't', 'Z'):
                    break
                require(time.monotonic() < deadline, 'owned test process did not stop for cleanup')
                time.sleep(0.001)
        except ProcessLookupError:
            return
        finally:
            if not registered:
                os.close(handle)
        for child, starttime in direct_children(target):
            freeze(child, expected_starttime=starttime, expected_parent=target)

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


def bounded_communicate(process, timeout):
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        return stdout, stderr, False
    except subprocess.TimeoutExpired as error:
        def text(value):
            if isinstance(value, bytes):
                return value.decode(errors='replace')
            return value or ''

        stdout, stderr = text(error.output), text(error.stderr)
        process.stdout.close(); process.stderr.close()
        return stdout, stderr, True


def validate_userspace_counts(counts, topology):
    require(len(topology) == 13 and
        sum(command[:2] == ['link', 'add'] for command in topology) == 1 and
        sum(command[2:4] == ['addr', 'add'] for command in topology) == 8 and
        sum(command[2:4] == ['link', 'set'] for command in topology) == 4,
        'incomplete acknowledged userspace PM topology')
    require(counts['live'] == 0 and counts['namespaces_created'] == counts['namespaces_deleted'] == 3,
        'userspace PM cleanup incomplete')
    require(counts['sendfile_calls'] >= 2 and counts['imported_files'] == counts['sendfile_calls'],
        'original sendfile inputs did not reach native Linux')
    require(counts['negotiated'] == 4 and counts['accepts'] == 2 and counts['fallback'] == 0,
        'native userspace PM negotiation missing')
    require(counts['mp_join_syn_rx'] >= 8 and counts['mp_join_ack_rx'] >= 8 and counts['netlinks'] >= 69,
        'native userspace PM subflow/event operations missing')


def main():
    parser = argparse.ArgumentParser()
    for name in ('server', 'binary', 'preload', 'tools', 'launcher', 'library', 'worker', 'pmd_dir', 'manifest', 'evidence'):
        parser.add_argument('--' + name.replace('_', '-'), type=Path, required=True)
    parser.add_argument('--suite', choices=('diag', 'sockopt', 'simult', 'userspace', 'connect', 'mmap', 'sendfile', 'checksum', 'join'), default='diag')
    for name in ('sockopt', 'inq', 'pm'):
        parser.add_argument('--' + name, type=Path)
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    if not args.inside:
        return subprocess.run(['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()), *sys.argv[1:], '--inside']).returncode
    join_suite = args.suite == 'join'
    connect_suite = args.suite in ('connect', 'mmap', 'sendfile', 'checksum', 'join')
    manifest = json.loads(args.manifest.read_text())
    source = Path(manifest['source']) / 'tools/testing/selftests/net'
    script = {'diag':'diag.sh', 'sockopt':'mptcp_sockopt.sh', 'simult':'simult_flows.sh', 'userspace':'userspace_pm.sh', 'connect':'mptcp_connect.sh', 'mmap':'mptcp_connect_mmap.sh', 'sendfile':'mptcp_connect_sendfile.sh', 'checksum':'mptcp_connect_checksum.sh', 'join':'mptcp_join.sh'}[args.suite]
    extra = () if args.suite == 'diag' else ('mptcp/mptcp_sockopt.c', 'mptcp/mptcp_inq.c', 'mptcp/pm_nl_ctl.c')
    if connect_suite and not join_suite and script != 'mptcp_connect.sh':
        extra += ('mptcp/mptcp_connect.sh',)
    originals = {}
    for name in extra + ('mptcp/' + script, 'mptcp/mptcp_lib.sh', 'mptcp/mptcp_connect.c', 'mptcp/Makefile', 'lib.sh', 'net_helper.sh'):
        original = subprocess.check_output(['git', '-C', manifest['source'], 'show', manifest['linux']['revision'] + ':tools/testing/selftests/net/' + name])
        require((source / name).read_bytes() == original, 'modified upstream source: ' + name)
        originals[name] = original
    report = dict(status='FAIL', revision=manifest['linux']['revision'], fingerprint=manifest['fingerprint'],
        source_hashes={name: hashlib.sha256(data).hexdigest() for name, data in originals.items()},
        binary_sha256=hashlib.sha256(args.binary.read_bytes()).hexdigest(),
        preload_sha256=hashlib.sha256(args.preload.read_bytes()).hexdigest(),
        library_sha256=hashlib.sha256(args.library.read_bytes()).hexdigest())
    bins = None
    if args.suite != 'diag':
        require(all(x and x.is_file() for x in (args.sockopt, args.inq, args.pm)), 'missing upstream sockopt helpers')
        report['helper_sha256'] = {name: hashlib.sha256(getattr(args, name).read_bytes()).hexdigest() for name in ('sockopt', 'inq', 'pm')}
    try:
        tools = json.loads((args.tools / 'provenance.json').read_text())
        require(tools['version'] == '6.12.0' and tools['archive_sha256'] ==
                'bbd141ef7b5d0127cc2152843ba61f274dc32814fa3e0f13e7d07a080bef53d9', 'wrong iproute2 pin')
        for name in (('ss', 'nstat', 'tc') if args.suite == 'simult' or connect_suite else ('ss', 'nstat')):
            require(hashlib.sha256((args.tools / name).read_bytes()).hexdigest() == tools['binaries'][name], 'modified iproute2 binary')
        if join_suite:
            require(hashlib.sha256((args.tools / 'ip').read_bytes()).hexdigest() == tools['binaries']['ip'], 'modified pinned iproute2 ip binary')
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
            not k.startswith(('KER_', 'PROC_', 'NSTAT_', 'SELFTESTS_MPTCP_', 'MPTCP_LIB_', 'XTABLES_')) and k != 'TCPDIAG_FILE'}
        environment.update(SELFTESTS_MPTCP_LIB_EXPECT_ALL_FEATURES='1', SELFTESTS_MPTCP_LIB_OVERRIDE_FLAKY='1', NO_COLOR='1')
        if args.suite == 'simult' or connect_suite:
            environment['KER_LINUX_SELFTEST_MEMORY_MB'] = '1024' if join_suite else '512'
        if connect_suite:
            environment['KER_LINUX_SELFTEST_REPORT_EXIT'] = '1'
        bins = Path(tempfile.mkdtemp(prefix='ker-mptcp-diag-bin-', dir=args.binary.resolve().parent))
        shim = Path(__file__).with_name('linux-mptcp-join-ip.py' if join_suite else 'linux-mptcp-connect-ip.py' if connect_suite else {'diag':'linux-mptcp-diag-shim.py', 'sockopt':'linux-mptcp-sockopt-ip.py', 'simult':'linux-mptcp-simult-ip.py', 'userspace':'linux-mptcp-sockopt-ip.py'}[args.suite]).read_text()
        for name in (('ip', 'ss', 'grep', 'tc', 'cmp', 'nstat') if connect_suite else {'diag':('ip', 'ss'), 'sockopt':('ip', 'grep'), 'simult':('ip', 'grep', 'tc'), 'userspace':('ip', 'grep')}[args.suite]):
            (bins / name).write_text('#!' + sys.executable + '\n' + shim)
            (bins / name).chmod(0o700)
        with tempfile.TemporaryDirectory(prefix='ker-mptcp-diag-', dir='/tmp' if connect_suite else '/dev/shm') as temporary:
            root = Path(temporary); work = root / 'net/mptcp'; work.mkdir(parents=True)
            if connect_suite:
                (root / 'files').mkdir()
                environment['TMPDIR'] = str(root / 'files')
            for name, data in originals.items(): (root / 'net' / name).write_bytes(data)
            if connect_suite:
                for name in originals:
                    if name.endswith('.sh'): (root / 'net' / name).chmod(0o700)
            (work / 'mptcp_connect').symlink_to(args.binary)
            if args.suite != 'diag':
                for name, binary in (('mptcp_sockopt', args.sockopt), ('mptcp_inq', args.inq), ('pm_nl_ctl', args.pm)):
                    (work / name).symlink_to(binary)
            channel, stats, counts_file = root / 'socket', root / 'stats.json', root / 'counts.json'
            environment.update(KER_MPTCP_SOCKET_CHANNEL=str(channel), KER_MPTCP_DIAG_PRELOAD=str(args.preload),
                KER_MPTCP_DIAG_SS=str(args.tools / 'ss'), KER_MPTCP_DIAG_NSTAT=str(args.tools / 'nstat'), KER_MPTCP_DIAG_IP=str(args.tools / 'ip'),
                KER_MPTCP_DIAG_REAL_IP=shutil.which('ip'), PATH=str(bins) + os.pathsep + environment['PATH'])
            if args.suite != 'diag':
                environment.update(KER_MPTCP_IPTABLES=shutil.which('iptables-legacy'), KER_MPTCP_IP6TABLES=shutil.which('ip6tables-legacy'),
                    KER_MPTCP_TOPOLOGY_LOG=str(root / 'topology.jsonl'), XTABLES_LOCKFILE=str(root / 'xtables.lock'), KER_MPTCP_REAL_GREP=shutil.which('grep'), KER_MPTCP_FIXTURE_SOURCE=str(Path(__file__).resolve().parent))
                require(environment['KER_MPTCP_IPTABLES'] and environment['KER_MPTCP_IP6TABLES'], 'legacy iptables tools unavailable')
                environment.update(KER_MPTCP_DIAG_TC=str(args.tools / 'tc'), KER_MPTCP_NETEM_LOG=str(root / 'netem.jsonl'))
                report['netfilter_tools'] = {}
                for name in ('iptables', 'ip6tables'):
                    program = environment['KER_MPTCP_' + name.upper()]
                    (bins / name).symlink_to(program)
                    version = subprocess.check_output([program, '--version'], text=True).strip()
                    require('(legacy)' in version, 'expected original legacy netfilter tool')
                    report['netfilter_tools'][name] = dict(path=program, version=version, sha256=hashlib.sha256(Path(program).read_bytes()).hexdigest())
            if connect_suite:
                environment['KER_MPTCP_CONNECT_LOG'] = str(root / 'connect-tools.jsonl')
                environment['KER_MPTCP_CONNECT_CMP'] = shutil.which('cmp')
                report['connect_tools'] = {}
                for name in ('ping', 'ethtool', 'nft'):
                    program = Path(shutil.which(name)).resolve()
                    # Copy unchanged bytes so ping file capabilities cannot suppress
                    # the fixture preload when entering the isolated user namespace.
                    target = bins / ('original-' + name)
                    shutil.copyfile(program, target); target.chmod(0o700)
                    environment['KER_MPTCP_CONNECT_' + name.upper()] = str(target)
                    report['connect_tools'][name] = dict(path=str(program), sha256=hashlib.sha256(target.read_bytes()).hexdigest())
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
                if args.suite == 'userspace':
                    report['native_pm_type'] = transport.rpc(transport.FILE, '', '/proc/sys/net/mptcp/pm_type').decode().strip()
                    require(report['native_pm_type'] in ('0', '1'), 'native userspace PM sysctl unavailable')
                # A real second namespace both tests isolation and leaves a
                # genuine nonmatching entry for upstream cleanup_ns's grep -v.
                # No namespace listing or diagnostic result is synthesized.
                report['native_boot_resources'] = {path: transport.rpc(transport.FILE, '', path).decode() for path in
                        ('/proc/meminfo', '/proc/sys/net/ipv4/tcp_wmem', '/proc/sys/net/ipv4/tcp_rmem')}
                requested_mb = 1024 if join_suite else 512 if args.suite == 'simult' or connect_suite else 64
                actual_kb = int(re.search(r'^MemTotal:\s+(\d+) kB$', report['native_boot_resources']['/proc/meminfo'], re.M).group(1))
                require(requested_mb * 1024 * 0.8 < actual_kb <= requested_mb * 1024, 'native kernel memory provisioning differs from request')
                report['native_boot_resources']['requested_memory_mb'] = requested_mb
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

                shell_out = (root / 'shell.stdout').open('w+', errors='backslashreplace') if connect_suite else None
                shell_err = (root / 'shell.stderr').open('w+', errors='backslashreplace') if connect_suite else None
                result = subprocess.Popen(['bash', './' + script], cwd=work, env=environment,
                    stdout=shell_out if connect_suite else subprocess.PIPE,
                    stderr=shell_err if connect_suite else subprocess.PIPE, text=True, start_new_session=True)
                observer = threading.Thread(target=observe_isolation)
                if args.suite == 'diag':
                    observer.start()
                try:
                    if connect_suite:
                        deadline = time.monotonic() + 3600
                        while result.poll() is None:
                            require(process.poll() is None, 'resident kernel exited during original shell')
                            require(time.monotonic() < deadline, 'original shell exceeded fixture deadline')
                            try:
                                result.wait(timeout=0.5)
                            except subprocess.TimeoutExpired:
                                pass
                        shell_out.seek(0); shell_err.seek(0)
                        stdout, stderr = shell_out.read(), shell_err.read()
                    else:
                        stdout, stderr = result.communicate(timeout=220)
                except BaseException:
                    try:
                        kill_tree(result.pid)
                    finally:
                        stdout, stderr, capture_timed_out = bounded_communicate(result, timeout=5)
                        if connect_suite:
                            shell_out.seek(0); shell_err.seek(0)
                            stdout, stderr = shell_out.read(), shell_err.read()
                        report.update(stdout=stdout, stderr=stderr)
                        if capture_timed_out:
                            raise RuntimeError('diagnostic output remained open after bounded process cleanup')
                    report.update(stdout=stdout, stderr=stderr); raise
                finally:
                    finished.set()
                    if connect_suite:
                        tool_log = root / 'connect-tools.jsonl'
                        if tool_log.exists():
                            report['native_connect_operations'] = [json.loads(line) for line in tool_log.read_text().splitlines()]
                        for suffix in ('stdout', 'stderr'):
                            raw = (root / ('shell.' + suffix)).read_bytes()
                            args.evidence.with_suffix('.' + suffix).write_bytes(raw)
                            report[suffix + '_sha256'] = hashlib.sha256(raw).hexdigest()
                        shell_out.close(); shell_err.close()
                    if args.suite == 'diag':
                        observer.join(timeout=7)
                report.update(returncode=result.returncode, stdout=stdout, stderr=stderr)
                report['namespace_isolation_control'] = observation
                require(not observer.is_alive() and not errors and (observation or args.suite != 'diag'), 'namespace isolation control failed: ' + repr(errors))
                require(result.returncode == 0, 'original ' + script + ' failed: ' + stdout + stderr)
                report['cases'] = tap_result(stdout, {'diag':29, 'sockopt':11, 'simult':10, 'userspace':37, 'connect':68, 'mmap':68, 'sendfile':68, 'checksum':68, 'join':126}[args.suite])
                if args.suite == 'sockopt':
                    require(not stderr.strip(), 'original topology/helper errors: ' + stderr)
                    topology = [json.loads(line) for line in (root / 'topology.jsonl').read_text().splitlines()]
                    report['acknowledged_native_topology'] = topology
                    require(len(topology) == 35 and sum(command[:2] == ['link', 'add'] for command in topology) == 4 and
                        sum(command[2:4] == ['addr', 'add'] for command in topology) == 16 and
                        sum(command[2:4] == ['route', 'add'] for command in topology) == 4 and
                        sum(command[2:4] == ['link', 'set'] for command in topology) == 11,
                        'incomplete acknowledged native topology')
                require(transport.rpc(transport.LISTNS).decode().splitlines() == [control], 'original test namespace was not deleted')
                if args.suite == 'sockopt':
                    module_spec = importlib.util.spec_from_file_location('sockopt_fixture', Path(__file__).with_name('linux-mptcp-sockopt-ip.py'))
                    fixture = importlib.util.module_from_spec(module_spec); module_spec.loader.exec_module(fixture)
                    report['unmarked_syn_negative_control'] = fixture.mark_negative_control(control, environment, args.preload)
                if args.suite == 'simult':
                    topology = [json.loads(line) for line in (root / 'topology.jsonl').read_text().splitlines()]
                    report['acknowledged_native_topology'] = topology
                    require(len(topology) == 30 and sum(command[:2] == ['link', 'add'] for command in topology) == 3 and
                        sum(command[2:4] == ['addr', 'add'] for command in topology) == 12 and
                        sum(command[2:4] == ['route', 'add'] for command in topology) == 6 and
                        sum(command[2:4] == ['link', 'set'] for command in topology) == 9,
                        'incomplete simultaneous-flows topology')
                    netem = [json.loads(line) for line in (root / 'netem.jsonl').read_text().splitlines()]
                    report['native_netem_operations'] = netem
                    additions = [entry for entry in netem if entry['arguments'][:2] == ['qdisc', 'add']]
                    require(len(additions) == 20 and all(entry['returncode'] == 0 and entry.get('native_qdiscs') for entry in additions),
                        'original netem matrix was not installed and read back')
                transport.rpc(transport.DELNS, control)
                require(transport.rpc(transport.LISTNS) == b'', 'control namespace was not deleted')
                deadline = time.monotonic() + 5
                while json.loads(transport.rpc(transport.STATUS))['live']:
                    require(time.monotonic() < deadline, 'native diagnostic sockets leaked')
                    time.sleep(0.01)
                socket_runner.stop(channel)
                require(process.wait(timeout=20) == 0, 'native kernel/worker shutdown failed')
                counts = json.loads(counts_file.read_text()); report['native_fixture'] = counts
                if args.suite == 'diag':
                    validate_counts(counts)
                elif args.suite == 'sockopt':
                    require(counts['live'] == 0 and counts['namespaces_created'] == counts['namespaces_deleted'] == 4, 'sockopt namespace/socket cleanup incomplete')
                    require(counts['raw_sockets'] >= 6 and counts['filter_sets'] >= 18 and counts['filter_gets'] >= 6 and counts['netlinks'] >= 53, 'native packet mark filter activity missing')
                    require(counts['mp_join_syn_rx'] > 0 and counts['mp_join_ack_rx'] > 0, 'native MP_JOIN handshakes missing')
                    require(counts['negotiated'] >= 8 and counts['full_info'] > 0 and counts['inq'] > 0, 'original socket helper coverage missing')
                elif args.suite == 'userspace':
                    topology = [json.loads(line) for line in (root / 'topology.jsonl').read_text().splitlines()]
                    report['acknowledged_native_topology'] = topology
                    validate_userspace_counts(counts, topology)
                elif join_suite:
                    require(counts['live'] == 0 and counts['namespaces_created'] == counts['namespaces_deleted'], 'join namespace/socket cleanup incomplete')
                    require(counts['mp_join_syn_rx'] > 0 and counts['mp_join_ack_rx'] > 0 and counts['filter_sets'] > 0, 'native join/fault-injection activity missing')
                elif connect_suite:
                    report['native_connect_operations'] = [json.loads(line) for line in (root / 'connect-tools.jsonl').read_text().splitlines()]
                    require(counts['live'] == 0 and counts['namespaces_created'] == counts['namespaces_deleted'] == 6, 'connect namespace/socket cleanup incomplete')
                    require(counts['mptcp'] > 100 and counts['negotiated'] > 80 and counts['fallback'] > 0, 'connect/fallback native socket matrix missing')
                    require(sum(x.get('tool') == 'ping' and x['returncode'] == 0 for x in report['native_connect_operations']) == 48, 'complete original ICMP connectivity matrix missing')
                    operations = report['native_connect_operations']
                    comparisons = [x for x in operations if x.get('tool') == 'cmp']
                    require(len(comparisons) == 132 and all(x['returncode'] == 0 for x in comparisons), 'original bidirectional file comparisons incomplete')
                    filters = [x for x in operations if x.get('tool') == 'nft']
                    require(len(filters) == 4 and all(x['returncode'] == 0 for x in filters), 'native IPv4/IPv6 tproxy rules were not installed and removed')
                    require(sum('acknowledged_policy' in x for x in operations) == 8, 'native tproxy policy routing matrix incomplete')
                    require(counts['channels_opened'] > 4096 and counts['channel_slots'] < 64, 'complete shell did not exercise bounded native task reuse')
                    if args.suite == 'sendfile':
                        require(counts['sendfile_calls'] > 0 and counts['imported_files'] > 0, 'native sendfile input transport missing')
                else:
                    require(counts['live'] == 0 and counts['namespaces_created'] == counts['namespaces_deleted'] == 4,
                        'simultaneous-flows cleanup incomplete')
                    require(counts['mptcp'] == 20 and counts['accepts'] == 10 and counts['negotiated'] == 20 and counts['fallback'] == 0,
                        'full native simultaneous transfer matrix missing')
                    require(counts['mp_join_syn_rx'] >= 10 and counts['mp_join_ack_rx'] >= 10, 'native second subflow handshakes missing')
                    require(counts['netlinks'] >= 93 and counts['sent'] >= 168591360 and counts['received'] >= 168591360,
                        'original traffic-control/data transfer volume missing')
                report['stats'] = json.loads(stats.read_text())
                require(report['stats'].get('outstanding') == 0, 'packet ownership did not settle')
                for name, data in originals.items():
                    require((source / name).read_bytes() == data and (root / 'net' / name).read_bytes() == data, 'upstream source changed')
                report['status'] = 'PASS_IMPORTED_LINUX'
                print('LINUX_ORIGINAL_MPTCP_' + args.suite.upper() + '_PASS', len(report['cases']))
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
        sys.exit('Linux MPTCP shell selftest failed: ' + str(error))
