"""Run original socket selftests against the shared native socket fixture."""
import argparse
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import time


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fixture = load('native_socket_fixture', 'linux-mptcp-socket-selftest.py')
cleanup = load('native_socket_cleanup', 'linux-mptcp-diag-selftest.py')
tap = load('original_kselftest_tap', 'linux-unix-selftest.py')
require = fixture.require

# Complete default programs; helper and individual assertion counts stay separate.
CONTRACTS = {
    'reuseaddr_conflict': (None, 5, 0),
    'sk_bind_sendto_listen': (None, 2, 0),
    # The fixture counts socket() and accept() separately: three socket()
    # calls plus one accept() in each of the two original variants.
    'bind_timewait': (2, 6, 2),
    'bind_wildcard': (132, 1056, 0),
    'reuseport_dualstack': (None, 110, 2),
    'sk_so_peek_off': (None, 12, 2),
    'tun': (5, 5, 0),
    'reuseport_addr_any.sh': (None, 91, 6),
    'run_netsocktests': (None, 2, 0),
    'tap': (3, 12, 0),
    'netlink-dumps': (3, 3, 0),
    'conntrack_dump_flush': (3, 3, 0),
}
SHELL_HELPERS = {'run_netsocktests': 'socket', 'reuseport_addr_any.sh': 'reuseport_addr_any'}
MACVTAP_CASES = ['tap.test_packet_valid_udp_gso', 'tap.test_packet_valid_udp_csum',
                 'tap.test_packet_crash_tap_invalid_eth_proto']
CONNTRACK_CASES = ['conntrack_dump_flush.test_dump_by_zone',
                   'conntrack_dump_flush.test_flush_by_zone',
                   'conntrack_dump_flush.test_flush_by_zone_default']


def validate_original(program, result):
    """An exit code alone permits sk_so_peek_off's all-unsupported path."""
    if program == 'conntrack_dump_flush':
        require(tap.tap_result(result) == CONNTRACK_CASES,
                'incomplete original conntrack zone dump/flush TAP matrix')
    elif program == 'run_netsocktests':
        require(result['stdout'].splitlines() == ['--------------------', 'running socket test',
                '--------------------', '[PASS]'] and not result['stderr'],
                'incomplete original socket creation shell')
    elif program == 'sk_so_peek_off':
        expected = [f'{protocol}/IPv{family} with MSG_PEEK_OFF works correctly'
                    for protocol in ('TCP', 'UDP') for family in (4, 6)]
        require(result['stdout'].splitlines() == expected and not result['stderr'],
                'missing original TCP/UDP IPv4/IPv6 peek-offset assertion matrix')
    elif program == 'reuseport_addr_any.sh':
        expected = [f'{protocol} {family} ... pass' for protocol in ('UDP', 'TCP', 'DCCP')
                    for family in ('IPv4', 'IPv6', 'IPv4 mapped to IPv6')]
        require(not result['stdout'] and result['stderr'].splitlines() == [*expected, 'SUCCESS'],
                'incomplete original UDP/TCP/DCCP address-preference matrix')
    elif program == 'reuseport_dualstack':
        expected = [f'---- {protocol} IPv{first} created before IPv{second}{suffix} ----'
                    for protocol, suffix in (('UDP', ''), ('UDP', ' (large)'), ('TCP', ''))
                    for first, second in ((4, 6), (6, 4))]
        require(not result['stdout'] and result['stderr'].splitlines() == [*expected, 'SUCCESS'],
                'incomplete original dual-stack reuseport groups')


def validate_socket_creation(native):
    # socket.c permits EAFNOSUPPORT for configured-out IPv4. Require both
    # actual native protocols and every rejected request, not just its exit 0.
    keys = ('creation_attempts', 'creation_eafnosupport', 'creation_eprotonosupport',
            'creation_tcp', 'creation_udp')
    require(tuple(native.get(key) for key in keys) == (5, 1, 2, 1, 1),
            'incomplete imported Linux socket creation/error matrix')


def validate_missing_backend(program, result):
    if program == 'run_netsocktests':
        # This control invokes the silent C helper, not the shell wrapper.
        require(result['returncode'] != 0, 'original socket helper passed without the imported kernel')
        return
    completed = False
    if result['returncode'] == 0:
        try:
            validate_original(program, result)
            completed = True
        except RuntimeError:
            pass
    require(not completed, 'original matrix passed without the imported kernel')


def validate_macvtap(native):
    keys = ('macvtap_opens', 'tun_if_sets', 'macvtap_writes', 'macvtap_bytes',
            'macvtap_write_einval', 'netlinks')
    require(tuple(native.get(key) for key in keys) == (3, 3, 2, 2149, 1, 12),
            'incomplete native macvtap device/packet/error matrix')


def validate_netlink_dumps(native):
    keys = ('generic_netlinks', 'mq_opens', 'mq_notifications', 'mq_closes', 'notified_netlink_closes')
    require(tuple(native.get(key) for key in keys) == (3, 1, 1, 1, 1) and
            (native.get('writes'), native.get('sent'), native.get('reads')) == (3, 84, 2),
            'original dump close-with-reference did not reach real native mqueue/Netlink operations')


def validate_conntrack(native):
    # Each original fixture inserts eight IPv4/IPv6 tuples in four zones:
    # 24 CT_NEW, 15 CT_GET and two CT_DELETE requests across its three cases.
    require(tuple(native.get(k) for k in ('sockets', 'netlinks', 'writes', 'sent', 'live',
                'accepts', 'mptcp', 'raw_sockets', 'udp_sockets')) == (3, 3, 41, 5180, 0, 0, 0, 0, 0) and
            native.get('reads', 0) >= 41,
            'incomplete native conntrack insert/dump/zone-flush matrix')


def main():
    parser = argparse.ArgumentParser()
    for name in ('server', 'binary', 'control', 'launcher', 'library', 'worker', 'pmd_dir', 'manifest', 'evidence'):
        parser.add_argument('--' + name.replace('_', '-'), type=Path, required=True)
    parser.add_argument('--program', choices=CONTRACTS, required=True)
    parser.add_argument('--preload', type=Path)
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    if not args.inside:
        return subprocess.run(['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()),
                               *sys.argv[1:], '--inside']).returncode
    manifest = json.loads(args.manifest.read_text())
    source = Path(manifest['source'])
    if args.program == 'conntrack_dump_flush':
        require(args.preload and args.preload.is_file() and
                manifest.get('config_fragment') == 'config/native-linux-conntrack.config',
                'original conntrack entry requires its native profile and libc socket transport')
        config = set((Path(manifest['kernel']) / '.config').read_text().splitlines())
        require({'CONFIG_NF_CONNTRACK=y', 'CONFIG_NF_CONNTRACK_ZONES=y',
                 'CONFIG_NF_CT_NETLINK=y'}.issubset(config), 'missing real native conntrack facilities')
    profile_program = args.program in ('tun', 'reuseport_addr_any.sh')
    if profile_program:
        require(manifest.get('config_fragment') == 'config/native-linux-net-selftests.config',
                'original TUN/DCCP tests require their dedicated native profile')
        config = set((Path(manifest['kernel']) / '.config').read_text().splitlines())
        require({'CONFIG_TUN=y', 'CONFIG_IP_DCCP=y'}.issubset(config), 'missing real native TUN/DCCP facilities')
    if args.program == 'tap':
        require(manifest.get('config_fragment') == 'config/native-linux-macvtap.config',
                'original tap test requires the dedicated macvtap profile')
        config = set((Path(manifest['kernel']) / '.config').read_text().splitlines())
        require({'CONFIG_DUMMY=y', 'CONFIG_MACVLAN=y', 'CONFIG_MACVTAP=y', 'CONFIG_TAP=y',
                 'CONFIG_SYSFS=y'}.issubset(config), 'missing real native macvtap facilities')
    if args.program == 'netlink-dumps':
        require(manifest.get('config_fragment') == 'config/native-linux-netlink-dumps.config',
                'original Netlink dumps require their dedicated native mqueue profile')
        require('CONFIG_POSIX_MQUEUE=y' in (Path(manifest['kernel']) / '.config').read_text().splitlines(),
                'missing real native POSIX message queues')
    helper = SHELL_HELPERS.get(args.program, args.program)
    collection = 'tools/testing/selftests/net/' + ('netfilter/' if args.program == 'conntrack_dump_flush' else '')
    paths = [collection + helper + '.c',
             collection + 'Makefile', 'tools/testing/selftests/kselftest.h',
             'tools/testing/selftests/kselftest_harness.h']
    if args.program in SHELL_HELPERS:
        paths += ['tools/testing/selftests/net/' + args.program]
        if args.program.endswith('.sh'):
            paths += ['tools/testing/selftests/net/in_netns.sh']
    originals = {}
    for path in paths:
        original = subprocess.check_output(['git', '-C', str(source), 'show', manifest['linux']['revision'] + ':' + path])
        require((source / path).read_bytes() == original, 'modified upstream source: ' + path)
        originals[path] = original
    report = dict(status='FAIL', program=args.program, revision=manifest['linux']['revision'],
                  fingerprint=manifest['fingerprint'], source_hashes={p: hashlib.sha256(b).hexdigest() for p, b in originals.items()},
                  binary_sha256=hashlib.sha256(args.binary.read_bytes()).hexdigest(),
                  library_sha256=hashlib.sha256(args.library.read_bytes()).hexdigest(),
                  server_sha256=hashlib.sha256(args.server.read_bytes()).hexdigest())
    environment = {k: v for k, v in os.environ.items() if k != 'LD_PRELOAD' and not k.startswith('KER_')}
    try:
        for command in (['ip', 'link', 'set', 'lo', 'up'],
                        ['ip', 'link', 'add', 'kerhost', 'type', 'veth', 'peer', 'name', 'kerlink'],
                        ['ip', 'tuntap', 'add', 'dev', 'kerpeer', 'mode', 'tap', 'multi_queue'],
                        *[['ip', 'link', 'set', name, 'up'] for name in ('kerhost', 'kerlink', 'kerpeer')]):
            subprocess.run(command, check=True)
        cpu = min(os.sched_getaffinity(0))
        eal = (f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry --iova-mode=va -m 64 '
               f'-d {shlex.quote(str(args.pmd_dir / "librte_net_tap.so"))} --vdev=net_tap0,iface=kerpeer,remote=kerlink')
        with tempfile.TemporaryDirectory(prefix='ker-linux-net-', dir='/dev/shm') as temporary, \
                tempfile.TemporaryDirectory(prefix='ker-linux-net-exec-', dir=args.binary.parent) as executable:
            stage = Path(executable)
            command = [str(args.binary)]
            if args.program in SHELL_HELPERS:
                names = (args.program, 'in_netns.sh') if args.program.endswith('.sh') else (args.program,)
                for name in names:
                    target = stage / name
                    target.write_bytes(originals['tools/testing/selftests/net/' + name]); target.chmod(0o700)
                (stage / helper).symlink_to(args.binary.resolve())
                if args.program.endswith('.sh'):
                    shutil.copyfile(Path(__file__).with_name('linux-mptcp-diag-shim.py'), stage / 'ip')
                    (stage / 'ip').chmod(0o700)
                    environment['PATH'] = str(stage) + os.pathsep + environment.get('PATH', '')
                command = [str(stage / args.program)]
            root = Path(temporary)
            channel, counts, stats = root / 'socket', root / 'counts.json', root / 'stats.json'
            environment['KER_MPTCP_SOCKET_CHANNEL'] = str(channel)
            report['missing_backend_control'] = fixture.run_helper([args.control], environment)
            require(report['missing_backend_control']['returncode'] == 0 and
                    report['missing_backend_control']['stdout'].strip() == 'MISSING_BACKEND_REJECTED',
                    'unavailable native backend was not rejected')
            child_environment = dict(environment)
            if args.program == 'conntrack_dump_flush':
                child_environment['LD_PRELOAD'] = str(args.preload)
                report['preload_sha256'] = hashlib.sha256(args.preload.read_bytes()).hexdigest()
            if args.program in ('reuseport_dualstack', 'sk_so_peek_off', 'tun', 'reuseport_addr_any.sh', 'run_netsocktests', 'tap', 'netlink-dumps', 'conntrack_dump_flush'):
                missing = fixture.run_helper([args.binary], child_environment)
                report['original_missing_backend_control'] = missing
                validate_missing_backend(args.program, missing)
            with (root / 'server.stdout').open('w+') as out, (root / 'server.stderr').open('w+') as err:
                process = subprocess.Popen([sys.executable, str(args.launcher), '--library', str(args.library),
                    '--io-worker', str(args.worker), '--address', '198.18.0.2/24', '--port', 'net_tap0', '--eal', eal,
                    '--stats', str(stats), '--', str(args.server), str(channel), str(counts)],
                    env=environment, stdout=out, stderr=err, start_new_session=True)
                try:
                    deadline = time.monotonic() + 20
                    while not channel.exists():
                        require(process.poll() is None and time.monotonic() < deadline, 'resident kernel startup failed')
                        time.sleep(0.01)
                    child = subprocess.Popen(command, cwd=stage, env=child_environment, stdout=subprocess.PIPE,
                                             stderr=subprocess.PIPE, text=True, start_new_session=True)
                    try:
                        stdout, stderr = child.communicate(timeout=300)
                    except BaseException:
                        cleanup.kill_tree(child.pid)
                        cleanup.bounded_communicate(child, timeout=5)
                        raise
                    result = dict(returncode=child.returncode, stdout=stdout, stderr=stderr)
                    report['original'] = result
                    require(child.returncode == 0, 'original selftest failed: ' + stdout + stderr)
                    validate_original(args.program, result)
                    expected_tap, sockets, accepts = CONTRACTS[args.program]
                    if expected_tap is not None:
                        result['cases'] = tap.tap_result(result)
                        require(len(result['cases']) == expected_tap, 'incomplete original fixture/variant matrix')
                        if args.program == 'netlink-dumps':
                            require(result['cases'] == ['global.test_sanity', 'global.close_in_progress', 'global.close_with_ref'],
                                    'incomplete original Netlink dump lifecycle TAP cases')
                        if args.program == 'tap':
                            require(result['cases'] == MACVTAP_CASES, 'incomplete original macvtap TAP cases')
                        if args.program == 'conntrack_dump_flush':
                            require(result['cases'] == CONNTRACK_CASES,
                                    'incomplete original conntrack zone dump/flush TAP cases')
                    deadline = time.monotonic() + 5
                    while True:
                        try:
                            fixture.stop(channel)
                            break
                        except OSError as error:
                            require(error.errno == errno.EBUSY and time.monotonic() < deadline, 'native sockets did not settle')
                            time.sleep(0.01)
                    require(process.wait(timeout=20) == 0, 'native kernel/worker shutdown failed')
                    native = json.loads(counts.read_text())
                    report['native_fixture'] = native
                    require(native['sockets'] == sockets and native['accepts'] == accepts and native['live'] == 0,
                            'original native socket matrix or cleanup differs')
                    require(native['mptcp'] == 0 and native['raw_sockets'] == 0,
                            'unexpected protocol substitution')
                    expected_udp = {'reuseport_dualstack': 88, 'sk_so_peek_off': 6,
                                    'reuseport_addr_any.sh': 30, 'run_netsocktests': 1}.get(args.program, 0)
                    require(native['udp_sockets'] == expected_udp, 'incomplete native UDP matrix')
                    if args.program == 'run_netsocktests':
                        validate_socket_creation(native)
                    if args.program == 'tap':
                        validate_macvtap(native)
                    if args.program == 'netlink-dumps':
                        validate_netlink_dumps(native)
                    if args.program == 'conntrack_dump_flush':
                        validate_conntrack(native)
                    require(native.get('dccp_sockets', 0) == (31 if args.program == 'reuseport_addr_any.sh' else 0),
                            'missing native DCCP sockets; a skipped protocol is not a complete shell entry')
                    expected_epoll = {'reuseport_dualstack': (6, 104, 6),
                                      'reuseport_addr_any.sh': (9, 81, 9)}.get(args.program, (0, 0, 0))
                    if args.program == 'tun':
                        require(tuple(native[k] for k in ('tun_opens', 'tun_if_sets', 'tun_queue_calls',
                                'tun_attaches', 'tun_detaches', 'tun_queue_einval', 'netlinks')) ==
                                (10, 10, 7, 2, 4, 1, 5), 'incomplete native TUN lifetime/error matrix')
                    require(tuple(native[key] for key in ('epoll_creates', 'epoll_controls', 'epoll_waits')) == expected_epoll,
                            'original readiness checks did not reach native epoll')
                    expected_namespaces = int(args.program.endswith('.sh'))
                    require(native['namespaces_created'] == native['namespaces_deleted'] == expected_namespaces,
                            'unexpected namespace lifetime')
                    report['stats'] = json.loads(stats.read_text())
                    require(report['stats'].get('outstanding') == 0, 'packet ownership did not settle')
                    require(report['stats'].get('worker_exit_code') == 0 and
                            report['stats'].get('control_eof') is True and
                            report['stats'].get('shutdown_timed_out') is False,
                            'native worker did not stop normally')
                    if accepts:
                        mib = report['stats'].get('native', {})
                        if args.program == 'reuseport_addr_any.sh':
                            require(native['namespace_tcp_active'] == native['namespace_tcp_passive'] == 3 and
                                    mib.get('active_opens') == mib.get('passive_opens') == 0,
                                    'original connections did not reach native TCP in the test namespace')
                        else:
                            require(mib.get('active_opens') == accepts and mib.get('passive_opens') == accepts,
                                    'original connections did not reach native TCP')
                    for path, original in originals.items():
                        require((source / path).read_bytes() == original, 'upstream source changed during test')
                    report['status'] = 'PASS_IMPORTED_LINUX'
                    print('LINUX_ORIGINAL_NETWORK_PASS', args.program, expected_tap or 'program-exit', sockets)
                    return 0
                finally:
                    if process.poll() is None:
                        cleanup.kill_tree(process.pid)
                        process.wait(timeout=10)
                    for stream, name in ((out, 'server_stdout'), (err, 'server_stderr')):
                        stream.flush(); stream.seek(0); report[name] = stream.read()
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
        sys.exit('Linux network selftest failed: ' + str(error))
