"""Run the complete original shared nexthop IPv4/IPv6 routing shell on imported Linux."""
import argparse
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

spec = importlib.util.spec_from_file_location('network_runner', Path(__file__).with_name('linux-network-selftest.py'))
common = importlib.util.module_from_spec(spec); spec.loader.exec_module(common)
require = common.require


def forwarding_counts(content):
    lines = content['ipv4'].splitlines()
    row = next(i for i, line in enumerate(lines) if line.startswith('Ip:'))
    ipv4 = dict(zip(lines[row].split()[1:], map(int, lines[row + 1].split()[1:])))
    ipv6 = dict(line.split() for line in content['ipv6'].splitlines())
    return dict(ipv4=ipv4['ForwDatagrams'], ipv6=int(ipv6['Ip6OutForwDatagrams']))


def validate_evidence(report):
    original = report.get('original', {})
    require(original.get('returncode') == 0 and not original.get('stderr') and
            original.get('stdout', '').split() == ['TEST:', 'ping', '[', 'OK', ']', 'TEST:', 'ping6', '[', 'OK', ']'],
            'incomplete original shared nexthop shell')
    rows = report.get('commands', [])
    pings = [r for r in rows if r['arguments'][:2] == ['vrf', 'exec']]
    require([r['arguments'] for r in pings] == [
        ['vrf','exec','vrf-h1','ping','-c','10','-i','0.1','-w','5','198.51.100.2'],
        ['vrf','exec','vrf-h1','ping6','-c','10','-i','0.1','-w','5','2001:db8:2::2']],
        'modified or missing original nexthop ping arguments')
    require(all(r['returncode'] == 0 and '10 received' in r['stdout'] and not r['stderr'] and
                r.get('native_clock_reads', 0) > 0 and
                r['vrf']['linkinfo']['info_kind'] == 'vrf' for r in pings),
            'original dual-stack traffic did not traverse the native VRF')
    require([r['arguments'] for r in rows if r['returncode']] == [
        ['link','show','dev','veth0'], ['link','show','dev','veth2']],
        'unexpected original topology or cleanup error')
    require(all(not r['stderr'] for r in rows if r['returncode'] == 0), 'native nexthop command warning')
    changes = [r['arguments'] for r in rows if r['arguments'][1:2] == ['nexthop'] or 'nhid' in r['arguments']]
    expected = [['-6','nexthop','add','id','101','dev','veth1'],
                ['-6','nexthop','add','id','102','dev','veth2'],
                ['route','replace','192.0.2.0/24','nhid','101'],
                ['route','replace','2001:db8:1::/64','nhid','101'],
                ['route','replace','198.51.100.0/24','nhid','102'],
                ['route','replace','2001:db8:2::/64','nhid','102']]
    require(changes == expected, 'missing or modified original IPv6 nexthop objects/shared routes')
    tc = [r for r in rows if r['tool'] == 'tc']
    require([r['arguments'] for r in tc] == [['qdisc','add','dev','veth2','clsact'],
                                           ['qdisc','del','dev','veth2','clsact']],
            'incomplete original clsact lifecycle')
    indices = [rows.index(tc[0])] + [next(i for i,r in enumerate(rows) if r['arguments'] == c) for c in expected] + [rows.index(r) for r in pings] + [rows.index(tc[1])]
    require(indices == sorted(indices), 'nexthop/route/traffic/clsact lifecycle reordered')
    for r in pings:
        state = r['routing_state']
        require(sorted((n['id'],n['dev']) for n in state['nexthops']) == [(101,'veth1'),(102,'veth2')],
                'actual AF_INET6 nexthop objects missing')
        for family, destinations in (('ipv4', ('192.0.2.0/24','198.51.100.0/24')),
                                     ('ipv6', ('2001:db8:1::/64','2001:db8:2::/64'))):
            for nhid, dev, dst in zip((101,102), ('veth1','veth2'), destinations):
                require(sum(route.get('dst') == dst and route.get('nhid') == nhid and route.get('dev') == dev
                            for route in state[family]) == 1, 'native FIB did not retain shared nexthop reference')
        require(sum(q['kind'] == 'clsact' for q in state['qdisc']) == 1, 'native clsact missing during original traffic')
        require(len(state['lookup4']) == len(state['lookup6']) == 1 and
                state['lookup4'][0].get('nhid') == 102 and state['lookup4'][0].get('dev') == 'veth2' and
                state['lookup6'][0].get('dev') == 'veth2' and 'nhid' not in state['lookup6'][0],
                'native route selection differs from unchanged original connected-route precedence')
    for family in ('ipv4','ipv6'):
        writes = [r['arguments'][1] for r in rows if r['tool'] == 'sysctl' and
                  r['arguments'][0] == '-qw' and r['arguments'][1].startswith('net.'+family+'.')]
        require(writes == ['net.'+family+'.conf.all.forwarding=1','net.'+family+'.conf.all.forwarding=0'] and
                report['cleanup_state'][family].strip() == '0', 'native forwarding sysctl was not restored')
    require(not any(link['ifname'] in ('vrf-h1','vrf-h2') for link in report['cleanup_state']['links']) and
            not any(q['kind'] == 'clsact' for q in report['cleanup_state']['qdisc']),
            'native VRF or clsact leaked after original cleanup')
    require(report.get('missing_backend_control', {}).get('returncode') not in (None,0),
            'original nexthop shell passed without native Linux')
    before, after = map(forwarding_counts, (report['mib_before'], report['mib_after']))
    require(all(after[f] - before[f] >= 20 for f in ('ipv4','ipv6')), 'no actual native dual-stack forwarding')
    binding = report.get('vrf_binding_control', {})
    require(binding.get('baseline', {}).get('returncode') == 0 and
            '1 received' in binding.get('baseline', {}).get('stdout','') and
            binding.get('unknown_vrf', {}).get('returncode') not in (None,0), 'ineffective native VRF binding')
    native, stats = report.get('native_fixture', {}), report.get('stats', {})
    require(native.get('netlinks',0) > 0 and native.get('raw_sockets',0) > 0 and native.get('live') == 0 and
            stats.get('outstanding') == 0 and stats.get('worker_exit_code') == 0 and stats.get('control_eof') is True and
            stats.get('shutdown_timed_out') is False, 'native nexthop resources did not stop normally')


def main():
    parser = argparse.ArgumentParser()
    for name in ('server', 'preload', 'tools', 'launcher', 'library', 'worker', 'pmd_dir', 'manifest', 'evidence'):
        parser.add_argument('--' + name.replace('_', '-'), type=Path, required=True)
    parser.add_argument('--program', choices=('router_nh.sh',), default='router_nh.sh')
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    if not args.inside:
        return subprocess.run(['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()),
                               *sys.argv[1:], '--inside']).returncode
    validator = validate_evidence
    manifest = json.loads(args.manifest.read_text())
    config = set((Path(manifest['kernel']) / '.config').read_text().splitlines())
    require(manifest.get('config_fragment') == 'config/native-linux-nexthop-selftests.config' and
            {'CONFIG_VETH=y', 'CONFIG_NET_VRF=y', 'CONFIG_IP_ROUTE_MULTIPATH=y',
             'CONFIG_IP_MULTIPLE_TABLES=y', 'CONFIG_IPV6_MULTIPLE_TABLES=y', 'CONFIG_NET_CLS_ACT=y', 'CONFIG_NET_SCH_INGRESS=y'}.issubset(config),
            'original forwarding test requires real native nexthop/clsact/VRF routing')
    source = Path(manifest['source']) / 'tools/testing/selftests/net'
    originals = {}
    for name in ('forwarding/' + args.program, 'forwarding/lib.sh', 'forwarding/tc_common.sh', 'lib.sh', 'forwarding/Makefile'):
        original = subprocess.check_output(['git', '-C', manifest['source'], 'show',
            manifest['linux']['revision'] + ':tools/testing/selftests/net/' + name])
        require((source / name).read_bytes() == original, 'modified upstream source: ' + name)
        originals[name] = original
    tools = json.loads((args.tools / 'provenance.json').read_text())
    require(tools['version'] == '6.12.0' and tools['archive_sha256'] ==
            'bbd141ef7b5d0127cc2152843ba61f274dc32814fa3e0f13e7d07a080bef53d9' and
            all(hashlib.sha256((args.tools / name).read_bytes()).hexdigest() == tools['binaries'][name] for name in ('ip','tc')),
            'wrong or modified pinned iproute2 tool')
    report = dict(status='FAIL', program=args.program, revision=manifest['linux']['revision'], fingerprint=manifest['fingerprint'],
        source_hashes={name: hashlib.sha256(data).hexdigest() for name, data in originals.items()},
        iproute2=tools, preload_sha256=hashlib.sha256(args.preload.read_bytes()).hexdigest(),
        library_sha256=hashlib.sha256(args.library.read_bytes()).hexdigest(),
        server_sha256=hashlib.sha256(args.server.read_bytes()).hexdigest(),
        transport_sha256=hashlib.sha256(Path(__file__).with_name('linux-nexthop-tools.py').read_bytes()).hexdigest())
    controls = {'LD_PRELOAD', 'TESTS', 'PING', 'PING6', 'MZ', 'PING_COUNT', 'PING_TIMEOUT', 'WAIT_TIME',
                'WAIT_TIMEOUT', 'INTERFACE_TIMEOUT', 'NETIF_CREATE', 'NETIF_TYPE', 'NETIF_FIND_DRIVER',
                'REQUIRE_JQ', 'REQUIRE_MZ', 'REQUIRE_MTOOLS', 'PAUSE_ON_CLEANUP', 'PAUSE_ON_FAIL',
                'STABLE_MAC_ADDRS', 'KSFT_MACHINE_SLOW'}
    environment = {k: v for k, v in os.environ.items() if k not in controls and not k.startswith('KER_')}
    environment['LC_ALL'] = 'C'
    require(shutil.which('mausezahn') is not None and shutil.which('jq') is not None,
            'original forwarding framework requires mausezahn and jq')
    report['framework_tools'] = {name: dict(path=shutil.which(name), sha256=hashlib.sha256(
        Path(shutil.which(name)).read_bytes()).hexdigest()) for name in ('mausezahn', 'jq')}
    try:
        for command in (['ip', 'link', 'set', 'lo', 'up'],
                        ['ip', 'link', 'add', 'kerhost', 'type', 'veth', 'peer', 'name', 'kerlink'],
                        ['ip', 'tuntap', 'add', 'dev', 'kerpeer', 'mode', 'tap', 'multi_queue'],
                        *[['ip', 'link', 'set', name, 'up'] for name in ('kerhost', 'kerlink', 'kerpeer')]):
            subprocess.run(command, check=True)
        cpu = min(os.sched_getaffinity(0))
        eal = (f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry --iova-mode=va -m 64 '
               f'-d {shlex.quote(str(args.pmd_dir / "librte_net_tap.so"))} --vdev=net_tap0,iface=kerpeer,remote=kerlink')
        with tempfile.TemporaryDirectory(prefix='ker-nexthop-', dir='/dev/shm') as temporary, \
                tempfile.TemporaryDirectory(prefix='ker-nexthop-exec-', dir=args.server.parent) as executable:
            root, work = Path(temporary), Path(executable)
            for name, data in originals.items():
                (work / name).parent.mkdir(parents=True, exist_ok=True)
                (work / name).write_bytes(data)
            bins = work / 'bin'; bins.mkdir()
            for name in ('ip', 'tc', 'sysctl'):
                (bins / name).write_text('#!' + sys.executable + '\n' + Path(__file__).with_name('linux-nexthop-tools.py').read_text())
                (bins / name).chmod(0o700)
            report['ping_tools'] = {}
            for name in ('ping', 'ping6'):
                program = Path(shutil.which(name)).resolve()
                target = bins / ('original-' + name)
                shutil.copyfile(program, target); target.chmod(0o700)
                environment['KER_FORWARDING_' + name.upper()] = str(target)
                report['ping_tools'][name] = dict(path=str(program), sha256=hashlib.sha256(target.read_bytes()).hexdigest())
            channel, counts, stats, log = root / 'socket', root / 'counts.json', root / 'stats.json', root / 'commands.jsonl'
            environment.update(KER_MPTCP_SOCKET_CHANNEL=str(channel),
                KER_MPTCP_FIXTURE_SOURCE=str(Path(__file__).resolve().parent),
                KER_FORWARDING_IP=str(args.tools / 'ip'), KER_FORWARDING_TC=str(args.tools / 'tc'), KER_FORWARDING_PRELOAD=str(args.preload),
                KER_FORWARDING_LOG=str(log), PATH=str(bins) + os.pathsep + environment['PATH'])
            negative = dict(environment, KER_MPTCP_SOCKET_CHANNEL=str(root / 'absent'), WAIT_TIMEOUT='1', INTERFACE_TIMEOUT='1')
            missing = subprocess.run(['bash', './' + args.program], cwd=work / 'forwarding', env=negative,
                                     capture_output=True, text=True, timeout=30)
            report['missing_backend_control'] = dict(returncode=missing.returncode, stdout=missing.stdout, stderr=missing.stderr)
            require(missing.returncode != 0, 'original forwarding shell passed without native Linux')
            log.unlink(missing_ok=True)
            with (root / 'server.stdout').open('w+') as out, (root / 'server.stderr').open('w+') as err:
                process = subprocess.Popen([sys.executable, str(args.launcher), '--library', str(args.library),
                    '--io-worker', str(args.worker), '--address', '198.18.0.2/24', '--port', 'net_tap0', '--eal', eal,
                    '--stats', str(stats), '--', str(args.server), str(channel), str(counts)],
                    env=environment, stdout=out, stderr=err, start_new_session=True)
                try:
                    deadline = time.monotonic() + 20
                    while not channel.exists():
                        require(process.poll() is None and time.monotonic() < deadline, 'native namespace fixture startup failed')
                        time.sleep(0.01)
                    diag = common.load('forwarding_native_proc', 'linux-mptcp-diag-shim.py')
                    os.environ['KER_MPTCP_SOCKET_CHANNEL'] = str(channel)
                    def counters():
                        return dict(ipv4=diag.rpc(diag.FILE, '', '/proc/net/snmp').decode(),
                                    ipv6=diag.rpc(diag.FILE, '', '/proc/net/snmp6').decode())
                    report['vrf_binding_control'] = {}
                    for control in ('baseline', 'unknown_vrf'):
                        env = dict(environment, LD_PRELOAD=str(args.preload))
                        if control == 'unknown_vrf':
                            env['KER_FORWARDING_VRF'] = 'ker-absent-vrf'
                        result = subprocess.run([environment['KER_FORWARDING_PING'], '-c', '1', '-w', '1', '127.0.0.1'],
                                                env=env, capture_output=True, text=True, timeout=5)
                        report['vrf_binding_control'][control] = dict(returncode=result.returncode,
                            stdout=result.stdout, stderr=result.stderr)
                    report['mib_before'] = counters()
                    child = subprocess.Popen(['bash', './' + args.program], cwd=work / 'forwarding', env=environment,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
                    try:
                        stdout, stderr = child.communicate(timeout=120)
                    except BaseException:
                        common.cleanup.kill_tree(child.pid)
                        common.cleanup.bounded_communicate(child, timeout=5)
                        raise
                    report['original'] = dict(returncode=child.returncode, stdout=stdout, stderr=stderr)
                    report['commands'] = [json.loads(line) for line in log.read_text().splitlines()]
                    require(child.returncode == 0 and not stderr,
                            'original forwarding shell failed: ' + stdout + stderr)
                    report['mib_after'] = counters()
                    report['cleanup_state'] = {}
                    cleanenv = dict(environment, LD_PRELOAD=str(args.preload))
                    for key, query in (
                        ('links', [str(args.tools / 'ip'), '-d', '-j', 'link', 'show']),
                        ('qdisc', [str(args.tools / 'tc'), '-j', 'qdisc', 'show', 'dev', 'veth2'])):
                        result = subprocess.run(query, env=cleanenv, capture_output=True, text=True, timeout=10, check=True)
                        require(not result.stderr, 'native cleanup observation warning')
                        report['cleanup_state'][key] = json.loads(result.stdout)
                    for family in ('ipv4','ipv6'):
                        report['cleanup_state'][family] = diag.rpc(diag.FILE, '', '/proc/sys/net/' + family + '/conf/all/forwarding').decode()
                    common.fixture.stop(channel)
                    require(process.wait(timeout=20) == 0, 'native fixture shutdown failed')
                    native = json.loads(counts.read_text()); report['native_fixture'] = native
                    require(native['netlinks'] > 0 and native['raw_sockets'] > 0 and native['live'] == 0,
                            'original native forwarding matrix or cleanup incomplete')
                    report['stats'] = json.loads(stats.read_text())
                    require(report['stats'].get('outstanding') == 0 and report['stats'].get('worker_exit_code') == 0 and
                            report['stats'].get('control_eof') is True and report['stats'].get('shutdown_timed_out') is False,
                            'native resources did not stop normally')
                    for name, original in originals.items():
                        require((source / name).read_bytes() == original and (work / name).read_bytes() == original,
                                'upstream shell or library changed during execution')
                    validator(report)
                    report['status'] = 'PASS_IMPORTED_LINUX'
                finally:
                    if process.poll() is None:
                        common.cleanup.kill_tree(process.pid)
                        process.wait(timeout=5)
                    out.seek(0); err.seek(0)
                    report['server_stdout'], report['server_stderr'] = out.read(), err.read()
    except BaseException as error:
        report['error'] = str(error)
        raise
    finally:
        args.evidence.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        sys.exit('Linux forwarding selftest failed: ' + str(error))
