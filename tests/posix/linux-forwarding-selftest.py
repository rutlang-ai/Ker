"""Run the complete original VLAN/VRF IPv4/IPv6 forwarding shell on imported Linux."""
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


def validate_commands(records):
    pings = [r for r in records if r['arguments'][:2] == ['vrf', 'exec']]
    require(len(pings) == 2 and [r['arguments'] for r in pings] == [
        ['vrf', 'exec', 'vrf-h1', 'ping', '-c', '10', '-i', '0.1', '-w', '5', '198.51.100.2'],
        ['vrf', 'exec', 'vrf-h1', 'ping6', '-c', '10', '-i', '0.1', '-w', '5', '2001:db8:2::2']],
        'incomplete original IPv4/IPv6 forwarding traffic')
    require(all(r['returncode'] == 0 and '10 received' in r['stdout'] and
                r['vrf']['linkinfo']['info_kind'] == 'vrf' for r in pings),
            'original ping did not receive all ten replies through a native VRF')
    require([r['arguments'] for r in records if r['returncode']] == [
        ['link', 'show', 'dev', 'veth0'], ['link', 'show', 'dev', 'veth2']],
        'unexpected native topology or cleanup failure')
    vlans = [r for r in records if 'vlan' in r['arguments'] and 'add' in r['arguments']]
    require(len(vlans) == 4 and all(r['arguments'][-2:] == ['id', '1'] for r in vlans),
            'original VLAN 1 topology is incomplete')
    for family in ('ipv4', 'ipv6'):
        writes = [r['arguments'][1] for r in records if r['tool'] == 'sysctl' and
                  r['arguments'][0] == '-qw' and r['arguments'][1].startswith('net.' + family + '.')]
        require(writes == ['net.' + family + '.conf.all.forwarding=1',
                           'net.' + family + '.conf.all.forwarding=0'],
                'native forwarding sysctl was not enabled and restored')


def forwarding_counts(content):
    lines = content['ipv4'].splitlines()
    row = next(i for i, line in enumerate(lines) if line.startswith('Ip:'))
    ipv4 = dict(zip(lines[row].split()[1:], map(int, lines[row + 1].split()[1:])))
    ipv6 = dict(line.split() for line in content['ipv6'].splitlines())
    return dict(ipv4=ipv4['ForwDatagrams'], ipv6=int(ipv6['Ip6OutForwDatagrams']))


def validate_evidence(report):
    if report.get('program') == 'ip6_forward_instats_vrf.sh':
        return common.load('instats_contract', 'linux-forwarding-instats-contract.py').validate_evidence(report)
    if report.get('program') == 'router_broadcast.sh':
        return common.load('broadcast_contract', 'linux-broadcast-contract.py').validate_evidence(report)
    if report.get('program') == 'min_max_mtu.sh':
        return common.load('mtu_contract', 'linux-forwarding-mtu-contract.py').validate_evidence(report)
    original = report.get('original', {})
    require(original.get('returncode') == 0 and not original.get('stderr') and
            original.get('stdout', '').split() == ['TEST:', 'ping', '[', 'OK', ']', 'TEST:', 'ping6', '[', 'OK', ']'],
            'incomplete original forwarding shell')
    require(report.get('missing_backend_control', {}).get('returncode') not in (None, 0),
            'original forwarding shell passed without imported Linux')
    validate_commands(report.get('commands', []))
    before, after = map(forwarding_counts, (report['mib_before'], report['mib_after']))
    require(all(after[family] - before[family] >= 20 for family in ('ipv4', 'ipv6')),
            'original traffic did not traverse both native forwarding paths')
    binding = report.get('vrf_binding_control', {})
    require(binding.get('baseline', {}).get('returncode') == 0 and
            '1 received' in binding.get('baseline', {}).get('stdout', '') and
            binding.get('unknown_vrf', {}).get('returncode') not in (None, 0),
            'native socket-create VRF binding is ineffective')
    native, stats = report.get('native_fixture', {}), report.get('stats', {})
    require(native.get('netlinks', 0) > 0 and native.get('raw_sockets', 0) > 0 and native.get('live') == 0 and
            stats.get('outstanding') == 0 and stats.get('worker_exit_code') == 0 and
            stats.get('control_eof') is True and stats.get('shutdown_timed_out') is False,
            'native forwarding resources did not close normally')


def main():
    parser = argparse.ArgumentParser()
    for name in ('server', 'preload', 'tools', 'launcher', 'library', 'worker', 'pmd_dir', 'manifest', 'evidence'):
        parser.add_argument('--' + name.replace('_', '-'), type=Path, required=True)
    parser.add_argument('--program', choices=('router_vid_1.sh', 'min_max_mtu.sh', 'router_broadcast.sh', 'ip6_forward_instats_vrf.sh'), default='router_vid_1.sh')
    parser.add_argument('--poll-control', type=Path)
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    if not args.inside:
        return subprocess.run(['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()),
                               *sys.argv[1:], '--inside']).returncode
    validator = validate_evidence
    manifest = json.loads(args.manifest.read_text())
    config = set((Path(manifest['kernel']) / '.config').read_text().splitlines())
    require(manifest.get('config_fragment') == ('config/native-linux-bridge-selftests.config' if args.program == 'ip6_forward_instats_vrf.sh' else 'config/native-linux-forwarding.config') and
            {'CONFIG_VETH=y', 'CONFIG_NET_VRF=y', 'CONFIG_VLAN_8021Q=y', 'CONFIG_IP_ROUTE_MULTIPATH=y',
             'CONFIG_IP_MULTIPLE_TABLES=y', 'CONFIG_IPV6_MULTIPLE_TABLES=y'}.issubset(config),
            'original forwarding test requires real native VLAN/VRF routing')
    if args.program == 'ip6_forward_instats_vrf.sh':
        require(args.poll_control is not None and args.poll_control.is_file(), 'native mixed poll control is required')
        require('CONFIG_XFRM_USER=y' in config, 'original IPv6 ingress discard requires real native XFRM policy')
    source = Path(manifest['source']) / 'tools/testing/selftests/net'
    originals = {}
    for name in ('forwarding/' + args.program, 'forwarding/lib.sh', 'lib.sh', 'forwarding/Makefile'):
        original = subprocess.check_output(['git', '-C', manifest['source'], 'show',
            manifest['linux']['revision'] + ':tools/testing/selftests/net/' + name])
        require((source / name).read_bytes() == original, 'modified upstream source: ' + name)
        originals[name] = original
    tools = json.loads((args.tools / 'provenance.json').read_text())
    require(tools['version'] == '6.12.0' and tools['archive_sha256'] ==
            'bbd141ef7b5d0127cc2152843ba61f274dc32814fa3e0f13e7d07a080bef53d9' and
            hashlib.sha256((args.tools / 'ip').read_bytes()).hexdigest() == tools['binaries']['ip'],
            'wrong or modified pinned iproute2 tool')
    report = dict(status='FAIL', program=args.program, revision=manifest['linux']['revision'], fingerprint=manifest['fingerprint'],
        source_hashes={name: hashlib.sha256(data).hexdigest() for name, data in originals.items()},
        iproute2=tools, preload_sha256=hashlib.sha256(args.preload.read_bytes()).hexdigest(),
        library_sha256=hashlib.sha256(args.library.read_bytes()).hexdigest(),
        server_sha256=hashlib.sha256(args.server.read_bytes()).hexdigest(),
        transport_sha256=hashlib.sha256(Path(__file__).with_name('linux-forwarding-tools.py').read_bytes()).hexdigest())
    controls = {'TROUTE6', 'LD_PRELOAD', 'TESTS', 'PING', 'PING6', 'MZ', 'PING_COUNT', 'PING_TIMEOUT', 'WAIT_TIME',
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
        with tempfile.TemporaryDirectory(prefix='ker-forwarding-', dir='/dev/shm') as temporary, \
                tempfile.TemporaryDirectory(prefix='ker-forwarding-exec-', dir=args.server.parent) as executable:
            root, work = Path(temporary), Path(executable)
            for name, data in originals.items():
                (work / name).parent.mkdir(parents=True, exist_ok=True)
                (work / name).write_bytes(data)
            bins = work / 'bin'; bins.mkdir()
            for name in (('ip', 'sysctl', 'cat') if args.program == 'ip6_forward_instats_vrf.sh' else ('ip', 'sysctl')):
                (bins / name).write_text('#!' + sys.executable + '\n' + Path(__file__).with_name('linux-forwarding-tools.py').read_text())
                (bins / name).chmod(0o700)
            report['ping_tools'] = {}
            for name in ('ping', 'ping6'):
                program = Path(shutil.which(name)).resolve()
                target = bins / ('original-' + name)
                shutil.copyfile(program, target); target.chmod(0o700)
                environment['KER_FORWARDING_' + name.upper()] = str(target)
                report['ping_tools'][name] = dict(path=str(program), sha256=hashlib.sha256(target.read_bytes()).hexdigest())
            if args.program == 'ip6_forward_instats_vrf.sh':
                report['poll_control_sha256'] = hashlib.sha256(args.poll_control.read_bytes()).hexdigest()
                environment['KER_FORWARDING_INSTATS'] = '1'
                traceroute = Path(shutil.which('traceroute6')).resolve()
                target = bins / 'original-tools' / 'traceroute6'; target.parent.mkdir()
                shutil.copyfile(traceroute, target); target.chmod(0o700)
                environment['KER_FORWARDING_TRACEROUTE6'] = str(target)
                # Original command spelling remains traceroute6; only its VRF
                # process launch/socket ownership is translated by the ip shim.
                report['traceroute_tool'] = dict(path=str(traceroute), sha256=hashlib.sha256(target.read_bytes()).hexdigest())
            channel, counts, stats, log = root / 'socket', root / 'counts.json', root / 'stats.json', root / 'commands.jsonl'
            environment.update(KER_MPTCP_SOCKET_CHANNEL=str(channel),
                KER_MPTCP_FIXTURE_SOURCE=str(Path(__file__).resolve().parent),
                KER_FORWARDING_IP=str(args.tools / 'ip'), KER_FORWARDING_PRELOAD=str(args.preload),
                KER_FORWARDING_LOG=str(log), PATH=str(bins) + os.pathsep + environment['PATH'])
            if args.program == 'router_broadcast.sh':
                environment['KER_FORWARDING_BROADCAST'] = '1'
                grep = Path(shutil.which('grep', path=os.environ['PATH'])).resolve()
                environment['KER_BROADCAST_GREP'] = str(grep)
                report['grep'] = dict(path=str(grep), sha256=hashlib.sha256(grep.read_bytes()).hexdigest())
                shim = Path(__file__).with_name('linux-broadcast-grep.py')
                (bins / 'grep').write_text('#!' + sys.executable + '\n' + shim.read_text())
                (bins / 'grep').chmod(0o700)
                report['grep_transport_sha256'] = hashlib.sha256(shim.read_bytes()).hexdigest()
            negative = dict(environment, KER_MPTCP_SOCKET_CHANNEL=str(root / 'absent'), WAIT_TIMEOUT='1', INTERFACE_TIMEOUT='1')
            missing = subprocess.run(['bash', './' + args.program], cwd=work / 'forwarding', env=negative,
                                     capture_output=True, text=True, timeout=30)
            report['missing_backend_control'] = dict(returncode=missing.returncode, stdout=missing.stdout, stderr=missing.stderr)
            require(missing.returncode != 0, 'original forwarding shell passed without native Linux')
            if args.program == 'ip6_forward_instats_vrf.sh':
                negative_control = subprocess.run([str(args.poll_control)], env=dict(negative, LD_PRELOAD=str(args.preload)),
                    capture_output=True, text=True, timeout=10)
                report['mixed_poll_missing_backend'] = dict(returncode=negative_control.returncode, stdout=negative_control.stdout, stderr=negative_control.stderr)
                require(negative_control.returncode != 0, 'IPv6 UDP17 control used host fallback')
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
                    if args.program == 'ip6_forward_instats_vrf.sh':
                        report['native_proc_control'] = dict(loopback=diag.rpc(diag.FILE, '', '/proc/net/dev_snmp6/lo').decode())
                        for name, path in (('missing_device', '/proc/net/dev_snmp6/ker-missing'), ('path_escape', '/proc/net/dev_snmp6/../snmp6')):
                            try: diag.rpc(diag.FILE, '', path)
                            except OSError as error: report['native_proc_control'][name] = dict(errno=error.errno, error=str(error))
                            else: raise RuntimeError('native per-interface proc boundary unexpectedly succeeded: ' + path)
                    if args.program == 'ip6_forward_instats_vrf.sh':
                        control = subprocess.run([str(args.poll_control)], env=dict(environment, LD_PRELOAD=str(args.preload)),
                            capture_output=True, text=True, timeout=10)
                        report['mixed_poll_control'] = dict(returncode=control.returncode, stdout=control.stdout, stderr=control.stderr)
                        require(control.returncode == 0, 'native IPv6 mixed poll/select control failed: ' + control.stderr)
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
                    if args.program == 'router_broadcast.sh':
                        observed = {}
                        for key, query in (('links', ['-d', '-j', 'link', 'show']),
                                ('addresses', ['-j', 'address', 'show']),
                                ('routes', ['-4', '-j', 'route', 'show', 'table', 'all'])):
                            clean = subprocess.run([str(args.tools / 'ip'), *query],
                                env=dict(environment, LD_PRELOAD=str(args.preload)),
                                capture_output=True, text=True, timeout=10, check=True)
                            require(not clean.stderr, 'native broadcast cleanup observation warning')
                            observed[key] = json.loads(clean.stdout)
                        report['cleanup_state'] = dict(**observed, sysctls={
                            name: diag.rpc(diag.FILE, '', '/proc/sys/' + name.replace('.', '/')).decode().strip()
                            for name in ('net.ipv4.conf.all.forwarding', 'net.ipv6.conf.all.forwarding',
                                'net.ipv4.conf.all.bc_forwarding', 'net.ipv4.conf.veth1.bc_forwarding',
                                'net.ipv4.conf.veth2.bc_forwarding', 'net.ipv4.icmp_echo_ignore_broadcasts')})
                    if args.program == 'ip6_forward_instats_vrf.sh':
                        # Match the child's real native endpoint without changing
                        # the observer's ordinary iproute2 binary or namespace.
                        old_env = os.environ.copy()
                        try:
                            os.environ.update(environment)
                            shim = common.load('instats_observer', 'linux-forwarding-tools.py')
                            report['cleanup_state'] = shim.instats_snapshot(dict(environment, LD_PRELOAD=str(args.preload)))
                        finally:
                            os.environ.clear(); os.environ.update(old_env)
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
