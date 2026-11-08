"""Run the complete original routed bridge/PVID IPv4/IPv6 shell on imported Linux."""
import argparse
import hashlib
import importlib.util
import json
import os
import re
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
    if report.get('program') == 'bridge_vlan_unaware.sh':
        return common.load('bridge_unaware_contract', 'linux-bridge-unaware-contract.py').validate_evidence(report)
    if report.get('program') == 'bridge_port_isolation.sh':
        return common.load('bridge_isolation_contract', 'linux-bridge-isolation-contract.py').validate_evidence(report)
    if report.get('program') == 'bridge_mdb_port_down.sh':
        return common.load('bridge_mdb_port_contract', 'linux-bridge-mdb-port-contract.py').validate_evidence(report)
    if report.get('program') == 'bridge_fdb_learning_limit.sh':
        return common.load('bridge_learning_contract', 'linux-bridge-learning-contract.py').validate_evidence(report)
    if report.get('program') == 'bridge_sticky_fdb.sh':
        return common.load('bridge_sticky_contract', 'linux-bridge-sticky-contract.py').validate_evidence(report)
    if report.get('program') == 'bridge_mdb_host.sh':
        return common.load('bridge_mdb_host_contract', 'linux-bridge-mdb-host-contract.py').validate_evidence(report)
    if report.get('program') == 'router_bridge_vlan_upper_pvid.sh':
        return common.load('bridge_upper_pvid_contract', 'linux-bridge-upper-pvid-contract.py').validate_evidence(report)
    if report.get('program') == 'router_bridge_pvid_vlan_upper.sh':
        return common.load('bridge_pvid_upper_contract', 'linux-bridge-pvid-upper-contract.py').validate_evidence(report)
    if report.get('program') == 'router_bridge_vlan_upper.sh':
        return common.load('bridge_vlan_upper_contract', 'linux-bridge-vlan-upper-contract.py').validate_evidence(report)
    if report.get('program') == 'router_bridge_1d.sh':
        return common.load('bridge_1d_contract', 'linux-bridge-1d-contract.py').validate_evidence(report)
    if report.get('program') == 'router_bridge_vlan.sh':
        return common.load('bridge_vlan_contract', 'linux-bridge-vlan-contract.py').validate_evidence(report)
    original = report.get('original', {})
    names = ['ping', 'ping6', 'ping', 'ping6', 'ping fails', 'ping6 fails', 'ping', 'ping6', 'ping', 'ping6']
    results = [re.fullmatch(r'TEST: (.*?)\s+\[ OK \]', line) for line in original.get('stdout', '').splitlines() if line.startswith('TEST:')]
    require(original.get('returncode') == 0 and not original.get('stderr') and len(results) == 10 and all(results) and [m[1] for m in results] == names, 'incomplete original router_bridge outcomes')
    rows = report.get('commands', [])
    pings = [r for r in rows if r['arguments'][:2] == ['vrf', 'exec']]
    require(len(pings) == 10 and [r['returncode'] for r in pings] == [0,0,0,0,1,1,0,0,0,0], 'missing original bridge/PVID reachability and isolation matrix')
    for index, r in enumerate(pings):
        require(r.get('native_clock_reads', 0) > 0,
                'original bridge ping did not use native realtime for its SO_TIMESTAMP clock domain')
        require(r['arguments'] == ['vrf', 'exec', 'vveth0', 'ping' if index % 2 == 0 else 'ping6', '-c', '10', '-i', '0.1', '-w', '5', '192.0.2.130' if index % 2 == 0 else '2001:db8:2::2'], 'modified original bridge traffic or timing')
        require(r['vrf']['linkinfo']['info_kind'] == 'vrf', 'bridge ping did not use native VRF')
        require(('10 received' if r['returncode'] == 0 else '0 received') in r['stdout'] and not r['stderr'], 'wrong actual native bridge ping output')
    bridge = [r for r in rows if r['tool'] == 'bridge']
    require([r['arguments'] for r in bridge] == [['vlan','add','dev','br1','vid','1','self'], ['vlan','add','dev','br1','vid','1','self','pvid','untagged']], 'missing original bridge PVID updates')
    # Require actual successful configuration/cleanup, apart from the original
    # absent-device probes and the two deliberate isolation pings.
    failures = [r['arguments'] for r in rows if r['returncode'] and r not in pings]
    require(failures == [['link','show','dev','veth0'], ['link','show','dev','veth2']],
            'unexpected native bridge configuration or cleanup error')
    require(all(not r['stderr'] for r in rows if r['returncode'] == 0), 'native bridge command warning')
    phase_rows = [r for r in rows if r in pings or r['tool'] == 'bridge' or
                  r['arguments'] in (['link','set','dev','veth1','nomaster'],
                      ['link','set','dev','veth1','master','br1']) or
                  'vlan_default_pvid' in r['arguments']]
    phase = [r['arguments'] if r not in pings else r['arguments'][3] for r in phase_rows]
    detach = ['link','set','dev','veth1','nomaster']
    attach = ['link','set','dev','veth1','master','br1']
    require(phase == [attach, 'ping','ping6', detach, attach, 'ping','ping6',
            bridge[0]['arguments'], 'ping','ping6', bridge[1]['arguments'], 'ping','ping6',
            detach, ['link','set','dev','br1','type','bridge','vlan_default_pvid','0'], attach,
            ['link','set','dev','br1','type','bridge','vlan_default_pvid','1'], 'ping','ping6', detach],
            'missing or reordered original bridge remaster/PVID phases')
    for index, r in enumerate(pings):
        state = r['bridge_state']
        require(len(state['link']) == len(state['port']) == len(state['vlans']) == 1,
                'missing native bridge state')
        link, port, vlan = state['link'][0], state['port'][0], state['vlans'][0]
        require(link['ifname'] == 'br1' and link['linkinfo']['info_kind'] == 'bridge' and
                link['linkinfo']['info_data']['vlan_filtering'] == 1 and
                port['ifname'] == 'veth1' and port['master'] == 'br1' and
                port['linkinfo']['info_slave_kind'] == 'bridge' and
                port['linkinfo']['info_slave_data']['state'] == 'forwarding',
                'ping did not traverse the actual VLAN-filtering bridge port')
        require(vlan['ifname'] == 'br1' and len(vlan['vlans']) == 1 and vlan['vlans'][0]['vlan'] == 1 and
                set(vlan['vlans'][0].get('flags', [])) ==
                (set() if index in (4,5) else {'PVID', 'Egress Untagged'}),
                'native PVID removal/restoration did not match original isolation phases')
    for family in ('ipv4','ipv6'):
        writes = [r['arguments'][1] for r in rows if r['tool'] == 'sysctl' and
                  r['arguments'][0] == '-qw' and r['arguments'][1].startswith('net.'+family+'.')]
        require(writes == ['net.'+family+'.conf.all.forwarding=1', 'net.'+family+'.conf.all.forwarding=0'] and
                report['cleanup_state'][family].strip() == '0', 'native forwarding was not restored')
    remaining = report['cleanup_state']['links']
    require(not any(r['ifname'] in ('br1','vveth0','vveth3') for r in remaining),
            'original bridge/VRF devices leaked after cleanup')
    require(all(any(r['arguments'] == ['link','del','dev', dev] for r in rows)
                for dev in ('br1','vveth0','vveth3')), 'missing original bridge/VRF teardown')
    require(report.get('missing_backend_control', {}).get('returncode') not in (None, 0), 'original bridge test passed without native Linux')
    before, after = map(forwarding_counts, (report['mib_before'], report['mib_after']))
    require(all(after[f] - before[f] >= 80 for f in ('ipv4','ipv6')), 'bridge traffic did not traverse actual native forwarding paths')
    binding = report.get('vrf_binding_control', {})
    require(binding.get('baseline', {}).get('returncode') == 0 and '1 received' in binding.get('baseline', {}).get('stdout', '') and binding.get('unknown_vrf', {}).get('returncode') not in (None,0), 'native VRF binding control failed')
    native, stats = report.get('native_fixture', {}), report.get('stats', {})
    require(native.get('netlinks',0) > 0 and native.get('raw_sockets',0) > 0 and native.get('live') == 0 and stats.get('outstanding') == 0 and stats.get('worker_exit_code') == 0 and stats.get('control_eof') is True and stats.get('shutdown_timed_out') is False, 'native bridge resources did not stop normally')


def main():
    parser = argparse.ArgumentParser()
    for name in ('server', 'preload', 'tools', 'launcher', 'library', 'worker', 'pmd_dir', 'manifest', 'evidence'):
        parser.add_argument('--' + name.replace('_', '-'), type=Path, required=True)
    parser.add_argument('--program', choices=('router_bridge.sh', 'router_bridge_vlan.sh', 'router_bridge_1d.sh',
        'router_bridge_vlan_upper.sh', 'router_bridge_pvid_vlan_upper.sh', 'router_bridge_vlan_upper_pvid.sh',
        'bridge_mdb_host.sh', 'bridge_sticky_fdb.sh', 'bridge_fdb_learning_limit.sh', 'bridge_mdb_port_down.sh', 'bridge_port_isolation.sh', 'bridge_vlan_unaware.sh'),
        default='router_bridge.sh')
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    if not args.inside:
        return subprocess.run(['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()),
                               *sys.argv[1:], '--inside']).returncode
    validator = validate_evidence
    manifest = json.loads(args.manifest.read_text())
    config = set((Path(manifest['kernel']) / '.config').read_text().splitlines())
    require(manifest.get('config_fragment') == 'config/native-linux-bridge-selftests.config' and
            {'CONFIG_VETH=y', 'CONFIG_NET_VRF=y', 'CONFIG_VLAN_8021Q=y', 'CONFIG_IP_ROUTE_MULTIPATH=y',
             'CONFIG_IP_MULTIPLE_TABLES=y', 'CONFIG_IPV6_MULTIPLE_TABLES=y', 'CONFIG_BRIDGE=y', 'CONFIG_BRIDGE_VLAN_FILTERING=y', 'CONFIG_BRIDGE_IGMP_SNOOPING=y'}.issubset(config),
            'original forwarding test requires real native VLAN/VRF routing')
    if args.program in ('bridge_mdb_port_down.sh', 'bridge_port_isolation.sh', 'bridge_vlan_unaware.sh'):
        require({'CONFIG_NET_CLS_ACT=y', 'CONFIG_NET_SCH_INGRESS=y', 'CONFIG_NET_CLS_FLOWER=y',
                 'CONFIG_NET_ACT_GACT=y'}.issubset(config), 'original multicast counter requires actual native ingress/flower/GACT')
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
            all(hashlib.sha256((args.tools / name).read_bytes()).hexdigest() == tools['binaries'][name] for name in ('ip', 'bridge')),
            'wrong or modified pinned iproute2 tool')
    report = dict(status='FAIL', program=args.program, revision=manifest['linux']['revision'], fingerprint=manifest['fingerprint'],
        source_hashes={name: hashlib.sha256(data).hexdigest() for name, data in originals.items()},
        iproute2=tools, preload_sha256=hashlib.sha256(args.preload.read_bytes()).hexdigest(),
        library_sha256=hashlib.sha256(args.library.read_bytes()).hexdigest(),
        server_sha256=hashlib.sha256(args.server.read_bytes()).hexdigest(),
        transport_sha256=hashlib.sha256(Path(__file__).with_name('linux-bridge-tools.py').read_bytes()).hexdigest())
    controls = {'LD_PRELOAD', 'TESTS', 'PING', 'PING6', 'MZ', 'PING_COUNT', 'PING_TIMEOUT', 'WAIT_TIME',
                'WAIT_TIMEOUT', 'INTERFACE_TIMEOUT', 'NETIF_CREATE', 'NETIF_TYPE', 'NETIF_FIND_DRIVER',
                'REQUIRE_JQ', 'REQUIRE_MZ', 'REQUIRE_MTOOLS', 'PAUSE_ON_CLEANUP', 'PAUSE_ON_FAIL',
                'STABLE_MAC_ADDRS', 'KSFT_MACHINE_SLOW', 'LOW_AGEING_TIME'}
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
        with tempfile.TemporaryDirectory(prefix='ker-bridge-', dir='/dev/shm') as temporary, \
                tempfile.TemporaryDirectory(prefix='ker-bridge-exec-', dir=args.server.parent) as executable:
            root, work = Path(temporary), Path(executable)
            for name, data in originals.items():
                (work / name).parent.mkdir(parents=True, exist_ok=True)
                (work / name).write_bytes(data)
            bins = work / 'bin'; bins.mkdir()
            for name in ('ip', 'bridge', 'sysctl'):
                (bins / name).write_text('#!' + sys.executable + '\n' + Path(__file__).with_name('linux-bridge-tools.py').read_text())
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
                KER_FORWARDING_IP=str(args.tools / 'ip'), KER_FORWARDING_BRIDGE=str(args.tools / 'bridge'), KER_FORWARDING_PRELOAD=str(args.preload),
                KER_FORWARDING_LOG=str(log), PATH=str(bins) + os.pathsep + environment['PATH'])
            if args.program == 'bridge_fdb_learning_limit.sh':
                environment['KER_FORWARDING_BRIDGE_LEARNING'] = '1'
            if args.program in ('bridge_mdb_port_down.sh', 'bridge_port_isolation.sh', 'bridge_vlan_unaware.sh'):
                mode = {'bridge_mdb_port_down.sh': 'MDB_PORT', 'bridge_port_isolation.sh': 'ISOLATION',
                        'bridge_vlan_unaware.sh': 'UNAWARE'}[args.program]
                environment['KER_FORWARDING_BRIDGE_' + mode] = '1'
                require(hashlib.sha256((args.tools / 'tc').read_bytes()).hexdigest() == tools['binaries']['tc'],
                        'wrong pinned original tc binary')
                report['tc_tool'] = dict(path=str(args.tools / 'tc'),
                    sha256=hashlib.sha256((args.tools / 'tc').read_bytes()).hexdigest())
                environment['KER_FORWARDING_TC'] = str(args.tools / 'tc')
                (bins / 'tc').write_text('#!' + sys.executable + '\n' + Path(__file__).with_name('linux-bridge-tools.py').read_text())
                (bins / 'tc').chmod(0o700)
            if args.program == 'bridge_mdb_host.sh':
                environment['KER_FORWARDING_BRIDGE_MDB_HOST'] = '1'
            if args.program == 'router_bridge_vlan.sh':
                environment['KER_FORWARDING_BRIDGE_VLAN'] = '1'
            if args.program == 'router_bridge_1d.sh':
                environment['KER_FORWARDING_BRIDGE_1D'] = '1'
            if args.program == 'router_bridge_vlan_upper.sh':
                environment['KER_FORWARDING_BRIDGE_VLAN_UPPER'] = '1'
            if args.program == 'router_bridge_pvid_vlan_upper.sh':
                environment['KER_FORWARDING_BRIDGE_PVID_UPPER'] = '1'
            if args.program == 'router_bridge_vlan_upper_pvid.sh':
                environment['KER_FORWARDING_BRIDGE_UPPER_PVID'] = '1'
            if args.program in ('bridge_sticky_fdb.sh', 'bridge_mdb_port_down.sh', 'bridge_port_isolation.sh', 'bridge_vlan_unaware.sh'):
                if args.program == 'bridge_sticky_fdb.sh':
                    environment['KER_FORWARDING_BRIDGE_STICKY'] = '1'
                environment['KER_MPTCP_NATIVE_PACKET_LOG'] = str(root / 'packet.jsonl')
                program = Path(shutil.which('mausezahn')).resolve()
                target = bins / 'original-mausezahn'
                shutil.copyfile(program, target); target.chmod(0o700)
                environment['KER_FORWARDING_MAUSEZAHN'] = str(target)
                (bins / 'mausezahn').write_text('#!' + sys.executable + '\n' + Path(__file__).with_name('linux-bridge-tools.py').read_text())
                (bins / 'mausezahn').chmod(0o700)
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
                    require(child.returncode == 0 and (args.program == 'bridge_sticky_fdb.sh' or not stderr),
                            'original forwarding shell failed: ' + stdout + stderr)
                    report['mib_after'] = counters()
                    clean = subprocess.run([str(args.tools / 'ip'), '-d', '-j', 'link', 'show'],
                        env=dict(environment, LD_PRELOAD=str(args.preload)),
                        capture_output=True, text=True, timeout=10, check=True)
                    require(not clean.stderr, 'native cleanup observation warning')
                    report['cleanup_state'] = dict(links=json.loads(clean.stdout), **{
                        family: diag.rpc(diag.FILE, '', '/proc/sys/net/' + family + '/conf/all/forwarding').decode()
                        for family in ('ipv4','ipv6')})
                    if args.program in ('bridge_mdb_host.sh', 'bridge_sticky_fdb.sh', 'bridge_fdb_learning_limit.sh', 'bridge_mdb_port_down.sh', 'bridge_port_isolation.sh', 'bridge_vlan_unaware.sh'):
                        observed = {}
                        for key, query in (('addresses', [str(args.tools / 'ip'), '-j', 'address', 'show']),
                                ('ipv4_routes', [str(args.tools / 'ip'), '-4', '-j', 'route', 'show', 'table', 'all']),
                                ('ipv6_routes', [str(args.tools / 'ip'), '-6', '-j', 'route', 'show', 'table', 'all']),
                                ('mdb', [str(args.tools / 'bridge'), '-j', '-d', 'mdb', 'show'])):
                            clean = subprocess.run(query, env=dict(environment, LD_PRELOAD=str(args.preload)),
                                capture_output=True, text=True, timeout=10, check=True)
                            require(not clean.stderr, 'native MDB cleanup observation warning')
                            observed[key] = json.loads(clean.stdout)
                        report['cleanup_state'].update(observed)
                    if args.program in ('bridge_sticky_fdb.sh', 'bridge_fdb_learning_limit.sh', 'bridge_port_isolation.sh', 'bridge_vlan_unaware.sh'):
                        fdb = subprocess.run([str(args.tools / 'bridge'), '-j', 'fdb', 'show'],
                            env=dict(environment, LD_PRELOAD=str(args.preload)),
                            capture_output=True, text=True, timeout=10, check=True)
                        require(not fdb.stderr, 'native sticky FDB cleanup observation warning')
                        report['cleanup_state']['fdb'] = json.loads(fdb.stdout)
                    if args.program in ('bridge_sticky_fdb.sh', 'bridge_mdb_port_down.sh', 'bridge_port_isolation.sh', 'bridge_vlan_unaware.sh'):
                        packets = root / 'packet.jsonl'
                        report['packet_trace'] = [json.loads(line) for line in packets.read_text().splitlines()] if packets.exists() else []
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
