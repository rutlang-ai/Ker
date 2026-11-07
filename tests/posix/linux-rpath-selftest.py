"""Run the complete original reverse-path filtering shell on imported Linux."""
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


PING_ARGUMENTS = [
    ['-q', '-c', '1', '-W', '1', '-I', 'v0', '192.168.42.1'],
    ['-q', '-c', '1', '-W', '1', '-I', 'v0', 'fec0:42::1'],
    ['-q', '-c', '1', '-W', '1', '192.168.23.1'],
    ['-q', '-c', '1', '-W', '1', 'fec0:23::1'],
] * 2
LEGACY_TOOLS = ('iptables-legacy', 'ip6tables-legacy')


def validate_commands(records):
    for tool in (*LEGACY_TOOLS, 'nft'):
        versions = [r for r in records if r['tool'] == tool and r['arguments'] == ['--version']]
        require(len(versions) == 1 and versions[0]['returncode'] == 0 and
                (tool == 'nft' or '(legacy)' in versions[0]['stdout']),
                'original legacy IPv4/IPv6 and nft tools must all participate')
    pings = [r for r in records if r['tool'] == 'ping']
    require([r['arguments'] for r in pings] == PING_ARGUMENTS and
            [r['returncode'] for r in pings] == [1, 1, 0, 0] * 2 and
            len({r['namespace'] for r in pings}) == 1 and pings[0]['namespace'].startswith('ns1-'),
            'incomplete original dual-stack regular/martian matrix before and after VRF')
    for ping in pings:
        if ping['stderr']:
            # Preserve the original source-device warning and verify the actual
            # native source address together with all original rule counters.
            require('-I' in ping['arguments'] and ping['stderr'].splitlines() and
                    all(line.endswith(': Warning: source address might be selected on device other than: v0')
                        for line in ping['stderr'].splitlines()), 'unexpected original ping error')
            source = '192.168.42.2' if ':' not in ping['arguments'][-1] else 'fec0:42::2'
            require('from ' + source + ' v0:' in ping['stdout'], 'wrong actual native ping source')
    counters = [r for r in records if r['tool'] in LEGACY_TOOLS and r['arguments'] == ['-t', 'raw', '-vS']]
    require(len(counters) == 16, 'missing original legacy counter observations')
    for index, row in enumerate(counters):
        require(row['tool'] == LEGACY_TOOLS[index % 2] and row['namespace'].startswith('ns2-'),
                'wrong legacy family/namespace')
        matches = re.findall(r'-m rpfilter( --invert)? -c (\d+) (\d+)', row['stdout'])
        group, size = index // 4, 84 if index % 2 == 0 else 104
        packets = 1 if group < 2 else 2  # VRF invokes both original prerouting hooks.
        normal, inverse = (packets, 0) if group % 2 else (0, packets)
        require(matches == [('', str(normal), str(normal * size)),
                            (' --invert', str(inverse), str(inverse * size))],
                'wrong native rpfilter/inverted counters')
    nft = [r for r in records if r['tool'] == 'nft' and r['arguments'] == ['list', 'chain', 'inet', 't', 'c']]
    require(len(nft) == 8, 'missing original nft fib counter observations')
    for index, row in enumerate(nft):
        group = index // 2
        packets = (1 if group < 2 else 2) if group % 2 else 0
        matches = re.findall(r'^\s*(ip6?) saddr .* counter packets (\d+) bytes (\d+)\s*$', row['stdout'], re.M)
        require(matches == [('ip', str(packets), str(packets * 84)),
                            ('ip6', str(packets), str(packets * 104))], 'wrong native dual-stack nft fib counters')
    rules = [r for r in records if r['tool'] in LEGACY_TOOLS and r['arguments'][:4] == ['-t', 'raw', '-A', 'PREROUTING']]
    require(len(rules) == 4 and [r['tool'] for r in rules] == [*([LEGACY_TOOLS[0]] * 2), *([LEGACY_TOOLS[1]] * 2)] and
            all('-m' in r['arguments'] and 'rpfilter' in r['arguments'] for r in rules),
            'missing original IPv4/IPv6 rpfilter rules')
    resets = [r for r in records if r['tool'] in LEGACY_TOOLS and r['arguments'] == ['-t', 'raw', '-Z']]
    require([r['tool'] for r in resets] == list(LEGACY_TOOLS) * 4, 'legacy counters were not reset in each phase')
    rulesets = [r for r in records if r['tool'] == 'nft' and r['arguments'] == ['-f', '-']]
    require(len(rulesets) == 5 and all('table inet t' in r.get('ruleset', '') for r in rulesets),
            'missing original nft create/reset rule transactions')
    vrfs = [r for r in records if r['tool'] == 'ip' and r['arguments'] == ['link', 'add', 'vrf0', 'type', 'vrf', 'table', '10']]
    binds = [r for r in records if r['tool'] == 'ip' and r['arguments'] == ['link', 'set', 'v0', 'master', 'vrf0']]
    ping_positions = [i for i, row in enumerate(records) if row['tool'] == 'ping']
    vrf_positions = [i for i, row in enumerate(records) if row is vrfs[0]] if len(vrfs) == 1 else []
    bind_positions = [i for i, row in enumerate(records) if row is binds[0]] if len(binds) == 1 else []
    require(len(vrf_positions) == len(bind_positions) == 1 and
            ping_positions[3] < vrf_positions[0] < bind_positions[0] < ping_positions[4],
            'missing original VRF transition')
    require(all(r['returncode'] == 0 and not r.get('stderr') for r in records if r['tool'] != 'ping'),
            'native setup/filter/counter/cleanup tool failed')


def validate_evidence(report):
    original = report.get('original', {})
    require(original.get('returncode') == 0 and
            original.get('stdout', '').splitlines() == ['PASS: netfilter reverse path match works as intended'],
            'incomplete original reverse-path shell')
    require(report.get('missing_backend_control', {}).get('returncode') not in (None, 0),
            'original rpath passed without native Linux')
    records = report.get('commands', [])
    validate_commands(records)
    require(sorted(original.get('stderr', '').splitlines()) ==
            sorted(line for row in records for line in row.get('stderr', '').splitlines()),
            'unrecorded original shell diagnostic')
    native, stats = report.get('native_fixture', {}), report.get('stats', {})
    require(native.get('namespaces_created') == native.get('namespaces_deleted') == 2 and
            native.get('netlinks', 0) > 0 and native.get('raw_sockets', 0) > 0 and
            native.get('accepts') == native.get('mptcp') == native.get('live') == 0 and
            stats.get('outstanding') == 0 and stats.get('worker_exit_code') == 0 and
            stats.get('control_eof') is True and stats.get('shutdown_timed_out') is False,
            'native rpath resources did not stop normally')

def main():
    parser = argparse.ArgumentParser()
    for name in ('server', 'preload', 'tools', 'launcher', 'library', 'worker', 'pmd_dir', 'manifest', 'evidence'):
        parser.add_argument('--' + name.replace('_', '-'), type=Path, required=True)
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    if not args.inside:
        return subprocess.run(['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()),
                               *sys.argv[1:], '--inside']).returncode
    manifest = json.loads(args.manifest.read_text())
    require(manifest.get('config_fragment') == 'config/native-linux-rpath-selftests.config',
            'rpath test requires its real native rpfilter/fib profile')
    config = set((Path(manifest['kernel']) / '.config').read_text().splitlines())
    require({
        'CONFIG_DUMMY=y', 'CONFIG_IP_ROUTE_MULTIPATH=y', 'CONFIG_NETFILTER_XTABLES=y',
        'CONFIG_IP_NF_IPTABLES=y', 'CONFIG_IP_NF_RAW=y', 'CONFIG_IP_NF_MATCH_RPFILTER=y',
        'CONFIG_IP6_NF_IPTABLES=y', 'CONFIG_IP6_NF_RAW=y', 'CONFIG_IP6_NF_MATCH_RPFILTER=y',
        'CONFIG_NF_TABLES=y', 'CONFIG_NF_TABLES_INET=y', 'CONFIG_NFT_FIB_IPV4=y',
        'CONFIG_NFT_FIB_IPV6=y', 'CONFIG_NFT_FIB_INET=y',
    }.issubset(config), 'missing actual native reverse-path facilities')
    source = Path(manifest['source']) / 'tools/testing/selftests/net'
    originals = {}
    for name in ('netfilter/rpath.sh', 'netfilter/Makefile'):
        original = subprocess.check_output(['git', '-C', manifest['source'], 'show',
            manifest['linux']['revision'] + ':tools/testing/selftests/net/' + name])
        require((source / name).read_bytes() == original, 'modified upstream source: ' + name)
        originals[name] = original
    tools = json.loads((args.tools / 'provenance.json').read_text())
    require(tools['version'] == '6.12.0' and tools['archive_sha256'] ==
            'bbd141ef7b5d0127cc2152843ba61f274dc32814fa3e0f13e7d07a080bef53d9' and
            hashlib.sha256((args.tools / 'ip').read_bytes()).hexdigest() == tools['binaries']['ip'],
            'wrong or modified pinned iproute2 tool')
    report = dict(status='FAIL', revision=manifest['linux']['revision'], fingerprint=manifest['fingerprint'],
        source_hashes={name: hashlib.sha256(data).hexdigest() for name, data in originals.items()},
        iproute2=tools, preload_sha256=hashlib.sha256(args.preload.read_bytes()).hexdigest(),
        library_sha256=hashlib.sha256(args.library.read_bytes()).hexdigest(),
        server_sha256=hashlib.sha256(args.server.read_bytes()).hexdigest(),
        transport_sha256=hashlib.sha256(Path(__file__).with_name('linux-rpath-tools.py').read_bytes()).hexdigest())
    environment = {k: v for k, v in os.environ.items() if k not in ('LD_PRELOAD', 'WAIT_TIMEOUT', 'BUSYWAIT_TIMEOUT', 'PAUSE_ON_FAIL') and not k.startswith(('KER_', 'KSFT_'))}
    environment['LC_ALL'] = 'C'
    try:
        for command in (['ip', 'link', 'set', 'lo', 'up'],
                        ['ip', 'link', 'add', 'kerhost', 'type', 'veth', 'peer', 'name', 'kerlink'],
                        ['ip', 'tuntap', 'add', 'dev', 'kerpeer', 'mode', 'tap', 'multi_queue'],
                        *[['ip', 'link', 'set', name, 'up'] for name in ('kerhost', 'kerlink', 'kerpeer')]):
            subprocess.run(command, check=True)
        cpu = min(os.sched_getaffinity(0))
        eal = (f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry --iova-mode=va -m 64 '
               f'-d {shlex.quote(str(args.pmd_dir / "librte_net_tap.so"))} --vdev=net_tap0,iface=kerpeer,remote=kerlink')
        with tempfile.TemporaryDirectory(prefix='ker-rpath-', dir='/dev/shm') as temporary, \
                tempfile.TemporaryDirectory(prefix='ker-rpath-exec-', dir=args.server.parent) as executable:
            root, work = Path(temporary), Path(executable)
            for name, data in originals.items():
                (work / name).parent.mkdir(parents=True, exist_ok=True)
                (work / name).write_bytes(data)
            bins = work / 'bin'; bins.mkdir()
            for name in ('ip', 'nft', 'ping', 'iptables-legacy', 'ip6tables-legacy'):
                (bins / name).write_text('#!' + sys.executable + '\n' + Path(__file__).with_name('linux-rpath-tools.py').read_text())
                (bins / name).chmod(0o700)
            report['original_tools'] = {}
            for name in ('ping', 'nft'):
                program = Path(shutil.which(name)).resolve()
                target = bins / ('original-' + name)
                shutil.copyfile(program, target); target.chmod(0o700)
                environment['KER_RPATH_' + name.upper()] = str(target)
                report['original_tools'][name] = dict(path=str(program), sha256=hashlib.sha256(target.read_bytes()).hexdigest())
            for name in ('iptables-legacy', 'ip6tables-legacy'):
                program = shutil.which(name)
                require(program is not None, 'missing original ' + name)
                environment['KER_RPATH_' + name.upper().replace('-', '_')] = program
                report['original_tools'][name] = dict(path=program, sha256=hashlib.sha256(Path(program).read_bytes()).hexdigest())
            channel, counts, stats, log = root / 'socket', root / 'counts.json', root / 'stats.json', root / 'commands.jsonl'
            environment.update(KER_MPTCP_SOCKET_CHANNEL=str(channel),
                KER_MPTCP_FIXTURE_SOURCE=str(Path(__file__).resolve().parent),
                KER_RPATH_IP=str(args.tools / 'ip'), KER_RPATH_PRELOAD=str(args.preload),
                KER_RPATH_LOG=str(log), XTABLES_LOCKFILE=str(root / 'xtables.lock'), PATH=str(bins) + os.pathsep + environment['PATH'])
            negative = dict(environment, KER_MPTCP_SOCKET_CHANNEL=str(root / 'absent'), WAIT_TIMEOUT='1')
            missing = subprocess.run(['bash', './rpath.sh'], cwd=work / 'netfilter', env=negative,
                                     capture_output=True, text=True, timeout=30)
            report['missing_backend_control'] = dict(returncode=missing.returncode, stdout=missing.stdout, stderr=missing.stderr)
            require(missing.returncode != 0, 'original rpath shell passed without native Linux')
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
                    child = subprocess.Popen(['bash', './rpath.sh'], cwd=work / 'netfilter', env=environment,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
                    try:
                        stdout, stderr = child.communicate(timeout=120)
                    except BaseException:
                        common.cleanup.kill_tree(child.pid)
                        common.cleanup.bounded_communicate(child, timeout=5)
                        raise
                    report['original'] = dict(returncode=child.returncode, stdout=stdout, stderr=stderr)
                    report['commands'] = [json.loads(line) for line in log.read_text().splitlines()]
                    require(child.returncode == 0 and stdout.splitlines() == ['PASS: netfilter reverse path match works as intended'],
                            'original rpath shell failed: ' + stdout + stderr)
                    common.fixture.stop(channel)
                    require(process.wait(timeout=20) == 0, 'native fixture shutdown failed')
                    native = json.loads(counts.read_text()); report['native_fixture'] = native
                    require(native['namespaces_created'] == native['namespaces_deleted'] == 2 and
                            native['netlinks'] > 0 and native['raw_sockets'] > 0 and
                            native['accepts'] == native['mptcp'] == native['live'] == 0,
                            'original native namespace/Netlink matrix or cleanup incomplete')
                    report['stats'] = json.loads(stats.read_text())
                    require(report['stats'].get('outstanding') == 0 and report['stats'].get('worker_exit_code') == 0 and
                            report['stats'].get('control_eof') is True and report['stats'].get('shutdown_timed_out') is False,
                            'native resources did not stop normally')
                    for name, original in originals.items():
                        require((source / name).read_bytes() == original and (work / name).read_bytes() == original,
                                'upstream shell or library changed during execution')
                    validate_evidence(report)
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
        sys.exit('Linux rpath selftest failed: ' + str(error))
