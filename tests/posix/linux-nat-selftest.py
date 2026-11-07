"""Run the complete original ICMP RELATED/NAT shell on imported Linux."""
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


EXPECTED_COUNTERS = [
    ('nsclient1', 'unknown', 0, 0), ('nsclient2', 'unknown', 0, 0),
    ('nsrouter1', 'unknown', 0, 0), ('nsrouter2', 'unknown', 0, 0),
    ('nsrouter1', 'related', 0, 0), ('nsrouter2', 'related', 0, 0), ('nsclient1', 'related', 0, 0),
    ('nsclient2', 'new', 2, 2076), ('nsrouter2', 'related', 0, 0),
    ('nsrouter1', 'related', 1, 576), ('nsclient1', 'related', 1, 576),
    ('nsrouter1', 'related', 2, 1856), ('nsclient1', 'related', 2, 1856),
    ('nsclient1', 'redir4', 1, 112), ('nsclient1', 'redir6', 1, 192),
]
PING_ARGUMENTS = [
    ['-c', '1', '-s', '1000', '-q', '-M', 'do', '192.168.2.2'],
    ['-c', '1', '-s', '1000', '-q', 'dead:2::2'],
    ['-W', '0.5', '-q', '-c', '1', '-s', '1300', '-M', 'do', '192.168.2.2'],
    ['-W', '0.5', '-c', '1', '-s', '1300', 'dead:2::2'],
    ['-W', '1', '-q', '-i', '0.5', '-c', '2', '192.168.1.42'],
    ['-W', '1', '-c', '1', 'dead:1::42'],
]


def validate_commands(records):
    pings = [r for r in records if r['tool'] in ('ping', 'ping6')]
    require([r['arguments'] for r in pings] == PING_ARGUMENTS and
            [r['returncode'] == 0 for r in pings[:4]] == [True, True, False, False] and
            all(r['namespace'].startswith('nsclient1-') and not r['stderr'] for r in pings),
            'incomplete original dual-stack connectivity/PMTU/error/redirect probes')
    counters = [r for r in records if r['tool'] == 'nft' and r['arguments'][:2] == ['list', 'counter']]
    observed = []
    for record in counters:
        values = re.findall(r'packets (\d+) bytes (\d+)', record['stdout'])
        require(record['returncode'] == 0 and len(values) == 1, 'missing actual native counter response')
        observed.append((record['namespace'].split('-', 1)[0], record['arguments'][-1], *map(int, values[0])))
    require(observed == EXPECTED_COUNTERS, 'incomplete native RELATED/unknown/new/redirect counter matrix')
    rules = [r for r in records if 'ruleset' in r]
    require(len(rules) == 5 and all(r['returncode'] == 0 for r in rules) and
            'table ip nat' in rules[-1]['ruleset'] and 'table ip6 nat' in rules[-1]['ruleset'] and
            rules[-1]['ruleset'].count('masquerade') == 2,
            'original dual-stack NAT rules did not load in the resident kernel')
    snapshots = [r['nat_snapshots'] for r in records if 'nat_snapshots' in r]
    require(len(snapshots) == 1 and len(snapshots[0]) == 2, 'missing native masquerade observations')
    for snapshot, family, size in zip(snapshots[0], ('ip', 'ip6'), (2356, 2396)):
        rules = [item['rule'] for item in snapshot['nftables'] if 'rule' in item]
        require(len(rules) == 1 and rules[0]['family'] == family and
                any('masquerade' in e for e in rules[0]['expr']) and
                [e['counter'] for e in rules[0]['expr'] if 'counter' in e] == [dict(packets=2, bytes=size)],
                'native masquerade did not account for the original two probes per family')
    require(all(r['returncode'] == 0 for r in records if r not in pings),
            'unexpected native setup/counter/cleanup failure')


def validate_evidence(report):
    result = report.get('original', {})
    require(result.get('returncode') == 0 and not result.get('stderr') and result.get('stdout', '').splitlines() ==
            ['PASS: icmp mtu error had RELATED state', 'PASS: icmp redirects had RELATED state'],
            'incomplete original ICMP RELATED shell')
    require(report.get('missing_backend_control', {}).get('returncode') not in (None, 0),
            'original NAT shell passed without imported Linux')
    validate_commands(report.get('commands', []))
    native, stats = report.get('native_fixture', {}), report.get('stats', {})
    require(native.get('namespaces_created') == native.get('namespaces_deleted') == 4 and
            native.get('netlinks', 0) > 0 and native.get('raw_sockets', 0) > 0 and
            native.get('accepts') == native.get('mptcp') == native.get('live') == 0 and
            stats.get('outstanding') == 0 and stats.get('worker_exit_code') == 0 and
            stats.get('control_eof') is True and stats.get('shutdown_timed_out') is False,
            'native namespaces/sockets/packets did not stop normally')


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
    require(manifest.get('config_fragment') == 'config/native-linux-nat-selftests.config',
            'NAT test requires its real native nftables/masquerade profile')
    config = set((Path(manifest['kernel']) / '.config').read_text().splitlines())
    require({'CONFIG_NF_CONNTRACK=y', 'CONFIG_NF_NAT=y', 'CONFIG_NF_TABLES=y', 'CONFIG_NF_TABLES_INET=y',
             'CONFIG_NFT_CT=y', 'CONFIG_NFT_NAT=y', 'CONFIG_NFT_MASQ=y'}.issubset(config),
            'missing actual native NAT/nftables facilities')
    source = Path(manifest['source']) / 'tools/testing/selftests/net'
    originals = {}
    for name in ('netfilter/conntrack_icmp_related.sh', 'netfilter/lib.sh', 'lib.sh', 'netfilter/Makefile'):
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
        transport_sha256=hashlib.sha256(Path(__file__).with_name('linux-nat-tools.py').read_bytes()).hexdigest())
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
        with tempfile.TemporaryDirectory(prefix='ker-nat-', dir='/dev/shm') as temporary, \
                tempfile.TemporaryDirectory(prefix='ker-nat-exec-', dir=args.server.parent) as executable:
            root, work = Path(temporary), Path(executable)
            for name, data in originals.items():
                (work / name).parent.mkdir(parents=True, exist_ok=True)
                (work / name).write_bytes(data)
            bins = work / 'bin'; bins.mkdir()
            for name in ('ip', 'nft'):
                (bins / name).write_text('#!' + sys.executable + '\n' + Path(__file__).with_name('linux-nat-tools.py').read_text())
                (bins / name).chmod(0o700)
            report['original_tools'] = {}
            for name in ('ping', 'ping6', 'nft'):
                program = Path(shutil.which(name)).resolve()
                target = bins / ('original-' + name)
                shutil.copyfile(program, target); target.chmod(0o700)
                environment['KER_NAT_' + name.upper()] = str(target)
                report['original_tools'][name] = dict(path=str(program), sha256=hashlib.sha256(target.read_bytes()).hexdigest())
            channel, counts, stats, log = root / 'socket', root / 'counts.json', root / 'stats.json', root / 'commands.jsonl'
            environment.update(KER_MPTCP_SOCKET_CHANNEL=str(channel),
                KER_MPTCP_FIXTURE_SOURCE=str(Path(__file__).resolve().parent),
                KER_NAT_IP=str(args.tools / 'ip'), KER_NAT_PRELOAD=str(args.preload),
                KER_NAT_LOG=str(log), PATH=str(bins) + os.pathsep + environment['PATH'])
            negative = dict(environment, KER_MPTCP_SOCKET_CHANNEL=str(root / 'absent'), WAIT_TIMEOUT='1')
            missing = subprocess.run(['bash', './conntrack_icmp_related.sh'], cwd=work / 'netfilter', env=negative,
                                     capture_output=True, text=True, timeout=30)
            report['missing_backend_control'] = dict(returncode=missing.returncode, stdout=missing.stdout, stderr=missing.stderr)
            require(missing.returncode != 0, 'original NAT shell passed without native Linux')
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
                    child = subprocess.Popen(['bash', './conntrack_icmp_related.sh'], cwd=work / 'netfilter', env=environment,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
                    try:
                        stdout, stderr = child.communicate(timeout=120)
                    except BaseException:
                        common.cleanup.kill_tree(child.pid)
                        common.cleanup.bounded_communicate(child, timeout=5)
                        raise
                    report['original'] = dict(returncode=child.returncode, stdout=stdout, stderr=stderr)
                    report['commands'] = [json.loads(line) for line in log.read_text().splitlines()]
                    require(child.returncode == 0 and stdout.splitlines() == ['PASS: icmp mtu error had RELATED state', 'PASS: icmp redirects had RELATED state'] and not stderr,
                            'original NAT shell failed: ' + stdout + stderr)
                    validate_commands(report['commands'])
                    common.fixture.stop(channel)
                    require(process.wait(timeout=20) == 0, 'native fixture shutdown failed')
                    native = json.loads(counts.read_text()); report['native_fixture'] = native
                    require(native['namespaces_created'] == native['namespaces_deleted'] == 4 and
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
        sys.exit('Linux NAT selftest failed: ' + str(error))
