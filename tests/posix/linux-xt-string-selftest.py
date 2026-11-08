"""Run the unchanged complete Linux xt_string shell against imported Linux."""
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


def validate_evidence(report):
    original = report.get('original', {})
    require(original.get('returncode') == 0 and original.get('stdout', '').splitlines() == ['PASS: string match tests'] and not original.get('stderr'), 'incomplete original xt_string shell')
    require(report.get('missing_backend_control', {}).get('returncode') not in (None, 0), 'original string shell passed without native Linux')
    records = report.get('commands', [])
    require(records and all(r['returncode'] == 0 and not r.get('stderr') for r in records), 'original string setup/tool/counter command failed')
    sends = [r for r in records if r['tool'] == 'socat' and r['arguments'] != ['-h']]
    offsets = [0, 989, 1000, 1389, 1489, 1495, 1500, 1589, 1590, 1600]
    require(len(sends) == len(offsets), 'missing original UDP string probes')
    for row, offset in zip(sends, offsets):
        require(row['arguments'] == ['-t', '1', '-u', 'STDIN', 'UDP-SENDTO:10.1.2.2:27374'] and row.get('stdin') == ' ' * max(0, offset - 28) + 'foo bar baz', 'modified original UDP payload or timeout')
    counters = [r for r in records if r['tool'] == 'iptables' and r['arguments'] == ['-v', '-S', 'OUTPUT']]
    require(len(counters) == 8, 'missing original matching windows')
    expected = [(0,0,0,0), (2,0,2,0), (1,1,1,1), (0,0,0,1), (0,1,0,1), (0,1,0,1), (0,0,0,0), (0,0,0,0)]
    sizes = [0, 2411, 1500, 1506, 1511, 1600, 0, 0]
    rule_specs = [('bm', 1000, 1500), ('bm', 1400, 1600), ('kmp', 1000, 1500), ('kmp', 1400, 1600)]
    for row, packets, size in zip(counters, expected, sizes):
        lines = [line for line in row['stdout'].splitlines() if line.startswith('-A ')]
        require(len(lines) == 4, 'missing native string rules')
        for line, (algorithm, low, high), count in zip(lines, rule_specs, packets):
            prefix = f'-A OUTPUT -o d0 -m string --string "foo bar baz" --algo {algorithm} --from {low} --to {high}'
            require(line == prefix + f' -c {count} {size if count else 0}', 'wrong original BM/KMP fragment/offset counters')
    rules = [r for r in records if r['tool'] == 'iptables' and r['arguments'][:2] == ['-A', 'OUTPUT']]
    require([r['arguments'] for r in rules] == [['-A', 'OUTPUT', '-o', 'd0', '-m', 'string', '--string', 'foo bar baz', '--algo', algorithm, '--from', str(low), '--to', str(high)] for algorithm, low, high in rule_specs], 'modified original string rules')
    require(len({r['namespace'] for r in sends + counters + rules}) == 1 and sends[0]['namespace'].startswith('netns-'), 'wrong native string namespace')
    versions = [r for r in records if r['tool'] == 'iptables' and r['arguments'] == ['--version']]
    require(len(versions) == 1 and '(legacy)' in versions[0]['stdout'], 'original legacy iptables did not participate')
    require(len([r for r in records if r['tool'] == 'iptables' and r['arguments'] == ['-Z', 'OUTPUT']]) == 8, 'missing original counter resets')
    resets = [i for i, row in enumerate(records) if row['tool'] == 'iptables' and row['arguments'] == ['-Z', 'OUTPUT']]
    counter_positions = [i for i, row in enumerate(records) if row['tool'] == 'iptables' and row['arguments'] == ['-v', '-S', 'OUTPUT']]
    send_positions = [i for i, row in enumerate(records) if row['tool'] == 'socat' and row['arguments'] != ['-h']]
    cursor = 0
    for phase, count in enumerate([2, 2, 1, 1, 1, 1, 1, 1]):
        require(resets[phase] < send_positions[cursor] <= send_positions[cursor + count - 1] < counter_positions[phase] and
                (phase == 7 or counter_positions[phase] < resets[phase + 1]), 'wrong original reset/probe/counter order')
        cursor += count
    native, stats = report.get('native_fixture', {}), report.get('stats', {})
    require(native.get('namespaces_created') == native.get('namespaces_deleted') == 1 and native.get('udp_sockets') == 10 and native.get('netlinks', 0) > 0 and native.get('live') == native.get('accepts') == native.get('mptcp') == 0 and stats.get('outstanding') == 0 and stats.get('worker_exit_code') == 0 and stats.get('control_eof') is True and stats.get('shutdown_timed_out') is False, 'native string resources did not stop normally')

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
    require(manifest.get('config_fragment') == 'config/native-linux-xt-string-selftests.config',
            'xt-string test requires its real native xt_string profile')
    config = set((Path(manifest['kernel']) / '.config').read_text().splitlines())
    require({'CONFIG_DUMMY=y', 'CONFIG_NETFILTER_XTABLES=y', 'CONFIG_IP_NF_FILTER=y', 'CONFIG_TEXTSEARCH_BM=y', 'CONFIG_TEXTSEARCH=y', 'CONFIG_TEXTSEARCH_KMP=y', 'CONFIG_NETFILTER_XT_MATCH_STRING=y', 'CONFIG_IP_NF_IPTABLES=y'}.issubset(config), 'missing actual native xt_string facilities')
    source = Path(manifest['source']) / 'tools/testing/selftests/net'
    originals = {}
    for name in ('netfilter/xt_string.sh', 'netfilter/lib.sh', 'lib.sh', 'netfilter/Makefile'):
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
        transport_sha256=hashlib.sha256(Path(__file__).with_name('linux-xt-string-tools.py').read_bytes()).hexdigest())
    environment = {k: v for k, v in os.environ.items() if k not in ('LD_PRELOAD', 'WAIT_TIMEOUT', 'BUSYWAIT_TIMEOUT', 'PAUSE_ON_FAIL') and not k.startswith(('KER_', 'KSFT_'))}
    environment['LC_ALL'] = 'C'
    try:
        for command in (['ip', 'link', 'set', 'lo', 'up'],
                        ['ip', 'link', 'add', 'kerhost', 'type', 'veth', 'peer', 'name', 'kerlink'],
                        ['ip', 'tuntap', 'add', 'dev', 'kerpeer', 'mode', 'tap', 'multi_queue'],
                        ['ip', 'addr', 'add', '198.18.0.1/24', 'dev', 'kerhost'],
                        *[['ip', 'link', 'set', name, 'up'] for name in ('kerhost', 'kerlink', 'kerpeer')]):
            subprocess.run(command, check=True)
        cpu = min(os.sched_getaffinity(0))
        eal = (f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry --iova-mode=va -m 64 '
               f'-d {shlex.quote(str(args.pmd_dir / "librte_net_tap.so"))} --vdev=net_tap0,iface=kerpeer,remote=kerlink')
        with tempfile.TemporaryDirectory(prefix='ker-xt-string-', dir='/dev/shm') as temporary, \
                tempfile.TemporaryDirectory(prefix='ker-xt-string-exec-', dir=args.server.parent) as executable:
            root, work = Path(temporary), Path(executable)
            for name, data in originals.items():
                (work / name).parent.mkdir(parents=True, exist_ok=True)
                (work / name).write_bytes(data)
            bins = work / 'bin'; bins.mkdir()
            for name in ('ip', 'socat', 'iptables'):
                (bins / name).write_text('#!' + sys.executable + '\n' + Path(__file__).with_name('linux-xt-string-tools.py').read_text())
                (bins / name).chmod(0o700)
            report['original_tools'] = {}
            program = Path(shutil.which('socat')).resolve()
            target = bins / 'original-socat'
            shutil.copyfile(program, target); target.chmod(0o700)
            environment['KER_XT_STRING_SOCAT'] = str(target)
            report['original_tools']['socat'] = dict(path=str(program), sha256=hashlib.sha256(target.read_bytes()).hexdigest())
            program = shutil.which('iptables-legacy')
            require(program is not None, 'missing original iptables-legacy')
            environment['KER_XT_STRING_IPTABLES'] = program
            report['original_tools']['iptables'] = dict(path=program, sha256=hashlib.sha256(Path(program).read_bytes()).hexdigest())
            channel, counts, stats, log = root / 'socket', root / 'counts.json', root / 'stats.json', root / 'commands.jsonl'
            environment.update(KER_MPTCP_SOCKET_CHANNEL=str(channel),
                KER_MPTCP_FIXTURE_SOURCE=str(Path(__file__).resolve().parent),
                KER_XT_STRING_IP=str(args.tools / 'ip'), KER_XT_STRING_PRELOAD=str(args.preload),
                KER_XT_STRING_LOG=str(log), XTABLES_LOCKFILE=str(root / 'xtables.lock'), PATH=str(bins) + os.pathsep + environment['PATH'])
            negative = dict(environment, KER_MPTCP_SOCKET_CHANNEL=str(root / 'absent'), WAIT_TIMEOUT='1')
            missing = subprocess.run(['bash', './xt_string.sh'], cwd=work / 'netfilter', env=negative,
                                     capture_output=True, text=True, timeout=30)
            report['missing_backend_control'] = dict(returncode=missing.returncode, stdout=missing.stdout, stderr=missing.stderr)
            require(missing.returncode != 0, 'original xt-string shell passed without native Linux')
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
                    child = subprocess.Popen(['bash', './xt_string.sh'], cwd=work / 'netfilter', env=environment,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
                    try:
                        stdout, stderr = child.communicate(timeout=120)
                    except BaseException:
                        common.cleanup.kill_tree(child.pid)
                        common.cleanup.bounded_communicate(child, timeout=5)
                        raise
                    report['original'] = dict(returncode=child.returncode, stdout=stdout, stderr=stderr)
                    report['commands'] = [json.loads(line) for line in log.read_text().splitlines()]
                    require(child.returncode == 0 and stdout.splitlines() == ['PASS: string match tests'],
                            'original xt-string shell failed: ' + stdout + stderr)
                    common.fixture.stop(channel)
                    require(process.wait(timeout=20) == 0, 'native fixture shutdown failed')
                    native = json.loads(counts.read_text()); report['native_fixture'] = native
                    require(native['namespaces_created'] == native['namespaces_deleted'] == 1 and
                            native['netlinks'] > 0 and native['udp_sockets'] == 10 and
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
        sys.exit('Linux xt-string selftest failed: ' + str(error))
