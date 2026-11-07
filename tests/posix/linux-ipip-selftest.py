"""Run the complete original IPIP PMTU shell on imported Linux."""
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


def validate_evidence(report):
    result = report.get('original', {})
    require(result.get('returncode') == 0 and result.get('stdout', '').splitlines() ==
            ['OK: PMTU without connection tracking', 'OK: PMTU with connection tracking'],
            'incomplete original IPIP PMTU shell')
    require(report.get('missing_backend_control', {}).get('returncode', 0) != 0, 'host fallback passed')
    require(report.get('mixed_poll_missing_backend', {}).get('returncode', 0) != 0, 'readiness control used host fallback')
    records = report['commands']
    listeners = [r for r in records if r['tool'] == 'socat' and any('udp4-listen:' in a for a in r['arguments'])]
    senders = [r for r in records if r['tool'] == 'socat' and 'UDP:192.168.20.2:5000' in r['arguments']]
    require(len(listeners) == 2 and all(r['stdout'] == 'a' * 1400 for r in listeners) and
            len(senders) == 6,
            'incomplete original IPIP UDP sender/receiver matrix')
    require(all(r['arguments'] == ['-t', '3', '-', 'udp4-listen:5000,reuseaddr'] for r in listeners) and
            all(r['arguments'] == ['-t', '1', '-u', 'STDIN', 'UDP:192.168.20.2:5000'] for r in senders),
            'modified original UDP commands or deadlines')
    require(len([r for r in records if r['tool'] == 'iptables' and
                r['arguments'] == ['-A', 'FORWARD', '-m', 'conntrack', '--ctstate', 'NEW']]) == 1,
            'missing original conntrack rule')
    native, stats = report.get('native_fixture', {}), report.get('stats', {})
    # The original shell asserts received bytes and intentionally ignores socat
    # exit statuses during PMTU discovery. Preserve those errors and require
    # every reported UDP error to have a real resident syscall observation.
    errors = {'Message too long': 0, 'Connection refused': 0}
    for row in records:
        if row['tool'] != 'socat':
            require(row['returncode'] == 0 and not row.get('stderr'), 'native setup tool failed')
            continue
        require(row['returncode'] in (0, 1), 'unexpected original socat exit')
        for line in row['stderr'].splitlines():
            match = re.fullmatch(r'.*socat\[\d+\] E (?:write|read)\(.*: (Message too long|Connection refused)', line)
            require(match is not None, 'unexpected socat error: ' + line)
            errors[match[1]] += 1
    require(sorted(result.get('stderr', '').splitlines()) ==
            sorted(line for row in records for line in row.get('stderr', '').splitlines()),
            'unrecorded original shell error')
    require(native.get('native_emsgsize', 0) >= errors['Message too long'] and
            native.get('native_econnrefused', 0) >= errors['Connection refused'],
            'UDP errors lack resident syscall evidence')
    control = report.get('mixed_poll_control', {})
    require(control.get('returncode') == 0 and control.get('stdout') == 'PASS mixed native UDP and host poll/select\n'
            and not control.get('stderr'), 'mixed readiness control failed')
    require(native.get('namespaces_created') == native.get('namespaces_deleted') == 5 and
            native.get('netlinks', 0) > 0 and native.get('udp_sockets', 0) >= 8 and
            native.get('accepts') == native.get('mptcp') == native.get('live') == 0 and
            stats.get('outstanding') == 0 and stats.get('worker_exit_code') == 0 and
            stats.get('control_eof') is True and stats.get('shutdown_timed_out') is False,
            'native IPIP namespaces/sockets/packets did not stop normally')


def main():
    parser = argparse.ArgumentParser()
    for name in ('server', 'poll_control', 'preload', 'tools', 'launcher', 'library', 'worker', 'pmd_dir', 'manifest', 'evidence'):
        parser.add_argument('--' + name.replace('_', '-'), type=Path, required=True)
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    if not args.inside:
        return subprocess.run(['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()),
                               *sys.argv[1:], '--inside']).returncode
    manifest = json.loads(args.manifest.read_text())
    require(manifest.get('config_fragment') == 'config/native-linux-ipip-selftests.config',
            'IPIP test requires its real native tunnel/conntrack profile')
    config = set((Path(manifest['kernel']) / '.config').read_text().splitlines())
    require({'CONFIG_NET_IPIP=y', 'CONFIG_NF_CONNTRACK=y', 'CONFIG_NETFILTER_XTABLES=y',
             'CONFIG_IP_NF_IPTABLES=y', 'CONFIG_IP_NF_FILTER=y', 'CONFIG_NETFILTER_XT_MATCH_CONNTRACK=y'}.issubset(config),
            'missing actual native IPIP/conntrack facilities')
    source = Path(manifest['source']) / 'tools/testing/selftests/net'
    originals = {}
    for name in ('netfilter/conntrack_ipip_mtu.sh', 'netfilter/lib.sh', 'lib.sh', 'netfilter/Makefile'):
        original = subprocess.check_output(['git', '-C', manifest['source'], 'show',
            manifest['linux']['revision'] + ':tools/testing/selftests/net/' + name])
        require((source / name).read_bytes() == original, 'modified upstream source: ' + name)
        originals[name] = original
    tools = json.loads((args.tools / 'provenance.json').read_text())
    require(tools['version'] == '6.12.0' and tools['archive_sha256'] ==
            'bbd141ef7b5d0127cc2152843ba61f274dc32814fa3e0f13e7d07a080bef53d9' and
            all(hashlib.sha256((args.tools / name).read_bytes()).hexdigest() == tools['binaries'][name]
                for name in ('ip', 'ss')),
            'wrong or modified pinned iproute2 tool')
    report = dict(status='FAIL', revision=manifest['linux']['revision'], fingerprint=manifest['fingerprint'],
        source_hashes={name: hashlib.sha256(data).hexdigest() for name, data in originals.items()},
        iproute2=tools, preload_sha256=hashlib.sha256(args.preload.read_bytes()).hexdigest(),
        library_sha256=hashlib.sha256(args.library.read_bytes()).hexdigest(),
        poll_control_sha256=hashlib.sha256(args.poll_control.read_bytes()).hexdigest(),
        server_sha256=hashlib.sha256(args.server.read_bytes()).hexdigest(),
        transport_sha256=hashlib.sha256(Path(__file__).with_name('linux-ipip-tools.py').read_bytes()).hexdigest())
    environment = {k: v for k, v in os.environ.items() if k not in ('LD_PRELOAD', 'WAIT_TIMEOUT', 'BUSYWAIT_TIMEOUT', 'PAUSE_ON_FAIL') and not k.startswith(('KER_', 'KSFT_'))}
    environment['LC_ALL'] = 'C'
    try:
        for command in (['ip', 'link', 'set', 'lo', 'up'],
                        ['ip', 'link', 'add', 'kerhost', 'type', 'veth', 'peer', 'name', 'kerlink'],
                        # libc AI_ADDRCONFIG runs in this host process namespace.
                        # Give the isolated transport a real IPv4 address; all
                        # test IP sockets still require the resident backend.
                        ['ip', 'addr', 'add', '198.18.0.1/24', 'dev', 'kerhost'],
                        ['ip', 'tuntap', 'add', 'dev', 'kerpeer', 'mode', 'tap', 'multi_queue'],
                        *[['ip', 'link', 'set', name, 'up'] for name in ('kerhost', 'kerlink', 'kerpeer')]):
            subprocess.run(command, check=True)
        cpu = min(os.sched_getaffinity(0))
        eal = (f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry --iova-mode=va -m 64 '
               f'-d {shlex.quote(str(args.pmd_dir / "librte_net_tap.so"))} --vdev=net_tap0,iface=kerpeer,remote=kerlink')
        with tempfile.TemporaryDirectory(prefix='ker-ipip-', dir='/dev/shm') as temporary, \
                tempfile.TemporaryDirectory(prefix='ker-ipip-exec-', dir=args.server.parent) as executable:
            root, work = Path(temporary), Path(executable)
            for name, data in originals.items():
                (work / name).parent.mkdir(parents=True, exist_ok=True)
                (work / name).write_bytes(data)
            bins = work / 'bin'; bins.mkdir()
            for name in ('ip', 'ss', 'socat', 'iptables'):
                (bins / name).write_text('#!' + sys.executable + '\n' + Path(__file__).with_name('linux-ipip-tools.py').read_text())
                (bins / name).chmod(0o700)
            report['original_tools'] = {}
            for name in ('socat', 'iptables'):
                program = shutil.which('iptables-legacy' if name == 'iptables' else name)
                require(program is not None, 'missing original ' + name)
                environment['KER_IPIP_' + name.upper()] = program
                report['original_tools'][name] = dict(path=program, sha256=hashlib.sha256(Path(program).read_bytes()).hexdigest())
            environment['KER_IPIP_SS'] = str(args.tools / 'ss')
            channel, counts, stats, log = root / 'socket', root / 'counts.json', root / 'stats.json', root / 'commands.jsonl'
            environment.update(KER_MPTCP_SOCKET_CHANNEL=str(channel),
                KER_MPTCP_FIXTURE_SOURCE=str(Path(__file__).resolve().parent),
                KER_IPIP_IP=str(args.tools / 'ip'), KER_IPIP_PRELOAD=str(args.preload),
                KER_IPIP_LOG=str(log), XTABLES_LOCKFILE=str(root / 'xtables.lock'), PATH=str(bins) + os.pathsep + environment['PATH'])
            negative = dict(environment, KER_MPTCP_SOCKET_CHANNEL=str(root / 'absent'), WAIT_TIMEOUT='1')
            missing = subprocess.run(['bash', './conntrack_ipip_mtu.sh'], cwd=work / 'netfilter', env=negative,
                                     capture_output=True, text=True, timeout=30)
            report['missing_backend_control'] = dict(returncode=missing.returncode, stdout=missing.stdout, stderr=missing.stderr)
            require(missing.returncode != 0, 'original IPIP shell passed without native Linux')
            control_negative = subprocess.run([str(args.poll_control)],
                env=dict(negative, LD_PRELOAD=str(args.preload)), capture_output=True, text=True, timeout=15)
            report['mixed_poll_missing_backend'] = dict(returncode=control_negative.returncode,
                stdout=control_negative.stdout, stderr=control_negative.stderr)
            require(control_negative.returncode != 0, 'mixed readiness control used host UDP fallback')
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
                    control = subprocess.run([str(args.poll_control)], env=dict(environment, LD_PRELOAD=str(args.preload)),
                        capture_output=True, text=True, timeout=15)
                    report['mixed_poll_control'] = dict(returncode=control.returncode, stdout=control.stdout, stderr=control.stderr)
                    require(control.returncode == 0, 'mixed readiness control failed: ' + control.stderr)
                    child = subprocess.Popen(['bash', './conntrack_ipip_mtu.sh'], cwd=work / 'netfilter', env=environment,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
                    try:
                        stdout, stderr = child.communicate(timeout=120)
                    except BaseException:
                        common.cleanup.kill_tree(child.pid)
                        common.cleanup.bounded_communicate(child, timeout=5)
                        raise
                    report['original'] = dict(returncode=child.returncode, stdout=stdout, stderr=stderr)
                    report['commands'] = [json.loads(line) for line in log.read_text().splitlines()]
                    require(child.returncode == 0 and stdout.splitlines() == ['OK: PMTU without connection tracking', 'OK: PMTU with connection tracking'],
                            'original IPIP shell failed: ' + stdout + stderr)
                    common.fixture.stop(channel)
                    require(process.wait(timeout=20) == 0, 'native fixture shutdown failed')
                    native = json.loads(counts.read_text()); report['native_fixture'] = native
                    require(native['namespaces_created'] == native['namespaces_deleted'] == 5 and
                            native['netlinks'] > 0 and native['udp_sockets'] > 0 and
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
        sys.exit('Linux IPIP selftest failed: ' + str(error))
