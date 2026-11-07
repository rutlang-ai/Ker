"""Run the complete original namespace/device-name shell on imported Linux."""
import argparse
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import time

spec = importlib.util.spec_from_file_location('network_runner', Path(__file__).with_name('linux-network-selftest.py'))
common = importlib.util.module_from_spec(spec); spec.loader.exec_module(common)
require = common.require


def validate_commands(records):
    moves = [r for r in records if r['operation'] == 'move']
    require(len(moves) == 5 and [r['returncode'] for r in moves] == [0, 1, 0, 1, 0],
            'incomplete native move/conflict/rename/alternative-name matrix')
    require([r.get('errno') for r in moves if r['returncode']] == [errno.EEXIST, errno.EEXIST],
            'name conflicts did not return actual native EEXIST')
    require(moves[2]['arguments'][-2:] == ['name', 'dummy-dev1'], 'missing move with rename')
    tools = [r for r in records if r['operation'] == 'ip']
    shows = [r for r in tools if r['arguments'][:2] == ['link', 'show']]
    require(len(tools) == 25 and len(shows) == 4 and
            [r['returncode'] == 0 for r in shows] == [True, True, True, False],
            'incomplete native link/alternative-name visibility checks')
    require(shows[-2]['arguments'][-1] == shows[-1]['arguments'][-1] == 'some-alt-name' and
            shows[-2]['namespace'] != shows[-1]['namespace'],
            'alternative-name lookup did not cross namespace boundaries')
    require(all(r['returncode'] == 0 for r in tools if r is not shows[-1]),
            'unexpected native iproute2 failure')


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
    require(manifest.get('config_fragment') == 'config/native-linux-netns-name.config',
            'namespace-name test requires its native dummy-device profile')
    require('CONFIG_DUMMY=y' in (Path(manifest['kernel']) / '.config').read_text().splitlines(),
            'original namespace-name test requires the actual dummy driver')
    source = Path(manifest['source']) / 'tools/testing/selftests/net'
    originals = {}
    for name in ('netns-name.sh', 'lib.sh', 'Makefile'):
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
        transport_sha256=hashlib.sha256(Path(__file__).with_name('linux-netns-name-ip.py').read_bytes()).hexdigest())
    environment = {k: v for k, v in os.environ.items() if k not in ('LD_PRELOAD', 'WAIT_TIMEOUT', 'PAUSE_ON_FAIL') and not k.startswith('KER_')}
    try:
        for command in (['ip', 'link', 'set', 'lo', 'up'],
                        ['ip', 'link', 'add', 'kerhost', 'type', 'veth', 'peer', 'name', 'kerlink'],
                        ['ip', 'tuntap', 'add', 'dev', 'kerpeer', 'mode', 'tap', 'multi_queue'],
                        *[['ip', 'link', 'set', name, 'up'] for name in ('kerhost', 'kerlink', 'kerpeer')]):
            subprocess.run(command, check=True)
        cpu = min(os.sched_getaffinity(0))
        eal = (f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry --iova-mode=va -m 64 '
               f'-d {shlex.quote(str(args.pmd_dir / "librte_net_tap.so"))} --vdev=net_tap0,iface=kerpeer,remote=kerlink')
        with tempfile.TemporaryDirectory(prefix='ker-netns-', dir='/dev/shm') as temporary, \
                tempfile.TemporaryDirectory(prefix='ker-netns-exec-', dir=args.server.parent) as executable:
            root, work = Path(temporary), Path(executable)
            for name, data in originals.items():
                (work / name).write_bytes(data)
            (work / 'ip').write_text('#!' + sys.executable + '\n' + Path(__file__).with_name('linux-netns-name-ip.py').read_text())
            (work / 'ip').chmod(0o700)
            channel, counts, stats, log = root / 'socket', root / 'counts.json', root / 'stats.json', root / 'commands.jsonl'
            environment.update(KER_MPTCP_SOCKET_CHANNEL=str(channel),
                KER_MPTCP_FIXTURE_SOURCE=str(Path(__file__).resolve().parent),
                KER_NETNS_NAME_IP=str(args.tools / 'ip'), KER_NETNS_NAME_PRELOAD=str(args.preload),
                KER_NETNS_NAME_LOG=str(log), PATH=str(work) + os.pathsep + environment['PATH'])
            negative = dict(environment, KER_MPTCP_SOCKET_CHANNEL=str(root / 'absent'), WAIT_TIMEOUT='1')
            missing = subprocess.run(['bash', './netns-name.sh'], cwd=work, env=negative,
                                     capture_output=True, text=True, timeout=30)
            report['missing_backend_control'] = dict(returncode=missing.returncode, stdout=missing.stdout, stderr=missing.stderr)
            require(missing.returncode != 0, 'original namespace-name shell passed without native Linux')
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
                    child = subprocess.Popen(['bash', './netns-name.sh'], cwd=work, env=environment,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
                    try:
                        stdout, stderr = child.communicate(timeout=120)
                    except BaseException:
                        common.cleanup.kill_tree(child.pid)
                        common.cleanup.bounded_communicate(child, timeout=5)
                        raise
                    report['original'] = dict(returncode=child.returncode, stdout=stdout, stderr=stderr)
                    require(child.returncode == 0 and stdout.split() == ['netns-name.sh', '[', 'OK', ']'] and not stderr,
                            'original namespace-name shell failed: ' + stdout + stderr)
                    records = [json.loads(line) for line in log.read_text().splitlines()]
                    report['commands'] = records
                    validate_commands(records)
                    common.fixture.stop(channel)
                    require(process.wait(timeout=20) == 0, 'native fixture shutdown failed')
                    native = json.loads(counts.read_text()); report['native_fixture'] = native
                    require(native['namespaces_created'] == native['namespaces_deleted'] == 2 and
                            native['netlinks'] >= 30 and native['sockets'] == native['netlinks'] and
                            native['diag_sends'] >= 30 and native['diag_receives'] >= native['diag_sends'] and
                            native['accepts'] == native['mptcp'] == native['raw_sockets'] == native['live'] == 0,
                            'original native namespace/Netlink matrix or cleanup incomplete')
                    report['stats'] = json.loads(stats.read_text())
                    require(report['stats'].get('outstanding') == 0 and report['stats'].get('worker_exit_code') == 0 and
                            report['stats'].get('control_eof') is True and report['stats'].get('shutdown_timed_out') is False,
                            'native resources did not stop normally')
                    for name, original in originals.items():
                        require((source / name).read_bytes() == original and (work / name).read_bytes() == original,
                                'upstream shell or library changed during execution')
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
        sys.exit('Linux namespace-name selftest failed: ' + str(error))
