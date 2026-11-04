"""Run pinned mptcp_connect against an independent peer through native Linux/DPDK."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time


def require(value, message):
    if not value:
        raise RuntimeError(message)


def negotiated(counters, role):
    required = {'mptcp_capable_syn_tx', 'mptcp_capable_syn_rx', 'mptcp_capable_synack_rx',
                'mptcp_capable_ack_rx', 'mptcp_fallback_synack', 'mptcp_fallback_ack'}
    if not required <= counters.keys():
        return False
    key = 'mptcp_capable_synack_rx' if role == 'client' else 'mptcp_capable_ack_rx'
    return counters.get(key, 0) > 0 and not any(
        counters.get(k, 0) for k in ('mptcp_fallback_synack', 'mptcp_fallback_ack'))


def packet_evidence(directory, port):
    found = {}
    files = {}
    for path in directory.glob('*.pcap'):
        data = path.read_bytes()
        require(len(data) >= 24 and data[:4] in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'), 'invalid capture')
        endian = '<' if data[0] == 0xd4 else '>'
        files[path.name] = hashlib.sha256(data).hexdigest()
        offset = 24
        while offset < len(data):
            require(offset + 16 <= len(data), 'truncated capture record')
            _, _, length, original = struct.unpack_from(endian + 'IIII', data, offset)
            offset += 16
            frame = data[offset:offset + length]
            offset += length
            require(length == original and len(frame) == length, 'truncated frame')
            if len(frame) < 54:
                continue
            ethertype = struct.unpack_from('!H', frame, 12)[0]
            if ethertype == 0x0800 and frame[23] == 6:
                tcp = 14 + (frame[14] & 15) * 4
            elif ethertype == 0x86dd and frame[20] == 6:
                tcp = 54
            else:
                continue
            if len(frame) < tcp + 20 or port not in struct.unpack_from('!HH', frame, tcp):
                continue
            end = tcp + (frame[tcp + 12] >> 4) * 4
            require(tcp + 20 <= end <= len(frame), 'bad TCP header')
            flags = frame[tcp + 13]
            cursor = tcp + 20
            while cursor < end:
                kind = frame[cursor]
                if kind == 0:
                    break
                if kind == 1:
                    cursor += 1
                    continue
                require(cursor + 2 <= end and frame[cursor + 1] >= 2, 'bad TCP option')
                size = frame[cursor + 1]
                require(cursor + size <= end, 'truncated TCP option')
                if kind == 30 and size >= 3:
                    subtype = frame[cursor + 2] >> 4
                    direction = 'tx' if path.name.startswith('ker-tx-') else 'rx'
                    event = ('synack' if flags & 0x12 == 0x12 else 'syn' if flags & 2 else 'ack')
                    key = direction + ('_capable_' + event if subtype == 0 else '_dss' if subtype == 2 else '_other')
                    found[key] = found.get(key, 0) + 1
                cursor += size
    require(files, 'missing native capture files')
    return dict(options=found, sha256=files)


def terminate(process):
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    process.wait()


def transfer(args, root, eal, mode, fallback, index):
    work = root / (mode + ('-fallback' if fallback else ''))
    work.mkdir()
    capture = work / 'capture'
    capture.mkdir(mode=0o700)
    ready = work / 'ready'
    stats_file = work / 'stats.json'
    port = 29500 + index
    host = '198.18.0.1' if args.family == 4 else '2001:db8:1::1'
    native = '198.18.0.2' if args.family == 4 else '2001:db8:1::2'
    environment = {k: v for k, v in os.environ.items() if k != 'LD_PRELOAD' and not k.startswith('KER_')}
    payloads = {role: (bytes(range(256)) * (257 if role == 'client' else 193) +
                      f'{args.family}/{args.role}/{mode}/{fallback}/{role}'.encode())
                for role in ('client', 'server')}
    for role, payload in payloads.items():
        (work / (role + '.input')).write_bytes(payload)
    for command in (['ip', 'neigh', 'flush', 'dev', 'kerhost'],
                    ['ip', '-6', 'neigh', 'flush', 'dev', 'kerhost']):
        subprocess.run(command, check=True)
    launcher = [sys.executable, str(args.launcher), '--library', str(args.library),
                '--io-worker', str(args.worker), '--address', '198.18.0.2/24',
                '--address6', '2001:db8:1::2/64', '--port', 'net_tap0', '--eal', eal,
                '--stats', str(stats_file), '--pcap-dir', str(capture)]
    commands = {}
    for role in ('server', 'client'):
        is_native = role == args.role
        address = (native if args.role == 'server' else host)
        protocol = 'TCP' if fallback and not is_native else 'MPTCP'
        command = [str(args.binary), '-p', str(port), '-s', protocol, '-m', mode,
                   '-i', str(work / (role + '.input'))]
        if role == 'server':
            command.append('-l')
        if args.family == 6:
            command.append('-6')
        command.append(address)
        commands[role] = launcher + ['--'] + command if is_native else command
    processes = {}
    files = []
    try:
        for role in ('server', 'client'):
            env = dict(environment)
            if mode == 'sendfile' and role == args.role:
                env['KER_MPTCP_TEST_NATIVE_INPUT'] = str(work / (role + '.input'))
            if role == 'server':
                env['KER_MPTCP_TEST_LISTENER_READY'] = str(ready)
            output = (work / (role + '.output')).open('wb')
            errors = (work / (role + '.stderr')).open('wb')
            files += [output, errors]
            process = subprocess.Popen(commands[role], env=env, stdout=output, stderr=errors,
                                       start_new_session=True)
            processes[role] = process
            if role == 'server':
                deadline = time.monotonic() + 20
                while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.01)
                require(ready.exists() and process.poll() is None, 'listener did not become ready: ' +
                        (work / 'server.stderr').read_text(errors='replace'))
        for role, process in processes.items():
            require(process.wait(timeout=40) == 0, role + ' failed: ' +
                    (work / (role + '.stderr')).read_text(errors='replace'))
        for role in ('client', 'server'):
            peer = 'server' if role == 'client' else 'client'
            require((work / (role + '.output')).read_bytes() == payloads[peer], role + ' payload mismatch')
        stats = json.loads(stats_file.read_text())
        require(stats.get('tx', 0) > 0 and stats.get('rx', 0) > 0 and stats.get('outstanding') == 0,
                'missing DPDK activity or leaked packet buffers')
        counters = stats.get('native', {})
        require(counters.get('active_opens' if args.role == 'client' else 'passive_opens', 0) > 0,
                'missing imported Linux TCP activity')
        packets = packet_evidence(capture, port)
        archive = args.evidence.parent / (args.evidence.stem + '-captures') / work.name
        shutil.copytree(capture, archive, dirs_exist_ok=True)
        packets['directory'] = str(archive)
        if fallback:
            require(not negotiated(counters, args.role), 'TCP-only peer unexpectedly negotiated MPTCP')
        else:
            require(negotiated(counters, args.role), 'MPTCP negotiation missing or silently fell back to TCP')
            options = packets['options']
            require(options.get('tx_capable_syn' if args.role == 'client' else 'rx_capable_syn', 0) > 0 and
                    options.get('rx_capable_synack' if args.role == 'client' else 'tx_capable_synack', 0) > 0 and
                    options.get('tx_dss', 0) + options.get('rx_dss', 0) > 0,
                    'capture does not show MP_CAPABLE and DSS on the native wire path')
        return dict(mode=mode, tcp_fallback_control=fallback, stats=stats, capture=packets,
                    native_input_backend='imported-kernel-readonly-fixture' if mode == 'sendfile' else 'host-file',
                    payloads={k: hashlib.sha256(v).hexdigest() for k, v in payloads.items()},
                    stderr={r: (work / (r + '.stderr')).read_text(errors='replace') for r in processes})
    except BaseException as error:
        failure = args.evidence.parent / (args.evidence.stem + '-failed-' + work.name)
        shutil.copytree(work, failure, dirs_exist_ok=True)
        details = {role: {'returncode': process.poll(),
                         'stderr': (work / (role + '.stderr')).read_text(errors='replace')}
                   for role, process in processes.items()}
        raise RuntimeError(str(error) + '; processes=' + json.dumps(details) +
                           '; evidence=' + str(failure)) from error
    finally:
        for process in processes.values():
            terminate(process)
        for file in files:
            file.close()


def main():
    parser = argparse.ArgumentParser()
    for name in ('binary', 'source', 'launcher', 'library', 'worker', 'manifest', 'evidence', 'pmd_dir'):
        parser.add_argument('--' + name.replace('_', '-'), type=Path, required=True)
    parser.add_argument('--family', type=int, choices=(4, 6), required=True)
    parser.add_argument('--role', choices=('client', 'server'), required=True)
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    if not args.inside:
        return subprocess.run(['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()),
                               *sys.argv[1:], '--inside']).returncode
    manifest = json.loads(args.manifest.read_text())
    relative = 'tools/testing/selftests/net/mptcp/mptcp_connect.c'
    original = subprocess.check_output(['git', '-C', manifest['source'], 'show',
                                       manifest['linux']['revision'] + ':' + relative])
    require(args.source.read_bytes() == original, 'modified upstream MPTCP program')
    report = dict(status='FAIL', family=args.family, role=args.role,
                  revision=manifest['linux']['revision'], fingerprint=manifest['fingerprint'],
                  source=relative, source_sha256=hashlib.sha256(original).hexdigest(),
                  binary_sha256=hashlib.sha256(args.binary.read_bytes()).hexdigest(), profiles=[])
    try:
        for command in (['ip', 'link', 'set', 'lo', 'up'],
                        ['ip', 'link', 'add', 'kerhost', 'type', 'veth', 'peer', 'name', 'kerlink'],
                        ['ip', 'tuntap', 'add', 'dev', 'kerpeer', 'mode', 'tap', 'multi_queue'],
                        ['ip', 'addr', 'add', '198.18.0.1/24', 'dev', 'kerhost'],
                        ['ip', '-6', 'addr', 'add', '2001:db8:1::1/64', 'dev', 'kerhost', 'nodad'],
                        *[['ip', 'link', 'set', name, 'up'] for name in ('kerhost', 'kerlink', 'kerpeer')]):
            subprocess.run(command, check=True)
        cpu = min(os.sched_getaffinity(0))
        eal = (f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry --iova-mode=va -m 64 '
               f'-d {shlex.quote(str(args.pmd_dir / "librte_net_tap.so"))} --vdev=net_tap0,iface=kerpeer,remote=kerlink')
        with tempfile.TemporaryDirectory(prefix='ker-mptcp-') as temporary:
            for index, mode in enumerate(('poll', 'mmap', 'sendfile')):
                report['profiles'].append(transfer(args, Path(temporary), eal, mode, False, index))
            report['profiles'].append(transfer(args, Path(temporary), eal, 'poll', True, 3))
        require(args.source.read_bytes() == original, 'upstream source changed during execution')
        report['status'] = 'PASS'
        print(f'LINUX_MPTCP_PASS IPv{args.family} {args.role}: 3 modes; TCP fallback rejected as negotiation')
    except BaseException as error:
        report['error'] = str(error)
        raise
    finally:
        args.evidence.parent.mkdir(parents=True, exist_ok=True)
        args.evidence.write_text(json.dumps(report, indent=2) + '\n')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        print('Linux MPTCP selftest failed: ' + str(error), file=sys.stderr)
        sys.exit(1)
