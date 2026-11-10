#!/usr/bin/env python3
"""Host process/native network transport for the original forwarding scripts.

Ordinary ip commands use unmodified pinned iproute2. Only process VRF binding
and proc/sysctl access need translation between the two kernel instances.
"""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

root = Path(os.environ['KER_MPTCP_FIXTURE_SOURCE'])
spec = importlib.util.spec_from_file_location('forwarding_diag', root / 'linux-mptcp-diag-shim.py')
diag = importlib.util.module_from_spec(spec); spec.loader.exec_module(diag)


def broadcast_snapshot(env):
    state = {}
    for key, query in (
        ('links', ['-d', '-j', 'link', 'show']),
        ('addresses', ['-j', 'address', 'show']),
        ('routes', ['-4', '-j', 'route', 'show', 'table', 'all'])):
        result = subprocess.run([os.environ['KER_FORWARDING_IP'], *query],
                                env=env, capture_output=True, text=True, timeout=10, check=True)
        if result.stderr:
            raise RuntimeError('native broadcast observation warning: ' + result.stderr)
        state[key] = json.loads(result.stdout)
    state['sysctls'] = {name: diag.rpc(diag.FILE, '', '/proc/sys/' + name.replace('.', '/')).decode().strip()
        for name in ('net.ipv4.conf.all.forwarding', 'net.ipv4.conf.all.bc_forwarding',
            'net.ipv4.conf.veth1.bc_forwarding', 'net.ipv4.conf.veth2.bc_forwarding',
            'net.ipv4.icmp_echo_ignore_broadcasts')}
    state['snmp'] = diag.rpc(diag.FILE, '', '/proc/net/snmp').decode()
    return state


def instats_snapshot(env):
    state = {}
    for key, words in (('links', ['-s', '-d', '-j', 'link', 'show']),
                       ('addresses', ['-j', 'address', 'show']),
                       ('ipv4_routes', ['-4', '-j', 'route', 'show', 'table', 'all']),
                       ('ipv6_routes', ['-6', '-j', 'route', 'show', 'table', 'all']),
                       ('xfrm', ['-s', 'xfrm', 'policy', 'list'])):
        result = subprocess.run([os.environ['KER_FORWARDING_IP'], *words], env=env,
                                capture_output=True, text=True, timeout=10)
        if result.returncode or result.stderr:
            raise RuntimeError('native IPv6 ingress observation failed: ' + repr(words) + ': ' + result.stdout + result.stderr)
        # Pinned iproute2's XFRM policy dump is text, including an empty
        # successful dump for no policies. Preserve that actual native output.
        state[key] = result.stdout if key == 'xfrm' else json.loads(result.stdout)
    state['forwarding'] = diag.rpc(diag.FILE, '', '/proc/sys/net/ipv6/conf/all/forwarding').decode().strip()
    state['ipv6_mib'] = {device: diag.rpc(diag.FILE, '', '/proc/net/dev_snmp6/' + device).decode()
                         for device in ('veth0', 'veth1', 'veth2', 'veth3')}
    return state


def main():
    tool, words = Path(sys.argv[0]).name, sys.argv[1:]
    record = dict(tool=tool, arguments=words, started_monotonic=time.monotonic())
    instats = os.environ.get('KER_FORWARDING_INSTATS') == '1'
    if tool == 'cat':
        if not instats or len(words) != 1 or not words[0].startswith('/proc/net/dev_snmp6/'):
            raise RuntimeError('unsupported native proc read: ' + repr(words))
        value = diag.rpc(diag.FILE, '', words[0]).decode()
        record.update(returncode=0, stdout=value, stderr='')
    elif tool == 'sysctl':
        if len(words) != 2 or words[0] not in ('-n', '-qw'):
            raise RuntimeError('unsupported native sysctl arguments: ' + repr(words))
        if words[0] == '-n':
            value = diag.rpc(diag.FILE, '', '/proc/sys/' + words[1].replace('.', '/')).decode()
            record.update(returncode=0, stdout=value, stderr='')
        else:
            diag.rpc(diag.SYSCTL, '', words[1])
            record.update(returncode=0, stdout='', stderr='')
    else:
        env = dict(os.environ, LD_PRELOAD=os.environ['KER_FORWARDING_PRELOAD'], KER_MPTCP_SOCKET_NAMESPACE='')
        if words[:2] == ['vrf', 'exec']:
            if tool != 'ip' or len(words) < 5 or words[3] not in (('ping', 'ping6', 'traceroute6') if instats else ('ping', 'ping6')):
                raise RuntimeError('unsupported VRF process: ' + repr(words))
            vrf, program, arguments = words[2], words[3], words[4:]
            # Validate that the requested device really is a native Linux VRF.
            link = subprocess.run([os.environ['KER_FORWARDING_IP'], '-d', '-j', 'link', 'show', 'dev', vrf],
                                  env=env, capture_output=True, text=True, timeout=10, check=True)
            objects = json.loads(link.stdout)
            if len(objects) != 1 or objects[0]['linkinfo']['info_kind'] != 'vrf':
                raise RuntimeError('native VRF device missing: ' + vrf)
            env['KER_FORWARDING_VRF'] = vrf
            command = [os.environ['KER_FORWARDING_' + program.upper()], *arguments]
            record['vrf'] = objects[0]
            if os.environ.get('KER_FORWARDING_BROADCAST') == '1':
                record['broadcast_before'] = broadcast_snapshot(env)
                native_time_log = os.environ['KER_FORWARDING_LOG'] + '.native-time-' + str(os.getpid())
                env['KER_MPTCP_NATIVE_REALTIME'] = '1'
                env['KER_MPTCP_NATIVE_TIME_LOG'] = native_time_log
        else:
            command = [os.environ['KER_FORWARDING_IP'], *words]
        broadcast = words[:2] == ['vrf', 'exec'] and os.environ.get('KER_FORWARDING_BROADCAST') == '1'
        observe_inststats = instats and tool == 'ip' and (words[:2] == ['vrf', 'exec'] or words[:1] == ['xfrm'])
        if observe_inststats:
            record['instats_before'] = instats_snapshot(env)
            native_time_log = os.environ['KER_FORWARDING_LOG'] + '.native-time-' + str(os.getpid())
            env['KER_MPTCP_NATIVE_REALTIME'] = '1'
            env['KER_MPTCP_NATIVE_TIME_LOG'] = native_time_log
        # Preserve the upstream shell's 2>&1 stream before its literal grep.
        result = subprocess.run(command, env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT if broadcast else subprocess.PIPE,
                                text=True, timeout=30)
        record.update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr or '')
        if observe_inststats:
            record['instats_after'] = instats_snapshot(env)
            record['native_clock_reads'] = Path(native_time_log).stat().st_size if Path(native_time_log).exists() else 0
            Path(native_time_log).unlink(missing_ok=True)
        if words[:2] == ['vrf', 'exec'] and os.environ.get('KER_FORWARDING_BROADCAST') == '1':
            record['broadcast_after'] = broadcast_snapshot(env)
            try:
                record['native_clock_reads'] = Path(native_time_log).stat().st_size
            except FileNotFoundError:
                record['native_clock_reads'] = 0
            Path(native_time_log).unlink(missing_ok=True)
    record['finished_monotonic'] = time.monotonic()
    with open(os.environ['KER_FORWARDING_LOG'], 'a') as stream:
        stream.write(json.dumps(record) + '\n')
    sys.stdout.write(record['stdout']); sys.stderr.write(record['stderr'])
    return record['returncode']


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        sys.exit('native forwarding transport: ' + str(error))
