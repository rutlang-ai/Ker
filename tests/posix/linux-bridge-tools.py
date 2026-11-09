#!/usr/bin/env python3
"""Process transport for the unchanged original routed bridge selftest.

Ordinary ip commands use unmodified pinned iproute2. Only process VRF binding
and proc/sysctl access need translation between the two kernel instances.
"""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

root = Path(os.environ['KER_MPTCP_FIXTURE_SOURCE'])
spec = importlib.util.spec_from_file_location('forwarding_diag', root / 'linux-mptcp-diag-shim.py')
diag = importlib.util.module_from_spec(spec); spec.loader.exec_module(diag)


def bridge_snapshot(env):
    result = {}
    for key, query in (
        ('links', [os.environ['KER_FORWARDING_IP'], '-d', '-j', 'link', 'show']),
        ('addresses', [os.environ['KER_FORWARDING_IP'], '-j', 'address', 'show']),
        ('ipv4_routes', [os.environ['KER_FORWARDING_IP'], '-4', '-j', 'route', 'show', 'table', 'all']),
        ('ipv6_routes', [os.environ['KER_FORWARDING_IP'], '-6', '-j', 'route', 'show', 'table', 'all']),
        ('vlans', [os.environ['KER_FORWARDING_BRIDGE'], '-j', 'vlan', 'show'])):
        state = subprocess.run(query, env=env, capture_output=True, text=True, timeout=10, check=True)
        if state.stderr:
            raise RuntimeError('native bridge VLAN upper observation warning: ' + state.stderr)
        result[key] = json.loads(state.stdout)
    if os.environ.get('KER_FORWARDING_BRIDGE_MDB_HOST') == '1':
        state = subprocess.run([os.environ['KER_FORWARDING_BRIDGE'], '-j', '-d', 'mdb', 'show'],
                               env=env, capture_output=True, text=True, timeout=10, check=True)
        if state.stderr:
            raise RuntimeError('native bridge MDB observation warning: ' + state.stderr)
        result['mdb'] = json.loads(state.stdout)
    return result


def sticky_snapshot(env):
    state = {}
    for key, query in (
        ('links', [os.environ['KER_FORWARDING_IP'], '-s', '-d', '-j', 'link', 'show']),
        ('fdb', [os.environ['KER_FORWARDING_BRIDGE'], '-j', '-d', 'fdb', 'show', 'br', 'br0'])):
        result = subprocess.run(query, env=env, capture_output=True, text=True, timeout=10, check=True)
        if result.stderr:
            raise RuntimeError('native sticky FDB observation warning: ' + result.stderr)
        state[key] = json.loads(result.stdout)
    return state


def main():
    tool, words = Path(sys.argv[0]).name, sys.argv[1:]
    record = dict(tool=tool, arguments=words)
    if tool == 'sysctl':
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
            if tool != 'ip' or len(words) < 5 or words[3] not in ('ping', 'ping6'):
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
            if (os.environ.get('KER_FORWARDING_BRIDGE_VLAN_UPPER') == '1' or
                    os.environ.get('KER_FORWARDING_BRIDGE_PVID_UPPER') == '1' or
                    os.environ.get('KER_FORWARDING_BRIDGE_UPPER_PVID') == '1'):
                record['bridge_state'] = bridge_snapshot(env)
            elif os.environ.get('KER_FORWARDING_BRIDGE_1D') == '1':
                state = subprocess.run([os.environ['KER_FORWARDING_IP'], '-d', '-j', 'link', 'show'],
                                       env=env, capture_output=True, text=True, timeout=10, check=True)
                if state.stderr:
                    raise RuntimeError('native 802.1D observation warning: ' + state.stderr)
                record['bridge_state'] = dict(links=json.loads(state.stdout))
            else:
                # Observe the resident kernel's actual bridge state before each
                # original ping, including the PVID-removal negative phases.
                record['bridge_state'] = {}
                for key, query in (
                    ('link', [os.environ['KER_FORWARDING_IP'], '-d', '-j', 'link', 'show', 'dev', 'br1']),
                    ('port', [os.environ['KER_FORWARDING_IP'], '-d', '-j', 'link', 'show', 'dev', 'veth1']),
                    ('vlans', [os.environ['KER_FORWARDING_BRIDGE'], '-j', 'vlan', 'show', 'dev', 'br1'])):
                    state = subprocess.run(query, env=env, capture_output=True, text=True, timeout=10, check=True)
                    if state.stderr:
                        raise RuntimeError('native bridge observation warning: ' + state.stderr)
                    record['bridge_state'][key] = json.loads(state.stdout)
                if os.environ.get('KER_FORWARDING_BRIDGE_VLAN') == '1':
                    for key, query in (
                        ('port_vlans', [os.environ['KER_FORWARDING_BRIDGE'], '-j', 'vlan', 'show', 'dev', 'veth1']),
                        ('host_vlans', [os.environ['KER_FORWARDING_IP'], '-d', '-j', 'link', 'show', 'type', 'vlan'])):
                        state = subprocess.run(query, env=env, capture_output=True, text=True, timeout=10, check=True)
                        if state.stderr:
                            raise RuntimeError('native VLAN observation warning: ' + state.stderr)
                        record['bridge_state'][key] = json.loads(state.stdout)
            native_time_log = os.environ['KER_FORWARDING_LOG'] + '.native-time-' + str(os.getpid())
            env['KER_MPTCP_NATIVE_REALTIME'] = '1'
            env['KER_MPTCP_NATIVE_TIME_LOG'] = native_time_log
        else:
            if tool not in ('ip', 'bridge', 'mausezahn'):
                raise RuntimeError('unsupported native tool: ' + tool)
            command = [os.environ['KER_FORWARDING_' + tool.upper()], *words]
        if tool == 'bridge' and os.environ.get('KER_FORWARDING_BRIDGE_MDB_HOST') == '1':
            record['mdb_before'] = bridge_snapshot(env)
        if tool in ('bridge', 'mausezahn') and os.environ.get('KER_FORWARDING_BRIDGE_STICKY') == '1':
            record['sticky_before'] = sticky_snapshot(env)
        result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=30)
        record.update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
        if tool in ('bridge', 'mausezahn') and os.environ.get('KER_FORWARDING_BRIDGE_STICKY') == '1':
            record['sticky_after'] = sticky_snapshot(env)
        if tool == 'bridge' and os.environ.get('KER_FORWARDING_BRIDGE_MDB_HOST') == '1':
            record['mdb_after'] = bridge_snapshot(env)
        if words[:2] == ['vrf', 'exec']:
            try:
                record['native_clock_reads'] = Path(native_time_log).stat().st_size
            except FileNotFoundError:
                record['native_clock_reads'] = 0
            Path(native_time_log).unlink(missing_ok=True)
        if (tool == 'ip' and os.environ.get('KER_FORWARDING_BRIDGE_1D') == '1' and
                words[:3] == ['link', 'set', 'dev'] and words[3:4] in (['veth1.100'], ['veth1.200']) and
                words[4:5] in (['master'], ['nomaster'])):
            state = subprocess.run([os.environ['KER_FORWARDING_IP'], '-d', '-j', 'link', 'show', 'dev', words[3]],
                                   env=env, capture_output=True, text=True, timeout=10, check=True)
            if state.stderr:
                raise RuntimeError('native bridge port observation warning: ' + state.stderr)
            record['port_after'] = json.loads(state.stdout)
        if (tool == 'ip' and os.environ.get('KER_FORWARDING_BRIDGE_VLAN_UPPER') == '1' and
                words[:3] == ['link', 'set', 'dev'] and words[3:4] in (['veth1'], ['veth2']) and
                ('master' in words[4:] or 'nomaster' in words[4:])):
            state = subprocess.run([os.environ['KER_FORWARDING_IP'], '-d', '-j', 'link', 'show', 'dev', words[3]],
                                   env=env, capture_output=True, text=True, timeout=10, check=True)
            if state.stderr:
                raise RuntimeError('native bridge VLAN upper port observation warning: ' + state.stderr)
            record['port_after'] = json.loads(state.stdout)
        if (tool == 'ip' and os.environ.get('KER_FORWARDING_BRIDGE_PVID_UPPER') == '1' and
                'br1.10' in words and words[0] in ('link', 'address')):
            record['upper_after'] = bridge_snapshot(env)
        if tool == 'bridge' and (os.environ.get('KER_FORWARDING_BRIDGE_VLAN') == '1' or
                                 os.environ.get('KER_FORWARDING_BRIDGE_VLAN_UPPER') == '1' or
                                 os.environ.get('KER_FORWARDING_BRIDGE_PVID_UPPER') == '1' or
                                 os.environ.get('KER_FORWARDING_BRIDGE_UPPER_PVID') == '1'):
            state = subprocess.run([os.environ['KER_FORWARDING_BRIDGE'], '-j', 'vlan', 'show'],
                                   env=env, capture_output=True, text=True, timeout=10, check=True)
            if state.stderr:
                raise RuntimeError('native VLAN observation warning: ' + state.stderr)
            record['bridge_vlans_after'] = json.loads(state.stdout)
            if os.environ.get('KER_FORWARDING_BRIDGE_UPPER_PVID') == '1':
                record['pvid_after'] = bridge_snapshot(env)
    with open(os.environ['KER_FORWARDING_LOG'], 'a') as stream:
        stream.write(json.dumps(record) + '\n')
    sys.stdout.write(record['stdout']); sys.stderr.write(record['stderr'])
    return record['returncode']


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        sys.exit('native forwarding transport: ' + str(error))
