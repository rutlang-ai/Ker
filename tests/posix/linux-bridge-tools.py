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
import time

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
    if (os.environ.get('KER_FORWARDING_BRIDGE_MDB_HOST') == '1' or
            os.environ.get('KER_FORWARDING_BRIDGE_MDB_PORT') == '1' or
            os.environ.get('KER_FORWARDING_BRIDGE_MCAST') == '1' or
            os.environ.get('KER_FORWARDING_BRIDGE_SG') == '1' or os.environ.get('KER_FORWARDING_BRIDGE_L2MISS') == '1'):
        state = subprocess.run([os.environ['KER_FORWARDING_BRIDGE'], '-j', '-d', 'mdb', 'show'],
                               env=env, capture_output=True, text=True, timeout=10, check=True)
        if state.stderr:
            raise RuntimeError('native bridge MDB observation warning: ' + state.stderr)
        result['mdb'] = json.loads(state.stdout)
    if os.environ.get('KER_FORWARDING_BRIDGE_MCAST') == '1':
        for key,query in (('vlan_global',[os.environ['KER_FORWARDING_BRIDGE'],'-j','vlan','global','show']),
                          ('vlan_details',[os.environ['KER_FORWARDING_BRIDGE'],'-j','-d','vlan','show']),
                          ('mdb_timers',[os.environ['KER_FORWARDING_BRIDGE'],'-j','-d','-s','mdb','show'])):
            observed = subprocess.run(query,env=env,capture_output=True,text=True,timeout=10,check=True)
            if observed.stderr: raise RuntimeError('native multicast VLAN observation warning: '+observed.stderr)
            result[key] = json.loads(observed.stdout)
        result['observed_monotonic'] = time.monotonic()
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


def learning_snapshot(env):
    state = {}
    for key, query in (
        ('links', [os.environ['KER_FORWARDING_IP'], '-s', '-d', '-j', 'link', 'show']),
        ('fdb', [os.environ['KER_FORWARDING_BRIDGE'], '-j', '-d', 'fdb', 'show', 'br', 'br0'])):
        result = subprocess.run(query, env=env, capture_output=True, text=True, timeout=10, check=True)
        if result.stderr:
            raise RuntimeError('native FDB learning observation warning: ' + result.stderr)
        state[key] = json.loads(result.stdout)
    return state


def packet_bridge_snapshot(env, traffic=False, pedit_counter_sample=False):
    state = bridge_snapshot(env)
    if os.environ.get('KER_FORWARDING_BRIDGE_L2MISS') == '1':
        observed = subprocess.run([os.environ['KER_FORWARDING_BRIDGE'], '-j', '-d', 'fdb', 'show', 'br', 'br1'],
            env=env, capture_output=True, text=True, timeout=10, check=True)
        if observed.stderr: raise RuntimeError('native L2 miss FDB observation warning: '+observed.stderr)
        state['fdb'] = json.loads(observed.stdout)
    query = [os.environ['KER_FORWARDING_IP'], '-s', '-d', '-j', 'link', 'show']
    result = subprocess.run(query, env=env, capture_output=True, text=True, timeout=10, check=True)
    if result.stderr:
        raise RuntimeError('native MDB port observation warning: ' + result.stderr)
    state['links'] = json.loads(result.stdout)
    if traffic:
        devices = (('veth0','veth1','veth2','veth3') if (os.environ.get('KER_FORWARDING_BRIDGE_PEDIT') == '1' or (os.environ.get('KER_FORWARDING_BRIDGE_FLOWER_RANGE') == '1' or os.environ.get('KER_FORWARDING_BRIDGE_L2MISS') == '1')) else
                   ('br0','veth3') if os.environ.get('KER_FORWARDING_BRIDGE_MDB_API') == '1' else
                   ('veth0','veth1','veth3') if os.environ.get('KER_FORWARDING_BRIDGE_LOCKED') == '1' else
                   ('veth0', 'veth3') if (os.environ.get('KER_FORWARDING_BRIDGE_UNAWARE') == '1' or os.environ.get('KER_FORWARDING_BRIDGE_SG') == '1') else ('veth3',))
        filters = {}
        counter_sample = None
        for device in devices:
            query = [os.environ['KER_FORWARDING_TC'], '-j', '-s', 'filter', 'show', 'dev', device, 'ingress']
            if pedit_counter_sample and device == 'veth1':
                qstart = time.monotonic_ns()
                result = subprocess.run(query, env=env, capture_output=True, text=True, timeout=10, check=True)
                qend = time.monotonic_ns()
                counter_sample = dict(command=query[1:], qstart_monotonic_ns=qstart, qend_monotonic_ns=qend)
            else:
                result = subprocess.run(query, env=env, capture_output=True, text=True, timeout=10, check=True)
            if result.stderr:
                raise RuntimeError('native bridge flower observation warning: ' + result.stderr)
            filters[device] = json.loads(result.stdout)
        if len(devices) == 1:
            state['filters'] = filters['veth3']
        else:
            state['filters_by_device'] = filters
        if counter_sample is not None:
            state['pedit_veth1_counter_sample'] = counter_sample
    if traffic and (os.environ.get('KER_FORWARDING_BRIDGE_MCAST') == '1' or
                    os.environ.get('KER_FORWARDING_BRIDGE_PEDIT') == '1' or
                    os.environ.get('KER_FORWARDING_BRIDGE_FLOWER_RANGE') == '1' or
                    os.environ.get('KER_FORWARDING_BRIDGE_L2MISS') == '1'):
        state['egress_filters'] = {}
        for device in ('veth1','veth2'):
            observed = subprocess.run([os.environ['KER_FORWARDING_TC'],'-j','-s','filter','show','dev',device,'egress'],
                env=env,capture_output=True,text=True,timeout=10,check=True)
            if observed.stderr: raise RuntimeError('native multicast egress counter warning: '+observed.stderr)
            state['egress_filters'][device] = json.loads(observed.stdout)
    if (os.environ.get('KER_FORWARDING_BRIDGE_UNAWARE') == '1' or
            traffic and os.environ.get('KER_FORWARDING_BRIDGE_ISOLATION') == '1'):
        query = [os.environ['KER_FORWARDING_BRIDGE'], '-j', 'fdb', 'show']
        if os.environ.get('KER_FORWARDING_BRIDGE_MCAST') != '1': query += ['br','br0']
        result = subprocess.run(query, env=env, capture_output=True, text=True, timeout=10, check=True)
        if result.stderr:
            raise RuntimeError('native bridge FDB observation warning: ' + result.stderr)
        state['fdb'] = json.loads(result.stdout)
    return state


def mdb_api_snapshot(env):
    result = subprocess.run([os.environ['KER_FORWARDING_BRIDGE'], '-j', '-d', '-s', 'mdb', 'show', 'dev', 'br0'],
                            env=env, capture_output=True, text=True, timeout=10, check=True)
    if result.stderr:
        raise RuntimeError('native MDB API observation warning: ' + result.stderr)
    return json.loads(result.stdout)


def mdb_max_snapshot(env):
    state = packet_bridge_snapshot(env)
    for key, args in (('port_details',['-j','-d','link','show']),
                      ('vlan_details',['-j','-d','vlan','show']),
                      ('vlan_global',['-j','vlan','global','show'])):
        result = subprocess.run([os.environ['KER_FORWARDING_BRIDGE'], *args],env=env,
            capture_output=True,text=True,timeout=10,check=True)
        if result.stderr: raise RuntimeError('native MDB limits observation warning: '+result.stderr)
        state[key] = json.loads(result.stdout)
    return state


def main():
    tool, words = Path(sys.argv[0]).name, sys.argv[1:]
    record = dict(tool=tool, arguments=words)
    if (tool == 'tc' and os.environ.get('KER_FORWARDING_BRIDGE_PEDIT') == '1' and
            words[:2] == ['filter', 'add'] and 'pedit' in words):
        ready_path = os.environ.get('KER_FORWARDING_PEDIT_OBSERVER_READY')
        if not ready_path or not Path(ready_path).is_file():
            raise RuntimeError('native PEDIT observer is not ready before original rule installation')
        ready = json.loads(Path(ready_path).read_text())
        if ready.get('type') != 'ready' or {(x.get('name'), x.get('direction')) for x in ready.get('interfaces', [])} != {('veth1', 'ingress')}:
            raise RuntimeError('native PEDIT observer did not bind the original ingress action locus')
    if os.environ.get('KER_FORWARDING_BRIDGE_MDB_API') == '1' and tool == 'bridge' and words[:1] == ['-b']:
        if len(words) != 2:
            raise RuntimeError('unsupported native MDB batch arguments')
        batch = Path(words[1]).read_bytes()
        record['batch_text'] = batch.decode()
        record['batch_sha256'] = __import__('hashlib').sha256(batch).hexdigest()
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
            if os.environ.get('KER_FORWARDING_BRIDGE_UNAWARE') == '1':
                record['unaware_before'] = packet_bridge_snapshot(env, os.environ.get('KER_FORWARDING_BRIDGE_LOCKED') == '1')
            elif os.environ.get('KER_FORWARDING_BRIDGE_ISOLATION') == '1':
                record['isolation_before'] = packet_bridge_snapshot(env)
            elif os.environ.get('KER_FORWARDING_BRIDGE_LEARNING') == '1':
                record['learning_before'] = learning_snapshot(env)
            elif (os.environ.get('KER_FORWARDING_BRIDGE_VLAN_UPPER') == '1' or
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
            if tool not in ('ip', 'bridge', 'mausezahn') and not (
                    tool == 'ethtool' and os.environ.get('KER_FORWARDING_BRIDGE_AWARE') == '1') and not (
                    tool == 'tc' and (os.environ.get('KER_FORWARDING_BRIDGE_MDB_PORT') == '1' or
                                      os.environ.get('KER_FORWARDING_BRIDGE_ISOLATION') == '1' or
                                      os.environ.get('KER_FORWARDING_BRIDGE_UNAWARE') == '1' or
                                      os.environ.get('KER_FORWARDING_BRIDGE_SG') == '1' or
                                      os.environ.get('KER_FORWARDING_BRIDGE_PEDIT') == '1' or
                                      (os.environ.get('KER_FORWARDING_BRIDGE_FLOWER_RANGE') == '1' or os.environ.get('KER_FORWARDING_BRIDGE_L2MISS') == '1'))):
                raise RuntimeError('unsupported native tool: ' + tool)
            command = [os.environ['KER_FORWARDING_' + tool.upper()], *words]
        if tool == 'bridge' and os.environ.get('KER_FORWARDING_BRIDGE_MDB_HOST') == '1':
            record['mdb_before'] = bridge_snapshot(env)
        if tool in ('bridge', 'mausezahn') and os.environ.get('KER_FORWARDING_BRIDGE_STICKY') == '1':
            record['sticky_before'] = sticky_snapshot(env)
        if (os.environ.get('KER_FORWARDING_BRIDGE_LEARNING') == '1' and
                (tool == 'bridge' and words[:2] in
                 (['fdb', 'add'], ['fdb', 'replace'], ['fdb', 'del'], ['fdb', 'flush']) or
                 tool == 'ip' and words[:3] == ['link', 'set', 'veth5'] and
                 words[3:4] in (['master'], ['nomaster']) or
                 tool == 'ip' and words[:5] == ['link', 'set', 'dev', 'veth5', 'addr'])):
            record['learning_before'] = learning_snapshot(env)
        observe_mdb_port = (os.environ.get('KER_FORWARDING_BRIDGE_MDB_PORT') == '1' and
                            (tool in ('bridge', 'tc', 'mausezahn') or tool == 'ip' and
                             words[:4] == ['link', 'set', 'dev', 'veth2']))
        if observe_mdb_port:
            record['mdb_port_before'] = packet_bridge_snapshot(env, tool == 'mausezahn')
        observe_isolation = (os.environ.get('KER_FORWARDING_BRIDGE_ISOLATION') == '1' and
                             (tool in ('tc', 'mausezahn') or tool == 'ip' and
                              words[:3] == ['link', 'set', 'dev'] and
                              words[3:4] in (['veth1'], ['veth2'], ['veth4']) and 'isolated' in words or
                              tool == 'ip' and words[:3] == ['link', 'set', 'veth3'] and 'promisc' in words))
        if observe_isolation:
            record['isolation_before'] = packet_bridge_snapshot(env, tool == 'mausezahn')
        observe_unaware = (os.environ.get('KER_FORWARDING_BRIDGE_UNAWARE') == '1' and
                           not (tool == 'tc' and words == ['-j']) and
                           (tool in ('bridge', 'tc', 'mausezahn', 'ethtool') or
                            os.environ.get('KER_FORWARDING_BRIDGE_MCAST') == '1' and tool == 'ip' and words[:1] in (['link'],['address'],['addr']) or tool == 'ip' and
                            ('promisc' in words or words == ['-d', '-j', 'link', 'show', 'dev', 'br0', 'type', 'bridge'])))
        observe_sg = (os.environ.get('KER_FORWARDING_BRIDGE_SG') == '1' and
                      (tool == 'mausezahn' or tool == 'tc' and words[:4] == ['-j','-s','filter','show'] or
                       tool == 'ip' and words[:4] == ['link','set','dev','br0']))
        observe_pedit = os.environ.get('KER_FORWARDING_BRIDGE_PEDIT') == '1' and tool in ('tc','mausezahn')
        observe_range = os.environ.get('KER_FORWARDING_BRIDGE_FLOWER_RANGE') == '1' and tool in ('tc','mausezahn')
        if observe_range:
            record['range_before'] = packet_bridge_snapshot(env, True)
        observe_l2 = os.environ.get('KER_FORWARDING_BRIDGE_L2MISS') == '1' and tool in ('tc','mausezahn','bridge')
        if observe_l2:
            record['l2_before'] = packet_bridge_snapshot(env, True)
        if observe_pedit:
            sample_delete = tool == 'tc' and words[:4] == ['filter','del','dev','veth1']
            sample_add = tool == 'tc' and words[:5] == ['filter','add','dev','veth1','ingress']
            record['pedit_before'] = packet_bridge_snapshot(env, True, pedit_counter_sample=sample_delete)
        observe_mdb_api = (os.environ.get('KER_FORWARDING_BRIDGE_MDB_API') == '1' and tool == 'bridge' and
                           words[:2] in (['mdb', 'add'], ['mdb', 'del'], ['mdb', 'replace'], ['mdb', 'flush']))
        observe_mdb_max = os.environ.get('KER_FORWARDING_BRIDGE_MDB_MAX') == '1' and tool == 'bridge'
        if observe_mdb_max:
            record['mdb_max_before'] = mdb_max_snapshot(env)
        if observe_mdb_api:
            record['mdb_api_before'] = mdb_api_snapshot(env)
        if observe_sg:
            record['sg_before'] = packet_bridge_snapshot(env, tool == 'mausezahn')
        if observe_unaware:
            record['unaware_before'] = packet_bridge_snapshot(env, tool == 'mausezahn')
        if tool == 'ethtool':
            features = subprocess.run([os.environ['KER_FORWARDING_ETHTOOL'], '--json', '--show-features', words[1]],
                env=env, capture_output=True, text=True, timeout=10, check=True)
            if features.stderr: raise RuntimeError('native ethtool feature query warning: ' + features.stderr)
            record['ethtool_features_before'] = json.loads(features.stdout)
        if os.environ.get('KER_FORWARDING_BRIDGE_UNAWARE') == '1' or os.environ.get('KER_FORWARDING_BRIDGE_SG') == '1' or os.environ.get('KER_FORWARDING_BRIDGE_PEDIT') == '1' or (os.environ.get('KER_FORWARDING_BRIDGE_FLOWER_RANGE') == '1' or os.environ.get('KER_FORWARDING_BRIDGE_L2MISS') == '1'):
            record['started_monotonic'] = time.monotonic()
        result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=30)
        if os.environ.get('KER_FORWARDING_BRIDGE_UNAWARE') == '1' or os.environ.get('KER_FORWARDING_BRIDGE_SG') == '1' or os.environ.get('KER_FORWARDING_BRIDGE_PEDIT') == '1' or (os.environ.get('KER_FORWARDING_BRIDGE_FLOWER_RANGE') == '1' or os.environ.get('KER_FORWARDING_BRIDGE_L2MISS') == '1'):
            record['finished_monotonic'] = time.monotonic()
        record.update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
        if tool == 'ethtool':
            features = subprocess.run([os.environ['KER_FORWARDING_ETHTOOL'], '--json', '--show-features', words[1]],
                env=env, capture_output=True, text=True, timeout=10, check=True)
            if features.stderr: raise RuntimeError('native ethtool feature query warning: ' + features.stderr)
            record['ethtool_features_after'] = json.loads(features.stdout)
        if observe_range:
            record['range_after'] = packet_bridge_snapshot(env, True)
        if observe_l2:
            record['l2_after'] = packet_bridge_snapshot(env, True)
        if observe_pedit:
            record['pedit_after'] = packet_bridge_snapshot(env, True, pedit_counter_sample=sample_add)
        if observe_mdb_max:
            record['mdb_max_after'] = mdb_max_snapshot(env)
        if observe_mdb_api:
            record['mdb_api_after'] = mdb_api_snapshot(env)
        if observe_sg:
            record['sg_after'] = packet_bridge_snapshot(env, tool == 'mausezahn')
        if 'unaware_before' in record:
            record['unaware_after'] = packet_bridge_snapshot(env, tool == 'mausezahn' or
                os.environ.get('KER_FORWARDING_BRIDGE_LOCKED') == '1' and words[:2] == ['vrf','exec'])
        if 'isolation_before' in record:
            record['isolation_after'] = packet_bridge_snapshot(env, tool == 'mausezahn')
        if observe_mdb_port:
            record['mdb_port_after'] = packet_bridge_snapshot(env, tool == 'mausezahn')
        if 'learning_before' in record:
            record['learning_after'] = learning_snapshot(env)
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
