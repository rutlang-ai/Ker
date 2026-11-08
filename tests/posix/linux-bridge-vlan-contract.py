"""Require the complete original VLAN 555/777 bridge PVID switching matrix."""
import re


def require(value, message):
    if not value:
        raise RuntimeError(message)


def forwarding_counts(content):
    lines = content['ipv4'].splitlines()
    i = next(i for i,line in enumerate(lines) if line.startswith('Ip:'))
    ipv4 = dict(zip(lines[i].split()[1:], map(int,lines[i+1].split()[1:])))
    ipv6 = dict(line.split() for line in content['ipv6'].splitlines())
    return dict(ipv4=ipv4['ForwDatagrams'],ipv6=int(ipv6['Ip6OutForwDatagrams']))


def validate_evidence(report):
    original = report.get('original', {})
    results = [re.fullmatch(r'TEST: (.*?)\s+\[ OK \]',line) for line in original.get('stdout','').splitlines() if line.startswith('TEST:')]
    names = ['ping','ping6','vlan','ping fails: via 555','ping6 fails: via 555',
             'ping: via 777','ping6: via 777','ping','ping6']
    require(original.get('returncode') == 0 and not original.get('stderr') and len(results) == 9 and all(results) and
            [r[1] for r in results] == names, 'incomplete original nine-outcome VLAN switching shell')
    rows = report.get('commands', [])
    pings = [r for r in rows if r['arguments'][:2] == ['vrf','exec']]
    require(len(pings) == 8 and [r['returncode'] for r in pings] == [0,0,1,1,0,0,0,0],
            'missing native VLAN 555/777 connectivity and isolation matrix')
    for i,r in enumerate(pings):
        require(r.get('native_clock_reads', 0) > 0,
                'original bridge VLAN ping did not use native realtime for its SO_TIMESTAMP clock domain')
        vlan777 = i in (4,5)
        destination = ('192.0.2.146' if vlan777 else '192.0.2.130') if i%2==0 else ('2001:db8:4::2' if vlan777 else '2001:db8:2::2')
        require(r['arguments'] == ['vrf','exec','vveth0','ping' if i%2==0 else 'ping6',
                '-c','10','-i','0.1','-w','5',destination], 'modified original VLAN traffic/timing')
        require(r['vrf']['linkinfo']['info_kind'] == 'vrf' and not r['stderr'] and
                ('0 received' if i in (2,3) else '10 received') in r['stdout'], 'wrong native VLAN ping output')
    bridge = [r for r in rows if r['tool'] == 'bridge']
    expected = [
        ['vlan','add','dev','br1','vid','555','self','pvid','untagged'],
        ['vlan','add','dev','veth1','vid','555'],
        ['vlan','add','dev','veth1','vid','777'],
        ['vlan','add','dev','br1','vid','333','self'],
        ['vlan','del','dev','br1','vid','333','self'],
        ['vlan','add','dev','br1','vid','777','self','pvid','untagged'],
        ['vlan','del','dev','br1','vid','555','self'],
        ['vlan','add','dev','br1','vid','555','self','pvid','untagged'],
        ['vlan','del','dev','br1','vid','777','self']]
    require([r['arguments'] for r in bridge] == expected, 'missing original VLAN 333/PVID switching operations')
    phases = [rows.index(r) for r in [*bridge[:3], *pings[:2], *bridge[3:7], *pings[2:6], *bridge[7:], *pings[6:]]]
    require(phases == sorted(phases), 'original VLAN/PVID/traffic phases reordered')
    memberships = [[555],[555],[555],[333,555],[555],[555,777],[777],[555,777],[555]]
    pvids = [555,555,555,555,555,777,777,555,555]
    for r, members, pvid in zip(bridge, memberships, pvids):
        entries = [x for x in r['bridge_vlans_after'] if x['ifname'] == 'br1']
        require(len(entries) == 1 and sorted(x['vlan'] for x in entries[0]['vlans']) == members and
                [x['vlan'] for x in entries[0]['vlans'] if 'PVID' in x.get('flags',[])] == [pvid] and
                all(not x.get('flags') for x in entries[0]['vlans'] if x['vlan'] == 333),
                'native transient VLAN membership/PVID differs from original commands')
    for i,r in enumerate(pings):
        state = r['bridge_state']
        require(len(state['link']) == len(state['port']) == len(state['vlans']) == len(state['port_vlans']) == 1,
                'missing actual native bridge/port state')
        link, port = state['link'][0], state['port'][0]
        require(link['ifname'] == 'br1' and link['linkinfo']['info_kind'] == 'bridge' and
                link['linkinfo']['info_data']['vlan_filtering'] == 1 and
                link['linkinfo']['info_data']['vlan_default_pvid'] == 0 and
                port['ifname'] == 'veth1' and port['master'] == 'br1' and
                port['linkinfo']['info_slave_kind'] == 'bridge' and
                port['linkinfo']['info_slave_data']['state'] == 'forwarding', 'native VLAN bridge topology differs')
        self_vlan = state['vlans'][0]
        require(self_vlan['ifname'] == 'br1' and self_vlan['vlans'] ==
                [dict(vlan=777 if i in (2,3,4,5) else 555,flags=['PVID','Egress Untagged'])],
                'native bridge self PVID did not switch 555/777/555')
        require(state['port_vlans'][0] == dict(ifname='veth1',vlans=[dict(vlan=555),dict(vlan=777)]),
                'native bridge port VLAN membership/tagging incorrect')
        require(sorted((x['ifname'],x['link'],x['master'],x['linkinfo']['info_kind'],
                        x['linkinfo']['info_data']['id']) for x in state['host_vlans']) ==
                [('veth0.555','veth0','vveth0','vlan',555),('veth0.777','veth0','vveth0','vlan',777)],
                'native host VLAN subinterfaces missing or wrong')
    for family in ('ipv4','ipv6'):
        writes = [r['arguments'][1] for r in rows if r['tool'] == 'sysctl' and
                  r['arguments'][0] == '-qw' and r['arguments'][1].startswith('net.'+family+'.')]
        require(writes == ['net.'+family+'.conf.all.forwarding=1','net.'+family+'.conf.all.forwarding=0'] and
                report['cleanup_state'][family].strip() == '0', 'native VLAN forwarding not restored')
    devices = ('br1','vveth0','vveth3','veth0.555','veth0.777')
    require(not any(x['ifname'] in devices for x in report['cleanup_state']['links']),
            'native bridge/VRF/VLAN device leaked after original cleanup')
    require([r['arguments'] for r in rows if r['returncode'] and r not in pings] == [
            ['link','show','dev','veth0'],['link','show','dev','veth2']], 'native VLAN topology or cleanup error')
    require(all(not r['stderr'] for r in rows if r['returncode'] == 0), 'native VLAN command warning')
    before, after = map(forwarding_counts, (report['mib_before'],report['mib_after']))
    require(all(after[f]-before[f] >= 60 for f in ('ipv4','ipv6')), 'missing actual native routed VLAN traffic')
    binding = report.get('vrf_binding_control', {})
    require(binding.get('baseline',{}).get('returncode') == 0 and '1 received' in binding.get('baseline',{}).get('stdout','') and
            binding.get('unknown_vrf',{}).get('returncode') not in (None,0), 'native VLAN VRF binding ineffective')
    require(report.get('missing_backend_control',{}).get('returncode') not in (None,0), 'original VLAN script passed without native Linux')
    native, stats = report.get('native_fixture',{}), report.get('stats',{})
    require(native.get('netlinks',0) > 0 and native.get('raw_sockets',0) > 0 and native.get('live') == 0 and
            stats.get('outstanding') == 0 and stats.get('worker_exit_code') == 0 and stats.get('control_eof') is True and
            stats.get('shutdown_timed_out') is False, 'native VLAN resources did not stop normally')
