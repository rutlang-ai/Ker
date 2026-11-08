"""Require the complete original two-bridge 802.1D VLAN-port routing matrix."""
import re


def require(value, message):
    if not value:
        raise RuntimeError(message)


def forwarding_counts(content):
    lines = content['ipv4'].splitlines()
    i = next(i for i,line in enumerate(lines) if line.startswith('Ip:'))
    ipv4 = dict(zip(lines[i].split()[1:],map(int,lines[i+1].split()[1:])))
    ipv6 = dict(line.split() for line in content['ipv6'].splitlines())
    return dict(ipv4=ipv4['ForwDatagrams'],ipv6=int(ipv6['Ip6OutForwDatagrams']))


def validate_evidence(report):
    original = report.get('original',{})
    results = [re.fullmatch(r'TEST: (.*?)\s+\[ OK \]',line) for line in original.get('stdout','').splitlines() if line.startswith('TEST:')]
    names = ['ping: via 100','ping: via 200','ping6: via 100','ping6: via 200']*2
    require(original.get('returncode') == 0 and not original.get('stderr') and len(results) == 8 and all(results) and
            [r[1] for r in results] == names, 'incomplete original eight-outcome 802.1D shell')
    rows = report.get('commands',[])
    pings = [r for r in rows if r['arguments'][:2] == ['vrf','exec']]
    destinations = ['192.0.2.130','192.0.2.146','2001:db8:2::2','2001:db8:4::2']*2
    require(len(pings) == 8, 'missing original 802.1D ping')
    for i,r in enumerate(pings):
        require(r.get('native_clock_reads', 0) > 0,
                'original 802.1D ping did not use native realtime for its SO_TIMESTAMP clock domain')
        require(r['arguments'] == ['vrf','exec','vveth0','ping' if i%4 < 2 else 'ping6',
                '-c','10','-i','0.1','-w','5',destinations[i]] and r['returncode'] == 0 and
                '10 received' in r['stdout'] and not r['stderr'] and r['vrf']['linkinfo']['info_kind'] == 'vrf',
                'modified or ineffective original 802.1D traffic')
    for r in pings:
        links = {x['ifname']:x for x in r['bridge_state']['links']}
        for bridge,port,vid in (('br1','veth1.100',100),('br2','veth1.200',200)):
            b,p = links[bridge],links[port]
            require(b['linkinfo']['info_kind'] == 'bridge' and b['linkinfo']['info_data']['vlan_filtering'] == 0 and
                    b['address'] == p['address'] and p['link'] == 'veth1' and p['master'] == bridge and
                    p['linkinfo']['info_kind'] == 'vlan' and p['linkinfo']['info_data']['id'] == vid and
                    p['linkinfo']['info_slave_kind'] == 'bridge' and
                    p['linkinfo']['info_slave_data']['state'] == 'forwarding',
                    'native two-bridge VLAN-port topology incorrect')
            h = links['veth0.'+str(vid)]
            require(h['link'] == 'veth0' and h['master'] == 'vveth0' and
                    h['linkinfo']['info_kind'] == 'vlan' and h['linkinfo']['info_data']['id'] == vid and
                    'UP' in h['flags'], 'native host VLAN/VRF topology incorrect')
    actions = [r for r in rows if 'port_after' in r]
    expected = [
        ['link','set','dev','veth1.100','master','br1'],
        ['link','set','dev','veth1.200','master','br2'],
        ['link','set','dev','veth1.100','nomaster'],
        ['link','set','dev','veth1.200','nomaster'],
        ['link','set','dev','veth1.200','master','br2'],
        ['link','set','dev','veth1.100','master','br1'],
        ['link','set','dev','veth1.200','nomaster'],
        ['link','set','dev','veth1.100','nomaster']]
    require([r['arguments'] for r in actions] == expected, 'missing original 802.1D remaster/cleanup operations')
    ports = [i for i,r in enumerate(rows) if 'port_after' in r]
    traffic = [i for i,r in enumerate(rows) if r['arguments'][:2] == ['vrf','exec']]
    sequence = ports[:2]+traffic[:4]+ports[2:6]+traffic[4:]+ports[6:]
    require(sequence == sorted(sequence), 'original remaster/traffic phases reordered')
    for r in actions:
        state = r['port_after']
        require(len(state) == 1 and state[0]['ifname'] == r['arguments'][3], 'native port transition evidence missing')
        if r['arguments'][4] == 'nomaster':
            require('master' not in state[0] and 'info_slave_kind' not in state[0]['linkinfo'],
                    'native VLAN port remained enslaved after nomaster')
        else:
            require(state[0].get('master') == r['arguments'][5] and
                    state[0]['linkinfo']['info_slave_kind'] == 'bridge', 'native VLAN port was not remastered')
    for family in ('ipv4','ipv6'):
        writes = [r['arguments'][1] for r in rows if r['tool'] == 'sysctl' and
                  r['arguments'][0] == '-qw' and r['arguments'][1].startswith('net.'+family+'.')]
        require(writes == ['net.'+family+'.conf.all.forwarding=1','net.'+family+'.conf.all.forwarding=0'] and
                report['cleanup_state'][family].strip() == '0', 'native 802.1D forwarding not restored')
    devices = ('br1','br2','vveth0','vveth3','veth0.100','veth0.200','veth1.100','veth1.200')
    require(not any(x['ifname'] in devices for x in report['cleanup_state']['links']),
            'native bridge/VRF/VLAN device leaked after original 802.1D cleanup')
    require([r['arguments'] for r in rows if r['returncode']] == [
            ['link','show','dev','veth0'],['link','show','dev','veth2']], 'native 802.1D topology or cleanup error')
    require(all(not r['stderr'] for r in rows if r['returncode'] == 0), 'native 802.1D command warning')
    before,after = map(forwarding_counts,(report['mib_before'],report['mib_after']))
    require(all(after[f]-before[f] >= 80 for f in ('ipv4','ipv6')), 'missing actual native routed 802.1D traffic')
    require(report.get('missing_backend_control',{}).get('returncode') not in (None,0), 'original 802.1D script passed without native Linux')
    binding = report.get('vrf_binding_control',{})
    require(binding.get('baseline',{}).get('returncode') == 0 and '1 received' in binding.get('baseline',{}).get('stdout','') and
            binding.get('unknown_vrf',{}).get('returncode') not in (None,0), 'native 802.1D VRF binding ineffective')
    native,stats = report.get('native_fixture',{}),report.get('stats',{})
    require(native.get('netlinks',0)>0 and native.get('raw_sockets',0)>0 and native.get('live') == 0 and
            stats.get('outstanding') == 0 and stats.get('worker_exit_code') == 0 and stats.get('control_eof') is True and
            stats.get('shutdown_timed_out') is False, 'native 802.1D resources did not stop normally')
