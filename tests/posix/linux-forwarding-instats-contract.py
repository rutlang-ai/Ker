"""Qualify the complete original IPv6 VRF ingress-statistics entry."""
import json
import re

FIELDS = ('Ip6InTooBigErrors', 'Ip6InHdrErrors', 'Ip6InAddrErrors', 'Ip6InDiscards')
CONTROL = 'PASS mixed native IPv6 UDP17 and host poll/select timeout readiness EBADF EINTR\n'


def require(value, message):
    if not value: raise RuntimeError(message)


def links(state): return {x['ifname']: x for x in state['links']}


def mib(text):
    pairs = [line.split() for line in text.splitlines()]
    require(all(len(p) == 2 for p in pairs) and len({p[0] for p in pairs}) == len(pairs), 'invalid native per-interface IPv6 counters')
    return {name: int(value) for name, value in pairs}


def topology(state):
    devices = links(state); tables = []
    for vrf in ('vveth0', 'router', 'vveth3'):
        require(devices[vrf]['linkinfo']['info_kind'] == 'vrf' and ('UP' in devices[vrf]['flags']) == (vrf != 'router'), 'native IPv6 VRF state differs from original (router master remains down)')
        tables.append(devices[vrf]['linkinfo']['info_data']['table'])
    require(len(set(tables)) == 3, 'native IPv6 VRF tables overlap')
    for dev, peer, master, address, mtu in (('veth0','veth1','vveth0','2001:1:1::2',1500),
            ('veth1','veth0','router','2001:1:1::1',1500),('veth2','veth3','router','2001:1:2::1',1280),
            ('veth3','veth2','vveth3','2001:1:2::2',1280)):
        d = devices[dev]
        require(d['linkinfo']['info_kind'] == 'veth' and d['link'] == peer and d.get('master') == master and
                'UP' in d['flags'] and d['mtu'] == mtu, 'native IPv6 path/MTU/VRF changed')
        addresses = next(x for x in state['addresses'] if x['ifname'] == dev)['addr_info']
        require(any(a.get('local') == address and a.get('prefixlen') == 64 for a in addresses), 'original IPv6 interface address missing')
        counters = mib(state['ipv6_mib'][dev])
        require(counters['ifIndex'] == d['ifindex'] and all(name in counters for name in FIELDS), 'IPv6 counters belong to wrong native interface')
    for dev, dst, gateway, table in (('veth0','2001:1:2::/64','2001:1:1::1',tables[0]),
                                    ('veth3','2001:1:1::/64','2001:1:2::1',tables[2])):
        require(any(x.get('dst') == dst and x.get('gateway') == gateway and x.get('dev') == dev and str(x.get('table')) == str(table)
                    for x in state['ipv6_routes']), 'native host VRF forwarding route missing')
    for dev, dst in (('veth1','2001:1:1::/64'), ('veth2','2001:1:2::/64')):
        require(any(x.get('dst') == dst and x.get('dev') == dev and str(x.get('table')) == str(tables[1])
                    for x in state['ipv6_routes']), 'native router VRF connected route missing')
    return devices


def policy(text, enabled):
    if not enabled:
        require(not text.strip(), 'native XFRM policy leaked or unexpectedly active')
    else:
        require(len(re.findall(r'^src ', text, re.M)) == 1 and
                re.search(r'^src ::/0 dst 2001:1:2::2/128 uid 0$', text, re.M) and
                re.search(r'^\s+dir fwd action block index \d+ priority 0 share any flag', text, re.M),
                'actual native IPv6 forward XFRM block policy missing or changed')


def traversal(before, after, count, bytecount, forward_only=False):
    a, b = links(before), links(after)
    hops = [('veth0','tx'), ('veth1','rx')]
    if not forward_only: hops += [('veth2','tx'), ('veth3','rx'), ('veth3','tx'), ('veth2','rx'), ('veth1','tx'), ('veth0','rx')]
    for dev, direction in hops:
        first, last = a[dev]['stats64'][direction], b[dev]['stats64'][direction]
        require(last['packets'] - first['packets'] >= count and last['bytes'] - first['bytes'] >= count * bytecount,
                'original IPv6 traffic did not traverse actual native path')


def validate_evidence(report):
    original = report['original']; expected = ['ping6', *FIELDS]
    parsed = [re.fullmatch(r'TEST: (.*?)\s+\[ OK \]', line) for line in original['stdout'].splitlines() if line.startswith('TEST:')]
    require(original['returncode'] == 0 and not original['stderr'] and len(parsed) == 5 and all(parsed) and
            [p[1] for p in parsed] == expected and 'SKIP' not in original['stdout'], 'incomplete original IPv6 ingress default entry')
    tools = report['iproute2']
    require(tools.get('version') == '6.12.0' and tools.get('archive_sha256') == 'bbd141ef7b5d0127cc2152843ba61f274dc32814fa3e0f13e7d07a080bef53d9',
            'original pinned IPv6 route/XFRM tool provenance missing')
    require(re.fullmatch(r'[0-9a-f]{64}', report['traceroute_tool']['sha256']) and re.fullmatch(r'[0-9a-f]{64}', report['poll_control_sha256']),
            'original traceroute6 or native mixed poll control provenance missing')
    require(report['mixed_poll_control'] == dict(returncode=0, stdout=CONTROL, stderr='') and
            report['mixed_poll_missing_backend']['returncode'] not in (None, 0), 'native IPv6 UDP17 mixed readiness control failed or fell back to host')
    control = report['native_proc_control']
    require(mib(control['loopback'])['ifIndex'] == 1 and control['missing_device']['errno'] == 2 and control['path_escape']['errno'] == 95,
            'native per-interface proc boundary was bypassed')
    rows = report['commands']
    require([' '.join([x['tool'], *x['arguments']]) for x in rows] == COMMAND_PHASE.splitlines(), 'complete original IPv6 ingress command phases changed')
    traffic = [x for x in rows if x['arguments'][:2] == ['vrf', 'exec']]
    require(len(traffic) == 5 and [x['returncode'] for x in traffic] == [0, 1, 0, 1, 1], 'original IPv6 traffic/tool outcomes changed')
    for i, row in enumerate(traffic):
        a, b = row['instats_before'], row['instats_after']; topology(a); topology(b)
        require(a['forwarding'] == b['forwarding'] == ('0' if i == 3 else '1') and not row['stderr'] and row['native_clock_reads'] > 0 and
                row['vrf']['ifname'] == 'vveth0' and row['vrf']['linkinfo']['info_kind'] == 'vrf', 'native traffic forwarding/VRF/clock phase changed')
        policy(a['xfrm'], i == 4); policy(b['xfrm'], i == 4)
        if i == 0:
            require('10 packets transmitted, 10 received, 0% packet loss' in row['stdout'], 'original ten IPv6 echo replies missing')
            traversal(a, b, 10, 104)
        elif i == 2:
            require(re.search(r'traceroute to 2001:1:2::2 \(2001:1:2::2\), 30 hops max, \d+ byte packets', row['stdout']) and
                    re.search(r'^\s*2\s+.*2001:1:2::2.*\d+[.]\d+ ms', row['stdout'], re.M), 'original traceroute6 failed to reach actual native destination')
        else:
            sent = re.search(r'(\d+) packets transmitted, 0 received, 100% packet loss', row['stdout'])
            require(sent is not None and int(sent[1]) >= 1, 'original native error-phase ping evidence missing')
            traversal(a, b, int(sent[1]), 1348 if i == 1 else 104, forward_only=True)
    reads = [x for x in rows if x['tool'] == 'cat']
    require(len(reads) == 8 and all(x['arguments'] == ['/proc/net/dev_snmp6/veth1'] and not x['stderr'] for x in reads), 'original incoming-interface IPv6 proc reads missing')
    for field, row, first, last in zip(FIELDS, traffic[1:], reads[::2], reads[1::2]):
        a, b = mib(first['stdout']), mib(last['stdout'])
        c, d = mib(row['instats_before']['ipv6_mib']['veth1']), mib(row['instats_after']['ipv6_mib']['veth1'])
        index = links(row['instats_before'])['veth1']['ifindex']
        delta = b[field] - a[field]
        require(a['ifIndex'] == b['ifIndex'] == c['ifIndex'] == d['ifIndex'] == index and
                rows.index(first) < rows.index(row) < rows.index(last) and delta > 0 and delta == d[field] - c[field],
                'original IPv6 incoming-interface error delta missing or inconsistent with actual native traffic')
        require(all(d[other] == c[other] for other in FIELDS if other != field), 'native IPv6 error attributed to wrong failure class')
        if field != 'Ip6InHdrErrors':
            require(delta == int(re.search(r'(\d+) packets transmitted', row['stdout'])[1]), 'native IPv6 error count disagrees with actual sent pings')
    xfrm = [x for x in rows if x['arguments'][:1] == ['xfrm']]
    require(len(xfrm) == 2 and all(x['returncode'] == 0 and not x['stderr'] for x in xfrm), 'original XFRM policy add/delete failed')
    for row, enabled in zip(xfrm, (True, False)):
        policy(row['instats_before']['xfrm'], not enabled); policy(row['instats_after']['xfrm'], enabled)
    require(rows.index(xfrm[0]) < rows.index(traffic[4]) < rows.index(xfrm[1]), 'original native XFRM discard window reordered')
    for family in ('ipv4', 'ipv6'):
        writes = [x['arguments'][1] for x in rows if x['tool'] == 'sysctl' and x['arguments'][0] == '-qw' and x['arguments'][1].startswith('net.' + family + '.')]
        expected = [f'net.{family}.conf.all.forwarding=1']
        if family == 'ipv6': expected += ['net.ipv6.conf.all.forwarding=0', 'net.ipv6.conf.all.forwarding=1']
        expected += [f'net.{family}.conf.all.forwarding=0']
        require(writes == expected, 'native global forwarding enable/temporary-disable/restore changed')
    require([x['arguments'] for x in rows if x['returncode']] == [['link','show','dev','veth0'], ['link','show','dev','veth2']] +
            [x['arguments'] for x in traffic if x['returncode']] and all(not x['stderr'] for x in rows if x['returncode'] == 0),
            'unexpected original IPv6 configuration/cleanup failure')
    clean = report['cleanup_state']; devices = links(clean); names = [f'veth{i}' for i in range(4)]
    require(not any(name in devices for name in ('vveth0','router','vveth3')) and
            all('UP' not in devices[n]['flags'] and 'master' not in devices[n] and devices[n]['mtu'] == 1500 for n in names),
            'native IPv6 VRF/device/MTU cleanup incomplete')
    require(not any(a.get('scope') == 'global' for x in clean['addresses'] if x['ifname'] in names for a in x['addr_info']) and
            not any(x.get('dev') in names for family in ('ipv4_routes','ipv6_routes') for x in clean[family]) and clean['forwarding'] == '0',
            'native IPv6 route/address/forwarding leaked')
    policy(clean['xfrm'], False)
    lines = report['mib_after']['ipv4'].splitlines(); pos = next(i for i, s in enumerate(lines) if s.startswith('Ip:'))
    require(dict(zip(lines[pos].split()[1:], lines[pos + 1].split()[1:]))['Forwarding'] == '2', 'native IPv4 forwarding not restored')
    require(report['missing_backend_control']['returncode'] not in (None, 0) and report['vrf_binding_control']['baseline']['returncode'] == 0 and
            report['vrf_binding_control']['unknown_vrf']['returncode'] not in (None, 0), 'native IPv6 backend/VRF boundary control failed')
    native, stats = report['native_fixture'], report['stats']
    require(native['netlinks'] > 0 and native['raw_sockets'] > 0 and native['live'] == 0 and stats['outstanding'] == 0 and
            stats['worker_exit_code'] == 0 and stats['control_eof'] is True and stats['shutdown_timed_out'] is False,
            'native IPv6 ingress resources did not stop normally')


# Exact unchanged pinned default lifecycle.
COMMAND_PHASE = """ip link show dev veth0
ip link add veth0 type veth peer name veth1
ip link show dev veth2
ip link add veth2 type veth peer name veth3
ip link show dev veth0
ip link show dev veth1
ip link show dev veth2
ip link show dev veth3
ip -4 rule add pref 32765 table local
ip -4 rule del pref 0
ip -6 rule add pref 32765 table local
ip -6 rule del pref 0
ip link add dev vveth0 type vrf table 1
ip -4 route add table 1 unreachable default metric 4278198272
ip -6 route add table 1 unreachable default metric 4278198272
ip link set dev vveth0 up
ip link set dev veth0 master vveth0
ip link set dev veth0 up
ip address add 2001:1:1::2/64 dev veth0
ip -6 route add vrf vveth0 2001:1:2::/64 via 2001:1:1::1
ip link add dev router type vrf table 2
ip -4 route add table 2 unreachable default metric 4278198272
ip -6 route add table 2 unreachable default metric 4278198272
ip link set dev veth1 master router
ip link set dev veth1 up
ip address add 2001:1:1::1/64 dev veth1
ip link set dev veth2 master router
ip link set dev veth2 up
ip address add 2001:1:2::1/64 dev veth2
ip -j link show dev veth2
ip link set dev veth2 mtu 1280
ip link add dev vveth3 type vrf table 3
ip -4 route add table 3 unreachable default metric 4278198272
ip -6 route add table 3 unreachable default metric 4278198272
ip link set dev vveth3 up
ip link set dev veth3 master vveth3
ip link set dev veth3 up
ip address add 2001:1:2::2/64 dev veth3
ip -6 route add vrf vveth3 2001:1:1::/64 via 2001:1:2::1
ip -j link show dev veth3
ip link set dev veth3 mtu 1280
sysctl -n net.ipv4.conf.all.forwarding
sysctl -qw net.ipv4.conf.all.forwarding=1
sysctl -n net.ipv6.conf.all.forwarding
sysctl -qw net.ipv6.conf.all.forwarding=1
ip link show dev veth0 up
ip link show dev veth1 up
ip link show dev veth2 up
ip link show dev veth3 up
ip -j link show dev veth0
ip vrf exec vveth0 ping6 -c 10 -i 0.1 -w 5 2001:1:2::2
cat /proc/net/dev_snmp6/veth1
ip -j link show dev veth0
ip vrf exec vveth0 ping6 -s 1300 -c 1 -w 5 2001:1:2::2
cat /proc/net/dev_snmp6/veth1
cat /proc/net/dev_snmp6/veth1
ip -j link show dev veth0
ip vrf exec vveth0 traceroute6 2001:1:2::2
cat /proc/net/dev_snmp6/veth1
cat /proc/net/dev_snmp6/veth1
ip -j link show dev veth0
sysctl -qw net.ipv6.conf.all.forwarding=0
ip vrf exec vveth0 ping6 -c 1 -w 5 2001:1:2::2
sysctl -qw net.ipv6.conf.all.forwarding=1
cat /proc/net/dev_snmp6/veth1
cat /proc/net/dev_snmp6/veth1
ip -j link show dev veth0
ip xfrm policy add dst 2001:1:2::2/128 dir fwd action block
ip vrf exec vveth0 ping6 -c 1 -w 5 2001:1:2::2
ip xfrm policy del dst 2001:1:2::2/128 dir fwd
cat /proc/net/dev_snmp6/veth1
sysctl -qw net.ipv6.conf.all.forwarding=0
sysctl -qw net.ipv4.conf.all.forwarding=0
ip link set dev veth3 mtu 1500
ip -6 route del vrf vveth3 2001:1:1::/64 via 2001:1:2::1
ip address del 2001:1:2::2/64 dev veth3
ip link set dev veth3 down
ip link set dev veth3 nomaster
ip -6 route del table 3 unreachable default metric 4278198272
ip -4 route del table 3 unreachable default metric 4278198272
ip link del dev vveth3
ip link set dev veth2 mtu 1500
ip address del 2001:1:2::1/64 dev veth2
ip link set dev veth2 down
ip link set dev veth2 nomaster
ip address del 2001:1:1::1/64 dev veth1
ip link set dev veth1 down
ip link set dev veth1 nomaster
ip -6 route del table 2 unreachable default metric 4278198272
ip -4 route del table 2 unreachable default metric 4278198272
ip link del dev router
ip -6 route del vrf vveth0 2001:1:2::/64 via 2001:1:1::1
ip address del 2001:1:1::2/64 dev veth0
ip link set dev veth0 down
ip link set dev veth0 nomaster
ip -6 route del table 1 unreachable default metric 4278198272
ip -4 route del table 1 unreachable default metric 4278198272
ip link del dev vveth0
ip -6 rule add pref 0 table local
ip -6 rule del pref 32765
ip -4 rule add pref 0 table local
ip -4 rule del pref 32765"""
