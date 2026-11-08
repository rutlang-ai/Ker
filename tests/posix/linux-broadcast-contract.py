"""Evidence contract for the unchanged complete directed-broadcast selftest."""
import hashlib
import re


def require(value, message):
    if not value:
        raise RuntimeError(message)


DESTINATIONS = ['198.51.100.255', '198.51.200.255', '192.0.2.255', '255.255.255.255',
                '192.0.2.255', '198.51.200.255', '198.51.100.255', '255.255.255.255'] * 2
SOURCES = ['192.0.2.1'] * 4 + ['198.51.100.1'] * 4 + [
    '198.51.100.2', '198.51.200.2', '192.0.2.1', '192.0.2.1',
    '192.0.2.2', '198.51.200.2', '198.51.100.1', '198.51.100.1']
NAMES = [
    'h1 -> net2: reply from r1 (not forwarding)',
    'h1 -> net3: reply from r1 (not forwarding)',
    'h1 -> net1: reply from r1 (not dropping)',
    'h1 -> 255.255.255.255: reply from r1 (not forwarding)',
    'h2 -> net1: reply from r1 (not forwarding)',
    'h2 -> net3: reply from r1 (not forwarding)',
    'h2 -> net2: reply from r1 (not dropping)',
    'h2 -> 255.255.255.255: reply from r1 (not forwarding)',
    'h1 -> net2: reply from h2 (forwarding)',
    'h1 -> net3: reply from h3 (forwarding)',
    'h1 -> net1: no reply (dropping)',
    'h1 -> 255.255.255.255: reply from r1 (not forwarding)',
    'h2 -> net1: reply from h1 (forwarding)',
    'h2 -> net3: reply from h3 (forwarding)',
    'h2 -> net2: no reply (dropping)',
    'h2 -> 255.255.255.255: reply from r1 (not forwarding)']
BC_KEYS = ['net.ipv4.conf.' + dev + '.bc_forwarding' for dev in ('all', 'veth1', 'veth2')]
HOSTS = [('veth0', 'veth1', 'vrf-h1', '192.0.2'),
         ('veth3', 'veth2', 'vrf-h2', '198.51.100'),
         ('veth5', 'veth4', 'vrf-h3', '198.51.200')]


def topology(state):
    links = {x['ifname']: x for x in state['links']}
    addresses = {x['ifname']: x.get('addr_info', []) for x in state['addresses']}
    tables = []
    for host, port, vrf, prefix in HOSTS:
        require(all(links[n]['linkinfo']['info_kind'] == 'veth' and 'UP' in links[n]['flags']
                    for n in (host, port)) and links[host]['link'] == port and links[port]['link'] == host and
                links[host].get('master') == vrf and 'master' not in links[port] and
                links[vrf]['linkinfo']['info_kind'] == 'vrf' and 'UP' in links[vrf]['flags'],
                'native three-host broadcast links or VRFs changed')
        table = links[vrf]['linkinfo']['info_data']['table']; tables.append(table)
        for dev, suffix in ((host, '.2'), (port, '.1')):
            require(any(a.get('local') == prefix + suffix and a.get('prefixlen') == 24
                        for a in addresses[dev]), 'native broadcast interface address missing')
            require(any(r.get('dst') == prefix + '.0/24' and r.get('dev') == dev and
                        str(r.get('table', 'main')) == (str(table) if dev == host else 'main') and
                        r.get('protocol') == 'kernel' for r in state['routes']),
                    'native broadcast connected route missing')
        for _, _, _, remote in HOSTS:
            if remote != prefix:
                require(any(r.get('dst') == remote + '.0/24' and r.get('dev') == host and
                            str(r.get('table')) == str(table) and r.get('gateway') == prefix + '.1'
                            for r in state['routes']), 'native broadcast host FIB route missing')
    require(len(set(tables)) == 3, 'native broadcast VRFs share a routing table')


def forwarded(text):
    lines = text.splitlines()
    row = next(i for i, line in enumerate(lines) if line.startswith('Ip:'))
    return int(dict(zip(lines[row].split()[1:], lines[row + 1].split()[1:]))['ForwDatagrams'])


def validate_evidence(report):
    original = report.get('original', {})
    results = [re.fullmatch(r'TEST: (.*?)\s+\[ OK \]', line) for line in
               original.get('stdout', '').splitlines() if line.startswith('TEST:')]
    require(original.get('returncode') == 0 and not original.get('stderr') and
            len(results) == 16 and all(results) and [r[1] for r in results] == NAMES,
            'incomplete original sixteen-case broadcast matrix')
    records = report['commands']
    traffic = [r for r in records if r['tool'] == 'grep' or r['arguments'][:2] == ['vrf', 'exec']]
    require(len(traffic) == 32, 'missing original broadcast ping or literal grep')
    for i in range(16):
        ping, grep = traffic[2 * i:2 * i + 2]
        host, dev = ('vrf-h1', 'veth0') if i % 8 < 4 else ('vrf-h2', 'veth3')
        require(ping['tool'] == 'ip' and ping['arguments'] == [
            'vrf', 'exec', host, 'ping', '-I', dev, DESTINATIONS[i], '-c', '10', '-i', '0.1', '-w', '5', '-b']
            and ping['vrf']['ifname'] == host and ping['vrf']['linkinfo']['info_kind'] == 'vrf',
            'original broadcast target, VRF, count or timing changed')
        require(ping.get('native_clock_reads', 0) > 0, 'broadcast ping did not read native realtime')
        combined = ping['stdout'] + ping['stderr']
        require(not ping['stderr'] and 'time of day goes back' not in combined.lower(),
                'broadcast ping reported a backward native clock')
        require(grep['tool'] == 'grep' and grep['arguments'] == ['bytes from ' + SOURCES[i]] and
                grep['input'] == combined and grep['input_sha256'] == hashlib.sha256(combined.encode()).hexdigest()
                and not grep['stderr'], 'original literal broadcast source predicate changed')
        # Keep the shell's specific-source grep/check_err_fail oracle. Other
        # reply sources and partial reception do not mean that predicate passed.
        matched = re.search('bytes from ' + SOURCES[i], combined) is not None
        require(grep['returncode'] == (0 if matched else 1) and
                matched == (i not in (10, 14)), 'original broadcast source oracle failed')
        for key in ('broadcast_before', 'broadcast_after'):
            state = ping[key]
            topology(state)
            require(all(state['sysctls'].get(name) == str(i // 8) for name in BC_KEYS) and
                    state['sysctls'].get('net.ipv4.conf.all.forwarding') == '1' and
                    state['sysctls'].get('net.ipv4.icmp_echo_ignore_broadcasts') == '0',
                    'native broadcast phase or echo/forwarding sysctl is ineffective')
        delta = forwarded(ping['broadcast_after']['snmp']) - forwarded(ping['broadcast_before']['snmp'])
        require(delta > 0 if i in (8, 9, 12, 13) else delta == 0,
                'native per-probe broadcast forwarding disagrees with its phase')
    writes = [i for i, r in enumerate(records) if r['tool'] == 'sysctl' and r['arguments'][0] == '-qw']
    expected = ['net.ipv4.conf.all.forwarding=1', 'net.ipv6.conf.all.forwarding=1',
                'net.ipv4.icmp_echo_ignore_broadcasts=0']
    for phase in ('0', '1'):
        expected += [name + '=' + phase for name in BC_KEYS] + [name + '=0' for name in reversed(BC_KEYS)]
    expected += ['net.ipv4.icmp_echo_ignore_broadcasts=1', 'net.ipv6.conf.all.forwarding=0',
                 'net.ipv4.conf.all.forwarding=0']
    require([records[i]['arguments'][1] for i in writes] == expected,
            'original broadcast enable/restore commands changed')
    ping_indices = [i for i, r in enumerate(records) if r['arguments'][:2] == ['vrf', 'exec']]
    require(writes[5] < ping_indices[0] < ping_indices[7] < writes[6] < writes[11] <
            ping_indices[8] < ping_indices[15] < writes[12], 'broadcast phase restoration reordered')
    cleanup = report['cleanup_state']
    baseline = {r['arguments'][1]: r['stdout'].strip() for r in records
                if r['tool'] == 'sysctl' and r['arguments'][0] == '-n'}
    require(cleanup['sysctls'] == baseline and all(baseline.get(n) == '0' for n in BC_KEYS) and
            baseline.get('net.ipv4.icmp_echo_ignore_broadcasts') == '1' and
            all(baseline.get('net.' + f + '.conf.all.forwarding') == '0' for f in ('ipv4', 'ipv6')),
            'native broadcast sysctls not restored to observed baseline')
    cleaned = {x['ifname']: x for x in cleanup['links']}
    require(not any(vrf in cleaned for _, _, vrf, _ in HOSTS) and
            all('UP' not in cleaned[dev]['flags'] and 'master' not in cleaned[dev]
                for host, port, _, _ in HOSTS for dev in (host, port)),
            'native broadcast VRF or interface state leaked')
    devices = {dev for host, port, _, _ in HOSTS for dev in (host, port)}
    require(not any(a.get('scope') == 'global' for x in cleanup['addresses'] if x['ifname'] in devices
                    for a in x.get('addr_info', [])) and
            not any(r.get('dev') in devices for r in cleanup['routes']),
            'native broadcast addresses or routes leaked')
    require([r['arguments'] for r in records if r['returncode']] == [
        ['link', 'show', 'dev', 'veth0'], ['link', 'show', 'dev', 'veth2'], ['link', 'show', 'dev', 'veth4'],
        ['bytes from 192.0.2.1'], ['bytes from 198.51.100.1']], 'unexpected native broadcast command failure')
    require(all(not r['stderr'] for r in records if r['returncode'] == 0), 'native broadcast helper error')
    require(forwarded(report['mib_after']['ipv4']) > forwarded(report['mib_before']['ipv4']),
            'broadcast traffic did not traverse native forwarding')
    require(report.get('missing_backend_control', {}).get('returncode') not in (None, 0),
            'broadcast original passed without imported Linux')
    binding = report.get('vrf_binding_control', {})
    require(binding.get('baseline', {}).get('returncode') == 0 and
            binding.get('unknown_vrf', {}).get('returncode') not in (None, 0), 'ineffective native VRF control')
    native, stats = report.get('native_fixture', {}), report.get('stats', {})
    require(native.get('netlinks', 0) > 0 and native.get('raw_sockets', 0) > 0 and native.get('live') == 0 and
            stats.get('outstanding') == 0 and stats.get('worker_exit_code') == 0 and
            stats.get('control_eof') is True and stats.get('shutdown_timed_out') is False,
            'native broadcast resources did not close normally')
