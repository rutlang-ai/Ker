"""Independent evidence checks for the unchanged Linux tc_vlan_modify test."""
import ipaddress
import json
import struct


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def _action_rows(filters, locus):
    rows = filters.get(locus)
    require(isinstance(rows, list), f'missing native VLAN filter snapshot {locus}')
    for row in rows:
        require(row.get('protocol') == 'all' and row.get('pref') == 1 and
                row.get('kind') == 'flower' and row.get('chain', 0) == 0,
                f'unexpected native flower filter in {locus}')
    result = []
    for row in rows:
        options = row.get('options')
        if not options:
            continue
        actions = options.get('actions')
        require(isinstance(actions, list) and len(actions) == 1,
                f'VLAN flower filter in {locus} does not have exactly one action')
        action = actions[0]
        require(action.get('kind') == 'vlan' and action.get('vlan_action') == 'modify' and
                action.get('protocol') == '802.1Q' and action.get('order') == 1 and
                action.get('control_action', {}).get('type') == 'pipe' and
                row.get('options', {}).get('not_in_hw') is True,
                f'non-original native VLAN modify action in {locus}')
        result.append((row, action))
    return result


def _rules(snapshot, mode):
    filters = snapshot.get('filters')
    require(isinstance(filters, dict) and set(filters) == {
        'veth1:ingress', 'veth1:egress', 'veth2:ingress', 'veth2:egress'},
        'incomplete four-locus native TC VLAN snapshot')
    expected = ({'veth1:ingress': 65, 'veth2:ingress': 85} if mode == 'ingress' else
                {'veth1:egress': 85, 'veth2:egress': 65})
    found = {}
    for locus in filters:
        rows = _action_rows(filters, locus)
        if rows:
            require(locus in expected and len(rows) == 1,
                    f'unexpected/duplicate VLAN action at {locus}')
            row, action = rows[0]
            require(action.get('id') == expected[locus] and row.get('options', {}).get('handle') == 1,
                    f'wrong original VLAN ID/handle at {locus}')
            found[locus] = action.get('stats', {})
    require(set(found) == set(expected), f'original {mode} VLAN action pair is incomplete')
    for locus, stats in found.items():
        require(all(type(stats.get(key)) is int and stats[key] >= 0
                    for key in ('bytes', 'packets', 'drops', 'overlimits', 'requeues', 'backlog', 'qlen')),
                f'missing native action counters at {locus}')
        require(all(stats[key] == 0 for key in ('drops', 'overlimits', 'requeues', 'backlog', 'qlen')),
                f'native VLAN action dropped or queued packets at {locus}')
    return found


def _partial_rules(snapshot, mode, expected):
    filters = snapshot.get('filters')
    require(isinstance(filters, dict) and set(filters) == {
        'veth1:ingress', 'veth1:egress', 'veth2:ingress', 'veth2:egress'},
        'incomplete native VLAN filter snapshot')
    found = {}
    for locus in filters:
        rows = _action_rows(filters, locus)
        if rows:
            require(locus in expected and len(rows) == 1,
                    f'unexpected native VLAN action at {locus}')
            row, action = rows[0]
            require(action.get('id') == expected[locus] and row.get('options', {}).get('handle') == 1,
                    f'wrong original VLAN action at {locus}')
            found[locus] = action.get('stats', {})
    require(set(found) == set(expected), 'native VLAN action state differs from original script phase')
    for locus, stats in found.items():
        require(all(type(stats.get(key)) is int and stats[key] >= 0
                    for key in ('bytes', 'packets', 'drops', 'overlimits', 'requeues', 'backlog', 'qlen')) and
                all(stats[key] == 0 for key in ('drops', 'overlimits', 'requeues', 'backlog', 'qlen')),
                f'invalid native VLAN action counters at {locus}')
    return found


def _empty(snapshot):
    filters = snapshot.get('filters', {})
    require(set(filters) == {'veth1:ingress', 'veth1:egress', 'veth2:ingress', 'veth2:egress'},
            'incomplete empty native TC VLAN snapshot')
    require(all(not _action_rows(filters, locus) for locus in filters),
            'native VLAN actions were present in an original baseline/cleanup phase')


def _frame_packet(row):
    try:
        frame = bytes.fromhex(row['frame_hex'])
    except (KeyError, TypeError, ValueError) as error:
        raise RuntimeError('malformed captured native Ethernet frame') from error
    require(len(frame) == row.get('frame_length') and len(frame) >= 14,
            'native Ethernet frame length mismatch')
    protocol = struct.unpack_from('!H', frame, 12)[0]
    offset = 14
    raw_vlans = []
    raw_tpid = []
    while protocol in (0x8100, 0x88a8):
        require(offset + 4 <= len(frame), 'truncated inline VLAN header')
        tci = struct.unpack_from('!H', frame, offset)[0]
        raw_vlans.append(tci & 0x0fff)
        raw_tpid.append(protocol)
        protocol = struct.unpack_from('!H', frame, offset + 2)[0]
        offset += 4
    aux = row.get('vlan_auxdata')
    require(isinstance(aux, dict) and type(aux.get('status')) is int and
            type(aux.get('length')) is int and type(aux.get('snaplen')) is int and
            aux['length'] >= aux['snaplen'] == len(frame),
            'missing or inconsistent native PACKET_AUXDATA')
    vlan_tags = list(zip(raw_tpid, raw_vlans and [
        struct.unpack_from('!H', frame, 14 + index * 4)[0] for index in range(len(raw_vlans))] or []))
    aux_vlan = bool(aux['status'] & (1 << 4))
    if aux_vlan:
        require(type(aux.get('vlan_tci')) is int and 0 <= aux['vlan_tci'] <= 0xffff and
                type(aux.get('vlan_tpid')) is int and aux.get('vlan_tpid') == 0x8100 and
                aux['status'] & (1 << 6),
                'native VLAN-valid auxiliary data lacks valid 802.1Q TCI/TPID')
        if raw_vlans:
            require(raw_tpid[0] == aux['vlan_tpid'] and
                    struct.unpack_from('!H', frame, 14)[0] == aux['vlan_tci'],
                    'inline and auxiliary native VLAN tags contradict')
    effective_vlans = list(raw_vlans)
    if not effective_vlans and aux_vlan:
        effective_vlans.append(aux['vlan_tci'] & 0x0fff)
        vlan_tags.append((aux['vlan_tpid'], aux['vlan_tci']))
    elif raw_vlans:
        vlan_tags = [(tpid, struct.unpack_from('!H', frame, 14 + index * 4)[0])
                     for index, tpid in enumerate(raw_tpid)]

    source = destination = None
    icmp_type = identifier = sequence = None
    network_hex = None
    if protocol == 0x0800:
        require(offset + 20 <= len(frame) and frame[offset] >> 4 == 4,
                'truncated native IPv4 packet')
        header_length = (frame[offset] & 0x0f) * 4
        require(header_length >= 20 and offset + header_length + 8 <= len(frame),
                'invalid native IPv4 header length')
        source = str(ipaddress.IPv4Address(frame[offset + 12:offset + 16]))
        destination = str(ipaddress.IPv4Address(frame[offset + 16:offset + 20]))
        total_length = struct.unpack_from('!H', frame, offset + 2)[0]
        require(header_length <= total_length <= len(frame) - offset,
                'invalid native IPv4 total length')
        network_hex = frame[offset:offset + total_length].hex()
        if frame[offset + 9] == 1:
            pos = offset + header_length
            icmp_type = frame[pos]
            identifier, sequence = struct.unpack_from('!HH', frame, pos + 4)
    elif protocol == 0x86dd:
        require(offset + 40 <= len(frame) and frame[offset] >> 4 == 6,
                'truncated native IPv6 packet')
        source = str(ipaddress.IPv6Address(frame[offset + 8:offset + 24]))
        destination = str(ipaddress.IPv6Address(frame[offset + 24:offset + 40]))
        payload_length = struct.unpack_from('!H', frame, offset + 4)[0]
        require(offset + 40 + payload_length <= len(frame),
                'invalid native IPv6 payload length')
        network_hex = frame[offset:offset + 40 + payload_length].hex()
        next_header, pos = frame[offset + 6], offset + 40
        while next_header in (0, 43, 60):
            require(pos + 2 <= len(frame), 'truncated native IPv6 extension header')
            following, length = frame[pos], (frame[pos + 1] + 1) * 8
            require(pos + length <= len(frame), 'invalid native IPv6 extension length')
            next_header, pos = following, pos + length
        if next_header == 58 and pos + 8 <= len(frame):
            icmp_type = frame[pos]
            identifier, sequence = struct.unpack_from('!HH', frame, pos + 4)
    return {'vlans': tuple(effective_vlans), 'vlan_tags': tuple(vlan_tags),
            'ether_type': struct.unpack_from('!H', frame, 12)[0], 'protocol': protocol,
            'source_mac': frame[6:12].hex(),
            'source': source, 'destination': destination,
            'icmp_type': icmp_type, 'identifier': identifier, 'sequence': sequence,
            'network_hex': network_hex}


def _native_window(row):
    pair = row.get('native_clock_pair', {})
    require(type(pair.get('native_realtime_ns')) is int and
            type(pair.get('host_monotonic_before_ns')) is int and
            type(pair.get('host_monotonic_after_ns')) is int and
            pair['host_monotonic_before_ns'] <= pair['host_monotonic_after_ns'],
            'native packet timestamp lacks a valid realtime/monotonic calibration')
    offset = row['native_timestamp_ns'] - pair['native_realtime_ns']
    return pair['host_monotonic_before_ns'] + offset, pair['host_monotonic_after_ns'] + offset


def _overlaps(start, finish, low, high):
    return start <= high and finish >= low


def _feasible_counter_cuts(rows, started, finished):
    """Return ordered capture-prefix cuts possible during one tc query."""
    require(type(started) is int and type(finished) is int and started <= finished,
            'invalid native counter query bracket')
    candidates = []
    for cut in range(len(rows) + 1):
        prefix, suffix = rows[:cut], rows[cut:]
        if any(row['high'] <= started for row in suffix) or any(row['low'] >= finished for row in prefix):
            continue
        earliest = max(started, max((row['low'] for row in prefix), default=started))
        latest = min(finished, min((row['high'] for row in suffix), default=finished))
        if earliest <= latest:
            candidates.append((cut, earliest, latest))
    return candidates


def _counter_delta_matches(rows, before, after, packet_delta, byte_delta):
    before_cuts = _feasible_counter_cuts(rows, before['started_monotonic_ns'],
                                         before['finished_monotonic_ns'])
    after_cuts = _feasible_counter_cuts(rows, after['started_monotonic_ns'],
                                        after['finished_monotonic_ns'])
    return any(new_cut >= old_cut and
               new_cut - old_cut == packet_delta and
               sum(row['size'] for row in rows[old_cut:new_cut]) == byte_delta
               for old_cut, _, _ in before_cuts for new_cut, _, _ in after_cuts)


def _validate_action_prefixes(pings, frames):
    """Reconcile action counters with calibrated captures, including ARP/ND.

    A counter sample is taken somewhere within each four-interface TC query.
    Frames wholly between the before-query end and after-query start are
    definite members of the counter prefix. Frames inside either query bracket
    are possible members. The counter deltas must fit those ordered bounds.
    """
    for ping_index, ping in enumerate(pings):
        if ping['returncode'] != 0:
            continue
        mode = 'ingress' if ping_index < 4 else 'egress'
        before, after = ping['vlan_modify_before'], ping['vlan_modify_after']
        before_stats = _rules(before, mode)
        after_stats = _rules(after, mode)
        middle_low = before['finished_monotonic_ns']
        middle_high = after['started_monotonic_ns']
        require(before['started_monotonic_ns'] <= middle_low <= middle_high <=
                after['finished_monotonic_ns'], 'invalid native TC action counter query brackets')
        for locus, old in before_stats.items():
            interface, direction = locus.split(':')
            capture_direction = 'ingress' if direction == 'ingress' else 'outgoing'
            captured = []
            echo_packets = echo_bytes = 0
            for row in frames:
                if row.get('ifname') != interface or row.get('direction') != capture_direction:
                    continue
                event_start, event_finish = _native_window(row)
                size = row['frame_length'] - (14 if mode == 'ingress' else 0)
                require(size >= 0, 'invalid frame length for native TC byte counter')
                captured.append({'low': event_start, 'high': event_finish,
                                 'native_timestamp_ns': row['native_timestamp_ns'], 'size': size})
                if (ping['started_monotonic_ns'] <= event_start and
                        event_finish <= ping['finished_monotonic_ns']):
                    packet = _frame_packet(row)
                    if packet['icmp_type'] in (0, 8, 128, 129):
                        echo_packets += 1
                        echo_bytes += size
            packet_delta = after_stats[locus]['packets'] - old['packets']
            byte_delta = after_stats[locus]['bytes'] - old['bytes']
            captured.sort(key=lambda row: row['native_timestamp_ns'])
            feasible = _counter_delta_matches(captured, before, after, packet_delta, byte_delta)
            require(feasible,
                    f'native VLAN action counters do not match calibrated packet/byte prefix at {locus}')
            require(echo_packets == 10 and packet_delta >= echo_packets and byte_delta >= echo_bytes,
                    f'native VLAN action counter omitted original echo traffic at {locus}')


def _validate_observer(report, pings):
    observer = report.get('vlan_packet_observer', {})
    capture = report.get('vlan_packet_observer_capture', {})
    require(isinstance(capture.get('archive'), str) and capture.get('sha256') == observer.get('sha256') and
            type(capture.get('bytes')) is int and capture['bytes'] > 0 and
            isinstance(capture.get('stats_archive'), str) and
            isinstance(capture.get('stats_sha256'), str) and len(capture['stats_sha256']) == 64 and
            type(capture.get('stats_bytes')) is int and capture['stats_bytes'] > 0,
            'native VLAN packet/statistics artifacts were not retained for CI')
    ready = observer.get('ready', {})
    require(ready.get('type') == 'ready' and
            ready.get('backend_control') == {'missing_channel_errno': 2, 'host_fallback': False},
            'native VLAN observer did not prove the no-host-fallback control')
    interfaces = {row.get('name'): row for row in ready.get('interfaces', [])}
    require(set(interfaces) == {'veth0', 'veth1', 'veth2', 'veth3'},
            'native VLAN observer did not bind all original bridge ports')
    sockets = ready.get('socket', {}).get('interfaces', [])
    require(len(sockets) == 4 and {row.get('name') for row in sockets} == set(interfaces),
            'native VLAN observer socket identities are incomplete')
    native_links = {row.get('ifname'): row for row in
                    pings[0].get('bridge_state', {}).get('native_links', [])}
    require(set(native_links) == {'veth0', 'veth1', 'veth2', 'veth3'},
            'native VLAN socket identity lacks the resident Linux veth link census')
    for row in sockets:
        name = row['name']
        native_name = row.get('native_getsockname', {})
        link = native_links[name]
        address_hex = str(link.get('address', '')).replace(':', '').lower()
        require(row.get('family') == 17 and row.get('protocol') == 3 and
                type(row.get('ifindex')) is int and row['ifindex'] == interfaces[name].get('ifindex') and
                native_name == {'family': 17, 'protocol': 3,
                    'ifindex': interfaces[name].get('ifindex'), 'hatype': 1,
                    'halen': 6, 'address_hex': address_hex} and
                link.get('ifindex') == row.get('ifindex') and len(address_hex) == 12,
                f'native AF_PACKET socket identity mismatch on {name}')
    for ping in pings:
        links = {row.get('ifname'): row for row in ping.get('bridge_state', {}).get('native_links', [])}
        require(set(links) == set(native_links) and
                all(links[name].get('ifindex') == native_links[name].get('ifindex') and
                    links[name].get('address') == native_links[name].get('address')
                    for name in native_links),
                'native VLAN interface identity changed during original traffic')
    frames = observer.get('frames')
    require(isinstance(frames, list) and len(frames) > 0,
            'native VLAN observer captured no Ethernet frames')
    by_interface = {name: 0 for name in interfaces}
    parsed = []
    for row in frames:
        name = row.get('ifname')
        require(name in by_interface and row.get('type') == 'frame' and
                type(row.get('native_timestamp_ns')) is int and row['native_timestamp_ns'] > 0 and
                type(row.get('host_recv_before_ns')) is int and
                type(row.get('host_recv_after_ns')) is int and
                row['host_recv_before_ns'] <= row['host_recv_after_ns'] and
                row['host_recv_after_ns'] <= row.get('native_clock_pair', {}).get('host_monotonic_after_ns', 0) and
                row['native_timestamp_ns'] <= row.get('native_clock_pair', {}).get('native_realtime_ns', -1) and
                0 <= row.get('pkttype', -1) <= 4 and row.get('halen') == 6 and
                type(row.get('protocol')) is int and isinstance(row.get('native_address_hex'), str) and
                len(row['native_address_hex']) == 12 and
                row.get('native_hatype') == 1 and row.get('native_ifindex') == interfaces[name]['ifindex'] and
                row.get('ifindex') == interfaces[name]['ifindex'] and
                row.get('direction') == ('outgoing' if row['pkttype'] == 4 else 'ingress'),
                f'invalid native AF_PACKET identity/timestamp for {name}')
        packet = _frame_packet(row)
        require(row['protocol'] == packet['ether_type'] and
                row['native_address_hex'].lower() == packet['source_mac'],
                f'native AF_PACKET sockaddr protocol/source MAC mismatch on {name}')
        by_interface[name] += 1
        parsed.append((row, packet))
    stats = observer.get('statistics', {})
    require(stats.get('drops') == 0 and set(stats.get('by_interface', {})) == set(interfaces),
            'native AF_PACKET statistics lack a complete zero-drop census')
    for name, count in by_interface.items():
        per_interface = stats['by_interface'][name]
        require(per_interface.get('drops') == 0 and per_interface.get('packets') == count,
                f'native AF_PACKET frame census mismatch on {name}')
    require(observer.get('frame_count') == len(frames) and
            stats.get('packets') == len(frames), 'native AF_PACKET aggregate frame count mismatch')

    witnesses = []
    expected_ips = {
        'ipv4': ('192.0.2.17', '192.0.2.18', 8, 0),
        'ipv6': ('2001:db8:2::1', '2001:db8:2::2', 128, 129),
    }
    for ping in pings:
        if ping['returncode'] != 0:
            continue
        family = 'ipv4' if ping['arguments'][3] == 'ping' else 'ipv6'
        source, destination, request_type, reply_type = expected_ips[family]
        start, finish = ping['started_monotonic_ns'], ping['finished_monotonic_ns']
        scoped = []
        for row, packet in parsed:
            event_start, event_finish = _native_window(row)
            if not (start <= event_start and event_finish <= finish):
                continue
            if packet['icmp_type'] in (request_type, reply_type):
                scoped.append((row, packet))
        def seen(ifname, direction, vid, icmp_type, src, dst, ident, sequence, network_hex=None):
            matches = [(row, packet) for row, packet in scoped
                if row['ifname'] == ifname and row['direction'] == direction and
                   packet['vlans'] == (vid,) and packet['vlan_tags'] == ((0x8100, vid),) and
                   packet['icmp_type'] == icmp_type and
                   packet['source'] == src and packet['destination'] == dst and
                   packet['identifier'] == ident and packet['sequence'] == sequence and
                   (network_hex is None or packet['network_hex'] == network_hex)]
            require(len(matches) == 1,
                    f'native {family} echo id/sequence lacks one calibrated {ifname}/{direction} VID {vid} witness')
            return matches
        requests = [(packet['identifier'], packet['sequence']) for row, packet in scoped
            if row['ifname'] == 'veth1' and row['direction'] == 'ingress' and
               packet['vlans'] == (85,) and packet['vlan_tags'] == ((0x8100, 85),) and
               packet['icmp_type'] == request_type and
               packet['source'] == source and packet['destination'] == destination]
        require(sorted(sequence for _, sequence in requests) == list(range(1, 11)) and
                len({identifier for identifier, _ in requests}) == 1,
                f'native {family} ingress request witness does not contain the original 10 echo sequences')
        identifier = requests[0][0]
        replies = [(packet['identifier'], packet['sequence']) for row, packet in scoped
            if row['ifname'] == 'veth2' and row['direction'] == 'ingress' and
               packet['vlans'] == (65,) and packet['vlan_tags'] == ((0x8100, 65),) and
               packet['icmp_type'] == reply_type and
               packet['source'] == destination and packet['destination'] == source]
        require(sorted(sequence for _, sequence in replies) == list(range(1, 11)) and
                {value for value, _ in replies} == {identifier},
                f'native {family} ingress reply witness does not match request ID/sequences')
        for sequence in range(1, 11):
            # Match each original echo ID/sequence across source ingress,
            # rewritten destination ingress, reply ingress and rewritten
            # source ingress. VLAN IDs come from PACKET_AUXDATA because this
            # LKL AF_PACKET capture strips the inline header.
            request = seen('veth1', 'ingress', 85, request_type, source, destination,
                           identifier, sequence)
            request_bytes = request[0][1]['network_hex']
            seen('veth2', 'outgoing', 65, request_type, source, destination, identifier,
                 sequence, request_bytes)
            seen('veth3', 'ingress', 65, request_type, source, destination, identifier,
                 sequence, request_bytes)
            reply = seen('veth2', 'ingress', 65, reply_type, destination, source,
                         identifier, sequence)
            reply_bytes = reply[0][1]['network_hex']
            seen('veth1', 'outgoing', 85, reply_type, destination, source, identifier,
                 sequence, reply_bytes)
            seen('veth0', 'ingress', 85, reply_type, destination, source, identifier,
                 sequence, reply_bytes)
        witnesses.append((family, start, finish, identifier))
    require(len(witnesses) == 4, 'native VLAN rewrite packet witnesses do not cover both families/modes')


def validate_evidence(report):
    require(report.get('program') == 'tc_vlan_modify.sh' and
            report.get('revision') == '7fdb7c1824a1f9979d648d7ae28ac446bcee9c6e',
            'wrong original Linux VLAN modify source')
    require(report.get('source_hashes', {}).get('forwarding/tc_vlan_modify.sh') ==
            '91b692478a9c1506ad0fc57561b9ddd804cbc5a983b6a3001a35370e8b600ea9',
            'modified or wrong pinned original tc_vlan_modify.sh')
    require(report.get('source_hashes', {}).get('forwarding/lib.sh') ==
            '8fb499582bb13c830e7fe9cbcb0baffc0bedf552d12c3c9241b65ecf14414537' and
            report.get('source_hashes', {}).get('lib.sh') ==
            '875a357f3264e3126af195e97a36217ba6e44c0812afc1b6b8a414f1984dcccd' and
            report.get('source_hashes', {}).get('forwarding/Makefile') ==
            '2c66e188a0a956c79dfbedd3a3449fd455e94e0a2a5b07550aaed0b79f745d96',
            'modified or wrong pinned original forwarding framework')
    expected_tests = [
        'TEST: VLAN modify at ingress                                        [ OK ]',
        'TEST: VLAN modify at egress                                         [ OK ]']
    original = report.get('original', {})
    require(original.get('returncode') == 0 and original.get('stderr') == '' and
            original.get('stdout', '').splitlines() == expected_tests,
            'unchanged original VLAN ingress/egress selftests did not both pass')

    commands = report.get('commands', [])
    pings = [row for row in commands if row.get('arguments', [])[:2] == ['vrf', 'exec']]
    previous_finish = 0
    for row in commands:
        started, finished = row.get('started_monotonic_ns'), row.get('finished_monotonic_ns')
        require(type(started) is int and type(finished) is int and
                previous_finish <= started <= finished,
                'original native command timeline is incomplete or out of order')
        previous_finish = finished
    require(len(pings) == 8, 'incomplete original VLAN IPv4/IPv6 negative/positive ping matrix')
    expected_addresses = ['192.0.2.18', '2001:db8:2::2'] * 4
    expected_status = [1, 1, 0, 0, 1, 1, 0, 0]
    for index, row in enumerate(pings):
        family_tool = 'ping' if index % 2 == 0 else 'ping6'
        require(row.get('arguments') == ['vrf', 'exec', 'vveth0', family_tool,
                '-c', '10', '-i', '0.1', '-w', '5', expected_addresses[index]] and
                row.get('returncode') == expected_status[index] and row.get('native_clock_reads', 0) > 0 and
                row.get('stderr') == '', 'changed original VLAN ping arguments/result or missing native clock')
        if expected_status[index]:
            require('0 received' in row.get('stdout', ''), 'original VLAN baseline ping unexpectedly received a reply')
        else:
            require('10 received' in row.get('stdout', ''), 'original VLAN action ping did not receive all original replies')
        require(row.get('finished_monotonic_ns', 0) >= row.get('started_monotonic_ns', 0),
                'invalid original VLAN ping monotonic interval')
        bridge = row.get('bridge_state', {})
        links, ports = bridge.get('link', []), bridge.get('port', [])
        require(len(links) == len(ports) == 1 and links[0].get('ifname') == 'br0' and
                links[0].get('linkinfo', {}).get('info_data', {}).get('vlan_filtering') == 1 and
                ports[0].get('ifname') == 'veth1' and ports[0].get('master') == 'br0' and
                ports[0].get('linkinfo', {}).get('info_slave_kind') == 'bridge',
                'original VLAN ping did not use the pinned Linux VLAN-filtering bridge')
        require(bridge.get('port_vlans_veth1') and bridge.get('port_vlans_veth2') and
                bridge.get('host_vlans') is not None,
                'missing original native VLAN membership snapshot')
        for key, name in (('port_vlans_veth1', 'veth1'), ('port_vlans_veth2', 'veth2')):
            ports = bridge[key]
            require(len(ports) == 1 and ports[0].get('ifname') == name and
                    {item.get('vlan') for item in ports[0].get('vlans', [])} >= {1, 65, 85},
                    f'original VLAN bridge membership missing VID 65/85 on {name}')
        host_vlans = {item.get('ifname'): item for item in bridge['host_vlans']}
        require(set(host_vlans) == {'veth0.85', 'veth3.65'} and
                host_vlans['veth0.85'].get('link') == 'veth0' and
                host_vlans['veth0.85'].get('linkinfo', {}).get('info_data', {}).get('id') == 85 and
                host_vlans['veth0.85'].get('linkinfo', {}).get('info_slave_kind') == 'vrf' and
                host_vlans['veth0.85'].get('linkinfo', {}).get('info_slave_data', {}).get('table') == 1 and
                host_vlans['veth3.65'].get('link') == 'veth3' and
                host_vlans['veth3.65'].get('linkinfo', {}).get('info_data', {}).get('id') == 65 and
                host_vlans['veth3.65'].get('linkinfo', {}).get('info_slave_kind') == 'vrf' and
                host_vlans['veth3.65'].get('linkinfo', {}).get('info_slave_data', {}).get('table') == 2,
                'original VLAN subinterfaces were not assigned to their native Linux VRFs')
        expected_host_addresses = (
            ('host_addresses_veth0_85', {'192.0.2.17', '2001:db8:2::1'}),
            ('host_addresses_veth3_65', {'192.0.2.18', '2001:db8:2::2'}))
        for key, expected in expected_host_addresses:
            rows = bridge.get(key, [])
            actual = {address['local'] for row in rows for address in row.get('addr_info', [])
                      if address.get('scope') == 'global'}
            require(len(rows) == 1 and actual == expected,
                    f'original VLAN subinterface address set changed for {key}')
        require(row.get('vrf', {}).get('ifname') == 'vveth0' and
                row.get('vrf', {}).get('linkinfo', {}).get('info_data', {}).get('table') == 1,
                'original ping did not execute in native VRF table 1')

    phases = [
        ('ingress', 'add', 'veth1', 65, {}),
        ('ingress', 'add', 'veth2', 85, {'veth1:ingress': 65}),
        ('ingress', 'del', 'veth2', 85, {'veth1:ingress': 65, 'veth2:ingress': 85}),
        ('ingress', 'del', 'veth1', 65, {'veth1:ingress': 65}),
        ('egress', 'add', 'veth1', 85, {}),
        ('egress', 'add', 'veth2', 65, {'veth1:egress': 85}),
        ('egress', 'del', 'veth2', 65, {'veth1:egress': 85, 'veth2:egress': 65}),
        ('egress', 'del', 'veth1', 85, {'veth1:egress': 85})]
    tc_rows = [row for row in commands if row.get('tool') == 'tc' and
               row.get('arguments', [])[:2] in (['filter', 'add'], ['filter', 'del'])]
    require(len(tc_rows) == 8, 'original VLAN script did not install/delete exactly four action rules')
    qdiscs = [row['arguments'] for row in commands if row.get('tool') == 'tc' and
              row.get('arguments', [])[:2] == ['qdisc', 'add'] or
              row.get('tool') == 'tc' and row.get('arguments', [])[:2] == ['qdisc', 'del']]
    require(qdiscs == [
        ['qdisc', 'add', 'dev', 'veth1', 'clsact'],
        ['qdisc', 'add', 'dev', 'veth2', 'clsact'],
        ['qdisc', 'del', 'dev', 'veth2', 'clsact'],
        ['qdisc', 'del', 'dev', 'veth1', 'clsact']],
        'original VLAN clsact setup/teardown order changed')
    command_positions = {id(row): index for index, row in enumerate(commands)}
    ping_positions = [command_positions[id(row)] for row in pings]
    rule_positions = [command_positions[id(row)] for row in tc_rows]
    require(ping_positions[0] < ping_positions[1] < rule_positions[0] < rule_positions[1] <
            ping_positions[2] < ping_positions[3] < rule_positions[2] < rule_positions[3] <
            ping_positions[4] < ping_positions[5] < rule_positions[4] < rule_positions[5] <
            ping_positions[6] < ping_positions[7] < rule_positions[6] < rule_positions[7],
            'original VLAN negative/action/positive/cleanup phases were reordered')
    for row, phase in zip(tc_rows, phases):
        mode, operation, device, vid, before_expected = phase
        words = row['arguments']
        require(row.get('returncode') == 0 and words == ['filter', operation, 'dev', device, mode,
                'protocol', 'all', 'pref', '1', 'handle', '1', 'flower'] +
                (['action', 'vlan', 'modify', 'id', str(vid)] if operation == 'add' else []),
                'original VLAN tc command/rule order or expected error changed')
        require(row.get('finished_monotonic_ns', 0) >= row.get('started_monotonic_ns', 0),
                'invalid original VLAN tc action time bracket')
        before, after = row.get('vlan_modify_before'), row.get('vlan_modify_after')
        require(before and after and before.get('finished_monotonic_ns', 0) <= row['started_monotonic_ns'] and
                after.get('started_monotonic_ns', 0) >= row['finished_monotonic_ns'],
                'native VLAN action snapshot does not bracket original tc command')
        _partial_rules(before, mode, before_expected)
        if operation == 'add':
            _partial_rules(after, mode, {**before_expected, f'{device}:{mode}': vid})
        else:
            after_expected = dict(before_expected)
            del after_expected[f'{device}:{mode}']
            _partial_rules(after, mode, after_expected)

    for i, row in enumerate(pings):
        mode = 'ingress' if i < 4 else 'egress'
        before, after = row.get('vlan_modify_before'), row.get('vlan_modify_after')
        require(before and after and before.get('finished_monotonic_ns', 0) <= row['started_monotonic_ns'] and
                after.get('started_monotonic_ns', 0) >= row['finished_monotonic_ns'],
                'native VLAN action counters do not bracket original ping')
        if i % 4 < 2:
            _empty(before); _empty(after)
        else:
            before_stats, after_stats = _rules(before, mode), _rules(after, mode)
            require(all(after_stats[key]['packets'] > before_stats[key]['packets'] for key in before_stats),
                    'native VLAN action counters did not increase for original successful traffic')

    observer_process = report.get('vlan_packet_observer_process', {})
    require(observer_process.get('returncode') == 0 and not observer_process.get('stderr'),
            'native VLAN packet observer did not terminate cleanly')
    _validate_observer(report, pings)
    _validate_action_prefixes(pings, report['vlan_packet_observer']['frames'])
    missing = report.get('missing_backend_control', {})
    require(missing.get('returncode') not in (None, 0) and 'SKIP:' not in missing.get('stdout', '') and
            'Failed to create netif' in missing.get('stdout', '') and
            'No such file or directory' in missing.get('stderr', ''),
            'missing-native-backend control was a skip or host fallback')
    native, stats = report.get('native_fixture', {}), report.get('stats', {})
    require(native.get('netlinks', 0) > 0 and native.get('raw_sockets', 0) >= 4 and
            native.get('bridge_packet_sockets') == 4 and native.get('live') == 0 and
            stats.get('outstanding') == 0 and stats.get('worker_exit_code') == 0 and
            stats.get('control_eof') is True and stats.get('shutdown_timed_out') is False,
            'native Linux VLAN fixture did not close all sockets/resources')
    remaining = report.get('cleanup_state', {}).get('links', [])
    must_be_gone = {'br0', 'vveth0', 'vveth3', 'veth0.85', 'veth3.65'}
    require(not any(row.get('ifname') in must_be_gone for row in remaining),
            'original VLAN bridge, VRF, or VLAN subinterface leaked after cleanup')
    base_veths = {row.get('ifname'): row for row in remaining if row.get('ifname') in
                  {'veth0', 'veth1', 'veth2', 'veth3'}}
    require(set(base_veths) == {'veth0', 'veth1', 'veth2', 'veth3'} and
            all('UP' not in row.get('flags', []) and not row.get('master') for row in base_veths.values()),
            'original base veth cleanup did not leave only the expected unmastered down links')
    test_addresses = {'192.0.2.1', '192.0.2.2', '192.0.2.17', '192.0.2.18',
                      '2001:db8:1::1', '2001:db8:1::2', '2001:db8:2::1', '2001:db8:2::2'}
    for row in report.get('cleanup_state', {}).get('addresses', []):
        require(not test_addresses.intersection({item.get('local') for item in row.get('addr_info', [])}),
                'original VLAN test addresses leaked after cleanup')
    for family in ('ipv4_routes', 'ipv6_routes'):
        for route in report.get('cleanup_state', {}).get(family, []):
            require(route.get('dev') not in {'veth0', 'veth1', 'veth2', 'veth3', 'veth0.85', 'veth3.65'} and
                    route.get('table') not in (1, 2, '1', '2'),
                    'original VLAN test route/VRF table leaked after cleanup')
    require(not any(row.get('ifname') == 'br0' for row in report.get('cleanup_state', {}).get('fdb', [])) and
            all(not row.get('mdb') for row in report.get('cleanup_state', {}).get('mdb', [])),
            'original VLAN bridge MDB/FDB state leaked after cleanup')
    require(report.get('cleanup_state', {}).get('ipv4', '').strip() == '0' and
            report.get('cleanup_state', {}).get('ipv6', '').strip() == '0',
            'native forwarding/sysctl state leaked after original VLAN test')
