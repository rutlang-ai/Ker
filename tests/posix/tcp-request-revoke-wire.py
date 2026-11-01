#!/usr/bin/env python3
"""Exercise private TCP request revocation against original Linux over TAP."""
import argparse
import errno
import importlib.util
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time
import select
from types import SimpleNamespace


def checksum16(data):
	if len(data) & 1:
		data += b'\0'
	total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
	total = (total & 0xffff) + (total >> 16)
	total = (total & 0xffff) + (total >> 16)
	return (~total) & 0xffff


def require(value, message):
	if not value:
		raise RuntimeError(message)


def wait_state(prefix, expected, process, timeout=15):
	path = Path(str(prefix) + '.state')
	deadline = time.monotonic() + timeout
	while time.monotonic() < deadline:
		if process.poll() is not None:
			out, err = process.communicate()
			raise RuntimeError(f'request-revoke client exited early: rc={process.returncode}; '
				f'stdout={out!r}; stderr={err!r}')
		if path.exists():
			value = path.read_text().strip()
			if value.startswith(expected):
				return value
		time.sleep(0.01)
	raise RuntimeError(f'timed out waiting for {expected}; state={path.read_text() if path.exists() else None}')


def request_ack(host_syn, server_synack):
	options = b''
	def timestamp(options):
		index = 0
		while index < len(options):
			kind = options[index]
			if kind == 0:
				break
			if kind == 1:
				index += 1
				continue
			if index + 2 > len(options):
				break
			length = options[index + 1]
			if length < 2 or index + length > len(options):
				break
			if kind == 8 and length == 10:
				return struct.unpack_from('!II', options, index + 2)
			index += length
		return None
	server_ts = timestamp(server_synack['options'])
	client_ts = timestamp(host_syn['options'])
	if server_ts and client_ts:
		options = b'\x01\x01\x08\x0a' + struct.pack('!II',
			(client_ts[0] + 1) & 0xffffffff, server_ts[0])
	source = socket.inet_aton(host_syn['src'])
	destination = socket.inet_aton(host_syn['dst'])
	tcp = bytearray(struct.pack('!HHIIBBHHH', host_syn['sport'], host_syn['dport'],
		(host_syn['seq'] + 1) & 0xffffffff, (server_synack['seq'] + 1) & 0xffffffff,
		((20 + len(options)) // 4) << 4, 0x10, 65535, 0, 0) + options)
	pseudo = source + destination + b'\0\x06' + struct.pack('!H', len(tcp))
	struct.pack_into('!H', tcp, 16, checksum16(pseudo + tcp))
	ip = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp),
		0, 0x4000, 64, socket.IPPROTO_TCP, 0, source, destination))
	struct.pack_into('!H', ip, 10, checksum16(ip))
	return host_syn['eth_dst'] + host_syn['eth_src'] + b'\x08\x00' + ip + tcp


def wait_handshake_packets(capture, parse, port, source_port, process, timeout=12):
	host_syn = server_synack = None
	deadline = time.monotonic() + timeout
	while time.monotonic() < deadline and (host_syn is None or server_synack is None):
		if process.poll() is not None:
			out, err = process.communicate()
			raise RuntimeError(f'request-revoke client exited before packet capture: '
				f'rc={process.returncode}; stdout={out!r}; stderr={err!r}')
		try:
			frame, _ = capture.recvfrom(65535)
		except TimeoutError:
			continue
		packet = parse(frame)
		if not packet:
			continue
		if packet['src'] == '198.18.0.1' and packet['dst'] == '198.18.0.2' and \
			packet['dport'] == port and packet['sport'] == source_port and packet['flags'] & 0x02:
			host_syn = packet
		if packet['src'] == '198.18.0.2' and packet['dst'] == '198.18.0.1' and \
			packet['sport'] == port and packet['dport'] == source_port and packet['flags'] & 0x12 == 0x12:
			server_synack = packet
	require(host_syn is not None and server_synack is not None,
		f'missing original TCP SYN/SYN-ACK: SYN={host_syn} SYNACK={server_synack}')
	return host_syn, server_synack


def run_probe(args, eal, root, native):
	request_source = Path(__file__).with_name('native-ff-owner-requests.py')
	request_spec = importlib.util.spec_from_file_location('ker_native_ff_owner_requests', request_source)
	request_module = importlib.util.module_from_spec(request_spec)
	request_spec.loader.exec_module(request_module)
	table = f'ker_revoke_{os.getpid()}'
	prefix = root / 'request-revoke-control'
	capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
	client_one = client_two = peer6 = peer7 = raw6 = raw7 = process = None
	thread6 = thread7 = None
	table_created = False
	try:
		capture.bind(('kerhost', 0))
		capture.settimeout(0.25)
		subprocess.run(['ip', '-6', 'addr', 'add', '2001:db8::1/64', 'dev', 'kerhost', 'nodad'], check=True)
		native.census_nft('add', 'table', 'inet', table)
		table_created = True
		native.census_nft('add', 'chain', 'inet', table, 'output', '{', 'type', 'filter',
			'hook', 'output', 'priority', 'filter;', 'policy', 'accept;', '}')
		command = [sys.executable, str(args.launcher), '--library', str(args.library), '--io-worker',
			str(args.worker), '--address', '198.18.0.2/24', '--address6', '2001:db8::2/64',
			'--port', 'net_tap0',
			'--eal', eal, '--stats', str(root / 'stats.json'), '--', str(args.client)]
		environment = os.environ | {'PYTHONDONTWRITEBYTECODE': '1',
			'RUNTIME_DIRECTORY': str(root), 'KER_C14_REVOKE_CONTROL': str(prefix)}
		process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
			stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, text=True)
		ready = wait_state(prefix, 'READY', process)
		port = int(ready.split('port=', 1)[1].split()[0])
		port6 = int(ready.split('port6=', 1)[1].split()[0])
		native.census_nft('add', 'rule', 'inet', table, 'output', 'oifname', 'kerhost',
			'ip', 'saddr', '198.18.0.1', 'ip', 'daddr', '198.18.0.2', 'tcp',
			'dport', str(port), 'tcp', 'flags', '&',
			'(fin', '|', 'syn', '|', 'rst', '|', 'ack)', '==', 'ack', 'counter', 'drop')
		native.census_nft('add', 'rule', 'inet', table, 'output', 'oifname', 'kerhost',
			'ip6', 'saddr', '2001:db8::1', 'ip6', 'daddr', '2001:db8::2',
			'tcp', 'dport', str(port6), 'tcp', 'flags', '&',
			'(fin', '|', 'syn', '|', 'rst', '|', 'ack)', '==', 'ack', 'counter', 'drop')
		client_one = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		client_one.bind(('198.18.0.1', 0))
		client_one.setblocking(False)
		result = client_one.connect_ex(('198.18.0.2', port))
		require(result in (0, errno.EINPROGRESS, errno.EALREADY),
			f'host connect did not enter SYN_SENT: {result}')
		host_syn, server_synack = wait_handshake_packets(capture,
			native.ipv4_tcp_frame, port, client_one.getsockname()[1], process)
		deadline = time.monotonic() + 5
		chain = ''
		while time.monotonic() < deadline:
			chain = native.census_nft('list', 'chain', 'inet', table, 'output')
			match = __import__('re').search(r'counter packets (\d+)', chain)
			if match and int(match.group(1)) > 0:
				break
			time.sleep(0.02)
		require(match and int(match.group(1)) > 0,
			f'host did not drop its real third-handshake ACK: {chain!r}')
		Path(str(prefix) + '.command').write_text('REVOKE\n')
		require(wait_state(prefix, 'REVOKED', process).startswith('REVOKED'),
			'original Linux did not confirm exact half-open request revocation')
		capture.send(request_ack(host_syn, server_synack))
		reset_seen = False
		deadline = time.monotonic() + 4
		while time.monotonic() < deadline and not reset_seen:
			try:
				frame, _ = capture.recvfrom(65535)
			except TimeoutError:
				continue
			packet = native.ipv4_tcp_frame(frame)
			if packet and packet['src'] == '198.18.0.2' and packet['dst'] == '198.18.0.1' and \
				packet['sport'] == port and packet['dport'] == host_syn['sport'] and \
				packet['flags'] & 0x04:
				reset_seen = True
		require(reset_seen, 'late ACK for revoked request did not receive original Linux RST')
		client_one.close()
		client_one = None

		# The host considers connect() complete once it sends the third ACK,
		# even though nft drops it. Capture Linux's request identity before a
		# real host data+ACK packet promotes the request.
		chain = native.census_nft('list', 'chain', 'inet', table, 'output')
		baseline_match = __import__('re').search(r'counter packets (\d+)', chain)
		require(baseline_match, f'missing ACK-drop counter before ACK-win flow: {chain!r}')
		baseline_drops = int(baseline_match.group(1))
		client_two = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		client_two.bind(('198.18.0.1', 0))
		client_two.settimeout(10)
		client_two.connect(('198.18.0.2', port))
		wait_handshake_packets(capture, native.ipv4_tcp_frame, port,
			client_two.getsockname()[1], process)
		deadline = time.monotonic() + 5
		while time.monotonic() < deadline:
			chain = native.census_nft('list', 'chain', 'inet', table, 'output')
			current_match = __import__('re').search(r'counter packets (\d+)', chain)
			if current_match and int(current_match.group(1)) > baseline_drops:
				break
			time.sleep(0.02)
		require(current_match and int(current_match.group(1)) > baseline_drops,
			f'host third ACK was not held before request capture: {chain!r}')
		Path(str(prefix) + '.command').write_text('ACKWIN_CAPTURE\n')
		wait_state(prefix, 'ACKWIN_REQUEST_CAPTURED', process)
		native.census_nft('flush', 'chain', 'inet', table, 'output')
		client_two.sendall(b'hello')
		data_seen = False
		deadline = time.monotonic() + 4
		while time.monotonic() < deadline and not data_seen:
			try:
				frame, _ = capture.recvfrom(65535)
			except TimeoutError:
				continue
			packet = native.ipv4_tcp_frame(frame)
			if packet and packet['src'] == '198.18.0.1' and packet['dst'] == '198.18.0.2' and \
				packet['sport'] == client_two.getsockname()[1] and packet['dport'] == port and \
				packet['payload'] == b'hello' and packet['flags'] & 0x10:
				data_seen = True
		require(data_seen, 'real host data+ACK packet was not observed after releasing the drop rule')
		Path(str(prefix) + '.command').write_text('ACKWIN_PROMOTE\n')
		wait_state(prefix, 'ACKWIN_ACCEPTED', process)
		Path(str(prefix) + '.command').write_text('ACKWIN_READ\n')
		readable, _, _ = select.select([client_two], [], [], 8)
		require(readable, 'promoted child did not reply to live TCP data')
		require(client_two.recv(5) == b'world', 'promoted child did not carry live TCP data')
		wait_state(prefix, 'ACKWIN_CHILD_SURVIVED', process)
		Path(str(prefix) + '.command').write_text('START_IPV6\n')
		wait_state(prefix, 'IPV6_READY', process)
		native.census_nft('add', 'rule', 'inet', table, 'output', 'oifname', 'kerhost',
			'ip6', 'saddr', '2001:db8::1', 'ip6', 'daddr', '2001:db8::2',
			'tcp', 'dport', str(port6), 'tcp', 'flags', '&',
			'(fin', '|', 'syn', '|', 'rst', '|', 'ack)', '==', 'ack', 'counter', 'drop')
		peer6, syn6, synack6, thread6, _, _ = request_module.connect_and_capture(
			capture, port6, family=socket.AF_INET6, server_address='2001:db8::2',
			host_address='2001:db8::1')
		chain6 = native.census_nft('list', 'chain', 'inet', table, 'output')
		match6 = __import__('re').search(r'ip6.*counter packets (\d+)', chain6)
		require(match6 and int(match6.group(1)) > 0,
			f'IPv6 third-handshake ACK was not dropped: {chain6!r}')
		Path(str(prefix) + '.command').write_text('REVOKE6\n')
		wait_state(prefix, 'IPV6_REVOKED', process)
		raw6 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
		raw6.bind(('kerhost', 0))
		request_module.inject_ack(raw6, syn6['src_mac'], syn6, synack6)
		reset6 = False
		deadline = time.monotonic() + 4
		while time.monotonic() < deadline and not reset6:
			try:
				frame, _ = capture.recvfrom(65535)
			except TimeoutError:
				continue
			packet6 = request_module.packet(frame)
			if packet6 and packet6['src'] == '2001:db8::2' and \
				packet6['dst'] == '2001:db8::1' and packet6['sport'] == port6 and \
				packet6['dport'] == syn6['sport'] and packet6['flags'] & 0x04:
				reset6 = True
		require(reset6, 'late IPv6 ACK for revoked request did not receive original Linux RST')
		Path(str(prefix) + '.command').write_text('V6_DONE\n')
		peer6.close(); raw6.close(); thread6.join(5)
		require(not thread6.is_alive(), 'IPv6 late-ACK client did not finish')
		wait_state(prefix, 'IPV6_REBOUND', process)
		chain6 = native.census_nft('list', 'chain', 'inet', table, 'output')
		baseline6 = __import__('re').search(r'ip6.*counter packets (\d+)', chain6)
		require(baseline6, f'missing IPv6 ACK-drop counter before listener reuse: {chain6!r}')
		baseline6_count = int(baseline6.group(1))
		peer7, syn7, synack7, thread7, failures7, pending7 = request_module.connect_and_capture(
			capture, port6, family=socket.AF_INET6, server_address='2001:db8::2',
			host_address='2001:db8::1')
		chain6 = native.census_nft('list', 'chain', 'inet', table, 'output')
		current6 = __import__('re').search(r'ip6.*counter packets (\d+)', chain6)
		require(current6 and int(current6.group(1)) > baseline6_count,
			f'rebound IPv6 listener did not hold the fresh request: {chain6!r}')
		Path(str(prefix) + '.command').write_text('REVOKE6_STALE\n')
		wait_state(prefix, 'IPV6_REBOUND_REVOKED', process)
		raw7 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
		raw7.bind(('kerhost', 0))
		request_module.inject_ack(raw7, syn7['src_mac'], syn7, synack7)
		reset7 = False
		deadline = time.monotonic() + 4
		while time.monotonic() < deadline and not reset7:
			try:
				frame, _ = capture.recvfrom(65535)
			except TimeoutError:
				continue
			packet7 = request_module.packet(frame)
			if packet7 and packet7['src'] == '2001:db8::2' and \
				packet7['dst'] == '2001:db8::1' and packet7['sport'] == port6 and \
				packet7['dport'] == syn7['sport'] and packet7['flags'] & 0x04:
				reset7 = True
		require(reset7, 'stale request identity affected fresh IPv6 request')
		Path(str(prefix) + '.command').write_text('V6_DONE2\n')
		peer7.close(); raw7.close(); thread7.join(5)
		require(not thread7.is_alive(), 'rebound IPv6 client did not finish')
		output, errors = process.communicate(timeout=15)
		require(process.returncode == 0,
			f'private revoke runtime failed: stdout={output!r}; stderr={errors!r}')
		print(f'C14_REQUEST_REVOKE_WIRE_OK revoked=true late_ack_rst={reset_seen} '
			f'wrong_mark_cookie_listener_rejected=true ack_win_child_usable=true ipv6_revoked=true '
			f'nft_dropped_ack_packets={match.group(1)}')
	finally:
		for peer in (client_one, client_two, peer6, peer7):
			if peer is not None:
				peer.close()
		if process is not None and process.poll() is None:
			process.kill()
			process.wait()
		for raw in (raw6, raw7):
			if raw is not None:
				raw.close()
		for thread in (thread6, thread7):
			if thread is not None and thread.is_alive():
				thread.join(1)
		if table_created:
			try:
				native.census_nft('delete', 'table', 'inet', table)
			except BaseException:
				pass
		capture.close()


def invoke_inside(args):
	native_path = Path(__file__).with_name('native-socket-broker.py')
	spec = importlib.util.spec_from_file_location('ker_native_socket_broker', native_path)
	native = importlib.util.module_from_spec(spec)
	spec.loader.exec_module(native)
	native.run_payload_snapshot_wire_probe = lambda runner_args, eal, root: run_probe(
		runner_args, eal, root, native)
	runner_args = SimpleNamespace(dpdk_plugin_dir=args.dpdk_plugin_dir,
		launcher=args.launcher, library=args.library, worker=args.worker, client=args.client,
		member_census_runtime_test=args.client, member_census_test_library=args.library)
	return native.inside(runner_args)


def main():
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument('--launcher', type=Path, required=True)
	parser.add_argument('--library', type=Path, required=True)
	parser.add_argument('--worker', type=Path, required=True)
	parser.add_argument('--dpdk-plugin-dir', type=Path, required=True)
	parser.add_argument('--client', type=Path, required=True)
	parser.add_argument('--inside', action='store_true')
	args = parser.parse_args()
	if args.inside:
		return invoke_inside(args)
	command = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()), '--inside']
	for option in ('launcher', 'library', 'worker', 'dpdk_plugin_dir', 'client'):
		command += ['--' + option.replace('_', '-'), str(getattr(args, option).resolve())]
	return subprocess.run(command).returncode


if __name__ == '__main__':
	try:
		raise SystemExit(main())
	except Exception as error:
		print(f'tcp request revoke wire fixture failed: {error}', file=sys.stderr)
		raise SystemExit(1)
