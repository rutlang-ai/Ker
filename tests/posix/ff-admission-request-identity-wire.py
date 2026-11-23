#!/usr/bin/env python3
"""Verify exact original-Linux request identity and revocation over TAP."""
import argparse
import errno
import importlib.util
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time
from types import SimpleNamespace


def require(value, message):
	if not value:
		raise RuntimeError(message)


def checksum16(data):
	if len(data) & 1:
		data += b'\0'
	total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
	total = (total & 0xffff) + (total >> 16)
	total = (total & 0xffff) + (total >> 16)
	return (~total) & 0xffff


def make_ack(host_syn, server_synack):
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


def wait_state(prefix, expected, process, timeout=15):
	path = Path(str(prefix) + '.state')
	deadline = time.monotonic() + timeout
	while time.monotonic() < deadline:
		if process.poll() is not None:
			out, err = process.communicate()
			raise RuntimeError(f'identity client exited early: rc={process.returncode}; '
				f'stdout={out!r}; stderr={err!r}')
		if path.exists():
			value = path.read_text().strip()
			if value.startswith(expected):
				return value
		time.sleep(0.01)
	raise RuntimeError(f'timed out waiting for {expected}; state={path.read_text() if path.exists() else None}')


def wait_handshake(capture, parse, port, source_port, process, timeout=10):
	host_syn = server_synack = None
	deadline = time.monotonic() + timeout
	while time.monotonic() < deadline and (host_syn is None or server_synack is None):
		if process.poll() is not None:
			out, err = process.communicate()
			raise RuntimeError(f'identity client exited before capture: rc={process.returncode}; '
				f'stdout={out!r}; stderr={err!r}')
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
	require(host_syn and server_synack, f'missing SYN/SYN-ACK: SYN={host_syn}, SYNACK={server_synack}')
	return host_syn, server_synack


def run_probe(args, eal, root, native):
	table = f'ker_identity_{os.getpid()}'
	prefix = root / 'request-identity-control'
	capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
	client = process = None
	table_created = False
	try:
		capture.bind(('kerhost', 0))
		capture.settimeout(0.25)
		native.census_nft('add', 'table', 'inet', table)
		table_created = True
		native.census_nft('add', 'chain', 'inet', table, 'output', '{', 'type', 'filter',
			'hook', 'output', 'priority', 'filter;', 'policy', 'accept;', '}')
		command = [sys.executable, str(args.launcher), '--library', str(args.library),
			'--io-worker', str(args.worker), '--address', '198.18.0.2/24',
			'--port', 'net_tap0', '--eal', eal, '--stats', str(root / 'stats.json'),
			'--', str(args.client)]
		environment = os.environ | {'PYTHONDONTWRITEBYTECODE': '1',
			'RUNTIME_DIRECTORY': str(root), 'KER_C15_IDENTITY_CONTROL': str(prefix)}
		process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
			stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, text=True)
		ready = wait_state(prefix, 'READY', process)
		port = int(ready.split('port=', 1)[1].split()[0])
		native.census_nft('add', 'rule', 'inet', table, 'output', 'oifname', 'kerhost',
			'ip', 'saddr', '198.18.0.1', 'ip', 'daddr', '198.18.0.2', 'tcp',
			'dport', str(port), 'tcp', 'flags', '&',
			'(fin', '|', 'syn', '|', 'rst', '|', 'ack)', '==', 'ack', 'counter', 'drop')
		client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		client.bind(('198.18.0.1', 0))
		client.setblocking(False)
		result = client.connect_ex(('198.18.0.2', port))
		require(result in (0, errno.EINPROGRESS, errno.EALREADY),
			f'host connect did not enter SYN_SENT: {result}')
		host_syn, server_synack = wait_handshake(capture, native.ipv4_tcp_frame,
			port, client.getsockname()[1], process)
		deadline = time.monotonic() + 5
		while time.monotonic() < deadline:
			chain = native.census_nft('list', 'chain', 'inet', table, 'output')
			match = __import__('re').search(r'counter packets (\d+)', chain)
			if match and int(match.group(1)) > 0:
				break
			time.sleep(0.02)
		require(match and int(match.group(1)) > 0,
			f'third-handshake ACK was not held: {chain!r}')
		Path(str(prefix) + '.command').write_text(f'LOOKUP {client.getsockname()[1]}\n')
		wait_state(prefix, 'IDENTITY_REVOKED', process)
		capture.send(make_ack(host_syn, server_synack))
		reset = False
		deadline = time.monotonic() + 4
		while time.monotonic() < deadline and not reset:
			try:
				frame, _ = capture.recvfrom(65535)
			except TimeoutError:
				continue
			packet = native.ipv4_tcp_frame(frame)
			if packet and packet['src'] == '198.18.0.2' and packet['dst'] == '198.18.0.1' and \
				packet['sport'] == port and packet['dport'] == host_syn['sport'] and packet['flags'] & 0x04:
				reset = True
		require(reset, 'late ACK for identity-revoked request did not receive original Linux RST')
		Path(str(prefix) + '.command').write_text('CANCEL\n')
		wait_state(prefix, 'CANCELLED', process)
		Path(str(prefix) + '.command').write_text('CLOSE_DONE\n')
		out, err = process.communicate(timeout=15)
		require(process.returncode == 0, f'identity client failed: stdout={out!r}; stderr={err!r}')
		require(Path(str(prefix) + '.state').read_text().strip() == 'CLOSED_FD_REJECTED',
			'app listener close/reuse was not rejected')
		print(f'FF_ADMISSION_REQUEST_IDENTITY_WIRE_OK exact_request_revoke=true '
			f'late_ack_rst={reset} listener_close_estale=true cancellation_closes_fd=true '
			f'dropped_ack_packets={match.group(1)}')
	finally:
		if client is not None:
			client.close()
		if process is not None and process.poll() is None:
			process.kill()
			process.wait()
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
		print(f'FF admission identity wire fixture failed: {error}', file=sys.stderr)
		raise SystemExit(1)
