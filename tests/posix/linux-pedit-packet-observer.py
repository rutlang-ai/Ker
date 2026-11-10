#!/usr/bin/env python3
"""Passive native AF_PACKET capture for the unchanged imported Linux PEDIT test."""
import argparse
import errno
import ctypes
import json
import os
from pathlib import Path
import select
import struct
import socket
import sys
import time

SOL_PACKET = 263
PACKET_OUTGOING = getattr(socket, 'PACKET_OUTGOING', 4)
PACKET_STATISTICS = 6
SO_TIMESTAMPNS = getattr(socket, 'SO_TIMESTAMPNS', 35)
ETH_P_ALL = getattr(socket, 'ETH_P_ALL', 3)


class Timeval(ctypes.Structure):
    _fields_ = [('tv_sec', ctypes.c_long), ('tv_usec', ctypes.c_long)]



class Iovec(ctypes.Structure):
    _fields_ = [('base', ctypes.c_void_p), ('length', ctypes.c_size_t)]


class Msghdr(ctypes.Structure):
    _fields_ = [('name', ctypes.c_void_p), ('namelen', ctypes.c_uint),
                ('iov', ctypes.POINTER(Iovec)), ('iovlen', ctypes.c_size_t),
                ('control', ctypes.c_void_p), ('controllen', ctypes.c_size_t),
                ('flags', ctypes.c_int)]


class SockaddrLL(ctypes.Structure):
    _fields_ = [('family', ctypes.c_ushort), ('protocol', ctypes.c_ushort),
                ('ifindex', ctypes.c_int), ('hatype', ctypes.c_ushort),
                ('pkttype', ctypes.c_ubyte), ('halen', ctypes.c_ubyte),
                ('address', ctypes.c_ubyte * 8)]


def recv_native_packet(libc, descriptor):
    data = ctypes.create_string_buffer(65535)
    address = SockaddrLL()
    control = ctypes.create_string_buffer(256)
    vector = Iovec(ctypes.cast(data, ctypes.c_void_p), len(data))
    message = Msghdr(ctypes.cast(ctypes.byref(address), ctypes.c_void_p), ctypes.sizeof(address),
                     ctypes.pointer(vector), 1, ctypes.cast(control, ctypes.c_void_p), len(control), 0)
    libc.recvmsg.argtypes = [ctypes.c_int, ctypes.POINTER(Msghdr), ctypes.c_int]
    libc.recvmsg.restype = ctypes.c_ssize_t
    received = libc.recvmsg(descriptor, ctypes.byref(message), socket.MSG_DONTWAIT)
    if received < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    ancillary = []
    offset = 0
    control_bytes = bytes(control.raw[:message.controllen])
    while offset < message.controllen:
        if message.controllen - offset < 16:
            raise RuntimeError('truncated native packet cmsg header')
        cmsg_length = int.from_bytes(control_bytes[offset:offset + 8], sys.byteorder)
        level = int.from_bytes(control_bytes[offset + 8:offset + 12], sys.byteorder, signed=True)
        kind = int.from_bytes(control_bytes[offset + 12:offset + 16], sys.byteorder, signed=True)
        if cmsg_length < 16 or offset + cmsg_length > message.controllen:
            raise RuntimeError(f'invalid native packet cmsg length={cmsg_length}')
        ancillary.append((level, kind, control_bytes[offset + 16:offset + cmsg_length]))
        offset += (cmsg_length + 7) & ~7
    return data.raw[:received], ancillary, message.flags, address, message.namelen

def native_clock_pair(libc):
    value = Timeval()
    libc.gettimeofday.argtypes = [ctypes.POINTER(Timeval), ctypes.c_void_p]
    libc.gettimeofday.restype = ctypes.c_int
    before = time.monotonic_ns()
    if libc.gettimeofday(ctypes.byref(value), None) < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    after = time.monotonic_ns()
    if value.tv_usec < 0 or value.tv_usec >= 1_000_000:
        raise RuntimeError(f'invalid native gettimeofday usec={value.tv_usec}')
    return {'native_realtime_ns': value.tv_sec * 1_000_000_000 + value.tv_usec * 1_000,
            'host_monotonic_before_ns': before, 'host_monotonic_after_ns': after}


def write_record(stream, value):
    stream.write(json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n')
    stream.flush()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--ready', type=Path, required=True)
    parser.add_argument('--stop', type=Path, required=True)
    parser.add_argument('--ready-timeout', type=float, default=15.0)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.ready.unlink(missing_ok=True)
    sockets = []
    link_down_events = []
    poller = select.poll()
    definitions = [('veth1', 'ingress')]
    deadline = time.monotonic() + args.ready_timeout
    stage = 'wait interfaces'
    try:
        while time.monotonic() < deadline:
            indices = {}
            for name, direction in definitions:
                try:
                    indices[name] = socket.if_nametoindex(name)
                except OSError:
                    indices[name] = 0
            if all(indices.values()):
                break
            time.sleep(0.002)
        else:
            raise RuntimeError('PEDIT observer interfaces did not appear before deadline')

        stage = 'create native veth1 AF_PACKET socket'
        libc = ctypes.CDLL(None, use_errno=True)
        libc.socket.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int]
        libc.socket.restype = ctypes.c_int
        channel = os.environ.get('KER_MPTCP_SOCKET_CHANNEL')
        if not channel:
            raise RuntimeError('missing native packet socket channel')
        os.environ['KER_MPTCP_SOCKET_CHANNEL'] = str(args.output.parent / 'missing-packet-socket-channel')
        failed_descriptor = libc.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        missing_errno = ctypes.get_errno()
        if failed_descriptor >= 0:
            libc.close(failed_descriptor)
            os.environ['KER_MPTCP_SOCKET_CHANNEL'] = channel
            raise RuntimeError('AF_PACKET socket fell back to host when native channel was absent')
        if missing_errno != errno.ENOENT:
            os.environ['KER_MPTCP_SOCKET_CHANNEL'] = channel
            raise RuntimeError(f'missing native channel returned unexpected errno={missing_errno}')
        os.environ['KER_MPTCP_SOCKET_CHANNEL'] = channel
        descriptor = libc.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        if descriptor < 0:
            raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
        packet = socket.socket(fileno=descriptor)
        stage = 'enable native SO_TIMESTAMPNS'
        packet.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)
        stage = 'bind veth1 AF_PACKET socket'
        packet.bind(('veth1', ETH_P_ALL))
        native_address = SockaddrLL()
        native_length = ctypes.c_uint(ctypes.sizeof(native_address))
        libc.getsockname.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint)]
        libc.getsockname.restype = ctypes.c_int
        if libc.getsockname(descriptor, ctypes.byref(native_address), ctypes.byref(native_length)) < 0:
            raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
        bound = packet.getsockname()
        if (native_address.family != socket.AF_PACKET or native_address.protocol != socket.htons(ETH_P_ALL) or
                native_address.ifindex != indices['veth1']):
            raise RuntimeError(f'AF_PACKET native bind mismatch: family={native_address.family} '
                               f'protocol={native_address.protocol} ifindex={native_address.ifindex} '
                               f'python={bound!r}')
        sockets.append((packet, 'veth1', 'ingress', indices['veth1']))
        poller.register(packet.fileno(), select.POLLIN | select.POLLERR | select.POLLHUP)

        stage = 'sample native realtime clock'
        clock_pairs = [native_clock_pair(libc)]
        stage = 'write ready record'
        ready = {
            'type': 'ready',
            'monotonic_ns': time.monotonic_ns(),
            'backend_control': {'missing_channel_errno': missing_errno, 'host_fallback': False},
            'socket': {'family': 'AF_PACKET', 'type': 'SOCK_RAW', 'protocol': ETH_P_ALL,
                       'ifindex': indices['veth1'], 'getsockname': [*bound[:4], bound[4].hex() if len(bound) > 4 else ''],
                       'native_family': native_address.family, 'native_protocol': native_address.protocol,
                       'native_ifindex': native_address.ifindex},
            'interfaces': [{'name': name, 'direction': direction, 'ifindex': indices[name]}
                           for name, direction in definitions],
            'clock_pairs': clock_pairs,
        }
        args.ready.write_text(json.dumps(ready, sort_keys=True) + '\n')
        stage = 'capture frames'
        with args.output.open('w', buffering=1) as stream:
            write_record(stream, ready)
            while not args.stop.exists():
                stage = 'poll packet sockets'
                events = poller.poll(20)
                for fd, flags in events:
                    if flags & select.POLLHUP:
                        raise RuntimeError(f'AF_PACKET observer poll hangup flags={flags}')
                    entry = next(x for x in sockets if x[0].fileno() == fd)
                    packet, _, _, _ = entry
                    while True:
                        stage = 'receive veth1 frame with native timestamp'
                        host_before_ns = time.monotonic_ns()
                        try:
                            frame, ancillary, message_flags, address, address_length = recv_native_packet(libc, descriptor)
                        except BlockingIOError:
                            break
                        except OSError as error:
                            if error.errno == errno.ENETDOWN:
                                link_down_events.append(time.monotonic_ns())
                                time.sleep(0.01)
                                break
                            raise
                        host_after_ns = time.monotonic_ns()
                        if message_flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
                            raise RuntimeError(f'AF_PACKET receive truncated flags={message_flags}')
                        timestamp_ns = None
                        timestamp_count = 0
                        for level, kind, data in ancillary:
                            if level == socket.SOL_SOCKET and kind == SO_TIMESTAMPNS:
                                if len(data) != struct.calcsize('@ll'):
                                    raise RuntimeError(f'unexpected native SO_TIMESTAMPNS size={len(data)}')
                                sec, nsec = struct.unpack('@ll', data)
                                if nsec < 0 or nsec >= 1_000_000_000:
                                    raise RuntimeError(f'invalid native SO_TIMESTAMPNS nsec={nsec}')
                                timestamp_ns = sec * 1_000_000_000 + nsec
                                timestamp_count += 1
                        if timestamp_count != 1:
                            raise RuntimeError(f'expected exactly one native SO_TIMESTAMPNS cmsg, got {timestamp_count}')
                        if not frame:
                            continue
                        if address_length < ctypes.sizeof(SockaddrLL):
                            raise RuntimeError(f'native AF_PACKET sender address too short: {address_length}')
                        if address.family != socket.AF_PACKET or address.ifindex != indices['veth1']:
                            raise RuntimeError(f'AF_PACKET frame arrived from unexpected native address family={address.family} ifindex={address.ifindex}')
                        packet_type = address.pkttype
                        interface = 'veth1'
                        direction = 'outgoing' if packet_type == PACKET_OUTGOING else 'ingress'
                        index = address.ifindex
                        stage = f'write {interface} frame'
                        pair = native_clock_pair(libc)
                        clock_pairs.append(pair)
                        write_record(stream, {
                            'type': 'frame', 'monotonic_ns': time.monotonic_ns(),
                            'host_recv_before_ns': host_before_ns, 'host_recv_after_ns': host_after_ns,
                            'native_timestamp_ns': timestamp_ns,
                            'native_clock_pair': pair,
                            'ifname': interface, 'ifindex': index, 'direction': direction,
                            'pkttype': packet_type,
                            'protocol': socket.ntohs(address.protocol), 'native_ifindex': address.ifindex,
                            'native_hatype': address.hatype, 'native_address_hex': bytes(address.address[:address.halen]).hex(),
                            'frame_length': len(frame), 'frame_hex': frame.hex(),
                        })
        clock_pairs.append(native_clock_pair(libc))
        stats = packet.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8)
        if len(stats) != 8:
            raise RuntimeError(f'unexpected PACKET_STATISTICS length={len(stats)}')
        args.output.with_suffix(args.output.suffix + '.stats.json').write_text(
            json.dumps({'packets': int.from_bytes(stats[:4], sys.byteorder),
                        'drops': int.from_bytes(stats[4:], sys.byteorder),
                        'monotonic_ns': time.monotonic_ns(), 'clock_pairs': clock_pairs,
                        'link_down_events': link_down_events}, sort_keys=True) + '\n')
        return 0
    except Exception as error:
        args.ready.write_text(json.dumps({'type': 'error', 'error': str(error)}) + '\n')
        print(f'PEDIT packet observer failed during {stage}: {error}', file=sys.stderr)
        return 1
    finally:
        for packet, _, _, _ in sockets:
            try:
                poller.unregister(packet.fileno())
            except Exception:
                pass
            packet.close()


if __name__ == '__main__':
    sys.exit(main())
