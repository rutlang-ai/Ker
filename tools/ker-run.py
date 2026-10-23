#!/usr/bin/env python3
"""Run a POSIX application against imported Linux, with DPDK Ethernet I/O."""
import argparse
import configparser
import ipaddress
import json
import os
import re
from pathlib import Path
import selectors
import shlex
import signal
import socket
import subprocess
import sys
import time


class Interrupted(Exception):
    def __init__(self, signum):
        self.signum = signum


def interrupted(signum, _frame):
    raise Interrupted(signum)


def resolve_exit_code(exit_code, app_returncode, infrastructure_failure, preserve_signal):
    if infrastructure_failure and not preserve_signal:
        return 125
    if app_returncode is not None and app_returncode < 0 and preserve_signal:
        return 128 - app_returncode
    return exit_code if exit_code >= 0 else 128 - exit_code


# CMake substitutes the relative library path for the installed launcher.
LIB_FROM_BIN = '@KER_POSIX_LIB_FROM_BIN@'
if LIB_FROM_BIN.startswith('@'):
    LIB_FROM_BIN = '../lib64'


TCP_ECN = {'off': 0, 'passive': 2, 'on': 1}


def vip_addresses(text):
    return [ipaddress.IPv4Interface(item.strip()) for item in text.split(',')] if text.strip() else []


def vip_addresses6(text):
    return [ipaddress.IPv6Interface(item.strip()) for item in text.split(',')] if text.strip() else []


def vlan_setting(text):
    tag, separator, addresses = text.partition('=')
    if not separator or not tag.isascii() or not tag.isdecimal() or not 1 <= int(tag) <= 4094:
        raise ValueError('VLAN requires ID=IP/PREFIX[,IP/PREFIX...] with ID 1..4094')
    values = [ipaddress.ip_interface(item.strip()) for item in addresses.split(',')] if addresses.strip() else []
    if not 1 <= len(values) <= 8:
        raise ValueError('VLAN requires 1..8 IPv4/IPv6 addresses')
    if any(value.ip.is_unspecified or value.ip.is_multicast for value in values):
        raise ValueError('VLAN addresses must be unicast and nonzero')
    if any(value.version == 6 and ('%' in str(value) or value.ip.is_loopback or
            value.ip.ipv4_mapped is not None) for value in values):
        raise ValueError('VLAN IPv6 addresses must be unscoped native unicast addresses')
    if len({value.ip for value in values}) != len(values):
        raise ValueError('duplicate VLAN address')
    return int(tag), values


def vlan_gateway(text):
    tag, separator, address = text.partition('=')
    if not separator or not tag.isascii() or not tag.isdecimal() or not 1 <= int(tag) <= 4094:
        raise ValueError('VLAN gateway requires ID=IPv4 with ID 1..4094')
    gateway = ipaddress.IPv4Address(address)
    if gateway.is_unspecified or gateway.is_multicast or gateway.is_loopback or int(gateway) == 0xffffffff:
        raise ValueError('VLAN gateway requires a nonzero unicast IPv4 address')
    return int(tag), gateway


def vlan_gateway6(text):
    tag, separator, address = text.partition('=')
    if not separator or not tag.isascii() or not tag.isdecimal() or not 1 <= int(tag) <= 4094:
        raise ValueError('VLAN gateway requires ID=IPv6 with ID 1..4094')
    gateway = ipaddress.IPv6Address(address)
    if ('%' in address or gateway.is_unspecified or gateway.is_multicast or
            gateway.is_loopback or gateway.ipv4_mapped is not None):
        raise ValueError('VLAN gateway requires an unscoped native unicast IPv6 address')
    return int(tag), gateway


def sysctl_setting(text):
    key, separator, value = text.partition('=')
    key, value = key.strip(), value.strip()
    if not separator or len(key) > 128 or not re.fullmatch(r'net(?:\.[A-Za-z0-9_-]+){2,}', key):
        raise ValueError('sysctl requires a dotted Linux net.* key and =VALUE')
    if not value or len(value.encode('utf-8')) > 256 or any(c in value for c in '\r\n\0'):
        raise ValueError('sysctl value must be 1..256 UTF-8 bytes without line breaks or NUL')
    return key, value


def ephemeral_ports(text):
    if not re.fullmatch(r'[0-9]{1,5}-[0-9]{1,5}', text):
        raise ValueError('ephemeral ports require FIRST-LAST in 1024..65535')
    first, last = map(int, text.split('-'))
    if not 1024 <= first <= last <= 65535:
        raise ValueError('ephemeral ports require 1024 <= FIRST <= LAST <= 65535')
    return first, last


def base_virtaddr(text):
    # Leave room for DPDK's upward 16 MiB alignment in its uint64 parser.
    if not re.fullmatch(r'0[xX][0-9a-fA-F]+', text):
        raise ValueError('base virtual address must be hexadecimal with a 0x prefix')
    value = int(text, 16)
    if not 1 <= value <= (1 << 64) - (1 << 24):
        raise ValueError('base virtual address must be positive and leave room for 16 MiB alignment in uint64')
    return value


CONFIG_DEFAULTS = dict(nb_bond=0, bonds=(), nb_vdev=0, vdevs=(), base_virtaddr=None, file_prefix=None, eal_log_level=None, memory_mb=None, no_huge=None, tx_delay_us=0, numa=True, memory_channels=None, idle_sleep_us=1000, promiscuous=None, vlan_gateways=(), vlan_gateways6=(), ephemeral_ports=None, vlans=(), mbuf_mode='large', sysctls=(), gateway6=None, address6=None, vip_addresses6=(), vip_addresses=(), lcore_mask=None, tcp_ecn=None, mtu=1500, max_mtu=9000, address=None, gateway=None, port=None, eal=None,
    all_multicast=False, log_dir=None, log_level=None, pcap_dir=None,
    pcap_snaplen=65535, pcap_max_bytes=16 * 1024 * 1024, pcap_nsec=False,
    shutdown_timeout_ms=5000, stats=None, command=[])


class _LastOccurrenceDict(dict):
    """Preserve the final source position of repeated ConfigParser options."""

    def __setitem__(self, key, value):
        # ConfigParser stores parsed option values as lists, then joins them to
        # strings in _join_multiline_values. Move only during source parsing so
        # final-value order changes without mutating the mapping while joining.
        if isinstance(value, list) and key in self:
            del self[key]
        super().__setitem__(key, value)


CONFIG_SCHEMA = {
    'network': {'vip_addresses6': ('vip_addresses6', vip_addresses6), 'ephemeral_ports': ('ephemeral_ports', ephemeral_ports), 'gateway6': ('gateway6', ipaddress.IPv6Address), 'address6': ('address6', ipaddress.IPv6Interface), 'vip_addresses': ('vip_addresses', vip_addresses), 'tcp_ecn': ('tcp_ecn', str),
                'mtu': ('mtu', int), 'max_mtu': ('max_mtu', int), 'address': ('address', ipaddress.IPv4Interface),
                'gateway': ('gateway', ipaddress.IPv4Address)},
    'dpdk': {'nb_bond': ('nb_bond', int), 'nb_vdev': ('nb_vdev', int), 'base_virtaddr': ('base_virtaddr', base_virtaddr), 'file_prefix': ('file_prefix', str), 'log_level': ('eal_log_level', int), 'memory': ('memory_mb', int), 'no_huge': ('no_huge', bool), 'pkt_tx_delay': ('tx_delay_us', int), 'numa_on': ('numa', bool), 'channel': ('memory_channels', int), 'mbuf_mode': ('mbuf_mode', str), 'lcore_mask': ('lcore_mask', str), 'port': ('port', str), 'eal': ('eal', str),
             'idle_sleep': ('idle_sleep_us', int), 'all_multicast': ('all_multicast', bool), 'promiscuous': ('promiscuous', bool)},
    'logging': {'directory': ('log_dir', Path), 'level': ('log_level', int)},
    'capture': {'directory': ('pcap_dir', Path), 'snaplen': ('pcap_snaplen', int),
                'max_bytes': ('pcap_max_bytes', int), 'nsec': ('pcap_nsec', bool)},
    'runtime': {'shutdown_timeout_ms': ('shutdown_timeout_ms', int), 'stats': ('stats', Path)},
}


def virtual_devices(ini, directory):
    """Map F-Stack's indexed virtio-user sections to original DPDK options."""
    count = ini.getint('dpdk', 'nb_vdev', fallback=0)
    if not 0 <= count <= 16:
        raise ValueError('[dpdk] nb_vdev must be in 0..16')
    sections = [name for name in ini.sections() if name.startswith('vdev')]
    if sections and not count:
        raise ValueError('vdev sections require [dpdk] nb_vdev first')
    if set(sections) != {f'vdev{i}' for i in range(count)}:
        raise ValueError('vdev sections must exactly match indices 0..nb_vdev-1')
    devices = []
    allowed = {'iface', 'path', 'queues', 'queue_size', 'mac', 'cq'}
    for index in range(count):
        section = 'vdev' + str(index)
        entries = dict(ini.items(section, raw=True))
        if set(entries) - allowed or not entries.get('path'):
            raise ValueError(f'[{section}] requires path and only supports iface/path/queues/queue_size/mac/cq')
        device = {'name': 'net_virtio_user' + str(index)}
        for key, default in (('queues', 1), ('queue_size', 256), ('cq', 0)):
            device[key] = int(entries.get(key, default))
        if not 1 <= device['queues'] <= 128 or device['cq'] not in (0, 1):
            raise ValueError(f'[{section}] queues must be in 1..128 and cq must be 0 or 1')
        size = device['queue_size']
        if not 64 <= size <= 32768 or size & (size - 1):
            raise ValueError(f'[{section}] queue_size must be a power of two in 64..32768')
        if device['queues'] > 1 and not device['cq']:
            raise ValueError(f'[{section}] multiple queue pairs require cq=1')
        for key in ('iface', 'path', 'mac'):
            if key not in entries:
                continue
            value = entries[key]
            if not value or any(character in value for character in ',\x00\r\n'):
                raise ValueError(f'[{section}] invalid {key}')
            if key == 'iface' and not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', value):
                raise ValueError(f'[{section}] iface must be a Linux interface name of at most 15 characters')
            if key == 'mac':
                if not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', value):
                    raise ValueError(f'[{section}] invalid MAC address')
                octets = bytes.fromhex(value.replace(':', ''))
                if octets[0] & 1 or not any(octets):
                    raise ValueError(f'[{section}] MAC must be nonzero unicast')
                value = value.lower()
            if key == 'path':
                path = Path(value)
                value = str(path if path.is_absolute() else directory / path)
                if len(os.fsencode(value)) >= 4096:
                    raise ValueError(f'[{section}] path exceeds PATH_MAX')
            device[key] = value
        devices.append(device)
    return tuple(devices)


def virtual_device_argument(device):
    return '--vdev=' + device['name'] + ''.join(
        ',' + key + '=' + str(device[key]) for key in
        ('iface', 'path', 'queues', 'queue_size', 'mac', 'cq') if key in device)


def bond_devices(ini):
    count = ini.getint('dpdk', 'nb_bond', fallback=0)
    if count not in (0, 1):
        raise ValueError('[dpdk] nb_bond supports 0 or 1 selected bond')
    sections = [name for name in ini.sections() if name.startswith('bond')]
    if sections and not count:
        raise ValueError('bond sections require [dpdk] nb_bond first')
    if set(sections) != ({'bond0'} if count else set()):
        raise ValueError('bond section must be [bond0] for nb_bond=1')
    if not count:
        return ()
    fields = dict(ini.items('bond0', raw=True))
    allowed = {'mode', 'slave', 'primary', 'socket_id', 'mac', 'xmit_policy',
               'lsc_poll_period_ms', 'up_delay', 'down_delay'}
    if set(fields) - allowed or not {'mode', 'slave'} <= set(fields):
        raise ValueError('[bond0] requires mode/slave and only supports known bond options')
    bond = {'name': 'net_bonding0', 'mode': int(fields['mode']),
            'slave': fields['slave'].split(','), 'socket_id': int(fields.get('socket_id', 0)),
            'xmit_policy': fields.get('xmit_policy', 'l2')}
    if bond['mode'] not in range(7) or not -1 <= bond['socket_id'] <= 127:
        raise ValueError('[bond0] invalid mode or socket_id')
    if not 1 <= len(bond['slave']) <= 16 or len(set(bond['slave'])) != len(bond['slave']):
        raise ValueError('[bond0] requires 1..16 distinct members')
    if any(not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', member) for member in bond['slave']):
        raise ValueError('[bond0] invalid member name/port')
    if bond['name'] in bond['slave']:
        raise ValueError('[bond0] cannot contain itself')
    if 'primary' in fields:
        if fields['primary'] not in bond['slave']:
            raise ValueError('[bond0] primary must name a listed member')
        bond['primary'] = fields['primary']
    if bond['xmit_policy'] not in ('l2', 'l23', 'l34'):
        raise ValueError('[bond0] invalid xmit_policy')
    if 'mac' in fields:
        mac = fields['mac']
        if not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', mac):
            raise ValueError('[bond0] invalid MAC')
        octets = bytes.fromhex(mac.replace(':', ''))
        if octets[0] & 1 or not any(octets):
            raise ValueError('[bond0] MAC must be nonzero unicast')
        bond['mac'] = mac.lower()
    for key, default in (('lsc_poll_period_ms', 100), ('up_delay', 0), ('down_delay', 0)):
        value = int(fields.get(key, default))
        if not (1 if key == 'lsc_poll_period_ms' else 0) <= value <= 2147483647:
            raise ValueError('[bond0] invalid timing: ' + key)
        bond[key] = value
    return (bond,)


def bond_device_argument(bond):
    return ('--vdev=' + bond['name'] + ',mode=' + str(bond['mode']) +
            ''.join(',member=' + member for member in bond['slave']) +
            ''.join(',' + key + '=' + str(bond[key]) for key in
                    ('primary', 'socket_id', 'mac', 'xmit_policy') if key in bond))


def read_configuration(stream, directory, source='<stream>'):
    # Match F-Stack's repeated-key precedence: convert only the final value.
    # A repeated section continues the same section; unknown names remain errors.
    ini = configparser.ConfigParser(interpolation=None, inline_comment_prefixes=(';',),
        empty_lines_in_values=False, strict=False, dict_type=_LastOccurrenceDict)
    ini.optionxform = str
    ini.read_string(stream.read().removeprefix('\ufeff'), source=str(source))
    if ini.defaults():
        raise ValueError('DEFAULT inheritance is unsupported')
    devices = virtual_devices(ini, directory)
    values = {'vdevs': devices} if devices or ini.has_option('dpdk', 'nb_vdev') else {}
    bonds = bond_devices(ini)
    if bonds or ini.has_option('dpdk', 'nb_bond'):
        values['bonds'] = bonds
    for section in ini.sections():
        if section.startswith(('vdev', 'bond')):
            continue
        if section.startswith('vlan.'):
            if 'addresses' not in ini[section] or set(ini[section]) - {'addresses', 'gateway', 'gateway6'}:
                raise ValueError('VLAN section requires addresses and optional gateway/gateway6')
            if 'gateway' in ini[section]:
                values.setdefault('vlan_gateways', []).append(vlan_gateway(section[5:] + '=' + ini[section]['gateway']))
            if 'gateway6' in ini[section]:
                values.setdefault('vlan_gateways6', []).append(vlan_gateway6(section[5:] + '=' + ini[section]['gateway6']))
            values.setdefault('vlans', []).append(vlan_setting(section[5:] + '=' + ini[section]['addresses']))
            continue
        if section == 'sysctl':
            values['sysctls'] = [sysctl_setting(name + '=' + text)
                                 for name, text in ini.items(section, raw=True)]
            continue
        if section not in CONFIG_SCHEMA:
            raise ValueError(f'unknown section [{section}]')
        for name, text in ini.items(section, raw=True):
            if name not in CONFIG_SCHEMA[section]:
                raise ValueError(f'unknown option [{section}] {name}')
            field, convert = CONFIG_SCHEMA[section][name]
            try:
                value = ini.getboolean(section, name) if convert is bool else convert(text)
            except ValueError as error:
                raise ValueError(f'[{section}] {name}: {error}') from error
            if convert is Path and not value.is_absolute():
                value = directory / value
            values[field] = value
    return values


def load_configuration(path):
    path = path.resolve()
    with path.open(encoding='utf-8') as stream:
        return read_configuration(stream, path.parent, path)


def parse_arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, argument_default=argparse.SUPPRESS)
    parser.add_argument('--config', type=Path, default=None, help='Ker INI configuration; explicit CLI options take precedence')
    parser.add_argument('--address', type=ipaddress.IPv4Interface)
    parser.add_argument('--address6', type=ipaddress.IPv6Interface,
        help='additional native IPv6 address/prefix; enables multicast reception for neighbor discovery')
    parser.add_argument('--vip-address', dest='vip_addresses', action='append', type=ipaddress.IPv4Interface,
        help='additional IPv4 address/prefix; repeat up to 32 times; replaces INI vip_addresses')
    parser.add_argument('--vip-address6', dest='vip_addresses6', action='append', type=ipaddress.IPv6Interface,
        help='additional IPv6 address/prefix; requires --address6; repeat up to 32 times; replaces INI vip_addresses6')
    parser.add_argument('--vlan', dest='vlans', action='append', type=vlan_setting,
        help='802.1Q ID=IP/PREFIX[,IP/PREFIX...]; repeat up to 16 VLANs; replaces INI VLAN sections')
    parser.add_argument('--vlan-gateway', dest='vlan_gateways', action='append', type=vlan_gateway,
        help='ID=IPv4 default gateway on a configured VLAN; replaces INI VLAN IPv4 gateways; one default allowed')
    parser.add_argument('--vlan-gateway6', dest='vlan_gateways6', action='append', type=vlan_gateway6,
        help='ID=IPv6 default gateway on a configured VLAN; replaces INI VLAN gateways; one default allowed')
    parser.add_argument('--mbuf-mode', choices=('large', 'scatter'), help='DPDK packet storage; scatter uses chained standard-size mbufs')
    parser.add_argument('--mtu', type=int, help='native and DPDK interface MTU, 1280..9000 (default 1500)')
    parser.add_argument('--max-mtu', type=int, help='startup/live MTU ceiling and large-buffer capacity, 1280..9000 (default 9000)')
    parser.add_argument('--tcp-ecn', choices=tuple(TCP_ECN),
        help='off, passive acceptance, or active/passive ECN; default preserves Linux policy')
    parser.add_argument('--sysctl', dest='sysctls', action='append', type=sysctl_setting,
        help='Linux net.* KEY=VALUE; repeat up to 32 keys; overrides matching INI [sysctl] keys')
    parser.add_argument('--gateway6', type=ipaddress.IPv6Address,
        help='native IPv6 default gateway on this interface; requires --address6')
    parser.add_argument('--ephemeral-ports', type=ephemeral_ports, metavar='FIRST-LAST',
        help='native Linux automatic local port range for TCP/UDP and IPv4/IPv6')
    parser.add_argument('--gateway', type=ipaddress.IPv4Address)
    parser.add_argument('--numa', action=argparse.BooleanOptionalAction,
        help='use worker lcore NUMA socket for pool/queues (default); --no-numa uses socket 0')
    parser.add_argument('--base-virtaddr', type=base_virtaddr, help='hexadecimal EAL virtual-address hint (0x...); DPDK rounds up to 16 MiB and may choose another address')
    parser.add_argument('--file-prefix', help='EAL runtime namespace: 1..64 ASCII letters/digits/dot/underscore/hyphen, starting with a letter or digit')
    parser.add_argument('--eal-log-level', type=int, choices=range(1, 9),
        help='EAL startup global log level, 1..8; dpdk.log_level; later --log-level still overrides after initialization')
    parser.add_argument('--memory-mb', type=int, help='initial EAL memory in MiB, 1..2147483647; actual allocation remains subject to host capacity')
    huge_policy = parser.add_mutually_exclusive_group()
    huge_policy.add_argument('--no-huge', action='store_true', help='use regular pages for DPDK EAL memory')
    huge_policy.add_argument('--hugepages', dest='no_huge', action='store_false', help='require EAL hugepage mode; needs configured host hugepages')
    parser.add_argument('--memory-channels', type=int,
        help='DPDK memory channels per socket, 1..2147483647; omitted preserves EAL policy; conflicts with EAL -n/--memory-channels')
    parser.add_argument('--lcore-mask', help='nonzero hexadecimal DPDK lcore mask; conflicts with EAL -c/-l/--lcores')
    parser.add_argument('--port', help='DPDK ethdev name')
    parser.add_argument('--tx-delay-us', type=int, help='Ethernet TX batch wait, 0..100 microseconds; default 0 sends without intentional delay')
    parser.add_argument('--idle-sleep-us', type=int,
        help='worker idle wait in microseconds, 0..100000 (default 1000; 0 polls without sleeping)')
    parser.add_argument('--promiscuous', action=argparse.BooleanOptionalAction,
        help='enable or disable PMD promiscuous reception; omitted preserves the PMD state')
    parser.add_argument('--all-multicast', action=argparse.BooleanOptionalAction,
        help='receive all Ethernet multicast frames for native Linux membership filtering')
    parser.add_argument('--log-dir', type=Path, help='existing directory for append-only DPDK worker logs')
    parser.add_argument('--log-level', type=int, choices=range(1, 9), help='DPDK global and ker.io level (1=emergency, 8=debug); overrides EAL level after startup')
    parser.add_argument('--pcap-dir', type=Path, help='existing private capture directory; rotates ten files per direction')
    parser.add_argument('--pcap-snaplen', type=int)
    parser.add_argument('--pcap-max-bytes', type=int)
    parser.add_argument('--pcap-nsec', action=argparse.BooleanOptionalAction, help='write nanosecond PCAP timestamps')
    parser.add_argument('--eal', help='DPDK EAL arguments, parsed without a shell')
    parser.add_argument('--library', type=Path, default=Path(__file__).resolve().parent / LIB_FROM_BIN / 'libker-posix.so')
    parser.add_argument('--io-worker', type=Path, default=Path(__file__).resolve().parent / 'ker-io-worker')
    parser.add_argument('--shutdown-timeout-ms', type=int)
    parser.add_argument('--stats', type=Path, help='write Ethernet I/O counters at shutdown')
    parser.add_argument('command', nargs=argparse.REMAINDER)
    supplied = parser.parse_args(argv)
    values = dict(CONFIG_DEFAULTS)
    if supplied.config is not None:
        try:
            values.update(load_configuration(supplied.config))
        except (OSError, UnicodeError, configparser.Error, ValueError) as error:
            parser.error(f'{supplied.config}: {error}')
    sysctls = dict(values['sysctls'])
    for key, value in getattr(supplied, 'sysctls', ()):
        sysctls.pop(key, None)
        sysctls[key] = value
    values.update(vars(supplied))
    values['sysctls'] = sysctls
    args = argparse.Namespace(**values)
    missing = [name for name in ('address', 'port', 'eal') if getattr(args, name) is None]
    if missing:
        parser.error('required via CLI or --config: ' + ', '.join('--' + name for name in missing))
    if args.command[:1] == ['--']:
        args.command.pop(0)
    if not args.command:
        parser.error('an application command is required after --')
    if args.ephemeral_ports is not None:
        key = 'net.ipv4.ip_local_port_range'
        if key in args.sysctls:
            parser.error('--ephemeral-ports conflicts with sysctl ' + key)
        unprivileged_port_key = 'net.ipv4.ip_unprivileged_port_start'
        if unprivileged_port_key in args.sysctls:
            parser.error('--ephemeral-ports conflicts with sysctl ' + unprivileged_port_key +
                '; use generic sysctl settings for explicit kernel ordering')
        args.sysctls[key] = ' '.join(map(str, args.ephemeral_ports))
    if len(args.sysctls) > 32:
        parser.error('--sysctl supports at most 32 distinct keys')
    if args.tcp_ecn is not None and 'net.ipv4.tcp_ecn' in args.sysctls:
        parser.error('--tcp-ecn conflicts with sysctl net.ipv4.tcp_ecn')
    if args.address6 is not None and ('%' in str(args.address6) or
            args.address6.ip.is_unspecified or args.address6.ip.is_multicast or
            args.address6.ip.is_loopback or args.address6.ip.ipv4_mapped is not None):
        parser.error('--address6 requires an unscoped native unicast IPv6 interface address')
    args.vip_addresses6 = list(args.vip_addresses6)
    if args.vip_addresses6 and args.address6 is None:
        parser.error('--vip-address6 requires --address6')
    if len(args.vip_addresses6) > 32:
        parser.error('--vip-address6 supports at most 32 additional addresses')
    for value in args.vip_addresses6:
        if ('%' in str(value) or value.ip.is_unspecified or value.ip.is_multicast or
                value.ip.is_loopback or value.ip.ipv4_mapped is not None):
            parser.error('--vip-address6 requires unscoped native unicast IPv6 interface addresses')
    addresses6 = ([args.address6.ip] if args.address6 is not None else []) + [value.ip for value in args.vip_addresses6]
    if len(set(addresses6)) != len(addresses6):
        parser.error('--vip-address6 must not duplicate the primary or another VIP address')
    if args.gateway6 is not None and (args.address6 is None or '%' in str(args.gateway6) or
            args.gateway6.is_unspecified or args.gateway6.is_multicast or args.gateway6.is_loopback or
            args.gateway6.ipv4_mapped is not None):
        parser.error('--gateway6 requires --address6 and an unscoped unicast IPv6 gateway')
    args.vip_addresses = list(args.vip_addresses)
    if len(args.vip_addresses) > 32:
        parser.error('--vip-address supports at most 32 additional addresses')
    addresses = [args.address.ip] + [value.ip for value in args.vip_addresses]
    if len(set(addresses)) != len(addresses):
        parser.error('--vip-address must not duplicate the primary or another VIP address')
    if len(args.vlans) > 16 or len({tag for tag, _ in args.vlans}) != len(args.vlans):
        parser.error('--vlan requires at most 16 unique VLAN IDs')
    vlan_ips = [value.ip for _, entries in args.vlans for value in entries]
    all_ips = addresses + addresses6 + vlan_ips
    if len(set(all_ips)) != len(all_ips):
        parser.error('--vlan addresses must not duplicate primary, VIP, or other VLAN addresses')
    if len(args.vlan_gateways) > 1 or (args.vlan_gateways and args.gateway is not None):
        parser.error('only one IPv4 default gateway is supported across parent and VLAN interfaces')
    for tag, gateway in args.vlan_gateways:
        entries = [value for value in dict(args.vlans).get(tag, []) if value.version == 4]
        if not entries:
            parser.error('--vlan-gateway requires IPv4 addresses on the selected VLAN')
        if gateway in all_ips:
            parser.error('--vlan-gateway must not equal a local address')
        if any(value.network.prefixlen < 31 and gateway == value.network.broadcast_address for value in entries):
            parser.error('--vlan-gateway must not be a VLAN subnet broadcast address')
    if len(args.vlan_gateways6) > 1 or (args.vlan_gateways6 and args.gateway6 is not None):
        parser.error('only one IPv6 default gateway is supported across parent and VLAN interfaces')
    for tag, gateway in args.vlan_gateways6:
        entries = dict(args.vlans).get(tag, [])
        if not any(value.version == 6 for value in entries):
            parser.error('--vlan-gateway6 requires IPv6 addresses on the selected VLAN')
        if gateway in all_ips:
            parser.error('--vlan-gateway6 must not equal a local address')
    if not 0 <= args.idle_sleep_us <= 100000:
        parser.error('--idle-sleep-us must be in 0..100000 microseconds')
    if args.mbuf_mode not in ('large', 'scatter'):
        parser.error('--mbuf-mode must be large or scatter')
    if not 1280 <= args.mtu <= 9000:
        parser.error('--mtu must be in 1280..9000')
    if not 1280 <= args.max_mtu <= 9000:
        parser.error('--max-mtu must be in 1280..9000')
    if args.mtu > args.max_mtu:
        parser.error('--mtu must not exceed --max-mtu')
    if args.tcp_ecn is not None and args.tcp_ecn not in TCP_ECN:
        parser.error('--tcp-ecn must be off, passive or on')
    if not 0 <= args.shutdown_timeout_ms <= 60000:
        parser.error("--shutdown-timeout-ms must be in 0..60000")
    if not 1 <= args.pcap_snaplen <= 2147483647 or not 1 <= args.pcap_max_bytes <= 2147483647:
        parser.error('PCAP snaplen and max-bytes must be in 1..2147483647')
    if args.log_level is not None and not 1 <= args.log_level <= 8:
        parser.error('--log-level must be in 1..8')
    try:
        args.eal_args = shlex.split(args.eal)
    except ValueError as error:
        parser.error(f'--eal: {error}')
    try:
        separator = args.eal_args.index('--')
    except ValueError:
        eal_prefix, eal_remainder = list(args.eal_args), []
    else:
        eal_prefix, eal_remainder = args.eal_args[:separator], args.eal_args[separator:]
    raw_eal_options = list(eal_prefix)
    if not 0 <= args.tx_delay_us <= 100:
        parser.error('--tx-delay-us must be in 0..100')
    if args.base_virtaddr is not None:
        if any(token.split('=', 1)[0] == '--base-virtaddr' for token in raw_eal_options):
            parser.error('--base-virtaddr conflicts with EAL --base-virtaddr')
        eal_prefix += ['--base-virtaddr=' + hex(args.base_virtaddr)]
    if args.file_prefix is not None:
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', args.file_prefix):
            parser.error('--file-prefix must be 1..64 ASCII letters/digits/dot/underscore/hyphen, starting with a letter or digit')
        if any(token.split('=', 1)[0] == '--file-prefix' for token in raw_eal_options):
            parser.error('--file-prefix conflicts with EAL --file-prefix')
        eal_prefix += ['--file-prefix=' + args.file_prefix]
    if args.eal_log_level is not None:
        if not 1 <= args.eal_log_level <= 8:
            parser.error('--eal-log-level must be in 1..8')
        raw_global_log_level = False
        index = 0
        while index < len(raw_eal_options):
            token = raw_eal_options[index]
            if token.startswith('--log-level='):
                value = token.split('=', 1)[1]
            elif token == '--log-level':
                value = raw_eal_options[index + 1] if index + 1 < len(raw_eal_options) else ''
                index += 1
            else:
                index += 1
                continue
            if ':' not in value and ',' not in value:
                raw_global_log_level = True
                break
            index += 1
        if raw_global_log_level:
            parser.error('--eal-log-level conflicts with EAL --log-level')
        eal_prefix += ['--log-level=' + str(args.eal_log_level)]
    if args.memory_mb is not None:
        if not 1 <= args.memory_mb <= 2147483647:
            parser.error('--memory-mb must be in 1..2147483647')
        if any(token.startswith('-m') or token.split('=', 1)[0] in
                ('--memory-size', '--numa-mem', '--socket-mem') for token in raw_eal_options):
            parser.error('--memory-mb conflicts with EAL -m/--memory-size/--numa-mem/--socket-mem')
        eal_prefix += ['-m', str(args.memory_mb)]
    if args.no_huge is not None:
        if any(token.split('=', 1)[0] == '--no-huge' for token in raw_eal_options):
            parser.error('typed hugepage policy conflicts with EAL --no-huge')
        if args.no_huge:
            if any(token.split('=', 1)[0] == '--in-memory' for token in raw_eal_options):
                parser.error('--no-huge conflicts with EAL --in-memory')
            eal_prefix.append('--no-huge')
    if args.memory_channels is not None:
        if not 1 <= args.memory_channels <= 2147483647:
            parser.error('--memory-channels must be in 1..2147483647')
        if any(token == '--memory-channels' or token.startswith(('--memory-channels=', '-n'))
                for token in raw_eal_options):
            parser.error('--memory-channels conflicts with EAL -n or --memory-channels')
        if any(token.split('=', 1)[0] in ('--no-shconf', '--in-memory') for token in raw_eal_options):
            parser.error('--memory-channels requires EAL shared configuration; --no-shconf/--in-memory skip channel initialization')
        eal_prefix += ['-n', str(args.memory_channels)]
    if args.lcore_mask is not None:
        mask = args.lcore_mask.strip()
        if not re.fullmatch(r'(?:0[xX])?[0-9a-fA-F]+', mask) or int(mask, 16) == 0:
            parser.error('--lcore-mask must be a nonzero hexadecimal mask')
        # Keep one source of EAL CPU selection. Do not silently override or
        # remove caller-provided CPU mapping, especially --lcores remapping.
        if any(token in ('--lcores', '-c', '-l') or token.startswith(('--lcores=', '-c', '-l'))
                for token in raw_eal_options):
            parser.error('--lcore-mask conflicts with EAL -c, -l or --lcores')
        args.lcore_mask = format(int(mask, 16), 'x')
        eal_prefix += ['-c', args.lcore_mask]
    if args.vdevs:
        if any(token == '--vdev' or token.startswith('--vdev=') for token in raw_eal_options):
            parser.error('typed [vdevN] configuration conflicts with EAL --vdev')
        if not args.bonds and args.port not in {device['name'] for device in args.vdevs}:
            parser.error('--port must select a configured typed net_virtio_userN device')
        eal_prefix += [virtual_device_argument(device) for device in args.vdevs]
    if args.bonds:
        if args.port != args.bonds[0]['name']:
            parser.error('--port must select the configured net_bonding0')
        raw_devices = []
        for index, token in enumerate(raw_eal_options):
            if token.startswith('--vdev='):
                raw_devices.append(token.split('=', 1)[1].split(',', 1)[0])
            elif token == '--vdev' and index + 1 < len(raw_eal_options):
                raw_devices.append(raw_eal_options[index + 1].split(',', 1)[0])
        if any(name.startswith(('net_bonding', 'eth_bond')) for name in raw_devices):
            parser.error('typed bond conflicts with raw EAL bonding device')
        eal_prefix += [bond_device_argument(bond) for bond in args.bonds]
    args.eal_args = eal_prefix + eal_remainder
    return args


def main():
    args = parse_arguments()
    library = args.library.resolve(strict=True)
    worker_path = args.io_worker.resolve(strict=True)
    channel_app, channel_io = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM | socket.SOCK_NONBLOCK)
    mtu_app, mtu_io = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    control_read, control_write = os.pipe2(os.O_CLOEXEC)
    startup_read, startup_write = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
    signal.signal(signal.SIGTERM, interrupted)
    worker = app = None
    exit_code = 125
    stats = None
    info = None
    startup_status = b""
    infrastructure_failure = False
    preserve_signal = False
    try:
        vlan_ipv6 = any(value.version == 6 for _, entries in args.vlans for value in entries)
        multicast_options = ['--all-multicast'] if args.all_multicast or args.address6 is not None or vlan_ipv6 else []
        promiscuous_options = [] if args.promiscuous is None else [
            '--promiscuous' if args.promiscuous else '--no-promiscuous']
        log_options = []
        if args.log_dir is not None:
            log_options += ['--log-dir', str(args.log_dir.resolve())]
        if args.log_level is not None:
            log_options += ['--log-level', str(args.log_level)]
        capture_options = []
        if args.pcap_dir is not None:
            capture_options = ['--pcap-dir', str(args.pcap_dir.resolve()),
                '--pcap-snaplen', str(args.pcap_snaplen), '--pcap-max-bytes', str(args.pcap_max_bytes)]
            if args.pcap_nsec:
                capture_options.append('--pcap-nsec')
        bond_options = []
        if args.bonds:
            bond_options = ['--bond-policy', ','.join(str(args.bonds[0][key]) for key in
                            ('lsc_poll_period_ms', 'up_delay', 'down_delay'))]
        worker = subprocess.Popen([str(worker_path), '--packet-fd', str(channel_io.fileno()),
            '--mtu-fd', str(mtu_io.fileno()), '--max-mtu', str(args.max_mtu), '--control-fd', str(control_read), '--idle-sleep-us', str(args.idle_sleep_us), '--tx-delay-us', str(args.tx_delay_us), '--port', args.port, '--mtu', str(args.mtu), '--mbuf-mode', args.mbuf_mode, '--numa' if args.numa else '--no-numa', *multicast_options, *promiscuous_options, *capture_options, *log_options, *bond_options, '--', *args.eal_args],
            pass_fds=(channel_io.fileno(), mtu_io.fileno(), control_read), stdout=subprocess.PIPE, text=True)
        channel_io.close()
        mtu_io.close()
        os.close(control_read)
        control_read = -1
        with selectors.DefaultSelector() as selector:
            selector.register(worker.stdout, selectors.EVENT_READ)
            if not selector.select(20):
                raise RuntimeError('DPDK worker startup timed out')
            ready = worker.stdout.readline().strip()
        if not ready.startswith('KER_IO_READY '):
            # A worker that fails after EAL initialization can emit its cleanup
            # snapshot as the first line. Preserve it for --stats: communicate()
            # below cannot read this already-consumed line again.
            if ready.startswith('KER_IO_DONE '):
                stats = json.loads(ready.removeprefix('KER_IO_DONE '))
            raise RuntimeError('DPDK worker failed before packet I/O became ready: ' + ready)
        info = json.loads(ready.removeprefix('KER_IO_READY '))
        env = {key: value for key, value in os.environ.items() if not key.startswith(('LKL_', 'KER_PACKET_'))}
        env.update(KER_PRELOAD_LIBRARY=(env.pop('LD_PRELOAD') + ':' if env.get('LD_PRELOAD') else '') + str(library),
            KER_STARTUP_FD=str(startup_write), KER_SHUTDOWN_TIMEOUT_MS=str(args.shutdown_timeout_ms),
            KER_PACKET_CONTROL_FD=str(mtu_app.fileno()), KER_PACKET_MAX_MTU=str(args.max_mtu),
            KER_PACKET_FD=str(channel_app.fileno()), KER_PACKET_MTU=str(args.mtu), LKL_HIJACK_NET_IFTYPE='ker-channel',
            LKL_HIJACK_NET_IP=str(args.address.ip), LKL_HIJACK_NET_NETMASK_LEN=str(args.address.network.prefixlen),
            LKL_HIJACK_NET_MAC=info['mac'], LKL_HIJACK_OFFLOAD='0')
        env.pop('KER_NATIVE_VLANS', None)
        if args.vlans:
            env['KER_NATIVE_VLANS'] = ';'.join(str(tag) + '=' + ','.join(map(str, addresses))
                                               for tag, addresses in args.vlans)
        env.pop('KER_NATIVE_VLAN_GATEWAY', None)
        if args.vlan_gateways:
            tag, gateway = args.vlan_gateways[0]
            env['KER_NATIVE_VLAN_GATEWAY'] = f'{tag}={gateway}'
        env.pop('KER_NATIVE_VLAN_GATEWAY6', None)
        if args.vlan_gateways6:
            tag, gateway = args.vlan_gateways6[0]
            env['KER_NATIVE_VLAN_GATEWAY6'] = f'{tag}={gateway}'
        env.pop('KER_NATIVE_GATEWAY6', None)
        if args.gateway6 is not None:
            env['KER_NATIVE_GATEWAY6'] = str(args.gateway6)
        env.pop('KER_NATIVE_ADDRESS6', None)
        if args.address6 is not None:
            env['KER_NATIVE_ADDRESS6'] = str(args.address6)
        env.pop('KER_NATIVE_VIP_ADDRESSES6', None)
        if args.vip_addresses6:
            env['KER_NATIVE_VIP_ADDRESSES6'] = ','.join(map(str, args.vip_addresses6))
        env.pop('KER_NATIVE_VIP_ADDRESSES', None)
        if args.vip_addresses:
            env['KER_NATIVE_VIP_ADDRESSES'] = ','.join(map(str, args.vip_addresses))
        env.pop('KER_NATIVE_SYSCTLS', None)
        if args.sysctls:
            env['KER_NATIVE_SYSCTLS'] = '\n'.join(key + '=' + value for key, value in args.sysctls.items())
        env.pop('KER_NATIVE_TCP_ECN', None)
        if args.tcp_ecn is not None:
            env['KER_NATIVE_TCP_ECN'] = str(TCP_ECN[args.tcp_ecn])
        if args.gateway:
            env['LKL_HIJACK_NET_GATEWAY'] = str(args.gateway)
        app_guard = worker_path.parent / 'ker-app'
        app = subprocess.Popen([str(app_guard), *args.command], env=env,
            pass_fds=(channel_app.fileno(), mtu_app.fileno(), startup_write))
        channel_app.close()
        mtu_app.close()
        os.close(startup_write)
        startup_write = -1
        with selectors.DefaultSelector() as selector:
            selector.register(startup_read, selectors.EVENT_READ)
            if selector.select(20):
                startup_status = os.read(startup_read, 128)
            if not startup_status.startswith(b'KER_NATIVE_READY\n'):
                raise RuntimeError('application did not initialize the native Linux backend')
        stopping_at = None
        while True:
            try:
                exit_code = app.wait(timeout=0.25)
                if exit_code < 0:
                    preserve_signal = True
                break
            except subprocess.TimeoutExpired:
                try:
                    startup_status += os.read(startup_read, 4096)
                except BlockingIOError:
                    pass
                if b'KER_NATIVE_STOPPING\n' in startup_status:
                    if stopping_at is None:
                        stopping_at = time.monotonic()
                    if time.monotonic() - stopping_at > 5:
                        raise RuntimeError('native kernel teardown timed out')
                elif worker.poll() is not None:
                    raise RuntimeError('DPDK worker stopped while the application was running')
    except (KeyboardInterrupt, Interrupted) as interruption:
        preserve_signal = True
        signum = interruption.signum if isinstance(interruption, Interrupted) else signal.SIGINT
        exit_code = 128 + signum
        if app and app.poll() is None:
            app.send_signal(signum)
            try:
                app.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
    except (OSError, ValueError, RuntimeError) as error:
        print(f'ker-run: {error}', file=sys.stderr)
    finally:
        if app and app.poll() is None:
            app.terminate()
            try:
                app.wait(timeout=5)
            except subprocess.TimeoutExpired:
                app.kill()
                app.wait()
        channel_app.close()
        channel_io.close()
        mtu_app.close()
        mtu_io.close()
        if control_read >= 0:
            os.close(control_read)
        os.close(control_write)
        while True:
            try:
                extra = os.read(startup_read, 1024)
                if not extra:
                    break
                startup_status += extra
            except BlockingIOError:
                break
        os.close(startup_read)
        if app and b'KER_NATIVE_READY\n' in startup_status and b'KER_NATIVE_DONE\n' not in startup_status:
            print('ker-run: native Linux shutdown did not complete', file=sys.stderr)
            infrastructure_failure = True
        if startup_write >= 0:
            os.close(startup_write)
        if worker:
            try:
                output, _ = worker.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                worker.kill()
                output, _ = worker.communicate()
                print('ker-run: DPDK worker shutdown timed out', file=sys.stderr)
                infrastructure_failure = True
            for line in output.splitlines():
                if line.startswith('KER_IO_DONE '):
                    stats = json.loads(line.removeprefix('KER_IO_DONE '))
            if worker.returncode:
                infrastructure_failure = True
            if stats is not None:
                stats['io'] = info
                for line in startup_status.splitlines():
                    if line.startswith(b'KER_NATIVE_STATS '):
                        stats['native'] = json.loads(line.removeprefix(b'KER_NATIVE_STATS '))
            if args.stats and stats:
                args.stats.write_text(json.dumps(stats, indent=2) + '\n')
    return resolve_exit_code(exit_code, app.returncode if app else None,
        infrastructure_failure, preserve_signal)


if __name__ == '__main__':
    sys.exit(main())
