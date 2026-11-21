"""Bounded metadata parser tests using synthetic, never-executed ELF bytes."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import time
import unittest
from unittest import mock


MODULE = Path(__file__).resolve().parents[2] / 'tools/nginx_source_bootstrap_supervisor.py'
SPEC = importlib.util.spec_from_file_location('test_source_bootstrap_supervisor', MODULE)
bootstrap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bootstrap)

SIZES = bootstrap.SOURCE_EXPORT_SIZES
SHDR = struct.Struct('<IIQQQQIIQQ')
SYMBOL = struct.Struct('<IBBHQQ')
HEADER = struct.Struct('<16sHHIQQQIHHHHHH')


def synthetic_elf(*, duplicate=None):
    names = bytearray(b'\0')
    offsets = {}
    for name in SIZES:
        offsets[name] = len(names)
        names.extend(name.encode() + b'\0')
    strings_offset = 64
    symbols_offset = (strings_offset + len(names) + 7) & ~7
    rows = [(0, 0, 0, 0, 0, 0)]
    for index, name in enumerate(SIZES):
        rows.append((offsets[name], 0x11, 0, 1, 0x100000 + index * 16, SIZES[name]))
    if duplicate:
        rows.append((offsets[duplicate], 0x11, 0, 1, 0x100100, SIZES[duplicate]))
    entries = b''.join(SYMBOL.pack(*row) for row in rows)
    table_offset = (symbols_offset + len(entries) + 7) & ~7
    section_count = 4
    header = HEADER.pack(b'\x7fELF\x02\x01\x01' + bytes(9), 2, 62, 1,
        0, 0, table_offset, 0, 64, 0, 0, 64, section_count, 0)
    sections = [
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (0, 8, 3, 0x100000, 0, 0x1000, 0, 0, 16, 0),
        (0, 3, 0, 0, strings_offset, len(names), 0, 0, 1, 0),
        (0, 11, 0, 0, symbols_offset, len(entries), 2, 1, 8, 24),
    ]
    data = bytearray(table_offset + section_count * 64 + 1)
    data[:64] = header
    data[strings_offset:strings_offset + len(names)] = names
    data[symbols_offset:symbols_offset + len(entries)] = entries
    for index, row in enumerate(sections):
        data[table_offset + index * 64:table_offset + (index + 1) * 64] = SHDR.pack(*row)
    data[-1] = ord('Z')  # stable padding for content-mutation tests
    return data, {'strings': strings_offset, 'names_size': len(names),
        'symbols': symbols_offset, 'symbol_rows': len(rows), 'table': table_offset,
        'target': table_offset + 64, 'dynstr': table_offset + 128,
        'dynsym': table_offset + 192, 'padding': len(data) - 1}


class BoundedSourceExports(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'synthetic.elf'
        self.data, self.offset = synthetic_elf()
        self.path.write_bytes(self.data)
        self.fd = os.open(self.path, os.O_RDONLY | os.O_CLOEXEC)
        self.addCleanup(lambda: os.close(self.fd))

    def expected_hash(self, data=None):
        return hashlib.sha256(self.data if data is None else data).digest()

    def parse(self, fd=None, expected=None, deadline=None):
        return bootstrap.bounded_source_exports(self.fd if fd is None else fd,
            self.expected_hash() if expected is None else expected,
            time.monotonic_ns() + 2_000_000_000 if deadline is None else deadline)

    def test_minimal_elf_returns_exact_six_object_exports(self):
        result = self.parse()
        self.assertEqual(result.keys(), SIZES.keys())
        self.assertEqual(result['ngx_ff_reload_shm'], 0x100000)
        self.assertEqual(result['ngx_process_slot'], 0x100050)

    def test_truncated_header_and_table_ranges_reject_without_fd_leak(self):
        before = len(os.listdir('/proc/self/fd'))
        for blob in (b'\x7fELF', self.data[:self.offset['table'] + 64]):
            with self.subTest(size=len(blob)):
                self._parse_blob(blob)
        self.assertEqual(len(os.listdir('/proc/self/fd')), before)

    def test_header_class_endian_machine_and_type_are_rejected(self):
        for label, location, value in (
                ('class', 4, 1), ('endian', 5, 2),
                ('machine', 18, 3), ('type', 16, 1)):
            with self.subTest(field=label):
                blob = bytearray(self.data)
                blob[location] = value
                self._parse_blob(blob)

    def test_section_table_shape_overflow_and_bounds_are_rejected(self):
        mutations = (
            ('table offset', 40, '<Q', len(self.data) + 64),
            ('entry size', 58, '<H', 63),
            ('section count', 60, '<H', 4097),
        )
        for label, location, format_, value in mutations:
            with self.subTest(field=label):
                blob = bytearray(self.data)
                struct.pack_into(format_, blob, location, value)
                self._parse_blob(blob)
        blob = bytearray(self.data)
        struct.pack_into('<Q', blob, self.offset['table'] + 3 * 64 + 32,
            (1 << 64) - 8)
        self._parse_blob(blob)

    def test_dynsym_shape_and_string_ranges_are_rejected(self):
        cases = (
            ('bad entry size', self.offset['dynsym'] + 56, '<Q', 16),
            ('bad string link', self.offset['dynsym'] + 40, '<I', 99),
            ('symbol section offset overflow', self.offset['dynsym'] + 24, '<Q', (1 << 64) - 8),
            ('symbol section size out of file', self.offset['dynsym'] + 32, '<Q', len(self.data) * 2),
            ('symbol count bound', self.offset['dynsym'] + 32, '<Q', 24 * 65537),
            ('string section offset overflow', self.offset['dynstr'] + 24, '<Q', (1 << 64) - 4),
            ('string section size cap', self.offset['dynstr'] + 32, '<Q', 4 * 1024 * 1024 + 1),
            ('out of range name', self.offset['symbols'] + 24, '<I', 0xffffffff),
        )
        for label, location, format_, value in cases:
            with self.subTest(case=label):
                blob = bytearray(self.data)
                struct.pack_into(format_, blob, location, value)
                self._parse_blob(blob)
        for label, location in (
                ('nonempty null dynsym entry', self.offset['symbols']),
                ('non-null first string byte', self.offset['strings'])):
            with self.subTest(case=label):
                blob = bytearray(self.data)
                blob[location] = 1
                self._parse_blob(blob)
        blob = bytearray(self.data)
        blob[self.offset['strings'] + self.offset['names_size'] - 1] = ord('X')
        self._parse_blob(blob)

    def test_export_binding_type_visibility_definition_and_size_are_checked(self):
        first = self.offset['symbols'] + 24
        for label, location, format_, value in (
                ('local binding', first + 4, '<B', 0x01),
                ('function type', first + 4, '<B', 0x12),
                ('hidden visibility', first + 5, '<B', 1),
                ('undefined', first + 6, '<H', 0),
                ('wrong object size', first + 16, '<Q', 9)):
            with self.subTest(case=label):
                blob = bytearray(self.data)
                struct.pack_into(format_, blob, location, value)
                self._parse_blob(blob)

    def test_duplicate_export_nonwritable_and_virtual_overflow_reject(self):
        duplicate, _ = synthetic_elf(duplicate='ngx_process')
        self._parse_blob(duplicate)
        for label, field_offset, value in (
                ('nonwritable target', 8, 2),
                ('target virtual overflow', 16, (1 << 64) - 4)):
            with self.subTest(case=label):
                blob = bytearray(self.data)
                struct.pack_into('<Q' if field_offset == 16 else '<I', blob,
                    self.offset['target'] + field_offset, value)
                self._parse_blob(blob)

    def test_expected_hash_and_initial_deadline_are_enforced(self):
        with self.assertRaises(PermissionError):
            self.parse(expected=b'\0' * 32)
        with self.assertRaises(PermissionError):
            self.parse(deadline=time.monotonic_ns() - 1)

    def test_content_and_stat_mutation_during_parse_are_rejected(self):
        original = os.pread
        size = len(self.data)
        for mode in ('content', 'stat'):
            with self.subTest(mode=mode):
                changed = [False]
                def wrapped(fd, count, offset):
                    if fd == self.fd and offset == 0 and count == size and not changed[0]:
                        # First full-size read is the initial digest; mutate
                        # immediately before the second full-size digest.
                        changed[0] = True
                    elif fd == self.fd and offset == 0 and count == size and changed[0]:
                        changed[0] = 'done'
                        if mode == 'content':
                            write_fd = os.open(self.path, os.O_WRONLY | os.O_CLOEXEC)
                            try:
                                os.pwrite(write_fd, b'Y', self.offset['padding'])
                            finally:
                                os.close(write_fd)
                        else:
                            st = os.fstat(self.fd)
                            os.utime(self.path, ns=(st.st_atime_ns, st.st_mtime_ns + 2_000_000))
                    return original(fd, count, offset)
                with mock.patch.object(bootstrap.os, 'pread', side_effect=wrapped):
                    with self.assertRaises(PermissionError):
                        self.parse()
                # Restore the synthetic input before the next case.
                os.close(self.fd)
                self.path.write_bytes(self.data)
                self.fd = os.open(self.path, os.O_RDONLY | os.O_CLOEXEC)

    def test_deadline_advancing_during_bounded_reads_is_rejected(self):
        original = time.monotonic_ns
        calls = [0]
        deadline = original() + 10_000_000
        def advancing():
            calls[0] += 1
            return deadline - 1 if calls[0] < 5 else deadline
        with mock.patch.object(bootstrap.time, 'monotonic_ns', side_effect=advancing):
            with self.assertRaises(PermissionError):
                self.parse(deadline=deadline)

    def _parse_blob(self, blob):
        path = Path(self.temp.name) / 'bad.elf'
        path.write_bytes(blob)
        before = len(os.listdir('/proc/self/fd'))
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
        try:
            with self.assertRaises((PermissionError, struct.error, OverflowError)):
                bootstrap.bounded_source_exports(fd, hashlib.sha256(blob).digest(),
                    time.monotonic_ns() + 2_000_000_000)
        finally:
            os.close(fd)
        self.assertEqual(len(os.listdir('/proc/self/fd')), before,
            'malformed input leaked a descriptor')

    @unittest.skipUnless(os.environ.get('KER_FSTACK_NGINX_BINARY'),
        'set KER_FSTACK_NGINX_BINARY for optional trusted-nm comparison')
    def test_real_pinned_nginx_exports_match_trusted_nm_metadata(self):
        path = os.environ['KER_FSTACK_NGINX_BINARY']
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
        try:
            digest = hashlib.sha256()
            offset = 0
            while True:
                block = os.pread(fd, 65536, offset)
                if not block:
                    break
                digest.update(block)
                offset += len(block)
            actual = bootstrap.bounded_source_exports(fd, digest.digest(),
                time.monotonic_ns() + 5_000_000_000)
            nm = subprocess.run(['nm', '-D', '--defined-only', path], check=True,
                capture_output=True, text=True, timeout=5)
            expected = {fields[2]: int(fields[0], 16)
                for line in nm.stdout.splitlines()
                if len(fields := line.split()) == 3 and fields[2] in SIZES}
            self.assertEqual(actual, expected)
        finally:
            os.close(fd)


if __name__ == '__main__':
    unittest.main()
