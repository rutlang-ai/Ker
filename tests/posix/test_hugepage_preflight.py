"""Fixtures for selected-hugetlbfs capacity checks; no host hugepages required."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('hugepage_preflight', HERE / 'hugepage_preflight.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

MIB = 1024 * 1024
GIB = 1024 * MIB


class HugepagePreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ker-hugepage-preflight-')
        self.root = Path(self.temp.name)
        self.mount = self.root / 'huge pages'
        self.mount.mkdir()
        self.mountinfo = self.root / 'mountinfo'
        self.sysfs = self.root / 'sys'
        self.sysfs.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def set_class(self, page_size, free, reserved=0):
        directory = self.sysfs / f'hugepages-{page_size // 1024}kB'
        directory.mkdir(parents=True, exist_ok=True)
        (directory / 'free_hugepages').write_text(str(free))
        (directory / 'resv_hugepages').write_text(str(reserved))

    def set_mount(self, page_size, options=''):
        if page_size % GIB == 0:
            size_option = f'pagesize={page_size // GIB}G'
        elif page_size % MIB == 0:
            size_option = f'pagesize={page_size // MIB}M'
        else:
            size_option = f'pagesize={page_size // 1024}kB'
        options = ','.join(item for item in ('rw', size_option, options) if item)
        escaped = str(self.mount).replace(' ', r'\040')
        self.mountinfo.write_text(
            f'41 1 0:42 / {escaped} rw - hugetlbfs hugetlbfs {options}\n')

    def check(self, page_size, free, reserved=0, *, mount_options='', blocks=0, available=0):
        self.set_mount(page_size, mount_options)
        self.set_class(page_size, free, reserved)
        stats = SimpleNamespace(f_bsize=page_size, f_frsize=page_size,
                                f_blocks=blocks, f_bavail=available)
        with patch.object(probe.os, 'statvfs', return_value=stats):
            return probe.hugepage_capacity_error(
                self.mount, 64 * MIB, mountinfo_path=self.mountinfo, sysfs_root=self.sysfs)

    def test_unbounded_two_megabyte_mount_uses_its_32_free_pages(self):
        # hugetlbfs statfs reports f_blocks=0 and f_bavail=0 when unbounded.
        self.assertIsNone(self.check(2 * MIB, 32))

    def test_unbounded_mount_minus_one_statfs_sentinel_is_not_a_quota(self):
        self.assertIsNone(self.check(2 * MIB, 32, blocks=(1 << 64) - 1, available=0))

    def test_one_gigabyte_mount_uses_its_page_class_not_default_class(self):
        self.set_class(2 * MIB, 128)
        self.assertIsNone(self.check(GIB, 2, reserved=1))

    def test_page_class_mismatch_does_not_borrow_default_pool_count(self):
        self.set_class(2 * MIB, 32)
        error = self.check(GIB, 0)
        self.assertIn('selected 1073741824-byte hugepage pool', error)

    def test_insufficient_bounded_mount_quota_is_reported(self):
        error = self.check(2 * MIB, 64, mount_options='size=64M', blocks=32, available=31)
        self.assertIn('mount has 31 quota pages available', error)

    def test_reserved_global_pages_do_not_count_as_available(self):
        error = self.check(2 * MIB, 32, reserved=1)
        self.assertIn('has 31 unreserved pages', error)

    def test_non_hugetlbfs_path_is_rejected(self):
        self.mountinfo.write_text(f'41 1 0:42 / {self.mount} rw - tmpfs tmpfs rw\n')
        stats = SimpleNamespace(f_bsize=4096, f_frsize=4096, f_blocks=0, f_bavail=0)
        with patch.object(probe.os, 'statvfs', return_value=stats):
            error = probe.hugepage_capacity_error(
                self.mount, 64 * MIB, mountinfo_path=self.mountinfo, sysfs_root=self.sysfs)
        self.assertIn('not on a hugetlbfs mount', error)


if __name__ == '__main__':
    unittest.main()
