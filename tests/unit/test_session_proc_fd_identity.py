#!/usr/bin/env python3
"""Verify the session TAP handoff proof uses fdinfo identity, not fd-slot stat."""

from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from ker_session_run import (tap_interface_fds_for_process, validate_exception_endpoint_closed)


ENDPOINT = 'kex1234abcd'
MODE = 'frame-death-both-prepared'
OLD_FD = 17


def write_fdinfo(directory, fd, *, interface=None, extra=''):
    lines = ['pos:\t0', 'flags:\t02100002', 'mnt_id:\t39', 'ino:\t1292']
    if interface is not None:
        lines.append(f'iff:\t{interface}')
    if extra:
        lines.append(extra)
    (directory / str(fd)).write_text('\n'.join(lines) + '\n', encoding='utf-8')


class SessionProcFdIdentityTests(unittest.TestCase):
    def test_fdinfo_census_maps_tun_identity_to_every_numeric_descriptor(self):
        with tempfile.TemporaryDirectory(prefix='session-fdinfo-') as tmp:
            directory = Path(tmp)
            write_fdinfo(directory, 17, interface=ENDPOINT)
            write_fdinfo(directory, 19, interface=ENDPOINT)
            write_fdinfo(directory, 23)
            self.assertEqual(tap_interface_fds_for_process(1234, fdinfo_dir=directory), {
                17: (ENDPOINT,), 19: (ENDPOINT,),
            })

    def test_successful_close_and_absent_interface_accept_unrelated_slot_reuse(self):
        before = {OLD_FD: (ENDPOINT,)}
        # A reused number for a non-TUN fd has no `iff` line and is omitted
        # from the endpoint-specific fdinfo map.
        after = {}
        closed = {'mode': MODE}
        self.assertTrue(validate_exception_endpoint_closed(ENDPOINT, OLD_FD, before, after, closed, MODE))

    def test_stable_old_slot_reuse_is_allowed_only_without_tun_fdinfo_identity(self):
        before = {OLD_FD: (ENDPOINT,)}
        closed = {'mode': MODE}
        self.assertTrue(validate_exception_endpoint_closed(ENDPOINT, OLD_FD, before, {}, closed, MODE))
        for after in ({OLD_FD: ('another-tun',)}, {19: ('another-tun',)}):
            with self.subTest(after=after), self.assertRaisesRegex(RuntimeError, 'TUN fd|aliases'):
                validate_exception_endpoint_closed(ENDPOINT, OLD_FD, before, after, closed, MODE)

    def test_old_endpoint_at_old_slot_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'aliases'):
            validate_exception_endpoint_closed(ENDPOINT, OLD_FD,
                {OLD_FD: (ENDPOINT,)}, {OLD_FD: (ENDPOINT,)}, {'mode': MODE}, MODE)

    def test_endpoint_alias_on_a_different_slot_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'aliases'):
            validate_exception_endpoint_closed(ENDPOINT, OLD_FD,
                {OLD_FD: (ENDPOINT,)}, {29: (ENDPOINT,)}, {'mode': MODE}, MODE)

    def test_original_fd_must_be_bound_to_the_expected_endpoint_before_handoff(self):
        with self.assertRaisesRegex(RuntimeError, 'before handoff'):
            validate_exception_endpoint_closed(ENDPOINT, OLD_FD,
                {OLD_FD: ('another-tap',)}, {}, {'mode': MODE}, MODE)

    def test_close_marker_must_match_the_current_profile(self):
        for marker in (None, {}, {'mode': 'positive'}):
            with self.subTest(marker=marker), self.assertRaisesRegex(RuntimeError, 'successful exception endpoint close'):
                validate_exception_endpoint_closed(ENDPOINT, OLD_FD,
                    {OLD_FD: (ENDPOINT,)}, {}, marker, MODE)

    def test_uninstrumented_handoff_does_not_require_test_close_marker(self):
        self.assertTrue(validate_exception_endpoint_closed(ENDPOINT, OLD_FD,
            {OLD_FD: (ENDPOINT,)}, {}, None, None))

    def test_fdinfo_permission_denial_is_not_treated_as_closed(self):
        with tempfile.TemporaryDirectory(prefix='session-fdinfo-denied-') as tmp:
            fdinfo = Path(tmp) / '17'
            fdinfo.write_text('iff: kex1234abcd\n', encoding='utf-8')
            with mock.patch.object(Path, 'read_text', side_effect=PermissionError(13, 'denied')):
                with self.assertRaises(PermissionError):
                    tap_interface_fds_for_process(1234, fdinfo_dir=Path(tmp))

    def test_reused_non_tun_slot_needs_no_procfd_readlink_classification(self):
        with tempfile.TemporaryDirectory(prefix='session-fdinfo-reused-') as tmp:
            directory = Path(tmp)
            # This descriptor number has been reused for an unrelated file.
            # Its fdinfo is readable and contains no TUN interface identity.
            write_fdinfo(directory, OLD_FD)
            after = tap_interface_fds_for_process(1234, fdinfo_dir=directory)
            self.assertTrue(validate_exception_endpoint_closed(ENDPOINT, OLD_FD,
                {OLD_FD: (ENDPOINT,)}, after, {'mode': MODE}, MODE))


if __name__ == '__main__':
    unittest.main()
