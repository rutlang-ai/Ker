"""Validation for the private ker-run companion helper wire codec."""
import unittest

from nginx_companion_wire import *


class CompanionWireTest(unittest.TestCase):
    def setUp(self):
        self.nonce = bytes.fromhex('0123456789abcdef0123456789abcdef')
        self.epoch = 17
        self.sequence = 0

    def test_record_sizes_are_exact(self):
        self.assertEqual((HELLO_BYTES, START_BYTES, STARTED_BYTES,
            RELOAD_BYTES, RELOAD_RESULT_BYTES, STOP_BYTES, SETTLED_BYTES,
            ERROR_BYTES), (48, 168, 136, 48, 96, 48, 104, 104))

    def test_valid_header_round_trip(self):
        packet = pack_record(HELLO, b'', self.nonce, self.epoch, self.sequence)
        self.assertEqual(unpack_header(packet),
            (HELLO, self.nonce, self.epoch, self.sequence))

    def test_zero_nonce_epoch_and_sequence_are_rejected(self):
        for values in ((HELLO, 48, bytes(16), 1, 1),
                       (HELLO, 48, self.nonce, 0, 1),
                       (START, 48, self.nonce, 1, 0)):
            with self.subTest(values=values), self.assertRaises(ValueError):
                pack_header(*values)

    def test_hello_uses_reserved_zero_sequence_only(self):
        packet = pack_record(HELLO, b'', self.nonce, self.epoch, 0)
        self.assertEqual(unpack_header(packet)[-1], 0)
        with self.assertRaises(ValueError):
            pack_header(START, 48, self.nonce, self.epoch, 0)

    def test_request_sequence_exhaustion_does_not_wrap(self):
        sequence = RequestSequence()
        self.assertEqual(sequence.take(), 1)
        sequence._next = MAX_SEQUENCE
        self.assertEqual(sequence.take(), MAX_SEQUENCE)
        with self.assertRaises(OverflowError):
            sequence.take()

    def test_record_type_size_correlation_and_trailing_bytes_fail_closed(self):
        packet = pack_record(HELLO, b'', self.nonce, self.epoch, self.sequence)
        with self.assertRaises(ValueError):
            unpack_record(packet, START, self.nonce, self.epoch,
                self.sequence, START_BODY)
        with self.assertRaises(ValueError):
            unpack_record(packet, HELLO, self.nonce, self.epoch + 1,
                self.sequence, struct.Struct(''))
        with self.assertRaises(ValueError):
            unpack_header(packet + b'x')

    def test_start_and_settlement_layouts(self):
        body = START_BODY.pack(1, 1000, 1000, 0, 42, b'p' * 32,
            b'n' * 32, b'c' * 32)
        request_sequence = self.sequence + 1
        packet = pack_record(START, body, self.nonce, self.epoch, request_sequence)
        self.assertEqual(len(packet), START_BYTES)
        self.assertEqual(unpack_record(packet, START, self.nonce, self.epoch,
            request_sequence, START_BODY), START_BODY.unpack(body))
        settled = SETTLED_BODY.pack(0, CLEANUP_SETTLED, 55, 0, 42,
            b'n' * 32)
        packet = pack_record(SETTLED, settled, self.nonce, self.epoch, 2)
        self.assertEqual(len(packet), SETTLED_BYTES)
        fields = unpack_record(packet, SETTLED, self.nonce, self.epoch,
            2, SETTLED_BODY)
        self.assertEqual(fields[3], 0)
        validate_settled(fields, 55, 42, b'n' * 32)

    def test_settlement_requires_exact_master_and_clean_state(self):
        fields = (0, CLEANUP_SETTLED, 55, 0, 42, b'n' * 32)
        validate_settled(fields, 55, 42, b'n' * 32)
        for bad in (
                (0, CLEANUP_UNRESOLVED, 55, 1, 42, b'n' * 32),
                (0, CLEANUP_SETTLED, 55, 1, 42, b'n' * 32),
                (0, CLEANUP_SETTLED, 55, 0, 42, b'x' * 32),
                (0, 8, 55, 0, 42, b'n' * 32),
                (-1, CLEANUP_SETTLED, 55, 0, 42, b'n' * 32),
                (1, CLEANUP_SETTLED, 55, 0, 42, b'n' * 32)):
            with self.subTest(fields=bad), self.assertRaises(ValueError):
                validate_settled(bad, 55, 42, b'n' * 32)

    def test_error_requires_positive_errno_and_phase(self):
        validate_error((5, 2, 55, 1, 42, b'n' * 32))
        for bad in ((0, 2, 55, 1, 42, b'n' * 32),
                    (-5, 2, 55, 1, 42, b'n' * 32),
                    (5, 0, 55, 0, 42, b'\0' * 32)):
            with self.subTest(fields=bad), self.assertRaises(ValueError):
                validate_error(bad)


if __name__ == '__main__':
    import struct
    unittest.main()
