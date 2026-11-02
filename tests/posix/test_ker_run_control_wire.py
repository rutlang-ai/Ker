"""Fixed-layout tests for the private ker-run generation relay."""
import importlib.util
from pathlib import Path
import struct
import unittest

WIRE_PATH = Path(__file__).resolve().parents[2] / 'tools' / 'ker_run_control_wire.py'
SPEC = importlib.util.spec_from_file_location('_ker_run_control_wire_test', WIRE_PATH)
wire = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(wire)


class KerRunControlWireTests(unittest.TestCase):
    def setUp(self):
        self.nonce = bytes(range(1, 17))
        self.broker_nonce = bytes(range(17, 33))
        self.epoch = 0x0102030405060708
        self.broker_epoch = 0x1112131415161718
        self.profile = b'P' * 32
        self.app_hash = b'A' * 32
        self.worker_hash = b'W' * 32
        self.app = (101, 1000, 1000, 111)
        self.worker = (102, 1000, 1000, 112)

    def test_ready_contains_distinct_contexts_and_full_process_identities(self):
        packet = wire.pack_ready(self.nonce, self.epoch, self.broker_nonce,
            self.broker_epoch, self.profile, self.app_hash, self.worker_hash,
            self.app, self.worker)
        self.assertEqual(len(packet), 216)
        ready = wire.unpack_ready(packet)
        self.assertEqual(ready, (self.nonce, self.epoch, self.broker_nonce,
            self.broker_epoch, self.profile, self.app_hash, self.worker_hash,
            self.app, self.worker))
        self.assertNotEqual(ready[0], ready[2])
        damaged = bytearray(packet)
        damaged[180] = 1
        with self.assertRaises(ValueError):
            wire.unpack_ready(damaged)
        with self.assertRaises(ValueError):
            wire.pack_ready(bytes(16), self.epoch, self.broker_nonce,
                self.broker_epoch, self.profile, self.app_hash,
                self.worker_hash, self.app, self.worker)

    def test_verify_request_and_result_bind_both_contexts(self):
        packet = wire.pack_verify(self.nonce, self.epoch, 1)
        self.assertEqual(wire.unpack_verify(packet), (self.nonce, self.epoch, 1))
        broker_result = bytearray(128)
        struct.pack_into('<IHHII16sQQIIQQQIQ32sI', broker_result, 0,
            0x4B425234, 1, 5, 128, 0, self.broker_nonce,
            self.broker_epoch, 1, 44, 0, 99, 123, 7, 0xE07A0001, 55,
            self.profile, 1)
        wrapped = wire.pack_verify_result(self.nonce, self.epoch, 1,
            bytes(broker_result))
        status, returned = wire.unpack_verify_result(wrapped, self.nonce,
            self.epoch, 1, self.broker_nonce, self.broker_epoch, self.profile)
        self.assertEqual(status, 0)
        self.assertEqual(returned, bytes(broker_result))
        with self.assertRaises(ValueError):
            wire.unpack_verify_result(wrapped, self.nonce, self.epoch, 2,
                self.broker_nonce, self.broker_epoch, self.profile)
        with self.assertRaises(ValueError):
            wire.unpack_verify_result(wrapped, self.nonce, self.epoch, 1,
                self.nonce, self.broker_epoch, self.profile)
        for offset, value, fmt in ((60, 4096, '<I'), (88, 2, '<Q'),
                (100, 1, '<I'), (172, 0, '<I')):
            damaged = bytearray(wrapped)
            struct.pack_into(fmt, damaged, offset, value)
            with self.assertRaises(ValueError):
                wire.unpack_verify_result(damaged, self.nonce, self.epoch, 1,
                    self.broker_nonce, self.broker_epoch, self.profile)
        staged = bytearray(broker_result)
        struct.pack_into('<I', staged, 12, 16)  # EBUSY, not retired.
        struct.pack_into('<I', staged, 124, 0)
        struct.pack_into('<I', staged, 48, 0)  # Unpublished watch identity is partial.
        staged_wrapped = wire.pack_verify_result(self.nonce, self.epoch, 1,
            bytes(staged))
        status, _ = wire.unpack_verify_result(staged_wrapped, self.nonce,
            self.epoch, 1, self.broker_nonce, self.broker_epoch, self.profile)
        self.assertEqual(status, 16)

    def test_stop_and_settled_require_complete_matching_lifecycle(self):
        stop = wire.pack_stop(self.nonce, self.epoch, 2)
        self.assertEqual(wire.unpack_stop(stop), (self.nonce, self.epoch, 2))
        stop_accepted = wire.pack_stop_reply(wire.STOP_ACCEPTED, self.nonce,
            self.epoch, 2)
        self.assertEqual(wire.unpack_stop_reply(stop_accepted,
            wire.STOP_ACCEPTED, self.nonce, self.epoch, 2),
            (wire.STOP_ACCEPTED, self.nonce, self.epoch, 2))
        ready = (self.nonce, self.epoch, self.broker_nonce, self.broker_epoch,
            self.profile, self.app_hash, self.worker_hash, self.app, self.worker)
        settled = wire.pack_settled(self.nonce, self.epoch, 2,
            self.app[0], self.worker[0], self.app[3], self.worker[3],
            0, 0, 0, wire.SETTLED_FLAGS, self.broker_nonce,
            self.broker_epoch, self.profile)
        self.assertEqual(len(settled), 144)
        wire.unpack_settled(settled, ready, self.nonce, self.epoch, 2)
        partial = bytearray(settled)
        struct.pack_into('<I', partial, 84, wire.SETTLED_FLAGS ^ wire.IO_DONE)
        with self.assertRaises(ValueError):
            wire.unpack_settled(partial, ready, self.nonce, self.epoch, 2)
        wrong_pid = bytearray(settled)
        struct.pack_into('<I', wrong_pid, 48, self.app[0] + 1)
        with self.assertRaises(ValueError):
            wire.unpack_settled(wrong_pid, ready, self.nonce, self.epoch, 2)


if __name__ == '__main__':
    unittest.main()
