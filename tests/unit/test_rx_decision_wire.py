#!/usr/bin/env python3
import pathlib
import struct
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import rx_decision_wire as wire


class RxDecisionWireTests(unittest.TestCase):
    def test_version_matches_c_and_old_version_is_rejected(self):
        source = (ROOT / "src/posix/rx-decision-wire.h").read_text(encoding="utf-8")
        self.assertIn(f"KER_RX_DECISION_VERSION UINT16_C({wire.VERSION})", source)
        nonce = bytes(range(wire.NONCE_BYTES))
        packet = wire.pack_header(wire.HELLO, nonce, 9, control_id=wire.HELLO_CONTROL_ID)
        self.assertEqual(wire.unpack_header(packet)[1], 2)
        old = wire.HEADER.pack(wire.MAGIC, 1, wire.HELLO, wire.HEADER_BYTES,
            wire.HEADER_BYTES, nonce, 9, 0, wire.HELLO_CONTROL_ID, 0)
        with self.assertRaises(ValueError):
            wire.unpack_header(old)

    def test_full_frame_payload_ceiling_fits_private_datagram(self):
        self.assertEqual(wire.MAX_FRAME_PAYLOAD, wire.MAX_FRAME)
        data_bytes = wire.DATA_BODY.size + wire.MAX_FRAME_PAYLOAD
        header = wire.pack_header(wire.DATA, bytes(wire.NONCE_BYTES), 1,
            packet_id=1, deadline_ns=1, body_bytes=data_bytes)
        self.assertEqual(len(header), wire.HEADER_BYTES)
        self.assertLessEqual(wire.HEADER_BYTES + data_bytes, wire.MAX_MESSAGE)
        with self.assertRaises(ValueError):
            wire.pack_header(wire.DATA, bytes(wire.NONCE_BYTES), 1,
                packet_id=1, deadline_ns=1,
                body_bytes=wire.MAX_MESSAGE - wire.HEADER_BYTES + 1)


if __name__ == "__main__":
    unittest.main()
