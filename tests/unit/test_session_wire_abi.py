"""Small regression checks for the private resident-control message ABI."""
import importlib.util
from pathlib import Path
import unittest


TOOL = Path(__file__).resolve().parents[2] / 'tools' / 'ker-session.py'
SPEC = importlib.util.spec_from_file_location('ker_session_wire_abi_test', TOOL)
SESSION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SESSION)


class SessionWireAbiTests(unittest.TestCase):
    def test_frame_fields_are_appended_to_version_ten_message(self):
        self.assertEqual(SESSION.VERSION, 10)
        self.assertEqual(SESSION.WIRE.size, 128)
        self.assertEqual(SESSION.FIELDS[-4:], (
            'packet_pool_tag', 'packet_object_index', 'packet_port', 'packet_queue'))
        self.assertEqual((SESSION.FRAME_PREPARE, SESSION.FRAME_COMMIT, SESSION.FRAME_CANCEL),
            (19, 20, 21))

    def test_frame_prepare_round_trips_full_packet_lease_tuple(self):
        request = SESSION.packet(SESSION.FRAME_PREPARE, 7, session=11, epoch=13,
            generation=0, process=0, token=17, slot=1, capability=19,
            packet_pool_tag=23, packet_object_index=0xffffffff,
            packet_port=0, packet_queue=1)
        decoded = dict(zip(SESSION.FIELDS, SESSION.WIRE.unpack(SESSION.encode(request))))
        self.assertEqual(len(SESSION.encode(request)), 128)
        self.assertEqual(decoded, request)
        self.assertEqual(decoded['packet_object_index'], 0xffffffff)
        self.assertEqual(decoded['packet_queue'], 1)

    def test_existing_commands_zero_new_fields_by_default(self):
        request = SESSION.packet(SESSION.PMD_STATUS)
        self.assertEqual(tuple(request[name] for name in SESSION.FIELDS[-4:]), (0, 0, 0, 0))


if __name__ == '__main__':
    unittest.main()
