import unittest
from packet import Packet
import struct

class TestPacket(unittest.TestCase):
    def test_timestamp_set(self):
        packet = Packet()
        buffer1 = struct.pack('I', 10)  # Seconds: 10
        buffer2 = struct.pack('<I', 500000)  # Microseconds: 0.5 seconds

        packet.timestamp_set(buffer1, buffer2, 0.0)

        self.assertAlmostEqual(packet.timestamp, 10.5, places=6)

    def test_packet_No_set(self):
        packet = Packet()
        packet.packet_No_set(42)

        self.assertEqual(packet.packet_No, 42)

    def test_get_RTT_value(self):
        packet = Packet()
        packet.timestamp = 10.5

        test_packet = Packet()
        test_packet.timestamp = 20.0

        packet.get_RTT_value(test_packet)

        self.assertAlmostEqual(packet.RTT_value, 9.5, places=8)

if __name__ == '__main__':
    unittest.main()
