import unittest
from packet_header import PacketHeader

class TestPacketHeader(unittest.TestCase):
    def test_from_bytes_valid_header(self):
        # Valid packet header
        header_bytes = b'\x8d\xad\xe7CX\xbb\x0c\x00>\x00\x00\x00>\x00\x00\x00'
        packet_header = PacketHeader.from_bytes(header_bytes, '0xa1b2c3d4')

        # Verify that the attributes are correctly parsed
        self.assertEqual(packet_header.ts_sec, 0x43E7AD8D),
        self.assertEqual(packet_header.ts_usec, 0xCBB58),
        self.assertEqual(packet_header.incl_len, 62)
        self.assertEqual(packet_header.orig_len, 62)

    def test_from_bytes_invalid_header(self):
        # Invalid packet header with incorrect length (should raise a ValueError)
        header_bytes = b'\x8d\xad\xe7CX\xbb\x0c\x00>\x00\x00\x00>\x00\x00'  # Missing 4 bytes
        with self.assertRaises(ValueError):
            PacketHeader.from_bytes(header_bytes, '0xa1b2c3d4')

if __name__ == '__main__':
    unittest.main()
