import unittest
from pcap_header import PCAPHeader

class TestPCAPHeader(unittest.TestCase):
    def test_from_bytes_valid_header(self):
        # Valid global header in little-endian byte order
        header_bytes = b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00'
        pcap_header = PCAPHeader.from_bytes(header_bytes)

        # Verify that the attributes are correctly parsed
        self.assertEqual(pcap_header.magic_number, 0xa1b2c3d4)
        self.assertEqual(pcap_header.version_major, 2)
        self.assertEqual(pcap_header.version_minor, 4)
        self.assertEqual(pcap_header.thiszone, 0)
        self.assertEqual(pcap_header.sigfigs, 0)
        self.assertEqual(pcap_header.snaplen, 65535)
        self.assertEqual(pcap_header.network, 1)

    def test_from_bytes_invalid_header(self):
        # Invalid global header with incorrect length (should raise a ValueError)
        header_bytes = b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00'
        with self.assertRaises(ValueError):
            PCAPHeader.from_bytes(header_bytes)

if __name__ == '__main__':
    unittest.main()