import unittest
from ethernet_header import EthernetHeader
import struct

class TestEthernetHeader(unittest.TestCase):
    def test_creation(self):
        dest_mac = b'\x00\x10Z\x98\xc5\x00'
        source_mac = b'\x0e5\xa1H`'
        eth_type = 0x0800

        eth_header = EthernetHeader(dest_mac, source_mac, eth_type)

        self.assertEqual(eth_header.dest_mac, dest_mac)
        self.assertEqual(eth_header.source_mac, source_mac)
        self.assertEqual(eth_header.eth_type, eth_type)

    def test_from_bytes(self):
        eth_bytes = b'\x00\x10Z \x98\xc5\x00\x0e5\xa1H`\x08\x00'
        expected_dest_mac = b'\x00\x10Z \x98\xc5'
        expected_source_mac = b'\x00\x0e5\xa1H`'
        expected_eth_type = 0x0800

        eth_header = EthernetHeader.from_bytes(eth_bytes)

        self.assertEqual(eth_header.dest_mac, expected_dest_mac)
        self.assertEqual(eth_header.source_mac, expected_source_mac)
        self.assertEqual(eth_header.eth_type, expected_eth_type)

if __name__ == '__main__':
    unittest.main()