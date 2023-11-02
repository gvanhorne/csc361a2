import unittest
from ip_header import IP_Header

class TestIPHeader(unittest.TestCase):
    def test_get_IP(self):
        ip_header = IP_Header()

        buffer1 = b'\x7f\x00\x00\x01'  # Source IP: 127.0.0.1
        buffer2 = b'\x0a\x00\x00\x02'  # Destination IP: 10.0.0.2

        ip_header.get_IP(buffer1, buffer2)

        self.assertEqual(ip_header.src_ip, '127.0.0.1')
        self.assertEqual(ip_header.dst_ip, '10.0.0.2')

    def test_get_header_len(self):
        ip_header = IP_Header()

        value = b'\x45'  # Header Length: 5 (20 bytes)

        ip_header.get_header_len(value)

        self.assertEqual(ip_header.ip_header_len, 20)

    def test_get_total_len(self):
        ip_header = IP_Header()

        buffer = b'\x00\x14'  # Total Length: 20 bytes

        ip_header.get_total_len(buffer)

        self.assertEqual(ip_header.total_len, 20)

if __name__ == '__main__':
    unittest.main()
