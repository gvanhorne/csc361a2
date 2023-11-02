import unittest
from tcp_header import TCPHeader

class TestTCPHeader(unittest.TestCase):
    def test_get_src_port(self):
        tcp_header = TCPHeader()

        buffer = b'\x00\x50'  # Source Port: 80

        tcp_header.get_src_port(buffer)

        self.assertEqual(tcp_header.src_port, 80)

    def test_get_dst_port(self):
        tcp_header = TCPHeader()

        buffer = b'\x04\x00'  # Destination Port: 1024

        tcp_header.get_dst_port(buffer)

        self.assertEqual(tcp_header.dst_port, 1024)

    def test_get_seq_num(self):
        tcp_header = TCPHeader()

        buffer = b'\x00\x01\x02\x03'  # Sequence Number: 66051

        tcp_header.get_seq_num(buffer)

        self.assertEqual(tcp_header.seq_num, 66051)

    def test_get_ack_num(self):
        tcp_header = TCPHeader()

        buffer = b'\x04\x03\x02\x01'  # Acknowledgment Number: 67305985

        tcp_header.get_ack_num(buffer)

        self.assertEqual(tcp_header.ack_num, 67305985)

    def test_get_flags(self):
        tcp_header = TCPHeader()

        buffer = b'\x12'  # Flags: 00010010 (ACK and SYN set)

        tcp_header.get_flags(buffer)

        self.assertEqual(tcp_header.flags, {"ACK": 1, "RST": 0, "SYN": 1, "FIN": 0})

    def test_get_window_size(self):
        tcp_header = TCPHeader()

        buffer1 = b'\x01'  # First byte of window size
        buffer2 = b'\x02'  # Second byte of window size

        tcp_header.get_window_size(buffer1, buffer2)

        self.assertEqual(tcp_header.window_size, 258)

    def test_get_data_offset(self):
        tcp_header = TCPHeader()

        buffer = b'\x50'  # Data Offset: 5 (20 bytes)

        tcp_header.get_data_offset(buffer)

        self.assertEqual(tcp_header.data_offset, 20)

if __name__ == '__main__':
    unittest.main()
