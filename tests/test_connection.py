import unittest
from connection import Connection

class TestConnectionEquality(unittest.TestCase):
    def test_equal_connections(self):
        conn1 = Connection("192.168.1.1", 80, "192.168.1.2", 443)
        conn2 = Connection("192.168.1.1", 80, "192.168.1.2", 443)
        self.assertEqual(conn1, conn2)

    def test_equal_connections_reversed(self):
        conn1 = Connection("192.168.1.1", 80, "192.168.1.2", 443)
        conn2 = Connection("192.168.1.2", 443, "192.168.1.1", 80)
        self.assertEqual(conn1, conn2)

    def test_unequal_connections(self):
        conn1 = Connection("192.168.1.1", 80, "192.168.1.2", 443)
        conn2 = Connection("192.168.1.2", 8080, "192.168.1.1", 22)
        self.assertNotEqual(conn1, conn2)

    def test_mixed_equal_connections(self):
        conn1 = Connection("192.168.1.1", 80, "192.168.1.2", 443)
        conn2 = Connection("192.168.1.2", 8080, "192.168.1.1", 22)
        self.assertNotEqual(conn1, conn2)

if __name__ == '__main__':
    unittest.main()
