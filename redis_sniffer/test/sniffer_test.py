import unittest

import redis_sniffer
from redis_sniffer.sniffer.packet import RedisPacket
from redis_sniffer.sniffer.sniffer import Sniffer

class TestSniffer(unittest.TestCase):
    def setUp(self):
        self.packets = []
        self.sniffer = Sniffer(self.packets)

    def test_empty(self):
        iter = self.sniffer.sniff()

        with self.assertRaises(StopIteration):
            iter.next()

    def test_single_packet(self):
        command = ['*2', '$3', 'GET', '$5', 'mykey', '']
        self.packets.append(RedisPacket(1, 10, '127.0.0.1:12345', True, "\r\n".join(command)))
        self.packets.append(RedisPacket(2, 12, '127.0.0.1:12345', False, "\r\n".join(command)))

        time, client, req_size, resp_size, command = self.sniffer.sniff().next()
        self.assertEqual(2, time)
        self.assertEqual('127.0.0.1:12345', client)
        self.assertEqual(10, req_size)
        self.assertEqual(12, resp_size)
        self.assertEqual('GET mykey', command)

if __name__ == '__main__':
    unittest.main()
