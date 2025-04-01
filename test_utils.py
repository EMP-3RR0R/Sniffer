import unittest
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether
from scapy.layers.dns import DNS

from utils import get_protocol, parse_arguments

class TestUtils(unittest.TestCase):

    def test_get_protocol_arp(self):
        packet = Ether()/ARP()
        self.assertEqual(get_protocol(packet), "ARP")

    def test_get_protocol_icmp(self):
        packet = Ether()/IP()/ICMP()
        self.assertEqual(get_protocol(packet), "ICMP")

    def test_get_protocol_tcp_http(self):
        packet = Ether()/IP()/TCP(dport=80)
        self.assertEqual(get_protocol(packet), "HTTP")

    def test_get_protocol_tcp_https(self):
        packet = Ether()/IP()/TCP(dport=443)
        self.assertEqual(get_protocol(packet), "HTTPS")

    def test_get_protocol_tcp_other(self):
        packet = Ether()/IP()/TCP(dport=12345)
        self.assertEqual(get_protocol(packet), "TCP")

    def test_get_protocol_udp(self):
        packet = Ether()/IP()/UDP(dport=53)/DNS()
        self.assertEqual(get_protocol(packet), "DNS")

    def test_get_protocol_udp_other(self):
        packet = Ether()/IP()/UDP(dport=12345)
        self.assertEqual(get_protocol(packet), "UDP")

    def test_get_protocol_other(self):
        packet = Ether()/IP()
        self.assertEqual(get_protocol(packet), "Other")

if __name__ == '__main__':
    unittest.main()