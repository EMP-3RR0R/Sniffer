import unittest
from unittest.mock import patch, call
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
import time

from sniffer import packet_callback, start_sniffer

class TestSniffer(unittest.TestCase):

    @patch('builtins.print')
    @patch('time.strftime', return_value='2025-04-01 04:30:41')
    @patch('utils.get_protocol', return_value='TCP')
    def test_packet_callback(self, mock_get_protocol, mock_strftime, mock_print):
        packet = Ether()/IP(src='192.168.0.1', dst='192.168.0.2')/TCP(dport=12345)
        packet_callback(packet)
        mock_print.assert_called_with("2025-04-01 04:30:41 - From: 192.168.0.1 To: 192.168.0.2 Protocol: TCP Length: 54")

    @patch('sniffer.sniff')
    @patch('builtins.print')
    def test_start_sniffer(self, mock_print, mock_sniff):
        start_sniffer('eth0')
        mock_print.assert_called_with('Starting sniffer on interface eth0...')
        mock_sniff.assert_called_with(iface='eth0', prn=packet_callback, store=0)

if __name__ == '__main__':
    unittest.main()