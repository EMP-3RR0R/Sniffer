import unittest
from unittest.mock import patch, MagicMock
from sniffer import packet_callback

class TestSniffer(unittest.TestCase):
    @patch('sniffer.time.strftime', return_value='2025-03-26 06:29:05')
    def test_packet_callback_tcp(self, mock_time):
        packet = MagicMock()
        packet.haslayer.return_value = True
        packet[IP].src = '192.168.0.1'
        packet[IP].dst = '192.168.0.2'
        packet.summary.return_value = "TCP"
        packet.__len__.return_value = 60

        with patch('builtins.print') as mock_print:
            packet_callback(packet)
            mock_print.assert_called_with('2025-03-26 06:29:05 - From: 192.168.0.1 To: 192.168.0.2 Protocol: TCP Length: 60')

    @patch('sniffer.time.strftime', return_value='2025-03-26 06:29:05')
    def test_packet_callback_udp(self, mock_time):
        packet = MagicMock()
        packet.haslayer.return_value = True
        packet[IP].src = '192.168.0.1'
        packet[IP].dst = '192.168.0.3'
        packet.summary.return_value = "UDP"
        packet.__len__.return_value = 42

        with patch('builtins.print') as mock_print:
            packet_callback(packet)
            mock_print.assert_called_with('2025-03-26 06:29:05 - From: 192.168.0.1 To: 192.168.0.3 Protocol: UDP Length: 42')

if __name__ == '__main__':
    unittest.main()