import argparse
from scapy.all import TCP, UDP, ICMP

def parse_arguments():
    """Парсит аргументы командной строки"""
    parser = argparse.ArgumentParser(description="Network Packet Sniffer")
    parser.add_argument('-i', '--interface', type=str, required=True, help="Network interface to sniff on")
    return parser.parse_args()

def get_protocol(packet):
    """Определяет протокол пакета (TCP, UDP, ICMP или другие)"""
    if TCP in packet:
        return "TCP"
    elif UDP in packet:
        return "UDP"
    elif ICMP in packet:
        return "ICMP"
    else:
        return "Other"