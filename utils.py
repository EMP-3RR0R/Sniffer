import argparse
from scapy.layers.inet import TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS
from scapy.all import get_if_list

def parse_arguments():
    """Парсит аргументы командной строки"""
    parser = argparse.ArgumentParser(description="Network Packet Sniffer")
    parser.add_argument('-i', '--interface', type=str, required=True, help="Network interface to sniff on")
    return parser.parse_args()

def get_protocol(packet):
    """Определяет протокол пакета (TCP, UDP, ICMP, ARP, DNS, HTTP, HTTPS, FTP, SMTP, POP3 или другие)"""
    if ARP in packet:
        return "ARP"
    elif ICMP in packet:
        return "ICMP"
    elif TCP in packet:
        if packet[TCP].dport == 80 or packet[TCP].sport == 80:
            return "HTTP"
        elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
            return "HTTPS"
        elif packet[TCP].dport == 21 or packet[TCP].sport == 21:
            return "FTP"
        elif packet[TCP].dport == 25 or packet[TCP].sport == 25:
            return "SMTP"
        elif packet[TCP].dport == 110 or packet[TCP].sport == 110:
            return "POP3"
        return "TCP"
    elif UDP in packet:
        if DNS in packet:
            return "DNS"
        return "UDP"
    else:
        return "Other"