import time
import sys
from scapy.all import sniff, IP, TCP, UDP, ICMP
from utils import get_protocol

def packet_callback(packet):
    """Обрабатывает перехваченные пакеты и выводит информацию о них"""
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = get_protocol(packet)
        print(f"{timestamp} - From: {ip_src} To: {ip_dst} Protocol: {protocol} Length: {len(packet)}")

def start_sniffer(interface):
    """Запускает сниффер на указанном сетевом интерфейсе"""
    print(f"Starting sniffer on interface {interface}...")
    try:
        sniff(iface=interface, prn=packet_callback, store=0)
    except PermissionError:
        print("Error: Permission denied. Please run as root or with appropriate permissions.")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)