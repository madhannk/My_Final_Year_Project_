from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from attack_detector import detect_attacks
from utils import protocol_name
import threading

stop_sniffing = threading.Event()

def process_packet(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = protocol_name(packet[IP].proto)

        port = None
        if TCP in packet:
            port = packet[TCP].dport
        elif UDP in packet:
            port = packet[UDP].dport
        elif ICMP in packet:
            port = None

        attack = detect_attacks(src, proto, port)
        if attack:
            print(f"[ALERT] {attack} from {src} → {dst}")

def start_sniffing():
    stop_sniffing.clear()
    while not stop_sniffing.is_set():
        sniff(
            filter="ip",
            prn=process_packet,
            timeout=1,        # 🔴 FIX: reliable stop
            store=False
        )

def stop_sniffer():
    stop_sniffing.set()
