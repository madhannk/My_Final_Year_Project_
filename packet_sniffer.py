from scapy.all import sniff
from scapy.layers.inet import IP, TCP
from attack_detector import detect_attacks
from utils import protocol_name
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def process_packet(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = protocol_name(packet[IP].proto)

        attack = detect_attacks(src, proto)
        if attack:
            print(f"[ALERT] {attack} from {src} → {dst}")

def start_sniffing():
    sniff(filter="ip", prn=process_packet, store=False)
