from collections import defaultdict, deque
import time
from logger import log_attack
from config import *

packet_times = defaultdict(deque)
attack_start = {}
last_alert_time = {}

def cleanup(now):
    inactive = [
        key for key, times in packet_times.items()
        if times and now - times[-1] > DOS_TIME_WINDOW * 2
    ]
    for key in inactive:
        packet_times.pop(key, None)
        attack_start.pop(key, None)
        last_alert_time.pop(key, None)

def detect_attacks(src_ip, protocol, port):
    now = time.time()

    # 🔴 FIX: ICMP must NOT include port in key
    if protocol == "ICMP":
        key = (src_ip, protocol)
    else:
        key = (src_ip, protocol, port)

    packet_times[key].append(now)

    while packet_times[key] and now - packet_times[key][0] > DOS_TIME_WINDOW:
        packet_times[key].popleft()

    rate = len(packet_times[key])
    cleanup(now)

    if key in last_alert_time and now - last_alert_time[key] < ALERT_COOLDOWN:
        return None

    # -------- DoS Detection --------
    if rate >= DOS_PACKET_THRESHOLD:
        attack_start.setdefault(key, now)

        if now - attack_start[key] >= MIN_ATTACK_DURATION:
            if rate >= SEVERITY_HIGH_RATE:
                severity = "HIGH"
            elif rate >= SEVERITY_MEDIUM_RATE:
                severity = "MEDIUM"
            else:
                severity = "LOW"

            attack_type = f"DoS Attack | Protocol:{protocol} | Port:{port} | Severity:{severity}"
            log_attack(src_ip, attack_type)
            last_alert_time[key] = now

            packet_times[key].clear()
            attack_start.pop(key, None)

            return attack_type

    # -------- Suspicious Traffic --------
    if rate >= SUSPICIOUS_PACKET_RATE:
        attack_type = f"Suspicious Traffic | Protocol:{protocol} | Port:{port}"
        log_attack(src_ip, attack_type)
        last_alert_time[key] = now
        return attack_type

    return None
