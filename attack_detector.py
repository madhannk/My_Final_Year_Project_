from collections import defaultdict, deque
import time
from logger import log_attack
from config import (
    DOS_PACKET_THRESHOLD,
    DOS_TIME_WINDOW,
    SUSPICIOUS_PACKET_RATE,
    MIN_ATTACK_DURATION,
    ALERT_COOLDOWN
)

packet_times = defaultdict(deque)
attack_start = {}
last_alert_time = {}

def cleanup(now):
    inactive = [ip for ip, times in packet_times.items()
                if times and now - times[-1] > DOS_TIME_WINDOW * 2]
    for ip in inactive:
        packet_times.pop(ip, None)
        attack_start.pop(ip, None)
        last_alert_time.pop(ip, None)

def detect_attacks(src_ip, protocol):
    now = time.time()
    packet_times[src_ip].append(now)

    # Sliding window cleanup
    while packet_times[src_ip] and now - packet_times[src_ip][0] > DOS_TIME_WINDOW:
        packet_times[src_ip].popleft()

    rate = len(packet_times[src_ip])

    cleanup(now)

    # Cooldown check
    if src_ip in last_alert_time and now - last_alert_time[src_ip] < ALERT_COOLDOWN:
        return None

    # ---- DoS Detection ----
    if rate >= DOS_PACKET_THRESHOLD:
        attack_start.setdefault(src_ip, now)
        if now - attack_start[src_ip] >= MIN_ATTACK_DURATION:
            log_attack(src_ip, f"DoS Attack ({protocol})")
            last_alert_time[src_ip] = now
            packet_times[src_ip].clear()
            attack_start.pop(src_ip, None)
            return "DoS Attack"

    # ---- Suspicious Activity ----
    if rate >= SUSPICIOUS_PACKET_RATE:
        log_attack(src_ip, f"Suspicious Traffic ({protocol})")
        last_alert_time[src_ip] = now
        return "Suspicious Activity"

    return None
