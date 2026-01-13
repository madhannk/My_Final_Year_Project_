import sqlite3
from datetime import datetime
from config import DB_NAME
import threading

db_lock = threading.Lock()

def log_attack(source_ip, attack_type):
    with db_lock:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO attacks (source_ip, attack_type, time) VALUES (?, ?, ?)",
            (source_ip, attack_type, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        conn.commit()
        conn.close()

def fetch_attacks(limit=100):
    with db_lock:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT source_ip, attack_type, time FROM attacks ORDER BY time DESC LIMIT ?",
            (limit,)
        )
        data = cursor.fetchall()
        conn.close()
        return data
