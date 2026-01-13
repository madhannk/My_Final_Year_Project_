import sqlite3
from config import DB_NAME

conn = sqlite3.connect(DB_NAME)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS attacks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip TEXT,
    attack_type TEXT,
    time TEXT
)
""")

cursor.execute("CREATE INDEX IF NOT EXISTS idx_time ON attacks(time)")
conn.commit()
conn.close()

print("✔ Database initialized successfully")
