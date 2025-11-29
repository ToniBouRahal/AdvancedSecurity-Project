import sqlite3
from datetime import datetime

DB_PATH = "login.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Table of login attempts
    c.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER,
            ip TEXT,
            username TEXT,
            success INTEGER,
            user_agent TEXT
        )
    """)

    # Table for IP decisions (block / challenge)
    c.execute("""
        CREATE TABLE IF NOT EXISTS ip_decisions (
            ip TEXT PRIMARY KEY,
            decision TEXT,            -- 'allow', 'challenge', 'block'
            last_update INTEGER
        )
    """)

    conn.commit()
    conn.close()
    print("DB initialized.")

if __name__ == "__main__":
    init_db()
