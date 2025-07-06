import sqlite3

DB_PATH = '<fill in name>.db'  # path to your SQLite database

def trim_audit_log():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        DELETE FROM audit_log
        WHERE timestamp < datetime('now', '-7 days')
    """)
    deleted = cur.rowcount
    conn.commit()
    conn.close()

    print(f"Deleted {deleted} audit_log entries older than 7 days.")

if __name__ == "__main__":
    trim_audit_log()
