from flask import Flask, jsonify
from flask_cors import CORS
import sqlite3

app = Flask(__name__)
CORS(app)  # 🔓 Allow all domains; restrict if needed

DATABASE = 'erli.db'

def query_audit_log():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, timestamp, direction, source, destination, message, msgid, rejected, note
        FROM audit_log
        WHERE timestamp >= datetime('now', '-7 days')
          AND (LOWER(message) LIKE '%cq%' OR LOWER(message) LIKE '%netmsg erli%')
          AND destination NOT LIKE 'BLN%'
        ORDER BY timestamp DESC
    """)


    rows = cursor.fetchall()
    conn.close()
    columns = ['timestamp', 'direction', 'source', 'destination', 'message', 'msgid', 'rejected']
    return [dict(zip(columns, row)) for row in rows]

@app.route('/logs')
def get_logs():
    try:
        logs = query_audit_log()
        return jsonify(logs)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
