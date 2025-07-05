from flask import Flask, jsonify
from flask_cors import CORS
import sqlite3
import re

app = Flask(__name__)
CORS(app)  # 🔓 Allow all domains; restrict if needed

DATABASE = 'erli.db'

def trim_aprs_message(message):
    """
    Removes 'CQ <word>' or 'NETMSG <word>' from the start of a message, case-insensitive.
    """
    pattern = r'^(CQ|NETMSG)\s+\S+\s+(.*)'
    match = re.match(pattern, message.strip(), re.IGNORECASE)
    return match.group(2) if match else message

def query_audit_log():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT timestamp, direction, source, destination, message, msgid, rejected
        FROM audit_log
        WHERE timestamp >= datetime('now', '-7 days')
          AND (LOWER(message) LIKE '%cq%' OR LOWER(message) LIKE '%netmsg erli%')
          AND destination NOT LIKE 'BLN%'
        ORDER BY timestamp DESC
    """)
    rows = cursor.fetchall()
    conn.close()

    columns = ['timestamp', 'direction', 'source', 'destination', 'message', 'msgid', 'rejected']
    trimmed_logs = []
    for row in rows:
        row_dict = dict(zip(columns, row))
        row_dict['message'] = trim_aprs_message(row_dict['message'])
        trimmed_logs.append(row_dict)

    return trimmed_logs

@app.route('/logs')
def get_logs():
    try:
        logs = query_audit_log()
        return jsonify(logs)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
