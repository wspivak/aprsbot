from flask import Flask, jsonify
from flask_cors import CORS
import sqlite3
import re
import sys # Import sys for direct stderr print

app = Flask(__name__)
CORS(app)  # Enable CORS

DATABASE = 'erli.db'

def trim_aprs_message(message):
    pattern = r'^(NETMSG)\s+\S+\s+(.*)'
    match = re.match(pattern, message.strip(), re.IGNORECASE)
    return match.group(2) if match else message

def query_audit_log():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    print("DEBUG: Inside query_audit_log function", file=sys.stderr)
    cursor.execute("""
        SELECT
            al.timestamp,
            al.direction,
            al.source,
            al.destination,
            al.message,
            al.msgid,
            al.rejected
        FROM
            audit_log AS al
        LEFT JOIN
            erli_users AS eu ON al.source = eu.callsign
        LEFT JOIN
            blacklist AS bl ON al.source = bl.callsign
        WHERE
            al.timestamp >= datetime('now', '-7 days')
            AND (LOWER(al.message) LIKE '%cq%' OR LOWER(al.message) LIKE '%netmsg erli%')
            AND al.destination NOT LIKE 'BLN%'
            AND eu.callsign IS NOT NULL
            AND bl.callsign IS NULL
        ORDER BY
            al.timestamp DESC; -- The semicolon at the very end is fine for a single statement
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
    print("DEBUG: /logs endpoint hit", file=sys.stderr) # Add this
    try:
        logs = query_audit_log()
        return jsonify(logs)
    except Exception as e:
        import traceback
        error_msg = f"Error fetching logs: {e}\n{traceback.format_exc()}"
        print(f"DEBUG: Caught exception in /logs: {error_msg}", file=sys.stderr) # And this
        app.logger.error(error_msg) # Keep this too
        return jsonify({"error": "An internal server error occurred."}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
