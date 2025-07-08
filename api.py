from flask import Flask, jsonify
from flask_cors import CORS
import sqlite3
import re
import sys

app = Flask(__name__)
CORS(app)

DATABASE = 'erli.db'

def trim_aprs_message(message):
    pattern = r'^(NETMSG)\s+\S+\s+(.*)'
    match = re.match(pattern.strip(), message.strip(), re.IGNORECASE)
    return match.group(2).strip() if match else message.strip()

def query_audit_log():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    print("DEBUG: Inside query_audit_log function", file=sys.stderr)
    cursor.execute("""
        SELECT
            MAX(al.timestamp) AS timestamp,
            TRIM(LOWER(al.direction)) AS direction,
            TRIM(LOWER(al.source)) AS source,
            TRIM(LOWER(al.destination)) AS destination,
            TRIM(al.message) AS message,
            REPLACE(TRIM(al.msgid), X'0D', '') AS msgid, -- <--- KEY CHANGE: REPLACE \r and then TRIM again
            al.rejected
        FROM
            audit_log AS al
        LEFT JOIN
            users AS eu ON al.source = eu.callsign
        LEFT JOIN
            blacklist AS bl ON al.source = bl.callsign
        WHERE
            al.timestamp >= datetime('now', '-7 days')
            AND (LOWER(al.message) LIKE '%cq%' OR LOWER(al.message) LIKE '%netmsg erli%')
            AND al.destination NOT LIKE 'BLN%'
            AND eu.callsign IS NOT NULL
            AND bl.callsign IS NULL
        GROUP BY
            TRIM(LOWER(al.direction)),
            TRIM(LOWER(al.source)),
            TRIM(LOWER(al.destination)),
            TRIM(al.message),
            REPLACE(TRIM(al.msgid), X'0D', ''), -- <--- KEY CHANGE: REPLACE \r and then TRIM again in GROUP BY
            al.rejected
        ORDER BY
            timestamp DESC;
    """)

    rows = cursor.fetchall()
    conn.close()

    columns = ['timestamp', 'direction', 'source', 'destination', 'message', 'msgid', 'rejected']
    trimmed_logs = []
    for row in rows:
        row_dict = dict(zip(columns, row))
        row_dict['message'] = trim_aprs_message(row_dict['message'])
        trimmed_logs.append(row_dict)

    print(f"DEBUG: Data about to be JSONified: {trimmed_logs}", file=sys.stderr) # Keep this for debugging

    return trimmed_logs

@app.route('/logs')
def get_logs():
    print("DEBUG: /logs endpoint hit", file=sys.stderr)
    try:
        logs = query_audit_log()
        return jsonify(logs)
    except Exception as e:
        import traceback
        error_msg = f"Error fetching logs: {e}\n{traceback.format_exc()}"
        print(f"DEBUG: Caught exception in /logs: {error_msg}", file=sys.stderr)
        app.logger.error(error_msg)
        return jsonify({"error": "An internal server error occurred."}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
