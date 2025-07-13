from flask import Flask, jsonify
from flask_cors import CORS
import sqlite3
import re
import sys
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app)

DATABASE = 'erli.db'

def trim_aprs_message(message):
    # Updated pattern to remove the netname requirement for NETMSG
    # Now it captures everything after 'NETMSG ' as the message content
    pattern = r'^(NETMSG)\s+(.*)'
    match = re.match(pattern.strip(), message.strip(), re.IGNORECASE)
    # If it's a NETMSG, return the captured group (the message content)
    # Otherwise, return the original message stripped of leading/trailing whitespace
    return match.group(2).strip() if match else message.strip()

def query_audit_log():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    print("DEBUG: Inside query_audit_log function", file=sys.stderr)

    # Modified SQL query to select a single message using MIN() instead of GROUP_CONCAT()
    cursor.execute("""
        SELECT
            STRFTIME('%Y-%m-%d %H:', al.timestamp) ||
            PRINTF('%02d', (CAST(STRFTIME('%M', al.timestamp) AS INT) / 5) * 5) ||
            ':00' AS grouped_timestamp,
            TRIM(LOWER(al.direction)) AS direction,
            TRIM(LOWER(al.source)) AS source,
            MIN(TRIM(al.message)) AS message, -- Changed from GROUP_CONCAT to MIN()
            GROUP_CONCAT(TRIM(LOWER(al.destination)), ' | ') AS destinations, -- Keep destinations concatenated
            MAX(REPLACE(TRIM(al.msgid), X'0D', '')) AS msgid,
            MAX(al.transport) AS transport,
            MAX(al.rejected) AS rejected
        FROM
            audit_log AS al
        LEFT JOIN
            users AS eu ON al.source = eu.callsign
        LEFT JOIN
            blacklist AS bl ON al.source = bl.callsign
        WHERE
            al.timestamp >= datetime('now', '-7 days')
            AND al.destination NOT LIKE 'BLN%'
            AND al.direction = 'recv'
            AND (LOWER(al.message) LIKE '%cq%' OR LOWER(al.message) LIKE '%netmsg%')
            AND eu.callsign IS NOT NULL
            AND bl.callsign IS NULL
        GROUP BY
            grouped_timestamp,
            TRIM(LOWER(al.direction)),
            TRIM(LOWER(al.source))
        ORDER BY
            grouped_timestamp DESC;
    """)

    rows = cursor.fetchall()
    conn.close()

    # The columns list remains the same as 'message' is the column name returned by MIN()
    columns = ['timestamp', 'direction', 'source', 'message', 'destinations', 'msgid', 'transport', 'rejected']
    trimmed_logs = []
    for row in rows:
        row_dict = dict(zip(columns, row))
        # No need to split and join for 'message' since it's a single value from MIN()
        row_dict['message'] = trim_aprs_message(row_dict['message'])
        trimmed_logs.append(row_dict)

    print(f"DEBUG: Data about to be JSONified: {trimmed_logs}", file=sys.stderr)
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
