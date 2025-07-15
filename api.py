from flask import Flask, jsonify
from flask_cors import CORS
import sqlite3
import re
import sys
from datetime import datetime, timedelta
from pytz import timezone, utc # Import timezone and utc

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
            STRFTIME('%Y-%m-%d %H:%M:%S', al.timestamp) AS full_timestamp, -- Get full timestamp for accurate conversion
            TRIM(LOWER(al.direction)) AS direction,
            TRIM(LOWER(al.source)) AS source,
            MIN(TRIM(al.message)) AS message,
            GROUP_CONCAT(TRIM(LOWER(al.destination)), ' | ') AS destinations,
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
            full_timestamp, -- Group by the full timestamp for now
            TRIM(LOWER(al.direction)),
            TRIM(LOWER(al.source))
        ORDER BY
            full_timestamp DESC;
    """)

    rows = cursor.fetchall()
    conn.close()

    columns = ['timestamp_utc', 'direction', 'source', 'message', 'destinations', 'msgid', 'transport', 'rejected']
    trimmed_logs = []

    # Define the UTC and ET timezones
    utc_zone = utc
    et_zone = timezone('America/New_York') # Eastern Time (ET) is typically America/New_York

    for row in rows:
        row_dict = dict(zip(columns, row))

        # Convert UTC timestamp to datetime object
        utc_datetime_str = row_dict['timestamp_utc']
        utc_datetime = datetime.strptime(utc_datetime_str, '%Y-%m-%d %H:%M:%S')

        # Localize the UTC datetime object to UTC timezone
        utc_datetime = utc_zone.localize(utc_datetime)

        # Convert UTC datetime to ET datetime
        et_datetime = utc_datetime.astimezone(et_zone)

        # Format the ET datetime to your desired string format
        # You want to group by 5-minute intervals in ET now
        et_year = et_datetime.year
        et_month = et_datetime.month
        et_day = et_datetime.day
        et_hour = et_datetime.hour
        et_minute_grouped = (et_datetime.minute // 5) * 5

        row_dict['timestamp'] = f"{et_year:04d}-{et_month:02d}-{et_day:02d} {et_hour:02d}:{et_minute_grouped:02d}:00"

        # Remove the original 'timestamp_utc' if you only want the ET one
        del row_dict['timestamp_utc']

        row_dict['message'] = trim_aprs_message(row_dict['message'])
        trimmed_logs.append(row_dict)

    # Re-sort the logs after conversion if needed, although the original SQL ORDER BY should be fine
    # if you changed the grouping in SQL.
    # For now, if the SQL ORDER BY is still on 'full_timestamp', the order should be preserved.
    # If you were to group by the new ET timestamp in SQL, you would need to adjust the SQL query accordingly.

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
