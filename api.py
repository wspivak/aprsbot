from flask import Flask, jsonify
from flask_cors import CORS
import sqlite3
import re
import sys
from datetime import datetime, timedelta
from pytz import timezone, utc
from collections import defaultdict

app = Flask(__name__)
CORS(app)

DATABASE = 'erli.db'

# -----------------------------
# Utility: Clean/truncate message content (remove NETMSG prefix)
# -----------------------------
def trim_aprs_message(message):
    pattern = r'^(NETMSG|MSG)\s+(.*)'
    match = re.match(pattern.strip(), message.strip(), re.IGNORECASE)
    return match.group(2).strip() if match else message.strip()

# -----------------------------
# Core logic: Query SQLite and deduplicate messages
# -----------------------------
def query_audit_log_deduplicated():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    print("DEBUG: Inside query function", file=sys.stderr)

    # Fetch raw data
    cursor.execute("""
        SELECT
            STRFTIME('%Y-%m-%d %H:%M:%S', al.timestamp) AS timestamp_utc,
            TRIM(LOWER(al.direction)) AS direction,
            TRIM(LOWER(al.source)) AS source,
            TRIM(al.message) AS message,
            TRIM(LOWER(al.destination)) AS destination,
            REPLACE(TRIM(al.msgid), X'0D', '') AS msgid,
            al.transport AS transport,
            al.rejected AS rejected
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
            AND (
                LOWER(al.message) LIKE '%cq%' OR
                LOWER(al.message) LIKE '%netmsg%' OR
                LOWER(al.message) LIKE 'msg %'
            )
            AND eu.callsign IS NOT NULL
            AND bl.callsign IS NULL
        ORDER BY
            al.timestamp ASC
    """)

    rows = cursor.fetchall()
    conn.close()

    # Timezone setup
    utc_zone = utc
    et_zone = timezone('America/New_York')

    columns = ['timestamp_utc', 'direction', 'source', 'message', 'destination', 'msgid', 'transport', 'rejected']

    # Step 1: Group by (source, trimmed message)
    grouped = defaultdict(list)
    #for row in rows:
    #    row_dict = dict(zip(columns, row))
    #    trimmed_msg = trim_aprs_message(row_dict['message'])
    #    row_dict['trimmed_message'] = trimmed_msg
    #    grouped[(row_dict['source'], trimmed_msg)].append(row_dict)

    for row in rows:
        row_dict = dict(zip(columns, row))
    
        # Pre-sanitize and normalize
        original_message = row_dict['message'].strip()
        lowered = original_message.lower()
    
        is_netmsg = lowered.startswith("netmsg ") or lowered.startswith("msg ")
        is_cq = "cq" in lowered
    
        # Process NETMSG
        if is_netmsg:
            trimmed = trim_aprs_message(original_message)
            if not trimmed:
                continue  # skip blank/empty NETMSG content
            display_msg = trimmed
    
        # Process CQ
        elif is_cq:
            if not original_message:
                continue  # skip empty CQ messages
            display_msg = original_message
    
        else:
            continue  # skip anything not NETMSG or CQ
    
        # Skip null/empty payload just in case
        if not display_msg.strip():
            continue
    
        row_dict['trimmed_message'] = display_msg
        grouped[(row_dict['source'], display_msg)].append(row_dict)




    # Step 2: Deduplicate within 1-minute window
    deduped = []

    for (source, trimmed_msg), msgs in grouped.items():
        msgs.sort(key=lambda r: datetime.strptime(r['timestamp_utc'], '%Y-%m-%d %H:%M:%S'))

        bucket = None
        destinations = set()

        for row in msgs:
            row_time = datetime.strptime(row['timestamp_utc'], '%Y-%m-%d %H:%M:%S')

            if bucket is None:
                bucket = row.copy()
                destinations = {row['destination']}
            else:
                bucket_time = datetime.strptime(bucket['timestamp_utc'], '%Y-%m-%d %H:%M:%S')
                if (row_time - bucket_time) <= timedelta(minutes=3):
                    destinations.add(row['destination'])
                else:
                    # Finalize the last group
                    bucket['destinations'] = ' | '.join(sorted(destinations))
                    # Format timestamp to ET
                    utc_dt = utc_zone.localize(bucket_time)
                    et_dt = utc_dt.astimezone(et_zone)
                    et_time_str = f"{et_dt:%Y-%m-%d %H:%M}:00"
                    bucket['timestamp'] = et_time_str

                    # Drop unneeded fields
                    del bucket['timestamp_utc']
                    #del bucket['message']
                    deduped.append(bucket)

                    # Start new group
                    bucket = row.copy()
                    destinations = {row['destination']}

        # Add the final group
        if bucket:
            bucket_time = datetime.strptime(bucket['timestamp_utc'], '%Y-%m-%d %H:%M:%S')
            bucket['destinations'] = ' | '.join(sorted(destinations))
            utc_dt = utc_zone.localize(bucket_time)
            et_dt = utc_dt.astimezone(et_zone)
            et_time_str = f"{et_dt:%Y-%m-%d %H:%M}:00"
            bucket['timestamp'] = et_time_str

            del bucket['timestamp_utc']
            del bucket['message']
            deduped.append(bucket)
    deduped.sort(key=lambda r: r['timestamp'], reverse=True)
    print(f"DEBUG: Returning {len(deduped)} deduplicated entries", file=sys.stderr)
    return deduped

# -----------------------------
# Route: /logs
# -----------------------------
@app.route('/logs')
def get_logs():
    print("DEBUG: /logs endpoint hit", file=sys.stderr)
    try:
        logs = query_audit_log_deduplicated()
        return jsonify(logs)
    except Exception as e:
        import traceback
        error_msg = f"Error fetching logs: {e}\n{traceback.format_exc()}"
        print(f"DEBUG: Caught exception in /logs: {error_msg}", file=sys.stderr)
        return jsonify({"error": "An internal server error occurred."}), 500

# -----------------------------
# Run the server
# -----------------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
