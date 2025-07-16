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

def trim_aprs_message(message):
    # Trim NETMSG / MSG command prefixes
    pattern = r'^(NETMSG|MSG|NETMRG|MRG)\s+(.*)'
    match = re.match(pattern, message.strip(), re.IGNORECASE)
    return match.group(2).strip() if match else message.strip()

def query_audit_log_deduplicated():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

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
            AND al.direction = 'recv'
            AND eu.callsign IS NOT NULL
            AND bl.callsign IS NULL
        ORDER BY
            al.timestamp ASC
    """)
    rows = cursor.fetchall()
    conn.close()

    utc_zone = utc
    et_zone = timezone('America/New_York')
    columns = ['timestamp_utc', 'direction', 'source', 'message', 'destination', 'msgid', 'transport', 'rejected']

    # Step 1: Filter and group messages by prefix
    grouped = defaultdict(list)
    for row in rows:
        row_dict = dict(zip(columns, row))
        original_message = (row_dict['message'] or '').strip()
        lowered = original_message.lower()

        # new allowed prefixes
        if lowered.startswith("netmsg ") or lowered.startswith("netmrg "):
            trimmed = trim_aprs_message(original_message)
            if not trimmed:
                continue
            display_msg = trimmed
        
        elif lowered.startswith("msg ") or lowered.startswith("mrg "):
            trimmed = trim_aprs_message(original_message)
            if not trimmed:
                continue
            display_msg = trimmed
        
        elif lowered.startswith("cq"):
            display_msg = original_message
        
        else:
            continue   # ❌ Skip anything not starting with NETMSG / MSG / CQ

        # Double-check message isn't blank
        if not display_msg.strip():
            continue

        row_dict['trimmed_message'] = display_msg
        grouped[(row_dict['source'], display_msg)].append(row_dict)

    # Step 2: Deduplicate within 3-minute window
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
                    bucket['destinations'] = ' | '.join(sorted(destinations))
                    utc_dt = utc_zone.localize(bucket_time)
                    et_dt = utc_dt.astimezone(et_zone)
                    bucket['timestamp'] = f"{et_dt:%Y-%m-%d %H:%M}:00"
                    del bucket['timestamp_utc']
                    deduped.append(bucket)
                    bucket = row.copy()
                    destinations = {row['destination']}

        # Final group push
        if bucket:
            bucket_time = datetime.strptime(bucket['timestamp_utc'], '%Y-%m-%d %H:%M:%S')
            bucket['destinations'] = ' | '.join(sorted(destinations))
            utc_dt = utc_zone.localize(bucket_time)
            et_dt = utc_dt.astimezone(et_zone)
            bucket['timestamp'] = f"{et_dt:%Y-%m-%d %H:%M:%S}"
            del bucket['timestamp_utc']
            deduped.append(bucket)

    # Sort final list (newest first)
    deduped.sort(key=lambda r: r['timestamp'], reverse=True)
    return deduped

@app.route('/logs')
def get_logs():
    try:
        logs = query_audit_log_deduplicated()
        return jsonify(logs)
    except Exception as e:
        import traceback
        print(f"DEBUG: log API error {e}\n{traceback.format_exc()}", file=sys.stderr)
        return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8081)
