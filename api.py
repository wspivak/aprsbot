from flask import Flask, jsonify
from flask_cors import CORS
import sqlite3
import re
from datetime import datetime, timedelta
from pytz import timezone, utc
from collections import defaultdict

app = Flask(__name__)
CORS(app)

DB_FILE = 'erli.db'
ET_ZONE = timezone('America/New_York')


import re

def clean_message(raw_msg):
    if not raw_msg:
        return None

    msg = raw_msg.strip()

    # Skip telemetry/ACKs/position junk
    if msg[0] in ('@', '!', '=', '/', '_', ';', '`', ':'):
        return None
    if re.match(r'^T#\d+', msg): return None
    if re.match(r'^ack\d+\}?$', msg.lower()): return None

    # Remove call aliases like <KC2NJV-7> or prefaces like ERLI :
    msg = re.sub(r'^<[^>]{3,10}>\s*', '', msg)
    msg = re.sub(r'^[A-Z0-9\-]{3,9}\s*:\s*', '', msg)

    # Match proword and body
    m = re.match(r'^(netmsg|netmrg|msg|mrg|cq)\b\s+(.*)', msg, re.IGNORECASE)
    if not m:
        return None

    proword = m.group(1).lower()
    body = m.group(2).strip()

    # Strip trailing {xxx}, even if malformed ({97, {77}
    body = re.sub(r'\s*\{[^\s{}]{1,6}\}?\s*$', '', body).strip()

    if not body:
        return None

    # Preserve "CQ", drop others
    return f"CQ {body}" if proword == "cq" else body


def fetch_rows():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    cur.execute("""
        SELECT
            STRFTIME('%Y-%m-%d %H:%M:%S', timestamp),
            direction,
            source,
            destination,
            message,
            msgid,
            transport
        FROM audit_log
        WHERE timestamp >= datetime('now', 'utc', '-7 days')
          AND COALESCE(rejected, 0) = 0
        ORDER BY timestamp ASC
    """)

    rows = cur.fetchall()
    conn.close()
    return rows

def deduplicate(rows):
    grouped = defaultdict(list)
    for row in rows:
        ts_utc, direction, source, dest, raw_msg, msgid, transport = row
        trimmed = clean_message(raw_msg)
        if not trimmed:
            continue
        grouped[(source, trimmed)].append({
            'timestamp_utc': ts_utc,
            'source': source,
            'destination': dest,
            'transport': transport,
            'trimmed_message': trimmed,
        })

    deduped = []
    for (source, trimmed), msgs in grouped.items():
        msgs.sort(key=lambda x: x['timestamp_utc'])
        bucket = None
        destinations = set()

        for msg in msgs:
            msg_time = datetime.strptime(msg['timestamp_utc'], '%Y-%m-%d %H:%M:%S')
            if bucket is None:
                bucket = msg.copy()
                bucket_time = msg_time
                destinations = {msg['destination']}
            elif msg_time - bucket_time <= timedelta(minutes=3):
                destinations.add(msg['destination'])
            else:
                # Finalize previous bucket
                utc_dt = utc.localize(bucket_time)
                et_dt = utc_dt.astimezone(ET_ZONE)
                deduped.append({
                    'timestamp': et_dt.strftime('%Y-%m-%d %H:%M:%S'),
                    'source': bucket['source'],
                    'transport': bucket['transport'],
                    'trimmed_message': bucket['trimmed_message'],
                    'destinations': ' | '.join(sorted(destinations)),
                })
                # Start new bucket
                bucket = msg.copy()
                bucket_time = msg_time
                destinations = {msg['destination']}

        # Add final group
        if bucket:
            utc_dt = utc.localize(bucket_time)
            et_dt = utc_dt.astimezone(ET_ZONE)
            deduped.append({
                'timestamp': et_dt.strftime('%Y-%m-%d %H:%M:%S'),
                'source': bucket['source'],
                'transport': bucket['transport'],
                'trimmed_message': bucket['trimmed_message'],
                'destinations': ' | '.join(sorted(destinations)),
            })

    # Sort newest -> oldest
    return sorted(deduped, key=lambda x: x['timestamp'], reverse=True)

@app.route('/logs')
def get_logs():
    try:
        rows = fetch_rows()
        logs = deduplicate(rows)
        return jsonify(logs)
    except Exception as e:
        print(f"🚨 ERROR: {e}")
        return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8081)
