from flask import Flask, jsonify
from flask_cors import CORS
import sqlite3
import re
from datetime import datetime, timedelta
from pytz import timezone, utc
from collections import defaultdict

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

DB_FILE = '/opt/aprsbot/erli.db'
ET_ZONE = timezone('America/New_York')


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


def get_known_users():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT callsign FROM users")
    rows = cur.fetchall()
    conn.close()
    return set(r[0] for r in rows)


def deduplicate(rows):
    known_users = get_known_users()
    grouped = defaultdict(list)

    for row in rows:
        ts_utc, direction, source, dest, raw_msg, msgid, transport = row
        trimmed = clean_message(raw_msg)
        if not trimmed:
            continue

        # Skip CQ messages from unknown users
        if trimmed.startswith("CQ ") and source not in known_users:
            app.logger.info(f"Skipping CQ from unknown user: {source}")
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
                utc_dt = utc.localize(bucket_time)
                et_dt = utc_dt.astimezone(ET_ZONE)
                deduped.append({
                    'timestamp': et_dt.strftime('%Y-%m-%d %H:%M:%S'),
                    'source': bucket['source'],
                    'transport': bucket['transport'],
                    'trimmed_message': bucket['trimmed_message'],
                    'destinations': ' | '.join(sorted(destinations)),
                })
                bucket = msg.copy()
                bucket_time = msg_time
                destinations = {msg['destination']}

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

    return sorted(deduped, key=lambda x: x['timestamp'], reverse=True)


@app.route('/logs')
def get_logs():
    try:
        rows = fetch_rows()
        logs = deduplicate(rows)
        return jsonify(logs)
    except Exception as e:
        app.logger.error(f"🚨 ERROR in /logs route: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route('/users')
def get_users():
    try:
        conn = sqlite3.connect(DB_FILE, check_same_thread=False)
        cur = conn.cursor()
        cur.execute("SELECT callsign, timestamp FROM users ORDER BY timestamp DESC")
        rows = cur.fetchall()
        conn.close()
        users = [{'callsign': r[0], 'timestamp': r[1]} for r in rows]
        return jsonify({"users": users})
    except Exception as e:
        app.logger.error(f"🚨 ERROR in /users route: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/blist')
def get_blacklist():
    try:
        conn = sqlite3.connect(DB_FILE, check_same_thread=False)
        cur = conn.cursor()
        cur.execute("SELECT callsign, timestamp FROM blacklist ORDER BY timestamp DESC")
        rows = cur.fetchall()
        conn.close()
        users = [{'callsign': r[0], 'timestamp': r[1]} for r in rows]
        return jsonify({"users": users})
    except Exception as e:
        app.logger.error(f"🚨 ERROR in /blist route: {e}")
        return jsonify({"error": "Internal server error"}), 500

        
@app.route('/health')
def health_check():
    return jsonify({"status": "ok"}), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8081)

print("✅ Flask app loaded")
print("✅ Registered routes:")
for rule in app.url_map.iter_rules():
    print(f"🔗 {rule.endpoint}: {rule.rule}")
