
#lat=40^39.385N long=073^31.3378W

#PASSCODE = "16569"        # Replace with your APRS-IS passcode
#LAT = "4030.385N"          # Latitude in APRS format
#LON = "07300.34W"         # Longitude in APRS format


import socket
import time
import sys
import logging

# === CONFIGURATION ===
CALLSIGN = "KC2NJV-10"            # Use a licensed callsign
PASSCODE = "16569"       # Replace with correct APRS-IS passcode
SERVER = "rotate.aprs.net"
PORT = 14580

OBJECT_NAME = "ERLI-NET"         # Must be ≤ 9 characters
LAT = "4039.38N"
LON = "07331.34W"
SYMBOL_TABLE = "/"               # '/' = primary table, '\' = alternate
SYMBOL = ">"                     # Example: '>' = right arrow
COMMENT = "144.390MHz Net Check-In Now!"
INTERVAL = 15 * 60               # Send every 15 min
RUN_FOREVER = True               # Set to False to send once

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("erli-object")

def build_object_packet():
    # Timestamp: dummy value, real format is DDHHMMz
    timestamp = "111111z"
    name_field = OBJECT_NAME.ljust(9)[:9]  # Exactly 9 chars
    position = f"{LAT}/{LON}{SYMBOL}"
    return f"{CALLSIGN}>APRS,TCPIP*:=;{name_field}{timestamp}{position}{COMMENT}"

def send_beacon():
    try:
        logger.info("Connecting to APRS-IS...")
        with socket.create_connection((SERVER, PORT), timeout=10) as s:
            login = f"user {CALLSIGN} pass {PASSCODE} vers ERLI-Object 1.0\n"
            s.sendall(login.encode("utf-8"))
            resp = s.recv(1024).decode("utf-8").strip()
            logger.info(f"Server response: {resp}")


            if "unverified" in resp.lower():
                logger.warning("Your APRS-IS login was not verified — check your callsign and passcode!")

            packet = build_object_packet() + "\n"
            s.sendall(packet.encode("utf-8"))
            logger.info(f"Sent object beacon: {packet.strip()}")

    except Exception as e:
        logger.error(f"Beacon failed: {e}")

def main():
    if RUN_FOREVER:
        while True:
            send_beacon()
            time.sleep(INTERVAL)
    else:
        send_beacon()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Interrupted. Exiting.")
        sys.exit(0)
