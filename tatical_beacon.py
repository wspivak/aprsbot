import socket
import time

APRS_IS_SERVER = 'rotate.aprs2.net'
APRS_IS_PORT = 14580
CALLSIGN = 'ERLI'
LOGIN_CALL = 'KC2NJV-4'  # must be real
PASSCODE = '16569'  # replace with real passcode from https://apps.magicbug.co.uk/passcode/

BEACON_TEXT = '>ERLI tactical alias for KC2NJV-4'
POSITION = '!4040.33N/07331.98W-'  # or '!' + your latitude/longitude + symbol
SYMBOL = '-'  # house, or use other symbols as needed

def connect_and_beacon():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((APRS_IS_SERVER, APRS_IS_PORT))

        login = f'user {LOGIN_CALL} pass {PASSCODE} vers erli-beacon 1.0\n'
        sock.sendall(login.encode())

        time.sleep(2)

        # Build ERLI status frame
        frame = f"{CALLSIGN}>APRS:{POSITION}{BEACON_TEXT}\n"
        sock.sendall(frame.encode())

        print(f"Sent: {frame.strip()}")
        time.sleep(2)

if __name__ == '__main__':
    connect_and_beacon()
