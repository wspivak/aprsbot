import socket
import time

APRS_IS_SERVER = 'rotate.aprs2.net'
APRS_IS_PORT = 14580
CALLSIGN = 'xxx'
LOGIN_CALL = 'xxx  # must be real
PASSCODE = '1xxxx'  # replace with real passcode from https://apps.magicbug.co.uk/passcode/

BEACON_TEXT = '>x'
POSITION = '!4039.38N/07331.33W-'  # or '!' + your latitude/longitude + symbol
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
