import socket
import time
import random
import sys

from .aprs import Handler 

# --- Configuration ---
APRS_IS_SERVER = 'rotate.aprs2.net'
APRS_IS_PORT = 14580
BOT_ALIAS = 'ERLI'  # Destination alias
LOGIN_CALL = 'KC2NJV-10'
PASSCODE = '16569'  # Make sure this is your true passcode

def send_aprs_message(message_text):
    print(f"Attempting to send message: '{message_text}' from {LOGIN_CALL} to {BOT_ALIAS} using Ioreth Handler.")

    aprs_handler = Handler(callsign=LOGIN_CALL)
    aprs_handler.destination = BOT_ALIAS
    
    # === Critical fix: Set path to APRS-IS digipeater path ===
    aprs_handler.path = "TCPIP,qAR"  # This flags message as APRS-IS originated
    
    msg_id = str(random.randint(100, 999))
    message_with_id = f"{message_text}{{{msg_id}}}"

    aprs_frame = aprs_handler.make_aprs_msg(to_call=BOT_ALIAS, text=message_with_id)

    aprs_message_frame_bytes = aprs_frame.to_aprs_string() + b'\n'

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.settimeout(15) 
            sock.connect((APRS_IS_SERVER, APRS_IS_PORT))
            print(f"Connected to APRS-IS server: {APRS_IS_SERVER}:{APRS_IS_PORT}")

            login = f'user {LOGIN_CALL} pass {PASSCODE} vers aprs-message-sender 1.0\n'
            sock.sendall(login.encode())
            print(f"Sent login: {login.strip()}")

            time.sleep(3)

            sock.sendall(aprs_message_frame_bytes)
            print(f"Sent APRS Message (via Ioreth Handler): {aprs_message_frame_bytes.decode('utf-8').strip()}")

            time.sleep(10)

            print("Message send sequence complete. Disconnecting.")

        except ConnectionRefusedError:
            print(f"ERROR: Connection refused. Ensure APRS-IS server is reachable and port {APRS_IS_PORT} is open.")
        except socket.timeout:
            print("ERROR: Connection timed out during connect or send. Network issue or server unresponsive.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

if __name__ == '__main__':
    if len(sys.argv) > 1:
        message_to_send = sys.argv[1]
        print(f"Using message from command line: {message_to_send}")
        send_aprs_message(message_to_send)
    else:
        print("No message provided as a command-line argument.")
        print("Usage (from /opt/aprsbot/): python -m ioreth.tatical_text_msg \"YOUR_MESSAGE_HERE\"")
