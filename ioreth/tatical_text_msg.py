import socket
import time
import random
import sys

# IMPORTANT: This is the critical change.
# When tatical_text_msg.py is run as a module (e.g., python -m ioreth.tatical_text_msg),
# it is part of the 'ioreth' package. To import 'aprs.py' (a sibling file),
# you must use a relative import.

# to Run from a cron job:  0 7,15,22 * * * cd /opt/aprsbot/ && /usr/bin/python -m ioreth.tatical_text_msg "NETMSG ERLI APRS NET Saturday 0800ET http://sbanetweb.com:8080"
from .aprs import Handler 

# --- Configuration ---
APRS_IS_SERVER = 'rotate.aprs2.net'
APRS_IS_PORT = 14580
BOT_ALIAS = 'ERLI'
LOGIN_CALL = 'KC2NJV-10'
PASSCODE = '16569' # Ensure this is correct for your callsign KC2NJV

def send_aprs_message(message_text):
    """
    Connects to APRS-IS and sends a direct message using the Ioreth Handler library.
    """
    print(f"Attempting to send message: '{message_text}' from {LOGIN_CALL} to {BOT_ALIAS} using Ioreth Handler.")

    # Initialize your Ioreth Handler with the sender's callsign
    aprs_handler = Handler(callsign=LOGIN_CALL)

    # Append a random message ID as per APRS specification and your bot's expectation
    msg_id = str(random.randint(100, 999))
    message_with_id = f"{message_text}{{{msg_id}}}"

    # Use the Handler's make_aprs_msg method to create the AX.25 Frame object.
    # This method internally handles the message formatting and uses ax25.py.
    aprs_frame = aprs_handler.make_aprs_msg(to_call=BOT_ALIAS, text=message_with_id)

    # Convert the AX.25 Frame object into the raw APRS-IS string format (bytes).
    # The .to_aprs_string() method is provided by the Frame class in ax25.py.
    # A newline character (b'\n') is appended as required by APRS-IS for packet termination.
    aprs_message_frame_bytes = aprs_frame.to_aprs_string() + b'\n'

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            # Set a timeout for all socket operations to prevent indefinite hangs
            sock.settimeout(15) 

            sock.connect((APRS_IS_SERVER, APRS_IS_PORT))
            print(f"Connected to APRS-IS server: {APRS_IS_SERVER}:{APRS_IS_PORT}")

            # APRS-IS login string, including callsign, passcode, and software version
            login = f'user {LOGIN_CALL} pass {PASSCODE} vers aprs-message-sender 1.0\n'
            sock.sendall(login.encode())
            print(f"Sent login: {login.strip()}")

            # Give the server time to process the login before sending the message
            time.sleep(3)

            # Send the fully constructed APRS message frame
            sock.sendall(aprs_message_frame_bytes)
            # Decode for printing, but send as bytes
            print(f"Sent APRS Message (via Ioreth Handler): {aprs_message_frame_bytes.decode('utf-8').strip()}")

            # Give the server time to process the message before closing the connection
            time.sleep(10)

            print("Message send sequence complete. Disconnecting.")

        except ConnectionRefusedError:
            print(f"ERROR: Connection refused. Ensure APRS-IS server is reachable and port {APRS_IS_PORT} is open.")
        except socket.timeout:
            print("ERROR: Connection timed out during connect or send. Network issue or server unresponsive.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

# --- Main Execution Block ---
if __name__ == '__main__':
    # Check if a message was provided as a command-line argument
    if len(sys.argv) > 1:
        message_to_send = sys.argv[1]
        print(f"Using message from command line: {message_to_send}")
        send_aprs_message(message_to_send)
    else:
        print("No message provided as a command-line argument.")
        print("Usage (from /opt/aprsbot/): python -m ioreth.tatical_text_msg \"YOUR_MESSAGE_HERE\"")
        # Example usage if no command-line argument is given (currently commented out)
        # test_message = "Netmsg Saturday morn 0800ET APRS NET"
        # send_aprs_message(test_message)