# Ioreth - An APRS library and bot
# Copyright (C) 2020  Alexandre Erwin Ittner, PP5ITT <alexandre@ittner.com.br>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

import sys
import time
import logging
import configparser
import os
import re
import random
import sqlite3
import difflib


logging.basicConfig()
logger = logging.getLogger(__name__)

from cronex import CronExpression

from .clients import AprsClient
from . import aprs
from . import remotecmd
from . import utils

from collections import deque
import threading

# Global cache for recently sent messages to prevent processing echoes
recent_messages = deque()
recent_lock = threading.Lock()

def cache_sent_message(to_call, message):
    now = time.monotonic()
    with recent_lock:
        recent_messages.append((now, to_call, message))
        _cleanup_old_entries(now)

def is_loopback(to_call, message):
    now = time.monotonic()
    with recent_lock:
        _cleanup_old_entries(now)
        return any((t == to_call and m == message) for _, t, m in recent_messages)

def _cleanup_old_entries(current_time, ttl=30):
    while recent_messages and (current_time - recent_messages[0][0]) > ttl:
        recent_messages.popleft()


def is_br_callsign(callsign):
    return bool(re.match("P[PTUY][0-9].+", callsign.upper()))

class BotAprsHandler(aprs.Handler):
    KNOWN_COMMANDS = {
        "cq":          "CQ",
        "netmsg":      "NETMSG",
        "netcheckout": "NETCHECKOUT",
        "netusers":    "NETUSERS",
        "blacklist_add": "blacklist_add",
        "blacklist_del": "blacklist_del",
        "admin_add":     "admin_add",
        "admin_del":     "admin_del",
        "ping":       "ping",
        "?aprst":     "?aprst",
        "?ping?":     "?ping?",
        "version":    "version",
        "time":       "time",
        "help":       "help",
    }

    def __init__(self, callsign, client, config_file="aprsbot.conf"):
        """
        callsign      – your APRS callsign
        client        – the AprsClient instance
        config_file   – path to the aprsbot.conf file
        """
        super().__init__(callsign)
        self.callsign      = callsign
        self._client       = client
        self._config_file  = config_file

        self.db       = None
        self._dbfile  = None

        # load netname, aliases, dbfile
        self._load_config()

        # open or create SQLite DB
        if not self._dbfile:
            raise ValueError("Missing 'dbfile' in [aprs] config")
        self.db = sqlite3.connect(self._dbfile, check_same_thread=False)
        self._init_db()

    def _load_config(self):
        cfg = configparser.ConfigParser()
        # ← use the passed-in filename, not a literal
        cfg.read(self._config_file)

        self.netname = cfg.get("aprs", "netname").strip().upper()
        self.aliases = { self.callsign.upper() }
        aliases_from_config = cfg.get("aprs", "aliases", fallback="")
        self.aliases.update(
            alias.strip().upper()
            for alias in aliases_from_config.split(",")
            if alias.strip()
        )

        self._dbfile = cfg.get("aprs", "dbfile", fallback="erli.db").strip()

        # ensure directory exists & is writable
        db_dir = os.path.dirname(self._dbfile) or "."
        if not os.path.isdir(db_dir):
            os.makedirs(db_dir, exist_ok=True)
        if not os.access(db_dir, os.W_OK):
            raise RuntimeError(f"Cannot write to database directory: {db_dir}")

        logger.info(f"Using database file: {self._dbfile}")


    def beacon_as_erli(self, text="ERLI tactical alias active"):
        """Send a status beacon as 'ERLI' so APRS-IS learns the alias."""
        original_callsign = self.callsign
        self.callsign = "ERLI"  # temporarily pretend we're ERLI
        frame = self.make_aprs_status(text)
        self._client.enqueue_frame(frame)
        logger.info(f"Beaconed as ERLI: {text}")
        self.callsign = original_callsign

    def _init_db(self):
        cur = self.db.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS erli_users (
                callsign TEXT PRIMARY KEY,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS blacklist (
                callsign TEXT PRIMARY KEY,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS admins (
            callsign TEXT PRIMARY KEY,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cur.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                direction TEXT,         -- 'recv' or 'sent'
                source TEXT,            -- who sent the message or who it's being sent to
                destination TEXT,       -- where it was going (only for 'sent')
                message TEXT,           -- content
                msgid TEXT,              -- APRS msgid if available
                rejected BOOLEAN DEFAULT 0,
                note TEXT
            )
        """)
        
        self.db.commit()
 
    def exec_db(self, query, args=()):
        try:
            cur = self.db.cursor()
            cur.execute(query, args)
            self.db.commit()
        except Exception as e:
            logger.error(f"DB error: {e}")
 
    def _log_audit(self, direction, source, destination, message, msgid=None, rejected=False, note=None):

        try:
            cur = self.db.cursor()
            cur.execute("""
              INSERT INTO audit_log (direction, source, destination, message, msgid, rejected, note)
              VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (direction, source, destination, message, msgid, int(rejected), note))
            self.db.commit()
            
            logger.debug(f"Audit logged: {direction} {source} -> {destination}: {message}")
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")


    def is_admin(self, callsign):
        cur = self.db.cursor()
        cur.execute("SELECT 1 FROM admins WHERE callsign = ?", (callsign.upper(),))
        return cur.fetchone() is not None


    def sanitize_text(self, text):
        text = re.sub(r'\{\d+\}$', '', text.strip())
        return re.sub(r'\s+', ' ', text)


    def is_blacklisted(self, callsign):
        cur = self.db.cursor()
        cur.execute("SELECT 1 FROM blacklist WHERE callsign = ?", (callsign,))
        return cur.fetchone() is not None



    def detect_and_correct_command(self, input_qry):
        matches = difflib.get_close_matches(input_qry, self.KNOWN_COMMANDS, n=1, cutoff=0.8)
        if matches:
            return self.KNOWN_COMMANDS[matches[0]]
        return input_qry

    def detect_typo_command(self, qry):
        """
        Detects typos and suggests known command using fuzzy match.
        """
        matches = difflib.get_close_matches(qry, self.KNOWN_COMMANDS.keys(), n=1, cutoff=0.8)
        if matches:
            return matches[0]
        return None


    def on_aprs_message(self, source, addressee, text, origframe, msgid=None, via=None):
        logger.info("Processing APRS message: from=%s to=%s text=%s msgid=%s via=%s",
                            source, addressee, text, msgid, via)
        logger.warning(f"APRS MSG RECEIVED: from={source} to={addressee} via={via} text={text}")

        cleaned = self.sanitize_text(text)

        # Handle 'rej0' control messages immediately
        if cleaned == "rej0":
            logger.debug("Ignoring 'rej0' control message.")
            return

        logger.info(f"Sanitized text: '{cleaned}'")
        
        clean_source = source.replace("*", "")
        upper_addressee = addressee.strip().upper()
        
        # Check if the message is a loopback
        # If it's a loopback to an alias, we allow it to be processed further,
        # otherwise, we reject it as a loopback and log it.
        if is_loopback(source, text):
            if upper_addressee in self.aliases:
                logger.debug(f"Allowing looped-back message to alias {upper_addressee}")
            else:
                logger.warning(f"Ignoring loopback message from {source} to {addressee}: {text}")
                self._log_audit(
                    direction="recv",
                    source=source,
                    destination=addressee,
                    message=text,
                    msgid=msgid,
                    rejected=True,
                    note="Loopback detected and rejected"
                )
                return
        
        # Check if the addressee is an alias of this bot
        logger.info(f"Checking if addressee '{upper_addressee}' is in aliases: {self.aliases}")
        if upper_addressee not in self.aliases:
            logger.warning(f"Ignoring message to {upper_addressee} — not in aliases.")
            self._log_audit(
                direction="recv",
                source=clean_source,
                destination=upper_addressee,
                message=cleaned,
                msgid=msgid,
                rejected=True,
                note="Addressee not in aliases"
            )
            return
        
        # Check if the direct source callsign is blacklisted
        if self.is_blacklisted(clean_source):
            logger.info(f"Ignoring message from blacklisted callsign: {clean_source}")
            self._log_audit(
                direction="recv",
                source=clean_source,
                destination=upper_addressee,
                message=cleaned,
                msgid=msgid,
                rejected=True,
                note="Blacklisted direct source"
            )
            return
        
        # Check for encapsulated source and its blacklist status
        force_tcpip_reply = False # Retained for compatibility if used elsewhere
        if "}" in text:
            try:
                payload = text.split("}", 1)[1]
                if ">" in payload and ":" in payload:
                    inner_src, rest = payload.split(">", 1)
                    inner_path = rest.split(":", 1)[0]
                else:
                    raise ValueError("Encapsulated frame missing delimiter")

                if self.is_blacklisted(inner_src):
                    logger.info(f"Ignoring encapsulated message from blacklisted callsign: {inner_src}")
                    self._log_audit(
                        direction="recv",
                        source=inner_src,
                        destination=upper_addressee,
                        message=cleaned,
                        msgid=msgid,
                        rejected=True,
                        note="Blacklisted encapsulated source"
                    )
                    return
        
                if "TCPIP" in inner_path:
                    force_tcpip_reply = True
        
            except Exception as e:
                logger.warning("Could not parse encapsulated frame: %s", e)
        
        # Process user query and get a flag indicating if a command was handled
        was_command_handled = self.handle_aprs_query(clean_source, cleaned, origframe=origframe) 
        
        # Send ACK if a message ID is present
        if msgid:
            logger.info(f"Sending ack to message {msgid} from {clean_source}")
            # Explicitly mark as ACK to prevent audit logging
            self.send_aprs_msg(clean_source, f"ack{msgid}", is_ack=True)

        # Log the received message to the audit log after all processing
        # This occurs only if the message was not rejected by earlier checks.
        self._log_audit(
            direction="recv",
            source=clean_source,
            destination=upper_addressee,
            message=cleaned,
            msgid=msgid,
            rejected=False,
            note=f"Received and processed. Command handled: {was_command_handled}"
        )


    def handle_aprs_query(self, source, text, origframe):
        logger.info(f"handle_aprs_query called with text: '{text}' from {source}")
        logger.info("Handling query from %s: %s", source, text)
        
        replies = {
            "help": "Commands: ping, version, time, help, blacklist_add <CALL>, blacklist_del <CALL>, admin_add <CALL>, admin_del <CALL>"
        }

        clean_source = source.replace("*", "")
        # Ensure stripping happens after sanitization
        text = self.sanitize_text(text).strip() 
        qry_args = text.split(" ", 1)
        qry = qry_args[0]
        args = qry_args[1] if len(qry_args) == 2 else ""

        qry_lower = qry.lower()
        corrected_qry = self.detect_and_correct_command(qry_lower)

        # Flag to indicate if a command was successfully handled
        command_executed = False 

        if corrected_qry != qry_lower:
            logger.info(f"Corrected command from '{qry}' to '{corrected_qry}' for {clean_source}")
            self.send_aprs_msg(clean_source, f"Interpreting '{qry}' as '{corrected_qry}'")
            qry_lower = corrected_qry # Use the corrected query for further processing

        # If the command isn't in our known commands after correction attempt
        # Use .keys() for checking existence in the dictionary
        if qry_lower not in self.KNOWN_COMMANDS.keys(): 
            self.send_aprs_msg(clean_source, f"Unknown command '{qry}'. Send 'help' for valid commands.")
            return False # Command not recognized or executed

        # Combine corrected query and args for normalized comparison
        normalized_command_args = f"{corrected_qry} {args}".strip().upper()

        # Net related commands
        if normalized_command_args.startswith(f"CQ {self.netname.upper()}"): # Ensure netname is upper for comparison
            # Use re.escape() for self.netname to handle special characters if any
            match = re.match(rf"^CQ\s+{re.escape(self.netname)}\s+(.+)", text, re.IGNORECASE)
            if match:
                self._broadcast_to_net(clean_source, match.group(1).strip())
                command_executed = True
            return command_executed # Return here as CQ is handled

        if normalized_command_args.startswith(f"NETMSG {self.netname.upper()}"): # Ensure netname is upper for comparison
            match = re.match(rf"^NETMSG\s+{re.escape(self.netname)}\s+(.+)", text, re.IGNORECASE)
            if match:
                cur = self.db.cursor()
                cur.execute("SELECT 1 FROM erli_users WHERE callsign = ?", (clean_source,))
                if not cur.fetchone():
                    # Log the failed attempt to the audit log
                    self._log_audit(
                        direction="recv",
                        source=clean_source,
                        destination=self.callsign,
                        message=text,
                        msgid=None,
                        rejected=True,
                        note="NETMSG attempt by unregistered user"
                    )
                    self.send_aprs_msg(clean_source, f"You're not registered on {self.netname}. Send 'CQ {self.netname} <msg>' first.")
                    return False # Command not executed successfully

                self._broadcast_message(clean_source, match.group(1).strip())
                command_executed = True
            return command_executed # Return here as NETMSG is handled

        if normalized_command_args == f"NETCHECKOUT {self.netname.upper()}":
            self._remove_user(clean_source)
            command_executed = True
            return command_executed # Return here as NETCHECKOUT is handled

        if normalized_command_args == f"NETUSERS {self.netname.upper()}":
            self._send_user_list(clean_source)
            command_executed = True
            return command_executed # Return here as NETUSERS is handled

        # Admin commands - require admin privileges
        if qry_lower in ["blacklist_add", "blacklist_del", "admin_add", "admin_del"] and args:
            if not self.is_admin(clean_source):
                self.send_aprs_msg(clean_source, "Admin privileges required for this command.")
                # Log unauthorized access attempt
                self._log_audit(
                    direction="recv",
                    source=clean_source,
                    destination=self.callsign,
                    message=text,
                    msgid=None,
                    rejected=True,
                    note=f"Unauthorized attempt to '{qry_lower}' by non-admin"
                )
                return False # Command not executed due to lack of privileges

            if qry_lower == "blacklist_add":
                self.exec_db("INSERT OR IGNORE INTO blacklist (callsign) VALUES (?)", (args.upper(),))
                self.send_aprs_msg(clean_source, f"{args.upper()} has been blacklisted.")
            elif qry_lower == "blacklist_del":
                self.exec_db("DELETE FROM blacklist WHERE callsign = ?", (args.upper(),))
                self.send_aprs_msg(clean_source, f"{args.upper()} removed from blacklist.")
            elif qry_lower == "admin_add":
                self.exec_db("INSERT OR IGNORE INTO admins (callsign) VALUES (?)", (args.upper(),))
                self.send_aprs_msg(clean_source, f"{args.upper()} is now an admin.")
            elif qry_lower == "admin_del":
                self.exec_db("DELETE FROM admins WHERE callsign = ?", (args.upper(),))
                self.send_aprs_msg(clean_source, f"{args.upper()} removed from admins.")
            
            command_executed = True
            return command_executed # Return after handling admin commands


        # Standard general commands
        if qry_lower == "ping":
            logger.info(f"Detected ping command from {clean_source}, args: '{args}' - sending pong reply")
            self.send_aprs_msg(clean_source, "Pong! " + args)
            command_executed = True
        elif qry_lower in ["?aprst", "?ping?"]:
            try:
                frame_str = origframe.to_aprs_string().decode("utf-8", errors="replace")
                self.send_aprs_msg(clean_source, frame_str.split("::", 2)[0] + ":")
                command_executed = True
            except Exception as e:
                logging.error("Error responding to ?aprst: %s", e)
        elif qry_lower == "version":
            self.send_aprs_msg(clean_source, "Python " + sys.version.replace("\n", " "))
            command_executed = True
        elif qry_lower == "time":
            self.send_aprs_msg(clean_source, "Localtime is " + time.strftime("%Y-%m-%d %H:%M:%S UTC%Z"))
            command_executed = True
        elif qry_lower == "help":
            self.send_aprs_msg(clean_source, replies[qry_lower])
            command_executed = True
        else:
            # Fallback for unrecognized commands or general messages
            if is_br_callsign(clean_source):
                self.send_aprs_msg(clean_source, "Sou um bot. Envie 'help' para a lista de comandos")
            else:
                self.send_aprs_msg(clean_source, "I'm a bot. Send 'help' for command list")
            command_executed = True # Even if it's a generic info message, it's a handled interaction.

        return command_executed # Return the flag indicating if a command was executed

    # --- End of handle_aprs_query ---

    def _broadcast_to_net(self, source, payload):
        cur = self.db.cursor()
        cur.execute("SELECT 1 FROM erli_users WHERE callsign = ?", (source,))
        if not cur.fetchone():
            cur.execute("INSERT INTO erli_users (callsign) VALUES (?)", (source,))
            logging.info(f"Added {source} to {self.netname} heard list")
        self.db.commit()

        cur.execute("SELECT callsign FROM erli_users")
        for callsign, in cur.fetchall():
            msg = f"<{source}> {payload}"
            # Ensure _broadcast_to_net uses send_aprs_msg, which now has the is_ack parameter
            # This is a regular message, not an ACK.
            self.send_aprs_msg(callsign, msg, is_ack=False)

    def send_aprs_status(self, status):
        # Assuming _client is the APRS client that handles enqueue_frame
        self._client.enqueue_frame(self.make_aprs_status(status))
        # This call seems to send a separate message from the status update itself
        # Consider if this should also be subject to audit logging or if it's a special system message
        self.send_aprs_msg("APRS", ">ERLI is active here at KC2NJV-4.", is_ack=False)


    def _broadcast_message(self, source, message):
        cur = self.db.cursor()
        cur.execute("SELECT callsign FROM erli_users")
        for callsign, in cur.fetchall():
            # Broadcasted messages are regular messages, not ACKs
            self.send_aprs_msg(callsign, message, is_ack=False)
            logging.info(f"Broadcast from {source} to {callsign}: {message}")

    def _remove_user(self, source):
        self.db.cursor().execute("DELETE FROM erli_users WHERE callsign = ?", (source,))
        self.db.commit()
        logging.info(f"Removed {source} from {self.netname}")
        self.send_aprs_msg(source, "NETCheckOUT Successful", is_ack=False)

    def _send_user_list(self, source):
        cur = self.db.cursor()
        cur.execute("SELECT callsign FROM erli_users ORDER BY timestamp DESC LIMIT 10")
        rows = cur.fetchall()
        reply = "Last 10 users:\n" + ", ".join(row[0] for row in rows) if rows else f"No {self.netname} users heard yet."
        self.send_aprs_msg(source, reply, is_ack=False)
        logging.info(f"Sent user list to {source}")

    def send_aprs_msg(self, to_call, text, is_ack=False): # Added is_ack parameter with default False
        if not self._client.is_connected():
            logger.warning(f"Client not connected - cannot send message to {to_call}")
            return

        logger.info("Sending APRS message to %s: %s", to_call, text)
        frame = self.make_aprs_msg(to_call, text)
        logger.info("Built APRS frame: %s", frame.to_aprs_string())
        self._client.enqueue_frame(frame)
        logger.info("Frame enqueued to APRS-IS: %s", frame.to_aprs_string())
        # Assuming cache_sent_message is defined elsewhere
        cache_sent_message(to_call, text)
        
        # Only log to audit if it's not an ACK message to prevent audit log clutter
        if not is_ack:
            self._log_audit(
                direction="sent",
                source=self.callsign, # The bot's callsign is the source of sent messages
                destination=to_call,
                message=text,
                msgid=None # msgid is typically for received messages, not generated sent messages
            )

        
class SystemStatusCommand(remotecmd.BaseRemoteCommand):
    def __init__(self, cfg):
        remotecmd.BaseRemoteCommand.__init__(self, "system-status")
        self._cfg = cfg
        self.status_str = ""

    def run(self):
        net_status = (
            self._check_host_scope("Eth", "eth_host")
            + self._check_host_scope("Inet", "inet_host")
            + self._check_host_scope("DNS", "dns_host")
            + self._check_host_scope("VPN", "vpn_host")
        )
        self.status_str = "At %s: Uptime %s" % (
            time.strftime("%Y-%m-%d %H:%M:%S UTC%Z"),
            utils.human_time_interval(utils.get_uptime()),
        )
        if len(net_status) > 0:
            self.status_str += "," + net_status

    def _check_host_scope(self, label, cfg_key):
        if not cfg_key in self._cfg:
            return ""
        ret = utils.simple_ping(self._cfg[cfg_key])
        return " " + label + (":Ok" if ret else ":Err")


class ReplyBot(AprsClient):
    def __init__(self, config_file):
        # 1) call parent ctor
        super().__init__()

        # 2) record the config path immediately
        self._config_file = config_file

        # 3) prepare config‐watcher state
        self._config_mtime = None
        self._cfg = configparser.ConfigParser()
        self._cfg.optionxform = str     # keep case sensitivity

        # 4) instantiate the APRS handler with the config path
        #    (empty callsign for now; real one will be set in _load_config)
        self._aprs = BotAprsHandler("", self, config_file=self._config_file)

        # 5) other state
        self._last_blns            = time.monotonic()
        self._last_cron_blns       = 0
        self._last_status          = time.monotonic()
        self._last_reconnect_attempt = 0
        self._rem                  = remotecmd.RemoteCommandHandler()

        # 6) now read the config and wire everything up
        self._check_updated_config()


    def _load_config(self):
        try:
            self._cfg.clear()
            self._cfg.read(self._config_file)
            self.addr = self._cfg["tnc"]["addr"]
            self.port = int(self._cfg["tnc"]["port"])

            # Get values from config
            callsign = self._cfg["aprs"]["callsign"]
            path = self._cfg["aprs"]["path"]

            # Initialize the APRS handler with the proper callsign and path
            self._aprs = BotAprsHandler(callsign, self, config_file=self._config_file)
            self._aprs.path = path

            logger.info(f"Bot initialized with callsign: {self._aprs.callsign}, aliases: {self._aprs.aliases}")

        except Exception as exc:
            logger.error("Failed to load config: %s", exc)
            logger.error(exc)

    def _check_updated_config(self):
        try:
            mtime = os.stat(self._config_file).st_mtime
            if self._config_mtime != mtime:
                self._load_config()
                self._config_mtime = mtime
                logger.info("Configuration reloaded")
        except Exception as exc:
            logger.error(exc)

    def on_connect(self):
        logger.info("Connected")

    def on_disconnect(self):
        logger.warning("Disconnected! Will try again soon...")

    def on_recv_frame(self, frame):
        logger.debug("Received frame object: %s", frame)
        try:
            logger.warning("RECV FRAME: %s", frame.to_aprs_string().decode(errors="replace"))
        except Exception:
            logger.warning("RECV FRAME (could not decode)")
        self._aprs.handle_frame(frame)


    def _update_bulletins(self):
        if not self._cfg.has_section("bulletins"):
            return

        try:
            max_age = int(self._cfg.get("bulletins", "send_freq", fallback="600"))
        except Exception as e:
            logger.warning(f"Invalid send_freq value in config, using default: {e}")
            max_age = 600


        now_mono = time.monotonic()  # Make sure this line comes before any logging involving now_mono
        now_time = time.time()
#        logger.debug(f"now_mono type: {type(now_mono)}")
#        logger.debug(f"self._last_blns type: {type(self._last_blns)}")
#        logger.debug(f"max_age type: {type(max_age)}")
#        logger.info(f"Type of self._last_blns: {type(self._last_blns)}, value: {self._last_blns}")
#        logger.info(f"Type of max_age: {type(max_age)}, value: {max_age}")
        try:
            self._last_blns = float(self._last_blns)
        except Exception:
            self._last_blns = 0.0





        # Optimization: return ASAP if nothing to do.
        if (now_mono <= (self._last_blns + max_age)) and (
            now_time <= (self._last_cron_blns + 60)
        ):
            return

        bln_map = dict()

        # Find all standard (non rule-based) bulletins.
        keys = self._cfg.options("bulletins")
        keys.sort()
        std_blns = [
            k for k in keys if k.startswith("BLN") and len(k) > 3 and "_" not in k
        ]

        # Do not run if time was not set yet (e.g. Raspberry Pis getting their
        # time from NTP but before conecting to the network)
        time_was_set = time.gmtime().tm_year > 2000

        # Map all matching rule-based bulletins.
        if time_was_set and now_time > (self._last_cron_blns + 60):
            # Randomize the delay until next check to prevent packet storms
            # in the first seconds following a minute. It will, of course,
            # still run within the minute.
            self._last_cron_blns = 60 * int(now_time / 60.0) + random.randint(0, 30)

            cur_time = time.localtime()
            try:
                utc_offset = int(cur_time.tm_gmtoff) / 3600  # UTC offset in hours
            except Exception as e:
                logger.exception("Failed to compute UTC offset")    
            ref_time = cur_time[:5]  # (Y, M, D, hour, min)

            for k in keys:
                # if key is "BLNx_rule_x", etc.
                lst = k.split("_", 3)
                if (
                    len(lst) == 3
                    and lst[0].startswith("BLN")
                    and lst[1] == "rule"
                    and (lst[0] not in std_blns)
                ):
                    expr = CronExpression(self._cfg.get("bulletins", k))
                    if expr.check_trigger(ref_time, utc_offset):
                        bln_map[lst[0]] = expr.comment

        # If we need to send standard bulletins now, copy them to the map.
        if now_mono > (self._last_blns + max_age):
            self._last_blns = now_mono
            for k in std_blns:
                bln_map[k] = self._cfg.get("bulletins", k)

        if len(bln_map) > 0:
            to_send = [(k, v) for k, v in bln_map.items()]
            to_send.sort()
            for (bln, text) in to_send:
                logger.info("Posting bulletin: %s=%s", bln, text)
                self._aprs.send_aprs_msg(bln, text)

    def _update_status(self):
        if not self._cfg.has_section("status"):
            return
        max_age = self._cfg.getint("status", "send_freq", fallback=600)
        now_mono = time.monotonic()
        
#        logger.debug(f"now_mono type: {type(now_mono)}")
#        logger.debug(f"self._last_status type: {type(self._last_status)}")
#        logger.debug(f"max_age type: {type(max_age)}")
#        logger.info(f"Type of self._last_status: {type(self._last_status)}, value: {self._last_status}")
#        logger.info(f"Type of max_age: {type(max_age)}, value: {max_age}")
        try:
            self._last_status = float(self._last_status)
        except Exception:
            self._last_status = 0.0

        if now_mono < (self._last_status + max_age):
            return

        self._last_status = now_mono
        self._rem.post_cmd(SystemStatusCommand(self._cfg["status"]))

    def _check_reconnection(self):
#        logger.debug(f"last reconnect attempt type: {type(self._last_reconnect_attempt)}")
#        logger.info(f"Type of self._last_reconnect_attempt: {type(self._last_reconnect_attempt)}, value: {self._last_reconnect_attempt}")
        try:
            self._last_reconnect_attempt = float(self._last_reconnect_attempt)
        except Exception:
            self._last_reconnect_attempt = 0.0

        if self.is_connected():
            return

        try:
            if time.monotonic() > self._last_reconnect_attempt + 5: 
                logger.info("Trying to reconnect")
                self._last_reconnect_attempt = time.monotonic()
                self.connect()
        except ConnectionRefusedError as e:
            logger.warning(e)

    def on_loop_hook(self):
        AprsClient.on_loop_hook(self)
        self._check_updated_config()
        self._check_reconnection()
        self._update_bulletins()
        self._update_status()

        # 🌐 Beacon as ERLI every 15 minutes or so    
        now = time.monotonic()
        if not hasattr(self, "_last_erli_beacon"):
            self._last_erli_beacon = 0
        if now - self._last_erli_beacon > 900:  # 15 minutes
            self._last_erli_beacon = now
            self._aprs.beacon_as_erli("ERLI tactical alias for KC2NJV-4")
            
        # Poll results from external commands, if any.
        while True:
            rcmd = self._rem.poll_ret()
            if not rcmd:
                break
            self.on_remote_command_result(rcmd)

    def on_remote_command_result(self, cmd):
        logger.debug("ret = %s", cmd)

        if isinstance(cmd, SystemStatusCommand):
            self._aprs.send_aprs_status(cmd.status_str)
