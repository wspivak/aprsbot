import sys
import time
import logging
import configparser
import os
import re
import random
import sqlite3
import difflib
import hashlib  
import sqlite3
import time

# Configure the logging
logging.basicConfig(
    level=logging.DEBUG,  # Set the minimum logging level (INFO, DEBUG, WARNING, ERROR, CRITICAL)
    format='%(asctime)s - %(levelname)s - %(message)s', # This format string includes the timestamp
    handlers=[
        logging.FileHandler("/opt/aprsbot/logs/replybot.log"), # Log to the specified file
        logging.StreamHandler(sys.stdout) # Also log to console (optional, but good for debugging)
    ]
)
logger = logging.getLogger(__name__)

from cronex import CronExpression

from .clients import AprsIsClient
from .clients import AprsIsClient, RfKissClient

from . import aprs
from . import remotecmd
from . import utils

from collections import deque

DEDUP_TTL = 3600  # 60 minutes

# ---- Persistent Deduplication with SQLite ----

DEDUP_DB = '/opt/aprsbot/audit_log.db'
conn = sqlite3.connect(DEDUP_DB, isolation_level=None, check_same_thread=False)
# isolation_level=None will autocommit transactions (no explicit commit needed).

# Create the dedup table if it doesn't exist
conn.execute("""
CREATE TABLE IF NOT EXISTS dedup_cache (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT,
    destination TEXT,
    text TEXT,
    msg_time INTEGER
)
""")

def is_duplicate_sqlite(conn, source, dest, text):
    now = int(time.time())
    key = (str(source).strip().lower(), str(dest).strip().lower(), str(text).strip().lower())
    conn.execute("DELETE FROM dedup_cache WHERE ? - msg_time > ?", (now, DEDUP_TTL))
    cur = conn.execute(
        "SELECT 1 FROM dedup_cache WHERE source=? AND destination=? AND text=?",
        key
    )
    if cur.fetchone():
        logger.debug(f"[DEDUP-TRACE] Duplicate hit, key={key}")
        return True
    conn.execute(
        "INSERT INTO dedup_cache (source, destination, text, msg_time) VALUES (?, ?, ?, ?)",
        (*key, now)
    )
    logger.debug(f"[DEDUP-TRACE] New dedup key inserted: {key}")
    return False


def is_loopback(to_call, message):
    # No longer needed—with SQLite-backed deduplication and message audit, true loopback detection is handled elsewhere.
    return False


def is_br_callsign(callsign):
    return bool(re.match("P[PTUY][0-9].+", callsign.upper()))

# Added for classifying Transport value
def classify_transport(via):
    if not via:
        return None
    if isinstance(via, str):
        path_elements = [item.strip().lower() for item in via.split(',')]
    elif isinstance(via, (list, tuple)):
        path_elements = [str(item).strip().lower() for item in via]
    else:
        return None
    aprsis_ids = {"tcpip", "qac", "qas", "qar", "qao", "qax"}
    if any(elem in aprsis_ids or elem.startswith("q") for elem in path_elements):
        return "APRS-IS"
    return "RF"



class BotAprsHandler(aprs.Handler):
    # CORRECTED __init__ METHOD - Combine both previous ones
    def __init__(self, callsign, client, config_file="aprsbot.conf"):
        """
        callsign – your APRS callsign
        client – the AprsClient instance
        config_file – path to the aprsbot.conf file
        """
        super().__init__(callsign)
        self.callsign = callsign
        self._client = client
        self._config_file = config_file

        self.db = None
        self._dbfile = None

        # Initialize KNOWN_COMMANDS as an empty dictionary, to be populated by _load_config
        # This will map user-typed command (lowercase) to its canonical name
        self.KNOWN_COMMANDS = {}

        # START CHANGE: Add a placeholder for the configurable response
        self.netcheckout_response = "NETCheckOUT Successful" # Default value
        # END CHANGE

        # load netname, aliases, dbfile, and commands
        self._load_config()

        # open or create SQLite DB for other data (users, blacklist, etc.)
        if not self._dbfile:
            raise ValueError("Missing 'dbfile' in [aprs] config")
        self.db = sqlite3.connect(self._dbfile, check_same_thread=False)
        self._init_db() # This will still initialize other tables like users, blacklist, admins, audit_log

    def _load_config(self):
        cfg = configparser.ConfigParser()
        cfg.optionxform = str # Keep case sensitivity for option names (command names)
        cfg.read(self._config_file)

        self.netname = cfg.get("aprs", "netname").strip().upper()
        self.aliases = { self.callsign.upper() }
        aliases_from_config = cfg.get("aprs", "aliases", fallback="")
        self.aliases.update(
            alias.strip().strip('"').upper()
            for alias in aliases_from_config.split(",")
            if alias.strip()
        )

        self._dbfile = cfg.get("aprs", "dbfile", fallback="erli.db").strip()

        # --- Load KNOWN_COMMANDS SOLELY from the [commands] section of the config file ---
        self.KNOWN_COMMANDS = {} # Clear existing commands on reload
        if cfg.has_section("commands"):
            for cmd_key, canonical_name in cfg.items("commands"):
                # Store lowercased command_key for lookup, canonical name as value
                self.KNOWN_COMMANDS[cmd_key.lower()] = canonical_name.strip()

        # Ensure 'help' is always available, even if not in config
        if 'help' not in self.KNOWN_COMMANDS:
             self.KNOWN_COMMANDS['help'] = 'help'

        self.beacon_message_template = cfg.get("aprs", "beacon_message", fallback="APRS Bot active").strip()
        self.user_defined_beacon_alias = cfg.get("aprs", "beacon_alias", fallback="NoAlias").strip()

        # START CHANGE: Load configurable responses
        self.netcheckout_response = cfg.get("responses", "netcheckout_success", fallback="NETCheckOUT Successful").strip()
        # END CHANGE

        # ensure directory exists & is writable
        db_dir = os.path.dirname(self._dbfile) or "."
        if not os.path.isdir(db_dir):
            os.makedirs(db_dir, exist_ok=True)
        if not os.access(db_dir, os.W_OK):
            raise RuntimeError(f"Cannot write to database directory: {db_dir}")

        logger.info(f"Using database file: {self._dbfile}")
        logger.info(f"Loaded commands from config: {list(self.KNOWN_COMMANDS.keys())}")

    # CORRECTED _init_db METHOD - Includes PRAGMAs and Indexes
    def _init_db(self):
        cur = self.db.cursor()

        # --- Set PRAGMAs for Performance ---
        cur.execute("PRAGMA journal_mode = WAL;")
        cur.execute("PRAGMA synchronous = NORMAL;")
        cur.execute("PRAGMA temp_store = MEMORY;")
        cur.execute("PRAGMA mmap_size = 67108864;")

        # --- Create Tables (Your existing code) ---
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
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
                direction TEXT,
                source TEXT,
                destination TEXT,
                message TEXT,
                msgid TEXT,
                rejected BOOLEAN DEFAULT 0,
                note TEXT,
                transport TEXT
            )
        """)

        # --- Add Indexes (New Section) ---
        cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log (timestamp);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_source ON audit_log (source);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_destination ON audit_log (destination);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_message ON audit_log (message);")

        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_log_group_by_order_by ON audit_log (
                direction,
                source,
                destination,
                message,
                msgid,
                rejected,
                transport,
                timestamp DESC
            );
        """)

        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_callsign ON users (callsign);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_blacklist_callsign ON blacklist (callsign);")

        # --- Final Commit for Tables and Indexes ---
        self.db.commit()

        # --- Analyze Database (Recommended after creating tables/indexes or significant data changes) ---
        cur.execute("ANALYZE;")
        self.db.commit()

    def exec_db(self, query, args=()):
        try:
            cur = self.db.cursor()
            cur.execute(query, args)
            self.db.commit()
        except Exception as e:
            logger.error(f"DB error: {e}")

    def _log_audit(self, direction, source, destination, message, msgid=None, rejected=False, note=None, transport=None):
        try:
            cur = self.db.cursor()
            cur.execute("""
                INSERT INTO audit_log (direction, source, destination, message, msgid, rejected, note, transport)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (direction, source, destination, message, msgid, int(rejected), note, transport))
            self.db.commit()
            logger.debug(f"Audit logged: {direction} {source} -> {destination}: {message} [{transport}]")
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
        matches = difflib.get_close_matches(input_qry, self.KNOWN_COMMANDS.keys(), n=1, cutoff=0.8)
        if matches:
            return self.KNOWN_COMMANDS[matches[0]]
        return input_qry

    def detect_typo_command(self, qry):
        matches = difflib.get_close_matches(qry, self.KNOWN_COMMANDS.keys(), n=1, cutoff=0.8)
        if matches:
            return matches[0]
        return None

    def on_aprs_message(self, source, addressee, text, origframe, msgid=None, via=None):
        """
        Handler for inbound APRS messages (data type ':'), with full dedupe, blacklist,
        alias, and loopback logic. Only processes unique, allowed messages for this bot instance.
        """
        # Normalize and prepare dedup key
        clean_source_l = str(source).replace("*", "").strip().lower()
        addressee_u = str(addressee).strip().upper()
        cleaned_text_l = str(text).strip().lower()
    
        # --- De-duplication ---
        if is_duplicate_sqlite(conn, clean_source_l, addressee_u.lower(), cleaned_text_l):
            logger.info(f"[DEDUP] Duplicate suppressed: {clean_source_l}->{addressee_u}: '{cleaned_text_l}'")
            return
    
        logger.debug(f"[DEDUP-TRACE] Checking key: ({clean_source_l}, {addressee_u.lower()}, {cleaned_text_l})")
        logger.info(f"Sanitized text: '{cleaned_text_l}'")
    
        # Prepare for logging/audit (preserving CQ, MSG, etc.)
        audit_source = source.replace("*", "").strip()
        audit_addressee = addressee_u
        audit_message = text.strip()
    
        # --- Loopback Protection ---
        if is_loopback(source, text):
            if addressee_u in self.aliases:
                logger.debug(f"Allowing looped-back message to alias {addressee_u}")
                # Proceed—may want to skip or allow depending on net rules
            else:
                logger.warning(f"Ignoring loopback message from {source} to {addressee_u}: {text}")
                self._log_audit(
                    direction="recv",
                    source=audit_source,
                    destination=audit_addressee,
                    message=audit_message,
                    msgid=msgid,
                    rejected=True,
                    note="Loopback detected and rejected",
                    transport=classify_transport(via) if via else "RF"
                )
                return
    
        # --- Alias Filtering ---
        logger.info(f"Checking if addressee '{addressee_u}' is in aliases: {self.aliases}")
        if addressee_u not in self.aliases:
            logger.warning(f"Ignoring message to {addressee_u} — not in aliases.")
            self._log_audit(
                direction="recv",
                source=audit_source,
                destination=audit_addressee,
                message=audit_message,
                msgid=msgid,
                rejected=True,
                note="Addressee not in aliases",
                transport=classify_transport(via) if via else "RF"
            )
            return
    
        # --- Blacklist Filtering (direct source) ---
        if self.is_blacklisted(clean_source_l):
            logger.info(f"Ignoring message from blacklisted callsign: {clean_source_l}")
            self._log_audit(
                direction="recv",
                source=audit_source,
                destination=audit_addressee,
                message=audit_message,
                msgid=msgid,
                rejected=True,
                note="Blacklisted direct source",
                transport=classify_transport(via) if via else "RF"
            )
            return
    
        # --- Blacklist Filtering (encapsulated/3rd-party source) ---
        if "}" in text:
            try:
                payload = text.split("}", 1)[1]
                if ">" in payload and ":" in payload:
                    encaps_src, rest = payload.split(">", 1)
                    if self.is_blacklisted(encaps_src.strip().lower()):
                        logger.info(f"Ignoring encapsulated message from blacklisted callsign: {encaps_src}")
                        self._log_audit(
                            direction="recv",
                            source=encaps_src.strip(),
                            destination=audit_addressee,
                            message=audit_message,
                            msgid=msgid,
                            rejected=True,
                            note="Blacklisted encapsulated source",
                            transport=classify_transport(via) if via else "RF"
                        )
                        return
                else:
                    raise ValueError("Encapsulated frame missing delimiter")
            except Exception as e:
                logger.warning(f"Could not parse encapsulated frame: {e}")
    
        # --- Main message/command processing ---
        was_command_handled = self.handle_aprs_query(audit_source, audit_message, origframe=origframe)
    
        # --- Acknowledge if msgid present and not a dedup ---
        if msgid:
            logger.info(f"Sending ack to message {msgid} from {audit_source}")
            self.send_aprs_msg(audit_source, f"ack{msgid}", is_ack=True)
    
        # --- Final audit logging ---
        self._log_audit(
            direction="recv",
            source=audit_source,
            destination=audit_addressee,
            message=audit_message,  # Preserved with prefixes/punctuation intact
            msgid=msgid,
            rejected=False,
            note=f"Received and processed. Command handled: {was_command_handled}",
            transport=classify_transport(via) if via else "RF"
        )
    
    def handle_aprs_query(self, source, text, origframe, via=None):
            logger.info(f"handle_aprs_query called with text: '{text}' from {source}")
            logger.info("Handling query from %s: %s", source, text)
    
            via = via if via else None
            clean_source = source.replace("*", "")
            text = self.sanitize_text(text).strip()
            qry_args = text.split(" ", 1)
            qry = qry_args[0]
            args = qry_args[1] if len(qry_args) == 2 else ""
    
            qry_lower = qry.lower()
            corrected_qry = self.detect_and_correct_command(qry_lower)
    
            command_executed = False
    
            actual_command_to_process = None
            if corrected_qry != qry_lower and corrected_qry in self.KNOWN_COMMANDS.values():
                logger.info(f"Corrected command from '{qry}' to '{corrected_qry}' for {clean_source}")
#                self.send_aprs_msg(clean_source, f"Interpreting '{qry}' as '{corrected_qry}'")
                actual_command_to_process = corrected_qry
            elif qry_lower in self.KNOWN_COMMANDS:
                actual_command_to_process = self.KNOWN_COMMANDS[qry_lower]
            else:
                if is_br_callsign(clean_source):
                    self.send_aprs_msg(clean_source, "Sou um bot. Envie 'help' para a lista de comandos")
                else:
                    self.send_aprs_msg(clean_source, "I'm a bot. Send 'help' for command list")
                return False
    
            if actual_command_to_process == "ping":
                logger.info(f"Detected ping command from {clean_source}, args: '{args}' - sending pong reply")
                self.send_aprs_msg(clean_source, "Pong! " + args)
                command_executed = True
            elif actual_command_to_process in ["?aprst", "?ping?"]:
                try:
                    frame_str = origframe.to_aprs_string().decode("utf-8", errors="replace")
                    self.send_aprs_msg(clean_source, frame_str.split("::", 2)[0] + ":")
                    command_executed = True
                except Exception as e:
                    logging.error("Error responding to ?aprst: %s", e)
            elif actual_command_to_process == "version":
                self.send_aprs_msg(clean_source, "Python " + sys.version.replace("\n", " "))
                command_executed = True
            elif actual_command_to_process == "time":
                self.send_aprs_msg(clean_source, "Localtime is " + time.strftime("%Y-%m-%d %H:%M:%S UTC%Z"))
                command_executed = True
            elif actual_command_to_process == "help":
                display_commands = sorted(list(set(self.KNOWN_COMMANDS.keys())))
                help_msg = "Commands: " + ", ".join(display_commands)
                self.send_aprs_msg(clean_source, help_msg)
                command_executed = True
            elif actual_command_to_process.lower() == "netusers":
                # Get last 10 users by timestamp
                cur = self.db.cursor()
                cur.execute("SELECT callsign FROM users ORDER BY timestamp DESC LIMIT 10")
                rows = cur.fetchall()
                if rows:
                    user_list = ", ".join(row[0] for row in rows)
                    self.send_aprs_msg(clean_source, f"Last 10 users: {user_list}")
                else:
                    self.send_aprs_msg(clean_source, "No users found.")
                command_executed = True
                
    
            if command_executed:
                return True
    
            # CQ still requires netname as per your request
            if actual_command_to_process == "cq" and args.upper().startswith(self.netname.upper()):
                match_text = f"{actual_command_to_process} {args}"
                match = re.match(rf"^{re.escape(actual_command_to_process)}\s+{re.escape(self.netname)}\s+(.+)", match_text, re.IGNORECASE)
                if match:
                    self._broadcast_to_net(clean_source, match.group(1).strip())
                    command_executed = True
                return command_executed
    
            # NETMSG still requires netname as per current logic (it checks registration)
            if actual_command_to_process == "netmsg":
                # The 'args' now directly contains the message to be broadcasted,
                # assuming 'netmsg' is the only command word.
                # No need for re.match to strip the netname if it's not expected.
                # The original 'args' variable already holds everything after 'netmsg'.

                cur = self.db.cursor()
                cur.execute("SELECT 1 FROM users WHERE callsign = ?", (clean_source,))
                if not cur.fetchone():
                    self._log_audit(
                        direction="recv",
                        source=clean_source,
                        destination=self.callsign,
                        message=text,
                        msgid=None,
                        rejected=True,
                        note="NETMSG attempt by unregistered user",
                        transport=classify_transport(via) if via else "RF"
                    )
                    self.send_aprs_msg(clean_source, f"You're not registered on {self.netname}. Send 'CQ {self.netname} <msg>' first.")
                    return False

                # Use the original 'args' directly as the message payload
                # as it no longer contains the netname prefix to strip.
                self._broadcast_message(clean_source, args.strip())
                command_executed = True
                return command_executed
    
            # Modified: Removed 'and args.upper() == self.netname.upper()'
            if actual_command_to_process == "netcheckout":
                self._remove_user(clean_source)
                command_executed = True
                return command_executed
    

    
            if actual_command_to_process in ["blacklist_add", "blacklist_del", "admin_add", "admin_del"] and args:
                if not self.is_admin(clean_source):
                    self.send_aprs_msg(clean_source, "Admin privileges required for this command.")
                    self._log_audit(
                        direction="recv",
                        source=clean_source,
                        destination=self.callsign,
                        message=text,
                        msgid=None,
                        rejected=True,
                        note=f"Unauthorized attempt to '{actual_command_to_process}' by non-admin",
                        transport=classify_transport(via) if via else "RF"
                    )
                    return False
    
                if actual_command_to_process == "blacklist_add":
                    self.exec_db("INSERT OR IGNORE INTO blacklist (callsign) VALUES (?)", (args.upper(),))
                    self.send_aprs_msg(clean_source, f"{args.upper()} has been blacklisted.")
                elif actual_command_to_process == "blacklist_del":
                    self.exec_db("DELETE FROM blacklist WHERE callsign = ?", (args.upper(),))
                    self.send_aprs_msg(clean_source, f"{args.upper()} removed from blacklist.")
#                elif actual_command_to_process == "admin_add":
#                    self.exec_db("INSERT OR IGNORE INTO admins (callsign) VALUES (?)", (args.upper(),))
#                    self.send_aprs_msg(clean_source, f"{args.upper()} is now an admin.")
#                elif actual_command_to_process == "admin_del":
#                    self.exec_db("DELETE FROM admins WHERE callsign = ?", (args.upper(),))
#                    self.send_aprs_msg(clean_source, f"{args.upper()} removed from admins.")
    
                command_executed = True
                return command_executed
    
            return command_executed

    def beacon_as_botnet(self, text=None): # Renamed method, changed default text to None
        """Send a status beacon as self.netname so APRS-IS learns the alias."""
        # If no specific text is provided, use a default that includes netname
        if text is None:
            text = f"{self.netname} tactical alias active"

        original_callsign = self.callsign
        self.callsign = self.netname # <--- CRITICAL CHANGE: Use netname from config
        frame = self.make_aprs_status(text)
        for label, client in self.clients.items():
            if client.is_connected():
                client.enqueue_frame(frame)
                logger.info(f"Beaconed as {self.netname} via {label}: {text}") # Log message updated

        logger.info(f"Beaconed as {self.netname}: {text}") # Log message updated
        self.callsign = original_callsign

    def _broadcast_to_net(self, source, payload):
        cur = self.db.cursor()
        cur.execute("SELECT 1 FROM users WHERE callsign = ?", (source,))
        if not cur.fetchone():
            cur.execute("INSERT INTO users (callsign) VALUES (?)", (source,))
            logging.info(f"Added {source} to {self.netname} heard list")
        self.db.commit()

        cur.execute("SELECT callsign FROM users")
        for callsign, in cur.fetchall():
            msg = f"<{source}> {payload}"
            self.send_aprs_msg(callsign, msg, is_ack=False)

    def send_aprs_status(self, status):
        frame = self.make_aprs_status(status)
        for label, client in self.clients.items():
            if client.is_connected():
                client.enqueue_frame(frame)
                logger.info(f"Status frame sent via {label}: {status}")

        # Dynamic status message using current bot identity
        self.send_aprs_msg("APRS", f">The Net is active here at {self.callsign}.", is_ack=False)


    def _broadcast_message(self, source, message):
        cur = self.db.cursor()
        cur.execute("SELECT callsign FROM users")
        for callsign, in cur.fetchall():
            self.send_aprs_msg(callsign, message, is_ack=False)
            logging.info(f"Broadcast from {source} to {callsign}: {message}")

    def _remove_user(self, source):
        self.db.cursor().execute("DELETE FROM users WHERE callsign = ?", (source,))
        self.db.commit()
        logging.info(f"Removed {source} from {self.netname}")
        self.send_aprs_msg(source, self.netcheckout_response, is_ack=False)

    def _send_user_list(self, source):
        cur = self.db.cursor()
        cur.execute("SELECT callsign FROM users ORDER BY timestamp DESC LIMIT 10")
        rows = cur.fetchall()
        reply = "Last 10 users:\n" + ", ".join(row[0] for row in rows) if rows else f"No {self.netname} users heard yet."
        self.send_aprs_msg(source, reply, is_ack=False)
        logging.info(f"Sent user list to {source}")

    def send_aprs_msg(self, to_call, text, is_ack=False):
        frame = self.make_aprs_msg(to_call, text)
    
        for label, client in self.clients.items():
            if client.is_connected():
                client.enqueue_frame(frame)
                logger.info(f"Sent via {label}: {to_call} -> {text}")
             
    
                if not is_ack:
                    transport = "RF" if label.lower() == "rf" else "APRS-IS"
                    logger.info(f"[AUDIT TEST] Logging outbound APRS message: {self.callsign} -> {to_call} via {transport}")

                    self._log_audit(
                        direction="sent",
                        source=self.callsign,
                        destination=to_call,
                        message=text,
                        msgid=None,
                        transport=transport
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


class ReplyBot:
    def __init__(self, config_file):
        
        self._config_file = config_file
        self._cfg = configparser.ConfigParser()
        self._cfg.optionxform = str
        self._cfg.read(self._config_file)

        if self._cfg.has_section("aprs"):
            callsign_from_cfg = self._cfg["aprs"].get("callsign", "N0CALL").strip()
        else:
            logger.warning("[aprs] section missing in config — defaulting to N0CALL")
            callsign_from_cfg = "N0CALL"
            aliases_from_cfg = set(a.strip().upper() for a in self._cfg["aprs"].get("aliases", "").split(",") if a.strip())
            aliases_from_cfg.add(callsign_from_cfg.upper())

        self._aprs_handler = BotAprsHandler(callsign_from_cfg, None, config_file=config_file)


        # Store TNC clients
        self.clients = {}
        self._aprs_handler.clients = self.clients  # Share client dictionary with handler

        # Load client config (RF + APRS-IS)
        self._load_config()

        # Connect each client so they're live
        for label, client in self.clients.items():
            try:
                client.connect()
                logger.info(f"{label} client connected: {client.is_connected()}")
            except Exception as e:
                logger.error(f"{label} client failed to connect: {e}")

        self._last_blns = time.monotonic()
        self._last_cron_blns = 0
        self._last_status = time.monotonic()
        self._last_reconnect_attempt = 0
        self._rem = remotecmd.RemoteCommandHandler()
        self._config_mtime = 0.0
        self._check_updated_config()



    def _load_config(self):

        # Load RF TNC configuration and initialize client
        if self._cfg.has_section("tnc_rf"):
            rf_addr = self._cfg["tnc_rf"]["addr"]
            rf_port = int(self._cfg["tnc_rf"]["port"])
            rf_callsign = self._cfg["aprs"].get("callsign", "RF").strip()

            rf_client = RfKissClient(addr=rf_addr, port=rf_port)
            rf_client.callsign = rf_callsign

            # RF frames: explicitly indicate these are from RF
            rf_client.on_recv_frame = lambda frame: self._aprs_handler.handle_frame(frame, from_aprsis=False)

            self.clients["rf"] = rf_client

        # Load APRS-IS TNC
        if self._cfg.has_section("tnc_aprsis"):
            is_addr = self._cfg["tnc_aprsis"]["addr"]
            is_port = int(self._cfg["tnc_aprsis"]["port"])
            callsign = self._cfg["tnc_aprsis"].get("callsign", self._cfg["aprs"].get("callsign", "N0CALL")).strip()
            passcode = self._cfg["tnc_aprsis"].get("passcode", "00000").strip()
            filter_str = self._cfg["tnc_aprsis"].get("filter", "")

            aprsis_client = AprsIsClient(
                addr=is_addr,
                port=is_port,
                callsign=callsign,
                passcode=passcode,
                aprs_filter=filter_str
            )

            aprsis_client.filter = filter_str

            # APRS-IS frames: explicitly indicate these are from APRS-IS
            aprsis_client.on_recv_frame = lambda frame: self._aprs_handler.handle_frame(frame, from_aprsis=True)

            self.clients["aprsis"] = aprsis_client

        logger.info("Loaded both RF and APRS-IS interfaces")

    def _check_updated_config(self):
        try:
            mtime = os.stat(self._config_file).st_mtime
        except Exception as exc:
            logger.error(exc)
            return
        def _get_config_hash(file_path):
            """
            Computes an MD5 hash of the config file contents for change tracking.
            Returns the hex digest as a string, or None if file cannot be read.
            """
            try:
                with open(file_path, "rb") as f:
                    return hashlib.md5(f.read()).hexdigest()
            except Exception as e:
                logger.error(f"Failed to hash config file: {e}")
                return None

        try:
            new_hash = _get_config_hash(self._config_file)
            if self._config_mtime != mtime and new_hash != getattr(self, "_config_hash", ""):
                self._load_config()
                self._config_mtime = mtime
                self._config_hash = new_hash
                logger.info("Configuration reloaded")
        except Exception as exc:
            logger.error(exc)

    def is_connected(self):
        # Return True if any TNC client is currently connected
        return any(client.is_connected() for client in self.clients.values())


    def on_connect(self):
        logger.info("Connected")

        try:
            if self._cfg.has_option("tnc_aprsis", "filter"):
                filter_str = self._cfg.get("tnc_aprsis", "filter")
                if hasattr(self, 'sock') and self.sock and self.sock.fileno() >= 0:
                    logger.info(f"Sending APRS-IS filter: {filter_str}")
                    self.sock.sendall(f"filter {filter_str}\n".encode())
                else:
                    logger.warning("Cannot send filter: self.sock not available or invalid.")
            else:
                logger.info("No filter defined in [tnc] section of config.")
        except Exception as e:
            logger.error(f"Failed to send APRS-IS filter: {e}")


    def on_disconnect(self):
        logger.warning("Disconnected! Will try again soon...")

    def on_recv_frame(self, frame):
        logger.debug("Received frame object: %s", frame)
        logger.warning("🔥 handle_frame() was triggered — frame inbound")
        try:
            frame_str = frame.to_aprs_string().decode(errors="replace")
            logger.warning("RECV FRAME: %s", frame_str)
        except Exception as e:
            logger.warning("RECV FRAME (could not decode): %s", e)
    
        # The critical fix: set from_aprsis to True for APRS-IS socket input
        self._aprs_handler.handle_frame(frame, from_aprsis=True)




    def _update_bulletins(self):
        if not self._cfg.has_section("bulletins"):
            return

        try:
            max_age = int(self._cfg.get("bulletins", "send_freq", fallback="600"))
        except Exception as e:
            logger.warning(f"Invalid send_freq value in config, using default: {e}")
            max_age = 600


        now_mono = time.monotonic()
        now_time = time.time()
        try:
            self._last_blns = float(self._last_blns)
        except Exception:
            self._last_blns = 0.0


        if (now_mono <= (self._last_blns + max_age)) and (
            now_time <= (self._last_cron_blns + 60)
        ):
            return

        bln_map = dict()

        keys = self._cfg.options("bulletins")
        keys.sort()
        std_blns = [
            k for k in keys if k.startswith("BLN") and len(k) > 3 and "_" not in k
        ]

        time_was_set = time.gmtime().tm_year > 2000

        if time_was_set and now_time > (self._last_cron_blns + 60):
            self._last_cron_blns = 60 * int(now_time / 60.0) + random.randint(0, 30)

            cur_time = time.localtime()
            try:
                utc_offset = int(cur_time.tm_gmtoff) / 3600
            except Exception as e:
                logger.exception("Failed to compute UTC offset")

            ref_time = cur_time[:5]

            for k in keys:
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

        if now_mono > (self._last_blns + max_age):
            self._last_blns = now_mono
            for k in std_blns:
                bln_map[k] = self._cfg.get("bulletins", k)

        if len(bln_map) > 0:
            to_send = [(k, v) for k, v in bln_map.items()]
            to_send.sort()
            for (bln, text) in to_send:
                logger.info("Posting bulletin: %s=%s", bln, text)
                self._aprs_handler.send_aprs_msg(bln, text)

    def _update_status(self):
        if not self._cfg.has_section("status"):
            return
        max_age = self._cfg.getint("status", "send_freq", fallback=600)
        now_mono = time.monotonic()

        try:
            self._last_status = float(self._last_status)
        except Exception:
            self._last_status = 0.0

        if now_mono < (self._last_status + max_age):
            return

        self._last_status = now_mono
        self._rem.post_cmd(SystemStatusCommand(self._cfg["status"]))

    def _check_reconnection(self):
        try:
            self._last_reconnect_attempt = float(self._last_reconnect_attempt)
        except Exception:
            self._last_reconnect_attempt = 0.0

        if time.monotonic() < self._last_reconnect_attempt + 5:
            return

        self._last_reconnect_attempt = time.monotonic()

        for label, client in self.clients.items():
            if not client.is_connected():
                try:
                    logger.info(f"Trying to reconnect {label}")
                    client.connect()
                    logger.info(f"{label} reconnected: {client.is_connected()}")
                    passcode_str = getattr(client, "passcode", None)

                    callsign_str = getattr(client, "callsign", label)
                    #logger.warning(f"[{callsign_str}] Loop is executing for {label}")
                    callsign_str = getattr(client, "callsign", label)
                    logger.warning(f"[{callsign_str}] Loop is executing for {label}")



                except ConnectionRefusedError as e:
                    logger.warning(f"{label} reconnect failed: {e}")
                except Exception as e:
                    logger.error(f"{label} reconnect error: {e}")


    def on_loop_hook(self):

        self._check_updated_config()
        self._check_reconnection()
        self._update_bulletins()
        self._update_status()
        # ✅ FRAME POLLING — process inbound APRS-IS and RF frames
        for label, client in self.clients.items():
            logger.debug(f"{label} connected: {client.is_connected()}")
            logger.debug(f"Polling APRS-IS loop")

            try:
                client.loop()
                logger.debug(f"Polling APRS-IS loop")

            except Exception as e:
                logger.error(f"Error in {label} client.loop(): {e}")


        now = time.monotonic()
        if not hasattr(self, "_last_netname_beacon"):
            self._last_netname_beacon = 0
        # NEW: Ensure each TNC client processes its input

        if now - self._last_netname_beacon > 900:
            self._last_netname_beacon = now
            beacon_text = self._aprs_handler.beacon_message_template.format(
                alias=self._aprs_handler.user_defined_beacon_alias,
                call=self._aprs_handler.callsign
            )

            self._aprs_handler.beacon_as_botnet(beacon_text)

        while True:
            rcmd = self._rem.poll_ret()
            if not rcmd:
                break
            self.on_remote_command_result(rcmd)

    def on_remote_command_result(self, cmd):
        logger.debug("ret = %s", cmd)

        if isinstance(cmd, SystemStatusCommand):
            self._aprs_handler.send_aprs_status(cmd.status_str)
