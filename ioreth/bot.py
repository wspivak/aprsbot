import sys
import time
import logging
import configparser
import os
import re
import random
import sqlite3
import difflib

# Configure the logging
logging.basicConfig(
    level=logging.INFO,  # Set the minimum logging level (INFO, DEBUG, WARNING, ERROR, CRITICAL)
    format='%(asctime)s - %(levelname)s - %(message)s', # This format string includes the timestamp
    handlers=[
        logging.FileHandler("/opt/aprsbot/logs/replybot"), # Log to the specified file
        logging.StreamHandler(sys.stdout) # Also log to console (optional, but good for debugging)
    ]
)
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
            alias.strip().upper()
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
                note TEXT
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
        logger.info("Processing APRS message: from=%s to=%s text=%s msgid=%s via=%s",
                      source, addressee, text, msgid, via)
        logger.warning(f"APRS MSG RECEIVED: from={source} to={addressee} via={via} text={text}")

        cleaned = self.sanitize_text(text)

        if cleaned == "rej0":
            logger.debug("Ignoring 'rej0' control message.")
            return

        logger.info(f"Sanitized text: '{cleaned}'")

        clean_source = source.replace("*", "")
        upper_addressee = addressee.strip().upper()

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

            except Exception as e:
                logger.warning("Could not parse encapsulated frame: %s", e)

        was_command_handled = self.handle_aprs_query(clean_source, cleaned, origframe=origframe)

        if msgid:
            logger.info(f"Sending ack to message {msgid} from {clean_source}")
            self.send_aprs_msg(clean_source, f"ack{msgid}", is_ack=True)

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
            self.send_aprs_msg(clean_source, f"Interpreting '{qry}' as '{corrected_qry}'")
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

        if command_executed:
            return True

        if actual_command_to_process == "cq" and args.upper().startswith(self.netname.upper()):
            match_text = f"{actual_command_to_process} {args}"
            match = re.match(rf"^{re.escape(actual_command_to_process)}\s+{re.escape(self.netname)}\s+(.+)", match_text, re.IGNORECASE)
            if match:
                self._broadcast_to_net(clean_source, match.group(1).strip())
                command_executed = True
            return command_executed

        if actual_command_to_process == "netmsg" and args.upper().startswith(self.netname.upper()):
            match_text = f"{actual_command_to_process} {args}"
            match = re.match(rf"^{re.escape(actual_command_to_process)}\s+{re.escape(self.netname)}\s+(.+)", match_text, re.IGNORECASE)
            if match:
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
                        note="NETMSG attempt by unregistered user"
                    )
                    self.send_aprs_msg(clean_source, f"You're not registered on {self.netname}. Send 'CQ {self.netname} <msg>' first.")
                    return False

                self._broadcast_message(clean_source, match.group(1).strip())
                command_executed = True
            return command_executed

        if actual_command_to_process == "netcheckout" and args.upper() == self.netname.upper():
            self._remove_user(clean_source)
            command_executed = True
            return command_executed

        if actual_command_to_process == "netusers" and args.upper() == self.netname.upper():
            self._send_user_list(clean_source)
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
                    note=f"Unauthorized attempt to '{actual_command_to_process}' by non-admin"
                )
                return False

            if actual_command_to_process == "blacklist_add":
                self.exec_db("INSERT OR IGNORE INTO blacklist (callsign) VALUES (?)", (args.upper(),))
                self.send_aprs_msg(clean_source, f"{args.upper()} has been blacklisted.")
            elif actual_command_to_process == "blacklist_del":
                self.exec_db("DELETE FROM blacklist WHERE callsign = ?", (args.upper(),))
                self.send_aprs_msg(clean_source, f"{args.upper()} removed from blacklist.")
            elif actual_command_to_process == "admin_add":
                self.exec_db("INSERT OR IGNORE INTO admins (callsign) VALUES (?)", (args.upper(),))
                self.send_aprs_msg(clean_source, f"{args.upper()} is now an admin.")
            elif actual_command_to_process == "admin_del":
                self.exec_db("DELETE FROM admins WHERE callsign = ?", (args.upper(),))
                self.send_aprs_msg(clean_source, f"{args.upper()} removed from admins.")

            command_executed = True
            return command_executed

        return command_executed

    def beacon_as_erli(self, text="ERLI tactical alias active"):
        """Send a status beacon as 'ERLI' so APRS-IS learns the alias."""
        original_callsign = self.callsign
        self.callsign = "ERLI"
        frame = self.make_aprs_status(text)
        self._client.enqueue_frame(frame)
        logger.info(f"Beaconed as ERLI: {text}")
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
        self._client.enqueue_frame(self.make_aprs_status(status))
        self.send_aprs_msg("APRS", ">ERLI is active here at KC2NJV-4.", is_ack=False)

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
        if not self._client.is_connected():
            logger.warning(f"Client not connected - cannot send message to {to_call}")
            return

        logger.info("Sending APRS message to %s: %s", to_call, text)
        frame = self.make_aprs_msg(to_call, text)
        logger.info("Built APRS frame: %s", frame.to_aprs_string())
        self._client.enqueue_frame(frame)
        logger.info("Frame enqueued to APRS-IS: %s", frame.to_aprs_string())
        cache_sent_message(to_call, text)

        if not is_ack:
            self._log_audit(
                direction="sent",
                source=self.callsign,
                destination=to_call,
                message=text,
                msgid=None
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
        super().__init__()

        self._config_file = config_file

        self._config_mtime = None
        self._cfg = configparser.ConfigParser()
        self._cfg.optionxform = str

        self._aprs = BotAprsHandler("", self, config_file=self._config_file)

        self._last_blns = time.monotonic()
        self._last_cron_blns = 0
        self._last_status = time.monotonic()
        self._last_reconnect_attempt = 0
        self._rem = remotecmd.RemoteCommandHandler()

        self._check_updated_config()


    def _load_config(self):
        try:
            self._cfg.clear()
            self._cfg.read(self._config_file)
            self.addr = self._cfg["tnc"]["addr"]
            self.port = int(self._cfg["tnc"]["port"])

            callsign = self._cfg["aprs"]["callsign"]
            path = self._cfg["aprs"]["path"]

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
                self._aprs.send_aprs_msg(bln, text)

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


        now = time.monotonic()
        if not hasattr(self, "_last_erli_beacon"):
            self._last_erli_beacon = 0
        if now - self._last_erli_beacon > 900:
            self._last_erli_beacon = now


            beacon_text = self._aprs.beacon_message_template.format(
                alias=self._aprs.user_defined_beacon_alias,
                call=self._aprs.callsign
            )

            self._aprs.beacon_as_erli(beacon_text)

        while True:
            rcmd = self._rem.poll_ret()
            if not rcmd:
                break
            self.on_remote_command_result(rcmd)

    def on_remote_command_result(self, cmd):
        logger.debug("ret = %s", cmd)

        if isinstance(cmd, SystemStatusCommand):
            self._aprs.send_aprs_status(cmd.status_str)
