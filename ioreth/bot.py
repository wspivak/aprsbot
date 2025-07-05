#
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
        "cq": "CQ",
        "netmsg": "NETMSG",
        "netcheckout": "NETCHECKOUT",
        "netusers": "NETUSERS",
        "blacklist_add": "blacklist_add",
        "blacklist_del": "blacklist_del",
        "admin_add": "admin_add",
        "admin_del": "admin_del",
        "ping": "ping",
        "?aprst": "?aprst",
        "?ping?": "?ping?",
        "version": "version",
        "time": "time",
        "help": "help",
    }

    def exec_db(self, query, args=()):
        try:
            cur = self.db.cursor()
            cur.execute(query, args)
            self.db.commit()
        except Exception as e:
            logger.error(f"DB error: {e}")
    

    def __init__(self, callsign, client):
        super().__init__(callsign)
        self.callsign = callsign
        self._client = client
        self.db = None  # placeholder
        self._dbfile = None
        self._client = client
        self.callsign = callsign
        self._load_config()
        if self._dbfile:
            self.db = sqlite3.connect(self._dbfile, check_same_thread=False)
            self._init_db()
        else:
            raise ValueError("Missing 'dbfile' in [aprs] config")


    def _load_config(self):
        cfg = configparser.ConfigParser()
        cfg.read("aprsbot.conf")
        self.netname = cfg.get("aprs", "netname").strip().upper()
        self.aliases = {self.callsign.upper()}
        aliases_from_config = cfg.get("aprs", "aliases", fallback="")
        self.aliases.update(
            alias.strip().upper() for alias in aliases_from_config.split(",") if alias.strip()
        )
        self._dbfile = cfg.get("aprs", "dbfile", fallback="erli.db").strip()
        
        # ✅ Check DB path access before attempting to connect
        if not os.path.isfile(self._dbfile):
            db_dir = os.path.dirname(self._dbfile) or "."
            if not os.access(db_dir, os.W_OK):
                raise RuntimeError(f"Cannot write to database directory: {db_dir}")
                
        logger.info(f"Using database file: {self._dbfile}")

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
        """
        Detects typos and returns corrected command from known list if similar enough.
        """
        matches = difflib.get_close_matches(input_qry.lower(), self.KNOWN_COMMANDS.keys(), n=1, cutoff=0.8)
        if matches:
            return matches[0]
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
        logger.info("Processing APRS message: from=%s to=%s text=%s msgid=%s", source, addressee, text, msgid)
        logger.warning(f"APRS MSG RECEIVED: from={source} to={addressee} via={via} text={text}")

        cleaned = self.sanitize_text(text)

        # If loopback
        if is_loopback(source, text):
            if addressee.upper() in self.aliases:
               # Allow this message, it's a legit message for the alias, even if from direwolf client callsign
               pass
            else:
                logger.debug(f"Ignoring looped-back message from {source}: {text}")
                return

        if cleaned == "rej0":
            logger.debug("Ignoring 'rej0' control message.")
            return
        else:
            logger.info(f"Sanitized text: '{cleaned}'")
    
        clean_source = source.replace("*", "")
        upper_addressee = addressee.strip().upper()
    
        # Check addressee alias
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
    
        # Direct blacklist check
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
    
        # Encapsulated source blacklist check
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
    
        # ✅ Log accepted message
        self._log_audit(
            direction="recv",
            source=clean_source,
            destination=upper_addressee,
            message=cleaned,
            msgid=msgid
        )
    
        # Ignore pure control messages (ack/rej)
        if re.match(r"^(ack|rej)\d+$", cleaned.strip()):
            logger.info(f"Ignoring control message '{cleaned}' from {clean_source}")
            return
    
        # Process user query
        self.handle_aprs_query(clean_source, cleaned, origframe=origframe)
    
        # Send ack if message ID is present
        if msgid:
            logger.info(f"Sending ack to message {msgid} from {clean_source}")
            self.send_aprs_msg(clean_source, f"ack{msgid}")


    def handle_aprs_query(self, source, text, origframe):
        logger.info(f"handle_aprs_query called with text: '{text}' from {source}")
        logger.info("Handling query from %s: %s", source, text)

        clean_source = source.replace("*", "")
        text = text.strip()
        text = self.sanitize_text(text)
        qry_args = text.split(" ", 1)
        qry = qry_args[0]
        args = qry_args[1] if len(qry_args) == 2 else ""

        qry_lower = qry.lower()
        corrected_qry = self.detect_and_correct_command(qry_lower)

        if corrected_qry != qry_lower:
            logger.info(f"Corrected command from '{qry}' to '{corrected_qry}' for {clean_source}")
            self.send_aprs_msg(clean_source, f"Interpreting '{qry}' as '{corrected_qry}'")
            qry_lower = corrected_qry

        elif qry_lower not in self.KNOWN_COMMANDS:
            self.send_aprs_msg(clean_source, f"Unknown command '{qry}'. Send 'help' for valid commands.")
            return

        normalized = f"{corrected_qry} {args}".strip().upper()


        if normalized.startswith(f"CQ {self.netname}"):
            match = re.match(rf"^CQ\s+{self.netname}\s+(.+)", text, re.IGNORECASE)
            if match:
                self._broadcast_to_net(clean_source, match.group(1).strip())
            return

        if normalized.startswith(f"NETMSG {self.netname}"):
            match = re.match(rf"^NETMSG\s+{self.netname}\s+(.+)", text, re.IGNORECASE)
            if match:
                self._broadcast_message(clean_source, match.group(1).strip())
            return

        if normalized == f"NETCHECKOUT {self.netname}":
            self._remove_user(clean_source)
            return

        if normalized == f"NETUSERS {self.netname}":
            self._send_user_list(clean_source)
            return

        # Blacklist management - Admin only
        if qry_lower == "blacklist_add" and args:
            self.exec_db("INSERT OR IGNORE INTO blacklist (callsign) VALUES (?)", (args.upper(),))
            self.send_aprs_msg(clean_source, f"{args.upper()} has been blacklisted.")
            return

        if qry_lower == "blacklist_del" and args:
            self.exec_db("DELETE FROM blacklist WHERE callsign = ?", (args.upper(),))
            self.send_aprs_msg(clean_source, f"{args.upper()} removed from blacklist.")
            return

        if qry_lower == "admin_add" and args:
            self.exec_db("INSERT OR IGNORE INTO admins (callsign) VALUES (?)", (args.upper(),))
            self.send_aprs_msg(clean_source, f"{args.upper()} is now an admin.")
            return

        if qry_lower == "admin_del" and args:
            self.exec_db("DELETE FROM admins WHERE callsign = ?", (args.upper(),))
            self.send_aprs_msg(clean_source, f"{args.upper()} removed from admins.")
            return
    

        # Standard commands
        if qry == "ping":
            logger.info(f"Detected ping command from {clean_source}, args: '{args}' - sending pong reply")
            self.send_aprs_msg(clean_source, "Pong! " + args)
            logger.info(f"Pong sent to {clean_source}")
        elif qry in ["?aprst", "?ping?"]:
            try:
                frame_str = origframe.to_aprs_string().decode("utf-8", errors="replace")
                self.send_aprs_msg(clean_source, frame_str.split("::", 2)[0] + ":")
            except Exception as e:
                logging.error("Error responding to ?aprst: %s", e)
        elif qry == "version":
            
            self.send_aprs_msg(clean_source, "Python " + sys.version.replace("\n", " "))
        elif qry == "time":
           
            self.send_aprs_msg(clean_source, "Localtime is " + time.strftime("%Y-%m-%d %H:%M:%S UTC%Z"))
        elif qry == "help":
            
            self.send_aprs_msg(clean_source, "Commands: ping, version, time, help, blacklist_add <CALL>, blacklist_del <CALL>")

            
            self.send_aprs_msg(clean_source, replies[qry])
        else:
            
            if is_br_callsign(clean_source):
                self.send_aprs_msg(clean_source, "Sou um bot. Envie 'help' para a lista de comandos")
            else:
                self.send_aprs_msg(clean_source, "I'm a bot. Send 'help' for command list")

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
            self.send_aprs_msg(callsign, msg)

    def send_aprs_status(self, status):
        self._client.enqueue_frame(self.make_aprs_status(status))

    def _broadcast_message(self, source, message):
        cur = self.db.cursor()
        cur.execute("SELECT callsign FROM erli_users")
        for callsign, in cur.fetchall():
            self.send_aprs_msg(callsign, message)
            logging.info(f"Broadcast from {source} to {callsign}: {message}")

    def _remove_user(self, source):
        self.db.cursor().execute("DELETE FROM erli_users WHERE callsign = ?", (source,))
        self.db.commit()
        logging.info(f"Removed {source} from {self.netname}")
        self.send_aprs_msg(source, "NETCheckOUT Successful")

    def _send_user_list(self, source):
        cur = self.db.cursor()
        cur.execute("SELECT callsign FROM erli_users ORDER BY timestamp DESC LIMIT 10")
        rows = cur.fetchall()
        reply = "Last 10 users:\n" + ", ".join(row[0] for row in rows) if rows else f"No {self.netname} users heard yet."
        self.send_aprs_msg(source, reply)
        logging.info(f"Sent user list to {source}")

    def send_aprs_msg(self, to_call, text):
        if not self._client.is_connected():
            logger.warning(f"Client not connected - cannot send message to {to_call}")
            return

        logger.info("Sending APRS message to %s: %s", to_call, text)
        frame = self.make_aprs_msg(to_call, text)
        logger.info("Built APRS frame: %s", frame.to_aprs_string())
        self._client.enqueue_frame(frame)
        logger.info("Frame enqueued to APRS-IS: %s", frame.to_aprs_string())
        cache_sent_message(to_call, text)
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
        AprsClient.__init__(self)
        self._aprs = BotAprsHandler("", self)
        self._config_file = config_file
        self._config_mtime = None
        self._cfg = configparser.ConfigParser()
        self._cfg.optionxform = str  # config is case-sensitive
        self._check_updated_config()
        self._last_blns = time.monotonic()
        self._last_cron_blns = 0
        self._last_status = time.monotonic()
        self._last_reconnect_attempt = 0
        self._rem = remotecmd.RemoteCommandHandler()

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
            self._aprs = BotAprsHandler(callsign, self)
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
        logger.debug("Received frame: %s", frame)
        #logger.warning("RECV FRAME: %s", frame.to_aprs_string().decode(errors="replace"))
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
            self._last_blns = float(self._last_blns)
        except Exception:
            self._last_blns = 0.0



        if now_mono < (self._last_status + max_age):
            return

        self._last_status = now_mono
        self._rem.post_cmd(SystemStatusCommand(self._cfg["status"]))

    def _check_reconnection(self):
#        logger.debug(f"last reconnect attempt type: {type(self._last_reconnect_attempt)}")
#        logger.info(f"Type of self._last_reconnect_attempt: {type(self._last_reconnect_attempt)}, value: {self._last_reconnect_attempt}")
        try:
            self._last_blns = float(self._last_blns)
        except Exception:
            self._last_blns = 0.0

        if self.is_connected():
#            logger.info("I'm Connected")
            return
        try:
            # Server is in localhost, no need for a fancy exponential backoff.
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
