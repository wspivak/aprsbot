#
# Ioreth - An APRS library and bot
# Modified for logging APRS messages with transport classification
#

import logging

logging.basicConfig()
logger = logging.getLogger(__name__)

from . import ax25


# ✅ Transport classifier placed before Handler class
def classify_transport(via):
    if not via:
        return "RF"  # Assume RF when path is missing

    if isinstance(via, str):
        path_elements = [v.strip().lower() for v in via.split(',')]
    elif isinstance(via, (list, tuple)):
        path_elements = [str(v).strip().lower() for v in via]
    else:
        return "RF"

    aprsis_ids = {"tcpip", "tcpxx", "qac", "qas", "qar", "qao", "qax"}
    if any(part in aprsis_ids or part.startswith("q") for part in path_elements):
        return "APRS-IS"
    return "RF"


class Handler:
    """Handle parsing and generation of APRS packets."""

    DEFAULT_PATH = "WIDE1-1,WIDE2-2"
    DEFAULT_DESTINATION = "PYBOT1"

    def __init__(self, callsign="XX0ABC"):
        self.callsign = callsign
        self.destination = Handler.DEFAULT_DESTINATION
        self.path = Handler.DEFAULT_PATH

    def make_frame(self, data):
        return ax25.Frame(
            ax25.Address.from_string(self.callsign),
            ax25.Address.from_string(self.destination),
            [ax25.Address.from_string(s) for s in self.path.split(",")],
            ax25.APRS_CONTROL_FLD,
            ax25.APRS_PROTOCOL_ID,
            data,
        )

    def make_aprs_msg(self, to_call, text):
        addr_msg = ":" + to_call.ljust(9, " ") + ":" + text
        return self.make_frame(addr_msg.encode("utf-8"))

    def make_aprs_status(self, status):
        return self.make_frame((">" + status).encode("utf-8"))

    def handle_frame(self, frame):
        if frame.info == b"":
            return

        via = None
        source = frame.source.to_string()
        payload = frame.info

        if payload[0] == ord(b"}"):
            via = source
            src_rest = frame.info[1:].split(b">", 1)
            if len(src_rest) != 2:
                logger.debug("Discarding third party packet with no destination.")
                return

            source = src_rest[0].decode("utf-8", errors="replace")
            destpath_payload = src_rest[1].split(b":", 1)
            if len(destpath_payload) != 2:
                logger.debug("Discarding third party packet with no payload.")
                return

            payload = destpath_payload[1]

        try:
            self.on_aprs_packet(frame, source, payload, via)
        except Exception as e:
            logger.error(
                f"Error processing APRS packet from {source} with payload '{payload.decode('utf-8', errors='replace')}': {e}"
            )

    def on_aprs_packet(self, origframe, source, payload, via=None):
        if payload == b"":
            self.on_aprs_empty(origframe, source, payload, via)
            return

        data_type = payload[0]

        if data_type == ord(b":"):
            self._handle_aprs_message(origframe, source, payload, via)
        elif data_type == ord(b">"):
            self.on_aprs_status(origframe, source, payload, via)
        elif data_type == ord(b";"):
            self.on_aprs_object(origframe, source, payload, via)
        elif data_type == ord(b")"):
            self.on_aprs_item(origframe, source, payload, via)
        elif data_type == ord(b"?"):
            self.on_aprs_query(origframe, source, payload, via)
        elif data_type == ord(b"<"):
            self.on_aprs_capabilities(origframe, source, payload, via)
        elif data_type == ord(b"!"):
            try:
                self.on_aprs_position_wtr(origframe, source, payload, via)
            except Exception as e:
                logger.error(f"Position packet error for {source}: {e}")
        elif data_type == ord(b"@"):
            try:
                self.on_aprs_position_ts_msg(origframe, source, payload, via)
            except Exception as e:
                logger.error(f"TS position packet error for {source}: {e}")
        elif data_type == ord(b"="):
            try:
                self.on_aprs_position_msg(origframe, source, payload, via)
            except Exception as e:
                logger.error(f"Position msg packet error for {source}: {e}")
        elif data_type == ord(b"/"):
            try:
                self.on_aprs_position_ts(origframe, source, payload, via)
            except Exception as e:
                logger.error(f"Slash position packet error for {source}: {e}")
        elif data_type == ord(b"T"):
            self.on_aprs_telemetry(origframe, source, payload, via)
        elif data_type == ord(b"`"):
            self.on_aprs_mic_e(origframe, source, payload, via)
        elif data_type == ord(b"'"):
            self.on_aprs_old_mic_e(origframe, source, payload, via)
        else:
            self.on_aprs_others(origframe, source, payload, via)

    def _handle_aprs_message(self, origframe, source, payload, via):
        data_str = payload.decode("utf-8", errors="replace")
        addressee_text = data_str[1:].split(":", 1)
        if len(addressee_text) != 2:
            logger.warning("Bad addressee:text pair: %s", addressee_text)
            return

        addressee = addressee_text[0].strip()
        text_msgid = addressee_text[1].rsplit("{", 1)
        text = text_msgid[0]
        msgid = text_msgid[1] if len(text_msgid) == 2 else None

        logger.info("Message from %s: %s", source, text)
        self.on_aprs_message(source, addressee, text, origframe, msgid, via)

    # ✅ Updated to include transport + audit logging
    def on_aprs_message(self, source, addressee, text, origframe, msgid=None, via=None):
        """APRS message packet (data type :)"""
        clean_source = source.replace("*", "").strip()
        destination = addressee.upper().strip()
        cleaned_text = text.strip()
        transport = classify_transport(via) if via else "RF"


        logger.info(f"[AUDIT] {clean_source} → {destination} via {via or 'RF'} | msg='{cleaned_text}'")

        try:
            self._log_audit(
                direction="recv",
                source=clean_source,
                destination=destination,
                # ✅ preserve MSG / CQ prefix
                message= text.strip(),  
                msgid=msgid,
                transport=transport
            )
        except Exception as e:
            logger.error(f"Error logging APRS message: {e}")

    # Remaining methods:
    def on_aprs_empty(self, origframe, source, payload, via): pass
    def on_aprs_status(self, origframe, source, payload, via=None): pass
    def on_aprs_object(self, origframe, source, payload, via=None): pass
    def on_aprs_item(self, origframe, source, payload, via=None): pass
    def on_aprs_query(self, origframe, source, payload, via=None): pass
    def on_aprs_capabilities(self, origframe, source, payload, via=None): pass
    def on_aprs_position_wtr(self, origframe, source, payload, via=None): pass
    def on_aprs_position_ts_msg(self, origframe, source, payload, via=None): pass
    def on_aprs_position_msg(self, origframe, source, payload, via=None): pass
    def on_aprs_position_ts(self, origframe, source, payload, via=None): pass
    def on_aprs_telemetry(self, origframe, source, payload, via=None): pass
    def on_aprs_mic_e(self, origframe, source, payload, via=None): pass
    def on_aprs_old_mic_e(self, origframe, source, payload, via=None): pass
    def on_aprs_others(self, origframe, source, payload, via=None): pass
