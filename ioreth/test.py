import re
text = "ping{43"
text = text.strip()
#re.match(r"^(ack|rej)\d+", text)  # returns None ✅
