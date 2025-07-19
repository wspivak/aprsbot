
# About (from the original)

Ioreth is a **very experimental** APRS bot. There are a lot of things to be
done yet, including writing the documentation. For now, you are welcome to
use it as you want.

Note that transmitting on the usual APRS ham bands requires (at least) an
Amateur Radio license and additional conditions and limitations for this
particular mode of operation may apply on your country or region. You MUST
ensure compliance with your local regulations before transmitting, but all
other uses are only subjected to the GNU GPLv3+ (see license bellow).

Connecting this program to the APRS-IS network also requires a license as
you will be, effectively, operating remote transmitters through the Internet.

# Updates to original (by Wayne Spivak, KC2NJV)

<b>MAJOR NOTE:</b>  I strongly suggest you put eveything in /opt/aprsbot.  I don't think there is anything hard-coded in Bot.py (some fallbacks), everything is in aprsbot.conf.  

<b>Files that need configuration:</b>
aprsbot.conf
log.html (make it to your liking, maybe as a php file..)
relaybot.service


<b>Installation:</b> Copy to a directory du jour (suggest /opt/aprsbot), configure and enjoy.

<b>Changes:</b>

Logger provides timestamps

SQLite3 database for users, blacklisted callsigns and admins (with timestamps)

Blacklist limited to Admins

Public logging via the DB, based on the full audit trail.  Logging handled by gunicorn, a service is supplied (check paths). Api.py and basic HTML page supplied.  You should use nginx for the proxy between log.php and api.py.

Added code to prevent loopback from sent messages

Anyone sending HELP to an alias for the list will recieve a response, unless they are blacklisted.

Configurable in aprsbot.conf:
Added configurable Welcome message for new subscribers
Callsign, Callsign Alias, List Names, DB name.
Configurable Beacon text
Configurable Known Commands
Configurable NetCheckOut stanza

Added a beacon (tatical_beacon.py) which will enable APRS-IS only devices to find your tactical callsign (add a cronjob @15min intervals).

Added a script to trim audit_log in SQLite3 db.  Just add a cron job.

Added a db to keep deduplication persistent over bot reboots.  Time frame "DEDUP_TTL = 3600  # 60 minutes" is in Bot.py row 36.  It seems AndroidAPRS app doesn't accept ACK's properly, and it sends 7 retries, stopping just under 60 minutes total time.

Relaybot.service to automatically start (on my system I had to run python in a virtual environment)

To create or delete ADMINS, I have commented out those lines in Bot.py.  I suggest you use sqlite3 and use
a) To Add:
    "INSERT OR IGNORE INTO admins (callsign) VALUES (?)"
b) To Delete:
     "DELETE FROM admins WHERE callsign = ?"
     
<b>New/Changed Commands:</b>

<b>NOTE:</b> Commands are not case sensitive (given my radios, that would be insane :) )

CQ [space] [listname] [message] <-- listname is configured in APRSBOT and can be multiples

[<b>NOTE:</b> There is no automatic unsubscribe (concept is that this was made for Emergency Communications)

NetMSG [space] [message] <-- to distribute message to list

NETUSERS  <-- list of users

NETCHECKOUT  <-- to leave the list.

BLACKLIST ADD/BLACKLIST DEL <-- needs Admin Privileges

# Special Thanks to:

Ben Jackson, N1WBV for his assistance!!!!

# ToDo List:

Add a Store and Forward sub-system, with a 3-day window.  

# License (from the original)

Copyright (C) 2020  Alexandre Erwin Ittner, PP5ITT <alexandre@ittner.com.br>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.



# Contact information

Hacker:

Wayne Spivak (callsign: KC2NJV)

E-mail: <kc2njv@sbanetweb.com>

Web: <http://sbanetweb.com:8080>

Special extra thanks to Gemini, Co-Pilot and Perplexity AI's that did ALL the HEAVY, Medium and lite lifting!

Original Author:
Author: Alexandre Erwin Ittner   (callsign: PP5ITT)

Email: <alexandre@ittner.com.br>

Web: <https://www.ittner.com.br>
