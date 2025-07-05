
# About (from the orginal)

Ioreth is a **very experimental** APRS bot. There is a lot f things to be
done yet, including writing the documentation. For now, you are welcome to
use it as you want.

Note that transmitting on the usual APRS ham bands requires (at least) an
Amateur Radio license and additional conditions and limitations for this
particular mode of operation may apply on your country or region. You MUST
ensure compliance with your local regulations before transmitting, but all
other uses are only subjected to the GNU GPLv3+ (see license bellow).

Connecting this program to the APRS-IS network also requires a license as
you will be, effectively, operating remote transmitters through the Internet.

# Updates to orginal

SQLite3 database for users, blacklisted callsigns and admins

Blacklist limited to Admins

Public logging via the DB, based on the full audit trail.  Logging handled by gunicorn, a service is supplied (check paths). Api.py and basic HTML page supplied.

Added code to prevent loopback from sent messages

Relaybot.service to automatically start (on my system I had to run python in a virtual environment)

<b>New/Changed Commands:</b>

<b>NOTE:</b> Commands are not case sensitive (given my radios, that would be insane :) )

CQ [space] [listname] [message] <-- listname is configured in APRSBOT and can be multiples

[<b>NOTE:</b> There is no automatic unsubscribe (concept is that this was made for Emergency Communications)

NetMSG [space] [listname] [message] <-- to distribute message to list

NETUSERS [space] [listname] <-- list of users

NETCHECKOUT [space] [listname] <-- to leave the list.


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


Original Author:
Author: Alexandre Erwin Ittner   (callsign: PP5ITT)

Email: <alexandre@ittner.com.br>

Web: <https://www.ittner.com.br>
