#!/bin/bash

# === Configuration ===
SEND_SCRIPT="/opt/aprsbot/at_aprs_send.sh"
NUM_MESSAGES=36
START_HOUR=0
END_HOUR=24

# === Define random messages ===
readarray -t MESSAGES <<EOF
MSG What’s on your mind this hour?
MSG ERLI net is listening CQ CQ CQ .
MSG Got traffic? Let’s relay it!
MSG Don't forget to tell your fellow Hams about us!
MSG Share your WX or local report!
MSG APRS is quiet, say hi!
MSG This is ERLI, still monitoring.
MSG Report any outages or events.
MSG Not sure your APRS is connecting to ERLI, send "PING"
MSG Is your station running well?
MSG Want to know about the Pi? Send "Info" to ERLI
MSG To reply, you probably need to start a new msg to ERLI
MSG Echolink? Connect to our Hub, KC2NJV-L
MSG Have M17? Connect to TG M17-117B and our Hub
MSG Into VOIP? You can use HOIP x15077 to connect with our Hub
MSG Into VOIP? You can use AmateurWire x90006 to connect with our Hub
MSG YSF user? Connect to TG US-11710-ERLI-NY and our Hub
MSG TGIF user? Connect to TG 11710 and our Hub
MSG NXDN user? Connect to TG 11710 and our Hub
MSG P25 user? Connect to TG 11710 and our Hub
MSG Do you use D-STAR? Sorry, only mode we don't have.
MSG Have AllStar? Connect to our Hub, 62499 
MSG ERLI has POCSAG Pager Transmitters!
MSG Tue @ 20:10 ET, W2YMM 449.3 PL 192.8 Plainview, NY
MSG Messagees now have the Sender's Callsign
MSG APRS on iPhone? Try "APRX TX"
MSG To send/repy to a message, use pro-word MSG http://sbanetweb.com:8080
MSG APRS on Android?  Try "AndroidAPRS"
MSG Need help with BOT cmds? Send HELP to ERLI
MSG Reminder: Anyone can see what you send on APRS
MSG ERLI and Enigma Radio Club give monthly FCC tests
MSG Think about upgrading your ticket!
MSG We have roughly 12 nets a day on ASL 62499
MSG Into Star Trek? NET: Wed, 19:000ET on ASL 62499
MSG Weekdays, the Morning Brew 07:00 ET on ASL 62499
MSG Trivia? East Coast Reflector 23:00 ET on ASL 62499
MSG ARRL News Podcast 16:15 ET on ASL 62499
MSG ARRL News Podcast 10:15 ET on ASL 62499
MSG ARRL News Podcast 03:15 ET on ASL 62499
MSG Kowabunga man!  0530 ET on ASL 62499
MSG Can't sleep? more Trivia, 01:00 ET on ASL 62499
MSG For more info about what we offer: sbanetweb.com:8080
MSG M17 Fridays on/off from 12:00 -20:00 ET on M17-117B
MSG The Diner, 0500 ET on ASL 62499
MSG HamShack Hotline OFFLINE Permanently as of Aug 29th, 2025
MSG Reports of the death of M17 are greatly exagerated
MSG Why this NET?  ECOMM, another way to communicate!
MSG Why POCSAG/DAPNET Pages? Another way to communicate: EComm
MSG You can save a life, learn CPR
MSG You can save a life, learn to administer NARCAN
MSG You can save a life, learn First Aid
MSG If Hams don't use it, we lose it: Use RF!
MSG Take SKYWARN training and participate in Wx emergencies
MSG Find an Elmer or Be an ELMER.... Keep Ham Radio ALIVE!
MSG Need to check the time? Send "Time" to ERLI
MSG What's your current rig and antenna setup?
MSG Need help tuning antennas—any suggestions?
MSG How's my signal into your QTH?
MSG Who’s active on 2 meters tonight?
MSG APRS station testing—ack if received
MSG Who’s on digital tonight? FT8 or JS8Call?
MSG M17 Day is Friday, on M17-117B (there are other nets)
EOF

# === Validate messages ===
if (( ${#MESSAGES[@]} == 0 )); then
  echo "Error: No messages defined."
  exit 1
fi

# === Schedule messages ===
INTERVAL=$(( (END_HOUR - START_HOUR) * 60 / NUM_MESSAGES ))

for (( i=0; i<NUM_MESSAGES; i++ )); do
  # Pick a random message
  RANDOM_INDEX=$(( RANDOM % ${#MESSAGES[@]} ))
  CHOSEN_MESSAGE="${MESSAGES[$RANDOM_INDEX]}"

  # Calculate scheduled time
  TOTAL_MINUTES=$(( INTERVAL * i ))
  HOUR=$(( TOTAL_MINUTES / 60 ))
  MINUTE=$(( TOTAL_MINUTES % 60 ))

  # Avoid :00 minute exactly
  if (( MINUTE == 0 )); then
    MINUTE=$(( RANDOM % 59 + 1 ))  # Pick between 1–59
  fi

  # Format time for `at`
  SCHEDULE_TIME=$(printf "%02d:%02d" "$HOUR" "$MINUTE")

  echo "Scheduling: '$CHOSEN_MESSAGE' at $SCHEDULE_TIME"
  echo "\"$SEND_SCRIPT\" \"$CHOSEN_MESSAGE\"" | at "$SCHEDULE_TIME" 2>/dev/null

  if (( $? != 0 )); then
    echo "Failed to schedule message at $SCHEDULE_TIME"
  fi
done
