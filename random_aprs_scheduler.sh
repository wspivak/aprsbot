#!/bin/bash

# === Configuration ===
SEND_SCRIPT="/opt/aprsbot/at_aprs_send.sh"
NUM_MESSAGES=36
START_HOUR=0
END_HOUR=24

# === Define random messages ===
readarray -t MESSAGES <<EOF
<ADD messages with first word the PRO-word MSG, as many as you want>
<Adjust the Num_Messaegs a day above>
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
