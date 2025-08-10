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
declare -A USED_MESSAGES
MESSAGE_INDEX=0

for (( hour=START_HOUR; hour<END_HOUR; hour++ )); do
  for (( i=0; i<60; i+=INTERVAL )); do
    if (( MESSAGE_INDEX >= NUM_MESSAGES )); then
      break 2
    fi

    # Pick a unique message
    while :; do
      RANDOM_INDEX=$(( RANDOM % ${#MESSAGES[@]} ))
      CHOSEN_MESSAGE="${MESSAGES[$RANDOM_INDEX]}"
      if [[ -z "${USED_MESSAGES[$CHOSEN_MESSAGE]}" ]]; then
        USED_MESSAGES["$CHOSEN_MESSAGE"]=1
        break
      fi
    done

    # Safe minute selection
    while :; do
      MINUTE=$(( RANDOM % 60 ))
      if (( MINUTE > 2 && MINUTE < 58 )); then
        break
      fi
    done

    SCHEDULE_TIME=$(printf "%02d:%02d" "$hour" "$MINUTE")
    echo "Scheduling: '$CHOSEN_MESSAGE' at $SCHEDULE_TIME"
    echo "\"$SEND_SCRIPT\" \"$CHOSEN_MESSAGE\"" | at -M "$SCHEDULE_TIME" 2>/dev/null

    if (( $? != 0 )); then
      echo "Failed to schedule message at $SCHEDULE_TIME"
    fi

    (( MESSAGE_INDEX++ ))
  done
done
