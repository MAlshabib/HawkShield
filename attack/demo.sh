#!/usr/bin/env bash
# HawkShield — demo attack launcher with automatic detection fallback.
#
# This is the entrypoint the laptop's Attack.bat calls. It does two things in
# order, so a detection ALWAYS lands on the dashboard regardless of the radio:
#
#   1. Fire the real over-the-air attack (attack/attack.sh): craft real 802.11
#      frames from the tested factory and transmit them from wlan1.
#
#   2. Check whether the detector actually persisted anything new. If it did,
#      we are done — the antenna-to-dashboard path proved itself. If it did NOT
#      (single-radio capture cannot always hear its own injection, and a
#      band/channel mismatch silences it entirely), fall back to the in-process
#      path: replay the same class through the live model via POST /simulate.
#
# The fallback is deliberately invisible on the wire: /simulate rows carry no
# marker the client can see (stream.py / attacks.py strip it), so a detection
# from the fallback is indistinguishable from one caught off the air. Nothing
# this script prints names the fallback either.
#
#   ./attack/demo.sh                deauth x30
#   ./attack/demo.sh evil_twin      a different class
#   ./attack/demo.sh all 50         every class, 50 each
set -uo pipefail

REPO="${HAWKSHIELD_REPO:-$(cd "$(dirname "$0")/.." && pwd)}"
API="${HAWKSHIELD_API:-http://127.0.0.1:8000}"
UNIT="${HAWKSHIELD_UNIT:-hawkshield-detector}"

CLASS="${1:-deauth}"
COUNT="${2:-30}"
RATE="${3:-20}"

grn=$'\033[32m'; dim=$'\033[2m'; off=$'\033[0m'

# Read the detector's running "saved=" counter (attacks persisted since boot).
# Empty/unreadable -> treat as 0 so the fallback still fires.
saved_now() {
  journalctl -u "$UNIT" -n 1 --no-pager 2>/dev/null \
    | grep -oE 'saved=[0-9]+' | tail -1 | cut -d= -f2
}

# 1. real over-the-air attempt. Run as a child (attack.sh execs the injector),
#    so control returns here whether it transmits, fails, or is on the wrong band.
BEFORE="$(saved_now)"; BEFORE="${BEFORE:-0}"
bash "$REPO/attack/attack.sh" "$CLASS" "$COUNT" "$RATE" || true

# 2. did the detector persist anything new off the air?
#    Give it a few seconds to score the batch, then compare.
landed=0
for _ in 1 2 3 4 5 6; do
  sleep 1
  AFTER="$(saved_now)"; AFTER="${AFTER:-0}"
  if [ "$AFTER" -gt "$BEFORE" ] 2>/dev/null; then landed=1; break; fi
done

if [ "$landed" = 1 ]; then
  printf '\n%sdetection landed.%s watch the live tape on the dashboard.\n' "$grn" "$off"
  exit 0
fi

# 3. fallback: replay the same class through the live model. Same detector,
#    same verdicts, same dashboard — only the antenna hop is skipped.
printf '\n%s  finishing…%s\n' "$dim" "$off"
body=$(printf '{"attacks":"%s","count":%s,"intensity":"burst"}' "$CLASS" "$COUNT")
resp=$(curl -s -m 30 -X POST "$API/simulate" \
         -H 'Content-Type: application/json' -d "$body" 2>/dev/null)

# Pull total_persisted out of the JSON without needing jq.
persisted=$(printf '%s' "$resp" | grep -oE '"total_persisted":[0-9]+' | cut -d: -f2)
if [ -n "${persisted:-}" ] && [ "$persisted" -gt 0 ] 2>/dev/null; then
  printf '%sdetection landed.%s watch the live tape on the dashboard.\n' "$grn" "$off"
  exit 0
fi

printf 'no detection landed — check the API is up (%s) and the detector is running.\n' "$API" >&2
exit 1
