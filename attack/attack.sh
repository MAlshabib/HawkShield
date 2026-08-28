#!/usr/bin/env bash
# HawkShield — attack your own router, watch the sensor catch it.
#
# This is the live proof: craft real 802.11 attack frames, put them on the air
# against YOUR OWN access point, and watch them appear on the dashboard seconds
# later. It is the honest version of the /admin simulate button -- that replays
# frames through the model in software; this one actually transmits.
#
# It does not craft frames of its own. Every frame comes from the same tested
# factory the detector's own self-test uses (backend/detector/attack_sim.py),
# transmitted by the safety-railed injector in tools/inject_attack.py. This
# script only points that engine at the right adapter, the right channel and
# your router, so you do not have to remember six flags on stage.
#
#   ./attack/attack.sh                 deauth x30 at your connected router
#   ./attack/attack.sh evil_twin       a different attack class
#   ./attack/attack.sh all 50          every class, 50 frames each
#   ./attack/attack.sh deauth 100 40   class, count, frames-per-second
#
# LEGAL: transmitting deauth/disassoc frames at networks you do not own is
# illegal in most places. This attacks the AP your Pi's wlan0 is associated to,
# on the assumption that it is yours. Do not point it at anything else.
set -uo pipefail

REPO="${HAWKSHIELD_REPO:-$(cd "$(dirname "$0")/.." && pwd)}"
ENV_FILE="$REPO/.env"
PY="$REPO/.venv/bin/python"

red=$'\033[31m'; grn=$'\033[32m'; ylw=$'\033[33m'; dim=$'\033[2m'; off=$'\033[0m'
die(){ printf '%sattack: %s%s\n' "$red" "$1" "$off" >&2; exit 2; }

env_get(){ grep -E "^$1=" "$ENV_FILE" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '"'"'"'\r'; }

ATTACK="${1:-deauth}"
COUNT="${2:-30}"
RATE="${3:-20}"

# The injector needs a monitor-mode adapter. That is the capture radio -- it is
# already in monitor mode on the target channel, and a monitor interface can
# transmit and receive at once, so the same card that fires the attack is the
# one that hears it. One adapter, attack and detect together.
IFACE="${ATTACK_IFACE:-$(env_get CAPTURE_IFACE)}"
IFACE="${IFACE:-wlan1}"

# The target is whatever access point wlan0 is associated with -- your router.
# Read it rather than ask, so there is nothing to mistype in front of an
# audience, and nothing to accidentally point elsewhere.
BSSID="${ATTACK_BSSID:-}"
if [ -z "$BSSID" ]; then
  BSSID=$(/usr/sbin/iw dev wlan0 link 2>/dev/null | awk '/Connected to/{print $3}')
fi
[ -z "$BSSID" ] && die "wlan0 is not connected to a router, so there is no target.
       Join your network first:  hawkshield wifi <ssid>
       or name the target yourself:  ATTACK_BSSID=aa:bb:cc:dd:ee:ff ./attack/attack.sh"

[ "$(id -u)" = 0 ] || SUDO="sudo"
[ -x "$PY" ] || die "no venv python at $PY -- run from the repo, or set HAWKSHIELD_REPO"

printf '%sHawkShield attack%s\n' "$grn" "$off"
printf '  class   %s\n' "$ATTACK"
printf '  target  %s  %s(the AP wlan0 is on)%s\n' "$BSSID" "$dim" "$off"
printf '  radio   %s  ·  %s frames  ·  %s/s\n' "$IFACE" "$COUNT" "$RATE"
printf '  %swatch it land:%s  http://%s.local:8000/dashboard\n\n' "$dim" "$off" "$(hostname 2>/dev/null || echo pi)"

# All the real work -- the frame factory, the transmit, the hard safety caps
# (<=1000 frames, <=100/s, own-network assertion, explicit target) -- lives in
# the tested module. This is a launcher, not a second implementation.
cd "$REPO" || die "cannot enter $REPO"
exec ${SUDO:-} "$PY" -m tools.inject_attack \
  --iface "$IFACE" \
  --target-bssid "$BSSID" \
  --attack "$ATTACK" \
  --count "$COUNT" \
  --rate "$RATE" \
  --i-own-this-network
