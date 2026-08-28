#!/usr/bin/env bash
# HawkShield operator command.
#
# There is nothing to "start": both services are systemd units enabled at boot,
# so powering the Pi on brings up capture, the model and the dashboard. This
# script exists for the things that genuinely change when the Pi leaves the
# bench -- which network it is on, which channel it should listen to, and
# whether the answer to "is it working" is yes.
#
#   hawkshield              status, and the URL to open
#   hawkshield channel auto follow whatever channel wlan0 is on
#   hawkshield channel 6    or name one explicitly
#   hawkshield wifi SSID    join a network on wlan0 (prompts for the password)
#   hawkshield hotspot      serve a network from wlan0 when the venue has none
#   hawkshield reset        re-bind the adapter when the radio goes silent
#   hawkshield restart      restart both services
#   hawkshield logs         follow the detector
set -uo pipefail

REPO="${HAWKSHIELD_REPO:-/home/pi/HawkShield}"
ENV_FILE="$REPO/.env"
PORT=8000
IW=/usr/sbin/iw

bold=$'\033[1m'; dim=$'\033[2m'; red=$'\033[31m'; grn=$'\033[32m'; ylw=$'\033[33m'; off=$'\033[0m'
ok(){ printf '  %s✓%s %s\n' "$grn" "$off" "$1"; }
bad(){ printf '  %s✗%s %s\n' "$red" "$off" "$1"; }
warn(){ printf '  %s!%s %s\n' "$ylw" "$off" "$1"; }
head_(){ printf '\n%s%s%s\n' "$bold" "$1" "$off"; }

env_get(){ grep -E "^$1=" "$ENV_FILE" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '"'"'"'\r'; }

status(){
  printf '\n%sHawkShield%s  %s%s%s\n' "$bold" "$off" "$dim" "$(date '+%a %d %b %H:%M')" "$off"

  head_ 'Services'
  for unit in hawkshield-api hawkshield-detector; do
    state=$(systemctl is-active "$unit" 2>/dev/null)
    boot=$(systemctl is-enabled "$unit" 2>/dev/null)
    if [ "$state" = active ]; then ok "$unit ($state, $boot at boot)"
    else bad "$unit is $state -- try: hawkshield restart"; fi
  done

  head_ 'Capture'
  local iface chan
  iface=$(env_get CAPTURE_IFACE); chan=$(env_get CAPTURE_CHANNEL)
  if [ -e "/sys/class/net/$iface" ]; then
    local mode live
    mode=$($IW dev "$iface" info 2>/dev/null | awk '/type/{print $2}')
    live=$($IW dev "$iface" info 2>/dev/null | awk '/channel/{print $2}')
    if [ "$mode" = monitor ]; then ok "$iface in monitor mode, channel ${live:-?}"
    else bad "$iface is '$mode', not monitor -- try: hawkshield restart"; fi
    [ -n "$live" ] && [ "$live" != "$chan" ] && warn "radio is on $live but .env says $chan"
  else
    bad "$iface is missing -- is the USB adapter plugged in?"
  fi
  # Frames actually arriving is the only proof the radio is working. `seen` is
  # cumulative since the process started, so a total tells you nothing about now
  # -- a stalled radio keeps reporting the same large number. Sample twice and
  # report the change. The heartbeat lands every ~2s, so read the last few lines
  # rather than only the newest, and retry the first read: catching it between
  # heartbeats once returned nothing and read as a false "silent", which is the
  # last thing you want to see on stage over a healthy sensor.
  latest_seen(){ journalctl -u hawkshield-detector -n 6 --no-pager 2>/dev/null \
                 | grep -oE 'seen=[0-9]+' | tail -1 | cut -d= -f2; }
  local a b delta tries=0
  a=$(latest_seen)
  while [ -z "$a" ] && [ "$tries" -lt 3 ]; do sleep 2; a=$(latest_seen); tries=$((tries+1)); done
  if [ -z "$a" ]; then warn 'detector is not logging yet -- give it a few seconds'
  else
    sleep 8
    b=$(latest_seen)
    delta=$(( ${b:-$a} - a ))
    if [ "$delta" -gt 0 ]; then ok "hearing traffic ($delta frames in 8s)"
    else
      bad "radio is silent (0 frames in 8s)"
      printf '      %sthe channel may be wrong:%s hawkshield channel auto\n' "$dim" "$off"
      printf '      %sor the adapter has stalled:%s hawkshield reset\n' "$dim" "$off"
    fi
  fi

  head_ 'Detections'
  # Pulled with grep rather than a JSON parser: this runs over ssh, and every
  # layer of nested quoting is another thing that can silently mangle.
  local health packets model spec
  health=$(curl -s -m 6 "http://localhost:$PORT/health" 2>/dev/null)
  if [ -n "$health" ]; then
    packets=$(printf '%s' "$health" | grep -oE '"packets":[0-9]+' | cut -d: -f2)
    model=$(printf '%s' "$health" | grep -oE '"model_version":"[^"]*"' | cut -d: -f2 | tr -d '"')
    spec=$(printf '%s' "$health" | grep -oE '"spec_version":"[^"]*"' | cut -d: -f2 | tr -d '"')
    if [ -n "$packets" ]; then ok "stored $packets - model ${model:-?} - spec ${spec:-?}"
    else bad 'could not read /health'; fi
  else bad "API not answering on :$PORT"; fi

  head_ 'Network'
  # Three radios/ports, three jobs. Worth printing because the failure people hit
  # is not "no network" -- it is the wrong interface doing the wrong job.
  local uplink
  uplink=$(ip route show default 2>/dev/null | sort -k9 -n | awk 'NR==1{print $5}')
  local e_ip w_ip
  e_ip=$(ip -4 -br addr show eth0 2>/dev/null | awk '{print $3}')
  w_ip=$(ip -4 -br addr show wlan0 2>/dev/null | awk '{print $3}')
  [ -n "$e_ip" ] && ok "eth0  ${e_ip}$([ "$uplink" = eth0 ] && echo '  <- internet')" \
                 || warn 'eth0 has no address (cable out?)'
  local w0mode w0ssid
  w0mode=$($IW dev wlan0 info 2>/dev/null | awk '/type/{print $2}')
  w0ssid=$($IW dev wlan0 link 2>/dev/null | awk '/SSID/{ $1=""; sub(/^ /,""); print }')
  if [ "$w0mode" = AP ]; then
    ok "wlan0 serving a hotspot${w_ip:+ (}${w_ip}${w_ip:+)}"
    printf '      %sit cannot follow the target channel while it is an AP%s\n' "$dim" "$off"
  elif [ -n "$w0ssid" ]; then
    ok "wlan0 on '${w0ssid}' ch $($IW dev wlan0 info 2>/dev/null | awk '/channel/{print $2}') -- 'channel auto' follows this"
  else
    warn "wlan0 idle -- join the target network so 'channel auto' has something to copy"
  fi

  head_ 'Saqr'
  if [ -z "$(env_get OPENROUTER_API_KEY)" ]; then bad 'no OPENROUTER_API_KEY -- Saqr will return 503'
  elif curl -s -o /dev/null -m 8 https://openrouter.ai/api/v1/models; then ok 'model provider reachable'
  else bad 'no internet -- Saqr will fail. Everything else still works.'; fi
  [ -n "$(env_get SAQR_ADMIN_TOKEN)" ] && ok 'operator tools enabled' || warn 'no SAQR_ADMIN_TOKEN -- read-only tools only'

  head_ 'Open the dashboard'
  printf '  %shttp://%s.local:%s%s   %s(works even when the IP changes)%s\n' "$bold" "$(hostname)" "$PORT" "$off" "$dim" "$off"
  for ip in $(hostname -I); do
    case "$ip" in *:*) continue;; esac
    printf '  http://%s:%s\n' "$ip" "$PORT"
  done
  printf '\n'
}

set_channel(){
  local ch="$1"
  # `auto` reads the channel wlan0 is actually associated on and listens there.
  # Access points move -- a home router picked 11 one day and 9 the next, and the
  # detector sat on empty air reporting a healthy radio and seen=0. At a venue you
  # will not know the channel in advance, so ask the radio rather than guessing.
  if [ "$ch" = auto ]; then
    ch=$($IW dev wlan0 info 2>/dev/null | awk '/channel/{print $2}')
    if [ -z "$ch" ]; then
      echo "wlan0 is not associated with anything, so there is no channel to copy." >&2
      echo "Join the target network first:  hawkshield wifi <ssid>" >&2
      exit 2
    fi
    echo "wlan0 is on channel $ch -- following it"
  fi
  case "$ch" in ''|*[!0-9]*) echo "channel must be a number, or 'auto'" >&2; exit 2;; esac
  sed -i "s|^CAPTURE_CHANNEL=.*|CAPTURE_CHANNEL=$ch|" "$ENV_FILE"
  echo "CAPTURE_CHANNEL=$ch"
  sudo systemctl restart hawkshield-detector
  sleep 12
  local iface; iface=$(env_get CAPTURE_IFACE)
  $IW dev "$iface" info 2>/dev/null | grep -E 'type|channel' || true
}

join_wifi(){
  local ssid="$1"
  # --ask keeps the password off the command line and out of shell history.
  sudo nmcli --ask device wifi connect "$ssid" ifname wlan0
  sleep 3
  hostname -I
}

# The RTL8811AU sometimes comes back from a mode switch in a state where the
# interface reports monitor mode on the right channel and delivers nothing. No
# amount of re-running `iw` fixes it; re-binding the USB driver does, every time.
reset_radio(){
  local iface dev
  iface=$(env_get CAPTURE_IFACE)
  dev=$(basename "$(readlink -f "/sys/class/net/$iface/device")" 2>/dev/null)
  if [ -z "$dev" ]; then echo "cannot find the USB device behind $iface" >&2; exit 2; fi
  echo "re-binding $iface ($dev)"
  sudo sh -c "echo -n '$dev' > /sys/bus/usb/drivers/rtw88_8821au/unbind" 2>/dev/null || true
  sleep 3
  sudo sh -c "echo -n '$dev' > /sys/bus/usb/drivers/rtw88_8821au/bind" 2>/dev/null || true
  sleep 8
  sudo systemctl restart hawkshield-detector
  sleep 20
  status
}

# When the venue gives you no usable network, wlan0 can serve one. Only sensible
# because eth0 carries the internet -- a hotspot on the only uplink would cut Saqr
# off. Note this costs you `channel auto`: an AP sits on its own channel, not the
# target's, so set the capture channel by hand afterwards.
start_hotspot(){
  local ssid="${1:-HawkShield}"
  echo "wlan0 -> hotspot '$ssid' (password will be shown once)"
  sudo nmcli device wifi hotspot ifname wlan0 ssid "$ssid" || return 1
  sudo nmcli device wifi show-password ifname wlan0 2>/dev/null || true
  printf '\nJoin that network, then open http://%s.local:%s\n' "$(hostname)" "$PORT"
  printf '%sSet the capture channel by hand now -- channel auto follows wlan0, which is the hotspot.%s\n' "$dim" "$off"
}

case "${1:-status}" in
  status|'')  status ;;
  reset)      reset_radio ;;
  hotspot)    start_hotspot "${2:-}" ;;
  channel)    set_channel "${2:?usage: hawkshield channel <number>}" ;;
  wifi)       join_wifi "${2:?usage: hawkshield wifi <ssid>}" ;;
  restart)    sudo systemctl restart hawkshield-api hawkshield-detector; sleep 12; status ;;
  logs)       journalctl -u hawkshield-detector -f --no-pager ;;
  *)          sed -n '3,17p' "$0" | sed 's/^# \{0,1\}//' ;;
esac
