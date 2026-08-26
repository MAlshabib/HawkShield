#!/usr/bin/env bash
# =============================================================================
# HawkShield - put a Wi-Fi adapter into monitor mode and pin it to a channel
# =============================================================================
#
#   sudo ./monitor_mode.sh wlan1 6            # monitor mode, channel 6
#   sudo ./monitor_mode.sh --restore wlan1    # back to managed / NetworkManager
#   ./monitor_mode.sh --help
#
# HARDWARE NOTE - read this before opening a bug:
# The Raspberry Pi 4's built-in wlan0 uses a Broadcom/Cypress chip whose closed
# firmware does NOT support monitor mode. "iw dev wlan0 set monitor none" either
# fails outright or reports success while capturing nothing. HawkShield expects
# an EXTERNAL USB adapter (typically wlan1) on a chipset with real monitor
# support - Atheros AR9271, Ralink RT3070/RT5372, Realtek RTL8812AU with the
# aircrack-ng driver, MediaTek MT7601U, and similar.
#
# Idempotent: re-running against an interface already in monitor mode on the
# requested channel is a no-op that still verifies and prints the state.
# =============================================================================

set -euo pipefail

readonly SCRIPT_NAME="${0##*/}"

# --- output helpers ----------------------------------------------------------
if [[ -t 1 ]]; then
    C_RED=$'\033[0;31m'; C_GRN=$'\033[0;32m'; C_YLW=$'\033[0;33m'
    C_BLU=$'\033[0;34m'; C_OFF=$'\033[0m'
else
    C_RED=''; C_GRN=''; C_YLW=''; C_BLU=''; C_OFF=''
fi

info()  { printf '%s[*]%s %s\n' "$C_BLU" "$C_OFF" "$*"; }
ok()    { printf '%s[+]%s %s\n' "$C_GRN" "$C_OFF" "$*"; }
warn()  { printf '%s[!]%s %s\n' "$C_YLW" "$C_OFF" "$*" >&2; }
die()   { printf '%s[x] %s%s\n' "$C_RED" "$*" "$C_OFF" >&2; exit 1; }

usage() {
    cat <<USAGE_TEXT_EOF
${SCRIPT_NAME} - HawkShield monitor-mode helper

USAGE
    sudo ${SCRIPT_NAME} <interface> <channel>
    sudo ${SCRIPT_NAME} --restore <interface>
    ${SCRIPT_NAME} --help

ARGUMENTS
    <interface>   Wi-Fi interface, e.g. wlan1. Must be an external USB adapter;
                  the Pi's built-in wlan0 firmware does not do monitor mode.
    <channel>     2.4 GHz channel 1-14, or a 5 GHz channel the adapter supports.

OPTIONS
    --restore     Return <interface> to managed mode and hand it back to
                  NetworkManager. Takes no channel argument.
    -h, --help    This text.

EXAMPLES
    sudo ${SCRIPT_NAME} wlan1 6
    sudo ${SCRIPT_NAME} --restore wlan1

The channel must match CAPTURE_CHANNEL in your .env and the interface must
match CAPTURE_IFACE, or the detector will listen to the wrong thing.
USAGE_TEXT_EOF
}

# --- preflight ---------------------------------------------------------------
require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        die "must run as root. Try: sudo ${SCRIPT_NAME} $*"
    fi
}

require_linux() {
    if [[ "$(uname -s)" != "Linux" ]]; then
        die "this script only runs on Linux (target: Raspberry Pi OS Bookworm). Detected: $(uname -s)"
    fi
}

require_tool() {
    local tool="$1" pkg="$2"
    if ! command -v "$tool" >/dev/null 2>&1; then
        die "'${tool}' not found. Install it with: sudo apt install -y ${pkg}"
    fi
}

require_iface() {
    local iface="$1"
    if [[ ! -e "/sys/class/net/${iface}" ]]; then
        warn "interface '${iface}' does not exist. Interfaces present:"
        ip -br link show 2>/dev/null | sed 's/^/      /' >&2 || true
        die "no such interface: ${iface}. Plug in the USB adapter, or fix CAPTURE_IFACE in .env."
    fi
    if [[ ! -d "/sys/class/net/${iface}/wireless" ]] && ! iw dev "${iface}" info >/dev/null 2>&1; then
        die "'${iface}' exists but is not a wireless interface."
    fi
}

# Current interface type as reported by iw ("managed", "monitor", ...).
iface_type() {
    iw dev "$1" info 2>/dev/null | awk '/^[[:space:]]*type /{print $2; exit}'
}

# --- NetworkManager / wpa_supplicant -----------------------------------------
# NetworkManager will happily yank an interface back into managed mode a second
# after we switch it. Tell it to stop managing this one first.
nm_unmanage() {
    local iface="$1"
    if command -v nmcli >/dev/null 2>&1 && systemctl is-active --quiet NetworkManager 2>/dev/null; then
        info "telling NetworkManager to stop managing ${iface}"
        nmcli dev set "${iface}" managed no || warn "nmcli dev set ${iface} managed no failed (continuing)"
    else
        info "NetworkManager not active - nothing to unmanage"
    fi
}

nm_manage() {
    local iface="$1"
    if command -v nmcli >/dev/null 2>&1 && systemctl is-active --quiet NetworkManager 2>/dev/null; then
        info "handing ${iface} back to NetworkManager"
        nmcli dev set "${iface}" managed yes || warn "nmcli dev set ${iface} managed yes failed"
    fi
}

# wpa_supplicant keeps the interface associated and fights the mode change.
# Bookworm runs it under NetworkManager, plus possibly the legacy
# wpa_supplicant@<iface>.service unit.
stop_supplicant() {
    local iface="$1"
    local unit="wpa_supplicant@${iface}.service"
    if systemctl is-active --quiet "${unit}" 2>/dev/null; then
        info "stopping ${unit}"
        systemctl stop "${unit}" || warn "could not stop ${unit} (continuing)"
    fi
    # Any stray per-interface process (started by hand, or by dhcpcd).
    if command -v pgrep >/dev/null 2>&1 && pgrep -f "wpa_supplicant.*${iface}" >/dev/null 2>&1; then
        info "killing stray wpa_supplicant bound to ${iface}"
        pkill -f "wpa_supplicant.*${iface}" || true
    fi
}

start_supplicant() {
    local iface="$1"
    local unit="wpa_supplicant@${iface}.service"
    if systemctl list-unit-files "${unit}" >/dev/null 2>&1; then
        systemctl start "${unit}" 2>/dev/null || true
    fi
}

# --- actions -----------------------------------------------------------------
set_monitor() {
    local iface="$1" channel="$2"

    require_iface "${iface}"

    local before
    before="$(iface_type "${iface}" || true)"
    info "interface ${iface} is currently type: ${before:-unknown}"

    if [[ "${iface}" == "wlan0" ]]; then
        warn "wlan0 is normally the Pi's built-in radio, whose firmware does not"
        warn "support monitor mode. If this fails, use an external USB adapter."
    fi

    nm_unmanage "${iface}"
    stop_supplicant "${iface}"

    info "bringing ${iface} down"
    ip link set "${iface}" down

    info "setting ${iface} to monitor mode"
    if ! iw dev "${iface}" set monitor none; then
        ip link set "${iface}" up || true
        die "iw dev ${iface} set monitor none failed. This chipset/driver most likely does
      not support monitor mode. Check with:  iw phy | grep -A10 'Supported interface modes'"
    fi

    info "bringing ${iface} up"
    ip link set "${iface}" up

    info "pinning ${iface} to channel ${channel}"
    if ! iw dev "${iface}" set channel "${channel}"; then
        die "could not set channel ${channel} on ${iface}. The adapter may not support it
      (5 GHz on a 2.4-only dongle, or a regulatory-domain restriction).
      List what it supports with:  iw phy | grep -E 'MHz|Frequencies'"
    fi

    verify_monitor "${iface}" "${channel}"
}

verify_monitor() {
    local iface="$1" channel="$2"
    local info_out type_now

    info_out="$(iw dev "${iface}" info 2>&1 || true)"
    type_now="$(printf '%s\n' "${info_out}" | awk '/^[[:space:]]*type /{print $2; exit}')"

    printf '\n%s--- iw dev %s info ---%s\n' "$C_BLU" "${iface}" "$C_OFF"
    printf '%s\n' "${info_out}"
    printf '%s----------------------%s\n\n' "$C_BLU" "$C_OFF"

    if [[ "${type_now}" != "monitor" ]]; then
        die "verification FAILED: ${iface} reports type '${type_now:-unknown}', expected 'monitor'.
      Something re-claimed the interface, usually NetworkManager or wpa_supplicant.
      Check:  systemctl status NetworkManager ; nmcli dev status"
    fi

    ok "${iface} is in MONITOR mode, channel ${channel}"
    printf '    resulting type: %s%s%s\n' "$C_GRN" "${type_now}" "$C_OFF"
    printf '    next: confirm CAPTURE_IFACE=%s and CAPTURE_CHANNEL=%s in your .env,\n' "${iface}" "${channel}"
    printf '          then: sudo systemctl restart hawkshield-detector\n'
}

restore_managed() {
    local iface="$1"

    require_iface "${iface}"
    info "restoring ${iface} to managed mode"

    ip link set "${iface}" down
    if ! iw dev "${iface}" set type managed; then
        ip link set "${iface}" up || true
        die "iw dev ${iface} set type managed failed."
    fi
    ip link set "${iface}" up

    nm_manage "${iface}"
    start_supplicant "${iface}"

    local type_now
    type_now="$(iface_type "${iface}" || true)"
    printf '\n%s--- iw dev %s info ---%s\n' "$C_BLU" "${iface}" "$C_OFF"
    iw dev "${iface}" info 2>&1 || true
    printf '%s----------------------%s\n\n' "$C_BLU" "$C_OFF"

    if [[ "${type_now}" != "managed" ]]; then
        warn "expected type 'managed', got '${type_now:-unknown}'. It may settle once"
        warn "NetworkManager re-scans; check with: nmcli dev status"
    else
        ok "${iface} restored to MANAGED mode (resulting type: ${type_now})"
    fi
}

# --- main --------------------------------------------------------------------
main() {
    if [[ $# -eq 0 ]]; then
        usage
        exit 2
    fi
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
    esac

    require_linux
    require_tool iw "iw"
    require_tool ip "iproute2"

    if [[ "$1" == "--restore" ]]; then
        if [[ $# -ne 2 ]]; then
            usage
            die "--restore takes exactly one argument: the interface"
        fi
        require_root "$@"
        restore_managed "$2"
        return
    fi

    if [[ $# -ne 2 ]]; then
        usage
        die "expected 2 arguments: <interface> <channel>"
    fi

    local iface="$1" channel="$2"
    if ! [[ "${channel}" =~ ^[0-9]+$ ]]; then
        die "channel must be a number, got: '${channel}'"
    fi

    require_root "$@"
    set_monitor "${iface}" "${channel}"
}

main "$@"
