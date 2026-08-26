#!/usr/bin/env bash
# =============================================================================
# HawkShield - Raspberry Pi installer
# =============================================================================
# Takes a fresh clone on a fresh Raspberry Pi OS Bookworm install to a running
# system: apt deps, PostgreSQL role + database, virtualenv, schema, systemd.
#
#   git clone <repo> ~/HawkShield
#   cd ~/HawkShield
#   sudo ./deploy/install_pi.sh
#
# The install path is wherever you cloned it - this script detects the repo root
# from its own location and rewrites the /opt/hawkshield placeholder inside the
# systemd unit templates before installing them.
#
# IDEMPOTENT. Run it as many times as you like:
#   - apt install is a no-op for packages already present
#   - the SQL script skips an existing role/database and never resets a password
#   - the venv is reused; pip re-resolves the pins
#   - an existing .env is never overwritten
#   - the systemd units are rewritten and reloaded every run
#
# It deliberately STOPS after creating .env for the first time. It will not
# invent a database password for you.
#
# Options:
#   --skip-apt     do not touch apt (useful for a fast re-run)
#   --no-enable    install the units but do not enable/start them
#   -h, --help
# =============================================================================

set -euo pipefail

# --- constants ---------------------------------------------------------------
readonly SCRIPT_NAME="${0##*/}"
readonly REQUIRED_PY_MAJOR=3
readonly REQUIRED_PY_MINOR=11
readonly UNIT_PLACEHOLDER='/opt/hawkshield'
readonly SYSTEMD_DIR='/etc/systemd/system'
readonly UNITS=(hawkshield-api.service hawkshield-detector.service)

# Repo root = parent of the directory holding this script.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
readonly REPO_ROOT
readonly VENV_DIR="${REPO_ROOT}/.venv"
readonly ENV_FILE="${REPO_ROOT}/.env"
readonly ENV_EXAMPLE="${REPO_ROOT}/.env.example"

SKIP_APT=0
NO_ENABLE=0

# apt packages.
#   iw / wireless-tools     monitor mode + channel control
#   libpcap0.8              scapy's capture backend
#   libgomp1                REQUIRED by the lightgbm aarch64 wheel at import time
#   postgresql              the database
#   libpq-dev + build-essential + python3-dev
#                           only needed if a wheel is missing for this arch and
#                           pip has to build from source (psycopg2 in particular)
readonly APT_PACKAGES=(
    python3
    python3-venv
    python3-pip
    python3-dev
    build-essential
    libpq-dev
    postgresql
    iw
    wireless-tools
    libpcap0.8
    libgomp1
    git
    curl
)

# --- output helpers ----------------------------------------------------------
if [[ -t 1 ]]; then
    C_RED=$'\033[0;31m'; C_GRN=$'\033[0;32m'; C_YLW=$'\033[0;33m'
    C_BLU=$'\033[0;34m'; C_BLD=$'\033[1m'; C_OFF=$'\033[0m'
else
    C_RED=''; C_GRN=''; C_YLW=''; C_BLU=''; C_BLD=''; C_OFF=''
fi

step()  { printf '\n%s==>%s %s%s%s\n' "$C_BLU" "$C_OFF" "$C_BLD" "$*" "$C_OFF"; }
info()  { printf '    %s\n' "$*"; }
ok()    { printf '    %s[ok]%s %s\n' "$C_GRN" "$C_OFF" "$*"; }
warn()  { printf '    %s[!]%s %s\n' "$C_YLW" "$C_OFF" "$*" >&2; }
die()   { printf '\n%s[FATAL] %s%s\n\n' "$C_RED" "$*" "$C_OFF" >&2; exit 1; }

usage() {
    # Print the header comment block: every comment line after the shebang, up
    # to the first line that is not a comment.
    awk 'NR==1 {next} /^#/ {sub(/^# ?/, ""); print; next} {exit}' "${BASH_SOURCE[0]}"
}

# =============================================================================
# Preflight
# =============================================================================
preflight() {
    step "Preflight checks"

    # --- OS ---
    if [[ "$(uname -s)" != "Linux" ]]; then
        die "This installer targets Raspberry Pi OS (Linux). Detected: $(uname -s).
        Nothing here works on macOS or Windows/WSL-without-systemd. Run it on the Pi."
    fi
    ok "Linux: $(uname -sr)"

    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        info "distro: ${PRETTY_NAME:-unknown}  (arch: $(uname -m))"
        if [[ "${VERSION_CODENAME:-}" != "bookworm" ]]; then
            warn "expected Raspberry Pi OS Bookworm, found '${VERSION_CODENAME:-unknown}'."
            warn "Continuing, but package names and PostgreSQL version may differ."
        fi
    fi

    # --- root ---
    if [[ "${EUID}" -ne 0 ]]; then
        die "Must run as root (apt, systemd and postgres all need it).
        Try:  sudo ${SCRIPT_DIR}/${SCRIPT_NAME}"
    fi
    ok "running as root"

    # --- systemd ---
    if ! command -v systemctl >/dev/null 2>&1; then
        die "systemctl not found - this system does not run systemd, so the
        hawkshield-api / hawkshield-detector services cannot be installed."
    fi
    ok "systemd present"

    # --- python ---
    local py_bin py_ver py_major py_minor
    py_bin="$(command -v python3 || true)"
    [[ -n "${py_bin}" ]] || die "python3 not found. Install it: sudo apt install -y python3 python3-venv"
    py_ver="$("${py_bin}" -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])')"
    py_major="${py_ver%%.*}"
    py_minor="$(printf '%s' "${py_ver}" | cut -d. -f2)"
    if (( py_major != REQUIRED_PY_MAJOR || py_minor < REQUIRED_PY_MINOR )); then
        die "Python ${REQUIRED_PY_MAJOR}.${REQUIRED_PY_MINOR}+ required, found ${py_ver} at ${py_bin}.
        Raspberry Pi OS Bookworm ships 3.11 - if you are on Bullseye, upgrade the OS.
        HawkShield's pinned wheels (lightgbm 4.6.0, numpy 2.3.2) have no 3.10 build here."
    fi
    ok "python ${py_ver} (${py_bin})"
    if (( py_minor > REQUIRED_PY_MINOR )); then
        warn "python ${py_ver} is newer than the tested 3.11; pins may not all have wheels."
    fi

    # --- repo layout sanity ---
    [[ -f "${REPO_ROOT}/backend/requirements.txt" ]] \
        || die "backend/requirements.txt not found under ${REPO_ROOT} - is this a full clone?"
    [[ -f "${ENV_EXAMPLE}" ]] \
        || die ".env.example not found at ${ENV_EXAMPLE} - is this a full clone?"
    for unit in "${UNITS[@]}"; do
        [[ -f "${SCRIPT_DIR}/${unit}" ]] || die "missing unit template: ${SCRIPT_DIR}/${unit}"
    done
    [[ -f "${SCRIPT_DIR}/postgres_setup.sql" ]] || die "missing ${SCRIPT_DIR}/postgres_setup.sql"
    ok "repo root: ${REPO_ROOT}"
}

# =============================================================================
# Service account
# =============================================================================
# The API runs unprivileged. Use the account that owns the checkout - normally
# the human who cloned it (pi / your login), reached through SUDO_USER.
resolve_service_user() {
    step "Resolving the unprivileged account for the API service"

    if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
        SERVICE_USER="${SUDO_USER}"
    else
        # Fall back to the owner of the checkout.
        SERVICE_USER="$(stat -c '%U' "${REPO_ROOT}")"
    fi

    if [[ -z "${SERVICE_USER}" || "${SERVICE_USER}" == "root" ]]; then
        die "Could not determine a non-root account to run the API as.
        Re-run with sudo from your normal login (so SUDO_USER is set), or create a
        dedicated account and chown the checkout to it:
            sudo useradd -r -s /usr/sbin/nologin hawkshield
            sudo chown -R hawkshield: ${REPO_ROOT}"
    fi
    id "${SERVICE_USER}" >/dev/null 2>&1 || die "account '${SERVICE_USER}' does not exist."

    SERVICE_GROUP="$(id -gn "${SERVICE_USER}")"
    readonly SERVICE_USER SERVICE_GROUP
    ok "API will run as ${SERVICE_USER}:${SERVICE_GROUP} (detector runs as root - raw sockets)"
}

# =============================================================================
# apt
# =============================================================================
install_apt_packages() {
    step "Installing system packages"

    if (( SKIP_APT )); then
        warn "--skip-apt given, skipping apt entirely"
        return
    fi

    local missing=()
    local pkg
    for pkg in "${APT_PACKAGES[@]}"; do
        if ! dpkg-query -W -f='${Status}' "${pkg}" 2>/dev/null | grep -q '^install ok installed$'; then
            missing+=("${pkg}")
        fi
    done

    if (( ${#missing[@]} == 0 )); then
        ok "all ${#APT_PACKAGES[@]} packages already installed"
    else
        info "installing: ${missing[*]}"
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get install -y --no-install-recommends "${missing[@]}"
        ok "installed ${#missing[@]} package(s)"
    fi

    # Hard requirement checks that survive --skip-apt on a later run.
    command -v iw >/dev/null 2>&1 \
        || die "'iw' is still not available. Monitor mode is impossible without it.
        Install it manually:  sudo apt install -y iw wireless-tools"
    ok "iw: $(command -v iw)"

    # libgomp is what makes the lightgbm wheel importable on aarch64.
    if ! ldconfig -p 2>/dev/null | grep -q 'libgomp\.so\.1'; then
        die "libgomp.so.1 not found. 'import lightgbm' will fail with an OSError.
        Install it:  sudo apt install -y libgomp1"
    fi
    ok "libgomp.so.1 present (lightgbm runtime dependency)"
}

# =============================================================================
# PostgreSQL
# =============================================================================
setup_postgres_service() {
    step "Enabling PostgreSQL"

    systemctl enable postgresql >/dev/null 2>&1 || warn "could not enable postgresql (continuing)"
    if ! systemctl is-active --quiet postgresql; then
        info "starting postgresql"
        systemctl start postgresql || die "failed to start PostgreSQL.
        Look at:  systemctl status postgresql ; journalctl -u postgresql -n 50"
    fi
    ok "postgresql.service is active"

    # is-active on the wrapper unit can be true while no cluster listens. Prove
    # a real connection before we try to create anything.
    if ! su - postgres -c 'psql -tAc "SELECT 1"' >/dev/null 2>&1; then
        die "PostgreSQL is not reachable as the 'postgres' superuser.
        The service claims to be running but 'psql -c \"SELECT 1\"' failed.
        Check the cluster:   sudo pg_lsclusters
        Start it:            sudo pg_ctlcluster <version> main start
        Then look at:        sudo journalctl -u postgresql -n 50"
    fi
    ok "PostgreSQL reachable ($(su - postgres -c "psql -tAc 'SHOW server_version'" | tr -d ' '))"
}

# Pull the password out of DATABASE_URL in .env so the role we create and the
# URL the app connects with can never disagree.
db_password_from_env_file() {
    local url
    url="$(grep -E '^[[:space:]]*DATABASE_URL=' "${ENV_FILE}" | tail -n1 | cut -d= -f2- || true)"
    [[ -n "${url}" ]] || return 1
    # postgresql+psycopg2://USER:PASSWORD@HOST:PORT/DB
    # Passed through the environment, not argv: /proc/<pid>/cmdline is
    # world-readable on Linux, /proc/<pid>/environ is not.
    HS_DB_URL="${url}" python3 - <<'PYEOF'
import os
from urllib.parse import urlsplit, unquote
try:
    parts = urlsplit(os.environ["HS_DB_URL"].strip().strip('"').strip("'"))
    print(unquote(parts.password or ""))
except Exception:
    print("")
PYEOF
}

setup_database() {
    step "Creating the hawkshield role and database"

    local pw
    pw="$(db_password_from_env_file || true)"

    if [[ -z "${pw}" || "${pw}" == "CHANGE_ME" ]]; then
        die "DATABASE_URL in ${ENV_FILE} still has no usable password
        (found: '${pw:-<empty>}').
        Edit it and set a real one, keeping this exact shape:

            DATABASE_URL=postgresql+psycopg2://hawkshield:YOURPASSWORD@localhost:5432/hawkshield

        Then re-run this installer. The password you put there is the password
        the 'hawkshield' PostgreSQL role will be created with - this script will
        never make one up for you."
    fi

    info "using the password from DATABASE_URL in .env (not shown)"

    # Hand the password to psql through a 0600 temp script rather than `-v` on
    # the command line: /proc/<pid>/cmdline is world-readable. The whole of
    # postgres_setup.sql is inlined into the temp file too, so the postgres user
    # never has to be able to read the checkout (a $HOME at mode 0700 would
    # otherwise break `psql -f`).
    local tmp_sql
    tmp_sql="$(mktemp)"
    # shellcheck disable=SC2064
    trap "rm -f '${tmp_sql}'" RETURN EXIT
    chmod 0600 "${tmp_sql}"

    {
        HS_PW="${pw}" python3 -c \
            'import os; print("\\set hs_password %s" % ("\x27" + os.environ["HS_PW"].replace("\\", "\\\\").replace("\x27", "\\\x27") + "\x27"))'
        cat "${SCRIPT_DIR}/postgres_setup.sql"
    } > "${tmp_sql}"
    chown postgres "${tmp_sql}"

    su - postgres -c "psql -v ON_ERROR_STOP=1 -f '${tmp_sql}'" \
        || die "deploy/postgres_setup.sql failed. See the psql output above."

    ok "role + database ready"

    # Prove the app's own credentials actually work over TCP, which is what
    # SQLAlchemy will use - peer auth succeeding tells us nothing about that.
    if ! PGPASSWORD="${pw}" psql -h localhost -U hawkshield -d hawkshield -tAc 'SELECT 1' >/dev/null 2>&1; then
        die "Created the role, but connecting as hawkshield@localhost FAILED.
        This is almost always pg_hba.conf: the 'host ... 127.0.0.1/32' line needs
        method 'scram-sha-256' (or 'md5'), not 'ident'.

            sudo nano /etc/postgresql/*/main/pg_hba.conf
            sudo systemctl reload postgresql

        Or, if the role predates this install, its password differs from .env:
            sudo -u postgres psql -c \"ALTER ROLE hawkshield WITH PASSWORD 'thepasswordinyour.env';\""
    fi
    ok "verified: hawkshield@localhost:5432/hawkshield accepts the .env password"
}

# =============================================================================
# .env
# =============================================================================
ensure_env_file() {
    step "Configuration file (.env)"

    if [[ -f "${ENV_FILE}" ]]; then
        ok "${ENV_FILE} already exists - leaving it untouched"
        return 0
    fi

    install -o "${SERVICE_USER}" -g "${SERVICE_GROUP}" -m 0600 "${ENV_EXAMPLE}" "${ENV_FILE}"

    cat <<BANNER

${C_YLW}${C_BLD}  ============================================================${C_OFF}
${C_YLW}${C_BLD}   STOP - configuration required before the install continues${C_OFF}
${C_YLW}${C_BLD}  ============================================================${C_OFF}

  Created:  ${ENV_FILE}   (mode 0600, owned by ${SERVICE_USER})
  From:     ${ENV_EXAMPLE}

  No password has been generated for you. Open the file and set, at minimum:

    ${C_BLD}DATABASE_URL${C_OFF}   pick a password and put it here, exactly in this shape:
                     DATABASE_URL=postgresql+psycopg2://hawkshield:YOURPASSWORD@localhost:5432/hawkshield
                   (currently the placeholder ...:CHANGE_ME@...)
                   Whatever you write becomes the PostgreSQL role's password -
                   this installer reads it back out on the next run.

    ${C_BLD}CAPTURE_IFACE${C_OFF}  the monitor-mode adapter. Default: wlan1.
                   Confirm the real name with:  ip -br link
                   The Pi's built-in wlan0 does NOT support monitor mode.

  Optional, everything works without them:

    CAPTURE_CHANNEL   channel to pin (default 6) - must match monitor_mode.sh
    OPENROUTER_API_KEY  leave empty and POST /ask returns HTTP 503; nothing else
                      is affected.

  Then:

      nano ${ENV_FILE}
      sudo ${SCRIPT_DIR}/${SCRIPT_NAME}

BANNER
    exit 3
}

# =============================================================================
# virtualenv
# =============================================================================
setup_venv() {
    step "Python virtualenv"

    if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
        info "creating ${VENV_DIR}"
        su "${SERVICE_USER}" -s /bin/bash -c "python3 -m venv '${VENV_DIR}'" \
            || die "python3 -m venv failed. Install the venv module: sudo apt install -y python3-venv"
    else
        ok "reusing existing venv"
    fi

    info "upgrading pip / setuptools / wheel"
    su "${SERVICE_USER}" -s /bin/bash -c "'${VENV_DIR}/bin/pip' install --quiet --upgrade pip setuptools wheel" \
        || die "could not upgrade pip inside ${VENV_DIR}"

    info "installing pinned dependencies (this takes a few minutes on a Pi)"
    su "${SERVICE_USER}" -s /bin/bash -c "'${VENV_DIR}/bin/pip' install -r '${REPO_ROOT}/backend/requirements.txt'" \
        || die "pip install failed.
        If a wheel was missing and the source build broke, the usual fixes are:
            sudo apt install -y build-essential python3-dev libpq-dev
        then re-run this installer."

    # Import-check the two things most likely to be broken by a missing .so.
    su "${SERVICE_USER}" -s /bin/bash -c "'${VENV_DIR}/bin/python' -c 'import lightgbm, scapy; print(lightgbm.__version__)'" >/dev/null \
        || die "the venv installed but 'import lightgbm' / 'import scapy' failed.
        For lightgbm this is nearly always the missing OpenMP runtime:
            sudo apt install -y libgomp1"
    ok "dependencies installed and importable"
}

# =============================================================================
# schema
# =============================================================================
init_database_schema() {
    step "Creating the database schema"

    # Run from the repo root: backend/ must be importable as a package.
    su "${SERVICE_USER}" -s /bin/bash -c "cd '${REPO_ROOT}' && '${VENV_DIR}/bin/python' -m backend.scripts.init_db" \
        || die "python -m backend.scripts.init_db failed. See the traceback above.
        The usual cause is a DATABASE_URL in .env that does not match the role
        created earlier."
    ok "schema ready (table 'packets')"
}

# =============================================================================
# systemd
# =============================================================================
install_units() {
    step "Installing systemd units"

    local unit src tmp
    for unit in "${UNITS[@]}"; do
        src="${SCRIPT_DIR}/${unit}"
        tmp="$(mktemp)"

        # Rewrite the placeholder install path, and the service account for the
        # unprivileged API unit. The detector unit intentionally stays root.
        sed -e "s|${UNIT_PLACEHOLDER}|${REPO_ROOT}|g" "${src}" > "${tmp}"
        if [[ "${unit}" == "hawkshield-api.service" ]]; then
            sed -i \
                -e "s|^User=hawkshield$|User=${SERVICE_USER}|" \
                -e "s|^Group=hawkshield$|Group=${SERVICE_GROUP}|" \
                "${tmp}"
        fi

        install -m 0644 -o root -g root "${tmp}" "${SYSTEMD_DIR}/${unit}"
        rm -f "${tmp}"
        ok "${SYSTEMD_DIR}/${unit}"
    done

    systemctl daemon-reload

    # Catch a malformed unit now rather than at boot.
    if command -v systemd-analyze >/dev/null 2>&1; then
        local u
        for u in "${UNITS[@]}"; do
            systemd-analyze verify "${SYSTEMD_DIR}/${u}" 2>&1 | sed 's/^/    /' || true
        done
    fi

    if (( NO_ENABLE )); then
        warn "--no-enable given: units installed but not enabled or started"
        return
    fi

    local u
    for u in "${UNITS[@]}"; do
        systemctl enable "${u}" >/dev/null 2>&1 || warn "could not enable ${u}"
    done
    ok "both units enabled at boot"

    info "starting hawkshield-api"
    systemctl restart hawkshield-api || warn "hawkshield-api failed to start - see: journalctl -u hawkshield-api -n 50"

    # The detector needs the adapter in monitor mode first, so it is enabled but
    # only started if the interface is already there and in the right mode.
    local iface
    iface="$(grep -E '^[[:space:]]*CAPTURE_IFACE=' "${ENV_FILE}" | tail -n1 | cut -d= -f2- | tr -d '"'\''[:space:]' || true)"
    iface="${iface:-wlan1}"

    if [[ -e "/sys/class/net/${iface}" ]] \
        && iw dev "${iface}" info 2>/dev/null | grep -qE '^[[:space:]]*type[[:space:]]+monitor'; then
        info "${iface} is already in monitor mode - starting hawkshield-detector"
        systemctl restart hawkshield-detector || warn "detector failed to start - see: journalctl -u hawkshield-detector -n 50"
    else
        warn "${iface} is not in monitor mode yet - detector enabled but NOT started."
        warn "Run:  sudo ${SCRIPT_DIR}/monitor_mode.sh ${iface} <channel>"
        warn "Then: sudo systemctl start hawkshield-detector"
    fi
}

# =============================================================================
# Summary
# =============================================================================
print_summary() {
    local ip iface channel
    ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    ip="${ip:-<pi-ip>}"
    iface="$(grep -E '^[[:space:]]*CAPTURE_IFACE=' "${ENV_FILE}" | tail -n1 | cut -d= -f2- | tr -d '"'\''[:space:]' || true)"
    iface="${iface:-wlan1}"
    channel="$(grep -E '^[[:space:]]*CAPTURE_CHANNEL=' "${ENV_FILE}" | tail -n1 | cut -d= -f2- | tr -d '"'\''[:space:]' || true)"
    channel="${channel:-6}"

    cat <<SUMMARY

${C_GRN}${C_BLD}=============================================================${C_OFF}
${C_GRN}${C_BLD} HawkShield installed${C_OFF}
${C_GRN}${C_BLD}=============================================================${C_OFF}

  Install path : ${REPO_ROOT}
  API runs as  : ${SERVICE_USER}:${SERVICE_GROUP}
  Detector     : root (raw sockets / monitor mode)
  Config       : ${ENV_FILE}

  ${C_BLD}1. Put the adapter into monitor mode${C_OFF}
     The Pi's built-in wlan0 cannot do this - use the USB adapter.

       sudo ${SCRIPT_DIR}/monitor_mode.sh ${iface} ${channel}
       sudo systemctl start hawkshield-detector

     To undo it later:
       sudo ${SCRIPT_DIR}/monitor_mode.sh --restore ${iface}

  ${C_BLD}2. Open the dashboard${C_OFF}

       http://${ip}:8000

     (If the page 404s, the frontend has not been built yet:
      cd ${REPO_ROOT}/frontend && npm ci && npm run build)

  ${C_BLD}3. Check status${C_OFF}

       systemctl status hawkshield-api
       systemctl status hawkshield-detector
       curl -s http://localhost:8000/health

  ${C_BLD}4. Follow the logs${C_OFF}

       journalctl -u hawkshield-detector -f
       journalctl -u hawkshield-api -f

  ${C_BLD}5. After a code change${C_OFF}

       cd ${REPO_ROOT} && git pull
       sudo systemctl restart hawkshield-api hawkshield-detector

  Troubleshooting: ${SCRIPT_DIR}/README.md

SUMMARY
}

# =============================================================================
# main
# =============================================================================
main() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --skip-apt)  SKIP_APT=1 ;;
            --no-enable) NO_ENABLE=1 ;;
            -h|--help)   usage; exit 0 ;;
            *)           usage; die "unknown option: $1" ;;
        esac
        shift
    done

    preflight
    resolve_service_user
    install_apt_packages
    ensure_env_file          # exits 3 on first run, after writing .env
    setup_postgres_service
    setup_database
    setup_venv
    init_database_schema
    install_units
    print_summary
}

main "$@"
