#!/usr/bin/env python3
"""
HawkShield launcher -- one command, both machines.

    python run.py

Works out where it is running and starts the right things:

  Raspberry Pi   detector (live 802.11 capture) + API + dashboard
  Laptop         API + dashboard, reading whatever is in the database

Override anything:

    python run.py --mode laptop        force laptop behaviour on the Pi
    python run.py --mode pi            force Pi behaviour (needs a monitor-mode adapter)
    python run.py --demo               replay a sample capture into the DB first
    python run.py --port 8080          serve somewhere else
    python run.py --no-detector        Pi, but dashboard only

Stdlib only. Ctrl-C stops everything cleanly.
"""
from __future__ import annotations

import argparse
import os
import platform
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

# Windows consoles default to a legacy code page; keep output safe either way.
try:  # pragma: no cover - platform dependent
    # line_buffering keeps our output interleaved correctly with uvicorn's when
    # this script is piped to a log file rather than a terminal.
    sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
    sys.stderr.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
except Exception:
    pass

REPO_ROOT = Path(__file__).resolve().parent
DEFAULT_PORT = 8000
SAMPLE_CAPTURE = REPO_ROOT / "data" / "samples" / "assoc_flood_raw_decrypted.pcapng"

# --- tiny terminal helpers ---
_COLOUR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLOUR else text


def ok(msg: str) -> None:
    print(f"  {_c('32', 'OK')}    {msg}")


def warn(msg: str) -> None:
    print(f"  {_c('33', 'WARN')}  {msg}")


def bad(msg: str) -> None:
    print(f"  {_c('31', 'FAIL')}  {msg}")


def info(msg: str) -> None:
    print(f"        {msg}")


def rule(title: str = "") -> None:
    print(f"\n{_c('36', '-- ' + title + ' ' + '-' * max(0, 66 - len(title)))}" if title else "")


# --- environment detection ---
def detect_mode() -> str:
    """Return 'pi' or 'laptop'. Pi detection is by device tree, then architecture."""
    model = Path("/proc/device-tree/model")
    try:
        if model.exists() and "raspberry pi" in model.read_text(errors="ignore").lower():
            return "pi"
    except OSError:
        pass
    if platform.system() == "Linux" and platform.machine() in {"aarch64", "armv7l", "armv6l"}:
        return "pi"
    return "laptop"


def pi_model_name() -> str:
    model = Path("/proc/device-tree/model")
    try:
        return model.read_text(errors="ignore").strip("\x00").strip()
    except OSError:
        return f"{platform.system()} {platform.machine()}"


def lan_ip() -> str:
    """Best-effort LAN address, for the 'open this on your phone' line."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # no packets sent; just picks the default route
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def port_free(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host if host != "0.0.0.0" else "", port))
            return True
        except OSError:
            return False


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0  # type: ignore[attr-defined]


# --- preflight ---
def ensure_env_file() -> None:
    env, example = REPO_ROOT / ".env", REPO_ROOT / ".env.example"
    if env.exists():
        ok(".env found")
    elif example.exists():
        shutil.copyfile(example, env)
        warn(".env was missing -- created it from .env.example")
        info("Defaults are fine for a laptop demo. Edit it for the Pi (DB password, interface).")
    else:
        warn("no .env and no .env.example; falling back to built-in defaults")


def resolve_database_url(mode: str) -> str:
    """Pick a database. Laptops get SQLite for free; the Pi expects PostgreSQL."""
    url = os.environ.get("DATABASE_URL", "").strip()
    if not url:
        # .env is loaded by the app itself, so read it here only to make a decision.
        env = REPO_ROOT / ".env"
        if env.exists():
            for line in env.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if line.startswith("DATABASE_URL=") and not line.startswith("#"):
                    url = line.split("=", 1)[1].strip()
                    break
    if url and "CHANGE_ME" not in url:
        return url

    if mode == "laptop":
        fallback = f"sqlite:///{(REPO_ROOT / 'hawkshield.db').as_posix()}"
        warn("no usable DATABASE_URL -- using a local SQLite file for this session")
        info(f"{fallback}")
        os.environ["DATABASE_URL"] = fallback
        return fallback

    bad("DATABASE_URL is unset or still contains CHANGE_ME")
    info("On the Pi, edit .env and set a real PostgreSQL password, then re-run.")
    info("See deploy/README.md, or run: sudo ./deploy/install_pi.sh")
    sys.exit(2)


def _model_dir() -> Path:
    """MODEL_DIR if set (env or .env), else <repo>/models.

    Hardcoding the path here would disagree with the app's own config, which is
    exactly the kind of drift this project keeps getting bitten by.
    """
    raw = os.environ.get("MODEL_DIR", "").strip()
    if not raw:
        env = REPO_ROOT / ".env"
        if env.exists():
            for line in env.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if line.startswith("MODEL_DIR=") and not line.startswith("#"):
                    raw = line.split("=", 1)[1].strip()
                    break
    if not raw:
        return REPO_ROOT / "models"
    d = Path(raw)
    return d if d.is_absolute() else (REPO_ROOT / d)


def check_models() -> bool:
    """Any one of the three targets is enough to run.

    v2-gbdt is a LightGBM text model plus the shared meta; v2-tcn is the ONNX
    graph plus the same meta; v1 is the two joblib bundles. The detector picks
    whichever is valid, so refusing to start because the *others* are absent would
    block a perfectly good single-target checkout for no reason.
    """
    d = _model_dir()
    meta = d / "hawkshield_v2_meta.json"
    gbdt = (d / "hawkshield_v2_gbdt.txt", meta)
    tcn = (d / "hawkshield_v2.onnx", meta)
    v1 = (d / "stage1_binary_bundle.joblib", d / "stage2_multiclass_bundle.joblib")

    found = []
    if all(f.exists() for f in gbdt):
        found.append("v2-gbdt (LightGBM + causal rolling aggregates)")
    if all(f.exists() for f in tcn):
        found.append("v2-tcn (causal TCN, ONNX)")
    if all(f.exists() for f in v1):
        found.append("v1 (two-stage LightGBM bundles)")

    if found:
        ok("model present: " + ", ".join(found))
        if found[0].startswith("v2-gbdt"):
            info("MODEL_VERSION=auto will serve v2-gbdt -- it won on the held-out set")
        return True

    bad(f"no usable model in {d}")
    info("Expected any of: hawkshield_v2_gbdt.txt + hawkshield_v2_meta.json (v2-gbdt),")
    info("hawkshield_v2.onnx + hawkshield_v2_meta.json (v2-tcn),")
    info("or stage1_binary_bundle.joblib + stage2_multiclass_bundle.joblib (v1).")
    return False


def check_frontend() -> bool:
    index = REPO_ROOT / "frontend" / "out" / "index.html"
    if index.exists():
        ok("dashboard build found (frontend/out)")
        return True
    warn("no dashboard build at frontend/out -- the API will run, but there is no UI")
    info("Build it on a machine with internet:  cd frontend && npm install && npm run build")
    return False


def init_database(py: str) -> bool:
    r = subprocess.run([py, "-m", "backend.scripts.init_db"], cwd=REPO_ROOT,
                       capture_output=True, text=True)
    if r.returncode == 0:
        ok("database reachable, schema ready")
        return True
    bad("could not reach the database")
    for line in (r.stderr or r.stdout).strip().splitlines()[-4:]:
        info(line)
    return False


def packets_in_db(py: str) -> int | None:
    code = ("from backend.app.db import SessionLocal;"
            "from sqlalchemy import text;"
            "s=SessionLocal();"
            "print(s.execute(text('SELECT COUNT(*) FROM packets')).scalar());"
            "s.close()")
    r = subprocess.run([py, "-c", code], cwd=REPO_ROOT, capture_output=True, text=True)
    try:
        return int(r.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return None


def run_demo_replay(py: str, capture: Path, limit: int) -> None:
    if not capture.exists():
        bad(f"sample capture not found: {capture}")
        return
    info(f"replaying {capture.name} ({limit} frames) into the database...")
    r = subprocess.run([py, "backend/scripts/replay_pcap.py", str(capture),
                        "--to-db", "--limit", str(limit)],
                       cwd=REPO_ROOT, capture_output=True, text=True)
    for line in (r.stdout or "").splitlines():
        if "persisted" in line or "stage-1" in line or "packets read" in line:
            info(line.strip())
    if r.returncode != 0:
        bad("replay failed")
        for line in (r.stderr or "").strip().splitlines()[-4:]:
            info(line)


# --- process management ---
class Runner:
    def __init__(self) -> None:
        self.procs: list[tuple[str, subprocess.Popen]] = []

    def start(self, name: str, cmd: list[str]) -> subprocess.Popen:
        p = subprocess.Popen(cmd, cwd=REPO_ROOT)
        self.procs.append((name, p))
        return p

    def stop_all(self) -> None:
        for name, p in reversed(self.procs):
            if p.poll() is None:
                print(f"  stopping {name}...")
                try:
                    p.terminate()
                except OSError:
                    pass
        deadline = time.time() + 8
        for _, p in self.procs:
            while p.poll() is None and time.time() < deadline:
                time.sleep(0.1)
            if p.poll() is None:
                p.kill()


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="run.py", description="Start HawkShield (auto-detects Pi vs laptop).",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=["auto", "pi", "laptop"], default="auto")
    ap.add_argument("--host", default="0.0.0.0", help="bind address (default: all interfaces)")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--demo", action="store_true",
                    help="replay a sample capture into the database before starting")
    ap.add_argument("--demo-capture", type=Path, default=SAMPLE_CAPTURE)
    ap.add_argument("--demo-frames", type=int, default=4000)
    ap.add_argument("--detector", dest="detector", action="store_true", default=None,
                    help="force the live detector on (needs a monitor-mode adapter + root)")
    ap.add_argument("--no-detector", dest="detector", action="store_false",
                    help="dashboard only, no live capture")
    ap.add_argument("--iface", default=None, help="capture interface (default: from .env)")
    ap.add_argument("--channel", default=None, help="Wi-Fi channel (default: from .env)")
    ap.add_argument("--reload", action="store_true", help="uvicorn auto-reload (development)")
    args = ap.parse_args()

    py = sys.executable
    mode = detect_mode() if args.mode == "auto" else args.mode
    run_detector = (mode == "pi") if args.detector is None else args.detector

    print()
    print(_c("1;36", "  HawkShield"))
    print(f"  {pi_model_name()}")
    print(f"  detected: {_c('1', mode.upper())}" + ("" if args.mode == "auto" else "  (forced)"))

    rule("checks")
    ensure_env_file()
    db_url = resolve_database_url(mode)
    info(f"database: {db_url.split('@')[-1] if '@' in db_url else db_url}")
    have_models = check_models()
    check_frontend()

    if not init_database(py):
        if mode == "pi":
            info("Is PostgreSQL running?  sudo systemctl status postgresql")
        return 2

    if not port_free(args.host, args.port):
        bad(f"port {args.port} is already in use")
        info(f"Something else is bound to it. Try: python run.py --port {args.port + 1}")
        return 2

    if run_detector:
        if not have_models:
            bad("cannot start the detector without the model bundles")
            return 2
        if platform.system() != "Linux":
            warn(f"live capture needs Linux; {platform.system()} cannot run the detector")
            info("Starting the dashboard only. Use --demo to load sample data.")
            run_detector = False
        elif not is_root():
            warn("not running as root -- the detector needs raw-socket access")
            info(f"Dashboard only for now. For live capture:  sudo {py} run.py")
            run_detector = False

    if args.demo:
        rule("demo data")
        run_demo_replay(py, args.demo_capture, args.demo_frames)
    elif mode == "laptop" and not run_detector:
        n = packets_in_db(py)
        if n == 0:
            warn("the database is empty -- the dashboard will render but show nothing")
            info("Load sample attacks with:  python run.py --demo")

    runner = Runner()
    stopping = False

    def handle_signal(signum, _frame):  # noqa: ANN001
        nonlocal stopping
        if stopping:
            return
        stopping = True
        print("\n  shutting down...")
        runner.stop_all()

    signal.signal(signal.SIGINT, handle_signal)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, handle_signal)

    rule("starting")
    if run_detector:
        cmd = [py, "-m", "backend.detector.cli"]
        if args.iface:
            cmd += ["--iface", args.iface]
        if args.channel:
            cmd += ["--channel", str(args.channel)]
        runner.start("detector", cmd)
        ok("detector started (live 802.11 capture)")
        info("If it reports no packets, the adapter is probably not in monitor mode:")
        info("  sudo ./deploy/monitor_mode.sh wlan1 6")
    else:
        info("detector off -- dashboard reads existing data only")

    uvicorn_cmd = [py, "-m", "uvicorn", "backend.app.main:app",
                   "--host", args.host, "--port", str(args.port), "--log-level", "info"]
    if args.reload:
        uvicorn_cmd.append("--reload")
    runner.start("api", uvicorn_cmd)

    time.sleep(2.5)
    ip = lan_ip()
    print()
    print(f"  {_c('1;32', 'Dashboard')}   http://localhost:{args.port}")
    if ip != "127.0.0.1":
        print(f"              http://{ip}:{args.port}   {_c('2', '(from another device on this network)')}")
    print(f"  {_c('2', 'API docs')}    http://localhost:{args.port}/docs")
    print(f"  {_c('2', 'Health')}      http://localhost:{args.port}/health")
    print(f"\n  {_c('2', 'Ctrl-C to stop')}\n")

    try:
        while not stopping:
            for name, p in runner.procs:
                rc = p.poll()
                if rc is not None and not stopping:
                    print(f"\n  {_c('31', name + ' exited')} (code {rc})")
                    runner.stop_all()
                    return rc or 1
            time.sleep(0.4)
    except KeyboardInterrupt:
        handle_signal(signal.SIGINT, None)
    return 0


if __name__ == "__main__":
    sys.exit(main())
