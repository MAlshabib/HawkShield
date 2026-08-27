#!/usr/bin/env python3
"""
Go/no-go gate for the shipped ``frontend/out`` build.

Run this before and after any change to the API the built dashboard talks to --
most importantly before and after ``POST /ask`` is reimplemented as a shim over
the Saqr agent:

    python backend/scripts/check_frontend.py

Exit code 0 means the already-built bundle still works end to end against this
backend.  Anything else names the endpoint and the field that broke.

It verifies, in order:
  1. the built bundle exists and the API process actually serves its pages,
  2. every endpoint the bundle really calls answers with the shape it consumes,
  3. ``POST /ask`` returns the exact envelope the built RAG page destructures,
  4. optionally, one live ``/ask`` round-trip through the real model.

Steps 1-3 need no API key, no network and no PostgreSQL: the app runs against a
throwaway seeded SQLite database and the model is faked.  Step 4 runs only when
``OPENROUTER_API_KEY`` is set; without one the script says exactly what it could
not verify and still exits 0, because this gate has to be runnable on an offline
Pi.

The endpoint list and the ``/ask`` field list were extracted from
``frontend/out/_next/static/chunks/`` -- from what the bundle *does*, not from
what the contract says it should do.  That is the entire point: the contract can
be right while the shipped build still breaks.

Exit codes:  0 ok | 2 bundle missing or not served | 3 an API endpoint broke
             4 the /ask envelope broke | 5 the live round-trip broke
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

GREEN, RED, YELLOW, DIM, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"

#: Pages the built export ships.  Serving these proves the static mount is
#: present *and* that no API route was shadowed by it (or vice versa).
PAGES = ("/", "/dashboard/", "/attacks/", "/rag/", "/admin/")

#: Response keys the built RAG page destructures out of ``POST /ask``.
ASK_KEYS = ("mode", "sql", "answer", "cols", "rows", "error")


def ok(msg: str) -> None:
    print(f"  {GREEN}OK{RESET}    {msg}")


def fail(msg: str) -> None:
    print(f"  {RED}FAIL{RESET}  {msg}")


def warn(msg: str) -> None:
    print(f"  {YELLOW}WARN{RESET}  {msg}")


def info(msg: str) -> None:
    print(f"        {DIM}{msg}{RESET}")


def skipped(checks: List[str]) -> None:
    """Name what did not run, rather than letting silence imply a pass."""
    print(f"\n  {YELLOW}Not verified:{RESET}")
    for check in checks:
        print(f"    - {check}")


# --------------------------------------------------------------------------- #
# Fixture: the real app over a throwaway seeded SQLite database                #
# --------------------------------------------------------------------------- #
def _seed(engine: Any) -> None:
    """A handful of attack rows across several classes, spread over time."""
    from sqlalchemy.orm import sessionmaker

    from backend.app.models import Packet

    maker = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    rows: List[Any] = []
    for i in range(6):
        rows.append(
            Packet(
                ts=now - timedelta(minutes=7 * (i + 1)),
                iface="wlan1",
                src_mac=f"AA:BB:CC:DD:EE:{i % 3:02d}",
                dst_mac="FF:FF:FF:FF:FF:FF",
                bssid="AA:AA:AA:AA:AA:01",
                frame_len=120 + i,
                channel_freq=2437 if i % 2 else 5180,
                datarate=1.0,
                signal_dbm=-42.0 - i,
                wlan_ds=0,
                wlan_retry=0,
                wlan_type=0,
                wlan_subtype=12,
                wlan_duration=0,
                proba_anomaly=0.95,
                proba_attack=0.91,
                predicted_label=("Deauth", "Kr00k", "Disas")[i % 3],
                raw={"iface": "wlan1", "ssid": "HawkNet"},
            )
        )
    session = maker()
    try:
        session.add_all(rows)
        session.commit()
    finally:
        session.close()


@contextmanager
def app_client(db_path: Path) -> Iterator[Any]:
    """The real application, serving the real bundle, over a seeded SQLite file.

    ``DATABASE_URL`` and ``backend.app.db.engine`` are both repointed, not just
    the ``get_db`` dependency: ``/ask`` reaches the database through the module
    engine rather than through the request's session, so overriding only the
    dependency would leave it talking to the configured PostgreSQL.  (The Saqr
    agent does honour the request's bind; this is a property of the current
    ``packet_qa`` path, and the gate has to work for both.)
    """
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session, sessionmaker
    from sqlalchemy.pool import StaticPool

    from backend.app import db as db_module
    from backend.app.config import settings
    from backend.app.db import Base, get_db
    from backend.app.main import app

    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(bind=engine)
    _seed(engine)

    original_engine = db_module.engine
    original_url = settings.DATABASE_URL
    db_module.engine = engine
    settings.DATABASE_URL = f"sqlite:///{db_path}"

    def override_get_db() -> Iterator[Session]:
        maker = sessionmaker(bind=engine, autocommit=False, autoflush=False)
        session: Session = maker()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db
    try:
        with TestClient(app) as client:
            yield client
    finally:
        app.dependency_overrides.pop(get_db, None)
        db_module.engine = original_engine
        settings.DATABASE_URL = original_url
        engine.dispose()


@contextmanager
def faked_model(sql: str) -> Iterator[None]:
    """Fake the language model at every boundary ``/ask`` might use.

    Two boundaries are patched because ``/ask`` is being reimplemented:

    * ``packet_qa._get_client`` -- the current text-to-SQL path;
    * ``agent.llm.chat`` / ``chat_stream`` -- the path the S5 shim will use.

    Whichever is live gets a canned reply; the other patch is simply never
    reached.  That is deliberate: this gate has to give the same verdict before
    and after the flip, or it cannot tell you which of the two broke.

    The SQL itself is *not* faked -- it runs against the seeded database, so the
    ``cols``/``rows`` the bundle renders are real query output.
    """
    from backend.app.rag import packet_qa

    routing = json.dumps({"mode": "SQL", "sql": sql, "answer": ""})
    prose = "Deauth is the most frequent detected class in this window."

    class _Completions:
        def __init__(self) -> None:
            self.calls = 0

        def create(self, **kwargs: Any) -> Any:
            self.calls += 1
            content = routing if self.calls == 1 else prose
            return SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content=content))]
            )

    fake_client = SimpleNamespace(chat=SimpleNamespace(completions=_Completions()))

    def fake_chat(messages: Any, **kwargs: Any) -> Any:
        """One tool call, then prose -- enough for a shim to produce an envelope."""
        if kwargs.get("tool_choice") == "none" or kwargs.get("tools") is None:
            return SimpleNamespace(content=prose, tool_calls=None)
        return SimpleNamespace(
            content="",
            tool_calls=[
                SimpleNamespace(
                    id="gate_call_1",
                    type="function",
                    function=SimpleNamespace(
                        name="aggregate_threats",
                        arguments=json.dumps({"group_by": "label"}),
                    ),
                )
            ],
        )

    def fake_chat_stream(messages: Any, **kwargs: Any) -> Iterator[str]:
        yield prose

    from backend.app.agent import llm as agent_llm

    originals = (packet_qa._get_client, agent_llm.chat, agent_llm.chat_stream)
    packet_qa._get_client = lambda: fake_client  # type: ignore[assignment]
    agent_llm.chat = fake_chat  # type: ignore[assignment]
    agent_llm.chat_stream = fake_chat_stream  # type: ignore[assignment]
    try:
        yield
    finally:
        packet_qa._get_client, agent_llm.chat, agent_llm.chat_stream = originals


# --------------------------------------------------------------------------- #
# 1. The bundle is present and served                                          #
# --------------------------------------------------------------------------- #
def check_bundle_served(client: Any) -> bool:
    from backend.app.config import settings

    dist = settings.FRONTEND_DIST
    if not (dist / "index.html").is_file():
        fail(f"no built frontend at {dist}")
        info("Build it first:  cd frontend && npm run build")
        info("Without a build there is nothing for this gate to protect.")
        return False
    ok(f"built bundle present at {dist}")

    broken: List[str] = []
    for page in PAGES:
        response = client.get(page)
        content_type = response.headers.get("content-type", "")
        if response.status_code != 200 or "text/html" not in content_type:
            broken.append(f"{page} -> {response.status_code} {content_type or '(no type)'}")
    if broken:
        fail("the API process does not serve every built page")
        for entry in broken:
            info(entry)
        info("A page 404ing here means the static mount is missing or an API route")
        info("shadowed it. Check the router order in backend/app/main.py.")
        return False
    ok(f"all {len(PAGES)} built pages served by the API process ({', '.join(PAGES)})")
    return True


# --------------------------------------------------------------------------- #
# 2. Every endpoint the bundle actually calls                                  #
# --------------------------------------------------------------------------- #
def _require(condition: bool, message: str, problems: List[str]) -> None:
    if not condition:
        problems.append(message)


def _check_health(body: Any, problems: List[str]) -> None:
    _require(isinstance(body, dict), "not a JSON object", problems)
    for key in ("status", "database", "packets", "models", "model_version", "version"):
        _require(key in body, f"missing key {key!r}", problems)


def _check_attacks(body: Any, problems: List[str]) -> None:
    _require(isinstance(body, list), "not a JSON array", problems)
    if isinstance(body, list) and body:
        row = body[0]
        _require(isinstance(row, dict), "rows are not objects", problems)
        for key in ("id", "ts", "predicted_label", "src_mac"):
            _require(key in row, f"row missing key {key!r}", problems)


def _check_analysis(body: Any, problems: List[str]) -> None:
    from backend.app.config import ATTACK_CLASSES

    _require(isinstance(body, dict), "not a JSON object", problems)
    if isinstance(body, dict):
        for label in ATTACK_CLASSES:
            _require(label in body, f"missing attack class {label!r}", problems)
        _require(
            all(isinstance(v, int) for v in body.values()), "values are not integers", problems
        )


def _check_count(body: Any, problems: List[str]) -> None:
    _require(isinstance(body, dict) and "count" in body, "expected {'count': int}", problems)
    if isinstance(body, dict):
        _require(isinstance(body.get("count"), int), "count is not an integer", problems)


def _check_top_offenders(body: Any, problems: List[str]) -> None:
    _require(isinstance(body, list), "not a JSON array", problems)
    if isinstance(body, list) and body:
        # The key is wlan_sa, not src_mac: the built bundle depends on the legacy name.
        _require("wlan_sa" in body[0], "entries must use the legacy key 'wlan_sa'", problems)
        _require("count" in body[0], "entries missing 'count'", problems)


def _check_channel_usage(body: Any, problems: List[str]) -> None:
    _require(isinstance(body, list), "not a JSON array", problems)
    if isinstance(body, list) and body:
        for key in ("channel_freq", "count"):
            _require(key in body[0], f"entries missing {key!r}", problems)


def _check_heatmap(body: Any, problems: List[str]) -> None:
    expected_days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
    _require(isinstance(body, list), "not a JSON array", problems)
    if isinstance(body, list):
        _require(
            [entry.get("day") for entry in body] == expected_days,
            f"days must be Sun-first: {expected_days}",
            problems,
        )
        for entry in body:
            _require(len(entry.get("hours", [])) == 24, "each day needs 24 hour buckets", problems)


def _check_summary(body: Any, problems: List[str]) -> None:
    from backend.app.config import FRONT_TYPES

    _require(isinstance(body, dict), "not a JSON object", problems)
    if not isinstance(body, dict):
        return
    for key in ("period", "totals", "summary"):
        _require(key in body, f"missing key {key!r}", problems)
    totals = body.get("totals") or {}
    for key in list(FRONT_TYPES) + ["other"]:
        _require(key in totals, f"totals missing {key!r}", problems)
    headline = body.get("summary") or {}
    for key in ("totalAttacks", "mostFrequentType", "peakHour", "uniqueSources"):
        _require(key in headline, f"summary missing {key!r}", problems)


ENDPOINTS: Tuple[Tuple[str, str, Optional[Dict[str, Any]], Optional[Callable]], ...] = (
    ("GET", "/health", None, _check_health),
    ("GET", "/attacks?limit=5&offset=0", None, _check_attacks),
    ("GET", "/attacks/analysis", None, _check_analysis),
    ("GET", "/packets/count", None, _check_count),
    ("GET", "/top-offenders", None, _check_top_offenders),
    ("GET", "/channel-usage", None, _check_channel_usage),
    ("GET", "/heatmap-attack", None, _check_heatmap),
    ("GET", "/reports/summary?days=30", None, _check_summary),
)


def probe_stream(timeout_s: float = 10.0) -> Tuple[int, str]:
    """Read the opening frame of ``GET /stream`` without hanging the gate.

    ``/stream`` is an endless generator that only stops when
    ``request.is_disconnected()`` goes true, and that makes it genuinely awkward
    to probe in process:

    * ``TestClient`` never signals a disconnect, so closing the response blocks
      forever -- which is why the suite has no ``/stream`` test, and it cost this
      gate its own first run;
    * ``httpx.ASGITransport`` buffers the whole body before returning a response,
      so with an endless body it never returns at all, not even the status line.

    So the ASGI app is driven directly: send the request, capture frames as they
    are emitted, and once the opening ``event: hello`` arrives, hand the endpoint
    a real ``http.disconnect`` so it shuts down the way a closing browser tab
    would.  ``receive()`` returns that disconnect *without awaiting*, because
    Starlette polls ``is_disconnected()`` inside an already-cancelled scope and
    anything that suspends there is simply abandoned.

    Belt and braces: the whole probe runs on a daemon thread with a deadline, so
    a future change to ``/stream`` can never wedge the gate.
    """
    collected: Dict[str, Any] = {"status": 0, "text": ""}

    def runner() -> None:
        import asyncio

        from backend.app.main import app

        state = {"body_sent": False, "stop": False}

        scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": "/stream",
            "raw_path": b"/stream",
            "query_string": b"since_id=0",
            "root_path": "",
            "headers": [(b"host", b"gate"), (b"accept", b"text/event-stream")],
            "client": ("127.0.0.1", 50000),
            "server": ("gate", 80),
        }

        async def receive() -> Dict[str, Any]:
            if not state["body_sent"]:
                state["body_sent"] = True
                return {"type": "http.request", "body": b"", "more_body": False}
            if state["stop"]:
                # Returned without awaiting, so Starlette's cancelled poll sees it.
                return {"type": "http.disconnect"}
            await asyncio.sleep(3600)
            return {"type": "http.disconnect"}  # pragma: no cover - unreachable

        async def send(message: Dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                collected["status"] = int(message["status"])
            elif message["type"] == "http.response.body":
                chunk = message.get("body", b"") or b""
                collected["text"] += chunk.decode("utf-8", "replace")
                if "hello" in collected["text"] or len(collected["text"]) > 512:
                    state["stop"] = True

        try:
            asyncio.run(
                asyncio.wait_for(app(scope, receive, send), timeout=timeout_s * 0.7)
            )
        except BaseException:  # noqa: BLE001 - the frame is captured either way
            pass

    thread = threading.Thread(target=runner, daemon=True, name="gate-stream-probe")
    thread.start()
    thread.join(timeout=timeout_s)
    return int(collected["status"]), str(collected["text"])


def check_endpoints(client: Any) -> bool:
    """Every JSON endpoint the bundle calls, asserting shape and not just status."""
    healthy = True
    for method, path, body, checker in ENDPOINTS:
        response = client.request(method, path, json=body)
        if response.status_code != 200:
            fail(f"{method} {path} -> {response.status_code}")
            info(response.text[:200])
            healthy = False
            continue
        problems: List[str] = []
        if checker is not None:
            checker(response.json(), problems)
        if problems:
            fail(f"{method} {path} answered 200 with the wrong shape")
            for problem in problems:
                info(problem)
            healthy = False
        else:
            ok(f"{method} {path}")

    # The PDF export is a binary stream, so it gets its own check.
    response = client.post("/reports/export", json={"days": 30})
    if response.status_code != 200 or not response.content.startswith(b"%PDF-"):
        fail(f"POST /reports/export -> {response.status_code}, not a PDF")
        healthy = False
    else:
        ok("POST /reports/export (application/pdf)")

    # /simulate writes rows and needs the model and the corpus, so the gate only
    # proves it is routable and fails cleanly -- 403 (disabled) and 503 (no model
    # or no corpus) are correct answers on a laptop, 404 and 500 are not.
    response = client.post("/simulate", json={"attacks": "all", "count": 1})
    if response.status_code in (200, 403, 503):
        ok(f"POST /simulate routable ({response.status_code})")
    else:
        fail(f"POST /simulate -> {response.status_code} (expected 200, 403 or 503)")
        healthy = False

    status, opening = probe_stream()
    if status != 200:
        fail(f"GET /stream -> {status or 'no response'}")
        healthy = False
    elif "hello" not in opening:
        fail("GET /stream did not open with its `event: hello` frame")
        info(f"received: {opening[:160]!r}")
        healthy = False
    else:
        ok("GET /stream (SSE, opens with `event: hello`)")

    return healthy


# --------------------------------------------------------------------------- #
# 3. The /ask envelope the built RAG page destructures                         #
# --------------------------------------------------------------------------- #
def _explain_mode_matters() -> None:
    info("WHY THIS MATTERS -- this is the failure a human eyeball passes on stage:")
    info("  the built RAG page branches on `\"SQL\" === e.mode`, and ONLY that branch")
    info("  renders the sample-rows table. Every other value falls through to")
    info("  `r = e.answer || \"(no answer)\"`. So a wrong mode still shows a fluent,")
    info("  plausible answer -- and the rows table silently disappears. Nothing")
    info("  errors, nothing is red, and the demo looks fine until someone asks")
    info("  where the table went.")


def check_ask_envelope(client: Any) -> bool:
    """The exact contract ``frontend/out``'s RAG page has with ``POST /ask``."""
    from backend.app.routers import ask as ask_router

    ask_router.cache.store.clear()
    ask_router.SESSION_MEMORY.clear()

    sql = "SELECT predicted_label, COUNT(*) AS count FROM packets GROUP BY predicted_label"
    with faked_model(sql):
        response = client.post(
            "/ask",
            json={"question": "how many attacks by class?", "session_id": "gate-session"},
        )

    if response.status_code != 200:
        fail(f"POST /ask -> {response.status_code}")
        info(response.text[:300])
        info("The bundle renders any non-2xx as a bare 'Network error' bubble.")
        return False

    data = response.json()
    healthy = True

    missing = [key for key in ASK_KEYS if key not in data]
    if missing:
        fail(f"/ask is missing the keys the bundle reads: {missing}")
        info(f"present: {sorted(data)}")
        healthy = False
    else:
        ok(f"/ask returns every key the bundle reads: {', '.join(ASK_KEYS)}")

    # `error` short-circuits everything: a truthy value renders an error bubble
    # and nothing else, however good the rest of the envelope is.
    if data.get("error"):
        fail(f"/ask set `error` on a successful answer: {data['error']!r}")
        info("The bundle checks `if (e.error)` FIRST and returns early, so a")
        info("non-null error discards the answer and the rows entirely.")
        healthy = False
    else:
        ok("/ask leaves `error` falsy on success")

    # The crux.
    if data.get("mode") != "SQL":
        fail(f"/ask returned mode={data.get('mode')!r}, not \"SQL\"")
        _explain_mode_matters()
        healthy = False
    else:
        ok('/ask returns mode="SQL" for a database question (the rows-table branch)')

    rows, cols = data.get("rows"), data.get("cols")
    if not isinstance(rows, list):
        fail(f"/ask `rows` is {type(rows).__name__}, not a list")
        healthy = False
    elif not rows:
        fail("/ask returned no rows for a question that should produce some")
        info("The bundle only renders the table when `rows.length` is truthy.")
        healthy = False
    elif not isinstance(rows[0], dict):
        fail(f"/ask rows are {type(rows[0]).__name__}, not objects")
        info("The bundle reads `row[col]` per column; an array row renders as blanks.")
        healthy = False
    else:
        ok(f"/ask `rows` is a list of {len(rows)} column-keyed object(s)")

    if not isinstance(cols, list) or not cols:
        fail(f"/ask `cols` is {cols!r}; the bundle needs a list of column names")
        healthy = False
    elif isinstance(rows, list) and rows and isinstance(rows[0], dict):
        unknown = [c for c in cols if c not in rows[0]]
        if unknown:
            fail(f"/ask `cols` names columns absent from the rows: {unknown}")
            info("Those columns render as empty strings in the sample table.")
            healthy = False
        else:
            ok(f"/ask `cols` matches the row keys: {cols}")

    if not str(data.get("answer") or "").strip():
        fail("/ask returned an empty `answer`")
        info('The bundle would render the literal string "(no summary)".')
        healthy = False
    else:
        ok("/ask returns a non-empty `answer`")

    if not isinstance(data.get("sql"), str):
        warn("/ask `sql` is not a string; the contract declares it as one")

    if healthy:
        info(f"answer: {str(data.get('answer'))[:150]}")
        info(f"sql:    {str(data.get('sql'))[:150]}")
    return healthy


def check_ask_unavailable(client: Any) -> bool:
    """With no key configured, ``/ask`` must still fail the way the bundle expects."""
    from backend.app.config import settings

    original = settings.OPENROUTER_API_KEY
    settings.OPENROUTER_API_KEY = ""
    try:
        from backend.app.routers import ask as ask_router

        ask_router.cache.store.clear()
        response = client.post("/ask", json={"question": "unavailable path check"})
    finally:
        settings.OPENROUTER_API_KEY = original

    if response.status_code != 503:
        fail(f"/ask with no API key -> {response.status_code}, expected 503")
        info("The bundle renders a non-2xx as a 'Network error' bubble, which is the")
        info("intended degradation. A 200 with an empty answer is not.")
        return False
    ok("/ask answers 503 when no API key is configured")
    return True


# --------------------------------------------------------------------------- #
# 4. Optional live round-trip                                                  #
# --------------------------------------------------------------------------- #
def check_ask_live(client: Any) -> bool:
    """One real ``/ask`` through the configured model, against the seeded database."""
    from backend.app.routers import ask as ask_router

    ask_router.cache.store.clear()
    ask_router.SESSION_MEMORY.clear()

    question = "How many attacks were detected for each attack class?"
    try:
        response = client.post("/ask", json={"question": question, "session_id": "gate-live"})
    except Exception as exc:  # noqa: BLE001 - a network failure is the finding
        fail(f"the live call failed: {exc}")
        return False

    if response.status_code != 200:
        fail(f"live POST /ask -> {response.status_code}")
        info(response.text[:300])
        return False

    data = response.json()
    if data.get("error"):
        fail(f"live /ask returned an error: {data['error']}")
        return False
    if data.get("mode") != "SQL":
        fail(f"live /ask routed to mode={data.get('mode')!r}, not \"SQL\"")
        _explain_mode_matters()
        info(f"answer: {str(data.get('answer'))[:200]}")
        return False
    if not data.get("rows"):
        fail("live /ask produced mode=SQL but no rows")
        info(f"sql: {data.get('sql')}")
        return False

    ok("live /ask answered in SQL mode with real rows from the seeded database")
    info(f"sql:    {str(data.get('sql'))[:200]}")
    info(f"answer: {str(data.get('answer'))[:200]}")
    return True


# --------------------------------------------------------------------------- #
# Entry point                                                                  #
# --------------------------------------------------------------------------- #
def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify the shipped frontend/out build still works against this backend.",
    )
    parser.add_argument(
        "--skip-live", action="store_true",
        help="never make a billed model call, even when a key is configured",
    )
    args = parser.parse_args()

    from backend.app.config import settings

    print("\n  HawkShield frontend gate")
    print(f"  bundle: {settings.FRONTEND_DIST}\n")

    with tempfile.TemporaryDirectory() as scratch:
        db_path = Path(scratch) / "gate.db"
        with app_client(db_path) as client:
            print("-- built bundle " + "-" * 55)
            if not check_bundle_served(client):
                return 2

            print("\n-- API endpoints the bundle calls " + "-" * 36)
            if not check_endpoints(client):
                info("The dashboard reads these directly; a shape change breaks a panel")
                info("without breaking a request, so this is checked by field, not status.")
                return 3

            print("\n-- POST /ask envelope " + "-" * 48)
            if not check_ask_envelope(client):
                return 4
            if not check_ask_unavailable(client):
                return 4

            live_wanted = bool(settings.OPENROUTER_API_KEY.strip()) and not args.skip_live
            if live_wanted:
                print("\n-- live /ask round-trip " + "-" * 46)
                if not check_ask_live(client):
                    return 5
            else:
                reason = (
                    "--skip-live was passed"
                    if args.skip_live
                    else "OPENROUTER_API_KEY is not set"
                )
                skipped([
                    f"a live POST /ask through the real model ({reason})",
                    "that the configured model routes a database question to SQL mode",
                ])
                info("Everything above ran against a faked model and real SQL, so the")
                info("envelope is verified; only the model's routing is not.")

    print(f"\n  {GREEN}The shipped frontend/out build works against this backend.{RESET}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
