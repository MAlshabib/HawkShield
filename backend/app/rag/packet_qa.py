"""HawkShield RAG: natural-language question answering over the ``packets`` table.

Single-shot router: one LLM call classifies the question into
``MODE = SQL | DOCS | OOS`` and either emits a read-only ``SELECT`` or answers
from the attack knowledge base.  For ``SQL`` a second, strictly facts-only LLM
call humanises the result set (with a deterministic, model-free fallback).

Design notes:

* Importing this module never fails and never touches the network.  The OpenAI
  client is built lazily on first use; missing configuration raises the typed
  :class:`RagUnavailable` so the router can answer ``503``.
* ``DATABASE_URL`` arrives in SQLAlchemy form (``postgresql+psycopg2://...``);
  it is normalised before being handed to ``psycopg.connect()``.
* The knowledge base is resolved relative to this package, not the CWD, and
  cached in memory after the first read.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from datetime import date, datetime, time as _time, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple
from uuid import UUID

logger = logging.getLogger(__name__)

__all__ = ["RagUnavailable", "packet_ask", "SYSTEM_PROMPT"]


# --------------------------------------------------------------------------- #
# Typed failure                                                               #
# --------------------------------------------------------------------------- #
class RagUnavailable(RuntimeError):
    """The RAG stack cannot serve requests (no API key / no database URL).

    The ``/ask`` router turns this into a clean HTTP 503.
    """


# --------------------------------------------------------------------------- #
# Configuration                                                               #
# --------------------------------------------------------------------------- #
# ``backend.app.config`` is owned by the backend agent and may not exist yet;
# never let its absence break the import of this module.
try:  # pragma: no cover - trivial import shim
    from backend.app.config import settings as _settings  # type: ignore
except Exception:  # noqa: BLE001 - any failure means "no settings object yet"
    _settings = None  # type: ignore[assignment]


def _cfg(name: str, default: str = "") -> str:
    """Read a setting from ``backend.app.config.settings``, else the environment."""
    if _settings is not None:
        for attr in (name, name.lower()):
            value = getattr(_settings, attr, None)
            if value is not None and str(value) != "":
                return str(value)
    return os.getenv(name, default)


def _cfg_int(name: str, default: int) -> int:
    try:
        return int(_cfg(name, str(default)))
    except (TypeError, ValueError):
        return default


def _truthy(value: str) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


# OpenRouter (OpenAI-compatible API). Default is DeepSeek V4 Flash: strong at
# SQL generation and strict JSON, ~$0.08/$0.16 per M tokens, 1M context.
# Alternatives that work well here: z-ai/glm-5.3-flash, qwen/qwen3.7-flash.
DEFAULT_GEN_MODEL = "deepseek/deepseek-v4-flash"
DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"
DEFAULT_MAX_ROWS = 500          # LIMIT safety net for un-limited SELECTs
DEFAULT_SQL_TIMEOUT_MS = 15000  # server-side statement timeout


# --------------------------------------------------------------------------- #
# System prompt — schema block must mirror docs/CONTRACT.md §2                 #
# --------------------------------------------------------------------------- #
SYSTEM_PROMPT = r"""
You are PacketQA, the assistant for HawkShield, a Wi-Fi (802.11) intrusion
detection system. You answer questions about detected wireless attacks, either
from the live detection database or from the supplied attack knowledge base.

Decide the user's intent and set exactly one MODE.

• MODE=SQL → the user asks for facts held in the database (counts, lists, top
  offenders, time ranges, per-attack breakdowns, channels, signal strength...).
  Output ONLY a single SELECT statement in "sql".

  === DATABASE SCHEMA (PostgreSQL) — the ONLY table you may query ===
  Table: packets                     -- plural; there is NO table called "packet"

    id               integer            primary key
    ts               timestamp          UTC; the moment the frame was classified.
                                        ALL time filtering uses this column.
    iface            varchar(64)        capture interface, e.g. 'wlan1'
    src_mac          varchar(32)        802.11 addr2 — transmitter. This is the
                                        "source" / "offender" / "attacker" MAC.
    dst_mac          varchar(32)        802.11 addr1 — receiver / "target".
    bssid            varchar(32)        802.11 addr3 — the AP / BSS involved.
    frame_len        integer            frame length in bytes
    channel_freq     integer            RadioTap channel frequency in MHz
                                        (2437 = ch 6, 2412 = ch 1, 5180 = ch 36)
    datarate         double precision   PHY data rate in Mb/s
    signal_dbm       double precision   RSSI in dBm (negative; nearer 0 = stronger)
    wlan_ds          integer            ToDS/FromDS 2-bit value, 0..3
    wlan_retry       integer            802.11 retry flag, 0 or 1
    wlan_type        integer            frame type: 0=management, 1=control, 2=data
    wlan_subtype     integer            frame subtype
    wlan_duration    integer            802.11 duration/ID field
    proba_anomaly    double precision   stage-1 model probability of maliciousness (0..1)
    proba_attack     double precision   stage-2 model confidence in predicted_label (0..1)
    predicted_label  varchar(64)        the detected attack class (see below)
    raw              json               small JSON blob of the original frame fields

  === CRITICAL FACTS ABOUT THIS DATA — read before writing any SQL ===
  1. ONLY ATTACK PACKETS ARE STORED. Normal/benign traffic is classified and
     dropped by the detector and never reaches the database. Consequences:
       - "how many attacks today / this hour / in total?" is a plain COUNT(*)
         over packets, optionally filtered on ts. Nothing else.
       - There is NO benign traffic to count, and there is NO `label`,
         `attack_type`, `is_attack` or `frame_number` column. NEVER write
         `WHERE label = 0`, `WHERE label = 1` or `WHERE attack_type = ...`;
         those columns do not exist and the query will fail.
       - A question about attacks as a share/percentage of all traffic cannot be
         answered from this table: return the plain attack count instead.
  2. The attack class column is `predicted_label`. Its only possible values,
     spelled exactly like this, are:
         'SSDP', 'Evil_Twin', 'Krack', 'Deauth', '(Re)Assoc', 'RogueAP'
     Always compare against a single-quoted string literal. '(Re)Assoc'
     contains parentheses: they are part of the literal text and must stay
     inside the quotes — they are never SQL syntax. Correct forms:
         WHERE predicted_label = '(Re)Assoc'
         WHERE LOWER(predicted_label) = LOWER('Deauth')
     Map the user's wording onto those six values, e.g.
     "deauthentication"/"deauth flood" -> 'Deauth';
     "evil twin"/"fake access point" -> 'Evil_Twin';
     "krack"/"key reinstallation" -> 'Krack';
     "rogue ap"/"unauthorised ap" -> 'RogueAP';
     "reassociation"/"association flood" -> '(Re)Assoc';
     "ssdp"/"amplification"/"reflection" -> 'SSDP'.
  3. Time filtering always uses `ts` (a UTC timestamp):
         WHERE ts >= NOW() - INTERVAL '1 hour'
         WHERE ts >= NOW() - INTERVAL '24 hours'
         WHERE ts >= date_trunc('day', NOW())        -- "today"
         WHERE ts >= NOW() - INTERVAL '7 days'
     For breakdowns use date_trunc('hour', ts), EXTRACT(HOUR FROM ts) or
     EXTRACT(DOW FROM ts) (0 = Sunday).
  4. `raw` is a JSON column. Extract scalars with the ->> operator (it returns
     text, so cast when you need a number). Available keys: 'ssid', 'sa', 'da',
     'bssid', 'len', 'type', 'subtype', 'rate', 'sig', 'iface'. Examples:
         SELECT raw->>'ssid' AS ssid, COUNT(*) AS count FROM packets
          WHERE raw->>'ssid' IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 10
         SELECT AVG((raw->>'sig')::float) AS avg_signal FROM packets
     Prefer the real columns (src_mac, bssid, frame_len, signal_dbm, ...) and
     use `raw` only for fields with no column of their own, such as 'ssid'.

  === SQL RULES ===
  - Exactly one SELECT statement. No trailing semicolon, no second statement,
    no CTE that writes.
  - NEVER emit INSERT/UPDATE/DELETE/DROP/ALTER/CREATE/TRUNCATE/GRANT/COPY,
    and never SELECT ... INTO.
  - Alias every aggregate, e.g. COUNT(*) AS count.
  - When listing individual rows, select only the useful columns, add
    ORDER BY ts DESC and a LIMIT (25 unless the user asks for more).
  - Never write SELECT * without a LIMIT.

• MODE=DOCS → the user asks a conceptual question about an attack (what it is,
  how it works, its impact, how to detect or defend against it). Answer ONLY
  from the supplied CONTEXT (the attack knowledge base). If the CONTEXT does not
  support an answer, say you do not have that information.

• MODE=OOS → the question is about neither the packet database nor the attacks
  in the CONTEXT. Reply briefly that HawkShield answers questions about Wi-Fi
  packet analytics and wireless attacks only.

Return a single JSON object with EXACTLY these keys:
{"mode": "<SQL|DOCS|OOS>", "sql": "<query or empty>", "answer": "<answer text or empty>"}

Rules:
- MODE=SQL : "sql" holds the SELECT query, "answer" is "".
- MODE=DOCS: "answer" holds the answer drawn from CONTEXT, "sql" is "".
- MODE=OOS : "answer" holds a brief scope message, "sql" is "".
- No extra keys and no text outside the JSON object.
"""


# --------------------------------------------------------------------------- #
# Fix #2 — database URL normalisation                                          #
# --------------------------------------------------------------------------- #
_DIALECT_RE = re.compile(r"^(postgres(?:ql)?)\+[a-zA-Z0-9_]+://")


def _normalize_db_url(url: str) -> str:
    """Strip the SQLAlchemy driver suffix so ``psycopg.connect()`` accepts the URL.

    ``postgresql+psycopg2://u:p@h/db`` -> ``postgresql://u:p@h/db``
    ``postgresql+psycopg://...``       -> ``postgresql://...``
    Anything else is returned untouched.
    """
    if not url:
        return ""
    return _DIALECT_RE.sub(r"\1://", url.strip(), count=1)


def _db_url() -> str:
    url = _normalize_db_url(_cfg("DATABASE_URL"))
    if not url:
        raise RagUnavailable("DATABASE_URL is not configured; database questions are unavailable.")
    return url


# --------------------------------------------------------------------------- #
# Fix #3 — lazy OpenAI client                                                  #
# --------------------------------------------------------------------------- #
_client: Any = None


def _get_client() -> Any:
    """Build (once) and return the OpenRouter client. Raises :class:`RagUnavailable`."""
    global _client
    if _client is not None:
        return _client

    api_key = _cfg("OPENROUTER_API_KEY")
    if not api_key:
        raise RagUnavailable("OPENROUTER_API_KEY is not configured; the assistant is disabled.")

    try:
        from openai import OpenAI  # OpenRouter speaks the OpenAI wire protocol
    except Exception as exc:  # pragma: no cover - packaging problem
        raise RagUnavailable(f"The openai package is not installed: {exc}") from exc

    base_url = _cfg("OPENROUTER_BASE_URL", DEFAULT_BASE_URL)
    # Optional attribution headers; OpenRouter uses them for its app leaderboard.
    headers = {
        "HTTP-Referer": _cfg("OPENROUTER_SITE_URL", "https://github.com/MAlshabib/HawkShield"),
        "X-Title": _cfg("OPENROUTER_APP_NAME", "HawkShield"),
    }
    _client = OpenAI(api_key=api_key, base_url=base_url, default_headers=headers)
    logger.info(
        "OpenRouter client initialised (model=%s, base_url=%s)",
        _cfg("GEN_MODEL", DEFAULT_GEN_MODEL), base_url,
    )
    return _client


# --------------------------------------------------------------------------- #
# Fix #4 — package-relative, cached knowledge base                             #
# --------------------------------------------------------------------------- #
DEFAULT_KNOWLEDGE_FILE = Path(__file__).resolve().parent / "knowledge" / "attacks.md"

_attacks_cache: Dict[str, str] = {}


def _knowledge_path() -> Path:
    """Knowledge-base location: env override, else next to this package."""
    override = _cfg("ATTACKS_FILE") or _cfg("RAG_KNOWLEDGE_FILE")
    if override:
        return Path(override).expanduser()
    return DEFAULT_KNOWLEDGE_FILE


def _load_attacks_context() -> str:
    """Read the knowledge base, caching the text per resolved path."""
    path = _knowledge_path()
    key = str(path)
    if key in _attacks_cache:
        return _attacks_cache[key]
    try:
        text = path.read_text(encoding="utf-8", errors="ignore").strip()
    except OSError as exc:
        logger.warning("Knowledge base unreadable at %s: %s", path, exc)
        text = ""
    _attacks_cache[key] = text
    return text


# --------------------------------------------------------------------------- #
# SQL guards                                                                   #
# --------------------------------------------------------------------------- #
_FORBIDDEN_RE = re.compile(
    r"\b(insert|update|delete|drop|alter|create|truncate|merge|upsert|grant|revoke|"
    r"copy|vacuum|reindex|cluster|comment|call|prepare|execute|listen|notify|lock|"
    r"begin|commit|rollback|savepoint|into)\b",
    re.IGNORECASE,
)
_LIMIT_RE = re.compile(r"\blimit\s+(\d+|all)\b|\bfetch\s+(first|next)\b", re.IGNORECASE)
_AGGREGATE_RE = re.compile(
    r"\b(count|sum|avg|min|max|stddev|stddev_samp|stddev_pop|variance|var_samp|var_pop)\s*\(",
    re.IGNORECASE,
)
_GROUP_BY_RE = re.compile(r"\bgroup\s+by\b", re.IGNORECASE)


def _assert_select_only(sql: str) -> str:
    """Validate that ``sql`` is one read-only SELECT. Returns the cleaned statement.

    Rejects: non-SELECT starts, a second statement hidden behind ``;``, and any
    write keyword anywhere (which also covers a CTE such as
    ``WITH x AS (INSERT ...) SELECT ...``).
    """
    statement = (sql or "").strip()
    if not statement:
        raise ValueError("Refusing to run an empty SQL statement.")

    # One optional trailing semicolon is tolerated; anything after it is not.
    while statement.endswith(";"):
        statement = statement[:-1].rstrip()
    if ";" in statement:
        raise ValueError("Refusing to run SQL that contains more than one statement.")

    head = statement.lstrip("( \t\r\n").lower()
    if not (head.startswith("select") or head.startswith("with")):
        raise ValueError("Refusing to run non-SELECT SQL.")

    forbidden = _FORBIDDEN_RE.search(statement)
    if forbidden:
        raise ValueError(f"Refusing to run SQL containing the keyword '{forbidden.group(0)}'.")

    if head.startswith("with") and not re.search(r"\bselect\b", statement, re.IGNORECASE):
        raise ValueError("Refusing to run a CTE that does not end in a SELECT.")

    return statement


def _apply_row_limit(sql: str, max_rows: Optional[int] = None) -> str:
    """Append a bounded ``LIMIT`` to an unbounded, non-aggregate SELECT."""
    limit = max_rows if max_rows is not None else _cfg_int("RAG_MAX_ROWS", DEFAULT_MAX_ROWS)
    statement = sql.rstrip().rstrip(";").rstrip()

    if _LIMIT_RE.search(statement):
        return statement
    # A bare aggregate (no GROUP BY) returns a single row; leave it alone.
    if _AGGREGATE_RE.search(statement) and not _GROUP_BY_RE.search(statement):
        return statement

    logger.debug("Appending LIMIT %s to unbounded SELECT", limit)
    return f"{statement}\nLIMIT {limit}"


# --------------------------------------------------------------------------- #
# JSON-safe result rows                                                        #
# --------------------------------------------------------------------------- #
def _jsonable(value: Any) -> Any:
    """Convert a psycopg value into something FastAPI's encoder can serialise."""
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, (datetime, date, _time)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, timedelta):
        return value.total_seconds()
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, memoryview):
        return value.tobytes().hex()
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(v) for v in value]
    return str(value)


def _rows_to_dicts(cols: Sequence[str], rows: Sequence[Sequence[Any]]) -> List[Dict[str, Any]]:
    return [{col: _jsonable(row[i]) for i, col in enumerate(cols)} for row in rows]


# --------------------------------------------------------------------------- #
# SQL dialect                                                                  #
# --------------------------------------------------------------------------- #
# The same repo runs on the Pi (PostgreSQL) and on a laptop demo (SQLite), so the
# generated SQL has to match whichever database is actually configured.
_POSTGRES_NOTES = """
=== SQL DIALECT: PostgreSQL ===
- Time filters: ts >= NOW() - INTERVAL '1 hour' / '24 hours' / '7 days';
  "today" is ts >= date_trunc('day', NOW()).
- Buckets: date_trunc('hour', ts), EXTRACT(HOUR FROM ts), EXTRACT(DOW FROM ts) (0 = Sunday).
- JSON: raw->>'ssid' returns text; cast when you need a number, e.g. (raw->>'sig')::float.
"""

_SQLITE_NOTES = """
=== SQL DIALECT: SQLite ===
This database is SQLite, NOT PostgreSQL. PostgreSQL-only syntax will fail.
- Time filters: ts >= datetime('now', '-1 hour') / '-24 hours' / '-7 days';
  "today" is ts >= date('now').
- Buckets: strftime('%H', ts) for the hour, strftime('%w', ts) for the weekday (0 = Sunday).
  There is no date_trunc, no EXTRACT, no INTERVAL keyword and no NOW().
- JSON: json_extract(raw, '$.ssid') instead of raw->>'ssid'.
- There is no :: cast syntax; use CAST(x AS REAL) or CAST(x AS INTEGER).
"""


def _sql_dialect() -> str:
    """Return 'sqlite' or 'postgresql', derived from DATABASE_URL."""
    return "sqlite" if _cfg("DATABASE_URL").strip().lower().startswith("sqlite") else "postgresql"


def _dialect_notes() -> str:
    return _SQLITE_NOTES if _sql_dialect() == "sqlite" else _POSTGRES_NOTES


# --------------------------------------------------------------------------- #
# Database access                                                              #
# --------------------------------------------------------------------------- #
def _run_sql(sql: str) -> Tuple[List[str], List[Tuple[Any, ...]]]:
    """Execute a validated, row-limited SELECT and return ``(cols, rows)``."""
    statement = _apply_row_limit(_assert_select_only(sql))
    timeout_ms = _cfg_int("RAG_SQL_TIMEOUT_MS", DEFAULT_SQL_TIMEOUT_MS)
    dialect = _sql_dialect()

    logger.info("Executing RAG SELECT (%s): %s", dialect, statement.replace("\n", " "))

    if dialect == "sqlite":
        # Reuse the app's SQLAlchemy engine; psycopg cannot parse a sqlite:// URL.
        from sqlalchemy import text as sa_text

        from backend.app.db import engine

        with engine.connect() as conn:
            result = conn.execute(sa_text(statement))
            cols = list(result.keys())
            rows = [tuple(r) for r in result.fetchall()]
        return cols, rows

    import psycopg  # imported lazily so the module imports without a DB driver

    with psycopg.connect(_db_url(), options=f"-c statement_timeout={timeout_ms}") as conn:
        with conn.cursor() as cur:
            cur.execute(statement)  # type: ignore[arg-type]
            cols = [d[0] for d in (cur.description or [])]
            rows = cur.fetchall()
    return cols, list(rows)


# --------------------------------------------------------------------------- #
# LLM plumbing                                                                 #
# --------------------------------------------------------------------------- #
def _chat(messages: List[Dict[str, str]], temperature: float, json_mode: bool = False) -> str:
    """One chat completion, returning the message text."""
    client = _get_client()
    model = _cfg("GEN_MODEL", DEFAULT_GEN_MODEL)
    kwargs: Dict[str, Any] = {"model": model, "temperature": temperature, "messages": messages}
    if json_mode:
        kwargs["response_format"] = {"type": "json_object"}
    try:
        resp = client.chat.completions.create(**kwargs)
    except Exception:
        if not json_mode:
            raise
        logger.warning("JSON response_format rejected by the API; retrying without it.")
        kwargs.pop("response_format", None)
        resp = client.chat.completions.create(**kwargs)
    return (resp.choices[0].message.content or "").strip()


def _strip_code_fences(text: str) -> str:
    t = (text or "").strip()
    if not t.startswith("```"):
        return t
    parts = t.split("```")
    if len(parts) >= 3:
        inner = parts[1]
        if inner.lower().startswith("json"):
            inner = inner.split("\n", 1)[-1]
        return inner.strip()
    return parts[-1].strip()


def _json_or_none(text: str) -> Optional[Dict[str, Any]]:
    try:
        data = json.loads(text)
    except Exception:  # noqa: BLE001
        return None
    return data if isinstance(data, dict) else None


def _route_and_generate(question: str) -> Dict[str, str]:
    """Single LLM call: classify the question and emit SQL or a docs answer."""
    attacks_ctx = _load_attacks_context()
    messages: List[Dict[str, str]] = [
        {"role": "system", "content": SYSTEM_PROMPT.strip()},
        {"role": "system", "content": _dialect_notes().strip()},
    ]
    if attacks_ctx:
        messages.append({"role": "system", "content": f"CONTEXT (attack knowledge base):\n{attacks_ctx}"})
    else:
        messages.append({"role": "system", "content": "CONTEXT (attack knowledge base) is empty or missing."})
    messages.append({"role": "user", "content": question.strip()})

    raw = _strip_code_fences(_chat(messages, temperature=0.0, json_mode=True))
    data = _json_or_none(raw)
    if data is None:
        raise ValueError(f"The model did not return valid JSON. Got:\n{raw}")

    mode = str(data.get("mode") or "").strip().upper()
    sql = str(data.get("sql") or "").strip()
    answer = str(data.get("answer") or "").strip()

    if mode not in {"SQL", "DOCS", "OOS"}:
        raise ValueError(f"Invalid mode from model: {mode!r}")
    if mode == "SQL":
        sql = _assert_select_only(sql)
    else:
        sql = ""
    return {"mode": mode, "sql": sql, "answer": answer}


# --------------------------------------------------------------------------- #
# Strict, facts-only humanisation                                              #
# --------------------------------------------------------------------------- #
def _extract_facts_from_result(
    cols: Sequence[str], rows: Sequence[Sequence[Any]]
) -> Dict[str, Any]:
    """Build a facts blob strictly from the SQL result — no derived statistics."""
    facts: Dict[str, Any] = {
        "schema": list(cols),
        "row_count": len(rows),
        "scalar_value": None,
        "rows_sample": [],
    }
    if len(cols) == 1 and len(rows) == 1:
        facts["scalar_value"] = {cols[0]: _jsonable(rows[0][0])}
        return facts
    facts["rows_sample"] = _rows_to_dicts(cols, rows[:10])
    return facts


def _humanize_with_llm(question: str, facts: Dict[str, Any]) -> str:
    """Second LLM call: explain the result using ONLY the literal facts given."""
    guardrails = f"""
You are a helpful analyst. Explain the SQL result in 3-6 sentences, friendly and clear.

STRICT RULES:
- You may ONLY use facts from the JSON under "FACTS" below.
- Do NOT introduce statistics (min/max/median/percentages/time-ranges) unless those exact
  values appear explicitly in FACTS (as columns or literal row values).
- If FACTS shows a single scalar (e.g., a count), explain that number and what it represents.
- If FACTS shows multiple rows/columns, describe the columns and notable literal values.
- Remember: the database stores detected attacks only, so every row is an attack packet.
- No hedging, no SQL jargon, no assumptions. Stay within FACTS.

FACTS:
{json.dumps(facts, ensure_ascii=False, default=str)}
"""
    return _chat(
        [
            {"role": "system", "content": "You produce concise, human-friendly explanations."},
            {"role": "user", "content": f"User question: {question}"},
            {"role": "user", "content": guardrails.strip()},
        ],
        temperature=0.2,
    )


def _deterministic_explanation(
    question: str, cols: Sequence[str], rows: Sequence[Sequence[Any]]
) -> str:
    """Model-free fallback explanation with zero derived statistics."""
    if not rows:
        return "The query returned no rows."
    if len(cols) == 1 and len(rows) == 1:
        key, value = cols[0], _jsonable(rows[0][0])
        return (
            f"The query returns a single value: {key} = {value}. "
            "That is the total for the filter in your question."
        )
    examples = [
        "- " + ", ".join(f"{col}={_jsonable(row[i])}" for i, col in enumerate(cols))
        for row in rows[:3]
    ]
    return (
        f"The query returned {len(rows)} row(s) with columns {', '.join(cols)}. "
        "Here are a few exact examples from the result:\n" + "\n".join(examples)
    )


# --------------------------------------------------------------------------- #
# Public API                                                                   #
# --------------------------------------------------------------------------- #
def packet_ask(question: str) -> Dict[str, Any]:
    """Answer ``question`` about wireless attacks.

    Returns ``{"mode", "sql", "answer", "cols", "rows"}`` plus ``"error"`` when
    something failed. ``rows`` is a list of JSON-serialisable dicts.
    Raises :class:`RagUnavailable` when the RAG stack is not configured.
    """
    if not question or not question.strip():
        return {"mode": "ERROR", "sql": "", "answer": "", "cols": [], "rows": [], "error": "Empty question."}

    try:
        routed = _route_and_generate(question)
        mode, sql, answer = routed["mode"], routed["sql"], routed["answer"]

        if mode == "SQL":
            sql = _apply_row_limit(sql)  # report the statement we actually run
            cols, rows = _run_sql(sql)
            humanize = _truthy(_cfg("HUMANIZE_SQL", "1"))
            if humanize:
                try:
                    summary = _humanize_with_llm(question, _extract_facts_from_result(cols, rows))
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Humanisation failed, using deterministic summary: %s", exc)
                    summary = _deterministic_explanation(question, cols, rows)
            else:
                summary = _deterministic_explanation(question, cols, rows)

            return {
                "mode": "SQL",
                "sql": sql,
                "answer": summary,
                "cols": list(cols),
                "rows": _rows_to_dicts(cols, rows),
            }

        if not answer:
            answer = (
                "HawkShield answers questions about Wi-Fi packet analytics and wireless attacks only."
                if mode == "OOS"
                else "I don't have that in the provided context."
            )
        return {"mode": mode, "sql": "", "answer": answer, "cols": [], "rows": []}

    except RagUnavailable:
        raise
    except Exception as exc:  # noqa: BLE001
        logger.exception("packet_ask failed for question: %s", question)
        return {"mode": "ERROR", "sql": "", "answer": "", "cols": [], "rows": [], "error": str(exc)}


# --------------------------------------------------------------------------- #
# CLI (printing is allowed here)                                               #
# --------------------------------------------------------------------------- #
def _print_cli(result: Dict[str, Any]) -> None:
    if result.get("error"):
        print(f"[ERROR] {result['error']}")
        return
    if result.get("mode") == "SQL":
        print(result.get("answer", ""))
        cols = result.get("cols", [])
        rows = result.get("rows", [])
        if rows:
            shown = min(10, len(rows))
            print(f"\nSQL: {result.get('sql', '')}")
            print(f"\nSample {shown} row(s):")
            print("\t".join(cols))
            for row in rows[:shown]:
                print("\t".join(str(row.get(c, "")) for c in cols))
    else:
        print(str(result.get("answer", "")).strip())


def main() -> None:
    logging.basicConfig(level=_cfg("LOG_LEVEL", "INFO").upper())
    question = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else input("Question: ").strip()
    try:
        _print_cli(packet_ask(question))
    except RagUnavailable as exc:
        print(f"[UNAVAILABLE] {exc}")


if __name__ == "__main__":
    main()
