"""Read-only SQL guards, dialect handling and row normalisation.

Extracted verbatim from ``backend/app/rag/packet_qa.py``, which now imports them
back, so ``/ask`` behaviour is unchanged and there is one implementation of each
guard rather than two.  The agent uses the same functions for its ``run_sql``
escape hatch and for previewing the SQL its structured tools generate.

Three things live here that ``packet_qa`` did not have:

* :func:`assert_tables_allowed` -- an allow-list over every ``FROM``/``JOIN``
  target.  ``assert_select_only`` proves a statement only *reads*; it says
  nothing about *what*.  ``documents``, ``sqlite_master``, ``pg_catalog.*`` and
  ``information_schema.*`` are all readable today, and none of them is data the
  assistant has any business reaching.
* :func:`normalise_packet_row` -- ``raw`` is a ``dict`` on PostgreSQL and TEXT on
  SQLite, and ``ts`` is a ``datetime`` on one and TEXT on the other.  That
  divergence has already been re-solved twice in this repository
  (``routers.attacks._normalise_row``, ``routers.stream._sim_flag``); this is
  the shared implementation, not a third copy.
* :func:`sql_dialect` / :func:`normalize_db_url` as public helpers, so the agent
  prompt can name the dialect the process is actually connected to.
"""
from __future__ import annotations

import json
import logging
import os
import re
from datetime import date, datetime, time as _time, timedelta
from decimal import Decimal
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from uuid import UUID

logger = logging.getLogger(__name__)

__all__ = [
    "DEFAULT_MAX_ROWS",
    "DEFAULT_SQL_TIMEOUT_MS",
    "PACKETS_ONLY",
    "apply_row_limit",
    "assert_select_only",
    "assert_tables_allowed",
    "default_max_rows",
    "dialect_notes",
    "jsonable",
    "normalise_packet_row",
    "normalize_db_url",
    "rows_to_dicts",
    "run_select",
    "sql_dialect",
    "table_references",
]

#: ``LIMIT`` safety net for an unbounded ``SELECT``.
DEFAULT_MAX_ROWS = 500
#: Server-side statement timeout, PostgreSQL only.
DEFAULT_SQL_TIMEOUT_MS = 15000

#: The only base table the assistant may read.  ``packets`` is the only table
#: that holds data; ``documents`` is legacy and unused.
PACKETS_ONLY: Set[str] = {"packets"}

#: Schema qualifiers that mean "the ordinary application schema" and so do not,
#: on their own, make a reference suspicious.
_NEUTRAL_SCHEMAS: Set[str] = {"public", "main", "temp"}


# --------------------------------------------------------------------------- #
# Database URL normalisation / dialect                                         #
# --------------------------------------------------------------------------- #
_DIALECT_RE = re.compile(r"^(postgres(?:ql)?)\+[a-zA-Z0-9_]+://")


def normalize_db_url(url: str) -> str:
    """Strip the SQLAlchemy driver suffix so ``psycopg.connect()`` accepts the URL.

    ``postgresql+psycopg2://u:p@h/db`` -> ``postgresql://u:p@h/db``
    ``postgresql+psycopg://...``       -> ``postgresql://...``
    Anything else is returned untouched.
    """
    if not url:
        return ""
    return _DIALECT_RE.sub(r"\1://", url.strip(), count=1)


def sql_dialect(database_url: Optional[str] = None) -> str:
    """Return ``"sqlite"`` or ``"postgresql"``, derived from ``DATABASE_URL``.

    Reads the environment first and the settings object second, so a test that
    monkeypatches ``DATABASE_URL`` sees its own value rather than whatever was
    loaded from ``.env`` at import time.
    """
    if database_url is None:
        database_url = os.getenv("DATABASE_URL")
    if database_url is None:
        try:
            from backend.app.config import settings

            database_url = settings.DATABASE_URL
        except Exception:  # noqa: BLE001 - configuration is optional here
            database_url = ""
    return "sqlite" if str(database_url).strip().lower().startswith("sqlite") else "postgresql"


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


def dialect_notes(dialect: Optional[str] = None) -> str:
    """The dialect crib sheet handed to a model that is about to write SQL."""
    if dialect is None:
        dialect = sql_dialect()
    return _SQLITE_NOTES if dialect == "sqlite" else _POSTGRES_NOTES


# --------------------------------------------------------------------------- #
# SELECT-only guard                                                            #
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


def assert_select_only(sql: str) -> str:
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


# --------------------------------------------------------------------------- #
# Table allow-list                                                             #
# --------------------------------------------------------------------------- #
# ``assert_select_only`` proves a statement only reads.  It does not say what it
# reads, and the answer today includes ``documents`` (legacy, unused),
# ``sqlite_master`` (the whole schema), ``pg_catalog.*`` (including
# ``pg_shadow``) and ``information_schema.*``.  None of those is packet data.
#
# This is a lexical guard, not a SQL parser: string literals and comments are
# removed, then every ``FROM``/``JOIN`` clause is split into its comma-separated
# table references and the leading identifier of each is checked.  A derived
# table (``FROM (SELECT ...) x``) contributes nothing itself -- its own inner
# ``FROM`` is matched separately, because the scan runs over the whole statement.
_LINE_COMMENT_RE = re.compile(r"--[^\n]*")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_STRING_RE = re.compile(r"'(?:[^']|'')*'")
_FROM_JOIN_RE = re.compile(r"\b(from|join)\b", re.IGNORECASE)
_IDENT_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_$]*|"[^"]+"|`[^`]+`|\[[^\]]+\]')

#: Words that may sit between the FROM/JOIN keyword and the table name.
_REF_PREFIXES = {"only", "lateral"}

#: Keywords that end a table-reference list at paren depth 0.
_CLAUSE_END_RE = re.compile(
    r"\b(where|group|having|order|limit|offset|fetch|window|union|intersect|except|"
    r"on|using|inner|left|right|full|cross|natural|join|for|qualify|returning)\b",
    re.IGNORECASE,
)

#: CTE definition: ``name AS (`` or ``name (cols) AS MATERIALIZED (``.
_CTE_RE = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_$]*)\s*(?:\([^()]*\))?\s+as\s+(?:not\s+)?(?:materialized\s+)?\(",
    re.IGNORECASE,
)


def _blank_literals(sql: str) -> str:
    """Replace comments and single-quoted literals with same-length spaces.

    Offsets are preserved so error messages and any later slicing still line up
    with the caller's statement.  Double-quoted / backticked / bracketed text is
    left alone: in every dialect HawkShield runs on, that is a quoted identifier,
    and a quoted table name is exactly what this guard must still see.
    """
    def blank(match: "re.Match[str]") -> str:
        return " " * (match.end() - match.start())

    text = _BLOCK_COMMENT_RE.sub(blank, sql)
    text = _LINE_COMMENT_RE.sub(blank, text)
    text = _STRING_RE.sub(blank, text)
    return text


def _unquote(identifier: str) -> str:
    ident = identifier.strip()
    if len(ident) >= 2 and ident[0] in '"`[' and ident[-1] in '"`]':
        ident = ident[1:-1]
    return ident.lower()


def _split_top_level(text: str, sep: str = ",") -> List[str]:
    """Split ``text`` on ``sep`` at parenthesis depth zero."""
    parts: List[str] = []
    depth = 0
    start = 0
    for i, ch in enumerate(text):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif ch == sep and depth == 0:
            parts.append(text[start:i])
            start = i + 1
    parts.append(text[start:])
    return parts


def _clause_body(text: str) -> str:
    """The table-reference list that follows a ``FROM``/``JOIN``, minus what follows it."""
    depth = 0
    i = 0
    length = len(text)
    while i < length:
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            if depth == 0:
                return text[:i]
            depth -= 1
        elif depth == 0:
            match = _CLAUSE_END_RE.match(text, i)
            if match:
                return text[:i]
        i += 1
    return text


def _reference_name(chunk: str) -> Optional[str]:
    """The table name at the head of one comma-separated table reference."""
    rest = chunk.lstrip()
    while True:
        if not rest or rest.startswith("("):
            return None  # a derived table / VALUES list, scanned on its own
        match = _IDENT_RE.match(rest)
        if match is None:
            return None
        word = match.group(0)
        if _unquote(word) in _REF_PREFIXES:
            rest = rest[match.end():].lstrip()
            continue
        break

    # Consume a dotted qualifier chain: schema.table, catalog.schema.table.
    parts = [word]
    rest = rest[match.end():]
    while True:
        stripped = rest.lstrip()
        if not stripped.startswith("."):
            break
        stripped = stripped[1:].lstrip()
        nxt = _IDENT_RE.match(stripped)
        if nxt is None:
            break
        parts.append(nxt.group(0))
        rest = stripped[nxt.end():]
    return ".".join(_unquote(p) for p in parts)


def table_references(sql: str) -> List[str]:
    """Every table named after a ``FROM`` or ``JOIN``, lower-cased and unquoted.

    Dotted references keep their qualifier (``pg_catalog.pg_tables``) so the
    caller can reject a schema as well as a table.  Derived tables and CTE
    bodies contribute nothing directly; their own ``FROM`` clauses are found by
    the same scan.
    """
    text = _blank_literals(sql)
    refs: List[str] = []
    for match in _FROM_JOIN_RE.finditer(text):
        body = _clause_body(text[match.end():])
        chunks = _split_top_level(body) if match.group(1).lower() == "from" else [body]
        for chunk in chunks:
            name = _reference_name(chunk)
            if name:
                refs.append(name)
    return refs


def cte_names(sql: str) -> Set[str]:
    """Names defined by a ``WITH`` clause in this statement, lower-cased."""
    text = _blank_literals(sql)
    if not re.match(r"^\s*\(*\s*with\b", text, re.IGNORECASE):
        return set()
    return {_unquote(m.group(1)) for m in _CTE_RE.finditer(text)}


def assert_tables_allowed(sql: str, allowed: Optional[Iterable[str]] = None) -> str:
    """Reject a SELECT that reads anything outside ``allowed`` (plus its own CTEs).

    ``allowed`` defaults to :data:`PACKETS_ONLY`.  A name defined by a ``WITH``
    clause in the same statement is always permitted, so

        WITH recent AS (SELECT * FROM packets ...) SELECT ... FROM recent

    passes while ``SELECT * FROM documents``, ``sqlite_master``,
    ``pg_catalog.pg_shadow`` and ``information_schema.tables`` do not.

    Returns ``sql`` unchanged so the call can be chained.
    """
    permitted = {str(t).strip().lower() for t in (allowed if allowed is not None else PACKETS_ONLY)}
    local = cte_names(sql)

    for ref in table_references(sql):
        parts = ref.split(".")
        name = parts[-1]
        qualifier = parts[-2] if len(parts) > 1 else ""
        if qualifier and qualifier not in _NEUTRAL_SCHEMAS:
            raise ValueError(
                f"Refusing to read from schema '{qualifier}': the assistant may only "
                f"query {sorted(permitted)}."
            )
        if name in local or name in permitted:
            continue
        raise ValueError(
            f"Refusing to read from table '{ref}': the assistant may only query "
            f"{sorted(permitted)}."
        )
    return sql


# --------------------------------------------------------------------------- #
# LIMIT safety net                                                             #
# --------------------------------------------------------------------------- #
def default_max_rows() -> int:
    """The row cap to apply when the caller does not name one."""
    raw = os.getenv("SAQR_MAX_ROWS") or os.getenv("RAG_MAX_ROWS")
    if raw:
        try:
            return max(1, int(raw))
        except (TypeError, ValueError):
            logger.warning("Ignoring non-integer row cap %r", raw)
    try:
        from backend.app.config import settings

        return max(1, int(settings.SAQR_MAX_ROWS))
    except Exception:  # noqa: BLE001 - configuration is optional here
        return DEFAULT_MAX_ROWS


def apply_row_limit(sql: str, max_rows: Optional[int] = None) -> str:
    """Append a bounded ``LIMIT`` to an unbounded, non-aggregate SELECT."""
    limit = max_rows if max_rows is not None else default_max_rows()
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
def jsonable(value: Any) -> Any:
    """Convert a driver value into something FastAPI's encoder can serialise."""
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
        return {str(k): jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [jsonable(v) for v in value]
    return str(value)


def rows_to_dicts(cols: Sequence[str], rows: Sequence[Sequence[Any]]) -> List[Dict[str, Any]]:
    """Zip ``(cols, rows)`` into JSON-safe dicts."""
    return [{col: jsonable(row[i]) for i, col in enumerate(cols)} for row in rows]


def normalise_packet_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """Undo the driver differences a raw ``SELECT *`` over ``packets`` exposes.

    On PostgreSQL psycopg2 returns a ``dict`` for ``raw`` and a ``datetime`` for
    ``ts``; on SQLite both arrive as TEXT.  Normalise so the shape is identical
    whichever backend is configured.  Mutates and returns ``row``.
    """
    value = row.get("raw")
    if isinstance(value, str):
        try:
            row["raw"] = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            logger.debug("Packet %s has a non-JSON raw payload", row.get("id"))

    ts = row.get("ts")
    if isinstance(ts, str):
        try:
            row["ts"] = datetime.fromisoformat(ts)
        except ValueError:
            logger.debug("Packet %s has an unparseable ts %r", row.get("id"), ts)

    return row


# --------------------------------------------------------------------------- #
# Execution                                                                    #
# --------------------------------------------------------------------------- #
def run_select(
    statement: str,
    *,
    db: Any = None,
    dialect: Optional[str] = None,
    timeout_ms: Optional[int] = None,
    db_url: Optional[str] = None,
) -> Tuple[List[str], List[Tuple[Any, ...]]]:
    """Execute an already-validated, already-limited SELECT.

    Three execution paths, in order of preference:

    * ``db`` -- a SQLAlchemy ``Session``.  Used by the agent, so a request's
      ``get_db`` override (tests) and its engine (production) are honoured.
    * SQLite without a session -- the application engine, because psycopg cannot
      parse a ``sqlite://`` URL.
    * PostgreSQL without a session -- ``psycopg.connect(db_url)`` with a
      server-side ``statement_timeout``.  This is the ``/ask`` path.

    The caller is responsible for :func:`assert_select_only` /
    :func:`assert_tables_allowed` / :func:`apply_row_limit`; this function does
    not re-validate, so that the statement it runs is exactly the one reported.
    """
    if dialect is None:
        dialect = sql_dialect()

    if db is not None:
        from sqlalchemy import text as sa_text

        result = db.execute(sa_text(statement))
        cols = list(result.keys())
        rows = [tuple(r) for r in result.fetchall()]
        return cols, rows

    if dialect == "sqlite":
        from sqlalchemy import text as sa_text

        from backend.app.db import engine

        with engine.connect() as conn:
            result = conn.execute(sa_text(statement))
            cols = list(result.keys())
            rows = [tuple(r) for r in result.fetchall()]
        return cols, rows

    import psycopg  # imported lazily so the module imports without a DB driver

    if not db_url:
        raise ValueError("No database URL supplied for a PostgreSQL SELECT.")
    ms = DEFAULT_SQL_TIMEOUT_MS if timeout_ms is None else int(timeout_ms)
    with psycopg.connect(db_url, options=f"-c statement_timeout={ms}") as conn:
        with conn.cursor() as cur:
            cur.execute(statement)  # type: ignore[arg-type]
            cols = [d[0] for d in (cur.description or [])]
            rows = cur.fetchall()
    return cols, list(rows)
