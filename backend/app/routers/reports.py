"""Report summary and PDF export endpoints."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from io import BytesIO
from typing import Annotated, Any, Dict, List

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from reportlab.lib.colors import HexColor
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.pdfgen.canvas import Canvas
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.app.config import FRONT_TYPE_MAP, FRONT_TYPES as _FRONT_TYPES
from backend.app.db import get_db
from backend.app.models import Packet
from backend.app.schemas import ReportExportPayload, ReportSummary

logger = logging.getLogger(__name__)

router = APIRouter(tags=["reports"])

#: Upper bound on ``days``, matching ``routers.attacks.MAX_DAYS``.
MAX_DAYS = 3650

# DB label -> frontend key.  Derived in ``backend.app.config`` from
# ``feature_spec.ATTACK_CLASSES`` so there is one class list in the repo, not two.
# The six v1 keys are unchanged and keep their historical order; spec 2.1.0 appends
# ``disas`` and ``kr00k``.  Punctuation is dropped rather than escaped, so
# ``(Re)Assoc`` still becomes plain ``reassoc`` -- no key needs URL or JSON quoting.
TYPE_MAP_DB_TO_FRONT: Dict[str, str] = dict(FRONT_TYPE_MAP)
FRONT_TYPES: List[str] = list(_FRONT_TYPES)

# Row order used by the PDF export.
PDF_TYPE_ORDER: List[str] = FRONT_TYPES + ["other"]


# ---------------------------------------------------------------------------
# The PDF's visual language
#
# This file renders the *fallback* report.  The showpiece is the browser print
# view at ``/report`` -- it has the brand face, Arabic shaping, bidi and the
# whole token system, none of which ReportLab can be given here:
# ``thmanyahsans-*.otf`` carries PostScript/CFF outlines that ``TTFont``
# rejects outright, the Pi ships no Arabic TTF at all, and ReportLab performs
# neither shaping nor the bidi algorithm.  So this stays Helvetica and Latin,
# and earns its keep by being the one that works with no browser in the room.
#
# What it can have is the brand drawn as vector primitives.  The two hues are
# the ones sampled from the mark (frontend/brand-spec.md): navy is the hawk
# head, azure the Wi-Fi arcs.  Everything else is a neutral derived from them.
# ---------------------------------------------------------------------------
NAVY = HexColor("#0E2A55")
AZURE = HexColor("#2E8FDD")
PAPER = HexColor("#FBFBFD")
PAPER_TINT = HexColor("#F1F4F8")
RULE = HexColor("#D9DEE6")
INK = HexColor("#1B2436")
INK_DIM = HexColor("#5D6880")


def _wordmark(pdf: Canvas, x: float, y: float, size: float, ground: Any) -> float:
    """Draw "HawkShield" the way the mark splits it, and return its width.

    Two draws rather than one string: the azure has to begin exactly where the
    navy ends, so the second baseline offset is measured, never guessed.
    """
    pdf.setFont("Helvetica-Bold", size)
    hawk = pdf.stringWidth("Hawk", "Helvetica-Bold", size)
    shield = pdf.stringWidth("Shield", "Helvetica-Bold", size)
    pdf.setFillColor(ground)
    pdf.drawString(x, y, "Hawk")
    pdf.setFillColor(AZURE)
    pdf.drawString(x + hawk, y, "Shield")
    return hawk + shield


def _label(pdf: Canvas, x: float, y: float, text: str, colour: Any = None) -> None:
    """The mono micro-label, as close as Helvetica gets: small, tracked, upper.

    Drawn through a text object because letter-spacing lives on the text state,
    not on the canvas -- ``Canvas`` has no ``setCharSpace``, only ``beginText``
    does.
    """
    obj = pdf.beginText(x, y)
    obj.setFont("Helvetica-Bold", 7)
    obj.setFillColor(colour if colour is not None else INK_DIM)
    obj.setCharSpace(1.1)
    obj.textOut(text.upper())
    pdf.drawText(obj)


def _rule(pdf: Canvas, x0: float, y: float, x1: float, colour: Any = RULE, width: float = 0.6) -> None:
    """One hairline. The system has two weights and no third."""
    pdf.setStrokeColor(colour)
    pdf.setLineWidth(width)
    pdf.line(x0, y, x1, y)


def _since_dt(days: int) -> datetime:
    """Lower bound of the reporting window, as an aware UTC datetime."""
    return datetime.now(timezone.utc) - timedelta(days=days)


def compute_summary(db: Session, days: int = 30) -> ReportSummary:
    """Aggregate the last ``days`` of packets into the report structure."""
    lb_dt = _since_dt(days)

    rows = (
        db.query(Packet.predicted_label, func.count(Packet.id))
        .filter(Packet.ts >= lb_dt)
        .group_by(Packet.predicted_label)
        .all()
    )

    totals: Dict[str, int] = {k: 0 for k in FRONT_TYPES}
    other = 0
    for db_label, cnt in rows:
        key = TYPE_MAP_DB_TO_FRONT.get(db_label, None)
        if key in totals:
            totals[key] += int(cnt)
        else:
            other += int(cnt)
    totals["other"] = other

    # Peak hour (UTC).
    hours = [0] * 24
    for (ts,) in db.query(Packet.ts).filter(Packet.ts >= lb_dt).all():
        if not ts:
            continue
        dt = ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
        hours[dt.hour] += 1
    peak_hour = max(range(24), key=lambda h: hours[h]) if any(hours) else 0

    unique_sources = (
        db.query(func.count(func.distinct(Packet.src_mac))).filter(Packet.ts >= lb_dt).scalar() or 0
    )

    total_attacks = sum(totals.values())
    most = max(totals, key=totals.get) if total_attacks else "other"

    return ReportSummary(
        period=f"Last {days} day(s)",
        totals=totals,
        summary={
            "totalAttacks": total_attacks,
            "mostFrequentType": most,
            "peakHour": peak_hour,
            "uniqueSources": int(unique_sources),
        },
    )


@router.get("/reports/summary")
def get_report_summary(
    days: Annotated[int, Query(
        ge=1, le=MAX_DAYS,
        description="Reporting window in days.",
    )] = 30,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Totals + headline summary for the last ``days`` days.

    ``days`` is validated to match the analytics endpoints.  It previously
    accepted ``0`` and negatives, which produced a lower bound in the *future*
    and therefore a confidently-rendered report of zero attacks -- a wrong
    answer presented as a right one, which is worse than an error.

    Annotated form, not ``days: int = Query(30, ...)``: only this leaves a real
    Python default on the function, and ``compute_summary`` / the Saqr agent
    call these handlers directly rather than over HTTP.
    """
    data = compute_summary(db, days=days)
    return data.model_dump()


@router.post("/reports/export")
def export_pdf(payload: ReportExportPayload, db: Session = Depends(get_db)) -> StreamingResponse:
    """Render the same summary as a one-page A4 PDF attachment.

    The response shape is fixed by the contract and by
    ``backend/scripts/check_frontend.py``: ``application/pdf``, an attachment
    named ``hawkshield_report_<days>d.pdf``, one page.  Only the ink changed.

    Class keys are printed verbatim (``evil_twin``, ``reassoc``).  They are the
    identifiers the model and the database emit, and inventing prettier labels
    here would put a second, drifting copy of the frontend's class vocabulary
    in the backend.
    """
    data = compute_summary(db, days=payload.days)

    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    pdf.setTitle("HawkShield - Detection report")
    pdf.setAuthor("HawkShield sensor")
    pdf.setSubject(f"Detection report - {data.period}")
    width, height = A4

    margin = 46.0
    right = width - margin
    band_h = 78.0

    # ── Masthead ─────────────────────────────────────────────────────────
    # A navy field with the wordmark reversed out of it, closed by an azure
    # rule. The band IS the identity here; there is no raster to place, and a
    # hand-drawn hawk is banned by the brand spec for good reason.
    pdf.setFillColor(NAVY)
    pdf.rect(0, height - band_h, width, band_h, stroke=0, fill=1)
    pdf.setFillColor(AZURE)
    pdf.rect(0, height - band_h - 3, width, 3, stroke=0, fill=1)

    _wordmark(pdf, margin, height - 46, 21, PAPER)
    _label(pdf, margin, height - 62, "Wi-Fi intrusion detection", AZURE)

    pdf.setFont("Helvetica", 8)
    pdf.setFillColor(PAPER)
    pdf.drawRightString(right, height - 46, "Detection report")
    pdf.setFillColor(AZURE)
    pdf.drawRightString(
        right, height - 62, datetime.now(timezone.utc).strftime("Compiled %Y-%m-%d %H:%M UTC")
    )

    y = height - band_h - 44

    # ── Title and lede ───────────────────────────────────────────────────
    pdf.setFont("Helvetica-Bold", 19)
    pdf.setFillColor(NAVY)
    pdf.drawString(margin, y, "What the sensor detected")
    y -= 18
    pdf.setFont("Helvetica", 9.5)
    pdf.setFillColor(INK_DIM)
    pdf.drawString(
        margin,
        y,
        "Every figure below is a count of frames this sensor captured, stored and classified.",
    )
    y -= 12
    pdf.drawString(margin, y, "Nothing is estimated.")

    y -= 26
    _rule(pdf, margin, y, right)
    y -= 22

    # ── The window at a glance ───────────────────────────────────────────
    # Four figures across the measure, each under its own micro-label. The
    # display size is what makes this read as a report rather than a log dump.
    glance = (
        ("Reporting window", data.period),
        ("Classified detections", f"{data.summary['totalAttacks']:,}"),
        ("Distinct source MACs", f"{data.summary['uniqueSources']:,}"),
        ("Busiest hour (UTC)", f"{int(data.summary['peakHour']):02d}:00"),
    )
    column = (right - margin) / len(glance)
    for i, (label, value) in enumerate(glance):
        x = margin + i * column
        _label(pdf, x, y, label)
        pdf.setFont("Helvetica-Bold", 15)
        pdf.setFillColor(INK)
        pdf.drawString(x, y - 21, str(value))

    y -= 40
    _label(pdf, margin, y, "Most frequent class")
    pdf.setFont("Helvetica-Bold", 10)
    pdf.setFillColor(INK)
    pdf.drawString(margin + 118, y, str(data.summary["mostFrequentType"]))

    y -= 30

    # ── Detections by class ──────────────────────────────────────────────
    pdf.setFont("Helvetica-Bold", 12)
    pdf.setFillColor(NAVY)
    pdf.drawString(margin, y, "Detections by class")
    y -= 20

    total = int(data.summary["totalAttacks"]) or 0
    col_count = right - 168
    col_share = right - 108
    bar_x = right - 96
    bar_w = 96.0
    row_h = 19.0

    # Header: navy strip, reversed labels. One fill, not a border on each cell.
    pdf.setFillColor(NAVY)
    pdf.rect(margin, y - 5, right - margin, 17, stroke=0, fill=1)
    _label(pdf, margin + 8, y, "Class", PAPER)
    # Right-aligned, so no tracking: `drawRightString` measures the untracked
    # advance and the label would drift past its column by the tracked width.
    pdf.setFont("Helvetica-Bold", 7)
    pdf.setFillColor(PAPER)
    pdf.drawRightString(col_count, y, "FRAMES")
    pdf.drawRightString(col_share, y, "SHARE")
    y -= 17

    for i, key in enumerate(PDF_TYPE_ORDER):
        value = int(data.totals.get(key, 0))
        share = (value / total) if total else 0.0

        if i % 2 == 1:
            pdf.setFillColor(PAPER_TINT)
            pdf.rect(margin, y - 6, right - margin, row_h, stroke=0, fill=1)

        pdf.setFont("Helvetica", 9.5)
        pdf.setFillColor(INK if value else INK_DIM)
        pdf.drawString(margin + 8, y, key)
        pdf.drawRightString(col_count, y, f"{value:,}")
        pdf.drawRightString(col_share, y, f"{share * 100:.1f}%" if total else "-")

        # The share bar. Azure on a paper track, so a reader can rank the
        # classes without reading a single digit.
        pdf.setFillColor(RULE)
        pdf.rect(bar_x, y - 1, bar_w, 4, stroke=0, fill=1)
        if share > 0:
            pdf.setFillColor(AZURE)
            pdf.rect(bar_x, y - 1, bar_w * share, 4, stroke=0, fill=1)

        y -= row_h
        _rule(pdf, margin, y + 12, right)

    # Total, set apart by weight rather than by a second rule weight.
    pdf.setFont("Helvetica-Bold", 9.5)
    pdf.setFillColor(NAVY)
    pdf.drawString(margin + 8, y - 4, "Total")
    pdf.drawRightString(col_count, y - 4, f"{total:,}")

    # ── Reading this report ──────────────────────────────────────────────
    # The same three sentences the browser view carries, for the same reason:
    # a page of counts with nothing saying what was counted invites the reader
    # to assume the sensor saw everything. It did not, and the report says so.
    # Every line is measured against the 503pt measure rather than wrapped by
    # eye -- ReportLab's drawString does not wrap, it just runs off the page.
    y -= 44
    pdf.setFont("Helvetica-Bold", 12)
    pdf.setFillColor(NAVY)
    pdf.drawString(margin, y, "Reading this report")
    y -= 18

    pdf.setFont("Helvetica", 9.5)
    pdf.setFillColor(INK_DIM)
    for line in (
        "Every figure is a count of frames the sensor stored and the classifier labelled. A class",
        "with no count is a class with no detection in this window -- the absence of evidence, not",
        "evidence of absence.",
        "",
        "The sensor listens on one interface at a time, so anything outside that radio's reach was",
        "never offered to the classifier and cannot appear here.",
    ):
        if line:
            pdf.drawString(margin, y, line)
        y -= 13

    # ── Footer ───────────────────────────────────────────────────────────
    foot = margin + 30
    _rule(pdf, margin, foot + 16, right)
    pdf.setFont("Helvetica", 8)
    pdf.setFillColor(INK_DIM)
    pdf.drawString(
        margin,
        foot,
        "HawkShield detects, classifies and reports. Nothing here was blocked, "
        "no client was disconnected, and no network is called clean.",
    )
    pdf.drawString(margin, foot - 11, "Compiled by the sensor from its own stored frames.")
    pdf.drawRightString(right, foot - 11, "Page 1 of 1")

    pdf.showPage()
    pdf.save()
    buffer.seek(0)

    filename = f"hawkshield_report_{payload.days}d.pdf"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return StreamingResponse(buffer, media_type="application/pdf", headers=headers)
