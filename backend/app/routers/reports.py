"""Report summary and PDF export endpoints."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from io import BytesIO
from typing import Annotated, Any, Dict, List

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
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
    """Render the same summary as a one-page A4 PDF attachment."""
    data = compute_summary(db, days=payload.days)

    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    y = height - 50
    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(40, y, "HawkShield – Attack Report")
    y -= 20
    pdf.setFont("Helvetica", 10)
    pdf.drawString(40, y, f"Period: {data.period}")
    y -= 30

    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(40, y, "Totals by Type")
    y -= 16
    pdf.setFont("Helvetica", 10)
    for k in PDF_TYPE_ORDER:
        line = f"{k:12s} : {data.totals.get(k, 0)}"
        pdf.drawString(60, y, line)
        y -= 14

    y -= 10
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(40, y, "Summary")
    y -= 16
    pdf.setFont("Helvetica", 10)
    pdf.drawString(60, y, f"Total Attacks     : {data.summary['totalAttacks']}")
    y -= 14
    pdf.drawString(60, y, f"Most Frequent     : {data.summary['mostFrequentType']}")
    y -= 14
    pdf.drawString(60, y, f"Peak Hour (UTC)   : {data.summary['peakHour']}:00")
    y -= 14
    pdf.drawString(60, y, f"Unique Sources    : {data.summary['uniqueSources']}")

    pdf.showPage()
    pdf.save()
    buffer.seek(0)

    filename = f"hawkshield_report_{payload.days}d.pdf"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return StreamingResponse(buffer, media_type="application/pdf", headers=headers)
