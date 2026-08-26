"""HawkShield FastAPI application factory.

One uvicorn process serves both the JSON API and — when a built frontend is
present — the static Next.js export at ``/``.
"""
from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend.app.config import APP_VERSION, configure_logging, settings
from backend.app.routers import ask, attacks, health, maps, reports

logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    """Build and configure the ASGI application."""
    configure_logging()

    app = FastAPI(title="HawkShield API", version=APP_VERSION)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # API routes first: registered without any prefix, exactly as the frontend
    # expects (``${API_BASE}/attacks``, ...).
    app.include_router(health.router)
    app.include_router(attacks.router)
    app.include_router(reports.router)
    app.include_router(maps.router)
    app.include_router(ask.router)

    # Static frontend last, so the catch-all mount at "/" can never shadow an
    # API route.  Absent in dev (no `next build` run) - skip cleanly.
    frontend_dist = settings.FRONTEND_DIST
    frontend_mounted = frontend_dist.is_dir()
    if frontend_mounted:
        app.mount("/", StaticFiles(directory=str(frontend_dist), html=True), name="frontend")

    logger.info(
        "HawkShield API %s starting | db=%s | cors=%s | frontend=%s",
        APP_VERSION,
        settings.safe_database_url(),
        ",".join(settings.CORS_ORIGINS) or "(none)",
        f"mounted from {frontend_dist}" if frontend_mounted else f"not mounted ({frontend_dist} absent)",
    )

    return app


app = create_app()
