from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.aggregate import SEVERITY_ORDER, build_dashboard
from app.db import DashboardError, load_findings

ROOT = Path(__file__).resolve().parents[1]
STATIC = Path(__file__).resolve().parent / "static"
load_dotenv(ROOT / ".env")

logger = logging.getLogger("vuln_dashboard")
app = FastAPI(title="Vulnerability dashboard", version="1.0")
app.mount("/static", StaticFiles(directory=STATIC), name="static")


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    if stripped == "" or stripped.lower() == "all":
        return None
    return stripped


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


@app.get("/api/dashboard")
def dashboard(
    repo: str | None = None,
    severity: str | None = None,
    status: str | None = Query(default="open"),
    scan_type: str | None = None,
    refresh: bool = False,
) -> dict:
    repo = _clean(repo)
    severity = _clean(severity)
    status = _clean(status)
    scan_type = _clean(scan_type)

    if severity and severity.upper() not in SEVERITY_ORDER:
        raise HTTPException(status_code=400, detail="Unknown severity.")
    if scan_type and scan_type not in ("container", "manifest"):
        raise HTTPException(status_code=400, detail="Unknown scan type.")

    try:
        rows = load_findings(force=refresh)
    except DashboardError as exc:
        logger.error("dashboard read failed: %s", type(exc.__cause__ or exc).__name__)
        raise HTTPException(status_code=exc.status, detail=exc.message) from exc

    return build_dashboard(
        rows,
        now=datetime.now(timezone.utc),
        repo=repo,
        severity=severity,
        status=status,
        scan_type=scan_type,
    )
