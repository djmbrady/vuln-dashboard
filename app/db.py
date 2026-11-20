"""Read-only access to the scan tables. Findings are cached briefly for filter changes."""

from __future__ import annotations

import os
import time
from typing import Any

import psycopg2
from psycopg2.extras import RealDictCursor

CACHE_SECONDS = 30
_cache: dict[str, Any] = {"loaded_at": 0.0, "rows": None}

FINDINGS_SQL = """
SELECT
    v.repo_full_name,
    v.scan_type,
    v.cve_id,
    v.package_name,
    v.installed_version,
    v.fixed_version,
    v.severity,
    v.title,
    v.mitigation,
    v.status,
    v.first_seen_at,
    v.last_seen_at,
    s.image_tag,
    s.branch,
    s.scanned_at
FROM vulnerabilities v
LEFT JOIN scan_runs s ON s.id = v.last_scan_run_id
"""


class DashboardError(Exception):
    def __init__(self, message: str, status: int = 503) -> None:
        super().__init__(message)
        self.message = message
        self.status = status


def load_findings(force: bool = False) -> list[dict[str, Any]]:
    now = time.monotonic()
    cached = _cache["rows"]
    if not force and cached is not None and now - _cache["loaded_at"] < CACHE_SECONDS:
        return cached

    database_url = os.environ.get("DATABASE_URL", "").strip()
    if not database_url:
        raise DashboardError(
            "DATABASE_URL is not set. Add it to the .env file in the project root."
        )

    try:
        with psycopg2.connect(database_url, connect_timeout=10) as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(FINDINGS_SQL)
                rows = [dict(row) for row in cur.fetchall()]
    except DashboardError:
        raise
    except Exception as exc:
        # The driver can include the connection string in its message. Keep that off the client.
        raise DashboardError(
            "Could not read the vulnerability database. Check DATABASE_URL and network access."
        ) from exc

    _cache["loaded_at"] = now
    _cache["rows"] = rows
    return rows
