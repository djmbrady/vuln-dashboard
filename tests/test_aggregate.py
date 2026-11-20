from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

import app.main as main
from app.aggregate import age_bucket, build_dashboard, has_fix, normalize_severity
from app.db import DashboardError

NOW = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)


def _row(**overrides):
    base = {
        "repo_full_name": "acme/payments",
        "scan_type": "manifest",
        "cve_id": "CVE-2024-0001",
        "package_name": "lodash",
        "installed_version": "4.17.15",
        "fixed_version": "4.17.21",
        "severity": "HIGH",
        "title": "Prototype pollution",
        "mitigation": "Upgrade lodash to 4.17.21.",
        "status": "open",
        "first_seen_at": NOW - timedelta(days=3),
        "scanned_at": NOW - timedelta(hours=2),
        "image_tag": None,
        "branch": "main",
    }
    base.update(overrides)
    return base


def test_age_bucket_boundaries():
    assert age_bucket(0) == "0-7 days"
    assert age_bucket(7) == "0-7 days"
    assert age_bucket(8) == "8-30 days"
    assert age_bucket(30) == "8-30 days"
    assert age_bucket(31) == "31-90 days"
    assert age_bucket(90) == "31-90 days"
    assert age_bucket(91) == "90+ days"


def test_fix_and_severity_normalization():
    assert has_fix("1.2.3") is True
    assert has_fix("  ") is False
    assert has_fix("unfixed") is False
    assert has_fix(None) is False
    assert normalize_severity("high") == "HIGH"
    assert normalize_severity("weird") == "UNKNOWN"


def test_dashboard_counts_and_default_open_filter():
    rows = [
        _row(),
        _row(
            cve_id="CVE-2024-0002",
            severity="CRITICAL",
            fixed_version=None,
            first_seen_at=NOW - timedelta(days=40),
            scan_type="container",
            image_tag="payments:1",
        ),
        _row(
            repo_full_name="acme/web",
            cve_id="CVE-2023-9999",
            severity="LOW",
            status="resolved",
            fixed_version="",
            first_seen_at=NOW - timedelta(days=10),
        ),
    ]

    report = build_dashboard(rows, now=NOW, status="open")

    assert report["kpis"]["findings"] == 2
    assert report["kpis"]["open_findings"] == 2
    assert report["kpis"]["critical_high"] == 2
    assert report["kpis"]["critical_high_with_fix"] == 1
    assert report["kpis"]["repositories"] == 1
    assert report["kpis"]["fix_available"] == 1
    assert report["kpis"]["fix_available_pct"] == 50
    assert report["kpis"]["oldest_age_days"] == 40
    assert report["kpis"]["median_age_days"] == 22
    assert report["kpis"]["image_findings"] == 1
    assert report["kpis"]["repository_findings"] == 1
    assert report["filters"]["repos"] == ["acme/payments", "acme/web"]
    assert [item["bucket"] for item in report["by_age"]] == [
        "0-7 days",
        "8-30 days",
        "31-90 days",
        "90+ days",
    ]
    assert report["by_age"][2]["CRITICAL"] == 1
    assert report["by_age"][0]["HIGH"] == 1
    assert report["findings"][0]["severity"] == "CRITICAL"
    assert report["findings"][0]["age_label"] == "40 days"
    assert "fix version" in report["narrative"]


def test_repo_filter_limits_charts_but_keeps_dropdown_options():
    rows = [
        _row(),
        _row(repo_full_name="acme/web", cve_id="CVE-2024-0008", severity="MEDIUM"),
    ]
    report = build_dashboard(rows, now=NOW, repo="acme/web", status="open")
    assert report["kpis"]["findings"] == 1
    assert report["by_repository"][0]["repo"] == "acme/web"
    assert report["filters"]["repos"] == ["acme/payments", "acme/web"]


def test_api_hides_database_secrets(monkeypatch):
    def explode(force=False):
        raise DashboardError("Could not read the vulnerability database.") from RuntimeError(
            "postgresql://neondb_owner:supersecret@example/db"
        )

    monkeypatch.setattr(main, "load_findings", explode)
    response = TestClient(main.app).get("/api/dashboard")
    assert response.status_code == 503
    assert "supersecret" not in response.text
    assert "DATABASE_URL" not in response.text or "Check DATABASE_URL" in response.text


def test_api_serves_aggregated_sample(monkeypatch):
    monkeypatch.setattr(main, "load_findings", lambda force=False: [_row()])
    response = TestClient(main.app).get("/api/dashboard", params={"status": "open"})
    assert response.status_code == 200
    body = response.json()
    assert body["kpis"]["critical_high"] == 1
    assert body["findings"][0]["cve_id"] == "CVE-2024-0001"

    page = TestClient(main.app).get("/")
    assert page.status_code == 200
    assert "Vulnerability dashboard" in page.text
