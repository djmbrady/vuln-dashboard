"""Turn vulnerability rows into the charts and totals the dashboard shows."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
AGE_BUCKETS = ("0-7 days", "8-30 days", "31-90 days", "90+ days")
# Trivy and the scanner sometimes store these instead of a real version.
UNFIXED_TOKENS = {"", "unfixed", "none", "n/a", "null", "not fixed"}


def normalize_severity(value: str | None) -> str:
    upper = (value or "").strip().upper()
    return upper if upper in SEVERITY_ORDER else "UNKNOWN"


def has_fix(fixed_version: str | None) -> bool:
    if fixed_version is None:
        return False
    return str(fixed_version).strip().lower() not in UNFIXED_TOKENS


def age_days(first_seen: datetime, now: datetime) -> int:
    if first_seen.tzinfo is None:
        first_seen = first_seen.replace(tzinfo=timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    return max(0, (now - first_seen).days)


def age_bucket(days: int) -> str:
    if days <= 7:
        return "0-7 days"
    if days <= 30:
        return "8-30 days"
    if days <= 90:
        return "31-90 days"
    return "90+ days"


def age_label(days: int | None) -> str:
    if days is None:
        return "Unknown"
    if days == 0:
        return "Today"
    if days == 1:
        return "1 day"
    return f"{days} days"


def _median(values: list[int]) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return round((ordered[mid - 1] + ordered[mid]) / 2)


def _empty_severity_counts() -> dict[str, int]:
    return {severity: 0 for severity in SEVERITY_ORDER}


def filter_findings(
    rows: list[dict[str, Any]],
    *,
    repo: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    scan_type: str | None = None,
) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    wanted_severity = severity.upper() if severity else None
    wanted_status = status.lower() if status else None
    for row in rows:
        if repo and row.get("repo_full_name") != repo:
            continue
        if wanted_severity and normalize_severity(row.get("severity")) != wanted_severity:
            continue
        if wanted_status and (row.get("status") or "").lower() != wanted_status:
            continue
        if scan_type and row.get("scan_type") != scan_type:
            continue
        selected.append(row)
    return selected


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.isoformat()


def narrative(kpis: dict[str, Any], status: str | None) -> str:
    count = kpis["findings"]
    if count == 0:
        return "No findings match the current filters."

    scope = "open findings" if status == "open" else "findings"
    oldest = kpis["oldest_age_days"]
    if oldest is None:
        age_sentence = "Age is unavailable because first-seen dates are missing."
    elif oldest == 0:
        age_sentence = "Every matching finding was first seen today."
    else:
        age_sentence = f"The oldest matching finding was first seen {oldest} days ago."

    return (
        f"{kpis['critical_high']} of {count} {scope} are high or critical, "
        f"and {kpis['critical_high_with_fix']} of those have a fix version listed. "
        f"Across this view, a fix is listed for {kpis['fix_available']} "
        f"({kpis['fix_available_pct']}%). {age_sentence}"
    )


def build_dashboard(
    rows: list[dict[str, Any]],
    *,
    now: datetime,
    repo: str | None = None,
    severity: str | None = None,
    status: str | None = "open",
    scan_type: str | None = None,
) -> dict[str, Any]:
    """Aggregate a full result set. Filters apply to charts; dropdowns use every row."""
    repos = sorted({row["repo_full_name"] for row in rows if row.get("repo_full_name")})
    severities_present = [
        level
        for level in SEVERITY_ORDER
        if any(normalize_severity(row.get("severity")) == level for row in rows)
    ]
    statuses = sorted({(row.get("status") or "unknown").lower() for row in rows})
    scan_types = sorted({row["scan_type"] for row in rows if row.get("scan_type")})

    selected = filter_findings(
        rows,
        repo=repo,
        severity=severity,
        status=status,
        scan_type=scan_type,
    )

    by_severity = _empty_severity_counts()
    by_repo: dict[str, dict[str, int]] = {}
    by_age = {bucket: _empty_severity_counts() for bucket in AGE_BUCKETS}
    by_scan: dict[str, int] = {}
    ages: list[int] = []
    fix_yes = 0
    critical_high_with_fix = 0
    latest_scan: datetime | None = None
    findings: list[dict[str, Any]] = []

    for row in selected:
        level = normalize_severity(row.get("severity"))
        by_severity[level] += 1

        repo_name = row.get("repo_full_name") or "unknown"
        by_repo.setdefault(repo_name, _empty_severity_counts())
        by_repo[repo_name][level] += 1

        first_seen = row.get("first_seen_at")
        days = age_days(first_seen, now) if isinstance(first_seen, datetime) else None
        if days is None:
            bucket = None
        else:
            ages.append(days)
            bucket = age_bucket(days)
            by_age[bucket][level] += 1

        fixed = has_fix(row.get("fixed_version"))
        if fixed:
            fix_yes += 1
            if level in ("CRITICAL", "HIGH"):
                critical_high_with_fix += 1

        source = row.get("scan_type") or "unknown"
        by_scan[source] = by_scan.get(source, 0) + 1

        scanned_at = row.get("scanned_at")
        if isinstance(scanned_at, datetime) and (latest_scan is None or scanned_at > latest_scan):
            latest_scan = scanned_at

        findings.append(
            {
                "repo_full_name": repo_name,
                "scan_type": source,
                "image_tag": row.get("image_tag"),
                "branch": row.get("branch"),
                "cve_id": row.get("cve_id"),
                "package_name": row.get("package_name"),
                "installed_version": row.get("installed_version"),
                "fixed_version": row.get("fixed_version") if fixed else None,
                "severity": level,
                "title": row.get("title"),
                "mitigation": row.get("mitigation"),
                "status": (row.get("status") or "unknown").lower(),
                "age_days": days,
                "age_label": age_label(days),
                "first_seen_at": _iso(first_seen if isinstance(first_seen, datetime) else None),
            }
        )

    severity_rank = {level: index for index, level in enumerate(SEVERITY_ORDER)}
    findings.sort(
        key=lambda item: (
            severity_rank[item["severity"]],
            -(item["age_days"] if item["age_days"] is not None else -1),
            item.get("cve_id") or "",
            item.get("package_name") or "",
        )
    )

    total = len(selected)
    critical_high = by_severity["CRITICAL"] + by_severity["HIGH"]
    kpis = {
        "findings": total,
        "open_findings": sum(1 for item in findings if item["status"] == "open"),
        "critical_high": critical_high,
        "critical_high_with_fix": critical_high_with_fix,
        "repositories": len(by_repo),
        "fix_available": fix_yes,
        "fix_available_pct": round(100 * fix_yes / total) if total else 0,
        "median_age_days": _median(ages),
        "oldest_age_days": max(ages) if ages else None,
        "image_findings": by_scan.get("container", 0),
        "repository_findings": by_scan.get("manifest", 0),
        "latest_scan_at": _iso(latest_scan),
    }

    return {
        "generated_at": now.isoformat(),
        "filters": {
            "applied": {
                "repo": repo,
                "severity": severity.upper() if severity else None,
                "status": status.lower() if status else None,
                "scan_type": scan_type,
            },
            "repos": repos,
            "severities": severities_present,
            "statuses": statuses,
            "scan_types": scan_types,
        },
        "kpis": kpis,
        "narrative": narrative(kpis, status.lower() if status else None),
        "by_severity": [
            {"severity": level, "count": by_severity[level]}
            for level in SEVERITY_ORDER
            if by_severity[level]
        ],
        "by_repository": [
            {
                "repo": repo_name,
                "total": sum(counts.values()),
                **counts,
            }
            for repo_name, counts in sorted(
                by_repo.items(),
                key=lambda item: (-sum(item[1].values()), item[0]),
            )
        ],
        "by_age": [
            {
                "bucket": bucket,
                "total": sum(counts.values()),
                **counts,
            }
            for bucket, counts in by_age.items()
        ],
        "by_fix": [
            {"label": "Fix listed", "count": fix_yes},
            {"label": "No fix listed", "count": total - fix_yes},
        ],
        "by_scan_type": [
            {"scan_type": scan, "count": by_scan[scan]}
            for scan in ("container", "manifest")
            if by_scan.get(scan)
        ] + [
            {"scan_type": scan, "count": count}
            for scan, count in sorted(by_scan.items())
            if scan not in ("container", "manifest")
        ],
        "findings": findings,
    }
