# Vulnerability dashboard

Read-only view of the Neon scan database used by the CVE and container scanners. It summarizes open findings for stakeholders: severity, repository, whether a fix version is listed, where the finding came from (repository manifest or CI image), and how long it has been known.

The page only runs `SELECT` queries against `vulnerabilities` and `scan_runs`.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Put the Neon connection string in `.env` as `DATABASE_URL`. That file is gitignored.

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000.

## What the page shows

- Totals for the current filter: finding count, high and critical count, repositories, and the share with a fix version.
- Severity mix, fix availability, and manifest versus image source.
- Findings per repository, stacked by severity.
- Age profile from `first_seen_at`: 0–7 days, 8–30 days, 31–90 days, and 90+ days, stacked by severity.
- A table of CVE, package, installed version, fix version, repository, source, and mitigation.

Filters cover repository, severity, status, and source. Status defaults to open. Refresh bypasses a 30-second cache of the database read.

Findings first seen today all sit in the 0–7 day bucket. The older buckets fill in as findings stay open across later scans.

## Verify

```bash
source .venv/bin/activate
pytest
```

With the app running, the unfiltered open view should match the database. At the time this was built that was 40 open findings, 5 high or critical, 2 repositories (`djmbrady/demo` and `djmbrady/devsecops-sandbox`), and a fix version on half of the findings. Choosing one repository in the filter should shrink the charts and the table to that repository only.

```bash
curl -s 'http://127.0.0.1:8000/api/dashboard?status=open' | python -m json.tool
```
