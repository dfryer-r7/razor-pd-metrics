# pd-metrics

PagerDuty incident & alert analysis for the razor services. Pulls data from the
PagerDuty Analytics API and produces CSV rollups plus self-contained, styled
HTML reports (charts and tables embedded — just open the `.html` in a browser).

Two scripts:

| Script | What it reports |
|--------|-----------------|
| `pd_service_metrics.py` | Incident counts **by PagerDuty service**, with regional duplicate-alert noise analysis, WoW/MoM trends, and a weekly trend chart. |
| `pd_alert_report.py` | Alerts **by application service** (resolved from the alert body's `- service =` label), split into working-hours vs off-hours, with a day×hour density heatmap. |

## Prerequisites

- [**uv**](https://docs.astral.sh/uv/) — the only thing you need to install.
  Each script declares its own dependencies inline ([PEP 723](https://peps.python.org/pep-0723/));
  `uv run` installs them into an ephemeral, cached environment automatically.
  There is no `requirements.txt` and no virtualenv to manage.

  Install uv (macOS):

  ```bash
  brew install uv
  ```

## Setup

1. Copy the example env file and add your API key:

   ```bash
   cp env.example .env
   ```

2. Edit `.env` and set `PAGERDUTY_API_KEY` (see below). `PAGERDUTY_SERVICE_IDS`
   is pre-filled with the razor services; leave it as-is or override per-run
   with `--service`.

   `.env` is git-ignored — your key never gets committed.

### Getting a PagerDuty API key

The scripts need a **REST API key with read access**:

1. In PagerDuty, go to **Integrations → API Access Keys**
   (requires admin/account-owner permissions).
2. Click **Create New API Key**.
3. Give it a description (e.g. `pd-metrics read-only`) and check
   **Read-only API Key** — these scripts only read data.
4. Copy the generated key into `.env` as `PAGERDUTY_API_KEY=...`. You won't be
   able to view it again after closing the dialog.

> **Analytics must be enabled.** These reports use the PagerDuty Analytics API.
> If it isn't enabled on the account, or the incidents are very recent, you may
> get empty results — Analytics data lags real-time by up to ~24 hours.

## Usage

```bash
# Discover service IDs/names
uv run pd_service_metrics.py --list-services

# Service incident report, last 90 days (uses PAGERDUTY_SERVICE_IDS from .env)
uv run pd_service_metrics.py --days 90

# Alert working/off-hours report, last 30 days, Eastern time
uv run pd_alert_report.py --days 30 --tz America/New_York

# Override which services to report on
uv run pd_service_metrics.py --days 90 --service PZZG5VN,P27C0CY

# Arbitrary past window: last quarter (92d window ending 2026-06-23)
uv run pd_service_metrics.py --days 92 --end 2026-06-23
uv run pd_alert_report.py --days 92 --end 2026-06-23
```

`--days` is a lookback window; it defaults to ending now, but `--end YYYY-MM-DD`
shifts that end date into the past — combine the two to pull an arbitrary
historical window (e.g. a prior quarter) for side-by-side comparison against
a current-window run.

Pass `--help` to either script for the full flag list.

## Outputs

All generated files are written to the **`reports/`** directory (created
automatically). Each filename gets a `_YYYYMMDD` run-date stamp so successive
runs accumulate instead of overwriting:

```
reports/
├── pd_service_metrics_20260729.csv    per-service incident rollup (Pareto %)
├── pd_daily_counts_20260729.csv       daily counts, dates × services
├── pd_service_report_20260729.html    ranking, trends, duplicate-noise analysis
├── pd_alert_counts_20260729.csv       per-service alert count, working/off-hours split
├── pd_alert_report_20260729.html      heatmap + trend + working/off-hours breakdown
└── …
```

- Change the output directory with `--outdir DIR`.
- Pass `--no-timestamp` for fixed filenames that overwrite prior runs.

**Report artifacts are never committed** — `reports/` (and any other output
directory, e.g. `quarterly_reports/` from `--outdir`) is git-ignored. Share the
HTML files by sending the file directly; they're fully self-contained.

## Notes

- System Python may emit a harmless LibreSSL/urllib3 warning on stderr — ignore it.
- Both scripts default to **high-urgency, war-room-routed alerts only**. Pass
  `--all-urgency` and/or `--all-alerts` to widen the scope.
