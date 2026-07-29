# pd-metrics — PagerDuty service incident analysis

Pulls incident metrics from the PagerDuty Analytics API and produces CSV + a
self-contained styled HTML report. Two scripts share the same `.env`, API
helpers, and war-room alert filter:

- `pd_service_metrics.py` — incident counts aggregated **by service**, with
  duplicate-alert (regional-noise) analysis. Documented below through the
  Gotchas section.
- `pd_alert_report.py` — alerts aggregated **by application service** (resolved
  from the alert body's `- service =` label), split into working vs off-hours.
  See the Alert report section.

## Running

Single-file script with [PEP 723](https://peps.python.org/pep-0723/) inline
dependency metadata — **run it with `uv`, never a manual venv**:

```bash
uv run pd_service_metrics.py --list-services      # discover service IDs/names
uv run pd_service_metrics.py --days 90            # uses PAGERDUTY_SERVICE_IDS
uv run pd_service_metrics.py --days 90 --service P1,P2   # override services
```

`uv run` reads the `# /// script` block at the top of the file and installs
deps (requests, pandas, jinja2, matplotlib) into its own ephemeral, cached env.
Do **not** create a `.venv/` — it's unnecessary and git-ignored.

To add a dependency, edit the `# dependencies = [...]` block at the top of
`pd_service_metrics.py`, not a requirements file.

## Configuration — `.env`

Config lives in `.env` (git-ignored), auto-loaded by the script. Env vars
already set in the shell take precedence over `.env`.

- `PAGERDUTY_API_KEY` — read-enabled API key. **Required.** Secret; never commit
  or paste it into a chat/session.
- `PAGERDUTY_SERVICE_IDS` — comma-separated default service IDs. Optional.

Service selection precedence: `--service` flag → `PAGERDUTY_SERVICE_IDS` → all
visible services.

## Outputs

- `pd_service_metrics.csv` — per-service incident-count rollup (with Pareto cumulative %)
- `pd_daily_counts.csv` — daily counts, dates × services (full resolution)
- `pd_service_report.html` — ranking, WoW/MoM deltas + sparklines, embedded
  weekly trend chart (base64 PNG), weekly table

All outputs are written to the **`reports/`** directory (created automatically;
override with `--outdir DIR`). Relative `--csv`/`--html`/etc. paths are resolved
under `--outdir`; an absolute override path bypasses it.

Output filenames get a `_YYYYMMDD` run-date stamp appended before the extension
(e.g. `reports/pd_service_metrics_20260729.csv`) so successive runs accumulate
rather than overwrite. The stamp is the UTC run date, shared across all files
from one run. Pass `--no-timestamp` to revert to fixed names (overwrites prior runs).

The entire `reports/` directory is git-ignored — report artifacts are never
committed. Human-facing setup/onboarding lives in `README.md`; this file is the
agent-facing reference.

## Gotchas

- **WoW/MoM deltas, sparklines, and the trend chart require the raw-incidents
  pull** (`/analytics/raw/incidents`). `--no-timeseries` skips it → ranking table
  only, no trend section.
- Trend windows are **trailing, anchored on the last data date** (last 7d vs
  prior 7d; last 30d vs prior 30d) — not calendar weeks/months — so a partial
  current period doesn't skew the delta.
- PagerDuty Analytics data lags real-time by up to ~24h and must be enabled on
  the account; empty results despite known incidents usually means one of these.
- System Python emits a harmless LibreSSL/urllib3 warning on stderr — ignore it.
- Raw-incident fields used: `created_at`, `service_name`, `service_id`
  (confirmed against live API 2026-07-02).

## Alert report — `pd_alert_report.py`

Companion script that groups **alerts** by application service and classifies
each as working-hours vs off-hours. Same `.env` and `uv run` conventions.

```bash
uv run pd_alert_report.py --days 90                      # PAGERDUTY_SERVICE_IDS
uv run pd_alert_report.py --days 30 --tz America/New_York
uv run pd_alert_report.py --list-services
```

### Service-name resolution

The application-service label is resolved per alert, in order:

1. The `- service = <name>` label inside the alert body — fetched via
   `GET /incidents/{id}/alerts` (concurrent, ~20 workers). **This is the
   authoritative grouping key; always prefer it over the PD `service_name`.**
2. For database alerts, the DB type (and resource name, when parseable) from
   the alert description — e.g. `DynamoDB/MyTable`.
3. PagerDuty `service_name` as a last-resort fallback.

### Working-hours classification

- Each alert is bucketed working vs off-hours using the **first assignee's
  PagerDuty profile timezone** (fetched via `GET /users/{id}`), falling back to
  `--tz` (default UTC) when there's no assignee or timezone.
- Working window is `Mon–Fri [--work-start, --work-end)`, default `09:00–17:00`.

### Outputs

- `pd_alert_counts.csv` — per-service alert count with working/off-hours split
  and off-hours %. Reflects the **longest** time window fetched.
- `pd_alert_report.html` — time-window dropdown (1w / 2w / 1mo / 3mo, sliced
  in-memory from one fetch), per-service table, stacked working/off-hours bar,
  day-of-week × hour density heatmap, and weekly trend chart.

Written to `reports/` with the same `--outdir`, `_YYYYMMDD` stamping, and
`--no-timestamp` behavior as the service metrics script.

### Alert-report gotchas

- **One fetch, many windows:** it pulls the full `--days` window once (capped at
  91d to cover all four dropdown presets) and slices each window in memory, so
  bumping `--days` past 91 doesn't add presets.
- Per-incident alert-detail and per-user timezone lookups are **N extra API
  calls each** (concurrent). Large windows over many services can be slow and
  rate-limit-sensitive.
- Shares the `_SLACK_SKIP_PATTERNS` war-room filter and `--all-alerts` /
  `--all-urgency` flags with the service-metrics script; keep the two pattern
  lists in sync when editing.
