# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "requests>=2.31",
#     "pandas>=2.0",
#     "matplotlib>=3.7",
#     "jinja2>=3.0",
# ]
# ///
"""Pull alerts from PagerDuty, broken down by application service, and categorize
by working vs off-hours.

The application service name is resolved from the alert's custom details:
each Grafana/Datadog alert fires with a "- service = <name>" label inside the
alert body. That label is fetched via GET /incidents/{id}/alerts and used as
the grouping key. Falls back to the PD service name when absent.

For database alerts, the DB type (and resource name when available) is extracted
from the alert description and used as the service label instead.

Usage:
    uv run pd_alert_report.py --days 90
    uv run pd_alert_report.py --days 30 --tz America/New_York
    uv run pd_alert_report.py --list-services

Outputs:
    pd_alert_counts.csv    per-service alert count with working/off-hours split
    pd_alert_report.html   styled report with heatmap + trend chart
"""
from __future__ import annotations

import argparse
import base64
import io
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
import requests

BASE = "https://api.pagerduty.com"
ACCEPT = "application/vnd.pagerduty+json;version=2"
TIMEOUT = 30
HERE = Path(__file__).resolve().parent

# ── Database keyword detection ───────────────────────────────────────────────

# Ordered by specificity: DynamoDB before RDS before generic SQL, etc.
_DB_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bdynamodb\b", re.IGNORECASE), "DynamoDB"),
    (re.compile(r"\baurora\b", re.IGNORECASE), "Aurora"),
    (re.compile(r"\brds\b", re.IGNORECASE), "RDS"),
    (re.compile(r"\bpostgresql\b|\bpostgres\b", re.IGNORECASE), "PostgreSQL"),
    (re.compile(r"\bmysql\b", re.IGNORECASE), "MySQL"),
    (re.compile(r"\bmariadb\b", re.IGNORECASE), "MariaDB"),
    (re.compile(r"\belasticache\b", re.IGNORECASE), "ElastiCache"),
    (re.compile(r"\bredis\b", re.IGNORECASE), "Redis"),
    (re.compile(r"\belasticsearch\b", re.IGNORECASE), "Elasticsearch"),
    (re.compile(r"\bopensearch\b", re.IGNORECASE), "OpenSearch"),
    (re.compile(r"\bmongodb\b|\bmongo\b", re.IGNORECASE), "MongoDB"),
    (re.compile(r"\bcassandra\b", re.IGNORECASE), "Cassandra"),
    (re.compile(r"\bsql\s+server\b|\bmssql\b", re.IGNORECASE), "SQL Server"),
]

# Tried in order to extract a specific resource name (table, cluster, instance).
_RESOURCE_RES: list[re.Pattern] = [
    # "GSI on table in TableName"
    re.compile(r"\btable\s+in\s+[\"']?([\w][\w.\-]*)", re.IGNORECASE),
    # "on table TableName" / "for table TableName"
    re.compile(r"\b(?:on|for)\s+table\s+[\"']?([\w][\w.\-]*)", re.IGNORECASE),
    # "table 'TableName'" or "table TableName"
    re.compile(r"\btable\s+[\"']?([\w][\w.\-/]*)[\"']?", re.IGNORECASE),
    # "cluster ClusterName"
    re.compile(r"\bcluster\s+[\"']?([\w][\w.\-/]*)[\"']?", re.IGNORECASE),
    # "instance InstanceName"
    re.compile(r"\binstance\s+[\"']?([\w][\w.\-/]*)[\"']?", re.IGNORECASE),
    # "database DatabaseName"
    re.compile(r"\bdatabase\s+[\"']?([\w][\w.\-/]*)[\"']?", re.IGNORECASE),
    # any quoted identifier of reasonable length
    re.compile(r"[\"']([\w][\w.\-/]{2,})[\"']"),
]

_RESOURCE_SKIP = frozenset({
    "the", "max", "min", "aws", "alarm", "alert", "metric", "count",
    "rate", "high", "low", "error", "read", "write", "above", "below",
    "close", "quota", "limit", "usage", "capacity", "threshold", "gsi",
    "provisioned", "account", "table", "index", "region", "service",
})


def extract_db_service(title: str) -> str | None:
    """Return 'DBType/instance', 'DBType', or None if not a DB alert.

    Scans the alert title/description for known database keywords, then tries
    to extract a specific resource name (table, cluster, instance) from the text.
    """
    db_type: str | None = None
    for pat, canonical in _DB_PATTERNS:
        if pat.search(title):
            db_type = canonical
            break
    if db_type is None:
        return None
    for r in _RESOURCE_RES:
        m = r.search(title)
        if m:
            resource = m.group(1).strip("'\"/ ")
            if len(resource) >= 3 and resource.lower() not in _RESOURCE_SKIP:
                return f"{db_type}/{resource}"
    return db_type


# ── Working-hours classification ─────────────────────────────────────────────

def is_working_hours(ts: pd.Timestamp, tz: ZoneInfo, work_start: int, work_end: int) -> bool:
    """True if ts falls Mon–Fri within [work_start, work_end) in the given timezone."""
    local = ts.tz_convert(tz)
    if local.day_of_week >= 5:  # Saturday=5, Sunday=6
        return False
    return work_start <= local.hour < work_end


# ── War-room alert filter (mirrors pd_service_metrics.py) ───────────────────

_SLACK_SKIP_PATTERNS: list[str] = [
    "Synthetic Check Failure",
    "synthetic test fails",
    "Detection Management Heart Beat",
    "razor-job-service: No successful job executions in the past day",
    "razor-job-service: No successful CommonLocationUpdateJob job executions",
    "razor-job-service: No successful pwnedlistallorgs job executions",
    "razor-job-service: Collector emails are failing to be sent",
    "razor-job-service: Errors processing nexpose blobs",
    "razor-job-service: Errors running pwnedlist job",
    "razor-job-service: Job executions are taking longer than the configured alert threshold",
    "razor-job-service: Detected Event Sources Showing 0 EPM",
    "razor-job-service: Insight IDR Office365 certificate is about to expire",
    "Deprovisioning failure detected",
    "Provisioning failure detected",
    "S3 removal failure detected",
    "DynamoDB RCU is close to the max provisioned capacity",
    "DynamoDB WCU is close to the max provisioned capacity",
    "DynamoDB, AWS provisioned RCU account quota",
    "DynamoDB, AWS provisioned WCU account quota",
    "DynamoDB, AWS provisioned RCU table quota",
    "DynamoDB, AWS provisioned WCU table quota",
    "GSI on table in",
    "Application LB: high 5xx error rate for some services",
    "RAZOR : [High Urgency] High CnC error count reported from collector",
    "RAZOR collector-boss-service: [High Urgency] High C&C Failure count",
    "collector-boss-service: [HIGH URGENCY] ICS publishing failures",
    "endpoint-converter-app [HIGH URGENCY] LE transmission failures",
    "endpoint-converter-app [LOW URGENCY] LE transmission failures",
    "razor-odin-matching-app Zero odin content matches from Odin",
    "razor-kafka-payload-backup-app [HIGH URGENCY] Missing uploads",
    "RAZOR sqs-direct-publish Config Parse error",
    "SQS: Oldest message in l-e-s queue is above threshold",
    "Evidence description strings failing to generate",
    "Ingress dual read execution took more than 30 seconds",
    "RAZOR Payload receives for cloud-monitoring-service-metrics is below threshold",
    "RAZOR Customer DB NLB Proxy",
]
_SLACK_SKIP_LOWER: list[str] = [p.lower() for p in _SLACK_SKIP_PATTERNS]


def is_war_room_alert(description: str) -> bool:
    d = description.lower()
    return not any(p in d for p in _SLACK_SKIP_LOWER)


# ── PagerDuty API helpers ─────────────────────────────────────────────────────

def stamp_path(path: str, stamp: str) -> Path:
    """Insert a date stamp before the file extension.

    pd_alert_counts.csv + 20260729 -> pd_alert_counts_20260729.csv
    Preserves the parent directory and suffix.
    """
    p = Path(path)
    return p.with_name(f"{p.stem}_{stamp}{p.suffix}")


def load_dotenv() -> None:
    env_path = HERE / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        os.environ.setdefault(key.strip(), val.strip().strip("'\""))


def session() -> requests.Session:
    key = os.environ.get("PAGERDUTY_API_KEY")
    if not key:
        sys.exit(
            "PAGERDUTY_API_KEY is not set. Put it in .env next to this script:\n"
            "  PAGERDUTY_API_KEY=your_key_here"
        )
    s = requests.Session()
    s.headers.update({
        "Authorization": f"Token token={key}",
        "Accept": ACCEPT,
        "Content-Type": "application/json",
    })
    return s


def list_services(s: requests.Session) -> pd.DataFrame:
    rows, offset = [], 0
    while True:
        r = s.get(
            f"{BASE}/services",
            params={"limit": 100, "offset": offset, "total": "true"},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        body = r.json()
        for svc in body["services"]:
            rows.append({"id": svc["id"], "name": svc["name"], "status": svc.get("status")})
        if not body.get("more"):
            break
        offset += 100
    return pd.DataFrame(rows)


def fetch_raw_incidents(
    s: requests.Session, start: str, end: str, service_ids: list[str]
) -> pd.DataFrame:
    filters = {"created_at_start": start, "created_at_end": end}
    if service_ids:
        filters["service_ids"] = service_ids
    rows: list[dict] = []
    payload = {"filters": filters, "limit": 1000, "order": "asc", "order_by": "created_at"}
    while True:
        r = s.post(f"{BASE}/analytics/raw/incidents", json=payload, timeout=TIMEOUT)
        r.raise_for_status()
        body = r.json()
        rows.extend(body.get("data", []))
        if not body.get("more"):
            break
        payload["starting_after"] = body["last"]
    return pd.DataFrame(rows)


_SERVICE_LABEL_RE = re.compile(r"^\s*-\s*service\s*=\s*(.+)$", re.IGNORECASE | re.MULTILINE)


def _fetch_alert_service_label(s: requests.Session, incident_id: str) -> str | None:
    """Fetch the first alert for an incident and extract the '- service = ' label."""
    try:
        r = s.get(
            f"{BASE}/incidents/{incident_id}/alerts",
            params={"limit": 1},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        alerts = r.json().get("alerts", [])
        if not alerts:
            return None
        details = alerts[0].get("body", {}).get("details", {})
        text = details.get("firing", "") if isinstance(details, dict) else str(details)
        m = _SERVICE_LABEL_RE.search(text)
        return m.group(1).strip() if m else None
    except Exception:
        return None


def fetch_service_labels(
    s: requests.Session, incident_ids: list[str], workers: int = 20
) -> dict[str, str | None]:
    """Concurrently fetch the '- service = ' label for each incident ID."""
    result: dict[str, str | None] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_fetch_alert_service_label, s, iid): iid for iid in incident_ids}
        for fut in as_completed(futures):
            iid = futures[fut]
            result[iid] = fut.result()
    return result


def fetch_user_timezones(
    s: requests.Session, user_ids: list[str], workers: int = 20
) -> dict[str, ZoneInfo]:
    """Fetch IANA timezone for each user ID; returns only those that succeed."""
    def _get(uid: str) -> tuple[str, ZoneInfo | None]:
        try:
            r = s.get(f"{BASE}/users/{uid}", timeout=TIMEOUT)
            r.raise_for_status()
            tz_name = r.json().get("user", {}).get("time_zone")
            return uid, ZoneInfo(tz_name) if tz_name else None
        except Exception:
            return uid, None

    result: dict[str, ZoneInfo] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for uid, tz in pool.map(_get, user_ids):
            if tz is not None:
                result[uid] = tz
    return result


# ── Data enrichment ───────────────────────────────────────────────────────────

def enrich(
    raw: pd.DataFrame,
    s: requests.Session,
    fallback_tz: ZoneInfo,
    work_start: int,
    work_end: int,
) -> pd.DataFrame:
    """Add resolved_service, hour_type, local_hour, day_of_week columns.

    Service name resolution order:
      1. '- service = ' label from alert custom details
      2. DB type extracted from alert description
      3. PD service_name fallback

    Working-hours classification uses the first assignee's profile timezone.
    Falls back to fallback_tz when no assignee or timezone is available.
    """
    title_col = next((c for c in ("description", "title", "summary") if c in raw.columns), None)
    name_col = "service_name" if "service_name" in raw.columns else "service_id"

    r = raw.copy()
    r["ts"] = pd.to_datetime(r["created_at"], utc=True, errors="coerce")

    # ── Service labels ──
    id_col = "incident_id" if "incident_id" in r.columns else "id"
    incident_ids = r[id_col].dropna().unique().tolist()
    print(f"  Fetching alert details for {len(incident_ids)} incidents...", file=sys.stderr)
    labels = fetch_service_labels(s, incident_ids)

    def resolve_service(row) -> str:
        label = labels.get(str(row[id_col]))
        if label:
            return label
        if title_col:
            db = extract_db_service(str(row[title_col]))
            if db:
                return db
        return str(row[name_col])

    r["resolved_service"] = r.apply(resolve_service, axis=1)

    # ── User timezones ──
    all_user_ids: list[str] = []
    if "assigned_user_ids" in r.columns:
        for cell in r["assigned_user_ids"].dropna():
            if isinstance(cell, list) and cell:
                all_user_ids.append(str(cell[0]))
            elif isinstance(cell, str) and cell:
                all_user_ids.append(cell)
    unique_user_ids = list(dict.fromkeys(all_user_ids))  # deduplicated, order-preserving
    if unique_user_ids:
        print(f"  Fetching timezones for {len(unique_user_ids)} users...", file=sys.stderr)
    user_tz: dict[str, ZoneInfo] = fetch_user_timezones(s, unique_user_ids) if unique_user_ids else {}

    def first_assignee_tz(cell) -> ZoneInfo:
        if isinstance(cell, list) and cell:
            uid = str(cell[0])
        elif isinstance(cell, str) and cell:
            uid = cell
        else:
            return fallback_tz
        return user_tz.get(uid, fallback_tz)

    # ── Working-hours classification ──
    # Resolve each row's effective timezone once, then vectorize per unique tz.
    assignee_col = "assigned_user_ids" if "assigned_user_ids" in r.columns else None
    fallback_tz_name = str(fallback_tz)

    def first_assignee_tz_name(cell) -> str:
        tz_obj = first_assignee_tz(cell)
        return str(tz_obj)

    if assignee_col:
        r["_eff_tz"] = r[assignee_col].apply(first_assignee_tz_name)
    else:
        r["_eff_tz"] = fallback_tz_name

    r["hour_type"] = "off-hours"
    r["local_hour"] = pd.NA
    r["day_of_week"] = pd.NA

    valid = ~r["ts"].isna()
    for tz_name, group_idx in r[valid].groupby("_eff_tz").groups.items():
        tz_obj = ZoneInfo(tz_name)
        local = r.loc[group_idx, "ts"].dt.tz_convert(tz_obj)
        dow = local.dt.day_of_week
        hour = local.dt.hour
        is_working = (dow < 5) & (hour >= work_start) & (hour < work_end)
        r.loc[group_idx, "hour_type"] = is_working.map({True: "working", False: "off-hours"})
        r.loc[group_idx, "local_hour"] = hour.values
        r.loc[group_idx, "day_of_week"] = dow.values

    r = r.drop(columns=["_eff_tz"])
    return r


def service_summary(df: pd.DataFrame) -> pd.DataFrame:
    """Per-service alert count table with working/off-hours split, sorted by total."""
    pivot = df.groupby(["resolved_service", "hour_type"]).size().unstack(fill_value=0)
    if "working" not in pivot.columns:
        pivot["working"] = 0
    if "off-hours" not in pivot.columns:
        pivot["off-hours"] = 0
    pivot["total"] = pivot["working"] + pivot["off-hours"]
    pivot["off_hours_pct"] = (
        pivot["off-hours"] / pivot["total"].replace(0, float("nan")) * 100
    ).round(1)
    return (
        pivot.sort_values("total", ascending=False)
        .reset_index()
        .rename(columns={"resolved_service": "service"})
    )


# ── Chart helpers ─────────────────────────────────────────────────────────────

def heatmap_png(df: pd.DataFrame, tz_name: str) -> str:
    """Day-of-week × hour-of-day alert density heatmap as base64 PNG."""
    valid = df.dropna(subset=["day_of_week", "local_hour"])
    heat = (
        valid.groupby(["day_of_week", "local_hour"])
        .size()
        .unstack(fill_value=0)
        .reindex(index=range(7), columns=range(24), fill_value=0)
    )
    day_labels = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]

    fig, ax = plt.subplots(figsize=(12, 4), dpi=110)
    im = ax.imshow(heat.values, aspect="auto", cmap="YlOrRd", interpolation="nearest")
    ax.set_xticks(range(24))
    ax.set_xticklabels([f"{h:02d}:00" for h in range(24)], rotation=45, ha="right", fontsize=7)
    ax.set_yticks(range(7))
    ax.set_yticklabels(day_labels)
    ax.set_xlabel(f"Hour of day ({tz_name})")
    ax.set_ylabel("Day of week")
    ax.set_title("Alert density — day of week × hour of day")
    plt.colorbar(im, ax=ax, label="alert count")
    fig.tight_layout()

    buf = io.BytesIO()
    fig.savefig(buf, format="png")
    plt.close(fig)
    return base64.b64encode(buf.getvalue()).decode("ascii")


def weekly_trend_png(df: pd.DataFrame) -> str:
    """Weekly working vs off-hours alert count as base64 PNG."""
    ts_series = df["ts"].dt.tz_convert("UTC")
    df2 = pd.DataFrame({"ts_utc": ts_series, "hour_type": df["hour_type"].values})
    df2 = df2.dropna(subset=["ts_utc"]).set_index("ts_utc")
    weekly = df2.groupby([pd.Grouper(freq="W"), "hour_type"]).size().unstack(fill_value=0)

    fig, ax = plt.subplots(figsize=(9, 4), dpi=110)
    if "working" in weekly.columns:
        ax.plot(weekly.index, weekly["working"], marker="o", markersize=4,
                label="Working hours (M–F)", color="#27ae60")
    if "off-hours" in weekly.columns:
        ax.plot(weekly.index, weekly["off-hours"], marker="o", markersize=4,
                label="Off-hours", color="#c0392b")
    ax.set_ylabel("alerts / week")
    ax.set_xlabel("week")
    ax.legend()
    ax.grid(True, alpha=0.3)
    fig.autofmt_xdate()
    fig.tight_layout()

    buf = io.BytesIO()
    fig.savefig(buf, format="png")
    plt.close(fig)
    return base64.b64encode(buf.getvalue()).decode("ascii")


def top_off_hours_alerts_png(df: pd.DataFrame, top_n: int = 15) -> str:
    """Horizontal bar chart: top N services by off-hours alert count, stacked working/off."""
    svc_counts = (
        df.groupby(["resolved_service", "hour_type"])
        .size()
        .unstack(fill_value=0)
        .assign(total=lambda x: x.get("working", 0) + x.get("off-hours", 0))
        .sort_values("total", ascending=False)
        .head(top_n)
    )
    svc_counts = svc_counts[::-1]  # flip for horizontal bar (largest at top)
    labels = svc_counts.index.tolist()
    working = svc_counts.get("working", pd.Series(0, index=svc_counts.index)).values
    offhours = svc_counts.get("off-hours", pd.Series(0, index=svc_counts.index)).values

    fig, ax = plt.subplots(figsize=(9, max(4, top_n * 0.35)), dpi=110)
    y = range(len(labels))
    ax.barh(y, working, label="Working hours", color="#27ae60", alpha=0.85)
    ax.barh(y, offhours, left=working, label="Off-hours", color="#c0392b", alpha=0.85)
    ax.set_yticks(list(y))
    ax.set_yticklabels(labels, fontsize=8)
    ax.set_xlabel("alert count")
    ax.set_title(f"Top {top_n} services — working vs off-hours alerts")
    ax.legend(loc="lower right")
    ax.grid(True, axis="x", alpha=0.3)
    fig.tight_layout()

    buf = io.BytesIO()
    fig.savefig(buf, format="png")
    plt.close(fig)
    return base64.b64encode(buf.getvalue()).decode("ascii")


# ── HTML report ───────────────────────────────────────────────────────────────

def _color_off_pct(v: object) -> str:
    if pd.isna(v):  # type: ignore[arg-type]
        return "color:#999"
    if v >= 70:  # type: ignore[operator]
        return "color:#c0392b;font-weight:bold"
    if v >= 50:  # type: ignore[operator]
        return "color:#e67e22"
    return "color:#27ae60" if v < 30 else "color:#999"  # type: ignore[operator]


def _render_period(summary: pd.DataFrame, df: pd.DataFrame, tz_name: str) -> str:
    """Render the HTML content for one time-window panel (no outer wrapper)."""
    parts: list[str] = []

    n_off = int(summary["off-hours"].sum())
    n_total = int(summary["total"].sum())
    off_pct = n_off / n_total * 100 if n_total else 0
    parts.append(
        f"<p class='meta'>{n_total} alerts &nbsp;·&nbsp; "
        f"{n_off} off-hours ({off_pct:.1f}%) &nbsp;·&nbsp; "
        f"{len(summary)} services</p>"
    )

    # Service summary table
    parts.append("<h2>Alert count by service — working vs off-hours</h2>")
    parts.append(
        "<p class='meta'>"
        "Application service name from the <code>- service = </code> alert label. "
        "Database alerts without that label use the DB type extracted from the description. "
        "Off-hours = outside the working hours window shown above. "
        "Red ≥70% off-hours, orange ≥50%, green &lt;30%."
        "</p>"
    )
    col_order = ["service", "total", "working", "off-hours", "off_hours_pct"]
    disp = summary[[c for c in col_order if c in summary.columns]]
    styler = (
        disp.style.hide(axis="index")
        .bar(subset=["total"], color="#5b9bd5")
        .bar(subset=["off-hours"], color="#c0392b")
        .bar(subset=["working"], color="#27ae60")
        .map(_color_off_pct, subset=["off_hours_pct"])
        .format(
            {"working": "{:.0f}", "off-hours": "{:.0f}", "total": "{:.0f}", "off_hours_pct": "{:.1f}%"},
            na_rep="—",
        )
    )
    parts.append(styler.to_html())

    # Stacked bar chart
    parts.append("<h2>Top services — working vs off-hours (stacked)</h2>")
    try:
        b64 = top_off_hours_alerts_png(df)
        parts.append(f"<img alt='top services stacked bar' src='data:image/png;base64,{b64}'/>")
    except Exception as exc:
        parts.append(f"<p class='meta'>Chart unavailable: {exc}</p>")

    # Heatmap
    parts.append("<h2>Alert density heatmap — day of week × hour of day</h2>")
    parts.append(f"<p class='meta'>All times in assignee's local timezone; falls back to {tz_name}. Darker = more alerts.</p>")
    try:
        b64 = heatmap_png(df, tz_name)
        parts.append(f"<img alt='alert density heatmap' src='data:image/png;base64,{b64}'/>")
    except Exception as exc:
        parts.append(f"<p class='meta'>Heatmap unavailable: {exc}</p>")

    # Weekly trend
    parts.append("<h2>Weekly alert trend — working hours vs off-hours</h2>")
    try:
        b64 = weekly_trend_png(df)
        parts.append(f"<img alt='weekly trend' src='data:image/png;base64,{b64}'/>")
    except Exception as exc:
        parts.append(f"<p class='meta'>Trend chart unavailable: {exc}</p>")

    return "\n".join(parts)


def write_html(
    periods: list[tuple[str, pd.DataFrame, pd.DataFrame]],
    meta: dict,
    out_path: Path,
) -> None:
    """Render a self-contained HTML report with a time-window dropdown.

    periods: list of (label, summary_df, enriched_df), one per time window.
    The first entry is shown by default.
    """
    tz_name = meta["tz"]

    opts_html = "".join(
        f"<option value='panel-{i}'{' selected' if i == 0 else ''}>{label}</option>"
        for i, (label, _, _) in enumerate(periods)
    )
    select_js = (
        "var sel=this.value;"
        "document.querySelectorAll('.period-panel').forEach(function(el){"
        "el.style.display=el.id===sel?'':'none'"
        "});"
    )

    parts = [
        "<html><head><meta charset='utf-8'><title>PagerDuty alert report</title>",
        "<style>",
        "body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:2rem;color:#1a1a1a;}",
        "h1{font-size:1.4rem;} h2{font-size:1.1rem;margin-top:2rem;color:#333;}",
        "table{border-collapse:collapse;font-size:0.9rem;} .meta{color:#666;font-size:0.85rem;}",
        "td,th{padding:4px 10px;text-align:right;} th{background:#f4f4f4;}",
        "td:first-child,th:first-child{text-align:left;}",
        ".window-select{font-size:1rem;padding:4px 8px;margin-left:0.75rem;}",
        "</style></head><body>",
        "<h1>PagerDuty alert report — working hours vs off-hours</h1>",
        f"<p class='meta'>Data pulled: {meta['start']} → {meta['end']} "
        f"&nbsp;·&nbsp; generated {meta['generated']} "
        f"&nbsp;·&nbsp; fallback timezone: <strong>{tz_name}</strong>"
        f"&nbsp;·&nbsp; working hours: <strong>Mon–Fri {meta['work_start']:02d}:00–{meta['work_end']:02d}:00</strong>"
        f"{' &nbsp;·&nbsp; high-urgency only' if not meta.get('all_urgency') else ''}"
        f"{' &nbsp;·&nbsp; war-room alerts only' if not meta.get('all_alerts') else ''}</p>",
        "<div style='margin:1rem 0'>",
        "<label style='font-size:1rem;font-weight:600'>Time window:</label>",
        f"<select class='window-select' onchange=\"{select_js}\">{opts_html}</select>",
        "</div>",
    ]

    for i, (label, summary, df) in enumerate(periods):
        display = "" if i == 0 else "display:none"
        parts.append(f"<div id='panel-{i}' class='period-panel' style='{display}'>")
        parts.append(_render_period(summary, df, tz_name))
        parts.append("</div>")

    parts.append("</body></html>")
    out_path.write_text("\n".join(parts))


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--days", type=int, default=91,
                    help="max lookback window in days (default 91; covers all four presets)")
    ap.add_argument(
        "--service",
        dest="services",
        action="append",
        default=[],
        help="service ID(s); comma-separated and/or repeatable. "
        "Overrides PAGERDUTY_SERVICE_IDS; omit both for all visible services",
    )
    ap.add_argument("--list-services", action="store_true", help="print service IDs/names and exit")
    ap.add_argument(
        "--tz",
        default="UTC",
        metavar="TIMEZONE",
        help="IANA timezone for working-hours classification (default UTC, e.g. America/New_York)",
    )
    ap.add_argument("--work-start", type=int, default=9, metavar="HOUR",
                    help="working day start hour, 0-23 (default 9)")
    ap.add_argument("--work-end", type=int, default=17, metavar="HOUR",
                    help="working day end hour exclusive, 0-23 (default 17)")
    ap.add_argument("--all-urgency", action="store_true",
                    help="include low-urgency incidents (default: high only)")
    ap.add_argument("--all-alerts", action="store_true",
                    help="include alerts not routed to razor-war-room Slack (default: war-room only)")
    ap.add_argument("--csv", default="pd_alert_counts.csv", help="output CSV path")
    ap.add_argument("--html", default="pd_alert_report.html", help="output HTML path")
    ap.add_argument(
        "--outdir",
        default="reports",
        help="directory for generated outputs, created if missing (default: reports/). "
        "Relative --csv/--html paths are resolved under it; absolute paths ignore it",
    )
    ap.add_argument(
        "--no-timestamp",
        action="store_true",
        help="write fixed output filenames instead of appending a YYYYMMDD stamp (overwrites prior runs)",
    )
    args = ap.parse_args()

    load_dotenv()

    try:
        tz = ZoneInfo(args.tz)
    except Exception:
        sys.exit(f"Unknown timezone: {args.tz!r}. Use an IANA name like 'America/New_York'.")

    raw_services = args.services or (
        [os.environ["PAGERDUTY_SERVICE_IDS"]] if os.environ.get("PAGERDUTY_SERVICE_IDS") else []
    )
    service_ids = [
        sid.strip() for chunk in raw_services for sid in chunk.split(",") if sid.strip()
    ]

    s = session()

    if args.list_services:
        print(list_services(s).to_string(index=False))
        return

    # Always fetch the full lookback window; windows are sliced in memory.
    WINDOWS: list[tuple[str, int]] = [("1 week", 7), ("2 weeks", 14), ("1 month", 30), ("3 months", 91)]
    fetch_days = max(days for _, days in WINDOWS if days <= args.days) if args.days < 91 else 91

    end = datetime.now(timezone.utc).replace(microsecond=0)
    start = end - timedelta(days=fetch_days)
    start_iso, end_iso = start.isoformat(), end.isoformat()
    print(f"Fetching {fetch_days}d window: {start_iso} -> {end_iso}", file=sys.stderr)

    raw = fetch_raw_incidents(s, start_iso, end_iso, service_ids)
    if raw.empty:
        print("No data returned for that window/filter.", file=sys.stderr)
        return

    if not args.all_urgency and "urgency" in raw.columns:
        n_before = len(raw)
        raw = raw[raw["urgency"] == "high"].reset_index(drop=True)
        n_dropped = n_before - len(raw)
        if n_dropped:
            print(
                f"  Dropped {n_dropped} low-urgency incidents "
                f"(pass --all-urgency to include)",
                file=sys.stderr,
            )

    title_col = next((c for c in ("description", "title", "summary") if c in raw.columns), None)
    if not args.all_alerts and title_col:
        n_before = len(raw)
        raw = raw[raw[title_col].fillna("").apply(is_war_room_alert)].reset_index(drop=True)
        n_dropped = n_before - len(raw)
        if n_dropped:
            print(
                f"  Dropped {n_dropped} non-war-room alerts "
                f"(pass --all-alerts to include)",
                file=sys.stderr,
            )

    print(f"  Processing {len(raw)} alerts...", file=sys.stderr)
    df_full = enrich(raw, s, tz, args.work_start, args.work_end)

    # Slice each time window from the already-enriched full dataframe.
    periods: list[tuple[str, pd.DataFrame, pd.DataFrame]] = []
    for label, days in WINDOWS:
        if days > fetch_days:
            continue
        cutoff = end - timedelta(days=days)
        df_w = df_full[df_full["ts"] >= cutoff].reset_index(drop=True)
        summary_w = service_summary(df_w)
        n_off = int(summary_w["off-hours"].sum())
        n_total = int(summary_w["total"].sum())
        off_pct = n_off / n_total * 100 if n_total else 0
        print(
            f"  [{label}] {n_total} alerts · {n_off} off-hours ({off_pct:.1f}%) "
            f"· {len(summary_w)} services",
            file=sys.stderr,
        )
        periods.append((label, summary_w, df_w))

    # Resolve output paths: place under --outdir (created if missing), then
    # append a run-date stamp unless --no-timestamp. An absolute --csv/--html
    # override ignores --outdir (Path's / operator drops the left side).
    stamp = end.strftime("%Y%m%d")
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    csv_p, html_p = outdir / args.csv, outdir / args.html
    csv_path = csv_p if args.no_timestamp else stamp_path(str(csv_p), stamp)
    html_path = html_p if args.no_timestamp else stamp_path(str(html_p), stamp)

    # Write CSV for the longest window (first period that equals fetch_days).
    summary_full = periods[-1][1] if periods else pd.DataFrame()
    summary_full.to_csv(csv_path, index=False)

    meta = {
        "start": start_iso,
        "end": end_iso,
        "generated": end.isoformat(),
        "tz": args.tz,
        "work_start": args.work_start,
        "work_end": args.work_end,
        "all_urgency": args.all_urgency,
        "all_alerts": args.all_alerts,
    }
    write_html(periods, meta, html_path)

    print(summary_full.to_string(index=False))
    print(f"\nWrote: {csv_path}", file=sys.stderr)
    print(f"Wrote: {html_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
