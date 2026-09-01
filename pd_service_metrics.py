# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "requests>=2.31",
#     "pandas>=2.0",
#     "jinja2>=3.0",
#     "matplotlib>=3.7",
# ]
# ///
"""Pull incident metrics from the PagerDuty Analytics API, aggregated by service,
and produce incident-count summaries as CSV + a styled HTML report.

The API key is read from PAGERDUTY_API_KEY. If it is not already in the
environment, a .env file next to this script is loaded automatically, so the
secret lives in .env (git-ignore it) and never has to be pasted anywhere.

Services can also be preset via PAGERDUTY_SERVICE_IDS (comma-separated) in
.env; the --service flag overrides it when given.

Usage:
    uv run pd_service_metrics.py --list-services            # discover IDs/names
    uv run pd_service_metrics.py --days 90                  # all visible services
    uv run pd_service_metrics.py --days 90 --service PXXXXXX --service PYYYYYY
    uv run pd_service_metrics.py --days 90 --no-timeseries  # skip per-incident pull

Outputs (paths configurable):
    pd_service_metrics.csv   per-service rollup
    pd_service_report.html   styled report with rankings + daily trend
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import requests

BASE = "https://api.pagerduty.com"
ACCEPT = "application/vnd.pagerduty+json;version=2"
TIMEOUT = 30
HERE = Path(__file__).resolve().parent

# Alerts that are routed to PagerDuty only — not to the razor-war-room Slack channel.
# Derived from tf-razor-observability-monitors: any monitor whose contact is
# "pagerduty-*" (without "webhook and pagerduty-*") never hits the slackbot webhook.
# These are excluded by default; pass --all-alerts to include them.
# Note: Detection Management Heart Beat is not in that repo (manually created monitor)
# but is also PD-only in practice.
_SLACK_SKIP_PATTERNS: list[str] = [
    # Synthetic checks
    "Synthetic Check Failure",
    "synthetic test fails",
    # Detection Management
    "Detection Management Heart Beat",
    # Job service - no-slack variants
    "razor-job-service: No successful job executions in the past day",
    "razor-job-service: No successful CommonLocationUpdateJob job executions",
    "razor-job-service: No successful pwnedlistallorgs job executions",
    "razor-job-service: Collector emails are failing to be sent",
    "razor-job-service: Errors processing nexpose blobs",
    "razor-job-service: Errors running pwnedlist job",
    "razor-job-service: Job executions are taking longer than the configured alert threshold",
    "razor-job-service: Detected Event Sources Showing 0 EPM",
    "razor-job-service: Insight IDR Office365 certificate is about to expire",
    # Provisioning / deprovisioning
    "Deprovisioning failure detected",
    "Provisioning failure detected",
    "S3 removal failure detected",
    # DynamoDB quota (account/table level, not per-service)
    "DynamoDB RCU is close to the max provisioned capacity",
    "DynamoDB WCU is close to the max provisioned capacity",
    "DynamoDB, AWS provisioned RCU account quota",
    "DynamoDB, AWS provisioned WCU account quota",
    "DynamoDB, AWS provisioned RCU table quota",
    "DynamoDB, AWS provisioned WCU table quota",
    "GSI on table in",
    # ELB - business-hours variant (5xx for some services, not the main war-room one)
    "Application LB: high 5xx error rate for some services",
    # Collector boss
    "RAZOR : [High Urgency] High CnC error count reported from collector",
    "RAZOR collector-boss-service: [High Urgency] High C&C Failure count",
    "collector-boss-service: [HIGH URGENCY] ICS publishing failures",
    # endpoint-converter low-urgency slack-skip variant
    "endpoint-converter-app [HIGH URGENCY] LE transmission failures",
    "endpoint-converter-app [LOW URGENCY] LE transmission failures",
    # Misc
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
    """Return False if the alert is known to not route to the war-room Slack channel."""
    d = description.lower()
    return not any(p in d for p in _SLACK_SKIP_LOWER)



def stamp_path(path: str, stamp: str) -> Path:
    """Insert a date stamp before the file extension.

    pd_service_metrics.csv + 20260729 -> pd_service_metrics_20260729.csv
    Preserves the parent directory and (multi-part) suffix.
    """
    p = Path(path)
    return p.with_name(f"{p.stem}_{stamp}{p.suffix}")


def load_dotenv() -> None:
    """Populate os.environ from a sibling .env (only for keys not already set)."""
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
    s.headers.update(
        {
            "Authorization": f"Token token={key}",
            "Accept": ACCEPT,
            "Content-Type": "application/json",
        }
    )
    return s


def list_services(s: requests.Session) -> pd.DataFrame:
    """Page through GET /services so you can find the IDs you care about."""
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


def fetch_service_metrics(
    s: requests.Session, start: str, end: str, service_ids: list[str]
) -> pd.DataFrame:
    """POST /analytics/metrics/incidents/services — server-side aggregation by service.

    Paginates via an opaque `starting_after` cursor when the result set is large.
    """
    filters = {"created_at_start": start, "created_at_end": end}
    if service_ids:
        filters["service_ids"] = service_ids

    rows: list[dict] = []
    payload = {"filters": filters, "time_zone": "Etc/UTC"}
    while True:
        r = s.post(
            f"{BASE}/analytics/metrics/incidents/services",
            json=payload,
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        body = r.json()
        rows.extend(body.get("data", []))
        cursor = body.get("pagination", {}).get("cursor")
        if not cursor:
            break
        payload["starting_after"] = cursor
    return pd.DataFrame(rows)


def fetch_raw_incidents(
    s: requests.Session, start: str, end: str, service_ids: list[str]
) -> pd.DataFrame:
    """POST /analytics/raw/incidents — one row per incident, for time-series work.

    Cursor-paginated with a 1000-row page cap.
    """
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


# --------------------------------------------------------------------------- #
# Summaries (incident-count focused)
# --------------------------------------------------------------------------- #
def rollup_table(df: pd.DataFrame) -> pd.DataFrame:
    """Trim the service-metrics response to an incident-count ranking."""
    keep = [c for c in ["service_name", "service_id", "total_incident_count"] if c in df.columns]
    out = df[keep].copy() if keep else df.copy()
    if "total_incident_count" in out.columns:
        out = out.sort_values("total_incident_count", ascending=False).reset_index(drop=True)
        total = out["total_incident_count"].sum()
        out["pct_of_total"] = (out["total_incident_count"] / total * 100).round(1) if total else 0
        out["cumulative_pct"] = out["pct_of_total"].cumsum().round(1)
    return out


def daily_pivot(raw: pd.DataFrame) -> pd.DataFrame:
    """Daily incident counts per service (dates x services) from raw incidents."""
    if raw.empty or "created_at" not in raw.columns:
        return pd.DataFrame()
    r = raw.copy()
    r["date"] = pd.to_datetime(r["created_at"], utc=True, errors="coerce").dt.date
    name_col = "service_name" if "service_name" in r.columns else "service_id"
    pivot = (
        r.groupby(["date", name_col]).size().unstack(fill_value=0).sort_index()
    )
    pivot["ALL_SERVICES"] = pivot.sum(axis=1)
    return pivot


# Matches AWS-style region tokens: us-east-1, eu-west-2, ap-southeast-1, etc.
_REGION_RE = re.compile(
    r"\b(?:us|eu|ap|sa|ca|af|me|il)-(?:east|west|north|south|central|northeast|northwest|southeast|southwest)-\d+\b",
    re.IGNORECASE,
)


def normalize_title(title: str) -> str:
    """Strip AWS region codes and collapse extra whitespace."""
    return _REGION_RE.sub("", title).strip()


def episode_pivot(raw: pd.DataFrame, gap_minutes: int = 30) -> pd.DataFrame:
    """Daily episode counts per service.

    An 'episode' is a firing of a normalized alert title that is either the
    first firing of that title for the service, or is more than gap_minutes
    after the previous firing of the same title in the same service.  Firings
    within gap_minutes of each other are the same episode (regional burst).
    """
    if raw.empty or "created_at" not in raw.columns:
        return pd.DataFrame()
    title_col = next((c for c in ("title", "description", "summary") if c in raw.columns), None)
    if title_col is None:
        return pd.DataFrame()
    r = raw.copy()
    r["ts"] = pd.to_datetime(r["created_at"], utc=True, errors="coerce")
    r["date"] = r["ts"].dt.date
    name_col = "service_name" if "service_name" in r.columns else "service_id"
    r["normalized_title"] = r[title_col].fillna("").apply(normalize_title)

    r = r.sort_values([name_col, "normalized_title", "ts"])
    gap_thresh = pd.Timedelta(minutes=gap_minutes)
    # Within each (service, normalized_title) group, a new episode starts when the
    # gap from the previous firing exceeds the threshold (or it's the first firing).
    r["gap"] = r.groupby([name_col, "normalized_title"])["ts"].diff()
    r["new_episode"] = r["gap"].isna() | (r["gap"] > gap_thresh)

    pivot = (
        r.groupby(["date", name_col])["new_episode"]
        .sum()
        .astype(int)
        .unstack(fill_value=0)
        .sort_index()
    )
    # ALL_SERVICES: unique (normalized_title, episode_start) pairs across all services per day.
    # Simplest defensible approach: sum per-service episodes (each service is independent).
    pivot["ALL_SERVICES"] = pivot.sum(axis=1)
    return pivot


def duplicate_alert_table(raw: pd.DataFrame, gap_minutes: int = 30) -> pd.DataFrame:
    """Per-alert summary of regional duplicate noise over the full window.

    Returns one row per (service, normalized_title) that fired more than once,
    sorted by duplicate count descending.  Columns:
        service         service name (or ID)
        alert           normalized alert title (region codes stripped)
        total_fires     total raw incident count
        episodes        distinct firing episodes (>gap_minutes apart)
        duplicates      total_fires - episodes
        dup_pct         duplicates / total_fires * 100
        example_title   one real title showing the original region-tagged text
    """
    if raw.empty or "created_at" not in raw.columns:
        return pd.DataFrame()
    title_col = next((c for c in ("title", "description", "summary") if c in raw.columns), None)
    if title_col is None:
        return pd.DataFrame()
    r = raw.copy()
    r["ts"] = pd.to_datetime(r["created_at"], utc=True, errors="coerce")
    name_col = "service_name" if "service_name" in r.columns else "service_id"
    r["normalized_title"] = r[title_col].fillna("").apply(normalize_title)

    r = r.sort_values([name_col, "normalized_title", "ts"])
    gap_thresh = pd.Timedelta(minutes=gap_minutes)
    r["gap"] = r.groupby([name_col, "normalized_title"])["ts"].diff()
    r["new_episode"] = r["gap"].isna() | (r["gap"] > gap_thresh)

    grp = r.groupby([name_col, "normalized_title"])
    agg = pd.DataFrame({
        "total_fires": grp.size(),
        "episodes": grp["new_episode"].sum().astype(int),
        "example_title": grp[title_col].first(),
    }).reset_index()
    agg = agg.rename(columns={name_col: "service", "normalized_title": "alert"})
    agg["duplicates"] = agg["total_fires"] - agg["episodes"]
    agg["dup_pct"] = (agg["duplicates"] / agg["total_fires"] * 100).round(1)

    # Only keep alerts that actually have duplicates
    agg = agg[agg["duplicates"] > 0].sort_values("duplicates", ascending=False).reset_index(drop=True)
    return agg[["service", "alert", "total_fires", "episodes", "duplicates", "dup_pct", "example_title"]]


def duplicate_pivot(daily: pd.DataFrame, episodes: pd.DataFrame) -> pd.DataFrame:
    """Daily duplicate-alert counts per service (raw - episodes, floored at 0)."""
    if daily.empty or episodes.empty:
        return pd.DataFrame()
    shared_cols = daily.columns.intersection(episodes.columns)
    shared_idx = daily.index.intersection(episodes.index)
    return daily.loc[shared_idx, shared_cols].subtract(
        episodes.loc[shared_idx, shared_cols]
    ).clip(lower=0)


def period_deltas(daily: pd.DataFrame) -> pd.DataFrame:
    """D/D and W/W deltas per service.

    Today vs yesterday (d/d) and trailing 7 days vs prior 7 days (w/w),
    both anchored on the last date in the data.
    """
    if daily.empty:
        return pd.DataFrame()
    d = daily.copy()
    d.index = pd.to_datetime(d.index)
    d = d.sort_index()
    last = d.index.max()

    def window_sum(days_end_offset: int, length: int) -> pd.Series:
        end = last - pd.Timedelta(days=days_end_offset)
        start = end - pd.Timedelta(days=length - 1)
        mask = (d.index >= start) & (d.index <= end)
        return d.loc[mask].sum()

    today = window_sum(0, 1)
    yesterday = window_sum(1, 1)
    this_wk = window_sum(0, 7)
    last_wk = window_sum(7, 7)

    def pct(cur: pd.Series, prev: pd.Series) -> pd.Series:
        out = (cur - prev) / prev.replace(0, float("nan")) * 100
        out = out.where(~((prev == 0) & (cur == 0)), 0.0)
        out = out.where(~((prev == 0) & (cur > 0)), 100.0)
        return out.round(1)

    df = pd.DataFrame(
        {
            "today": today,
            "yesterday": yesterday,
            "dod_pct": pct(today, yesterday),
            "this_7d": this_wk,
            "prev_7d": last_wk,
            "wow_pct": pct(this_wk, last_wk),
        }
    )
    df.index.name = "service"
    return df


def sparkline_svg(values: list, width: int = 120, height: int = 24) -> str:
    """Inline SVG polyline sparkline — no external image files needed."""
    if not len(values):
        return ""
    vmin, vmax = min(values), max(values)
    span = (vmax - vmin) or 1
    n = len(values)
    step = width / max(n - 1, 1)
    pts = [
        f"{i * step:.1f},{height - 2 - (v - vmin) / span * (height - 4):.1f}"
        for i, v in enumerate(values)
    ]
    return (
        f"<svg width='{width}' height='{height}' "
        f"style='vertical-align:middle'>"
        f"<polyline fill='none' stroke='#5b9bd5' stroke-width='1.5' "
        f"points='{' '.join(pts)}'/></svg>"
    )


def trend_chart_b64(weekly: pd.DataFrame) -> str:
    """Render a weekly per-service line chart to a base64-encoded PNG."""
    import base64
    import io

    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(9, 4), dpi=110)
    for col in [c for c in weekly.columns if c != "ALL_SERVICES"]:
        ax.plot(weekly.index, weekly[col], marker="o", markersize=3, label=col)
    if "ALL_SERVICES" in weekly.columns:
        ax.plot(
            weekly.index,
            weekly["ALL_SERVICES"],
            color="#333",
            linewidth=2,
            linestyle="--",
            label="ALL",
        )
    ax.set_ylabel("incidents / week")
    ax.set_xlabel("week")
    ax.legend(fontsize=7, ncol=2)
    ax.grid(True, alpha=0.3)
    fig.autofmt_xdate()
    fig.tight_layout()

    buf = io.BytesIO()
    fig.savefig(buf, format="png")
    plt.close(fig)
    return base64.b64encode(buf.getvalue()).decode("ascii")



def write_html(
    rollup: pd.DataFrame,
    daily: pd.DataFrame,
    meta: dict,
    out_path: Path,
    unique: pd.DataFrame | None = None,
    dup: pd.DataFrame | None = None,
    dup_alerts: pd.DataFrame | None = None,
    dup_alerts_by_period: dict | None = None,
) -> None:
    """Render a self-contained styled HTML report (bars via pandas Styler)."""
    parts = [
        "<html><head><meta charset='utf-8'><title>PagerDuty service report</title>",
        "<style>",
        "body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:2rem;color:#1a1a1a;}",
        "h1{font-size:1.4rem;} h2{font-size:1.1rem;margin-top:2rem;color:#333;}",
        "table{border-collapse:collapse;font-size:0.9rem;} .meta{color:#666;font-size:0.85rem;}",
        "td,th{padding:4px 10px;text-align:right;} th{background:#f4f4f4;}",
        "td:first-child,th:first-child{text-align:left;}",
        "</style></head><body>",
        "<h1>PagerDuty incident report — by service</h1>",
        f"<p class='meta'>Window: {meta['start']} → {meta['end']} "
        f"({meta['days']}d) · generated {meta['generated']} · "
        f"{meta['n_services']} services · {meta['n_incidents']} incidents"
        f"{' · high-urgency only' if not meta.get('all_urgency') else ''}"
        f"{' · war-room alerts only' if not meta.get('all_alerts') else ''}</p>",
        "<h2>Incident count by service</h2>",
    ]

    if "total_incident_count" in rollup.columns and not rollup.empty:
        styler = (
            rollup.style.hide(axis="index")
            .bar(subset=["total_incident_count"], color="#5b9bd5")
            .format({"pct_of_total": "{:.1f}%", "cumulative_pct": "{:.1f}%"})
        )
        parts.append(styler.to_html())
    else:
        parts.append(rollup.to_html(index=False))

    if not daily.empty:
        daily_dt = daily.copy()
        daily_dt.index = pd.to_datetime(daily_dt.index)
        weekly = daily_dt.resample("W").sum()

        def color_pct(v):
            if pd.isna(v):
                return "color:#999"
            return "color:#c0392b" if v > 0 else ("color:#27ae60" if v < 0 else "color:#999")

        # --- Incident d/d and w/w trend table ---
        deltas = period_deltas(daily_dt)
        if not deltas.empty:
            spark = {
                svc: sparkline_svg(list(weekly[svc].values))
                for svc in weekly.columns
                if svc in deltas.index
            }
            deltas = deltas.copy()
            deltas.insert(0, "trend", [spark.get(svc, "") for svc in deltas.index])
            deltas = deltas.sort_values("this_7d", ascending=False)

            parts.append("<h2>Incident trend — day-over-day &amp; week-over-week</h2>")
            dstyler = (
                deltas.style.map(color_pct, subset=["dod_pct", "wow_pct"])
                .format(
                    {
                        "today": "{:.0f}", "yesterday": "{:.0f}", "dod_pct": "{:+.1f}%",
                        "this_7d": "{:.0f}", "prev_7d": "{:.0f}", "wow_pct": "{:+.1f}%",
                    },
                    na_rep="—",
                )
                .format({"trend": lambda s: s}, escape=None, subset=["trend"])
            )
            parts.append(dstyler.to_html())
            parts.append(
                "<p class='meta'>Trailing windows anchored on the last data date. "
                "Red = increasing, green = decreasing.</p>"
            )

        # --- Duplicate noise section ---
        if unique is not None and not unique.empty:
            unique_dt = unique.copy()
            unique_dt.index = pd.to_datetime(unique_dt.index)
            weekly_ep = unique_dt.resample("W").sum()

            # Weekly dup % per service: (raw - episodes) / raw * 100
            shared = weekly.columns.intersection(weekly_ep.columns)
            weekly_dup_pct = (
                (weekly[shared] - weekly_ep[shared]).clip(lower=0)
                .div(weekly[shared].replace(0, float("nan"))) * 100
            ).round(1)

            # --- Dup % trend chart ---
            parts.append("<h2>Duplicate alert noise — weekly % of alerts that are regional duplicates</h2>")
            parts.append(
                "<p class='meta'>An alert is a <em>duplicate</em> if it fires within 30 minutes of "
                "another alert with the same title (AWS region codes stripped) in the same service. "
                "Higher % = more regional fan-out noise.</p>"
            )
            try:
                import base64 as _b64, io as _io, matplotlib as _mpl
                _mpl.use("Agg")
                import matplotlib.pyplot as _plt
                fig, ax = _plt.subplots(figsize=(9, 4), dpi=110)
                for col in [c for c in weekly_dup_pct.columns if c != "ALL_SERVICES"]:
                    ax.plot(weekly_dup_pct.index, weekly_dup_pct[col],
                            marker="o", markersize=3, label=col)
                if "ALL_SERVICES" in weekly_dup_pct.columns:
                    ax.plot(weekly_dup_pct.index, weekly_dup_pct["ALL_SERVICES"],
                            color="#c0392b", linewidth=2.5, linestyle="--", label="ALL")
                ax.set_ylabel("duplicate %")
                ax.set_xlabel("week")
                ax.set_ylim(0, 100)
                ax.yaxis.set_major_formatter(_plt.FuncFormatter(lambda v, _: f"{v:.0f}%"))
                ax.legend(fontsize=7, ncol=2)
                ax.grid(True, alpha=0.3)
                fig.autofmt_xdate()
                fig.tight_layout()
                buf = _io.BytesIO()
                fig.savefig(buf, format="png")
                _plt.close(fig)
                b64 = _b64.b64encode(buf.getvalue()).decode("ascii")
                parts.append(f"<img alt='duplicate % trend' src='data:image/png;base64,{b64}'/>")
            except Exception as exc:
                parts.append(f"<p class='meta'>Chart unavailable: {exc}</p>")

            # Per-service dup noise table: raw / episodes / dup count / dup% for today, yesterday, this_7d, prev_7d
            ep_deltas = period_deltas(unique_dt)
            raw_deltas = deltas.drop(columns=["trend"], errors="ignore")
            if not ep_deltas.empty and not raw_deltas.empty:
                compare = pd.DataFrame(index=ep_deltas.index)
                for period in [("today", "yesterday", "dod_pct"), ("this_7d", "prev_7d", "wow_pct")]:
                    cur, prev, pct_col = period
                    r_cur = raw_deltas[cur]
                    e_cur = ep_deltas[cur]
                    d_cur = (r_cur - e_cur).clip(lower=0)
                    compare[f"raw_{cur}"] = r_cur
                    compare[f"ep_{cur}"] = e_cur
                    compare[f"dup_{cur}"] = d_cur
                    compare[f"dup_pct_{cur}"] = (
                        d_cur.div(r_cur.replace(0, float("nan"))) * 100
                    ).round(1)
                    prev_dup_pct = (
                        (raw_deltas[prev] - ep_deltas[prev]).clip(lower=0)
                        .div(raw_deltas[prev].replace(0, float("nan"))) * 100
                    ).round(1)
                    compare[f"dup_pct_delta_{cur}"] = (
                        compare[f"dup_pct_{cur}"] - prev_dup_pct
                    ).astype(float).round(1)

                svc_rows = [i for i in compare.index if i != "ALL_SERVICES"]
                all_row = [i for i in compare.index if i == "ALL_SERVICES"]
                compare = pd.concat([
                    compare.loc[all_row],
                    compare.loc[svc_rows].sort_values("dup_pct_this_7d", ascending=False),
                ])

                def color_dup_pct(v):
                    if pd.isna(v):
                        return "color:#999"
                    if v >= 50:
                        return "color:#c0392b;font-weight:bold"
                    if v >= 25:
                        return "color:#e67e22"
                    return "color:#27ae60" if v < 10 else "color:#999"

                dup_pct_cols = [c for c in compare.columns if c.startswith("dup_pct_") and "delta" not in c]
                delta_cols = [c for c in compare.columns if "delta" in c]
                cnt_cols = [c for c in compare.columns if c not in dup_pct_cols and c not in delta_cols]
                fmt = {c: "{:.0f}" for c in cnt_cols}
                fmt.update({c: "{:.1f}%" for c in dup_pct_cols})
                fmt.update({c: "{:+.1f}pp" for c in delta_cols})

                parts.append("<h2>Duplicate noise by service — today vs yesterday &amp; this week vs last</h2>")
                cstyler = (
                    compare.style
                    .map(color_dup_pct, subset=dup_pct_cols)
                    .map(color_pct, subset=delta_cols)
                    .format(fmt, na_rep="—")
                )
                parts.append(cstyler.to_html())
                parts.append(
                    "<p class='meta'>"
                    "<strong>ep</strong> = distinct alert episodes (firings &gt;30 min apart). "
                    "<strong>dup_%</strong> = (raw − ep) / raw. "
                    "<strong>delta</strong> = change in dup % vs prior period (percentage points). "
                    "Red ≥50%, orange ≥25%, green &lt;10%. Sorted by 7d dup %, worst first."
                    "</p>"
                )

            # Per-alert duplicate table (multi-period drop-down)
            periods_data = dup_alerts_by_period or {}
            # Fall back to the full-window table if no period slices were provided
            if not periods_data and dup_alerts is not None and not dup_alerts.empty:
                periods_data = {"full window": dup_alerts}
            if periods_data:
                parts.append("<h2>Duplicate alerts — by alert name</h2>")
                parts.append(
                    "<p class='meta'>One row per alert title (region codes stripped) that fired "
                    "more than once within a regional burst window (&gt;30 min apart = new episode). "
                    "Sorted by duplicate count, worst first. "
                    "<em>example_title</em> shows the original title from one real incident.</p>"
                )
                period_keys = list(periods_data.keys())
                # Build the <select> control
                opts_html = "".join(
                    f"<option value='dup-period-{i}'{' selected' if i==0 else ''}>{k}</option>"
                    for i, k in enumerate(period_keys)
                )
                parts.append(
                    "<div style='margin:0.5rem 0'>"
                    "<label style='font-size:0.9rem;font-weight:600'>Time period: </label>"
                    f"<select id='dup-period-sel' onchange=\""
                    "var sel=this.value;"
                    "document.querySelectorAll('.dup-period-panel').forEach(function(el){"
                    "el.style.display=el.id===sel?'':'none'"
                    "});\""
                    f">{opts_html}</select></div>"
                )
                for i, (period_key, df_p) in enumerate(periods_data.items()):
                    display = "" if i == 0 else "display:none"
                    parts.append(f"<div id='dup-period-{i}' class='dup-period-panel' style='{display}'>")
                    if df_p is not None and not df_p.empty:
                        at_styler = (
                            df_p.style.hide(axis="index")
                            .bar(subset=["duplicates"], color="#c0392b")
                            .bar(subset=["total_fires"], color="#5b9bd5")
                            .format({"dup_pct": "{:.1f}%", "total_fires": "{:.0f}",
                                     "episodes": "{:.0f}", "duplicates": "{:.0f}"})
                        )
                        parts.append(at_styler.to_html())
                    else:
                        parts.append("<p class='meta'>No duplicate alerts in this period.</p>")
                    parts.append("</div>")

            # Weekly dup % heat map
            parts.append("<h2>Weekly duplicate % heat map (per service)</h2>")
            wk_dup_styler = (
                weekly_dup_pct.style
                .background_gradient(cmap="RdYlGn_r", vmin=0, vmax=100)
                .format("{:.1f}%", na_rep="—")
            )
            parts.append(wk_dup_styler.to_html())

            # Weekly episode trend chart
            parts.append("<h2>Weekly episode trend (unique problems)</h2>")
            try:
                b64 = trend_chart_b64(weekly_ep)
                parts.append(f"<img alt='weekly episode trend' src='data:image/png;base64,{b64}'/>")
            except Exception as exc:
                parts.append(f"<p class='meta'>Chart unavailable: {exc}</p>")

        # --- Embedded weekly raw incident trend chart ---
        parts.append("<h2>Weekly incident trend (raw)</h2>")
        try:
            b64 = trend_chart_b64(weekly)
            parts.append(f"<img alt='weekly trend' src='data:image/png;base64,{b64}'/>")
        except Exception as exc:
            parts.append(f"<p class='meta'>Chart unavailable: {exc}</p>")

        # --- Weekly table ---
        parts.append("<h2>Weekly incident count (per service)</h2>")
        wk_styler = weekly.style.bar(subset=["ALL_SERVICES"], color="#ed7d31").format("{:.0f}")
        parts.append(wk_styler.to_html())
        parts.append(
            "<p class='meta'>Daily-resolution data is in the CSV; "
            "weekly shown here for readability.</p>"
        )

    parts.append("</body></html>")
    out_path.write_text("\n".join(parts))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--days", type=int, default=90, help="lookback window (default 90)")
    ap.add_argument(
        "--service",
        dest="services",
        action="append",
        default=[],
        help="service ID(s) to include; comma-separated and/or repeatable. "
        "Overrides PAGERDUTY_SERVICE_IDS; omit both for all visible services",
    )
    ap.add_argument("--list-services", action="store_true", help="print service IDs/names and exit")
    ap.add_argument("--no-timeseries", action="store_true", help="skip the per-incident raw pull")
    ap.add_argument("--csv", default="pd_service_metrics.csv", help="rollup CSV output path")
    ap.add_argument("--daily-csv", default="pd_daily_counts.csv", help="daily-counts CSV output path")
    ap.add_argument("--episodes-csv", default="pd_episodes.csv", help="episode counts CSV output path")
    ap.add_argument("--dup-csv", default="pd_duplicate_counts.csv", help="duplicate alert counts CSV output path")
    ap.add_argument("--dup-alerts-csv", default="pd_duplicate_alerts.csv", help="per-alert duplicate summary CSV output path")
    ap.add_argument("--all-urgency", action="store_true", help="include low-urgency incidents (default: high only)")
    ap.add_argument("--all-alerts", action="store_true", help="include alerts not routed to razor-war-room Slack (default: war-room only)")
    ap.add_argument("--html", default="pd_service_report.html", help="HTML report output path")
    ap.add_argument(
        "--outdir",
        default="reports",
        help="directory for generated outputs, created if missing (default: reports/). "
        "Relative --csv/--html/etc. paths are resolved under it; absolute paths ignore it",
    )
    ap.add_argument(
        "--no-timestamp",
        action="store_true",
        help="write fixed output filenames instead of appending a YYYYMMDD stamp (overwrites prior runs)",
    )
    args = ap.parse_args()

    load_dotenv()

    # Service selection: --service (comma-separated and/or repeatable) wins;
    # otherwise fall back to PAGERDUTY_SERVICE_IDS (comma-separated) from env/.env.
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

    end = datetime.now(timezone.utc).replace(microsecond=0)
    start = end - timedelta(days=args.days)
    start_iso, end_iso = start.isoformat(), end.isoformat()
    print(f"Window: {start_iso} -> {end_iso}", file=sys.stderr)

    metrics = fetch_service_metrics(s, start_iso, end_iso, service_ids)
    if metrics.empty:
        print("No data returned for that window/filter.", file=sys.stderr)
        return
    rollup = rollup_table(metrics)

    daily = pd.DataFrame()
    unique = pd.DataFrame()
    dup = pd.DataFrame()
    dup_alerts = pd.DataFrame()
    dup_alerts_by_period: dict[str, pd.DataFrame] = {}
    n_incidents = int(rollup.get("total_incident_count", pd.Series(dtype=int)).sum())
    if not args.no_timeseries:
        print("Fetching raw incidents for time-series...", file=sys.stderr)
        raw = fetch_raw_incidents(s, start_iso, end_iso, service_ids)
        if not args.all_urgency and "urgency" in raw.columns:
            n_before = len(raw)
            raw = raw[raw["urgency"] == "high"].reset_index(drop=True)
            n_dropped = n_before - len(raw)
            if n_dropped:
                print(f"  Dropped {n_dropped} low-urgency incidents (pass --all-urgency to include)", file=sys.stderr)
        title_col = next((c for c in ("description", "title", "summary") if c in raw.columns), None)
        if not args.all_alerts and title_col:
            n_before = len(raw)
            raw = raw[raw[title_col].fillna("").apply(is_war_room_alert)].reset_index(drop=True)
            n_dropped = n_before - len(raw)
            if n_dropped:
                print(f"  Dropped {n_dropped} non-war-room alerts (pass --all-alerts to include)", file=sys.stderr)
        daily = daily_pivot(raw)
        unique = episode_pivot(raw)
        dup = duplicate_pivot(daily, unique)
        dup_alerts = duplicate_alert_table(raw)

        # Pre-compute per-alert dup tables for each selectable time window.
        if not raw.empty and "created_at" in raw.columns:
            raw_ts = pd.to_datetime(raw["created_at"], utc=True, errors="coerce")
            last_ts = raw_ts.max()
            for label, days_back in [("7d", 7), ("2 weeks", 14), ("1 month", 30), ("1 quarter", 91)]:
                cutoff = last_ts - pd.Timedelta(days=days_back)
                subset = raw[raw_ts >= cutoff].reset_index(drop=True)
                dup_alerts_by_period[label] = duplicate_alert_table(subset)

        if not raw.empty:
            n_incidents = len(raw)
            if "ALL_SERVICES" in daily.columns and "ALL_SERVICES" in unique.columns:
                shared_idx = daily.index.intersection(unique.index)
                n_ep = int(unique.loc[shared_idx, "ALL_SERVICES"].sum())
                n_dup = int(dup.loc[shared_idx, "ALL_SERVICES"].sum()) if "ALL_SERVICES" in dup.columns else 0
                dup_pct = n_dup / n_incidents * 100 if n_incidents else 0
                print(
                    f"  {n_incidents} raw incidents → {n_ep} episodes, "
                    f"{n_dup} duplicates ({dup_pct:.1f}% noise)",
                    file=sys.stderr,
                )

    # Resolve output paths: place under --outdir (created if missing), then
    # append a run-date stamp unless --no-timestamp. An absolute --csv/--html
    # override ignores --outdir (Path's / operator drops the left side).
    stamp = end.strftime("%Y%m%d")
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    def out(path: str) -> Path:
        p = outdir / path
        return p if args.no_timestamp else stamp_path(str(p), stamp)

    csv_path = out(args.csv)
    daily_csv_path = out(args.daily_csv)
    episodes_csv_path = out(args.episodes_csv)
    dup_csv_path = out(args.dup_csv)
    dup_alerts_csv_path = out(args.dup_alerts_csv)
    html_path = out(args.html)

    rollup.to_csv(csv_path, index=False)
    if not daily.empty:
        daily.to_csv(daily_csv_path)
    if not unique.empty:
        unique.to_csv(episodes_csv_path)
    if not dup.empty:
        dup.to_csv(dup_csv_path)
    if not dup_alerts.empty:
        dup_alerts.to_csv(dup_alerts_csv_path, index=False)

    meta = {
        "start": start_iso,
        "end": end_iso,
        "days": args.days,
        "generated": end.isoformat(),
        "n_services": len(rollup),
        "n_incidents": n_incidents,
        "all_urgency": args.all_urgency,
        "all_alerts": args.all_alerts,
    }
    write_html(
        rollup, daily, meta, html_path,
        unique=unique if not unique.empty else None,
        dup=dup if not dup.empty else None,
        dup_alerts=dup_alerts if not dup_alerts.empty else None,
        dup_alerts_by_period=dup_alerts_by_period if dup_alerts_by_period else None,
    )

    print(rollup.to_string(index=False))
    print(f"\nWrote: {csv_path}", file=sys.stderr)
    if not daily.empty:
        print(f"Wrote: {daily_csv_path}", file=sys.stderr)
    if not unique.empty:
        print(f"Wrote: {episodes_csv_path}", file=sys.stderr)
    if not dup.empty:
        print(f"Wrote: {dup_csv_path}", file=sys.stderr)
    if not dup_alerts.empty:
        print(f"Wrote: {dup_alerts_csv_path}", file=sys.stderr)
    print(f"Wrote: {html_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
