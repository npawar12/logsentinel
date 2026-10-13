"""Write a Markdown summary, CSV exports, and PNG charts for an analyst."""
from __future__ import annotations

from pathlib import Path

import matplotlib
matplotlib.use("Agg")  # no display needed
import matplotlib.pyplot as plt
import pandas as pd


def _chart_activity(events: pd.DataFrame, out: Path) -> None:
    d = events.assign(kind=events["event"].map(
        {"success": "Successful", "failure": "Failed", "invalid_user": "Failed"}))
    per_hour = d.groupby([d["timestamp"].dt.floor("h"), "kind"]).size().unstack(fill_value=0)
    fig, ax = plt.subplots(figsize=(10, 4))
    for col, color in (("Failed", "#c0392b"), ("Successful", "#2c7fb8")):
        if col in per_hour:
            ax.plot(per_hour.index, per_hour[col], label=col, color=color, linewidth=1.5)
    ax.set_title("Login attempts per hour")
    ax.set_ylabel("Attempts")
    ax.legend(frameon=False)
    ax.spines[["top", "right"]].set_visible(False)
    fig.autofmt_xdate()
    fig.tight_layout()
    fig.savefig(out, dpi=130)
    plt.close(fig)


def _chart_top_ips(events: pd.DataFrame, out: Path, n: int = 10) -> None:
    fails = events[events["event"] != "success"]["ip"].value_counts().head(n)[::-1]
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.barh(fails.index, fails.values, color="#c0392b")
    ax.set_title(f"Top {len(fails)} source IPs by failed logins")
    ax.set_xlabel("Failed attempts")
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(out, dpi=130)
    plt.close(fig)


def _chart_scores(scored: pd.DataFrame, out: Path) -> None:
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.hist(scored.loc[~scored["is_anomaly"], "anomaly_score"], bins=40, color="#9ecae1", label="Normal")
    ax.hist(scored.loc[scored["is_anomaly"], "anomaly_score"], bins=10, color="#c0392b", label="Anomalous")
    ax.set_title("Isolation Forest anomaly scores (IP-hour buckets)")
    ax.set_xlabel("Anomaly score (higher = more unusual)")
    ax.set_ylabel("Buckets")
    ax.legend(frameon=False)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(out, dpi=130)
    plt.close(fig)


def write_report(events: pd.DataFrame, alerts: pd.DataFrame, scored: pd.DataFrame, out_dir: str | Path) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    alerts.to_csv(out / "alerts.csv", index=False)
    scored.to_csv(out / "anomaly_scores.csv", index=False)
    _chart_activity(events, out / "activity.png")
    _chart_top_ips(events, out / "top_ips.png")
    _chart_scores(scored, out / "anomaly_scores.png")

    by_rule = alerts["rule"].value_counts() if not alerts.empty else pd.Series(dtype=int)
    top_anoms = scored[scored["is_anomaly"]].head(10)
    lines = [
        "# LogSentinel report",
        "",
        f"- Events parsed: **{len(events)}** "
        f"({(events['event'] == 'success').sum()} successful, {(events['event'] != 'success').sum()} failed)",
        f"- Time range: {events['timestamp'].min()} to {events['timestamp'].max()}",
        f"- Distinct source IPs: {events['ip'].nunique()}, distinct users: {events['user'].nunique()}",
        f"- Rule alerts: **{len(alerts)}**",
        "",
        "## Alerts by rule",
        "",
        "| Rule | Count |",
        "|---|---|",
        *[f"| {rule} | {n} |" for rule, n in by_rule.items()],
        "",
        "## Most anomalous IP-hour buckets (Isolation Forest)",
        "",
        "| IP | Hour | Failed | Successful | Users tried | Score |",
        "|---|---|---|---|---|---|",
        *[f"| {r.ip} | {r.window:%Y-%m-%d %H:00} | {r.n_fail} | {r.n_success} | {r.n_users} | {r.anomaly_score:.3f} |"
          for r in top_anoms.itertuples()],
        "",
        "## Alerts",
        "",
        "| Time | Severity | Rule | User | IP | Detail |",
        "|---|---|---|---|---|---|",
        *[f"| {r.timestamp} | {r.severity} | {r.rule} | {r.user} | {r.ip} | {r.detail} |"
          for r in alerts.itertuples()],
        "",
        "![Activity](activity.png)",
        "![Top IPs](top_ips.png)",
        "![Scores](anomaly_scores.png)",
        "",
    ]
    path = out / "report.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    return path
