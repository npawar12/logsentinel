"""Rule-based detections. Each rule returns a DataFrame of alerts with the same columns,
so they can be concatenated into one alert table."""
from __future__ import annotations

from dataclasses import dataclass

import pandas as pd

ALERT_COLUMNS = ["timestamp", "rule", "severity", "user", "ip", "detail"]


@dataclass
class RuleConfig:
    brute_force_threshold: int = 10        # failures from one IP...
    brute_force_window: str = "5min"       # ...within this window
    off_hours_start: int = 0               # successful logins in [start, end) are off-hours
    off_hours_end: int = 6
    baseline_fraction: float = 0.5         # first X of the timeline defines "known" IPs per user


def _empty() -> pd.DataFrame:
    return pd.DataFrame(columns=ALERT_COLUMNS)


def detect_brute_force(df: pd.DataFrame, cfg: RuleConfig) -> pd.DataFrame:
    """Flag IPs with >= threshold failed logins inside a sliding time window.

    Uses a time-based rolling count per IP, then keeps one alert per IP (the moment the
    threshold was first crossed) so a long attack doesn't produce thousands of alerts.
    """
    fails = df[df["event"].isin(["failure", "invalid_user"])]
    if fails.empty:
        return _empty()
    alerts = []
    for ip, g in fails.groupby("ip"):
        counts = g.set_index("timestamp").assign(n=1)["n"].rolling(cfg.brute_force_window).sum()
        hit = counts[counts >= cfg.brute_force_threshold]
        if not hit.empty:
            first = hit.index[0]
            users = g["user"].nunique()
            alerts.append({
                "timestamp": first,
                "rule": "brute_force",
                "severity": "high",
                "user": "*" if users > 1 else g["user"].iloc[0],
                "ip": ip,
                "detail": f"{len(g)} failed logins total, {users} distinct usernames tried",
            })
    return pd.DataFrame(alerts, columns=ALERT_COLUMNS)


def detect_success_after_failures(df: pd.DataFrame, cfg: RuleConfig) -> pd.DataFrame:
    """A successful login from an IP that already crossed the brute-force threshold is the
    scariest pattern: the attacker may have guessed a password."""
    bf = detect_brute_force(df, cfg)
    if bf.empty:
        return _empty()
    bad_ips = dict(zip(bf["ip"], bf["timestamp"]))
    s = df[(df["event"] == "success") & (df["ip"].isin(bad_ips))]
    s = s[s.apply(lambda r: r["timestamp"] >= bad_ips[r["ip"]], axis=1)] if not s.empty else s
    return pd.DataFrame([{
        "timestamp": r.timestamp, "rule": "success_after_brute_force", "severity": "critical",
        "user": r.user, "ip": r.ip, "detail": "successful login from an IP that was brute-forcing",
    } for r in s.itertuples()], columns=ALERT_COLUMNS)


def detect_off_hours(df: pd.DataFrame, cfg: RuleConfig) -> pd.DataFrame:
    s = df[df["event"] == "success"]
    hours = s["timestamp"].dt.hour
    off = s[(hours >= cfg.off_hours_start) & (hours < cfg.off_hours_end)]
    return pd.DataFrame([{
        "timestamp": r.timestamp, "rule": "off_hours_login", "severity": "medium",
        "user": r.user, "ip": r.ip, "detail": f"successful login at {r.timestamp:%H:%M}",
    } for r in off.itertuples()], columns=ALERT_COLUMNS)


def detect_new_ip(df: pd.DataFrame, cfg: RuleConfig) -> pd.DataFrame:
    """Learn each user's known IPs from the baseline period, then flag successful logins
    from IPs that user has never used before."""
    s = df[df["event"] == "success"]
    if s.empty:
        return _empty()
    t0, t1 = df["timestamp"].min(), df["timestamp"].max()
    cutoff = t0 + (t1 - t0) * cfg.baseline_fraction
    baseline = s[s["timestamp"] < cutoff]
    known = baseline.groupby("user")["ip"].apply(set).to_dict()
    later = s[s["timestamp"] >= cutoff]
    rows, seen = [], set()
    for r in later.itertuples():
        # Users with no baseline history are skipped: we can't call an IP "unusual" for them.
        if r.user in known and r.ip not in known[r.user] and (r.user, r.ip) not in seen:
            seen.add((r.user, r.ip))
            rows.append({
                "timestamp": r.timestamp, "rule": "new_ip_for_user", "severity": "medium",
                "user": r.user, "ip": r.ip, "detail": "first successful login from this IP for this user",
            })
    return pd.DataFrame(rows, columns=ALERT_COLUMNS)


def run_all(df: pd.DataFrame, cfg: RuleConfig | None = None) -> pd.DataFrame:
    cfg = cfg or RuleConfig()
    parts = [f(df, cfg) for f in (detect_brute_force, detect_success_after_failures,
                                  detect_off_hours, detect_new_ip)]
    parts = [p for p in parts if not p.empty]
    if not parts:
        return _empty()
    return pd.concat(parts, ignore_index=True).sort_values("timestamp").reset_index(drop=True)
