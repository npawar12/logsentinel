"""Parse Linux auth.log (sshd) lines into a structured DataFrame.

A typical line looks like:
    Oct 12 03:14:07 web01 sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 52311 ssh2

Syslog timestamps don't include a year, so the caller supplies one.
"""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

import pandas as pd

# One regex per event type we care about. Named groups become columns.
_PREFIX = r"^(?P<ts>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[\d+\]: "
PATTERNS = {
    "success": re.compile(
        _PREFIX + r"Accepted (?P<method>password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+) port \d+"
    ),
    "failure": re.compile(
        _PREFIX + r"Failed (?P<method>password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port \d+"
    ),
    "invalid_user": re.compile(
        _PREFIX + r"Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)"
    ),
}

COLUMNS = ["timestamp", "host", "event", "user", "ip", "method"]


def parse_line(line: str, year: int) -> dict | None:
    """Return a dict for a recognized sshd auth event, or None if the line isn't one."""
    for event, pattern in PATTERNS.items():
        m = pattern.match(line)
        if m:
            g = m.groupdict()
            # " ".join(split()) collapses the double space syslog uses for 1-digit days.
            ts = datetime.strptime(f"{year} {' '.join(g['ts'].split())}", "%Y %b %d %H:%M:%S")
            return {
                "timestamp": ts,
                "host": g["host"],
                "event": event,
                "user": g["user"],
                "ip": g["ip"],
                "method": g.get("method"),
            }
    return None


def parse_lines(lines, year: int) -> pd.DataFrame:
    rows = [r for r in (parse_line(l.rstrip("\n"), year) for l in lines) if r]
    df = pd.DataFrame(rows, columns=COLUMNS)
    if not df.empty:
        df = df.sort_values("timestamp").reset_index(drop=True)
    return df


def parse_file(path: str | Path, year: int) -> pd.DataFrame:
    with open(path, encoding="utf-8", errors="replace") as f:
        return parse_lines(f, year)
