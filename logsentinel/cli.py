"""Command-line entry point:  python -m logsentinel path/to/auth.log --year 2026 --out report/"""
from __future__ import annotations

import argparse
from datetime import datetime

from .model import score
from .parser import parse_file
from .report import write_report
from .rules import RuleConfig, run_all


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Detect suspicious SSH login activity in Linux auth logs.")
    p.add_argument("logfile", help="path to an auth.log file")
    p.add_argument("--year", type=int, default=datetime.now().year, help="year of the log (syslog omits it)")
    p.add_argument("--out", default="report", help="output directory")
    p.add_argument("--bf-threshold", type=int, default=10, help="failures that count as brute force")
    p.add_argument("--bf-window", default="5min", help="window for brute-force counting, e.g. 5min")
    args = p.parse_args(argv)

    events = parse_file(args.logfile, args.year)
    if events.empty:
        print("No sshd login events found.")
        return 1
    alerts = run_all(events, RuleConfig(brute_force_threshold=args.bf_threshold,
                                        brute_force_window=args.bf_window))
    scored = score(events)
    path = write_report(events, alerts, scored, args.out)

    print(f"Parsed {len(events)} events, raised {len(alerts)} alerts, "
          f"{int(scored['is_anomaly'].sum())} anomalous IP-hour buckets.")
    if not alerts.empty:
        print(alerts.groupby(["severity", "rule"]).size().to_string())
    print(f"Report written to {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
