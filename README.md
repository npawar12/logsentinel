# LogSentinel

Detects suspicious SSH login activity in Linux authentication logs (`/var/log/auth.log`) by combining **rule-based detections** with an **unsupervised Isolation Forest model**, then produces an analyst report with charts.

## What it detects

| Detection | How | Severity |
|---|---|---|
| Brute force | ≥ 10 failed logins from one IP inside a sliding 5-minute window (configurable) | high |
| Success after brute force | A successful login from an IP that already tripped the brute-force rule (likely compromised account) | critical |
| Off-hours login | Successful login between 00:00 and 06:00 | medium |
| New IP for user | A user's first successful login from an IP not seen in the baseline period | medium |
| Statistical anomaly | Isolation Forest over per-(IP, hour) features: failures, successes, distinct usernames, failure ratio, hour of day | ranked score |

Rules catch attacks we already know the shape of. The model catches activity that is unusual compared with everything else, without anyone having to write a rule for it — on the sample data it independently ranks both attackers at the top and also surfaces the 3 a.m. login.

## Quick start

```bash
pip install -r requirements.txt
python scripts/generate_sample_log.py          # writes sample_data/auth.log
python -m logsentinel sample_data/auth.log --year 2026 --out sample_report
```

Output:

```
Parsed 445 events, raised 6 alerts, 5 anomalous IP-hour buckets.
severity  rule
critical  success_after_brute_force    1
high      brute_force                  2
medium    new_ip_for_user              2
          off_hours_login              1
```

`sample_report/` contains `report.md`, `alerts.csv`, `anomaly_scores.csv`, and three charts.

Options: `--bf-threshold`, `--bf-window` (e.g. `2min`), `--out`, `--year`.

## Project layout

```
logsentinel/
  parser.py   regex parsing of sshd events -> pandas DataFrame
  rules.py    the four rule-based detections
  model.py    feature engineering + Isolation Forest scoring
  report.py   Markdown report, CSV exports, matplotlib charts
  cli.py      command-line entry point
scripts/generate_sample_log.py   synthetic log with four injected attacks
tests/                           pytest suite (parser, every rule, model ranking)
```

## Design notes

- **Sliding window, not fixed buckets, for brute force.** A fixed 5-minute bucket can split an attack in half across a boundary and miss it; a rolling time window per IP can't.
- **One alert per attacking IP.** A 180-attempt attack produces one brute-force alert, not 171, so the analyst isn't flooded.
- **Baseline period for "new IP".** The first half of the log defines each user's known IPs. Users with no baseline history are skipped rather than flagged, to avoid false positives on new employees.
- **Synthetic data.** Real auth logs contain private IPs and usernames, so the repo ships a seeded generator. Tests assert every injected attack is caught and that background internet noise (single probes) is *not* flagged as brute force.

## Tests

```bash
pytest -q
```
