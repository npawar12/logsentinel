import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from generate_sample_log import generate  # noqa: E402
from logsentinel.model import score  # noqa: E402
from logsentinel.parser import parse_line, parse_lines  # noqa: E402
from logsentinel.rules import RuleConfig, run_all  # noqa: E402


def test_parse_failed_invalid_user():
    r = parse_line("Oct  2 03:14:07 web01 sshd[1234]: Failed password for invalid user admin "
                   "from 203.0.113.5 port 52311 ssh2", 2026)
    assert r["event"] == "failure" and r["user"] == "admin" and r["ip"] == "203.0.113.5"
    assert r["timestamp"].day == 2 and r["timestamp"].hour == 3


def test_parse_accepted_publickey():
    r = parse_line("Oct 12 09:01:22 web01 sshd[99]: Accepted publickey for deploy from 10.0.3.5 port 1 ssh2", 2026)
    assert r["event"] == "success" and r["method"] == "publickey"


def test_parse_ignores_unrelated_lines():
    assert parse_line("Oct 12 09:01:22 web01 CRON[5]: pam_unix(cron:session): session opened", 2026) is None
    assert parse_line("garbage", 2026) is None


def _events():
    return parse_lines(generate(), 2026)


def test_detects_all_injected_attacks():
    alerts = run_all(_events())
    found = set(zip(alerts["rule"], alerts["ip"]))
    assert ("brute_force", "203.0.113.77") in found
    assert ("brute_force", "192.0.2.45") in found
    assert ("success_after_brute_force", "192.0.2.45") in found
    assert ("off_hours_login", "10.0.1.12") in found
    assert ("new_ip_for_user", "172.16.9.200") in found


def test_no_brute_force_false_positives_from_noise():
    alerts = run_all(_events())
    bf_ips = set(alerts.loc[alerts["rule"] == "brute_force", "ip"])
    assert bf_ips == {"203.0.113.77", "192.0.2.45"}


def test_threshold_is_configurable():
    alerts = run_all(_events(), RuleConfig(brute_force_threshold=1000))
    assert "brute_force" not in set(alerts["rule"])


def test_isolation_forest_ranks_attacker_highest():
    scored = score(_events())
    assert scored.iloc[0]["ip"] in {"203.0.113.77", "192.0.2.45"}
    flagged = set(scored.loc[scored["is_anomaly"], "ip"])
    assert {"203.0.113.77", "192.0.2.45"} <= flagged
