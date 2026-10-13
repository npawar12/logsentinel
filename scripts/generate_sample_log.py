"""Generate a realistic synthetic auth.log with known attacks injected, so the detector can
be demoed and tested without real (private) server logs.

Normal traffic: 8 employees logging in during work hours from their usual IPs, with the
occasional typo. Injected: a brute-force attack, a compromised account (brute force followed
by success), an off-hours login, and a login from a new IP.
"""
from __future__ import annotations

import argparse
import os
import random
from datetime import datetime, timedelta

USERS = {
    "alice": ["10.0.1.11"], "bob": ["10.0.1.12"], "carol": ["10.0.1.13", "10.0.2.40"],
    "dave": ["10.0.1.14"], "erin": ["10.0.1.15"], "frank": ["10.0.1.16"],
    "grace": ["10.0.1.17"], "deploy": ["10.0.3.5"],
}


def line(ts: datetime, msg: str, pid: int) -> str:
    return f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S} web01 sshd[{pid}]: {msg}"


def generate(days: int = 14, start: datetime = datetime(2026, 9, 28), seed: int = 7) -> list[str]:
    rng = random.Random(seed)
    out: list[tuple[datetime, str]] = []
    pid = 2000

    def add(ts, msg):
        nonlocal pid
        pid += 1
        out.append((ts, line(ts, msg, pid)))

    # Normal weekday behaviour
    for d in range(days):
        day = start + timedelta(days=d)
        if day.weekday() >= 5:
            continue
        for user, ips in USERS.items():
            for _ in range(rng.randint(1, 3)):
                ts = day + timedelta(hours=rng.randint(8, 18), minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
                ip = rng.choice(ips)
                if rng.random() < 0.08:  # a typo, then success
                    add(ts, f"Failed password for {user} from {ip} port {rng.randint(40000, 65000)} ssh2")
                    ts += timedelta(seconds=rng.randint(5, 30))
                method = "publickey" if user == "deploy" else "password"
                add(ts, f"Accepted {method} for {user} from {ip} port {rng.randint(40000, 65000)} ssh2")

    # Background internet noise: occasional single probes from random IPs
    for _ in range(60):
        ts = start + timedelta(minutes=rng.randint(0, days * 24 * 60))
        ip = f"198.51.100.{rng.randint(1, 254)}"
        add(ts, f"Invalid user {rng.choice(['test', 'oracle', 'pi', 'ubuntu'])} from {ip} port {rng.randint(40000, 65000)}")

    # ATTACK 1: credential-stuffing brute force, many usernames, no success
    t = start + timedelta(days=9, hours=2, minutes=13)
    for i in range(180):
        u = rng.choice(["root", "admin", "user", "test", "postgres", "git", "ubuntu"])
        add(t + timedelta(seconds=i * 2), f"Failed password for invalid user {u} from 203.0.113.77 port {rng.randint(40000, 65000)} ssh2")

    # ATTACK 2: targeted brute force on a real account that eventually succeeds
    t = start + timedelta(days=10, hours=23, minutes=40)
    for i in range(40):
        add(t + timedelta(seconds=i * 4), f"Failed password for frank from 192.0.2.45 port {rng.randint(40000, 65000)} ssh2")
    add(t + timedelta(seconds=40 * 4 + 3), f"Accepted password for frank from 192.0.2.45 port {rng.randint(40000, 65000)} ssh2")

    # ATTACK 3: a valid user logging in at 3am from their normal IP
    add(start + timedelta(days=11, hours=3, minutes=12), "Accepted password for bob from 10.0.1.12 port 51515 ssh2")

    # ATTACK 4: a valid user logging in from an IP they've never used, during work hours
    add(start + timedelta(days=12, hours=14, minutes=5), "Accepted password for alice from 172.16.9.200 port 50001 ssh2")

    out.sort(key=lambda x: x[0])
    return [l for _, l in out]


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="sample_data/auth.log")
    args = ap.parse_args()
    lines = generate()
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"Wrote {len(lines)} lines to {args.out}")
