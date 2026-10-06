"""Generates clearly labelled SIMULATED alerts for development. Never used for real events."""

import random
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Alert

ANCHOR = datetime(2026, 10, 6, 9, 30, tzinfo=timezone.utc)
HOSTS = [
    "srv-db-01", "dc-01", "srv-web-02", "vpn-gw-01",
    "ws-fin-01", "ws-hr-04", "ws-dev-07", "srv-mail-01",
]
RULES = [
    ("Multiple failed logons", "medium", "T1110 Brute Force"),
    ("Suspicious encoded PowerShell", "high", "T1059.001 PowerShell"),
    ("Possible C2 beacon to rare domain", "critical", "T1071 Application Layer Protocol"),
    ("Service created with elevated rights", "high", "T1543.003 Windows Service"),
    ("Port scan from single source", "low", "T1046 Network Service Discovery"),
    ("Malware signature match", "high", "T1204 User Execution"),
    ("Unusual outbound data volume", "medium", "T1041 Exfiltration Over C2"),
    ("Login from new geolocation", "low", "T1078 Valid Accounts"),
]
STATUSES = ["New", "New", "Investigating", "Closed", "Closed"]


def _documentation_ip(rng: random.Random) -> str:
    # RFC 5737 documentation ranges, so no simulated IP can be a real address.
    base = rng.choice(["203.0.113.", "198.51.100."])
    return f"{base}{rng.randint(1, 254)}"


def seed_simulated_alerts(db: Session, count: int = 48, seed: int = 20261006) -> int:
    """Insert simulated alerts that do not already exist. Returns the number inserted."""
    rng = random.Random(seed)
    existing = set(db.scalars(select(Alert.external_id)).all())
    inserted = 0
    for i in range(count):
        external_id = f"AL-{1200 + i}"
        rule, severity, mitre = rng.choice(RULES)
        occurred = ANCHOR - timedelta(minutes=rng.randint(0, 24 * 60 - 1))
        host = rng.choice(HOSTS)
        source_ip = _documentation_ip(rng)
        status = rng.choice(STATUSES)
        if external_id in existing:
            continue
        db.add(
            Alert(
                external_id=external_id,
                rule=rule,
                severity=severity,
                host=host,
                source_ip=source_ip,
                mitre=mitre,
                status=status,
                occurred_at=occurred,
                is_simulated=True,
            )
        )
        inserted += 1
    db.commit()
    return inserted
