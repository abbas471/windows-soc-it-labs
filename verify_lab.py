"""Verify the failed-logon lab's synthetic fixture with Python's standard library."""

import csv
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


def detect(rows):
    groups = defaultdict(list)
    for row in rows:
        source = row["source_ip"].strip()
        if row["event_id"] != "4625" or row["logon_type"] != "3" or source in {"", "-"}:
            continue

        try:
            timestamp = datetime.strptime(row["event_time"], "%Y-%m-%dT%H:%M:%S%z")
        except ValueError:
            continue

        timestamp = timestamp.astimezone(timezone.utc)
        bucket = timestamp.replace(minute=timestamp.minute // 5 * 5, second=0)
        groups[bucket, source, row["computer"]].append(row["target_user"])

    return [
        (bucket.isoformat(), source, computer, len(users), sorted(set(users)))
        for (bucket, source, computer), users in sorted(groups.items())
        if len(users) >= 5
    ]


def main():
    fixture = Path(__file__).with_name("windows_failed_logon_events.csv")
    with fixture.open(encoding="utf-8", newline="") as events:
        actual = detect(csv.DictReader(events))

    expected = [
        (
            "2026-10-01T10:00:00+00:00",
            "192.0.2.41",
            "FILE01",
            6,
            ["svc_backup", "user_amina", "user_sami"],
        )
    ]
    if actual != expected:
        raise SystemExit(f"Expected {expected!r}\nGot      {actual!r}")

    window, source, computer, failures, accounts = actual[0]
    print(f"PASS: {window} {source} -> {computer}: {failures} failures ({', '.join(accounts)})")


if __name__ == "__main__":
    main()
