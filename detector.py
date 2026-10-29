"""Detect successful SSH logins that follow a burst of failed attempts.

Reads OpenSSH (sshd) auth logs and flags every source IP that logged in
successfully after at least N failed attempts within the preceding window.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable, Iterator

LINE_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) \S+ sshd\[\d+\]: "
    r"(?P<kind>Failed|Accepted) \S+ for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\S+) port \d+"
)


@dataclass(frozen=True)
class Event:
    ts: datetime
    kind: str  # "Failed" or "Accepted"
    user: str
    ip: str


@dataclass(frozen=True)
class Alert:
    ip: str
    user: str
    accepted_at: datetime
    failures: int


def parse(lines: Iterable[str], year: int = 2000) -> Iterator[Event]:
    """Yield auth events; lines that are not Failed/Accepted are ignored.

    syslog timestamps carry no year, so one is supplied (it only matters
    for ordering within the file).
    """
    for line in lines:
        m = LINE_RE.match(line)
        if not m:
            continue
        ts = datetime.strptime(f"{year} {m['ts']}", "%Y %b %d %H:%M:%S")
        yield Event(ts, m["kind"], m["user"], m["ip"])


def detect(
    events: Iterable[Event], min_failures: int = 5, window: timedelta = timedelta(seconds=60)
) -> list[Alert]:
    """Sliding window of failures per IP; alert on Accepted if the window is full enough."""
    failures: dict[str, deque[datetime]] = defaultdict(deque)
    alerts = []
    for ev in events:
        q = failures[ev.ip]
        while q and ev.ts - q[0] > window:
            q.popleft()
        if ev.kind == "Failed":
            q.append(ev.ts)
        elif len(q) >= min_failures:
            alerts.append(Alert(ev.ip, ev.user, ev.ts, len(q)))
    return alerts


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("logfile", help="sshd log file, or - for stdin")
    ap.add_argument("--min-failures", type=int, default=5)
    ap.add_argument("--window", type=int, default=60, help="seconds")
    args = ap.parse_args(argv)

    src = sys.stdin if args.logfile == "-" else open(args.logfile, encoding="utf-8")
    with src:
        alerts = detect(parse(src), args.min_failures, timedelta(seconds=args.window))
    for a in alerts:
        print(f"{a.accepted_at:%b %d %H:%M:%S}  {a.ip:<15}  user={a.user}  failures={a.failures}")
    return 1 if alerts else 0


if __name__ == "__main__":
    raise SystemExit(main())
