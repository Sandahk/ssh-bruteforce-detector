from datetime import timedelta

from detector import detect, parse


def log(*lines: str) -> list[str]:
    return [f"Mar  1 {line}\n" for line in lines]


def fails(ip: str, times: list[str]) -> list[str]:
    return [f"{t} host sshd[1]: Failed password for invalid user admin from {ip} port 22 ssh2" for t in times]


def accept(ip: str, t: str, user: str = "alice") -> str:
    return f"{t} host sshd[1]: Accepted password for {user} from {ip} port 22 ssh2"


def run(lines: list[str]):
    return detect(parse(log(*lines)))


def test_burst_then_success_is_flagged():
    alerts = run(fails("10.0.0.1", ["10:00:01", "10:00:05", "10:00:09", "10:00:12", "10:00:20"])
                 + [accept("10.0.0.1", "10:00:30")])
    assert [(a.ip, a.user, a.failures) for a in alerts] == [("10.0.0.1", "alice", 5)]


def test_failures_outside_window_do_not_count():
    # 5 failures, but the first one is 61s before the login
    alerts = run(fails("10.0.0.2", ["10:00:00", "10:00:40", "10:00:45", "10:00:50", "10:00:55"])
                 + [accept("10.0.0.2", "10:01:01")])
    assert alerts == []


def test_noisy_ip_without_success_is_ignored():
    alerts = run(fails("10.0.0.3", [f"10:00:{s:02d}" for s in range(0, 60, 2)]))
    assert alerts == []


def test_failures_are_counted_per_ip():
    lines = fails("10.0.0.4", ["10:00:01", "10:00:02", "10:00:03"]) + \
            fails("10.0.0.5", ["10:00:04", "10:00:05"]) + [accept("10.0.0.4", "10:00:06")]
    assert run(lines) == []


def test_unrelated_lines_are_skipped():
    lines = ["10:00:00 host sshd[1]: Connection closed by authenticating user root 10.0.0.6 port 22 [preauth]",
             "10:00:00 host sshd[1]: pam_unix(sshd:session): session opened for user bob(uid=1000) by (uid=0)"]
    assert list(parse(log(*lines))) == []


def test_threshold_and_window_are_configurable():
    lines = fails("10.0.0.7", ["10:00:00", "10:00:10"]) + [accept("10.0.0.7", "10:00:20")]
    assert len(detect(parse(log(*lines)), min_failures=2, window=timedelta(seconds=30))) == 1
