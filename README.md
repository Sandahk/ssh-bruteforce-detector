# ssh-bruteforce-detector

Flags SSH logins that succeeded right after a burst of failed attempts – the
classic sign of a brute-forced or credential-stuffed account.

It reads OpenSSH (`sshd`) auth logs and, per source IP, keeps a sliding window
of failed attempts. When an `Accepted` login arrives and the window holds at
least *N* failures (default: 5 in 60 s), it raises an alert.

```
$ python detector.py /var/log/auth.log
Mar 01 09:08:50  203.0.113.7      user=alice   failures=7
```

Exit code is `1` when alerts were found, `0` otherwise, so it can gate a cron
job or a CI step.

## Why a sliding window per IP

Real logs are noisy in ways that break naive counting:

| Pattern | Naive "≥5 failures, then success" | This tool |
|---|---|---|
| Scanner with hundreds of failures, never logs in | ignored | ignored |
| User mistypes twice, then logs in with a key | ignored | ignored |
| 5 failures spread over several minutes, then success | **false positive** | ignored |
| Failures from IP A, success from IP B | **false positive** | ignored |
| 7 failures in 30 s, then success | flagged | flagged |

## Usage

```
python detector.py LOGFILE [--min-failures 5] [--window 60]
cat auth.log | python detector.py -
```

## Tests

```
pip install pytest
pytest
```

The tests cover the window boundary, per-IP isolation, noisy IPs that never
succeed, and unrelated log lines.

## Limitations

- syslog timestamps have no year; logs that cross New Year will be misordered.
- Only `Failed` / `Accepted` lines are used; `Invalid user` and PAM failures
  are ignored.
- IPv6 and hostnames work as long as sshd logs them after `from`.
