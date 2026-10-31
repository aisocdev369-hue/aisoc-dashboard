#!/usr/bin/env python3
"""AISOC Dashboard endpoint agent — Linux.

Reports logins (from /var/log/auth.log, falling back to `journalctl -u ssh/sshd` on
distributions without a flat auth log), new processes, and changes to a short list of
watched files/directories to the dashboard's /api/v1/ingest endpoint. See common.py for
shared polling/upload logic and the configuration environment variables.

Requires: pip install requests psutil
Run as:   a systemd service or cron @reboot job, as a user with read access to
          /var/log/auth.log (the adm group on Debian/Ubuntu) or to `journalctl`.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from common import AgentConfig, StateStore, make_event, run_loop

AUTH_LOG_CANDIDATES = ("/var/log/auth.log", "/var/log/secure")
_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

_FAILED_MARKERS = ("Failed password", "authentication failure", "Invalid user")
_SUCCESS_MARKERS = ("Accepted password", "Accepted publickey")


def _classify(line: str) -> tuple[str, str] | None:
    """Returns (detail, ip) for a login-relevant log line, or None to skip it."""
    if any(marker in line for marker in _FAILED_MARKERS):
        ip_match = _IPV4.search(line)
        return f"Failed login attempt: {line.strip()[-200:]}", (ip_match.group(0) if ip_match else None)
    if any(marker in line for marker in _SUCCESS_MARKERS):
        ip_match = _IPV4.search(line)
        return f"Successful login: {line.strip()[-200:]}", (ip_match.group(0) if ip_match else None)
    return None


def _poll_auth_log(path: str, state: StateStore) -> list[dict]:
    file = Path(path)
    if not file.exists():
        return []

    last_size = state.data.get("auth_log_offset", {}).get(path, 0)
    try:
        size = file.stat().st_size
    except OSError:
        return []

    if size < last_size:  # log was rotated/truncated
        last_size = 0

    events: list[dict] = []
    first_run = path not in state.data.get("auth_log_offset", {})
    with file.open("r", errors="replace") as fh:
        fh.seek(last_size)
        for line in fh:
            if not first_run:
                classified = _classify(line)
                if classified:
                    detail, ip = classified
                    events.append(make_event("login", detail, source_ip=ip))
        new_offset = fh.tell()

    state.data.setdefault("auth_log_offset", {})[path] = new_offset
    return events


def _poll_journald(state: StateStore) -> list[dict]:
    if shutil.which("journalctl") is None:
        return []

    cursor = state.data.get("journal_cursor")
    cmd = ["journalctl", "-u", "ssh.service", "-u", "sshd.service", "--no-pager", "-o", "short-iso"]
    if cursor:
        cmd += ["--after-cursor", cursor]
    else:
        cmd += ["-n", "0"]  # first run: just establish a cursor, don't replay history

    try:
        proc = subprocess.run(cmd + ["--show-cursor"], capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return []

    events: list[dict] = []
    lines = proc.stdout.splitlines()
    for line in lines:
        if line.startswith("-- cursor:"):
            state.data["journal_cursor"] = line.split("-- cursor:", 1)[1].strip()
            continue
        classified = _classify(line)
        if classified and cursor:  # cursor is None only on the very first run
            detail, ip = classified
            events.append(make_event("login", detail, source_ip=ip))

    return events


def poll_logins(config: AgentConfig, state: StateStore) -> list[dict]:
    for candidate in AUTH_LOG_CANDIDATES:
        if Path(candidate).exists():
            return _poll_auth_log(candidate, state)
    return _poll_journald(state)


def main() -> None:
    config = AgentConfig.from_env()
    state = StateStore(config.state_file)
    run_loop(config, state, poll_logins)


if __name__ == "__main__":
    main()
