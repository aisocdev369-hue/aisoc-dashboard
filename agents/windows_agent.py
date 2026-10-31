#!/usr/bin/env python3
"""AISOC Dashboard endpoint agent — Windows 11.

Reports logins (Security event log 4624/4625), new processes, and changes to a short list
of watched files/directories to the dashboard's /api/v1/ingest endpoint. See common.py for
shared polling/upload logic and the configuration environment variables.

Requires: pip install requests psutil pywin32
Run as:   a scheduled task or a Windows service running as a low-privilege account that has
          "Read" access to the Security event log (local Administrators have this by default;
          a dedicated service account needs to be added to the "Event Log Readers" group).
"""

from __future__ import annotations

import re
import sys

from common import AgentConfig, StateStore, make_event, run_loop

try:
    import win32evtlog
    import win32evtlogutil  # noqa: F401  (imported for its side effect of registering message DLLs)
except ImportError:
    print("pywin32 is required on Windows: pip install pywin32", file=sys.stderr)
    raise

SECURITY_LOG = "Security"
LOGON_SUCCESS_ID = 4624
LOGON_FAILURE_ID = 4625
_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def _event_id(event) -> int:
    # Vista+ event records pack qualifiers into the high bits of EventID.
    return event.EventID & 0xFFFF


def _extract_ip(inserts: list[str]) -> str | None:
    for value in reversed(inserts):  # the source-address insert is usually near the end
        match = _IPV4.search(value or "")
        if match and match.group(0) not in ("0.0.0.0", "127.0.0.1"):
            return match.group(0)
    return None


def poll_logins(config: AgentConfig, state: StateStore) -> list[dict]:
    try:
        handle = win32evtlog.OpenEventLog(None, SECURITY_LOG)
    except Exception as exc:  # pywin32 raises a plain pywintypes.error
        print(f"Could not open the Security event log (run as admin / Event Log Readers): {exc}", file=sys.stderr)
        return []

    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    last_record = state.data.get("last_security_record", 0)
    first_run = last_record == 0
    newest_seen = last_record
    events: list[dict] = []

    try:
        while True:
            records = win32evtlog.ReadEventLog(handle, flags, 0)
            if not records:
                break
            if first_run:
                # Backwards-read starts at the newest record; just note it and stop,
                # rather than reading the entire log history on first startup.
                newest_seen = records[0].RecordNumber
                break
            stop = False
            for record in records:
                if record.RecordNumber <= last_record:
                    stop = True
                    break
                newest_seen = max(newest_seen, record.RecordNumber)
                event_id = _event_id(record)
                if event_id not in (LOGON_SUCCESS_ID, LOGON_FAILURE_ID):
                    continue
                inserts = list(record.StringInserts or [])
                account = next((v for v in inserts if v and "\\" not in v and v not in ("-", "")), "unknown")
                ip = _extract_ip(inserts)
                occurred_at = record.TimeGenerated.isoformat() if hasattr(record.TimeGenerated, "isoformat") else None

                if event_id == LOGON_SUCCESS_ID:
                    detail = f"Successful logon for {account} from {ip or 'local'}"
                else:
                    detail = f"Failed logon attempt for {account} from {ip or 'local'}"
                events.append(make_event("login", detail, occurred_at=occurred_at, source_ip=ip))
            if stop:
                break
    finally:
        win32evtlog.CloseEventLog(handle)

    state.data["last_security_record"] = newest_seen
    return events


def main() -> None:
    config = AgentConfig.from_env()
    state = StateStore(config.state_file)
    run_loop(config, state, poll_logins)


if __name__ == "__main__":
    main()
