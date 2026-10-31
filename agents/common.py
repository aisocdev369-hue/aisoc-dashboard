"""Shared plumbing for the AISOC Dashboard endpoint agents (windows_agent.py, linux_agent.py).

Both agents are deliberately simple pollers, not a SIEM agent: they watch a short, fixed
list of signals (logins, new processes, changes to a few watched paths) and POST batches of
events to the dashboard's /api/v1/ingest endpoint. See the project doc's "Future
Enhancements" section for when a full Wazuh/Suricata deployment would replace this.

Configuration is via environment variables so nothing sensitive lives in the script:

    AISOC_API_URL        e.g. https://your-dashboard.example.com   (required)
    AISOC_AGENT_TOKEN     the token printed by POST /api/v1/admin/endpoints  (required)
    AISOC_POLL_SECONDS    how often to poll, default 30
    AISOC_WATCH_PATHS     comma-separated files/dirs to watch for changes (optional)
    AISOC_STATE_FILE      where to persist dedup state between restarts (optional)
"""

from __future__ import annotations

import json
import logging
import os
import socket
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import requests

logger = logging.getLogger("aisoc-agent")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

MAX_EVENTS_PER_BATCH = 100
REQUEST_TIMEOUT_SECONDS = 15


@dataclass
class AgentConfig:
    api_url: str
    token: str
    poll_seconds: int
    watch_paths: list[str]
    state_file: Path
    hostname: str = field(default_factory=socket.gethostname)

    @classmethod
    def from_env(cls) -> "AgentConfig":
        api_url = os.environ.get("AISOC_API_URL", "").rstrip("/")
        token = os.environ.get("AISOC_AGENT_TOKEN", "")
        if not api_url or not token:
            raise SystemExit("AISOC_API_URL and AISOC_AGENT_TOKEN must both be set.")

        watch_paths = [p.strip() for p in os.environ.get("AISOC_WATCH_PATHS", "").split(",") if p.strip()]
        state_file = Path(os.environ.get("AISOC_STATE_FILE", "aisoc-agent-state.json"))
        poll_seconds = int(os.environ.get("AISOC_POLL_SECONDS", "30"))

        return cls(api_url=api_url, token=token, poll_seconds=poll_seconds, watch_paths=watch_paths, state_file=state_file)

    @property
    def ingest_url(self) -> str:
        return f"{self.api_url}/api/v1/ingest"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_event(event_type: str, detail: str, occurred_at: str | None = None, source_ip: str | None = None) -> dict:
    return {
        "client_event_id": str(uuid.uuid4()),
        "event_type": event_type,
        "detail": detail[:2000],
        "occurred_at": occurred_at or now_iso(),
        "source_ip": source_ip,
    }


class StateStore:
    """Small JSON file so a restarted agent doesn't resend every login/process it's ever seen
    or lose track of file mtimes. Loss of this file just means a noisier first poll, not data
    corruption — nothing here is a substitute for the dashboard's own audit log."""

    def __init__(self, path: Path):
        self.path = path
        self.data: dict = {}
        if path.exists():
            try:
                self.data = json.loads(path.read_text())
            except (OSError, ValueError):
                logger.warning("Could not read state file %s; starting fresh.", path)
                self.data = {}

    def save(self) -> None:
        try:
            self.path.write_text(json.dumps(self.data))
        except OSError:
            logger.warning("Could not write state file %s.", self.path)


def post_events(config: AgentConfig, events: list[dict]) -> bool:
    """Sends events in batches of MAX_EVENTS_PER_BATCH. Returns True only if every batch
    was accepted; a failed batch is logged and left for the next poll cycle to retry
    (events aren't removed from the caller's pending list unless this returns True)."""
    if not events:
        return True

    headers = {"Authorization": f"Bearer {config.token}", "Content-Type": "application/json"}
    for i in range(0, len(events), MAX_EVENTS_PER_BATCH):
        batch = events[i : i + MAX_EVENTS_PER_BATCH]
        try:
            resp = requests.post(
                config.ingest_url,
                json={"events": batch},
                headers=headers,
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
        except requests.RequestException as exc:
            logger.warning("Ingest request failed (%s); will retry next poll.", exc)
            return False

        if resp.status_code == 401:
            logger.error("Ingest rejected the agent token (401). Check AISOC_AGENT_TOKEN and retry.")
            return False
        if not resp.ok:
            logger.warning("Ingest returned %s: %s", resp.status_code, resp.text[:300])
            return False

        result = resp.json()
        logger.info("Sent %d events (%d became new alerts).", len(batch), result.get("alerts_created", 0))

    return True


def poll_watched_paths(paths: Iterable[str], state: StateStore) -> list[dict]:
    """Emits a file_change event for any watched file whose mtime/size differs from what
    was last recorded, and for any watched directory whose file listing changed."""
    seen: dict = state.data.setdefault("watched_paths", {})
    events: list[dict] = []

    for raw_path in paths:
        p = Path(raw_path)
        if not p.exists():
            continue
        try:
            if p.is_dir():
                entries = sorted(child.name for child in p.iterdir())
                fingerprint = json.dumps(entries)
                if seen.get(raw_path) is not None and seen[raw_path] != fingerprint:
                    events.append(make_event("file_change", f"Directory listing changed: {raw_path}"))
                seen[raw_path] = fingerprint
            else:
                stat = p.stat()
                fingerprint = f"{stat.st_mtime_ns}:{stat.st_size}"
                if seen.get(raw_path) is not None and seen[raw_path] != fingerprint:
                    events.append(make_event("file_change", f"File modified: {raw_path}"))
                seen[raw_path] = fingerprint
        except OSError as exc:
            logger.debug("Could not stat watched path %s: %s", raw_path, exc)

    return events


def poll_new_processes(state: StateStore) -> list[dict]:
    """Diffs the running-process set against the last poll. Requires psutil; returns no
    events (rather than failing) if psutil isn't installed, so login/file-change monitoring
    still works without it."""
    try:
        import psutil
    except ImportError:
        logger.debug("psutil not installed; skipping process-start monitoring.")
        return []

    previous = set(state.data.get("known_pids", []))
    current_procs = []
    try:
        for proc in psutil.process_iter(["pid", "name", "cmdline", "username"]):
            current_procs.append(proc.info)
    except psutil.Error as exc:
        logger.debug("Process enumeration failed: %s", exc)
        return []

    current_pids = {str(p["pid"]) for p in current_procs}
    events = []
    if previous:  # skip the very first poll so startup doesn't report every existing process
        for proc in current_procs:
            pid = str(proc["pid"])
            if pid not in previous:
                cmdline = " ".join(proc.get("cmdline") or []) or proc.get("name") or "unknown"
                events.append(make_event("process_start", f"New process (pid {pid}, user {proc.get('username')}): {cmdline}"))

    state.data["known_pids"] = sorted(current_pids)
    return events


def run_loop(config: AgentConfig, state: StateStore, collect_events) -> None:
    """collect_events(config, state) -> list[dict] is called once per poll cycle, in
    addition to the shared process and file-change checks."""
    logger.info("AISOC agent starting for %s. Polling every %ss.", config.hostname, config.poll_seconds)
    while True:
        events: list[dict] = []
        try:
            events.extend(collect_events(config, state))
        except Exception:
            logger.exception("Error collecting source-specific events; continuing.")
        events.extend(poll_new_processes(state))
        events.extend(poll_watched_paths(config.watch_paths, state))

        if events and post_events(config, events):
            state.save()
        elif not events:
            state.save()
        # On a failed post, state (and the unsent events) is intentionally not saved as
        # "delivered" — the next cycle's process/file diff will naturally pick up any new
        # changes, and a real retry queue is future-enhancement territory for a 2-endpoint demo.

        time.sleep(config.poll_seconds)
