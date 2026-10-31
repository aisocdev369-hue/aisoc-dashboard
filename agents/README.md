# AISOC Dashboard endpoint agents

Lightweight pollers for the project's two monitored machines (one Windows 11, one Linux).
Each agent watches logins, new processes, and a short list of watched files/directories,
and posts batches of events to the dashboard's `POST /api/v1/ingest`. There is no central
manager or enrollment protocol — each agent only needs the dashboard's URL and its own token.

This intentionally is not Wazuh/Suricata. See the project doc's "Future Enhancements"
section for when a full SIEM stack would be worth the operational overhead.

## 1. Register the endpoint and get its token

As an admin, call the dashboard once per machine:

```bash
curl -X POST https://your-dashboard.example.com/api/v1/admin/endpoints \
  -H "Authorization: Bearer <your admin access token>" \
  -H "Content-Type: application/json" \
  -d '{"hostname": "WIN11-DESKTOP", "os": "windows"}'
```

The response's `token` field is shown once — copy it immediately, it is not stored in
recoverable form and cannot be displayed again. If it's lost, register a new endpoint
(or extend the admin API with a reset-token action) rather than trying to recover it.

## 2. Install and run

On each machine:

```bash
cd agents
pip install -r requirements.txt
# Windows only:
pip install pywin32

export AISOC_API_URL="https://your-dashboard.example.com"
export AISOC_AGENT_TOKEN="<the token from step 1>"
export AISOC_WATCH_PATHS="/etc/passwd,/etc/shadow"   # optional, comma-separated

python linux_agent.py     # or windows_agent.py on the Windows machine
```

Run it under systemd (Linux) or Task Scheduler / a Windows service (Windows) for anything
beyond a quick test — see the comments at the top of each script for the account
permissions each needs (event log read access on Windows, `/var/log/auth.log` or
`journalctl` read access on Linux).

## 3. Confirm it's working

`GET /api/v1/sources/health` (as an analyst or admin) shows each registered endpoint's
`last_seen_at` and a status of `online`, `stale`, `never_seen`, or `disabled`. New events
appear as ordinary alerts in the dashboard with `external_id` prefixed `AGENT-`.

## Environment variables

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `AISOC_API_URL` | yes | — | Dashboard base URL, no trailing slash |
| `AISOC_AGENT_TOKEN` | yes | — | Token from endpoint registration |
| `AISOC_POLL_SECONDS` | no | `30` | How often to poll and upload |
| `AISOC_WATCH_PATHS` | no | empty | Comma-separated files/dirs to watch for changes |
| `AISOC_STATE_FILE` | no | `aisoc-agent-state.json` | Where dedup/offset state is kept |
