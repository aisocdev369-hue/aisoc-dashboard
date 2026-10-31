# SOC Dashboard

AI-assisted Security Operations Center dashboard. Stage 2: Codespaces environment, Postgres, API health check, and Nginx.

## Google sign-in and registration

Create a Google OAuth 2.0 **Web application** client in Google Cloud Console and add the dashboard's exact URL origin under **Authorized JavaScript origins** (for example, `http://localhost:8080` or the Codespaces forwarded HTTPS origin). Put its client ID in `.env` as `GOOGLE_CLIENT_ID`. The client ID is public; Google ID tokens are verified by the API.

On the sign-in page, users can create an Analyst account with an email and password or continue with Google. Email registration requires a password of at least 12 characters. New accounts are always assigned the Analyst role; users cannot choose or self-assign Admin access. Existing accounts can sign in with email and password or Google. Bootstrap an administrator with the CLI below using the same Google account email. Admins and SOC Analysts can view accounts in the dashboard's **Users** section and use `GET /api/v1/admin/users`. Analysts can assign the Analyst role; only Admins can grant the Admin role, create accounts, or view audit logs. Role updates use `PATCH /api/v1/admin/users/{user_id}/role` with body `{"role":"admin"}` or `{"role":"analyst"}`. The last active Admin cannot be demoted.

## Run in Codespaces

1. Open the repository in a Codespace.
2. Edit `.env` (created from `.env.example` on first setup) and replace every `change-me` value. Keep `POSTGRES_PASSWORD` identical in `POSTGRES_PASSWORD` and `DATABASE_URL`.
3. Start the stack:

   ```bash
   docker compose up --build -d
   docker compose ps          # all services should report "healthy"
   ```

4. Open the forwarded port 8080. Check `http://localhost:8080/health` returns `{"status":"ok", ...}`.

## First-time setup (after the stack is healthy)

Migrations run automatically when the API starts. Then create the first administrator. Use the Google account email if they will sign in with Google. The password is typed at a prompt and never passed as an argument:

```bash
docker compose exec api python -m app.cli create-user --email you@example.com --role admin
docker compose exec api python -m app.cli seed-simulated --count 48
```

Analysts can register from the sign-in page with email and password or Google, or be created by an administrator through `POST /api/v1/admin/users`.

If the account already exists (for example, it registered with Google first), `create-user` will not modify it. To reset its password or promote it to Admin from the operator shell, run:

```bash
docker compose exec api python -m app.cli set-password --email you@example.com
docker compose exec api python -m app.cli set-role --email you@example.com --role admin
```

The password reset prompts interactively and does not put the password in shell history. The CLI will not demote the last active Admin.

To reset a password (e.g. if you forgot the one you set), run:

```bash
docker compose exec api python -m app.cli set-password --email you@example.com
```

## Endpoint agents (Windows 11 + Linux)

The dashboard monitors two known machines directly — no Wazuh/Suricata deployment. An
admin registers each endpoint and gets back a one-time token:

```bash
curl -X POST http://localhost:8080/api/v1/admin/endpoints \
  -H "Authorization: Bearer <admin access token>" \
  -H "Content-Type: application/json" \
  -d '{"hostname": "WIN11-DESKTOP", "os": "windows"}'
```

Run the matching agent on that machine with the printed token — see `agents/README.md`
for full setup. Each agent polls logins, new processes, and a few watched paths, and posts
them to `POST /api/v1/ingest`, where they become ordinary alerts (`external_id` prefixed
`AGENT-`). Check endpoint status with `GET /api/v1/sources/health` (analyst or admin).

Set `MONITORING_MODE=live` once both agents are running — this stops `seed-simulated` from
mixing fake alerts into real data (override with `--force` if that's intentional).

## Gemini AI analysis

Set `GEMINI_API_KEY` in Codespaces Secrets or `.env`. Without it, the analysis button returns "not configured" and nothing is sent to Google. Analysis sends only the alert fields listed in `backend/app/routers/ai.py`. Outputs are validated and stored, and never executed.

## Run tests

```bash
cd backend && pip install -r requirements.txt && pytest -q
```

## Production readiness

This repository is a development preview, not a production SOC deployment. Before production:

- Register both endpoints (`POST /api/v1/admin/endpoints`) and get their agents running before switching `MONITORING_MODE` to `live`. Do not seed simulated alerts into a database that's also receiving real agent events.
- Terminate HTTPS at the deployment boundary and configure the production domain, Google OAuth authorized origins, and narrow CORS origins.
- Replace all placeholder credentials with strong production secrets stored outside the repository. Use a production database and verify migrations and health checks in the deployment environment.
- Decide whether Gemini analysis is enabled. Review the alert fields sent to Google and applicable data-handling requirements before configuring `GEMINI_API_KEY`.
- Set up database backups and restore testing, centralized logs and monitoring, deployment rollback procedures, and end-to-end tests for authentication and alert workflows.

## Notes

- Postgres and the API are not published to the host. Only Nginx on port 8080 is reachable.
- Secrets must never be committed. Use Codespaces Secrets for real values.
- HTTPS must be configured at the deployment boundary; the local Nginx container serves HTTP only.
