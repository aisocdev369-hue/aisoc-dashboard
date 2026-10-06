# SOC Dashboard

AI-assisted Security Operations Center dashboard. Stage 2: Codespaces environment, Postgres, API health check, and Nginx.

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

Migrations run automatically when the API starts. Then create the first administrator. The password is typed at a prompt and never passed as an argument:

```bash
docker compose exec api python -m app.cli create-user --email you@example.com --role admin
docker compose exec api python -m app.cli seed-simulated --count 48
```

Analysts are created by an administrator from the admin API (`POST /api/v1/admin/users`).

## Gemini AI analysis

Set `GEMINI_API_KEY` in Codespaces Secrets or `.env`. Without it, the analysis button returns "not configured" and nothing is sent to Google. Analysis sends only the alert fields listed in `backend/app/routers/ai.py`. Outputs are validated and stored, and never executed.

## Run tests

```bash
cd backend && pip install -r requirements.txt && pytest -q
```

## Notes

- Postgres and the API are not published to the host. Only Nginx on port 8080 is reachable.
- Secrets must never be committed. Use Codespaces Secrets for real values.
- Not production-ready: HTTPS is configured at the deployment boundary (see later stages).
