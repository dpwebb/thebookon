# The Book On Publishing

Git-backed publishing site and author intake portal for `thebookon.ca`.

The public pages live in `public/` and are served by a small Node.js app in Docker. The app also handles author registration, login, manuscript uploads, contact messages, password reset-help requests, and author dashboard status data. Hostinger VPS ingress is handled by the shared Traefik stack through `docker-compose.yml`.

Runtime submissions and uploaded files are stored in the Docker volume mounted at `/app/data`. Do not commit runtime data.

## Refresh Static Content

Use the bundled Codex Python runtime or any Python 3.11+ interpreter:

```powershell
& 'C:\Users\webbd\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' tools\export_static.py
```

## Deploy On Hostinger

```bash
cd /opt/thebookon/app
bash scripts/deploy-production.sh
```

See `HOSTINGER_DEPLOYMENT.md` for the full setup and DNS checklist.

## Local Checks

```powershell
npm ci
npm run check
docker compose config
docker compose build
```

## GitHub Managed Deployment

The Hostinger VPS can poll `origin/main` with a systemd timer and run `scripts/deploy-production.sh` when a new commit is available. With that timer installed, future site updates are managed by editing the repo and pushing to `main`.

The repository also includes `.github/workflows/deploy-production.yml` for manual GitHub Actions deployment once the `production` environment secrets are configured.

Required GitHub environment secrets:

```text
PRODUCTION_HOST
PRODUCTION_USER
PRODUCTION_SSH_PRIVATE_KEY
PRODUCTION_SSH_PORT
```

## Editorial withdrawal

An author can request withdrawal from the dashboard for a manuscript attached
to their account. Guest submissions continue through support. Before closing
a request, editorial staff must verify the requester, the destination email,
and that no publishing agreement has been signed. The authorized production
operator then runs the following inside the application container:

```bash
docker exec thebookon node scripts/editorial-withdrawal.cjs <submission-reference> --verified-pre-agreement
```

The author dashboard confirms the decision immediately. The command reports
the notification outbox result. If the result is unavailable, resolve the
outbox issue and run the same command again. Repeating the command preserves
the original decision timestamp and deduplicates the confirmation.
