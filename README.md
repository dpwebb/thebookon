# The Book On Publishing

Static, Git-backed deployment for `thebookon.ca`.

The public pages are exported from the current WordPress site into `public/` and served by Nginx in Docker. Hostinger VPS ingress is handled by the shared Traefik stack through `docker-compose.yml`.

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

## GitHub Managed Deployment

The repository includes `.github/workflows/deploy-production.yml`. Once the `production` environment secrets are configured in GitHub, every push to `main` can deploy the exact pushed commit to the Hostinger VPS.

Required GitHub environment secrets:

```text
PRODUCTION_HOST
PRODUCTION_USER
PRODUCTION_SSH_PRIVATE_KEY
PRODUCTION_SSH_PORT
```
