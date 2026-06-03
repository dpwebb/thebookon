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
git fetch --prune origin
git checkout main
git pull --ff-only origin main
docker compose up -d --build
```

See `HOSTINGER_DEPLOYMENT.md` for the full setup and DNS checklist.
