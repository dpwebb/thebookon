# Hostinger VPS Deployment

This site is deployed from GitHub as a Docker service on the shared Hostinger VPS.

## Production Targets

```text
domain: https://thebookon.ca
www: https://www.thebookon.ca
repo: git@github.com:dpwebb/thebookon.git
vps path: /opt/thebookon/app
container: thebookon
local port: 127.0.0.1:3515
proxy: shared Traefik + Let's Encrypt
runtime data: Docker volume `thebookon_thebookon_data` mounted at `/app/data`
```

## DNS Cutover

The active DNS zone must point both records at the shared Hostinger VPS:

| Host | Type | Value |
| --- | --- | --- |
| `@` | `A` | `187.127.252.51` |
| `www` | `A` | `187.127.252.51` |

Current public DNS is managed by the authoritative nameservers for the domain. Change the active DNS zone there, or move the domain to Hostinger DNS first and create the same records in hPanel.

## One-Time VPS Setup

```bash
sudo mkdir -p /opt/thebookon
sudo chown -R "$USER":"$USER" /opt/thebookon
git clone git@github.com:dpwebb/thebookon.git /opt/thebookon/app
cd /opt/thebookon/app
docker compose up -d --build
```

The first container start creates persistent JSON stores for author accounts, contact messages, reset-help requests, manuscript submissions, and private uploaded files inside the Docker volume. Keep that volume in place across redeploys.

## Updating Production

```bash
cd /opt/thebookon/app
bash scripts/deploy-production.sh
```

To deploy a specific commit:

```bash
cd /opt/thebookon/app
bash scripts/deploy-production.sh <commit-sha>
```

## GitHub Actions

`.github/workflows/deploy-production.yml` validates the Compose file, connects to the VPS over SSH, and runs `scripts/deploy-production.sh` with the exact GitHub commit SHA. It is manual by default because the VPS systemd timer can already poll GitHub and deploy pushes to `main`.

Create a `production` environment in GitHub and add:

```text
PRODUCTION_HOST=187.127.252.51
PRODUCTION_USER=<VPS deploy user>
PRODUCTION_SSH_PRIVATE_KEY=<OpenSSH private key authorized for the deploy user>
PRODUCTION_SSH_PORT=22
```

Do not commit private keys or runtime secrets. The workflow reads them only from GitHub environment secrets.

## VPS Git Poller

Root can install the systemd poller on the Hostinger VPS:

```bash
sudo cp deploy/systemd/thebookon-git-deploy.service /etc/systemd/system/
sudo cp deploy/systemd/thebookon-git-deploy.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now thebookon-git-deploy.timer
sudo systemctl start thebookon-git-deploy.service
```

The timer checks GitHub every five minutes and deploys only when `origin/main` differs from the running checkout or the container is unhealthy.

## Verify

Before DNS cutover:

```bash
curl -H 'Host: thebookon.ca' http://127.0.0.1:3515/health
curl -H 'Host: thebookon.ca' http://127.0.0.1:3515/
```

After DNS cutover:

```bash
curl -I https://thebookon.ca/
curl -I https://www.thebookon.ca/
curl https://thebookon.ca/health
```
