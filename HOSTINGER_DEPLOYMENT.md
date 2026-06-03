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

## Updating Production

```bash
cd /opt/thebookon/app
git fetch --prune origin
git pull --ff-only origin main
docker compose up -d --build
docker image prune -f
```

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
