#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/thebookon/app}"
DEPLOY_REF="${1:-origin/main}"

cd "$APP_DIR"

git fetch --prune origin
git checkout main

if git cat-file -e "${DEPLOY_REF}^{commit}" 2>/dev/null; then
  git reset --hard "$DEPLOY_REF"
else
  git pull --ff-only origin main
fi

docker compose config >/dev/null
docker compose up -d --build
docker image prune -f >/dev/null

for attempt in {1..12}; do
  status="$(docker inspect thebookon --format '{{.State.Health.Status}}' 2>/dev/null || true)"
  if [ "$status" = "healthy" ]; then
    break
  fi
  sleep 5
done

docker inspect thebookon --format '{{.State.Health.Status}}' | grep -q '^healthy$'
curl --fail --silent --show-error http://127.0.0.1:3515/health
