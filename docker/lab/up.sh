#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
mkdir -p "$ROOT_DIR/docker/lab/logs"

docker compose -f "$ROOT_DIR/docker/lab/compose.yaml" up -d --build

cat <<'EOF'
[+] NCAE lab is starting.

Suggested next steps:
  bash docker/lab/status.sh
  bash docker/lab/deploy-role.sh shell
  bash docker/lab/deploy-role.sh www
  bash docker/lab/deploy-role.sh db
  bash docker/lab/deploy-role.sh dns
  bash docker/lab/deploy-role.sh backup

The lab uses Docker-safe Team 1-style IPs:
  router  10.77.13.1 / 10.88.1.254
  shell   10.77.14.1
  scoring 10.77.0.38
  www     10.88.1.5
  db      10.88.1.7
  dns     10.88.1.12
  backup  10.88.1.15
EOF
