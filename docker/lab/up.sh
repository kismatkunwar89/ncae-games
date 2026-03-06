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

The lab uses Team 1-style IPs:
  router  172.18.13.1 / 192.168.1.1
  shell   172.18.14.1
  scoring 172.18.0.38
  www     192.168.1.5
  db      192.168.1.7
  dns     192.168.1.12
  backup  192.168.1.15
EOF
