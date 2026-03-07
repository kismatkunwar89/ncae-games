#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <service>"
    echo "Services: shell www db dns backup"
    exit 1
fi

SERVICE="$1"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TEAM="${TEAM:-1}"
NCAE_LAN="${NCAE_LAN:-10.88.${TEAM}.0/24}"
NCAE_LAN_BASE="${NCAE_LAN_BASE:-$(echo "${NCAE_LAN}" | sed 's/\.[0-9]*\/[0-9]*//')}"
NCAE_SCORING="${NCAE_SCORING:-10.77.0.0/16}"
NCAE_SHELL_IP="${NCAE_SHELL_IP:-10.77.14.${TEAM}}"
NCAE_BACKUP_IP="${NCAE_BACKUP_IP:-${NCAE_LAN_BASE}.15}"
NCAE_CA_IP="${NCAE_CA_IP:-10.77.0.38}"

case "$SERVICE" in
    shell|www|db|dns|backup) ;;
    *)
        echo "Unknown service: $SERVICE"
        exit 1
        ;;
esac

docker compose -f "$ROOT_DIR/docker/lab/compose.yaml" exec \
    -e TEAM="${TEAM}" \
    -e NCAE_AUTO_ACCEPT=1 \
    -e NCAE_LAN="${NCAE_LAN}" \
    -e NCAE_LAN_BASE="${NCAE_LAN_BASE}" \
    -e NCAE_SCORING="${NCAE_SCORING}" \
    -e NCAE_SHELL_IP="${NCAE_SHELL_IP}" \
    -e NCAE_BACKUP_IP="${NCAE_BACKUP_IP}" \
    -e NCAE_CA_IP="${NCAE_CA_IP}" \
    -e NCAE_SKIP_BACKUP=1 \
    -e NCAE_SKIP_SCRIPT_LOCK=1 \
    -e NCAE_SKIP_UPDATE=1 \
    -e NCAE_SKIP_INSTALL=1 \
    "$SERVICE" \
    bash /opt/ncae/scripts/deploy_all.sh "$SERVICE"
