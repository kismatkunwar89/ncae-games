#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <service>"
    echo "Services: shell www db dns backup"
    exit 1
fi

SERVICE="$1"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

case "$SERVICE" in
    shell|www|db|dns|backup) ;;
    *)
        echo "Unknown service: $SERVICE"
        exit 1
        ;;
esac

docker compose -f "$ROOT_DIR/docker/lab/compose.yaml" exec \
    -e NCAE_AUTO_ACCEPT=1 \
    -e NCAE_SKIP_BACKUP=1 \
    -e NCAE_SKIP_SCRIPT_LOCK=1 \
    -e NCAE_SKIP_UPDATE=1 \
    -e NCAE_SKIP_INSTALL=1 \
    "$SERVICE" \
    bash /opt/ncae/scripts/deploy_all.sh
