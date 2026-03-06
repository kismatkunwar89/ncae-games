#!/usr/bin/env bash
set -euo pipefail

mkdir -p /run/sshd /vagrant/logs

if [[ ! -s /etc/machine-id ]]; then
    systemd-machine-id-setup >/dev/null 2>&1 || true
fi

exec "$@"
