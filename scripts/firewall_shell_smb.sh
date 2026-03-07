#!/usr/bin/env bash
# Compatibility wrapper: shell is now FTP-scored, not SMB-scored.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "${SCRIPT_DIR}/firewall_shell_ftp.sh" "$@"
