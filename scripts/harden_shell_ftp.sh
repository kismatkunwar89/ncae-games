#!/usr/bin/env bash
# Compatibility entrypoint: the shell role is FTP-scored, but we keep the
# original implementation in harden_shell_smb.sh until the repo fully renames it.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "${SCRIPT_DIR}/harden_shell_smb.sh" "$@"
