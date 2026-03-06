#!/usr/bin/env bash
# =============================================================================
# NCAE Cyber Games 2026 - backup_configs.sh (FIXED v2)
#
# PURPOSE: Snapshot all scored service configs to both local disk and the
#          backup VM (192.168.t.15) every 5 minutes. If red team trashes a
#          config, you restore from here instead of rebuilding from scratch.
#
# SENSITIVE FILE HANDLING:
#   - /etc/shadow and credential files are copied locally ONLY (chmod 000)
#   - They are NEVER pushed to the backup VM over the network
#   - rsync excludes *.local_only files explicitly
#
# SSH KEY FLOW:
#   - First run generates /root/.ssh/ncae_backup_ed25519 and tries ssh-copy-id
#   - After key is deployed, all future rsync runs are passwordless/unattended
#   - If ssh-copy-id fails, manual instructions are printed
#
# Usage: bash backup_configs.sh [backup_vm_ip]
# =============================================================================
LOGFILE="/vagrant/logs/ncae_backup.log"
mkdir -p /vagrant/logs
touch "$LOGFILE" && chmod 600 "$LOGFILE"
exec > >(tee -a "$LOGFILE") 2>&1

# Auto-detect team number from our IP (192.168.t.x -> t)
# Fall back to team 1 if detection fails
TEAM=$(ip addr show | grep -oP '192\.168\.\K[0-9]+' | grep -E '^[0-9]+$' | head -1 2>/dev/null || echo "1")
HOSTNAME_SHORT=$(hostname | tr '.' '_')
LOCAL_BACKUP="/root/ncae_config_backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
# Allow overriding backup VM IP as first argument; default to 192.168.t.15
BACKUP_VM_IP="${1:-192.168.${TEAM}.15}"

echo "[$(date)] === Config Backup START - $HOSTNAME_SHORT ==="
mkdir -p "$LOCAL_BACKUP"

# -- SSH key setup for passwordless backup push --------------------------------
setup_ssh_key() {
    local key="/root/.ssh/ncae_backup_ed25519"
    if [[ ! -f "$key" ]]; then
        echo "[*] Generating backup SSH key..."
        # ed25519 is faster and smaller than RSA while providing equivalent security
        ssh-keygen -t ed25519 -N "" -f "$key" -C "ncae_backup_$(hostname)" 2>/dev/null
        echo "[+] Key generated: $key"
    else
        echo "[*] Using existing backup SSH key: $key"
    fi

    # Deploy our public key to the backup VM's authorized_keys
    # This requires password auth to still be enabled on the backup VM (harden_backup.sh keeps it on)
    echo "[*] Copying SSH key to backup VM $BACKUP_VM_IP..."
    ssh-copy-id -i "${key}.pub" \
        -o StrictHostKeyChecking=accept-new \
        -o ConnectTimeout=10 \
        "root@${BACKUP_VM_IP}" 2>/dev/null && \
        echo "[+] Key deployed to backup VM" || \
        echo "[!] Key copy failed - run manually: ssh-copy-id -i ${key}.pub root@${BACKUP_VM_IP}"
}

# -- Collect configs (FIXED: info to stderr, path to stdout only) -------------
# IMPORTANT: The function echoes the backup directory path to STDOUT only.
# All log/status messages go to STDERR. This lets the caller capture the path
# cleanly via BACKUP_PATH=$(collect_configs) without log lines contaminating it.
collect_configs() {
    local dest="$LOCAL_BACKUP/${TIMESTAMP}"
    mkdir -p "$dest"

    # Always back up: users, groups, SSH config, crontabs
    # /etc/shadow is hashed passwords - local only, never pushed remotely
    cp /etc/passwd /etc/group "$dest/" 2>/dev/null || true
    cp /etc/shadow "$dest/shadow.local_only" 2>/dev/null || true
    chmod 000 "$dest/shadow.local_only" 2>/dev/null || true  # Unreadable even as root via accident
    cp -r /etc/ssh/ "$dest/ssh/" 2>/dev/null || true
    crontab -l > "$dest/root_crontab.txt" 2>/dev/null || true
    cp /etc/cron.d/* "$dest/" 2>/dev/null || true

    # Apache / Nginx web server configs + web root content
    if [[ -d /etc/apache2 ]]; then cp -r /etc/apache2/ "$dest/apache2/" 2>/dev/null; fi
    if [[ -d /etc/nginx ]]; then cp -r /etc/nginx/ "$dest/nginx/" 2>/dev/null; fi
    if [[ -d /var/www/html ]]; then cp -r /var/www/html/ "$dest/webroot/" 2>/dev/null; fi

    # BIND DNS - named.conf + zone files (both /var/named for Rocky and /etc/bind for Ubuntu)
    if [[ -f /etc/named.conf ]]; then cp /etc/named.conf "$dest/" 2>/dev/null; fi
    if [[ -d /var/named ]]; then cp -r /var/named/ "$dest/var_named/" 2>/dev/null; fi
    if [[ -d /etc/bind ]]; then cp -r /etc/bind/ "$dest/bind/" 2>/dev/null; fi

    # Samba config
    if [[ -f /etc/samba/smb.conf ]]; then cp /etc/samba/smb.conf "$dest/" 2>/dev/null; fi

    # PostgreSQL - glob expands to whichever version is installed (14, 15, 16...)
    for pgconf in /etc/postgresql/*/main/postgresql.conf \
                  /etc/postgresql/*/main/pg_hba.conf; do
        if [[ -f "$pgconf" ]]; then cp "$pgconf" "$dest/" 2>/dev/null; fi
    done

    # Firewall rules - saves current active ruleset for fast restoration
    if command -v ufw &>/dev/null; then ufw status verbose > "$dest/ufw_status.txt" 2>/dev/null; fi
    if [[ -d /etc/ufw ]]; then cp -r /etc/ufw/ "$dest/ufw/" 2>/dev/null; fi
    if command -v firewall-cmd &>/dev/null; then firewall-cmd --list-all > "$dest/firewalld_status.txt" 2>/dev/null; fi
    if [[ -d /etc/firewalld ]]; then cp -r /etc/firewalld/ "$dest/firewalld/" 2>/dev/null; fi

    # SSL certificates and keys
    if [[ -d /etc/ssl/ncae ]]; then cp -r /etc/ssl/ncae/ "$dest/ssl_ncae/" 2>/dev/null; fi

    # Credential files - LOCAL ONLY, contain plaintext passwords, never pushed remotely
    cp /root/ncae_credentials_*.txt "$dest/credentials.local_only" 2>/dev/null || true
    chmod 000 "$dest/credentials.local_only" 2>/dev/null || true

    # FIXED: status message to stderr so caller captures only the clean path from stdout
    echo "[+] Local backup: $dest" >&2
    echo "$dest"  # stdout only: the path, nothing else
}

prune_local() {
    # Keep only the 12 most recent local backup snapshots (1hr at 5min intervals) to prevent disk fill
    # Uses find instead of ls to handle any special characters in directory names
    local count
    count=$(find "$LOCAL_BACKUP" -mindepth 1 -maxdepth 1 -type d -name "2*" 2>/dev/null | wc -l)
    if [[ "$count" -gt 12 ]]; then
        find "$LOCAL_BACKUP" -mindepth 1 -maxdepth 1 -type d -name "2*" 2>/dev/null | \
            sort | head -$((count - 12)) | xargs -r rm -rf
        echo "[*] Pruned to 12 local backups"
    fi
}

push_to_backup_vm() {
    local src="$1"
    local key="/root/.ssh/ncae_backup_ed25519"
    local dest_dir="/srv/ncae_backups/${HOSTNAME_SHORT}/${TIMESTAMP}"

    echo "[*] Pushing to backup VM $BACKUP_VM_IP..."

    # Build SSH options as an array - avoids SC2089/SC2090 quoting issues with strings
    # BatchMode=yes means rsync/ssh won't hang asking for a password if key auth fails
    local ssh_opts=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o BatchMode=yes)
    [[ -f "$key" ]] && ssh_opts+=(-i "$key")

    # Create destination directory on backup VM, then rsync to it
    # --exclude: local_only files (shadow, credentials) are NEVER pushed remotely
    if ssh "${ssh_opts[@]}" "root@${BACKUP_VM_IP}" mkdir -p "${dest_dir}" 2>/dev/null; then
        rsync -az --timeout=30 --exclude="shadow.local_only" --exclude="credentials.local_only" \
            -e "ssh ${ssh_opts[*]}" \
            "$src/" \
            "root@${BACKUP_VM_IP}:${dest_dir}/" 2>/dev/null && \
            echo "[+] Pushed to $BACKUP_VM_IP:$dest_dir" || \
            echo "[!] rsync failed - local backup still intact at $src"
    else
        echo "[!] Cannot reach backup VM - local backup only at $src"
    fi
}

# -- Install cron job ----------------------------------------------------------
install_cron() {
    # Only install once - idempotent check prevents duplicate cron entries
    if [[ ! -f /etc/cron.d/ncae_config_backup ]]; then
        local script_path
        script_path=$(realpath "$0")
        cat > /etc/cron.d/ncae_config_backup <<EOF
*/5 * * * * root bash ${script_path} ${BACKUP_VM_IP} >> /var/log/ncae_backup.log 2>&1
EOF
        echo "[+] Cron installed: every 5 min"
    fi
}

# -- Main ----------------------------------------------------------------------
setup_ssh_key
BACKUP_PATH=$(collect_configs)   # Captures clean path from stdout only (FIXED)
prune_local
push_to_backup_vm "$BACKUP_PATH"
install_cron

echo "[$(date)] === Config Backup COMPLETE ==="
echo "  Local:  $BACKUP_PATH"
echo "  Remote: $BACKUP_VM_IP:/srv/ncae_backups/${HOSTNAME_SHORT}/${TIMESTAMP}"
echo ""
echo "  Restore:"
echo "    cp $BACKUP_PATH/smb.conf /etc/samba/ && systemctl restart smb"
echo "    cp $BACKUP_PATH/named.conf /etc/ && systemctl restart named"
echo "    cp $BACKUP_PATH/pg_hba.conf /etc/postgresql/*/main/ && systemctl restart postgresql"
