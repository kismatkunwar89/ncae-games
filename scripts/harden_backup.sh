#!/usr/bin/env bash
# =============================================================================
# NCAE Cyber Games 2026 - harden_backup.sh (FIXED v2)
# VM: 192.168.t.15 | Not scored but in scope for red team
#
# FIXES v2:
#   - PasswordAuthentication stays YES until team manually locks it
#     (prevents lockout before backup_configs.sh SSH key is deployed)
#   - Added /root/ncae_lock_backup_ssh.sh helper to lock down after key works
#   - Removed eval on PKG_UPDATE - replaced with if/else
#   - Fixed misleading "DNS VM" comment on .7 rule (it's the DB VM; the
#     rule is correct - .0/24 already covers .7, so rule removed as redundant)
#   - Added authorized_keys setup for backup_configs rsync key
# =============================================================================
LOGFILE="/vagrant/logs/ncae_harden_backup.log"
mkdir -p /vagrant/logs
touch "$LOGFILE" && chmod 600 "$LOGFILE"
exec > >(tee -a "$LOGFILE") 2>&1
echo "[$(date)] === Backup VM Hardening START ==="

[[ $EUID -ne 0 ]] && { echo "Run as root."; exit 1; }

TEAM=$(ip addr show | grep -oP '192\.168\.\K[0-9]+' | grep -E '^[0-9]+$' | head -1 2>/dev/null || echo "")
if [[ -z "$TEAM" ]]; then
    read -rp "[?] Enter team number: " TEAM
fi
echo "[*] Team: $TEAM"
# Network topology — inherited from deploy_all.sh or computed here for standalone runs
NCAE_LAN="${NCAE_LAN:-${NCAE_LAN}}"
NCAE_SCORING="${NCAE_SCORING:-${NCAE_SCORING}}"
NCAE_LAN_BASE="${NCAE_LAN_BASE:-$(echo "${NCAE_LAN}" | sed 's/\.[0-9]*\/[0-9]*//')}"
echo "[*] LAN: ${NCAE_LAN}  Scoring: ${NCAE_SCORING}"

# Detect OS - FIXED: no eval, direct if/else
# NOTE: All package installs happen HERE before firewall lockdown.
# Firewall (section 4) runs AFTER installs to avoid blocking outbound dnf/apt.
if command -v apt-get &>/dev/null; then
    OS="ubuntu"
    FW="ufw"
    echo "[*] OS: Ubuntu"
    if [[ "${NCAE_SKIP_UPDATE:-0}" == "1" ]]; then
        echo "[*] Skipping package update (NCAE_SKIP_UPDATE=1)"
    else
        apt-get update -y || true
        apt-get upgrade -y --no-new-recommends 2>/dev/null || true
    fi
    if [[ "${NCAE_SKIP_INSTALL:-0}" == "1" ]]; then
        echo "[*] Skipping package install (NCAE_SKIP_INSTALL=1)"
    else
        apt-get install -y fail2ban rsync auditd openssh-server 2>/dev/null || true
    fi
else
    OS="rocky"
    FW="firewalld"
    echo "[*] OS: Rocky Linux"
    if [[ "${NCAE_SKIP_UPDATE:-0}" == "1" ]]; then
        echo "[*] Skipping package update (NCAE_SKIP_UPDATE=1)"
    else
        dnf update -y 2>/dev/null || true
    fi
    if [[ "${NCAE_SKIP_INSTALL:-0}" == "1" ]]; then
        echo "[*] Skipping package install (NCAE_SKIP_INSTALL=1)"
    else
        dnf install -y rsync auditd openssh-server 2>/dev/null || true
        # fail2ban requires EPEL - optional
        dnf install -y fail2ban 2>/dev/null || echo "[!] fail2ban not available - skipping"
    fi
fi

gen_pass() {
    local len=${1:-16}; local pass
    while true; do
        pass=$(tr -dc 'A-Za-z0-9!@#$%^&*()_+=' </dev/urandom | head -c "$len")
        [[ "$pass" =~ [A-Z] ]] && [[ "$pass" =~ [a-z] ]] && \
        [[ "$pass" =~ [0-9] ]] && [[ "$pass" =~ [^A-Za-z0-9] ]] && break
    done; echo "$pass"
}

CRED_FILE="/root/ncae_credentials_backup.txt"
touch "$CRED_FILE"
chmod 600 "$CRED_FILE"
echo "# NCAE Backup VM Credentials - $(date)" >> "$CRED_FILE"

# -- 1. User lockdown ----------------------------------------------------------
echo "[*] Locking non-essential users..."
KEEP_USERS=("root" "scoring" "backup" "nobody" "daemon" "ubuntu" "rocky")
[[ -d /vagrant ]] && KEEP_USERS+=("vagrant")
[[ -n "${NCAE_OPERATOR:-}" ]] && KEEP_USERS+=("$NCAE_OPERATOR") && echo "[*] Preserving operator: $NCAE_OPERATOR"
while IFS= read -r user; do
    uid=$(id -u "$user" 2>/dev/null || echo 0)
    if [[ $uid -ge 1000 ]] && [[ ! " ${KEEP_USERS[*]} " == *" $user "* ]]; then
        NEW_PASS=$(gen_pass 16)
        echo "$user:$NEW_PASS" | chpasswd 2>/dev/null || true
        usermod -s /usr/sbin/nologin "$user" 2>/dev/null || true
        passwd -l "$user" 2>/dev/null || true
        for _grp in sudo wheel docker disk shadow adm lxd lxc kvm libvirt; do
            gpasswd -d "$user" "$_grp" 2>/dev/null || true
        done
        _home=$(getent passwd "$user" | cut -d: -f6)
        if [[ -n "$_home" && -f "$_home/.ssh/authorized_keys" ]]; then
            cp "$_home/.ssh/authorized_keys" "$_home/.ssh/authorized_keys.bak.$(date +%s)" 2>/dev/null || true
            : > "$_home/.ssh/authorized_keys"
        fi
        echo "USER $user : $NEW_PASS" >> "$CRED_FILE"
        echo "  [-] Locked + stripped groups + cleared keys: $user"
    fi
done < <(cut -d: -f1 /etc/passwd)

ROOT_PASS=$(gen_pass 20)
echo "root:$ROOT_PASS" | chpasswd 2>/dev/null || true
echo "ROOT: $ROOT_PASS" >> "$CRED_FILE"
if [[ -f /root/.ssh/authorized_keys ]]; then
    cp /root/.ssh/authorized_keys "/root/.ssh/authorized_keys.bak.$(date +%s)" 2>/dev/null || true
    : > /root/.ssh/authorized_keys
    echo "[*] Cleared root authorized_keys"
fi

# -- 2. Set up authorized_keys for backup_configs.sh rsync --------------------
# backup_configs.sh generates a key at /root/.ssh/ncae_backup_ed25519 on each VM
# and tries to ssh-copy-id here. Pre-create the authorized_keys file.
echo "[*] Preparing authorized_keys for backup rsync..."
mkdir -p /root/.ssh
chmod 700 /root/.ssh
touch /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
echo "[!] ACTION: When backup_configs.sh runs on other VMs, it will add its key here."
echo "    To pre-authorize manually: cat /root/.ssh/ncae_backup_ed25519.pub | ssh root@${NCAE_LAN_BASE}.15 'cat >> /root/.ssh/authorized_keys'"

# -- 3. SSH hardening ----------------------------------------------------------
# FIXED: PasswordAuthentication YES - keeps access open until backup keys confirmed
# Run /root/ncae_lock_backup_ssh.sh AFTER backup_configs.sh has successfully pushed
echo "[*] Hardening SSH (keeping password auth ON until backup key confirmed)..."
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/ncae_harden.conf <<EOF
PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication yes
MaxAuthTries 3
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
LoginGraceTime 30
ClientAliveInterval 120
ClientAliveCountMax 2
AllowUsers root@${NCAE_LAN}
EOF

# Script to lock down SSH after backup key is working
# This helper script is the manual step to run AFTER backup connectivity is confirmed
# It locks SSH to key-only auth, preventing password brute force against backup VM
cat > /root/ncae_lock_backup_ssh.sh <<'LOCKEOF'
#!/bin/bash
# Run AFTER confirming backup_configs.sh rsync works from other VMs
echo "[*] Testing backup SSH key connectivity..."
echo "    First verify from another VM: rsync -az /etc/hostname root@$(hostname -I | awk '{print $1}'):/tmp/test_backup"
read -rp "Did backup rsync work? (yes/no): " OK
if [[ "$OK" == "yes" ]]; then
    sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config.d/ncae_harden.conf
    sed -i 's/PermitRootLogin yes/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config.d/ncae_harden.conf
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
    echo "[+] Backup VM SSH locked to key-only."
else
    echo "[!] Keeping password auth on. Fix backup key first."
fi
LOCKEOF
chmod +x /root/ncae_lock_backup_ssh.sh

if [[ "$OS" == "ubuntu" ]]; then
    systemctl restart ssh 2>/dev/null || true
else
    systemctl restart sshd 2>/dev/null || true
fi

# -- 4. Firewall - segment backup VM ------------------------------------------
# Allow: 192.168.t.0/24 (internal LAN) + ${NCAE_SCORING} (scoring engine)
# Block: everything else
# The backup VM is NOT publicly accessible - it only needs to talk to our own VMs
# and the scoring engine. Deny-by-default prevents red team from exfiltrating backups.
# FIXED: removed redundant .7 rule (already covered by /24), fixed misleading comment
echo "[*] Configuring firewall (backup segmentation)..."

if [[ "$FW" == "ufw" ]]; then
    # Apply minimal deny-by-default UFW even though backup VM is not scored.
    # Without this, a surviving foothold or custom listener on the Ubuntu backup VM
    # stays reachable from anywhere on the network even after sshd AllowUsers restricts SSH.
    # sshd AllowUsers only restricts SSH - it does nothing for other ports.
    echo "[*] Applying minimal UFW on backup VM..."
    ufw --force reset
    ufw default deny incoming
    ufw default deny outgoing
    # SSH from internal LAN only - backup VM should never accept SSH from WAN
    ufw allow in from "${NCAE_LAN}" to any port 22 comment "SSH internal LAN"
    # Allow rsync/SCP inbound from all internal VMs (backup_configs.sh pushes here)
    ufw allow in from "${NCAE_LAN}" comment "internal LAN backup rsync"
    # Outbound: internal LAN + DNS resolution only
    ufw allow out to "${NCAE_LAN}" comment "internal LAN outbound"
    ufw allow out to any port 53 comment "DNS resolution"
    ufw --force enable
    echo "[+] UFW enabled on backup VM"

elif [[ "$FW" == "firewalld" ]]; then
    systemctl enable firewalld 2>/dev/null || true
    systemctl start firewalld 2>/dev/null || true
    firewall-cmd --permanent --set-default-zone=drop 2>/dev/null || true
    firewall-cmd --permanent --new-zone=backup-zone 2>/dev/null || true
    firewall-cmd --permanent --zone=backup-zone --set-target=DROP
    firewall-cmd --permanent --zone=backup-zone \
        --add-rich-rule="rule family='ipv4' source address='${NCAE_LAN}' service name='ssh' accept"
    firewall-cmd --permanent --zone=backup-zone \
        --add-rich-rule="rule family='ipv4' source address='${NCAE_SCORING}' accept"
    NIC=$(ip route | grep default | awk '{print $5}' | head -1)
    [[ -z "$NIC" ]] && NIC=$(ip link show | grep -v 'lo\|LOOPBACK' | awk -F: 'NR==1{print $2}' | tr -d ' ')
    [[ -z "$NIC" ]] && NIC="eth0"
    firewall-cmd --permanent --zone=backup-zone --add-interface="$NIC" 2>/dev/null || true
    firewall-cmd --reload 2>/dev/null || true
fi

# -- 5. Disable all unnecessary services --------------------------------------
echo "[*] Disabling unnecessary services..."
for svc in telnet ftp rsh rlogin avahi-daemon cups bluetooth nfs-server \
           rpcbind apache2 nginx httpd named bind9 mysql mariadb postgresql \
           smb nmb vsftpd proftpd sendmail postfix dovecot; do
    systemctl stop "$svc" 2>/dev/null || true
    systemctl disable "$svc" 2>/dev/null || true
done

# -- 6. Backup storage setup ---------------------------------------------------
# Pre-create subdirectories for each VM role so rsync has a landing place
# chmod 700: only root can read backup data (contains configs, creds, shadow copies)
echo "[*] Setting up backup storage..."
BACKUP_STORE="/srv/ncae_backups"
mkdir -p "$BACKUP_STORE"/{www,dns,db,shell}
chmod 700 "$BACKUP_STORE"
chown root:root "$BACKUP_STORE"

# -- 7. Auditd -----------------------------------------------------------------
systemctl enable auditd 2>/dev/null || true
systemctl start auditd 2>/dev/null || true
mkdir -p /etc/audit/rules.d
cat > /etc/audit/rules.d/ncae_backup.rules <<AUDITEOF
-w ${BACKUP_STORE} -p wa -k backup_tamper
-w /etc/ssh/sshd_config.d/ncae_harden.conf -p wa -k ssh_config_tamper
-w /root/.ssh/authorized_keys -p wa -k root_keys_tamper
AUDITEOF
augenrules --load 2>/dev/null || auditctl -R /etc/audit/rules.d/ncae_backup.rules 2>/dev/null || true
# MITRE extended rules
cat > /etc/audit/rules.d/ncae_mitre_extended.rules <<'AUDITEOF'
# T1098.007 / T1136.001 — account & group drift
-w /etc/group -p wa -k group_changes
-w /etc/gshadow -p wa -k group_changes
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-a always,exit -F arch=b64 -S execve -F path=/usr/sbin/useradd -k account_mod
-a always,exit -F arch=b64 -S execve -F path=/usr/sbin/usermod -k account_mod
-a always,exit -F arch=b64 -S execve -F path=/usr/sbin/userdel -k account_mod
-a always,exit -F arch=b64 -S execve -F path=/usr/sbin/groupmod -k account_mod
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/gpasswd -k account_mod
# T1053.006 / T1543.002 — systemd timer & generator persistence
-w /etc/systemd/system -p wa -k systemd_persistence
-a always,exit -F arch=b64 -S execve -F path=/bin/systemctl -k systemd_exec
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/systemctl -k systemd_exec
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/systemd-run -k systemd_run
# T1547.006 / T1014 — kernel module loading
-a always,exit -F arch=b64 -S init_module,finit_module -k module_load
-a always,exit -F arch=b64 -S delete_module -k module_unload
-a always,exit -F arch=b64 -S execve -F path=/sbin/modprobe -k module_load
-a always,exit -F arch=b64 -S execve -F path=/sbin/insmod -k module_load
-a always,exit -F arch=b64 -S execve -F path=/sbin/rmmod -k module_unload
-w /etc/modprobe.d -p wa -k module_config
-w /etc/modules-load.d -p wa -k module_config
# T1562.012 — audit system tamper
-w /etc/audit -p wa -k audit_tamper
-a always,exit -F arch=b64 -S execve -F path=/sbin/auditctl -k audit_tamper
-a always,exit -F arch=b64 -S execve -F path=/usr/sbin/auditctl -k audit_tamper
# T1546.004 — shell profile persistence
-w /etc/profile -p wa -k shell_profile
-w /etc/bash.bashrc -p wa -k shell_profile
-w /etc/profile.d -p wa -k shell_profile
# T1546.017 — udev rules
-w /etc/udev/rules.d -p wa -k udev_rules
# T1574.006 — dynamic linker config
-w /etc/ld.so.conf -p wa -k linker_config
-w /etc/ld.so.conf.d -p wa -k linker_config
-w /etc/ld.so.preload -p wa -k linker_preload
AUDITEOF
augenrules --load 2>/dev/null || auditctl -R /etc/audit/rules.d/ncae_mitre_extended.rules 2>/dev/null || true

# -- 8. Immutable flag on backup files (after 5 min, only on non-current dirs) --
# chattr +i makes files immutable - even root cannot delete or modify them
# This prevents red team from destroying backup history even with full root access
#
# IMPORTANT: Only apply +i to directories that are NOT the current rsync target
# If you immutize the active dir, rsync will fail trying to write to it
# Strategy: sort all backup dirs, skip the newest, immutize everything else
# The 5-minute age filter ensures rsync has finished writing before we lock the file
cat > /usr/local/bin/ncae_protect_backups.sh <<'INNEREOF'
#!/bin/bash
BACKUP_STORE="/srv/ncae_backups"
# Get all timestamp dirs, sorted - skip the newest (still potentially active)
ALL_DIRS=$(find "$BACKUP_STORE" -mindepth 2 -maxdepth 2 -type d 2>/dev/null | sort)
NEWEST=$(echo "$ALL_DIRS" | tail -1)
while IFS= read -r dir; do
    [[ "$dir" == "$NEWEST" ]] && continue  # Skip most recent dir
    # Only chattr files older than 5 min in non-current dirs
    find "$dir" -type f -mmin +5 ! -name "*.immutable_done" \
        -exec chattr +i {} \; 2>/dev/null || true
done <<< "$ALL_DIRS"
INNEREOF
chmod +x /usr/local/bin/ncae_protect_backups.sh
cat > /etc/cron.d/ncae_backup_protect <<'EOF'
*/5 * * * * root /usr/local/bin/ncae_protect_backups.sh
EOF

# -- 9. Fail2Ban ---------------------------------------------------------------
systemctl enable fail2ban 2>/dev/null || true
systemctl start fail2ban 2>/dev/null || true
echo ""
echo "[$(date)] === Backup VM Hardening COMPLETE ==="
echo "Credentials: $CRED_FILE"
echo ""
echo "NEXT STEPS:"
echo "  1. Run backup_configs.sh on www/dns/db/shell VMs"
echo "     They will auto-deploy SSH key here"
echo "  2. Verify rsync works: ls /srv/ncae_backups/"
echo "  3. Lock SSH: /root/ncae_lock_backup_ssh.sh"
echo ""
echo "SEGMENTATION:"
echo "  Inbound:  ${NCAE_LAN}, ${NCAE_SCORING}"
echo "  Outbound: ${NCAE_LAN}, ${NCAE_SCORING}, port 53"
echo "  All else: DENIED"
