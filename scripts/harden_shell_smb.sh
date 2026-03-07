#!/usr/bin/env bash
# =============================================================================
# NCAE Cyber Games 2026 - Shell / FTP Hardening (Rocky Linux 9)
# VM: 172.18.14.t (DHCP on External LAN)
# Services: SSH Login (500), FTP Content (1500), FTP Write (500)
#           => 2500pts total
#
# FIXES:
#   - Scoring password preserved unless explicitly provided
#   - Full package update skipped by default
#   - Operator account preserved automatically
#   - SSH password auth stays enabled until scoring key confirmed, then locked
#   - Firewall moved to separate script once topology is confirmed
#   - vsftpd replaces the old SMB-based shell model
#   - FTP content/write paths are created for scoring checks
#   - CISA 14+ char passwords for all local users
#   - Disk quota guard against FTP write-fill DoS
# Run as root. Re-run safe.
# =============================================================================
LOGFILE="/vagrant/logs/ncae_harden_shell.log"
mkdir -p /vagrant/logs
touch "$LOGFILE" && chmod 600 "$LOGFILE"
exec > >(tee -a "$LOGFILE") 2>&1
echo "[$(date)] === Shell/FTP Hardening START ==="

[[ $EUID -ne 0 ]] && { echo "Run as root."; exit 1; }

PRIMARY_IF="${PRIMARY_IF:-$(ip route 2>/dev/null | awk '/default/ {print $5; exit}')}"
PRIMARY_CIDR="${PRIMARY_CIDR:-$(ip -o -4 addr show dev "${PRIMARY_IF}" scope global 2>/dev/null | awk '{print $4}' | head -1)}"
PRIMARY_IP="${PRIMARY_IP:-${PRIMARY_CIDR%/*}}"
PRIMARY_NET="${PRIMARY_NET:-$(ip route show dev "${PRIMARY_IF}" 2>/dev/null | awk '/proto kernel/ {print $1; exit}')}"
[[ -z "$PRIMARY_NET" ]] && PRIMARY_NET="$PRIMARY_CIDR"

TEAM="${TEAM:-$(ip addr show | grep -oP '172\.18\.14\.\K[0-9]+' | head -1 2>/dev/null || \
                ip addr show | grep -oP '192\.168\.\K[0-9]+' | head -1 2>/dev/null || echo "1")}"

# Network topology — inherited from deploy_all.sh or computed here for standalone runs.
# If we are not clearly on the expected competition ranges, fall back to the
# currently connected management subnet so we do not lock ourselves out.
if [[ -z "${NCAE_LAN:-}" || -z "${NCAE_SCORING:-}" || -z "${NCAE_SHELL_IP:-}" ]]; then
    if [[ "$PRIMARY_IP" =~ ^172\.18\.14\.([0-9]+)$ ]]; then
        TEAM="${TEAM:-${BASH_REMATCH[1]}}"
        NCAE_LAN="${NCAE_LAN:-192.168.${TEAM}.0/24}"
        NCAE_SCORING="${NCAE_SCORING:-172.18.0.0/16}"
        NCAE_SHELL_IP="${NCAE_SHELL_IP:-172.18.14.${TEAM}}"
    else
        NCAE_LAN="${NCAE_LAN:-$PRIMARY_NET}"
        NCAE_SCORING="${NCAE_SCORING:-$PRIMARY_NET}"
        NCAE_SHELL_IP="${NCAE_SHELL_IP:-$PRIMARY_IP}"
        echo "[*] Non-competition subnet detected; using active management network ${PRIMARY_NET}"
    fi
fi

NCAE_LAN_BASE="${NCAE_LAN_BASE:-$(echo "${NCAE_LAN}" | sed 's/\.[0-9]*\/[0-9]*//')}"
echo "[*] Team: $TEAM  LAN: ${NCAE_LAN}  Scoring: ${NCAE_SCORING}"

detect_operator_user() {
    local user=""
    if [[ -n "${NCAE_OPERATOR:-}" && "${NCAE_OPERATOR}" != "root" ]]; then
        echo "$NCAE_OPERATOR"
        return
    fi
    if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
        echo "$SUDO_USER"
        return
    fi
    user=$(logname 2>/dev/null || true)
    if [[ -n "$user" && "$user" != "root" ]]; then
        echo "$user"
        return
    fi
    user=$(who 2>/dev/null | awk '$1 != "root" {print $1; exit}')
    if [[ -n "$user" && "$user" != "root" ]]; then
        echo "$user"
        return
    fi
}

OPERATOR_USER="$(detect_operator_user)"

# -- Password generator (CISA: 14+ chars, 4 complexity classes) ---------------
gen_pass() {
    local len=${1:-16}
    local pass
    while true; do
        pass=$(tr -dc 'A-Za-z0-9!@#$%^&*()_+=' </dev/urandom | head -c "$len")
        [[ "$pass" =~ [A-Z] ]] && [[ "$pass" =~ [a-z] ]] && \
        [[ "$pass" =~ [0-9] ]] && [[ "$pass" =~ [^A-Za-z0-9] ]] && break
    done
    echo "$pass"
}

CRED_FILE="/root/ncae_credentials_shell.txt"
touch "$CRED_FILE"
chmod 600 "$CRED_FILE"
echo "# NCAE Shell/FTP Credentials - $(date)" >> "$CRED_FILE"

# -- Scoring password policy ---------------------------------------------------
# SAFETY: Do not change the scoring password unless explicitly provided or we
# are creating the scoring user from scratch for a smoke test environment.
SCORING_PASS_KNOWN=0
[[ -n "${NCAE_SCORING_PASS:-}" ]] && SCORING_PASS_KNOWN=1

# -- 1. Update -----------------------------------------------------------------
# SAFETY: In a live competition, blanket package upgrades can disrupt scoring
# services or change configs unexpectedly. Default to no full-system update
# unless the operator explicitly opts in.
if [[ "${NCAE_DO_UPDATE:-0}" == "1" ]]; then
    echo "[*] Updating packages (NCAE_DO_UPDATE=1)..."
    dnf update -y
else
    echo "[*] Skipping package update by default"
    echo "    Set NCAE_DO_UPDATE=1 to perform a full dnf update"
fi

# -- 2. Install packages -------------------------------------------------------
if [[ "${NCAE_SKIP_INSTALL:-0}" == "1" ]]; then
    echo "[*] Skipping package install (NCAE_SKIP_INSTALL=1)"
else
    echo "[*] Installing packages..."
    # Core packages - must succeed
    dnf install -y vsftpd libcap curl \
        policycoreutils-python-utils quota
    # fail2ban requires EPEL - optional, skip silently if unavailable
    dnf install -y fail2ban 2>/dev/null || echo "[!] fail2ban not available (EPEL not enabled) - skipping"
fi

# -- 3. User lockdown + admin account policy ----------------------------------
echo "[*] Hardening accounts..."
KEEP_USERS=("root" "scoring" "nobody" "daemon" "dbus" "systemd-network")
[[ -d /vagrant ]] && KEEP_USERS+=("vagrant")
if [[ -n "$OPERATOR_USER" ]]; then
    KEEP_USERS+=("$OPERATOR_USER")
    echo "[*] Preserving operator: $OPERATOR_USER"
fi
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

if [[ -n "$OPERATOR_USER" && "$OPERATOR_USER" != "root" && "$OPERATOR_USER" != "scoring" ]] && id "$OPERATOR_USER" &>/dev/null; then
    echo "[*] Hardening operator account: $OPERATOR_USER"
    OPERATOR_PASS=$(gen_pass 20)
    echo "$OPERATOR_USER:$OPERATOR_PASS" | chpasswd 2>/dev/null || true
    echo "OPERATOR ${OPERATOR_USER} password: $OPERATOR_PASS" >> "$CRED_FILE"
    usermod -s /bin/bash "$OPERATOR_USER" 2>/dev/null || true
    if getent group wheel >/dev/null; then
        usermod -aG wheel "$OPERATOR_USER" 2>/dev/null || true
    elif getent group sudo >/dev/null; then
        usermod -aG sudo "$OPERATOR_USER" 2>/dev/null || true
    fi
    for _grp in docker disk shadow adm lxd lxc kvm libvirt; do
        gpasswd -d "$OPERATOR_USER" "$_grp" 2>/dev/null || true
    done
    _home=$(getent passwd "$OPERATOR_USER" | cut -d: -f6)
    if [[ -n "$_home" && -f "$_home/.ssh/authorized_keys" ]]; then
        cp "$_home/.ssh/authorized_keys" "$_home/.ssh/authorized_keys.bak.$(date +%s)" 2>/dev/null || true
        chmod 600 "$_home/.ssh/authorized_keys" 2>/dev/null || true
        chown "$OPERATOR_USER":"$OPERATOR_USER" "$_home/.ssh/authorized_keys" 2>/dev/null || true
    fi
    echo "  [+] Operator rotated, kept admin access, stripped extra privileged groups: $OPERATOR_USER"
fi

ROOT_PASS=$(gen_pass 20)
echo "root:$ROOT_PASS" | chpasswd 2>/dev/null || true
echo "ROOT password: $ROOT_PASS" >> "$CRED_FILE"
if [[ -f /root/.ssh/authorized_keys ]]; then
    cp /root/.ssh/authorized_keys "/root/.ssh/authorized_keys.bak.$(date +%s)" 2>/dev/null || true
    : > /root/.ssh/authorized_keys
    echo "[*] Cleared root authorized_keys"
fi

# -- 4. Create scoring user ----------------------------------------------------
echo "[*] Setting up scoring user..."
SCORING_CREATED=0
if ! id scoring &>/dev/null; then
    useradd -m -s /bin/bash scoring
    SCORING_CREATED=1
fi
if [[ "$SCORING_PASS_KNOWN" -eq 1 ]]; then
    echo "scoring:$NCAE_SCORING_PASS" | chpasswd
    echo "SCORING FTP/SSH password: $NCAE_SCORING_PASS" >> "$CRED_FILE"
elif [[ "$SCORING_CREATED" -eq 1 ]]; then
    NCAE_SCORING_PASS=$(gen_pass 16)
    SCORING_PASS_KNOWN=1
    echo "scoring:$NCAE_SCORING_PASS" | chpasswd
    echo "[*] Created scoring user with generated temporary password"
    echo "SCORING FTP/SSH temporary password: $NCAE_SCORING_PASS" >> "$CRED_FILE"
else
    echo "[*] Preserving existing scoring password (no NCAE_SCORING_PASS provided)"
fi

# SSH key setup for scoring
SSH_DIR="/home/scoring/.ssh"
mkdir -p "$SSH_DIR"
chmod 700 "$SSH_DIR"
chown scoring:scoring "$SSH_DIR"

# Placeholder for scoring engine public key
AUTH_KEYS="${SSH_DIR}/authorized_keys"
if [[ ! -s "$AUTH_KEYS" ]]; then
    echo "# PASTE SCORING ENGINE PUBLIC KEY HERE" > "$AUTH_KEYS"
    echo "[!!] ACTION REQUIRED: Add scoring engine SSH pubkey to $AUTH_KEYS"
    echo "     Get it from the competition scoreboard at 10:30 AM"
fi
chmod 600 "$AUTH_KEYS"
chown scoring:scoring "$AUTH_KEYS"

# -- 6. SSH hardening ---------------------------------------------------------
# STRATEGY: Keep password auth ON initially so we don't lock ourselves out
# before the scoring engine's public key is added to /home/scoring/.ssh/authorized_keys
# Run /root/ncae_lock_ssh.sh AFTER confirming the scoring key works to disable passwords
echo "[*] Hardening SSH..."
echo "[*] Keeping PasswordAuthentication YES until scoring pubkey is confirmed"
echo "    Run: sudo bash /root/ncae_lock_ssh.sh  - AFTER confirming key works"
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/ncae_harden.conf <<EOF
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication yes
MaxAuthTries 3
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
# NOTE: Do not restrict SSH by source subnet here.
# Apply network policy separately with firewall_shell_ftp.sh after the real
# admin/scoring paths are confirmed for the event environment.
EOF

# Script to disable password auth AFTER confirming key works
cat > /root/ncae_lock_ssh.sh <<'EOF'
#!/bin/bash
# Run this ONLY after confirming scoring SSH key works
echo "[*] Testing scoring SSH key..."
echo "Test this first: ssh -i <scoring_key> scoring@$(hostname -I | awk '{print $1}')"
read -rp "Did the key work? (yes/no): " confirm
if [[ "$confirm" == "yes" ]]; then
    sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config.d/ncae_harden.conf
    systemctl restart sshd
    echo "[+] Password auth disabled. Key-only from now on."
else
    echo "[!] Keeping password auth enabled. Fix the key first."
fi
EOF
chmod +x /root/ncae_lock_ssh.sh
systemctl restart sshd 2>/dev/null || true

# -- 7. FTP content/write setup ------------------------------------------------
echo "[*] Setting up FTP content..."
FTP_ROOT="/srv/ftp/scoring"
FTP_UPLOAD_DIR="${FTP_ROOT}/upload"
mkdir -p "$FTP_ROOT" "$FTP_UPLOAD_DIR"

cat > "${FTP_ROOT}/readme.txt" <<'EOF'
NCAE CyberGames 2026 - FTP content available
EOF
cat > "${FTP_ROOT}/scorefile.txt" <<'EOF'
Team operational - FTP content path active.
EOF

chown -R scoring:scoring "$FTP_ROOT"
chmod 755 "$FTP_ROOT"
chmod 775 "$FTP_UPLOAD_DIR"

# -- 8. vsftpd ---------------------------------------------------------------
echo "[*] Writing vsftpd.conf..."
cp /etc/vsftpd/vsftpd.conf "/etc/vsftpd/vsftpd.conf.bak.$(date +%s)" 2>/dev/null || true
cat > /etc/vsftpd/vsftpd.conf <<EOF
listen=YES
listen_ipv6=NO
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=022
dirmessage_enable=NO
xferlog_enable=YES
log_ftp_protocol=YES
use_localtime=YES
connect_from_port_20=YES
chroot_local_user=YES
allow_writeable_chroot=YES
userlist_enable=YES
userlist_deny=NO
userlist_file=/etc/vsftpd/user_list
pam_service_name=vsftpd
pasv_enable=YES
pasv_min_port=30000
pasv_max_port=30010
local_root=${FTP_ROOT}
EOF
printf 'scoring\n' > /etc/vsftpd/user_list

# -- 9. Start FTP --------------------------------------------------------------
echo "[*] Starting vsftpd..."
systemctl enable vsftpd 2>/dev/null || true
systemctl restart vsftpd 2>/dev/null || true

# -- 10. SELinux contexts ------------------------------------------------------
echo "[*] Setting SELinux contexts..."
semanage fcontext -a -t public_content_t "${FTP_ROOT}(/.*)?" 2>/dev/null || true
semanage fcontext -a -t public_content_rw_t "${FTP_UPLOAD_DIR}(/.*)?" 2>/dev/null || true
restorecon -Rv "$FTP_ROOT" "$FTP_UPLOAD_DIR" 2>/dev/null || true
setsebool -P ftpd_use_passive_mode on 2>/dev/null || true
setsebool -P ftp_home_dir on 2>/dev/null || true

# -- 11. Firewall --------------------------------------------------------------
echo "[*] Skipping firewall changes in host hardening by design"
echo "    Run: bash firewall_shell_ftp.sh"
echo "    only after confirming the real admin and scoring network paths."

# -- 12. Fail2Ban --------------------------------------------------------------
echo "[*] Installing Fail2Ban..."
systemctl enable fail2ban 2>/dev/null || true
systemctl start fail2ban 2>/dev/null || true
# -- 13a. Disk write DoS guard --------------------------------------------------
# Red team might flood the FTP upload path with large files to fill the disk.
echo "[*] Setting FTP upload quota guard (1GB max - alert only, no auto-delete)..."
cat > /usr/local/bin/ncae_ftp_quota_check.sh <<'QUOTAEOF'
#!/bin/bash
WRITE_DIR="/srv/ftp/scoring/upload"
SIZE=$(du -sb "$WRITE_DIR" 2>/dev/null | awk '{print $1}')
LIMIT=1073741824  # 1GB
if [[ "$SIZE" -gt "$LIMIT" ]]; then
    echo "[ALERT][$(date)] FTP upload path exceeds 1GB (${SIZE} bytes) - possible disk fill attack" \
        | tee -a /var/log/ncae_alerts.log
fi
QUOTAEOF
chmod +x /usr/local/bin/ncae_ftp_quota_check.sh
cat > /etc/cron.d/ncae_ftp_quota <<'EOF'
* * * * * root /usr/local/bin/ncae_ftp_quota_check.sh
EOF

# -- 13b. Auditd ---------------------------------------------------------------
echo "[*] Configuring auditd..."
dnf install -y audit 2>/dev/null || true
systemctl enable auditd 2>/dev/null || true
systemctl start auditd 2>/dev/null || true
mkdir -p /etc/audit/rules.d
cat > /etc/audit/rules.d/ncae_shell.rules <<'AUDITEOF'
-w /etc/vsftpd/vsftpd.conf -p wa -k ftp_config
-w /etc/vsftpd/user_list -p wa -k ftp_config
-w /srv/ftp -p wa -k ftp_content
-w /etc/ssh/sshd_config.d -p wa -k ssh_config_changes
-w /home/scoring/.ssh/authorized_keys -p wa -k scoring_keys_tamper
-w /root/.ssh/authorized_keys -p wa -k root_keys_tamper
AUDITEOF
augenrules --load 2>/dev/null || auditctl -R /etc/audit/rules.d/ncae_shell.rules 2>/dev/null || true
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

# -- 14. Watchdog cron ---------------------------------------------------------
cat > /etc/cron.d/ncae_ftp_watchdog <<'EOF'
* * * * * root systemctl is-active --quiet vsftpd || systemctl restart vsftpd 2>/dev/null
* * * * * root systemctl is-active --quiet sshd || systemctl restart sshd 2>/dev/null
EOF

echo ""
echo "[$(date)] === Shell/FTP Hardening COMPLETE ==="
echo "Credentials: $CRED_FILE"
echo ""
echo "SCORING CHECKLIST (2500pts):"
echo "  SSH Login   (500): Add scoring pubkey to $AUTH_KEYS"
echo "    -> Then run: /root/ncae_lock_ssh.sh"
echo "  Firewall    (later): run firewall_shell_ftp.sh after confirming admin/scoring subnets"
if [[ "$SCORING_PASS_KNOWN" -eq 1 ]]; then
    echo "  FTP Content (1500): curl --user scoring:\$(grep 'SCORING FTP' $CRED_FILE | awk '{print \$NF}' | tail -1) ftp://${NCAE_SHELL_IP}/readme.txt"
    echo "  FTP Write   (500):  curl -T /etc/hostname --user scoring:'<pass>' ftp://${NCAE_SHELL_IP}/upload/test.txt"
    echo "  (Password in $CRED_FILE)"
else
    echo "  FTP Content (1500): after password is known, test ftp://${NCAE_SHELL_IP}/readme.txt"
    echo "  FTP Write   (500):  after password is known, test ftp://${NCAE_SHELL_IP}/upload/"
    echo "  (Password preserved/not recorded here; use competition-provided credential)"
fi
echo ""
echo "  [!!] CHECK SCOREBOARD AT 10:30 AM for exact FTP content filenames expected by scoring engine"
