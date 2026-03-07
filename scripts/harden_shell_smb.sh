#!/usr/bin/env bash
# =============================================================================
# NCAE Cyber Games 2026 - Shell / SMB Hardening (Rocky Linux 9)
# VM: 172.18.14.t (DHCP on External LAN)
# Services: SSH Login (1000), SMB Login (500), SMB Write (1000), SMB Read (1000)
#           => 3500pts total
#
# FIXES:
#   - Scoring password preserved unless explicitly provided
#   - Full package update skipped by default
#   - Operator account preserved automatically
#   - SSH password auth stays enabled until scoring key confirmed, then locked
#   - Firewall moved to separate script once topology is confirmed
#   - nmb made optional (may not exist on Rocky 9 minimal)
#   - Share names flagged as TBD - check scoreboard at 10:30 AM
#   - CISA 14+ char passwords for all local users
#   - Disk quota guard against write-fill DoS
# Run as root. Re-run safe.
# =============================================================================
LOGFILE="/vagrant/logs/ncae_harden_shell.log"
mkdir -p /vagrant/logs
touch "$LOGFILE" && chmod 600 "$LOGFILE"
exec > >(tee -a "$LOGFILE") 2>&1
echo "[$(date)] === Shell/SMB Hardening START ==="

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
echo "# NCAE Shell/SMB Credentials - $(date)" >> "$CRED_FILE"

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
    dnf install -y samba samba-client samba-common libcap \
        policycoreutils-python-utils quota
    # fail2ban requires EPEL - optional, skip silently if unavailable
    dnf install -y fail2ban 2>/dev/null || echo "[!] fail2ban not available (EPEL not enabled) - skipping"
fi

# -- 3. User lockdown + admin account policy ----------------------------------
echo "[*] Hardening accounts..."
KEEP_USERS=("root" "scoring" "nobody" "daemon" "samba" "dbus" "systemd-network")
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
    echo "SCORING SMB/SSH password: $NCAE_SCORING_PASS" >> "$CRED_FILE"
elif [[ "$SCORING_CREATED" -eq 1 ]]; then
    NCAE_SCORING_PASS=$(gen_pass 16)
    SCORING_PASS_KNOWN=1
    echo "scoring:$NCAE_SCORING_PASS" | chpasswd
    echo "[*] Created scoring user with generated temporary password"
    echo "SCORING SMB/SSH temporary password: $NCAE_SCORING_PASS" >> "$CRED_FILE"
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
# Apply network policy separately with firewall_shell_smb.sh after the real
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

# -- 7. SMB share setup --------------------------------------------------------
echo "[*] Setting up SMB shares..."
# NOTE: Share names below are placeholders.
# Check the competition scoreboard at 10:30 AM for exact share names the scoring engine expects.
# Common names: 'share', 'files', 'data', 'scoring', 'public'
# Update [share_name] sections in /etc/samba/smb.conf if needed.
SMB_WRITE_DIR="/srv/samba/write"
SMB_READ_DIR="/srv/samba/read"
mkdir -p "$SMB_WRITE_DIR" "$SMB_READ_DIR"

# Populate read share with scoring-expected files
cat > "$SMB_READ_DIR/readme.txt" <<'EOF'
NCAE CyberGames 2026 - UNH Blue Team
SMB Read Share - operational
EOF
cat > "$SMB_READ_DIR/scorefile.txt" <<'EOF'
Team operational - SMB read share active.
EOF

chown -R scoring:scoring "$SMB_WRITE_DIR" "$SMB_READ_DIR"
chmod 770 "$SMB_WRITE_DIR"
chmod 755 "$SMB_READ_DIR"

# SMB scoring user
# smbpasswd -a adds the user to Samba's password database (separate from /etc/shadow)
# -s reads password from stdin (non-interactive), two copies = password + confirmation
# Samba uses its own TDB password database, NOT the system /etc/shadow
if [[ "$SCORING_PASS_KNOWN" -eq 1 ]]; then
    echo -e "${NCAE_SCORING_PASS}\n${NCAE_SCORING_PASS}" | smbpasswd -s -a scoring 2>/dev/null || true
    smbpasswd -e scoring 2>/dev/null || true  # -e enables the account (it may be disabled by default)
else
    echo "[!] SMB password preserved/unknown - add scoring to Samba manually when the correct password is known:"
    echo "    smbpasswd -a scoring && smbpasswd -e scoring"
fi

# -- 8. smb.conf --------------------------------------------------------------
# SMBv2+ only (server min protocol = SMB2): disables SMBv1 which has known
# critical vulnerabilities (EternalBlue/WannaCry). Scoring engine supports SMB2+.
# ntlm auth = ntlmv2-only: disables NTLMv1 (easily cracked) and anonymous NTLM
# restrict anonymous = 2: prevents unauthenticated listing of shares
# server signing = mandatory: requires message signing, prevents MITM/relay attacks
echo "[*] Writing smb.conf..."
cp /etc/samba/smb.conf "/etc/samba/smb.conf.bak.$(date +%s)" 2>/dev/null || true

cat > /etc/samba/smb.conf <<EOF
[global]
    workgroup = NCAE
    server string = UNH Shell ${TEAM}
    netbios name = SHELL${TEAM}
    security = user
    map to guest = Never
    passdb backend = tdbsam
    log file = /var/log/samba/log.%m
    max log size = 50
    logging = file

    # Harden: SMBv2+ only
    server min protocol = SMB2
    ntlm auth = ntlmv2-only
    restrict anonymous = 2
    client signing = auto
    server signing = mandatory

# -- WRITE SHARE --------------------------------------------------------------
# [!] Rename section if scoreboard specifies a different share name
[write]
    comment = Scoring Write Share
    path = ${SMB_WRITE_DIR}
    browseable = yes
    read only = no
    writable = yes
    valid users = scoring
    create mask = 0664
    directory mask = 0775
    force user = scoring

# -- READ SHARE ---------------------------------------------------------------
# [!] Rename section if scoreboard specifies a different share name
[read]
    comment = Scoring Read Share
    path = ${SMB_READ_DIR}
    browseable = yes
    read only = yes
    valid users = scoring
    force user = scoring
EOF

# testparm validates smb.conf syntax and logic - run this after any manual edits too
testparm -s /etc/samba/smb.conf 2>/dev/null && echo "[+] smb.conf valid" || echo "[!] smb.conf invalid - check above"

# -- 9. Start Samba ------------------------------------------------------------
echo "[*] Starting Samba..."
systemctl enable smb 2>/dev/null || true
systemctl restart smb 2>/dev/null || true
# nmb may not exist on Rocky 9 minimal - optional
systemctl enable nmb 2>/dev/null || true
systemctl restart nmb 2>/dev/null || true
# -- 10. SELinux contexts ------------------------------------------------------
# SELinux on Rocky Linux enforces mandatory access control based on file labels
# samba_share_t is the correct type for files/dirs that Samba is allowed to serve
# Without this, SELinux will block Samba from reading the share dirs even though
# Unix permissions are correct. restorecon applies the labels we set with semanage.
echo "[*] Setting SELinux contexts..."
semanage fcontext -a -t samba_share_t "${SMB_WRITE_DIR}(/.*)?" 2>/dev/null || true
semanage fcontext -a -t samba_share_t "${SMB_READ_DIR}(/.*)?" 2>/dev/null || true
restorecon -Rv "$SMB_WRITE_DIR" "$SMB_READ_DIR" 2>/dev/null || true

# -- 11. Firewall --------------------------------------------------------------
echo "[*] Skipping firewall changes in host hardening by design"
echo "    Run: bash firewall_shell_smb.sh"
echo "    only after confirming the real admin and scoring network paths."

# -- 12. Fail2Ban --------------------------------------------------------------
echo "[*] Installing Fail2Ban..."
systemctl enable fail2ban 2>/dev/null || true
systemctl start fail2ban 2>/dev/null || true
# -- 13a. Disk write DoS guard --------------------------------------------------
# Red team might flood the write share with large files to fill the disk
# This fills /srv/samba/write which could crash services that write to /
# Alert-only (not auto-delete) to avoid accidentally removing scoring files
echo "[*] Setting write share quota guard (1GB max - alert only, no auto-delete)..."
cat > /usr/local/bin/ncae_smb_quota_check.sh <<'QUOTAEOF'
#!/bin/bash
WRITE_DIR="/srv/samba/write"
SIZE=$(du -sb "$WRITE_DIR" 2>/dev/null | awk '{print $1}')
LIMIT=1073741824  # 1GB
if [[ "$SIZE" -gt "$LIMIT" ]]; then
    echo "[ALERT][$(date)] SMB write share exceeds 1GB (${SIZE} bytes) - possible disk fill attack" \
        | tee -a /var/log/ncae_alerts.log
fi
QUOTAEOF
chmod +x /usr/local/bin/ncae_smb_quota_check.sh
cat > /etc/cron.d/ncae_smb_quota <<'EOF'
* * * * * root /usr/local/bin/ncae_smb_quota_check.sh
EOF

# -- 13b. Auditd ---------------------------------------------------------------
echo "[*] Configuring auditd..."
dnf install -y audit 2>/dev/null || true
systemctl enable auditd 2>/dev/null || true
systemctl start auditd 2>/dev/null || true
mkdir -p /etc/audit/rules.d
cat > /etc/audit/rules.d/ncae_shell.rules <<'AUDITEOF'
-w /etc/samba/smb.conf -p wa -k smb_config
-w /srv/samba -p wa -k smb_shares
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
cat > /etc/cron.d/ncae_smb_watchdog <<'EOF'
* * * * * root systemctl is-active --quiet smb  || systemctl restart smb 2>/dev/null
* * * * * root systemctl is-active --quiet sshd || systemctl restart sshd 2>/dev/null
EOF

echo ""
echo "[$(date)] === Shell/SMB Hardening COMPLETE ==="
echo "Credentials: $CRED_FILE"
echo ""
echo "SCORING CHECKLIST (3500pts):"
echo "  SSH Login  (1000): Add scoring pubkey to $AUTH_KEYS"
echo "    -> Then run: /root/ncae_lock_ssh.sh"
echo "  Firewall   (later): run firewall_shell_smb.sh after confirming admin/scoring subnets"
if [[ "$SCORING_PASS_KNOWN" -eq 1 ]]; then
    echo "  SMB Login  (500):  smbclient -L //${NCAE_SHELL_IP}/ -U scoring%\$(grep SCORING $CRED_FILE | awk '{print \$NF}')"
    echo "  SMB Write  (1000): smbclient //${NCAE_SHELL_IP}/write -U scoring%'<pass>' -c 'put /etc/hostname test.txt'"
    echo "  SMB Read   (1000): smbclient //${NCAE_SHELL_IP}/read  -U scoring%'<pass>' -c 'get readme.txt /tmp/readme.txt'"
    echo "  (Password in $CRED_FILE)"
else
    echo "  SMB Login  (500):  set/confirm the competition scoring password, then: smbpasswd -a scoring"
    echo "  SMB Write  (1000): after password is known, test //${NCAE_SHELL_IP}/write"
    echo "  SMB Read   (1000): after password is known, test //${NCAE_SHELL_IP}/read"
    echo "  (Password preserved/not recorded here; use competition-provided credential)"
fi
echo ""
echo "  [!!] CHECK SCOREBOARD AT 10:30 AM for exact share names expected by scoring engine"
echo "       If wrong, edit /etc/samba/smb.conf share names and: systemctl restart smb"
