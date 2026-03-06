#!/usr/bin/env bash
# =============================================================================
# NCAE Cyber Games 2026 - 00_recon.sh
# Run this FIRST on every VM the moment you get access.
# Outputs a full picture of what you're defending before touching anything.
#
# All output is tee'd to a timestamped log file so you can review later.
# =============================================================================

# Redirect all stdout + stderr to a timestamped log, and also print to terminal
LOGFILE="/vagrant/logs/ncae_recon_$(hostname)_$(date +%Y%m%d_%H%M%S).log"
mkdir -p /vagrant/logs
exec > >(tee -a "$LOGFILE") 2>&1
chmod 600 "$LOGFILE" 2>/dev/null || true  # Lock down immediately - log may contain shadow hashes, key material

echo "================================================================"
echo " NCAE RECON - $(hostname) - $(date)"
echo "================================================================"

# -- Network identity ----------------------------------------------------------
# Shows all IPs on all interfaces - tells you what subnet you're on and confirms
# which VM you're on (www=.5, db=.7, dns=.12, shell=172.18.14.t, backup=.15)
echo ""
echo "[ NETWORK INTERFACES ]"
ip addr show
echo ""
echo "[ ROUTING TABLE ]"
ip route show
echo ""
# ARP table - shows other hosts that have recently communicated with this VM
# Useful for spotting unexpected devices on the subnet
echo "[ ARP / NEIGHBORS ]"
ip neigh show

# -- Open ports / listening services ------------------------------------------
# -t=TCP -u=UDP -l=listening -n=no DNS resolution -p=show process name
# This is the most important recon step: anything listening that shouldn't be is a risk
echo ""
echo "[ LISTENING PORTS ]"
ss -tulnp

# -- Running services ----------------------------------------------------------
# Grep for known scored/risky services so we don't miss something running
# unexpectedly. Red team may have started a backdoor service.
echo ""
echo "[ ACTIVE SERVICES ]"
systemctl list-units --type=service --state=running --no-pager | \
    grep -E "ssh|ftp|http|apache|nginx|mysql|mariadb|postgres|bind|named|smb|samba|dns|vsftpd|proftpd"

# All enabled services - anything here survives reboots
echo ""
echo "[ ALL ENABLED SERVICES ]"
systemctl list-unit-files --state=enabled --no-pager

# -- User accounts -------------------------------------------------------------
# Users with real shells can log in - should only be root + scoring on most VMs
# /nologin and /false are safe - they can't get a shell even with valid credentials
echo ""
echo "[ USER ACCOUNTS WITH LOGIN SHELLS ]"
grep -v '/nologin\|/false\|/sync\|/halt\|/shutdown' /etc/passwd

# UID >= 1000 are human/competition accounts; UID 65534 is typically 'nobody'
echo ""
echo "[ USERS WITH UID >= 1000 ]"
awk -F: '$3 >= 1000 && $3 < 65534 {print $1, $3, $6, $7}' /etc/passwd

# Check sudo/wheel membership - any unexpected user here is a privilege escalation risk
echo ""
echo "[ SUDO / WHEEL MEMBERS ]"
getent group sudo wheel 2>/dev/null
grep -E '^%?(sudo|wheel|admin)' /etc/sudoers /etc/sudoers.d/* 2>/dev/null || true

# Empty passwords ($2=="") or locked accounts (!!) - both are bad if unexpected
echo ""
echo "[ USERS WITH EMPTY PASSWORDS ]"
awk -F: '($2 == "" || $2 == "!!" ) {print "[!] Empty/locked: " $1}' /etc/shadow 2>/dev/null || true

# Last logins - shows if red team has already accessed the system
echo ""
echo "[ LAST LOGINS ]"
last -n 20 2>/dev/null || true

echo ""
echo "[ CURRENTLY LOGGED IN ]"
who

# -- SSH keys ------------------------------------------------------------------
# Authorized keys allow passwordless login - red team commonly plants backdoor
# keys here. Check every user home, not just root.
echo ""
echo "[ SSH AUTHORIZED_KEYS (all users) ]"
for home in /root /home/*; do
    keyfile="$home/.ssh/authorized_keys"
    if [[ -f "$keyfile" ]]; then
        echo "  [$home]:"
        cat "$keyfile"
    fi
done

# -- Crontabs -----------------------------------------------------------------
# Cron is a classic red team persistence mechanism - they add jobs that
# re-backdoor the system every minute even after you clean it up
echo ""
echo "[ CRONTABS ]"
crontab -l 2>/dev/null || echo "  (none for root)"
ls /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ 2>/dev/null
cat /etc/cron.d/* 2>/dev/null || true

# -- SUID/SGID binaries (potential escalation) --------------------------------
# SUID binaries run as their owner (usually root) regardless of who executes them
# Unexpected SUID binaries are a privilege escalation indicator
echo ""
echo "[ SUID BINARIES ]"
find / -perm -4000 -type f 2>/dev/null | grep -v proc

# -- World-writable directories ------------------------------------------------
# World-writable dirs outside /tmp can be used to plant malicious files
# or used as staging areas for privilege escalation
echo ""
echo "[ WORLD-WRITABLE DIRECTORIES ]"
find /etc /var /srv /opt /home /tmp -type d -perm -0002 2>/dev/null | grep -v '^/tmp$\|^/var/tmp$' | head -20

# -- Web root check ------------------------------------------------------------
echo ""
echo "[ WEB ROOT CONTENTS ]"
ls -la /var/www/html/ 2>/dev/null || ls -la /srv/www/ 2>/dev/null || echo "  No web root found"

# Pattern match for common PHP/Python web shell signatures
# eval() + base64_decode() together is the classic obfuscated web shell pattern
# exec/system/passthru/shell_exec all run arbitrary OS commands from PHP
echo ""
echo "[ WEB SHELL DETECTION (eval/base64/exec in web root) ]"
grep -rn --include="*.php" --include="*.phtml" --include="*.py" \
    -E 'eval\(|base64_decode\(|exec\(|system\(|passthru\(|shell_exec\(' \
    /var/www/ 2>/dev/null | head -20 || echo "  None found"

# -- Config file locations -----------------------------------------------------
# Confirms which config files exist - helps you know which services are
# installed and where to look when something breaks
echo ""
echo "[ KEY CONFIG FILES ]"
for f in /etc/ssh/sshd_config /etc/apache2/apache2.conf /etc/nginx/nginx.conf \
          /etc/named.conf /etc/samba/smb.conf \
          /etc/postgresql/*/main/postgresql.conf \
          /etc/postgresql/*/main/pg_hba.conf; do
    if [[ -f "$f" ]]; then echo "  EXISTS: $f"; fi
done

# -- Firewall status -----------------------------------------------------------
# Tries ufw first (Ubuntu), then firewalld (Rocky), then falls back to raw iptables
echo ""
echo "[ FIREWALL STATUS ]"
if command -v ufw &>/dev/null; then
    ufw status verbose
elif command -v firewall-cmd &>/dev/null; then
    firewall-cmd --list-all 2>/dev/null
else
    iptables -L -n 2>/dev/null | head -30
fi

# -- Network connections -------------------------------------------------------
# Shows currently established connections - active sessions right now
# Flag anything connecting to/from IPs outside 172.18.x and 192.168.t.x
echo ""
echo "[ ESTABLISHED CONNECTIONS (potential red team) ]"
ss -tunp state established

# -- OS info -------------------------------------------------------------------
echo ""
echo "[ OS / KERNEL ]"
uname -a
head -5 /etc/os-release 2>/dev/null

echo ""
echo "================================================================"
echo " RECON COMPLETE - Log: $LOGFILE"
echo "================================================================"
echo ""
echo "NEXT STEPS (priority order):"
echo "  1. Note ALL open ports above - close anything not scored"
echo "  2. Note ALL users with shells - lock everything non-scoring"
echo "  3. Check authorized_keys - remove unknown keys"
echo "  4. Check crontabs - remove red team persistence"
echo "  5. Check web root for shells"
echo "  6. Run appropriate harden_*.sh for this VM"
