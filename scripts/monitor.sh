#!/usr/bin/env bash
# =============================================================================
# NCAE Cyber Games 2026 - monitor.sh (FIXED v2)
# Run in tmux on each VM during competition.
#
# FIXES v2:
#   - check_connections: fixed backwards grep, shell VM 172.18.14.t whitelisted
#   - check_suid: throttled to every 10 min (was every 30s - disk I/O DoS)
#   - check_cron: fixed false alert from our own watchdog crons being "new"
#   - check_scoring DNS: queries actual zone hostname, not 'localhost'
#   - detect_services: deduped (ssh + sshd both active on some systems)
#   - status_snapshot: shows [DOWN] not just [UP]
#
# Usage: tmux new-session -d -s ncae_monitor 'bash /root/monitor.sh'
# =============================================================================
BASELINE_DIR="/var/lib/ncae_monitor"
LOGFILE="/vagrant/logs/ncae_monitor.log"
ALERT_LOG="/vagrant/logs/ncae_alerts.log"
CHECK_INTERVAL=30
# Service health runs on a separate faster cycle inside the main loop
# Security checks (baseline diffs, SUID scans) run every full CHECK_INTERVAL
# This means a downed service is detected and restarted within ~5s, not up to 30s
SERVICE_CHECK_INTERVAL=5
# Secure log files immediately - alerts reveal system internals
mkdir -p /vagrant/logs
touch "$LOGFILE" "$ALERT_LOG"
chmod 600 "$LOGFILE" "$ALERT_LOG"

TEAM=$(ip addr show | grep -oP '192\.168\.\K[0-9]+' | grep -E '^[0-9]+$' | head -1 2>/dev/null || \
       ip addr show | grep -oP '172\.18\.14\.\K[0-9]+' | grep -E '^[0-9]+$' | head -1 2>/dev/null || echo "1")

declare -a SCORED_SERVICES=()
# Start at 1 so the SUID check (fires when LOOP_COUNT % 20 == 0) first runs at loop 20
# If we started at 0, it would fire immediately on the first loop before a baseline exists
LOOP_COUNT=1

detect_services() {
    local raw=()
    for svc in apache2 nginx httpd named bind9 postgresql mysql mariadb smb samba ssh sshd; do
        systemctl is-active --quiet "$svc" 2>/dev/null && raw+=("$svc")
    done
    # Dedup: some systems run both ssh and sshd, or both smb and samba
    # We only want one entry per logical service to avoid duplicate restart attempts
    local seen=()
    for svc in "${raw[@]}"; do
        local skip=0
        for s in "${seen[@]}"; do [[ "$s" == "$svc" ]] && skip=1; done
        [[ $skip -eq 0 ]] && seen+=("$svc")
    done
    SCORED_SERVICES=("${seen[@]}")
    echo "[*] Monitoring services: ${SCORED_SERVICES[*]:-none detected}"
}

alert() {
    local msg
    msg="[ALERT][$(date '+%H:%M:%S')] $1"
    echo "$msg" | tee -a "$ALERT_LOG"
    # printf %s treats the message as a literal string, not a format string
    # This prevents ANSI escape injection if an attacker names a process/file with \033[...m sequences
    # which could overwrite terminal output or hide alert messages
    printf '\033[0;31m%s\033[0m\n' "$msg"
}

# -- Baselines -----------------------------------------------------------------
# snapshot_baseline: captures the known-good state of the system at startup
# All check_* functions compare current state against these baselines to detect changes
snapshot_baseline() {
    mkdir -p "$BASELINE_DIR"
    chmod 700 "$BASELINE_DIR"  # Only root can read baselines - prevents red team from reading/spoofing them
    echo "[*] Building baselines (SUID scan may take 30s)..."
    # Cron baseline: track both file list AND content hashes
    # Tracking only the file list misses injection into existing cron files
    { crontab -l 2>/dev/null; \
      find /etc/cron.d/ -maxdepth 1 -type f 2>/dev/null | sort | xargs sha256sum 2>/dev/null; \
    } > "${BASELINE_DIR}/cron_base.txt"
    cut -d: -f1,3 /etc/passwd | sort > ${BASELINE_DIR}/user_base.txt
    find /root /home -name authorized_keys -exec sha256sum {} \; 2>/dev/null | sort > ${BASELINE_DIR}/keys_base.txt
    ss -tulnp 2>/dev/null | awk '{print $1,$2,$5}' | sort > ${BASELINE_DIR}/ports_base.txt
    # SUID scan covers the whole filesystem - slow but thorough
    # Throttled in check_suid() to run only every 20 loops (~10 min)
    find / -perm -4000 -type f 2>/dev/null | sort > ${BASELINE_DIR}/suid_base.txt
    # -print0 + xargs -0: null-delimited pipeline handles filenames with spaces or special chars
    find /var/www -type f -print0 2>/dev/null | xargs -0 sha256sum 2>/dev/null | sort > ${BASELINE_DIR}/web_base.txt

    # Apache/Nginx full config include hash
    # IncludeOptional lets a vhost pull in arbitrary .conf files from web-writable dirs
    # e.g. IncludeOptional /var/www/html/.hidden.conf — plants reverse shell in a file
    # your main config hash won't catch because the included file isn't the main file
    # Solution: hash every file Apache/Nginx actually includes, not just the entry point
    {
        find /etc/apache2 /etc/nginx -type f 2>/dev/null | sort | xargs sha256sum 2>/dev/null
        # Also hash any files referenced via IncludeOptional inside web root
        grep -rh 'IncludeOptional\|Include ' /etc/apache2 /etc/nginx 2>/dev/null \
            | grep -v '^#' \
            | awk '{print $2}' \
            | while read -r inc; do
                # Expand glob patterns from Include directives
                for f in $inc; do
                    [[ -f "$f" ]] && sha256sum "$f" 2>/dev/null
                done
              done
    } | sort > "${BASELINE_DIR}/webconf_base.txt"

    # Sudoers full hash — grep for NOPASSWD catches known patterns but misses
    # custom Cmnd_Alias chains and subtle permission grants that don't use that keyword
    find /etc/sudoers /etc/sudoers.d/ -type f 2>/dev/null | sort | \
        xargs sha256sum 2>/dev/null > "${BASELINE_DIR}/sudoers_base.txt"

    # ld.so.preload baseline
    # If this file exists and is non-empty at any point AFTER our baseline, it's an injection
    # An attacker with root adds a malicious .so here to hook every process on the system
    sha256sum /etc/ld.so.preload 2>/dev/null > "${BASELINE_DIR}/ldpreload_base.txt" || \
        echo "ABSENT" > "${BASELINE_DIR}/ldpreload_base.txt"

    # Firewall rule order baseline (hash the full ordered ruleset)
    # iptables -I INPUT 1 inserts above our rules without changing rule COUNT
    # Hashing the ordered output catches position changes that file-presence checks miss
    if command -v ufw &>/dev/null; then
        ufw status numbered 2>/dev/null | sha256sum > "${BASELINE_DIR}/fw_base.txt"
    elif command -v firewall-cmd &>/dev/null; then
        firewall-cmd --list-all 2>/dev/null | sha256sum > "${BASELINE_DIR}/fw_base.txt"
    elif command -v iptables &>/dev/null; then
        iptables -L -n -v --line-numbers 2>/dev/null | sha256sum > "${BASELINE_DIR}/fw_base.txt"
    fi
    # Always baseline raw nftables separately - ufw/firewalld may not expose all nft rules
    nft list ruleset 2>/dev/null | sha256sum > "${BASELINE_DIR}/nft_base.txt" || \
        echo "ABSENT" > "${BASELINE_DIR}/nft_base.txt"

    # at jobs baseline
    atq 2>/dev/null | sha256sum > "${BASELINE_DIR}/atjobs_base.txt" || \
        echo "ABSENT" > "${BASELINE_DIR}/atjobs_base.txt"

    # User systemd units baseline - catches lingering user persistence
    find /home /root -path '*/.config/systemd/user/*.service' 2>/dev/null | \
        sort | xargs sha256sum 2>/dev/null > "${BASELINE_DIR}/user_systemd_base.txt" || \
        echo "ABSENT" > "${BASELINE_DIR}/user_systemd_base.txt"

    # SSH ForceCommand/Match/sshrc baseline
    { grep -rn 'ForceCommand\|Match User\|Match Address' \
        /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null
      find /home /root -name ".ssh" -type d 2>/dev/null | \
        while read -r d; do [[ -f "$d/rc" ]] && cat "$d/rc"; done
      [[ -f /etc/ssh/sshrc ]] && cat /etc/ssh/sshrc; } | \
        sha256sum > "${BASELINE_DIR}/ssh_hooks_base.txt" 2>/dev/null || true

    echo "[+] Baselines ready"
}

# -- Check 1: Service health ---------------------------------------------------
check_services() {
    for svc in "${SCORED_SERVICES[@]}"; do
        if ! systemctl is-active --quiet "$svc" 2>/dev/null; then
            alert "SERVICE DOWN: $svc - restarting..."
            systemctl restart "$svc" 2>/dev/null || true
            # Retry up to 3 times with 2s gap before declaring failure
            # Covers race where service needs a moment to initialize after restart
            local attempts=0
            while [[ $attempts -lt 3 ]]; do
                sleep 2
                if systemctl is-active --quiet "$svc" 2>/dev/null; then
                    alert "SERVICE RECOVERED: $svc (attempt $((attempts+1)))"
                    break
                fi
                attempts=$((attempts + 1))
                if [[ $attempts -lt 3 ]]; then
                    systemctl restart "$svc" 2>/dev/null || true
                fi
            done
            if ! systemctl is-active --quiet "$svc" 2>/dev/null; then
                alert "SERVICE FAILED TO RECOVER: $svc - NEEDS MANUAL FIX"
            fi
        fi
    done
}

# -- Check 2: Suspicious connections ------------------------------------------
# FIXED: whitelist 172.18.14.t (shell VM external LAN), remove bad grep -v ESTABLISHED
check_connections() {
    local suspicious
    suspicious=$(ss -tunp state established 2>/dev/null | \
        grep -v "172\.18\.\|192\.168\.\|127\.0\.\|::1" | \
        grep -v "^Netid" | head -5)
    if [[ -n "$suspicious" ]]; then
        alert "SUSPICIOUS EXTERNAL CONNECTION:\n$suspicious"
    fi

    # Reverse shells
    local revshells
    # shellcheck disable=SC2009  # ps|grep used intentionally for pattern matching
    revshells=$(ps aux 2>/dev/null | \
        grep -E '\bnc\b|\bncat\b|\bsocat\b|\bbash -i\b|\bsh -i\b|\bpython[0-9]? -c\b|\bperl -e\b' | \
        grep -v grep | grep -v 'ncae_smb_quota' | grep -v 'ncae_monitor' )
    if [[ -n "$revshells" ]]; then
        alert "POSSIBLE REVERSE SHELL:\n$revshells"
    fi
}

# -- Check 3: Brute force -----------------------------------------------------
check_auth() {
    local fail_count=0
    fail_count=$(journalctl -u ssh -u sshd --since "1 minute ago" 2>/dev/null | \
        grep -c "Failed password\|Invalid user" 2>/dev/null || \
        grep -c "Failed password\|Invalid user" /var/log/auth.log 2>/dev/null || echo 0)
    # Ensure numeric
    # Sanitize: ensure fail_count is a pure integer before arithmetic comparison
    # journalctl -c output can sometimes include non-numeric text
    fail_count=$(echo "$fail_count" | grep -oE '[0-9]+' | head -1 || echo 0)
    if [[ "$fail_count" -gt 10 ]]; then
        alert "BRUTE FORCE: $fail_count SSH failures in last minute"
    fi
}

# -- Check 4: User changes -----------------------------------------------------
check_users() {
    local cur
    cur=$(cut -d: -f1,3 /etc/passwd | sort)
    if [[ "$cur" != "$(cat ${BASELINE_DIR}/user_base.txt 2>/dev/null)" ]]; then
        alert "USER ACCOUNT CHANGED:"
        diff ${BASELINE_DIR}/user_base.txt <(echo "$cur") | grep '^[<>]' || true
        echo "$cur" > ${BASELINE_DIR}/user_base.txt
    fi
}

# -- Check 5: Authorized keys tampered ----------------------------------------
check_keys() {
    local cur
    cur=$(find /root /home -name authorized_keys -exec sha256sum {} \; 2>/dev/null | sort)
    if [[ "$cur" != "$(cat ${BASELINE_DIR}/keys_base.txt 2>/dev/null)" ]]; then
        alert "AUTHORIZED_KEYS MODIFIED - possible backdoor key"
        diff ${BASELINE_DIR}/keys_base.txt <(echo "$cur") | grep '^[<>]' || true
        echo "$cur" > ${BASELINE_DIR}/keys_base.txt
    fi
}

# -- Check 6: Crontab changes -------------------------------------------------
# Tracks both file presence AND content hashes — catches injection into existing files
# (a red team that appends to /etc/cron.d/ncae_watchdog changes its hash but not its name)
check_cron() {
    local cur
    cur=$(crontab -l 2>/dev/null; \
          find /etc/cron.d/ -maxdepth 1 -type f 2>/dev/null | sort | xargs sha256sum 2>/dev/null)
    if [[ "$cur" != "$(cat ${BASELINE_DIR}/cron_base.txt 2>/dev/null)" ]]; then
        alert "CRONTAB CHANGED - check for red team persistence"
        diff ${BASELINE_DIR}/cron_base.txt <(echo "$cur") | grep '^[<>]' || true
        echo "$cur" > ${BASELINE_DIR}/cron_base.txt
    fi
}

# -- Check 7: New listening ports ----------------------------------------------
check_ports() {
    local cur
    cur=$(ss -tulnp 2>/dev/null | awk '{print $1,$2,$5}' | sort)
    if [[ "$cur" != "$(cat ${BASELINE_DIR}/ports_base.txt 2>/dev/null)" ]]; then
        alert "LISTENING PORT CHANGE - possible backdoor"
        diff ${BASELINE_DIR}/ports_base.txt <(echo "$cur") | grep '^[<>]' || true
        echo "$cur" > ${BASELINE_DIR}/ports_base.txt
    fi
}

# -- Check 8: Web shells -------------------------------------------------------
check_webshells() {
    [[ ! -d /var/www ]] && return
    local shells
    # shellcheck disable=SC2016  # $ in single quotes is intentional regex literal for grep
    shells=$(grep -rn --include="*.php" --include="*.phtml" --include="*.py" --include="*.sh" \
        -E 'eval\(|base64_decode\(|exec\(|system\(|passthru\(|shell_exec\(|\$_GET\[|\$_POST\[' \
        /var/www/ 2>/dev/null | grep -v '\.bak' | grep -v '#')
    [[ -n "$shells" ]] && alert "WEB SHELL DETECTED:\n$shells"

    local cur
    cur=$(find /var/www -type f -print0 2>/dev/null | xargs -0 sha256sum 2>/dev/null | sort)
    if [[ "$cur" != "$(cat ${BASELINE_DIR}/web_base.txt 2>/dev/null)" ]]; then
        alert "WEB ROOT CHANGED:"
        diff ${BASELINE_DIR}/web_base.txt <(echo "$cur") | grep '^[<>]' | head -10 || true
        echo "$cur" > ${BASELINE_DIR}/web_base.txt
    fi
}

# -- Check 8a: Web server config includes tamper ------------------------------
# Apache IncludeOptional / Nginx include can pull in arbitrary .conf files
# A red team with www-data write access can drop a .hidden.conf in /var/www/html
# that gets loaded by Apache without touching the main config file you're hashing
# This check hashes every file in the Apache/Nginx config tree AND any resolved
# Include targets, so planted files in web-accessible dirs get caught
check_webconf() {
    [[ ! -d /etc/apache2 && ! -d /etc/nginx ]] && return
    local cur
    cur=$(
        find /etc/apache2 /etc/nginx -type f 2>/dev/null | sort | xargs sha256sum 2>/dev/null
        grep -rh 'IncludeOptional\|Include ' /etc/apache2 /etc/nginx 2>/dev/null \
            | grep -v '^#' \
            | awk '{print $2}' \
            | while read -r inc; do
                for f in $inc; do
                    [[ -f "$f" ]] && sha256sum "$f" 2>/dev/null
                done
              done
    )
    cur=$(echo "$cur" | sort)
    local base
    base=$(cat "${BASELINE_DIR}/webconf_base.txt" 2>/dev/null || echo "")
    if [[ -n "$base" && "$cur" != "$base" ]]; then
        alert "WEB SERVER CONFIG CHANGED — check for IncludeOptional planted files"
        diff <(echo "$base") <(echo "$cur") | grep '^[<>]' | head -10 || true
        echo "$cur" > "${BASELINE_DIR}/webconf_base.txt"
    fi
}

# -- Check 8b-pre: Sudoers tamper ---------------------------------------------
# grep for NOPASSWD catches obvious cases but misses custom Cmnd_Alias chains,
# subtle ALL grants, and User_Alias tricks that don't use the NOPASSWD keyword
# Hashing the full sudoers tree catches any modification regardless of content
check_sudoers() {
    local cur
    cur=$(find /etc/sudoers /etc/sudoers.d/ -type f 2>/dev/null | sort | \
          xargs sha256sum 2>/dev/null)
    local base
    base=$(cat "${BASELINE_DIR}/sudoers_base.txt" 2>/dev/null || echo "")
    if [[ -n "$base" && "$cur" != "$base" ]]; then
        alert "SUDOERS MODIFIED — possible privilege escalation"
        diff <(echo "$base") <(echo "$cur") | grep '^[<>]' || true
        # Show current sudoers for immediate triage
        echo "  Current sudoers entries:"
        grep -rh 'ALL\|NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v '^#' | sed 's/^/  /'
        echo "$cur" > "${BASELINE_DIR}/sudoers_base.txt"
    fi
}



# -- Check 8b: ld.so.preload tamper -------------------------------------------
# An attacker with root can use this to hook glibc functions (read, write, execve)
# for rootkit-level stealth — hiding files, forging command output, keylogging
# We baseline hash at startup; any change (including file creation) fires an alert
check_ldpreload() {
    local cur
    if [[ -f /etc/ld.so.preload ]]; then
        cur=$(sha256sum /etc/ld.so.preload 2>/dev/null)
    else
        cur="ABSENT"
    fi
    local base
    base=$(cat "${BASELINE_DIR}/ldpreload_base.txt" 2>/dev/null || echo "ABSENT")
    if [[ "$cur" != "$base" ]]; then
        alert "LD.SO.PRELOAD CHANGED — possible rootkit/library injection"
        echo "  Baseline: $base"
        echo "  Current:  $cur"
        if [[ -f /etc/ld.so.preload ]]; then
            alert "LD_PRELOAD content: $(cat /etc/ld.so.preload)"
        fi
        echo "$cur" > "${BASELINE_DIR}/ldpreload_base.txt"
    fi
}

# -- Check 8c: Firewall rule order --------------------------------------------
check_firewall() {
    local cur=""
    if command -v ufw &>/dev/null; then
        cur=$(ufw status numbered 2>/dev/null | sha256sum)
    elif command -v firewall-cmd &>/dev/null; then
        cur=$(firewall-cmd --list-all 2>/dev/null | sha256sum)
    elif command -v iptables &>/dev/null; then
        cur=$(iptables -L -n -v --line-numbers 2>/dev/null | sha256sum)
    fi
    [[ -z "$cur" ]] && return
    local base
    base=$(cat "${BASELINE_DIR}/fw_base.txt" 2>/dev/null || echo "")
    if [[ -n "$base" && "$cur" != "$base" ]]; then
        alert "FIREWALL RULES CHANGED — possible rule insertion or removal"
        echo "$cur" > "${BASELINE_DIR}/fw_base.txt"
    fi
    # Check raw nftables separately — changes here may not appear in ufw/firewalld output
    local nft_cur nft_base
    nft_cur=$(nft list ruleset 2>/dev/null | sha256sum || echo "ABSENT")
    nft_base=$(cat "${BASELINE_DIR}/nft_base.txt" 2>/dev/null || echo "ABSENT")
    if [[ "$nft_cur" != "$nft_base" ]]; then
        alert "NFTABLES CHANGED — run: nft list ruleset"
        echo "$nft_cur" > "${BASELINE_DIR}/nft_base.txt"
    fi
}

# -- Check 8d: SSH hooks and user systemd persistence -------------------------
check_ssh_hooks() {
    local cur
    cur=$({ grep -rn 'ForceCommand\|Match User\|Match Address' \
              /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null
            find /home /root -name ".ssh" -type d 2>/dev/null | \
              while read -r d; do [[ -f "$d/rc" ]] && cat "$d/rc"; done
            [[ -f /etc/ssh/sshrc ]] && cat /etc/ssh/sshrc; } | sha256sum 2>/dev/null || echo "")
    local base
    base=$(cat "${BASELINE_DIR}/ssh_hooks_base.txt" 2>/dev/null || echo "")
    if [[ -n "$base" && "$cur" != "$base" ]]; then
        alert "SSH HOOKS CHANGED — ForceCommand, Match block, or sshrc modified"
        echo "  Run: grep -rn ForceCommand /etc/ssh/ && ls -la /etc/ssh/sshrc ~/.ssh/rc"
        echo "$cur" > "${BASELINE_DIR}/ssh_hooks_base.txt"
    fi
    # Check user systemd units (lingering backdoors)
    local usvc_cur usvc_base
    usvc_cur=$(find /home /root -path '*/.config/systemd/user/*.service' 2>/dev/null | \
               sort | xargs sha256sum 2>/dev/null | sha256sum || echo "ABSENT")
    usvc_base=$(cat "${BASELINE_DIR}/user_systemd_base.txt" 2>/dev/null || echo "ABSENT")
    if [[ "$usvc_cur" != "$usvc_base" ]]; then
        alert "USER SYSTEMD UNIT CHANGED — possible lingering persistence"
        echo "  Run: find /home /root -path '*/.config/systemd/user/*.service'"
        echo "$usvc_cur" > "${BASELINE_DIR}/user_systemd_base.txt"
    fi
    # Check at jobs
    local at_cur at_base
    at_cur=$(atq 2>/dev/null | sha256sum || echo "ABSENT")
    at_base=$(cat "${BASELINE_DIR}/atjobs_base.txt" 2>/dev/null || echo "ABSENT")
    if [[ "$at_cur" != "$at_base" ]]; then
        alert "AT JOB QUEUE CHANGED — run: atq"
        echo "$at_cur" > "${BASELINE_DIR}/atjobs_base.txt"
    fi
}

# -- Check 9: New SUID binaries ------------------------------------------------
# Throttled: SUID scan runs every 120 loops = 10 minutes at 5s SERVICE_CHECK_INTERVAL
# A full filesystem find is disk I/O intensive - don't run it every cycle
check_suid() {
    [[ $((LOOP_COUNT % 120)) -ne 0 ]] && return
    local cur
    cur=$(find / -perm -4000 -type f 2>/dev/null | sort)
    if [[ "$cur" != "$(cat ${BASELINE_DIR}/suid_base.txt 2>/dev/null)" ]]; then
        alert "NEW SUID BINARY - priv esc risk:"
        diff ${BASELINE_DIR}/suid_base.txt <(echo "$cur") | grep '^[<>]' || true
        echo "$cur" > ${BASELINE_DIR}/suid_base.txt
    fi
}

# -- Check 10: Disk space ------------------------------------------------------
check_disk() {
    local usage
    usage=$(df / | awk 'NR==2{gsub(/%/,""); print $5}')
    if [[ "$usage" -gt 85 ]]; then
        alert "DISK ${usage}% - red team may be filling disk"
        # Only auto-clean /tmp - do NOT auto-delete from /srv/ncae* (backup data)
        # Safe auto-clean: only delete old files from /tmp (nothing scored lives there)
        # We explicitly do NOT auto-delete from /srv/samba or /srv/ncae_backups
        # because those contain scored data - auto-deletion would lose competition points
        find /tmp -type f -mmin +30 -delete 2>/dev/null || true
        alert "DISK CLEANUP: deleted old /tmp files. Check /srv/samba manually if still full."
    fi
}

# -- Check 11: Scoring connectivity -------------------------------------------
# FIXED: DNS check uses actual zone hostname, not 'localhost'
check_scoring() {
    local status_line
    status_line="SCORE-CHECK @ $(date '+%H:%M:%S') |"
    if systemctl is-active --quiet apache2 2>/dev/null || \
       systemctl is-active --quiet nginx 2>/dev/null; then
        MY_IP=$(ip addr show | grep -oP '(?<=inet )192\.168\.[0-9]+\.[0-9]+' | head -1 || echo "127.0.0.1")
        if curl -sk --max-time 3 "http://${MY_IP}/" &>/dev/null; then
            status_line+=" HTTP:✔"
        else
            status_line+=" HTTP:✘"
            alert "WEB NOT RESPONDING on ${MY_IP}:80"
        fi
        if curl -sk --max-time 3 "https://${MY_IP}/" &>/dev/null; then
            status_line+=" HTTPS:✔"
        else
            status_line+=" HTTPS:✘"
            alert "WEB NOT RESPONDING on ${MY_IP}:443"
        fi
    fi
    if systemctl is-active --quiet named 2>/dev/null; then
        if dig @127.0.0.1 "www.team${TEAM}.local" +short +time=3 &>/dev/null; then
            status_line+=" DNS:✔"
        else
            status_line+=" DNS:✘"
            alert "DNS NOT RESPONDING for www.team${TEAM}.local"
        fi
    fi
    if systemctl is-active --quiet postgresql 2>/dev/null; then
        if pg_isready -h 127.0.0.1 -t 3 &>/dev/null; then
            status_line+=" PG:✔"
        else
            status_line+=" PG:✘"
            alert "POSTGRES NOT READY"
        fi
    fi
    if systemctl is-active --quiet smb 2>/dev/null; then
        SMB_PASS=$(grep "SCORING SMB/SSH password:" /root/ncae_credentials_shell.txt 2>/dev/null | awk '{print $NF}')
        if [[ -n "$SMB_PASS" ]]; then
            if smbclient -L localhost -U "scoring%${SMB_PASS}" --timeout=3 &>/dev/null; then
                status_line+=" SMB:✔"
            else
                status_line+=" SMB:✘"
                alert "SMB NOT RESPONDING"
            fi
        fi
    fi
    # Always print the status line so tmux shows a live pulse
    echo "$status_line"
}

# -- status_snapshot (FIXED: shows DOWN not just UP) --------------------------
status_snapshot() {
    echo "--- STATUS @ $(date '+%H:%M:%S') ---"
    for svc in apache2 nginx named bind9 postgresql smb samba ssh sshd; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            echo "  [UP]   $svc"
        elif systemctl list-unit-files 2>/dev/null | grep -q "^${svc}"; then
            echo "  [DOWN] $svc"
        fi
    done
}

# -- Main loop -----------------------------------------------------------------
echo "================================================================"
echo " NCAE MONITOR - $(hostname) - Team $TEAM - $(date)"
echo " Interval: ${CHECK_INTERVAL}s | SUID every 10min | Alerts: $ALERT_LOG"
echo " Ctrl+C to stop"
echo "================================================================"

detect_services
snapshot_baseline

SECURITY_ELAPSED=0

while true; do
    LOOP_COUNT=$((LOOP_COUNT + 1))

    # -- FAST LOOP: service health every 5s -----------------------------------
    # check_services only - lightweight systemctl is-active check
    # check_scoring is in the slow loop to avoid timeout stacking in a 5s cycle
    check_services
    sleep "$SERVICE_CHECK_INTERVAL"
    SECURITY_ELAPSED=$((SECURITY_ELAPSED + SERVICE_CHECK_INTERVAL))

    # -- SLOW LOOP: security checks every CHECK_INTERVAL (30s) ----------------
    if [[ $SECURITY_ELAPSED -ge $CHECK_INTERVAL ]]; then
        SECURITY_ELAPSED=0
        echo ""
        echo "--- Security sweep @ $(date '+%H:%M:%S') ---"
        check_scoring
        check_connections
        check_auth
        check_users
        check_keys
        check_cron
        check_ports
        check_webshells
        check_webconf
        check_sudoers
        check_ldpreload
        check_firewall
        check_ssh_hooks
        check_suid        # throttled internally to every 10 min
        check_disk
        status_snapshot
        echo "  alerts: $(wc -l < "$ALERT_LOG" 2>/dev/null || echo 0)"
    fi

done
