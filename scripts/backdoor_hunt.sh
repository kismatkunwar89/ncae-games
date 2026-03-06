#!/usr/bin/env bash
# =============================================================================
# NCAE Cyber Games 2026 — backdoor_hunt.sh
# Team NightHax | Full persistence/backdoor sweep
#
# Covers: cron, systemd, PAM, SUID, SSH keys, shell profiles, rc.local,
#         motd, LD_PRELOAD, kernel modules, /tmp/dev/shm, web shells,
#         suspicious files in /root, bind/reverse shells, alias backdoors
#
# Run as root on every VM at competition start and after any red team activity.
# Safe to re-run. Output logged to /var/log/ncae_backdoor_hunt.log
# =============================================================================
set -uo pipefail

LOG="/vagrant/logs/ncae_backdoor_hunt.log"
FINDINGS=0
mkdir -p /vagrant/logs
exec > >(tee -a "$LOG") 2>&1

RED='\033[0;31m'
YEL='\033[1;33m'
GRN='\033[0;32m'
NC='\033[0m'

flag()  { echo -e "${RED}[!] SUSPICIOUS: $1${NC}"; FINDINGS=$((FINDINGS+1)); }
warn()  { echo -e "${YEL}[?] REVIEW:     $1${NC}"; }
ok()    { echo -e "${GRN}[+] CLEAN:      $1${NC}"; }
head()  { echo -e "\n========== $1 =========="; }

echo "======================================================"
echo " NCAE Backdoor Hunt — $(date)"
echo " Host: $(hostname) | $(id)"
echo "======================================================"

# ── 1. ROOT FILES ─────────────────────────────────────────────────────────────
head "ROOT HOME FILES"
echo "[*] Files in /root modified in last 7 days:"
find /root -maxdepth 3 -type f -newer /root/.bashrc 2>/dev/null \
  | grep -v -E '\.(log|hist)$' \
  | while read -r f; do
      warn "$f  (mtime: $(stat -c '%y' "$f" 2>/dev/null))"
    done

echo "[*] Checking /root/.ssh/authorized_keys:"
if [[ -f /root/.ssh/authorized_keys ]]; then
    while IFS= read -r line; do
        [[ -z "$line" || "$line" == \#* ]] && continue
        comment=$(echo "$line" | awk '{print $NF}')
        warn "Key found → $comment"
        # Forced-command check on root keys specifically
        if echo "$line" | grep -qE '^command='; then
            flag "FORCED-COMMAND on root key → $comment (reverse shell risk)"
        fi
    done < /root/.ssh/authorized_keys
else
    ok "No /root authorized_keys"
fi

# ── 2. ALL USER AUTHORIZED_KEYS ───────────────────────────────────────────────
head "SSH AUTHORIZED_KEYS — ALL USERS"
while IFS=: read -r user _ uid _ _ homedir _; do
    [[ $uid -lt 500 && $uid -ne 0 ]] && continue
    keyfile="$homedir/.ssh/authorized_keys"
    [[ ! -f "$keyfile" ]] && continue
    count=$(grep -vc '^\s*#\|^\s*$' "$keyfile" 2>/dev/null || true)
    warn "User $user has $count key(s) in $keyfile"
    grep -v '^\s*#\|^\s*$' "$keyfile" | awk '{print "  KEY:", $NF}'
    # Check for forced-command keys — these execute arbitrary commands on SSH connect
    # regardless of what the client requests. Pattern: command="..." ssh-rsa AAAA...
    # Red teams use this to plant persistent reverse shells that fire on every SSH login
    # even after the backdoor process is killed, as long as the key stays in the file.
    if grep -qE '^command=' "$keyfile" 2>/dev/null; then
        flag "FORCED-COMMAND key in $keyfile — executes arbitrary command on SSH connect"
        grep -nE '^command=' "$keyfile" | sed 's/^/  /'
    fi
done < /etc/passwd

# ── 3. CRON JOBS ──────────────────────────────────────────────────────────────
head "CRON JOBS"

echo "[*] /etc/crontab:"
if grep -vE '^\s*#|^\s*$' /etc/crontab 2>/dev/null | grep -v 'run-parts\|anacron'; then
    flag "Non-standard entries in /etc/crontab (see above)"
else
    ok "/etc/crontab looks standard"
fi

echo "[*] /etc/cron.d/ entries:"
for f in /etc/cron.d/*; do
    [[ ! -f "$f" ]] && continue
    suspicious=$(grep -vE '^\s*#|^\s*$' "$f" 2>/dev/null | grep -vE 'run-parts|0anacron' || true)
    if [[ -n "$suspicious" ]]; then
        flag "$f contains: $suspicious"
    fi
done

echo "[*] User crontabs:"
while IFS= read -r user; do
    ctab=$(crontab -u "$user" -l 2>/dev/null | grep -vE '^\s*#|^\s*$' || true)
    if [[ -n "$ctab" ]]; then
        flag "Crontab for $user: $ctab"
    fi
done < <(cut -d: -f1 /etc/passwd)

echo "[*] /etc/cron.{hourly,daily,weekly,monthly} executables:"
for dir in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
    find "$dir" -type f -executable 2>/dev/null | while read -r f; do
        warn "$f (verify it's legitimate)"
    done
done

# ── 4. SYSTEMD SERVICES & TIMERS ─────────────────────────────────────────────
head "SYSTEMD — SUSPICIOUS SERVICES & TIMERS"

echo "[*] Services added/modified in last 7 days:"
find /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system \
     -type f -name '*.service' -newer /etc/hostname 2>/dev/null \
  | while read -r f; do
      flag "Recently modified service: $f"
      grep -E 'ExecStart|ExecStartPre|ExecStop' "$f" | sed 's/^/    /'
    done

echo "[*] Active timers (look for unexpected ones):"
systemctl list-timers --all 2>/dev/null | grep -v 'ACTIVATES\|---\|^$' \
  | awk '{print "  " $0}' \
  | grep -vE 'apt|dpkg|fwupd|systemd|logrotate|man-db|shadow|mlocate|e2scrub|phpsessionclean|motd|sysstat' \
  | while read -r line; do warn "$line"; done

echo "[*] Services with /tmp or /dev/shm in ExecStart:"
grep -rl 'ExecStart.*\(/tmp\|/dev/shm\|/var/tmp\)' \
    /etc/systemd/system /lib/systemd/system 2>/dev/null \
  | while read -r f; do flag "Service executes from temp path: $f"; done

echo "[*] Systemd drop-in override directories (ExecStartPre / ExecStart injection):"
# Drop-in overrides live in /etc/systemd/system/<service>.service.d/override.conf
# Red teams use these to inject ExecStartPre commands that run before the real service starts
# without modifying the main .service file — so file-mtime checks on the main unit miss it
find /etc/systemd/system -type d -name '*.service.d' 2>/dev/null | while read -r dropdir; do
    find "$dropdir" -type f -name '*.conf' 2>/dev/null | while read -r override; do
        warn "Drop-in found: $override"
        # Flag if the override contains executable directives
        if grep -qE '^\s*(ExecStart|ExecStartPre|ExecStop|ExecStopPost|ExecReload)\s*=' "$override" 2>/dev/null; then
            flag "Drop-in $override modifies exec chain:"
            grep -E '^\s*(ExecStart|ExecStartPre|ExecStop|ExecStopPost|ExecReload)\s*=' "$override" | sed 's/^/  /'
        fi
    done
done

# ── 5. PAM MODULES ────────────────────────────────────────────────────────────
head "PAM MODULE INTEGRITY"

PAM_SO=$(find /lib/security /lib/x86_64-linux-gnu/security \
              /lib64/security /usr/lib/security \
              -name 'pam_unix.so' 2>/dev/null | head -1)

if [[ -n "$PAM_SO" ]]; then
    echo "[*] Checking pam_unix.so for hardcoded passwords:"
    if strings "$PAM_SO" 2>/dev/null | grep -qiE '(password|pass|secret|backdoor|ncae|hack)'; then
        flag "Suspicious strings in pam_unix.so — may be patched PAM backdoor"
        strings "$PAM_SO" | grep -iE '(password|pass|secret|backdoor|ncae|hack)' | head -10 | sed 's/^/  /'
    else
        ok "pam_unix.so strings look clean"
    fi
else
    warn "Could not locate pam_unix.so"
fi

echo "[*] Checking for pam_exec entries (can run arbitrary scripts on auth):"
if grep -rE 'pam_exec' /etc/pam.d/ 2>/dev/null; then
    flag "pam_exec found in PAM config — verify script is legitimate"
else
    ok "No pam_exec in /etc/pam.d/"
fi

echo "[*] /etc/pam.d/ files modified recently:"
find /etc/pam.d -newer /etc/hostname -type f 2>/dev/null \
  | while read -r f; do flag "Recently modified PAM config: $f"; done

# ── 5b. LINUX CAPABILITIES ────────────────────────────────────────────────────
head "LINUX CAPABILITIES (cap_setuid / cap_dac_override)"

echo "[*] Scanning all files for elevated capabilities:"
if command -v getcap &>/dev/null; then
    # getcap -r / recursively scans the entire filesystem for capability-enabled binaries
    # Capabilities are a red team favorite for priv esc because they bypass SUID detection:
    # a binary with cap_setuid+ep can set UID to 0 without the SUID bit being set
    # Common dangerous caps:
    #   cap_setuid    - can change UID to root
    #   cap_dac_override - bypass file read/write/execute permission checks
    #   cap_sys_admin - broad system administration (nearly equivalent to root)
    #   cap_net_raw   - raw socket access (packet sniffing)
    DANGEROUS_CAPS="cap_setuid|cap_dac_override|cap_sys_admin|cap_net_raw|cap_chown|cap_fowner"
    CAP_OUTPUT=$(getcap -r / 2>/dev/null)
    if [[ -n "$CAP_OUTPUT" ]]; then
        while IFS= read -r line; do
            if echo "$line" | grep -qE "$DANGEROUS_CAPS"; then
                flag "DANGEROUS CAPABILITY: $line"
            else
                warn "Capability set: $line"
            fi
        done <<< "$CAP_OUTPUT"
    else
        ok "No capability-enabled binaries found"
    fi
else
    warn "getcap not available (install libcap2-bin on Ubuntu / libcap on Rocky)"
fi

# ── 6. SUID / SGID BINARIES ───────────────────────────────────────────────────
head "SUID/SGID BINARIES"

echo "[*] All SUID binaries (review for unexpected entries):"
KNOWN_SUID=(
    /usr/bin/sudo /usr/bin/su /usr/bin/passwd /usr/bin/newgrp
    /usr/bin/chfn /usr/bin/chsh /usr/bin/gpasswd /usr/bin/mount
    /usr/bin/umount /usr/bin/pkexec /usr/lib/openssh/ssh-keysign
    /usr/lib/dbus-1.0/dbus-daemon-launch-helper /bin/su /bin/mount
    /bin/umount /usr/sbin/pam_extrausers_chkpwd
    /usr/lib/policykit-1/polkit-agent-helper-1
    /usr/bin/at /usr/bin/crontab /usr/bin/ssh-agent
    /usr/libexec/openssh/ssh-keysign
)

while IFS= read -r -d '' f; do
    known=0
    for k in "${KNOWN_SUID[@]}"; do
        [[ "$f" == "$k" ]] && { known=1; break; }
    done
    if [[ $known -eq 0 ]]; then
        flag "Unexpected SUID binary: $f  ($(stat -c '%U %G %a' "$f"))"
    fi
done < <(find / -xdev -type f -perm /4000 -print0 2>/dev/null)

# ── 7. SHELL PROFILES & STARTUP FILES ────────────────────────────────────────
head "SHELL STARTUP FILE BACKDOORS"

PROFILE_FILES=(
    /etc/profile
    /etc/bash.bashrc
    /etc/environment
    /etc/profile.d/*.sh
)

echo "[*] Checking global profiles for reverse shell indicators:"
for f in "${PROFILE_FILES[@]}"; do
    for match in $f; do
        [[ ! -f "$match" ]] && continue
        if grep -qE '(/dev/tcp|nc |ncat |bash -i|python.*socket|perl.*socket|php.*socket|/tmp/|/dev/shm/)' "$match" 2>/dev/null; then
            flag "Suspicious content in $match"
            grep -nE '(/dev/tcp|nc |ncat |bash -i|python.*socket|perl.*socket|php.*socket|/tmp/|/dev/shm/)' "$match" | sed 's/^/  /'
        fi
    done
done

echo "[*] User .bashrc / .profile backdoors:"
while IFS=: read -r user _ uid _ _ homedir _; do
    [[ $uid -lt 500 && $uid -ne 0 ]] && continue
    for dotfile in "$homedir/.bashrc" "$homedir/.profile" "$homedir/.bash_profile" "$homedir/.zshrc"; do
        [[ ! -f "$dotfile" ]] && continue
        if grep -qE '(/dev/tcp|nc |ncat |bash -i|python.*socket|perl.*socket|alias sudo|/tmp/|/dev/shm/)' "$dotfile" 2>/dev/null; then
            flag "Suspicious content in $dotfile"
            grep -nE '(/dev/tcp|nc |ncat |bash -i|python.*socket|perl.*socket|alias sudo|/tmp/|/dev/shm/)' "$dotfile" | sed 's/^/  /'
        fi
    done
done < /etc/passwd

# ── 8. RC.LOCAL & MOTD ────────────────────────────────────────────────────────
head "RC.LOCAL AND MOTD"

if [[ -f /etc/rc.local ]]; then
    content=$(grep -vE '^\s*#|^\s*$|^exit' /etc/rc.local 2>/dev/null || true)
    if [[ -n "$content" ]]; then
        flag "/etc/rc.local has active content: $content"
    else
        ok "/etc/rc.local is empty/default"
    fi
fi

echo "[*] /etc/update-motd.d/ executables:"
find /etc/update-motd.d -type f -executable 2>/dev/null | while read -r f; do
    if grep -qE '(/dev/tcp|nc |bash -i|/tmp/|/dev/shm/)' "$f" 2>/dev/null; then
        flag "Malicious MOTD script: $f"
    else
        warn "MOTD script (verify): $f"
    fi
done

# ── 9. LD_PRELOAD HOOKS ────────────────────────────────────────────────────────
head "LD_PRELOAD / LIBRARY HOOKS"

if [[ -f /etc/ld.so.preload ]]; then
    content=$(cat /etc/ld.so.preload 2>/dev/null)
    if [[ -n "$content" ]]; then
        flag "/etc/ld.so.preload is set: $content"
    fi
else
    ok "/etc/ld.so.preload not present"
fi

echo "[*] Checking LD_PRELOAD in systemd service files:"
grep -rl 'LD_PRELOAD' /etc/systemd/system /lib/systemd/system 2>/dev/null \
  | while read -r f; do flag "LD_PRELOAD in service: $f"; done

# ── 10. SUSPICIOUS FILES IN TEMP LOCATIONS ───────────────────────────────────
head "SUSPICIOUS FILES IN /tmp /var/tmp /dev/shm"

for tmpdir in /tmp /var/tmp /dev/shm; do
    echo "[*] Executables in $tmpdir:"
    find "$tmpdir" -type f -executable 2>/dev/null | while read -r f; do
        flag "Executable in $tmpdir: $f"
    done
    echo "[*] Hidden files in $tmpdir:"
    find "$tmpdir" -name '.*' 2>/dev/null | while read -r f; do
        flag "Hidden file: $f"
    done
done

# ── 11. KERNEL MODULES ────────────────────────────────────────────────────────
head "KERNEL MODULES (ROOTKIT CHECK)"

echo "[*] Non-standard kernel modules:"
lsmod 2>/dev/null | tail -n +2 | awk '{print $1}' | while read -r mod; do
    modpath=$(modinfo "$mod" 2>/dev/null | grep '^filename' | awk '{print $2}')
    if [[ -n "$modpath" ]] && echo "$modpath" | grep -qvE '^/lib/modules|^/usr/lib/modules|(builtin)'; then
        flag "Module loaded from unusual path: $mod → $modpath"
    fi
done | sort -u

# ── 12. ACTIVE NETWORK CONNECTIONS (BIND/REVERSE SHELLS) ─────────────────────
head "SUSPICIOUS NETWORK CONNECTIONS"

echo "[*] Listening on unexpected ports (not 22/80/443/53/21/3306/5432/445/139):"
ss -tlnp 2>/dev/null | grep LISTEN | awk '{print $4, $6}' | while read -r addr proc; do
    port=$(echo "$addr" | awk -F: '{print $NF}')
    if ! echo "22 80 443 53 21 3306 5432 445 139 3389" | grep -qw "$port"; then
        flag "Unexpected listener on port $port  [$proc]"
    fi
done

echo "[*] Established outbound connections to non-RFC1918 addresses:"
ss -tnp 2>/dev/null | grep ESTAB | while read -r line; do
    remote=$(echo "$line" | awk '{print $5}')
    ip=$(echo "$remote" | cut -d: -f1)
    if ! echo "$ip" | grep -qE '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1)'; then
        flag "Outbound connection to external IP: $line"
    fi
done

# ── 13. WEB SHELLS ────────────────────────────────────────────────────────────
head "WEB SHELL DETECTION"

echo "[*] Scanning /var/www for common web shell indicators:"
find /var/www -type f \( -name '*.php' -o -name '*.py' -o -name '*.pl' -o -name '*.sh' \) 2>/dev/null \
  | while read -r f; do
      # shellcheck disable=SC2016  # $_ vars are grep regex literals, not bash expansions
      if grep -qilE '(eval\s*\(|base64_decode|system\s*\(|passthru|shell_exec|exec\s*\(|popen|proc_open|\$_REQUEST|\$_GET|\$_POST.*eval)' "$f" 2>/dev/null; then
          flag "Possible web shell: $f"
          grep -niE '(eval\s*\(|base64_decode|system\s*\(|passthru|shell_exec)' "$f" | head -3 | sed 's/^/  /'
      fi
    done

# ── 14. PASSWD/SHADOW — UID 0 AND EXTRA SUDO ─────────────────────────────────
head "PASSWD / SUDO PRIVILEGE ESCALATION"

echo "[*] All UID 0 accounts:"
awk -F: '($3 == 0) {print $1}' /etc/passwd | while read -r u; do
    if [[ "$u" != "root" ]]; then
        flag "Non-root UID 0 account: $u"
    else
        ok "root UID 0 — expected"
    fi
done

echo "[*] Users in sudo/wheel group:"
getent group sudo wheel 2>/dev/null | while read -r line; do
    warn "$line"
done

echo "[*] /etc/sudoers NOPASSWD entries:"
grep -rE 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | while read -r line; do
    flag "NOPASSWD sudo: $line"
done

# ── 15. RECENTLY MODIFIED SYSTEM BINARIES ─────────────────────────────────────
head "RECENTLY MODIFIED SYSTEM BINARIES"

echo "[*] System binaries modified in last 3 days (possible binary replacement):"
find /usr/bin /usr/sbin /bin /sbin -type f -newer /etc/hostname 2>/dev/null \
  | while read -r f; do
      flag "Modified system binary: $f  ($(stat -c 'mtime: %y size: %s' "$f"))"
    done

# ── 16. USER-LEVEL PERMISSIONS AUDIT ─────────────────────────────────────────
head "USER-LEVEL PERMISSIONS AUDIT"

echo "[*] SGID binaries (group escalation — often missed):"
while IFS= read -r -d '' f; do
    warn "SGID binary: $f  ($(stat -c '%U %G %a' "$f"))"
done < <(find / -xdev -type f -perm /2000 -print0 2>/dev/null)

echo "[*] Critical file permissions:"
declare -A EXPECTED_PERMS=(
    ["/etc/passwd"]="644"
    ["/etc/shadow"]="640"
    ["/etc/group"]="644"
    ["/etc/gshadow"]="640"
    ["/etc/sudoers"]="440"
    ["/etc/ssh/sshd_config"]="600"
    ["/etc/crontab"]="644"
)
for f in "${!EXPECTED_PERMS[@]}"; do
    [[ ! -f "$f" ]] && continue
    actual=$(stat -c '%a' "$f" 2>/dev/null)
    owner=$(stat -c '%U:%G' "$f" 2>/dev/null)
    expected="${EXPECTED_PERMS[$f]}"
    if [[ "$actual" != "$expected" ]]; then
        flag "$f permissions are $actual (expected $expected) owner=$owner"
    fi
    # All critical files must be owned by root
    if [[ "$owner" != "root:root" && "$owner" != "root:shadow" && "$owner" != "root:sudo" ]]; then
        flag "$f has unexpected owner: $owner"
    fi
done

echo "[*] Dangerous group memberships (docker/disk/lxd/shadow/adm = near-root access):"
DANGEROUS_GROUPS=("docker" "disk" "lxd" "lxc" "shadow" "adm" "kvm" "libvirt")
for grp in "${DANGEROUS_GROUPS[@]}"; do
    members=$(getent group "$grp" 2>/dev/null | cut -d: -f4)
    if [[ -n "$members" ]]; then
        flag "Group '$grp' has members: $members"
    fi
done

echo "[*] Home directory permissions (should be 700 — 755 lets others read files):"
while IFS=: read -r user _ uid _ _ homedir _; do
    [[ $uid -lt 1000 || -z "$homedir" || ! -d "$homedir" ]] && continue
    perms=$(stat -c '%a' "$homedir" 2>/dev/null)
    if [[ "$perms" != "700" && "$perms" != "750" ]]; then
        flag "Home dir $homedir is $perms (user=$user) — other users may read files"
    fi
done < /etc/passwd

echo "[*] ACLs on sensitive paths (getfacl reveals permissions invisible to ls):"
if command -v getfacl &>/dev/null; then
    for path in /etc/passwd /etc/shadow /etc/sudoers /root /home; do
        acl=$(getfacl -p "$path" 2>/dev/null | grep -v '^#\|^user::\|^group::\|^other::\|^mask::' | grep -v '^$' || true)
        if [[ -n "$acl" ]]; then
            flag "ACL found on $path: $acl"
        fi
    done
else
    warn "getfacl not available (install acl package)"
fi

echo "[*] World-writable files outside /tmp (anyone can modify these):"
find /etc /var /srv /opt /home /root -type f -perm -0002 2>/dev/null \
  | grep -v '/proc\|/sys' \
  | while read -r f; do
      flag "World-writable file: $f  ($(stat -c '%U %G %a' "$f"))"
    done

echo "[*] Writable directories in root PATH (command hijacking risk):"
echo "$PATH" | tr ':' '\n' | while read -r dir; do
    [[ -z "$dir" ]] && continue
    if [[ -w "$dir" ]] && [[ "$(stat -c '%U' "$dir" 2>/dev/null)" != "root" ]]; then
        flag "Writable non-root dir in PATH: $dir"
    fi
done

# ── 17. SSH CERTIFICATE / PRINCIPAL PERSISTENCE ───────────────────────────────
head "SSH CERTIFICATE PERSISTENCE (T1098.004)"

echo "[*] TrustedUserCAKeys — any CA key here grants SSH access for all users it signs:"
if grep -rn 'TrustedUserCAKeys' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null; then
    flag "TrustedUserCAKeys is set — verify the CA file and all principals it grants access to"
    grep -rn 'TrustedUserCAKeys' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null | \
        awk '{print $2}' | while read -r cafile; do
            [[ -f "$cafile" ]] && warn "CA key file: $cafile" && cat "$cafile" | sed 's/^/  /'
        done
else
    ok "TrustedUserCAKeys not set"
fi

echo "[*] AuthorizedPrincipalsFile — overrides authorized_keys; maps cert principals to users:"
if grep -rn 'AuthorizedPrincipalsFile' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null; then
    flag "AuthorizedPrincipalsFile is set — check what principals are allowed"
    grep -rn 'AuthorizedPrincipalsFile' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null
else
    ok "AuthorizedPrincipalsFile not set"
fi

echo "[*] Scanning per-user authorized_principals files:"
while IFS=: read -r user _ uid _ _ homedir _; do
    [[ $uid -lt 500 && $uid -ne 0 ]] && continue
    pfile="$homedir/.ssh/authorized_principals"
    [[ ! -f "$pfile" ]] && continue
    flag "authorized_principals file found: $pfile"
    cat "$pfile" | sed 's/^/  principal: /'
done < /etc/passwd

echo "[*] SSH certificates in use (ssh-keygen -L to inspect):"
for home in /root /home/*; do
    for keyfile in "$home/.ssh/authorized_keys" "$home/.ssh/id_"*"-cert.pub"; do
        [[ ! -f "$keyfile" ]] && continue
        if grep -q 'cert-authority' "$keyfile" 2>/dev/null; then
            flag "cert-authority key in $keyfile — a signed cert from this CA grants access"
            grep 'cert-authority' "$keyfile" | sed 's/^/  /'
        fi
    done
done

# ── 18. CONTAINER PERSISTENCE ─────────────────────────────────────────────────
head "CONTAINER PERSISTENCE (T1543.005)"

echo "[*] Docker daemon and restart-always containers:"
if command -v docker &>/dev/null && systemctl is-active --quiet docker 2>/dev/null; then
    flag "Docker is RUNNING — unexpected on competition VMs"
    docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}' 2>/dev/null | sed 's/^/  /'
    # Restart-always containers survive reboots even without a systemd unit
    restart_always=$(docker inspect $(docker ps -q 2>/dev/null) 2>/dev/null | \
        python3 -c "import json,sys; cs=json.load(sys.stdin); [print(c['Name'],c['HostConfig']['RestartPolicy']['Name']) for c in cs]" 2>/dev/null | \
        grep -v 'no\|unless-stopped' || true)
    [[ -n "$restart_always" ]] && flag "Container with restart-always: $restart_always"
else
    ok "Docker not running"
fi

echo "[*] Podman containers and quadlets:"
if command -v podman &>/dev/null; then
    warn "Podman is installed"
    podman ps -a 2>/dev/null | grep -v '^CONTAINER' | sed 's/^/  /'
    # Podman quadlets auto-generate systemd units from ~/.config/containers/systemd/
    find /home /root -path '*/.config/containers/systemd/*' -type f 2>/dev/null | while read -r f; do
        flag "Podman quadlet (auto-systemd): $f"
    done
fi

# ── 19. SYSTEMD TIMERS & GENERATORS ──────────────────────────────────────────
head "SYSTEMD TIMERS & GENERATORS (T1053.006 / T1543.002)"

echo "[*] All .timer units — look for unexpected entries:"
find /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system \
     -name '*.timer' 2>/dev/null | while read -r f; do
    # Exclude well-known system timers from WARN output — only flag user-dropped ones
    if echo "$f" | grep -qvE '/(apt|dpkg|fwupd|logrotate|man-db|shadow|e2scrub|phpsessclean|motd|sysstat|unattended|systemd-tmpfiles|systemd-readahead)'; then
        warn "Timer: $f"
        grep -E 'OnActiveSec|OnBootSec|OnCalendar|Unit=' "$f" 2>/dev/null | sed 's/^/    /'
    fi
done

echo "[*] User-level timers (lingering persistence):"
find /home /root -path '*/.config/systemd/user/*.timer' 2>/dev/null | while read -r f; do
    flag "User timer: $f"
    cat "$f" | sed 's/^/  /'
done

echo "[*] Systemd generator paths (T1543.002 — run before normal units):"
for gendir in /etc/systemd/system-generators /usr/lib/systemd/system-generators \
              /run/systemd/generator /run/systemd/generator.early /run/systemd/generator.late; do
    if [[ -d "$gendir" ]]; then
        find "$gendir" -type f 2>/dev/null | while read -r f; do
            if echo "$gendir" | grep -q '/run/systemd/generator'; then
                flag "Runtime generator (in-memory — disappears on reboot unless seeded): $f"
            else
                warn "Generator binary: $f"
            fi
        done
    fi
done

# ── 18. UDEV RULES ────────────────────────────────────────────────────────────
head "UDEV RULES (T1546.017)"

echo "[*] Scanning udev rules for RUN+= (arbitrary command execution on device event):"
for rulesdir in /etc/udev/rules.d /run/udev/rules.d /usr/lib/udev/rules.d; do
    [[ ! -d "$rulesdir" ]] && continue
    find "$rulesdir" -name '*.rules' -type f 2>/dev/null | while read -r f; do
        if grep -qiE 'RUN\+=' "$f" 2>/dev/null; then
            flag "Udev rule with RUN+=: $f"
            grep -niE 'RUN\+=' "$f" | sed 's/^/  /'
        fi
    done
done

echo "[*] Custom rules in /etc/udev/rules.d (not from packages):"
find /etc/udev/rules.d -name '*.rules' -type f -newer /etc/hostname 2>/dev/null | while read -r f; do
    flag "Recently modified udev rule: $f"
done

# ── 19. DYNAMIC LINKER EXTENDED (T1574.006) ───────────────────────────────────
head "DYNAMIC LINKER (T1574.006)"

echo "[*] /etc/ld.so.conf and ld.so.conf.d entries:"
cat /etc/ld.so.conf 2>/dev/null | grep -v '^#\|^$' | while read -r line; do
    warn "ld.so.conf entry: $line"
done
find /etc/ld.so.conf.d -name '*.conf' -type f 2>/dev/null | while read -r f; do
    grep -v '^#\|^$' "$f" 2>/dev/null | while read -r path; do
        warn "ld.so.conf.d ($f): $path"
    done
done

echo "[*] .so files in world-writable or non-standard library paths:"
# Check for .so files outside standard system lib dirs — may indicate planted library
find /tmp /var/tmp /dev/shm /home /opt /srv \( -name '*.so' -o -name '*.so.*' \) -type f 2>/dev/null | while read -r f; do
    flag ".so file in unusual path: $f"
done

echo "[*] Recently modified .so files in system lib dirs (possible library replacement):"
find /lib /usr/lib /lib64 /usr/lib64 -name '*.so' -newer /etc/hostname -type f 2>/dev/null | while read -r f; do
    flag "Recently modified shared library: $f  ($(stat -c 'mtime: %y' "$f"))"
done

# ── 20. AUDITD INTEGRITY (T1562.012) ──────────────────────────────────────────
head "AUDITD INTEGRITY (T1562.012)"

echo "[*] Auditd service state:"
if systemctl is-active --quiet auditd 2>/dev/null; then
    ok "auditd is running"
else
    flag "AUDITD IS STOPPED — audit logging is blind"
fi

echo "[*] Current audit rules (look for -D flush or missing key rules):"
if command -v auditctl &>/dev/null; then
    rules=$(auditctl -l 2>/dev/null)
    if echo "$rules" | grep -q '\-D'; then
        flag "Audit rules have been flushed (-D present) — all watches removed"
    fi
    echo "$rules" | head -30 | sed 's/^/  /'
else
    warn "auditctl not available"
fi

echo "[*] /etc/audit/rules.d/ files:"
find /etc/audit/rules.d -type f 2>/dev/null | while read -r f; do
    warn "$f  ($(stat -c 'mtime: %y' "$f"))"
done

echo "[*] HISTFILE / shell history tampering indicators:"
# Attackers set HISTFILE=/dev/null or HISTCONTROL=ignorespace to avoid logging
for home in /root /home/*; do
    for rc in "$home/.bashrc" "$home/.bash_profile" "$home/.profile"; do
        [[ ! -f "$rc" ]] && continue
        if grep -qE 'HISTFILE\s*=\s*/dev/null|HISTCONTROL.*ignorespace|HISTSIZE\s*=\s*0|unset\s+HISTFILE' "$rc" 2>/dev/null; then
            flag "History suppression in $rc"
            grep -nE 'HISTFILE|HISTCONTROL|HISTSIZE|unset HIST' "$rc" | sed 's/^/  /'
        fi
    done
done

# ── 21. KERNEL MODULE LOAD CONFIG (T1547.006) ────────────────────────────────
head "KERNEL MODULE LOAD CONFIG (T1547.006)"

echo "[*] /etc/modules-load.d/ entries (loaded at boot):"
find /etc/modules-load.d -name '*.conf' -type f 2>/dev/null | while read -r f; do
    content=$(grep -v '^#\|^$' "$f" 2>/dev/null || true)
    if [[ -n "$content" ]]; then
        warn "$f: $content"
    fi
done

echo "[*] /etc/modprobe.d/ entries (look for 'install' overrides — run commands on modprobe):"
find /etc/modprobe.d -name '*.conf' -type f 2>/dev/null | while read -r f; do
    if grep -qiE '^\s*install\s' "$f" 2>/dev/null; then
        warn "modprobe install override in $f:"
        grep -niE '^\s*install\s' "$f" | sed 's/^/  /'
        # Flag if the install target is a script in a non-standard path
        grep -oE 'install\s+\S+\s+\S+' "$f" 2>/dev/null | while read -r _ _ target; do
            echo "$target" | grep -qvE '^(/sbin|/bin|/usr/sbin|/usr/bin)' && \
                flag "modprobe install runs non-standard binary: $target"
        done
    fi
done

echo "[*] Recently modified modprobe.d files:"
find /etc/modprobe.d /etc/modules-load.d -newer /etc/hostname -type f 2>/dev/null | while read -r f; do
    flag "Recently modified module config: $f"
done

# ── SUMMARY ───────────────────────────────────────────────────────────────────
echo ""
echo "======================================================"
if [[ $FINDINGS -gt 0 ]]; then
    echo -e "${RED} HUNT COMPLETE — $FINDINGS FINDING(S) REQUIRE ATTENTION${NC}"
    echo " Full log: $LOG"
else
    echo -e "${GRN} HUNT COMPLETE — No suspicious indicators found${NC}"
fi
echo "======================================================"
