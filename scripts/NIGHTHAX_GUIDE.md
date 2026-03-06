# NightHax v4 — Competition Day Guide
**NCAE Cyber Games 2026 | Team 56 | March 7, 2026**

---

## Quick Start

```bash
# Copy scripts to each VM from USB
sudo mkdir -p /opt/ncae
sudo cp -r /media/usb/nighthax/* /opt/ncae/
sudo chmod +x /opt/ncae/*.sh

# Run deploy_all on each VM (auto-detects role)
sudo bash /opt/ncae/deploy_all.sh

# Start monitor in tmux
sudo tmux new -s monitor
sudo bash /opt/ncae/monitor.sh
# Ctrl+B then D to detach
```

---

## VM Reference

| VM     | IP             | Script                | Points |
|--------|----------------|-----------------------|--------|
| www    | 192.168.t.5    | harden_www.sh         | 3500   |
| db     | 192.168.t.7    | harden_db.sh          | 2000   |
| dns    | 192.168.t.12   | harden_dns.sh         | 2000   |
| shell  | 192.168.t.14   | harden_shell_smb.sh   | 3500   |
| backup | 192.168.t.15   | harden_backup.sh      | 0      |
| router | MikroTik       | harden_router.sh      | -      |

---

## Script Walkthroughs

---

### 00_recon.sh
**Purpose:** Snapshot the VM state before hardening. Run first on every VM.

**What it does:**
- Lists open ports, running services, active users
- Checks for SUID binaries, world-writable files
- Saves output to /vagrant/logs/

**How to run:**
```bash
sudo bash /opt/ncae/00_recon.sh
```

**When to use:** First thing on every VM before touching anything else.

---

### deploy_all.sh
**Purpose:** Runs all hardening scripts in the correct order for the detected VM role.

**What it does:**
- Auto-detects VM role from IP address
- Runs 00_recon, then the appropriate harden script, then backup_configs
- Starts monitor in tmux
- Saves credentials to /root/ncae_credentials_<role>.txt

**How to run:**
```bash
sudo bash /opt/ncae/deploy_all.sh
# If role not detected, enter manually: www | dns | db | shell | backup | router
```

**When to use:** Competition start — run this on every VM in the first 10 minutes.

**Check credentials after:**
```bash
sudo cat /root/ncae_credentials_www.txt   # replace www with role
```

---

### harden_www.sh
**Purpose:** Harden the web server VM. Ubuntu 24.04. Apache2 + SSL.

**What it does:**
- Updates packages, installs Apache, OpenSSL, fail2ban, auditd
- Generates self-signed SSL cert (replace with CA cert at 10:30 AM)
- Configures HTTP -> HTTPS redirect
- Sets security headers (X-Frame-Options, CSP, HSTS)
- Locks user accounts with CISA 14+ char passwords
- Sets up UFW firewall (SSH + HTTP/HTTPS from scoring subnets only)
- Installs watchdog cron to restart Apache if it goes down
- Creates web content baseline for integrity checking

**How to run:**
```bash
sudo bash /opt/ncae/harden_www.sh
```

**Scoring checklist (3500pts):**
```bash
curl -I http://192.168.t.5              # HTTP -> HTTPS redirect (500pts)
curl -Ik https://192.168.t.5            # SSL response (1500pts)
curl -sk https://192.168.t.5 | grep -i '<title>'  # Content (1500pts)
```

**At 10:30 AM — replace self-signed cert:**
```bash
# Get CA cert from 172.18.0.38, then:
sudo cp /etc/ssl/ncae/certs/server.csr /tmp/
# Submit CSR to CA, get signed cert back, copy to /etc/ssl/ncae/certs/server.crt
sudo systemctl restart apache2
```

---

### harden_db.sh
**Purpose:** Harden the database VM. Rocky Linux 9. PostgreSQL.

**What it does:**
- Updates packages, installs PostgreSQL
- Sets scram-sha-256 authentication in pg_hba.conf
- Creates scoring user and database
- Locks down PostgreSQL to local connections only
- Sets firewalld rules (SSH + PostgreSQL from internal LAN only)
- Locks user accounts

**How to run:**
```bash
sudo bash /opt/ncae/harden_db.sh
```

**Scoring checklist (2000pts):**
```bash
sudo -u postgres psql -c "\l"           # DB accessible
sudo -u postgres psql -c "\du"          # Users exist
```

---

### harden_dns.sh
**Purpose:** Harden the DNS VM. Rocky Linux 9. BIND named.

**What it does:**
- Updates packages, installs BIND
- Creates forward and reverse zone files for team56.local
- Configures recursion restricted to 192.168.t.0/24
- Sets firewalld (SSH from internal + 172.18/16, port 53 open)
- Locks user accounts

**How to run:**
```bash
sudo bash /opt/ncae/harden_dns.sh
```

**Scoring checklist (2000pts):**
```bash
dig @192.168.t.12 www.team56.local +short      # Internal forward (500pts)
dig @192.168.t.12 -x 192.168.56.5 +short       # Internal reverse (500pts)
dig @172.18.t.56 www.team56.local +short        # External forward (500pts)
dig @172.18.t.56 -x 192.168.56.5 +short        # External reverse (500pts)
```

**Router port forwards required for external scoring:**
```
/ip firewall nat add chain=dstnat in-interface=ether1 dst-port=53 protocol=tcp action=dst-nat to-addresses=192.168.56.12 to-ports=53
/ip firewall nat add chain=dstnat in-interface=ether1 dst-port=53 protocol=udp action=dst-nat to-addresses=192.168.56.12 to-ports=53
```

**Zone reload after edits:**
```bash
sudo rndc reload
```

---

### harden_shell_smb.sh
**Purpose:** Harden the shell/SMB VM. Rocky Linux 9. Samba.

**What it does:**
- Updates packages, installs Samba + samba-client
- Creates scoring user with competition password
- Sets up read and write SMB shares
- Configures SELinux contexts for shares
- Sets firewalld (SSH + SMB from 172.18/16 only)
- Locks user accounts

**How to run:**
```bash
# Set scoring password via env var to skip prompt:
NCAE_SCORING_PASS='YourPassword123!' sudo bash /opt/ncae/harden_shell_smb.sh
# Or run and enter password when prompted
sudo bash /opt/ncae/harden_shell_smb.sh
```

**At 10:30 AM — add scoring SSH pubkey:**
```bash
echo 'SCORING_PUBKEY_HERE' >> /home/scoring/.ssh/authorized_keys
sudo bash /root/ncae_lock_ssh.sh   # Lock SSH to key-only after confirming key works
```

**Scoring checklist (3500pts):**
```bash
# Get password first
sudo grep SCORING /root/ncae_credentials_shell.txt

smbclient -L //172.18.t.14 -U scoring%'<pass>'                          # SMB Login (500pts)
smbclient //172.18.t.14/write -U scoring%'<pass>' -c 'put /etc/hostname test.txt'  # SMB Write (1000pts)
smbclient //172.18.t.14/read  -U scoring%'<pass>' -c 'get readme.txt /tmp/out.txt' # SMB Read (1000pts)
# SSH Login (1000pts) — requires scoring pubkey in authorized_keys
```

**Check scoreboard at 10:30 AM for exact share names.**

---

### harden_backup.sh
**Purpose:** Harden the backup VM. Ubuntu 24.04. Not scored but protects your backups.

**What it does:**
- Locks user accounts
- Hardens SSH (password auth kept ON until backup key deployed)
- Skips UFW (not scored, SSH restricted via AllowUsers instead)
- Creates /srv/ncae_backups/{www,dns,db,shell} directories
- Sets up auditd monitoring on backup directories
- Installs immutable file protection cron

**How to run:**
```bash
sudo bash /opt/ncae/harden_backup.sh
```

**After running — lock SSH once backup_configs.sh works:**
```bash
sudo bash /root/ncae_lock_backup_ssh.sh
```

---

### backup_configs.sh
**Purpose:** Snapshot all scored service configs locally and push to backup VM every 30 min.

**What it does:**
- Generates SSH key for passwordless backup (first run only)
- Copies /etc/ssh, /etc/apache2, /etc/bind, /etc/samba, pg_hba.conf, SSL certs, web root
- Pushes to backup VM at 192.168.t.15:/srv/ncae_backups/<hostname>/<timestamp>
- Excludes shadow and credential files from remote push (local only)
- Installs cron job to run every 30 minutes

**How to run:**
```bash
sudo bash /opt/ncae/backup_configs.sh
# First run prompts for backup VM root password (one time only)
```

**Verify backup landed:**
```bash
# On backup VM
sudo ls /srv/ncae_backups/
```

---

### monitor.sh
**Purpose:** Continuous monitoring for suspicious activity. Run in tmux on every VM.

**What it does:**
- Monitors scored services (restarts if down)
- Checks for new SUID binaries every 10 min
- Alerts on unexpected external connections
- Monitors web root integrity (sha256 baseline)
- Alerts on new cron jobs
- Logs all alerts to /var/log/ncae_alerts.log

**How to run:**
```bash
sudo tmux new -s monitor
sudo bash /opt/ncae/monitor.sh
# Ctrl+B then D to detach
# Reattach: tmux attach -t ncae_monitor
```

**Check alerts:**
```bash
tail -f /var/log/ncae_alerts.log
```

**Note:** VirtualBox NAT connections (10.0.2.x) will trigger false positives in lab — ignore them.

---

### backdoor_hunt.sh
**Purpose:** One-shot scan for red team persistence mechanisms.

**What it does:**
- Scans /root for recently modified files
- Checks all authorized_keys files
- Reviews cron jobs for suspicious entries
- Checks systemd services and timers
- Scans PAM modules for backdoors
- Lists unexpected SUID binaries
- Checks /tmp, /var/tmp, /dev/shm for executables
- Scans for kernel modules (rootkits)
- Checks for web shells in /var/www
- Reviews sudoers for NOPASSWD entries

**How to run:**
```bash
sudo bash /opt/ncae/backdoor_hunt.sh
```

**When to use:** Run every 30 minutes during competition, or immediately after suspecting compromise.

**Tip:** Plant a test backdoor first to confirm it works:
```bash
echo "nc -lvp 4444 -e /bin/bash &" > /tmp/test.sh && chmod +x /tmp/test.sh
sudo bash /opt/ncae/backdoor_hunt.sh
# Should flag /tmp/test.sh
rm /tmp/test.sh
```

---

### incident_response.sh
**Purpose:** Interactive IR menu for responding to active attacks.

**How to run:**
```bash
sudo bash /opt/ncae/incident_response.sh
```

**Menu options:**

**1) Kill suspicious connections / block IP**
- Shows all established connections
- Enter attacker IP to block via firewall and kill their sessions
- Guards against blocking scoring engine (172.18.x or 192.168.x = warning)

**2) Hunt & kill reverse shells**
- Shows suspicious processes (nc, socat, bash -i, python -c)
- Shows non-service established connections
- Enter PID to kill

**3) Remove web shells**
- Scans /var/www for eval, base64_decode, exec, system calls
- Shows suspicious files, confirm to delete
- Auto-restarts web server after removal

**4) Purge unauthorized SSH keys**
- Shows all authorized_keys files with contents
- WARNING: scoring user key has extra confirmation required
- Backs up key file before clearing

**5) Purge unauthorized cron jobs**
- Shows all cron.d entries and root crontab
- Removes non-NCAE cron files (preserves ncae_* watchdogs)

**6) Force re-harden**
- Lists available harden scripts
- Enter full path to re-run (e.g. /opt/ncae/harden_www.sh)
- Use when red team has modified configs

**7) Restore config from backup**
- Lists available backup timestamps
- Pick timestamp, then pick which config to restore
- Selection format: 1d (directory), 2f (file), a (all)
- Auto-restarts affected service after restore

**8) Emergency restart all services**
- Auto-detects installed services on current VM
- Restarts apache2, nginx, named, postgresql, smb, nmb, ssh as applicable
- Shows UP/DOWN status after restart

**9) Status snapshot**
- Shows service status, active connections, disk usage, load, recent failures

---

### harden_router.sh
**Purpose:** Harden the MikroTik CHR router.

**How to run:**
```bash
sudo bash /opt/ncae/harden_router.sh
```

**What it does:**
- Changes router admin password
- Sets firewall rules to restrict management access
- Configures NAT port forwards for external scoring
- Hardens SSH on router

**Note:** Requires MikroTik CHR. Not testable in local lab.

---

## Competition Day Timeline

### Before 10:00 AM
- [ ] Copy scripts to all VMs from USB
- [ ] Run `deploy_all.sh` on every VM
- [ ] Start monitor in tmux on every VM
- [ ] Run `backup_configs.sh` on every VM
- [ ] Verify all services are up

### At 10:30 AM (Scoreboard opens)
- [ ] Submit free CTF flag: `c2ctf{welcomeToTheCyberGames!}`
- [ ] Check exact SMB share names on scoreboard
- [ ] Add scoring SSH pubkey to /home/scoring/.ssh/authorized_keys on shell VM
- [ ] Run /root/ncae_lock_ssh.sh on shell VM
- [ ] Get CA cert from 172.18.0.38, replace self-signed cert on www VM
- [ ] Add router port forwards for external DNS scoring

### During Competition
- [ ] Check monitor alerts every 15 min: `tail -f /var/log/ncae_alerts.log`
- [ ] Run backdoor_hunt.sh every 30 min on each VM
- [ ] backup_configs.sh runs automatically every 30 min (verify occasionally)

### If Compromised
1. Run `incident_response.sh` on affected VM
2. Option 1 — block attacker IP
3. Option 2 — kill reverse shells
4. Option 3 — remove web shells
5. Option 7 — restore configs from backup
6. Option 6 — re-harden VM
7. Option 8 — restart all services
8. Verify scoring still works after recovery

---

## Credentials Location

All credentials saved to `/root/ncae_credentials_<role>.txt` (chmod 600).

```bash
sudo cat /root/ncae_credentials_www.txt
sudo cat /root/ncae_credentials_dns.txt
sudo cat /root/ncae_credentials_db.txt
sudo cat /root/ncae_credentials_shell.txt
sudo cat /root/ncae_credentials_backup.txt
```

---

## Emergency Commands

```bash
# Restart all services on current VM
sudo bash /opt/ncae/incident_response.sh  # Option 8

# Block an IP immediately
sudo ufw deny from <IP>                   # Ubuntu
sudo firewall-cmd --add-rich-rule="rule family='ipv4' source address='<IP>' reject" --permanent && sudo firewall-cmd --reload  # Rocky

# Check what's listening
ss -tunlp

# Check who's logged in
w
last | head -20

# Kill a process by PID
sudo kill -9 <PID>

# Check recent auth failures
grep "Failed password" /var/log/auth.log | tail -20      # Ubuntu
grep "Failed password" /var/log/secure | tail -20        # Rocky

# Reload DNS zone
sudo rndc reload

# Restart SMB
sudo systemctl restart smb nmb

# Check apache config
sudo apache2ctl configtest

# Check named config
sudo named-checkconf
sudo named-checkzone team56.local /var/named/team56.local.fwd
```

---

## Scoring Summary

| Service | VM | Points | Verify |
|---|---|---|---|
| WWW HTTP | www | 500 | `curl -I http://192.168.t.5` |
| WWW SSL | www | 1500 | `curl -Ik https://192.168.t.5` |
| WWW Content | www | 1500 | `curl -sk https://192.168.t.5 \| grep title` |
| DNS Int Fwd | dns | 500 | `dig @192.168.t.12 www.team56.local` |
| DNS Int Rev | dns | 500 | `dig @192.168.t.12 -x 192.168.56.5` |
| DNS Ext Fwd | dns | 500 | `dig @172.18.t.56 www.team56.local` |
| DNS Ext Rev | dns | 500 | `dig @172.18.t.56 -x 192.168.56.5` |
| SSH Login | shell | 1000 | scoring pubkey in authorized_keys |
| SMB Login | shell | 500 | `smbclient -L //172.18.t.14 -U scoring` |
| SMB Write | shell | 1000 | `smbclient //172.18.t.14/write ...` |
| SMB Read | shell | 1000 | `smbclient //172.18.t.14/read ...` |
| DB SSH | db | 1000 | scoring pubkey in authorized_keys |
| DB Login | db | 1000 | scoring engine connects to PostgreSQL |
| **TOTAL** | | **11000** | |

---

*NightHax v4 | Built by Ryker | NCAE 2026*
