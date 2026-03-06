# SHELL/FTP — Security Plan
**IP:** 172.18.14.t (directly on WAN — NO router protection)
**Points:** SSH login 500 | FTP login 500 | FTP content 1500 | FTP write 500 = **3000pts**

---

> ⚠️ HIGHEST PRIORITY VM — Directly exposed on WAN
> Red Team WILL hit this first. Harden within first 5 minutes.

---

## ⚡ PHASE 0 — CHECK (Do this FIRST)

### Suspicious Users
```bash
# List all users with shell access
cat /etc/passwd | grep -v "nologin\|false"

# Check sudo privileges
cat /etc/sudoers
getent group sudo
sudo -l

# Check recently created users
ls -la /home/
lastlog | grep -v "Never"
last | head -20
```

### Suspicious Network Connections
```bash
# Check ALL established connections
ss -tunap

# Look for outgoing connections — should have NONE
ss -tunap | grep ESTABLISHED

# Check listening ports — should only be 22 and 21
ss -tunap | grep LISTEN

# Check open files by network
lsof -i
```

### Suspicious Processes
```bash
# Check all running processes
ps aux

# Look for reverse shells
ps aux | grep -E "bash -i|nc|ncat|python|perl" | grep -v grep

# Check processes listening on unexpected ports
ss -tunap | grep -v ":22\|:21\|:20"
```

### Suspicious SSH Keys
```bash
# Check ALL authorized_keys files
for user in $(cut -d: -f1 /etc/passwd); do
    if [ -f "/home/$user/.ssh/authorized_keys" ]; then
        echo "=== $user ==="
        cat /home/$user/.ssh/authorized_keys
    fi
done

# Check root
cat /root/.ssh/authorized_keys 2>/dev/null
```

### Suspicious Cron Jobs
```bash
# Check all crontabs
crontab -l
sudo crontab -l
cat /etc/crontab
ls -la /etc/cron.*
for user in $(cut -d: -f1 /etc/passwd); do
    echo "=== $user ==="; crontab -u $user -l 2>/dev/null
done
```

### Suspicious Files
```bash
# Recently modified files (last 2 hours)
find / -mmin -120 -type f 2>/dev/null | grep -v proc

# SUID files (privilege escalation risk)
find / -perm -4000 -type f 2>/dev/null

# Hidden files in home dirs
find /home /root -name ".*" -type f 2>/dev/null

# Check FTP directory for unexpected files
ls -la /home/*/
ls -la /var/ftp/ 2>/dev/null
```

---

## 🔒 PHASE 1 — HARDEN

### iptables Rules
```bash
# Flush existing
sudo iptables -F
sudo iptables -X

# Default DROP
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

# Allow established
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow loopback
sudo iptables -A INPUT -i lo -j ACCEPT

# Allow SSH with rate limiting
sudo iptables -A INPUT -p tcp --dport 22 -m limit --limit 3/min --limit-burst 5 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 22 -j DROP

# Allow FTP
sudo iptables -A INPUT -p tcp --dport 21 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 20 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 49152:65535 -j ACCEPT

# Save rules
sudo iptables-save > /etc/iptables/rules.v4
```

### SSH Hardening
```bash
sudo nano /etc/ssh/sshd_config
```
```
PermitRootLogin no
PasswordAuthentication no
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
AllowTcpForwarding no
PermitEmptyPasswords no
LogLevel VERBOSE
```
```bash
sudo systemctl restart sshd
# TEST IN NEW TERMINAL BEFORE CLOSING!
```

### FTP Hardening
```bash
sudo nano /etc/vsftpd.conf
```
```
anonymous_enable=NO
local_enable=YES
write_enable=YES
chroot_local_user=YES
allow_writeable_chroot=YES
pasv_enable=YES
pasv_min_port=49152
pasv_max_port=65535
xferlog_enable=YES
xferlog_file=/var/log/vsftpd.log
```
```bash
sudo systemctl restart vsftpd
```

### Install Fail2ban
```bash
sudo apt install fail2ban -y

sudo cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = 22
logpath = /var/log/auth.log
maxretry = 3

[vsftpd]
enabled = true
port = ftp,ftp-data
logpath = /var/log/vsftpd.log
maxretry = 3
EOF

sudo systemctl enable fail2ban
sudo systemctl restart fail2ban
```

### Remove Suspicious Users Found in Check Phase
```bash
# Remove unknown user
sudo userdel -r <suspicious_user>

# Remove unknown SSH key
# Edit authorized_keys and remove unknown key
sudo nano /home/<user>/.ssh/authorized_keys
```

---

## 💾 PHASE 2 — BACKUP

### Crown Jewels — FTP Scoring Files
```bash
# Find FTP files
ls -la /home/*/
ls -la /var/ftp/

# Backup ALL FTP files immediately
sudo cp -r /home/ /tmp/home_backup_$(date +%H%M)/
sudo cp -r /var/ftp/ /tmp/ftp_backup_$(date +%H%M)/ 2>/dev/null

# Create integrity checksums
find /home -type f | xargs md5sum > /tmp/ftp_checksums.txt
cat /tmp/ftp_checksums.txt

# Store on Backup VM
scp -r /tmp/home_backup_* user@192.168.t.15:/backups/ftp/
```

### What to Backup
```
✅ /home/*/          — all user home dirs (FTP files)
✅ /var/ftp/         — FTP root if exists
✅ /etc/ssh/         — SSH config
✅ /etc/vsftpd.conf  — FTP config
✅ /etc/passwd       — user list
✅ /etc/iptables/    — firewall rules
```

---

## 👁️ PHASE 3 — MONITOR

### Terminal 1 — SSH Attacks
```bash
sudo tail -f /var/log/auth.log | grep --line-buffered "Failed\|Accepted\|Invalid\|Disconnected"
```

### Terminal 2 — FTP Activity
```bash
sudo tail -f /var/log/vsftpd.log
```

### Terminal 3 — Fail2ban Active Bans
```bash
watch -n 10 'sudo fail2ban-client status sshd && sudo fail2ban-client status vsftpd'
```

### Terminal 4 — File Integrity Watch
```bash
# Watch for file changes in FTP dirs
watch -n 30 'md5sum -c /tmp/ftp_checksums.txt 2>/dev/null | grep FAILED'
```

### What to Watch For
```
- Repeated failed SSH from same IP = brute force
- FTP login from unknown user = unauthorized access
- File checksum FAILED = tampering detected
- New process appearing = reverse shell
- New outgoing connection = compromise
```

---

## 🚨 PHASE 4 — RESPOND

### SSH Brute Force Detected
```bash
# Check fail2ban status
sudo fail2ban-client status sshd

# Manually ban IP if not auto-banned
sudo fail2ban-client set sshd banip <attacker_ip>

# Verify ban
sudo iptables -L -n | grep <attacker_ip>

# Log it for team
echo "[$(date)] SSH Brute Force from <attacker_ip>" >> /tmp/incident_log.txt
```

### FTP Unauthorized Access
```bash
# Check who is connected
who
w

# Kill suspicious session
sudo pkill -u <suspicious_user>

# Lock the account
sudo passwd -l <suspicious_user>

# Check what they did
sudo cat /var/log/vsftpd.log | grep <suspicious_user>
```

### File Tampering Detected
```bash
# Identify which file changed
md5sum -c /tmp/ftp_checksums.txt | grep FAILED

# Restore from backup immediately
sudo cp /tmp/home_backup_*/<filename> /home/<user>/<filename>

# Verify restored
md5sum /home/<user>/<filename>

# Log incident
echo "[$(date)] File tampered: <filename> — Restored from backup" >> /tmp/incident_log.txt
```

### Reverse Shell / Unknown Process Found
```bash
# Find the process
ps aux | grep -E "bash -i|nc|ncat"

# Kill it
sudo kill -9 <PID>

# Find how it got in
last
cat /var/log/auth.log | tail -50

# Check crontabs for persistence
crontab -l
sudo crontab -l

# Remove persistence
crontab -r
```

### Unknown User Found
```bash
# Lock account immediately
sudo passwd -l <unknown_user>

# Kill their sessions
sudo pkill -u <unknown_user>

# Remove account
sudo userdel -r <unknown_user>

# Audit how they got in
last <unknown_user>
cat /var/log/auth.log | grep <unknown_user>
```

---

## ✅ CHECKLIST
```
□ Check /etc/passwd — no unknown users
□ Check ss -tunap — no suspicious connections
□ Check authorized_keys — no unknown keys
□ Check crontabs — no malicious jobs
□ Check FTP files — all scoring files present
□ iptables applied with rate limiting
□ SSH hardened — key auth only
□ FTP hardened — no anonymous
□ Fail2ban running
□ FTP files backed up with checksums
□ Config backed up to Backup VM
□ Monitoring active in second terminal
□ Test SSH login works for scoring
□ Test FTP login works for scoring
□ Test FTP files downloadable
□ Test FTP write works
```
