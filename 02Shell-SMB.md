# SHELL / SMB
**IP:** 172.18.14.t | **OS:** Rocky Linux 9 | **Points:** 3500
SSH Login (1000) + SMB Login (500) + SMB Write (1000) + SMB Read (1000)

> WAN-exposed — no router between this VM and the internet. Do this VM first.

---

## PHASE 1 — CHECK
Hunt for red team persistence before touching anything else.
```bash
sudo bash /opt/ncae/00_recon.sh        # full snapshot — review output before proceeding
sudo bash /opt/ncae/backdoor_hunt.sh   # check keys, crons, shells, SUID, web shells
```

Look for and remove immediately:
- Unknown users in `/etc/passwd`
- Unknown SSH keys in `~/.ssh/authorized_keys`
- Suspicious cron jobs in `/etc/cron.d/` and `crontab -l`
- Unexpected listening ports: `ss -tunap | grep LISTEN`
- Active reverse shells: `ps aux | grep -E "bash -i|nc |ncat|python" | grep -v grep`

---

## PHASE 2 — HARDEN
```bash
sudo bash /opt/ncae/harden_shell_smb.sh
sudo cat /root/ncae_credentials_shell.txt
```

**At scoreboard open — SMB share names are revealed then, not before:**
```bash
sudo nano /etc/samba/smb.conf     # rename [write]/[read] to match scoreboard
sudo testparm -s                  # validate
sudo systemctl restart smb
```

**Add scoring SSH key when provided:**
```bash
echo 'PASTE_PUBKEY_HERE' >> /home/scoring/.ssh/authorized_keys
sudo bash /root/ncae_lock_ssh.sh   # only after confirming key works
```

---

## PHASE 3 — MONITOR

### monitor.sh (service watchdog + alerts)
```bash
sudo tmux new -s monitor -d
sudo tmux send-keys -t monitor 'sudo bash /opt/ncae/monitor.sh' Enter
# Detach: Ctrl+B then D  |  Reattach: tmux attach -t monitor
```

### Suricata (IDS — network threat detection)
```bash
# Install (requires EPEL)
sudo dnf install -y epel-release
sudo dnf install -y suricata

# Whitelist scoring engine — CRITICAL: prevents false blocks on scoring traffic
sudo tee /etc/suricata/rules/ncae-whitelist.rules <<'EOF'
pass ip 172.18.0.0/16 any -> any any (msg:"scoring engine whitelist"; sid:1000001; rev:1;)
pass ip 192.168.0.0/16 any -> any any (msg:"internal LAN whitelist"; sid:1000002; rev:1;)
EOF

# Add whitelist to rule-files in suricata.yaml
sudo sed -i '/rule-files:/a \ - ncae-whitelist.rules' /etc/suricata/suricata.yaml

# Set HOME_NET to your team subnet
sudo sed -i "s|HOME_NET: .*|HOME_NET: \"[192.168.t.0/24,172.18.14.t/32]\"|" /etc/suricata/suricata.yaml

# Update rules and start
sudo suricata-update
sudo systemctl enable --now suricata

# Watch alerts live
sudo tail -f /var/log/suricata/fast.log
```

### What to watch for in Suricata alerts
```
ET SCAN          — port scan from Red Team
ET EXPLOIT       — exploit attempt against SSH/SMB
ET TROJAN        — reverse shell / C2 beacon outgoing
ET POLICY        — suspicious tool usage (ncat, netcat)
ATTACK RESPONSE  — successful exploit indicator
```

### Run backdoor hunt every 30 min
```bash
sudo bash /opt/ncae/backdoor_hunt.sh
```

---

## PHASE 4 — RESPOND

Use the IR script for everything — it's faster than manual commands:
```bash
sudo bash /opt/ncae/incident_response.sh
```

| Option | Use When |
|--------|----------|
| 1 — Block IP | Suricata shows repeated attacks from same IP |
| 2 — Kill reverse shells | Suricata shows outgoing C2 / backdoor process found |
| 3 — Remove web shells | N/A for this VM |
| 5 — Purge cron jobs | Persistence found in cron |
| 6 — Re-harden | Config was modified by red team |
| 7 — Restore from backup | Files or configs corrupted |
| 8 — Restart all services | SMB/SSH went down |

---

## Verify Scoring
```bash
PASS=$(sudo grep SCORING /root/ncae_credentials_shell.txt | awk '{print $NF}')

smbclient -L //172.18.14.t/ -U scoring%"$PASS"                                 # SMB Login   500
smbclient //172.18.14.t/write -U scoring%"$PASS" -c 'put /etc/hostname t.txt'  # SMB Write  1000
smbclient //172.18.14.t/read  -U scoring%"$PASS" -c 'get readme.txt /tmp/r'    # SMB Read   1000
ssh scoring@172.18.14.t                                                          # SSH Login  1000
```

---

## Quick Fix Reference

| Problem | Fix |
|---------|-----|
| SMB scores 0 | Share names wrong — check scoreboard, edit `smb.conf`, restart `smb` |
| Samba silently broken | SELinux missing: `sudo restorecon -Rv /srv/samba/` |
| Scoring user missing from Samba | `echo -e "PASS\nPASS" \| sudo smbpasswd -s -a scoring && sudo smbpasswd -e scoring` |
| SSH login fails | Check `authorized_keys`, `sudo systemctl status sshd` |
| Suricata blocking scoring | Check whitelist rules loaded: `sudo suricata --list-runmodes` — restart Suricata |
| Any service down | `sudo systemctl restart smb nmb sshd suricata` |
| Something badly broken | `sudo bash /opt/ncae/harden_shell_smb.sh` (safe to re-run) |
