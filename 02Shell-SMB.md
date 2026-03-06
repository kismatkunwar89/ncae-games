# SHELL / SMB
**IP:** 172.18.14.t | **OS:** Rocky Linux 9 | **Points:** 3500
SSH Login (1000) + SMB Login (500) + SMB Write (1000) + SMB Read (1000)

> WAN-exposed — no router between this VM and the internet. Do this VM first.

---

## Run First
```bash
sudo bash /opt/ncae/00_recon.sh
sudo bash /opt/ncae/harden_shell_smb.sh
sudo tmux new -s monitor -d && sudo tmux send-keys -t monitor 'sudo bash /opt/ncae/monitor.sh' Enter
sudo cat /root/ncae_credentials_shell.txt
```

## At Scoreboard Open
SMB share names are unknown until the scoreboard opens — do not assume `read`/`write`.
```bash
# Update share names to match scoreboard
sudo nano /etc/samba/smb.conf
sudo testparm -s
sudo systemctl restart smb
```

Add scoring SSH key:
```bash
echo 'PASTE_PUBKEY_HERE' >> /home/scoring/.ssh/authorized_keys
sudo bash /root/ncae_lock_ssh.sh   # only after confirming key works
```

---

## Verify Scoring
```bash
PASS=$(sudo grep SCORING /root/ncae_credentials_shell.txt | awk '{print $NF}')

smbclient -L //172.18.14.t/ -U scoring%"$PASS"                                # SMB Login   500
smbclient //172.18.14.t/write -U scoring%"$PASS" -c 'put /etc/hostname t.txt' # SMB Write  1000
smbclient //172.18.14.t/read  -U scoring%"$PASS" -c 'get readme.txt /tmp/r'   # SMB Read   1000
ssh scoring@172.18.14.t                                                         # SSH Login  1000
```

---

## If It Breaks

| Problem | Fix |
|---------|-----|
| SMB scores 0 | Share names wrong — check scoreboard, edit `/etc/samba/smb.conf`, restart `smb` |
| Samba broken silently | SELinux missing: `sudo restorecon -Rv /srv/samba/` |
| Scoring user not in Samba | `sudo pdbedit -L` — if missing: `echo -e "PASS\nPASS" \| sudo smbpasswd -s -a scoring && sudo smbpasswd -e scoring` |
| SSH login fails | Check `authorized_keys`, check `sshd` running: `sudo systemctl status sshd` |
| Any service down | `sudo systemctl restart smb nmb sshd` |
| Reverse shell / backdoor | `sudo bash /opt/ncae/incident_response.sh` |
| Something badly broken | Re-run: `sudo bash /opt/ncae/harden_shell_smb.sh` (safe to re-run) |
