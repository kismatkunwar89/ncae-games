# UNH Blue Team Toolkit — NCAE Cyber Games 2026

A defense-in-depth toolkit for the NCAE Cyber Games blue team competition.
Covers recon, hardening, persistence hunting, continuous monitoring, and incident response across all scored VMs.

---

## Quick Start

SSH into any VM, clone the repo, and run one command:

```bash
git clone https://github.com/kismatkunwar89/ncae-games.git /opt/ncae
cd /opt/ncae/scripts
sudo bash deploy_all.sh
```

`deploy_all.sh` auto-detects your team number and VM role from the IP address, confirms with you before proceeding (press Enter to accept, type to override), then runs all phases automatically.

To specify role manually if auto-detection fails:

```bash
sudo bash deploy_all.sh www       # web server
sudo bash deploy_all.sh dns       # DNS server
sudo bash deploy_all.sh db        # database
sudo bash deploy_all.sh shell     # shell/SMB
sudo bash deploy_all.sh backup    # backup VM
sudo bash deploy_all.sh router 172.18.13.X   # MikroTik router
```

---

## Deployment Phases

| Phase | Script | What it does |
|-------|--------|--------------|
| 1 | `00_recon.sh` | Full system snapshot before touching anything |
| 1b | `backdoor_hunt.sh` | Deep persistence sweep — runs before monitor baselines |
| 2 | `harden_<role>.sh` | VM-specific hardening, firewall, auditd, fail2ban |
| 3 | `monitor.sh` | Continuous baseline-diff monitoring in tmux |
| 4 | `backup_configs.sh` | Push configs to backup VM via SSH |
| 5 | Script lock | `chattr +i` on all scripts to prevent tampering |

---

## Script Reference

| Script | Purpose |
|--------|---------|
| `deploy_all.sh` | Single entry point — runs all phases in order |
| `00_recon.sh` | Network, users, ports, keys, cron, firewall, SSH hooks, nftables |
| `backdoor_hunt.sh` | PAM, SUID/SGID, capabilities, timers, generators, udev, linker, modules, SSH certs, containers |
| `monitor.sh` | 30-second loop: services, connections, users, keys, cron, ports, web shells, sudoers, firewall, SSH hooks, timers, groups, shell RC files, udev, linker, auditd, containers, history suppression |
| `incident_response.sh` | Interactive IR menu: block IPs, kill shells, remove web shells, purge keys/cron, restore configs, restart services, persistence sweep |
| `harden_www.sh` | Apache2 + SSL, UFW, fail2ban, auditd (Ubuntu) |
| `harden_dns.sh` | BIND9, firewalld, auditd (Rocky 9) |
| `harden_db.sh` | PostgreSQL, UFW, PAM, auditd (Ubuntu) |
| `harden_shell_smb.sh` | Samba, SSH, Suricata IDS, firewalld, auditd (Rocky 9) |
| `harden_backup.sh` | UFW deny-by-default, backup storage, auditd (Ubuntu) |
| `harden_router.sh` | MikroTik RouterOS port forwards + firewall rules |
| `backup_configs.sh` | rsync configs from each VM to backup host |
| `score_check.sh` | Quick scoring health check for all services |

---

## VM Playbooks

Step-by-step field guides for each VM role. Use these during the competition alongside the scripts.

| File | VM |
|------|----|
| `01router.md` | MikroTik CHR router |
| `02Shell-SMB.md` | Shell / Samba VM |
| `03.Webserver.md` | Apache2 web server |
| `04.Database.md` | PostgreSQL database |
| `05.DNS.md` | BIND9 DNS server |
| `06.Backup.md` | Backup VM |

---

## Incident Response

```bash
sudo bash /opt/ncae/scripts/incident_response.sh
```

```
1) Kill suspicious connections / block IP
2) Hunt & kill reverse shells
3) Remove web shells
4) Purge unauthorized SSH keys
5) Purge unauthorized cron jobs
6) Force re-harden this VM
7) Restore config from backup
8) Emergency restart all services
9) Status snapshot
10) Full persistence sweep
```

Monitor alerts live:
```bash
tmux attach -t ncae_monitor
tail -f /vagrant/logs/ncae_alerts.log
```

---

## MITRE ATT&CK Coverage

| Technique | Description | Where covered |
|-----------|-------------|---------------|
| T1053.006 | Systemd Timers | backdoor_hunt §19, monitor `check_timers` |
| T1543.002 | Systemd Generators | backdoor_hunt §19, monitor `check_timers` |
| T1098.007 | Group Drift | backdoor_hunt §16, monitor `check_groups`, auditd |
| T1136.001 | Local Account | monitor `check_users`, auditd `account_mod` |
| T1546.004 | Shell RC Modification | backdoor_hunt §7, monitor `check_shellrc` |
| T1546.017 | Udev Rules | backdoor_hunt §20, monitor `check_udev` |
| T1574.006 | Dynamic Linker Hijack | backdoor_hunt §19, monitor `check_linker` + `check_ldpreload` |
| T1547.006 | Kernel Modules | backdoor_hunt §21, monitor `check_modules`, auditd |
| T1505.003 | Web Shell | backdoor_hunt §13, monitor `check_webshells` + `check_webproc` |
| T1562.004 | Disable Firewall | monitor `check_firewall` (ufw + nftables) |
| T1562.012 | Disable Auditd | monitor `check_auditd` (auto-restarts), auditd rules |
| T1078 | Valid Accounts | monitor `check_auth`, `check_users` |
| T1098.004 | SSH Cert Persistence | backdoor_hunt §17, monitor `check_ssh_hooks` |
| T1543.005 | Container Persistence | backdoor_hunt §18, monitor `check_containers` |
| T1014 | Rootkit / Modules | backdoor_hunt §11, auditd `module_load` |
| T1562.003 | History Suppression | backdoor_hunt §20, monitor `check_histsuppress` |

Auditd rules deployed to all VMs via `ncae_mitre_extended.rules` on every harden script.

---

## Network Topology

> **Hypothetical — actual IPs assigned at competition start. `deploy_all.sh` will prompt you to confirm or override.**

| VM | Default IP | Role |
|----|------------|------|
| Router | 172.18.13.T | MikroTik CHR |
| Web | 192.168.T.5 | Apache2 + SSL |
| DB | 192.168.T.7 | PostgreSQL |
| DNS | 192.168.T.12 | BIND9 |
| Shell | 172.18.14.T | SSH + Samba |
| Backup | 192.168.T.15 | rsync storage |

`T` = your team number. Scoring engine at `172.18.0.38` (CA) — never block `172.18.0.0/16`.

---

## Notes

- All logs written to `/vagrant/logs/` (shared with host)
- Credentials saved to `/root/ncae_credentials_<role>.txt` (chmod 600)
- Scripts are `chattr +i` locked after deploy — use `chattr -i <script>` to edit
- SMB share names are revealed at scoreboard open (10:30 AM) — do not hardcode
- Free CTF flag: `c2ctf{welcomeToTheCyberGames!}` — submit at 11:00 AM
