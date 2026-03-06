# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Repo Is

This is a **Blue Team competition playbook** for the NCAE Cyber Games — a collegiate defensive cybersecurity competition sponsored by NSA and Lockheed Martin. The goal is to defend live infrastructure against a Red Team while keeping scored services online.

Competition duration: **7 hours of active scoring** (3h + lunch break + 4h). Team number `T` is assigned on competition day (1–24), replacing `t` in all IPs.

## Scoring Overview

> **Note:** Point values, services, and totals below are from a previous example environment. Actual scoring table is provided on competition day.

Total: **~12,000 pts** (Infrastructure 10,000 + CTF 2,000)

| VM | Service | Points | IP |
|----|---------|--------|----|
| www | WWW Content | 1500 | 192.168.t.5 |
| www | SSL & Content | 2000 | 192.168.t.5 |
| dns | Internal DNS | 500 | 192.168.t.12 |
| dns | External DNS | 500 | 192.168.t.12 |
| dns | SSH | 500 | 192.168.t.12 |
| shell | SSH login | 500 | 172.18.14.t (WAN-exposed) |
| shell | FTP login | 500 | 172.18.14.t |
| shell | FTP content | 1500 | 172.18.14.t |
| shell | FTP write | 500 | 172.18.14.t |
| db | MySQL read/write | 1000 | 192.168.t.7 |
| db | SSH | 500 | 192.168.t.7 |
| router | ICMP ping | 500 | external interface |

## Network Topology

> **Note:** The topology below is hypothetical/example only, based on a previous competition environment. Actual IPs, VM layout, and services will be provided on competition day and are subject to change. `t` = your assigned team number (1–24).

```
Internet
   |
172.18.14.t  <-- Shell/FTP VM (directly WAN-exposed — NO router protection)
   |
Router (192.168.t.1 internal / 172.18.13.t external)
   |
192.168.t.0/24  (Internal LAN)
   ├── 192.168.t.5   Web Server
   ├── 192.168.t.7   Database
   ├── 192.168.t.12  DNS
   └── 192.168.t.15  Backup VM (not scored, but critical)
```

## Playbook Files

Each file follows the same 4-phase structure: **CHECK → HARDEN → BACKUP → MONITOR → RESPOND**

| File | VM | Priority |
|------|----|----------|
| `01router.md` | Router | TBD |
| `02FTP.md` | Shell/FTP (172.18.14.t) | HIGHEST — WAN exposed, harden in first 5 min |
| `03.Webserver.md` | Web Server (192.168.t.5) | High — 3500pts |
| `04.Database.md` | Database (192.168.t.7) | Medium — 1500pts |
| `05.DNS.md` | DNS (192.168.t.12) | Critical dependency — if DNS dies, web scoring fails |
| `06.Backup.md` | Backup VM (192.168.t.15) | Support — recovery lifeline for the team |

## First 5 Minutes Priority Order

1. **Shell/FTP VM first** — directly WAN-exposed, Red Team hits this first
2. **DNS second** — if this dies, web SSL scoring and external scoring breaks
3. **Web Server** — run SSL check, backup /var/www/html immediately
4. **Database** — restrict MySQL bind-address and drop unknown users
5. **Backup VM** — receive backups from all other team members via scp

## Key Architecture Decisions Across All VMs

- **iptables default DROP** on INPUT and FORWARD; OUTPUT ACCEPT — applied to every VM
- **Fail2ban** on SSH (and FTP for shell VM) with 3 retries, 1-hour ban
- **SSH hardening**: `PasswordAuthentication no`, `PermitRootLogin no`, `MaxAuthTries 3`
- **Backups go to 192.168.t.15** via `scp` immediately after each VM is secured
- **md5sum checksums** created for all scoring files (FTP content, web content, zone files)
- **4 monitoring terminals** per VM: service log, auth log, file integrity watch, network watch

## Domain Names (Example — verify on competition day)

- Internal: `teamT.net`
- External: `www.teamT.ncaecybergames.org` (SSL cert must match this exactly)

## Brainstorming Notes

- DNS failure cascades to web SSL scoring — DNS person must never restart bind9 without testing
- Shell/FTP VM has no router between it and the internet — treat it as already compromised at game start
- CTF (2000pts) is separate from infrastructure; dedicate at least 1 person to it exclusively
- Black Team (neutral helpers) can assist if a VM is completely broken — don't hesitate to ask
- Scoring checks run continuously — every minute of downtime costs points
