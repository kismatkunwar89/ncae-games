================================================================
 NCAE CyberGames 2026 - UNH Blue Team Toolkit
 Sat Mar  7 18:12:30 UTC 2026
================================================================

================================================================
 Auto-detected:
   IPs  : 127.0.0.1 10.88.1.15 
   Team : 1
   Role : backup
 Roles available: www | dns | db | shell | backup | router
 Press ENTER to accept detected value, or type to override.
================================================================
[*] NCAE_AUTO_ACCEPT=1 — keeping detected values without prompting
[*] Team=1  Role=backup  LAN=10.88.1.0/24  Scoring=10.77.0.0/16
[*] Operator: running as root directly (no sudo user detected)

[PHASE 1] Recon...

--------------------------------------------------------
 Running: 00_recon.sh 
--------------------------------------------------------
================================================================
 NCAE RECON - backup - Sat Mar  7 18:12:30 UTC 2026
================================================================

[ NETWORK INTERFACES ]
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0@if9: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether e2:54:18:77:8e:35 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 10.88.1.15/24 brd 10.88.1.255 scope global eth0
       valid_lft forever preferred_lft forever

[ ROUTING TABLE ]
default via 10.88.1.1 dev eth0 
10.88.1.0/24 dev eth0 proto kernel scope link src 10.88.1.15 

[ ARP / NEIGHBORS ]

[ LISTENING PORTS ]
Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess                                               
udp   UNCONN 0      0         127.0.0.11:51704      0.0.0.0:*                                                         
tcp   LISTEN 0      4096      127.0.0.11:35003      0.0.0.0:*                                                         
tcp   LISTEN 0      4096         0.0.0.0:22         0.0.0.0:*    users:(("sshd",pid=866,fd=3),("systemd",pid=1,fd=70))
tcp   LISTEN 0      4096            [::]:22            [::]:*    users:(("sshd",pid=866,fd=4),("systemd",pid=1,fd=76))

[ ACTIVE SERVICES ]
  ssh.service              loaded active running OpenBSD Secure Shell server

[ ALL ENABLED SERVICES ]
UNIT FILE               STATE   PRESET
auditd.service          enabled enabled
cron.service            enabled enabled
e2scrub_reap.service    enabled enabled
fail2ban.service        enabled enabled
getty@.service          enabled enabled
ssl-cert.service        enabled enabled
systemd-pstore.service  enabled enabled
ufw.service             enabled enabled
ssh.socket              enabled enabled
remote-fs.target        enabled enabled
apt-daily-upgrade.timer enabled enabled
apt-daily.timer         enabled enabled
dpkg-db-backup.timer    enabled enabled
e2scrub_all.timer       enabled enabled
fstrim.timer            enabled enabled
motd-news.timer         enabled enabled

16 unit files listed.

[ USER ACCOUNTS WITH LOGIN SHELLS ]
root:x:0:0:root:/root:/bin/bash
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
postgres:x:101:104:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash

[ USERS WITH UID >= 1000 ]
ubuntu 1000 /home/ubuntu /bin/bash

[ SUDO / WHEEL MEMBERS ]
sudo:x:27:ubuntu
/etc/sudoers:%admin ALL=(ALL) ALL
/etc/sudoers:%sudo	ALL=(ALL:ALL) ALL

[ USERS WITH EMPTY PASSWORDS ]

[ LAST LOGINS ]
root     pts/2        tmux(1500).%0    Sat Mar  7 17:52    gone - no logout
reboot   system boot  6.6.87.2-microso Sat Mar  7 17:28   still running

wtmp begins Sat Mar  7 17:28:57 2026

[ CURRENTLY LOGGED IN ]
root     pts/2        2026-03-07 17:52 (tmux(1500).%0)

[ SSH AUTHORIZED_KEYS (all users) ]
  [/root]:

[ CRONTABS ]
  (none for root)
/etc/cron.d/:
e2scrub_all
ncae_backup_protect

/etc/cron.daily/:
apache2
apt-compat
dpkg

/etc/cron.hourly/:
30 3 * * 0 root test -e /run/systemd/system || SERVICE_MODE=1 /usr/lib/x86_64-linux-gnu/e2fsprogs/e2scrub_all_cron
10 3 * * * root test -e /run/systemd/system || SERVICE_MODE=1 /sbin/e2scrub_all -A -r
*/5 * * * * root /usr/local/bin/ncae_protect_backups.sh

[ SUID BINARIES ]
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/umount
/usr/bin/chsh
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/su
/usr/bin/sudo

[ WORLD-WRITABLE DIRECTORIES ]
/var/tmp/systemd-private-4e587dbe1e0b48bb8d6803cb35f97fbc-systemd-logind.service-9RURVm/tmp
/tmp/systemd-private-4e587dbe1e0b48bb8d6803cb35f97fbc-systemd-logind.service-YD0uZZ/tmp
/tmp/.font-unix
/tmp/.XIM-unix
/tmp/.ICE-unix
/tmp/.X11-unix

[ WEB ROOT CONTENTS ]
total 20
drwxr-xr-x 2 root root  4096 Mar  7 00:19 .
drwxr-xr-x 3 root root  4096 Mar  7 00:19 ..
-rw-r--r-- 1 root root 10671 Mar  7 00:19 index.html

[ WEB SHELL DETECTION (eval/base64/exec in web root) ]

[ KEY CONFIG FILES ]
  EXISTS: /etc/ssh/sshd_config
  EXISTS: /etc/apache2/apache2.conf
  EXISTS: /etc/postgresql/16/main/postgresql.conf
  EXISTS: /etc/postgresql/16/main/pg_hba.conf

[ AT JOBS ]
  (at not installed or no jobs)

[ SYSTEMD LINGERING USERS ]
No users.

[ USER SYSTEMD UNITS ]

[ SSH CONFIG - ForceCommand / Match blocks ]
/etc/ssh/sshd_config:121:AcceptEnv LANG LC_*
/etc/ssh/sshd_config:127:#Match User anoncvs
/etc/ssh/sshd_config:131:#	ForceCommand cvs server

[ SSH HOOKS - sshrc / rc files ]

[ FIREWALL STATUS ]
Status: active
Logging: on (low)
Default: deny (incoming), deny (outgoing), deny (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22                         ALLOW IN    10.88.1.0/24               # SSH internal LAN
Anywhere                   ALLOW IN    10.88.1.0/24               # internal LAN backup rsync

10.88.1.0/24               ALLOW OUT   Anywhere                   # internal LAN outbound
53                         ALLOW OUT   Anywhere                   # DNS resolution
53 (v6)                    ALLOW OUT   Anywhere (v6)              # DNS resolution


[ NFTABLES (raw - may differ from ufw/firewalld view) ]

[ ESTABLISHED CONNECTIONS (potential red team) ]
Netid Recv-Q Send-Q Local Address:Port Peer Address:PortProcess

[ OS / KERNEL ]
Linux backup 6.6.87.2-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC Thu Jun  5 18:30:46 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
PRETTY_NAME="Ubuntu 24.04.4 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.4 LTS (Noble Numbat)"
VERSION_CODENAME=noble

================================================================
 RECON COMPLETE - Log: /vagrant/logs/ncae_recon_backup_20260307_181230.log
================================================================

NEXT STEPS (priority order):
  1. Note ALL open ports above - close anything not scored
  2. Note ALL users with shells - lock everything non-scoring
  3. Check authorized_keys - remove unknown keys
  4. Check crontabs - remove red team persistence
  5. Check web root for shells
  6. Run appropriate harden_*.sh for this VM
[+] 00_recon.sh done

[PHASE 1b] Persistence sweep (must complete before monitor baselines)...

--------------------------------------------------------
 Running: backdoor_hunt.sh 
--------------------------------------------------------
======================================================
 NCAE Backdoor Hunt — Sat Mar  7 18:12:31 UTC 2026
 Host: backup | uid=0(root) gid=0(root) groups=0(root)
======================================================

========== ROOT HOME FILES ==========
[*] Files in /root modified in last 7 days:
[1;33m[?] REVIEW:     /root/ncae_credentials_backup.txt  (mtime: 2026-03-07 17:52:48.506840751 +0000)[0m
[1;33m[?] REVIEW:     /root/ncae_lock_backup_ssh.sh  (mtime: 2026-03-07 17:52:48.518841545 +0000)[0m
[1;33m[?] REVIEW:     /root/.ssh/authorized_keys  (mtime: 2026-03-07 17:52:48.514841280 +0000)[0m
[*] Checking /root/.ssh/authorized_keys:

========== SSH AUTHORIZED_KEYS — ALL USERS ==========
[1;33m[?] REVIEW:     User root has 0 key(s) in /root/.ssh/authorized_keys[0m

========== CRON JOBS ==========
[*] /etc/crontab:
SHELL=/bin/sh
[0;31m[!] SUSPICIOUS: Non-standard entries in /etc/crontab (see above)[0m
[*] /etc/cron.d/ entries:
[0;31m[!] SUSPICIOUS: /etc/cron.d/e2scrub_all contains: 30 3 * * 0 root test -e /run/systemd/system || SERVICE_MODE=1 /usr/lib/x86_64-linux-gnu/e2fsprogs/e2scrub_all_cron
10 3 * * * root test -e /run/systemd/system || SERVICE_MODE=1 /sbin/e2scrub_all -A -r[0m
[0;31m[!] SUSPICIOUS: /etc/cron.d/ncae_backup_protect contains: */5 * * * * root /usr/local/bin/ncae_protect_backups.sh[0m
[*] User crontabs:
[*] /etc/cron.{hourly,daily,weekly,monthly} executables:
[1;33m[?] REVIEW:     /etc/cron.daily/dpkg (verify it's legitimate)[0m
[1;33m[?] REVIEW:     /etc/cron.daily/apt-compat (verify it's legitimate)[0m
[1;33m[?] REVIEW:     /etc/cron.daily/apache2 (verify it's legitimate)[0m

========== SYSTEMD — SUSPICIOUS SERVICES & TIMERS ==========
[*] Services added/modified in last 7 days:
[*] Active timers (look for unexpected ones):
[1;33m[?] REVIEW:     -                                  - -                                   - fstrim.timer                 fstrim.service[0m
[1;33m[?] REVIEW:     7 timers listed.[0m
[*] Services with /tmp or /dev/shm in ExecStart:
[0;31m[!] SUSPICIOUS: Service executes from temp path: /lib/systemd/system/kmod-static-nodes.service[0m
[*] Systemd drop-in override directories (ExecStartPre / ExecStart injection):

========== PAM MODULE INTEGRITY ==========
[*] Checking pam_unix.so for hardcoded passwords:
[0;32m[+] CLEAN:      pam_unix.so strings look clean[0m
[*] Checking for pam_exec entries (can run arbitrary scripts on auth):
[0;32m[+] CLEAN:      No pam_exec in /etc/pam.d/[0m
[*] /etc/pam.d/ files modified recently:

========== LINUX CAPABILITIES (cap_setuid / cap_dac_override) ==========
[*] Scanning all files for elevated capabilities:
[0;32m[+] CLEAN:      No capability-enabled binaries found[0m

========== SUID/SGID BINARIES ==========
[*] All SUID binaries (review for unexpected entries):

========== SHELL STARTUP FILE BACKDOORS ==========
[*] Checking global profiles for reverse shell indicators:
[*] User .bashrc / .profile backdoors:

========== RC.LOCAL AND MOTD ==========
[*] /etc/update-motd.d/ executables:
[1;33m[?] REVIEW:     MOTD script (verify): /etc/update-motd.d/50-motd-news[0m
[1;33m[?] REVIEW:     MOTD script (verify): /etc/update-motd.d/00-header[0m
[1;33m[?] REVIEW:     MOTD script (verify): /etc/update-motd.d/60-unminimize[0m
[1;33m[?] REVIEW:     MOTD script (verify): /etc/update-motd.d/10-help-text[0m

========== LD_PRELOAD / LIBRARY HOOKS ==========
[0;32m[+] CLEAN:      /etc/ld.so.preload not present[0m
[*] Checking LD_PRELOAD in systemd service files:

========== SUSPICIOUS FILES IN /tmp /var/tmp /dev/shm ==========
[*] Executables in /tmp:
[*] Hidden files in /tmp:
[0;31m[!] SUSPICIOUS: Hidden file: /tmp/.font-unix[0m
[0;31m[!] SUSPICIOUS: Hidden file: /tmp/.XIM-unix[0m
[0;31m[!] SUSPICIOUS: Hidden file: /tmp/.ICE-unix[0m
[0;31m[!] SUSPICIOUS: Hidden file: /tmp/.X11-unix[0m
[*] Executables in /var/tmp:
[*] Hidden files in /var/tmp:
[*] Executables in /dev/shm:
[*] Hidden files in /dev/shm:

========== KERNEL MODULES (ROOTKIT CHECK) ==========
[*] Non-standard kernel modules:

========== SUSPICIOUS NETWORK CONNECTIONS ==========
[*] Listening on unexpected ports (not 22/80/443/53/21/3306/5432/445/139):
[0;31m[!] SUSPICIOUS: Unexpected listener on port 35003  [][0m
[*] Established outbound connections to non-RFC1918 addresses:

========== WEB SHELL DETECTION ==========
[*] Scanning /var/www for common web shell indicators:

========== PASSWD / SUDO PRIVILEGE ESCALATION ==========
[*] All UID 0 accounts:
[0;32m[+] CLEAN:      root UID 0 — expected[0m
[*] Users in sudo/wheel group:
[1;33m[?] REVIEW:     sudo:x:27:ubuntu[0m
[*] /etc/sudoers NOPASSWD entries:

========== RECENTLY MODIFIED SYSTEM BINARIES ==========
[*] System binaries modified in last 3 days (possible binary replacement):

========== USER-LEVEL PERMISSIONS AUDIT ==========
[*] SGID binaries (group escalation — often missed):
[1;33m[?] REVIEW:     SGID binary: /usr/lib/x86_64-linux-gnu/utempter/utempter  (root utmp 2755)[0m
[1;33m[?] REVIEW:     SGID binary: /usr/sbin/pam_extrausers_chkpwd  (root shadow 2755)[0m
[1;33m[?] REVIEW:     SGID binary: /usr/sbin/unix_chkpwd  (root shadow 2755)[0m
[1;33m[?] REVIEW:     SGID binary: /usr/bin/chage  (root shadow 2755)[0m
[1;33m[?] REVIEW:     SGID binary: /usr/bin/expiry  (root shadow 2755)[0m
[1;33m[?] REVIEW:     SGID binary: /usr/bin/crontab  (root crontab 2755)[0m
[1;33m[?] REVIEW:     SGID binary: /usr/bin/ssh-agent  (root _ssh 2755)[0m
[*] Critical file permissions:
[0;31m[!] SUSPICIOUS: /etc/ssh/sshd_config permissions are 644 (expected 600) owner=root:root[0m
[*] Dangerous group memberships (docker/disk/lxd/shadow/adm = near-root access):
[0;31m[!] SUSPICIOUS: Group 'adm' has members: ubuntu[0m
[*] Home directory permissions (should be 700 — 755 lets others read files):
[*] ACLs on sensitive paths (getfacl reveals permissions invisible to ls):
[1;33m[?] REVIEW:     getfacl not available (install acl package)[0m
[*] World-writable files outside /tmp (anyone can modify these):
[*] Writable directories in root PATH (command hijacking risk):

========== SSH CERTIFICATE PERSISTENCE (T1098.004) ==========
[*] TrustedUserCAKeys — any CA key here grants SSH access for all users it signs:
[0;32m[+] CLEAN:      TrustedUserCAKeys not set[0m
[*] AuthorizedPrincipalsFile — overrides authorized_keys; maps cert principals to users:
/etc/ssh/sshd_config:52:#AuthorizedPrincipalsFile none
[0;31m[!] SUSPICIOUS: AuthorizedPrincipalsFile is set — check what principals are allowed[0m
/etc/ssh/sshd_config:52:#AuthorizedPrincipalsFile none
[*] Scanning per-user authorized_principals files:
[*] SSH certificates in use (ssh-keygen -L to inspect):

========== CONTAINER PERSISTENCE (T1543.005) ==========
[*] Docker daemon and restart-always containers:
[0;32m[+] CLEAN:      Docker not running[0m
[*] Podman containers and quadlets:

========== SYSTEMD TIMERS & GENERATORS (T1053.006 / T1543.002) ==========
[*] All .timer units — look for unexpected entries:
[1;33m[?] REVIEW:     Timer: /etc/systemd/system/timers.target.wants/fstrim.timer[0m
    OnCalendar=weekly
[1;33m[?] REVIEW:     Timer: /usr/lib/systemd/system/fstrim.timer[0m
    OnCalendar=weekly
[1;33m[?] REVIEW:     Timer: /usr/lib/systemd/system/pg_basebackup@.timer[0m
    OnCalendar=weekly
[1;33m[?] REVIEW:     Timer: /usr/lib/systemd/system/systemd-sysupdate-reboot.timer[0m
    OnCalendar=4:10
[1;33m[?] REVIEW:     Timer: /usr/lib/systemd/system/pg_dump@.timer[0m
    OnCalendar=weekly
[1;33m[?] REVIEW:     Timer: /usr/lib/systemd/system/pg_compresswal@.timer[0m
    OnCalendar=daily
[1;33m[?] REVIEW:     Timer: /usr/lib/systemd/system/systemd-sysupdate.timer[0m
    OnBootSec=15min
    OnCalendar=Sat
[1;33m[?] REVIEW:     Timer: /lib/systemd/system/fstrim.timer[0m
    OnCalendar=weekly
[1;33m[?] REVIEW:     Timer: /lib/systemd/system/pg_basebackup@.timer[0m
    OnCalendar=weekly
[1;33m[?] REVIEW:     Timer: /lib/systemd/system/systemd-sysupdate-reboot.timer[0m
    OnCalendar=4:10
[1;33m[?] REVIEW:     Timer: /lib/systemd/system/pg_dump@.timer[0m
    OnCalendar=weekly
[1;33m[?] REVIEW:     Timer: /lib/systemd/system/pg_compresswal@.timer[0m
    OnCalendar=daily
[1;33m[?] REVIEW:     Timer: /lib/systemd/system/systemd-sysupdate.timer[0m
    OnBootSec=15min
    OnCalendar=Sat
[*] User-level timers (lingering persistence):
[*] Systemd generator paths (T1543.002 — run before normal units):
[1;33m[?] REVIEW:     Generator binary: /usr/lib/systemd/system-generators/systemd-gpt-auto-generator[0m
[1;33m[?] REVIEW:     Generator binary: /usr/lib/systemd/system-generators/sshd-socket-generator[0m
[1;33m[?] REVIEW:     Generator binary: /usr/lib/systemd/system-generators/systemd-system-update-generator[0m
[1;33m[?] REVIEW:     Generator binary: /usr/lib/systemd/system-generators/systemd-debug-generator[0m
[1;33m[?] REVIEW:     Generator binary: /usr/lib/systemd/system-generators/systemd-sysv-generator[0m
[1;33m[?] REVIEW:     Generator binary: /usr/lib/systemd/system-generators/systemd-run-generator[0m
[1;33m[?] REVIEW:     Generator binary: /usr/lib/systemd/system-generators/systemd-fstab-generator[0m
[1;33m[?] REVIEW:     Generator binary: /usr/lib/systemd/system-generators/systemd-getty-generator[0m
[1;33m[?] REVIEW:     Generator binary: /usr/lib/systemd/system-generators/systemd-veritysetup-generator[0m
[1;33m[?] REVIEW:     Generator binary: /usr/lib/systemd/system-generators/systemd-integritysetup-generator[0m
[1;33m[?] REVIEW:     Generator binary: /usr/lib/systemd/system-generators/systemd-cryptsetup-generator[0m
[1;33m[?] REVIEW:     Generator binary: /usr/lib/systemd/system-generators/systemd-rc-local-generator[0m
[1;33m[?] REVIEW:     Generator binary: /usr/lib/systemd/system-generators/systemd-hibernate-resume-generator[0m
[1;33m[?] REVIEW:     Generator binary: /usr/lib/systemd/system-generators/postgresql-generator[0m

========== UDEV RULES (T1546.017) ==========
[*] Scanning udev rules for RUN+= (arbitrary command execution on device event):
[0;31m[!] SUSPICIOUS: Udev rule with RUN+=: /usr/lib/udev/rules.d/71-seat.rules[0m
  72:                  RUN+="/usr/bin/udevadm trigger --parent-match=%p/.."
  77:SUBSYSTEM=="input", ATTR{name}=="Wiebetech LLC Wiebetech", RUN+="/usr/bin/loginctl lock-sessions"
[0;31m[!] SUSPICIOUS: Udev rule with RUN+=: /usr/lib/udev/rules.d/99-systemd.rules[0m
  70:ACTION=="add", SUBSYSTEM=="net", KERNEL!="lo", RUN+="/usr/lib/systemd/systemd-sysctl --prefix=/net/ipv4/conf/$name --prefix=/net/ipv4/neigh/$name --prefix=/net/ipv6/conf/$name --prefix=/net/ipv6/neigh/$name"
[*] Custom rules in /etc/udev/rules.d (not from packages):

========== DYNAMIC LINKER (T1574.006) ==========
[*] /etc/ld.so.conf and ld.so.conf.d entries:
[1;33m[?] REVIEW:     ld.so.conf entry: include /etc/ld.so.conf.d/*.conf[0m
[1;33m[?] REVIEW:     ld.so.conf.d (/etc/ld.so.conf.d/x86_64-linux-gnu.conf): /usr/local/lib/x86_64-linux-gnu[0m
[1;33m[?] REVIEW:     ld.so.conf.d (/etc/ld.so.conf.d/x86_64-linux-gnu.conf): /lib/x86_64-linux-gnu[0m
[1;33m[?] REVIEW:     ld.so.conf.d (/etc/ld.so.conf.d/x86_64-linux-gnu.conf): /usr/lib/x86_64-linux-gnu[0m
[1;33m[?] REVIEW:     ld.so.conf.d (/etc/ld.so.conf.d/libc.conf): /usr/local/lib[0m
[*] .so files in world-writable or non-standard library paths:
[*] Recently modified .so files in system lib dirs (possible library replacement):

========== AUDITD INTEGRITY (T1562.012) ==========
[*] Auditd service state:
[0;31m[!] SUSPICIOUS: AUDITD IS STOPPED — audit logging is blind[0m
[*] Current audit rules (look for -D flush or missing key rules):
  
  ========== -30 ==========
[*] /etc/audit/rules.d/ files:
[1;33m[?] REVIEW:     /etc/audit/rules.d/audit.rules  (mtime: 2024-10-02 12:40:50.000000000 +0000)[0m
[1;33m[?] REVIEW:     /etc/audit/rules.d/ncae_mitre_extended.rules  (mtime: 2026-03-07 17:52:59.031537219 +0000)[0m
[1;33m[?] REVIEW:     /etc/audit/rules.d/ncae_backup.rules  (mtime: 2026-03-07 17:52:58.999535101 +0000)[0m
[*] HISTFILE / shell history tampering indicators:
[0;31m[!] SUSPICIOUS: History suppression in /root/.bashrc[0m
  10:HISTCONTROL=ignoredups:ignorespace
  15:# for setting history length see HISTSIZE and HISTFILESIZE in bash(1)
  16:HISTSIZE=1000
  17:HISTFILESIZE=2000

========== KERNEL MODULE LOAD CONFIG (T1547.006) ==========
[*] /etc/modules-load.d/ entries (loaded at boot):
[*] /etc/modprobe.d/ entries (look for 'install' overrides — run commands on modprobe):
[*] Recently modified modprobe.d files:

======================================================
[0;31m HUNT COMPLETE — 8 FINDING(S) REQUIRE ATTENTION[0m
 Full log: /vagrant/logs/ncae_backdoor_hunt.log
======================================================
[+] backdoor_hunt.sh done

[PHASE 2] Hardening: backup

--------------------------------------------------------
 Running: harden_backup.sh 
--------------------------------------------------------
[Sat Mar  7 18:12:32 UTC 2026] === Backup VM Hardening START ===
[*] Team: 1
[*] LAN: 10.88.1.0/24  Scoring: 10.77.0.0/16
[*] OS: Ubuntu
[*] Skipping package update (NCAE_SKIP_UPDATE=1)
[*] Skipping package install (NCAE_SKIP_INSTALL=1)
[*] Locking non-essential users...
[*] Cleared root authorized_keys
[*] Preparing authorized_keys for backup rsync...
[!] ACTION: When backup_configs.sh runs on other VMs, it will add its key here.
    To pre-authorize manually: cat /root/.ssh/ncae_backup_ed25519.pub | ssh root@10.88.1.15 'cat >> /root/.ssh/authorized_keys'
[*] Hardening SSH (keeping password auth ON until backup key confirmed)...
[*] Configuring firewall (backup segmentation)...
[*] Applying minimal UFW on backup VM...
Backing up 'user.rules' to '/etc/ufw/user.rules.20260307_181235'
Backing up 'before.rules' to '/etc/ufw/before.rules.20260307_181235'
Backing up 'after.rules' to '/etc/ufw/after.rules.20260307_181235'
Backing up 'user6.rules' to '/etc/ufw/user6.rules.20260307_181235'
Backing up 'before6.rules' to '/etc/ufw/before6.rules.20260307_181235'
Backing up 'after6.rules' to '/etc/ufw/after6.rules.20260307_181235'

Default incoming policy changed to 'deny'
(be sure to update your rules accordingly)
Default outgoing policy changed to 'deny'
(be sure to update your rules accordingly)
Rules updated
Rules updated
Rules updated
Rules updated
Rules updated (v6)
Firewall is active and enabled on system startup
[+] UFW enabled on backup VM
[*] Disabling unnecessary services...
[*] Setting up backup storage...
/usr/sbin/augenrules: No change
/usr/sbin/augenrules: No change

[Sat Mar  7 18:12:43 UTC 2026] === Backup VM Hardening COMPLETE ===
Credentials: /root/ncae_credentials_backup.txt

NEXT STEPS:
  1. Run backup_configs.sh on www/dns/db/shell VMs
     They will auto-deploy SSH key here
  2. Verify rsync works: ls /srv/ncae_backups/
  3. Lock SSH: /root/ncae_lock_backup_ssh.sh

SEGMENTATION:
  Inbound:  10.88.1.0/24, 10.77.0.0/16
  Outbound: 10.88.1.0/24, 10.77.0.0/16, port 53
  All else: DENIED
[+] harden_backup.sh done

[PHASE 3] Starting monitor...
[+] Monitor: tmux attach -t ncae_monitor

[PHASE 4] Config backup...
[*] Skipping backup push (NCAE_SKIP_BACKUP=1)

[PHASE 5] Locking script integrity...
[*] Skipping script integrity lock (NCAE_SKIP_SCRIPT_LOCK=1)

================================================================
 DEPLOY COMPLETE - 13s | Sat Mar  7 18:12:43 UTC 2026
================================================================

[ CREDENTIALS ]
  Credentials saved to: /root/ncae_credentials_*.txt
  View with: cat /root/ncae_credentials_backup.txt (root only - chmod 600)

[ SCORING CHECKLIST - backup ]
  Not scored. Verify backup storage: ls /srv/ncae_backups/
  Lock SSH when ready: /root/ncae_lock_backup_ssh.sh

[ QUICK COMMANDS ]
  Monitor:  tmux attach -t ncae_monitor
  Alerts:   tail -f /var/log/ncae_alerts.log
  IR:       sudo bash /opt/ncae/scripts/incident_response.sh
  Backup:   sudo bash /opt/ncae/scripts/backup_configs.sh

[ FREE CTF FLAG - submit at 11:00 AM ]
  c2ctf{welcomeToTheCyberGames!}
