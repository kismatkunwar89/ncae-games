# ROUTER — Security Plan
**IP:** 172.18.13.t (eth0 WAN) | 192.168.t.1 (eth1 LAN)
**Type:** MikroTik (possibly)
**Points:** ICMP Ping 500pts

---

## ⚡ PHASE 0 — CHECK (Do this FIRST before anything)

### Suspicious Users
```bash
# MikroTik
/user print
# Look for: unknown users, unexpected full-access accounts

# If Linux
cat /etc/passwd | grep -v nologin
getent group sudo
```

### Suspicious Network Connections
```bash
# MikroTik - check active connections
/ip firewall connection print
/tool torch interface=ether0

# Look for: outgoing connections to unknown external IPs
# Anything NOT scoring engine or your team traffic
```

### Suspicious Firewall Rules Already Present
```bash
# MikroTik
/ip firewall filter print
/ip firewall nat print

# Look for: rules that allow unexpected traffic
# Rules that forward traffic to unknown IPs
```

### Suspicious Services Running
```bash
# MikroTik
/ip service print

# Look for: telnet, FTP, API enabled
# These are backdoor entry points
```

### Suspicious Scheduled Tasks
```bash
# MikroTik
/system scheduler print

# Look for: unknown scheduled scripts
# Scripts calling external IPs
```

---

## 🔒 PHASE 1 — HARDEN

### Disable Unnecessary Services
```bash
/ip service disable telnet
/ip service disable ftp
/ip service disable www
/ip service disable www-ssl
/ip service disable api
/ip service disable api-ssl
/ip service disable winbox

# Restrict SSH to LAN only
/ip service set ssh address=192.168.t.0/24
```

### Change Default Password
```bash
/user set admin password=StrongPass123!
```

### Clean Firewall Rules
```bash
# Nuclear option if rules are messy
/ip firewall filter remove [find]
/ip firewall nat remove [find]

# Allow established
/ip firewall filter add chain=input connection-state=established,related action=accept comment="established"

# Allow ICMP (500pts scoring!)
/ip firewall filter add chain=input protocol=icmp action=accept comment="ICMP scoring"

# Allow Web
/ip firewall filter add chain=input protocol=tcp dst-port=80,443 action=accept comment="web scoring"

# Allow DNS
/ip firewall filter add chain=input protocol=udp dst-port=53 action=accept comment="DNS UDP"
/ip firewall filter add chain=input protocol=tcp dst-port=53 action=accept comment="DNS TCP"

# Allow LAN
/ip firewall filter add chain=input src-address=192.168.t.0/24 action=accept comment="LAN"

# Forward rules
/ip firewall filter add chain=forward connection-state=established,related action=accept
/ip firewall filter add chain=forward in-interface=ether0 protocol=tcp dst-port=80,443 action=accept
/ip firewall filter add chain=forward in-interface=ether0 protocol=udp dst-port=53 action=accept
/ip firewall filter add chain=forward in-interface=ether1 action=accept

# DEFAULT DENY — ALWAYS LAST
/ip firewall filter add chain=input action=drop comment="drop all"
/ip firewall filter add chain=forward action=drop comment="drop all forward"
```

### NAT Port Forwarding
```bash
# HTTP to web server
/ip firewall nat add chain=dstnat protocol=tcp dst-port=80 action=dst-nat to-addresses=192.168.t.5 to-ports=80

# HTTPS to web server
/ip firewall nat add chain=dstnat protocol=tcp dst-port=443 action=dst-nat to-addresses=192.168.t.5 to-ports=443

# DNS to DNS server
/ip firewall nat add chain=dstnat protocol=udp dst-port=53 action=dst-nat to-addresses=192.168.t.12 to-ports=53

# Masquerade LAN
/ip firewall nat add chain=srcnat src-address=192.168.t.0/24 action=masquerade
```

---

## 💾 PHASE 2 — BACKUP

```bash
# Save full backup
/system backup save name=router_clean_backup

# Export readable config
/export file=router_config_export

# Verify backup exists
/file print
```

**Store backup on:** Backup VM 192.168.t.15
**Copy via:** SCP or manual transfer

---

## 👁️ PHASE 3 — MONITOR

### Live Traffic Monitoring
```bash
# Watch all WAN traffic live
/tool torch interface=ether0

# Watch internal LAN traffic
/tool torch interface=ether1

# Watch firewall logs
/log print follow where topics~"firewall"

# Enable firewall logging for drops
/ip firewall filter set [find action=drop] log=yes log-prefix="DROPPED"
```

### What to Watch For
```
- Port scans from 172.18.15.t (Red Team)
- Unusual protocols on unexpected ports
- High volume traffic from single IP (DoS)
- Outgoing connections to unknown IPs
- Failed SSH attempts
```

---

## 🚨 PHASE 4 — RESPOND

### Port Scan Detected
```bash
# Identify scanning IP
/ip firewall connection print
# Verify drop rules are working
/ip firewall filter print
# Add rate limiting if needed
/ip firewall filter add chain=input src-address=<attacker_ip> action=drop
```

### DoS/Flooding Detected
```bash
# Add rate limiting
/ip firewall filter add chain=input protocol=tcp connection-limit=20,32 action=drop
/ip firewall filter add chain=input protocol=icmp limit=10,5 action=accept
/ip firewall filter add chain=input protocol=icmp action=drop
```

### Router Goes Down
```bash
# Restore from backup immediately
/system backup load name=router_clean_backup
# Reapply rules if needed
/import file=router_config_export
```

### Unknown Connection Found
```bash
# Kill the connection
/ip firewall connection remove [find dst-address=<unknown_ip>]
# Block the IP
/ip firewall filter add chain=input src-address=<unknown_ip> action=drop place-before=0
```

---

## ✅ CHECKLIST
```
□ Check users — no unknown accounts
□ Check connections — no suspicious outgoing
□ Check existing rules — no backdoor rules
□ Disable unnecessary services
□ Change default password
□ Apply clean firewall rules
□ Apply NAT port forwarding
□ Backup config saved
□ Test ICMP ping works (500pts)
□ Test web accessible externally
□ Test DNS resolving
□ Monitoring active in second terminal
```
