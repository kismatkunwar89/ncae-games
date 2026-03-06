# ROUTER
**External IP:** 172.18.13.t | **Internal IP:** 192.168.t.1 | **Points:** 500 (ICMP ping)
**Type:** MikroTik CHR (confirmed 2026) — VyOS possible alternative

> Router ICMP is 500pts but port forwards are required for ALL other external scoring to work.
> If the router dies, the entire team's external score goes to 0.

---

## Run First
```bash
# From any internal VM — push hardening script to router
sudo bash /opt/ncae/harden_router.sh <team_number> 172.18.13.t
sudo cat /root/ncae_credentials_router.txt
```

---

## Verify Scoring
```bash
ping 172.18.13.t                       # ICMP ping        500pts
curl -I http://172.18.13.t             # Web forward working
dig @172.18.13.t www.teamT.local       # DNS forward working
```

---

## MikroTik — Key Manual Commands

```bash
# Check current NAT rules
/ip firewall nat print

# Check firewall rules
/ip firewall filter print

# Check active connections
/ip firewall connection print

# View logs live
/log print follow where topics~"firewall"

# Save config
/system backup save name=backup_$(date +%H%M)
/export file=config_export
```

**If port forwards are missing (external scoring fails):**
```bash
/ip firewall nat add chain=dstnat in-interface=<WAN> dst-port=80  protocol=tcp action=dst-nat to-addresses=192.168.t.5  to-ports=80
/ip firewall nat add chain=dstnat in-interface=<WAN> dst-port=443 protocol=tcp action=dst-nat to-addresses=192.168.t.5  to-ports=443
/ip firewall nat add chain=dstnat in-interface=<WAN> dst-port=53  protocol=tcp action=dst-nat to-addresses=192.168.t.12 to-ports=53
/ip firewall nat add chain=dstnat in-interface=<WAN> dst-port=53  protocol=udp action=dst-nat to-addresses=192.168.t.12 to-ports=53
```

---

## VyOS — Key Manual Commands

```bash
# Enter config mode
configure

# Check interfaces
show interfaces

# Add port forward (NAT destination)
set nat destination rule 10 inbound-interface eth0
set nat destination rule 10 destination port 80
set nat destination rule 10 protocol tcp
set nat destination rule 10 translation address 192.168.t.5
set nat destination rule 10 translation port 80

# Firewall — allow ICMP (scoring)
set firewall name WAN_IN rule 10 action accept
set firewall name WAN_IN rule 10 protocol icmp

# Commit and save
commit
save

# Show NAT rules
run show nat destination rules

# Show firewall
run show firewall name WAN_IN
```

---

## If It Breaks

| Problem | Fix |
|---------|-----|
| ICMP fails | Verify ICMP accept rule exists and is before the drop rule |
| External web/DNS fails | Port forwards missing — add them (see above) |
| Locked out of router | Contact Black Team (neutral helpers) — they can assist |
| Config corrupted | MikroTik: `/system backup load name=backup_HHMM` |
| Re-run hardening | `sudo bash /opt/ncae/harden_router.sh <team_number> 172.18.13.t` |
