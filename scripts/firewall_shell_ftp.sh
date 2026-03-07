#!/usr/bin/env bash
# =============================================================================
# NCAE Cyber Games 2026 - Shell / FTP Firewall Lockdown
#
# PURPOSE:
#   Apply shell/FTP network restrictions only after the real topology is known.
#   This script is intentionally separate from harden_shell_smb.sh so we do not
#   lock ourselves out based on guessed subnets.
# =============================================================================
LOGFILE="/vagrant/logs/ncae_firewall_shell.log"
mkdir -p /vagrant/logs
touch "$LOGFILE" && chmod 600 "$LOGFILE"
exec > >(tee -a "$LOGFILE") 2>&1

echo "[$(date)] === Shell/FTP Firewall START ==="
[[ $EUID -ne 0 ]] && { echo "Run as root."; exit 1; }

PRIMARY_IF="${PRIMARY_IF:-$(ip route 2>/dev/null | awk '/default/ {print $5; exit}')}"
PRIMARY_CIDR="${PRIMARY_CIDR:-$(ip -o -4 addr show dev "${PRIMARY_IF}" scope global 2>/dev/null | awk '{print $4}' | head -1)}"
PRIMARY_IP="${PRIMARY_IP:-${PRIMARY_CIDR%/*}}"
PRIMARY_NET="${PRIMARY_NET:-$(ip route show dev "${PRIMARY_IF}" 2>/dev/null | awk '/proto kernel/ {print $1; exit}')}"
[[ -z "$PRIMARY_NET" ]] && PRIMARY_NET="$PRIMARY_CIDR"
TEAM="${TEAM:-$(ip addr show | grep -oP '172\.18\.14\.\K[0-9]+' | head -1 2>/dev/null || \
                ip addr show | grep -oP '192\.168\.\K[0-9]+' | head -1 2>/dev/null || echo "1")}"

if [[ "$PRIMARY_IP" =~ ^172\.18\.14\.([0-9]+)$ ]]; then
    TEAM="${TEAM:-${BASH_REMATCH[1]}}"
    ADMIN_NET_DEFAULT="192.168.${TEAM}.0/24"
    SCORING_NET_DEFAULT="172.18.0.0/16"
    SHELL_IP_DEFAULT="172.18.14.${TEAM}"
else
    ADMIN_NET_DEFAULT="${PRIMARY_NET}"
    SCORING_NET_DEFAULT="${PRIMARY_NET}"
    SHELL_IP_DEFAULT="${PRIMARY_IP}"
    echo "[*] Non-competition subnet detected; using live management subnet as a safe default"
fi

ADMIN_NET="${NCAE_LAN:-$ADMIN_NET_DEFAULT}"
SCORING_NET="${NCAE_SCORING:-$SCORING_NET_DEFAULT}"
SHELL_IP="${NCAE_SHELL_IP:-$SHELL_IP_DEFAULT}"

echo "[*] Active interface : ${PRIMARY_IF:-unknown}"
echo "[*] Shell IP         : ${SHELL_IP}"
echo "[*] Admin subnet     : ${ADMIN_NET}"
echo "[*] Scoring subnet   : ${SCORING_NET}"
echo ""
echo "[!] Admin subnet is auto-proposed from the current management path."
echo "[!] Scoring/external subnet must be confirmed before firewall lockdown."

if [[ "${NCAE_AUTO_ACCEPT:-0}" == "1" ]]; then
    echo "[*] NCAE_AUTO_ACCEPT=1 — applying firewall without prompt"
else
    if [[ -z "${NCAE_SCORING:-}" ]]; then
        read -rp "  Scoring/external subnet [${SCORING_NET}]: " _IN
        [[ -n "$_IN" ]] && SCORING_NET="$_IN"
    else
        echo "[*] Using scoring/external subnet from NCAE_SCORING=${SCORING_NET}"
    fi
    echo ""
    echo "[*] Final firewall plan:"
    echo "    Admin SSH   : ${ADMIN_NET}"
    echo "    Scoring SSH : ${SCORING_NET}"
    echo "    FTP         : ${SCORING_NET}"
    read -rp "Proceed with these firewall ranges? (yes/no): " confirm
    [[ "$confirm" == "yes" ]] || { echo "[!] Aborting firewall changes."; exit 1; }
fi

echo "[*] Configuring firewalld..."
systemctl enable firewalld 2>/dev/null || true
systemctl start firewalld 2>/dev/null || true

firewall-cmd --permanent --delete-zone=ncae-shell 2>/dev/null || true
firewall-cmd --permanent --new-zone=ncae-shell 2>/dev/null || true
firewall-cmd --permanent --zone=ncae-shell --set-target=DROP 2>/dev/null || true
firewall-cmd --permanent --set-default-zone=drop 2>/dev/null || true

firewall-cmd --permanent --zone=ncae-shell \
    --add-rich-rule="rule family='ipv4' source address='${ADMIN_NET}' service name='ssh' accept" 2>/dev/null || true

firewall-cmd --permanent --zone=ncae-shell \
    --add-rich-rule="rule family='ipv4' source address='${SCORING_NET}' service name='ssh' accept" 2>/dev/null || true
firewall-cmd --permanent --zone=ncae-shell \
    --add-rich-rule="rule family='ipv4' source address='${SCORING_NET}' service name='ftp' accept" 2>/dev/null || true
for port in 30000-30010/tcp; do
    firewall-cmd --permanent --zone=ncae-shell \
        --add-rich-rule="rule family='ipv4' source address='${SCORING_NET}' port port='${port%/*}' protocol='${port#*/}' accept" 2>/dev/null || true
done

[[ -z "$PRIMARY_IF" ]] && PRIMARY_IF="eth0"
firewall-cmd --permanent --zone=ncae-shell --add-interface="$PRIMARY_IF" 2>/dev/null || true
firewall-cmd --reload 2>/dev/null || true

echo "[+] Firewall applied."
echo "  Admin SSH allowed from : ${ADMIN_NET}"
echo "  Scoring SSH allowed from: ${SCORING_NET}"
echo "  FTP allowed from       : ${SCORING_NET}"
echo "  FTP passive ports      : ${SCORING_NET} -> 30000-30010/tcp"
echo "[$(date)] === Shell/FTP Firewall COMPLETE ==="
