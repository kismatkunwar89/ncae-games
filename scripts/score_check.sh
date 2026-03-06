#!/usr/bin/env bash
# =============================================================================
# NCAE Cyber Games 2026 - score_check.sh
# Quick manual scoring verification — run this any time to see current state.
# Simulates what the scoring engine checks. No logging, stdout only.
# Usage: bash score_check.sh
# =============================================================================
TEAM=$(ip addr show | grep -oP '192\.168\.\K[0-9]+' | grep -E '^[0-9]+$' | head -1 2>/dev/null || \
       ip addr show | grep -oP '172\.18\.14\.\K[0-9]+' | grep -E '^[0-9]+$' | head -1 2>/dev/null || echo "?")

GREEN='\033[0;32m'; RED='\033[0;31m'; YEL='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[✔] $1${NC}"; }
fail() { echo -e "${RED}[✘] $1${NC}"; }
warn() { echo -e "${YEL}[?] $1${NC}"; }

echo "======================================"
echo " NCAE Score Check — Team $TEAM — $(date '+%H:%M:%S')"
echo "======================================"

# -- HTTP (500pts) -------------------------------------------------------------
MY_IP=$(ip addr show | grep -oP '(?<=inet )192\.168\.[0-9]+\.[0-9]+' | head -1 || echo "127.0.0.1")
if curl -sI --max-time 5 "http://${MY_IP}/" 2>/dev/null | grep -q "HTTP/"; then
    ok "HTTP responding on ${MY_IP}:80 (500pts)"
else
    fail "HTTP NOT responding on ${MY_IP}:80 (500pts AT RISK)"
fi

# -- HTTPS (1500pts) -----------------------------------------------------------
if curl -skI --max-time 5 "https://${MY_IP}/" 2>/dev/null | grep -q "HTTP/"; then
    ok "HTTPS responding on ${MY_IP}:443 (1500pts)"
    # Check if cert is self-signed (scoring may require CA-signed)
    CERT_ISSUER=$(echo | openssl s_client -connect "${MY_IP}:443" 2>/dev/null | openssl x509 -noout -issuer 2>/dev/null || echo "unknown")
    if echo "$CERT_ISSUER" | grep -qi "ncae\|ca\.ncae\|cybergames"; then
        ok "  Cert appears CA-signed: $CERT_ISSUER"
    else
        warn "  Cert may be self-signed — replace with CA cert from 172.18.0.38"
        warn "  Issuer: $CERT_ISSUER"
    fi
else
    fail "HTTPS NOT responding on ${MY_IP}:443 (1500pts AT RISK)"
fi

# -- WWW Content (1500pts) -----------------------------------------------------
TITLE=$(curl -sk --max-time 5 "https://${MY_IP}/" 2>/dev/null | grep -i '<title>' | head -1 || echo "")
if [[ -n "$TITLE" ]]; then
    ok "WWW content present — $TITLE (1500pts)"
else
    warn "No <title> tag found in HTTPS response — verify content (1500pts)"
fi

# -- DNS INT FWD (500pts) ------------------------------------------------------
DNS_IP="192.168.${TEAM}.12"
if dig @"${DNS_IP}" "www.team${TEAM}.local" +short +time=3 2>/dev/null | grep -qE '^[0-9]'; then
    ok "DNS INT FWD: www.team${TEAM}.local resolves via ${DNS_IP} (500pts)"
else
    fail "DNS INT FWD FAILED via ${DNS_IP} (500pts AT RISK)"
fi

# -- DNS INT REV (500pts) ------------------------------------------------------
WWW_IP="192.168.${TEAM}.5"
if dig @"${DNS_IP}" -x "${WWW_IP}" +short +time=3 2>/dev/null | grep -q "team${TEAM}"; then
    ok "DNS INT REV: ${WWW_IP} reverse resolves (500pts)"
else
    fail "DNS INT REV FAILED for ${WWW_IP} (500pts AT RISK)"
fi

# -- PostgreSQL (500pts) -------------------------------------------------------
if command -v pg_isready &>/dev/null; then
    DB_IP="192.168.${TEAM}.7"
    if pg_isready -h "${DB_IP}" -t 5 2>/dev/null | grep -q "accepting"; then
        ok "PostgreSQL accepting connections on ${DB_IP}:5432 (500pts)"
    else
        # Try localhost if we ARE the db VM
        if pg_isready -h 127.0.0.1 -t 5 2>/dev/null | grep -q "accepting"; then
            ok "PostgreSQL accepting connections on localhost (500pts)"
        else
            fail "PostgreSQL NOT ready (500pts AT RISK)"
        fi
    fi
else
    warn "pg_isready not available — skipping DB check"
fi

# -- SMB (500pts login + 1000 write + 1000 read) -------------------------------
if command -v smbclient &>/dev/null; then
    SHELL_IP="172.18.14.${TEAM}"
    SMB_PASS=$(grep "SCORING SMB/SSH password:" /root/ncae_credentials_shell.txt 2>/dev/null | awk '{print $NF}')
    if [[ -n "$SMB_PASS" ]]; then
        if smbclient -L "${SHELL_IP}" -U "scoring%${SMB_PASS}" --timeout=5 &>/dev/null; then
            ok "SMB login works on ${SHELL_IP} (500pts)"
        else
            fail "SMB login FAILED on ${SHELL_IP} (500pts AT RISK)"
        fi
    else
        warn "No SMB creds in /root/ncae_credentials_shell.txt — skipping SMB check"
    fi
fi

# -- SSH (1000pts on shell VM) -------------------------------------------------
SHELL_IP="172.18.14.${TEAM}"
if ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
    "scoring@${SHELL_IP}" exit 2>/dev/null; then
    ok "SSH scoring@${SHELL_IP} key auth works (1000pts)"
else
    warn "SSH key auth to scoring@${SHELL_IP} failed or no key configured"
fi

# -- Services running ----------------------------------------------------------
echo ""
echo "[ LOCAL SERVICES ]"
for svc in apache2 nginx named bind9 postgresql smb samba ssh sshd; do
    systemctl list-unit-files 2>/dev/null | grep -q "^${svc}\.service" || continue
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        ok "$svc running"
    else
        fail "$svc DOWN"
    fi
done

echo ""
echo "======================================"
