#!/usr/bin/env bash
# =============================================================================
# NCAE Cyber Games 2026 - score_check.sh
# Quick manual scoring verification — run this any time to see current state.
# Simulates what the scoring engine checks. No logging, stdout only.
# Usage: bash score_check.sh
# =============================================================================
MY_IPS=$(ip addr show | grep -oP '(?<=inet )\d+\.\d+\.\d+\.\d+')
TEAM="${TEAM:-}"
if [[ -z "$TEAM" && -n "${NCAE_LAN_BASE:-}" ]]; then
    TEAM=$(echo "${NCAE_LAN_BASE}" | awk -F. '{print $3}')
fi
if [[ -z "$TEAM" && -n "${NCAE_LAN:-}" ]]; then
    TEAM=$(echo "${NCAE_LAN}" | sed 's/\.[0-9]*\/[0-9]*//' | awk -F. '{print $3}')
fi
if [[ -z "$TEAM" ]]; then
    TEAM=$(echo "$MY_IPS" | grep -oP '192\.168\.\K[0-9]+' | grep -E '^[0-9]+$' | head -1 || true)
fi
if [[ -z "$TEAM" ]]; then
    TEAM=$(echo "$MY_IPS" | grep -oP '172\.18\.14\.\K[0-9]+' | grep -E '^[0-9]+$' | head -1 || true)
fi
TEAM="${TEAM:-1}"
# Network topology — inherited from deploy_all.sh or computed here for standalone runs
NCAE_LAN="${NCAE_LAN:-192.168.${TEAM}.0/24}"
NCAE_SCORING="${NCAE_SCORING:-172.18.0.0/16}"
NCAE_LAN_BASE="${NCAE_LAN_BASE:-$(echo "${NCAE_LAN}" | sed 's/\.[0-9]*\/[0-9]*//')}"
NCAE_SHELL_IP="${NCAE_SHELL_IP:-172.18.14.${TEAM}}"
NCAE_CA_IP="${NCAE_CA_IP:-172.18.0.38}"

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
        warn "  Cert may be self-signed — replace with CA cert from ${NCAE_CA_IP}"
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
DNS_IP="${NCAE_LAN_BASE}.12"
if dig @"${DNS_IP}" "www.team${TEAM}.local" +short +time=3 2>/dev/null | grep -qE '^[0-9]'; then
    ok "DNS INT FWD: www.team${TEAM}.local resolves via ${DNS_IP} (500pts)"
else
    fail "DNS INT FWD FAILED via ${DNS_IP} (500pts AT RISK)"
fi

# -- DNS INT REV (500pts) ------------------------------------------------------
WWW_IP="${NCAE_LAN_BASE}.5"
if dig @"${DNS_IP}" -x "${WWW_IP}" +short +time=3 2>/dev/null | grep -q "team${TEAM}"; then
    ok "DNS INT REV: ${WWW_IP} reverse resolves (500pts)"
else
    fail "DNS INT REV FAILED for ${WWW_IP} (500pts AT RISK)"
fi

# -- PostgreSQL (500pts) -------------------------------------------------------
if command -v pg_isready &>/dev/null; then
    DB_IP="${NCAE_LAN_BASE}.7"
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

# -- FTP (1500 content + 500 write) --------------------------------------------
if command -v curl &>/dev/null; then
    FTP_PASS=$(grep -E "SCORING FTP/SSH (temporary )?password:" /root/ncae_credentials_shell.txt 2>/dev/null | awk '{print $NF}' | tail -1)
    if [[ -n "$FTP_PASS" ]]; then
        if curl --silent --show-error --fail --max-time 5 --user "scoring:${FTP_PASS}" "ftp://${NCAE_SHELL_IP}/readme.txt" >/dev/null 2>&1; then
            ok "FTP content works on ${NCAE_SHELL_IP} (1500pts)"
        else
            fail "FTP content FAILED on ${NCAE_SHELL_IP} (1500pts AT RISK)"
        fi
        if curl --silent --show-error --fail --max-time 5 -T /etc/hostname --user "scoring:${FTP_PASS}" \
            "ftp://${NCAE_SHELL_IP}/upload/score_check_$(hostname).txt" >/dev/null 2>&1; then
            ok "FTP write works on ${NCAE_SHELL_IP} (500pts)"
        else
            fail "FTP write FAILED on ${NCAE_SHELL_IP} (500pts AT RISK)"
        fi
    else
        warn "No FTP creds in /root/ncae_credentials_shell.txt — skipping FTP checks"
    fi
fi

# -- SSH (500pts on shell VM) --------------------------------------------------
if ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
    "scoring@${NCAE_SHELL_IP}" exit 2>/dev/null; then
    ok "SSH scoring@${NCAE_SHELL_IP} key auth works (500pts)"
else
    warn "SSH key auth to scoring@${NCAE_SHELL_IP} failed or no key configured"
fi

# -- Services running ----------------------------------------------------------
echo ""
echo "[ LOCAL SERVICES ]"
for svc in apache2 nginx named bind9 postgresql vsftpd proftpd ssh sshd; do
    systemctl list-unit-files 2>/dev/null | grep -q "^${svc}\.service" || continue
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        ok "$svc running"
    else
        fail "$svc DOWN"
    fi
done

echo ""
echo "======================================"
