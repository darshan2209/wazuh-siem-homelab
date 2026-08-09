#!/usr/bin/env bash
# Generate the traffic the detection rules are meant to catch, so you can tune
# them against something instead of guessing.
#
#   ./replay_attacks.sh <target-ip>
#
# Run it from the attacker VM (or the host) against the monitored VM. Every
# scenario maps to a rule ID in detection-rules/local_rules.xml. Run it twice:
# once to see what fires, once after tuning to show the false positives gone.
#
# Only run this against your own lab. It is noisy by design.

set -euo pipefail

TARGET="${1:-}"
if [[ -z "$TARGET" ]]; then
    echo "usage: $0 <target-ip>" >&2
    exit 1
fi

if ! [[ "$TARGET" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
    echo "target must be an IPv4 address" >&2
    exit 1
fi

log() { printf '\n=== %s ===\n' "$1"; }

# ---------------------------------------------------------------- rule 100001/2
log "SSH brute force (expect rule 100001 at 8 failures)"
for i in $(seq 1 12); do
    sshpass -p "wrongpassword${i}" \
        ssh -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o ConnectTimeout=3 \
            -o PreferredAuthentications=password \
            "labuser@${TARGET}" true 2>/dev/null || true
    sleep 1
done

# ------------------------------------------------------------------ rule 100003
log "Long DNS queries (expect rule 100003 above 52 chars)"
for i in $(seq 1 20); do
    label=$(head -c 40 /dev/urandom | base32 | tr -d '=' | tr 'A-Z' 'a-z' | head -c 60)
    dig +short +tries=1 +time=1 "${label}.example.com" @"${TARGET}" >/dev/null 2>&1 || true
done

# ------------------------------------------------------------------ rule 100004
log "DNS tunnelling burst (expect rule 100004 above 120 in 60s)"
for i in $(seq 1 140); do
    label=$(head -c 40 /dev/urandom | base32 | tr -d '=' | tr 'A-Z' 'a-z' | head -c 60)
    dig +short +tries=1 +time=1 "${label}.tunnel.example.com" @"${TARGET}" >/dev/null 2>&1 || true
done

# ------------------------------------------------------------------ rule 100012
log "Scripted HTTP clients (expect rule 100012)"
curl -s -m 5 "http://${TARGET}/" >/dev/null 2>&1 || true
wget -q -T 5 -O /dev/null "http://${TARGET}/" 2>/dev/null || true
python3 -c "
import urllib.request, socket
socket.setdefaulttimeout(5)
try: urllib.request.urlopen('http://${TARGET}/').read()
except Exception: pass
" 2>/dev/null || true

# ------------------------------------------------------------------ rule 100011
log "Large outbound transfer (expect Zeek notice, rule 100011 above 50 MB)"
dd if=/dev/zero bs=1M count=60 2>/dev/null | \
    nc -w 10 "${TARGET}" 9999 2>/dev/null || \
    echo "  (start 'nc -l -p 9999 > /dev/null' on the target first)"

cat <<'EOF'

Done. Now, on the monitored host:

  Rules that fired:
    /var/ossec/bin/wazuh-logtest                      # interactive rule testing
    tail -f /var/ossec/logs/alerts/alerts.json | jq '.rule.id + " " + .rule.description'

  Count per rule, for the EVIDENCE.md table:
    jq -r '.rule.id' /var/ossec/logs/alerts/alerts.json | sort | uniq -c | sort -rn

  Zeek saw:
    cat /opt/zeek/logs/current/dns.log | jq -r '.query' | awk '{print length, $0}' | sort -rn | head

Anything firing that should not be is a tuning opportunity. Record the before
and after numbers: that is the part of this lab worth talking about.
EOF
