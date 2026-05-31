#!/bin/sh
# Redeploy IDS stack on Alpine ISO VM after reboot.
# Self-contained: brings up network, fixes apk repos, installs packages, deploys bundle, starts services.
# Run from this directory on the VM (push bundle via GNS3 console base64 paste; SSH refused).
set -e
cd "$(dirname "$0")"

echo "=== [1/5] network up (eth0/eth1 promisc, eth2+DHCP) ==="
ip link set eth0 up 2>/dev/null && ip link set eth0 promisc on 2>/dev/null || true
ip link set eth1 up 2>/dev/null && ip link set eth1 promisc on 2>/dev/null || true
ip link set eth2 up 2>/dev/null || true
udhcpc -i eth2 -t 8 -q 2>/dev/null || true
# Ensure mgmt IP 192.168.122.205 (libvirt DNAT host→guest relies on this exact IP)
ip -4 -o addr show eth2 | grep -q 192.168.122.205 \
    || ip addr add 192.168.122.205/24 dev eth2 2>/dev/null || true

echo "=== [2/5] apk internet repos + update ==="
# Alpine ISO boots with only CDROM repos (102 packages, no python3/suricata).
# Add dl-cdn main+community so apk can fetch real packages.
if ! grep -q dl-cdn /etc/apk/repositories 2>/dev/null; then
    cat > /etc/apk/repositories <<'EOF'
https://dl-cdn.alpinelinux.org/alpine/v3.23/main
https://dl-cdn.alpinelinux.org/alpine/v3.23/community
EOF
fi
apk update 2>&1 | tail -3

echo "=== [3/5] apk install (python3, suricata, curl) ==="
apk add --no-cache python3 suricata curl 2>&1 | tail -5

echo "=== [4/5] install bundle files ==="
install -m 755 ids-api.py            /usr/local/bin/ids-api.py
install -m 755 ids-api.openrc        /etc/init.d/ids-api
install -m 755 suricata.openrc       /etc/init.d/suricata-zt
install -m 644 suricata-zt.yaml      /etc/suricata/suricata-zt.yaml
install -m 644 rules/zt-lab.rules    /etc/suricata/rules/zt-lab.rules
mkdir -p /var/log/suricata /etc/suricata/rules

rc-update add suricata-zt default 2>/dev/null || true
rc-update add ids-api     default 2>/dev/null || true

echo "=== [5/5] start services + verify ==="
rc-service suricata-zt start
sleep 5
rc-service ids-api start
sleep 3
rc-service suricata-zt status
rc-service ids-api status
ss -ltn 2>/dev/null | grep -q 8765 \
    && echo "API: listening on :8765 OK" \
    || echo "WARN: api not listening on 8765"
curl -s -m 5 http://127.0.0.1:8765/health 2>/dev/null | head -c 200 && echo
