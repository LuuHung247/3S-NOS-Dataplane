#!/bin/bash
# =============================================================================
# 03-setup-leaf2.sh — Config LEAF-2 cho cross-leaf routing
# =============================================================================
# Chạy trên: SONIC-LEAF-2 (console 5015, SSH admin@10.0.2.2 via SPINE)
# Prerequisite: 01-fix-forwarding.sh đã chạy trước
#
# LEAF-2 topology:
#   eth0 (adapter0) → Uplink tới SPINE, IP 10.0.2.2/30
#   eth2 (adapter2) → Alpine-3 (APP), qua Vlan100, IP 10.2.100.1/24
#   eth3 (adapter3) → Alpine-5 (MGT), qua Vlan300, IP 10.2.50.1/24
# =============================================================================

echo "=== LEAF-2: Cross-leaf route ==="

# Route tới LEAF-1 subnets (10.1.x.x) qua SPINE
# - 10.1.100.0/24 = Alpine-1 (WEB) trên LEAF-1
# - 10.1.200.0/24 = Alpine-2 (DB)  trên LEAF-1
# Gửi qua eth0 tới SPINE (10.0.2.1), SPINE forward tiếp tới LEAF-1
ip route add 10.1.0.0/16 via 10.0.2.1 dev eth0 2>/dev/null || \
ip route replace 10.1.0.0/16 via 10.0.2.1 dev eth0

echo "=== LEAF-2: Static ARP entries ==="

# Alpine-3 (APP): MAC 0c:87:e5:f0:00:00, IP 10.2.100.10, trên Vlan100
ip neigh replace 10.2.100.10 lladdr 0c:87:e5:f0:00:00 dev Vlan100 nud permanent

# Alpine-5 (MGT): MAC 0c:c8:49:9e:00:00, IP 10.2.50.10, trên Vlan300
ip neigh replace 10.2.50.10 lladdr 0c:c8:49:9e:00:00 dev Vlan300 nud permanent

echo "=== LEAF-2: Done ==="
echo "Verify:"
echo "  ip route | grep 10.1       (should show 10.1.0.0/16 via 10.0.2.1)"
echo "  ip neigh show dev Vlan100  (should show 10.2.100.10 PERMANENT)"
echo "  ip neigh show dev Vlan300  (should show 10.2.50.10 PERMANENT)"
