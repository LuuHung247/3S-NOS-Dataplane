#!/bin/bash
# =============================================================================
# 02-setup-leaf1.sh — Config LEAF-1 cho cross-leaf routing
# =============================================================================
# Chạy trên: SONIC-LEAF-1 (console 5010, SSH admin@10.0.1.2 via SPINE)
# Prerequisite: 01-fix-forwarding.sh đã chạy trước
#
# LEAF-1 topology:
#   eth0 (adapter0) → Uplink tới SPINE, IP 10.0.1.2/30
#   eth2 (adapter2) → Alpine-1 (WEB), qua Vlan100, IP 10.1.100.1/24
#   eth3 (adapter3) → Alpine-2 (DB),  qua Vlan200, IP 10.1.200.1/24
# =============================================================================

echo "=== LEAF-1: Cross-leaf route ==="

# Route tới LEAF-2 subnets (10.2.x.x) qua SPINE
# - 10.2.100.0/24 = Alpine-3 (APP) trên LEAF-2
# - 10.2.50.0/24  = Alpine-5 (MGT) trên LEAF-2
# Gửi qua eth0 tới SPINE (10.0.1.1), SPINE forward tiếp tới LEAF-2
ip route add 10.2.0.0/16 via 10.0.1.1 dev eth0 2>/dev/null || \
ip route replace 10.2.0.0/16 via 10.0.1.1 dev eth0

echo "=== LEAF-1: Static ARP entries ==="

# SONiC-VS bridge đôi khi không forward ARP reply từ Vlan SVI đến Alpine.
# Static ARP đảm bảo LEAF luôn biết MAC của Alpine hosts.
#
# Alpine-1 (WEB): MAC 0c:ec:b2:6c:00:00, IP 10.1.100.10, trên Vlan100
ip neigh replace 10.1.100.10 lladdr 0c:ec:b2:6c:00:00 dev Vlan100 nud permanent

# Alpine-2 (DB): MAC 0c:ce:e0:ff:00:00, IP 10.1.200.10, trên Vlan200
ip neigh replace 10.1.200.10 lladdr 0c:ce:e0:ff:00:00 dev Vlan200 nud permanent

echo "=== LEAF-1: Done ==="
echo "Verify:"
echo "  ip route | grep 10.2       (should show 10.2.0.0/16 via 10.0.1.1)"
echo "  ip neigh show dev Vlan100  (should show 10.1.100.10 PERMANENT)"
echo "  ip neigh show dev Vlan200  (should show 10.1.200.10 PERMANENT)"
