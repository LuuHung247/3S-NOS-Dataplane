#!/bin/bash
# =============================================================================
# 04-setup-spine.sh — Config SPINE cho inter-LEAF routing
# =============================================================================
# Chạy trên: SONIC-SPINE (console 5006, SSH admin@192.168.122.187)
# Prerequisite: 01-fix-forwarding.sh đã chạy trước
#
# SPINE topology:
#   eth0 (adapter0) → Management, DHCP (192.168.122.x)
#   eth1 (adapter1) → LEAF-1, IP 10.0.1.1/30
#   eth2 (adapter2) → LEAF-2, IP 10.0.2.1/30
#
# SPINE là trung tâm routing giữa 2 LEAFs:
#   LEAF-1 subnets (10.1.x.x) ←→ SPINE ←→ LEAF-2 subnets (10.2.x.x)
# =============================================================================

echo "=== SPINE: Inter-LEAF routes ==="

# Route tới LEAF-1 subnets qua eth1
# Next-hop 10.0.1.2 = LEAF-1's uplink IP
ip route replace 10.1.0.0/16 via 10.0.1.2 dev eth1

# Route tới LEAF-2 subnets qua eth2
# Next-hop 10.0.2.2 = LEAF-2's uplink IP
ip route replace 10.2.0.0/16 via 10.0.2.2 dev eth2

echo "=== SPINE: Done ==="
echo "Verify:"
echo "  ip route | grep '10\.[12]'  (should show both 10.1 and 10.2 routes)"
echo "  ping -c 1 10.0.1.2          (LEAF-1 uplink)"
echo "  ping -c 1 10.0.2.2          (LEAF-2 uplink)"
