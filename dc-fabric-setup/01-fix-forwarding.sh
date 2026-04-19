#!/bin/bash
# =============================================================================
# 01-fix-forwarding.sh — Enable IP forwarding trên TẤT CẢ interfaces
# =============================================================================
# Chạy trên: SPINE, LEAF-1, LEAF-2 (tất cả SONiC nodes)
# Khi nào: Sau mỗi lần boot / config reload
#
# TẠI SAO CẦN SCRIPT NÀY:
#   SONiC-VS chỉ enable forwarding (=1) cho EthernetX interfaces.
#   Các interface khác (eth0, VlanXXX, Bridge) mặc định forwarding=0.
#   Linux kernel kiểm tra forwarding flag trên CẢ input và output interface.
#   Nếu bất kỳ interface nào có forwarding=0, packet bị drop (EHOSTUNREACH).
#
#   Ví dụ cross-leaf path: eth0 → route → Vlan100 → Bridge → Ethernet4
#   - eth0.forwarding=0      → packet bị drop ngay khi vào
#   - Vlan100.forwarding=0   → packet bị drop khi route ra Vlan100
#
# CÁCH VERIFY:
#   ip route get 10.2.100.10 from 10.0.2.1 iif eth0
#   → Nếu forwarding=0: "RTNETLINK answers: No route to host"
#   → Nếu forwarding=1: "10.2.100.10 from 10.0.2.1 dev Vlan100 cache iif eth0"
# =============================================================================

echo "=== Enabling IP forwarding on all interfaces ==="

# Enable global IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Enable per-interface forwarding cho TẤT CẢ interfaces
# Bao gồm: eth0, eth1, eth2, eth3, Ethernet0, Vlan100, Vlan200, Vlan300, Bridge, ...
for f in /proc/sys/net/ipv4/conf/*/forwarding; do
    echo 1 > "$f"
done

echo "=== Disabling reverse path filter (rp_filter) ==="

# rp_filter kiểm tra xem source IP có thể reach được qua input interface không.
# Với SONiC-VS có dual interfaces (eth0/Ethernet0 cùng subnet), rp_filter
# có thể fail vì reverse path qua Ethernet0 nhưng packet đến qua eth0.
# Disable để tránh false positive drops.
for f in /proc/sys/net/ipv4/conf/*/rp_filter; do
    echo 0 > "$f"
done

echo "=== Done. Verify with: ==="
echo "  cat /proc/sys/net/ipv4/conf/eth0/forwarding     (should be 1)"
echo "  cat /proc/sys/net/ipv4/conf/Vlan100/forwarding   (should be 1)"
echo "  cat /proc/sys/net/ipv4/conf/all/rp_filter        (should be 0)"
