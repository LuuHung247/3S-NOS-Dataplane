#!/bin/bash
# =============================================================================
# 07-iptables-leaf2.sh — Zero Trust Microsegmentation rules cho LEAF-2
# =============================================================================
# Chạy trên: SONIC-LEAF-2 (console 5015)
# Chạy bằng: sudo bash 07-iptables-leaf2.sh
#
# LEAF-2 quản lý 2 zones:
#   Vlan100 (eth2) = APP zone  — Alpine-3: 10.2.100.0/24
#   Vlan300 (eth3) = MGT zone  — Alpine-5: 10.2.50.0/24
#
# POLICY MATRIX — phải đồng bộ với LEAF-1:
#   APP → DB  (10.1.200.0/24): ALLOW   (app query database)
#   APP → WEB (10.1.100.0/24): DENY    (app không gọi ngược web)
#   APP → MGT (10.2.50.0/24):  DENY
#   MGT → tất cả:              ALLOW   (management truy cập mọi thứ)
#   WEB → APP (10.2.100.0/24): ALLOW   (web gọi API backend)
#   DB  → bất kỳ đâu:          DENY    (chặn tại LEAF-1, nhưng LEAF-2 cũng chặn)
#
# TẠI SAO CẦN RULES TRÊN CẢ 2 LEAF:
#   Traffic cross-leaf đi qua: Source Alpine → Source LEAF → SPINE → Dest LEAF → Dest Alpine
#   Rules trên Source LEAF chặn OUTBOUND (ngăn packet rời zone)
#   Rules trên Dest LEAF chặn INBOUND (ngăn packet vào zone)
#   → Defense in depth: dù bypass 1 LEAF, LEAF còn lại vẫn chặn.
# =============================================================================

# Subnet definitions
WEB="10.1.100.0/24"
DB="10.1.200.0/24"
APP="10.2.100.0/24"
MGT="10.2.50.0/24"

echo "=== LEAF-2: Applying Zero Trust microsegmentation ==="

# ----- Step 1: Flush existing FORWARD rules -----
iptables -F FORWARD

# ----- Step 2: ALLOW established/related connections -----
# Critical: cho phép reply packets. Ví dụ:
#   WEB gửi HTTP request đến APP (allowed) → APP reply HTTP response
#   Không có rule này, APP→WEB reply bị DENY (vì APP→WEB = DENY)
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# ----- Step 3: Explicit ALLOW rules -----

# [WEB → APP] Inbound: packet từ WEB (qua SPINE) vào APP zone
iptables -A FORWARD -s $WEB -d $APP -j ACCEPT

# [APP → DB] Outbound: packet từ APP zone ra eth0 đi tới DB zone
iptables -A FORWARD -s $APP -d $DB -j ACCEPT

# [MGT → ALL] Management toàn quyền
iptables -A FORWARD -s $MGT -j ACCEPT

# ----- Step 4: Default DENY -----
iptables -A FORWARD -j LOG --log-prefix "[ZT-DENY-LEAF2] " --log-level 4
iptables -A FORWARD -j DROP

echo "=== LEAF-2: Rules applied ==="
echo ""
iptables -L FORWARD -n -v --line-numbers
echo ""
echo "Policy summary:"
echo "  ALLOW: WEB($WEB) → APP($APP)"
echo "  ALLOW: APP($APP) → DB($DB)"
echo "  ALLOW: MGT($MGT) → anywhere"
echo "  ALLOW: established/related replies"
echo "  DENY:  everything else (logged)"
