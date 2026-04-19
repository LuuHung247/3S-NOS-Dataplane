#!/bin/bash
# =============================================================================
# 07-iptables-leaf1.sh — Zero Trust Microsegmentation rules cho LEAF-1
# =============================================================================
# Chạy trên: SONIC-LEAF-1 (console 5010)
# Chạy bằng: sudo bash 07-iptables-leaf1.sh
#
# LEAF-1 quản lý 2 zones:
#   Vlan100 (eth2) = WEB zone  — Alpine-1: 10.1.100.0/24
#   Vlan200 (eth3) = DB zone   — Alpine-2: 10.1.200.0/24
#
# POLICY MATRIX (Zero Trust: default deny, explicit allow):
#   WEB → APP (10.2.100.0/24): ALLOW   (web gọi API backend)
#   WEB → DB  (10.1.200.0/24): DENY    (web KHÔNG được truy cập DB trực tiếp)
#   WEB → MGT (10.2.50.0/24):  DENY
#   DB  → bất kỳ đâu:          DENY    (DB chỉ nhận request, không gửi ra ngoài)
#   APP → DB  (10.1.200.0/24): ALLOW   (app query database)
#   MGT → tất cả:              ALLOW   (management truy cập mọi thứ)
#
# Enforcement point: iptables FORWARD chain
#   Traffic đi qua LEAF khi:
#   - Alpine gửi cross-subnet → LEAF forward ra eth0 (uplink) → SPINE
#   - SPINE gửi cross-leaf → LEAF forward từ eth0 vào Vlan → Alpine
#   - Alpine gửi same-leaf cross-VLAN → LEAF forward giữa Vlan100 ↔ Vlan200
# =============================================================================

# Subnet definitions
WEB="10.1.100.0/24"
DB="10.1.200.0/24"
APP="10.2.100.0/24"
MGT="10.2.50.0/24"

echo "=== LEAF-1: Applying Zero Trust microsegmentation ==="

# ----- Step 1: Flush existing FORWARD rules (clean slate) -----
iptables -F FORWARD

# ----- Step 2: ALLOW established/related connections -----
# Cho phép reply packets cho các connections đã được allow.
# Ví dụ: APP gửi request đến DB (allowed), DB reply lại → cần ESTABLISHED rule.
# Không có rule này, DB reply bị drop vì DB → anywhere = DENY.
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# ----- Step 3: Explicit ALLOW rules -----

# [WEB → APP] Web server gọi Application API (port 8080 hoặc bất kỳ)
# Outbound: packet từ WEB subnet ra eth0 đi tới APP subnet
iptables -A FORWARD -s $WEB -d $APP -j ACCEPT

# [APP → DB] Application query database
# Inbound: packet từ APP (qua SPINE → eth0) vào DB subnet
iptables -A FORWARD -s $APP -d $DB -j ACCEPT

# [MGT → ALL] Management truy cập mọi thứ (monitoring, SSH, debug)
iptables -A FORWARD -s $MGT -j ACCEPT

# ----- Step 4: Default DENY all other forwarded traffic -----
# Đây là core Zero Trust: mọi thứ không được explicit allow → DROP.
# LOG trước khi DROP để có thể debug/audit.
iptables -A FORWARD -j LOG --log-prefix "[ZT-DENY-LEAF1] " --log-level 4
iptables -A FORWARD -j DROP

echo "=== LEAF-1: Rules applied ==="
echo ""
iptables -L FORWARD -n -v --line-numbers
echo ""
echo "Policy summary:"
echo "  ALLOW: WEB($WEB) → APP($APP)"
echo "  ALLOW: APP($APP) → DB($DB)"
echo "  ALLOW: MGT($MGT) → anywhere"
echo "  ALLOW: established/related replies"
echo "  DENY:  everything else (logged)"
