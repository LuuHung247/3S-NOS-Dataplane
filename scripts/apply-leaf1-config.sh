#!/bin/bash
# ===================================================
# SONIC-LEAF-1 Configuration
# Telnet: telnet://112.137.129.232:5010
# Login: admin / YourPaSsWoRd
# ===================================================
# Chay tung lenh nay SAU KHI da SSH/telnet vao SONIC-LEAF-1

# --- Buoc 1: Startup interfaces ---
# Ethernet0 = noi SPINE (adapter 0)
# Ethernet4 = noi Alpine-Linux-1 (adapter 1)
# Ethernet8 = noi Alpine-Linux-2 (adapter 2)
sudo config interface startup Ethernet0
sudo config interface startup Ethernet4
sudo config interface startup Ethernet8

# --- Buoc 2: Xoa L3 config mac dinh tren cac port access ---
# Giu nguyen Ethernet0 (uplink den Spine) - se gan IP o buoc 3
sudo sonic-db-cli CONFIG_DB del "INTERFACE|Ethernet4"
sudo sonic-db-cli CONFIG_DB del "INTERFACE|Ethernet8"
sudo sonic-db-cli CONFIG_DB del "INTERFACE|Ethernet4|10.0.0.0/31"
sudo sonic-db-cli CONFIG_DB del "INTERFACE|Ethernet8|10.0.0.2/31"

# --- Buoc 3: Gan IP cho uplink Ethernet0 ---
sudo sonic-db-cli CONFIG_DB del "INTERFACE|Ethernet0"
sudo sonic-db-cli CONFIG_DB del "INTERFACE|Ethernet0|10.0.0.0/31"
sudo config interface ip add Ethernet0 10.0.1.2/30

# --- Buoc 4: Tao VLAN ---
# VLAN 100: WEB zone (Alpine-Linux-1)
# VLAN 200: DB zone (Alpine-Linux-2)
sudo config vlan add 100
sudo config vlan add 200

# --- Buoc 5: Gan port vao VLAN (untagged vi Alpine khong hieu 802.1Q) ---
sudo config vlan member add -u 100 Ethernet4   # Alpine-1 vao VLAN100
sudo config vlan member add -u 200 Ethernet8   # Alpine-2 vao VLAN200

# --- Buoc 6: Tao VLAN interface (SVI - L3 gateway cho moi VLAN) ---
# Day la gateway cho cac host trong VLAN
sudo config interface ip add Vlan100 10.1.100.1/24
sudo config interface ip add Vlan200 10.1.200.1/24

# --- Buoc 7: Them default route ve Spine ---
sudo vtysh -c "configure terminal" \
  -c "ip route 0.0.0.0/0 10.0.1.1" \
  -c "exit"

# --- Buoc 8: Verify ---
echo "=== VLAN Brief ==="
show vlan brief

echo "=== Interface IP ==="
show ip interface

echo "=== Routes ==="
show ip route

# --- Buoc 9: Save ---
sudo config save -y
