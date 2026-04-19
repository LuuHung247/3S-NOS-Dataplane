#!/bin/bash
# ===================================================
# SONIC-LEAF-2 Configuration
# Telnet: telnet://112.137.129.232:5012
# Login: admin / YourPaSsWoRd
# ===================================================

# --- Buoc 1: Startup interfaces ---
# Ethernet0 = noi SPINE
# Ethernet4 = noi Alpine-Linux-3
# Ethernet8 = noi Alpine-Linux-4
sudo config interface startup Ethernet0
sudo config interface startup Ethernet4
sudo config interface startup Ethernet8

# --- Buoc 2: Xoa L3 config mac dinh tren access ports ---
sudo sonic-db-cli CONFIG_DB del "INTERFACE|Ethernet4"
sudo sonic-db-cli CONFIG_DB del "INTERFACE|Ethernet8"
sudo sonic-db-cli CONFIG_DB del "INTERFACE|Ethernet4|10.0.0.0/31"
sudo sonic-db-cli CONFIG_DB del "INTERFACE|Ethernet8|10.0.0.2/31"

# --- Buoc 3: Gan IP cho uplink Ethernet0 ---
sudo sonic-db-cli CONFIG_DB del "INTERFACE|Ethernet0"
sudo sonic-db-cli CONFIG_DB del "INTERFACE|Ethernet0|10.0.0.0/31"
sudo config interface ip add Ethernet0 10.0.2.2/30

# --- Buoc 4: Tao VLAN ---
# VLAN 100: WEB zone (Alpine-Linux-3)
# VLAN 300: APP zone (Alpine-Linux-4)
sudo config vlan add 100
sudo config vlan add 300

# --- Buoc 5: Gan port vao VLAN ---
sudo config vlan member add -u 100 Ethernet4   # Alpine-3 vao VLAN100
sudo config vlan member add -u 300 Ethernet8   # Alpine-4 vao VLAN300

# --- Buoc 6: Tao VLAN interface (SVI gateway) ---
sudo config interface ip add Vlan100 10.2.100.1/24
sudo config interface ip add Vlan300 10.2.50.1/24

# --- Buoc 7: Default route ve Spine ---
sudo vtysh -c "configure terminal" \
  -c "ip route 0.0.0.0/0 10.0.2.1" \
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
