#!/bin/bash
# ===================================================
# SONIC-SPINE Configuration
# Telnet: telnet://112.137.129.232:5006
# Login: admin / YourPaSsWoRd
# ===================================================
# Chay tung lenh nay SAU KHI da SSH/telnet vao SONIC-SPINE

# --- Buoc 1: Startup interfaces uplink ---
# Ethernet4 = noi LEAF-1 (adapter 1)
# Ethernet8 = noi LEAF-2 (adapter 2)
sudo config interface startup Ethernet4
sudo config interface startup Ethernet8

# --- Buoc 2: Xoa L3 config mac dinh ---
# SONiC mac dinh dung L3 mode voi IP 10.0.0.x, can xoa de gan IP moi
sudo sonic-db-cli CONFIG_DB del "INTERFACE|Ethernet4"
sudo sonic-db-cli CONFIG_DB del "INTERFACE|Ethernet8"
# Xoa ca IP cu neu co
sudo sonic-db-cli CONFIG_DB del "INTERFACE|Ethernet4|10.0.0.0/31"
sudo sonic-db-cli CONFIG_DB del "INTERFACE|Ethernet8|10.0.0.2/31"

# --- Buoc 3: Gan IP moi cho uplink interfaces ---
# Spine-Leaf1 link: 10.0.1.0/30
sudo config interface ip add Ethernet4 10.0.1.1/30
# Spine-Leaf2 link: 10.0.2.0/30
sudo config interface ip add Ethernet8 10.0.2.1/30

# --- Buoc 4: Them static routes den cac VLAN subnet ---
# Routes den cac subnet tren Leaf-1
sudo vtysh -c "configure terminal" \
  -c "ip route 10.1.100.0/24 10.0.1.2" \
  -c "ip route 10.1.200.0/24 10.0.1.2" \
  -c "ip route 10.2.100.0/24 10.0.2.2" \
  -c "ip route 10.2.50.0/24 10.0.2.2" \
  -c "exit"

# --- Buoc 5: Verify ---
echo "=== Interface Status ==="
show ip interface

echo "=== Routing Table ==="
show ip route

echo "=== Interface Admin Status ==="
show interfaces status

# --- Buoc 6: Save config ---
sudo config save -y
