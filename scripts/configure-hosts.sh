#!/bin/sh
# ===================================================
# Alpine Linux Host Configuration
# Chay tung block tuong ung voi tung host
# Login: root (khong can password)
# ===================================================

# ===================================================
# Alpine-Linux-1 (WEB zone - Leaf-1)
# Telnet: telnet://112.137.129.232:5008
# ===================================================
# Gan IP va route
ip addr add 10.1.100.10/24 dev eth0
ip link set eth0 up
ip route add default via 10.1.100.1

# Verify
ip addr show eth0
ip route show
ping -c 2 10.1.100.1   # ping gateway Leaf-1

# ===================================================
# Alpine-Linux-2 (DB zone - Leaf-1)
# Telnet: telnet://112.137.129.232:5011
# ===================================================
ip addr add 10.1.200.10/24 dev eth0
ip link set eth0 up
ip route add default via 10.1.200.1

ip addr show eth0
ip route show
ping -c 2 10.1.200.1   # ping gateway Leaf-1

# ===================================================
# Alpine-Linux-3 (WEB zone - Leaf-2)
# Telnet: telnet://112.137.129.232:5014
# ===================================================
ip addr add 10.2.100.10/24 dev eth0
ip link set eth0 up
ip route add default via 10.2.100.1

ip addr show eth0
ip route show
ping -c 2 10.2.100.1   # ping gateway Leaf-2

# ===================================================
# Alpine-Linux-4 (APP zone - Leaf-2)
# Telnet: telnet://112.137.129.232:5016
# ===================================================
ip addr add 10.2.50.10/24 dev eth0
ip link set eth0 up
ip route add default via 10.2.50.1

ip addr show eth0
ip route show
ping -c 2 10.2.50.1   # ping gateway Leaf-2
