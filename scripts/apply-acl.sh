#!/bin/bash
# ===================================================
# Apply ACL Microsegmentation Policy
# Chay tung block tuong ung voi tung switch
# ===================================================

# ===================================================
# Tren SONIC-LEAF-1 (telnet://112.137.129.232:5010)
# ===================================================
# Buoc 1: Copy noi dung file acl-leaf1-microseg.json vao /tmp/
# (paste toan bo noi dung file vao terminal sau khi chay lenh cat):
# cat > /tmp/acl-leaf1.json << 'EOF'
# ... (paste noi dung acl-leaf1-microseg.json) ...
# EOF

# Buoc 2: Apply ACL vao CONFIG_DB
sudo sonic-cfggen -j /tmp/acl-leaf1.json --write-to-db

# Neu sonic-cfggen khong hoat dong, dung config load:
# sudo config load /tmp/acl-leaf1.json -y

# Buoc 3: Verify ACL da duoc load
show acl table
show acl rule

# Buoc 4: Save
sudo config save -y

# ===================================================
# Tren SONIC-LEAF-2 (telnet://112.137.129.232:5012)
# ===================================================
# Tuong tu Leaf-1, thay bang file acl-leaf2-microseg.json
sudo sonic-cfggen -j /tmp/acl-leaf2.json --write-to-db

show acl table
show acl rule

sudo config save -y

# ===================================================
# Verify ACL hoat dong (chay tu Alpine-1)
# ===================================================
# Nen co traffic bi DROP xuat hien trong logs:
# sudo tail -f /var/log/syslog | grep DROP
